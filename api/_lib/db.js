'use strict';
// Database access: a single Pool (max:1) with explicit client scopes.
// The Neon driver is imported LAZILY inside functions so every module loads
// (and every test runs) without @neondatabase/serverless being installed.

const config = require('./config');
const { log } = require('./log');

let pool = null;
let pending = null;
let poolFactory = null;
let driverQueryClass = null;
let driverClientClass = null;

// Serverless pool & bounded timeouts (verified supported by @neondatabase/serverless@0.10.4).
const DEFAULT_POOL_OPTIONS = Object.freeze({
  max: 1,
  connectionTimeoutMillis: 8000,
  statement_timeout: 10000,
  query_timeout: 12000,
  idleTimeoutMillis: 10000
});

const DEFAULT_OPERATION_TIMEOUT_MS = 15000;

const stats = { connect: 0, used: 0, closed: 0, discarded: 0 };

function markUnavailable(err, reason) {
  if (err && typeof err === 'object') {
    err.kind = 'db_unavailable';
    if (reason && !err.code) err.code = reason;
  }
  return err;
}

function unavailable(reason, message) {
  return markUnavailable(new Error(message || 'database unavailable'), reason);
}

// Test seam: inject a fake pool (or a factory returning one).
function setPoolFactoryForTests(fn) {
  poolFactory = typeof fn === 'function' ? fn : null;
  pool = null;
  pending = null;
}

function buildPoolConfig(connectionString) {
  return Object.assign({ connectionString }, DEFAULT_POOL_OPTIONS);
}

function shouldDiscardClient(err) {
  if (!err) return false;
  const code = String(err.code || '');
  if (
    code === 'probe_timeout' ||
    code === 'query_timeout' ||
    code === 'connect_timeout' ||
    code === 'connect_failed' ||
    code === 'rollback_failed'
  ) {
    return true;
  }
  if (isDbUnavailable(err)) return true;
  const message = String(err.message || '');
  return /Query read timeout|timeout|timed out|aborted|socket|destroyed|Connection terminated/i.test(message);
}

function guardClientErrorEvents(client) {
  if (!client || typeof client.on !== 'function' || client.__arkikErrorGuard) return;
  client.__arkikErrorGuard = true;
  client.on('error', (err) => {
    log('DATABASE', `client error ${errCode(err)}`);
  });
}

async function createPool() {
  const url = config.databaseUrl;
  if (!url) {
    throw unavailable('no_database', 'DATABASE_URL is not configured');
  }
  try {
    const mod = await import('@neondatabase/serverless');
    const Pool = mod.Pool || (mod.default && mod.default.Pool);
    if (typeof Pool !== 'function') {
      throw unavailable('driver_unavailable', 'neon driver unavailable');
    }
    driverQueryClass = mod.Query || (mod.default && mod.default.Query) || null;
    driverClientClass = mod.Client || (mod.default && mod.default.Client) || null;
    const created = new Pool(buildPoolConfig(url));
    if (typeof created.on === 'function') {
      created.on('error', (err) => log('DATABASE', `idle pool error ${errCode(err)}`));
    }
    stats.connect += 1;
    log('DATABASE', 'pool created (max:1)');
    return created;
  } catch (err) {
    throw markUnavailable(err, 'driver_unavailable');
  }
}

function errCode(err) {
  return (err && err.code) || (err && err.name) || 'unknown';
}

async function resolvePool() {
  if (poolFactory) {
    const injected = await poolFactory();
    if (!injected) throw unavailable('no_test_pool', 'test pool factory returned nothing');
    return injected;
  }
  if (pool) return pool;
  if (!pending) {
    pending = createPool()
      .then((created) => {
        pool = created;
        return created;
      })
      .finally(() => {
        pending = null;
      });
  }
  return pending;
}

async function takeClient(options = {}) {
  const active = await resolvePool();
  const timeoutMs =
    Number(options && options.connectTimeoutMs) > 0
      ? Number(options.connectTimeoutMs)
      : DEFAULT_POOL_OPTIONS.connectionTimeoutMillis;

  let timedOut = false;
  let timer = null;
  const timeoutErr = unavailable('connect_timeout', `database connect timeout after ${timeoutMs}ms`);

  const connectPromise = Promise.resolve().then(() => active.connect());
  // If connect finishes after timeout, discard the late client so max:1 pool never wedges.
  connectPromise.then(
    (lateClient) => {
      if (timedOut && lateClient) {
        stats.used += 1;
        releaseClient(lateClient, timeoutErr);
      }
    },
    () => {}
  );

  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      reject(timeoutErr);
    }, timeoutMs);
    if (typeof timer.unref === 'function') timer.unref();
  });

  try {
    const client = await Promise.race([connectPromise, timeoutPromise]);
    stats.used += 1;
    return client;
  } catch (err) {
    if (err === timeoutErr) throw err;
    throw markUnavailable(err, 'connect_failed');
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function releaseClient(client, err) {
  if (!client) return;
  const discardErr = err || null;
  try {
    if (typeof client.release === 'function') {
      if (discardErr) client.release(discardErr);
      else client.release();
    } else if (discardErr && typeof client.end === 'function') {
      client.end();
    }
    stats.closed += 1;
    if (discardErr) stats.discarded += 1;
  } catch (releaseErr) {
    log('ERROR', `client release failed ${errCode(releaseErr)}`);
  }
}

async function executeWithManagedClient(fn, options = {}) {
  const startMs = Date.now();
  const hasCustomTimeout = Number(options && options.timeoutMs) > 0;
  const totalTimeoutMs = hasCustomTimeout ? Number(options.timeoutMs) : DEFAULT_OPERATION_TIMEOUT_MS;
  const connectTimeoutMs = Math.min(totalTimeoutMs, DEFAULT_POOL_OPTIONS.connectionTimeoutMillis);

  const client = await takeClient({ connectTimeoutMs });
  guardClientErrorEvents(client);

  let released = false;
  let forceDiscard = false;
  let capturedErr = null;
  const releaseOnce = (err) => {
    if (released) return;
    released = true;
    releaseClient(client, err);
  };

  const remainingMs = Math.max(1, totalTimeoutMs - (Date.now() - startMs));
  let timer = null;
  let aborted = false;

  const context = {
    get aborted() {
      return aborted;
    },
    get remainingMs() {
      return Math.max(1, totalTimeoutMs - (Date.now() - startMs));
    },
    markDiscard(err) {
      forceDiscard = true;
      if (err && !capturedErr) capturedErr = err;
    }
  };

  const workPromise = Promise.resolve().then(() => fn(client, context));
  // Avoid UnhandledPromiseRejection if timeout fires while the driver query settles later.
  workPromise.catch(() => {});

  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      aborted = true;
      const timeoutErr = unavailable('query_timeout', `database operation timeout after ${totalTimeoutMs}ms`);
      capturedErr = timeoutErr;
      forceDiscard = true;
      releaseOnce(timeoutErr);
      reject(timeoutErr);
    }, remainingMs);
    if (typeof timer.unref === 'function') timer.unref();
  });

  try {
    return await Promise.race([workPromise, timeoutPromise]);
  } catch (err) {
    capturedErr = capturedErr || err;
    if (err && err.code === 'query_timeout') {
      forceDiscard = true;
    }
    throw err;
  } finally {
    if (timer) clearTimeout(timer);
    const discard = forceDiscard || shouldDiscardClient(capturedErr);
    releaseOnce(discard ? (capturedErr || new Error('discard_client')) : null);
  }
}

// Run fn(client) on a dedicated connection; the client is always released once.
async function withClient(fn, options) {
  return executeWithManagedClient((client, ctx) => fn(client, ctx), options);
}

// Run fn(client) inside BEGIN/COMMIT with ROLLBACK on any throw.
async function withTransaction(fn, options) {
  return executeWithManagedClient(async (client, ctx) => {
    let begun = false;
    try {
      await client.query('BEGIN');
      begun = true;
      const result = await fn(client, ctx);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      if (ctx.aborted || shouldDiscardClient(err)) {
        ctx.markDiscard(err);
      } else if (begun) {
        try {
          await client.query('ROLLBACK');
        } catch (rollbackErr) {
          log('ERROR', `rollback failed ${errCode(rollbackErr)}`);
          const marked = markUnavailable(rollbackErr, 'rollback_failed');
          ctx.markDiscard(marked);
        }
      }
      throw err;
    }
  }, options);
}

const CONNECTION_ERRNO = [
  'ECONNREFUSED',
  'ECONNRESET',
  'ETIMEDOUT',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EPIPE',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_SOCKET',
  'UND_ERR_HEADERS_TIMEOUT'
];

// True when the failure means "the database cannot be reached", which maps to
// HTTP 503 instead of 500.
function isDbUnavailable(err) {
  if (!err) return false;
  if (err.kind === 'db_unavailable') return true;
  const code = err.code;
  if (typeof code === 'string') {
    if (CONNECTION_ERRNO.indexOf(code) !== -1) return true;
    if (/^(08|53|57P)/.test(code)) return true; // connection exception / resource / admin shutdown
  }
  const name = err.name || '';
  if (/FetchError|ConnectTimeout|SocketError/.test(name)) return true;
  const message = String(err.message || '');
  if (/connect|fetch failed|socket hang up|Connection terminated|Connection refused|database is not currently accepting/i.test(message)) {
    return true;
  }
  return false;
}

function isUniqueViolation(err) {
  return Boolean(err) && err.code === '23505';
}

function getStats() {
  return Object.assign({}, stats);
}

function buildProbeQuery(client, remainingMs) {
  if (driverQueryClass && driverClientClass && client instanceof driverClientClass) {
    return new driverQueryClass({
      text: 'SELECT 1',
      query_timeout: Math.max(100, Number(remainingMs) || 4000)
    });
  }
  return 'SELECT 1';
}

/**
 * Execute a bounded SELECT 1 readiness check against the provided database adapter.
 * Cleans up the timeout timer deterministically, discards wedged/timed-out clients,
 * and never surfaces connection secrets.
 */
async function probeConnection(targetDb = module.exports, timeoutMs = 4000) {
  const effectiveTimeoutMs = Math.max(1, Number(timeoutMs) || 4000);
  if (targetDb && targetDb._usesManagedTimeouts) {
    try {
      await targetDb.withClient(
        (client, ctx) => client.query(buildProbeQuery(client, ctx ? ctx.remainingMs : effectiveTimeoutMs)),
        { timeoutMs: effectiveTimeoutMs }
      );
      return { ok: true, database: 'connected' };
    } catch (_err) {
      return { ok: false, database: 'unavailable' };
    }
  }

  let timer = null;
  const workPromise = Promise.resolve().then(() =>
    targetDb.withClient((client) => client.query(buildProbeQuery(client, effectiveTimeoutMs)), {
      timeoutMs: effectiveTimeoutMs
    })
  );
  workPromise.catch(() => {});

  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(unavailable('probe_timeout', 'database probe timeout'));
    }, effectiveTimeoutMs);
    if (typeof timer.unref === 'function') timer.unref();
  });

  try {
    await Promise.race([workPromise, timeoutPromise]);
    return { ok: true, database: 'connected' };
  } catch (_err) {
    return { ok: false, database: 'unavailable' };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

module.exports = {
  _usesManagedTimeouts: true,
  DEFAULT_POOL_OPTIONS,
  getPoolConfig: buildPoolConfig,
  withClient,
  withTransaction,
  setPoolFactoryForTests,
  probeConnection,
  isDbUnavailable,
  isUniqueViolation,
  getStats
};

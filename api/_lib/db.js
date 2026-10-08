'use strict';
// Database access: a single Pool (max:1) with explicit client scopes.
// The Neon driver is imported LAZILY inside functions so every module loads
// (and every test runs) without @neondatabase/serverless being installed.

const config = require('./config');
const { log } = require('./log');

let pool = null;
let pending = null;
let poolFactory = null;

const stats = { connect: 0, used: 0, closed: 0 };

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
    const created = new Pool({ connectionString: url, max: 1 });
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

async function takeClient() {
  const active = await resolvePool();
  try {
    const client = await active.connect();
    stats.used += 1;
    return client;
  } catch (err) {
    throw markUnavailable(err, 'connect_failed');
  }
}

function releaseClient(client) {
  if (!client) return;
  try {
    if (typeof client.release === 'function') client.release();
    stats.closed += 1;
  } catch (err) {
    log('ERROR', `client release failed ${errCode(err)}`);
  }
}

// Run fn(client) on a dedicated connection; the client is always released.
async function withClient(fn) {
  const client = await takeClient();
  try {
    return await fn(client);
  } finally {
    releaseClient(client);
  }
}

// Run fn(client) inside BEGIN/COMMIT with ROLLBACK on any throw.
async function withTransaction(fn) {
  const client = await takeClient();
  let begun = false;
  try {
    await client.query('BEGIN');
    begun = true;
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    if (begun) {
      try {
        await client.query('ROLLBACK');
      } catch (rollbackErr) {
        log('ERROR', `rollback failed ${errCode(rollbackErr)}`);
      }
    }
    throw err;
  } finally {
    releaseClient(client);
  }
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

module.exports = {
  withClient,
  withTransaction,
  setPoolFactoryForTests,
  isDbUnavailable,
  isUniqueViolation,
  getStats
};

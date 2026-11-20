'use strict';
// Offline unit & security invariant tests for P0.4.5-A remediation:
// - Direct CLI helper isolation (DIRECT_DATABASE_URL without fallback to DATABASE_URL)
// - seed-dev.js fail-closed environment & loopback guards
// - db/migrate.js single-client advisory lock, numeric ordering, checksums, and >=6 char PINs
// - db/manage-admin-pins.js >=6 char PIN validation, SET LOCAL rotation, and Direct CLI check
// - Runtime SET LOCAL / lockDate concurrency / atomic putPricing / HTTP timeout differentiation
// - Cookie sliding refresh, malformed cookie safety, trusted proxy IP resolution, and log redaction

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { describe, test } = require('node:test');

const REPO = path.resolve(__dirname, '..');
const directDb = require(path.join(REPO, 'db', '_lib', 'direct-db.js'));
const migrate = require(path.join(REPO, 'db', 'migrate.js'));
const managePins = require(path.join(REPO, 'db', 'manage-admin-pins.js'));
const seedDev = require(path.join(REPO, 'db', 'seed-dev.js'));
const db = require(path.join(REPO, 'api', '_lib', 'db.js'));
const config = require(path.join(REPO, 'api', '_lib', 'config.js'));
const respond = require(path.join(REPO, 'api', '_lib', 'respond.js'));
const repo = require(path.join(REPO, 'api', '_lib', 'repo.js'));
const service = require(path.join(REPO, 'api', '_lib', 'service.js'));
const auth = require(path.join(REPO, 'api', '_lib', 'auth.js'));
const logMod = require(path.join(REPO, 'api', '_lib', 'log.js'));
const readyHandler = require(path.join(REPO, 'api', 'ready.js'));
const loginHandler = require(path.join(REPO, 'api', 'admin', 'login.js'));
const sessionHandler = require(path.join(REPO, 'api', 'admin', 'session.js'));

async function withEnv(overrides, fn) {
  const saved = {};
  for (const k of Object.keys(overrides)) {
    saved[k] = process.env[k];
    if (overrides[k] === undefined || overrides[k] === null) delete process.env[k];
    else process.env[k] = String(overrides[k]);
  }
  try {
    return await fn();
  } finally {
    for (const k of Object.keys(saved)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

function makeRes() {
  return {
    headers: {},
    statusCode: 200,
    body: undefined,
    headersSent: false,
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
      return this;
    },
    getHeader(name) {
      return this.headers[name.toLowerCase()];
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      this.headersSent = true;
      return this;
    },
    end() {
      this.headersSent = true;
      return this;
    }
  };
}

describe('P0.4.5-A Direct Isolation, Fail-Closed Seed, Concurrency, Cookie & Timeout Suite (Offline Mocks)', () => {
  test('A1: direct-db requires DIRECT_DATABASE_URL strictly with zero fallback to DATABASE_URL', () => {
    assert.throws(
      () =>
        directDb.resolveDirectConnectionConfig({
          DATABASE_URL: 'postgresql://u:p@ep-abc-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require'
        }),
      /DIRECT_DATABASE_URL is not configured/
    );
  });

  test('A2: direct-db rejects -pooler, bad schemes, missing db, sslmode=disable & cert files without leaking credentials', () => {
    const secretPw = 'super_secret_pw_987';
    const badUrls = [
      `postgresql://neondb_owner:${secretPw}@ep-abc-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require`,
      `postgresql://user:${secretPw}@pooler.internal.example/neondb`,
      `http://user:${secretPw}@ep-abc.us-east-2.aws.neon.tech/neondb`,
      `postgresql://user:${secretPw}@ep-abc.us-east-2.aws.neon.tech/`,
      `postgresql://user:${secretPw}@ep-abc.us-east-2.aws.neon.tech/neondb?sslmode=disable`,
      `postgresql://user:${secretPw}@ep-abc.us-east-2.aws.neon.tech/neondb?sslmode=require&sslrootcert=/tmp/ca.pem`
    ];

    for (const url of badUrls) {
      let caught = null;
      try {
        directDb.validateDirectDatabaseUrl(url, { APP_ENV: 'staging' });
      } catch (err) {
        caught = err;
      }
      assert.ok(caught, `expected rejection for URL shape`);
      assert.equal(caught.message.includes(secretPw), false, 'error must never expose DB password');
    }

    const okUrl = `postgresql://neondb_owner:${secretPw}@ep-abc.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require`;
    const meta = directDb.validateDirectDatabaseUrl(okUrl, {
      APP_ENV: 'staging',
      DATABASE_URL: 'postgresql://arkik_app:other_pw@ep-abc-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require'
    });
    assert.equal(meta.host, 'ep-abc.us-east-2.aws.neon.tech');
    assert.equal(meta.dbName, 'neondb');
    assert.equal(meta.warnings.length, 0);
    assert.match(meta.targetSummary, /mode=direct/);
    assert.equal(meta.targetSummary.includes(secretPw), false);
    assert.equal(meta.targetSummary.includes('neondb_owner'), false);

    const mismatched = directDb.validateDirectDatabaseUrl(okUrl, {
      APP_ENV: 'staging',
      DATABASE_URL: 'postgresql://u:p@ep-other-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require'
    });
    assert.ok(mismatched.warnings.length >= 1, 'cross-endpoint mismatch must produce a sanitized warning');
  });

  test('A3: direct-db createDirectPool configures bounded timeouts and sanitized error handler without network', async () => {
    let capturedOpts = null;
    let errorHandler = null;
    class FakePool {
      constructor(opts) {
        capturedOpts = opts;
      }
      on(ev, fn) {
        if (ev === 'error') errorHandler = fn;
      }
    }

    const { pool, meta } = await directDb.createDirectPool({
      env: {
        APP_ENV: 'staging',
        DIRECT_DATABASE_URL: 'postgresql://u:p@ep-direct.us-east-2.aws.neon.tech/neondb?sslmode=require'
      },
      PoolClass: FakePool,
      silent: true
    });
    assert.ok(pool instanceof FakePool);
    assert.equal(meta.host, 'ep-direct.us-east-2.aws.neon.tech');
    assert.equal(capturedOpts.max, 1);
    assert.equal(capturedOpts.connectionTimeoutMillis, 15000);
    assert.equal(capturedOpts.idleTimeoutMillis, 10000);
    assert.equal(capturedOpts.query_timeout, 65000);
    assert.equal(typeof errorHandler, 'function');
  });

  test('B1: seed-dev enforces fail-closed dev allowlist and rejects remote/Neon destinations', () => {
    assert.equal(seedDev.refuseUnlessSeedEnabled({ SEED_MODE: 'false', APP_ENV: 'development' }), false);
    assert.equal(seedDev.refuseUnlessSeedEnabled({ SEED_MODE: 'true', APP_ENV: '' }), false);
    assert.equal(seedDev.refuseUnlessSeedEnabled({ SEED_MODE: 'true', APP_ENV: 'staging' }), false);
    assert.equal(seedDev.refuseUnlessSeedEnabled({ SEED_MODE: 'true', APP_ENV: 'preview' }), false);
    assert.equal(seedDev.refuseUnlessSeedEnabled({ SEED_MODE: 'true', APP_ENV: 'production' }), false);
    assert.equal(seedDev.refuseUnlessSeedEnabled({ SEED_MODE: 'true', APP_ENV: 'development', VERCEL: '1' }), false);
    assert.equal(seedDev.refuseUnlessSeedEnabled({ SEED_MODE: 'true', APP_ENV: 'development', VERCEL_ENV: 'preview' }), false);
    assert.equal(seedDev.refuseUnlessSeedEnabled({ SEED_MODE: 'true', APP_ENV: 'development', NODE_ENV: 'production' }), false);
    assert.equal(seedDev.refuseUnlessSeedEnabled({ SEED_MODE: 'true', APP_ENV: 'development', NODE_ENV: 'development' }), true);

    assert.throws(
      () =>
        directDb.validateDirectDatabaseUrl(
          'postgresql://u:p@ep-abc.us-east-2.aws.neon.tech/neondb?sslmode=require',
          { APP_ENV: 'development' },
          { requireLocalhost: true }
        ),
      /loopback hosts only/
    );

    const localMeta = directDb.validateDirectDatabaseUrl(
      'postgresql://postgres:localpw@localhost:5432/arkik_dev',
      { APP_ENV: 'development' },
      { requireLocalhost: true }
    );
    assert.equal(localMeta.host, 'localhost');

    // CLI spawn against remote Neon URL must fail before touching network even when SEED_MODE=true & APP_ENV=development
    const cliRes = spawnSync(process.execPath, [path.join(REPO, 'db', 'seed-dev.js')], {
      encoding: 'utf8',
      env: Object.assign({}, process.env, {
        SEED_MODE: 'true',
        APP_ENV: 'development',
        NODE_ENV: 'development',
        VERCEL: '',
        VERCEL_ENV: '',
        DATABASE_URL: '',
        DIRECT_DATABASE_URL: 'postgresql://u:secret999@ep-abc.us-east-2.aws.neon.tech/neondb?sslmode=require'
      })
    });
    assert.notEqual(cliRes.status, 0);
    assert.match(cliRes.stderr, /loopback hosts only/);
    assert.equal(cliRes.stderr.includes('secret999'), false);
  });

  test('B2: migrate ordering validates numeric prefixes & rejects duplicates; bootstrapAdmins enforces 6-char min PIN & warns per missing role', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arkik-mig-'));
    try {
      fs.writeFileSync(path.join(tmpDir, '010_tenth.sql'), '-- x\n');
      fs.writeFileSync(path.join(tmpDir, '002_second.sql'), '-- x\n');
      fs.writeFileSync(path.join(tmpDir, '1000_thousand.sql'), '-- x\n');
      fs.writeFileSync(path.join(tmpDir, '001_first.sql'), '-- x\n');
      assert.deepEqual(migrate.getOrderedMigrationFiles(tmpDir), [
        '001_first.sql',
        '002_second.sql',
        '010_tenth.sql',
        '1000_thousand.sql'
      ]);

      fs.writeFileSync(path.join(tmpDir, '002_duplicate.sql'), '-- dup\n');
      assert.throws(() => migrate.getOrderedMigrationFiles(tmpDir), /Duplicate migration numeric prefix/);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }

    const fakeClient = {
      async query(sql) {
        const s = String(sql).trim();
        if (s === 'BEGIN' || s === 'COMMIT' || s === 'ROLLBACK') return { rows: [], rowCount: 0 };
        if (/SELECT role, pin_hash FROM admin_credentials/i.test(s)) return { rows: [], rowCount: 0 };
        if (/SELECT role FROM admin_credentials/i.test(s)) return { rows: [{ role: 'it' }], rowCount: 1 };
        return { rows: [], rowCount: 0 };
      }
    };

    // Short 5-char PIN rejected before insert
    await assert.rejects(
      () => migrate.bootstrapAdmins(fakeClient, { ADMIN_OWNER_PIN: '12345', ADMIN_IT_PIN: null }),
      /between 6 and 64 characters/
    );

    // Partial role warning emitted when only 'it' exists and 'owner' is missing
    const warns = [];
    const origWarn = console.warn;
    console.warn = (...args) => warns.push(args.join(' '));
    try {
      await migrate.bootstrapAdmins(fakeClient, { ADMIN_IT_PIN: 'valid-it-6' });
    } finally {
      console.warn = origWarn;
    }
    assert.ok(warns.some((w) => w.includes('admin role "owner" is NOT initialized')));

    // manage-admin-pins also enforces >=6 chars & CLI verify rejects missing DIRECT_ADMIN_DATABASE_URL despite DATABASE_URL & DIRECT_DATABASE_URL
    await assert.rejects(() => managePins.generateScryptHash('12345'), /between 6 and 64 characters/);
    const verifyCli = spawnSync(process.execPath, [path.join(REPO, 'db', 'manage-admin-pins.js'), 'verify'], {
      encoding: 'utf8',
      env: Object.assign({}, process.env, {
        DATABASE_URL: 'postgresql://u:p@ep-abc-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require',
        DIRECT_DATABASE_URL: 'postgresql://u:p@ep-abc.us-east-2.aws.neon.tech/neondb?sslmode=require',
        DIRECT_ADMIN_DATABASE_URL: ''
      })
    });
    assert.notEqual(verifyCli.status, 0);
    assert.match(verifyCli.stderr, /DIRECT_ADMIN_DATABASE_URL is not configured/);
  });

  test('B3: migrate.runMigrations holds advisory lock on single max:1 client without self-deadlock and detects checksum drift', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arkik-runmig-'));
    try {
      fs.writeFileSync(path.join(tmpDir, '001_test.sql'), 'CREATE TABLE demo (id int);\n');
      fs.writeFileSync(path.join(tmpDir, '002_idx.sql'), 'CREATE INDEX demo_i ON demo (id);\n');

      const logEvents = [];
      const migrations = new Map();
      const creds = new Map();
      let checkedOut = 0;

      const singlePool = {
        async query() {
          throw new Error('max:1 pool.query() called while single lock client held (self-deadlock!)');
        },
        async connect() {
          assert.equal(checkedOut, 0, 'must never borrow a second client while lock client is held');
          checkedOut += 1;
          return {
            async query(sql, params = []) {
              const q = String(sql).trim();
              logEvents.push(q);
              if (/SELECT version, checksum FROM schema_migrations/i.test(q)) {
                return {
                  rows: Array.from(migrations.entries()).map(([version, checksum]) => ({ version, checksum })),
                  rowCount: migrations.size
                };
              }
              if (/INSERT INTO schema_migrations/i.test(q)) {
                migrations.set(params[0], params[1]);
                return { rows: [], rowCount: 1 };
              }
              if (/SELECT role, pin_hash FROM admin_credentials/i.test(q)) {
                return { rows: Array.from(creds.entries()).map(([role, pin_hash]) => ({ role, pin_hash })), rowCount: 0 };
              }
              if (/INSERT INTO admin_credentials/i.test(q)) {
                creds.set(params[0], params[1]);
                return { rows: [], rowCount: 1 };
              }
              if (/SELECT role FROM admin_credentials/i.test(q)) {
                return { rows: Array.from(creds.keys()).map((role) => ({ role })), rowCount: creds.size };
              }
              return { rows: [], rowCount: 0 };
            },
            release() {
              checkedOut -= 1;
            }
          };
        }
      };

      await migrate.runMigrations({
        pool: singlePool,
        migrationsDir: tmpDir,
        env: { ADMIN_OWNER_PIN: 'owner-pin-6', ADMIN_IT_PIN: 'it-pin-6' }
      });
      assert.equal(checkedOut, 0);
      assert.match(logEvents[0], /^SELECT pg_advisory_lock/i);
      assert.match(logEvents[logEvents.length - 1], /^SELECT pg_advisory_unlock/i);
      assert.ok(logEvents.some((s) => /^SET LOCAL lock_timeout = 5000/.test(s)));
      assert.equal(migrations.size, 2);
      assert.equal(creds.size, 2);

      // Mutating already-applied migration triggers checksum mismatch AND still executes advisory unlock
      logEvents.length = 0;
      fs.writeFileSync(path.join(tmpDir, '001_test.sql'), 'CREATE TABLE demo (id bigint);\n');
      await assert.rejects(
        () =>
          migrate.runMigrations({
            pool: singlePool,
            migrationsDir: tmpDir,
            env: { ADMIN_OWNER_PIN: 'owner-pin-6', ADMIN_IT_PIN: 'it-pin-6' }
          }),
        /Migration checksum mismatch/
      );
      assert.equal(checkedOut, 0);
      assert.match(logEvents[0], /^SELECT pg_advisory_lock/i);
      assert.match(logEvents[logEvents.length - 1], /^SELECT pg_advisory_unlock/i);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('C & D: Runtime SET LOCAL, withReadTransaction, HTTP 504/409/503 error taxonomy, atomic setAvailability/putPricing', async () => {
    const seenSql = [];
    const discardedCalls = [];
    const fakePool = {
      async connect() {
        return {
          async query(sql) {
            seenSql.push(String(sql).trim());
            return { rows: [], rowCount: 0 };
          },
          release(err) {
            discardedCalls.push(err || null);
          }
        };
      }
    };

    await withEnv({ DATABASE_URL: 'postgres://mock:mock@localhost:5432/t' }, async () => {
      db.setPoolFactoryForTests(() => fakePool);
      try {
        await db.withReadTransaction(async (c) => {
          await c.query('SELECT 42');
        });
        assert.equal(seenSql[0], 'BEGIN READ ONLY');
        assert.equal(
          seenSql[1],
          'SET LOCAL statement_timeout = 8000; SET LOCAL lock_timeout = 3000; SET LOCAL idle_in_transaction_session_timeout = 10000;'
        );
        assert.equal(seenSql[2], 'SELECT 42');
        assert.equal(seenSql[3], 'COMMIT');
        assert.equal(discardedCalls[0], null);
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });

    // HTTP timeout/lock classification (never 408)
    const err57014 = Object.assign(new Error('canceling statement due to statement timeout'), { code: '57014' });
    const errReadTimeout = new Error('Query read timeout');
    const err55P03 = Object.assign(new Error('canceling statement due to lock timeout'), { code: '55P03' });
    const errNet = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });

    assert.equal(db.classifyDbError(err57014), 'dependency_timeout');
    assert.equal(db.classifyDbError(errReadTimeout), 'dependency_timeout');
    assert.equal(db.classifyDbError(err55P03), 'resource_busy');
    assert.equal(db.classifyDbError(errNet), 'db_unavailable');
    assert.equal(db.isDbUnavailable(err57014), false);
    assert.equal(db.isDbUnavailable(err55P03), false);

    for (const [errObj, expectedStatus, expectedCode] of [
      [err57014, 504, 'dependency_timeout'],
      [errReadTimeout, 504, 'dependency_timeout'],
      [err55P03, 409, 'resource_busy'],
      [errNet, 503, 'service_unavailable']
    ]) {
      const r = makeRes();
      respond.handleError(r, errObj);
      assert.equal(r.statusCode, expectedStatus);
      assert.notEqual(r.statusCode, 408);
      assert.equal(r.body.error.code, expectedCode);
    }

    // Atomic setAvailability acquires pg_advisory_xact_lock & writes audit inside BEGIN...COMMIT
    const txSql = [];
    const availDate = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
    const txPool = {
      async connect() {
        return {
          async query(sql) {
            txSql.push(String(sql).trim().replace(/\s+/g, ' '));
            return { rows: [{ date: availDate, state: 'disabled', reason: 'mantenimiento' }], rowCount: 1 };
          },
          release() { }
        };
      }
    };
    await withEnv({ DATABASE_URL: 'postgres://mock:mock@localhost:5432/t' }, async () => {
      db.setPoolFactoryForTests(() => txPool);
      try {
        await service.setAvailability({ date: availDate, state: 'disabled', reason: 'mantenimiento' });
        assert.equal(txSql[0], 'BEGIN');
        assert.match(txSql[1], /^SET LOCAL statement_timeout = 8000/);
        assert.match(txSql[2], /^SELECT pg_advisory_xact_lock\(hashtext\('arkik_date'\)/);
        assert.match(txSql[3], /^INSERT INTO availability/);
        assert.match(txSql[4], /^INSERT INTO audit_log/);
        assert.equal(txSql[5], 'COMMIT');
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });

    // putPricing runs atomically in transaction and rolls back config writes if audit insert throws
    const cfgRollbackEvents = [];
    const failAuditPool = {
      async connect() {
        return {
          async query(sql) {
            const s = String(sql).trim();
            if (s === 'BEGIN' || s === 'COMMIT' || s === 'ROLLBACK') cfgRollbackEvents.push(s);
            if (/SELECT namespace, key, value FROM config/i.test(s)) {
              return {
                rows: [
                  { namespace: 'pricing', key: 'catalog', value: [{ id: 1, name: 'Test', price_crc: 100 }] },
                  { namespace: 'geo', key: 'provinces', value: { 'San José': ['Escazú'] } },
                  { namespace: 'geo', key: 'gam', value: ['San José'] }
                ],
                rowCount: 3
              };
            }
            if (/INSERT INTO audit_log/i.test(s)) throw new Error('simulated audit failure');
            return { rows: [], rowCount: 1 };
          },
          release() { }
        };
      }
    };
    service.invalidateConfigCache();
    await withEnv({ DATABASE_URL: 'postgres://mock:mock@localhost:5432/t' }, async () => {
      db.setPoolFactoryForTests(() => failAuditPool);
      try {
        await assert.rejects(
          () => service.putPricing({ rates: { extraHourMultiplier: 0.5, travelSurchargeRate: 0.15 } }, 'owner'),
          /simulated audit failure/
        );
        assert.deepEqual(cfgRollbackEvents, ['BEGIN', 'ROLLBACK']);
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });
  });

  test('E: Auth sliding cookie re-emission, cloud Secure cookie, malformed cookie 401, clientIp proxy & log redaction', async () => {
    const secret = 'e-test-secret-0123456789abcdefghijklmnopqrstuvwxyz';
    const token = auth.newSessionToken();
    const pastLastSeen = new Date(Date.now() - 120000);
    const futureExp = new Date(Date.now() + 10 * 60 * 1000);

    await withEnv({
      DATABASE_URL: 'postgres://mock:mock@localhost:5432/t',
      ADMIN_SESSION_SECRET: secret,
      APP_ENV: 'staging',
      NODE_ENV: 'development',
      VERCEL: '1',
      VERCEL_ENV: 'preview'
    }, async () => {
      const tokenHash = auth.hashToken(token);
      const sessPool = {
        async connect() {
          return {
            async query(sql, params) {
              const s = String(sql).trim();
              if (/FROM admin_sessions/i.test(s) && params[0] === tokenHash) {
                return { rows: [{ role: 'owner', expires_at: futureExp, last_seen_at: pastLastSeen }], rowCount: 1 };
              }
              if (/UPDATE admin_sessions/i.test(s)) {
                return { rows: [{ expires_at: new Date(Date.now() + 900000) }], rowCount: 1 };
              }
              return { rows: [], rowCount: 0 };
            },
            release() { }
          };
        }
      };

      db.setPoolFactoryForTests(() => sessPool);
      try {
        // Cloud Preview/Staging enforces __Host-session + Secure + sliding Set-Cookie refresh on GET /api/admin/session
        const res = makeRes();
        await sessionHandler(
          { method: 'GET', url: '/api/admin/session', headers: { cookie: `__Host-session=${encodeURIComponent(token)}` }, query: {} },
          res
        );
        assert.equal(res.statusCode, 200);
        assert.equal(res.getHeader('cache-control'), 'private, no-store');
        const refreshedCookie = res.getHeader('set-cookie');
        assert.match(refreshedCookie, /^__Host-session=/);
        assert.match(refreshedCookie, /Secure;/);
        assert.match(refreshedCookie, /Max-Age=900/);

        // Malformed %ZZ cookie yields clean 401 instead of URIError 500
        const badCookieRes = makeRes();
        await sessionHandler(
          { method: 'GET', url: '/api/admin/session', headers: { cookie: '__Host-session=%ZZ' }, query: {} },
          badCookieRes
        );
        assert.equal(badCookieRes.statusCode, 401);
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });

    // clientIp ignores X-Forwarded-For under bare NODE_ENV=production unless VERCEL=1 or TRUST_PROXY=true
    await withEnv({ NODE_ENV: 'production', VERCEL: null, VERCEL_ENV: null, TRUST_PROXY: null }, async () => {
      const ip = respond.clientIp({
        headers: { 'x-forwarded-for': '198.51.100.77' },
        socket: { remoteAddress: '10.0.0.5' }
      });
      assert.equal(ip, '10.0.0.5');
    });

    // log & respond redaction for direct_database_url, scrypt$, Bearer, v1. token & cookies
    const red = logMod.sanitize({
      direct_database_url: 'postgresql://u:p@host/db',
      set_cookie: '__Host-session=abc',
      msg: 'err scrypt$16384$8$1$aa$bb Bearer mysecret123 __Host-session=tokval v1.abc.def'
    });
    assert.equal(red.direct_database_url, '[redacted]');
    assert.equal(red.set_cookie, '[redacted]');
    assert.equal(red.msg.includes('scrypt$16384'), false);
    assert.equal(red.msg.includes('mysecret123'), false);
    assert.equal(red.msg.includes('tokval'), false);
    assert.equal(red.msg.includes('v1.abc.def'), false);

    // Runtime isolation: api/ and js/ contain zero references to DIRECT_DATABASE_URL or DIRECT_ADMIN_DATABASE_URL
    for (const rootDir of ['api', 'js']) {
      const stack = [path.join(REPO, rootDir)];
      while (stack.length) {
        const cur = stack.pop();
        for (const ent of fs.readdirSync(cur, { withFileTypes: true })) {
          const full = path.join(cur, ent.name);
          if (ent.isDirectory()) stack.push(full);
          else if (ent.isFile() && ent.name.endsWith('.js')) {
            const src = fs.readFileSync(full, 'utf8');
            assert.equal(/\bDIRECT_DATABASE_URL\b/.test(src), false, `forbidden DIRECT_DATABASE_URL in ${full}`);
            assert.equal(
              /\bDIRECT_ADMIN_DATABASE_URL\b/.test(src),
              false,
              `forbidden DIRECT_ADMIN_DATABASE_URL in ${full}`
            );
          }
        }
      }
    }
    const vercelIgnoreLines = fs
      .readFileSync(path.join(REPO, '.vercelignore'), 'utf8')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'));
    assert.ok(vercelIgnoreLines.includes('db'), '.vercelignore must exclude db directory');
    assert.ok(vercelIgnoreLines.includes('.env.local'), '.vercelignore must exclude .env.local');
  });

  test('F1: Three-way Direct identity separation (DIRECT_DATABASE_URL vs DIRECT_ADMIN_DATABASE_URL vs DATABASE_URL) & single-segment DB path guard', async () => {
    const pw = 'pw_three_way_987';
    // 1. Zero cross-fallback between DIRECT_DATABASE_URL, DIRECT_ADMIN_DATABASE_URL, and DATABASE_URL
    assert.throws(
      () =>
        directDb.resolveDirectConnectionConfig(
          {
            DATABASE_URL: `postgresql://arkik_app:${pw}@ep-abc-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require`,
            DIRECT_ADMIN_DATABASE_URL: `postgresql://arkik_admin:${pw}@ep-abc.us-east-2.aws.neon.tech/neondb?sslmode=require`
          },
          { envVarName: 'DIRECT_DATABASE_URL' }
        ),
      /DIRECT_DATABASE_URL is not configured/
    );

    assert.throws(
      () =>
        directDb.resolveDirectConnectionConfig(
          {
            DATABASE_URL: `postgresql://arkik_app:${pw}@ep-abc-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require`,
            DIRECT_DATABASE_URL: `postgresql://arkik_migrator:${pw}@ep-abc.us-east-2.aws.neon.tech/neondb?sslmode=require`
          },
          { envVarName: 'DIRECT_ADMIN_DATABASE_URL' }
        ),
      /DIRECT_ADMIN_DATABASE_URL is not configured/
    );

    assert.throws(
      () =>
        directDb.resolveDirectConnectionConfig(
          { DIRECT_DATABASE_URL: 'postgresql://u:p@ep-abc.us-east-2.aws.neon.tech/neondb?sslmode=require' },
          { envVarName: 'UNKNOWN_DB_VAR' }
        ),
      /Unsupported direct env var/
    );

    // 2. managePins.createPool strictly requires DIRECT_ADMIN_DATABASE_URL and rejects -pooler without network
    await assert.rejects(
      managePins.createPool({
        env: {
          DATABASE_URL: `postgresql://arkik_app:${pw}@ep-abc-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require`,
          DIRECT_DATABASE_URL: `postgresql://arkik_migrator:${pw}@ep-abc.us-east-2.aws.neon.tech/neondb?sslmode=require`
        },
        silent: true
      }),
      /DIRECT_ADMIN_DATABASE_URL is not configured/
    );

    class FakeAdminPool {
      constructor(opts) {
        this.opts = opts;
      }
      on() { }
    }
    const adminPool = await managePins.createPool({
      env: {
        APP_ENV: 'staging',
        DIRECT_ADMIN_DATABASE_URL: `postgresql://arkik_admin:${pw}@ep-direct.us-east-2.aws.neon.tech/neondb?sslmode=require`,
        DIRECT_DATABASE_URL: `postgresql://arkik_migrator:other@ep-other.us-east-2.aws.neon.tech/neondb?sslmode=require`
      },
      PoolClass: FakeAdminPool,
      silent: true
    });
    assert.ok(adminPool instanceof FakeAdminPool);
    assert.ok(adminPool.opts.connectionString.includes('arkik_admin:'), 'managePins must bind DIRECT_ADMIN_DATABASE_URL');

    // CLI spawn checks (DIRECT_ADMIN_DATABASE_URL="" shadows .env.local so neither file nor Neon is touched)
    const verifyPoolerRes = spawnSync(process.execPath, [path.join(REPO, 'db', 'manage-admin-pins.js'), 'verify'], {
      encoding: 'utf8',
      env: Object.assign({}, process.env, {
        DIRECT_ADMIN_DATABASE_URL: `postgresql://arkik_admin:${pw}@ep-abc-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require`,
        DIRECT_DATABASE_URL: `postgresql://arkik_migrator:${pw}@ep-abc.us-east-2.aws.neon.tech/neondb?sslmode=require`
      })
    });
    assert.notEqual(verifyPoolerRes.status, 0);
    assert.match(verifyPoolerRes.stderr, /DIRECT_ADMIN_DATABASE_URL must NOT use a PgBouncer "-pooler" endpoint/);
    assert.equal(verifyPoolerRes.stderr.includes(pw), false);

    const migrateMissingRes = spawnSync(process.execPath, [path.join(REPO, 'db', 'migrate.js')], {
      encoding: 'utf8',
      env: Object.assign({}, process.env, {
        DIRECT_DATABASE_URL: '',
        DIRECT_ADMIN_DATABASE_URL: `postgresql://arkik_admin:${pw}@ep-abc.us-east-2.aws.neon.tech/neondb?sslmode=require`
      })
    });
    assert.notEqual(migrateMissingRes.status, 0);
    assert.match(migrateMissingRes.stderr, /DIRECT_DATABASE_URL is not configured/);
    assert.equal(migrateMissingRes.stderr.includes(pw), false);

    // 3. Reject ambiguous / multi-segment database paths (AUD-05) without exposing password
    for (const badPathUrl of [
      `postgresql://arkik_migrator:${pw}@ep-abc.us-east-2.aws.neon.tech/neondb/extra?sslmode=require`,
      `postgresql://arkik_migrator:${pw}@ep-abc.us-east-2.aws.neon.tech/neondb/?sslmode=require`,
      `postgresql://arkik_migrator:${pw}@ep-abc.us-east-2.aws.neon.tech/neondb%2Fextra?sslmode=require`,
      `postgresql://arkik_migrator:${pw}@ep-abc.us-east-2.aws.neon.tech/bad%20db?sslmode=require`
    ]) {
      let caught = null;
      try {
        directDb.validateDirectDatabaseUrl(badPathUrl, { APP_ENV: 'staging' }, { envVarName: 'DIRECT_DATABASE_URL' });
      } catch (err) {
        caught = err;
      }
      assert.ok(caught, `expected ambiguous path rejection for URL`);
      assert.equal(caught.message.includes(pw), false);
    }
  });

  test('F2: AUD-05 comprehensive secret redaction in log.js, respond.js & direct-db.js without over-redacting telemetry', () => {
    const sanitized = logMod.sanitize({
      newPassword: 'secret_new_password_001',
      admin_owner_pin: '887766',
      admin_it_pin: '554433',
      sessionToken: 'tok_sensitive_002',
      DIRECT_ADMIN_DATABASE_URL: 'postgresql://arkik_admin:pw_secret_003@ep-direct.neon.tech/neondb',
      nested: {
        clientSecret: 'sec_004',
        cookieHeader: 'arkik_session=ck_005',
        inlineToken: 'should-redact-by-key',
        inlineVoucher: 'upload failed on data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA rest',
        detail: 'bad v1.payload999.sig999 token',
        inlinePinAssign: 'failed admin_owner_pin=998877 newPassword="npw_777"',
        bearerMsg: 'Authorization Bearer bearer_tok_666 expired',
        hashMsg: 'corrupt scrypt$16384$8$1$aabbcc$ddeeff in row'
      },
      // Non-sensitive operational telemetry must remain untouched
      ok: true,
      kind: 'internal',
      role: 'owner',
      action: 'ADMIN_LOGIN',
      status: 'confirmada',
      total: 125000,
      lock_level: 0,
      bookingCode: 'ARK-0123',
      idempotencyKey: 'idem-key-123',
      retryAfterMs: 30000
    });

    assert.equal(sanitized.newPassword, '[redacted]');
    assert.equal(sanitized.admin_owner_pin, '[redacted]');
    assert.equal(sanitized.admin_it_pin, '[redacted]');
    assert.equal(sanitized.sessionToken, '[redacted]');
    assert.equal(sanitized.DIRECT_ADMIN_DATABASE_URL, '[redacted]');
    assert.equal(sanitized.nested.clientSecret, '[redacted]');
    assert.equal(sanitized.nested.cookieHeader, '[redacted]');
    assert.equal(sanitized.nested.inlineToken, '[redacted]');
    assert.equal(sanitized.nested.inlineVoucher.includes('iVBORw0KGgo'), false);
    assert.match(sanitized.nested.inlineVoucher, /\[redacted-voucher\]/);
    assert.equal(sanitized.nested.detail.includes('payload999'), false);
    assert.match(sanitized.nested.detail, /\[redacted-token\]/);
    assert.equal(sanitized.nested.inlinePinAssign.includes('998877'), false);
    assert.equal(sanitized.nested.inlinePinAssign.includes('npw_777'), false);
    assert.equal(sanitized.nested.bearerMsg.includes('bearer_tok_666'), false);
    assert.equal(sanitized.nested.hashMsg.includes('aabbcc'), false);

    assert.equal(sanitized.ok, true);
    assert.equal(sanitized.kind, 'internal');
    assert.equal(sanitized.role, 'owner');
    assert.equal(sanitized.action, 'ADMIN_LOGIN');
    assert.equal(sanitized.status, 'confirmada');
    assert.equal(sanitized.total, 125000);
    assert.equal(sanitized.lock_level, 0);
    assert.equal(sanitized.bookingCode, 'ARK-0123');
    assert.equal(sanitized.idempotencyKey, 'idem-key-123');
    assert.equal(sanitized.retryAfterMs, 30000);

    // respond.handleError redacts secrets cleanly in logs and returns opaque 500 JSON
    const logged = [];
    const errRes = makeRes();
    respond.handleError(
      errRes,
      new Error(
        'boom postgres://u:pw_err@h/db scrypt$16384$8$1$s1$h1 Bearer tok_err __Host-session=cook_err v1.a1.b2 data:image/jpeg;base64,/9j/4AAQ newPassword=npw_err'
      ),
      (tag, msg, meta) => logged.push({ tag, msg, meta })
    );
    assert.equal(errRes.statusCode, 500);
    assert.equal(errRes.body.error.code, 'internal_error');
    const serializedLog = JSON.stringify(logged);
    for (const secretFragment of ['pw_err', 's1$h1', 'tok_err', 'cook_err', 'v1.a1.b2', '/9j/4AAQ', 'npw_err']) {
      assert.equal(serializedLog.includes(secretFragment), false, `respond log leaked ${secretFragment}`);
      assert.equal(JSON.stringify(errRes.body).includes(secretFragment), false, `HTTP body leaked ${secretFragment}`);
    }

    // directDb.safeError redacts tokens, data URLs & inline secret assignments too
    const safeDir = directDb.safeError(
      new Error('fail postgresql://arkik_admin:dirpw@ep/neondb v1.tok.sig data:image/png;base64,AAAA newPassword=dirnpw')
    );
    for (const leak of ['dirpw', 'v1.tok.sig', 'AAAA', 'dirnpw']) {
      assert.equal(safeDir.includes(leak), false, `directDb.safeError leaked ${leak}`);
    }
  });

  test('F3: AUD-06 GET /api/ready returns 503 unavailable when PostgreSQL raises 57014 statement_timeout', async () => {
    let released = false;
    let discarded = false;
    const timeoutPool = {
      async connect() {
        return {
          async query() {
            const err = new Error('canceling statement due to statement timeout');
            err.code = '57014';
            throw err;
          },
          release(destroy) {
            released = true;
            if (destroy) discarded = true;
          }
        };
      }
    };

    await withEnv({ DATABASE_URL: 'postgres://mock:mock@localhost:5432/t' }, async () => {
      db.setPoolFactoryForTests(() => timeoutPool);
      try {
        const res = makeRes();
        await readyHandler({ method: 'GET', url: '/api/ready', headers: {} }, res);
        assert.equal(res.statusCode, 503);
        assert.equal(res.getHeader('cache-control'), 'no-store');
        assert.equal(res.body.success, false);
        assert.equal(res.body.ready, false);
        assert.equal(res.body.database, 'unavailable');
        assert.equal(released, true);
        assert.equal(discarded, false);
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });
  });

  test('F4: AUD-06 cookie & env matrix across Vercel HTTPS, local HTTP dev, and local Staging vs Preview', async () => {
    const secret = 'f4-matrix-secret-0123456789abcdefghijklmnopqrstuvwxyz';
    const ownerPin = 'OwnerPin#2026!';
    const ownerHash = auth.hashPin(ownerPin);

    function createLoginPool() {
      return {
        async connect() {
          return {
            async query(sql) {
              const s = String(sql).trim();
              if (/FROM admin_credentials/i.test(s)) {
                return {
                  rows: [
                    {
                      role: 'owner',
                      pin_hash: ownerHash,
                      failed_attempts: 0,
                      lock_level: 0,
                      locked_until: null,
                      updated_at: new Date()
                    }
                  ],
                  rowCount: 1
                };
              }
              if (/INTO rate_limits/i.test(s)) {
                return { rows: [{ count: 1, window_start: new Date() }], rowCount: 1 };
              }
              if (/UPDATE admin_credentials/i.test(s) || /DELETE FROM rate_limits/i.test(s) || /INSERT INTO admin_sessions/i.test(s) || /INSERT INTO audit_log/i.test(s)) {
                return { rows: [], rowCount: 1 };
              }
              return { rows: [], rowCount: 0 };
            },
            release() { }
          };
        }
      };
    }

    // 1. Vercel Preview (cloud HTTPS): __Host-session; Secure; HttpOnly; SameSite=Strict
    await withEnv(
      {
        DATABASE_URL: 'postgres://mock:mock@ep-abc-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require',
        ADMIN_SESSION_SECRET: secret,
        APP_ENV: 'staging',
        NODE_ENV: 'development',
        VERCEL: '1',
        VERCEL_ENV: 'preview'
      },
      async () => {
        db.setPoolFactoryForTests(createLoginPool);
        try {
          const res = makeRes();
          await loginHandler(
            { method: 'POST', url: '/api/admin/login', headers: { origin: 'https://arkik-preview.vercel.app' }, body: { role: 'owner', pin: ownerPin } },
            res
          );
          assert.equal(res.statusCode, 200);
          const cookie = res.getHeader('set-cookie');
          assert.match(cookie, /^__Host-session=/);
          assert.match(cookie, /HttpOnly;/);
          assert.match(cookie, /Secure;/);
          assert.match(cookie, /SameSite=Strict;/);
          assert.match(cookie, /Path=\/;/);
          assert.match(auth.clearSessionCookie(), /^__Host-session=; HttpOnly; Secure; SameSite=Strict; Path=\/; Max-Age=0$/);
        } finally {
          db.setPoolFactoryForTests(null);
        }
      }
    );

    // 2. Vercel Production (HTTPS): __Host-session; Secure
    await withEnv(
      {
        DATABASE_URL: 'postgres://mock:mock@ep-prod-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require',
        ADMIN_SESSION_SECRET: secret,
        APP_ENV: 'production',
        NODE_ENV: 'production',
        VERCEL: '1',
        VERCEL_ENV: 'production'
      },
      async () => {
        db.setPoolFactoryForTests(createLoginPool);
        try {
          const res = makeRes();
          await loginHandler(
            { method: 'POST', url: '/api/admin/login', headers: { origin: 'https://arkikproductions.com' }, body: { role: 'owner', pin: ownerPin } },
            res
          );
          assert.equal(res.statusCode, 200);
          const cookie = res.getHeader('set-cookie');
          assert.match(cookie, /^__Host-session=/);
          assert.match(cookie, /Secure;/);
        } finally {
          db.setPoolFactoryForTests(null);
        }
      }
    );

    // 3. Local HTTP dev (explicit APP_ENV=development, no DB/VERCEL): arkik_session without Secure
    await withEnv(
      {
        DATABASE_URL: null,
        ADMIN_SESSION_SECRET: null,
        ADMIN_OWNER_PIN: ownerPin,
        APP_ENV: 'development',
        NODE_ENV: 'development',
        VERCEL: null,
        VERCEL_ENV: null
      },
      async () => {
        assert.equal(config.isExplicitLocalDev, true);
        const res = makeRes();
        await loginHandler(
          { method: 'POST', url: '/api/admin/login', headers: { origin: 'http://localhost:3000' }, body: { role: 'owner', pin: ownerPin } },
          res
        );
        assert.equal(res.statusCode, 200);
        const cookie = res.getHeader('set-cookie');
        assert.match(cookie, /^arkik_session=/);
        assert.match(cookie, /HttpOnly;/);
        assert.equal(/\bSecure;/.test(cookie), false);
      }
    );

    // 4. Local Staging (`APP_ENV=staging`, `NODE_ENV=development`, no VERCEL/VERCEL_ENV):
    // preserves `arkik_session` without Secure so local http://localhost staging smoke tests work,
    // while keeping strict Staging security (isExplicitLocalDev=false, ADMIN_SESSION_SECRET mandatory, v1. rejected).
    await withEnv(
      {
        DATABASE_URL: 'postgres://mock:mock@localhost:5432/t',
        ADMIN_SESSION_SECRET: secret,
        APP_ENV: 'staging',
        NODE_ENV: 'development',
        VERCEL: null,
        VERCEL_ENV: null
      },
      async () => {
        assert.equal(config.isStagingOrPreview, true);
        assert.equal(config.isCloud, false);
        assert.equal(config.isProduction, false);
        assert.equal(config.isExplicitLocalDev, false);

        const localV1Token = auth.createStatelessToken('owner', Date.now() + 60000);
        await assert.rejects(
          () => auth.requireAdmin({ headers: { cookie: `arkik_session=${encodeURIComponent(localV1Token)}` } }),
          { code: 'unauthorized', status: 401 }
        );

        db.setPoolFactoryForTests(createLoginPool);
        try {
          // Without SECURE_COOKIES, staging outside Vercel must NOT emit an
          // insecure session cookie (fail-closed).
          const res = makeRes();
          await loginHandler(
            { method: 'POST', url: '/api/admin/login', headers: { origin: 'http://localhost:3000' }, body: { role: 'owner', pin: ownerPin } },
            res
          );
          assert.equal(res.statusCode, 503);
        } finally {
          db.setPoolFactoryForTests(null);
        }

        // With SECURE_COOKIES=1, staging outside Vercel emits __Host-session + Secure.
        await withEnv({ SECURE_COOKIES: '1' }, async () => {
          db.setPoolFactoryForTests(createLoginPool);
          try {
            const res = makeRes();
            await loginHandler(
              { method: 'POST', url: '/api/admin/login', headers: { origin: 'http://localhost:3000' }, body: { role: 'owner', pin: ownerPin } },
              res
            );
            assert.equal(res.statusCode, 200);
            const cookie = res.getHeader('set-cookie');
            assert.match(cookie, /^__Host-session=/);
            assert.match(cookie, /Secure;/);
          } finally {
            db.setPoolFactoryForTests(null);
          }
        });
      }
    );
  });
});

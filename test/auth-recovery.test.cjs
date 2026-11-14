'use strict';
// Comprehensive authentication recovery & security regression test suite.
// Covers all 20 P0 recovery scenarios, local end-to-end HTTP integration,
// migration credential seeding, and frontend SecurityModule error discrimination.

const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test, describe } = require('node:test');

const REPO = path.resolve(__dirname, '..');

function load(rel) {
  return require(path.join(REPO, rel));
}

const config = load('api/_lib/config.js');
const db = load('api/_lib/db.js');
const auth = load('api/_lib/auth.js');
const migrate = load('db/migrate.js');

const loginHandler = load('api/admin/login.js');
const sessionHandler = load('api/admin/session.js');
const dashboardHandler = load('api/admin/dashboard.js');
const pricingAdminHandler = load('api/admin/pricing.js');
const availabilityHandler = load('api/availability/index.js');
const logoutHandler = load('api/admin/logout.js');

function buildConfigRows() {
  const d = config.DEFAULTS;
  return [
    {
      namespace: 'pricing',
      key: 'catalog',
      value: [
        { id: 1, name: 'Banda Completa', category: 'Música en Vivo', price_crc: 650000 }
      ]
    },
    { namespace: 'pricing', key: 'overrides', value: { services: {}, extras: {} } },
    { namespace: 'pricing', key: 'rates', value: d.rates },
    { namespace: 'geo', key: 'provinces', value: { 'San José': ['Central (San José)'] } },
    { namespace: 'geo', key: 'gam', value: ['San José'] },
    { namespace: 'geo', key: 'nonGamExceptions', value: {} },
    { namespace: 'logistics', key: 'limits', value: d.limits },
    { namespace: 'logistics', key: 'defaultStatus', value: d.defaultStatus },
    { namespace: 'sinpe', key: 'config', value: d.sinpe }
  ];
}

function createInMemoryDb(seedCredentials) {
  const state = {
    credentials: new Map(seedCredentials || []),
    sessions: new Map(),
    rateLimits: new Map(),
    auditLog: [],
    configRows: buildConfigRows(),
    availability: new Map(),
    bookings: [],
    nowMs: () => Date.now()
  };

  async function runQuery(sql, params = []) {
    const q = String(sql).trim().replace(/\s+/g, ' ');

    if (/^SELECT 1$/i.test(q)) {
      return { rows: [{ '?column?': 1 }], rowCount: 1 };
    }

    if (/^(BEGIN|COMMIT|ROLLBACK|SELECT pg_advisory_xact_lock)/i.test(q)) {
      return { rows: [], rowCount: 0 };
    }

    if (/SELECT role(?:, pin_hash)? FROM admin_credentials/i.test(q)) {
      const rows = Array.from(state.credentials.entries())
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([role, rec]) => ({ role, pin_hash: rec.pin_hash }));
      return { rows, rowCount: rows.length };
    }

    if (/SELECT role, pin_hash, failed_attempts, lock_level, locked_until FROM admin_credentials WHERE role = \$1/i.test(q)) {
      const row = state.credentials.get(params[0]);
      return { rows: row ? [Object.assign({}, row)] : [], rowCount: row ? 1 : 0 };
    }

    if (/INSERT INTO admin_credentials \(role, pin_hash\) VALUES \(\$1, \$2\)/i.test(q)) {
      const [role, pinHash] = params;
      if (state.credentials.has(role)) return { rows: [], rowCount: 0 };
      state.credentials.set(role, {
        role,
        pin_hash: pinHash,
        failed_attempts: 0,
        lock_level: 0,
        locked_until: null
      });
      return { rows: [], rowCount: 1 };
    }

    if (/UPDATE admin_credentials SET failed_attempts = \$2, lock_level = \$3, locked_until = \$4/i.test(q)) {
      const row = state.credentials.get(params[0]);
      if (row) {
        row.failed_attempts = params[1];
        row.lock_level = params[2];
        row.locked_until = params[3];
      }
      return { rows: [], rowCount: row ? 1 : 0 };
    }

    if (/UPDATE admin_credentials SET failed_attempts = 0, lock_level = 0, locked_until = NULL/i.test(q)) {
      const row = state.credentials.get(params[0]);
      if (row) {
        row.failed_attempts = 0;
        row.lock_level = 0;
        row.locked_until = null;
      }
      return { rows: [], rowCount: row ? 1 : 0 };
    }

    if (/INSERT INTO rate_limits \(bucket, window_start, count\)/i.test(q)) {
      const [bucket, nowDate, cutoffDate] = params;
      const nowMs = nowDate.getTime();
      const cutoffMs = cutoffDate.getTime();
      const existing = state.rateLimits.get(bucket);
      if (!existing || existing.windowStart <= cutoffMs) {
        const entry = { count: 1, windowStart: nowMs };
        state.rateLimits.set(bucket, entry);
        return { rows: [{ count: 1, window_start: new Date(nowMs) }], rowCount: 1 };
      }
      existing.count += 1;
      return { rows: [{ count: existing.count, window_start: new Date(existing.windowStart) }], rowCount: 1 };
    }

    if (/INSERT INTO admin_sessions \(token_hash, role, expires_at, last_seen_at\)/i.test(q)) {
      const [tokenHash, role, expiresAt] = params;
      const now = new Date(state.nowMs());
      state.sessions.set(tokenHash, {
        token_hash: tokenHash,
        role,
        expires_at: new Date(expiresAt),
        last_seen_at: now
      });
      return { rows: [], rowCount: 1 };
    }

    if (/SELECT role, expires_at, last_seen_at FROM admin_sessions WHERE token_hash = \$1 AND expires_at > now\(\)/i.test(q)) {
      const sess = state.sessions.get(params[0]);
      if (!sess || sess.expires_at.getTime() <= state.nowMs()) {
        return { rows: [], rowCount: 0 };
      }
      return {
        rows: [{
          role: sess.role,
          expires_at: sess.expires_at,
          last_seen_at: sess.last_seen_at
        }],
        rowCount: 1
      };
    }

    if (/UPDATE admin_sessions SET expires_at = \$2, last_seen_at = \$3 WHERE token_hash = \$1 RETURNING expires_at/i.test(q)) {
      const sess = state.sessions.get(params[0]);
      if (!sess) return { rows: [], rowCount: 0 };
      sess.expires_at = new Date(params[1]);
      sess.last_seen_at = new Date(params[2]);
      return { rows: [{ expires_at: sess.expires_at }], rowCount: 1 };
    }

    if (/DELETE FROM admin_sessions WHERE token_hash = \$1 RETURNING role/i.test(q)) {
      const sess = state.sessions.get(params[0]);
      if (!sess) return { rows: [], rowCount: 0 };
      state.sessions.delete(params[0]);
      return { rows: [{ role: sess.role }], rowCount: 1 };
    }

    if (/INSERT INTO audit_log/i.test(q)) {
      state.auditLog.push({
        action: params[0],
        entity_type: params[1],
        entity_id: params[2],
        actor: params[3],
        metadata: params[4] ? JSON.parse(params[4]) : null,
        created_at: new Date(state.nowMs()).toISOString()
      });
      return { rows: [], rowCount: 1 };
    }

    if (/SELECT action, entity_type, entity_id, actor, metadata, created_at FROM audit_log/i.test(q)) {
      const limit = Number(params[0] || 50);
      const rows = state.auditLog.slice().reverse().slice(0, limit);
      return { rows, rowCount: rows.length };
    }

    if (/SELECT namespace, key, value FROM config/i.test(q)) {
      return { rows: state.configRows.slice(), rowCount: state.configRows.length };
    }

    if (/INSERT INTO config/i.test(q)) {
      const [ns, key, valJson] = params;
      const val = JSON.parse(valJson);
      const idx = state.configRows.findIndex((r) => r.namespace === ns && r.key === key);
      if (idx >= 0) state.configRows[idx].value = val;
      else state.configRows.push({ namespace: ns, key, value: val });
      return { rows: [], rowCount: 1 };
    }

    if (/SELECT count\(\*\)::int AS total FROM bookings/i.test(q)) {
      return { rows: [{ total: state.bookings.length }], rowCount: 1 };
    }

    if (/SELECT 1 FROM bookings WHERE code = \$1/i.test(q)) {
      const found = state.bookings.some((b) => b.code === params[0]);
      return { rows: found ? [{ '?column?': 1 }] : [], rowCount: found ? 1 : 0 };
    }

    if (/FROM idempotency_keys ik/i.test(q)) {
      if (!state.idempotency) state.idempotency = new Map();
      const hit = state.idempotency.get(params[0]);
      return { rows: hit ? [Object.assign({}, hit)] : [], rowCount: hit ? 1 : 0 };
    }

    if (/INSERT INTO idempotency_keys/i.test(q)) {
      if (!state.idempotency) state.idempotency = new Map();
      const booking = state.bookings.find((b) => b.id === params[1]);
      if (booking) state.idempotency.set(params[0], booking);
      return { rows: [], rowCount: 1 };
    }

    if (/SELECT selected_time FROM bookings/i.test(q)) {
      const times = state.bookings
        .filter((b) => b.selected_date === params[0] && b.status !== 'cancelada')
        .map((b) => ({ selected_time: b.selected_time }));
      return { rows: times, rowCount: times.length };
    }

    if (/INSERT INTO bookings/i.test(q)) {
      const now = new Date(state.nowMs()).toISOString();
      const row = {
        id: `uuid_${state.bookings.length + 1}`,
        code: params[0],
        status: params[1],
        client_name: params[2],
        client_phone: params[3],
        client_email: params[4],
        event_type: params[5],
        service_id: params[6],
        service_name: params[7],
        setup_display: params[8],
        teardown_display: params[9],
        selected_date: params[10],
        selected_time: params[11],
        province: params[12],
        canton: params[13],
        address: params[14],
        subtotal: params[15],
        travel_surcharge: params[16],
        grand_total: params[17],
        deposit_amount: params[18],
        remaining_balance: params[19],
        sinpe_reference: params[20],
        extras: JSON.parse(params[21]),
        voucher_image: params[22],
        voucher_mime: params[23],
        voucher_bytes: params[24],
        has_voucher: Boolean(params[22]),
        idempotency_key: params[25],
        created_at: now,
        updated_at: now,
        confirmed_at: null,
        cancelled_at: null,
        completed_at: null
      };
      state.bookings.push(row);
      return { rows: [Object.assign({}, row)], rowCount: 1 };
    }

    if (/FROM bookings WHERE code = \$1/i.test(q) && /^SELECT/i.test(q)) {
      const row = state.bookings.find((b) => b.code === params[0]);
      return { rows: row ? [Object.assign({}, row)] : [], rowCount: row ? 1 : 0 };
    }

    if (/^UPDATE bookings SET status = \$2/i.test(q)) {
      const row = state.bookings.find((b) => b.code === params[0]);
      if (!row) return { rows: [], rowCount: 0 };
      const now = new Date(state.nowMs()).toISOString();
      row.status = params[1];
      row.updated_at = now;
      if (params[1] === 'confirmada') row.confirmed_at = now;
      if (params[1] === 'cancelada') row.cancelled_at = now;
      if (params[1] === 'pendiente') { row.confirmed_at = null; row.cancelled_at = null; row.completed_at = null; }
      return { rows: [Object.assign({}, row)], rowCount: 1 };
    }

    if (/FROM bookings WHERE .* ORDER BY created_at DESC/i.test(q)) {
      const rows = state.bookings.slice().reverse().map((b) => Object.assign({}, b));
      return { rows, rowCount: rows.length };
    }

    if (/count\(\*\)::int AS total, count\(\*\) FILTER/i.test(q)) {
      const c = { total: state.bookings.length, pendiente: 0, confirmada: 0, realizada: 0, cancelada: 0 };
      for (const b of state.bookings) c[b.status] = (c[b.status] || 0) + 1;
      return { rows: [c], rowCount: 1 };
    }

    if (/COALESCE\(sum\(grand_total\)/i.test(q)) {
      let gross = 0; let deposits = 0; let balances = 0;
      for (const b of state.bookings) {
        if (b.status !== 'cancelada') {
          gross += Number(b.grand_total || 0);
          deposits += Number(b.deposit_amount || 0);
          balances += Number(b.remaining_balance || 0);
        }
      }
      return { rows: [{ gross, deposits, balances }], rowCount: 1 };
    }

    if (/SELECT province, count\(\*\)::int AS count FROM bookings/i.test(q)) {
      return { rows: [], rowCount: 0 };
    }

    if (/SELECT to_char\(selected_date, 'YYYY-MM-DD'\) AS date/i.test(q)) {
      return { rows: [], rowCount: 0 };
    }

    if (/SELECT count\(\*\)::int AS blocked_count FROM availability/i.test(q)) {
      return { rows: [{ blocked_count: state.availability.size }], rowCount: 1 };
    }

    if (/SELECT count\(\*\)::int AS pending FROM bookings/i.test(q)) {
      const pending = state.bookings.filter((b) => b.status === 'pendiente').length;
      return { rows: [{ pending }], rowCount: 1 };
    }

    if (/SELECT to_char\(date, 'YYYY-MM-DD'\) AS date, state, reason FROM availability WHERE date = \$1/i.test(q)) {
      const row = state.availability.get(params[0]);
      return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
    }

    if (/INSERT INTO availability/i.test(q)) {
      const entry = { date: params[0], state: params[1], reason: params[2] || null };
      state.availability.set(params[0], entry);
      return { rows: [entry], rowCount: 1 };
    }

    if (/DELETE FROM availability WHERE date = \$1/i.test(q)) {
      const existed = state.availability.delete(params[0]);
      return { rows: [], rowCount: existed ? 1 : 0 };
    }

    if (/SELECT to_char\(date, 'YYYY-MM-DD'\) AS date, state, reason FROM availability/i.test(q)) {
      const rows = Array.from(state.availability.values());
      return { rows, rowCount: rows.length };
    }

    throw new Error(`Unhandled mock SQL query: ${q}`);
  }

  const fakePool = {
    query: runQuery,
    connect: async () => ({
      query: runQuery,
      release: () => {}
    }),
    end: async () => {}
  };

  return { state, fakePool };
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
    end(payload) {
      if (payload !== undefined && this.body === undefined) {
        try { this.body = JSON.parse(String(payload)); } catch { this.body = String(payload); }
      }
      this.headersSent = true;
      return this;
    }
  };
}

function makeReq(method, url, opts = {}) {
  return {
    method,
    url,
    headers: Object.assign({}, opts.headers || {}),
    query: Object.assign({}, opts.query || {}),
    body: opts.body,
    socket: { remoteAddress: opts.ip || '203.0.113.10' }
  };
}

function extractCookiePair(setCookieHeader) {
  const raw = Array.isArray(setCookieHeader) ? setCookieHeader[0] : setCookieHeader;
  assert.ok(raw, 'Set-Cookie header expected');
  return raw.split(';')[0];
}

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

describe('Auth Recovery Suite (Backend, Migration, Session, RBAC, HTTP E2E, Frontend)', () => {
  const OWNER_PIN = '849201';
  const IT_PIN = 'it-42#ark';

  test('1-4 & 10: Owner & IT valid/invalid PIN authentication + hashed session storage + no secrets leaked', async () => {
    const ownerHash = auth.hashPin(OWNER_PIN);
    const itHash = auth.hashPin(IT_PIN);
    const { state, fakePool } = createInMemoryDb([
      ['owner', { role: 'owner', pin_hash: ownerHash, failed_attempts: 0, lock_level: 0, locked_until: null }],
      ['it', { role: 'it', pin_hash: itHash, failed_attempts: 0, lock_level: 0, locked_until: null }]
    ]);

    await withEnv({
      DATABASE_URL: 'postgres://mock:mock@localhost:5432/arkik',
      ADMIN_SESSION_SECRET: 'test-secret-0123456789abcdef',
      NODE_ENV: 'test',
      ADMIN_OWNER_PIN: null,
      ADMIN_IT_PIN: null
    }, async () => {
      db.setPoolFactoryForTests(() => fakePool);
      try {
        // 1. Valid Owner login
        const ownerRes = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: OWNER_PIN }, ip: '198.51.100.1' }), ownerRes);
        assert.equal(ownerRes.statusCode, 200);
        assert.equal(ownerRes.body.success, true);
        assert.equal(ownerRes.body.data.role, 'owner');
        assert.equal('token' in ownerRes.body.data, false, 'session token must not be exposed in body');
        const ownerSetCookie = ownerRes.getHeader('set-cookie');
        assert.match(ownerSetCookie, /^arkik_session=/);
        assert.match(ownerSetCookie, /HttpOnly/);
        assert.match(ownerSetCookie, /SameSite=Strict/);

        // 10. Session stored strictly as HMAC hash, never raw token
        const cookieVal = decodeURIComponent(extractCookiePair(ownerSetCookie).split('=')[1]);
        assert.equal(state.sessions.has(cookieVal), false, 'raw token must never be stored in admin_sessions');
        assert.equal(state.sessions.has(auth.hashToken(cookieVal)), true, 'HMAC token hash must be persisted');

        // 2. Valid IT login (preserves non-digit characters)
        const itRes = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'it', pin: IT_PIN }, ip: '198.51.100.2' }), itRes);
        assert.equal(itRes.statusCode, 200);
        assert.equal(itRes.body.data.role, 'it');

        // 3. Invalid Owner PIN
        const badOwner = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: '000000' }, ip: '198.51.100.3' }), badOwner);
        assert.equal(badOwner.statusCode, 401);
        assert.equal(badOwner.body.success, false);
        assert.equal(badOwner.getHeader('set-cookie'), undefined);
        assert.equal(state.credentials.get('owner').failed_attempts, 1);

        // 4. Invalid IT PIN
        const badIt = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'it', pin: 'wrong-it' }, ip: '198.51.100.4' }), badIt);
        assert.equal(badIt.statusCode, 401);
        assert.equal(state.credentials.get('it').failed_attempts, 1);
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });
  });

  test('5: Malformed stored scrypt hash never verifies and fails closed', async () => {
    const malformedHashes = [
      '',
      '123456',
      'scrypt$16384$8$1$short$short',
      'scrypt$100$8$1$0123456789abcdef0123456789abcdef$' + 'ab'.repeat(64),
      'scrypt$16384$8$1$nothex!$' + 'ab'.repeat(64),
      'sha256$deadbeef$cafebabe'
    ];
    for (const bad of malformedHashes) {
      assert.equal(auth.isValidScryptHash(bad), false);
      assert.equal(auth.verifyPin('123456', bad), false);
    }

    const { fakePool } = createInMemoryDb([
      ['owner', { role: 'owner', pin_hash: 'corrupted-not-scrypt', failed_attempts: 0, lock_level: 0, locked_until: null }]
    ]);
    await withEnv({
      DATABASE_URL: 'postgres://mock:mock@localhost:5432/arkik',
      ADMIN_SESSION_SECRET: 'test-secret-0123456789abcdef',
      ADMIN_OWNER_PIN: null,
      ADMIN_IT_PIN: null
    }, async () => {
      db.setPoolFactoryForTests(() => fakePool);
      try {
        const res = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: '123456' }, ip: '198.51.100.5' }), res);
        assert.equal(res.statusCode, 503);
        assert.equal(res.body.success, false);
        assert.equal(res.getHeader('set-cookie'), undefined);
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });
  });

  test('6-8: Missing env vars, Neon connection outage, empty admin_credentials, & schema mismatch fail closed (never grant access)', async () => {
    // 6. Missing DATABASE_URL & missing env pins -> 503
    await withEnv({
      DATABASE_URL: null,
      ADMIN_OWNER_PIN: null,
      ADMIN_IT_PIN: null,
      ADMIN_PIN_OWNER: null,
      ADMIN_PIN_IT: null
    }, async () => {
      const res = makeRes();
      await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: '1234' } }), res);
      assert.equal(res.statusCode, 503);
      assert.equal(res.body.error.code, 'service_unavailable');
      assert.equal(res.getHeader('set-cookie'), undefined);
    });

    // 7. Neon connection error simulation -> 503 db_unavailable
    const brokenPool = {
      query: async () => {
        const err = new Error('connect ECONNREFUSED 127.0.0.1:5432');
        err.code = 'ECONNREFUSED';
        throw err;
      },
      connect: async () => {
        const err = new Error('connect ECONNREFUSED 127.0.0.1:5432');
        err.code = 'ECONNREFUSED';
        throw err;
      },
      end: async () => {}
    };
    await withEnv({ DATABASE_URL: 'postgres://mock:mock@localhost:5432/arkik', ADMIN_SESSION_SECRET: 'secret-abc' }, async () => {
      db.setPoolFactoryForTests(() => brokenPool);
      try {
        const res = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: '1234' } }), res);
        assert.equal(res.statusCode, 503);
        assert.equal(res.body.success, false);
        assert.equal(res.getHeader('set-cookie'), undefined);
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });

    // 8a. Schema mismatch (`relation "admin_credentials" does not exist`) -> >=500 failure, zero access
    const { fakePool: emptyCredsPool } = createInMemoryDb([]);
    await withEnv({ DATABASE_URL: 'postgres://mock:mock@localhost:5432/arkik', ADMIN_SESSION_SECRET: 'secret-abc' }, async () => {
      db.setPoolFactoryForTests(() => emptyCredsPool);
      try {
        const resEmpty = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: '1234' }, ip: '198.51.100.8' }), resEmpty);
        assert.equal(resEmpty.statusCode, 503, 'empty admin_credentials must fail closed with 503');
        assert.equal(resEmpty.getHeader('set-cookie'), undefined);
      } finally {
        db.setPoolFactoryForTests(null);
      }

      const schemaMismatchPool = {
        query: async () => ({ rows: [{ count: 1, window_start: new Date() }], rowCount: 1 }),
        connect: async () => ({
          query: async (sql) => {
            if (/rate_limits/i.test(sql)) return { rows: [{ count: 1, window_start: new Date() }], rowCount: 1 };
            if (/admin_credentials/i.test(sql)) {
              const e = new Error('relation "admin_credentials" does not exist');
              e.code = '42P01';
              throw e;
            }
            return { rows: [], rowCount: 0 };
          },
          release: () => {}
        }),
        end: async () => {}
      };
      db.setPoolFactoryForTests(() => schemaMismatchPool);
      try {
        const resSchema = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: '1234' } }), resSchema);
        assert.ok(resSchema.statusCode >= 500, 'schema mismatch must return 5xx and never succeed');
        assert.equal(resSchema.body.success, false);
        assert.equal(resSchema.getHeader('set-cookie'), undefined);
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });
  });

  test('9: Rate limiting enforces 429 Retry-After without cross-origin DoS lockout', async () => {
    const ownerHash = auth.hashPin(OWNER_PIN);
    const { fakePool } = createInMemoryDb([
      ['owner', { role: 'owner', pin_hash: ownerHash, failed_attempts: 0, lock_level: 0, locked_until: null }]
    ]);

    await withEnv({
      DATABASE_URL: 'postgres://mock:mock@localhost:5432/arkik',
      ADMIN_SESSION_SECRET: 'test-secret-0123456789abcdef',
      ADMIN_OWNER_PIN: null,
      ADMIN_IT_PIN: null
    }, async () => {
      db.setPoolFactoryForTests(() => fakePool);
      try {
        // 5 bad attempts from attacker IP
        for (let i = 0; i < 5; i++) {
          const r = makeRes();
          await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: '000000' }, ip: '203.0.113.99' }), r);
          assert.equal(r.statusCode, 401);
        }
        // 6th attempt from attacker IP -> 429 rate_limited
        const blocked = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: OWNER_PIN }, ip: '203.0.113.99' }), blocked);
        assert.equal(blocked.statusCode, 429);
        assert.ok(Number(blocked.getHeader('retry-after')) > 0);
        assert.ok(blocked.body.error.retryAfterMs > 0);

        // Legitimate admin IP still works (anti-global-lockout invariant)
        const legit = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: OWNER_PIN }, ip: '198.51.100.77' }), legit);
        assert.equal(legit.statusCode, 200);
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });
  });

  test('11-15: Sliding expiration, expired session, tampered cookies, v1 rejection with DB, logout & post-logout replay denial', async () => {
    const ownerHash = auth.hashPin(OWNER_PIN);
    let clock = Date.now();
    const { state, fakePool } = createInMemoryDb([
      ['owner', { role: 'owner', pin_hash: ownerHash, failed_attempts: 0, lock_level: 0, locked_until: null }]
    ]);
    state.nowMs = () => clock;

    await withEnv({
      DATABASE_URL: 'postgres://mock:mock@localhost:5432/arkik',
      ADMIN_SESSION_SECRET: 'test-secret-0123456789abcdef',
      NODE_ENV: 'test',
      ADMIN_OWNER_PIN: null,
      ADMIN_IT_PIN: null
    }, async () => {
      db.setPoolFactoryForTests(() => fakePool);
      try {
        const loginRes = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: OWNER_PIN }, ip: '198.51.100.11' }), loginRes);
        assert.equal(loginRes.statusCode, 200);
        const cookie = extractCookiePair(loginRes.getHeader('set-cookie'));
        const rawToken = decodeURIComponent(cookie.split('=')[1]);
        const storedSess = state.sessions.get(auth.hashToken(rawToken));
        const initialExpires = storedSess.expires_at.getTime();

        // 11. Simulate > TOUCH_AFTER_MS elapsed since last_seen_at -> lookup triggers sliding extension
        storedSess.last_seen_at = new Date(Date.now() - 2 * 60 * 1000);
        storedSess.expires_at = new Date(Date.now() + 13 * 60 * 1000);
        const beforeSliding = storedSess.expires_at.getTime();
        const sessRes1 = makeRes();
        await sessionHandler(makeReq('GET', '/api/admin/session', { headers: { cookie } }), sessRes1);
        assert.equal(sessRes1.statusCode, 200);
        assert.equal(sessRes1.body.data.role, 'owner');
        assert.ok(storedSess.expires_at.getTime() > beforeSliding, 'sliding expiry must extend expires_at');

        // 13. Tampered cookie / forged token / v1 stateless token rejected when DATABASE_URL is configured
        const tampered = makeRes();
        await sessionHandler(makeReq('GET', '/api/admin/session', { headers: { cookie: `arkik_session=${encodeURIComponent(rawToken + 'x')}` } }), tampered);
        assert.equal(tampered.statusCode, 401);

        const v1Token = auth.createStatelessToken('owner', clock + 60000);
        const v1Attempt = makeRes();
        await sessionHandler(makeReq('GET', '/api/admin/session', { headers: { cookie: `arkik_session=${encodeURIComponent(v1Token)}` } }), v1Attempt);
        assert.equal(v1Attempt.statusCode, 401, 'v1 stateless tokens must be rejected when DATABASE_URL is active');

        // 14 & 15. Logout clears cookie, deletes DB session, and denies post-logout replay
        const logoutRes = makeRes();
        await logoutHandler(makeReq('POST', '/api/admin/logout', { headers: { cookie } }), logoutRes);
        assert.equal(logoutRes.statusCode, 200);
        assert.match(logoutRes.getHeader('set-cookie'), /Max-Age=0/);
        assert.equal(state.sessions.size, 0);

        const replayRes = makeRes();
        await dashboardHandler(makeReq('GET', '/api/admin/dashboard', { headers: { cookie } }), replayRes);
        assert.equal(replayRes.statusCode, 401);

        // 12. Expired session returns 401
        const loginRes2 = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: OWNER_PIN }, ip: '198.51.100.12' }), loginRes2);
        const cookie2 = extractCookiePair(loginRes2.getHeader('set-cookie'));
        const rawToken2 = decodeURIComponent(cookie2.split('=')[1]);
        state.sessions.get(auth.hashToken(rawToken2)).expires_at = new Date(Date.now() - 1000);
        const expiredRes = makeRes();
        await sessionHandler(makeReq('GET', '/api/admin/session', { headers: { cookie: cookie2 } }), expiredRes);
        assert.equal(expiredRes.statusCode, 401);
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });

    // Logout must STILL clear cookie when DB is completely unavailable
    await withEnv({ DATABASE_URL: null, NODE_ENV: 'test' }, async () => {
      const logoutDown = makeRes();
      await logoutHandler(makeReq('POST', '/api/admin/logout', { headers: { cookie: 'arkik_session=stale_tok' } }), logoutDown);
      assert.equal(logoutDown.statusCode, 200);
      assert.match(logoutDown.getHeader('set-cookie'), /Max-Age=0/);
    });
  });

  test('16-18: Cookie attributes dev vs prod, RBAC (Owner vs IT), and CORS enforcement', async () => {
    await withEnv({ NODE_ENV: 'development', VERCEL_ENV: null }, async () => {
      const devSet = auth.sessionCookie('abc');
      assert.match(devSet, /^arkik_session=abc;/);
      assert.match(devSet, /HttpOnly/);
      assert.match(devSet, /SameSite=Strict/);
      assert.equal(/Secure/.test(devSet), false);
    });

    await withEnv({ NODE_ENV: 'production', VERCEL_ENV: 'production' }, async () => {
      const prodSet = auth.sessionCookie('abc');
      assert.match(prodSet, /^__Host-session=abc;/);
      assert.match(prodSet, /HttpOnly/);
      assert.match(prodSet, /Secure/);
      assert.match(prodSet, /SameSite=Strict/);
      assert.match(prodSet, /Path=\//);
      assert.match(auth.clearSessionCookie(), /^__Host-session=;/);
    });

    const ownerHash = auth.hashPin(OWNER_PIN);
    const itHash = auth.hashPin(IT_PIN);
    const { fakePool } = createInMemoryDb([
      ['owner', { role: 'owner', pin_hash: ownerHash, failed_attempts: 0, lock_level: 0, locked_until: null }],
      ['it', { role: 'it', pin_hash: itHash, failed_attempts: 0, lock_level: 0, locked_until: null }]
    ]);

    await withEnv({
      DATABASE_URL: 'postgres://mock:mock@localhost:5432/arkik',
      ADMIN_SESSION_SECRET: 'test-secret-0123456789abcdef',
      NODE_ENV: 'test',
      ALLOWED_ORIGINS: 'https://arkik.example.com'
    }, async () => {
      db.setPoolFactoryForTests(() => fakePool);
      try {
        // IT logs in -> allowed on /api/admin/dashboard and /api/availability PUT, but FORBIDDEN (403) on /api/admin/pricing PUT
        const itLogin = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'it', pin: IT_PIN }, ip: '198.51.100.16' }), itLogin);
        assert.equal(itLogin.statusCode, 200);
        const itCookie = extractCookiePair(itLogin.getHeader('set-cookie'));

        const itDash = makeRes();
        await dashboardHandler(makeReq('GET', '/api/admin/dashboard', { headers: { cookie: itCookie } }), itDash);
        assert.equal(itDash.statusCode, 200);
        assert.equal(itDash.body.data.role, 'it');
        assert.equal(typeof itDash.body.data.stats.total, 'number');

        const itPricingPut = makeRes();
        await pricingAdminHandler(makeReq('PUT', '/api/admin/pricing', {
          headers: { cookie: itCookie },
          body: { overrides: { services: { '1': 700000 }, extras: {} }, rates: { extraHourMultiplier: 0.5, travelSurchargeRate: 0.12 } }
        }), itPricingPut);
        assert.equal(itPricingPut.statusCode, 403, 'IT role must receive 403 on owner-only pricing endpoint');

        const itAvail = makeRes();
        await availabilityHandler(makeReq('PUT', '/api/availability', {
          headers: { cookie: itCookie },
          body: { date: '2027-05-01', state: 'disabled', reason: 'Maintenance' }
        }), itAvail);
        assert.equal(itAvail.statusCode, 403, 'IT role must receive 403 on owner-only availability mutation');

        // Owner allowed on requireOwner endpoint (PUT /api/admin/pricing)
        const ownerLogin = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: OWNER_PIN }, ip: '198.51.100.17' }), ownerLogin);
        assert.equal(ownerLogin.statusCode, 200);
        const ownerCookie = extractCookiePair(ownerLogin.getHeader('set-cookie'));

        const ownerPricingPut = makeRes();
        await pricingAdminHandler(makeReq('PUT', '/api/admin/pricing', {
          headers: { cookie: ownerCookie },
          body: { overrides: { services: { '1': 700000 }, extras: {} }, rates: { extraHourMultiplier: 0.5, travelSurchargeRate: 0.12 } }
        }), ownerPricingPut);
        assert.equal(ownerPricingPut.statusCode, 200, 'Owner role must succeed on requireOwner endpoint');

        // 18. Disallowed Origin rejected with 403 on OPTIONS preflight and receives no ACAO headers on POST
        const badCorsPreflight = makeRes();
        await loginHandler(makeReq('OPTIONS', '/api/admin/login', {
          headers: { origin: 'https://evil.attacker.invalid' }
        }), badCorsPreflight);
        assert.equal(badCorsPreflight.statusCode, 403);
        assert.equal(badCorsPreflight.getHeader('access-control-allow-origin'), undefined);

        const badCorsPost = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', {
          headers: { origin: 'https://evil.attacker.invalid' },
          body: { role: 'owner', pin: OWNER_PIN },
          ip: '198.51.100.18'
        }), badCorsPost);
        assert.equal(badCorsPost.getHeader('access-control-allow-origin'), undefined);
        assert.equal(badCorsPost.getHeader('access-control-allow-credentials'), undefined);

        const goodCorsPreflight = makeRes();
        await loginHandler(makeReq('OPTIONS', '/api/admin/login', {
          headers: { origin: 'https://arkik.example.com' }
        }), goodCorsPreflight);
        assert.equal(goodCorsPreflight.statusCode, 204);
        assert.equal(goodCorsPreflight.getHeader('access-control-allow-origin'), 'https://arkik.example.com');
        assert.equal(goodCorsPreflight.getHeader('access-control-allow-credentials'), 'true');
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });
  });

  test('19: migrate.bootstrapAdmins avoids double-hashing scrypt$ & DATABASE_URL stays authoritative over env PINs', async () => {
    const preHashedOwner = auth.hashPin(OWNER_PIN);
    const { state, fakePool } = createInMemoryDb([]);

    await withEnv({
      ADMIN_OWNER_PIN: preHashedOwner,
      ADMIN_PIN_IT: IT_PIN,
      ADMIN_IT_PIN: null
    }, async () => {
      await migrate.bootstrapAdmins(fakePool);
      const ownerRow = state.credentials.get('owner');
      const itRow = state.credentials.get('it');
      assert.equal(ownerRow.pin_hash, preHashedOwner, 'pre-hashed scrypt$ env var must NOT be double-hashed');
      assert.equal(auth.verifyPin(OWNER_PIN, ownerRow.pin_hash), true);
      assert.equal(auth.verifyPin(IT_PIN, itRow.pin_hash), true);

      // Running bootstrap again must NEVER overwrite existing DB credentials
      await withEnv({ ADMIN_OWNER_PIN: '999999' }, async () => {
        await migrate.bootstrapAdmins(fakePool);
        assert.equal(state.credentials.get('owner').pin_hash, preHashedOwner);
      });
    });

    // Reject malformed scrypt$ values explicitly
    await withEnv({ ADMIN_OWNER_PIN: 'scrypt$bad$format', ADMIN_IT_PIN: null, ADMIN_PIN_IT: null }, async () => {
      const { fakePool: p2 } = createInMemoryDb([]);
      await assert.rejects(() => migrate.bootstrapAdmins(p2), /Invalid pre-hashed scrypt string/);
    });

    // Authoritative DB path when BOTH DATABASE_URL and different ADMIN_OWNER_PIN are set
    await withEnv({
      DATABASE_URL: 'postgres://mock:mock@localhost:5432/arkik',
      ADMIN_SESSION_SECRET: 'test-secret-0123456789abcdef',
      ADMIN_OWNER_PIN: '000000', // stale env var must NOT override rotated DB credential!
      NODE_ENV: 'test'
    }, async () => {
      db.setPoolFactoryForTests(() => fakePool);
      try {
        const res = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: OWNER_PIN }, ip: '198.51.100.19' }), res);
        assert.equal(res.statusCode, 200, 'login must verify against Neon admin_credentials when DATABASE_URL is configured');
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });
  });

  test('20: Full E2E HTTP cycle (in-process router + live socket fallback) + Frontend SecurityModule VM contract', async () => {
    const ownerHash = auth.hashPin(OWNER_PIN);
    const { fakePool } = createInMemoryDb([
      ['owner', { role: 'owner', pin_hash: ownerHash, failed_attempts: 0, lock_level: 0, locked_until: null }]
    ]);

    const routes = {
      '/api/admin/login': loginHandler,
      '/api/admin/session': sessionHandler,
      '/api/admin/dashboard': dashboardHandler,
      '/api/admin/logout': logoutHandler
    };

    async function dispatchHttp(method, pathname, { headers = {}, body } = {}) {
      const req = makeReq(method, pathname, { headers, body });
      const res = makeRes();
      const fn = routes[pathname];
      if (!fn) {
        res.status(404).json({ success: false, error: { code: 'not_found', message: 'Not found' } });
        return res;
      }
      await fn(req, res);
      return res;
    }

    // Also probe real TCP HTTP server when the host permits loopback binding; fall back cleanly in network-isolated sandboxes
    let server = null;
    let baseUrl = null;
    try {
      server = http.createServer(async (req, res) => {
        const rawChunks = [];
        for await (const chunk of req) rawChunks.push(chunk);
        const rawBody = Buffer.concat(rawChunks).toString('utf8');
        if (rawBody) {
          try { req.body = JSON.parse(rawBody); } catch { req.body = rawBody; }
        }
        const wrappedRes = {
          setHeader: (k, v) => res.setHeader(k, v),
          getHeader: (k) => res.getHeader(k),
          status: (code) => { res.statusCode = code; return wrappedRes; },
          json: (obj) => {
            if (!res.getHeader('content-type')) res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(obj));
            return wrappedRes;
          },
          end: (data) => { res.end(data); return wrappedRes; }
        };
        const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
        const fn = routes[pathname];
        if (fn) return fn(req, wrappedRes);
        res.statusCode = 404;
        res.end(JSON.stringify({ success: false, error: { code: 'not_found', message: 'Not found' } }));
      });
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
      });
      baseUrl = `http://127.0.0.1:${server.address().port}`;
      // Quick loopback reachability probe
      await fetch(`${baseUrl}/api/admin/session`);
    } catch {
      if (server) {
        try { await new Promise((resolve) => server.close(resolve)); } catch {}
      }
      server = null;
      baseUrl = null;
    }

    try {
      await withEnv({
        DATABASE_URL: 'postgres://mock:mock@localhost:5432/arkik',
        ADMIN_SESSION_SECRET: 'test-secret-0123456789abcdef',
        NODE_ENV: 'test'
      }, async () => {
        db.setPoolFactoryForTests(() => fakePool);

        if (baseUrl) {
          const loginHttp = await fetch(`${baseUrl}/api/admin/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ role: 'owner', pin: OWNER_PIN })
          });
          assert.equal(loginHttp.status, 200);
          const cookieHeader = loginHttp.headers.get('set-cookie').split(';')[0];
          const dashHttp = await fetch(`${baseUrl}/api/admin/dashboard`, { headers: { Cookie: cookieHeader } });
          assert.equal(dashHttp.status, 200);
          const dashJson = await dashHttp.json();
          assert.equal(dashJson.data.role, 'owner');
          const logoutHttp = await fetch(`${baseUrl}/api/admin/logout`, { method: 'POST', headers: { Cookie: cookieHeader } });
          assert.equal(logoutHttp.status, 200);
          const postLogoutDash = await fetch(`${baseUrl}/api/admin/dashboard`, { headers: { Cookie: cookieHeader } });
          assert.equal(postLogoutDash.status, 401);
        } else {
          const loginRes = await dispatchHttp('POST', '/api/admin/login', { body: { role: 'owner', pin: OWNER_PIN } });
          assert.equal(loginRes.statusCode, 200);
          const cookieHeader = extractCookiePair(loginRes.getHeader('set-cookie'));
          const dashRes = await dispatchHttp('GET', '/api/admin/dashboard', { headers: { cookie: cookieHeader } });
          assert.equal(dashRes.statusCode, 200);
          assert.equal(dashRes.body.data.role, 'owner');
          const logoutRes = await dispatchHttp('POST', '/api/admin/logout', { headers: { cookie: cookieHeader } });
          assert.equal(logoutRes.statusCode, 200);
          const postLogoutDash = await dispatchHttp('GET', '/api/admin/dashboard', { headers: { cookie: cookieHeader } });
          assert.equal(postLogoutDash.statusCode, 401);
        }
      });
    } finally {
      db.setPoolFactoryForTests(null);
      if (server) {
        await new Promise((resolve) => server.close(resolve));
      }
    }

    // Frontend SecurityModule error discrimination in VM (real js/app.js + js/data.js)
    const dataSrc = fs.readFileSync(path.join(REPO, 'js', 'data.js'), 'utf8');
    const appSrc = fs.readFileSync(path.join(REPO, 'js', 'app.js'), 'utf8');

    let nextFetchResult = () => Promise.resolve({ status: 503, text: async () => JSON.stringify({ success: false, error: { code: 'no_database', message: 'DB down' } }) });
    const lsStore = new Map();
    const ssStore = new Map();
    const fakeStorage = (m) => ({
      getItem: (k) => (m.has(k) ? m.get(k) : null),
      setItem: (k, v) => m.set(k, String(v)),
      removeItem: (k) => m.delete(k)
    });

    const sandbox = {
      console,
      setTimeout,
      clearTimeout,
      setInterval,
      clearInterval,
      requestAnimationFrame: (fn) => setTimeout(fn, 0),
      Promise,
      JSON,
      Date,
      Math,
      Object,
      String,
      Number,
      Boolean,
      Array,
      Map,
      Set,
      RegExp,
      Error,
      TypeError,
      encodeURIComponent,
      decodeURIComponent,
      AbortController,
      fetch: (...args) => nextFetchResult(...args),
      localStorage: fakeStorage(lsStore),
      sessionStorage: fakeStorage(ssStore),
      location: { pathname: '/', hash: '', origin: 'http://127.0.0.1' },
      navigator: { userAgent: 'node-test' },
      document: {
        readyState: 'loading',
        addEventListener: () => {},
        getElementById: () => null,
        querySelector: () => null,
        querySelectorAll: () => [],
        body: { style: {}, classList: { add() {}, remove() {}, toggle() {} } }
      },
      addEventListener: () => {},
      scrollTo: () => {},
      history: { replaceState: () => {} },
      crypto: require('node:crypto').webcrypto
    };
    sandbox.window = sandbox;
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(dataSrc, sandbox, { filename: 'js/data.js' });
    vm.runInContext(appSrc + '\nwindow.__TEST_EXPORTS__ = { SecurityModule, ADMIN_CONFIG };', sandbox, { filename: 'js/app.js' });

    const { SecurityModule } = sandbox.__TEST_EXPORTS__;
    assert.equal(SecurityModule.normalizePin('  it-42#ark '), 'it-42#ark', 'normalizePin must preserve non-digit characters');

    // 503 must set infraError: true, NOT increment attempts, NOT say "Credenciales inválidas"
    SecurityModule.clearLockState();
    nextFetchResult = async () => ({
      status: 503,
      text: async () => JSON.stringify({ success: false, error: { code: 'no_database', message: 'Servicio no disponible temporalmente.' } })
    });
    const res503 = await SecurityModule.verifyPin('owner', '123456');
    assert.equal(res503.ok, false);
    assert.equal(res503.status, 503);
    assert.equal(res503.infraError, true);
    assert.equal(res503.locked, false);
    assert.equal(/Credenciales inválidas/i.test(res503.message), false);
    assert.equal(SecurityModule.status().attempts, 0, '503 infrastructure errors must NOT charge failed login attempts');

    // Network error (status 0) must set infraError: true, NOT increment attempts
    nextFetchResult = async () => { throw new TypeError('Failed to fetch'); };
    const resNet = await SecurityModule.verifyPin('owner', '123456');
    assert.equal(resNet.ok, false);
    assert.equal(resNet.status, 0);
    assert.equal(resNet.infraError, true);
    assert.equal(SecurityModule.status().attempts, 0);

    // 401 wrong PIN DOES increment failed attempts and shows generic message
    nextFetchResult = async () => ({
      status: 401,
      text: async () => JSON.stringify({ success: false, error: { code: 'unauthorized', message: 'Credenciales inválidas' } })
    });
    const res401 = await SecurityModule.verifyPin('owner', '000000');
    assert.equal(res401.ok, false);
    assert.equal(res401.status, 401);
    assert.equal(res401.infraError, false);
    assert.equal(res401.message, 'Credenciales inválidas');
    assert.equal(SecurityModule.status().attempts, 1);

    // 200 clears failed attempts and returns verified role
    nextFetchResult = async () => ({
      status: 200,
      text: async () => JSON.stringify({ success: true, data: { role: 'owner', expiresAt: new Date(Date.now() + 900000).toISOString() } })
    });
    const res200 = await SecurityModule.verifyPin('owner', '849201');
    assert.equal(res200.ok, true);
    assert.equal(res200.role, 'owner');
    assert.equal(SecurityModule.status().attempts, 0);

    // 200 text/html static SPA hijack must return infraError: true, NOT increment attempts
    nextFetchResult = async () => ({
      status: 200,
      headers: { get: (k) => (k.toLowerCase() === 'content-type' ? 'text/html; charset=utf-8' : null) },
      text: async () => '<!DOCTYPE html><html><body>SPA</body></html>'
    });
    const resHtml = await SecurityModule.verifyPin('owner', '849201');
    assert.equal(resHtml.ok, false);
    assert.equal(resHtml.infraError, true);
    assert.equal(resHtml.code, 'static_server_html');
    assert.equal(SecurityModule.status().attempts, 0);
  });

  test('21: manage-admin-pins verify + transactional rotate with session revocation & audit trail', async () => {
    const managePins = require(path.join(__dirname, '..', 'db', 'manage-admin-pins.js'));
    const ownerHash = auth.hashPin('112233');
    const badHash = 'not-a-scrypt-hash';

    const store = {
      credentials: new Map([
        ['owner', { role: 'owner', pin_hash: ownerHash, failed_attempts: 4, lock_level: 2, locked_until: '2030-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }],
        ['it', { role: 'it', pin_hash: badHash, failed_attempts: 0, lock_level: 0, locked_until: null, updated_at: '2026-01-01T00:00:00Z' }]
      ]),
      sessions: [
        { token_hash: 'tok_owner_1', role: 'owner' },
        { token_hash: 'tok_owner_2', role: 'owner' },
        { token_hash: 'tok_it_1', role: 'it' }
      ],
      audits: [],
      txEvents: []
    };

    const client = {
      async query(sql, params = []) {
        const s = String(sql).trim();
        if (s === 'BEGIN' || s === 'COMMIT' || s === 'ROLLBACK') {
          store.txEvents.push(s);
          return { rows: [], rowCount: 0 };
        }
        if (/SELECT role, pin_hash/i.test(s)) {
          return { rows: [...store.credentials.values()], rowCount: store.credentials.size };
        }
        if (/INSERT INTO admin_credentials/i.test(s)) {
          const [role, pinHash] = params;
          const now = new Date().toISOString();
          store.credentials.set(role, {
            role,
            pin_hash: pinHash,
            failed_attempts: 0,
            lock_level: 0,
            locked_until: null,
            updated_at: now
          });
          return { rows: [{ updated_at: now }], rowCount: 1 };
        }
        if (/DELETE FROM admin_sessions WHERE role/i.test(s)) {
          const role = params[0];
          const before = store.sessions.length;
          store.sessions = store.sessions.filter((item) => item.role !== role);
          return { rows: [], rowCount: before - store.sessions.length };
        }
        if (/INSERT INTO audit_log/i.test(s)) {
          const [entityId, actor, metadata] = params;
          const id = store.audits.length + 1;
          store.audits.push({ id, action: 'ADMIN_CREDENTIAL_ROTATED', entity_id: entityId, actor, metadata: JSON.parse(metadata) });
          return { rows: [{ id }], rowCount: 1 };
        }
        return { rows: [], rowCount: 0 };
      },
      release() {}
    };

    const pool = {
      query: (sql, params) => client.query(sql, params),
      connect: async () => client
    };

    // verify reports MATCH for matching owner PIN and CORRUPTED_HASH for corrupted it row
    const initialReport = await managePins.verifyAdminPins(pool, { ADMIN_OWNER_PIN: '112233', ADMIN_IT_PIN: 'it-ok-1' });
    const ownerEntry = initialReport.find((r) => r.role === 'owner');
    const itEntry = initialReport.find((r) => r.role === 'it');
    assert.equal(ownerEntry.status, 'MATCH');
    assert.equal(itEntry.status, 'CORRUPTED_HASH');

    // rotate refuses without --confirm
    await assert.rejects(
      () => managePins.rotateAdminPin(pool, { role: 'it', confirm: false, rawPin: 'new-it-pin!' }),
      /--confirm/
    );

    // rotate succeeds atomically, revokes ONLY rotated role sessions, clears lockout & logs audit
    const rotated = await managePins.rotateAdminPin(pool, {
      role: 'owner',
      confirm: true,
      rawPin: '998877',
      reason: 'incident_recovery'
    });
    assert.equal(rotated.ok, true);
    assert.equal(rotated.revokedSessions, 2);
    assert.deepEqual(store.txEvents, ['BEGIN', 'COMMIT']);
    assert.equal(store.sessions.length, 1);
    assert.equal(store.sessions[0].role, 'it');
    assert.equal(store.credentials.get('owner').failed_attempts, 0);
    assert.equal(store.credentials.get('owner').locked_until, null);
    assert.equal(auth.verifyPin('998877', store.credentials.get('owner').pin_hash), true);
    assert.equal(store.audits.length, 1);
    assert.equal(store.audits[0].action, 'ADMIN_CREDENTIAL_ROTATED');
    assert.equal(store.audits[0].metadata.reason, 'incident_recovery');
  });

  test('22: Booking mutation endpoints strictly enforce Owner-only RBAC (IT receives 403)', async () => {
    const bookingIndex = require(path.join(__dirname, '..', 'api', 'bookings', '[code]', 'index.js'));
    const bookingStatus = require(path.join(__dirname, '..', 'api', 'bookings', '[code]', 'status.js'));
    const bookingResched = require(path.join(__dirname, '..', 'api', 'bookings', '[code]', 'reschedule.js'));

    const secret = 'test-secret-0123456789abcdef';
    await withEnv({ DATABASE_URL: null, ADMIN_SESSION_SECRET: secret, NODE_ENV: 'test' }, async () => {
      const itToken = auth.createStatelessToken('it', secret, 60000);
      const cookieHeader = `arkik_session=${encodeURIComponent(itToken)}`;

      for (const [handler, pathUrl, body] of [
        [bookingIndex, '/api/bookings/ARK-100', { clientName: 'Test' }],
        [bookingStatus, '/api/bookings/ARK-100/status', { status: 'confirmada' }],
        [bookingResched, '/api/bookings/ARK-100/reschedule', { selectedDate: '2026-12-01', selectedTime: '19:00' }]
      ]) {
        const req = makeReq('PATCH', pathUrl, { headers: { cookie: cookieHeader }, body });
        req.query = { code: 'ARK-100' };
        const res = makeRes();
        await handler(req, res);
        assert.equal(res.statusCode, 403, `${pathUrl} must reject it role with 403`);
        assert.equal(res.body.success, false);
      }
    });
  });

  test('23: Dashboard endpoint hydrates server auditEvents alongside bookings/stats/pricing', async () => {
    const dashboardHandler = require(path.join(__dirname, '..', 'api', 'admin', 'dashboard.js'));
    const secret = 'test-secret-0123456789abcdef';
    const service = require(path.join(__dirname, '..', 'api', '_lib', 'service.js'));

    const origStats = service.getStats;
    const origBookings = service.listBookings;
    const origPricing = service.getPricing;
    const origAvail = service.getAvailability;
    const origAudit = service.listAudit;

    service.getStats = async () => ({ total: 1, pendientes: 1, confirmadas: 0, ingresoProyectadoCrc: 1000 });
    service.listBookings = async () => ({ bookings: [], total: 0 });
    service.getPricing = async () => ({ overrides: { services: {}, extras: {} }, rates: {} });
    service.getAvailability = async () => ({ blocked: {} });
    service.listAudit = async () => ({
      events: [{ action: 'ADMIN_LOGIN_SUCCESS', entityType: 'admin', entityId: 'it', actor: 'admin:it', metadata: {}, createdAt: '2026-11-13T00:00:00Z' }]
    });

    try {
      await withEnv({ DATABASE_URL: null, ADMIN_SESSION_SECRET: secret, NODE_ENV: 'test' }, async () => {
        const token = auth.createStatelessToken('it', secret, 60000);
        const res = makeRes();
        await dashboardHandler(makeReq('GET', '/api/admin/dashboard', { headers: { cookie: `arkik_session=${encodeURIComponent(token)}` } }), res);
        assert.equal(res.statusCode, 200);
        assert.equal(res.body.success, true);
        assert.equal(Array.isArray(res.body.data.auditEvents), true);
        assert.equal(res.body.data.auditEvents[0].action, 'ADMIN_LOGIN_SUCCESS');
      });
    } finally {
      service.getStats = origStats;
      service.listBookings = origBookings;
      service.getPricing = origPricing;
      service.getAvailability = origAvail;
      service.listAudit = origAudit;
    }
  });

  test('24: Full-stack dev server resolves /api/* dynamically and blocks sensitive dotfiles/directories', async () => {
    const devServer = require(path.join(__dirname, '..', 'scripts', 'dev-server.js'));

    const loginRoute = devServer.resolveApiRoute('/api/admin/login');
    assert.equal(loginRoute.handlerPath, '../api/admin/login.js');
    const statusRoute = devServer.resolveApiRoute('/api/bookings/ARK-2026/status');
    assert.equal(statusRoute.handlerPath, '../api/bookings/[code]/status.js');
    assert.equal(statusRoute.params.code, 'ARK-2026');
    assert.equal(devServer.resolveApiRoute('/api/does-not-exist'), null);

    // Static traversal / secret paths MUST be rejected
    assert.equal(devServer.isSafePublicPath('/.env'), null);
    assert.equal(devServer.isSafePublicPath('/.env.local'), null);
    assert.equal(devServer.isSafePublicPath('/db/manage-admin-pins.js'), null);
    assert.equal(devServer.isSafePublicPath('/api/health.js'), null);
    assert.equal(devServer.isSafePublicPath('/../secret.txt'), null);
    assert.ok(devServer.isSafePublicPath('/index.html').endsWith(`${path.sep}index.html`));

    // Unknown /api/* route MUST return 404 JSON, never HTML
    const req = makeReq('POST', '/api/unknown-endpoint');
    const res = makeRes();
    let endedBody = '';
    const wrappedRes = {
      statusCode: 200,
      headers: {},
      setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
      end(chunk) { endedBody = String(chunk || ''); }
    };
    await devServer.handleApiRequest(req, wrappedRes, new URL('http://127.0.0.1/api/unknown-endpoint'));
    assert.equal(wrappedRes.statusCode, 404);
    assert.match(wrappedRes.headers['content-type'], /application\/json/);
    const parsed = JSON.parse(endedBody);
    assert.equal(parsed.success, false);
    assert.equal(parsed.error.code, 'not_found');
  });

  test('25: Missing ADMIN_SESSION_SECRET in production returns 503 service_unavailable cleanly', async () => {
    const config = require(path.join(__dirname, '..', 'api', '_lib', 'config.js'));
    const respond = require(path.join(__dirname, '..', 'api', '_lib', 'respond.js'));
    await withEnv({ NODE_ENV: 'production', VERCEL_ENV: null, ADMIN_SESSION_SECRET: null }, async () => {
      let captured;
      try {
        void config.sessionSecret;
      } catch (err) {
        captured = err;
      }
      assert.ok(captured);
      assert.equal(captured.status, 503);
      assert.equal(captured.code, 'service_unavailable');
      const res = makeRes();
      respond.handleError(res, captured);
      assert.equal(res.statusCode, 503);
      assert.equal(res.body.success, false);
      assert.equal(res.body.error.code, 'service_unavailable');
    });
  });

  test('26: manage-admin-pins rolls back transaction atomically on partial failure & CLI rejects --pin', async () => {
    const managePins = require(path.join(__dirname, '..', 'db', 'manage-admin-pins.js'));
    const origHash = auth.hashPin('initial-owner-pin');
    const dbState = {
      pinHash: origHash,
      sessions: [{ role: 'owner', token_hash: 'keep_session' }],
      audits: [],
      tx: []
    };

    const failingClient = {
      async query(sql) {
        const s = String(sql).trim();
        if (s === 'BEGIN' || s === 'COMMIT' || s === 'ROLLBACK') {
          dbState.tx.push(s);
          return { rows: [], rowCount: 0 };
        }
        if (/INSERT INTO admin_credentials/i.test(s)) {
          return { rows: [{ updated_at: new Date().toISOString() }], rowCount: 1 };
        }
        if (/DELETE FROM admin_sessions/i.test(s)) {
          throw new Error('simulated failure mid-rotation');
        }
        return { rows: [], rowCount: 0 };
      },
      release() {}
    };

    const failingPool = { connect: async () => failingClient };
    await assert.rejects(
      () => managePins.rotateAdminPin(failingPool, { role: 'owner', confirm: true, rawPin: 'new-pin-999' }),
      /simulated failure mid-rotation/
    );
    assert.deepEqual(dbState.tx, ['BEGIN', 'ROLLBACK']);
    assert.equal(dbState.pinHash, origHash);
    assert.equal(dbState.sessions.length, 1);
    assert.equal(dbState.audits.length, 0);

    // CLI fast-fail before DB connection when --pin is passed on argv
    const { spawnSync } = require('child_process');
    const cliPinReject = spawnSync(
      process.execPath,
      [path.join(__dirname, '..', 'db', 'manage-admin-pins.js'), 'rotate', '--role', 'owner', '--confirm', '--pin', '123456'],
      { encoding: 'utf8', env: Object.assign({}, process.env, { DATABASE_URL: '' }) }
    );
    assert.notEqual(cliPinReject.status, 0);
    assert.match(cliPinReject.stderr, /Refusing --pin on command line argv/);
  });

  test('27: Complete RBAC write matrix enforces Owner vs IT vs anonymous across all write routes', async () => {
    const ownerPin = 'rbac-owner-91';
    const itPin = 'rbac-it-42';
    const { fakePool } = createInMemoryDb([
      ['owner', { role: 'owner', pin_hash: auth.hashPin(ownerPin), failed_attempts: 0, lock_level: 0, locked_until: null }],
      ['it', { role: 'it', pin_hash: auth.hashPin(itPin), failed_attempts: 0, lock_level: 0, locked_until: null }]
    ]);
    const pricingHandler = require(path.join(__dirname, '..', 'api', 'admin', 'pricing.js'));
    const availHandler = require(path.join(__dirname, '..', 'api', 'availability', 'index.js'));
    const bookingIdx = require(path.join(__dirname, '..', 'api', 'bookings', '[code]', 'index.js'));
    const bookingStatus = require(path.join(__dirname, '..', 'api', 'bookings', '[code]', 'status.js'));
    const bookingResched = require(path.join(__dirname, '..', 'api', 'bookings', '[code]', 'reschedule.js'));

    await withEnv({ DATABASE_URL: 'postgres://mock:mock@localhost/arkik', ADMIN_SESSION_SECRET: 'rbac-secret-0123456789' }, async () => {
      db.setPoolFactoryForTests(() => fakePool);
      try {
        const itLogin = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'it', pin: itPin }, ip: '198.51.100.60' }), itLogin);
        assert.equal(itLogin.statusCode, 200);
        const itCookie = extractCookiePair(itLogin.getHeader('set-cookie'));

        const ownerLogin = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: ownerPin }, ip: '198.51.100.61' }), ownerLogin);
        assert.equal(ownerLogin.statusCode, 200);
        const ownerCookie = extractCookiePair(ownerLogin.getHeader('set-cookie'));

        const writeCases = [
          [pricingHandler, 'PUT', '/api/admin/pricing', { rates: { depositRatio: 0.5, nonGamTravelCrc: 78000 } }, {}],
          [availHandler, 'PUT', '/api/availability', { date: '2026-12-20', state: 'disabled', reason: 'mantenimiento' }, {}],
          [availHandler, 'DELETE', '/api/availability?date=2026-12-20', undefined, { date: '2026-12-20' }],
          [bookingIdx, 'PATCH', '/api/bookings/ARK-MISSING', { clientName: 'X' }, { code: 'ARK-MISSING' }],
          [bookingStatus, 'PATCH', '/api/bookings/ARK-MISSING/status', { status: 'confirmada' }, { code: 'ARK-MISSING' }],
          [bookingResched, 'PATCH', '/api/bookings/ARK-MISSING/reschedule', { selectedDate: '2026-12-22', selectedTime: '18:00' }, { code: 'ARK-MISSING' }]
        ];

        for (const [fn, method, url, body, query] of writeCases) {
          const anonRes = makeRes();
          const anonReq = makeReq(method, url, { body });
          anonReq.query = query;
          await fn(anonReq, anonRes);
          assert.equal(anonRes.statusCode, 401, `${method} ${url} anonymous must return 401`);

          const itRes = makeRes();
          const itReq = makeReq(method, url, { headers: { cookie: itCookie }, body });
          itReq.query = query;
          await fn(itReq, itRes);
          assert.equal(itRes.statusCode, 403, `${method} ${url} IT role must return 403`);
        }

        // Verify Owner passes RBAC on pricing and availability writes
        const ownerAvail = makeRes();
        await availHandler(makeReq('PUT', '/api/availability', { headers: { cookie: ownerCookie }, body: { date: '2026-12-20', state: 'disabled', reason: 'bloqueo' } }), ownerAvail);
        assert.equal(ownerAvail.statusCode, 200);
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });
  });

  test('28: HTTPS Preview/Prod emits __Host-session cookies & PostgreSQL rate_limits enforces across instances', async () => {
    const ownerPin = 'dist-owner-77';
    const { state, fakePool } = createInMemoryDb([
      ['owner', { role: 'owner', pin_hash: auth.hashPin(ownerPin), failed_attempts: 0, lock_level: 0, locked_until: null }]
    ]);

    // HTTPS Preview (__Host-session + Secure + HttpOnly + SameSite=Strict + Path=/)
    await withEnv({
      DATABASE_URL: 'postgres://mock:mock@localhost/arkik',
      ADMIN_SESSION_SECRET: 'host-cookie-secret-0123456789',
      VERCEL_ENV: 'preview',
      NODE_ENV: 'production'
    }, async () => {
      db.setPoolFactoryForTests(() => fakePool);
      try {
        const res = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: ownerPin }, ip: '198.51.100.70' }), res);
        assert.equal(res.statusCode, 200);
        const setCookie = res.getHeader('set-cookie');
        assert.match(setCookie, /^__Host-session=/);
        assert.match(setCookie, /HttpOnly/);
        assert.match(setCookie, /Secure/);
        assert.match(setCookie, /SameSite=Strict/);
        assert.match(setCookie, /Path=\//);
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });

    // Multi-instance distributed rate limiting sharing PostgreSQL rate_limits table
    await withEnv({
      DATABASE_URL: 'postgres://mock:mock@localhost/arkik',
      ADMIN_SESSION_SECRET: 'host-cookie-secret-0123456789',
      VERCEL_ENV: null,
      NODE_ENV: 'test'
    }, async () => {
      db.setPoolFactoryForTests(() => fakePool);
      try {
        const rlModulePath = require.resolve(path.join(__dirname, '..', 'api', '_lib', 'ratelimit.js'));
        delete require.cache[rlModulePath];
        const instanceA = require(rlModulePath);
        delete require.cache[rlModulePath];
        const instanceB = require(rlModulePath);

        for (let i = 0; i < 3; i += 1) {
          await instanceA.enforce({ bucket: 'booking:203.0.113.1', limit: 4, windowMs: 60000 });
        }
        // 4th on independent Instance B succeeds; 5th across instances rejects 429 cleanly
        const fourth = await instanceB.enforce({ bucket: 'booking:203.0.113.1', limit: 4, windowMs: 60000 });
        assert.equal(fourth.allowed, true);
        assert.equal(fourth.count, 4);
        await assert.rejects(
          () => instanceA.enforce({ bucket: 'booking:203.0.113.1', limit: 4, windowMs: 60000 }),
          (err) => err && err.status === 429 && err.code === 'rate_limited'
        );
        assert.equal(state.rateLimits.get('booking:203.0.113.1').count, 5);
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });
  });

  test('29: End-to-End Business Flow (Booking -> Idempotency -> Owner Confirm -> 2nd Session Read -> Cancel -> Audit)', async () => {
    const ownerPin = 'flow-owner-88';
    const service = require(path.join(__dirname, '..', 'api', '_lib', 'service.js'));
    service.invalidateConfigCache();
    const { state, fakePool } = createInMemoryDb([
      ['owner', { role: 'owner', pin_hash: auth.hashPin(ownerPin), failed_attempts: 0, lock_level: 0, locked_until: null }]
    ]);
    state.configRows.push(
      { namespace: 'pricing', key: 'catalog', value: [{ id: 1, name: 'Dúo Acústico', price: 650000, setup_display: '90 min', teardown_display: '45 min' }] },
      { namespace: 'geo', key: 'provinces', value: { 'San José': ['Escazú', 'Santa Ana'] } },
      { namespace: 'geo', key: 'gam', value: ['San José'] }
    );
    const bookingsIdx = require(path.join(__dirname, '..', 'api', 'bookings', 'index.js'));
    const bookingItem = require(path.join(__dirname, '..', 'api', 'bookings', '[code]', 'index.js'));
    const bookingStatus = require(path.join(__dirname, '..', 'api', 'bookings', '[code]', 'status.js'));
    const auditHandler = require(path.join(__dirname, '..', 'api', 'admin', 'audit.js'));

    const futureDate = new Date(Date.now() + 21 * 86400000).toISOString().slice(0, 10);
    const payload = {
      clientName: 'Sofia Vargas',
      clientPhone: '88881234',
      clientEmail: 'sofia@example.com',
      eventType: 'Boda',
      serviceId: 1,
      selectedDate: futureDate,
      selectedTime: '18:00',
      province: 'San José',
      canton: 'Escazú',
      address: 'Guachipelín 120',
      sinpeRef: 'SINPE778899',
      extras: {}
    };

    await withEnv({ DATABASE_URL: 'postgres://mock:mock@localhost/arkik', ADMIN_SESSION_SECRET: 'flow-secret-0123456789' }, async () => {
      db.setPoolFactoryForTests(() => fakePool);
      try {
        // 1-2. Public createBooking + idempotency replay
        const createRes = makeRes();
        await bookingsIdx(makeReq('POST', '/api/bookings', { headers: { 'x-idempotency-key': 'idem-flow-1' }, body: payload, ip: '198.51.100.80' }), createRes);
        assert.equal(createRes.statusCode, 201);
        const bookingCode = createRes.body.data.booking.code;
        assert.ok(bookingCode);
        assert.equal(state.bookings.length, 1);

        const replayRes = makeRes();
        await bookingsIdx(makeReq('POST', '/api/bookings', { headers: { 'x-idempotency-key': 'idem-flow-1' }, body: payload, ip: '198.51.100.80' }), replayRes);
        assert.equal(replayRes.statusCode, 200);
        assert.equal(replayRes.body.data.booking.code, bookingCode);
        assert.equal(state.bookings.length, 1);

        // 3. Owner session #1 sees booking in dashboard
        const login1 = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: ownerPin }, ip: '198.51.100.81' }), login1);
        assert.equal(login1.statusCode, 200);
        const cookie1 = extractCookiePair(login1.getHeader('set-cookie'));

        const dashRes = makeRes();
        await dashboardHandler(makeReq('GET', '/api/admin/dashboard', { headers: { cookie: cookie1 } }), dashRes);
        assert.equal(dashRes.statusCode, 200);
        assert.equal(dashRes.body.data.bookings.length, 1);
        assert.equal(dashRes.body.data.bookings[0].code, bookingCode);

        // 4-5. Owner transitions to confirmada & persisted
        const confirmRes = makeRes();
        const confirmReq = makeReq('PATCH', `/api/bookings/${bookingCode}/status`, { headers: { cookie: cookie1 }, body: { status: 'confirmada' } });
        confirmReq.query = { code: bookingCode };
        await bookingStatus(confirmReq, confirmRes);
        assert.equal(confirmRes.statusCode, 200);
        assert.equal(confirmRes.body.data.booking.status, 'confirmada');

        // 6. Second independent Owner session ("device 2") sees confirmada status
        const login2 = makeRes();
        await loginHandler(makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: ownerPin }, ip: '198.51.100.82' }), login2);
        const cookie2 = extractCookiePair(login2.getHeader('set-cookie'));

        const getRes = makeRes();
        const getReq = makeReq('GET', `/api/bookings/${bookingCode}`, { headers: { cookie: cookie2 } });
        getReq.query = { code: bookingCode };
        await bookingItem(getReq, getRes);
        assert.equal(getRes.statusCode, 200);
        assert.equal(getRes.body.data.booking.status, 'confirmada');

        // 7. Cancel booking
        const cancelRes = makeRes();
        const cancelReq = makeReq('PATCH', `/api/bookings/${bookingCode}/status`, { headers: { cookie: cookie2 }, body: { status: 'cancelada' } });
        cancelReq.query = { code: bookingCode };
        await bookingStatus(cancelReq, cancelRes);
        assert.equal(cancelRes.statusCode, 200);
        assert.equal(cancelRes.body.data.booking.status, 'cancelada');

        // 8. Verify complete audit trail via /api/admin/audit
        const auditRes = makeRes();
        await auditHandler(makeReq('GET', '/api/admin/audit', { headers: { cookie: cookie1 } }), auditRes);
        assert.equal(auditRes.statusCode, 200);
        const actions = auditRes.body.data.events.map((e) => e.action);
        assert.ok(actions.includes('BOOKING_CREATED'));
        assert.ok(actions.includes('BOOKING_CONFIRMED'));
        assert.ok(actions.includes('BOOKING_CANCELLED'));
        assert.ok(actions.includes('ADMIN_LOGIN'));
      } finally {
        db.setPoolFactoryForTests(null);
      }
    });
  });

  test('30: Full HTTP dispatch through createDevServer verifies SPA + API login/dashboard/logout + 404/secret block', async () => {
    const devServer = require(path.join(__dirname, '..', 'scripts', 'dev-server.js'));
    const { Readable, Writable } = require('stream');
    const server = devServer.createDevServer();

    function runHttp(method, urlPath, headers = {}, bodyStr = '') {
      return new Promise((resolve) => {
        const req = new Readable({
          read() {
            if (bodyStr) this.push(Buffer.from(bodyStr, 'utf8'));
            this.push(null);
          }
        });
        req.method = method;
        req.url = urlPath;
        req.headers = Object.assign({ host: '127.0.0.1:3000' }, headers);
        req.socket = { remoteAddress: '127.0.0.1' };

        const chunks = [];
        const resHeaders = {};
        const res = new Writable({
          write(chunk, _enc, cb) { chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)); cb(); }
        });
        res.statusCode = 200;
        res.headersSent = false;
        res.setHeader = (k, v) => { resHeaders[String(k).toLowerCase()] = v; };
        res.getHeader = (k) => resHeaders[String(k).toLowerCase()];
        res.on('finish', () => {
          resolve({ status: res.statusCode, headers: resHeaders, body: Buffer.concat(chunks).toString('utf8') });
        });
        server.emit('request', req, res);
      });
    }

    await withEnv({
      DATABASE_URL: null,
      ADMIN_OWNER_PIN: 'dev-owner-555',
      ADMIN_IT_PIN: 'dev-it-555',
      ADMIN_SESSION_SECRET: 'dev-server-test-secret-0123456789',
      NODE_ENV: 'development'
    }, async () => {
      const rootRes = await runHttp('GET', '/');
      assert.equal(rootRes.status, 200);
      assert.match(rootRes.headers['content-type'], /text\/html/);

      const loginRes = await runHttp('POST', '/api/admin/login', { 'content-type': 'application/json' }, JSON.stringify({ role: 'owner', pin: 'dev-owner-555' }));
      assert.equal(loginRes.status, 200);
      assert.match(loginRes.headers['content-type'], /application\/json/);
      const cookiePair = String(loginRes.headers['set-cookie'] || '').split(';')[0];
      assert.match(cookiePair, /^arkik_session=/);

      const dashRes = await runHttp('GET', '/api/admin/dashboard', { cookie: cookiePair });
      assert.equal(dashRes.status, 200);
      assert.equal(JSON.parse(dashRes.body).data.role, 'owner');

      const logoutRes = await runHttp('POST', '/api/admin/logout', { cookie: cookiePair });
      assert.equal(logoutRes.status, 200);
      assert.match(String(logoutRes.headers['set-cookie'] || ''), /Max-Age=0/);

      const api404 = await runHttp('POST', '/api/not-found-route');
      assert.equal(api404.status, 404);
      assert.match(api404.headers['content-type'], /application\/json/);

      const envBlocked = await runHttp('GET', '/.env.example');
      assert.equal(envBlocked.status, 404);
    });
  });
});

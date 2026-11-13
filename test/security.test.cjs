'use strict';
// Security regression harness (run from repo root, no DB).
delete process.env.DATABASE_URL;
delete process.env.SEED_MODE;
delete process.env.ADMIN_OWNER_PIN;
delete process.env.ADMIN_IT_PIN;

const path = require('path');
const assert = require('node:assert');

function makeRes() {
  return {
    headers: {},
    statusCode: 200,
    body: undefined,
    headersSent: false,
    setHeader(name, value) { this.headers[name] = value; return this; },
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.body = payload; this.headersSent = true; return this; },
    end() { this.headersSent = true; return this; }
  };
}

function makeReq(method, url, opts) {
  opts = opts || {};
  return { method, url, headers: opts.headers || {}, query: opts.query || {}, body: opts.body };
}

async function call(file, req) {
  const handler = require(path.resolve(file));
  const res = makeRes();
  await handler(req, res);
  return res;
}

const checks = [];
function expect(name, condition, detail) {
  checks.push({ name, ok: Boolean(condition), detail });
}

(async () => {
  // F. IT/anonymous cannot execute Owner-only operations (availability PUT/DELETE, pricing PUT).
  let res = await call('api/availability/index.js', makeReq('PUT', '/api/availability', { body: {} }));
  expect('F1 availability PUT anonymous -> 401', res.statusCode === 401, JSON.stringify(res.body));

  res = await call('api/availability/index.js', makeReq('DELETE', '/api/availability', { query: { date: '2026-10-20' } }));
  expect('F2 availability DELETE anonymous -> 401', res.statusCode === 401, JSON.stringify(res.body));

  res = await call('api/admin/pricing.js', makeReq('PUT', '/api/admin/pricing', { body: {} }));
  expect('F3 pricing PUT anonymous -> 401', res.statusCode === 401, JSON.stringify(res.body));

  // G. Credentials must not appear in login error responses.
  res = await call('api/admin/login.js', makeReq('POST', '/api/admin/login', { body: { role: 'owner', pin: '0000' } }));
  const bodyStr = JSON.stringify(res.body || {});
  expect('G1 login failure does not echo pin', !bodyStr.includes('0000'), bodyStr);
  expect('G2 login failure does not leak auth details', res.body && res.body.error && !/pin|owner|it\b/i.test(res.body.error.message), bodyStr);

  // G. Logger redacts sensitive keys.
  const logMod = require(path.resolve('api/_lib/log.js'));
  const sanitized = logMod.sanitize({ pin: '1234', token: 'abc', password: 'pw', secret: 's', database_url: 'postgres://x', ok: 'value' });
  expect('G3 log redacts pin', sanitized.pin === '[redacted]', JSON.stringify(sanitized));
  expect('G4 log redacts token', sanitized.token === '[redacted]', JSON.stringify(sanitized));
  expect('G5 log redacts password', sanitized.password === '[redacted]', JSON.stringify(sanitized));
  expect('G6 log redacts secret', sanitized.secret === '[redacted]', JSON.stringify(sanitized));
  expect('G7 log redacts database_url', sanitized.database_url === '[redacted]', JSON.stringify(sanitized));
  expect('G8 log keeps non-sensitive', sanitized.ok === 'value', JSON.stringify(sanitized));

  // B. Rate limiter enforce throws rate_limited with retryAfterMs.
  const rl = require(path.resolve('api/_lib/ratelimit.js'));
  // consume would need DB; verify enforce signature exists.
  expect('B1 ratelimit.enforce is function', typeof rl.enforce === 'function', typeof rl.enforce);
  expect('B2 ratelimit.consume is function', typeof rl.consume === 'function', typeof rl.consume);

  // H. Booking creation endpoint rejects unauthenticated list (admin) but accepts POST path.
  res = await call('api/bookings/index.js', makeReq('GET', '/api/bookings'));
  expect('H1 bookings GET anonymous -> 401', res.statusCode === 401, JSON.stringify(res.body));

  // A. No global per-role bucket: verify service.login source does not contain 'login:role:'.
  const fs = require('node:fs');
  const serviceSrc = fs.readFileSync(path.resolve('api/_lib/service.js'), 'utf8');
  expect('A1 no global per-role bucket in service.login', !serviceSrc.includes('login:role:'), 'found global bucket');

  // I. Frontend syntax checks are handled by npm run check (not duplicated here).

  let failed = 0;
  for (const c of checks) {
    if (c.ok) console.log('PASS  ' + c.name);
    else { failed += 1; console.log('FAIL  ' + c.name + ' -> ' + c.detail); }
  }
  console.log('checks=' + checks.length + ' failed=' + failed);
  process.exit(failed ? 1 : 0);
})().catch((err) => {
  console.log('HARNESS ERROR: ' + (err && err.stack ? err.stack : err));
  process.exit(1);
});

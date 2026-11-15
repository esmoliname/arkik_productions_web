'use strict';
// Behavior harness for the Arkik API handlers (run from the repo root, no DB).
delete process.env.DATABASE_URL;
delete process.env.SEED_MODE;

const path = require('path');

function makeRes() {
  return {
    headers: {},
    statusCode: 200,
    body: undefined,
    headersSent: false,
    setHeader(name, value) {
      this.headers[name] = value;
      return this;
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

function makeReq(method, url, opts) {
  opts = opts || {};
  return {
    method,
    url,
    headers: opts.headers || {},
    query: opts.query || {},
    body: opts.body
  };
}

async function call(file, req) {
  const handler = require(path.resolve(file));
  const res = makeRes();
  await handler(req, res);
  return res;
}

function brief(res) {
  return JSON.stringify({ status: res.statusCode, body: res.body });
}

const checks = [];
function expect(name, condition, detail) {
  checks.push({ name, ok: Boolean(condition), detail });
}

(async () => {
  // 1. health without DATABASE_URL -> 200 pure liveness (no DB check)
  let res = await call('api/health.js', makeReq('GET', '/api/health'));
  expect(
    'health no-database 200 pure liveness',
    res.statusCode === 200 &&
      res.body &&
      res.body.success === true &&
      res.body.status === 'ok' &&
      res.body.database === 'not_checked' &&
      res.body.service === 'arkik-api' &&
      res.headers['Cache-Control'] === 'no-store',
    brief(res)
  );

  // 1a. health HEAD -> 200
  res = await call('api/health.js', makeReq('HEAD', '/api/health'));
  expect('health HEAD 200', res.statusCode === 200 && res.headers['Cache-Control'] === 'no-store', brief(res));

  // 1b. ready without DATABASE_URL -> 503 unconfigured (readiness requires DB)
  res = await call('api/ready.js', makeReq('GET', '/api/ready'));
  expect(
    'ready no-database 503 unconfigured',
    res.statusCode === 503 &&
      res.body &&
      res.body.success === false &&
      res.body.ready === false &&
      res.body.database === 'unconfigured' &&
      res.headers['Cache-Control'] === 'no-store',
    brief(res)
  );

  // 1c. ready rejects POST -> 405
  res = await call('api/ready.js', makeReq('POST', '/api/ready'));
  expect('ready POST 405', res.statusCode === 405 && res.body.error.code === 'method_not_allowed', brief(res));

  // 2. health rejects POST
  res = await call('api/health.js', makeReq('POST', '/api/health'));
  expect('health POST 405', res.statusCode === 405 && res.body.error.code === 'method_not_allowed', brief(res));

  // 3. OPTIONS preflight -> 204
  res = await call('api/bookings/index.js', makeReq('OPTIONS', '/api/bookings'));
  expect('preflight 204', res.statusCode === 204 && res.headers['Access-Control-Allow-Methods'], brief(res));

  // 4. admin session without cookie -> 401
  res = await call('api/admin/session.js', makeReq('GET', '/api/admin/session'));
  expect(
    'session unauthenticated 401',
    res.statusCode === 401 && res.body.error.code === 'unauthorized' && res.body.success === false,
    brief(res)
  );

  // 5. admin list without cookie -> 401 (auth before DB)
  res = await call('api/bookings/index.js', makeReq('GET', '/api/bookings'));
  expect('bookings GET unauthenticated 401', res.statusCode === 401, brief(res));

  // 6. status PATCH without cookie -> 401
  res = await call('api/bookings/[code]/status.js', makeReq('PATCH', '/api/bookings/ARK-X/status', { query: { code: 'ARK-X' } }));
  expect('status PATCH unauthenticated 401', res.statusCode === 401, brief(res));

  // 7. availability PUT without cookie -> 401
  res = await call('api/availability/index.js', makeReq('PUT', '/api/availability', { body: {} }));
  expect('availability PUT unauthenticated 401', res.statusCode === 401, brief(res));

  // 8. wrong method on session -> 405
  res = await call('api/admin/session.js', makeReq('DELETE', '/api/admin/session'));
  expect('session DELETE 405', res.statusCode === 405, brief(res));

  // 9. availability GET with no DATABASE_URL -> 503 service_unavailable
  res = await call('api/availability/index.js', makeReq('GET', '/api/availability'));
  expect(
    'availability GET db-down 503',
    res.statusCode === 503 && res.body.error.code === 'service_unavailable',
    brief(res)
  );

  // 10. availability GET ?date= with no DATABASE_URL -> 503 (same funnel)
  res = await call('api/availability/index.js', makeReq('GET', '/api/availability', { query: { date: '2026-10-20' } }));
  expect('availability detail db-down 503', res.statusCode === 503, brief(res));

  // 11. stats unauthenticated -> 401
  res = await call('api/admin/stats.js', makeReq('GET', '/api/admin/stats'));
  expect('stats unauthenticated 401', res.statusCode === 401, brief(res));

  // 12. audit unauthenticated -> 401
  res = await call('api/admin/audit.js', makeReq('GET', '/api/admin/audit'));
  expect('audit unauthenticated 401', res.statusCode === 401, brief(res));

  // 13. login without body -> validation path (hits DB first? rate limit before validation)
  res = await call('api/admin/login.js', makeReq('POST', '/api/admin/login', { body: {}, headers: { 'x-forwarded-for': '203.0.113.9' } }));
  expect('login db-down 503 (rate limit first)', res.statusCode === 503, brief(res));

  let failed = 0;
  for (const check of checks) {
    if (check.ok) {
      console.log('PASS  ' + check.name);
    } else {
      failed += 1;
      console.log('FAIL  ' + check.name + ' -> ' + check.detail);
    }
  }
  console.log('checks=' + checks.length + ' failed=' + failed);
  process.exit(failed ? 1 : 0);
})().catch((err) => {
  console.log('HARNESS ERROR: ' + (err && err.stack ? err.stack : err));
  process.exit(1);
});

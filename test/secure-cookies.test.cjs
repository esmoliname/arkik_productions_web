'use strict';
// Dedicated coverage for SECURE_COOKIES strict parsing and fail-closed behavior.
const assert = require('node:assert/strict');
const path = require('node:path');
const { describe, test } = require('node:test');

const REPO = path.resolve(__dirname, '..');
const config = require(path.join(REPO, 'api', '_lib', 'config.js'));
const auth = require(path.join(REPO, 'api', '_lib', 'auth.js'));
const loginHandler = require(path.join(REPO, 'api', 'admin', 'login.js'));

async function withEnv(overrides, fn) {
  const saved = {};
  for (const k of Object.keys(overrides)) {
    saved[k] = process.env[k];
    if (overrides[k] === undefined || overrides[k] === null) delete process.env[k];
    else process.env[k] = String(overrides[k]);
  }
  try { return await fn(); }
  finally {
    for (const k of Object.keys(saved)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

function makeRes() {
  return {
    headers: {}, statusCode: 200, body: undefined, headersSent: false,
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; return this; },
    getHeader(name) { return this.headers[name.toLowerCase()]; },
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.body = payload; this.headersSent = true; return this; },
    end() { this.headersSent = true; return this; }
  };
}

const SECRET = 'x'.repeat(64);

describe('SECURE_COOKIES strict parsing and fail-closed cookie policy', () => {
  test('1. SECURE_COOKIES absent in production: config.forceSecureCookies false but isProduction true', async () => {
    await withEnv({ APP_ENV: 'production', NODE_ENV: 'production', VERCEL: null, VERCEL_ENV: null, SECURE_COOKIES: null }, async () => {
      assert.equal(config.isProduction, true);
      assert.equal(config.forceSecureCookies, false);
      assert.equal(auth.isSecureCookieContext(), true);
    });
  });

  test('2. SECURE_COOKIES=false in production: still Secure (flag cannot weaken security)', async () => {
    await withEnv({ APP_ENV: 'production', NODE_ENV: 'production', VERCEL: null, VERCEL_ENV: null, SECURE_COOKIES: 'false' }, async () => {
      assert.equal(config.isProduction, true);
      assert.equal(auth.isSecureCookieContext(), true);
      assert.doesNotThrow(() => auth.assertSecureCookieAllowed());
    });
  });

  test('3. SECURE_COOKIES=true in production: Secure', async () => {
    await withEnv({ APP_ENV: 'production', NODE_ENV: 'production', VERCEL: null, VERCEL_ENV: null, SECURE_COOKIES: 'true' }, async () => {
      assert.equal(auth.isSecureCookieContext(), true);
    });
  });

  test('4. Vercel preview: always Secure regardless of SECURE_COOKIES', async () => {
    await withEnv({ APP_ENV: 'staging', NODE_ENV: 'development', VERCEL: '1', VERCEL_ENV: 'preview', SECURE_COOKIES: null }, async () => {
      assert.equal(config.isCloud, true);
      assert.equal(auth.isSecureCookieContext(), true);
      assert.doesNotThrow(() => auth.assertSecureCookieAllowed());
    });
  });

  test('5. Vercel production: always Secure', async () => {
    await withEnv({ APP_ENV: 'production', NODE_ENV: 'production', VERCEL: '1', VERCEL_ENV: 'production', SECURE_COOKIES: 'false' }, async () => {
      assert.equal(auth.isSecureCookieContext(), true);
      assert.doesNotThrow(() => auth.assertSecureCookieAllowed());
    });
  });

  test('6. Staging outside Vercel with SECURE_COOKIES=true: Secure, no throw', async () => {
    await withEnv({ APP_ENV: 'staging', NODE_ENV: 'development', VERCEL: null, VERCEL_ENV: null, SECURE_COOKIES: '1', DATABASE_URL: null, ADMIN_SESSION_SECRET: null, ADMIN_OWNER_PIN: null }, async () => {
      // need DB for login; just test config/auth
      assert.equal(config.isStagingOrPreview, true);
      assert.equal(config.forceSecureCookies, true);
      assert.equal(auth.isSecureCookieContext(), true);
      assert.doesNotThrow(() => auth.assertSecureCookieAllowed());
      const cookie = auth.sessionCookie('tok');
      assert.match(cookie, /^__Host-session=/);
      assert.match(cookie, /Secure;/);
    });
  });

  test('7. Staging outside Vercel with SECURE_COOKIES=false: fail-closed (throws)', async () => {
    await withEnv({ APP_ENV: 'staging', NODE_ENV: 'development', VERCEL: null, VERCEL_ENV: null, SECURE_COOKIES: 'false', DATABASE_URL: null, ADMIN_SESSION_SECRET: null }, async () => {
      assert.equal(config.isStagingOrPreview, true);
      assert.equal(config.forceSecureCookies, false);
      assert.equal(auth.isSecureCookieContext(), false);
      assert.throws(() => auth.assertSecureCookieAllowed(), { status: 503 });
    });
  });

  test('8. Staging outside Vercel without SECURE_COOKIES: fail-closed (throws)', async () => {
    await withEnv({ APP_ENV: 'staging', NODE_ENV: 'development', VERCEL: null, VERCEL_ENV: null, SECURE_COOKIES: null, DATABASE_URL: null, ADMIN_SESSION_SECRET: null }, async () => {
      assert.throws(() => auth.assertSecureCookieAllowed(), { status: 503 });
    });
  });

  test('9. Invalid SECURE_COOKIES value: treated as false (fail-closed in staging)', async () => {
    await withEnv({ APP_ENV: 'staging', NODE_ENV: 'development', VERCEL: null, VERCEL_ENV: null, SECURE_COOKIES: 'yes-please', DATABASE_URL: null, ADMIN_SESSION_SECRET: null }, async () => {
      assert.equal(config.forceSecureCookies, false);
      assert.throws(() => auth.assertSecureCookieAllowed(), { status: 503 });
    });
  });

  test('10. Explicit local dev HTTP: no Secure, no throw', async () => {
    await withEnv({ APP_ENV: 'development', NODE_ENV: 'development', VERCEL: null, VERCEL_ENV: null, SECURE_COOKIES: null, DATABASE_URL: null, ADMIN_SESSION_SECRET: null, ADMIN_OWNER_PIN: 'local-pin-123456' }, async () => {
      assert.equal(config.isExplicitLocalDev, true);
      assert.equal(config.isStagingOrPreview, false);
      assert.equal(auth.isSecureCookieContext(), false);
      assert.doesNotThrow(() => auth.assertSecureCookieAllowed());
      const cookie = auth.sessionCookie('tok');
      assert.match(cookie, /^arkik_session=/);
      assert.equal(/\bSecure;/.test(cookie), false);
    });
  });

  test('11. Cookie attributes: __Host-session has no Domain, HttpOnly, SameSite=Strict, Path=/', async () => {
    await withEnv({ APP_ENV: 'production', NODE_ENV: 'production', VERCEL: null, VERCEL_ENV: null, SECURE_COOKIES: null }, async () => {
      const cookie = auth.sessionCookie('tok');
      assert.match(cookie, /^__Host-session=tok;/);
      assert.match(cookie, /HttpOnly;/);
      assert.match(cookie, /Secure;/);
      assert.match(cookie, /SameSite=Strict;/);
      assert.match(cookie, /Path=\//);
      assert.ok(!/Domain=/.test(cookie));
    });
  });

  test('12. clearSessionCookie: no throw even in staging without SECURE_COOKIES', async () => {
    await withEnv({ APP_ENV: 'staging', NODE_ENV: 'development', VERCEL: null, VERCEL_ENV: null, SECURE_COOKIES: null, DATABASE_URL: null, ADMIN_SESSION_SECRET: null }, async () => {
      // clearSessionCookie must not throw (it only clears, never issues a session)
      const c = auth.clearSessionCookie();
      assert.ok(typeof c === 'string');
    });
  });
});

'use strict';
const assert = require('node:assert/strict');
const { describe, test } = require('node:test');

function withEnv(vars, fn) {
  const saved = {};
  for (const k of Object.keys(vars)) {
    saved[k] = process.env[k];
    if (vars[k] === undefined) delete process.env[k];
    else process.env[k] = vars[k];
  }
  try { return fn(); }
  finally {
    for (const k of Object.keys(vars)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

describe('auth cookies (cloudflare)', () => {
  test('cloud preview issues __Host-session with Secure, HttpOnly, SameSite, Path, no Domain', () => {
    withEnv({ DEPLOY_PLATFORM: 'cloudflare-pages', APP_ENV: 'preview', NODE_ENV: 'production', SECURE_COOKIES: '1', VERCEL: undefined, VERCEL_ENV: undefined, DATABASE_URL: undefined }, () => {
      const auth = require('../api/_lib/auth');
      const cookie = auth.sessionCookie('tok123');
      assert.ok(cookie.startsWith('__Host-session='));
      assert.ok(cookie.includes('HttpOnly'));
      assert.ok(cookie.includes('Secure'));
      assert.ok(cookie.includes('SameSite=Strict'));
      assert.ok(cookie.includes('Path=/'));
      assert.ok(!/Domain=/i.test(cookie));
      assert.ok(cookie.includes('Max-Age=900'));
    });
  });
  test('clearSessionCookie matches original attributes', () => {
    withEnv({ DEPLOY_PLATFORM: 'cloudflare-pages', APP_ENV: 'preview', NODE_ENV: 'production', SECURE_COOKIES: '1', VERCEL: undefined, VERCEL_ENV: undefined, DATABASE_URL: undefined }, () => {
      const auth = require('../api/_lib/auth');
      const cleared = auth.clearSessionCookie();
      assert.ok(cleared.startsWith('__Host-session=;'));
      assert.ok(cleared.includes('HttpOnly'));
      assert.ok(cleared.includes('Secure'));
      assert.ok(cleared.includes('SameSite=Strict'));
      assert.ok(cleared.includes('Path=/'));
      assert.ok(cleared.includes('Max-Age=0'));
    });
  });
  test('local http dev (no cloud) uses non-host cookie and no Secure by default', () => {
    withEnv({ DEPLOY_PLATFORM: undefined, APP_ENV: 'development', NODE_ENV: 'development', SECURE_COOKIES: undefined, VERCEL: undefined, VERCEL_ENV: undefined, DATABASE_URL: undefined }, () => {
      const auth = require('../api/_lib/auth');
      const cookie = auth.sessionCookie('tok123');
      assert.ok(cookie.startsWith('arkik_session='));
      assert.ok(!cookie.includes('Secure'));
    });
  });
  test('cloud preview without SECURE_COOKIES still secure (fail-closed detection)', () => {
    withEnv({ DEPLOY_PLATFORM: 'cloudflare-pages', APP_ENV: 'preview', NODE_ENV: 'production', SECURE_COOKIES: undefined, VERCEL: undefined, VERCEL_ENV: undefined, DATABASE_URL: undefined }, () => {
      const auth = require('../api/_lib/auth');
      // isCloud true => secure context; assertSecureCookieAllowed should not throw
      assert.doesNotThrow(() => auth.assertSecureCookieAllowed());
      const cookie = auth.sessionCookie('tok123');
      assert.ok(cookie.includes('Secure'));
    });
  });
});

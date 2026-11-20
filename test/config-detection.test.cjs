'use strict';
const assert = require('node:assert/strict');
const { describe, test } = require('node:test');
const config = require('../api/_lib/config');

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

describe('config cloud detection', () => {
  test('DEPLOY_PLATFORM=cloudflare-pages => isCloud true, isCloudflare true', () => {
    withEnv({ DEPLOY_PLATFORM: 'cloudflare-pages', VERCEL: undefined, VERCEL_ENV: undefined, APP_ENV: 'preview', NODE_ENV: 'production', DATABASE_URL: undefined }, () => {
      assert.equal(config.isCloudflare, true);
      assert.equal(config.isCloud, true);
      assert.equal(config.isExplicitLocalDev, false);
    });
  });
  test('Vercel still detected', () => {
    withEnv({ DEPLOY_PLATFORM: undefined, VERCEL: '1', VERCEL_ENV: 'production', APP_ENV: undefined, NODE_ENV: undefined, DATABASE_URL: undefined }, () => {
      assert.equal(config.isCloudflare, false);
      assert.equal(config.isCloud, true);
    });
  });
  test('local dev without cloud remains local dev', () => {
    withEnv({ DEPLOY_PLATFORM: undefined, VERCEL: undefined, VERCEL_ENV: undefined, APP_ENV: 'development', NODE_ENV: 'development', DATABASE_URL: undefined, SECURE_COOKIES: undefined }, () => {
      assert.equal(config.isCloud, false);
      assert.equal(config.isExplicitLocalDev, true);
    });
  });
  test('cloud preview is stagingOrPreview', () => {
    withEnv({ DEPLOY_PLATFORM: 'cloudflare-pages', APP_ENV: 'preview', NODE_ENV: 'preview', VERCEL: undefined, VERCEL_ENV: undefined, DATABASE_URL: undefined }, () => {
      assert.equal(config.isStagingOrPreview, true);
      assert.equal(config.isProduction, false);
    });
  });
  test('cloud production', () => {
    withEnv({ DEPLOY_PLATFORM: 'cloudflare-pages', APP_ENV: 'production', NODE_ENV: 'production', VERCEL: undefined, VERCEL_ENV: undefined, DATABASE_URL: undefined }, () => {
      assert.equal(config.isProduction, true);
      assert.equal(config.isStagingOrPreview, false);
    });
  });
});

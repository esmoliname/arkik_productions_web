'use strict';
const assert = require('node:assert/strict');
const { describe, test } = require('node:test');
const { runWithEnv, readEnv, getEnv } = require('../api/_lib/env-context');

describe('env-context request scoping', () => {
  test('readEnv uses store when present', async () => {
    await runWithEnv({ FOO: 'bar' }, async () => {
      assert.equal(readEnv('FOO'), 'bar');
      assert.equal(readEnv('MISSING', 'd'), 'd');
    });
  });
  test('falls back to process.env when no store', () => {
    process.env.__TEST_FALLBACK = 'fb';
    try {
      assert.equal(readEnv('__TEST_FALLBACK'), 'fb');
    } finally {
      delete process.env.__TEST_FALLBACK;
    }
  });
  test('concurrent requests do not contaminate env', async () => {
    let resolveA, resolveB;
    const pA = new Promise((r) => { resolveA = r; });
    const pB = new Promise((r) => { resolveB = r; });
    const results = {};
    const taskA = runWithEnv({ V: 'A' }, async () => {
      await pA;
      results.a = readEnv('V');
    });
    const taskB = runWithEnv({ V: 'B' }, async () => {
      await pB;
      results.b = readEnv('V');
    });
    // release B first, then A
    resolveB();
    await taskB;
    resolveA();
    await taskA;
    assert.equal(results.a, 'A');
    assert.equal(results.b, 'B');
  });
});

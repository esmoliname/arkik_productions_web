'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { describe, test } = require('node:test');

const REPO = path.resolve(__dirname, '..');
const vercel = JSON.parse(fs.readFileSync(path.join(REPO, 'vercel.json'), 'utf8'));

describe('vercel.json security headers (static regression guard)', () => {
  const root = vercel.headers.find((h) => h.source === '/(.*)');
  const keys = (root && root.headers ? root.headers : []).map((h) => h.key);

  test('Strict-Transport-Security present', () => assert.ok(keys.includes('Strict-Transport-Security')));
  test('X-Content-Type-Options present', () => assert.ok(keys.includes('X-Content-Type-Options')));
  test('X-Frame-Options present', () => assert.ok(keys.includes('X-Frame-Options')));
  test('Referrer-Policy present', () => assert.ok(keys.includes('Referrer-Policy')));
  test('Permissions-Policy present (regression guard for D2-NEW-01)', () => assert.ok(keys.includes('Permissions-Policy')));
  test('Content-Security-Policy-Report-Only present', () => assert.ok(keys.includes('Content-Security-Policy-Report-Only')));

  test('Permissions-Policy value unchanged', () => {
    const h = root.headers.find((x) => x.key === 'Permissions-Policy');
    assert.equal(h.value, 'camera=(), microphone=(), geolocation=()');
  });

  test('CSP frame-src allows YouTube embeds (D2-NEW-03)', () => {
    const h = root.headers.find((x) => x.key === 'Content-Security-Policy-Report-Only');
    assert.ok(h.value.includes("frame-src"));
    assert.ok(h.value.includes('https://www.youtube.com'));
    assert.ok(h.value.includes('https://www.youtube-nocookie.com'));
  });

  test('No duplicate header keys', () => {
    const seen = new Set();
    for (const h of root.headers) {
      assert.ok(!seen.has(h.key), 'duplicate key: ' + h.key);
      seen.add(h.key);
    }
  });
});

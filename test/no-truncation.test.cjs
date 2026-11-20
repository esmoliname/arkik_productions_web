'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { describe, test } = require('node:test');

const REPO = path.resolve(__dirname, '..');
const loginJs = fs.readFileSync(path.join(REPO, 'api', 'admin', 'login.js'), 'utf8');
const appJs = fs.readFileSync(path.join(REPO, 'js', 'app.js'), 'utf8');

describe('No silent truncation in credential flows (D2-NEW-05)', () => {
  test('api/admin/login.js sanitizePin does not use .slice(0, 64)', () => {
    assert.ok(!/\.trim\(\)\.slice\(0,\s*64\)/.test(loginJs));
  });

  test('js/app.js normalizePin does not use .slice(0, 64)', () => {
    assert.ok(!/\.trim\(\)\.slice\(0,\s*64\)/.test(appJs));
  });

  test('login.js rejects excessive input (>64)', () => {
    assert.ok(/s\.length > 64/.test(loginJs));
  });

  test('app.js rejects excessive input (>64)', () => {
    assert.ok(/s\.length > 64/.test(appJs));
  });
});

describe('UI label neutral (D2-NEW-06)', () => {
  const html = fs.readFileSync(path.join(REPO, 'index.html'), 'utf8');
  test('label does not expose scrypt or SHA-256', () => {
    assert.ok(!/PIN de Autorizaci[oó]n \(scrypt\)/.test(html));
    assert.ok(!/PIN de Autorizaci[oó]n \(SHA-256\)/.test(html));
  });
  test('label is neutral', () => {
    assert.ok(html.includes('PIN de Autorización'));
  });
});

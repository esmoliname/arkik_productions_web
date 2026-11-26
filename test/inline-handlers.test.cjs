'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { describe, test } = require('node:test');

const REPO = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(REPO, 'index.html'), 'utf8');
const appJs = fs.readFileSync(path.join(REPO, 'js', 'app.js'), 'utf8');

describe('Inline handler inventory (D2-NEW-03)', () => {
  const handlerRe = /on(click|change|submit|input|focus|blur|keydown|keyup|load|error)=/gi;
  test('index.html has 93 inline handlers', () => {
    const m = html.match(handlerRe) || [];
    assert.equal(m.length, 93);
  });
  test('js/app.js has 26 inline handlers', () => {
    const m = appJs.match(handlerRe) || [];
    assert.equal(m.length, 26);
  });
  test('total inline handlers = 119', () => {
    const a = (html.match(handlerRe) || []).length;
    const b = (appJs.match(handlerRe) || []).length;
    assert.equal(a + b, 119);
  });
});

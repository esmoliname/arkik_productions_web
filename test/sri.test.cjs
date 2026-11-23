'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { describe, test } = require('node:test');

const REPO = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(REPO, 'index.html'), 'utf8');

describe('SRI and pinned CDN versions (D2-NEW-02)', () => {
  test('html2pdf URL is pinned to 0.10.1 with valid SRI', () => {
    assert.ok(html.includes('html2pdf.js/0.10.1/html2pdf.bundle.min.js'));
    assert.ok(html.includes('integrity="sha384-Yv5O+t3uE3hunW8uyrbpPW3iw6/5/Y7HitWJBLgqfMoA36NogMmy+8wWZMpn3HWc"'));
    assert.ok(html.includes('crossorigin="anonymous"'));
  });
  test('EmailJS URL is pinned to 3.12.1 (no floating @3)', () => {
    assert.ok(html.includes('@emailjs/browser@3.12.1/dist/email.min.js'));
    assert.ok(!html.includes('@emailjs/browser@3/dist/email.min.js'));
    assert.ok(html.includes('integrity="sha384-VDbnsk/qjpIVHPQMkJiROI+vW/7cw0k8TFYVLUabm7EWoLEDwcXh09XQ6gQ86Y0B"'));
  });
  test('docx URL is pinned to 8.5.0 with valid SRI', () => {
    assert.ok(html.includes('docx@8.5.0/build/index.umd.js'));
    assert.ok(html.includes('integrity="sha384-4xaIisuLEy2lo2HkB2C4rEf7v8jbTb2kuogX6TkuEt9feTWKBSFSOzsqNNbV+sKh"'));
  });
  test('Tailwind play CDN documented as no-SRI (dynamic compiler)', () => {
    assert.ok(html.includes('cdn.tailwindcss.com'));
  });
});

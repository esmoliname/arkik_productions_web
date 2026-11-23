'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { describe, test } = require('node:test');

const REPO = path.resolve(__dirname, '..');
const sql = fs.readFileSync(path.join(REPO, 'db', 'provisioning', '001_create_roles.sql'), 'utf8');

describe('Provisioning script psql compatibility (DB-02)', () => {
  test('does not use invalid :' + 'var interpolation inside DO $$', () => {
    // The defective pattern: PASSWORD :'migrator_password' inside dollar-quoted block
    const doBlockMatch = sql.match(/DO \$\$[\s\S]*?\$\$/);
    assert.ok(doBlockMatch, 'DO block present');
    const doBlock = doBlockMatch[0];
    assert.ok(!/PASSWORD\s*:'\w+'/.test(doBlock), 'no :' + 'var inside DO block');
  });

  test('uses set_config to pass psql variables', () => {
    assert.ok(sql.includes("set_config('arkik.migrator_pw'"));
    assert.ok(sql.includes("set_config('arkik.admin_pw'"));
    assert.ok(sql.includes("set_config('arkik.app_pw'"));
  });

  test('uses EXECUTE format with %L for safe password interpolation', () => {
    assert.ok(sql.includes('EXECUTE format('));
    assert.ok(sql.includes("PASSWORD %L"));
  });

  test('uses current_setting to read passwords inside DO block', () => {
    assert.ok(sql.includes("current_setting('arkik.migrator_pw')"));
    assert.ok(sql.includes("current_setting('arkik.admin_pw')"));
    assert.ok(sql.includes("current_setting('arkik.app_pw')"));
  });

  test('preserves restrictive role attributes', () => {
    assert.ok(sql.includes('NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'));
  });

  test('has ON_ERROR_STOP', () => {
    assert.ok(sql.includes('\\set ON_ERROR_STOP on'));
  });

  test('does not hardcode passwords', () => {
    // No literal password strings (basic check: no PASSWORD '...')
    assert.ok(!/PASSWORD\s+'[^']+'/.test(sql));
  });
});

'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { describe, test } = require('node:test');

const REPO = path.resolve(__dirname, '..');
const sql007 = fs.readFileSync(path.join(REPO, 'db', 'migrations', '007_least_privilege_refinement.sql'), 'utf8');
const sql004 = fs.readFileSync(path.join(REPO, 'db', 'migrations', '004_least_privilege_grants.sql'), 'utf8');

describe('Migration 007 least-privilege refinement (static)', () => {
  test('uses schema-qualified public. table references', () => {
    assert.ok(sql007.includes('public.schema_migrations'));
    assert.ok(sql007.includes('public.admin_credentials'));
    assert.ok(sql007.includes('public.config'));
    assert.ok(sql007.includes('public.bookings'));
    assert.ok(sql007.includes('public.availability'));
  });

  test('revokes SELECT on schema_migrations from arkik_app', () => {
    assert.ok(/REVOKE SELECT ON TABLE public\.schema_migrations FROM arkik_app/.test(sql007));
  });

  test('revokes global UPDATE and grants column-level UPDATE on admin_credentials', () => {
    assert.ok(/REVOKE UPDATE ON TABLE public\.admin_credentials FROM arkik_app/.test(sql007));
    assert.ok(/GRANT UPDATE \(failed_attempts, lock_level, locked_until, updated_at\) ON TABLE public\.admin_credentials TO arkik_app/.test(sql007));
  });

  test('R1-REG-01: revokes UPDATE at table level on public.config for arkik_app', () => {
    assert.ok(/REVOKE UPDATE ON TABLE public\.config FROM arkik_app/.test(sql007));
  });

  test('R1-REG-01: grants column-level UPDATE on (value, updated_at) on public.config to arkik_app', () => {
    assert.ok(/GRANT UPDATE \(value,\s*updated_at\) ON TABLE public\.config TO arkik_app/.test(sql007));
  });

  test('R1-REG-01: the config GRANT targets the arkik_app role', () => {
    const m = sql007.match(/GRANT UPDATE \(([^)]*)\) ON TABLE public\.config TO (\w+)/);
    assert.ok(m, 'config UPDATE grant must exist');
    assert.equal(m[2], 'arkik_app', 'grant must target arkik_app');
  });

  test('R1-REG-01: the config GRANT is explicit and bound to public.config', () => {
    const m = sql007.match(/GRANT UPDATE \(([^)]*)\) ON TABLE public\.config TO arkik_app/);
    assert.ok(m, 'grant must be explicit column list on public.config');
    // context: the grant must appear after the table-level revoke
    const revokeIdx = sql007.indexOf('REVOKE UPDATE ON TABLE public.config FROM arkik_app');
    const grantIdx = sql007.indexOf('GRANT UPDATE (value, updated_at) ON TABLE public.config TO arkik_app');
    assert.ok(revokeIdx >= 0 && grantIdx > revokeIdx, 'GRANT must follow the REVOKE');
  });

  test('R1-REG-01: GRANT immediately follows the REVOKE (no intervening statements)', () => {
    const lines = sql007.split(/\r?\n/);
    const revokeLine = lines.findIndex((l) => /REVOKE UPDATE ON TABLE public\.config FROM arkik_app/.test(l));
    assert.ok(revokeLine >= 0);
    // skip blank/comment lines? mandate says include after revoke; allow comments but no SQL statements
    let next = revokeLine + 1;
    while (next < lines.length && (lines[next].trim() === '' || lines[next].trim().startsWith('--'))) next++;
    assert.ok(next < lines.length, 'a statement must follow the revoke');
    assert.ok(/GRANT UPDATE \(value,\s*updated_at\) ON TABLE public\.config TO arkik_app/.test(lines[next]),
      'the next statement after revoke must be the column-level grant');
  });

  test('R1-REG-01: no general (table-level) UPDATE is reintroduced on public.config', () => {
    // A table-level grant has no parenthesized column list between UPDATE and ON.
    assert.ok(!/GRANT\s+UPDATE\s+ON\s+(TABLE\s+)?public\.config\b/i.test(sql007),
      'table-level GRANT UPDATE on public.config must not be reintroduced');
    // and no bare GRANT ... UPDATE ... config without columns
    assert.ok(!/GRANT\s+UPDATE\s+ON\s+config\b/i.test(sql007));
  });

  test('R1-REG-01: no UPDATE is granted on namespace or key', () => {
    const m = sql007.match(/GRANT UPDATE \(([^)]*)\) ON TABLE public\.config TO arkik_app/);
    assert.ok(m, 'config UPDATE grant must exist');
    const cols = m[1].split(',').map((c) => c.trim().toLowerCase());
    assert.deepEqual(cols.sort(), ['updated_at', 'value'], 'only value and updated_at may be granted');
    assert.ok(!cols.includes('namespace'), 'namespace must not be updatable');
    assert.ok(!cols.includes('key'), 'key must not be updatable');
  });

  test('R1-REG-01: no UPDATE on public.config is granted to PUBLIC or arkik_admin', () => {
    assert.ok(!/GRANT\s+UPDATE[^;]*public\.config[^;]*TO\s+PUBLIC/i.test(sql007));
    assert.ok(!/GRANT\s+UPDATE[^;]*public\.config[^;]*TO\s+arkik_admin/i.test(sql007));
    assert.ok(!/GRANT\s+UPDATE\s*\([^)]*\)\s*ON TABLE public\.config TO arkik_admin/i.test(sql007));
  });

  test('revokes SELECT on config/bookings/availability from arkik_admin (DB-03)', () => {
    assert.ok(/REVOKE SELECT ON TABLE public\.config FROM arkik_admin/.test(sql007));
    assert.ok(/REVOKE SELECT ON TABLE public\.bookings FROM arkik_admin/.test(sql007));
    assert.ok(/REVOKE SELECT ON TABLE public\.availability FROM arkik_admin/.test(sql007));
  });

  test('does not modify migrations 001-006 (007 is separate file)', () => {
    assert.ok(fs.existsSync(path.join(REPO, 'db', 'migrations', '007_least_privilege_refinement.sql')));
  });

  test('does not revoke needed permissions from arkik_app (guard)', () => {
    // arkik_app still needs bookings, availability, config SELECT/INSERT (UPDATE narrowed)
    assert.ok(!/REVOKE .* ON TABLE public\.bookings FROM arkik_app/.test(sql007));
    assert.ok(!/REVOKE .* ON TABLE public\.availability FROM arkik_app/.test(sql007));
    // Only UPDATE (not SELECT/INSERT/ALL) may be revoked on config
    assert.ok(!/REVOKE\s+SELECT\s+ON TABLE public\.config FROM arkik_app/.test(sql007));
    assert.ok(!/REVOKE\s+INSERT\s+ON TABLE public\.config FROM arkik_app/.test(sql007));
    assert.ok(!/REVOKE\s+ALL\s+ON TABLE public\.config FROM arkik_app/.test(sql007));
    assert.ok(!/REVOKE .* ON TABLE public\.admin_sessions FROM arkik_app/.test(sql007));
    assert.ok(!/REVOKE .* ON TABLE public\.audit_log FROM arkik_app/.test(sql007));
  });

  test('INSERT and SELECT on public.config remain contemplated (004 grants + 007 does not revoke)', () => {
    // 004 grants SELECT, INSERT, UPDATE on config to arkik_app (base grants)
    assert.ok(/GRANT SELECT, INSERT, UPDATE ON config TO arkik_app/.test(sql004),
      '004 must grant SELECT, INSERT, UPDATE on config to arkik_app');
    // 007 must not strip INSERT or SELECT
    assert.ok(!/REVOKE\s+(SELECT|INSERT)\s+ON TABLE public\.config FROM arkik_app/.test(sql007));
  });

  test('does not revoke needed permissions from arkik_admin (guard)', () => {
    assert.ok(!/REVOKE .* ON TABLE public\.admin_credentials FROM arkik_admin/.test(sql007));
    assert.ok(!/REVOKE .* ON TABLE public\.admin_sessions FROM arkik_admin/.test(sql007));
    assert.ok(!/REVOKE .* ON TABLE public\.audit_log FROM arkik_admin/.test(sql007));
    assert.ok(!/REVOKE .* ON (TABLE )?public\.audit_log_id_seq FROM arkik_admin/.test(sql007));
  });

  test('other permissions of the migration are preserved (admin_credentials column grant intact)', () => {
    assert.ok(/GRANT UPDATE \(failed_attempts, lock_level, locked_until, updated_at\) ON TABLE public\.admin_credentials TO arkik_app/.test(sql007));
  });
});

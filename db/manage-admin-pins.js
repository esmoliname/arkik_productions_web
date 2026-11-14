'use strict';
// Arkik Productions - Explicit, audited admin PIN verification & rotation CLI.
//
// Usage:
//   node db/manage-admin-pins.js verify
//   node db/manage-admin-pins.js rotate --role owner --confirm [--from-env NEW_OWNER_PIN] [--reason "ticket-123"]
//   node db/manage-admin-pins.js hash --from-env NEW_OWNER_PIN
//
// Security invariants:
// - Never prints raw PINs or stored scrypt hashes.
// - Never reads plaintext PINs from command-line arguments (prevents shell/process leaks).
// - Rotation requires explicit --confirm and runs in a single transaction that
//   updates admin_credentials, revokes active admin_sessions for that role, and
//   writes an ADMIN_CREDENTIAL_ROTATED record to audit_log.

const fs = require('fs');
const { loadEnvFiles } = require('./migrate');
const auth = require('../api/_lib/auth');

const ROLE_ENV_CANDIDATES = {
  owner: ['ADMIN_OWNER_PIN', 'ADMIN_PIN_OWNER'],
  it: ['ADMIN_IT_PIN', 'ADMIN_PIN_IT']
};

function resolveEnvPin(role, env = process.env) {
  const keys = ROLE_ENV_CANDIDATES[role] || [];
  for (const key of keys) {
    const raw = env[key];
    if (typeof raw === 'string' && raw.trim().length > 0) {
      return { key, value: raw.trim() };
    }
  }
  return null;
}

function parseArgs(argv) {
  const args = argv.slice(2);
  const command = args[0] && !args[0].startsWith('--') ? args[0] : 'help';
  const flags = { _: [] };
  for (let i = command === 'help' && (!args[0] || args[0].startsWith('--')) ? 0 : 1; i < args.length; i += 1) {
    const token = args[i];
    if (!token.startsWith('--')) {
      flags._.push(token);
      continue;
    }
    const eqIdx = token.indexOf('=');
    if (eqIdx !== -1) {
      flags[token.slice(2, eqIdx)] = token.slice(eqIdx + 1);
      continue;
    }
    const name = token.slice(2);
    if (name === 'confirm' || name === 'json') {
      flags[name] = true;
      continue;
    }
    const next = args[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      flags[name] = next;
      i += 1;
    } else {
      flags[name] = true;
    }
  }
  return { command, flags };
}

async function verifyAdminPins(pool, env = process.env) {
  const { rows } = await pool.query(
    'SELECT role, pin_hash, failed_attempts, lock_level, locked_until, updated_at FROM admin_credentials ORDER BY role ASC'
  );
  const byRole = new Map();
  for (const row of rows || []) {
    byRole.set(String(row.role), row);
  }

  const results = [];
  for (const role of ['owner', 'it']) {
    const row = byRole.get(role);
    const configured = resolveEnvPin(role, env);
    if (!row) {
      results.push({
        role,
        status: 'MISSING',
        failedAttempts: 0,
        lockLevel: 0,
        lockedUntil: null,
        updatedAt: null,
        envKey: configured ? configured.key : null,
        envCheck: configured ? 'MISSING_DB_ROW' : 'NO_ENV_PIN'
      });
      continue;
    }

    const validFormat = auth.isValidScryptHash(row.pin_hash);
    if (!validFormat) {
      results.push({
        role,
        status: 'CORRUPTED_HASH',
        failedAttempts: Number(row.failed_attempts || 0),
        lockLevel: Number(row.lock_level || 0),
        lockedUntil: row.locked_until || null,
        updatedAt: row.updated_at || null,
        envKey: configured ? configured.key : null,
        envCheck: 'UNVERIFIABLE'
      });
      continue;
    }

    let envCheck = 'NO_ENV_PIN';
    let status = 'VALID_HASH';
    if (configured) {
      let matched = false;
      if (configured.value.startsWith('scrypt$')) {
        matched = auth.isValidScryptHash(configured.value) && configured.value === row.pin_hash;
      } else {
        matched = await auth.verifyPin(configured.value, row.pin_hash);
      }
      envCheck = matched ? 'MATCH' : 'MISMATCH';
      status = matched ? 'MATCH' : 'MISMATCH';
    }

    results.push({
      role,
      status,
      failedAttempts: Number(row.failed_attempts || 0),
      lockLevel: Number(row.lock_level || 0),
      lockedUntil: row.locked_until || null,
      updatedAt: row.updated_at || null,
      envKey: configured ? configured.key : null,
      envCheck
    });
  }

  return results;
}

function normalizeAndValidateSecretInput(rawInput) {
  const value = String(rawInput || '').trim();
  if (!value) {
    throw new Error('PIN input is empty.');
  }
  if (value.startsWith('scrypt$')) {
    if (!auth.isValidScryptHash(value)) {
      throw new Error('Provided scrypt$ value has an invalid format.');
    }
    return { pinHash: value, isPreHashed: true };
  }
  if (value.length < 4 || value.length > 64) {
    throw new Error('PIN length must be between 4 and 64 characters.');
  }
  return { pinHash: null, plaintext: value, isPreHashed: false };
}

async function generateScryptHash(rawInput) {
  const parsed = normalizeAndValidateSecretInput(rawInput);
  if (parsed.isPreHashed) {
    return parsed.pinHash;
  }
  return auth.hashPin(parsed.plaintext);
}

async function rotateAdminPin(pool, options = {}) {
  const role = String(options.role || '').trim().toLowerCase();
  if (role !== 'owner' && role !== 'it') {
    throw new Error('Invalid --role. Allowed values: owner | it.');
  }
  if (!options.confirm) {
    throw new Error('Rotation aborted: pass --confirm explicitly to overwrite admin_credentials.');
  }
  const pinHash = await generateScryptHash(options.rawPin);
  const actor = String(options.actor || 'cli:manage-admin-pins').slice(0, 80);
  const reason = String(options.reason || 'manual_rotation').slice(0, 200);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const upsertRes = await client.query(
      `INSERT INTO admin_credentials (role, pin_hash, failed_attempts, lock_level, locked_until, updated_at)
       VALUES ($1, $2, 0, 0, NULL, NOW())
       ON CONFLICT (role) DO UPDATE
         SET pin_hash = EXCLUDED.pin_hash,
             failed_attempts = 0,
             lock_level = 0,
             locked_until = NULL,
             updated_at = NOW()
       RETURNING updated_at`,
      [role, pinHash]
    );
    const delRes = await client.query(
      'DELETE FROM admin_sessions WHERE role = $1',
      [role]
    );
    const row = upsertRes.rows && upsertRes.rows[0] ? upsertRes.rows[0] : {};
    const meta = {
      role,
      revokedSessions: Number(delRes.rowCount || 0),
      lockReset: true,
      reason
    };
    const auditRes = await client.query(
      `INSERT INTO audit_log (action, entity_type, entity_id, actor, metadata)
       VALUES ('ADMIN_CREDENTIAL_ROTATED', 'admin_credential', $1, $2, $3::jsonb)
       RETURNING id`,
      [role, actor, JSON.stringify(meta)]
    );
    await client.query('COMMIT');
    const auditId = auditRes.rows && auditRes.rows[0] ? auditRes.rows[0].id : null;
    return {
      ok: true,
      role,
      revokedSessions: meta.revokedSessions,
      auditId,
      updatedAt: row.updated_at || null
    };
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (_) {
      // Ignore secondary rollback failure; rethrow original error.
    }
    throw err;
  } finally {
    client.release();
  }
}

function readSecretFromEnvOrStdin(flags, role, env = process.env) {
  if (flags.pin) {
    throw new Error('Refusing --pin on command line argv; use --from-env <VAR>, role env vars, or stdin.');
  }
  if (typeof flags['from-env'] === 'string' && flags['from-env'].trim()) {
    const varName = flags['from-env'].trim();
    const val = env[varName];
    if (!val || !String(val).trim()) {
      throw new Error(`Environment variable "${varName}" is empty or undefined.`);
    }
    return String(val).trim();
  }
  if (!process.stdin.isTTY) {
    try {
      const stdinText = fs.readFileSync(0, 'utf8').trim();
      if (stdinText) return stdinText;
    } catch (_) {
      // Ignore empty/non-readable stdin stream and fall back cleanly.
    }
  }
  if (role) {
    const roleEnv = resolveEnvPin(role, env);
    if (roleEnv) return roleEnv.value;
  }
  throw new Error('No PIN provided. Pass --from-env <ENV_VAR>, set ADMIN_OWNER_PIN/ADMIN_IT_PIN, or pipe via stdin.');
}

async function createPool() {
  const dbUrl = String(process.env.DATABASE_URL || '').trim();
  if (!dbUrl) {
    throw new Error('DATABASE_URL is not configured (set it in environment or .env.local).');
  }
  const { Pool } = require('@neondatabase/serverless');
  return new Pool({ connectionString: dbUrl });
}

function printHelp() {
  console.log([
    'Arkik Admin Credential Utility (zero-secret output)',
    '',
    'Commands:',
    '  node db/manage-admin-pins.js verify',
    '  node db/manage-admin-pins.js rotate --role <owner|it> --confirm [--from-env VAR] [--reason TEXT]',
    '  node db/manage-admin-pins.js hash --from-env VAR'
  ].join('\n'));
}

async function main() {
  loadEnvFiles();
  const { command, flags } = parseArgs(process.argv);

  if (command === 'help' || flags.help) {
    printHelp();
    return;
  }

  if (command === 'hash') {
    const rawPin = readSecretFromEnvOrStdin(flags, null, process.env);
    const hash = await generateScryptHash(rawPin);
    console.log(hash);
    return;
  }

  if (command !== 'verify' && command !== 'rotate') {
    throw new Error(`Unknown command "${command}". Run with "help" for usage.`);
  }

  let validatedRotate = null;
  if (command === 'rotate') {
    const role = String(flags.role || '').trim().toLowerCase();
    if (role !== 'owner' && role !== 'it') {
      throw new Error('Invalid --role. Allowed values: owner | it.');
    }
    if (!flags.confirm) {
      throw new Error('Rotation aborted: pass --confirm explicitly to overwrite admin_credentials.');
    }
    const rawPin = readSecretFromEnvOrStdin(flags, role, process.env);
    const pinHash = await generateScryptHash(rawPin);
    validatedRotate = { role, confirm: true, rawPin: pinHash, reason: flags.reason };
  }

  const pool = await createPool();
  try {
    if (command === 'verify') {
      const report = await verifyAdminPins(pool, process.env);
      if (flags.json) {
        console.log(JSON.stringify(report, null, 2));
      } else {
        for (const item of report) {
          console.log(
            `[admin-verify] role=${item.role} status=${item.status} env=${item.envCheck}${item.envKey ? `(${item.envKey})` : ''} failedAttempts=${item.failedAttempts} lockLevel=${item.lockLevel}`
          );
        }
      }
      const hasProblem = report.some(
        (r) => r.status === 'MISSING' || r.status === 'CORRUPTED_HASH' || r.status === 'MISMATCH'
      );
      if (hasProblem) process.exitCode = 2;
      return;
    }

    if (command === 'rotate') {
      const outcome = await rotateAdminPin(pool, validatedRotate);
      console.log(
        `[admin-rotate] role=${outcome.role} revokedSessions=${outcome.revokedSessions} auditId=${outcome.auditId}`
      );
      return;
    }
  } finally {
    await pool.end().catch(() => {});
  }
}

function sanitizeErrorMessage(err) {
  const raw = err && err.message ? String(err.message) : String(err);
  return raw
    .replace(/postgres(ql)?:\/\/\S+/gi, '[redacted-db-url]')
    .replace(/scrypt\$\S+/gi, '[redacted-hash]');
}

module.exports = {
  verifyAdminPins,
  rotateAdminPin,
  generateScryptHash,
  parseArgs,
  resolveEnvPin
};

if (require.main === module) {
  main().catch((err) => {
    console.error('[admin-pins] Failed:', sanitizeErrorMessage(err));
    process.exit(1);
  });
}

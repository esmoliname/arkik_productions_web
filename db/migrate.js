'use strict';
// Arkik Productions - idempotent migration runner.
//   node db/migrate.js   (npm run db:migrate)
// Applies db/migrations/*.sql in order, each file inside one transaction,
// recording the file name in schema_migrations. Never DROP/TRUNCATE.
// Sanitized output only: DATABASE_URL and PINs are never printed.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const auth = require('../api/_lib/auth');
const { loadEnvFiles, safeError, createDirectPool } = require('./_lib/direct-db');

const MIGRATIONS_DIR = path.join(__dirname, 'migrations');
const MIGRATION_FILE_RE = /^(\d{3,})_([a-z0-9_]+)\.sql$/i;
const MIGRATION_LOCK_KEY = 'arkik_migrations';
const PIN_MIN_LENGTH = 6;
const PIN_MAX_LENGTH = 64;

function computeChecksum(sql) {
  return crypto.createHash('sha256').update(String(sql || ''), 'utf8').digest('hex');
}

function hasNoTxDirective(sql) {
  // AUD-02 (deferred): no-tx migrations execute as submitted; do not split naively on ";"
  // because dollar-quoted bodies, comments, and string literals require a full SQL lexer/parser.
  return /^\s*--\s*arkik:no-tx\b/im.test(String(sql || ''));
}

function parseMigrationFilename(name) {
  const match = MIGRATION_FILE_RE.exec(String(name || ''));
  if (!match) return null;
  return {
    version: name,
    prefix: Number.parseInt(match[1], 10)
  };
}

function getOrderedMigrationFiles(dir = MIGRATIONS_DIR) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const parsed = [];
  const seenPrefixes = new Set();

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    if (!entry.name.toLowerCase().endsWith('.sql')) continue;
    const info = parseMigrationFilename(entry.name);
    if (!info) {
      throw new Error(
        `Invalid migration filename "${entry.name}". Expected numeric prefix format like "004_description.sql".`
      );
    }
    if (seenPrefixes.has(info.prefix)) {
      throw new Error(`Duplicate migration numeric prefix ${info.prefix} found at "${entry.name}".`);
    }
    seenPrefixes.add(info.prefix);
    parsed.push(info);
  }

  parsed.sort((a, b) => (a.prefix !== b.prefix ? a.prefix - b.prefix : a.version.localeCompare(b.version)));
  return parsed.map((item) => item.version);
}

function validateBootstrapPin(rawPin, role) {
  if (rawPin.startsWith('scrypt$')) {
    if (!auth.isValidScryptHash(rawPin)) {
      throw new Error(`Invalid pre-hashed scrypt string supplied for role "${role}"`);
    }
    return { isPreHashed: true, pinHash: rawPin };
  }
  if (rawPin.length < PIN_MIN_LENGTH || rawPin.length > PIN_MAX_LENGTH) {
    throw new Error(
      `Admin PIN for role "${role}" must be between ${PIN_MIN_LENGTH} and ${PIN_MAX_LENGTH} characters.`
    );
  }
  return { isPreHashed: false, pinHash: null };
}

// Seed admin_credentials from env pins inside one transaction. Existing rows are NEVER rotated automatically.
async function bootstrapAdmins(dbOrClient, env = process.env) {
  const isPool = dbOrClient && typeof dbOrClient.connect === 'function' && typeof dbOrClient.totalCount === 'number';
  const client = isPool ? await dbOrClient.connect() : dbOrClient;
  let begun = false;

  try {
    await client.query('BEGIN');
    begun = true;

    const existing = await client.query('SELECT role, pin_hash FROM admin_credentials');
    const existingByRole = new Map();
    for (const row of existing.rows || []) {
      existingByRole.set(row.role, row);
    }

    const targets = [
      { role: 'owner', envNames: ['ADMIN_OWNER_PIN', 'ADMIN_PIN_OWNER'] },
      { role: 'it', envNames: ['ADMIN_IT_PIN', 'ADMIN_PIN_IT'] }
    ];

    for (const target of targets) {
      let rawPin = '';
      for (const name of target.envNames) {
        const candidate = (env[name] || '').trim();
        if (candidate) {
          rawPin = candidate;
          break;
        }
      }

      const existingRow = existingByRole.get(target.role);
      if (existingRow) {
        if (typeof existingRow.pin_hash === 'string') {
          if (!auth.isValidScryptHash(existingRow.pin_hash)) {
            console.warn(
              `[ARKIK DB] WARNING: stored credential hash for role "${target.role}" is corrupted. Run "npm run admin:verify" and "npm run admin:rotate -- --role ${target.role} --confirm" to fix it.`
            );
          } else if (rawPin) {
            if (rawPin.startsWith('scrypt$') && !auth.isValidScryptHash(rawPin)) {
              console.warn(
                `[ARKIK DB] WARNING: env pre-hashed scrypt string for role "${target.role}" has invalid format (DB credential unchanged).`
              );
            } else {
              const matches = rawPin.startsWith('scrypt$')
                ? rawPin === existingRow.pin_hash
                : await auth.verifyPin(rawPin, existingRow.pin_hash);
              if (!matches) {
                console.warn(
                  `[ARKIK DB] WARNING: role "${target.role}" already exists in admin_credentials and does NOT match the current env PIN (never overwritten automatically). Run "npm run admin:rotate -- --role ${target.role} --confirm" to update it intentionally.`
                );
              }
            }
          }
        }
        continue;
      }

      if (!rawPin) continue;

      const validated = validateBootstrapPin(rawPin, target.role);
      const pinHash = validated.isPreHashed ? validated.pinHash : auth.hashPin(rawPin);

      await client.query(
        'INSERT INTO admin_credentials (role, pin_hash) VALUES ($1, $2) ON CONFLICT (role) DO NOTHING',
        [target.role, pinHash]
      );
      console.log(`[ARKIK DB] admin credentials bootstrapped for role "${target.role}"`);
    }

    await client.query('COMMIT');
    begun = false;

    const after = await client.query('SELECT role FROM admin_credentials');
    const presentRoles = new Set((after.rows || []).map((r) => String(r.role)));
    const missingRoles = ['owner', 'it'].filter((role) => !presentRoles.has(role));

    if (missingRoles.length === 2) {
      console.warn('[ARKIK DB] WARNING: no admin credentials exist. Admin login stays unavailable');
      console.warn(
        '[ARKIK DB] WARNING: until ADMIN_OWNER_PIN / ADMIN_IT_PIN (>= 6 chars) are set and this runner is re-executed.'
      );
    } else if (missingRoles.length > 0) {
      for (const missingRole of missingRoles) {
        console.warn(
          `[ARKIK DB] WARNING: admin role "${missingRole}" is NOT initialized in admin_credentials. Login for "${missingRole}" will fail until configured and re-migrated.`
        );
      }
    }
  } catch (err) {
    if (begun) {
      try {
        await client.query('ROLLBACK');
      } catch (_rollbackErr) {
        // Ignore rollback noise on broken socket
      }
    }
    throw err;
  } finally {
    if (isPool && typeof client.release === 'function') {
      try {
        client.release();
      } catch (_releaseErr) {
        // Ignore
      }
    }
  }
}

async function runMigrations(options = {}) {
  const env = options.env || process.env;
  const migrationsDir = options.migrationsDir || MIGRATIONS_DIR;
  let pool = options.pool || null;
  let ownsPool = false;

  if (!pool) {
    loadEnvFiles();
    const created = await createDirectPool({
      env,
      envVarName: 'DIRECT_DATABASE_URL',
      silent: Boolean(options.silent)
    });
    pool = created.pool;
    ownsPool = true;
  }

  const client = await pool.connect();
  let lockAcquired = false;

  try {
    // Hold session advisory lock on ONE Direct client across schema_migrations, DDL files, and bootstrapAdmins.
    await client.query('SELECT pg_advisory_lock(hashtext($1))', [MIGRATION_LOCK_KEY]);
    lockAcquired = true;

    await client.query(
      'CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now(), checksum text)'
    );
    await client.query('ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum text');

    const appliedRows = await client.query('SELECT version, checksum FROM schema_migrations');
    const applied = new Map();
    for (const row of appliedRows.rows || []) {
      applied.set(row.version, row.checksum || null);
    }

    const files = getOrderedMigrationFiles(migrationsDir);

    for (const file of files) {
      const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
      const checksum = computeChecksum(sql);

      if (applied.has(file)) {
        const storedChecksum = applied.get(file);
        if (storedChecksum && storedChecksum !== checksum) {
          throw new Error(
            `Migration checksum mismatch for "${file}". Applied migrations must remain immutable.`
          );
        }
        console.log(`[ARKIK DB] skipped  ${file}`);
        continue;
      }

      if (hasNoTxDirective(sql)) {
        try {
          await client.query('SET lock_timeout = 5000');
          await client.query('SET statement_timeout = 60000');
          await client.query(sql);
          await client.query('INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)', [
            file,
            checksum
          ]);
          console.log(`[ARKIK DB] applied  ${file} (no-tx)`);
        } catch (err) {
          console.error(`[ARKIK DB] FAILED   ${file}: ${safeError(err)}`);
          throw err;
        } finally {
          await client.query('RESET lock_timeout; RESET statement_timeout;').catch(() => { });
        }
        continue;
      }

      try {
        await client.query('BEGIN');
        await client.query(
          'SET LOCAL lock_timeout = 5000; SET LOCAL statement_timeout = 60000; SET LOCAL idle_in_transaction_session_timeout = 60000;'
        );
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)', [
          file,
          checksum
        ]);
        await client.query('COMMIT');
        console.log(`[ARKIK DB] applied  ${file}`);
      } catch (err) {
        try {
          await client.query('ROLLBACK');
        } catch (_rollbackErr) {
          // ignore: connection already broken
        }
        console.error(`[ARKIK DB] FAILED   ${file}: ${safeError(err)}`);
        throw err;
      }
    }

    await bootstrapAdmins(client, env);
    console.log('[ARKIK DB] schema is up to date.');
  } finally {
    if (lockAcquired) {
      await client.query('SELECT pg_advisory_unlock(hashtext($1))', [MIGRATION_LOCK_KEY]).catch(() => { });
    }
    try {
      client.release();
    } catch (_releaseErr) {
      // ignore
    }
    if (ownsPool && typeof pool.end === 'function') {
      try {
        await pool.end();
      } catch (_endErr) {
        // ignore shutdown noise
      }
    }
  }
}

async function main() {
  return runMigrations();
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`[ARKIK DB] ERROR: ${safeError(err)}`);
    process.exit(1);
  });
}

module.exports = {
  loadEnvFiles,
  bootstrapAdmins,
  runMigrations,
  getOrderedMigrationFiles,
  parseMigrationFilename,
  computeChecksum,
  hasNoTxDirective
};

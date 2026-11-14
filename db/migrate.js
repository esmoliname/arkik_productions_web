'use strict';
// Arkik Productions - idempotent migration runner.
//   node db/migrate.js   (npm run db:migrate)
// Applies db/migrations/*.sql in order, each file inside one transaction,
// recording the file name in schema_migrations. Never DROP/TRUNCATE.
// Sanitized output only: DATABASE_URL and PINs are never printed.

const fs = require('fs');
const path = require('path');

const MIGRATIONS_DIR = path.join(__dirname, 'migrations');
const ENV_FILES = ['.env.local', '.env'];

// Minimal KEY=VALUE reader (no dotenv dependency). Existing env wins.
function loadEnvFiles() {
  const roots = [process.cwd(), path.join(__dirname, '..')];
  const seen = new Set();
  for (const root of roots) {
    for (const file of ENV_FILES) {
      const full = path.join(root, file);
      if (seen.has(full)) continue;
      seen.add(full);
      if (!fs.existsSync(full)) continue;
      let raw = '';
      try {
        raw = fs.readFileSync(full, 'utf8');
      } catch (err) {
        continue;
      }
      for (const line of raw.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const separator = trimmed.indexOf('=');
        if (separator <= 0) continue;
        const key = trimmed.slice(0, separator).trim();
        if (!key || Object.prototype.hasOwnProperty.call(process.env, key)) continue;
        let value = trimmed.slice(separator + 1).trim();
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }
        process.env[key] = value;
      }
    }
  }
}

function safeError(err) {
  const message = err && err.message ? String(err.message) : String(err);
  return message.replace(/postgres(ql)?:\/\/\S+/gi, '[redacted]');
}

// Seed admin_credentials from env pins. Existing rows are NEVER rotated automatically.
async function bootstrapAdmins(pool) {
  const auth = require('../api/_lib/auth');

  const existing = await pool.query('SELECT role, pin_hash FROM admin_credentials');
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
      const candidate = (process.env[name] || '').trim();
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
      continue;
    }

    if (!rawPin) continue;

    let pinHash;
    if (rawPin.startsWith('scrypt$')) {
      if (!auth.isValidScryptHash(rawPin)) {
        throw new Error(`Invalid pre-hashed scrypt string supplied for role "${target.role}"`);
      }
      pinHash = rawPin;
    } else {
      pinHash = auth.hashPin(rawPin);
    }

    await pool.query('INSERT INTO admin_credentials (role, pin_hash) VALUES ($1, $2) ON CONFLICT (role) DO NOTHING', [
      target.role,
      pinHash
    ]);
    console.log(`[ARKIK DB] admin credentials bootstrapped for role "${target.role}"`);
  }

  const after = await pool.query('SELECT role FROM admin_credentials');
  if (after.rows.length === 0) {
    console.warn('[ARKIK DB] WARNING: no admin credentials exist. Admin login stays unavailable');
    console.warn('[ARKIK DB] WARNING: until ADMIN_OWNER_PIN / ADMIN_PIN_OWNER or ADMIN_IT_PIN / ADMIN_PIN_IT are set and this runner is re-executed.');
  }
}

async function main() {
  loadEnvFiles();

  const databaseUrl = (process.env.DATABASE_URL || '').trim();
  if (!databaseUrl) {
    console.error('[ARKIK DB] ERROR: DATABASE_URL is not configured.');
    console.error('[ARKIK DB] Set DATABASE_URL in .env.local (local) or in Vercel environment variables, then retry.');
    process.exit(1);
  }

  let Pool;
  try {
    const mod = await import('@neondatabase/serverless');
    Pool = mod.Pool || (mod.default && mod.default.Pool);
    if (typeof Pool !== 'function') throw new Error('Pool export missing');
  } catch (err) {
    console.error('[ARKIK DB] ERROR: @neondatabase/serverless is not installed or failed to load.');
    console.error('[ARKIK DB] Run "npm install" and retry.');
    process.exit(1);
  }

  const pool = new Pool({ connectionString: databaseUrl, max: 1 });
  try {
    await pool.query(
      'CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())'
    );

    const applied = new Set((await pool.query('SELECT version FROM schema_migrations')).rows.map((row) => row.version));
    const files = fs
      .readdirSync(MIGRATIONS_DIR)
      .filter((name) => name.toLowerCase().endsWith('.sql'))
      .sort();

    for (const file of files) {
      if (applied.has(file)) {
        console.log(`[ARKIK DB] skipped  ${file}`);
        continue;
      }
      const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, file), 'utf8');
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (version) VALUES ($1)', [file]);
        await client.query('COMMIT');
        console.log(`[ARKIK DB] applied  ${file}`);
      } catch (err) {
        try {
          await client.query('ROLLBACK');
        } catch (rollbackErr) {
          // ignore: the connection is already broken
        }
        console.error(`[ARKIK DB] FAILED   ${file}: ${safeError(err)}`);
        throw err;
      } finally {
        try {
          client.release();
        } catch (releaseErr) {
          // ignore
        }
      }
    }

    await bootstrapAdmins(pool);
    console.log('[ARKIK DB] schema is up to date.');
  } finally {
    try {
      await pool.end();
    } catch (err) {
      // ignore shutdown noise
    }
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`[ARKIK DB] ERROR: ${safeError(err)}`);
    process.exit(1);
  });
}

module.exports = { loadEnvFiles, bootstrapAdmins };

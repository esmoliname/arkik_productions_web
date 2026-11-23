'use strict';
// Direct PostgreSQL CLI helper for Arkik Productions administrative scripts.
// Isolation guarantees:
// - Explicit envVarName selector: 'DIRECT_DATABASE_URL' (migrations / local dev seed)
//   or 'DIRECT_ADMIN_DATABASE_URL' (admin PIN verify/rotate); zero fallback across
//   variables and never falls back to runtime DATABASE_URL.
// - Rejects Neon PgBouncer "-pooler" hosts before instantiating any Pool.
// - Never imports into Vercel serverless runtime (api/); never logs secrets.

const fs = require('fs');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const ENV_FILES = ['.env.local', '.env'];
const ALLOWED_DIRECT_ENV_VARS = Object.freeze([
  'DIRECT_DATABASE_URL',
  'DIRECT_ADMIN_DATABASE_URL'
]);
const ALLOWED_DIRECT_ENV_VAR_SET = new Set(ALLOWED_DIRECT_ENV_VARS);
const DB_IDENTIFIER_RE = /^[A-Za-z0-9_-]{1,63}$/;

const DEFAULT_DIRECT_POOL_OPTIONS = Object.freeze({
  max: 1,
  connectionTimeoutMillis: 15000,
  idleTimeoutMillis: 10000,
  query_timeout: 65000
});

// Minimal KEY=VALUE reader (no dotenv dependency). Existing process.env wins.
function loadEnvFiles(roots) {
  const targetRoots = Array.isArray(roots) && roots.length ? roots : [process.cwd(), REPO_ROOT];
  const seen = new Set();
  for (const root of targetRoots) {
    for (const file of ENV_FILES) {
      const full = path.join(root, file);
      if (seen.has(full)) continue;
      seen.add(full);
      if (!fs.existsSync(full)) continue;
      let raw = '';
      try {
        raw = fs.readFileSync(full, 'utf8');
      } catch (_err) {
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

function redactSecrets(text) {
  return String(text || '')
    .replace(/postgres(ql)?:\/\/\S+/gi, '[redacted-db-url]')
    .replace(/scrypt\$\S+/gi, '[redacted-hash]')
    .replace(/Bearer\s+\S+/gi, 'Bearer [redacted]')
    .replace(/(__Host-session|arkik_session)=[^;\s"']+/gi, '$1=[redacted]')
    .replace(/\bv1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[redacted-token]')
    .replace(/data:[^\s,"']*;base64,[^\s,"']*/gi, '[redacted-voucher]')
    .replace(
      /\b(admin_?(?:owner|it)?_?pin|admin_?session_?secret|new_?password|password|session_?token)\s*([:=])\s*("[^"]*"|'[^']*'|[^\s,;]+)/gi,
      '$1$2[redacted]'
    );
}

function safeError(err) {
  const message = err && err.message ? String(err.message) : String(err);
  return redactSecrets(message);
}

function isPoolerHostname(hostname) {
  return /(^|[.-])pooler(\.|$)/i.test(String(hostname || '').trim());
}

function isLoopbackHostname(hostname) {
  const normalized = String(hostname || '')
    .trim()
    .replace(/^\[|\]$/g, '')
    .toLowerCase();
  return normalized === 'localhost' || normalized === '127.0.0.1' || normalized === '::1';
}

function stripPoolerSegment(hostname) {
  return String(hostname || '')
    .trim()
    .toLowerCase()
    .replace(/-pooler(?=\.)/i, '')
    .replace(/\.pooler(?=\.)/i, '');
}

function resolveTargetEnv(env = process.env) {
  const appEnv = String(env.APP_ENV || '').trim().toLowerCase();
  if (appEnv) return appEnv;
  const vercelEnv = String(env.VERCEL_ENV || '').trim().toLowerCase();
  if (vercelEnv) return vercelEnv;
  return String(env.NODE_ENV || 'development').trim().toLowerCase() || 'development';
}

function normalizeDirectOptions(envVarOrOptions) {
  if (typeof envVarOrOptions === 'string') {
    return { envVarName: envVarOrOptions };
  }
  return envVarOrOptions && typeof envVarOrOptions === 'object' ? envVarOrOptions : {};
}

function assertAllowedDirectEnvVar(envVarName) {
  const selected =
    envVarName === undefined || envVarName === null || String(envVarName).trim() === ''
      ? 'DIRECT_DATABASE_URL'
      : String(envVarName).trim();
  if (!ALLOWED_DIRECT_ENV_VAR_SET.has(selected)) {
    throw new Error(
      `Unsupported direct env var "${selected}". Allowed values: ${ALLOWED_DIRECT_ENV_VARS.join(', ')}.`
    );
  }
  return selected;
}

function resolveDirectDatabaseUrl(env = process.env, envVarOrOptions = {}) {
  const opts = normalizeDirectOptions(envVarOrOptions);
  const envVarName = assertAllowedDirectEnvVar(opts.envVarName);
  const directUrl = String((env && env[envVarName]) || '').trim();
  if (!directUrl) {
    const otherVars = ['DATABASE_URL', ...ALLOWED_DIRECT_ENV_VARS.filter((name) => name !== envVarName)];
    const roleHint =
      envVarName === 'DIRECT_ADMIN_DATABASE_URL'
        ? 'Neon direct connection without "-pooler" for arkik_admin'
        : 'Neon direct connection without "-pooler" for arkik_migrator / local dev seed';
    throw new Error(
      `${envVarName} is not configured. Set ${envVarName} (${roleHint}) in .env.local or CLI environment. Silent fallback to ${otherVars.join(' or ')} is disabled.`
    );
  }
  return directUrl;
}

function validateDirectDatabaseUrl(rawUrl, env = process.env, options = {}) {
  const opts = normalizeDirectOptions(options);
  const envVarName = assertAllowedDirectEnvVar(opts.envVarName);
  const connectionString = String(rawUrl || '').trim();
  if (!connectionString) {
    throw new Error(`${envVarName} is empty.`);
  }

  let parsed;
  try {
    parsed = new URL(connectionString);
  } catch (_err) {
    throw new Error(`${envVarName} is not a valid PostgreSQL URI.`);
  }

  if (parsed.protocol !== 'postgres:' && parsed.protocol !== 'postgresql:') {
    throw new Error(`${envVarName} must use the postgres:// or postgresql:// scheme.`);
  }

  const host = String(parsed.hostname || '').trim();
  if (!host) {
    throw new Error(`${envVarName} is missing a hostname.`);
  }

  let username = '';
  try {
    username = decodeURIComponent(parsed.username || '').trim();
  } catch (_err) {
    username = String(parsed.username || '').trim();
  }
  if (!username) {
    throw new Error(`${envVarName} is missing a database username.`);
  }

  const isNeonHost = host.toLowerCase().endsWith('.neon.tech');
  if (isNeonHost && !parsed.password) {
    throw new Error(`${envVarName} targeting Neon is missing credentials.`);
  }

  if (isPoolerHostname(host)) {
    throw new Error(
      `${envVarName} must NOT use a PgBouncer "-pooler" endpoint (rejected host "${host}"). Configure Neon's Direct connection endpoint instead.`
    );
  }

  if (opts.requireLocalhost && !isLoopbackHostname(host)) {
    throw new Error(
      `Direct destination "${host}" rejected: this CLI permits loopback hosts only (localhost, 127.0.0.1, ::1).`
    );
  }

  const rawPath = String(parsed.pathname || '').replace(/^\/+/, '');
  if (!rawPath) {
    throw new Error(`${envVarName} must specify an explicit database name in its path.`);
  }
  if (rawPath.includes('/') || /\s/.test(rawPath)) {
    throw new Error(
      `${envVarName} has an ambiguous database path "${rawPath}". Specify a single database name without extra segments.`
    );
  }
  let dbName = '';
  try {
    dbName = decodeURIComponent(rawPath);
  } catch (_err) {
    throw new Error(`${envVarName} contains invalid percent-encoding in the database path.`);
  }
  if (!DB_IDENTIFIER_RE.test(dbName)) {
    throw new Error(
      `${envVarName} specifies invalid database name "${dbName}". Expected a single PostgreSQL database identifier.`
    );
  }

  if (opts.expectedDbName && dbName !== opts.expectedDbName) {
    throw new Error(
      `${envVarName} targets database "${dbName}" instead of expected "${opts.expectedDbName}".`
    );
  }

  if (isNeonHost) {
    const sslMode = String(parsed.searchParams.get('sslmode') || '').trim().toLowerCase();
    if (sslMode === 'disable') {
      throw new Error(`${envVarName} targeting Neon must not set sslmode=disable.`);
    }
    for (const unsupportedParam of ['sslcert', 'sslkey', 'sslrootcert']) {
      if (parsed.searchParams.has(unsupportedParam)) {
        throw new Error(
          `${envVarName} uses unsupported driver parameter "${unsupportedParam}" (not readable in serverless driver).`
        );
      }
    }
  }

  const warnings = [];
  if (isNeonHost && dbName !== 'neondb' && !opts.expectedDbName) {
    warnings.push(`[ARKIK DB] WARNING: ${envVarName} Neon URL targets non-default database "${dbName}" (expected "neondb").`);
  }

  const runtimeRaw = String((env && env.DATABASE_URL) || '').trim();
  if (runtimeRaw) {
    try {
      const runtimeParsed = new URL(runtimeRaw);
      const runtimeHost = String(runtimeParsed.hostname || '').trim();
      const runtimeDb = String(runtimeParsed.pathname || '').replace(/^\/+/, '').trim();
      if (stripPoolerSegment(host) !== stripPoolerSegment(runtimeHost) || dbName !== runtimeDb) {
        warnings.push(
          `[ARKIK DB] WARNING: ${envVarName} (${host}/${dbName}) does not match DATABASE_URL (${runtimeHost}/${runtimeDb}). Verify both point to the intended environment.`
        );
      }
    } catch (_err) {
      warnings.push(`[ARKIK DB] WARNING: DATABASE_URL is set alongside ${envVarName} but could not be parsed for cross-check.`);
    }
  }

  const targetEnv = resolveTargetEnv(env);
  const transport = isLoopbackHostname(host) ? 'local-ws' : 'wss';
  const targetSummary = `[ARKIK DB] target env=${targetEnv} envVar=${envVarName} mode=direct host=${host} db=${dbName} transport=${transport}`;

  return {
    envVarName,
    connectionString,
    host,
    dbName,
    targetEnv,
    isNeonHost,
    warnings,
    targetSummary
  };
}

function resolveDirectConnectionConfig(env = process.env, options = {}) {
  const opts = normalizeDirectOptions(options);
  const raw = resolveDirectDatabaseUrl(env, opts);
  return validateDirectDatabaseUrl(raw, env, opts);
}

async function createDirectPool(options = {}) {
  const env = options.env || process.env;
  const meta = resolveDirectConnectionConfig(env, options);

  if (!options.silent) {
    console.log(meta.targetSummary);
    for (const warning of meta.warnings) {
      console.warn(warning);
    }
  }

  let Pool = options.PoolClass;
  if (typeof Pool !== 'function') {
    try {
      const mod = await import('@neondatabase/serverless');
      Pool = mod.Pool || (mod.default && mod.default.Pool);
      if (typeof Pool !== 'function') throw new Error('Pool export missing');
    } catch (_err) {
      throw new Error('@neondatabase/serverless is not installed or failed to load. Run "npm install" and retry.');
    }
  }

  const poolConfig = Object.assign({}, DEFAULT_DIRECT_POOL_OPTIONS, {
    connectionString: meta.connectionString
  });
  if (Number(options.connectionTimeoutMillis) > 0) {
    poolConfig.connectionTimeoutMillis = Number(options.connectionTimeoutMillis);
  }
  if (Number(options.queryTimeoutMs) > 0) {
    poolConfig.query_timeout = Number(options.queryTimeoutMs);
  }
  if (Number(options.idleTimeoutMillis) > 0) {
    poolConfig.idleTimeoutMillis = Number(options.idleTimeoutMillis);
  }

  const pool = new Pool(poolConfig);
  if (pool && typeof pool.on === 'function') {
    pool.on('error', (err) => {
      console.error(`[ARKIK DB] Direct pool error: ${safeError(err)}`);
    });
  }

  return { pool, meta };
}

module.exports = {
  ALLOWED_DIRECT_ENV_VARS,
  DEFAULT_DIRECT_POOL_OPTIONS,
  assertAllowedDirectEnvVar,
  loadEnvFiles,
  redactSecrets,
  safeError,
  isPoolerHostname,
  isLoopbackHostname,
  resolveDirectDatabaseUrl,
  validateDirectDatabaseUrl,
  resolveDirectConnectionConfig,
  createDirectPool
};

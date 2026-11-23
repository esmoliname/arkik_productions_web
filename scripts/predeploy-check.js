'use strict';
// Arkik Productions - Automated pre-deploy verification & security invariant gate.
// Usage: node scripts/predeploy-check.js   (npm run predeploy:check)

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { loadEnvFiles } = require('../db/migrate');

const ROOT = path.resolve(__dirname, '..');

function runStep(label, fn) {
  process.stdout.write(`[predeploy] ${label}... `);
  const result = fn();
  console.log(`PASS${result ? ` (${result})` : ''}`);
}

function listJsFiles(dir) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) results.push(...listJsFiles(full));
    else if (entry.isFile() && entry.name.endsWith('.js')) results.push(full);
  }
  return results;
}

function verifyStaticInvariants() {
  const clientFiles = ['js/app.js', 'js/data.js', 'js/api.js', 'index.html'];
  for (const rel of clientFiles) {
    const content = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    if (content.includes('scrypt$')) {
      throw new Error(`Forbidden scrypt hash material found in client asset: ${rel}`);
    }
    if (
      /\bADMIN_OWNER_PIN\b|\bADMIN_IT_PIN\b|\bADMIN_SESSION_SECRET\b|\bDATABASE_URL\b|\bDIRECT_DATABASE_URL\b|\bDIRECT_ADMIN_DATABASE_URL\b|\bNEON_STAGING_PREFLIGHT_[A-Z0-9_]*\b|\bNEON_STAGING_EXPECTED_ENDPOINT_ID\b/.test(
        content
      )
    ) {
      throw new Error(`Forbidden server env identifier found in client asset: ${rel}`);
    }
  }

  for (const apiFile of listJsFiles(path.join(ROOT, 'api'))) {
    const rel = path.relative(ROOT, apiFile).replace(/\\/g, '/');
    const src = fs.readFileSync(apiFile, 'utf8');
    if (
      /\bDIRECT_DATABASE_URL\b|\bDIRECT_ADMIN_DATABASE_URL\b|\bNEON_STAGING_PREFLIGHT_[A-Z0-9_]*\b|\bNEON_STAGING_EXPECTED_ENDPOINT_ID\b/.test(
        src
      )
    ) {
      throw new Error(`Runtime isolation violation: restricted CLI/preflight DB env var referenced in ${rel}`);
    }
  }

  const vercelIgnoreLines = fs
    .readFileSync(path.join(ROOT, '.vercelignore'), 'utf8')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));
  if (!vercelIgnoreLines.includes('db') || !vercelIgnoreLines.includes('scripts') || !vercelIgnoreLines.includes('.env.local')) {
    throw new Error('.vercelignore must exclude "db", "scripts", and ".env.local" from Vercel bundles');
  }

  const bookingIndex = fs.readFileSync(path.join(ROOT, 'api/bookings/[code]/index.js'), 'utf8');
  const bookingStatus = fs.readFileSync(path.join(ROOT, 'api/bookings/[code]/status.js'), 'utf8');
  const bookingReschedule = fs.readFileSync(path.join(ROOT, 'api/bookings/[code]/reschedule.js'), 'utf8');
  const availabilityHandler = fs.readFileSync(path.join(ROOT, 'api/availability/index.js'), 'utf8');
  const adminPricingHandler = fs.readFileSync(path.join(ROOT, 'api/admin/pricing.js'), 'utf8');
  for (const [name, src] of [
    ['api/bookings/[code]/index.js', bookingIndex],
    ['api/bookings/[code]/status.js', bookingStatus],
    ['api/bookings/[code]/reschedule.js', bookingReschedule],
    ['api/availability/index.js', availabilityHandler],
    ['api/admin/pricing.js', adminPricingHandler]
  ]) {
    if (!src.includes('requireOwner')) {
      throw new Error(`Owner RBAC guard missing in ${name}`);
    }
  }

  const loginSrc = fs.readFileSync(path.join(ROOT, 'api/admin/login.js'), 'utf8');
  if (!loginSrc.includes('!config.databaseUrl') || !loginSrc.includes('canUseLocalEnvPinFallback')) {
    throw new Error('api/admin/login.js must enforce !config.databaseUrl and explicit local dev guard');
  }
  const configSrc = fs.readFileSync(path.join(ROOT, 'api/_lib/config.js'), 'utf8');
  if (!configSrc.includes('isExplicitLocalDev') || !configSrc.includes('isCloud') || !configSrc.includes('isStagingOrPreview')) {
    throw new Error('api/_lib/config.js must enforce unified isExplicitLocalDev, isStagingOrPreview and isCloud secret guards');
  }

  const healthSrc = fs.readFileSync(path.join(ROOT, 'api/health.js'), 'utf8');
  if (
    healthSrc.includes("database: 'configured'") ||
    healthSrc.includes('database: "configured"') ||
    healthSrc.includes('./_lib/db') ||
    healthSrc.includes('probeConnection') ||
    /SELECT\s+1/i.test(healthSrc)
  ) {
    throw new Error('api/health.js must remain a pure liveness endpoint with zero DB imports or queries');
  }

  const readyPath = path.join(ROOT, 'api/ready.js');
  if (!fs.existsSync(readyPath)) {
    throw new Error('Missing readiness endpoint api/ready.js');
  }
  const readySrc = fs.readFileSync(readyPath, 'utf8');
  if (!readySrc.includes('probeConnection') || !readySrc.includes('no-store')) {
    throw new Error('api/ready.js must probe PostgreSQL once and set Cache-Control: no-store');
  }

  const vercelCfg = JSON.parse(fs.readFileSync(path.join(ROOT, 'vercel.json'), 'utf8'));
  const spaRoutes = ['/admin', '/panel', '/bookings', '/booking', '/reserva', '/reservas'];
  const headerSources = new Set((vercelCfg.headers || []).map((h) => h.source));
  for (const route of ['/index.html', ...spaRoutes]) {
    if (!headerSources.has(route)) {
      throw new Error(`vercel.json missing Cache-Control rule for ${route}`);
    }
  }

  const migrationsDir = path.join(ROOT, 'db', 'migrations');
  const sqlFiles = fs.readdirSync(migrationsDir).filter((f) => f.toLowerCase().endsWith('.sql')).sort();
  if (sqlFiles.length < 3) {
    throw new Error(`Expected >= 3 SQL migration files, found ${sqlFiles.length}`);
  }
  return `${sqlFiles.length} SQL migrations + RBAC, runtime-isolation, probe & vercel invariants clean`;
}

function main() {
  loadEnvFiles();

  runStep('JS syntax check', () => {
    execSync('npm run check', { cwd: ROOT, stdio: 'pipe' });
    return 'client, db, and scripts JS syntax';
  });

  runStep('Unit & integration tests (offline mocks)', () => {
    const testEnv = Object.assign({}, process.env, { APP_ENV: 'development', NODE_ENV: 'development' });
    delete testEnv.SECURE_COOKIES;
    execSync('node --test "test/*.test.cjs"', { cwd: ROOT, stdio: 'inherit', env: testEnv });
    return 'all mock suites clean';
  });

  runStep('Security & RBAC static invariants', verifyStaticInvariants);

  const hasDb = Boolean((process.env.DATABASE_URL || '').trim());
  const hasDirectDb = Boolean((process.env.DIRECT_DATABASE_URL || '').trim());
  const hasDirectAdminDb = Boolean((process.env.DIRECT_ADMIN_DATABASE_URL || '').trim());
  const rawSecret = (process.env.ADMIN_SESSION_SECRET || '').trim();
  const hasSecret = Boolean(rawSecret && rawSecret !== 'dev-secret-change-me');
  const secretState = hasSecret ? 'SET' : (rawSecret === 'dev-secret-change-me' ? 'PLACEHOLDER' : 'UNSET');
  console.log(
    `[predeploy] Environment snapshot: DATABASE_URL=${hasDb ? 'SET' : 'UNSET'}, DIRECT_DATABASE_URL=${hasDirectDb ? 'SET' : 'UNSET'}, DIRECT_ADMIN_DATABASE_URL=${hasDirectAdminDb ? 'SET' : 'UNSET'}, ADMIN_SESSION_SECRET=${secretState}`
  );
  if (!hasDb || !hasSecret) {
    console.log('[predeploy] NOTE: Configure DATABASE_URL and a non-placeholder ADMIN_SESSION_SECRET in Vercel/local .env.local before live deployment.');
  }
  if (
    (process.env.NEON_STAGING_PREFLIGHT_DIRECT_URL || '').trim() ||
    (process.env.NEON_STAGING_PREFLIGHT_POOLED_URL || '').trim() ||
    (process.env.NEON_STAGING_EXPECTED_ENDPOINT_ID || '').trim()
  ) {
    console.log('[predeploy] WARNING: Temporary NEON_STAGING_PREFLIGHT_* / NEON_STAGING_EXPECTED_ENDPOINT_ID detected; remove after P0.4.5-B.');
  }
  console.log('[predeploy] Local offline verification gate PASSED (PostgreSQL/Neon real integration not executed here).');
}

main();


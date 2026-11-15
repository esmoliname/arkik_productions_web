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

function verifyStaticInvariants() {
  const clientFiles = ['js/app.js', 'js/data.js', 'js/api.js', 'index.html'];
  for (const rel of clientFiles) {
    const content = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    if (content.includes('scrypt$')) {
      throw new Error(`Forbidden scrypt hash material found in client asset: ${rel}`);
    }
    if (/\bADMIN_OWNER_PIN\b|\bADMIN_IT_PIN\b|\bADMIN_SESSION_SECRET\b|\bDATABASE_URL\b/.test(content)) {
      throw new Error(`Forbidden server env identifier found in client asset: ${rel}`);
    }
  }

  const bookingIndex = fs.readFileSync(path.join(ROOT, 'api/bookings/[code]/index.js'), 'utf8');
  const bookingStatus = fs.readFileSync(path.join(ROOT, 'api/bookings/[code]/status.js'), 'utf8');
  const bookingReschedule = fs.readFileSync(path.join(ROOT, 'api/bookings/[code]/reschedule.js'), 'utf8');
  for (const [name, src] of [
    ['api/bookings/[code]/index.js', bookingIndex],
    ['api/bookings/[code]/status.js', bookingStatus],
    ['api/bookings/[code]/reschedule.js', bookingReschedule]
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
  if (!configSrc.includes('isExplicitLocalDev') || !configSrc.includes('isCloud')) {
    throw new Error('api/_lib/config.js must enforce unified isExplicitLocalDev and isCloud secret guards');
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
  const sqlFiles = fs.readdirSync(migrationsDir).filter((f) => f.endsWith('.sql')).sort();
  if (sqlFiles.length < 3) {
    throw new Error(`Expected >= 3 SQL migration files, found ${sqlFiles.length}`);
  }
  return `${sqlFiles.length} SQL migrations + RBAC, auth, probe & vercel invariants clean`;
}

function main() {
  loadEnvFiles();

  runStep('JS syntax check', () => {
    execSync('npm run check', { cwd: ROOT, stdio: 'pipe' });
    return 'js/app.js, js/data.js, js/api.js';
  });

  runStep('Unit & integration tests', () => {
    execSync('node --test "test/*.test.cjs"', { cwd: ROOT, stdio: 'inherit' });
    return 'all suites clean';
  });

  runStep('Security & RBAC static invariants', verifyStaticInvariants);

  const hasDb = Boolean((process.env.DATABASE_URL || '').trim());
  const hasSecret = Boolean((process.env.ADMIN_SESSION_SECRET || '').trim());
  console.log(
    `[predeploy] Environment snapshot: DATABASE_URL=${hasDb ? 'SET' : 'UNSET'}, ADMIN_SESSION_SECRET=${hasSecret ? 'SET' : 'UNSET'}`
  );
  if (!hasDb || !hasSecret) {
    console.log('[predeploy] NOTE: Configure DATABASE_URL and ADMIN_SESSION_SECRET in Vercel/local .env.local before live deployment.');
  }
  console.log('[predeploy] Local verification gate PASSED.');
}

main();


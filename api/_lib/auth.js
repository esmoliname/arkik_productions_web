'use strict';
// Authentication: scrypt PIN hashes, HMAC-hashed sliding sessions, cookies.
// Requires NO environment at import time; DB access goes through the registry
// so tests can inject fakes.

const crypto = require('crypto');
const registry = require('./registry');
const config = require('./config');
const { appError } = require('./respond');

const COOKIE_NAME = 'arkik_session';
const SESSION_TTL_MS = 15 * 60 * 1000; // 15 minutes, sliding
const TOUCH_AFTER_MS = 60 * 1000; // refresh the sliding window at most once a minute
const SCRYPT = { cost: 16384, blockSize: 8, parallelization: 1, keylen: 64, saltBytes: 16, maxmem: 64 * 1024 * 1024 };

function hashPin(pin) {
  const salt = crypto.randomBytes(SCRYPT.saltBytes);
  const derived = crypto.scryptSync(String(pin), salt, SCRYPT.keylen, {
    cost: SCRYPT.cost,
    blockSize: SCRYPT.blockSize,
    parallelization: SCRYPT.parallelization,
    maxmem: SCRYPT.maxmem
  });
  return `scrypt$${SCRYPT.cost}$${SCRYPT.blockSize}$${SCRYPT.parallelization}$${salt.toString('hex')}$${derived.toString('hex')}`;
}

function verifyPin(pin, stored) {
  if (typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const cost = Number(parts[1]);
  const blockSize = Number(parts[2]);
  const parallelization = Number(parts[3]);
  const salt = Buffer.from(parts[4], 'hex');
  const expected = Buffer.from(parts[5], 'hex');
  if (!Number.isInteger(cost) || !Number.isInteger(blockSize) || !Number.isInteger(parallelization)) return false;
  if (!salt.length || !expected.length) return false;
  let derived;
  try {
    derived = crypto.scryptSync(String(pin), salt, expected.length, {
      cost,
      blockSize,
      parallelization,
      maxmem: SCRYPT.maxmem
    });
  } catch (err) {
    return false;
  }
  return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
}

function newSessionToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function hashToken(token) {
  return crypto.createHmac('sha256', config.sessionSecret).update(String(token)).digest('hex');
}

function parseCookies(req) {
  const jar = {};
  const header = req && req.headers ? req.headers.cookie : null;
  if (typeof header !== 'string' || !header) return jar;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    const name = part.slice(0, index).trim();
    if (!name) continue;
    jar[name] = decodeURIComponent(part.slice(index + 1).trim());
  }
  return jar;
}

function getSessionCookieName() {
  return config.isProduction ? '__Host-session' : COOKIE_NAME;
}

function getSessionToken(req) {
  const jar = parseCookies(req);
  return jar['__Host-session'] || jar[COOKIE_NAME] || null;
}

function sessionCookie(token) {
  const name = getSessionCookieName();
  const secure = config.isProduction ? ' Secure;' : '';
  return `${name}=${encodeURIComponent(token)}; HttpOnly;${secure} SameSite=Strict; Path=/; Max-Age=900`;
}

function clearSessionCookie() {
  const name = getSessionCookieName();
  const secure = config.isProduction ? ' Secure;' : '';
  return `${name}=; HttpOnly;${secure} SameSite=Strict; Path=/; Max-Age=0`;
}

function getEnvPinForRole(role) {
  if (role === 'owner') {
    return process.env.ADMIN_PIN_OWNER || process.env.ADMIN_OWNER_PIN || '';
  }
  if (role === 'it') {
    return process.env.ADMIN_PIN_IT || process.env.ADMIN_IT_PIN || '';
  }
  return '';
}

function hasEnvPinsConfigured() {
  return Boolean(getEnvPinForRole('owner') || getEnvPinForRole('it'));
}

function verifyEnvPin(role, pin) {
  if (role !== 'owner' && role !== 'it') return false;
  const cleanPin = String(pin ?? '').replace(/\D/g, '').trim();
  const expected = String(getEnvPinForRole(role) || '').trim();
  if (!cleanPin || !expected) return false;
  if (expected.startsWith('scrypt$')) {
    return verifyPin(cleanPin, expected);
  }
  const digestA = crypto.createHash('sha256').update(cleanPin, 'utf8').digest();
  const digestB = crypto.createHash('sha256').update(expected, 'utf8').digest();
  return crypto.timingSafeEqual(digestA, digestB);
}

function createStatelessToken(role, expiresAtMs) {
  const exp = Number.isFinite(expiresAtMs) ? expiresAtMs : Date.now() + SESSION_TTL_MS;
  const payload = Buffer.from(
    JSON.stringify({
      role,
      exp,
      nonce: crypto.randomBytes(16).toString('hex')
    }),
    'utf8'
  ).toString('base64url');
  const sig = crypto
    .createHmac('sha256', config.sessionSecret)
    .update(`v1.${payload}`)
    .digest('base64url');
  return `v1.${payload}.${sig}`;
}

function verifyStatelessToken(token) {
  if (typeof token !== 'string' || !token.startsWith('v1.')) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [, payload, sig] = parts;
  if (!payload || !sig) return null;

  const expectedSig = crypto
    .createHmac('sha256', config.sessionSecret)
    .update(`v1.${payload}`)
    .digest('base64url');

  const sigBuf = Buffer.from(sig, 'utf8');
  const expBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }

  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data || (data.role !== 'owner' && data.role !== 'it')) return null;
    const exp = Number(data.exp);
    if (!Number.isFinite(exp) || exp <= Date.now()) return null;
    return { role: data.role, expiresAt: new Date(exp).toISOString() };
  } catch (err) {
    return null;
  }
}

/**
 * Resolve the caller's admin session.
 * Throws appError('unauthorized', 401) when missing/expired; otherwise returns
 * {role, expiresAt} and slides the expiry (max once per minute).
 */
async function requireAdmin(req) {
  const token = getSessionToken(req);
  if (!token) throw appError('unauthorized', 'No autorizado.', 401);

  if (token.startsWith('v1.')) {
    const stateless = verifyStatelessToken(token);
    if (!stateless) throw appError('unauthorized', 'No autorizado.', 401);
    return stateless;
  }

  const tokenHash = hashToken(token);
  const db = registry.get('db');
  const repo = registry.get('repo');

  const session = await db.withClient(async (client) => {
    const row = await repo.getSession(client, tokenHash);
    if (!row) return null;

    const now = Date.now();
    const expires = new Date(row.expires_at).getTime();
    if (Number.isNaN(expires) || expires <= now) return null;

    const lastSeen = new Date(row.last_seen_at).getTime();
    if (now - lastSeen > TOUCH_AFTER_MS) {
      const nextExpiry = new Date(now + SESSION_TTL_MS);
      const updated = await repo.touchSession(client, tokenHash, nextExpiry, new Date(now));
      const effective = updated && updated.expires_at ? new Date(updated.expires_at) : nextExpiry;
      return { role: row.role, expiresAt: effective.toISOString() };
    }
    return { role: row.role, expiresAt: new Date(expires).toISOString() };
  });

  if (!session) throw appError('unauthorized', 'No autorizado.', 401);
  return session;
}

/**
 * Like requireAdmin but additionally requires role === 'owner'.
 * Throws appError('forbidden', 403) for non-owner roles.
 */
async function requireOwner(req) {
  const session = await requireAdmin(req);
  if (session.role !== 'owner') {
    throw appError('forbidden', 'Operaci\u00f3n reservada al propietario.', 403);
  }
  return session;
}

module.exports = {
  COOKIE_NAME,
  SESSION_TTL_MS,
  hashPin,
  verifyPin,
  hasEnvPinsConfigured,
  verifyEnvPin,
  createStatelessToken,
  verifyStatelessToken,
  newSessionToken,
  hashToken,
  parseCookies,
  getSessionToken,
  sessionCookie,
  clearSessionCookie,
  requireAdmin,
  requireOwner
};

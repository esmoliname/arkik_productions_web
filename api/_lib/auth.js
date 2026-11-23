'use strict';
// Authentication: scrypt PIN hashes, HMAC-hashed sliding sessions, cookies.
// Requires NO environment at import time; DB access goes through the registry
// so tests can inject fakes.

const crypto = require('crypto');
const registry = require('./registry');
const config = require('./config');
const { readEnv: readEnvFromContext } = require('./env-context');
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

function parseScryptHash(stored) {
  if (typeof stored !== 'string') return null;
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return null;
  const cost = Number(parts[1]);
  const blockSize = Number(parts[2]);
  const parallelization = Number(parts[3]);
  const saltHex = parts[4];
  const expectedHex = parts[5];
  if (!/^[0-9a-f]+$/i.test(saltHex) || !/^[0-9a-f]+$/i.test(expectedHex)) return null;
  if (saltHex.length % 2 !== 0 || expectedHex.length % 2 !== 0) return null;
  const salt = Buffer.from(saltHex, 'hex');
  const expected = Buffer.from(expectedHex, 'hex');
  if (!Number.isInteger(cost) || cost < 1024 || !Number.isInteger(blockSize) || blockSize < 1 || !Number.isInteger(parallelization) || parallelization < 1) {
    return null;
  }
  if (salt.length < 8 || expected.length < 16) return null;
  return { cost, blockSize, parallelization, salt, expected };
}

function isValidScryptHash(stored) {
  return parseScryptHash(stored) !== null;
}

function verifyPin(pin, stored) {
  const parsed = parseScryptHash(stored);
  if (!parsed) return false;
  let derived;
  try {
    derived = crypto.scryptSync(String(pin), parsed.salt, parsed.expected.length, {
      cost: parsed.cost,
      blockSize: parsed.blockSize,
      parallelization: parsed.parallelization,
      maxmem: SCRYPT.maxmem
    });
  } catch (err) {
    return false;
  }
  return derived.length === parsed.expected.length && crypto.timingSafeEqual(derived, parsed.expected);
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
    const rawValue = part.slice(index + 1).trim();
    try {
      jar[name] = decodeURIComponent(rawValue);
    } catch (_uriErr) {
      // Malformed percent-encoding must never turn into a 500 Internal Server Error.
      jar[name] = rawValue;
    }
  }
  return jar;
}

function isSecureCookieContext() {
  // Secure cookies are mandatory on HTTPS contexts. Vercel/cloud and production
  // are always HTTPS. Staging/preview outside Vercel only gets Secure when the
  // operator explicitly opts in via SECURE_COOKIES=1 (the deployment must
  // actually terminate TLS). Local development servers (loopback) never use
  // Secure cookies so that sessions work over http://localhost.
  if (config.isLocalServer) return false;
  return config.isProduction || config.isCloud || (config.isStagingOrPreview && config.forceSecureCookies);
}

// Fail-closed guard: staging/preview outside Vercel MUST NOT emit an insecure
// session cookie when SECURE_COOKIES is absent or disabled.
function assertSecureCookieAllowed() {
  // Local development servers (loopback) are allowed to issue insecure cookies
  // without SECURE_COOKIES=1 so that login works over http://localhost.
  if (config.isLocalServer) return;
  const stagingOutsideVercel = config.isStagingOrPreview && !config.isCloud && !config.isProduction;
  if (stagingOutsideVercel && !config.forceSecureCookies) {
    const err = new Error('SECURE_COOKIES must be enabled (1) for staging/preview outside Vercel to issue session cookies.');
    err.arkikApp = true;
    err.code = 'service_unavailable';
    err.status = 503;
    throw err;
  }
}

function getSessionCookieName() {
  return isSecureCookieContext() ? '__Host-session' : COOKIE_NAME;
}

function getSessionToken(req) {
  const jar = parseCookies(req);
  return jar['__Host-session'] || jar[COOKIE_NAME] || null;
}

function sessionCookie(token) {
  assertSecureCookieAllowed();
  const name = getSessionCookieName();
  const secure = isSecureCookieContext() ? ' Secure;' : '';
  return `${name}=${encodeURIComponent(token)}; HttpOnly;${secure} SameSite=Strict; Path=/; Max-Age=900`;
}

function clearSessionCookie() {
  const name = getSessionCookieName();
  const secure = isSecureCookieContext() ? ' Secure;' : '';
  return `${name}=; HttpOnly;${secure} SameSite=Strict; Path=/; Max-Age=0`;
}

function getEnvPinForRole(role) {
  if (role === 'owner') {
    return String(readEnvFromContext('ADMIN_OWNER_PIN', readEnvFromContext('ADMIN_PIN_OWNER', '')) || '').trim();
  }
  if (role === 'it') {
    return String(readEnvFromContext('ADMIN_IT_PIN', readEnvFromContext('ADMIN_PIN_IT', '')) || '').trim();
  }
  return '';
}

function hasEnvPinsConfigured() {
  return Boolean(getEnvPinForRole('owner') || getEnvPinForRole('it'));
}

function canUseLocalEnvPinFallback() {
  if (!config.isExplicitLocalDev) return false;
  return hasEnvPinsConfigured();
}

function verifyEnvPin(role, pin) {
  if (role !== 'owner' && role !== 'it') return false;
  const cleanPin = String(pin ?? '').trim();
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
async function requireAdmin(req, res) {
  const token = getSessionToken(req);
  if (!token) throw appError('unauthorized', 'No autorizado.', 401);

  if (token.startsWith('v1.')) {
    if (!config.isExplicitLocalDev) {
      throw appError('unauthorized', 'No autorizado.', 401);
    }
    const stateless = verifyStatelessToken(token);
    if (!stateless) throw appError('unauthorized', 'No autorizado.', 401);
    return stateless;
  }

  const tokenHash = hashToken(token);
  const db = registry.get('db');
  const repo = registry.get('repo');

  const outcome = await db.withClient(async (client) => {
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
      return { session: { role: row.role, expiresAt: effective.toISOString() }, refreshed: true };
    }
    return { session: { role: row.role, expiresAt: new Date(expires).toISOString() }, refreshed: false };
  });

  if (!outcome) throw appError('unauthorized', 'No autorizado.', 401);
  if (outcome.refreshed && res && typeof res.setHeader === 'function' && !res.headersSent) {
    res.setHeader('Set-Cookie', sessionCookie(token));
  }
  return outcome.session;
}

/**
 * Like requireAdmin but additionally requires role === 'owner'.
 * Throws appError('forbidden', 403) for non-owner roles.
 */
async function requireOwner(req, res) {
  const session = await requireAdmin(req, res);
  if (session.role !== 'owner') {
    throw appError('forbidden', 'Operaci\u00f3n reservada al propietario.', 403);
  }
  return session;
}

module.exports = {
  COOKIE_NAME,
  SESSION_TTL_MS,
  hashPin,
  isValidScryptHash,
  verifyPin,
  hasEnvPinsConfigured,
  canUseLocalEnvPinFallback,
  verifyEnvPin,
  createStatelessToken,
  verifyStatelessToken,
  newSessionToken,
  hashToken,
  parseCookies,
  getSessionToken,
  sessionCookie,
  clearSessionCookie,
  isSecureCookieContext,
  assertSecureCookieAllowed,
  requireAdmin,
  requireOwner
};

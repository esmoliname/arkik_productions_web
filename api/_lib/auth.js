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

function getSessionToken(req) {
  return parseCookies(req)[COOKIE_NAME] || null;
}

function secureSuffix() {
  return config.isProduction ? '; Secure' : '';
}

function sessionCookie(token) {
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=900${secureSuffix()}`;
}

function clearSessionCookie() {
  return `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secureSuffix()}`;
}

/**
 * Resolve the caller's admin session.
 * Throws appError('unauthorized', 401) when missing/expired; otherwise returns
 * {role, expiresAt} and slides the expiry (max once per minute).
 */
async function requireAdmin(req) {
  const token = getSessionToken(req);
  if (!token) throw appError('unauthorized', 'No autorizado.', 401);

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

module.exports = {
  COOKIE_NAME,
  hashPin,
  verifyPin,
  newSessionToken,
  hashToken,
  parseCookies,
  getSessionToken,
  sessionCookie,
  clearSessionCookie,
  requireAdmin
};

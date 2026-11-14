'use strict';
// POST /api/admin/login — {role, pin} -> HttpOnly, Secure, SameSite=Strict session cookie (15 min)
// Zero-Trust: validates PIN against process.env.ADMIN_PIN_OWNER / process.env.ADMIN_PIN_IT
// (or DB-backed service.login) and NEVER exposes session tokens in the response body.

const { withCors } = require('../_lib/cors');
const registry = require('../_lib/registry');

const ENV_ATTEMPTS = new Map();
// Per-origin throttling only: a third party must never be able to lock an
// administrator out globally by sending bad PINs. Backoff is progressive and
// temporary, and resets automatically.
const MAX_ENV_ATTEMPTS = 5;
const ENV_LOCKOUT_BASE_MS = 30 * 1000;
const ENV_LOCKOUT_MAX_MS = 15 * 60 * 1000;

function sanitizeRole(rawRole) {
  const role = typeof rawRole === 'string' ? rawRole.trim().toLowerCase() : '';
  if (role === 'tech') return 'it';
  return role === 'owner' || role === 'it' ? role : '';
}

function sanitizePin(rawPin) {
  if (rawPin === null || rawPin === undefined) return '';
  return String(rawPin).trim().slice(0, 64);
}

function checkEnvLockout(bucketKey, now) {
  const state = ENV_ATTEMPTS.get(bucketKey);
  if (!state) return 0;
  if (state.lockedUntil && state.lockedUntil > now) {
    return state.lockedUntil - now;
  }
  if (state.lockedUntil && state.lockedUntil <= now) {
    // Reset after the backoff window elapses.
    ENV_ATTEMPTS.delete(bucketKey);
  }
  return 0;
}

function recordEnvFailure(bucketKey, now) {
  const state = ENV_ATTEMPTS.get(bucketKey) || { count: 0, level: 0, lockedUntil: 0 };
  state.count += 1;
  if (state.count >= MAX_ENV_ATTEMPTS) {
    state.count = 0;
    const lockMs = Math.min(ENV_LOCKOUT_BASE_MS * Math.pow(2, state.level), ENV_LOCKOUT_MAX_MS);
    state.level = Math.min(state.level + 1, 6);
    state.lockedUntil = now + lockMs;
    ENV_ATTEMPTS.set(bucketKey, state);
    return { locked: true, retryAfterMs: lockMs };
  }
  ENV_ATTEMPTS.set(bucketKey, state);
  return { locked: false, retryAfterMs: 0 };
}

async function handler(req, res) {
  const respond = registry.get('respond');

  try {
    if (req.method !== 'POST') {
      return respond.fail(res, 'method_not_allowed', 'Método no permitido.', 405);
    }

    const body = await respond.readBody(req);
    const service = registry.get('service');
    const auth = registry.get('auth');
    const config = registry.get('config');

    const role = sanitizeRole(body ? body.role : undefined);
    const pin = sanitizePin(body ? body.pin : undefined);
    const ip = respond.clientIp(req);

    // Database authentication (Neon admin_credentials + admin_sessions + distributed rate_limits)
    // is authoritative whenever DATABASE_URL is configured. Stateless env-PIN mode only activates
    // when no database is configured (e.g., ephemeral preview/prototype environments).
    if (!config.databaseUrl && typeof auth.hasEnvPinsConfigured === 'function' && auth.hasEnvPinsConfigured()) {
      const now = Date.now();
      const bucketKey = `${ip || 'unknown'}:${role || 'unknown'}`;
      const lockedRemaining = checkEnvLockout(bucketKey, now);
      if (lockedRemaining > 0) {
        res.setHeader('Retry-After', String(Math.ceil(lockedRemaining / 1000)));
        return respond.fail(res, 'locked', 'Credenciales inválidas', 429, {
          retryAfterMs: Math.ceil(lockedRemaining)
        });
      }

      if (!role || !pin || !auth.verifyEnvPin(role, pin)) {
        const failure = recordEnvFailure(bucketKey, now);
        if (failure.locked) {
          res.setHeader('Retry-After', String(Math.ceil(failure.retryAfterMs / 1000)));
          return respond.fail(res, 'locked', 'Credenciales inválidas', 429, {
            retryAfterMs: failure.retryAfterMs
          });
        }
        return respond.fail(res, 'unauthorized', 'Credenciales inválidas', 401);
      }

      ENV_ATTEMPTS.delete(bucketKey);
      const expiresAtMs = now + (auth.SESSION_TTL_MS || 15 * 60 * 1000);
      const token = auth.createStatelessToken(role, expiresAtMs);
      const expiresAt = new Date(expiresAtMs).toISOString();

      res.setHeader('Set-Cookie', auth.sessionCookie(token));
      // The session token NEVER reaches the response body.
      return respond.ok(res, { role, expiresAt });
    }

    const fallbackRole = body && typeof body.role === 'string' ? body.role.trim().toLowerCase() : '';
    const result = await service.login({
      role: role || fallbackRole,
      pin,
      ip
    });

    res.setHeader('Set-Cookie', auth.sessionCookie(result.token));
    // The token itself never reaches the response body.
    return respond.ok(res, { role: result.role, expiresAt: result.expiresAt });
  } catch (err) {
    if (err && err.extra && err.extra.retryAfterMs) {
      try { res.setHeader('Retry-After', String(Math.ceil(err.extra.retryAfterMs / 1000))); } catch (e) { /* ignore */ }
    }
    return respond.handleError(res, err, registry.get('log'));
  }
}

module.exports = withCors(handler);

'use strict';
// CORS policy: same-origin by default (frontend and API ship from the same
// Vercel app). When ALLOWED_ORIGINS is configured the Origin header is checked
// against that list. The wrapper also handles OPTIONS preflight and logs one
// HTTP line per request (path only, never the query string).

const config = require('./config');
const { log } = require('./log');

function applyCors(req, res) {
  const allowed = config.allowedOrigins;
  const origin = req && req.headers ? req.headers.origin : null;
  res.setHeader('Vary', 'Origin');
  if (allowed.length && origin && allowed.indexOf(origin) !== -1) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    return true;
  }
  return false;
}

function pathOf(req) {
  return String((req && req.url) || '/').split('?')[0];
}

function withCors(handler) {
  return async function corsWrapped(req, res) {
    const started = Date.now();
    applyCors(req, res);

    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Idempotency-Key, Authorization');
      res.setHeader('Access-Control-Max-Age', '86400');
      res.status(204).end();
      log('HTTP', `${req.method} ${pathOf(req)} 204 ${Date.now() - started}ms`);
      return undefined;
    }

    try {
      return await handler(req, res);
    } catch (err) {
      log('ERROR', `unhandled ${(err && err.name) || 'error'} in ${req.method} ${pathOf(req)}`);
      if (!res.headersSent) {
        res.status(500).json({
          success: false,
          error: { code: 'internal_error', message: 'Error interno del servidor.' }
        });
      }
      return undefined;
    } finally {
      log('HTTP', `${req.method} ${pathOf(req)} ${res.statusCode} ${Date.now() - started}ms`);
    }
  };
}

module.exports = { withCors, applyCors };

'use strict';
// GET /api/ready — PostgreSQL readiness probe.
// Returns 200 ONLY when DATABASE_URL is configured and SELECT 1 succeeds within timeout;
// otherwise returns 503 ('unconfigured' or 'unavailable') without leaking secrets or errors.

const { withCors } = require('./_lib/cors');
const registry = require('./_lib/registry');
const dbHelpers = require('./_lib/db');

const PROBE_TIMEOUT_MS = 4000;

async function handler(req, res) {
  const respond = registry.get('respond');
  const config = registry.get('config');
  const timestamp = new Date().toISOString();

  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return respond.fail(res, 'method_not_allowed', 'Método no permitido.', 405);
  }

  if (!config.databaseUrl) {
    return res.status(503).json({
      success: false,
      service: 'arkik-api',
      ready: false,
      database: 'unconfigured',
      timestamp
    });
  }

  const db = registry.get('db');
  const probe = await dbHelpers.probeConnection(db, PROBE_TIMEOUT_MS);
  if (probe.ok) {
    return res.status(200).json({
      success: true,
      service: 'arkik-api',
      ready: true,
      database: 'connected',
      timestamp
    });
  }

  return res.status(503).json({
    success: false,
    service: 'arkik-api',
    ready: false,
    database: 'unavailable',
    timestamp
  });
}

module.exports = withCors(handler);

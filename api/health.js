'use strict';
// GET /api/health — liveness probe. Excludes the standard envelope on purpose:
// infrastructure expects {service, database, timestamp}.

const { withCors } = require('./_lib/cors');
const registry = require('./_lib/registry');

const PROBE_TIMEOUT_MS = 4000;

function withTimeout(promise, ms) {
  let timer = null;
  const timeout = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error('health probe timeout')), ms);
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

async function handler(req, res) {
  const respond = registry.get('respond');
  const config = registry.get('config');
  const timestamp = new Date().toISOString();

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return respond.fail(res, 'method_not_allowed', 'Método no permitido.', 405);
  }

  // No DATABASE_URL: report configured-but-unverified, still healthy.
  if (!config.databaseUrl) {
    return res.status(200).json({ success: true, service: 'arkik-api', database: 'configured', timestamp });
  }

  try {
    const db = registry.get('db');
    await withTimeout(db.withClient((client) => client.query('SELECT 1')), PROBE_TIMEOUT_MS);
    return res.status(200).json({ success: true, service: 'arkik-api', database: 'connected', timestamp });
  } catch (err) {
    // Never expose errors or stacks on a public probe.
    return res.status(503).json({ success: false, service: 'arkik-api', database: 'unavailable', timestamp });
  }
}

module.exports = withCors(handler);

'use strict';
// GET /api/health — pure liveness probe (zero database imports or queries).
// Readiness with PostgreSQL lives strictly at /api/ready.

const { withCors } = require('./_lib/cors');
const registry = require('./_lib/registry');

async function handler(req, res) {
  const respond = registry.get('respond');
  const timestamp = new Date().toISOString();

  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return respond.fail(res, 'method_not_allowed', 'Método no permitido.', 405);
  }

  return res.status(200).json({
    success: true,
    service: 'arkik-api',
    status: 'ok',
    database: 'not_checked',
    timestamp
  });
}

module.exports = withCors(handler);

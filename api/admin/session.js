'use strict';
// GET /api/admin/session — current session or 401 unauthorized

const { withCors } = require('../_lib/cors');
const registry = require('../_lib/registry');

async function handler(req, res) {
  const respond = registry.get('respond');

  try {
    if (req.method !== 'GET') {
      return respond.fail(res, 'method_not_allowed', 'Método no permitido.', 405);
    }

    const auth = registry.get('auth');
    const session = await auth.requireAdmin(req);
    return respond.ok(res, {
      authenticated: true,
      role: session.role,
      expiresAt: session.expiresAt
    });
  } catch (err) {
    return respond.handleError(res, err, registry.get('log'));
  }
}

module.exports = withCors(handler);

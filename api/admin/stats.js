'use strict';
// GET /api/admin/stats — aggregates for the admin dashboard

const { withCors } = require('../_lib/cors');
const registry = require('../_lib/registry');

async function handler(req, res) {
  const respond = registry.get('respond');

  try {
    if (req.method !== 'GET') {
      return respond.fail(res, 'method_not_allowed', 'Método no permitido.', 405);
    }

    const auth = registry.get('auth');
    await auth.requireAdmin(req);

    const service = registry.get('service');
    const data = await service.getStats();
    return respond.ok(res, data);
  } catch (err) {
    return respond.handleError(res, err, registry.get('log'));
  }
}

module.exports = withCors(handler);

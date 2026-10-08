'use strict';
// GET /api/admin/pricing — pricing overrides + rates (catalog is read-only)
// PUT /api/admin/pricing — {overrides?, rates?} validated, audited

const { withCors } = require('../_lib/cors');
const registry = require('../_lib/registry');

async function handler(req, res) {
  const respond = registry.get('respond');

  try {
    if (req.method !== 'GET' && req.method !== 'PUT') {
      return respond.fail(res, 'method_not_allowed', 'Método no permitido.', 405);
    }

    const auth = registry.get('auth');
    const admin = await auth.requireAdmin(req);
    const service = registry.get('service');

    if (req.method === 'GET') {
      const data = await service.getPricing();
      return respond.ok(res, data);
    }

    const body = await respond.readBody(req);
    const data = await service.putPricing(body, admin.role);
    return respond.ok(res, data);
  } catch (err) {
    return respond.handleError(res, err, registry.get('log'));
  }
}

module.exports = withCors(handler);

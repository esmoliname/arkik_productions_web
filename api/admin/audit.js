'use strict';
// GET /api/admin/audit?limit= — recent audit events (default 50, max 200)

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
    const data = await service.listAudit(req.query ? req.query.limit : undefined);
    return respond.ok(res, data);
  } catch (err) {
    return respond.handleError(res, err, registry.get('log'));
  }
}

module.exports = withCors(handler);

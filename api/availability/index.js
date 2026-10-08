'use strict';
// GET    /api/availability           — public blocked map (+ ?date= detail)
// PUT    /api/availability           — admin upsert/disable override
// DELETE /api/availability?date=     — admin clear override (idempotent)

const { withCors } = require('../_lib/cors');
const registry = require('../_lib/registry');

async function handler(req, res) {
  const respond = registry.get('respond');

  try {
    if (req.method === 'GET') {
      const service = registry.get('service');
      const query = req.query || {};
      let data;
      if (Object.prototype.hasOwnProperty.call(query, 'date')) {
        // Single date (or empty ?date=) keeps its original behavior.
        data = await service.getAvailability(query.date);
      } else if (query.from !== undefined || query.to !== undefined) {
        // Inclusive range view: {blocked, capacity}.
        data = await service.getAvailabilityRange(query);
      } else {
        data = await service.getAvailability(undefined);
      }
      return respond.ok(res, data);
    }

    if (req.method === 'PUT') {
      const auth = registry.get('auth');
      await auth.requireAdmin(req);
      const body = await respond.readBody(req);
      const service = registry.get('service');
      const data = await service.setAvailability(body);
      return respond.ok(res, data);
    }

    if (req.method === 'DELETE') {
      const auth = registry.get('auth');
      await auth.requireAdmin(req);
      const date = req.query ? req.query.date : '';
      const service = registry.get('service');
      const data = await service.clearAvailability(date);
      return respond.ok(res, data);
    }

    return respond.fail(res, 'method_not_allowed', 'Método no permitido.', 405);
  } catch (err) {
    return respond.handleError(res, err, registry.get('log'));
  }
}

module.exports = withCors(handler);

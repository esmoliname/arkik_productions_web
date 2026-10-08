'use strict';
// GET   /api/bookings/[code] — admin detail; voucher payload only with ?include=voucher
// PATCH /api/bookings/[code] — admin edit of contact fields only

const { withCors } = require('../../_lib/cors');
const registry = require('../../_lib/registry');

async function handler(req, res) {
  const respond = registry.get('respond');

  try {
    const code = req.query ? req.query.code : '';

    if (req.method === 'GET') {
      const auth = registry.get('auth');
      await auth.requireAdmin(req);
      const includeVoucher = req.query && req.query.include === 'voucher';
      const service = registry.get('service');
      const data = await service.getBooking(code, includeVoucher);
      return respond.ok(res, data);
    }

    if (req.method === 'PATCH') {
      const auth = registry.get('auth');
      await auth.requireAdmin(req);
      const body = await respond.readBody(req);
      const service = registry.get('service');
      const data = await service.updateBooking(code, body);
      return respond.ok(res, data);
    }

    return respond.fail(res, 'method_not_allowed', 'Método no permitido.', 405);
  } catch (err) {
    return respond.handleError(res, err, registry.get('log'));
  }
}

module.exports = withCors(handler);

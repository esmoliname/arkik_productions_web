'use strict';
// GET  /api/bookings       — admin list with filters (status/date/from/to/q/limit)
// POST /api/bookings       — public booking creation (rate limited, idempotent)

const { withCors } = require('../_lib/cors');
const registry = require('../_lib/registry');

const MAX_BODY_CHARS = 280000;

async function handler(req, res) {
  const respond = registry.get('respond');

  try {
    if (req.method === 'GET') {
      const auth = registry.get('auth');
      await auth.requireAdmin(req);
      const service = registry.get('service');
      const data = await service.listBookings(req.query || {});
      return respond.ok(res, data);
    }

    if (req.method === 'POST') {
      const body = await respond.readBody(req);
      // Cheap size guard measured on the serialized payload.
      let size = 0;
      try {
        size = JSON.stringify(body).length;
      } catch (err) {
        throw respond.appError('invalid_json', 'Cuerpo JSON inválido.', 400);
      }
      if (size > MAX_BODY_CHARS) {
        return respond.fail(res, 'payload_too_large', 'Solicitud demasiado grande.', 413);
      }

      const rawKey = req.headers ? req.headers['x-idempotency-key'] : null;
      const idempotencyKey =
        typeof rawKey === 'string' && rawKey.trim() !== '' ? rawKey.trim() : null;

      const service = registry.get('service');
      const result = await service.createBooking({
        body,
        ip: respond.clientIp(req),
        idempotencyKey
      });
      return respond.ok(res, { booking: result.booking }, result.status);
    }

    return respond.fail(res, 'method_not_allowed', 'Método no permitido.', 405);
  } catch (err) {
    return respond.handleError(res, err, registry.get('log'));
  }
}

module.exports = withCors(handler);

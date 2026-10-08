'use strict';
// PATCH /api/bookings/[code]/reschedule — admin move {selectedDate, selectedTime}

const { withCors } = require('../../_lib/cors');
const registry = require('../../_lib/registry');

async function handler(req, res) {
  const respond = registry.get('respond');

  try {
    if (req.method !== 'PATCH') {
      return respond.fail(res, 'method_not_allowed', 'Método no permitido.', 405);
    }

    const auth = registry.get('auth');
    await auth.requireAdmin(req);

    const body = await respond.readBody(req);
    const service = registry.get('service');
    const data = await service.rescheduleBooking(req.query ? req.query.code : '', {
      selectedDate: body ? body.selectedDate : undefined,
      selectedTime: body ? body.selectedTime : undefined
    });
    return respond.ok(res, data);
  } catch (err) {
    return respond.handleError(res, err, registry.get('log'));
  }
}

module.exports = withCors(handler);

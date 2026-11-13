'use strict';
// GET /api/admin/dashboard — Zero-Trust protected payload for the Admin Portal.
// Validates the HttpOnly session cookie BEFORE returning any metrics, bookings,
// pricing overrides, or availability data.

const { withCors } = require('../_lib/cors');
const registry = require('../_lib/registry');

const DEFAULT_STATS = {
  totalBookings: 0,
  confirmedCount: 0,
  pendingCount: 0,
  completedCount: 0,
  cancelledCount: 0,
  confirmedRevenue: 0,
  pendingDeposits: 0,
  upcomingEventsCount: 0
};

async function handler(req, res) {
  const respond = registry.get('respond');

  try {
    if (req.method !== 'GET') {
      return respond.fail(res, 'method_not_allowed', 'Método no permitido.', 405);
    }

    const auth = registry.get('auth');
    const service = registry.get('service');
    const config = registry.get('config');

    // Enforce HttpOnly session cookie validation before touching any data
    const session = await auth.requireAdmin(req);

    let stats = DEFAULT_STATS;
    let bookings = [];
    let total = 0;
    let pricing = {
      overrides: { services: {}, extras: {} },
      rates: Object.assign({}, config.DEFAULTS ? config.DEFAULTS.rates : {})
    };
    let availability = {};

    try {
      const [statsRes, bookingsRes, pricingRes, availabilityRes] = await Promise.all([
        service.getStats(),
        service.listBookings({ limit: 500 }),
        service.getPricing(),
        service.getAvailability()
      ]);

      if (statsRes && typeof statsRes === 'object') stats = statsRes;
      if (bookingsRes && Array.isArray(bookingsRes.bookings)) {
        bookings = bookingsRes.bookings;
        total = Number(bookingsRes.total) || bookings.length;
      }
      if (pricingRes && typeof pricingRes === 'object') pricing = pricingRes;
      if (availabilityRes && availabilityRes.blocked && typeof availabilityRes.blocked === 'object') {
        availability = availabilityRes.blocked;
      }
    } catch (dbErr) {
      // If running in stateless env-PIN mode without a database connection,
      // still return the authenticated session envelope and baseline structures.
      const isDbUnavailable = dbErr && (dbErr.kind === 'db_unavailable' || dbErr.code === 'no_database' || dbErr.status === 503);
      if (!isDbUnavailable) throw dbErr;
    }

    res.setHeader('Cache-Control', 'private, no-store');
    return respond.ok(res, {
      role: session.role,
      expiresAt: session.expiresAt,
      stats,
      bookings,
      total,
      pricing,
      availability
    });
  } catch (err) {
    return respond.handleError(res, err, registry.get('log'));
  }
}

module.exports = withCors(handler);


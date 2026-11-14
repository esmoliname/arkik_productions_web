'use strict';
// GET /api/admin/dashboard — Zero-Trust protected payload for the Admin Portal.
// Validates the HttpOnly session cookie BEFORE returning any metrics, bookings,
// pricing overrides, or availability data.

const { withCors } = require('../_lib/cors');
const registry = require('../_lib/registry');

const DEFAULT_STATS = {
  total: 0,
  pendiente: 0,
  confirmada: 0,
  realizada: 0,
  cancelada: 0,
  revenue: { gross: 0, deposits: 0, balances: 0 },
  byProvince: [],
  upcoming: [],
  blockedCount: 0,
  pendingVouchers: 0
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
    let auditEvents = [];

    try {
      const [statsRes, bookingsRes, pricingRes, availabilityRes, auditRes] = await Promise.all([
        service.getStats(),
        service.listBookings({ limit: 500 }),
        service.getPricing(),
        service.getAvailability(),
        typeof service.listAudit === 'function' ? service.listAudit(50) : Promise.resolve({ events: [] })
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
      if (auditRes && Array.isArray(auditRes.events)) {
        auditEvents = auditRes.events;
      }
    } catch (dbErr) {
      // Allow empty dashboard fallback ONLY when running in database-less env-PIN mode.
      // When DATABASE_URL IS configured, database/migration failures must surface as 503.
      const isNoDatabase = !config.databaseUrl && dbErr && (dbErr.kind === 'db_unavailable' || dbErr.code === 'no_database' || dbErr.status === 503);
      if (!isNoDatabase) throw dbErr;
    }

    res.setHeader('Cache-Control', 'private, no-store');
    return respond.ok(res, {
      role: session.role,
      expiresAt: session.expiresAt,
      stats,
      bookings,
      total,
      pricing,
      availability,
      auditEvents
    });
  } catch (err) {
    return respond.handleError(res, err, registry.get('log'));
  }
}

module.exports = withCors(handler);


import health from '../api/health.js';
import ready from '../api/ready.js';
import pricing from '../api/pricing.js';
import adminAudit from '../api/admin/audit.js';
import adminDashboard from '../api/admin/dashboard.js';
import adminLogin from '../api/admin/login.js';
import adminLogout from '../api/admin/logout.js';
import adminPricing from '../api/admin/pricing.js';
import adminSession from '../api/admin/session.js';
import adminStats from '../api/admin/stats.js';
import availability from '../api/availability/index.js';
import bookingsIndex from '../api/bookings/index.js';
import bookingsCode from '../api/bookings/[code]/index.js';
import bookingsReschedule from '../api/bookings/[code]/reschedule.js';
import bookingsStatus from '../api/bookings/[code]/status.js';

import { invokeHandler } from './_lib/cf-adapter.js';

// Static route table. Patterns use :param for single path segments.
const ROUTES = [
  { pattern: ['api', 'health'], handler: health },
  { pattern: ['api', 'ready'], handler: ready },
  { pattern: ['api', 'pricing'], handler: pricing },
  { pattern: ['api', 'admin', 'audit'], handler: adminAudit },
  { pattern: ['api', 'admin', 'dashboard'], handler: adminDashboard },
  { pattern: ['api', 'admin', 'login'], handler: adminLogin },
  { pattern: ['api', 'admin', 'logout'], handler: adminLogout },
  { pattern: ['api', 'admin', 'pricing'], handler: adminPricing },
  { pattern: ['api', 'admin', 'session'], handler: adminSession },
  { pattern: ['api', 'admin', 'stats'], handler: adminStats },
  { pattern: ['api', 'availability'], handler: availability },
  { pattern: ['api', 'bookings'], handler: bookingsIndex },
  { pattern: ['api', 'bookings', ':code'], handler: bookingsCode },
  { pattern: ['api', 'bookings', ':code', 'reschedule'], handler: bookingsReschedule },
  { pattern: ['api', 'bookings', ':code', 'status'], handler: bookingsStatus },
];

function matchRoute(segments) {
  for (const route of ROUTES) {
    if (route.pattern.length !== segments.length) continue;
    const params = {};
    let ok = true;
    for (let i = 0; i < route.pattern.length; i++) {
      const p = route.pattern[i];
      if (p.startsWith(':')) {
        params[p.slice(1)] = decodeURIComponent(segments[i]);
      } else if (p !== segments[i]) {
        ok = false;
        break;
      }
    }
    if (ok) return { handler: route.handler, params };
  }
  return null;
}

export async function onRequest(context) {
  const url = new URL(context.request.url);
  const segments = url.pathname.replace(/^\/+/, '').split('/').filter(Boolean);

  // Only handle /api/* paths; let static assets pass through.
  if (segments[0] !== 'api') {
    return context.next();
  }

  const matched = matchRoute(segments);
  if (!matched) {
    return new Response(JSON.stringify({ success: false, error: { code: 'not_found', message: 'Ruta no encontrada.' } }), {
      status: 404,
      headers: { 'content-type': 'application/json' }
    });
  }

  return invokeHandler(matched.handler, context.request, context.env, matched.params);
}

'use strict';
// POST /api/admin/logout — destroy the session row and clear the cookie

const { withCors } = require('../_lib/cors');
const registry = require('../_lib/registry');

async function handler(req, res) {
  const respond = registry.get('respond');

  try {
    if (req.method !== 'POST') {
      return respond.fail(res, 'method_not_allowed', 'Método no permitido.', 405);
    }

    const auth = registry.get('auth');
    const service = registry.get('service');

    // Always clear the browser cookie on logout, even if session cleanup fails.
    res.setHeader('Set-Cookie', auth.clearSessionCookie());
    const token = auth.getSessionToken(req);
    let data = { ok: true };
    try {
      data = await service.logout(token);
    } catch (err) {
      const isDbDown = err && (err.kind === 'db_unavailable' || err.code === 'no_database' || err.status === 503);
      if (!isDbDown) throw err;
    }
    return respond.ok(res, data);
  } catch (err) {
    return respond.handleError(res, err, registry.get('log'));
  }
}

module.exports = withCors(handler);

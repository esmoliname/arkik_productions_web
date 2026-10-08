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

    const token = auth.getSessionToken(req);
    const data = await service.logout(token);

    res.setHeader('Set-Cookie', auth.clearSessionCookie());
    return respond.ok(res, data);
  } catch (err) {
    return respond.handleError(res, err, registry.get('log'));
  }
}

module.exports = withCors(handler);

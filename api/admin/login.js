'use strict';
// POST /api/admin/login — {role, pin} -> session cookie (sliding, 15 min)

const { withCors } = require('../_lib/cors');
const registry = require('../_lib/registry');

async function handler(req, res) {
  const respond = registry.get('respond');

  try {
    if (req.method !== 'POST') {
      return respond.fail(res, 'method_not_allowed', 'Método no permitido.', 405);
    }

    const body = await respond.readBody(req);
    const service = registry.get('service');
    const auth = registry.get('auth');

    const result = await service.login({
      role: body ? body.role : undefined,
      pin: body ? body.pin : undefined,
      ip: respond.clientIp(req)
    });

    res.setHeader('Set-Cookie', auth.sessionCookie(result.token));
    // The token itself never reaches the response body.
    return respond.ok(res, { role: result.role, expiresAt: result.expiresAt });
  } catch (err) {
    return respond.handleError(res, err, registry.get('log'));
  }
}

module.exports = withCors(handler);

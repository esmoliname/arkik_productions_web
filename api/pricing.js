'use strict';
// GET /api/pricing — public read-only pricing configuration.
// Same config rows the admin endpoint reads (namespace 'pricing': catalog,
// overrides, rates). No auth; the admin PUT under /api/admin/pricing still
// requires a session. Success responses are cacheable for 60 seconds.

const { withCors } = require('./_lib/cors');
const registry = require('./_lib/registry');

const CACHE_CONTROL = 'public, max-age=60';

async function handler(req, res) {
  const respond = registry.get('respond');

  try {
    if (req.method !== 'GET') {
      return respond.fail(res, 'method_not_allowed', 'Método no permitido.', 405);
    }

    const service = registry.get('service');
    const data = await service.getPublicPricing();

    // Set only on success so failures are never cached by intermediaries.
    res.setHeader('Cache-Control', CACHE_CONTROL);
    return respond.ok(res, data);
  } catch (err) {
    return respond.handleError(res, err, registry.get('log'));
  }
}

module.exports = withCors(handler);

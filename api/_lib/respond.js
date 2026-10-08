'use strict';
// Response envelope helpers.
//   success: {success:true, data}
//   error:   {success:false, error:{code, message, ...extra}}
// Health (/api/health) builds its own shape and does not use these helpers.

const { log } = require('./log');
const db = require('./db');

function ok(res, data, status) {
  return res.status(status || 200).json({ success: true, data });
}

function fail(res, code, message, status, extra) {
  const error = { code, message };
  if (extra && typeof extra === 'object') {
    for (const key of Object.keys(extra)) error[key] = extra[key];
  }
  return res.status(status || 400).json({ success: false, error });
}

// Application-level error carrying its own HTTP mapping.
function appError(code, message, status, extra) {
  const err = new Error(message);
  err.arkikApp = true;
  err.code = code;
  err.status = status || 400;
  if (extra) err.extra = extra;
  return err;
}

function validationError(details, message) {
  return appError('validation_error', message || 'Datos de reserva inválidos.', 400, {
    details: Array.isArray(details) ? details : []
  });
}

function serviceUnavailable(res) {
  return fail(res, 'service_unavailable', 'Servicio no disponible, intente de nuevo.', 503);
}

function safeMessage(err) {
  if (!err) return 'unknown error';
  const message = err.message ? String(err.message) : String(err);
  return message.replace(/postgres(ql)?:\/\/\S+/gi, '[redacted]');
}

// Single error funnel used by every handler.
// `logger` may be the log function or the log module ({log}).
function handleError(res, err, logger) {
  const write =
    typeof logger === 'function'
      ? logger
      : logger && typeof logger.log === 'function'
        ? logger.log
        : log;
  if (res.headersSent) {
    write('ERROR', 'response already sent before error handling');
    return undefined;
  }
  if (err && err.arkikApp) {
    return fail(res, err.code, err.message, err.status || 400, err.extra);
  }
  if (err && err.name === 'SyntaxError') {
    write('ERROR', 'invalid json body');
    return fail(res, 'invalid_json', 'Cuerpo JSON inválido.', 400);
  }
  const unavailable = db.isDbUnavailable(err);
  write('ERROR', `${(err && err.code) || 'unhandled'} ${safeMessage(err)}`, {
    kind: unavailable ? 'db_unavailable' : 'internal'
  });
  if (unavailable) {
    return serviceUnavailable(res);
  }
  return fail(res, 'internal_error', 'Error interno del servidor.', 500);
}

// Parse the request body. Vercel usually pre-parses JSON into req.body; the
// stream branch keeps the module usable with plain Node test servers.
async function readBody(req) {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === 'string') return parseJson(req.body);
    if (Buffer.isBuffer(req.body)) return parseJson(req.body.toString('utf8'));
    return req.body;
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length || 0;
    if (size > 400000) {
      throw appError('payload_too_large', 'Solicitud demasiado grande.', 413);
    }
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  return parseJson(Buffer.concat(chunks).toString('utf8'));
}

function parseJson(raw) {
  if (!raw || !String(raw).trim()) return {};
  try {
    return JSON.parse(raw);
  } catch (err) {
    throw appError('invalid_json', 'Cuerpo JSON inválido.', 400);
  }
}

// First x-forwarded-for hop. Never logged anywhere.
function clientIp(req) {
  const forwarded = req && req.headers ? req.headers['x-forwarded-for'] : null;
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }
  return 'unknown';
}

module.exports = {
  ok,
  fail,
  appError,
  validationError,
  handleError,
  serviceUnavailable,
  readBody,
  clientIp
};

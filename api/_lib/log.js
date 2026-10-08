'use strict';
// Central logger. Every line is prefixed with [ARKIK API] and a fixed tag.
// Hard rule: never log DATABASE_URL, PINs, session tokens, voucher base64,
// credentials or client IPs. Sanitizing happens here so callers cannot leak.

const TAGS = ['HTTP', 'BOOKING', 'AVAILABILITY', 'AUTH', 'DATABASE', 'ERROR'];

const SENSITIVE_KEY = /^(pin|pin_hash|pinhash|token|token_hash|tokenhash|password|secret|database_url|databaseurl|voucher_image|voucherimage|authorization|cookie|session|apikey|api_key)$/i;

const MAX_STRING = 240;

function redactString(value) {
  let out = String(value);
  out = out.replace(/postgres(ql)?:\/\/\S+/gi, '[redacted-connection-string]');
  out = out.replace(/^data:[^,]*;base64,[\s\S]*$/i, '[redacted-voucher]');
  if (out.length > MAX_STRING) out = `${out.slice(0, MAX_STRING)}...`;
  return out;
}

function sanitize(value, depth) {
  const level = depth || 0;
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return redactString(value);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (level >= 3) return '[deep]';
  if (Array.isArray(value)) return value.slice(0, 20).map((item) => sanitize(item, level + 1));
  if (typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value)) {
      if (SENSITIVE_KEY.test(key)) {
        out[key] = '[redacted]';
        continue;
      }
      out[key] = sanitize(value[key], level + 1);
    }
    return out;
  }
  return String(value);
}

function log(tag, message, meta) {
  const safeTag = TAGS.indexOf(tag) !== -1 ? tag : 'HTTP';
  let line = `[ARKIK API] ${safeTag} ${redactString(message)}`;
  if (meta !== undefined && meta !== null) {
    try {
      line += ` ${JSON.stringify(sanitize(meta))}`;
    } catch (err) {
      line += ' [unserializable-meta]';
    }
  }
  try {
    console.log(line);
  } catch (err) {
    // Logging must never break the request path.
  }
}

module.exports = { log, TAGS, sanitize };

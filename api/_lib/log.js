'use strict';
// Central logger. Every line is prefixed with [ARKIK API] and a fixed tag.
// Hard rule: never log DATABASE_URL, PINs, session tokens, voucher base64,
// credentials or client IPs. Sanitizing happens here so callers cannot leak.

const TAGS = ['HTTP', 'BOOKING', 'AVAILABILITY', 'AUTH', 'DATABASE', 'ERROR'];

const SENSITIVE_EXACT = new Set([
  'pin',
  'pinhash',
  'token',
  'tokenhash',
  'password',
  'passwd',
  'secret',
  'sessionsecret',
  'adminsessionsecret',
  'databaseurl',
  'directdatabaseurl',
  'directadmindatabaseurl',
  'connectionstring',
  'voucherimage',
  'authorization',
  'cookie',
  'setcookie',
  'session',
  'sessionid',
  'sessiontoken',
  'apikey',
  'xapikey',
  'ownerpin',
  'itpin',
  'adminownerpin',
  'adminitpin'
]);
const SENSITIVE_TOKEN_RE = /^(pin|password|passwd|secret|token|cookie|authorization)$/;
const SESSION_SENSITIVE_SECOND_RE = /^(id|token|secret|key|cookie|hash)$/;

const MAX_STRING = 240;

function isSensitiveKey(key) {
  const raw = String(key || '').trim();
  if (!raw) return false;
  const compact = raw.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (SENSITIVE_EXACT.has(compact)) return true;

  const segments = raw
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .split(/[_-]+/)
    .filter(Boolean);

  if (segments.some((seg) => SENSITIVE_TOKEN_RE.test(seg))) return true;
  if (segments.includes('database') && segments.includes('url')) return true;
  if (segments.includes('connection') && segments.includes('string')) return true;
  if (segments.includes('voucher') && segments.includes('image')) return true;
  if (segments.includes('api') && segments.includes('key')) return true;
  if (
    segments.includes('session') &&
    (segments[segments.length - 1] === 'session' ||
      segments.some((seg) => SESSION_SENSITIVE_SECOND_RE.test(seg)))
  ) {
    return true;
  }
  return false;
}

function redactString(value) {
  let out = String(value);
  out = out.replace(/postgres(ql)?:\/\/\S+/gi, '[redacted-connection-string]');
  out = out.replace(/scrypt\$\S+/gi, '[redacted-hash]');
  out = out.replace(/Bearer\s+\S+/gi, 'Bearer [redacted]');
  out = out.replace(/(__Host-session|arkik_session)=[^;\s"']+/gi, '$1=[redacted]');
  out = out.replace(/\bv1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[redacted-token]');
  out = out.replace(/data:[^\s,"']*;base64,[^\s,"']*/gi, '[redacted-voucher]');
  out = out.replace(
    /\b(admin_?(?:owner|it)?_?pin|admin_?session_?secret|new_?password|password|session_?token)\s*([:=])\s*("[^"]*"|'[^']*'|[^\s,;]+)/gi,
    '$1$2[redacted]'
  );
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
      if (isSensitiveKey(key)) {
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

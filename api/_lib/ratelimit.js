'use strict';
// DB-backed fixed-window rate limiter (rate_limits table).
// Windows roll over by timestamp comparison, so no background job is needed.

const registry = require('./registry');
const { appError } = require('./respond');

/**
 * Count one hit against `bucket`.
 * Returns {allowed, count, remaining, retryAfterMs}.
 */
async function consume(bucket, limit, windowMs) {
  const db = registry.get('db');
  const repo = registry.get('repo');
  const now = Date.now();

  const record = await db.withClient((client) => repo.hitRateLimit(client, bucket, now, windowMs));
  const retryAfterMs = Math.max(0, record.windowStart + windowMs - now);
  return {
    allowed: record.count <= limit,
    count: record.count,
    remaining: Math.max(0, limit - record.count),
    retryAfterMs
  };
}

/** Count a hit and throw appError('rate_limited', 429) when over the limit. */
async function enforce(params) {
  const result = await consume(params.bucket, params.limit, params.windowMs);
  if (!result.allowed) {
    throw appError(
      'rate_limited',
      params.message || 'Demasiadas solicitudes. Intente más tarde.',
      429
    );
  }
  return result;
}

module.exports = { consume, enforce };

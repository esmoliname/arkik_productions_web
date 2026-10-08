'use strict';
// Thin SQL layer. Every function takes (client, params): no pooling, no
// transactions, no business rules — those live in db.js and service.js.

const BOOKING_COLS = `
  id, code, status, client_name, client_phone, client_email, event_type,
  service_id, service_name, setup_display, teardown_display,
  to_char(selected_date, 'YYYY-MM-DD') AS selected_date, selected_time,
  province, canton, address, subtotal, travel_surcharge, grand_total,
  deposit_amount, remaining_balance, sinpe_reference, extras,
  voucher_mime, voucher_bytes, idempotency_key,
  voucher_image IS NOT NULL AS has_voucher,
  created_at, updated_at, confirmed_at, cancelled_at, completed_at`;

const BOOKING_COLS_WITH_VOUCHER = `${BOOKING_COLS}, voucher_image`;

const FIELD_COLUMNS = {
  clientName: 'client_name',
  clientPhone: 'client_phone',
  clientEmail: 'client_email',
  eventType: 'event_type',
  address: 'address',
  sinpeRef: 'sinpe_reference'
};

function toIso(value) {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return value.toISOString();
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function formatDateOnly(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value.slice(0, 10);
  if (value instanceof Date) {
    const month = String(value.getMonth() + 1).padStart(2, '0');
    const day = String(value.getDate()).padStart(2, '0');
    return `${value.getFullYear()}-${month}-${day}`;
  }
  return String(value).slice(0, 10);
}

function intOrNull(value) {
  if (value === null || value === undefined) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : null;
}

function escapeLike(value) {
  return String(value).replace(/[\\%_]/g, '\\$&');
}

function parseExtras(raw) {
  let extras = raw;
  if (typeof extras === 'string') {
    try {
      extras = JSON.parse(extras);
    } catch (err) {
      extras = {};
    }
  }
  if (!extras || typeof extras !== 'object') extras = {};
  const num = (value) => {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? Math.trunc(parsed) : 0;
  };
  return {
    extraHoursCount: num(extras.extraHoursCount),
    djHoursCount: num(extras.djHoursCount),
    subwoofersCount: num(extras.subwoofersCount),
    extraHoursTotal: num(extras.extraHoursTotal),
    djTotal: num(extras.djTotal),
    subwoofersTotal: num(extras.subwoofersTotal)
  };
}

// Database row -> public API shape (camelCase). voucherImage only on demand.
function mapBooking(row, options) {
  if (!row) return null;
  const opts = options || {};
  const booking = {
    code: row.code,
    status: row.status,
    clientName: row.client_name,
    clientPhone: row.client_phone,
    clientEmail: row.client_email || null,
    eventType: row.event_type,
    serviceId: row.service_id,
    serviceName: row.service_name,
    setupDisplay: row.setup_display || null,
    teardownDisplay: row.teardown_display || null,
    selectedDate: formatDateOnly(row.selected_date),
    selectedTime: row.selected_time,
    province: row.province,
    canton: row.canton,
    address: row.address || null,
    extras: parseExtras(row.extras),
    subtotal: row.subtotal,
    travelSurcharge: row.travel_surcharge,
    granTotal: row.grand_total,
    deposit50Amount: row.deposit_amount,
    remainingBalance: row.remaining_balance,
    sinpeRef: row.sinpe_reference || null,
    hasVoucher: row.has_voucher !== undefined && row.has_voucher !== null
      ? Boolean(row.has_voucher)
      : Boolean(row.voucher_image),
    voucherBytes: intOrNull(row.voucher_bytes),
    voucherMime: row.voucher_mime || null,
    createdAt: toIso(row.created_at),
    updatedAt: toIso(row.updated_at),
    confirmedAt: toIso(row.confirmed_at),
    cancelledAt: toIso(row.cancelled_at),
    completedAt: toIso(row.completed_at)
  };
  if (opts.includeVoucher && Object.prototype.hasOwnProperty.call(row, 'voucher_image')) {
    booking.voucherImage = row.voucher_image || null;
  }
  return booking;
}

// ---- bookings ----

async function codeExists(client, code) {
  const result = await client.query('SELECT 1 FROM bookings WHERE code = $1', [code]);
  return result.rowCount > 0;
}

// Serializes every writer for a given date (released on COMMIT/ROLLBACK).
async function lockDate(client, dateISO) {
  await client.query("SELECT pg_advisory_xact_lock(hashtext('arkik_date:' || $1::date))", [dateISO]);
}

async function insertBooking(client, p) {
  const result = await client.query(
    `INSERT INTO bookings (
      code, status, client_name, client_phone, client_email, event_type,
      service_id, service_name, setup_display, teardown_display,
      selected_date, selected_time, province, canton, address,
      subtotal, travel_surcharge, grand_total, deposit_amount, remaining_balance,
      sinpe_reference, extras, voucher_image, voucher_mime, voucher_bytes, idempotency_key
    ) VALUES (
      $1, $2, $3, $4, $5, $6,
      $7, $8, $9, $10,
      $11::date, $12, $13, $14, $15,
      $16, $17, $18, $19, $20,
      $21, $22::jsonb, $23, $24, $25, $26
    ) RETURNING ${BOOKING_COLS}`,
    [
      p.code,
      p.status,
      p.clientName,
      p.clientPhone,
      p.clientEmail,
      p.eventType,
      p.serviceId,
      p.serviceName,
      p.setupDisplay,
      p.teardownDisplay,
      p.selectedDate,
      p.selectedTime,
      p.province,
      p.canton,
      p.address,
      p.subtotal,
      p.travelSurcharge,
      p.grandTotal,
      p.depositAmount,
      p.remainingBalance,
      p.sinpeRef,
      JSON.stringify(p.extras),
      p.voucherImage,
      p.voucherMime,
      p.voucherBytes,
      p.idempotencyKey
    ]
  );
  return result.rows[0];
}

async function getBookingByCode(client, code, options) {
  const opts = options || {};
  const cols = opts.includeVoucher ? BOOKING_COLS_WITH_VOUCHER : BOOKING_COLS;
  let sql = `SELECT ${cols} FROM bookings WHERE code = $1`;
  if (opts.forUpdate) sql += ' FOR UPDATE';
  const result = await client.query(sql, [code]);
  return result.rows[0] || null;
}

async function getIdempotencyBooking(client, key) {
  const result = await client.query(
    `SELECT ${BOOKING_COLS} FROM idempotency_keys ik
     INNER JOIN bookings b ON b.id = ik.booking_id
     WHERE ik.key = $1`,
    [key]
  );
  return result.rows[0] || null;
}

async function insertIdempotency(client, key, bookingId) {
  await client.query('INSERT INTO idempotency_keys (key, booking_id) VALUES ($1, $2)', [key, bookingId]);
}

// Active (non-cancelled) start times for a date; optionally excluding one code.
async function listActiveTimes(client, dateISO, excludeCode) {
  const params = [dateISO];
  let sql = "SELECT selected_time FROM bookings WHERE selected_date = $1::date AND status <> 'cancelada'";
  if (excludeCode) {
    params.push(excludeCode);
    sql += ` AND code <> $${params.length}`;
  }
  sql += ' ORDER BY selected_time';
  const result = await client.query(sql, params);
  return result.rows.map((row) => row.selected_time);
}

// Active (non-cancelled) start times for an inclusive date range, grouped by date.
async function listActiveTimesInRange(client, fromISO, toISO) {
  const result = await client.query(
    `SELECT to_char(selected_date, 'YYYY-MM-DD') AS date, selected_time
     FROM bookings
     WHERE selected_date >= $1::date AND selected_date <= $2::date AND status <> 'cancelada'
     ORDER BY selected_date ASC, selected_time ASC`,
    [fromISO, toISO]
  );
  return result.rows;
}

async function listBookings(client, filters) {
  const where = ['1 = 1'];
  const params = [];
  const push = (clause, value) => {
    params.push(value);
    const index = params.length;
    // Function replacement: a string replacement would reinterpret `$10` etc.
    where.push(clause.replace('?', () => `$${index}`));
  };

  if (filters.status) push('status = ?', filters.status);
  if (filters.date) push('selected_date = ?::date', filters.date);
  if (filters.from) push('selected_date >= ?::date', filters.from);
  if (filters.to) push('selected_date <= ?::date', filters.to);
  if (filters.q) {
    params.push(`%${escapeLike(filters.q)}%`);
    const placeholder = `$${params.length}`;
    where.push(`(code ILIKE ${placeholder} OR client_name ILIKE ${placeholder} OR client_phone ILIKE ${placeholder})`);
  }

  const whereSql = where.join(' AND ');
  const countResult = await client.query(`SELECT count(*)::int AS total FROM bookings WHERE ${whereSql}`, params);

  params.push(filters.limit || 100);
  const rowsResult = await client.query(
    `SELECT ${BOOKING_COLS} FROM bookings WHERE ${whereSql} ORDER BY created_at DESC LIMIT $${params.length}`,
    params
  );
  return { rows: rowsResult.rows, total: countResult.rows[0].total };
}

async function updateBookingFields(client, code, values) {
  const sets = [];
  const params = [code];
  for (const key of Object.keys(values)) {
    const column = FIELD_COLUMNS[key];
    if (!column) continue;
    params.push(values[key]);
    sets.push(`${column} = $${params.length}`);
  }
  if (!sets.length) return null;
  sets.push('updated_at = now()');
  const result = await client.query(
    `UPDATE bookings SET ${sets.join(', ')} WHERE code = $1 RETURNING ${BOOKING_COLS}`,
    params
  );
  return result.rows[0] || null;
}

async function updateBookingStatus(client, code, status) {
  const result = await client.query(
    `UPDATE bookings SET
       status = $2,
       updated_at = now(),
       confirmed_at = CASE
         WHEN $2 = 'confirmada' THEN now()
         WHEN $2 = 'pendiente' THEN NULL
         ELSE confirmed_at END,
       cancelled_at = CASE
         WHEN $2 = 'cancelada' THEN now()
         WHEN $2 = 'pendiente' THEN NULL
         ELSE cancelled_at END,
       completed_at = CASE
         WHEN $2 = 'realizada' THEN now()
         WHEN $2 = 'pendiente' THEN NULL
         ELSE completed_at END
     WHERE code = $1
     RETURNING ${BOOKING_COLS}`,
    [code, status]
  );
  return result.rows[0] || null;
}

async function updateBookingSchedule(client, code, selectedDate, selectedTime) {
  const result = await client.query(
    `UPDATE bookings SET selected_date = $2::date, selected_time = $3, updated_at = now()
     WHERE code = $1 RETURNING ${BOOKING_COLS}`,
    [code, selectedDate, selectedTime]
  );
  return result.rows[0] || null;
}

// ---- availability ----

async function listAvailability(client) {
  const result = await client.query(
    "SELECT to_char(date, 'YYYY-MM-DD') AS date, state, reason FROM availability ORDER BY date ASC"
  );
  return result.rows;
}

async function getAvailability(client, dateISO) {
  const result = await client.query(
    "SELECT to_char(date, 'YYYY-MM-DD') AS date, state, reason FROM availability WHERE date = $1::date",
    [dateISO]
  );
  return result.rows[0] || null;
}

async function upsertAvailability(client, dateISO, state, reason) {
  const result = await client.query(
    `INSERT INTO availability (date, state, reason, updated_at)
     VALUES ($1::date, $2, $3, now())
     ON CONFLICT (date) DO UPDATE SET state = EXCLUDED.state, reason = EXCLUDED.reason, updated_at = now()
     RETURNING to_char(date, 'YYYY-MM-DD') AS date, state, reason`,
    [dateISO, state, reason]
  );
  return result.rows[0];
}

async function deleteAvailability(client, dateISO) {
  const result = await client.query('DELETE FROM availability WHERE date = $1::date', [dateISO]);
  return result.rowCount;
}

// ---- audit ----

async function insertAudit(client, entry) {
  await client.query(
    'INSERT INTO audit_log (action, entity_type, entity_id, actor, metadata) VALUES ($1, $2, $3, $4, $5::jsonb)',
    [
      entry.action,
      entry.entityType || null,
      entry.entityId || null,
      entry.actor || null,
      entry.metadata === undefined || entry.metadata === null ? null : JSON.stringify(entry.metadata)
    ]
  );
}

async function listAudit(client, limit) {
  const result = await client.query(
    'SELECT action, entity_type, entity_id, actor, metadata, created_at FROM audit_log ORDER BY created_at DESC, id DESC LIMIT $1',
    [limit]
  );
  return result.rows;
}

// ---- config ----

async function getConfigRows(client) {
  const result = await client.query('SELECT namespace, key, value FROM config');
  return result.rows;
}

async function putConfigValue(client, namespace, key, value) {
  await client.query(
    `INSERT INTO config (namespace, key, value, updated_at) VALUES ($1, $2, $3::jsonb, now())
     ON CONFLICT (namespace, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
    [namespace, key, JSON.stringify(value)]
  );
}

// ---- admin credentials ----

async function getCredentialForUpdate(client, role) {
  const result = await client.query(
    'SELECT role, pin_hash, failed_attempts, lock_level, locked_until FROM admin_credentials WHERE role = $1 FOR UPDATE',
    [role]
  );
  return result.rows[0] || null;
}

async function updateCredential(client, role, changes) {
  await client.query(
    'UPDATE admin_credentials SET failed_attempts = $2, lock_level = $3, locked_until = $4, updated_at = now() WHERE role = $1',
    [role, changes.failedAttempts, changes.lockLevel, changes.lockedUntil || null]
  );
}

async function resetCredential(client, role) {
  await client.query(
    'UPDATE admin_credentials SET failed_attempts = 0, lock_level = 0, locked_until = NULL, updated_at = now() WHERE role = $1',
    [role]
  );
}

async function insertCredentialIfMissing(client, role, pinHash) {
  const result = await client.query(
    'INSERT INTO admin_credentials (role, pin_hash) VALUES ($1, $2) ON CONFLICT (role) DO NOTHING',
    [role, pinHash]
  );
  return result.rowCount > 0;
}

async function listCredentialRoles(client) {
  const result = await client.query('SELECT role FROM admin_credentials ORDER BY role');
  return result.rows.map((row) => row.role);
}

// ---- admin sessions ----

async function createSession(client, params) {
  await client.query(
    'INSERT INTO admin_sessions (token_hash, role, expires_at, last_seen_at) VALUES ($1, $2, $3, now())',
    [params.tokenHash, params.role, params.expiresAt]
  );
}

async function getSession(client, tokenHash) {
  const result = await client.query(
    'SELECT role, expires_at, last_seen_at FROM admin_sessions WHERE token_hash = $1 AND expires_at > now()',
    [tokenHash]
  );
  return result.rows[0] || null;
}

async function touchSession(client, tokenHash, expiresAt, lastSeenAt) {
  const result = await client.query(
    'UPDATE admin_sessions SET expires_at = $2, last_seen_at = $3 WHERE token_hash = $1 RETURNING expires_at',
    [tokenHash, expiresAt, lastSeenAt]
  );
  return result.rows[0] || null;
}

async function deleteSession(client, tokenHash) {
  const result = await client.query('DELETE FROM admin_sessions WHERE token_hash = $1 RETURNING role', [tokenHash]);
  return result.rows[0] ? result.rows[0].role : null;
}

// ---- rate limits ----

// Fixed window: expires when window_start + windowMs has elapsed.
async function hitRateLimit(client, bucket, now, windowMs) {
  const result = await client.query(
    `INSERT INTO rate_limits (bucket, window_start, count)
     VALUES ($1, $2, 1)
     ON CONFLICT (bucket) DO UPDATE SET
       count = CASE WHEN rate_limits.window_start <= $3 THEN 1 ELSE rate_limits.count + 1 END,
       window_start = CASE WHEN rate_limits.window_start <= $3 THEN $2 ELSE rate_limits.window_start END
     RETURNING count, window_start`,
    [bucket, new Date(now), new Date(now - windowMs)]
  );
  const row = result.rows[0];
  return { count: Number(row.count), windowStart: new Date(row.window_start).getTime() };
}

// ---- stats ----

async function getStats(client, window) {
  const counts = await client.query(
    `SELECT count(*)::int AS total,
            count(*) FILTER (WHERE status = 'pendiente')::int AS pendiente,
            count(*) FILTER (WHERE status = 'confirmada')::int AS confirmada,
            count(*) FILTER (WHERE status = 'realizada')::int AS realizada,
            count(*) FILTER (WHERE status = 'cancelada')::int AS cancelada
     FROM bookings`
  );
  const revenue = await client.query(
    `SELECT COALESCE(sum(grand_total), 0)::int AS gross,
            COALESCE(sum(deposit_amount), 0)::int AS deposits,
            COALESCE(sum(remaining_balance), 0)::int AS balances
     FROM bookings WHERE status IN ('confirmada', 'realizada')`
  );
  const byProvince = await client.query(
    'SELECT province, count(*)::int AS count FROM bookings GROUP BY province ORDER BY count DESC, province ASC'
  );
  const upcoming = await client.query(
    `SELECT to_char(selected_date, 'YYYY-MM-DD') AS date, count(*)::int AS count
     FROM bookings
     WHERE status <> 'cancelada' AND selected_date >= $1::date AND selected_date <= $2::date
     GROUP BY selected_date ORDER BY selected_date ASC`,
    [window.from, window.to]
  );
  const blocked = await client.query('SELECT count(*)::int AS blocked_count FROM availability');
  const pendingVouchers = await client.query(
    "SELECT count(*)::int AS pending FROM bookings WHERE status = 'pendiente'"
  );

  const totals = counts.rows[0];
  const money = revenue.rows[0];
  return {
    total: totals.total,
    pendiente: totals.pendiente,
    confirmada: totals.confirmada,
    realizada: totals.realizada,
    cancelada: totals.cancelada,
    revenue: { gross: money.gross, deposits: money.deposits, balances: money.balances },
    byProvince: byProvince.rows.map((row) => ({ province: row.province, count: row.count })),
    upcoming: upcoming.rows.map((row) => ({ date: row.date, count: row.count })),
    blockedCount: blocked.rows[0].blocked_count,
    pendingVouchers: pendingVouchers.rows[0].pending
  };
}

module.exports = {
  mapBooking,
  formatDateOnly,
  toIso,
  codeExists,
  lockDate,
  insertBooking,
  getBookingByCode,
  getIdempotencyBooking,
  insertIdempotency,
  listActiveTimes,
  listActiveTimesInRange,
  listBookings,
  updateBookingFields,
  updateBookingStatus,
  updateBookingSchedule,
  listAvailability,
  getAvailability,
  upsertAvailability,
  deleteAvailability,
  insertAudit,
  listAudit,
  getConfigRows,
  putConfigValue,
  getCredentialForUpdate,
  updateCredential,
  resetCredential,
  insertCredentialIfMissing,
  listCredentialRoles,
  createSession,
  getSession,
  touchSession,
  deleteSession,
  hitRateLimit,
  getStats
};

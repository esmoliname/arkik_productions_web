'use strict';
// Orchestration layer: every use case runs through withTransaction + pure
// logic + thin repo. Handlers resolve this module via registry.get('service')
// INSIDE the handler body so tests can swap it out.

const crypto = require('crypto');
const registry = require('./registry');
const configModule = require('./config');
const { appError, validationError } = require('./respond');

const CONFIG_TTL_MS = 60000;
const CODE_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const CODE_ATTEMPTS = 5;
const SESSION_TTL_MS = 15 * 60 * 1000;
const LOCK_BASE_MS = 300000; // 5 minutes, doubles per lock
const LOCK_MAX_MS = 3600000; // 1 hour cap
const MAX_FAILED_ATTEMPTS = 3;
const IDEMPOTENCY_KEY_RE = /^[A-Za-z0-9_-]{8,64}$/;

let cachedConfig = null;
let cachedAt = 0;

function invalidateConfigCache() {
  cachedConfig = null;
  cachedAt = 0;
}

// ---- configuration ----

function normalizeConfig(rows) {
  const map = new Map();
  for (const row of rows || []) map.set(`${row.namespace}:${row.key}`, row.value);

  const catalog = map.get('pricing:catalog');
  const provinces = map.get('geo:provinces');
  const gam = map.get('geo:gam');
  if (!Array.isArray(catalog) || !provinces || !Array.isArray(gam)) {
    // Migrations not applied: fail closed with the standard 503.
    throw appError('service_unavailable', 'Servicio no disponible, intente de nuevo.', 503);
  }

  const limits = Object.assign({}, configModule.DEFAULTS.limits, map.get('logistics:limits') || {});
  if (!Array.isArray(limits.timeSlots) || !limits.timeSlots.length) {
    limits.timeSlots = configModule.TIME_SLOTS;
  }
  const overrides = map.get('pricing:overrides') || {};

  return {
    limits,
    defaultStatus: map.get('logistics:defaultStatus') || configModule.DEFAULTS.defaultStatus,
    sinpe: Object.assign({}, configModule.DEFAULTS.sinpe, map.get('sinpe:config') || {}),
    catalog,
    overrides: {
      services: (overrides && overrides.services) || {},
      extras: (overrides && overrides.extras) || {}
    },
    rates: Object.assign({}, configModule.DEFAULTS.rates, map.get('pricing:rates') || {}),
    geo: {
      provinces,
      gam,
      nonGamExceptions: map.get('geo:nonGamExceptions') || {}
    },
    extrasUnit: configModule.DEFAULTS.extrasUnit
  };
}

async function loadConfig() {
  if (cachedConfig && Date.now() - cachedAt < CONFIG_TTL_MS) return cachedConfig;
  const db = registry.get('db');
  const repo = registry.get('repo');
  const rows = await db.withClient((client) => repo.getConfigRows(client));
  const normalized = normalizeConfig(rows);
  cachedConfig = normalized;
  cachedAt = Date.now();
  return normalized;
}

// ---- shared helpers ----

function generateCode() {
  const bytes = crypto.randomBytes(8);
  let code = 'ARK-';
  for (let i = 0; i < 8; i++) code += CODE_ALPHABET[bytes[i] % CODE_ALPHABET.length];
  return code;
}

async function recordAudit(entry) {
  const db = registry.get('db');
  const repo = registry.get('repo');
  await db.withClient((client) => repo.insertAudit(client, entry));
}

function normalizeCode(code) {
  return typeof code === 'string' ? code.trim().toUpperCase() : '';
}

function requireExisting(row, message) {
  if (!row) throw appError('not_found', message || 'Reserva no encontrada.', 404);
  return row;
}

// ---- bookings ----

async function createBooking(input) {
  const db = registry.get('db');
  const repo = registry.get('repo');
  const logic = registry.get('logic');
  const ratelimit = registry.get('ratelimit');

  // 1) rate limit per client IP
  await ratelimit.enforce({
    bucket: `create:${input.ip || 'unknown'}`,
    limit: 10,
    windowMs: 10 * 60 * 1000
  });

  const idempotencyKey = input.idempotencyKey || null;
  if (idempotencyKey && !IDEMPOTENCY_KEY_RE.test(idempotencyKey)) {
    throw appError('invalid_idempotency_key', 'Clave de idempotencia inválida.', 400);
  }

  // 2) replay: same key => same booking, no new row, no audit
  if (idempotencyKey) {
    const replay = await db.withClient((client) => repo.getIdempotencyBooking(client, idempotencyKey));
    if (replay) return { status: 200, booking: repo.mapBooking(replay, {}) };
  }

  const cfg = await loadConfig();
  const validated = logic.validateBookingPayload(input.body, cfg);
  if (!validated.ok) throw validationError(validated.errors);

  const value = validated.value;
  // 3) server-side pricing: client-sent amounts never reach this function's math
  const pricing = logic.computePricing(
    { serviceId: value.serviceId, extras: value.extras, province: value.province, canton: value.canton },
    cfg
  );

  const extras = {
    extraHoursCount: pricing.extraHoursCount,
    djHoursCount: pricing.djHoursCount,
    subwoofersCount: pricing.subwoofersCount,
    extraHoursTotal: pricing.extraHoursTotal,
    djTotal: pricing.djTotal,
    subwoofersTotal: pricing.subwoofersTotal
  };

  let lastError = null;
  for (let attempt = 0; attempt < CODE_ATTEMPTS; attempt++) {
    try {
      const row = await db.withTransaction(async (client) => {
        // Serialize writers for this date, then re-read capacity state.
        await repo.lockDate(client, value.selectedDate);
        const override = await repo.getAvailability(client, value.selectedDate);
        const times = await repo.listActiveTimes(client, value.selectedDate);

        const capacity = logic.assertCapacity({
          dateISO: value.selectedDate,
          time: value.selectedTime,
          existingTimes: times,
          overrideState: override ? override.state : null,
          config: cfg,
          now: new Date()
        });
        if (!capacity.ok) throw appError(capacity.code, capacity.message, capacity.status);

        const code = generateCode();
        if (await repo.codeExists(client, code)) {
          const err = appError('code_taken', 'code collision', 409);
          err.arkikRetry = true;
          throw err;
        }

        const inserted = await repo.insertBooking(client, {
          code,
          status: cfg.defaultStatus || 'pendiente',
          clientName: value.clientName,
          clientPhone: value.clientPhone,
          clientEmail: value.clientEmail,
          eventType: value.eventType,
          serviceId: value.serviceId,
          serviceName: value.serviceName,
          setupDisplay: value.setupDisplay,
          teardownDisplay: value.teardownDisplay,
          selectedDate: value.selectedDate,
          selectedTime: value.selectedTime,
          province: value.province,
          canton: value.canton,
          address: value.address,
          subtotal: pricing.subtotal,
          travelSurcharge: pricing.travelSurcharge,
          grandTotal: pricing.granTotal,
          depositAmount: pricing.deposit50Amount,
          remainingBalance: pricing.remainingBalance,
          sinpeRef: value.sinpeRef,
          extras,
          voucherImage: value.voucherImage,
          voucherMime: value.voucherMime,
          voucherBytes: value.voucherBytes,
          idempotencyKey
        });

        if (idempotencyKey) {
          try {
            await repo.insertIdempotency(client, idempotencyKey, inserted.id);
          } catch (err) {
            if (db.isUniqueViolation(err)) {
              const race = appError('idempotency_race', 'idempotency race', 409);
              race.arkikIdempotencyRace = true;
              throw race;
            }
            throw err;
          }
        }

        await repo.insertAudit(client, {
          action: 'BOOKING_CREATED',
          entityType: 'booking',
          entityId: code,
          actor: 'system',
          metadata: { date: value.selectedDate, serviceId: value.serviceId, grandTotal: pricing.granTotal }
        });

        return inserted;
      });

      return { status: 201, booking: repo.mapBooking(row, {}) };
    } catch (err) {
      if (err && err.arkikRetry) {
        lastError = err;
        continue; // regenerate the code and retry the whole transaction
      }
      if (err && err.arkikIdempotencyRace && idempotencyKey) {
        const existing = await db.withClient((client) => repo.getIdempotencyBooking(client, idempotencyKey));
        if (existing) return { status: 200, booking: repo.mapBooking(existing, {}) };
      }
      throw err;
    }
  }

  throw (
    lastError ||
    appError('conflict', 'No fue posible generar un código de reserva. Intente de nuevo.', 409)
  );
}

async function listBookings(query) {
  const db = registry.get('db');
  const repo = registry.get('repo');
  const logic = registry.get('logic');

  const validated = logic.validateListFilters(query);
  if (!validated.ok) throw validationError(validated.errors);

  const result = await db.withClient((client) => repo.listBookings(client, validated.value));
  return {
    bookings: result.rows.map((row) => repo.mapBooking(row, {})),
    total: result.total
  };
}

async function getBooking(code, includeVoucher) {
  const db = registry.get('db');
  const repo = registry.get('repo');
  const normalized = normalizeCode(code);
  if (!normalized) throw appError('not_found', 'Reserva no encontrada.', 404);

  const row = await db.withClient((client) =>
    repo.getBookingByCode(client, normalized, { includeVoucher: Boolean(includeVoucher) })
  );
  requireExisting(row);
  return { booking: repo.mapBooking(row, { includeVoucher: Boolean(includeVoucher) }) };
}

async function updateBooking(code, body) {
  const db = registry.get('db');
  const repo = registry.get('repo');
  const logic = registry.get('logic');
  const normalized = normalizeCode(code);
  if (!normalized) throw appError('not_found', 'Reserva no encontrada.', 404);

  const validated = logic.validateBookingPatch(body);
  if (!validated.ok) throw validationError(validated.errors);

  const row = await db.withTransaction(async (client) => {
    const existing = await repo.getBookingByCode(client, normalized, { forUpdate: true });
    requireExisting(existing);

    const updated = await repo.updateBookingFields(client, normalized, validated.value);
    requireExisting(updated);

    await repo.insertAudit(client, {
      action: 'BOOKING_UPDATED',
      entityType: 'booking',
      entityId: normalized,
      actor: 'admin',
      metadata: { fields: validated.fields }
    });
    return updated;
  });

  return { booking: repo.mapBooking(row, {}) };
}

const STATUS_AUDIT = {
  confirmada: 'BOOKING_CONFIRMED',
  cancelada: 'BOOKING_CANCELLED',
  realizada: 'BOOKING_COMPLETED',
  pendiente: 'BOOKING_REVERTED'
};

async function updateStatus(code, statusValue) {
  const db = registry.get('db');
  const repo = registry.get('repo');
  const logic = registry.get('logic');
  const normalized = normalizeCode(code);
  if (!normalized) throw appError('not_found', 'Reserva no encontrada.', 404);

  const validated = logic.validateStatusValue(statusValue);
  if (!validated.ok) throw validationError(validated.errors);

  const row = await db.withTransaction(async (client) => {
    const existing = await repo.getBookingByCode(client, normalized, { forUpdate: true });
    requireExisting(existing);

    const transition = logic.assertTransition(existing.status, validated.value);
    if (!transition.ok) throw appError(transition.code, transition.message, transition.status);
    if (transition.noop) return existing; // no-op: no update, no audit row

    const updated = await repo.updateBookingStatus(client, normalized, validated.value);
    requireExisting(updated);

    await repo.insertAudit(client, {
      action: STATUS_AUDIT[validated.value] || 'BOOKING_STATUS_CHANGED',
      entityType: 'booking',
      entityId: normalized,
      actor: 'admin',
      metadata: { from: existing.status, to: validated.value }
    });
    return updated;
  });

  return { booking: repo.mapBooking(row, {}) };
}

async function rescheduleBooking(code, schedule) {
  const db = registry.get('db');
  const repo = registry.get('repo');
  const logic = registry.get('logic');
  const normalized = normalizeCode(code);
  if (!normalized) throw appError('not_found', 'Reserva no encontrada.', 404);

  const cfg = await loadConfig();
  const validated = logic.validateSchedule(schedule, cfg);
  if (!validated.ok) throw validationError(validated.errors);

  const target = validated.value;
  const row = await db.withTransaction(async (client) => {
    const existing = await repo.getBookingByCode(client, normalized, { forUpdate: true });
    requireExisting(existing);

    // Same date lock + capacity gate as creation, excluding the booking itself.
    await repo.lockDate(client, target.selectedDate);
    const override = await repo.getAvailability(client, target.selectedDate);
    const times = await repo.listActiveTimes(client, target.selectedDate, normalized);

    const capacity = logic.assertCapacity({
      dateISO: target.selectedDate,
      time: target.selectedTime,
      existingTimes: times,
      overrideState: override ? override.state : null,
      config: cfg,
      now: new Date()
    });
    if (!capacity.ok) throw appError(capacity.code, capacity.message, capacity.status);

    const updated = await repo.updateBookingSchedule(client, normalized, target.selectedDate, target.selectedTime);
    requireExisting(updated);

    await repo.insertAudit(client, {
      action: 'BOOKING_RESCHEDULED',
      entityType: 'booking',
      entityId: normalized,
      actor: 'admin',
      metadata: {
        from: { date: repo.formatDateOnly(existing.selected_date), time: existing.selected_time },
        to: { date: target.selectedDate, time: target.selectedTime }
      }
    });
    return updated;
  });

  return { booking: repo.mapBooking(row, {}) };
}

// ---- availability ----

async function getAvailability(date) {
  const db = registry.get('db');
  const repo = registry.get('repo');
  const logic = registry.get('logic');

  if (date === undefined || date === null || date === '') {
    const rows = await db.withClient((client) => repo.listAvailability(client));
    const blocked = {};
    for (const row of rows) {
      blocked[row.date] = { state: row.state, reason: row.reason || null };
    }
    return { blocked };
  }

  const requested = String(date);
  if (!logic.isDateISO(requested)) {
    throw validationError([{ field: 'date', message: 'Fecha inválida.' }]);
  }

  const cfg = await loadConfig();
  const state = await db.withClient(async (client) => {
    const override = await repo.getAvailability(client, requested);
    const times = await repo.listActiveTimes(client, requested);
    return { override, times };
  });

  const blockedSet = logic.buildBlockedTimes(state.times, cfg);
  const bookedTimes = state.times.slice().sort();
  const blockedTimes = Array.from(blockedSet).sort();
  const maxPerDay = Number(cfg.limits.maxEventsPerDay) || 2;
  const remainingSlots = Math.max(0, maxPerDay - state.times.length);

  return {
    blocked: state.override
      ? { [state.override.date]: { state: state.override.state, reason: state.override.reason || null } }
      : {},
    detail: {
      date: requested,
      state: state.override ? state.override.state : 'available',
      remainingSlots,
      blockedTimes,
      bookedTimes
    }
  };
}

/**
 * Range view for GET /api/availability?from=&to= (inclusive, validated first so
 * bad ranges never touch the database). Every date in the range carries its
 * active bookings and remaining slots. Blocked times per day are derivable
 * client-side from bookedTimes (+/- bufferHours), so capacity omits them on
 * purpose — `detail` still includes them for the single-date case.
 */
async function getAvailabilityRange(query) {
  const db = registry.get('db');
  const repo = registry.get('repo');
  const logic = registry.get('logic');

  const validated = logic.validateAvailabilityRange(query);
  if (!validated.ok) throw validationError(validated.errors);

  const { from, to, days } = validated.value;
  const cfg = await loadConfig();
  const maxPerDay = Number(cfg.limits.maxEventsPerDay) > 0 ? Number(cfg.limits.maxEventsPerDay) : 2;

  const [times, overrides] = await db.withClient(async (client) => [
    await repo.listActiveTimesInRange(client, from, to),
    await repo.listAvailability(client)
  ]);

  const capacity = {};
  let cursor = from;
  for (let i = 0; i < days; i += 1) {
    capacity[cursor] = { remainingSlots: maxPerDay, bookedTimes: [] };
    cursor = logic.addDaysISO(cursor, 1);
  }
  for (const row of times) {
    const bucket = capacity[row.date];
    if (bucket) bucket.bookedTimes.push(row.selected_time);
  }
  for (const key of Object.keys(capacity)) {
    const bucket = capacity[key];
    bucket.remainingSlots = Math.max(0, maxPerDay - bucket.bookedTimes.length);
  }

  // Only overrides inside the requested window are relevant to this response.
  const blocked = {};
  for (const row of overrides) {
    if (row.date >= from && row.date <= to) {
      blocked[row.date] = { state: row.state, reason: row.reason || null };
    }
  }

  return { blocked, capacity };
}

async function setAvailability(body) {
  const db = registry.get('db');
  const repo = registry.get('repo');
  const logic = registry.get('logic');

  const validated = logic.validateAvailabilityPayload(body);
  if (!validated.ok) throw validationError(validated.errors);

  const value = validated.value;
  if (value.state === 'available') {
    await db.withClient((client) => repo.deleteAvailability(client, value.date));
  } else {
    await db.withClient((client) => repo.upsertAvailability(client, value.date, value.state, value.reason));
  }

  await recordAudit({
    action: 'AVAILABILITY_CHANGED',
    entityType: 'availability',
    entityId: value.date,
    actor: 'admin',
    metadata: { date: value.date, state: value.state, reason: value.reason }
  });

  return { date: value.date, state: value.state, reason: value.reason };
}

async function clearAvailability(date) {
  const db = registry.get('db');
  const repo = registry.get('repo');
  const logic = registry.get('logic');

  const normalized = typeof date === 'string' ? date.trim() : '';
  if (!logic.isDateISO(normalized)) {
    throw validationError([{ field: 'date', message: 'Fecha inválida.' }]);
  }

  const removed = await db.withClient((client) => repo.deleteAvailability(client, normalized));
  if (removed > 0) {
    await recordAudit({
      action: 'AVAILABILITY_CHANGED',
      entityType: 'availability',
      entityId: normalized,
      actor: 'admin',
      metadata: { date: normalized, state: 'available', cleared: true }
    });
  }
  // Idempotent: absent row still answers cleared:true.
  return { date: normalized, cleared: true };
}

// ---- admin auth ----

async function login(input) {
  const db = registry.get('db');
  const repo = registry.get('repo');
  const auth = registry.get('auth');
  const ratelimit = registry.get('ratelimit');

  await ratelimit.enforce({ bucket: `login:${input.ip || 'unknown'}`, limit: 10, windowMs: 60 * 60 * 1000 });

  const role = typeof input.role === 'string' ? input.role.trim() : '';
  const pin = typeof input.pin === 'string' ? input.pin : '';
  const generic = () => appError('unauthorized', 'Credenciales inválidas.', 401);

  if ((role !== 'owner' && role !== 'it') || !pin) {
    await recordAudit({
      action: 'ADMIN_LOGIN_FAILED',
      entityType: 'admin_credentials',
      entityId: role || 'unknown',
      actor: role || 'unknown',
      metadata: { reason: 'invalid' }
    });
    throw generic();
  }

  const outcome = await db.withTransaction(async (client) => {
    const credential = await repo.getCredentialForUpdate(client, role);
    if (!credential) return { result: 'invalid' };

    const now = Date.now();
    const lockedUntil = credential.locked_until ? new Date(credential.locked_until).getTime() : 0;
    if (lockedUntil > now) return { result: 'locked', retryAfterMs: lockedUntil - now };

    if (!auth.verifyPin(pin, credential.pin_hash)) {
      const failed = (Number(credential.failed_attempts) || 0) + 1;
      if (failed >= MAX_FAILED_ATTEMPTS) {
        const level = Number(credential.lock_level) || 0;
        const lockMs = Math.min(LOCK_BASE_MS * Math.pow(2, level), LOCK_MAX_MS);
        await repo.updateCredential(client, role, {
          failedAttempts: 0,
          lockLevel: level + 1,
          lockedUntil: new Date(now + lockMs)
        });
        return { result: 'locked', retryAfterMs: lockMs };
      }
      await repo.updateCredential(client, role, {
        failedAttempts: failed,
        lockLevel: Number(credential.lock_level) || 0,
        lockedUntil: null
      });
      return { result: 'invalid' };
    }

    await repo.resetCredential(client, role);
    const token = auth.newSessionToken();
    const expiresAt = new Date(now + SESSION_TTL_MS);
    await repo.createSession(client, { tokenHash: auth.hashToken(token), role, expiresAt });
    return { result: 'ok', token, expiresAt };
  });

  if (outcome.result === 'locked') {
    await recordAudit({
      action: 'ADMIN_LOGIN_FAILED',
      entityType: 'admin_credentials',
      entityId: role,
      actor: role,
      metadata: { reason: 'locked' }
    });
    throw appError('locked', 'Cuenta bloqueada temporalmente.', 429, {
      retryAfterMs: Math.max(0, Math.round(outcome.retryAfterMs))
    });
  }

  if (outcome.result !== 'ok') {
    await recordAudit({
      action: 'ADMIN_LOGIN_FAILED',
      entityType: 'admin_credentials',
      entityId: role,
      actor: role,
      metadata: { reason: 'invalid' }
    });
    throw generic();
  }

  await recordAudit({
    action: 'ADMIN_LOGIN',
    entityType: 'admin_credentials',
    entityId: role,
    actor: role,
    metadata: null
  });

  return { token: outcome.token, role, expiresAt: outcome.expiresAt.toISOString() };
}

async function logout(token) {
  if (!token) return { ok: true };
  const db = registry.get('db');
  const repo = registry.get('repo');
  const auth = registry.get('auth');

  const role = await db.withClient((client) => repo.deleteSession(client, auth.hashToken(token)));
  if (role) {
    await recordAudit({
      action: 'ADMIN_LOGOUT',
      entityType: 'admin_credentials',
      entityId: role,
      actor: role,
      metadata: null
    });
  }
  return { ok: true };
}

// ---- stats / pricing / audit ----

async function getStats() {
  const db = registry.get('db');
  const repo = registry.get('repo');
  const logic = registry.get('logic');
  const today = logic.todayCR();
  return db.withClient((client) =>
    repo.getStats(client, { from: today, to: logic.addDaysISO(today, 60) })
  );
}

// Public read-only pricing for GET /api/pricing: same config rows the admin
// endpoint reads, plus the catalog. No auth; the handler sets the cache header.
async function getPublicPricing() {
  const cfg = await loadConfig();
  return clone({ catalog: cfg.catalog, overrides: cfg.overrides, rates: cfg.rates });
}

async function getPricing() {
  const cfg = await loadConfig();
  return clone({ overrides: cfg.overrides, rates: cfg.rates });
}

async function putPricing(body, actor) {
  const db = registry.get('db');
  const repo = registry.get('repo');
  const logic = registry.get('logic');

  const validated = logic.validatePricingPayload(body);
  if (!validated.ok) throw validationError(validated.errors);

  const cfg = await loadConfig();
  const nextOverrides = mergeOverrides(cfg.overrides, validated.value.overrides);
  const nextRates = Object.assign({}, cfg.rates, validated.value.rates || {});

  await db.withClient(async (client) => {
    if (validated.value.overrides) {
      await repo.putConfigValue(client, 'pricing', 'overrides', nextOverrides);
    }
    if (validated.value.rates) {
      await repo.putConfigValue(client, 'pricing', 'rates', nextRates);
    }
    await repo.insertAudit(client, {
      action: 'PRICE_CHANGED',
      entityType: 'config',
      entityId: 'pricing',
      actor: actor || 'admin',
      metadata: {
        overrides: validated.value.overrides ? Object.keys(validated.value.overrides) : [],
        rates: validated.value.rates ? Object.keys(validated.value.rates) : []
      }
    });
  });

  invalidateConfigCache();
  return clone({ overrides: nextOverrides, rates: nextRates });
}

// Groups present in the PUT replace that group; untouched groups are kept.
function mergeOverrides(current, incoming) {
  if (!incoming) return { services: current.services, extras: current.extras };
  const merged = { services: current.services, extras: current.extras };
  for (const group of Object.keys(incoming)) merged[group] = incoming[group];
  return merged;
}

async function listAudit(limitParam) {
  const db = registry.get('db');
  const repo = registry.get('repo');
  const logic = registry.get('logic');
  const limit = logic.parseLimit(limitParam, 50, 200);

  const rows = await db.withClient((client) => repo.listAudit(client, limit));
  return {
    events: rows.map((row) => ({
      action: row.action,
      entityType: row.entity_type || null,
      entityId: row.entity_id || null,
      actor: row.actor || null,
      metadata: row.metadata === undefined ? null : row.metadata,
      createdAt: repo.toIso(row.created_at)
    }))
  };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

module.exports = {
  loadConfig,
  invalidateConfigCache,
  createBooking,
  listBookings,
  getBooking,
  updateBooking,
  updateStatus,
  rescheduleBooking,
  getAvailability,
  getAvailabilityRange,
  setAvailability,
  clearAvailability,
  login,
  logout,
  getStats,
  getPublicPricing,
  getPricing,
  putPricing,
  listAudit
};

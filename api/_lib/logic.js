'use strict';
// PURE business logic: validation, pricing, capacity/buffer checks, the status
// state machine and blocked-time calculation. No I/O of any kind lives here,
// which is what makes the rules unit-testable without a database.
//
// Every function takes an explicit `config` object (built by service.loadConfig
// from the `config` table) so nothing reads env or globals.

const configModule = require('./config');

const PHONE_RE = /^[\d\s+\-()]+$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const VOUCHER_RE = /^data:image\/(png|jpeg|webp);base64,/;
const SINPE_REF_RE = /^[A-Za-z0-9]+$/;

const MAX_EXTRAS = { extraHoursCount: 6, djHoursCount: 6, subwoofersCount: 4 };
const MAX_RANGE_DAYS = 92;
const STATUSES = ['pendiente', 'confirmada', 'realizada', 'cancelada'];
const AVAILABILITY_STATES = ['disabled', 'soldout', 'available'];
const PATCH_FIELDS = ['clientName', 'clientPhone', 'clientEmail', 'eventType', 'address', 'sinpeRef'];

// Costa Rica has no DST: fixed UTC-6 for all date-threshold math.
const CR_OFFSET_MS = -6 * 3600 * 1000;

function text(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function isDateISO(value) {
  if (typeof value !== 'string' || !DATE_RE.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime())) return false;
  return parsed.toISOString().slice(0, 10) === value;
}

function timeToNumber(hhmm) {
  if (!hhmm || typeof hhmm !== 'string') return null;
  const parts = hhmm.split(':');
  const hours = parseInt(parts[0], 10);
  const minutes = parseInt(parts[1], 10);
  if (Number.isNaN(hours) || Number.isNaN(minutes)) return null;
  return hours + minutes / 60;
}

/** Today's date in Costa Rica wall time (UTC-6), as YYYY-MM-DD. */
function todayCR(now) {
  const reference = now instanceof Date && !Number.isNaN(now.getTime()) ? now.getTime() : Date.now();
  return new Date(reference + CR_OFFSET_MS).toISOString().slice(0, 10);
}

/** Calendar arithmetic on a YYYY-MM-DD string (UTC-based, no DST surprises). */
function addDaysISO(iso, days) {
  const base = new Date(`${iso}T00:00:00Z`).getTime();
  return new Date(base + days * 86400000).toISOString().slice(0, 10);
}

function count(value, field, max, errors) {
  if (value === undefined || value === null || value === '') return 0;
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(parsed) || !Number.isInteger(parsed) || parsed < 0 || parsed > max) {
    errors.push({ field, message: `Cantidad inválida (0-${max}).` });
    return 0;
  }
  return parsed;
}

function voucherBytesOf(dataUrl) {
  const base64 = dataUrl.split(',')[1] || '';
  const padding = base64.endsWith('==') ? 2 : base64.endsWith('=') ? 1 : 0;
  return Math.max(0, Math.floor((base64.length * 3) / 4) - padding);
}

// ---- shared field rules (used by create + admin patch) ----

function checkName(value, errors) {
  const parsed = text(value);
  if (parsed.length < 2 || parsed.length > 70) {
    errors.push({ field: 'clientName', message: 'Nombre debe tener entre 2 y 70 caracteres.' });
  }
  return parsed;
}

function checkPhone(value, errors) {
  const parsed = text(value);
  if (parsed.length < 8 || parsed.length > 30 || !PHONE_RE.test(parsed)) {
    errors.push({ field: 'clientPhone', message: 'Teléfono inválido.' });
  }
  return parsed;
}

function checkEmail(value, errors) {
  const parsed = text(value);
  if (!parsed) return null;
  if (parsed.length > 120 || !EMAIL_RE.test(parsed)) {
    errors.push({ field: 'clientEmail', message: 'Correo electrónico inválido.' });
  }
  return parsed;
}

function checkEventType(value, errors) {
  const parsed = text(value);
  if (parsed.length < 2 || parsed.length > 40) {
    errors.push({ field: 'eventType', message: 'Tipo de evento inválido.' });
  }
  return parsed;
}

function checkAddress(value, errors) {
  if (value === undefined || value === null) return null;
  const parsed = text(value);
  if (parsed.length > 300) {
    errors.push({ field: 'address', message: 'Dirección demasiado larga.' });
  }
  return parsed || null;
}

function checkSinpeRef(value, errors) {
  if (value === undefined || value === null) return null;
  const parsed = text(value);
  if (!parsed) return null;
  if (parsed.length > 15 || !SINPE_REF_RE.test(parsed)) {
    errors.push({ field: 'sinpeRef', message: 'Referencia SINPE inválida (máx. 15 alfanuméricos).' });
  }
  return parsed;
}

function failOrValue(errors, value) {
  if (errors.length) return { ok: false, errors };
  return { ok: true, value };
}

/**
 * Validate a public booking payload.
 * Unknown top-level fields (amounts, status, code, ...) are never read, so
 * client-sent money can neither validate nor persist.
 */
function validateBookingPayload(body, config) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, errors: [{ field: 'body', message: 'Cuerpo inválido.' }] };
  }

  const errors = [];
  const cfg = config || {};
  const limits = cfg.limits || configModule.DEFAULTS.limits;
  const timeSlots = limits.timeSlots || configModule.TIME_SLOTS;
  const catalog = cfg.catalog || [];
  const provinces = (cfg.geo && cfg.geo.provinces) || {};

  const clientName = checkName(body.clientName, errors);
  const clientPhone = checkPhone(body.clientPhone, errors);
  const clientEmail = checkEmail(body.clientEmail, errors);
  const eventType = checkEventType(body.eventType, errors);

  let serviceId = null;
  if (!Number.isInteger(body.serviceId)) {
    errors.push({ field: 'serviceId', message: 'Servicio inválido.' });
  } else {
    serviceId = body.serviceId;
    if (!catalog.some((service) => service.id === serviceId)) {
      errors.push({ field: 'serviceId', message: 'Servicio inválido.' });
      serviceId = null;
    }
  }

  const selectedDate = text(body.selectedDate);
  if (!isDateISO(selectedDate)) {
    errors.push({ field: 'selectedDate', message: 'Fecha inválida.' });
  }

  const selectedTime = text(body.selectedTime);
  if (timeSlots.indexOf(selectedTime) === -1) {
    errors.push({ field: 'selectedTime', message: 'Horario inválido.' });
  }

  const province = text(body.province);
  const canton = text(body.canton);
  if (!Object.prototype.hasOwnProperty.call(provinces, province)) {
    errors.push({ field: 'province', message: 'Provincia inválida.' });
  } else if (provinces[province].indexOf(canton) === -1) {
    errors.push({ field: 'canton', message: 'Cantón inválido.' });
  }

  const address = checkAddress(body.address, errors);
  const sinpeRef = checkSinpeRef(body.sinpeRef, errors);

  let extras = { extraHoursCount: 0, djHoursCount: 0, subwoofersCount: 0 };
  if (body.extras !== undefined && body.extras !== null) {
    if (typeof body.extras !== 'object' || Array.isArray(body.extras)) {
      errors.push({ field: 'extras', message: 'Extras inválidos.' });
    } else {
      extras = {
        extraHoursCount: count(body.extras.extraHoursCount, 'extras.extraHoursCount', MAX_EXTRAS.extraHoursCount, errors),
        djHoursCount: count(body.extras.djHoursCount, 'extras.djHoursCount', MAX_EXTRAS.djHoursCount, errors),
        subwoofersCount: count(body.extras.subwoofersCount, 'extras.subwoofersCount', MAX_EXTRAS.subwoofersCount, errors)
      };
    }
  }

  let voucherImage = null;
  let voucherMime = null;
  let voucherBytes = null;
  if (body.voucherImage !== undefined && body.voucherImage !== null && body.voucherImage !== '') {
    const raw = body.voucherImage;
    const match = typeof raw === 'string' ? raw.match(VOUCHER_RE) : null;
    if (!match || raw.length > 200000) {
      errors.push({ field: 'voucherImage', message: 'Comprobante inválido (máx. 200000 caracteres).' });
    } else {
      voucherImage = raw;
      voucherMime = `image/${match[1]}`;
      voucherBytes = voucherBytesOf(raw);
    }
  }

  const result = failOrValue(errors, null);
  if (!result.ok) return result;

  const service = catalog.find((entry) => entry.id === serviceId);
  return {
    ok: true,
    value: {
      clientName,
      clientPhone,
      clientEmail,
      eventType,
      serviceId,
      serviceName: service.name,
      setupDisplay: service.setup_display || null,
      teardownDisplay: service.teardown_display || null,
      selectedDate,
      selectedTime,
      province,
      canton,
      address,
      sinpeRef,
      extras,
      voucherImage,
      voucherMime,
      voucherBytes
    }
  };
}

/**
 * Admin PATCH of a booking: only editable contact fields, same rules as
 * creation. Amounts/status/date present in the body are silently ignored.
 */
function validateBookingPatch(body, config) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, errors: [{ field: 'body', message: 'Cuerpo inválido.' }] };
  }
  const errors = [];
  const value = {};
  let provided = 0;

  for (const field of PATCH_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(body, field)) continue;
    provided += 1;
    if (field === 'clientName') value.clientName = checkName(body.clientName, errors);
    else if (field === 'clientPhone') value.clientPhone = checkPhone(body.clientPhone, errors);
    else if (field === 'clientEmail') value.clientEmail = checkEmail(body.clientEmail, errors);
    else if (field === 'eventType') value.eventType = checkEventType(body.eventType, errors);
    else if (field === 'address') value.address = checkAddress(body.address, errors);
    else if (field === 'sinpeRef') value.sinpeRef = checkSinpeRef(body.sinpeRef, errors);
  }

  if (!provided) {
    errors.push({ field: 'body', message: 'Sin campos para actualizar.' });
  }
  const result = failOrValue(errors, value);
  if (!result.ok) return result;
  return { ok: true, value, fields: Object.keys(value) };
}

/** Validate {selectedDate, selectedTime} for reschedule. */
function validateSchedule(input, config) {
  const errors = [];
  const cfg = config || {};
  const limits = cfg.limits || configModule.DEFAULTS.limits;
  const timeSlots = limits.timeSlots || configModule.TIME_SLOTS;

  const selectedDate = text(input && input.selectedDate);
  const selectedTime = text(input && input.selectedTime);

  if (!isDateISO(selectedDate)) errors.push({ field: 'selectedDate', message: 'Fecha inválida.' });
  if (timeSlots.indexOf(selectedTime) === -1) errors.push({ field: 'selectedTime', message: 'Horario inválido.' });

  return failOrValue(errors, { selectedDate, selectedTime });
}

function validateStatusValue(value) {
  if (typeof value !== 'string' || STATUSES.indexOf(value) === -1) {
    return { ok: false, errors: [{ field: 'status', message: 'Estado inválido.' }] };
  }
  return { ok: true, value };
}

/** Validate PUT /api/availability body. */
function validateAvailabilityPayload(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, errors: [{ field: 'body', message: 'Cuerpo inválido.' }] };
  }
  const errors = [];

  const date = text(body.date);
  if (!isDateISO(date)) errors.push({ field: 'date', message: 'Fecha inválida.' });

  const state = text(body.state);
  if (AVAILABILITY_STATES.indexOf(state) === -1) {
    errors.push({ field: 'state', message: 'Estado inválido.' });
  }

  let reason = null;
  if (body.reason !== undefined && body.reason !== null) {
    if (typeof body.reason !== 'string') {
      errors.push({ field: 'reason', message: 'Motivo inválido.' });
    } else {
      reason = body.reason.trim() || null;
      if (reason && reason.length > 120) {
        errors.push({ field: 'reason', message: 'Motivo demasiado largo (máx. 120).' });
      }
    }
  }

  return failOrValue(errors, { date, state, reason });
}

/**
 * Validate GET /api/availability range query: ?from=YYYY-MM-DD&to=YYYY-MM-DD.
 * Both ends are required, inclusive, and the span is capped at MAX_RANGE_DAYS.
 */
function validateAvailabilityRange(query) {
  const q = query || {};
  const from = text(q.from);
  const to = text(q.to);
  const errors = [];

  if (!from) errors.push({ field: 'from', message: 'Fecha inicial requerida.' });
  else if (!isDateISO(from)) errors.push({ field: 'from', message: 'Fecha inicial inválida.' });

  if (!to) errors.push({ field: 'to', message: 'Fecha final requerida.' });
  else if (!isDateISO(to)) errors.push({ field: 'to', message: 'Fecha final inválida.' });

  if (errors.length) return { ok: false, errors };

  if (from > to) {
    errors.push({ field: 'range', message: 'El rango es inválido: la fecha inicial no puede ser posterior a la final.' });
  } else {
    const start = Date.parse(`${from}T00:00:00Z`);
    const end = Date.parse(`${to}T00:00:00Z`);
    const days = Math.round((end - start) / 86400000) + 1;
    if (days > MAX_RANGE_DAYS) {
      errors.push({ field: 'range', message: `El rango máximo es de ${MAX_RANGE_DAYS} días.` });
    } else {
      return { ok: true, value: { from, to, days } };
    }
  }

  return { ok: false, errors };
}

/**
 * Validate PUT /api/admin/pricing body: {overrides?, rates?}.
 * Catalog is read-only and therefore never accepted here.
 */
function validatePricingPayload(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, errors: [{ field: 'body', message: 'Cuerpo inválido.' }] };
  }
  const errors = [];
  const value = {};

  if (Object.prototype.hasOwnProperty.call(body, 'overrides')) {
    const overrides = body.overrides;
    if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) {
      errors.push({ field: 'overrides', message: 'Overrides inválidos.' });
    } else {
      const normalized = {};
      for (const group of ['services', 'extras']) {
        if (!Object.prototype.hasOwnProperty.call(overrides, group)) continue;
        const entries = overrides[group];
        if (!entries || typeof entries !== 'object' || Array.isArray(entries)) {
          errors.push({ field: `overrides.${group}`, message: 'Overrides inválidos.' });
          continue;
        }
        const clean = {};
        for (const key of Object.keys(entries)) {
          const parsed = typeof entries[key] === 'number' ? entries[key] : Number(entries[key]);
          if (!Number.isInteger(parsed) || parsed < 0) {
            errors.push({ field: `overrides.${group}.${key}`, message: 'Precio inválido (entero ≥ 0).' });
            continue;
          }
          clean[key] = parsed;
        }
        normalized[group] = clean;
      }
      value.overrides = normalized;
    }
  }

  if (Object.prototype.hasOwnProperty.call(body, 'rates')) {
    const rates = body.rates;
    if (!rates || typeof rates !== 'object' || Array.isArray(rates)) {
      errors.push({ field: 'rates', message: 'Tarifas inválidas.' });
    } else {
      const clean = {};
      for (const key of ['extraHourMultiplier', 'travelSurchargeRate']) {
        if (!Object.prototype.hasOwnProperty.call(rates, key)) continue;
        const parsed = typeof rates[key] === 'number' ? rates[key] : Number(rates[key]);
        if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1) {
          errors.push({ field: `rates.${key}`, message: 'Tarifa inválida (entre 0 y 1).' });
          continue;
        }
        clean[key] = parsed;
      }
      value.rates = clean;
    }
  }

  if (!Object.prototype.hasOwnProperty.call(body, 'overrides') && !Object.prototype.hasOwnProperty.call(body, 'rates')) {
    errors.push({ field: 'body', message: 'Sin campos para actualizar.' });
  }

  return failOrValue(errors, value);
}

/** Validate list query params for GET /api/bookings. */
function validateListFilters(query) {
  const q = query || {};
  const errors = [];
  const value = { limit: 100 };

  if (q.status !== undefined && q.status !== '') {
    if (typeof q.status !== 'string' || STATUSES.indexOf(q.status) === -1) {
      errors.push({ field: 'status', message: 'Estado inválido.' });
    } else {
      value.status = q.status;
    }
  }
  for (const key of ['date', 'from', 'to']) {
    if (q[key] === undefined || q[key] === '') continue;
    if (!isDateISO(q[key])) {
      errors.push({ field: key, message: 'Fecha inválida.' });
    } else {
      value[key] = q[key];
    }
  }
  if (q.q !== undefined && q.q !== '') {
    const search = String(q.q).trim();
    if (search.length > 60) {
      errors.push({ field: 'q', message: 'Búsqueda demasiado larga.' });
    } else if (search) {
      value.q = search;
    }
  }
  value.limit = parseLimit(q.limit, 100, 500);

  return failOrValue(errors, value);
}

function parseLimit(value, fallback, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(Math.floor(parsed), max);
}

// ---- pricing ----

function positiveInt(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.round(parsed) : 0;
}

function ratio(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

/**
 * Server-side pricing. Mirrors CartState in js/app.js: any amount sent by the
 * client is irrelevant — only catalog + overrides + rates are consulted.
 */
function computePricing(input, config) {
  const cfg = config || {};
  const catalog = cfg.catalog || [];
  const overrides = cfg.overrides || {};
  const serviceOverrides = overrides.services || {};
  const extraOverrides = overrides.extras || {};
  const rates = cfg.rates || configModule.DEFAULTS.rates;
  const sinpe = cfg.sinpe || configModule.DEFAULTS.sinpe;
  const geo = cfg.geo || {};
  const gam = geo.gam || [];
  const exceptions = geo.nonGamExceptions || {};
  const extrasUnit = cfg.extrasUnit || configModule.DEFAULTS.extrasUnit;

  const service = catalog.find((entry) => entry.id === input.serviceId);
  const overrideBase = positiveInt(serviceOverrides[input.serviceId]);
  const base = overrideBase > 0 ? overrideBase : service ? service.price_crc : 0;

  const extraHoursCount = countSafe(input.extras && input.extras.extraHoursCount, MAX_EXTRAS.extraHoursCount);
  const djHoursCount = countSafe(input.extras && input.extras.djHoursCount, MAX_EXTRAS.djHoursCount);
  const subwoofersCount = countSafe(input.extras && input.extras.subwoofersCount, MAX_EXTRAS.subwoofersCount);

  const overrideExtraHour = positiveInt(extraOverrides.extra_hours);
  const extraHoursUnit = overrideExtraHour > 0 ? overrideExtraHour : Math.round(base * ratio(rates.extraHourMultiplier, 0.5));
  const extraHoursTotal = extraHoursUnit * extraHoursCount;

  const djUnit = positiveInt(extraOverrides.dj_service) > 0 ? positiveInt(extraOverrides.dj_service) : extrasUnit.dj_service;
  const subwoofersUnit = positiveInt(extraOverrides.subwoofers) > 0 ? positiveInt(extraOverrides.subwoofers) : extrasUnit.subwoofers;
  const djTotal = djUnit * djHoursCount;
  const subwoofersTotal = subwoofersUnit * subwoofersCount;

  const subtotal = base + extraHoursTotal + djTotal + subwoofersTotal;

  let isNonGam = false;
  if (input.province) {
    if (gam.indexOf(input.province) === -1) isNonGam = true;
    else isNonGam = (exceptions[input.province] || []).indexOf(input.canton) !== -1;
  }

  const travelSurcharge = isNonGam ? Math.round(subtotal * ratio(rates.travelSurchargeRate, 0.12)) : 0;
  const granTotal = subtotal + travelSurcharge;
  const deposit50Amount = Math.round(granTotal * ratio(sinpe.depositPercentage, 0.5));
  const remainingBalance = granTotal - deposit50Amount;

  return {
    base,
    extraHoursUnit,
    extraHoursCount,
    extraHoursTotal,
    djHoursCount,
    djTotal,
    subwoofersCount,
    subwoofersTotal,
    subtotal,
    isNonGam,
    travelSurcharge,
    granTotal,
    deposit50Amount,
    remainingBalance
  };
}

function countSafe(value, max) {
  const parsed = typeof value === 'number' ? value : Number(value || 0);
  if (!Number.isFinite(parsed) || !Number.isInteger(parsed) || parsed < 0) return 0;
  return parsed > max ? max : parsed;
}

// ---- capacity / availability ----

/**
 * Which "HH:MM" slots are blocked for a date, mirroring computeBlockedTimes in
 * js/app.js:0 bookings => none, 1 booking => +/- bufferHours window (inclusive),
 * 2+ bookings => the whole day (maxEventsPerDay is 2, capped at 2 to keep the
 * frontend semantics).
 */
function buildBlockedTimes(existingTimes, config) {
  const blocked = new Set();
  const cfg = config || {};
  const limits = cfg.limits || configModule.DEFAULTS.limits;
  const slots = limits.timeSlots || configModule.TIME_SLOTS;
  const times = (Array.isArray(existingTimes) ? existingTimes : []).filter(Boolean);
  const maxPerDay = Number(limits.maxEventsPerDay) > 0 ? Number(limits.maxEventsPerDay) : 2;
  const bufferHours = Number.isFinite(Number(limits.bufferHours)) ? Number(limits.bufferHours) : 5;
  const fullThreshold = Math.min(maxPerDay, 2);

  if (times.length >= fullThreshold) {
    for (const slot of slots) blocked.add(slot);
    return blocked;
  }
  if (times.length === 1) {
    const booked = timeToNumber(times[0]);
    if (booked !== null) {
      for (const slot of slots) {
        const value = timeToNumber(slot);
        if (value >= booked - bufferHours && value <= booked + bufferHours) blocked.add(slot);
      }
    }
  }
  return blocked;
}

/**
 * Capacity gate executed inside the booking/reschedule transaction.
 * Order: blackout override -> min notice/horizon -> day full -> buffer.
 * Returns {ok:true} or {ok:false, code, status, message}.
 */
function assertCapacity(params) {
  const cfg = params.config || {};
  const limits = cfg.limits || configModule.DEFAULTS.limits;
  const times = Array.isArray(params.existingTimes) ? params.existingTimes : [];
  const dateISO = params.dateISO;
  const fail = (code, status, message) => ({ ok: false, code, status, message });

  if (params.overrideState === 'disabled') {
    return fail('blackout', 409, 'Fecha bloqueada por mantenimiento: no disponible.');
  }
  if (params.overrideState === 'soldout') {
    return fail('soldout', 409, 'Fecha agotada (capacidad completa de 2 eventos).');
  }

  const reference = params.now instanceof Date && !Number.isNaN(params.now.getTime()) ? params.now.getTime() : Date.now();
  const minNoticeHours = Number(limits.minNoticeHours) >= 0 ? Number(limits.minNoticeHours) : 72;
  const maxHorizonDays = Number(limits.maxHorizonDays) >= 0 ? Number(limits.maxHorizonDays) : 365;
  // Date thresholds in Costa Rica wall time (UTC-6).
  const crIso = (instant) => new Date(instant + CR_OFFSET_MS).toISOString().slice(0, 10);
  const minDateISO = crIso(reference + minNoticeHours * 3600 * 1000);
  const maxDateISO = crIso(reference + maxHorizonDays * 86400 * 1000);

  if (dateISO < minDateISO) {
    return fail('min_notice', 400, `Antelación mínima: este servicio se reserva con ${minNoticeHours} horas de anticipación.`);
  }
  if (dateISO > maxDateISO) {
    return fail('horizon', 400, `Horizonte máximo de reservas: ${maxHorizonDays} días.`);
  }

  const maxPerDay = Number(limits.maxEventsPerDay) > 0 ? Number(limits.maxEventsPerDay) : 2;
  if (times.length >= maxPerDay) {
    return fail('day_full', 409, 'Este día ya no tiene cupos disponibles.');
  }

  const blocked = buildBlockedTimes(times, cfg);
  if (blocked.has(params.time)) {
    return fail('slot_taken', 409, 'Horario acaba de ser reservado.');
  }

  return { ok: true };
}

// ---- status state machine ----

const TRANSITIONS = {
  pendiente: ['confirmada', 'cancelada'],
  confirmada: ['realizada', 'cancelada'],
  cancelada: ['pendiente'], // documented single reversal
  realizada: [] // terminal
};

/**
 * allowed => {ok:true, noop:false}; same status => {ok:true, noop:true};
 * anything else => {ok:false, code:'invalid_state', status:409}.
 */
function assertTransition(from, to) {
  if (from === to) return { ok: true, noop: true };
  const allowed = TRANSITIONS[from];
  if (!allowed) {
    return { ok: false, code: 'invalid_state', status: 409, message: 'Estado actual no válido.' };
  }
  if (allowed.indexOf(to) === -1) {
    return { ok: false, code: 'invalid_state', status: 409, message: 'Cambio de estado no permitido.' };
  }
  return { ok: true, noop: false };
}

module.exports = {
  STATUSES,
  PATCH_FIELDS,
  isDateISO,
  timeToNumber,
  todayCR,
  addDaysISO,
  validateBookingPayload,
  validateBookingPatch,
  validateSchedule,
  validateStatusValue,
  validateAvailabilityPayload,
  validateAvailabilityRange,
  validatePricingPayload,
  validateListFilters,
  parseLimit,
  computePricing,
  buildBlockedTimes,
  assertCapacity,
  assertTransition
};

'use strict';
// Environment access with defaults.
// Every value is read lazily through getters: importing this module must never
// throw and must never require the env vars to exist (tests import freely).

const TIME_SLOTS = (() => {
  const slots = [];
  for (let h = 8; h <= 23; h++) slots.push(`${String(h).padStart(2, '0')}:00`);
  return slots;
})();

// Fallbacks for values that are also seeded by db/migrations/003_config_seed.sql.
// Big structures (catalog, geo) intentionally have NO code fallback: if they are
// missing the system is not migrated yet and callers get a 503.
const DEFAULTS = {
  limits: {
    maxEventsPerDay: 2,
    bufferHours: 5,
    minNoticeHours: 72,
    maxHorizonDays: 365,
    timeSlots: TIME_SLOTS
  },
  defaultStatus: 'pendiente',
  sinpe: {
    depositPercentage: 0.5,
    phone: '+506 6227-4984',
    cleanPhone: '50662274984',
    holder: 'Juan José Ramírez Chaves',
    policyText:
      'El adelanto del 50% vía SINPE Móvil no es reembolsable. Se coordinará reprogramación de fecha sujeta a disponibilidad de agenda (excepto por negligencia o falta de comunicación).'
  },
  rates: {
    extraHourMultiplier: 0.5,
    travelSurchargeRate: 0.12
  },
  extrasUnit: {
    dj_service: 75000,
    subwoofers: 80000
  }
};

function readEnv(name, fallback) {
  const value = process.env[name];
  return value === undefined || value === '' ? fallback : value;
}

module.exports = {
  DEFAULTS,
  TIME_SLOTS,

  get databaseUrl() {
    return readEnv('DATABASE_URL', '');
  },

  // Empty => same-origin only (frontend + API served from the same Vercel app).
  get allowedOrigins() {
    return readEnv('ALLOWED_ORIGINS', '')
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);
  },

  get sessionSecret() {
    return readEnv('ADMIN_SESSION_SECRET', 'dev-secret-change-me');
  },

  get appEnv() {
    return readEnv('APP_ENV', readEnv('NODE_ENV', 'development'));
  },

  get seedMode() {
    return /^true$/i.test(readEnv('SEED_MODE', 'false'));
  },

  get isProduction() {
    return process.env.VERCEL_ENV === 'production' || process.env.NODE_ENV === 'production';
  }
};

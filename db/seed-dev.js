'use strict';
// Arkik Productions - DEV-ONLY seed. Never runs on production.
//   SEED_MODE=true node db/seed-dev.js   (npm run db:seed:dev)
// Inserts demo bookings (ARK-SEED0001..0005) and two blocked dates.
// Uses ON CONFLICT DO NOTHING. Never deletes, never overwrites, never rotates admin PINs.
// Sanitized output only: DATABASE_URL and PINs are never printed.

const { loadEnvFiles, safeError, createDirectPool } = require('./_lib/direct-db');

function refuseUnlessSeedEnabled(env = process.env) {
  const seedMode = (env.SEED_MODE || '').trim().toLowerCase() === 'true';
  const appEnv = (env.APP_ENV || '').trim().toLowerCase();
  const vercelEnv = (env.VERCEL_ENV || '').trim().toLowerCase();
  const vercelFlag = String(env.VERCEL || '').trim();
  const nodeEnv = (env.NODE_ENV || '').trim().toLowerCase();

  if (!seedMode) {
    console.error('[ARKIK SEED] Refused: SEED_MODE is not "true".');
    console.error('[ARKIK SEED] Run with SEED_MODE=true APP_ENV=development (npm run db:seed:dev) against a local database only.');
    return false;
  }
  if (vercelFlag === '1' || Boolean(vercelEnv)) {
    console.error('[ARKIK SEED] Refused: cloud/Vercel runtime environment detected (VERCEL/VERCEL_ENV).');
    return false;
  }
  if (nodeEnv === 'production') {
    console.error('[ARKIK SEED] Refused: NODE_ENV=production is forbidden.');
    return false;
  }
  if (appEnv !== 'development') {
    console.error(
      `[ARKIK SEED] Refused: APP_ENV must be explicitly "development" (received "${appEnv || 'unset'}").`
    );
    return false;
  }
  return true;
}

function isoDaysFromToday(days) {
  const date = new Date(Date.now() + days * 86400000);
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${date.getFullYear()}-${month}-${day}`;
}

function isoMinutesAgo(minutes) {
  return new Date(Date.now() - minutes * 60000).toISOString();
}

function amountFields(grandTotal) {
  const deposit = Math.round(grandTotal * 0.5);
  return { subtotal: grandTotal, grandTotal, deposit, remaining: grandTotal - deposit };
}

const SEED_EXTRAS = {
  extraHoursCount: 0,
  djHoursCount: 0,
  subwoofersCount: 0,
  extraHoursTotal: 0,
  djTotal: 0,
  subwoofersTotal: 0
};

// Mirrors SEED_BOOKINGS_V1 / SEED_BLOCKED_DATES_V1 in js/data.js (same codes,
// clients, service ids, dates and amounts). Empty optional text fields become NULL,
// and `isSeed` has no column, so it is intentionally not persisted.
const SEED_BOOKINGS = [
  {
    code: 'ARK-SEED0001',
    status: 'confirmada',
    clientName: 'María Fernanda Solís Arrieta',
    clientPhone: '+506 8888-1111',
    eventType: 'Boda',
    serviceId: 1,
    serviceName: 'Banda Completa',
    selectedDate: isoDaysFromToday(10),
    selectedTime: '14:00',
    province: 'San José',
    canton: 'Escazú',
    grandTotal: 650000,
    ageDays: 6
  },
  {
    code: 'ARK-SEED0002',
    status: 'confirmada',
    clientName: 'Carlos Villalobos Naranjo',
    clientPhone: '+506 8888-2222',
    eventType: 'Aniversario',
    serviceId: 2,
    serviceName: 'Cuarteto Arkik',
    selectedDate: isoDaysFromToday(24),
    selectedTime: '14:00',
    province: 'Heredia',
    canton: 'Central (Heredia)',
    grandTotal: 480000,
    ageDays: 9
  },
  {
    code: 'ARK-SEED0003',
    status: 'confirmada',
    clientName: 'Empresa Tica de Logística S.A.',
    clientPhone: '+506 8888-3333',
    eventType: 'Corporativo',
    serviceId: 3,
    serviceName: 'Trío Acústico Premium',
    selectedDate: isoDaysFromToday(24),
    selectedTime: '20:00',
    province: 'Heredia',
    canton: 'Belén',
    grandTotal: 380000,
    ageDays: 11
  },
  {
    code: 'ARK-SEED0004',
    status: 'confirmada',
    clientName: 'Andrea Chacón Vargas',
    clientPhone: '+506 8888-4444',
    eventType: 'Cumpleaños',
    serviceId: 4,
    serviceName: 'Dúo Íntimo Arkik',
    selectedDate: isoDaysFromToday(38),
    selectedTime: '18:00',
    province: 'Cartago',
    canton: 'Central (Cartago)',
    grandTotal: 250000,
    ageDays: 14
  },
  {
    code: 'ARK-SEED0005',
    status: 'pendiente',
    clientName: 'Bodegas del Valle S.A.',
    clientPhone: '+506 8888-5555',
    eventType: 'Lanzamiento de Producto',
    serviceId: 6,
    serviceName: 'Alquiler Sonido e Iluminación Pro',
    selectedDate: isoDaysFromToday(52),
    selectedTime: '12:00',
    province: 'Alajuela',
    canton: 'Central (Alajuela)',
    grandTotal: 250000,
    ageDays: 3
  }
];

const SEED_BLOCKED_DATES = [
  { date: isoDaysFromToday(17), state: 'disabled', reason: 'Mantenimiento técnico de equipo' },
  { date: isoDaysFromToday(31), state: 'soldout', reason: 'Bloqueo operativo interno' }
];

const BOOKING_INSERT_SQL = `
  INSERT INTO bookings (
    code, status, client_name, client_phone, client_email, event_type,
    service_id, service_name, setup_display, teardown_display,
    selected_date, selected_time, province, canton, address,
    subtotal, travel_surcharge, grand_total, deposit_amount, remaining_balance,
    sinpe_reference, extras, voucher_image, voucher_mime, voucher_bytes,
    idempotency_key, created_at, updated_at, confirmed_at
  ) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10,
    $11, $12, $13, $14, $15,
    $16, $17, $18, $19, $20,
    $21, $22, NULL, NULL, NULL,
    $23, $24, $24, $25
  )
  ON CONFLICT (code) DO NOTHING`;

function bookingParams(booking) {
  const amounts = amountFields(booking.grandTotal);
  const createdAt = isoMinutesAgo(60 * 24 * booking.ageDays);
  const confirmedAt = booking.status === 'confirmada' ? createdAt : null;
  return [
    booking.code,
    booking.status,
    booking.clientName,
    booking.clientPhone,
    null, // client_email (empty string in the app seed)
    booking.eventType,
    booking.serviceId,
    booking.serviceName,
    null, // setup_display
    null, // teardown_display
    booking.selectedDate,
    booking.selectedTime,
    booking.province,
    booking.canton,
    null, // address
    amounts.subtotal,
    0, // travel_surcharge
    amounts.grandTotal,
    amounts.deposit,
    amounts.remaining,
    'S/N', // sinpe_reference as displayed by the app seed
    JSON.stringify(SEED_EXTRAS),
    `seed:${booking.code}`,
    createdAt,
    confirmedAt
  ];
}

async function main() {
  loadEnvFiles();

  if (!refuseUnlessSeedEnabled(process.env)) process.exit(1);

  const { pool } = await createDirectPool({
    envVarName: 'DIRECT_DATABASE_URL',
    requireLocalhost: true,
    queryTimeoutMs: 30000
  });
  try {
    let bookingRows = 0;
    for (const booking of SEED_BOOKINGS) {
      const result = await pool.query(BOOKING_INSERT_SQL, bookingParams(booking));
      bookingRows += result.rowCount || 0;
    }

    let blockedRows = 0;
    for (const blocked of SEED_BLOCKED_DATES) {
      const result = await pool.query(
        'INSERT INTO availability (date, state, reason) VALUES ($1, $2, $3) ON CONFLICT (date) DO NOTHING',
        [blocked.date, blocked.state, blocked.reason]
      );
      blockedRows += result.rowCount || 0;
    }

    console.log(`[ARKIK SEED] inserted ${bookingRows}/${SEED_BOOKINGS.length} bookings, ${blockedRows}/${SEED_BLOCKED_DATES.length} blocked dates`);
    console.log('[ARKIK SEED] existing rows were left untouched.');
  } finally {
    try {
      await pool.end();
    } catch (_err) {
      // ignore shutdown noise
    }
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`[ARKIK SEED] ERROR: ${safeError(err)}`);
    process.exit(1);
  });
}

module.exports = { refuseUnlessSeedEnabled };

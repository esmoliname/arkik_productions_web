'use strict';
// Logic parity harness for api/_lib/logic.js (run from the repo root, no DB).
const path = require('path');
const logic = require(path.resolve('api/_lib/logic'));
const configModule = require(path.resolve('api/_lib/config'));

const checks = [];
function expect(name, condition, detail) {
  checks.push({ name, ok: Boolean(condition), detail: detail === undefined ? '' : JSON.stringify(detail) });
}

const geo = {
  provinces: { 'San José': ['Escazú', 'Pérez Zeledón'], Limón: ['Central (Limón)'] },
  gam: ['San José', 'Heredia', 'Alajuela', 'Cartago'],
  nonGamExceptions: { 'San José': ['Pérez Zeledón'] }
};
const catalog = [
  { id: 1, name: 'Banda Completa', price_crc: 650000, setup_display: '2.5 horas antes', teardown_display: '1.5 horas después' }
];
const cfg = { catalog, geo, overrides: { services: {}, extras: {} } };

// --- pricing parity ---
let p = logic.computePricing({ serviceId: 1, province: 'San José', canton: 'Escazú' }, cfg);
expect('pricing GAM base 650000', p.subtotal === 650000 && p.travelSurcharge === 0 && p.granTotal === 650000, p);
expect('pricing deposit/remaining 325000', p.deposit50Amount === 325000 && p.remainingBalance === 325000, p);

p = logic.computePricing({ serviceId: 1, province: 'Limón', canton: 'Central (Limón)' }, cfg);
expect('pricing non-GAM travel 78000', p.isNonGam === true && p.travelSurcharge === 78000 && p.granTotal === 728000, p);

p = logic.computePricing({ serviceId: 1, province: 'San José', canton: 'Pérez Zeledón' }, cfg);
expect('pricing GAM exception (Pérez Zeledón) travel applies', p.isNonGam === true && p.travelSurcharge === 78000, p);

p = logic.computePricing(
  { serviceId: 1, province: 'Limón', canton: 'Central (Limón)', extras: { extraHoursCount: 1, djHoursCount: 1, subwoofersCount: 1 } },
  cfg
);
expect(
  'pricing extras subtotal 1130000',
  p.extraHoursUnit === 325000 && p.extraHoursTotal === 325000 && p.djTotal === 75000 && p.subwoofersTotal === 80000 && p.subtotal === 1130000,
  p
);
expect(
  'pricing extras travel/total',
  p.travelSurcharge === 135600 && p.granTotal === 1265600 && p.deposit50Amount === 632800 && p.remainingBalance === 632800,
  p
);

// --- blocked slots parity (mirror of computeBlockedTimes in js/app.js) ---
let blocked = logic.buildBlockedTimes(['14:00'], configModule.DEFAULTS);
expect('1 booking 14:00 => 11 blocked slots', blocked.size === 11, [...blocked]);
expect('buffer window inclusive at edges', blocked.has('09:00') && blocked.has('19:00'), [...blocked]);
expect('buffer excludes 08:00 and 20:00', !blocked.has('08:00') && !blocked.has('20:00'), [...blocked]);

blocked = logic.buildBlockedTimes(['10:00', '20:00'], configModule.DEFAULTS);
expect('2 bookings => whole day blocked', blocked.size === configModule.TIME_SLOTS.length, [...blocked]);

blocked = logic.buildBlockedTimes([], configModule.DEFAULTS);
expect('0 bookings => no blocked slots', blocked.size === 0, [...blocked]);

// --- capacity gate ---
const today = logic.todayCR();
const soon = logic.addDaysISO(today, 10);
const far = logic.addDaysISO(today, 400);

let r = logic.assertCapacity({ config: cfg, overrideState: 'disabled', dateISO: soon, time: '10:00', existingTimes: [], now: new Date() });
expect('override disabled => blackout 409', r.ok === false && r.code === 'blackout' && r.status === 409, r);

r = logic.assertCapacity({ config: cfg, overrideState: 'soldout', dateISO: soon, time: '10:00', existingTimes: [], now: new Date() });
expect('override soldout => soldout 409', r.ok === false && r.code === 'soldout' && r.status === 409, r);

r = logic.assertCapacity({ config: cfg, dateISO: today, time: '10:00', existingTimes: [], now: new Date() });
expect('today => min_notice 400', r.ok === false && r.code === 'min_notice' && r.status === 400, r);

r = logic.assertCapacity({ config: cfg, dateISO: far, time: '10:00', existingTimes: [], now: new Date() });
expect('beyond horizon => horizon 400', r.ok === false && r.code === 'horizon' && r.status === 400, r);

r = logic.assertCapacity({ config: cfg, dateISO: soon, time: '10:00', existingTimes: ['10:00', '14:00'], now: new Date() });
expect('2 bookings => day_full 409', r.ok === false && r.code === 'day_full' && r.status === 409, r);

r = logic.assertCapacity({ config: cfg, dateISO: soon, time: '14:00', existingTimes: ['14:00'], now: new Date() });
expect('inside buffer => slot_taken 409', r.ok === false && r.code === 'slot_taken' && r.status === 409, r);

r = logic.assertCapacity({ config: cfg, dateISO: soon, time: '21:00', existingTimes: ['14:00'], now: new Date() });
expect('free slot => ok', r.ok === true, r);

// --- state machine ---
expect('pendiente -> confirmada allowed', logic.assertTransition('pendiente', 'confirmada').ok === true);
expect('pendiente -> realizada blocked 409', logic.assertTransition('pendiente', 'realizada').status === 409);
expect('confirmada -> cancelada allowed', logic.assertTransition('confirmada', 'cancelada').ok === true);
expect('cancelada -> pendiente allowed', logic.assertTransition('cancelada', 'pendiente').ok === true);
expect('realizada terminal', logic.assertTransition('realizada', 'cancelada').ok === false);
expect('same status is noop', logic.assertTransition('confirmada', 'confirmada').noop === true);

// --- payload validation ---
const validBody = {
  clientName: 'María Fernanda Solís Arrieta',
  clientPhone: '+506 8888-1111',
  clientEmail: 'maria@example.com',
  eventType: 'Boda',
  serviceId: 1,
  selectedDate: soon,
  selectedTime: '14:00',
  province: 'San José',
  canton: 'Escazú',
  address: 'Av. Central 123',
  sinpeRef: 'REF123',
  extras: { extraHoursCount: 1, djHoursCount: 0, subwoofersCount: 0 }
};
let v = logic.validateBookingPayload(validBody, cfg);
expect('valid payload accepted', v.ok === true && v.value.serviceName === 'Banda Completa', v.value || v.errors);

v = logic.validateBookingPayload(Object.assign({}, validBody, { serviceId: 99, selectedTime: '07:30', clientPhone: 'abc' }), cfg);
expect(
  'invalid payload rejected with details',
  v.ok === false &&
    v.errors.some((e) => e.field === 'serviceId') &&
    v.errors.some((e) => e.field === 'selectedTime') &&
    v.errors.some((e) => e.field === 'clientPhone'),
  v.errors
);

v = logic.validateBookingPayload(Object.assign({}, validBody, { province: 'Limón', canton: 'Escazú' }), cfg);
expect('canton mismatch rejected', v.ok === false && v.errors.some((e) => e.field === 'canton'), v.errors);

// --- list limit parsing ---
expect('parseLimit fallback on junk', logic.parseLimit('abc', 50, 200) === 50);
expect('parseLimit clamps to max', logic.parseLimit('9999', 50, 200) === 200);
expect('parseLimit keeps valid', logic.parseLimit('25', 50, 200) === 25);

let failed = 0;
for (const check of checks) {
  if (check.ok) {
    console.log('PASS  ' + check.name);
  } else {
    failed += 1;
    console.log('FAIL  ' + check.name + ' -> ' + check.detail);
  }
}
console.log('checks=' + checks.length + ' failed=' + failed);
process.exit(failed ? 1 : 0);

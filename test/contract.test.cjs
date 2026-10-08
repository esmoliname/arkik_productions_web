'use strict';
// Contract harness for the two new backend additions (run from the repo root):
//   1) GET /api/availability?from=&to= range mode
//   2) GET /api/pricing public endpoint
// Phase A runs with the database DOWN (validation must happen first).
// Phase B injects a fake pool through db.setPoolFactoryForTests.
delete process.env.DATABASE_URL;

const path = require('path');

function load(rel) {
  return require(path.resolve(rel));
}

const checks = [];
function expect(name, condition, detail) {
  checks.push({ name, ok: Boolean(condition), detail: detail === undefined ? '' : JSON.stringify(detail) });
}

function makeRes() {
  return {
    headers: {},
    statusCode: 200,
    body: undefined,
    headersSent: false,
    setHeader(name, value) {
      this.headers[name] = value;
      return this;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      this.headersSent = true;
      return this;
    },
    end() {
      this.headersSent = true;
      return this;
    }
  };
}

function makeReq(method, url, opts) {
  opts = opts || {};
  return { method, url, headers: opts.headers || {}, query: opts.query || {}, body: opts.body };
}

async function call(file, req) {
  const handler = load(file);
  const res = makeRes();
  await handler(req, res);
  return res;
}

const logic = load('api/_lib/logic.js');

// ---------- load checks ----------
for (const file of ['api/pricing.js', 'api/availability/index.js']) {
  try {
    const mod = load(file);
    expect('load ' + file, typeof mod === 'function' && mod.length === 2, typeof mod);
  } catch (err) {
    expect('load ' + file, false, err.message);
  }
}

// ---------- logic-level range validation ----------
const day0 = logic.addDaysISO(logic.todayCR(), 10);
const day = (n) => logic.addDaysISO(day0, n);

let v = logic.validateAvailabilityRange({ from: day0, to: day(91) });
expect('range unit: 92 days accepted', v.ok === true && v.value.days === 92, v);

v = logic.validateAvailabilityRange({ from: day0, to: day(92) });
expect('range unit: 93 days rejected', v.ok === false && v.errors.some((e) => e.field === 'range'), v.errors);

v = logic.validateAvailabilityRange({ from: day0, to: day(0) });
expect('range unit: single day accepted', v.ok === true && v.value.days === 1, v);

v = logic.validateAvailabilityRange({ from: '2026-13-45', to: day0 });
expect('range unit: bad from rejected', v.ok === false && v.errors.some((e) => e.field === 'from'), v.errors);

v = logic.validateAvailabilityRange({ from: day0 });
expect('range unit: missing to rejected', v.ok === false && v.errors.some((e) => e.field === 'to'), v.errors);

v = logic.validateAvailabilityRange({ from: day(5), to: day0 });
expect('range unit: from>to rejected', v.ok === false && v.errors.some((e) => e.field === 'range'), v.errors);

// ---------- phase A: database down ----------
(async () => {
  let res = await call('api/availability/index.js', makeReq('GET', '/api/availability', { query: { from: day0, to: day(92) } }));
  expect(
    'A: 93-day range -> 400 validation_error before DB',
    res.statusCode === 400 && res.body.error.code === 'validation_error' && Array.isArray(res.body.error.details),
    JSON.stringify({ status: res.statusCode, body: res.body })
  );

  res = await call('api/availability/index.js', makeReq('GET', '/api/availability', { query: { from: 'nope', to: day0 } }));
  expect('A: bad from -> 400', res.statusCode === 400 && res.body.error.code === 'validation_error', JSON.stringify(res.body));

  res = await call('api/availability/index.js', makeReq('GET', '/api/availability', { query: { from: day0 } }));
  expect('A: missing to -> 400', res.statusCode === 400 && res.body.error.code === 'validation_error', JSON.stringify(res.body));

  res = await call('api/availability/index.js', makeReq('GET', '/api/availability', { query: { to: day0 } }));
  expect('A: missing from -> 400', res.statusCode === 400 && res.body.error.code === 'validation_error', JSON.stringify(res.body));

  res = await call('api/availability/index.js', makeReq('GET', '/api/availability'));
  expect('A: no params -> 503 (db down, unchanged)', res.statusCode === 503 && res.body.error.code === 'service_unavailable', JSON.stringify(res.body));

  res = await call('api/availability/index.js', makeReq('GET', '/api/availability', { query: { date: day(0) } }));
  expect('A: ?date= -> 503 (db down, unchanged)', res.statusCode === 503, JSON.stringify(res.body));

  res = await call('api/availability/index.js', makeReq('GET', '/api/availability', { query: { date: 'garbage' } }));
  expect('A: ?date= invalid -> 400 (unchanged)', res.statusCode === 400 && res.body.error.code === 'validation_error', JSON.stringify(res.body));

  res = await call('api/pricing.js', makeReq('GET', '/api/pricing'));
  expect('A: pricing -> 503 (db down)', res.statusCode === 503 && res.body.error.code === 'service_unavailable', JSON.stringify(res.body));

  res = await call('api/pricing.js', makeReq('POST', '/api/pricing'));
  expect('A: pricing POST -> 405', res.statusCode === 405 && res.body.error.code === 'method_not_allowed', JSON.stringify(res.body));

  res = await call('api/admin/pricing.js', makeReq('GET', '/api/admin/pricing'));
  expect('A: admin pricing still 401 unauthenticated', res.statusCode === 401, JSON.stringify(res.body));

  // ---------- phase B: fake pool ----------
  const db = load('api/_lib/db.js');

  const configRows = [
    { namespace: 'pricing', key: 'catalog', value: [{ id: 1, name: 'Banda Completa', price_crc: 650000 }] },
    { namespace: 'pricing', key: 'overrides', value: { services: {}, extras: {} } },
    { namespace: 'pricing', key: 'rates', value: { extraHourMultiplier: 0.5, travelSurchargeRate: 0.12 } },
    { namespace: 'geo', key: 'provinces', value: { 'San José': ['Escazú'] } },
    { namespace: 'geo', key: 'gam', value: ['San José', 'Heredia', 'Alajuela', 'Cartago'] },
    { namespace: 'geo', key: 'nonGamExceptions', value: { 'San José': ['Pérez Zeledón'] } }
  ];

  const d0 = day(0);
  const d1 = day(1);
  const d2 = day(2);
  const outside = day(99);

  const rangeTimes = [
    { date: d0, selected_time: '14:00' },
    { date: d0, selected_time: '20:00' },
    { date: d1, selected_time: '10:00' }
  ];
  const availabilityRows = [
    { date: d1, state: 'disabled', reason: 'Mantenimiento' },
    { date: outside, state: 'soldout', reason: 'Fuera de rango' }
  ];
  const timesByDate = { [d0]: ['14:00', '20:00'], [d1]: ['10:00'], [d2]: [] };

  const fakeClient = {
    async query(sql, params) {
      const s = String(sql);
      if (s.includes('FROM config')) return { rows: configRows, rowCount: configRows.length };
      if (s.includes('FROM availability') && s.includes('WHERE date')) {
        const row = availabilityRows.find((r) => r.date === params[0]);
        return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
      }
      if (s.includes('FROM availability')) return { rows: availabilityRows, rowCount: availabilityRows.length };
      if (s.includes('FROM bookings') && s.includes('>=')) {
        const rows = rangeTimes.filter((r) => r.date >= params[0] && r.date <= params[1]);
        return { rows, rowCount: rows.length };
      }
      if (s.includes('FROM bookings') && s.includes('selected_time')) {
        const rows = (timesByDate[params[0]] || []).map((t) => ({ selected_time: t }));
        return { rows, rowCount: rows.length };
      }
      return { rows: [], rowCount: 0 };
    },
    release() {}
  };
  db.setPoolFactoryForTests(async () => ({ connect: async () => fakeClient }));

  res = await call('api/availability/index.js', makeReq('GET', '/api/availability', { query: { from: d0, to: d2 } }));
  const data = res.body && res.body.data;
  expect('B: range 200 envelope', res.statusCode === 200 && res.body.success === true, JSON.stringify(res.body).slice(0, 300));
  expect(
    'B: capacity covers every date in range',
    data && JSON.stringify(Object.keys(data.capacity).sort()) === JSON.stringify([d0, d1, d2].sort()),
    data && Object.keys(data.capacity)
  );
  expect(
    'B: remainingSlots/bookedTimes math',
    data &&
      data.capacity[d0].remainingSlots === 0 &&
      JSON.stringify(data.capacity[d0].bookedTimes) === JSON.stringify(['14:00', '20:00']) &&
      data.capacity[d1].remainingSlots === 1 &&
      JSON.stringify(data.capacity[d1].bookedTimes) === JSON.stringify(['10:00']) &&
      data.capacity[d2].remainingSlots === 2 &&
      data.capacity[d2].bookedTimes.length === 0,
    data && data.capacity
  );
  expect(
    'B: capacity omits blockedTimes and detail is absent',
    data &&
      Object.keys(data.capacity[d0]).join(',') === 'remainingSlots,bookedTimes' &&
      !Object.prototype.hasOwnProperty.call(data, 'detail'),
    data && { keys: Object.keys(data.capacity[d0]), top: Object.keys(data) }
  );
  expect(
    'B: blocked limited to the requested range',
    data && JSON.stringify(Object.keys(data.blocked)) === JSON.stringify([d1]) && data.blocked[d1].state === 'disabled',
    data && data.blocked
  );

  res = await call('api/availability/index.js', makeReq('GET', '/api/availability', { query: { from: day0, to: day(91) } }));
  expect(
    'B: exactly 92 days accepted with 92 capacity entries',
    res.statusCode === 200 && Object.keys(res.body.data.capacity).length === 92,
    res.statusCode === 200 ? Object.keys(res.body.data.capacity).length : JSON.stringify(res.body)
  );

  res = await call('api/availability/index.js', makeReq('GET', '/api/availability', { query: { date: d0 } }));
  const detail = res.body && res.body.data && res.body.data.detail;
  expect(
    'B: ?date= keeps detail + blockedTimes',
    res.statusCode === 200 &&
      detail &&
      detail.date === d0 &&
      detail.remainingSlots === 0 &&
      Array.isArray(detail.blockedTimes) &&
      detail.blockedTimes.length === 16 &&
      JSON.stringify(detail.bookedTimes) === JSON.stringify(['14:00', '20:00']),
    detail
  );
  expect(
    'B: ?date= blocked only that date',
    res.statusCode === 200 && JSON.stringify(Object.keys(res.body.data.blocked)) === '[]',
    res.body.data && res.body.data.blocked
  );

  res = await call('api/availability/index.js', makeReq('GET', '/api/availability'));
  expect(
    'B: no params keeps full blocked map (both overrides)',
    res.statusCode === 200 &&
      !Object.prototype.hasOwnProperty.call(res.body.data, 'detail') &&
      !Object.prototype.hasOwnProperty.call(res.body.data, 'capacity') &&
      JSON.stringify(Object.keys(res.body.data.blocked).sort()) === JSON.stringify([d1, outside].sort()),
    res.body.data
  );

  res = await call('api/pricing.js', makeReq('GET', '/api/pricing'));
  expect(
    'B: public pricing 200 + envelope + cache header',
    res.statusCode === 200 &&
      res.body.success === true &&
      res.headers['Cache-Control'] === 'public, max-age=60' &&
      Array.isArray(res.body.data.catalog) &&
      res.body.data.catalog[0].id === 1 &&
      res.body.data.overrides &&
      res.body.data.rates.extraHourMultiplier === 0.5,
    JSON.stringify({ status: res.statusCode, cache: res.headers['Cache-Control'], body: res.body }).slice(0, 400)
  );

  res = await call('api/pricing.js', makeReq('PUT', '/api/pricing', { body: {} }));
  expect('B: public pricing PUT -> 405 (writes stay admin-only)', res.statusCode === 405, JSON.stringify(res.body));

  res = await call('api/admin/pricing.js', makeReq('PUT', '/api/admin/pricing', { body: {}, headers: { cookie: '' } }));
  expect('B: admin pricing PUT still requires session', res.statusCode === 401, JSON.stringify(res.body));

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
})().catch((err) => {
  console.log('HARNESS ERROR: ' + (err && err.stack ? err.stack : err));
  process.exit(1);
});

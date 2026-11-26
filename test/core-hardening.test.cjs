'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const logic = require('../api/_lib/logic');

const ROOT = path.resolve(__dirname, '..');
const dataSrc = fs.readFileSync(path.join(ROOT, 'js', 'data.js'), 'utf8');
const apiSrc = fs.readFileSync(path.join(ROOT, 'js', 'api.js'), 'utf8');
const appSrc = fs.readFileSync(path.join(ROOT, 'js', 'app.js'), 'utf8');

function createAppSandbox(options = {}) {
  const lsMap = new Map();
  const ssMap = new Map();
  const listeners = new Map();

  const makeStorage = (map, customSetItem) => ({
    getItem(k) { return map.has(k) ? map.get(k) : null; },
    setItem(k, v) {
      if (typeof customSetItem === 'function') {
        return customSetItem(k, v, map);
      }
      map.set(String(k), String(v));
    },
    removeItem(k) { map.delete(String(k)); },
    clear() { map.clear(); },
    key(i) { return Array.from(map.keys())[i] || null; },
    get length() { return map.size; }
  });

  const sandbox = {
    console: { log() {}, warn() {}, error() {}, info() {} },
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    Date,
    Math,
    JSON,
    Object,
    String,
    Number,
    Boolean,
    Array,
    Map,
    Set,
    RegExp,
    Error,
    TypeError,
    encodeURIComponent,
    decodeURIComponent,
    AbortController,
    fetch: async () => ({ ok: false, status: 503, headers: { get: () => 'application/json' }, text: async () => '{}' }),
    localStorage: makeStorage(lsMap, options.localStorageSetItem),
    sessionStorage: makeStorage(ssMap),
    location: { pathname: '/', hash: '', origin: 'https://arkik-productions.vercel.app', hostname: 'arkik-productions.vercel.app' },
    navigator: { userAgent: 'node-test', onLine: true },
    document: {
      readyState: 'loading',
      visibilityState: 'visible',
      addEventListener() {},
      getElementById() { return null; },
      querySelector() { return null; },
      querySelectorAll() { return []; },
      body: { style: {}, classList: { add() {}, remove() {}, toggle() {} } }
    },
    addEventListener(type, fn) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type).add(fn);
    },
    removeEventListener(type, fn) {
      if (listeners.has(type)) listeners.get(type).delete(fn);
    },
    ResizeObserver: options.ResizeObserver,
    scrollTo() {},
    history: { replaceState() {} },
    crypto: require('node:crypto').webcrypto
  };

  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(dataSrc, sandbox, { filename: 'js/data.js' });
  vm.runInContext(apiSrc, sandbox, { filename: 'js/api.js' });
  vm.runInContext(
    appSrc + `
    window.__CORE_EXPORTS__ = {
      SafeStorage,
      MemoryStorage,
      MemoryCache,
      safeSaveBookings,
      STORAGE_KEYS,
      StorageEngine,
      AvailabilityManager,
      BookingStore,
      CalendarModule,
      CartState,
      crIsoOf,
      validateSlotAvailability,
      sanitizeBookingStatusClass,
      createDynamicCanvasController,
      setupCrossTabSync
    };
    `,
    sandbox,
    { filename: 'js/app.js' }
  );

  return { sandbox, exports: sandbox.__CORE_EXPORTS__, lsMap, listeners };
}

test('UTC-6 Costa Rica: CalendarModule.getThresholds aligns 100% with backend logic.js', () => {
  const { exports: core } = createAppSandbox();

  // 2026-06-15T03:00:00Z is already June 15 in UTC, but still June 14 21:00 in Costa Rica (UTC-6).
  const lateNightCR = new Date('2026-06-15T03:00:00.000Z');
  const thresholds = core.CalendarModule.getThresholds(lateNightCR);

  assert.equal(thresholds.nowISO, logic.todayCR(lateNightCR));
  assert.equal(thresholds.nowISO, '2026-06-14');
  assert.equal(thresholds.minISO, '2026-06-17'); // +72h in CR wall time
  assert.equal(thresholds.maxISO, '2027-06-14'); // +365d in CR wall time

  // Parity check with backend assertCapacity: 2026-06-16 must fail min_notice, 2026-06-17 must pass.
  const backendTooSoon = logic.assertCapacity({
    dateISO: '2026-06-16',
    time: '18:00',
    existingTimes: [],
    now: lateNightCR
  });
  assert.equal(backendTooSoon.ok, false);
  assert.equal(backendTooSoon.code, 'min_notice');

  const backendAllowed = logic.assertCapacity({
    dateISO: '2026-06-17',
    time: '18:00',
    existingTimes: [],
    now: lateNightCR
  });
  assert.equal(backendAllowed.ok, true);
});

test('AvailabilityManager.remainingSlots(undefined|null|NaN) fails closed in validateSlotAvailability and getDayState', () => {
  const { exports: core } = createAppSandbox();
  const thresholds = core.CalendarModule.getThresholds();
  const validDate = thresholds.minISO;

  const origRemaining = core.AvailabilityManager.remainingSlots;
  try {
    for (const invalidVal of [undefined, null, Number.NaN]) {
      core.AvailabilityManager.remainingSlots = () => invalidVal;

      const check = core.validateSlotAvailability(validDate, '18:00');
      assert.equal(check.ok, false, `Expected fail-closed for remainingSlots=${String(invalidVal)}`);
      assert.equal(check.code, 'availability_unverified');

      const dayState = core.CalendarModule.getDayState(validDate, thresholds.nowISO, thresholds.minISO, thresholds.maxISO);
      assert.equal(dayState.selectable, false, `Expected non-selectable day for remainingSlots=${String(invalidVal)}`);
    }
  } finally {
    core.AvailabilityManager.remainingSlots = origRemaining;
  }
});

test('safeSaveBookings delegates exclusively to SafeStorage and degrades cleanly to MemoryStorage in private mode', () => {
  // Static guarantee: safeSaveBookings must not call window.localStorage.setItem directly.
  const fnStart = appSrc.indexOf('function safeSaveBookings(');
  const fnEnd = appSrc.indexOf('function buildWhatsAppMessage(', fnStart);
  assert.ok(fnStart > 0 && fnEnd > fnStart, 'safeSaveBookings function block must exist');
  const safeSaveSrc = appSrc.slice(fnStart, fnEnd);
  assert.equal(safeSaveSrc.includes('localStorage.setItem'), false, 'safeSaveBookings must not call localStorage.setItem directly');

  // Runtime guarantee: SecurityError in localStorage degrades to MemoryStorage without throwing.
  const { exports: core } = createAppSandbox({
    localStorageSetItem() {
      const err = new Error('The operation is insecure.');
      err.name = 'SecurityError';
      throw err;
    }
  });

  const sample = [{ code: 'ARK-TEST0001', clientName: 'Test Private', selectedDate: '2026-12-20', selectedTime: '18:00' }];
  const saved = core.safeSaveBookings(sample);
  assert.equal(saved, true);
  assert.equal(core.SafeStorage.mode, 'memory');

  const storedRaw = core.MemoryStorage.getItem(core.STORAGE_KEYS.bookings);
  assert.ok(storedRaw, 'MemoryStorage must hold serialized bookings');
  const parsed = JSON.parse(storedRaw);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].code, 'ARK-TEST0001');
});

test('CartState.isNonGam safely falls back when StorageEngine config is unhydrated', () => {
  const { exports: core } = createAppSandbox();
  const origGetConfig = core.StorageEngine.getConfig;
  try {
    core.StorageEngine.getConfig = () => undefined;

    const cart = new core.CartState();
    cart.province = 'San José';
    cart.canton = 'Pérez Zeledón';
    assert.equal(cart.isNonGam, true);

    cart.province = 'San José';
    cart.canton = 'Escazú';
    assert.equal(cart.isNonGam, false);

    cart.province = 'Guanacaste';
    cart.canton = 'Liberia';
    assert.equal(cart.isNonGam, true);
  } finally {
    core.StorageEngine.getConfig = origGetConfig;
  }
});

test('sanitizeBookingStatusClass strictly whitelists CSS status classes', () => {
  const { exports: core } = createAppSandbox();
  assert.equal(core.sanitizeBookingStatusClass('confirmada'), 'confirmada');
  assert.equal(core.sanitizeBookingStatusClass('CANCELLED'), 'cancelled');
  assert.equal(core.sanitizeBookingStatusClass('pendiente" onclick="alert(1)'), 'pendiente');
  assert.equal(core.sanitizeBookingStatusClass(''), 'pendiente');
});

test('createDynamicCanvasController and setupCrossTabSync expose working destroy/cleanup hooks', () => {
  let disconnected = false;
  let observedEl = null;

  class FakeResizeObserver {
    observe(el) { observedEl = el; }
    disconnect() { disconnected = true; }
  }

  const { exports: core, listeners } = createAppSandbox({ ResizeObserver: FakeResizeObserver });

  const fakeCanvas = { width: 0, height: 0 };
  const fakeContainer = { getBoundingClientRect: () => ({ width: 320, height: 180 }) };
  const fakeCtx = { setTransform() {} };

  const ctrl = core.createDynamicCanvasController(fakeCanvas, fakeContainer, fakeCtx);
  assert.equal(observedEl, fakeContainer);
  assert.equal(typeof ctrl.destroy, 'function');
  assert.equal(typeof ctrl.cleanup, 'function');
  ctrl.destroy();
  assert.equal(disconnected, true, 'destroy() must disconnect ResizeObserver');

  const beforeCount = (listeners.get('storage') && listeners.get('storage').size) || 0;
  const syncHandle = core.setupCrossTabSync();
  const duringCount = (listeners.get('storage') && listeners.get('storage').size) || 0;
  assert.equal(duringCount, beforeCount + 1, 'setupCrossTabSync must attach storage listener');
  assert.equal(typeof syncHandle.destroy, 'function');
  syncHandle.destroy();
  const afterCount = (listeners.get('storage') && listeners.get('storage').size) || 0;
  assert.equal(afterCount, beforeCount, 'destroy() must remove storage listener');
});

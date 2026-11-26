'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.resolve(__dirname, '..');
const dataSrc = fs.readFileSync(path.join(ROOT, 'js', 'data.js'), 'utf8');
const apiSrc = fs.readFileSync(path.join(ROOT, 'js', 'api.js'), 'utf8');
const appSrc = fs.readFileSync(path.join(ROOT, 'js', 'app.js'), 'utf8');

function createBookingSandbox(options = {}) {
  const lsMap = options.lsMap || new Map();
  const ssMap = new Map();
  const elements = new Map();
  const toasts = [];
  const conflicts = [];
  const steps = [];
  const vouchers = [];
  const fetchCalls = [];
  let nextFetch = options.fetchImpl || (async () => ({
    status: 503,
    ok: false,
    headers: { get: () => 'application/json' },
    text: async () => JSON.stringify({ success: false, error: { code: 'service_unavailable', message: 'Offline' } })
  }));

  function getEl(id) {
    if (!elements.has(id)) {
      const classes = new Set();
      elements.set(id, {
        id,
        value: '',
        disabled: false,
        innerHTML: '',
        textContent: '',
        style: {},
        classList: {
          add(...c) { c.forEach((k) => classes.add(k)); },
          remove(...c) { c.forEach((k) => classes.delete(k)); },
          contains(c) { return classes.has(c); },
          toggle(c, force) {
            if (force === true) classes.add(c);
            else if (force === false) classes.delete(c);
            else if (classes.has(c)) classes.delete(c);
            else classes.add(c);
          }
        },
        addEventListener() {},
        setAttribute() {},
        removeAttribute() {}
      });
    }
    return elements.get(id);
  }

  const fakeStorage = (map) => ({
    getItem(k) { return map.has(k) ? map.get(k) : null; },
    setItem(k, v) { map.set(String(k), String(v)); },
    removeItem(k) { map.delete(String(k)); },
    clear() { map.clear(); },
    key(i) { return Array.from(map.keys())[i] || null; },
    get length() { return map.size; }
  });

  const activeTimeouts = new Set();
  const sandbox = {
    console: { log() {}, warn() {}, error() {}, info() {} },
    setTimeout(fn, ms) {
      const id = setTimeout(() => { activeTimeouts.delete(id); fn(); }, ms);
      activeTimeouts.add(id);
      return id;
    },
    clearTimeout(id) { activeTimeouts.delete(id); clearTimeout(id); },
    setInterval() { return 0; },
    clearInterval() {},
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
    open: options.windowOpen || (() => null),
    print: options.windowPrint || (() => {}),
    fetch: async (url, init) => {
      fetchCalls.push({ url, init });
      return nextFetch(url, init);
    },
    localStorage: fakeStorage(lsMap),
    sessionStorage: fakeStorage(ssMap),
    location: { pathname: '/', hash: '', origin: 'https://arkik-productions.vercel.app', hostname: 'arkik-productions.vercel.app' },
    navigator: { userAgent: 'node-test', onLine: true },
    document: {
      readyState: 'loading',
      visibilityState: 'visible',
      addEventListener() {},
      getElementById: (id) => getEl(id),
      querySelector: () => null,
      querySelectorAll: () => [],
      body: { style: {}, classList: { add() {}, remove() {}, toggle() {} } }
    },
    addEventListener() {},
    removeEventListener() {},
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
    CLIENT_GUARD_CONFIG.submitLockMs = 5;
    CLIENT_GUARD_CONFIG.maxSubmitAttempts = 10;
    const __flowCalls = { toasts: [], conflicts: [], steps: [], vouchers: [] };
    showToast = function (msg, type) { __flowCalls.toasts.push({ msg, type }); };
    showSlotConflictAlert = function (msg) { __flowCalls.conflicts.push(msg); };
    goToStep = function (step) { __flowCalls.steps.push(step); };
    renderConfirmedVoucherScreen = function (booking, waUrl) { __flowCalls.vouchers.push({ booking, waUrl }); };
    updateGenerateButtonState = function () {};
    window.__TEST_FLOW__ = {
      cart,
      StorageEngine,
      BookingStore,
      CloudSync,
      ClientThrottler,
      CLIENT_GUARD_CONFIG,
      CATALOG_SERVICES,
      submitStaticBooking,
      printFallback,
      exportOwnerReportDOCX,
      sendBookingEmail,
      toasts: __flowCalls.toasts,
      conflicts: __flowCalls.conflicts,
      steps: __flowCalls.steps,
      vouchers: __flowCalls.vouchers
    };
    `,
    sandbox,
    { filename: 'js/app.js' }
  );

  return {
    sandbox,
    flow: sandbox.__TEST_FLOW__,
    getEl,
    fetchCalls,
    setFetch(fn) { nextFetch = fn; },
    cleanup() {
      for (const id of activeTimeouts) clearTimeout(id);
      activeTimeouts.clear();
    }
  };
}

function populateValidCart(flow, getEl, futureDate) {
  flow.cart.isSubmitting = false;
  flow.cart.createdBooking = null;
  flow.cart.selectedService = flow.CATALOG_SERVICES[0];
  flow.cart.extraHoursCount = 2;
  flow.cart.djHoursCount = 0;
  flow.cart.subwoofersCount = 0;
  flow.cart.province = 'San José';
  flow.cart.canton = 'Pérez Zeledón'; // Non-GAM (+12% travel surcharge)
  flow.cart.clientName = 'Carlos Méndez';
  flow.cart.clientPhone = '8888-9999';
  flow.cart.clientEmail = 'carlos@example.com';
  flow.cart.eventType = 'Boda';
  flow.cart.selectedDate = futureDate;
  flow.cart.selectedTime = '18:00';
  flow.cart.address = 'San Isidro del General, 200m sur del parque';
  flow.cart.voucherImage = 'data:image/png;base64,iVBORw0KGgo=';
  flow.cart.sinpeRef = 'SINPE98765';
  getEl('sinpe-reference').value = 'SINPE98765';
}

test('Integration 1: Full booking happy path (Non-GAM + extras + POST /api/bookings + X-Idempotency-Key)', async () => {
  const ctx = createBookingSandbox();
  try {
    ctx.flow.StorageEngine.init();
    ctx.flow.CloudSync._enabled = false;

    const futureDate = new Date(Date.now() + 14 * 86400000).toISOString().slice(0, 10);
    populateValidCart(ctx.flow, ctx.getEl, futureDate);

    assert.equal(ctx.flow.cart.isNonGam, true);
    assert.ok(ctx.flow.cart.travelSurcharge > 0);
    assert.ok(ctx.flow.cart.extraHoursTotal > 0);

    ctx.setFetch(async (url, init) => {
      if (!String(url).includes('/api/bookings') || !init || init.method !== 'POST') {
        return {
          status: 200,
          ok: true,
          headers: { get: () => 'application/json' },
          text: async () => JSON.stringify({ success: true, data: {} })
        };
      }
      const body = JSON.parse(init.body);
      assert.equal(body.granTotal, undefined, 'Zero-Trust: client must not send amounts');
      assert.equal(body.deposit50Amount, undefined, 'Zero-Trust: client must not send deposit');
      assert.equal(body.extras.extraHoursCount, 2);
      assert.equal(body.canton, 'Pérez Zeledón');
      assert.ok(init.headers['X-Idempotency-Key'], 'Must include X-Idempotency-Key header');

      return {
        status: 201,
        ok: true,
        headers: { get: () => 'application/json' },
        text: async () => JSON.stringify({
          success: true,
          data: {
            booking: {
              code: 'ARK-INTEG001',
              status: 'pendiente',
              clientName: body.clientName,
              clientPhone: body.clientPhone,
              clientEmail: body.clientEmail,
              eventType: body.eventType,
              serviceId: body.serviceId,
              serviceName: ctx.flow.CATALOG_SERVICES[0].name,
              selectedDate: body.selectedDate,
              selectedTime: body.selectedTime,
              province: body.province,
              canton: body.canton,
              extras: body.extras,
              granTotal: ctx.flow.cart.granTotal,
              deposit50Amount: ctx.flow.cart.deposit50Amount,
              remainingBalance: ctx.flow.cart.remainingBalance
            }
          }
        })
      };
    });

    await ctx.flow.submitStaticBooking();
    await new Promise((r) => setTimeout(r, 20));

    const postBookings = ctx.fetchCalls.filter((c) => String(c.url).includes('/api/bookings') && c.init && c.init.method === 'POST');
    assert.equal(postBookings.length, 1);
    assert.equal(ctx.flow.cart.createdBooking.code, 'ARK-INTEG001');
    assert.equal(ctx.flow.steps.includes(4), true);
    assert.equal(ctx.flow.vouchers.length, 1);
  } finally {
    ctx.cleanup();
  }
});

test('Integration 2: Schedule conflict (409 slot_taken) blocks cleanly without emitting voucher', async () => {
  const ctx = createBookingSandbox();
  try {
    ctx.flow.StorageEngine.init();
    ctx.flow.CloudSync._enabled = false;

    const futureDate = new Date(Date.now() + 15 * 86400000).toISOString().slice(0, 10);
    populateValidCart(ctx.flow, ctx.getEl, futureDate);

    ctx.setFetch(async () => ({
      status: 409,
      ok: false,
      headers: { get: () => 'application/json' },
      text: async () => JSON.stringify({
        success: false,
        error: { code: 'slot_taken', message: 'Horario acaba de ser reservado.' }
      })
    }));

    await ctx.flow.submitStaticBooking();
    await new Promise((r) => setTimeout(r, 20));

    assert.equal(ctx.flow.cart.createdBooking, null);
    assert.equal(ctx.flow.vouchers.length, 0);
    assert.equal(ctx.flow.conflicts.length, 1);
    assert.equal(ctx.flow.steps.includes(2), true);
    assert.equal(ctx.flow.steps.includes(4), false);
  } finally {
    ctx.cleanup();
  }
});

test('Integration 3: Double-click / retry idempotency preserves X-Idempotency-Key without duplicate booking', async () => {
  const ctx = createBookingSandbox();
  try {
    ctx.flow.StorageEngine.init();
    ctx.flow.CloudSync._enabled = false;

    const futureDate = new Date(Date.now() + 16 * 86400000).toISOString().slice(0, 10);
    const seenKeys = [];
    const serverStore = new Map();

    ctx.setFetch(async (url, init) => {
      if (!String(url).includes('/api/bookings') || !init || init.method !== 'POST') {
        return {
          status: 200,
          ok: true,
          headers: { get: () => 'application/json' },
          text: async () => JSON.stringify({ success: true, data: {} })
        };
      }
      const idemKey = init.headers['X-Idempotency-Key'];
      seenKeys.push(idemKey);
      if (!serverStore.has(idemKey)) {
        const body = JSON.parse(init.body);
        serverStore.set(idemKey, {
          code: 'ARK-IDEMP777',
          status: 'pendiente',
          clientName: body.clientName,
          selectedDate: body.selectedDate,
          selectedTime: body.selectedTime,
          province: body.province,
          canton: body.canton,
          serviceId: body.serviceId
        });
      }
      return {
        status: 201,
        ok: true,
        headers: { get: () => 'application/json' },
        text: async () => JSON.stringify({ success: true, data: { booking: serverStore.get(idemKey) } })
      };
    });

    const payload = {
      clientName: 'Ana Vargas',
      clientPhone: '8888-1111',
      clientEmail: 'ana@example.com',
      eventType: 'Corporativo',
      serviceId: ctx.flow.CATALOG_SERVICES[0].id,
      selectedDate: futureDate,
      selectedTime: '19:00',
      province: 'San José',
      canton: 'Central (San José)',
      extras: { extraHoursCount: 0, djHoursCount: 0, subwoofersCount: 0 }
    };

    const fixedKey = 'idem-retry-fixed-001';
    const first = await ctx.flow.BookingStore.add(Object.assign({}, payload), fixedKey);
    const second = await ctx.flow.BookingStore.add(Object.assign({}, payload), fixedKey);

    assert.equal(first.ok, true);
    assert.equal(second.ok, true);
    assert.equal(first.booking.code, 'ARK-IDEMP777');
    assert.equal(second.booking.code, 'ARK-IDEMP777');
    assert.deepEqual(seenKeys, [fixedKey, fixedKey]);
    assert.equal(serverStore.size, 1);
  } finally {
    ctx.cleanup();
  }
});

test('Resilience: CDN library fallbacks (docx, emailjs), DOM printFallback, and persistent ClientThrottler', async () => {
  // 1. Static check: printFallback must NOT use document.write
  const pfStart = appSrc.indexOf('function printFallback(');
  const pfEnd = appSrc.indexOf('const SPA_ROUTES =', pfStart);
  assert.ok(pfStart > 0 && pfEnd > pfStart);
  assert.equal(appSrc.slice(pfStart, pfEnd).includes('document.write'), false, 'printFallback must not use document.write');

  // 2. Runtime: blocked popup shows actionable toast
  const ctxBlocked = createBookingSandbox({ windowOpen: () => null });
  try {
    const ok = ctxBlocked.flow.printFallback('<p>Doc</p>', 'Test');
    assert.equal(ok, false);
    assert.equal(ctxBlocked.flow.toasts.some((t) => t.type === 'error' && /emergente|pop-up/i.test(t.msg)), true);

    // 3. Missing docx / emailjs show actionable toast without throwing
    ctxBlocked.flow.exportOwnerReportDOCX();
    assert.equal(ctxBlocked.flow.toasts.some((t) => t.type === 'error' && /docx|CDN/i.test(t.msg)), true);

    ctxBlocked.flow.cart.createdBooking = { code: 'ARK-1', clientEmail: 'a@b.com', clientName: 'A', selectedDate: '2026-12-20', granTotal: 1000, deposit50Amount: 500, remainingBalance: 500 };
    ctxBlocked.flow.sendBookingEmail(null);
    assert.equal(ctxBlocked.flow.toasts.some((t) => t.type === 'error' && /EmailJS|CDN/i.test(t.msg)), true);
  } finally {
    ctxBlocked.cleanup();
  }

  // 4. Persistent ClientThrottler across page reloads (shared localStorage map)
  const sharedLs = new Map();
  const ctx1 = createBookingSandbox({ lsMap: sharedLs });
  try {
    ctx1.flow.CLIENT_GUARD_CONFIG.maxSubmitAttempts = 2;
    ctx1.flow.CLIENT_GUARD_CONFIG.submitLockMs = 1;
    ctx1.flow.ClientThrottler.record();
    ctx1.flow.ClientThrottler.record();
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(ctx1.flow.ClientThrottler.check().ok, false);
    assert.equal(ctx1.flow.ClientThrottler.check().reason, 'rate');
  } finally {
    ctx1.cleanup();
  }

  const ctx2 = createBookingSandbox({ lsMap: sharedLs });
  try {
    ctx2.flow.CLIENT_GUARD_CONFIG.maxSubmitAttempts = 2;
    ctx2.flow.CLIENT_GUARD_CONFIG.submitLockMs = 1;
    const afterReload = ctx2.flow.ClientThrottler.check();
    assert.equal(afterReload.ok, false, 'ClientThrottler must stay rate-limited across reload');
    assert.equal(afterReload.reason, 'rate');
  } finally {
    ctx2.cleanup();
  }
});

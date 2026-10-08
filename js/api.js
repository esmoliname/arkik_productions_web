// Arkik Productions - Remote API client (window.ArkikApi)
//
// Vanilla browser client for the Vercel serverless API under /api. Classic
// script (no modules, no top-level await): it only exposes a single global.
//
// Contract of every helper (and of ArkikApi.request itself):
//   success -> { ok: true,  status, data, error: null }
//   failure -> { ok: false, status, data: null, error: { code, message } }
// The promise NEVER rejects, so callers can branch on `ok` without try/catch.
//
// For convenience the failure object also mirrors `code` and `message` at the
// top level (plus `retryAfterMs` / `details` when the server sends them), so
// call sites can read `res.code` directly.
//
// Error codes:
//   network       - fetch failed OR timed out (offline, DNS, CORS, abort)
//   disabled      - API_CONFIG.enabled === false (local-only legacy mode)
//   <server code> - error.code from the standard envelope, e.g. day_full
//   http_<status> - non-2xx response without a parseable envelope
//
// The session cookie is HttpOnly and travels automatically (credentials:
// 'same-origin'); no token is ever read or stored by this module.
(function (global) {
  "use strict";

  const DEFAULTS = { enabled: true, baseUrl: "", pollIntervalMs: 8000, timeoutMs: 8000 };
  const NETWORK_MESSAGE = "No fue posible conectar con el servidor.";
  const FALLBACK_MESSAGE = "No fue posible completar la operación en el servidor.";
  const DISABLED_MESSAGE = "Servicio remoto deshabilitado.";

  function config() {
    return typeof API_CONFIG !== "undefined" && API_CONFIG && typeof API_CONFIG === "object"
      ? API_CONFIG
      : DEFAULTS;
  }

  function isEnabled() {
    return config().enabled !== false;
  }

  // "" (same origin) or an absolute origin, never a trailing slash.
  function baseUrl() {
    return String(config().baseUrl || "").replace(/\/+$/, "");
  }

  function url(path, query) {
    const search = queryString(query);
    return baseUrl() + path + (search ? "?" + search : "");
  }

  function queryString(query) {
    if (!query || typeof query !== "object") return "";
    const parts = [];
    Object.keys(query).forEach((key) => {
      const value = query[key];
      if (value === undefined || value === null || value === "") return;
      parts.push(encodeURIComponent(key) + "=" + encodeURIComponent(String(value)));
    });
    return parts.join("&");
  }

  function timeoutMs() {
    const value = Number(config().timeoutMs);
    return Number.isFinite(value) && value > 0 ? value : DEFAULTS.timeoutMs;
  }

  // Failure envelope. `error` always carries {code, message}; the extra keys
  // (retryAfterMs, details, ...) are mirrored at the top level for call sites.
  function fail(status, code, message, extra) {
    const out = {
      ok: false,
      status: status,
      data: null,
      error: { code: code, message: message },
      code: code,
      message: message
    };
    if (extra && typeof extra === "object") {
      Object.keys(extra).forEach((key) => { out[key] = extra[key]; });
    }
    return out;
  }

  // Builds a failure from the standard {success:false,error:{code,message}}
  // envelope (or from a non-envelope body).
  function failure(status, body, fallbackCode) {
    const envelope = body && typeof body === "object" && body.error ? body.error : null;
    const code = (envelope && envelope.code) || fallbackCode || "http_" + status;
    const message = (envelope && envelope.message) || FALLBACK_MESSAGE;
    const extra = {};
    if (envelope && typeof envelope.retryAfterMs === "number") extra.retryAfterMs = envelope.retryAfterMs;
    if (envelope && typeof envelope.details !== "undefined") extra.details = envelope.details;
    if (envelope && typeof envelope.currentStatus !== "undefined") extra.currentStatus = envelope.currentStatus;
    if (envelope && typeof envelope.nextStatus !== "undefined") extra.nextStatus = envelope.nextStatus;
    if (envelope && typeof envelope.maxPerDay !== "undefined") extra.maxPerDay = envelope.maxPerDay;
    return fail(status, code, message, extra);
  }

  function normalize(res, body) {
    const status = res.status;
    if (status >= 200 && status < 300) {
      // Standard envelope {success, data}; /api/health answers with its own
      // flat shape ({success, service, database, timestamp}) and is returned as-is.
      if (body && typeof body === "object" && body.success === true && body.data !== undefined) {
        return { ok: true, status: status, data: body.data, error: null };
      }
      if (body && typeof body === "object" && body.success === false) {
        // 2xx carrying an envelope error: still reported as a failure.
        return failure(status, body, null);
      }
      return { ok: true, status: status, data: body === undefined ? null : body, error: null };
    }
    return failure(status, body, null);
  }

  /**
   * Core transport. Resolves with the normalized envelope, never rejects.
   * @param {string} method HTTP verb ("GET", "POST", "PUT", "PATCH", "DELETE")
   * @param {string} path   e.g. "/api/bookings"
   * @param {object} [body] JSON body (omitted for GET/DELETE)
   * @param {object} [opts] {query, headers, idempotencyKey, timeoutMs}
   * @returns {Promise<{ok:boolean,status:number,data:*,error:{code,message}|null}>}
   */
  function request(method, path, body, opts) {
    const options = opts || {};
    const verb = String(method || "GET").toUpperCase();

    if (!isEnabled()) return Promise.resolve(fail(0, "disabled", DISABLED_MESSAGE));
    if (typeof fetch !== "function") return Promise.resolve(fail(0, "network", NETWORK_MESSAGE));

    const headers = Object.assign({ Accept: "application/json" }, options.headers || {});
    if (options.idempotencyKey) headers["X-Idempotency-Key"] = String(options.idempotencyKey);
    const hasBody = body !== undefined && body !== null;
    if (hasBody) headers["Content-Type"] = "application/json";

    const ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
    const limit = Number(options.timeoutMs) > 0 ? Number(options.timeoutMs) : timeoutMs();
    const timer = ctrl ? setTimeout(function () { ctrl.abort(); }, limit) : null;

    return fetch(url(path, options.query), {
      method: verb,
      headers: headers,
      body: hasBody ? JSON.stringify(body) : undefined,
      credentials: "same-origin",
      cache: "no-store",
      signal: ctrl ? ctrl.signal : undefined
    })
      .then(function (res) {
        return res.text().then(function (text) {
          let parsed = null;
          if (text) {
            try { parsed = JSON.parse(text); } catch (err) { parsed = null; }
          }
          return normalize(res, parsed);
        });
      })
      .catch(function () {
        // Network failure or AbortController timeout: both collapse to the
        // contract's code 'network' with status 0.
        return fail(0, "network", NETWORK_MESSAGE);
      })
      .finally(function () {
        if (timer) clearTimeout(timer);
      });
  }

  function dataOf(res, fallback) {
    return res.ok && res.data !== undefined && res.data !== null ? res.data : fallback;
  }

  const api = {
    get enabled() { return isEnabled(); },
    isEnabled: isEnabled,
    baseUrl: baseUrl,
    request: request,

    // ---- system ----
    health: function () { return request("GET", "/api/health"); },

    // ---- public pricing ----
    pricing: function () { return request("GET", "/api/pricing"); },

    // ---- availability ----
    availability: function (params) {
      const query = {};
      if (params && params.date !== undefined) query.date = params.date;
      if (params && params.from) query.from = params.from;
      if (params && params.to) query.to = params.to;
      return request("GET", "/api/availability", undefined, { query: query });
    },
    setAvailability: function (payload) {
      return request("PUT", "/api/availability", payload);
    },
    clearAvailability: function (dateISO) {
      return request("DELETE", "/api/availability", undefined, { query: { date: dateISO } });
    },

    // ---- bookings ----
    listBookings: function (filters) {
      return request("GET", "/api/bookings", undefined, { query: filters });
    },
    // The idempotency key makes a retried POST return the SAME booking.
    createBooking: function (payload, idempotencyKey) {
      return request("POST", "/api/bookings", payload, { idempotencyKey: idempotencyKey });
    },
    getBooking: function (code, includeVoucher) {
      return request("GET", "/api/bookings/" + encodeURIComponent(code), undefined, {
        query: includeVoucher ? { include: "voucher" } : undefined
      });
    },
    patchBooking: function (code, payload) {
      return request("PATCH", "/api/bookings/" + encodeURIComponent(code), payload);
    },
    setStatus: function (code, status) {
      return request("PATCH", "/api/bookings/" + encodeURIComponent(code) + "/status", { status: status });
    },
    reschedule: function (code, schedule) {
      return request("PATCH", "/api/bookings/" + encodeURIComponent(code) + "/reschedule", {
        selectedDate: schedule && schedule.selectedDate,
        selectedTime: schedule && schedule.selectedTime
      });
    },

    // ---- admin (session cookie) ----
    admin: {
      login: function (role, pin) {
        return request("POST", "/api/admin/login", { role: role, pin: pin });
      },
      logout: function () { return request("POST", "/api/admin/logout"); },
      session: function () { return request("GET", "/api/admin/session"); },
      stats: function () { return request("GET", "/api/admin/stats"); },
      audit: function (limit) {
        return request("GET", "/api/admin/audit", undefined, { query: { limit: limit } });
      },
      getPricing: function () { return request("GET", "/api/admin/pricing"); },
      putPricing: function (payload) { return request("PUT", "/api/admin/pricing", payload); }
    },

    dataOf: dataOf
  };

  global.ArkikApi = api;
})(typeof window !== "undefined" ? window : this);

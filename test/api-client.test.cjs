// Contract harness for js/api.js.
// Loads js/data.js + js/api.js in a node:vm context with a stubbed fetch and
// asserts the frontend contract for createBooking.
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const REPO = path.resolve(__dirname, "..");
const dataSrc = fs.readFileSync(path.join(REPO, "js", "data.js"), "utf8");
const apiSrc = fs.readFileSync(path.join(REPO, "js", "api.js"), "utf8");

let mode = "ok";
let lastCall = null;

function jsonResponse(status, body) {
  return {
    status: status,
    text: async () => JSON.stringify(body)
  };
}

function stubFetch(url, options) {
  lastCall = { url: url, options: options };
  switch (mode) {
    case "network":
      return Promise.reject(new TypeError("Failed to fetch"));
    case "timeout": {
      const err = new Error("The operation was aborted due to timeout");
      err.name = "AbortError";
      return Promise.reject(err);
    }
    case "conflict":
      return Promise.resolve(jsonResponse(409, {
        success: false,
        error: { code: "day_full", message: "No hay cupos disponibles para ese día." }
      }));
    case "rate":
      return Promise.resolve(jsonResponse(429, {
        success: false,
        error: { code: "rate_limited", message: "Demasiadas solicitudes.", retryAfterMs: 30000 }
      }));
    case "ok":
    default:
      return Promise.resolve(jsonResponse(201, {
        success: true,
        data: { code: "ARK-TEST1", selectedDate: "2026-11-14", selectedTime: "14:00", status: "pendiente" }
      }));
  }
}

const sandbox = {
  console: console,
  setTimeout: setTimeout,
  clearTimeout: clearTimeout,
  Promise: Promise,
  JSON: JSON,
  Date: Date,
  Math: Math,
  Object: Object,
  String: String,
  Number: Number,
  Array: Array,
  Error: Error,
  TypeError: TypeError,
  encodeURIComponent: encodeURIComponent,
  fetch: stubFetch,
  AbortController: AbortController
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
vm.createContext(sandbox);

vm.runInContext(dataSrc, sandbox, { filename: "data.js" });
vm.runInContext(apiSrc, sandbox, { filename: "api.js" });

const ArkikApi = sandbox.ArkikApi;

let failures = 0;
function check(label, cond, detail) {
  if (cond) {
    console.log("  PASS  " + label);
  } else {
    failures += 1;
    console.log("  FAIL  " + label + (detail ? " -- " + detail : ""));
  }
}

const AMOUNT_RE = /amount|total|price|subtotal|balance|cost|fee|discount/i;

async function main() {
  console.log("[1] createBooking success: body has NO amount fields + idempotency header");
  mode = "ok";
  lastCall = null;
  const res1 = await ArkikApi.createBooking(
    {
      service: "Produccion DJ",
      selectedDate: "2026-11-14",
      selectedTime: "14:00",
      clientName: "Prueba",
      clientPhone: "88888888",
      eventHours: 6,
      extraHoursCount: 1,
      province: "San Jose",
      canton: "Montes de Oca"
    },
    "key-Abc_12345678"
  );
  check("res.ok === true with 201 envelope", res1.ok === true && res1.data && res1.data.code === "ARK-TEST1");
  check("POST /api/bookings", lastCall && lastCall.options.method === "POST" && lastCall.url.indexOf("/api/bookings") !== -1,
    lastCall && lastCall.url + " " + lastCall.options.method);
  const sentBody = lastCall && lastCall.options.body ? JSON.parse(lastCall.options.body) : null;
  const amountKeys = sentBody ? Object.keys(sentBody).filter((k) => AMOUNT_RE.test(k)) : ["<no body>"];
  check("sent body contains NO amount/price/total fields", sentBody !== null && amountKeys.length === 0,
    "found: " + amountKeys.join(","));
  const hdrs = lastCall.options.headers || {};
  check("X-Idempotency-Key header sent verbatim", hdrs["X-Idempotency-Key"] === "key-Abc_12345678",
    JSON.stringify(hdrs["X-Idempotency-Key"]));
  check("Content-Type: application/json", hdrs["Content-Type"] === "application/json");
  check("credentials same-origin (cookie)", lastCall.options.credentials === "same-origin");
  mode = "ok";
  lastCall = null;
  await ArkikApi.createBooking({ service: "x" });
  check("no idempotency header when key omitted",
    !(("X-Idempotency-Key" in (lastCall.options.headers || {}))),
    JSON.stringify(lastCall.options.headers));

  console.log("[2] 409 day_full maps to code day_full (no rejection)");
  mode = "conflict";
  const res2 = await ArkikApi.createBooking({ service: "x" }, "key-12345678");
  check("promise resolved (no throw)", res2 && typeof res2 === "object");
  check("ok === false", res2.ok === false);
  check("status === 409", res2.status === 409, String(res2.status));
  check("error.code === day_full", res2.error && res2.error.code === "day_full", JSON.stringify(res2.error));
  check("top-level res.code mirrors server code", res2.code === "day_full");
  check("res.data === null on failure", res2.data === null);

  console.log("[3] rate_limited carries retryAfterMs");
  mode = "rate";
  const res3 = await ArkikApi.createBooking({ service: "x" }, "key-12345678");
  check("ok === false, code rate_limited", res3.ok === false && res3.code === "rate_limited");
  check("retryAfterMs === 30000", res3.retryAfterMs === 30000, String(res3.retryAfterMs));

  console.log("[4] network failure collapses to code 'network', status 0");
  mode = "network";
  const res4 = await ArkikApi.createBooking({ service: "x" }, "key-12345678");
  check("ok === false", res4.ok === false);
  check("code === 'network' (no 'timeout' code)", res4.code === "network", String(res4.code));
  check("status === 0", res4.status === 0, String(res4.status));
  check("error.message present", !!(res4.error && res4.error.message), JSON.stringify(res4.error));

  console.log("[5] AbortController timeout also collapses to code 'network'");
  mode = "timeout";
  const res5 = await ArkikApi.createBooking({ service: "x" }, "key-12345678");
  check("ok === false, code network", res5.ok === false && res5.code === "network", String(res5.code));
  check("status === 0", res5.status === 0, String(res5.status));

  console.log("");
  if (failures === 0) {
    console.log("HARNESS RESULT: ALL PASS");
  } else {
    console.log("HARNESS RESULT: " + failures + " FAILURE(S)");
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error("HARNESS CRASH:", err);
  process.exitCode = 1;
});

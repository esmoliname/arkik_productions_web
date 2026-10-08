'use strict';
// Test injection seam.
// Handlers resolve services through get(name) INSIDE the handler body, so a
// test can call __setForTests({service: fakeService}) before invoking the
// handler and no real database is ever touched.

let overrides = Object.create(null);

function get(name) {
  if (Object.prototype.hasOwnProperty.call(overrides, name)) {
    return overrides[name];
  }
  return require('./' + name);
}

function __setForTests(obj) {
  overrides = Object.create(null);
  if (obj && typeof obj === 'object') {
    for (const key of Object.keys(obj)) overrides[key] = obj[key];
  }
}

function __resetForTests() {
  overrides = Object.create(null);
}

module.exports = { get, __setForTests, __resetForTests };

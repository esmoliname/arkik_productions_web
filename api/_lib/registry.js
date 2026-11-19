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
  // Static require paths: Cloudflare Pages (esbuild) cannot bundle dynamic
  // require('./' + name). Keep the path as a string literal so the bundler
  // can resolve and include the module.
  switch (name) {
    case 'auth': return require('./auth');
    case 'config': return require('./config');
    case 'cors': return require('./cors');
    case 'db': return require('./db');
    case 'log': return require('./log');
    case 'logic': return require('./logic');
    case 'ratelimit': return require('./ratelimit');
    case 'repo': return require('./repo');
    case 'respond': return require('./respond');
    case 'service': return require('./service');
    default: return require('./' + name);
  }
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

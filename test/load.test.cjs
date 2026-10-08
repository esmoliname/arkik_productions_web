'use strict';
// Load-time smoke check for the Arkik API (run from the repo root).
const path = require('path');

const roots = ['api/_lib'];
const files = [
  'api/health.js',
  'api/bookings/index.js',
  'api/bookings/[code]/index.js',
  'api/bookings/[code]/status.js',
  'api/bookings/[code]/reschedule.js',
  'api/availability/index.js',
  'api/admin/login.js',
  'api/admin/logout.js',
  'api/admin/session.js',
  'api/admin/stats.js',
  'api/admin/pricing.js',
  'api/admin/audit.js'
];

const fs = require('fs');
for (const root of roots) {
  for (const name of fs.readdirSync(path.resolve(root))) {
    if (name.endsWith('.js')) files.push(path.join(root, name));
  }
}

let fails = 0;
for (const file of files) {
  try {
    const mod = require(path.resolve(file));
    if (file.includes('_lib')) continue;
    if (typeof mod !== 'function') {
      console.log('NOT A FUNCTION: ' + file);
      fails += 1;
    } else if (mod.length !== 2) {
      console.log('WRONG HANDLER ARITY: ' + file + ' -> ' + mod.length);
      fails += 1;
    }
  } catch (err) {
    console.log('LOAD FAIL: ' + file + ' -> ' + err.message);
    fails += 1;
  }
}

// Registry wiring: every module name a handler requests must resolve.
const registry = require(path.resolve('api/_lib/registry'));
const needed = ['config', 'log', 'respond', 'db', 'repo', 'logic', 'auth', 'service', 'ratelimit'];
for (const name of needed) {
  try {
    const value = registry.get(name);
    if (!value) throw new Error('empty');
  } catch (err) {
    console.log('REGISTRY FAIL: ' + name + ' -> ' + err.message);
    fails += 1;
  }
}

console.log('checked=' + files.length + ' fails=' + fails);
process.exit(fails ? 1 : 0);

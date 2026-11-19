'use strict';
// Request-scoped environment context for Cloudflare Pages (and Vercel fallback).
// Uses AsyncLocalStorage so concurrent requests never share env state.
// Falls back to process.env when no store is active (Vercel/Node/test context).

const { AsyncLocalStorage } = require('async_hooks');

const als = new AsyncLocalStorage();

function getEnv() {
  const store = als.getStore();
  if (store && store.env && typeof store.env === 'object') return store.env;
  return process.env;
}

function readEnv(name, fallback) {
  const env = getEnv();
  const value = env ? env[name] : undefined;
  return value === undefined || value === '' ? fallback : value;
}

function runWithEnv(env, fn) {
  return als.run({ env: env || {} }, fn);
}

module.exports = { als, getEnv, readEnv, runWithEnv };

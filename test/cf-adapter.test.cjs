'use strict';
const assert = require('node:assert/strict');
const { describe, test } = require('node:test');
const { buildReq, parseBody, createRes, invokeHandler } = require('../functions/_lib/cf-adapter');

describe('cf-adapter buildReq', () => {
  test('maps method, headers, query and cf-connecting-ip', async () => {
    const req = new Request('https://example.com/api/x?foo=bar&foo=baz', {
      method: 'POST',
      headers: { 'cf-connecting-ip': '203.0.113.9', 'content-type': 'application/json' }
    });
    const { req: r, url } = buildReq(req, { DEPLOY_PLATFORM: 'cloudflare-pages' }, { code: 'ABC' });
    assert.equal(r.method, 'POST');
    assert.equal(r.headers['cf-connecting-ip'], '203.0.113.9');
    assert.equal(r.query.foo, 'baz');
    assert.equal(r.query.code, 'ABC');
    assert.equal(r.socket.remoteAddress, '203.0.113.9');
    assert.equal(r.connection.remoteAddress, '203.0.113.9');
    assert.equal(r.__trustedProxy, 'cloudflare');
    assert.equal(r.cfConnectingIp, '203.0.113.9');
    assert.ok(url instanceof URL);
  });
});

describe('cf-adapter parseBody', () => {
  test('GET leaves body undefined', async () => {
    const req = { method: 'GET' };
    const r = { body: 'x' };
    await parseBody(req, r);
    assert.equal(r.body, undefined);
  });
  test('empty body becomes {}', async () => {
    const request = new Request('https://e.com/api/x', { method: 'POST', body: '' });
    const r = {};
    await parseBody(request, r);
    assert.deepEqual(r.body, {});
  });
  test('JSON body parsed', async () => {
    const request = new Request('https://e.com/api/x', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ a: 1 })
    });
    const r = {};
    await parseBody(request, r);
    assert.deepEqual(r.body, { a: 1 });
  });
  test('invalid JSON kept as raw', async () => {
    const request = new Request('https://e.com/api/x', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{bad'
    });
    const r = {};
    await parseBody(request, r);
    assert.equal(r.body, '{bad');
  });
  test('non-json body kept as raw', async () => {
    const request = new Request('https://e.com/api/x', {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: 'hello'
    });
    const r = {};
    await parseBody(request, r);
    assert.equal(r.body, 'hello');
  });
});

describe('cf-adapter createRes', () => {
  test('initial status 200 and statusCode getter/setter coherent', () => {
    const { res, getStatus } = createRes();
    assert.equal(res.statusCode, 200);
    assert.equal(getStatus(), 200);
    res.statusCode = 404;
    assert.equal(res.statusCode, 404);
    assert.equal(getStatus(), 404);
    res.status(201);
    assert.equal(res.statusCode, 201);
    assert.equal(getStatus(), 201);
  });
  test('setHeader captures set-cookie separately', () => {
    const { res, getHeaders } = createRes();
    res.setHeader('Set-Cookie', 'a=1; HttpOnly');
    res.setHeader('X-Test', 'v');
    const h = getHeaders();
    assert.equal(h.get('x-test'), 'v');
    const cookies = h.getSetCookie ? h.getSetCookie() : [];
    assert.ok(cookies.some((c) => c.includes('a=1')));
  });
  test('json sets body and content-type', () => {
    const { res, getBody, getHeaders, isBodySet } = createRes();
    res.status(200).json({ ok: true });
    assert.equal(getBody(), '{"ok":true}');
    assert.equal(getHeaders().get('content-type'), 'application/json');
    assert.equal(isBodySet(), true);
    assert.equal(res.headersSent, true);
  });
  test('end sets body', () => {
    const { res, getBody, isBodySet } = createRes();
    res.status(204).end();
    assert.equal(isBodySet(), true);
    assert.equal(getBody(), null);
  });
  test('writeHead sets status and headers', () => {
    const { res, getStatus, getHeaders } = createRes();
    res.writeHead(302, { Location: '/x' });
    assert.equal(getStatus(), 302);
    assert.equal(getHeaders().get('location'), '/x');
  });
});

describe('cf-adapter invokeHandler', () => {
  test('returns Response with status/headers/body', async () => {
    const handler = async (req, res) => {
      res.status(200).json({ echo: req.query.q });
    };
    const request = new Request('https://e.com/api/x?q=hi', { method: 'GET' });
    const response = await invokeHandler(handler, request, { DEPLOY_PLATFORM: 'cloudflare-pages' }, {});
    assert.equal(response.status, 200);
    const text = await response.text();
    assert.equal(text, '{"echo":"hi"}');
    assert.equal(response.headers.get('content-type'), 'application/json');
  });
  test('captures thrown error as 500', async () => {
    const handler = async (req, res) => { throw new Error('boom'); };
    const request = new Request('https://e.com/api/x', { method: 'GET' });
    const response = await invokeHandler(handler, request, {}, {});
    assert.equal(response.status, 500);
    const text = await response.text();
    assert.ok(text.includes('internal_error'));
  });
  test('empty body returns null body', async () => {
    const handler = async (req, res) => { res.status(204).end(); };
    const request = new Request('https://e.com/api/x', { method: 'GET' });
    const response = await invokeHandler(handler, request, {}, {});
    assert.equal(response.status, 204);
  });
});

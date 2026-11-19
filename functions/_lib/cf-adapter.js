'use strict';
// Cloudflare Pages adapter: converts a Web Request into the Node (req, res)
// shape expected by the existing Arkik handlers, and back to a Web Response.
// No business logic lives here.

const { runWithEnv, readEnv } = require('../../api/_lib/env-context');

// Build a req-like object from a CF Request.
function buildReq(request, env, pathParams) {
  const url = new URL(request.url);
  const headers = {};
  for (const [k, v] of request.headers.entries()) headers[k.toLowerCase()] = v;

  const req = {
    method: request.method,
    url: request.url,
    headers: headers,
    query: Object.assign({}, Object.fromEntries(url.searchParams.entries()), pathParams || {}),
    socket: { remoteAddress: headers['cf-connecting-ip'] || '' },
    connection: { remoteAddress: headers['cf-connecting-ip'] || '' },
    __trustedProxy: 'cloudflare',
    cfConnectingIp: headers['cf-connecting-ip'] || null,
    body: undefined
  };
  return { req, url };
}

// Parse request body into req.body (mirrors Vercel pre-parsing).
async function parseBody(request, req) {
  if (request.method === 'GET' || request.method === 'HEAD') {
    req.body = undefined;
    return;
  }
  const contentType = (request.headers.get('content-type') || '').toLowerCase();
  const raw = await request.text();
  if (!raw || !raw.trim()) {
    req.body = {};
    return;
  }
  if (contentType.includes('application/json')) {
    try {
      req.body = JSON.parse(raw);
    } catch (e) {
      req.body = raw; // let handler's readBody/parseJson throw
    }
  } else {
    req.body = raw;
  }
}

// Create a res shim that captures status/headers/body.
function createRes() {
  let status = 200;
  const headers = new Headers();
  const cookies = [];
  let body = null;
  let bodySet = false;
  let headersSent = false;

  const res = {
    get headersSent() { return headersSent; },
    get statusCode() { return status; },
    set statusCode(v) { status = v; },
    setHeader(name, value) {
      const lower = String(name).toLowerCase();
      if (lower === 'set-cookie') {
        cookies.push(String(value));
        return this;
      }
      if (lower === 'content-type') {
        // don't override if already set by json()
      }
      headers.set(name, String(value));
      return this;
    },
    status(code) {
      status = code;
      this.statusCode = code;
      return this;
    },
    json(data) {
      body = JSON.stringify(data);
      if (!headers.has('content-type')) headers.set('content-type', 'application/json');
      bodySet = true;
      headersSent = true;
      return this;
    },
    end(data) {
      if (data !== undefined && data !== null) body = (typeof data === 'string' ? data : String(data));
      bodySet = true;
      headersSent = true;
      return this;
    },
    writeHead(code, hdrs) {
      status = code;
      if (hdrs) for (const k of Object.keys(hdrs)) this.setHeader(k, hdrs[k]);
      return this;
    }
  };

  return {
    res,
    getStatus: () => status,
    getHeaders: () => {
      const h = new Headers(headers);
      for (const c of cookies) h.append('set-cookie', c);
      return h;
    },
    getBody: () => body,
    isBodySet: () => bodySet
  };
}

// Invoke an Arkik handler (already wrapped with withCors) under a request-scoped env.
async function invokeHandler(handler, request, env, pathParams) {
  const { req, url } = buildReq(request, env, pathParams);
  await parseBody(request, req);

  const { res, getStatus, getHeaders, getBody, isBodySet } = createRes();

  await runWithEnv(env || {}, async () => {
    try {
      await handler(req, res);
    } catch (err) {
      // withCors normally catches; if it escapes, produce 500.
      if (!res.headersSent) {
        res.status(500).json({ success: false, error: { code: 'internal_error', message: 'Error interno del servidor.' } });
      }
    }
  });

  const status = getStatus();
  const headers = getHeaders();
  const body = getBody();

  // Ensure a content-type for JSON-ish empty bodies
  if (!headers.has('content-type') && body && body.trim().startsWith('{')) {
    headers.set('content-type', 'application/json');
  }

  if (!isBodySet() || body === null) {
    return new Response(null, { status, headers });
  }
  return new Response(body, { status, headers });
}

module.exports = { buildReq, parseBody, createRes, invokeHandler, runWithEnv };

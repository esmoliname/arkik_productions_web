'use strict';
// Arkik Productions - Full-stack local development server.
// Serves static frontend assets AND routes /api/* requests directly to Vercel handlers,
// preventing static SPA rewrites from hijacking POST /api/* with 200 text/html.
//
// Usage: node scripts/dev-server.js   (npm run dev)

const http = require('http');
const fs = require('fs');
const path = require('path');
const { loadEnvFiles } = require('../db/migrate');

const ROOT_DIR = path.resolve(__dirname, '..');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.woff2': 'font/woff2'
};

const BLOCKED_TOP_LEVEL = new Set([
  'api',
  'db',
  'docs',
  'node_modules',
  'scripts',
  'test',
  'package.json',
  'package-lock.json',
  'vercel.json'
]);

const STATIC_API_MAP = new Map([
  ['/api/health', '../api/health.js'],
  ['/api/pricing', '../api/pricing.js'],
  ['/api/admin/audit', '../api/admin/audit.js'],
  ['/api/admin/dashboard', '../api/admin/dashboard.js'],
  ['/api/admin/login', '../api/admin/login.js'],
  ['/api/admin/logout', '../api/admin/logout.js'],
  ['/api/admin/pricing', '../api/admin/pricing.js'],
  ['/api/admin/session', '../api/admin/session.js'],
  ['/api/admin/stats', '../api/admin/stats.js'],
  ['/api/availability', '../api/availability/index.js'],
  ['/api/bookings', '../api/bookings/index.js']
]);

function resolveApiRoute(pathname) {
  const clean = pathname.length > 1 && pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;
  if (STATIC_API_MAP.has(clean)) {
    return { handlerPath: STATIC_API_MAP.get(clean), params: {} };
  }

  const bookingSub = /^\/api\/bookings\/([^/]+)\/(status|reschedule)$/.exec(clean);
  if (bookingSub) {
    return {
      handlerPath: `../api/bookings/[code]/${bookingSub[2]}.js`,
      params: { code: decodeURIComponent(bookingSub[1]) }
    };
  }

  const bookingItem = /^\/api\/bookings\/([^/]+)$/.exec(clean);
  if (bookingItem) {
    return {
      handlerPath: '../api/bookings/[code]/index.js',
      params: { code: decodeURIComponent(bookingItem[1]) }
    };
  }

  return null;
}

function decorateResponse(res) {
  if (typeof res.status !== 'function') {
    res.status = function status(code) {
      res.statusCode = code;
      return res;
    };
  }
  if (typeof res.json !== 'function') {
    res.json = function json(payload) {
      if (!res.headersSent) {
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
      }
      res.end(JSON.stringify(payload));
      return res;
    };
  }
  if (typeof res.send !== 'function') {
    res.send = function send(body) {
      res.end(body);
      return res;
    };
  }
  return res;
}

function sendJsonError(res, statusCode, code, message) {
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify({ success: false, error: { code, message } }));
}

function applySecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
}

async function handleApiRequest(req, res, urlObj) {
  const match = resolveApiRoute(urlObj.pathname);
  if (!match) {
    sendJsonError(res, 404, 'not_found', 'API endpoint not found.');
    return;
  }

  const query = {};
  for (const [k, v] of urlObj.searchParams.entries()) {
    query[k] = v;
  }
  Object.assign(query, match.params);
  req.query = query;

  decorateResponse(res);
  const handler = require(match.handlerPath);
  await handler(req, res);
}

function isSafePublicPath(pathname) {
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch (_) {
    return null;
  }
  if (decoded.includes('\0') || decoded.includes('\\')) return null;

  const trimmed = decoded === '/' ? 'index.html' : decoded.replace(/^\/+/, '');
  const segments = trimmed.split('/').filter(Boolean);
  if (segments.length === 0) return path.join(ROOT_DIR, 'index.html');
  for (const seg of segments) {
    if (seg === '.' || seg === '..' || seg.startsWith('.')) return null;
  }
  if (BLOCKED_TOP_LEVEL.has(segments[0])) return null;

  const fullPath = path.resolve(ROOT_DIR, ...segments);
  const rootPrefix = ROOT_DIR.endsWith(path.sep) ? ROOT_DIR : ROOT_DIR + path.sep;
  if (!fullPath.startsWith(rootPrefix)) return null;
  return fullPath;
}

function serveStatic(req, res, urlObj) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.statusCode = 405;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end('Method Not Allowed');
    return;
  }

  const target = isSafePublicPath(urlObj.pathname);
  if (!target || !fs.existsSync(target) || fs.statSync(target).isDirectory()) {
    res.statusCode = 404;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end('Not Found');
    return;
  }

  const ext = path.extname(target).toLowerCase();
  const mime = MIME_TYPES[ext] || 'application/octet-stream';
  res.statusCode = 200;
  res.setHeader('Content-Type', mime);
  res.setHeader('Cache-Control', ext === '.html' ? 'no-store' : 'public, max-age=60');
  if (req.method === 'HEAD') {
    res.end();
    return;
  }
  fs.createReadStream(target).pipe(res);
}

function createDevServer() {
  return http.createServer(async (req, res) => {
    applySecurityHeaders(res);
    const host = req.headers.host || '127.0.0.1';
    const urlObj = new URL(req.url || '/', `http://${host}`);

    if (urlObj.pathname === '/api' || urlObj.pathname.startsWith('/api/')) {
      try {
        await handleApiRequest(req, res, urlObj);
      } catch (err) {
        if (!res.headersSent) {
          sendJsonError(res, 500, 'internal_error', 'Unexpected dev server error executing API handler.');
        }
        console.error('[arkik dev] API error:', err && err.message ? err.message : err);
      }
      return;
    }

    serveStatic(req, res, urlObj);
  });
}

if (require.main === module) {
  loadEnvFiles();
  const port = Number(process.env.PORT || 3000);
  const host = process.env.HOST || '127.0.0.1';
  const server = createDevServer();
  server.listen(port, host, () => {
    console.log(`[arkik dev] Full-stack local server listening on http://${host}:${port}`);
    console.log('[arkik dev] Static assets + /api/* Vercel handlers active.');
    if (!process.env.DATABASE_URL) {
      console.log('[arkik dev] DATABASE_URL not set: using stateless env-var fallback mode (no DB persistence).');
    }
  });
}

module.exports = {
  resolveApiRoute,
  handleApiRequest,
  isSafePublicPath,
  createDevServer
};

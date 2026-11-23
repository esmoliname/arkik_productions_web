'use strict';
// Arkik Productions - Render single-service runtime.
// Serves the static frontend and routes /api/* to the existing Vercel handlers
// without duplicating resources or rewriting authentication.
const { loadEnvFiles } = require('../db/migrate');
const { createDevServer } = require('./dev-server');

loadEnvFiles();

const port = Number(process.env.PORT || 10000);
const host = process.env.HOST || '0.0.0.0';
const server = createDevServer();

server.listen(port, host, () => {
  console.log(`[arkik render] Full-stack service listening on http://${host}:${port}`);
});

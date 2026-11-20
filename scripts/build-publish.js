'use strict';
// Cloudflare Pages build script: reconstructs the publish/ directory.
// Usage: npm run build (or node scripts/build-publish.js)
// Output: publish/ (git-ignored, for Cloudflare Pages deployment)

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const PUB = path.join(ROOT, 'publish');

function copyRecursive(src, dest) {
  if (!fs.existsSync(src)) return;
  const stat = fs.statSync(src);
  if (stat.isDirectory()) {
    fs.mkdirSync(dest, { recursive: true });
    for (const entry of fs.readdirSync(src)) {
      copyRecursive(path.join(src, entry), path.join(dest, entry));
    }
  } else {
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(src, dest);
  }
}

// Clean and recreate publish/
if (fs.existsSync(PUB)) fs.rmSync(PUB, { recursive: true, force: true });
fs.mkdirSync(PUB, { recursive: true });

// Static assets
for (const f of ['index.html', '_headers', '_redirects']) {
  const src = path.join(ROOT, f);
  if (fs.existsSync(src)) fs.copyFileSync(src, path.join(PUB, f));
}

for (const d of ['css', 'js', 'img', 'functions', 'api']) {
  copyRecursive(path.join(ROOT, d), path.join(PUB, d));
}

console.log('[build] publish/ reconstructed successfully.');
console.log('[build] Contents:');
for (const entry of fs.readdirSync(PUB)) {
  const stat = fs.statSync(path.join(PUB, entry));
  console.log(`  ${entry}${stat.isDirectory() ? '/' : ''}`);
}
// Browser smoke test: the SPA must reach the load event and render content in
// <app-root> — regardless of auth state or role configuration. Guards against
// startup hangs like the roleGuard redirect loop ('' → hosts → '/' → …) that
// pegged the main thread and left the page blank forever.
//
// Usage:
//   node e2e/smoke.mjs               serve ../dist locally (with /v1/ui/config stub)
//   node e2e/smoke.mjs <url>         probe a running instance instead
//
// Requires Google Chrome (uses playwright-core with channel 'chrome').
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const LOAD_TIMEOUT_MS = 15_000;
const dist = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist');

const types = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.ico': 'image/x-icon',
  '.json': 'application/json',
};

// Mirrors internal/api/ui.go: files as-is, SPA fallback to index.html, plus a
// /v1/ui/config stub so the app boots like against a real server.
function serveDist() {
  const server = http.createServer((req, res) => {
    const { pathname } = new URL(req.url, 'http://localhost');
    if (pathname === '/v1/ui/config') {
      res.setHeader('content-type', 'application/json');
      res.end(
        JSON.stringify({
          oidc_issuer: 'https://idp.invalid',
          oidc_client_id: 'smoke-test',
          admin_group: '',
          auditor_group: '',
          readonly_group: '',
        }),
      );
      return;
    }
    let file = pathname.replace(/^\//, '') || 'index.html';
    if (!fs.existsSync(path.join(dist, file))) file = 'index.html';
    res.setHeader('content-type', types[path.extname(file)] ?? 'application/octet-stream');
    fs.createReadStream(path.join(dist, file)).pipe(res);
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

let url = process.argv[2];
let server;
if (!url) {
  if (!fs.existsSync(path.join(dist, 'index.html'))) {
    console.error(`SMOKE FAIL: no build in ${dist} — run the web build first (make web).`);
    process.exit(2);
  }
  server = await serveDist();
  url = `http://127.0.0.1:${server.address().port}/`;
}

const browser = await chromium.launch({ channel: 'chrome', headless: true });
const page = await browser.newPage({ ignoreHTTPSErrors: true });
const errors = [];
page.on('pageerror', (e) => errors.push(e.message.split('\n')[0]));

let loaded = false;
try {
  await page.goto(url, { waitUntil: 'load', timeout: LOAD_TIMEOUT_MS });
  loaded = true;
} catch {
  // load event never fired — the startup hang this test exists for.
}

let content = '';
if (loaded) {
  // App must render something meaningful: login card, error card or shell.
  await page
    .waitForFunction(() => (document.querySelector('app-root')?.innerHTML ?? '').trim() !== '', {
      timeout: 10_000,
    })
    .catch(() => {});
  content = await page.evaluate(() => document.querySelector('app-root')?.innerText ?? '');
}

await browser.close();
server?.close();

if (!loaded) {
  console.error(`SMOKE FAIL: ${url} — load event not fired within ${LOAD_TIMEOUT_MS}ms (JS hang?).`);
  process.exit(1);
}
if (content.trim() === '') {
  console.error(`SMOKE FAIL: ${url} — page loaded but <app-root> stayed empty.`);
  if (errors.length) console.error('page errors:\n  ' + errors.join('\n  '));
  process.exit(1);
}
console.log(`SMOKE OK: page loaded, app rendered: ${JSON.stringify(content.slice(0, 120))}`);
if (errors.length) console.log('page errors (non-fatal):\n  ' + errors.join('\n  '));

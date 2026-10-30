#!/usr/bin/env node
// tools/scripts/lib/wasm-verify.mjs — browser RUN driver for `web client` SPA
// examples. Serves the emitted `www/` tree with a local HTTP server (no binary
// to boot — the WASM runs entirely in the browser), launches headless Chromium,
// runs the named scenario, and exits 0/1.
//
// Usage:
//   node wasm-verify.mjs <www-dir> <scenario> [port]
//
// <www-dir>   — path to the `out/rust/www/` directory (must contain
//               index.html + pkg/ipe_app.js + pkg/ipe_app_bg.wasm)
// <scenario>  — a scenario key, or "smoke" (boot + non-empty body only)
// [port]      — TCP port for the local HTTP server (default: auto-pick)
//
// Exits 0 on pass, non-zero on any failure.

import { chromium } from 'playwright';
import { createServer } from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const wwwDir      = path.resolve(process.argv[2] || '');
const scenarioName = process.argv[3] || 'smoke';
const requestedPort = parseInt(process.argv[4] || '0', 10);

if (!wwwDir || !fs.existsSync(path.join(wwwDir, 'index.html'))) {
    console.error('usage: node wasm-verify.mjs <www-dir> <scenario> [port]');
    console.error(`www-dir ${wwwDir || '(missing)'} has no index.html`);
    process.exit(2);
}

// ── MIME types for the static server ──────────────────────────────────────
const MIME = {
    '.html': 'text/html',
    '.js':   'application/javascript',
    '.wasm': 'application/wasm',
    '.css':  'text/css',
    '.json': 'application/json',
};

// ── Static file server ────────────────────────────────────────────────────
function serveStatic(wwwRoot) {
    return createServer((req, res) => {
        const urlPath = req.url.split('?')[0];
        const filePath = path.join(wwwRoot, urlPath === '/' ? 'index.html' : urlPath);
        const ext = path.extname(filePath).toLowerCase();
        const mime = MIME[ext] || 'application/octet-stream';
        fs.readFile(filePath, (err, data) => {
            if (err) {
                res.writeHead(404);
                res.end('not found');
            } else {
                res.writeHead(200, {
                    'Content-Type': mime,
                    // WASM requires COOP/COEP only for SharedArrayBuffer; plain
                    // wasm-bindgen bundles need neither. Omit to avoid CORS
                    // complications with localhost test setups.
                });
                res.end(data);
            }
        });
    });
}

function freePort() {
    return new Promise((resolve, reject) => {
        const s = net.createServer();
        s.listen(0, '127.0.0.1', () => {
            const port = s.address().port;
            s.close(() => resolve(port));
        });
        s.on('error', reject);
    });
}

// ── Panic / error detection ────────────────────────────────────────────────
const PANIC_PATTERNS = [
    /panic:/i,
    /panicked/i,
    /RuntimeError/,
    /wasm trap/i,
    /StackOverflow/i,
    /CompilerBug/,
    /Uncaught/,
];

function looksLikePanic(text) {
    return PANIC_PATTERNS.some(re => re.test(text));
}

// ── Scenarios ─────────────────────────────────────────────────────────────
async function runScenario(page, baseUrl, name) {
    // Optional named-scenario module. The sweep drives every example with the
    // `smoke` key (boot + non-empty body), so this branch is dormant unless a
    // verify-scenarios.mjs is dropped alongside this file with a named export.
    const scenariosPath = path.join(__dirname, 'verify-scenarios.mjs');
    if (name !== 'smoke' && fs.existsSync(scenariosPath)) {
        const mod = await import(pathToFileURL(scenariosPath).href);
        const fn = mod[name] ?? mod.default?.[name];
        if (typeof fn === 'function') {
            await fn(page, { baseUrl, pause: (ms) => page.waitForTimeout(ms), log: console.log });
            return;
        }
    }

    // Smoke: navigate, wait for the WASM module to boot.
    // The runtime mounts directly into document.body (set_inner_html on body);
    // there is no #app wrapper div. Poll for a non-empty body with up to 10 s.
    await page.goto(baseUrl, { waitUntil: 'domcontentloaded', timeout: 20_000 });
    try {
        await page.waitForFunction(
            () => document.body?.children.length > 0,
            { timeout: 10_000 }
        );
    } catch {
        throw new Error('WASM app did not mount within 10 s (body stays empty)');
    }
}

// ── wasm-spa scenario: counter buttons ────────────────────────────────────
async function runWasmSpa(page, baseUrl) {
    await page.goto(baseUrl, { waitUntil: 'domcontentloaded', timeout: 20_000 });
    // Wait for the WASM scheduler's first frame
    await page.waitForFunction(
        () => (document.querySelector('[data-testid="counter"]') !== null),
        { timeout: 10_000 }
    );

    const read = () => page.locator('[data-testid="counter"]').textContent({ timeout: 3_000 });

    const initial = await read();
    if (initial !== '0') throw new Error(`initial count expected 0, got ${JSON.stringify(initial)}`);

    // Increment twice
    await page.locator('[data-testid="increment"]').click();
    await page.waitForTimeout(200);
    await page.locator('[data-testid="increment"]').click();
    await page.waitForTimeout(200);
    const after2 = await read();
    if (after2 !== '2') throw new Error(`after 2 increments expected 2, got ${JSON.stringify(after2)}`);

    // Decrement once
    await page.locator('[data-testid="decrement"]').click();
    await page.waitForTimeout(200);
    const after1 = await read();
    if (after1 !== '1') throw new Error(`after decrement expected 1, got ${JSON.stringify(after1)}`);

    // Reset
    await page.locator('[data-testid="reset"]').click();
    await page.waitForTimeout(200);
    const afterReset = await read();
    if (afterReset !== '0') throw new Error(`after reset expected 0, got ${JSON.stringify(afterReset)}`);

    console.log('wasm-spa scenario: PASS — increment/decrement/reset all correct');
}

// ── Main ──────────────────────────────────────────────────────────────────
async function main() {
    const port = requestedPort || await freePort();
    const server = serveStatic(wwwDir);
    await new Promise((resolve, reject) => {
        server.listen(port, '127.0.0.1', resolve);
        server.on('error', reject);
    });
    const baseUrl = `http://127.0.0.1:${port}/`;

    const executablePath = process.env.IPE_CHROMIUM && fs.existsSync(process.env.IPE_CHROMIUM)
        ? process.env.IPE_CHROMIUM
        : undefined;

    const browser = await chromium.launch({ headless: true, executablePath });
    const context = await browser.newContext({ viewport: { width: 1280, height: 720 } });
    const page = await context.newPage();

    const consoleErrors = [];
    page.on('console', msg => {
        if (msg.type() === 'error') {
            consoleErrors.push(msg.text());
        }
    });
    page.on('pageerror', err => consoleErrors.push(`pageerror: ${err.message}`));

    let failed = false;
    let failReason = '';

    try {
        if (scenarioName === 'wasm-spa') {
            await runWasmSpa(page, baseUrl);
        } else {
            await runScenario(page, baseUrl, scenarioName);
        }
    } catch (err) {
        failed = true;
        failReason = err.message;
    }

    // Check for browser-side panics / WASM traps in the console
    const panicLines = consoleErrors.filter(looksLikePanic);
    if (panicLines.length > 0 && !failed) {
        failed = true;
        failReason = `browser console panic/trap: ${panicLines[0]}`;
    }

    await browser.close();
    server.close();

    if (failed) {
        console.error(`FAIL ${scenarioName} — ${failReason}`);
        if (consoleErrors.length > 0) {
            console.error('console errors:', consoleErrors.slice(0, 10).join('\n'));
        }
        process.exit(1);
    }

    console.log(`PASS ${scenarioName}`);
    process.exit(0);
}

main().catch(err => {
    console.error('wasm-verify unexpected error:', err);
    process.exit(1);
});

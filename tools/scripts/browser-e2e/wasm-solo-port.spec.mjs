/**
 * Playwright behaviour spec for the wasm-solo-clipboard example: the port
 * round-trip in the browser wasm bundle, with no server behind the page.
 *
 *   1. Round-trip — the bundle's shell loads the SRI-pinned port glue before
 *      the wasm boots; "Copy" writes through the page's clipboard sink and
 *      "Paste" renders the read as "clipboard: <text>".
 *   2. Refusal — the glue is withheld (absent, or tampered so its integrity
 *      pin refuses it): no page host exists, so "Paste" renders the typed
 *      error well before the request deadline, never a wait.
 *
 * The page is served from the built `www/` directory by request interception,
 * so the browser applies the shell's CSP and the glue's integrity pin exactly
 * as on a static host.
 *
 * Prerequisites (satisfied by the CI `browser-e2e` job setup):
 *   - IPE_WASM_SOLO_WWW env var naming the built bundle's `www/` directory
 *   - Playwright and Chromium installed
 *
 * Run locally after building:
 *   bash tools/scripts/browser-e2e/run.sh
 */

import { test, expect } from "@playwright/test";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ARTIFACTS = path.join(__dirname, "artifacts");
fs.mkdirSync(ARTIFACTS, { recursive: true });

// Fail closed: without the bundle directory there is nothing to serve.
const WWW = process.env.IPE_WASM_SOLO_WWW;
if (!WWW || !fs.existsSync(path.join(WWW, "index.html"))) {
  throw new Error(
    `IPE_WASM_SOLO_WWW must name a built wasm bundle www/ directory (got '${WWW ?? ""}')`,
  );
}
const ROOT = path.resolve(WWW);
const ORIGIN = "http://127.0.0.1:18090";
const COPIED = "ipe-wasm-solo";
// Well under the runtime's request deadline: a refusal that waited it out
// fails this bound.
const REFUSAL_BOUND_MS = 5000;

const CONTENT_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".wasm": "application/wasm",
  ".css": "text/css; charset=utf-8",
};

/** The bundle file a request path names, or `null` outside the bundle. */
function bundleFile(urlPath) {
  const rel = urlPath === "/" ? "index.html" : decodeURIComponent(urlPath).replace(/^\/+/, "");
  const file = path.resolve(ROOT, rel);
  if (!file.startsWith(ROOT + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
    return null;
  }
  return file;
}

/** Whether `urlPath` is the content-addressed port glue the shell loads. */
function isGlue(urlPath) {
  return /^\/_ipe\/port\.[0-9a-f]+\.js$/.test(urlPath);
}

/**
 * A fresh context serving the bundle at ORIGIN. `glue` is "serve", "absent"
 * or "tampered".
 */
async function bundleContext(browser, glue) {
  const ctx = await browser.newContext();
  await ctx.grantPermissions(["clipboard-read", "clipboard-write"], { origin: ORIGIN });
  const glueRequests = [];
  await ctx.route(`${ORIGIN}/**`, async (route) => {
    const urlPath = new URL(route.request().url()).pathname;
    const file = bundleFile(urlPath);
    if (file === null) {
      await route.fulfill({ status: 404, body: "not found" });
      return;
    }
    const contentType = CONTENT_TYPES[path.extname(file)] ?? "application/octet-stream";
    if (isGlue(urlPath)) {
      glueRequests.push(urlPath);
      if (glue === "absent") {
        await route.fulfill({ status: 404, body: "not found" });
        return;
      }
      if (glue === "tampered") {
        const body = fs.readFileSync(file, "utf8") + "\n;";
        await route.fulfill({ status: 200, contentType, body });
        return;
      }
    }
    await route.fulfill({ status: 200, contentType, body: fs.readFileSync(file) });
  });
  return { ctx, glueRequests };
}

/** Block until the wasm app has booted and rendered its view. */
async function waitBooted(page) {
  await expect(page.getByRole("button", { name: "Paste" })).toBeVisible({ timeout: 15000 });
}

test("wasm solo: the pinned glue carries a clipboard round-trip", async ({ browser }) => {
  const { ctx, glueRequests } = await bundleContext(browser, "serve");
  const page = await ctx.newPage();
  const refused = [];
  page.on("console", (msg) => {
    if (/integrity|Content Security Policy/i.test(msg.text())) refused.push(msg.text());
  });
  await page.goto(ORIGIN + "/");
  await waitBooted(page);

  expect(glueRequests.length, "the shell must request the port glue").toBe(1);
  expect(await page.evaluate(() => typeof window.ipeOnReceive)).toBe("function");

  await page.getByRole("button", { name: "Copy" }).click();
  await expect
    .poll(async () => page.evaluate(() => navigator.clipboard.readText()), { timeout: 5000 })
    .toBe(COPIED);

  await page.getByRole("button", { name: "Paste" }).click();
  await expect(page.getByText(`clipboard: ${COPIED}`)).toBeVisible({ timeout: 5000 });
  expect(refused, "no integrity or CSP refusal on the shipped bundle").toEqual([]);

  await page.screenshot({ path: path.join(ARTIFACTS, "wasm-solo-roundtrip.png") });
  await ctx.close();
});

for (const glue of ["absent", "tampered"]) {
  test(`wasm solo: a ${glue} glue refuses the request at once`, async ({ browser }) => {
    const { ctx, glueRequests } = await bundleContext(browser, glue);
    const page = await ctx.newPage();
    await page.goto(ORIGIN + "/");
    await waitBooted(page);

    expect(glueRequests.length, "the shell must request the port glue").toBe(1);
    expect(await page.evaluate(() => typeof window.ipeOnReceive)).toBe("undefined");

    const started = Date.now();
    await page.getByRole("button", { name: "Paste" }).click();
    await expect(page.getByText(/clipboard: error:/)).toBeVisible({ timeout: REFUSAL_BOUND_MS });
    expect(Date.now() - started).toBeLessThan(REFUSAL_BOUND_MS);

    await page.screenshot({ path: path.join(ARTIFACTS, `wasm-solo-${glue}-glue.png`) });
    await ctx.close();
  });
}

/**
 * Playwright behaviour spec for the page-navigation example: a routed app's
 * browser URL follows the page its committed model shows.
 *
 *   1. Served (`web`):
 *      - a button's `update` that changes the page is one new history entry
 *        at the page's route, and a reload lands on that page;
 *      - a subscription that changes the page rewrites the current entry, so
 *        the history does not grow;
 *      - Back and Forward restore the page each entry names;
 *      - a deep link enters its page through the route table;
 *      - an element a page script plants with a `data-ipe-path` attribute
 *        names no location: the URL follows the committed page only.
 *   2. Browser bundle (`web client`): the same button's `update` is one new
 *      history entry at the page's route, and Back restores the page before.
 *
 * Prerequisites (satisfied by the CI `browser-e2e` job setup):
 *   - the page-navigation server listening on IPE_PAGE_NAVIGATION_PORT
 *   - IPE_PAGE_NAVIGATION_WWW naming its built `web client` bundle's `www/`
 *   - Playwright and Chromium installed
 *
 * Run locally after building:
 *   bash tools/scripts/browser-e2e/run.sh
 */

import { test, expect } from "@playwright/test";
import path from "path";
import fs from "fs";

const PORT = process.env.IPE_PAGE_NAVIGATION_PORT ?? "18086";
const BASE = `http://127.0.0.1:${PORT}`;

// Fail closed: without the bundle directory there is nothing to serve.
const WWW = process.env.IPE_PAGE_NAVIGATION_WWW;
if (!WWW || !fs.existsSync(path.join(WWW, "index.html"))) {
  throw new Error(
    `IPE_PAGE_NAVIGATION_WWW must name a built wasm bundle www/ directory (got '${WWW ?? ""}')`,
  );
}
const ROOT = path.resolve(WWW);
const CLIENT = "http://127.0.0.1:18091";

const CONTENT_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".wasm": "application/wasm",
  ".css": "text/css; charset=utf-8",
};

/** Open `route` on the served app and wait until its live channel is up. */
async function openLive(page, route = "/") {
  await page.goto(`${BASE}${route}`);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
}

/** The text of the page heading. */
function heading(page) {
  return page.locator("#page");
}

test("served: a button's page change is one history entry, and a reload lands on it", async ({
  page,
}) => {
  await openLive(page);
  await expect(heading(page)).toHaveText("home");
  const before = await page.evaluate(() => history.length);
  await page.locator("#open-entry").click();
  await expect(heading(page)).toHaveText("entry 1", { timeout: 10000 });
  await expect(page).toHaveURL(`${BASE}/entry/1`);
  expect(await page.evaluate(() => history.length)).toBe(before + 1);
  await page.reload();
  await expect(heading(page)).toHaveText("entry 1", { timeout: 10000 });
  await expect(page).toHaveURL(`${BASE}/entry/1`);
});

test("served: a subscription's page change rewrites the current entry", async ({ page }) => {
  await openLive(page);
  const before = await page.evaluate(() => history.length);
  await page.locator("#leave-soon").click();
  await expect(heading(page)).toHaveText("about", { timeout: 10000 });
  await expect(page).toHaveURL(`${BASE}/about`);
  expect(await page.evaluate(() => history.length)).toBe(before);
});

test("served: Back and Forward restore the page each entry names", async ({ page }) => {
  await openLive(page);
  await page.locator("#open-entry").click();
  await expect(page).toHaveURL(`${BASE}/entry/1`, { timeout: 10000 });
  await page.locator("#open-home").click();
  await expect(page).toHaveURL(`${BASE}/`, { timeout: 10000 });
  await expect(heading(page)).toHaveText("home");
  await page.goBack();
  await expect(heading(page)).toHaveText("entry 1", { timeout: 10000 });
  await expect(page).toHaveURL(`${BASE}/entry/1`);
  await page.goForward();
  await expect(heading(page)).toHaveText("home", { timeout: 10000 });
  await expect(page).toHaveURL(`${BASE}/`);
});

test("served: a deep link enters its page", async ({ page }) => {
  await openLive(page, "/entry/7");
  await expect(heading(page)).toHaveText("entry 7");
  await expect(page).toHaveURL(`${BASE}/entry/7`);
});

test("served: a planted data-ipe-path names no location", async ({ page }) => {
  await openLive(page);
  const before = await page.evaluate(() => history.length);
  await page.evaluate(() => {
    const planted = document.createElement("div");
    planted.id = "e2e-planted";
    planted.setAttribute("data-ipe-path", "/planted");
    document.body.appendChild(planted);
  });
  await page.locator("#open-entry").click();
  await expect(heading(page)).toHaveText("entry 1", { timeout: 10000 });
  await expect(page).toHaveURL(`${BASE}/entry/1`);
  expect(await page.evaluate(() => history.length)).toBe(before + 1);
  await page.locator("#open-home").click();
  await expect(page).toHaveURL(`${BASE}/`, { timeout: 10000 });
  expect(await page.evaluate(() => history.length)).toBe(before + 2);
});

/**
 * The bundle file a request path names: a file under the bundle, or the shell
 * for any other path, as a static host serving a routed app answers a deep
 * link. `null` for a path outside the bundle.
 */
function bundleFile(urlPath) {
  const rel = decodeURIComponent(urlPath).replace(/^\/+/, "");
  const file = path.resolve(ROOT, rel);
  if (!file.startsWith(ROOT + path.sep) && file !== ROOT) return null;
  if (fs.existsSync(file) && fs.statSync(file).isFile()) return file;
  return path.extname(rel) === "" ? path.join(ROOT, "index.html") : null;
}

test("web client: a button's page change is one history entry, and Back restores the page", async ({
  browser,
}) => {
  const ctx = await browser.newContext();
  await ctx.route(`${CLIENT}/**`, async (route) => {
    const file = bundleFile(new URL(route.request().url()).pathname);
    if (file === null) {
      await route.fulfill({ status: 404, body: "not found" });
      return;
    }
    const contentType = CONTENT_TYPES[path.extname(file)] ?? "application/octet-stream";
    await route.fulfill({ status: 200, contentType, body: fs.readFileSync(file) });
  });
  const page = await ctx.newPage();
  try {
    await page.goto(`${CLIENT}/`);
    await expect(heading(page)).toHaveText("home", { timeout: 15000 });
    const before = await page.evaluate(() => history.length);
    await page.locator("#open-entry").click();
    await expect(heading(page)).toHaveText("entry 1", { timeout: 10000 });
    await expect(page).toHaveURL(`${CLIENT}/entry/1`);
    expect(await page.evaluate(() => history.length)).toBe(before + 1);
    await page.goBack();
    await expect(heading(page)).toHaveText("home", { timeout: 10000 });
    await expect(page).toHaveURL(`${CLIENT}/`);
    await page.locator("#leave-soon").click();
    await expect(heading(page)).toHaveText("about", { timeout: 10000 });
    await expect(page).toHaveURL(`${CLIENT}/about`);
  } finally {
    await ctx.close();
  }
});

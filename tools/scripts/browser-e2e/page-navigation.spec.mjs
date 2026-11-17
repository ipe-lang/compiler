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
 *        names no location: the URL follows the committed page only;
 *      - a `Web.pageLink` click moves to its page in place, as one history
 *        entry, and `aria-current` follows the page on screen;
 *      - a page link a patch inserts is followed in place too;
 *      - a page link with `target="_blank"` or `download` is the browser's.
 *   2. Browser bundle (`web client`): the same button's `update` is one new
 *      history entry at the page's route, and Back restores the page before;
 *      a page-link click, and one on a link a patch inserts, moves in place as
 *      one history entry.
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

test("served: a page-link click moves in place, and aria-current follows the page", async ({
  page,
}) => {
  await openLive(page);
  await expect(page.locator("#link-home")).toHaveAttribute("aria-current", "page");
  await expect(page.locator("#link-entry")).not.toHaveAttribute("aria-current", /.*/);
  const before = await page.evaluate(() => history.length);
  // A full load would drop this marker; an in-place move keeps it.
  await page.evaluate(() => {
    window.__e2eSameDocument = true;
  });
  await page.locator("#link-entry").click();
  await expect(heading(page)).toHaveText("entry 2", { timeout: 10000 });
  await expect(page).toHaveURL(`${BASE}/entry/2`);
  expect(await page.evaluate(() => history.length)).toBe(before + 1);
  expect(await page.evaluate(() => window.__e2eSameDocument === true)).toBe(true);
  await expect(page.locator("#link-entry")).toHaveAttribute("aria-current", "page");
  await expect(page.locator("#link-home")).not.toHaveAttribute("aria-current", /.*/);
});

test("served: a page link a patch inserts moves in place", async ({ page }) => {
  await openLive(page);
  await expect(page.locator("#link-about")).toHaveCount(0);
  await page.locator("#open-entry").click();
  await expect(heading(page)).toHaveText("entry 1", { timeout: 10000 });
  const before = await page.evaluate(() => history.length);
  await page.evaluate(() => {
    window.__e2eSameDocument = true;
  });
  await page.locator("#link-about").click();
  await expect(heading(page)).toHaveText("about", { timeout: 10000 });
  await expect(page).toHaveURL(`${BASE}/about`);
  expect(await page.evaluate(() => history.length)).toBe(before + 1);
  expect(await page.evaluate(() => window.__e2eSameDocument === true)).toBe(true);
});

test("served: a new-tab or download page link is the browser's", async ({ page, context }) => {
  await openLive(page);
  const before = await page.evaluate(() => history.length);
  const [opened] = await Promise.all([
    context.waitForEvent("page"),
    page.locator("#link-about-tab").click(),
  ]);
  await opened.close();
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.locator("#link-about-download").click(),
  ]);
  await download.cancel();
  await expect(heading(page)).toHaveText("home");
  await expect(page).toHaveURL(`${BASE}/`);
  expect(await page.evaluate(() => history.length)).toBe(before);
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

    // A page-link click moves in place as one entry; so does one on a link
    // the patch that shows the entry inserts.
    await page.evaluate(() => {
      window.__e2eSameDocument = true;
    });
    const atLinks = await page.evaluate(() => history.length);
    await page.locator("#link-entry").click();
    await expect(heading(page)).toHaveText("entry 2", { timeout: 10000 });
    await expect(page).toHaveURL(`${CLIENT}/entry/2`);
    await expect(page.locator("#link-entry")).toHaveAttribute("aria-current", "page");
    expect(await page.evaluate(() => history.length)).toBe(atLinks + 1);
    await page.locator("#link-about").click();
    await expect(heading(page)).toHaveText("about", { timeout: 10000 });
    await expect(page).toHaveURL(`${CLIENT}/about`);
    expect(await page.evaluate(() => history.length)).toBe(atLinks + 2);
    expect(await page.evaluate(() => window.__e2eSameDocument === true)).toBe(true);
  } finally {
    await ctx.close();
  }
});

/**
 * Playwright worker-gate spec on the geo-clipboard app.
 *
 * Proves, in a real browser, that only the runtime's own worker script can be
 * installed on an Ipê origin:
 *
 *   1. Registering the app's own `client.js`, a same-origin script the server
 *      answers with a JavaScript type, rejects: the worker gate refuses the
 *      browser's `Service-Worker: script` fetch. A plain fetch of the same
 *      script still answers 200, so the refusal is the gate, not a dead route.
 *   2. Registering `/static/sw.js` rejects.
 *   3. Registering the runtime's worker route `/ipe-sw.js` resolves, and the
 *      retire body then unregisters the worker: no registration is left.
 *
 * Prerequisites and local run: see geo-clipboard.spec.mjs.
 */

import { test, expect } from "@playwright/test";

const PORT = process.env.IPE_GEO_CLIPBOARD_PORT ?? "18080";
const BASE = `http://127.0.0.1:${PORT}`;

/** Open the app page in a fresh context and wait for it to go live. */
async function openApp(browser) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto(BASE);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  return { ctx, page };
}

/** Register `url` as a worker; resolve to "registered" or the rejection's name. */
function register(page, url) {
  return page.evaluate(async (scriptUrl) => {
    try {
      await navigator.serviceWorker.register(scriptUrl);
      return "registered";
    } catch (err) {
      return `rejected:${err?.name ?? "unknown"}`;
    }
  }, url);
}

test("a same-origin script the runtime serves is never installed as a worker", async ({ browser }) => {
  const { ctx, page } = await openApp(browser);
  try {
    const src = await page.evaluate(
      () => document.querySelector('script[src*="/_ipe/client."]')?.getAttribute("src") ?? null,
    );
    expect(src, "the page loads the runtime client script").not.toBeNull();
    const plain = await page.evaluate(async (url) => {
      const resp = await fetch(url);
      return { status: resp.status, type: resp.headers.get("content-type") ?? "" };
    }, src);
    expect(plain.status).toBe(200);
    expect(plain.type).toContain("javascript");

    expect(await register(page, src)).toMatch(/^rejected:/);
    expect(await register(page, "/static/sw.js")).toMatch(/^rejected:/);
    const left = await page.evaluate(async () => (await navigator.serviceWorker.getRegistrations()).length);
    expect(left).toBe(0);
  } finally {
    await ctx.close();
  }
});

test("the runtime worker route installs and then retires itself", async ({ browser }) => {
  const { ctx, page } = await openApp(browser);
  try {
    expect(await register(page, "/ipe-sw.js")).toBe("registered");
    await expect
      .poll(
        () => page.evaluate(async () => (await navigator.serviceWorker.getRegistrations()).length),
        { timeout: 15000 },
      )
      .toBe(0);
  } finally {
    await ctx.close();
  }
});

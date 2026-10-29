/**
 * Playwright install-offer spec on the install-offer / install-offer-off apps.
 *
 * Proves, in a real browser, that `installable = True` produces an offer
 * Chromium itself accepts, and that `installable = False` (the default)
 * produces none of it:
 *
 *   1. install-offer (`installable = True`): the page carries both head
 *      links (`rel="manifest"`, `rel="apple-touch-icon"`); the manifest the
 *      browser itself fetches answers `application/manifest+json`; its
 *      `icons[0].src` is the exact href the touch-icon link carries, and that
 *      URL serves `image/png`; the manifest has no `theme_color` and no
 *      `orientation` key; and Chromium's own installability check
 *      (`Page.getInstallabilityErrors`) finds nothing wrong with the page.
 *   2. install-offer-off (`installable = False`, the field's default): the
 *      page has no manifest link at all, and registers no service worker.
 *
 * Prerequisites (all satisfied by the CI `browser-e2e` job setup):
 *   - IPE_INSTALL_OFFER_PORT env var with the port the install-offer binary
 *     listens on (default 18084)
 *   - IPE_INSTALL_OFFER_OFF_PORT env var with the port the install-offer-off
 *     binary listens on (default 18085)
 *   - Playwright installed  (`npm install @playwright/test`)
 *   - Chromium browser      (`npx playwright install chromium`)
 *
 * Run locally after building:
 *   bash tools/scripts/browser-e2e/run.sh
 */

import { test, expect } from "@playwright/test";

const ON_PORT = process.env.IPE_INSTALL_OFFER_PORT ?? "18084";
const OFF_PORT = process.env.IPE_INSTALL_OFFER_OFF_PORT ?? "18085";
const ON_BASE = `http://127.0.0.1:${ON_PORT}`;
const OFF_BASE = `http://127.0.0.1:${OFF_PORT}`;

/** The manifest's own content-addressed route, wherever the mount base puts it. */
const MANIFEST_PATH = /\/_ipe\/manifest\.[0-9a-f]{16}\.webmanifest$/;

test("install-offer: the manifest, the touch icon, and Chromium's own installability check all line up", async ({
  browser,
}) => {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  try {
    // Chromium fetches the manifest itself as soon as the <link rel="manifest">
    // tag parses, during navigation — so the listener must be armed before
    // `goto` resolves, or the fetch is missed entirely.
    const manifestFetch = page.waitForResponse(
      (resp) => MANIFEST_PATH.test(new URL(resp.url()).pathname) && resp.status() === 200,
    );
    await page.goto(ON_BASE);
    await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });

    const manifestHref = await page.evaluate(
      () => document.querySelector('link[rel="manifest"]')?.getAttribute("href") ?? null,
    );
    const touchIconHref = await page.evaluate(
      () => document.querySelector('link[rel="apple-touch-icon"]')?.getAttribute("href") ?? null,
    );
    expect(manifestHref, "the page links a manifest").not.toBeNull();
    expect(touchIconHref, "the page links a touch icon").not.toBeNull();

    // Wait for the browser's own manifest fetch before asking Chromium for its
    // installability verdict: the verdict is only meaningful once the manifest
    // it depends on has actually loaded.
    const manifestResponse = await manifestFetch;
    expect(manifestResponse.headers()["content-type"]).toBe("application/manifest+json");
    const manifest = await manifestResponse.json();
    expect(manifest.icons[0].src).toBe(touchIconHref);
    expect(Object.hasOwn(manifest, "theme_color"), "no theme_color key").toBe(false);
    expect(Object.hasOwn(manifest, "orientation"), "no orientation key").toBe(false);

    const iconUrl = new URL(touchIconHref, ON_BASE).toString();
    const iconResponse = await page.request.get(iconUrl);
    expect(iconResponse.status()).toBe(200);
    expect(iconResponse.headers()["content-type"]).toBe("image/png");

    const cdp = await page.context().newCDPSession(page);
    await cdp.send("Page.enable");
    const { installabilityErrors } = await cdp.send("Page.getInstallabilityErrors");
    expect(installabilityErrors).toEqual([]);
  } finally {
    await ctx.close();
  }
});

test("install-offer-off: no manifest link and no service-worker registration", async ({ browser }) => {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  try {
    await page.goto(OFF_BASE);
    await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });

    const hasManifestLink = await page.evaluate(
      () => document.querySelector('link[rel="manifest"]') !== null,
    );
    expect(hasManifestLink, "installable = False links no manifest").toBe(false);

    const registrations = await page.evaluate(() => navigator.serviceWorker.getRegistrations());
    expect(registrations, "installable = False registers no worker").toEqual([]);
  } finally {
    await ctx.close();
  }
});

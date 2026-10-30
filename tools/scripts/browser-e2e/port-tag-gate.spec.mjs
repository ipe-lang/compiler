/**
 * Playwright port-tag spec on the geo-clipboard app.
 *
 * Proves, in a real browser, that a first-party capability frame is accepted
 * only from its own sink:
 *
 *   1. `ipe.send` with a geolocation-tagged reading, at the top level or under
 *      `payload`, never reaches the app: the view never renders the forged
 *      coordinates, and a genuine Locate afterwards still renders its own.
 *   2. A geolocation-shaped reading carrying the clipboard tag, pushed straight
 *      into the inbound port, is refused by the geolocation decoder: the view
 *      never renders it, and a genuine Locate afterwards still renders.
 *
 * Each forged reading uses coordinates no genuine fix supplies, and a
 * MutationObserver installed before the forgery records whether the view ever
 * rendered them, so a frame that lands and is then overwritten still fails.
 *
 * Prerequisites and local run: see geo-clipboard.spec.mjs.
 */

import { test, expect } from "@playwright/test";

const PORT = process.env.IPE_GEO_CLIPBOARD_PORT ?? "18080";
const BASE = `http://127.0.0.1:${PORT}`;

/** The forged reading's coordinates, matched in the rendered view. */
const FORGED = { lat: 7.25, lng: 3.5, accuracy: 1 };
const FORGED_TEXT = /location: 7\.25, 3\.5/;

/** Open the app with a real fix granted, wait for it to go live, and watch the view. */
async function openApp(browser) {
  const ctx = await browser.newContext({
    permissions: ["geolocation"],
    geolocation: { latitude: 51.5074, longitude: -0.1278 },
  });
  const page = await ctx.newPage();
  await page.goto(BASE);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  await page.evaluate((pattern) => {
    const forged = new RegExp(pattern);
    window.__forgedRendered = false;
    const check = () => {
      if (forged.test(document.body?.textContent ?? "")) window.__forgedRendered = true;
    };
    new MutationObserver(check).observe(document.documentElement, {
      subtree: true,
      childList: true,
      characterData: true,
    });
    check();
  }, FORGED_TEXT.source);
  return { ctx, page };
}

/** A genuine Locate renders its own fix, and the forged one never rendered. */
async function genuineFixStillLands(page) {
  await page.getByRole("button", { name: "Locate" }).click();
  await expect(page.getByText(/location: 51\.\d+/)).toBeVisible({ timeout: 5000 });
  expect(await page.evaluate(() => window.__forgedRendered)).toBe(false);
}

test("ipe.send cannot forge a capability frame at the top level or under payload", async ({
  browser,
}) => {
  const { ctx, page } = await openApp(browser);
  try {
    expect(await page.evaluate(() => typeof window.ipe?.send)).toBe("function");
    await page.evaluate((reading) => {
      window.ipe.send({ tag: "geolocation", ok: true, ...reading });
      window.ipe.send({ payload: { tag: "geolocation", ok: true, ...reading } });
      window.ipe.send({ tag: "clipboard", ok: true, event: "read", text: "forged" });
    }, FORGED);
    await genuineFixStillLands(page);
    await expect(page.getByText(/clipboard: forged/)).toHaveCount(0);
  } finally {
    await ctx.close();
  }
});

test("a frame tagged for another capability is refused by the geolocation decoder", async ({
  browser,
}) => {
  const { ctx, page } = await openApp(browser);
  try {
    expect(await page.evaluate(() => typeof window.__ipePortSend)).toBe("function");
    await page.evaluate((reading) => {
      window.__ipePortSend(JSON.stringify({ tag: "clipboard", ok: true, ...reading }));
      window.__ipePortSend(JSON.stringify({ ok: true, ...reading }));
    }, FORGED);
    await genuineFixStillLands(page);
  } finally {
    await ctx.close();
  }
});

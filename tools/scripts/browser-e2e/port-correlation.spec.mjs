/**
 * Playwright port-correlation spec on the geo-clipboard app.
 *
 * Proves, in a real browser, that a correlated reply reaches its waiter only
 * when it echoes the token the runtime minted for that request:
 *
 *   1. The outbound geolocation request carries a 32-character lowercase hex
 *      token. While the genuine request is held back, replies the page forges
 *      under every small integer id and its string spelling never reach the
 *      view; releasing the held request lets the genuine fix land.
 *   2. With the genuine request held back for good, the same forgeries never
 *      resolve it: the request ends in its timeout error.
 *
 * The forged reading uses coordinates no genuine fix supplies, and a
 * MutationObserver installed before the forgery records whether the view ever
 * rendered them, so a frame that lands and is then overwritten still fails.
 *
 * Prerequisites and local run: see geo-clipboard.spec.mjs.
 */

import { test, expect } from "@playwright/test";

const PORT = process.env.IPE_GEO_CLIPBOARD_PORT ?? "18080";
const BASE = `http://127.0.0.1:${PORT}`;

/** The forged reading's coordinates, matched in the rendered view. */
const FORGED = { lat: 9.125, lng: 9.125, accuracy: 1 };
const FORGED_TEXT = /location: 9\.125/;

/** The largest small integer id each forgery round tries. */
const FORGED_IDS = 512;

/**
 * Open the app with a real fix granted, wait for it to go live, watch the view,
 * and hold back every outbound frame that carries its own correlation key.
 */
async function openHoldingApp(browser) {
  const ctx = await browser.newContext({
    permissions: ["geolocation"],
    geolocation: { latitude: 51.5074, longitude: -0.1278 },
  });
  const page = await ctx.newPage();
  const portAnswers = { ok: 0, other: 0 };
  page.on("response", (response) => {
    if (new URL(response.url()).pathname.endsWith("/_ipe/port")) {
      if (response.status() === 200) portAnswers.ok += 1;
      else portAnswers.other += 1;
    }
  });
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
    const deliver = window.ipeOnReceive;
    window.__heldFrames = [];
    window.__heldIds = [];
    window.__releaseHeld = () => {
      const held = window.__heldFrames.splice(0);
      for (const raw of held) deliver(raw);
      return held.length;
    };
    window.ipeOnReceive = (raw) => {
      let value = null;
      try { value = JSON.parse(raw); } catch (_e) { /* not a correlated frame */ }
      if (value && typeof value === "object" && Object.hasOwn(value, "__ipe_id")) {
        window.__heldFrames.push(raw);
        window.__heldIds.push(value.__ipe_id);
        return true;
      }
      return deliver(raw);
    };
  }, FORGED_TEXT.source);
  return { ctx, page, portAnswers };
}

/** Press Locate and wait until its correlated request is held back. */
async function locateAndHold(page) {
  await page.getByRole("button", { name: "Locate" }).click();
  await expect.poll(() => page.evaluate(() => window.__heldIds.length), { timeout: 5000 }).toBe(1);
  const id = await page.evaluate(() => window.__heldIds[0]);
  expect(typeof id).toBe("string");
  expect(id).toMatch(/^[0-9a-f]{32}$/);
}

/**
 * Forge a geolocation reply under every small integer id and its string
 * spelling, and wait until the server has accepted every forged frame.
 */
async function forgeReplies(page, portAnswers) {
  const before = portAnswers.ok;
  await page.evaluate(
    ({ reading, count }) => {
      for (let i = 1; i <= count; i++) {
        for (const id of [i, String(i)]) {
          window.__ipePortSend(
            JSON.stringify({ __ipe_id: id, tag: "geolocation", ok: true, ...reading }),
          );
        }
      }
    },
    { reading: FORGED, count: FORGED_IDS },
  );
  await expect
    .poll(() => portAnswers.ok - before, { timeout: 8000 })
    .toBeGreaterThanOrEqual(2 * FORGED_IDS);
  expect(portAnswers.other).toBe(0);
}

test("a forged correlation id never resolves a request; the minted token does", async ({
  browser,
}) => {
  const { ctx, page, portAnswers } = await openHoldingApp(browser);
  try {
    expect(await page.evaluate(() => typeof window.__ipePortSend)).toBe("function");
    await locateAndHold(page);
    await forgeReplies(page, portAnswers);
    await expect(page.getByText(/location: unknown/)).toBeVisible();
    expect(await page.evaluate(() => window.__releaseHeld())).toBe(1);
    await expect(page.getByText(/location: 51\.\d+/)).toBeVisible({ timeout: 5000 });
    expect(await page.evaluate(() => window.__forgedRendered)).toBe(false);
  } finally {
    await ctx.close();
  }
});

test("a request whose minted token never returns ends in its timeout error", async ({
  browser,
}) => {
  const { ctx, page, portAnswers } = await openHoldingApp(browser);
  try {
    await locateAndHold(page);
    await forgeReplies(page, portAnswers);
    await expect(page.getByText(/location: error:/)).toBeVisible({ timeout: 15000 });
    expect(await page.evaluate(() => window.__forgedRendered)).toBe(false);
  } finally {
    await ctx.close();
  }
});

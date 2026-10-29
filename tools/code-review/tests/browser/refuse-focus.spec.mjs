/**
 * Playwright spec: the refuse panel's reason field takes focus when `r` opens
 * it, and `Escape` hands focus back to the page so the shortcuts work again,
 * for every later key and not only the first.
 *
 * Local only, never run by CI: it needs a running review server over a real
 * index whose queue holds at least three units, with `IPE_REVIEW_MAC_KEY` set so
 * the server is not read-only. From `tools/code-review`:
 *
 *   IPE_INDEX_DB=../../.ipe-index/index.db IPE_INDEX_ROOT=../.. \
 *     IPE_REVIEW_MAC_KEY=<64 hex> IPE_REVIEW_DB=/tmp/review.db ipe dev run
 *   IPE_CODE_REVIEW_URL=http://127.0.0.1:8000 npx playwright test tests/browser
 */

import { test, expect } from "@playwright/test";

const BASE = process.env.IPE_CODE_REVIEW_URL ?? "http://127.0.0.1:8000";

/** Whether focus is on the page root, which handles every key. */
const rootFocused = (page) =>
  page.evaluate(() => {
    const el = document.activeElement;
    return !!el && el.getAttribute("lang") === "en" && el.getAttribute("tabindex") === "0";
  });

/** The rail's border colours: the selected card's, then every other card's. */
const RAIL_BORDERS = ["rgb(130, 170, 240)", "rgb(40, 40, 52)"];

/** The index of the selected card in the queue rail, -1 when none is drawn. */
const selectedRow = (page) =>
  page.evaluate((borders) => {
    const rail = [...document.querySelectorAll("main button")].filter((el) =>
      borders.includes(getComputedStyle(el).borderTopColor),
    );
    return rail.findIndex((el) => getComputedStyle(el).borderTopColor === borders[0]);
  }, RAIL_BORDERS);

test("code-review: r focuses the refuse reason, Escape returns focus to the page", async ({ page }) => {
  await page.goto(BASE);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  await expect.poll(() => rootFocused(page)).toBe(true);

  await page.keyboard.press("r");
  const reason = page.getByPlaceholder("Why refuse?");
  await expect(reason).toHaveCount(1);
  await expect(reason).toBeFocused();
  await page.keyboard.type("abc");
  await expect(reason).toHaveValue("abc");

  await page.keyboard.press("Escape");
  await expect(reason).toHaveCount(0);
  await expect.poll(() => rootFocused(page)).toBe(true);

  const main = page.locator("main");
  const before = await main.textContent();
  await page.keyboard.press("j");
  await expect.poll(() => main.textContent()).not.toBe(before);
});

test("code-review: after r and Escape on the first unit, two j presses move two rows", async ({ page }) => {
  await page.goto(BASE);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  await expect.poll(() => rootFocused(page)).toBe(true);
  await expect.poll(() => selectedRow(page)).toBe(0);

  await page.keyboard.press("r");
  const reason = page.getByPlaceholder("Why refuse?");
  await expect(reason).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(reason).toHaveCount(0);

  await page.keyboard.press("j");
  await expect.poll(() => selectedRow(page)).toBe(1);
  await page.keyboard.press("j");
  await expect.poll(() => selectedRow(page)).toBe(2);
  expect(await rootFocused(page)).toBe(true);
});

/**
 * Playwright spec: the refuse panel's reason field takes focus when `r` opens
 * it, and `Escape` hands focus back to the page so the shortcuts work again.
 *
 * Local only, never run by CI: it needs a running review server over a real
 * index whose queue holds at least two units, with `IPE_REVIEW_MAC_KEY` set so
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

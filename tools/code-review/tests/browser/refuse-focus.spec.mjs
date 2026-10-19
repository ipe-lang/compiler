// Refuse panel focus: `r` opens the refuse panel and its reason field takes
// focus, so the reason is typed at once; `Escape` closes the panel and focus
// returns to the root, so the next shortcut reaches its handler.
//
// Local only: run against the app served from `tools/code-review`, with a
// queue of at least two units and a review key set:
//
//   IPE_INDEX_DB=../../.ipe-index/index.db IPE_INDEX_ROOT=../.. \
//     IPE_REVIEW_MAC_KEY=<key> ipe dev run
//   REVIEW_BASE=http://127.0.0.1:8000 \
//     npx playwright test tools/code-review/tests/browser/refuse-focus.spec.mjs

import { test, expect } from "@playwright/test";

const BASE = process.env.REVIEW_BASE ?? "http://127.0.0.1:8000";

/** The root: the page's one `tabindex="0"` element holding the main region. */
function rootFocused(page) {
  return page.evaluate(() => {
    const el = document.activeElement;
    return el !== null && el.getAttribute("tabindex") === "0" && el.querySelector("main, [role=main]") !== null;
  });
}

/** The selected unit's heading text. */
function selectedHeading(page) {
  return page.locator("h2").first().innerText();
}

test("refuse panel: the reason field takes focus, Escape returns it to the root", async ({ page }) => {
  await page.goto(BASE);
  await page.locator('html[data-ipe-live="1"]').waitFor();
  await page.locator("h1").click();
  await expect.poll(() => rootFocused(page)).toBe(true);
  const before = await selectedHeading(page);

  await page.keyboard.press("r");
  const reason = page.getByLabel("Reason");
  await expect(reason).toBeFocused();
  await page.keyboard.type("abc");
  await expect(reason).toHaveValue("abc");

  await page.keyboard.press("Escape");
  await expect(reason).toHaveCount(0);
  await expect.poll(() => rootFocused(page)).toBe(true);

  await page.keyboard.press("j");
  await expect.poll(() => selectedHeading(page)).not.toBe(before);
});

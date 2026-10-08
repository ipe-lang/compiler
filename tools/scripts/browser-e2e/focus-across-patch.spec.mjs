/**
 * Playwright refusal spec: a patch never moves keyboard focus.
 *
 * The client rewrites the children of the container a patch targets. A focused
 * node inside it is dropped by that rewrite, and focus falls to `body`, where
 * a key handler bound on an ancestor no longer receives keys. The client
 * records the focused node's position, puts focus back on the node at that
 * position once the swap lands, else on its nearest focusable ancestor, and
 * never reads or writes focus that sits outside the swapped container.
 *
 * Every test drives a real pointer click and a real key press; none sets focus
 * from the page. A key reaches the root's handler only while focus is below
 * the root, so a `keys: j` line proves focus survived the patch.
 *
 * Runs against the focus-across-patch example. Prerequisites and local run:
 * see geo-clipboard.spec.mjs.
 */

import { test, expect } from "@playwright/test";

const PORT = process.env.IPE_FOCUS_ACROSS_PATCH_PORT ?? "18082";
const BASE = `http://127.0.0.1:${PORT}`;

/** The id of the focused element, "" when focus is on `body`. */
const focusedId = (page) => page.evaluate(() => document.activeElement?.id ?? "");

async function open(page) {
  await page.goto(BASE);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
}

test("focus-across-patch: first mount focuses autofocus root", async ({ page }) => {
  await open(page);
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

test("focus-across-patch: button click keeps keys alive", async ({ page }) => {
  await open(page);
  await page.click("#add");
  // The panel gained a row: its children were swapped around the button.
  await expect(page.locator("#row")).toHaveCount(1);
  await expect.poll(() => focusedId(page)).toBe("add");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

test("focus-across-patch: removed focused node falls back to ancestor", async ({ page }) => {
  await open(page);
  await page.click("#drop");
  // The clicked button is gone from the swapped panel.
  await expect(page.locator("#drop")).toHaveCount(0);
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

test("focus-across-patch: typing survives patch", async ({ page }) => {
  await open(page);
  const field = page.locator("#ipe-root input");
  await field.click();
  await page.keyboard.type("hello");
  // Let the debounced input event settle before the patch under test.
  await page.waitForTimeout(500);
  await page.keyboard.press("ArrowLeft");
  await page.keyboard.press("ArrowLeft");
  // Escape toggles the panel's row, which swaps the panel around the field.
  await page.keyboard.press("Escape");
  await expect(page.locator("#row")).toHaveCount(1);
  await expect(field).toBeFocused();
  await expect(field).toHaveValue("hello");
  expect(await field.evaluate((el) => [el.selectionStart, el.selectionEnd])).toEqual([3, 3]);
  // Typing continues at the caret in the same node.
  await page.keyboard.type("X");
  await expect(field).toHaveValue("helXlo");
});

test("focus-across-patch: no focus theft into body-level", async ({ page }) => {
  await open(page);
  await page.evaluate(() => {
    document.body.insertAdjacentHTML("beforeend", '<input id="outside" aria-label="outside">');
    // A pressed button takes focus; this one does not, so the click below
    // patches the tree while focus stays on the outside field.
    document.getElementById("add").addEventListener("mousedown", (e) => e.preventDefault());
  });
  await page.click("#outside");
  expect(await focusedId(page)).toBe("outside");
  await page.click("#add");
  await expect(page.locator("#row")).toHaveCount(1);
  expect(await focusedId(page)).toBe("outside");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText(/^keys:\s*$/);
});

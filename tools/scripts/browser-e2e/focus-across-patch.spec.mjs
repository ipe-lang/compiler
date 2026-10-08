/**
 * Playwright refusal spec: a patch never moves keyboard focus.
 *
 * The client rewrites the children of the container a patch targets. A focused
 * node inside it is dropped by that rewrite, and focus falls to `body`, where
 * a key handler bound on an ancestor no longer receives keys. The client
 * records the focused node's position and the server identity (`ipe-id`) of
 * it and of each ancestor at its depth, puts focus back on the nearest node on
 * that path whose whole chain from the container carries the identities and
 * tags recorded for each depth once the swap lands, else on its nearest
 * focusable ancestor, and never reads or writes
 * focus that sits outside the swapped container.
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

/**
 * Leaves the first-mount focus to the client alone. Every server-rendered node
 * stays unfocusable until the client script tag is parsed: an observer strips
 * `tabindex` from each added element, and its callbacks run as microtasks,
 * ahead of the rendering step where Chrome focuses an `autofocus` candidate.
 * Each scripted `focus()` is recorded, since Chrome may still focus the
 * patched root natively once it is inserted; the client focuses it in the same
 * task as the insertion, before that rendering step.
 */
function clientOwnsFirstFocus() {
  const focus = HTMLElement.prototype.focus;
  window.__testFocusCalls = [];
  HTMLElement.prototype.focus = function (...args) {
    window.__testFocusCalls.push(this.id);
    return focus.apply(this, args);
  };
  const client = /\/_ipe\/client\.[0-9a-f]+\.js$/;
  const observer = new MutationObserver((records) => {
    for (const record of records) {
      for (const node of record.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        if (node.tagName === "SCRIPT" && client.test(node.getAttribute("src") ?? "")) {
          observer.disconnect();
          return;
        }
        node.removeAttribute("tabindex");
        for (const inner of node.querySelectorAll("[tabindex]")) inner.removeAttribute("tabindex");
      }
    }
  });
  observer.observe(document, { childList: true, subtree: true });
}

test("focus-across-patch: first mount focuses autofocus root", async ({ page }) => {
  await page.addInitScript(clientOwnsFirstFocus);
  await open(page);
  await expect.poll(() => focusedId(page)).toBe("root");
  // The client, not the browser's own autofocus, focused the root.
  expect(await page.evaluate(() => window.__testFocusCalls)).toContain("root");
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

test("focus-across-patch: another control at the focused position never takes focus", async ({ page }) => {
  await open(page);
  await page.click("#swap");
  // The clicked button's position now holds a different focusable control.
  await expect(page.locator("#swapped")).toHaveCount(1);
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

test("focus-across-patch: typing survives patch", async ({ page }) => {
  await open(page);
  // A compound selector: matching a descendant combinator walks `parentElement`
  // from every input, including those in the shadowing form below.
  const field = page.locator("input#note");
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

test("focus-across-patch: a node whose key spells a former descendant identity never takes focus", async ({ page }) => {
  await open(page);
  await page.click("#kbutton");
  // The keyed item now has key `k_0_button`: its `ipe-id` is the one the
  // clicked button held one level lower, and it is focusable.
  await expect(page.locator("#ktail")).toHaveCount(1);
  await expect(page.locator("#kspoof")).toHaveCount(1);
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

test("focus-across-patch: a form whose controls shadow DOM members keeps its fields across a patch", async ({ page }) => {
  await open(page);
  const field = page.locator("#typed");
  // Playwright's own actionability check walks `parentElement` up from the
  // field, and the form's `parentElement` control shadows it there, so the
  // pointer is driven by coordinates instead.
  const box = await field.boundingBox();
  expect(box).not.toBeNull();
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
  await page.keyboard.type("abc");
  // Let the debounced input event settle before the patch under test.
  await page.waitForTimeout(500);
  // Escape adds the form's row, which swaps the form's children around the
  // field while the `removeChild` control shadows the form's own method.
  await page.keyboard.press("Escape");
  await expect(page.locator("#formrow")).toHaveCount(1);
  await expect(field).toBeFocused();
  await expect(field).toHaveValue("abc");
  await page.keyboard.type("X");
  await expect(field).toHaveValue("abcX");
});

test("focus-across-patch: a click inside a form whose control is named parentElement completes", async ({ page }) => {
  await open(page);
  // The click handler walks up from the target to find a link; through the
  // form, `parentElement` is the `parentElement` control.
  await page.click("#formlabel");
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

test("focus-across-patch: a node whose own id matches under a different chain never takes focus", async ({ page }) => {
  await open(page);
  await page.click("#xdeep");
  // The column gained a sibling: its items were swapped. `#ydeep` sits at the
  // clicked node's path with its id and tag; the item above it does not match.
  await expect(page.locator("#deeptail")).toHaveCount(1);
  await expect(page.locator("#ydeep")).toHaveCount(1);
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

test("focus-across-patch: a node with the focused id under another tag never takes focus", async ({ page }) => {
  await open(page);
  await page.click("#tbutton");
  // A `button:x` element now holds the id the `button` named `x` held.
  await expect(page.locator("#tspoof")).toHaveCount(1);
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

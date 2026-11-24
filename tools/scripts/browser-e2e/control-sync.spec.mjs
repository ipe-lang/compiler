/**
 * Playwright refusal spec: a form field shows the view's value once the user's
 * edit has landed.
 *
 * A field the view owns carries `ipe-controlled`, so an owned value that is
 * false or empty still reaches the field. The client holds a field's own value
 * only while the user's edit to it is pending; the server's accept of the event
 * that carried the edit, or the tab's own stream frame, ends that hold, so the
 * next render the field is not focused in writes the view's value.
 *
 *   1. Add — the text field the `add` click empties shows `""` once the frame
 *      lands, an attribute patch on a field whose parent keeps its children.
 *   2. Delete — deleting the ticked first row of an unkeyed list leaves the
 *      unticked row in its place with an unticked box.
 *   3. Clear — the textarea the `clear` click empties shows `""`.
 *   4. Focus — a field the user types into keeps every typed character while
 *      timer renders land.
 *   5. Settled — once the `add` click is answered, the next event carries no
 *      value for the field.
 *
 * Runs against the control-sync example (`examples/shapes/web/control-sync`).
 *
 * Prerequisites and local run: see geo-clipboard.spec.mjs; run.sh serves the
 * example on `IPE_CONTROL_SYNC_PORT`.
 */

import { test, expect } from "@playwright/test";

const PORT = process.env.IPE_CONTROL_SYNC_PORT ?? "18087";
const BASE = `http://127.0.0.1:${PORT}`;

/** Block until the SSE handshake has landed (see geo-clipboard.spec.mjs). */
async function waitReady(page) {
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
}

/** Whether `request` is an event POST. */
function isEventPost(request) {
  return request.method() === "POST" && new URL(request.url()).pathname === "/_ipe/event";
}

/** Open the app at `path` and wait for it to go live. */
async function open(page, path = "/") {
  await page.goto(`${BASE}${path}`);
  await waitReady(page);
}

/** Click the element `selector` and wait for the answer to the event it sends. */
async function clickAnswered(page, selector) {
  const answered = page.waitForResponse((r) => isEventPost(r.request()), { timeout: 10000 });
  await page.click(selector);
  expect((await answered).status()).toBe(200);
}

/** Type `text` into the draft field and add it as the row at `position`. */
async function addRow(page, text, position) {
  await page.fill("#draft", text);
  await clickAnswered(page, "#add");
  await expect(page.locator(`#text${position}`)).toHaveText(text, { timeout: 10000 });
}

test("the field an add empties shows the empty value", async ({ page }) => {
  await open(page);
  const entryChildren = await page.locator("#entry").evaluate((el) => el.childElementCount);
  await addRow(page, "buy milk", 0);
  expect(await page.locator("#entry").evaluate((el) => el.childElementCount)).toBe(entryChildren);
  await expect(page.locator("#draft")).toHaveValue("", { timeout: 10000 });
});

test("a deleted ticked row leaves the next row unticked in its place", async ({ page }) => {
  await open(page);
  await addRow(page, "first", 0);
  await addRow(page, "second", 1);
  await clickAnswered(page, "#tick0");
  await expect(page.locator("#tick0")).toBeChecked({ timeout: 10000 });

  await clickAnswered(page, "#delete0");
  await expect(page.locator("#text1")).toHaveCount(0, { timeout: 10000 });
  await expect(page.locator("#text0")).toHaveText("second");
  await expect(page.locator("#tick0")).not.toBeChecked({ timeout: 10000 });
  expect(await page.locator("#tick0").evaluate((el) => el.checked)).toBe(false);
});

test("the textarea a clear empties shows the empty value", async ({ page }) => {
  await open(page);
  await page.fill("#memo", "a note to clear");
  await clickAnswered(page, "#clear");
  await expect(page.locator("#memo")).toHaveValue("", { timeout: 10000 });
});

test("a focused field keeps every typed character while renders land", async ({ page }) => {
  await open(page, "/?tick");
  const ticks = page.locator("#ticks");
  await expect(ticks).not.toHaveText("ticks: 0", { timeout: 10000 });
  const before = await ticks.textContent();

  await page.click("#draft");
  const typed = "slow typing";
  for (let i = 1; i <= typed.length; i += 1) {
    await page.keyboard.type(typed[i - 1]);
    await page.waitForTimeout(150);
    expect(await page.locator("#draft").inputValue(), "no render drops a typed character").toBe(
      typed.slice(0, i),
    );
  }
  expect(await ticks.textContent(), "timer renders landed while typing").not.toBe(before);
  await expect(page.locator("#draft")).toBeFocused();
});

test("an answered edit rides on no later event", async ({ page }) => {
  await open(page);
  await addRow(page, "buy milk", 0);
  await expect(page.locator("#draft")).toHaveValue("", { timeout: 10000 });
  const draftId = await page.locator("#draft").getAttribute("ipe-id");
  expect(draftId).toBeTruthy();

  const next = page.waitForRequest(isEventPost);
  await clickAnswered(page, "#tick0");
  const sent = JSON.parse((await next).postData() ?? "{}");
  expect(sent.inputState?.[draftId]).toBeUndefined();
});

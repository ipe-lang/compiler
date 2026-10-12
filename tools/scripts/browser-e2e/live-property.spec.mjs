/**
 * Playwright spec: a patch that removes a boolean attribute clears its live property.
 *
 * Once the user or a script sets `checked` or `selected`, the property stops
 * following its attribute, so removing the attribute alone leaves the control
 * as the user left it. A patch writes the property beside the attribute, on
 * removal as on set:
 *
 *   1. Checkbox — a box the user checked is unchecked when the server's
 *      render drops its `checked` attribute.
 *   2. Option — an option a script selected is deselected when the server's
 *      render drops its `selected` attribute.
 *
 * The patches frames are dispatched on the client's own `EventSource`, diffed
 * from the epoch on screen, onto controls added to the app's root.
 *
 * Prerequisites and local run: see geo-clipboard.spec.mjs.
 */

import { test, expect } from "@playwright/test";

const PORT = process.env.IPE_GEO_CLIPBOARD_PORT ?? "18080";
const BASE = `http://127.0.0.1:${PORT}`;

/** Split an epoch token `<32 hex>.<counter>`; `null` when malformed. */
function epochParts(token) {
  const m = typeof token === "string" ? token.match(/^([0-9a-f]{32})\.([1-9][0-9]*)$/) : null;
  return m ? { inc: m[1], n: Number(m[2]) } : null;
}

/** Load the app with every `EventSource` it opens kept in `window.__e2eStreams`. */
async function load(page) {
  await page.addInitScript(() => {
    const Native = window.EventSource;
    window.__e2eStreams = [];
    window.EventSource = function (url, opts) {
      const stream = new Native(url, opts);
      window.__e2eStreams.push(stream);
      return stream;
    };
    window.EventSource.prototype = Native.prototype;
  });
  await page.goto(BASE);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
}

/** Add `html` to the end of the app's root. */
async function addToRoot(page, html) {
  await page.evaluate(
    (markup) => document.getElementById("ipe-root").insertAdjacentHTML("beforeend", markup),
    html,
  );
}

/** Push a patches frame diffed from the epoch on screen, applying `patches`. */
async function pushPatches(page, patches) {
  const from = await page.evaluate(() => window.__ipeEpoch);
  const parts = epochParts(from);
  expect(parts, `the page carries a render epoch: ${from}`).not.toBeNull();
  const frame = { patches, from, to: `${parts.inc}.${parts.n + 1}` };
  await page.evaluate((data) => {
    const streams = window.__e2eStreams;
    streams[streams.length - 1].dispatchEvent(new MessageEvent("patches", { data }));
  }, JSON.stringify(frame));
}

test("checkbox: a removed checked attribute unchecks a box the user checked", async ({
  page,
}) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e));
  await load(page);
  await addToRoot(page, '<input type="checkbox" id="ipe-e2e-box" ipe-id="e2e-box" checked>');
  const box = page.locator("#ipe-e2e-box");
  // Two clicks leave the box checked with a property that no longer follows
  // its attribute.
  await box.click();
  await box.click();
  await expect(box).toBeChecked();
  await box.blur();
  await pushPatches(page, [{ id: "e2e-box", attrs: { checked: "" } }]);
  await expect(box).not.toBeChecked();
  expect(await box.evaluate((el) => el.hasAttribute("checked"))).toBe(false);
  expect(errors.map(String)).toEqual([]);
});

test("option: a removed selected attribute deselects an option a script selected", async ({
  page,
}) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e));
  await load(page);
  await addToRoot(
    page,
    '<select multiple id="ipe-e2e-list">' +
      '<option id="ipe-e2e-opt" ipe-id="e2e-opt" selected>a</option><option>b</option>' +
      "</select>",
  );
  const opt = page.locator("#ipe-e2e-opt");
  await opt.evaluate((el) => {
    el.selected = false;
    el.selected = true;
  });
  await pushPatches(page, [{ id: "e2e-opt", attrs: { selected: "" } }]);
  expect(await opt.evaluate((el) => el.selected)).toBe(false);
  expect(await opt.evaluate((el) => el.hasAttribute("selected"))).toBe(false);
  expect(errors.map(String)).toEqual([]);
});

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
 *   3. Presence — a set attribute turns its property on whatever its text,
 *      `"false"` included, as first paint renders it.
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
  await pushPatches(page, [{ id: "e2e-box", attrs: { checked: null } }]);
  await expect(box).not.toBeChecked();
  expect(await box.evaluate((el) => el.hasAttribute("checked"))).toBe(false);
  expect(errors.map(String)).toEqual([]);
});

test("checkbox: an attribute set to the empty value is present, never removed", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e));
  await load(page);
  await addToRoot(page, '<input type="checkbox" id="ipe-e2e-empty" ipe-id="e2e-empty">');
  const box = page.locator("#ipe-e2e-empty");
  await expect(box).not.toBeChecked();
  await pushPatches(page, [{ id: "e2e-empty", attrs: { checked: "", "data-mark": "" } }]);
  await expect(box).toBeChecked();
  expect(await box.evaluate((el) => [el.getAttribute("checked"), el.getAttribute("data-mark")])).toEqual([
    "",
    "",
  ]);
  expect(errors.map(String)).toEqual([]);
});

test("checkbox: a set attribute checks whatever its text, as first paint does", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e));
  await load(page);
  await addToRoot(page, '<input type="checkbox" id="ipe-e2e-text" ipe-id="e2e-text">');
  const box = page.locator("#ipe-e2e-text");
  await expect(box).not.toBeChecked();
  // First paint of `checked="false"` is a checked box; the patch path agrees,
  // and the property table is looked up case folded.
  await pushPatches(page, [{ id: "e2e-text", attrs: { Checked: "false" } }]);
  await expect(box).toBeChecked();
  await pushPatches(page, [{ id: "e2e-text", attrs: { Checked: null } }]);
  await expect(box).not.toBeChecked();
  expect(errors.map(String)).toEqual([]);
});

test("patch: an attribute value that is neither a string nor null is refused", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e));
  await load(page);
  await addToRoot(page, '<span id="ipe-e2e-shape" ipe-id="e2e-shape" title="kept">x</span>');
  const el = page.locator("#ipe-e2e-shape");
  await pushPatches(page, [{ id: "e2e-shape", attrs: { title: 5, lang: { a: 1 }, dir: true } }]);
  expect(
    await el.evaluate((n) => [n.getAttribute("title"), n.hasAttribute("lang"), n.hasAttribute("dir")]),
  ).toEqual(["kept", false, false]);
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
  await pushPatches(page, [{ id: "e2e-opt", attrs: { selected: null } }]);
  expect(await opt.evaluate((el) => el.selected)).toBe(false);
  expect(await opt.evaluate((el) => el.hasAttribute("selected"))).toBe(false);
  expect(errors.map(String)).toEqual([]);
});

// The frame rule on the patch path. `addToRoot` bypasses the parse-time fence,
// so these frames stand for nodes the fence never saw; each patch must still
// leave a sandboxed iframe and a loader without its URL.

test("frame patch: a url set on an unsandboxed iframe writes an empty sandbox first", async ({
  page,
}) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e));
  await load(page);
  await addToRoot(page, '<iframe id="ipe-e2e-frame" ipe-id="e2e-frame"></iframe>');
  const frame = page.locator("#ipe-e2e-frame");
  expect(await frame.evaluate((el) => el.hasAttribute("sandbox"))).toBe(false);
  await pushPatches(page, [{ id: "e2e-frame", attrs: { SRC: "/" } }]);
  expect(await frame.evaluate((el) => [el.getAttribute("sandbox"), el.getAttribute("src")])).toEqual([
    "",
    "/",
  ]);
  await expect.poll(() => frame.evaluate((el) => el.contentDocument === null)).toBe(true);
  expect(errors.map(String)).toEqual([]);
});

test("frame patch: an iframe sandbox is never removed and keeps only known tokens", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e));
  await load(page);
  await addToRoot(page, '<iframe id="ipe-e2e-boxed" ipe-id="e2e-boxed" sandbox="allow-forms"></iframe>');
  const frame = page.locator("#ipe-e2e-boxed");
  await pushPatches(page, [{ id: "e2e-boxed", attrs: { sandbox: null } }]);
  expect(await frame.evaluate((el) => el.getAttribute("sandbox"))).toBe("allow-forms");
  await pushPatches(page, [
    { id: "e2e-boxed", attrs: { Sandbox: "ALLOW-SAME-ORIGIN\tallow-scripts allow-popups-to-escape-sandbox x" } },
  ]);
  expect(await frame.evaluate((el) => el.getAttribute("sandbox"))).toBe("allow-scripts");
  expect(errors.map(String)).toEqual([]);
});

test("frame patch: a loader never gains its url, in any key case", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e));
  await load(page);
  await addToRoot(
    page,
    '<embed id="ipe-e2e-embed" ipe-id="e2e-embed"><object id="ipe-e2e-object" ipe-id="e2e-object"></object>',
  );
  await pushPatches(page, [
    { id: "e2e-embed", attrs: { SRC: "/", title: "kept" } },
    { id: "e2e-object", attrs: { data: "/" } },
  ]);
  expect(
    await page.evaluate(() => {
      const embed = document.getElementById("ipe-e2e-embed");
      const object = document.getElementById("ipe-e2e-object");
      return [embed.hasAttribute("src"), embed.getAttribute("title"), object.hasAttribute("data")];
    }),
  ).toEqual([false, "kept", false]);
  expect(errors.map(String)).toEqual([]);
});

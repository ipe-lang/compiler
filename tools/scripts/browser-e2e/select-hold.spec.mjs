/**
 * Playwright spec: a render pushed while a `<select>` is open waits for it to close.
 *
 * A focused `<select>` is the client's proxy for an open dropdown, which any
 * DOM mutation around it collapses. A full render the stream pushes meanwhile
 * is held, never dropped, and patches frames that cannot apply onto the
 * screen meanwhile never reopen the stream:
 *
 *   1. Held render — a full render pushed while the select is focused lands,
 *      with its epoch, the moment the select loses focus.
 *   2. No reopen storm — patches frames diffed from the held render, plus a
 *      committed event, leave the stream open while the select is focused;
 *      closing it reopens the stream once and the page converges on the
 *      server's render and epoch.
 *   3. No stuck hold — a select can lose focus with no `focusout` (a focused
 *      node removed from the page): the watchdog then releases the held
 *      render, and a patches frame that cannot apply resyncs the stream once.
 *
 * The pushed frames are dispatched on the client's own `EventSource`, so each
 * case controls exactly what the stream delivers while the select is open.
 *
 * Runs against the geo-clipboard example with no geolocation permission:
 * a dispatched `Locate` renders "location: error: ...".
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

/** Whether `response` answers an event POST. */
function isEventPost(response) {
  const request = response.request();
  return request.method() === "POST" && new URL(request.url()).pathname === "/_ipe/event";
}

/** Record every `EventSource` the client opens in `window.__e2eStreams`. */
async function recordStreams(page) {
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
}

/** Load the app, add a select to its root and focus it; returns the epoch. */
async function openSelect(page) {
  await recordStreams(page);
  await page.goto(BASE);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  await expect(page.getByText("location: unknown")).toBeVisible();
  await page.evaluate(() =>
    document
      .getElementById("ipe-root")
      .insertAdjacentHTML(
        "beforeend",
        '<select id="ipe-e2e-select" name="e2e-pick"><option>a</option><option>b</option></select>',
      ),
  );
  await page.locator("#ipe-e2e-select").focus();
  const epoch = await page.evaluate(() => window.__ipeEpoch);
  expect(epochParts(epoch), `the page carries a render epoch: ${epoch}`).not.toBeNull();
  return epoch;
}

/** Dispatch `frame` as an `event` on the client's current stream. */
async function push(page, event, frame) {
  await page.evaluate(
    ([name, data]) => {
      const streams = window.__e2eStreams;
      streams[streams.length - 1].dispatchEvent(new MessageEvent(name, { data }));
    },
    [event, JSON.stringify(frame)],
  );
}

/** Push a full render of the current root plus a marker, at epoch `held`. */
async function pushHeldRender(page, held) {
  const body = await page.evaluate(
    () => document.getElementById("ipe-root").innerHTML + '<i id="ipe-e2e-held"></i>',
  );
  await push(page, "patch", { body, epoch: held });
}

test("held render: a full render pushed while a select is open lands when it closes", async ({
  page,
}) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e));
  const epoch = await openSelect(page);
  const { inc, n } = epochParts(epoch);
  const held = `${inc}.${n + 50}`;
  await pushHeldRender(page, held);
  await expect(page.locator("#ipe-e2e-held")).toHaveCount(0);
  expect(await page.evaluate(() => window.__ipeEpoch)).toBe(epoch);

  await page.evaluate(() => document.getElementById("ipe-e2e-select").blur());
  await expect(page.locator("#ipe-e2e-held")).toHaveCount(1, { timeout: 5000 });
  expect(await page.evaluate(() => window.__ipeEpoch)).toBe(held);
  expect(errors.map(String)).toEqual([]);
});

test("no reopen storm: frames that cannot apply while a select is open keep the stream", async ({
  page,
}) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e));
  const epoch = await openSelect(page);
  const { inc, n } = epochParts(epoch);
  const opened = await page.evaluate(() => window.__e2eStreams.length);
  const held = `${inc}.${n + 50}`;
  await pushHeldRender(page, held);
  for (let i = 1; i <= 5; i++) {
    await push(page, "patches", { patches: [], from: held, to: `${inc}.${n + 50 + i}` });
  }
  // A committed event while the select keeps focus: a programmatic click
  // moves no focus.
  const committed = page.waitForResponse(isEventPost);
  await page.evaluate(() =>
    [...document.querySelectorAll("button")]
      .find((b) => b.textContent.trim() === "Locate")
      .click(),
  );
  expect((await committed).status()).toBe(200);
  await page.waitForTimeout(1000);
  expect(await page.evaluate(() => window.__e2eStreams.length)).toBe(opened);
  await expect(page.locator("#ipe-e2e-held")).toHaveCount(0);

  await page.evaluate(() => document.getElementById("ipe-e2e-select").blur());
  await expect
    .poll(() => page.evaluate(() => window.__e2eStreams.length), { timeout: 10000 })
    .toBe(opened + 1);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  await page.waitForTimeout(1000);
  expect(await page.evaluate(() => window.__e2eStreams.length)).toBe(opened + 1);
  await expect(page.locator("#ipe-e2e-held")).toHaveCount(0);
  await expect(page.getByText(/location: error:/)).toBeVisible();
  const converged = epochParts(await page.evaluate(() => window.__ipeEpoch));
  expect(converged?.inc).toBe(inc);
  expect(converged.n).toBeLessThan(n + 50);

  // The converged epoch is the server's: the next event is accepted.
  const reply = page.waitForResponse(isEventPost);
  await page.getByRole("button", { name: "Locate" }).click();
  expect((await reply).status()).toBe(200);
  expect(errors.map(String)).toEqual([]);
});

/** Keep every `focusout` from the client, as a removed focused node does. */
async function swallowFocusout(page) {
  await page.evaluate(() =>
    window.addEventListener("focusout", (e) => e.stopImmediatePropagation(), true),
  );
}

test("no stuck hold: a select removed while open releases the held render", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e));
  const epoch = await openSelect(page);
  const { inc, n } = epochParts(epoch);
  const held = `${inc}.${n + 50}`;
  await swallowFocusout(page);
  await pushHeldRender(page, held);
  await expect(page.locator("#ipe-e2e-held")).toHaveCount(0);

  await page.evaluate(() => document.getElementById("ipe-e2e-select").remove());
  await expect(page.locator("#ipe-e2e-held")).toHaveCount(1, { timeout: 10000 });
  expect(await page.evaluate(() => window.__ipeEpoch)).toBe(held);
  expect(errors.map(String)).toEqual([]);
});

test("no stuck hold: a frame that cannot apply with no select open resyncs", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e));
  const epoch = await openSelect(page);
  const { inc, n } = epochParts(epoch);
  const opened = await page.evaluate(() => window.__e2eStreams.length);
  const held = `${inc}.${n + 50}`;
  // Only the frame may release the hold here.
  await page.evaluate(() => clearInterval(window.__ipeWatchdogTimer));
  await swallowFocusout(page);
  await pushHeldRender(page, held);

  await page.evaluate(() => document.getElementById("ipe-e2e-select").remove());
  await push(page, "patches", { patches: [], from: `${inc}.${n + 60}`, to: `${inc}.${n + 61}` });
  await expect
    .poll(() => page.evaluate(() => window.__e2eStreams.length), { timeout: 5000 })
    .toBe(opened + 1);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  await expect(page.locator("#ipe-e2e-held")).toHaveCount(0);
  const converged = epochParts(await page.evaluate(() => window.__ipeEpoch));
  expect(converged?.inc).toBe(inc);
  expect(converged.n).toBeLessThan(n + 50);
  expect(errors.map(String)).toEqual([]);
});

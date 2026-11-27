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
 *   6. Order — an event reaches the server only after every edit the user made
 *      before it: one event is in flight at a time, and a send first posts the
 *      edits still waiting on their debounce.
 *   7. Channel — a post with no answer is retried in order past its bound, a
 *      burst of edits to one field queues one event, an accept whose handling
 *      throws is never posted again, and leaving the page sends a pending edit
 *      through the same ordered queue.
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

/** Whether `request` is an event POST that `handlerId` raised. */
function isEventOf(request, handlerId) {
  return isEventPost(request) && JSON.parse(request.postData() ?? "{}").handlerId === handlerId;
}

/**
 * Click the element `selector` and wait for the answer to the event it sends,
 * never to an earlier event's, such as the edit the click flushes ahead of it.
 */
async function clickAnswered(page, selector, click = () => page.click(selector)) {
  const handlerId = await page.locator(selector).getAttribute("data-ipe-hid");
  expect(handlerId, `${selector} raises an event`).toBeTruthy();
  const answered = page.waitForResponse((r) => isEventOf(r.request(), handlerId), {
    timeout: 10000,
  });
  await click();
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

test("a click never reaches the server before the edit posted ahead of it", async ({ page }) => {
  await open(page);
  // Hold the draft's input event at the network for a window. A client that
  // posts the click meanwhile has the click answered first, and only then is
  // the input event let through.
  let clickFirst = null;
  let releaseInput = () => {};
  const clickLanded = new Promise((resolve) => {
    releaseInput = resolve;
  });
  await page.route("**/_ipe/event", async (route) => {
    const body = JSON.parse(route.request().postData() ?? "{}");
    if (body.msg === "input") {
      await Promise.race([clickLanded, new Promise((resolve) => setTimeout(resolve, 1000))]);
      clickFirst ??= false;
      await route.continue();
      return;
    }
    clickFirst ??= true;
    const response = await route.fetch();
    releaseInput();
    await route.fulfill({ response });
  });
  await page.fill("#draft", "first");
  await clickAnswered(page, "#add");
  expect(clickFirst, "the click was posted while the input event was unanswered").toBe(false);
  await expect(page.locator("#text0")).toHaveText("first", { timeout: 10000 });
});

test("a click the field keeps focus through still follows the edit typed before it", async ({
  page,
}) => {
  await open(page);
  await page.fill("#draft", "first");
  // A synthetic click moves no focus, so no blur sends the edit ahead of it.
  await clickAnswered(page, "#add", () => page.locator("#add").dispatchEvent("click"));
  await expect(page.locator("#text0")).toHaveText("first", { timeout: 10000 });
});

test("a click queued behind an unreadable stale answer still goes", async ({ page }) => {
  await open(page);
  // The draft's input event is answered, once the click is queued behind it,
  // by a stale-render refusal whose body is no JSON.
  await page.route(
    "**/_ipe/event",
    async (route) => {
      await page.waitForFunction(() => window.__ipeEventQueue.length > 0, null, { timeout: 5000 });
      await route.fulfill({
        status: 409,
        headers: { "X-Ipe-Web": "1", "Content-Type": "application/json" },
        body: "{",
      });
    },
    { times: 1 },
  );
  await page.fill("#draft", "first");
  await clickAnswered(page, "#add");
  await expect(page.locator("#text0")).toHaveCount(1, { timeout: 10000 });
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

/** The handler id the element `selector` raises its events with. */
async function hidOf(page, selector) {
  const handlerId = await page.locator(selector).getAttribute("data-ipe-hid");
  expect(handlerId, `${selector} raises an event`).toBeTruthy();
  return handlerId;
}

test("a post that is never answered is retried in order past its bound", async ({ page }) => {
  await open(page);
  await page.evaluate(() => {
    window.__ipeEventAnswerBoundMs = 1000;
  });
  const draftHid = await hidOf(page, "#draft");
  const posted = [];
  let hung = false;
  await page.route("**/_ipe/event", async (route) => {
    const body = JSON.parse(route.request().postData() ?? "{}");
    posted.push(body.handlerId);
    // The draft's first post never gets an answer.
    if (!hung && body.handlerId === draftHid) {
      hung = true;
      return;
    }
    await route.continue();
  });
  await page.fill("#draft", "first");
  await clickAnswered(page, "#add");
  await expect(page.locator("#text0")).toHaveText("first", { timeout: 10000 });
  const addHid = await hidOf(page, "#add");
  expect(posted.indexOf(addHid), "the click went after the edit's retry").toBeGreaterThan(
    posted.lastIndexOf(draftHid),
  );
  expect(posted.filter((h) => h === draftHid).length, "the hung edit was posted again").toBe(2);
});

test("typing while an event is unanswered queues one event per field", async ({ page }) => {
  await open(page);
  const warnings = [];
  page.on("console", (m) => {
    if (m.type() === "warning") warnings.push(m.text());
  });
  let release = () => {};
  const released = new Promise((resolve) => {
    release = resolve;
  });
  let held = false;
  await page.route("**/_ipe/event", async (route) => {
    if (!held) {
      held = true;
      await released;
    }
    await route.continue();
  });
  // Each edit is sent at once by the blur that follows it, while the first
  // edit's post is held unanswered.
  const depth = await page.evaluate(() => {
    const draft = document.getElementById("draft");
    let deepest = 0;
    for (let i = 0; i < 80; i += 1) {
      draft.value = `burst ${i}`;
      draft.dispatchEvent(new Event("input", { bubbles: true }));
      draft.dispatchEvent(new FocusEvent("focusout", { bubbles: true }));
      deepest = Math.max(deepest, window.__ipeEventQueue.length);
    }
    return deepest;
  });
  expect(depth, "queued edits of one field coalesce").toBeLessThanOrEqual(1);
  release();
  await clickAnswered(page, "#add");
  await expect(page.locator("#text0")).toHaveText("burst 79", { timeout: 10000 });
  expect(warnings.filter((w) => w.includes("event queue at cap"))).toEqual([]);
});

test("an accepted event whose handling throws is never sent again", async ({ page }) => {
  await open(page);
  const seqs = [];
  page.on("request", (request) => {
    if (isEventPost(request)) seqs.push(JSON.parse(request.postData() ?? "{}").seq);
  });
  // The first accept's handling throws after the answer was read.
  await page.evaluate(() => {
    const success = window.__ipeOnPostSuccess;
    let thrown = false;
    window.__ipeOnPostSuccess = function () {
      if (!thrown) {
        thrown = true;
        throw new Error("e2e: handling an accept throws");
      }
      return success();
    };
  });
  await page.fill("#draft", "first");
  await clickAnswered(page, "#add");
  await expect(page.locator("#text0")).toHaveText("first", { timeout: 10000 });
  await page.waitForTimeout(1500);
  expect(seqs.length).toBeGreaterThan(1);
  expect(new Set(seqs).size, `each event was posted once: ${seqs}`).toBe(seqs.length);
});

test("leaving the page sends the pending edit through the ordered channel", async ({ page }) => {
  await open(page);
  const draftHid = await hidOf(page, "#draft");
  const clearHid = await hidOf(page, "#clear");
  const posted = [];
  let release = () => {};
  const released = new Promise((resolve) => {
    release = resolve;
  });
  await page.route("**/_ipe/event", async (route) => {
    const body = JSON.parse(route.request().postData() ?? "{}");
    posted.push(body);
    if (body.handlerId === clearHid) await released;
    await route.continue();
  });
  // The clear is in flight and unanswered when the edit is typed and the page
  // starts to leave.
  await page.locator("#clear").dispatchEvent("click");
  await expect.poll(() => posted.length).toBe(1);
  await page.locator("#draft").evaluate((draft) => {
    draft.value = "typed before leaving";
    draft.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await page.evaluate(() => window.dispatchEvent(new Event("pagehide")));
  await page.waitForTimeout(300);
  expect(await page.evaluate(() => window.__ipeEventQueue.length), "the edit waits its turn").toBe(1);
  expect(posted.length, "nothing overtook the unanswered clear").toBe(1);
  release();
  await expect.poll(() => posted.length, { timeout: 10000 }).toBe(2);
  const edit = posted[1];
  expect(edit.handlerId).toBe(draftHid);
  expect(edit.epoch, "the edit carries its render epoch").toBeTruthy();
  expect(edit.batch).toBeUndefined();
  expect(edit.seq).toBeGreaterThan(posted[0].seq);
});

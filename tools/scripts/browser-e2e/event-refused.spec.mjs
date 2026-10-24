/**
 * Playwright refusal spec: every answer to an event POST has one outcome.
 *
 * The client maps each answer to `/_ipe/event` once, in `__ipeEventAnswer`,
 * into a closed set of outcomes with one handler each. A refused event is said
 * on the status banner and never sent again, a value it carried rides on no
 * later event while the input still shows it, and a status no row names is
 * refused rather than retried. The retry queue keeps its order.
 *
 *   1. A real 413 — one oversized event is sent once, the banner names it too
 *      large, and the next click dispatches.
 *   2. The refused input — an input whose oversized value was refused does not
 *      ride on the next click, which is accepted, and keeps its text.
 *   3. The notice stands while the refused value is on screen, and an edit
 *      that replaces it clears it.
 *   4. Table rows — each status, unmarked `text/plain`, is refused once or
 *      retried as its row says; an unmarked `200 text/html` is retried.
 *   5. FIFO — events queued while the server is unreachable reach it in the
 *      order they were sent.
 *
 * Runs against the geo-clipboard example with no geolocation permission: a
 * dispatched `Locate` renders "location: error: ...". The example has no text
 * input, so the spec adds one outside `#ipe-root`, where no render replaces it.
 *
 * Prerequisites and local run: see geo-clipboard.spec.mjs.
 */

import { test, expect } from "@playwright/test";

const PORT = process.env.IPE_GEO_CLIPBOARD_PORT ?? "18080";
const BASE = `http://127.0.0.1:${PORT}`;

// Past the server's default event body ceiling (`WEB_MAX_BODY_CEILING`, 5 MiB).
const OVERSIZED = 6 * 1024 * 1024;

/** Block until the SSE handshake has landed (see geo-clipboard.spec.mjs). */
async function waitReady(page) {
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
}

/** Whether `request` is an event POST. */
function isEventPost(request) {
  return request.method() === "POST" && new URL(request.url()).pathname === "/_ipe/event";
}

/** Open the app and record every event POST the page sends. */
async function open(page) {
  const posts = [];
  page.on("request", (r) => {
    if (isEventPost(r)) posts.push(r);
  });
  await page.goto(BASE);
  await waitReady(page);
  return posts;
}

/** The status banner while it says a refusal of `kind`. */
const refusedBanner = (page, kind) => page.locator(`#__ipe-status[data-ipe-refused="${kind}"]`);

/** Click `Locate` and wait for its answer; the answer's status. */
async function locate(page) {
  const answered = page.waitForResponse((r) => isEventPost(r.request()), { timeout: 10000 });
  await page.getByRole("button", { name: "Locate" }).click();
  return (await answered).status();
}

/** Add a text input outside `#ipe-root`, so no render replaces it. */
async function addInput(page) {
  await page.evaluate(() => {
    document.body.insertAdjacentHTML(
      "beforeend",
      '<input id="e2e-refused" ipe-id="e2e-refused" ipe-input="e2e-type">',
    );
    window.__ipeBindEvents();
  });
}

/** Set the added input to `value` and fire its input event. */
async function typeInto(page, value) {
  await page.evaluate((v) => {
    const el = document.getElementById("e2e-refused");
    el.value = v;
    el.dispatchEvent(new Event("input", { bubbles: true }));
  }, value);
}

/** Type an oversized value into the added input and wait for its refusal. */
async function refuseInput(page, posts) {
  await addInput(page);
  const before = posts.length;
  await page.evaluate((n) => {
    const el = document.getElementById("e2e-refused");
    el.value = "x".repeat(n);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  }, OVERSIZED);
  await expect(refusedBanner(page, "too-large")).toBeVisible({ timeout: 10000 });
  const sent = posts.slice(before);
  expect(sent.length, "the oversized edit is sent once").toBe(1);
}

test("a real 413 is sent once, said too large, and the next click dispatches", async ({ page }) => {
  const posts = await open(page);
  await page.evaluate((n) => window.__ipeSend("e2e-oversized", ["x".repeat(n)]), OVERSIZED);
  await expect(refusedBanner(page, "too-large")).toBeVisible({ timeout: 10000 });
  // The fast retry is 200 ms; a retried refusal would repeat within 4 s.
  await page.waitForTimeout(4000);
  const oversized = posts.filter((r) => (r.postData() ?? "").length > OVERSIZED);
  expect(oversized.length, "a refused event is never sent again").toBe(1);

  expect(await locate(page)).toBe(200);
  await expect(page.getByText(/location: error/)).toBeVisible({ timeout: 10000 });
  await expect(page.locator("#__ipe-status[data-ipe-refused]")).toHaveCount(0);
});

test("a refused input rides on no later event and keeps its text", async ({ page }) => {
  const posts = await open(page);
  await refuseInput(page, posts);

  const click = page.waitForRequest(isEventPost);
  const status = locate(page);
  const body = (await click).postData() ?? "";
  expect(body.length, "the click carries no refused value").toBeLessThan(64 * 1024);
  const sent = JSON.parse(body);
  expect(sent.inputState?.["e2e-refused"]).toBeUndefined();
  expect(await status).toBe(200);
  await expect(page.getByText(/location: error/)).toBeVisible({ timeout: 10000 });
  expect(await page.locator("#e2e-refused").evaluate((el) => el.value.length)).toBe(OVERSIZED);
});

test("the refusal notice stands until the refused value is replaced", async ({ page }) => {
  const posts = await open(page);
  await refuseInput(page, posts);

  // An accepted unrelated click: the refused value is still on screen.
  expect(await locate(page)).toBe(200);
  await page.waitForTimeout(500);
  await expect(refusedBanner(page, "too-large")).toBeVisible();

  // The input no longer shows the refused value; its edit goes out with it.
  const edit = page.waitForRequest(isEventPost);
  await typeInto(page, "short");
  const sent = JSON.parse((await edit).postData() ?? "{}");
  expect(sent.inputState?.["e2e-refused"]?.value).toBe("short");
  expect(await locate(page)).toBe(200);
  await expect(page.locator("#__ipe-status[data-ipe-refused]")).toHaveCount(0);
});

// Each status as an unmarked `text/plain` answer, and the outcome its row names.
const ROWS = [
  { status: 400, refused: "refused" },
  { status: 403, refused: "refused" },
  { status: 404, refused: "refused" },
  { status: 409, refused: "refused" },
  { status: 418, refused: "refused" },
  { status: 413, refused: "too-large" },
  { status: 414, refused: "too-large" },
  { status: 431, refused: "too-large" },
  { status: 429, refused: null },
  { status: 502, refused: null },
  { status: 503, refused: null },
];

for (const row of ROWS) {
  const outcome = row.refused ? `refused as ${row.refused}` : "retried";
  test(`an unmarked ${row.status} is ${outcome}`, async ({ page }) => {
    await open(page);
    let answered = 0;
    await page.route("**/_ipe/event", (route) => {
      answered += 1;
      return route.fulfill({ status: row.status, contentType: "text/plain", body: "e2e" });
    });
    await page.getByRole("button", { name: "Locate" }).click();
    if (row.refused) {
      await expect(refusedBanner(page, row.refused)).toBeVisible({ timeout: 10000 });
      await page.waitForTimeout(2500);
      expect(answered, "a refused event is never sent again").toBe(1);
    } else {
      await expect.poll(() => answered, { timeout: 10000 }).toBeGreaterThanOrEqual(2);
      await expect(page.locator("#__ipe-status[data-ipe-refused]")).toHaveCount(0);
    }
  });
}

test("an unmarked 200 text/html is the proxy wedge and is retried", async ({ page }) => {
  await open(page);
  let answered = 0;
  await page.route("**/_ipe/event", (route) => {
    answered += 1;
    return route.fulfill({ status: 200, contentType: "text/html", body: "<p>edge</p>" });
  });
  await page.getByRole("button", { name: "Locate" }).click();
  await expect.poll(() => answered, { timeout: 10000 }).toBeGreaterThanOrEqual(2);
  await expect(page.locator("#__ipe-status[data-ipe-refused]")).toHaveCount(0);
});

test("events queued while the server is unreachable reach it in order", async ({ page }) => {
  await open(page);
  const attempts = [];
  const delivered = [];
  let reachable = false;
  await page.route("**/_ipe/event", (route) => {
    const msg = JSON.parse(route.request().postData() ?? "{}").msg;
    if (!reachable) {
      attempts.push(msg);
      return route.abort();
    }
    delivered.push(msg);
    return route.continue();
  });
  const queued = () => page.evaluate(() => window.__ipeEventQueue.map((b) => b.msg));

  await page.evaluate(() => window.__ipeSend("e2e-A", []));
  await expect.poll(queued).toEqual(["e2e-A"]);
  await page.evaluate(() => window.__ipeSend("e2e-B", []));
  await expect.poll(queued).toEqual(["e2e-A", "e2e-B"]);
  // A retry of the head fails and puts it back at the head.
  await expect
    .poll(() => attempts.filter((m) => m === "e2e-A").length, { timeout: 10000 })
    .toBeGreaterThanOrEqual(2);
  await expect.poll(queued).toEqual(["e2e-A", "e2e-B"]);
  // A live event sent while the queue holds events joins its tail.
  await page.evaluate(() => window.__ipeSend("e2e-C", []));
  await expect.poll(queued).toEqual(["e2e-A", "e2e-B", "e2e-C"]);

  reachable = true;
  await expect.poll(() => delivered, { timeout: 20000 }).toEqual(["e2e-A", "e2e-B", "e2e-C"]);
  await expect.poll(queued).toEqual([]);
});

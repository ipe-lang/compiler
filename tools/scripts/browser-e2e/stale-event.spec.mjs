/**
 * Playwright refusal spec: an event resolves only against the render it came from.
 *
 * Every `POST /_ipe/event` carries the render epoch its handler id was read
 * under. The server keeps the last few renders and refuses an event whose
 * epoch is not among them with `409` and the current render, so a replayed or
 * stale event can never act on a handler another render put at the same id.
 *
 *   1. Replay — an event body captured early, re-posted after more re-renders
 *      than the server keeps, is refused with 409 stale-render.
 *   2. Foreign epoch — a client whose epoch names another render history has
 *      its click refused, adopts the server's render and epoch, and its next
 *      click dispatches.
 *
 * Runs against the geo-clipboard example with no geolocation permission:
 * a dispatched `Locate` renders "location: error: ...", so "location: unknown"
 * proves nothing was dispatched.
 *
 * Prerequisites and local run: see geo-clipboard.spec.mjs.
 */

import { test, expect } from "@playwright/test";

const PORT = process.env.IPE_GEO_CLIPBOARD_PORT ?? "18080";
const BASE = `http://127.0.0.1:${PORT}`;

// The number of renders the server keeps (`RENDER_HISTORY_DEPTH`).
const HISTORY_DEPTH = 8;

/** Block until the SSE handshake has landed (see geo-clipboard.spec.mjs). */
async function waitReady(page) {
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
}

/** Split an epoch token `<32 hex>.<counter>`; `null` when malformed. */
function epochParts(token) {
  const m = typeof token === "string" ? token.match(/^([0-9a-f]{32})\.([1-9][0-9]*)$/) : null;
  return m ? { inc: m[1], n: Number(m[2]) } : null;
}

/** Whether `request` is an event POST. */
function isEventPost(request) {
  return request.method() === "POST" && new URL(request.url()).pathname === "/_ipe/event";
}

/** The headers a same-origin replay needs to pass the event route's checks. */
function replayHeaders(request) {
  const all = request.headers();
  const out = { "Content-Type": "application/json" };
  if (all["x-ipe-csrf"]) out["X-Ipe-Csrf"] = all["x-ipe-csrf"];
  return out;
}

test("replay: an event re-posted after its render was evicted is refused", async ({
  browser,
}) => {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto(BASE);
  await waitReady(page);

  const locate = page.getByRole("button", { name: "Locate" });
  const firstPost = page.waitForRequest(isEventPost);
  await locate.click();
  const captured = await firstPost;
  const body = captured.postData();
  const sent = epochParts(JSON.parse(body).epoch);
  expect(sent, `the event body must carry a render epoch: ${body}`).not.toBeNull();

  // Every dispatched Msg commits a render; push the captured one out of the
  // server's history.
  for (let i = 0; i < HISTORY_DEPTH + 1; i++) {
    const posted = page.waitForResponse((r) => isEventPost(r.request()));
    await locate.click();
    await posted;
  }
  await expect
    .poll(async () => epochParts(await page.evaluate(() => window.__ipeEpoch))?.n ?? 0, {
      timeout: 10000,
    })
    .toBeGreaterThan(sent.n + HISTORY_DEPTH);

  const reply = await page.evaluate(
    async ({ body, headers }) => {
      const r = await fetch("/_ipe/event", {
        method: "POST",
        headers,
        body,
        credentials: "same-origin",
      });
      const text = await r.text();
      return { status: r.status, web: r.headers.get("X-Ipe-Web"), text };
    },
    { body, headers: replayHeaders(captured) },
  );
  expect(reply.status, reply.text).toBe(409);
  expect(reply.web).toBe("1");
  const refusal = JSON.parse(reply.text);
  expect(refusal.refused).toBe("stale-render");
  expect(typeof refusal.body).toBe("string");
  expect(epochParts(refusal.epoch)?.inc).toBe(sent.inc);

  await ctx.close();
});

test("foreign epoch: the click is refused, the render recovers, the next click dispatches", async ({
  browser,
}) => {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto(BASE);
  await waitReady(page);
  await expect(page.getByText("location: unknown")).toBeVisible();

  const own = epochParts(await page.evaluate(() => window.__ipeEpoch));
  expect(own, "the page must embed a render epoch").not.toBeNull();
  // A well-formed epoch from another render history: never minted here.
  const foreignInc = own.inc === "f".repeat(32) ? "e".repeat(32) : "f".repeat(32);
  await page.evaluate((token) => {
    window.__ipeEpoch = token;
  }, `${foreignInc}.1`);

  const locate = page.getByRole("button", { name: "Locate" });
  const refused = page.waitForResponse((r) => isEventPost(r.request()));
  await locate.click();
  const response = await refused;
  expect(response.status()).toBe(409);
  expect(JSON.parse(response.request().postData()).epoch).toBe(`${foreignInc}.1`);

  // The client adopts the server's render and epoch, and dispatched nothing.
  await expect
    .poll(async () => epochParts(await page.evaluate(() => window.__ipeEpoch))?.inc, {
      timeout: 5000,
    })
    .toBe(own.inc);
  await expect(page.getByText("location: unknown")).toBeVisible();
  await expect(page.getByText(/location: error:/)).toHaveCount(0);

  const accepted = page.waitForResponse((r) => isEventPost(r.request()));
  await locate.click();
  expect((await accepted).status()).toBe(200);
  await expect(page.getByText(/location: error:/)).toBeVisible({ timeout: 5000 });

  await ctx.close();
});

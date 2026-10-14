/**
 * Playwright refusal spec: the tabs of one session share one live stream.
 *
 * A browser keeps at most 6 HTTP/1.1 connections per host, and an open
 * EventSource holds one for the page's life. One stream per tab leaves the 7th
 * tab of an origin waiting forever for a connection to fetch its page. The
 * client elects one tab per session (a Web Lock) to hold the stream and relays
 * its frames to the others (a BroadcastChannel).
 *
 *   1. Ten tabs of one session all load and go live, and exactly one of them
 *      holds a stream.
 *   2. Closing the tab that holds the stream hands it to another tab.
 *   3. A hidden tab holding the stream yields it to a visible one.
 *
 * Runs against the geo-clipboard example. Prerequisites and local run: see
 * geo-clipboard.spec.mjs.
 */

import { test, expect } from "@playwright/test";

const PORT = process.env.IPE_GEO_CLIPBOARD_PORT ?? "18080";
const BASE = `http://127.0.0.1:${PORT}`;

// More tabs than the browser's per-host connection limit (6).
const TABS = 10;

/** Block until the page has loaded and the session's stream is live. */
async function waitReady(page) {
  await expect(page.getByRole("button", { name: "Locate" })).toBeVisible({ timeout: 15000 });
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
}

/** Whether this tab holds an EventSource of its own that is not closed. */
async function holdsStream(page) {
  return page.evaluate(() => window.__ipeSSE !== null && window.__ipeSSE.readyState !== 2);
}

/** The tabs among `pages` that hold a stream. */
async function holders(pages) {
  const held = await Promise.all(pages.map(holdsStream));
  return pages.filter((_, i) => held[i]);
}

/** Open `n` tabs of one session, each loaded and live. */
async function openTabs(ctx, n) {
  const pages = [];
  for (let i = 0; i < n; i++) {
    const page = await ctx.newPage();
    await page.goto(BASE, { timeout: 15000 });
    await waitReady(page);
    pages.push(page);
  }
  return pages;
}

test("ten tabs of one session all load, sharing one stream", async ({ browser }) => {
  test.setTimeout(120_000);
  const ctx = await browser.newContext();
  const pages = await openTabs(ctx, TABS);

  await expect.poll(async () => (await holders(pages)).length, { timeout: 15000 }).toBe(1);
  for (const page of pages) {
    await expect(page.locator("html")).toHaveAttribute("data-ipe-live", "1");
  }
  await ctx.close();
});

test("closing the tab that holds the stream hands it to another tab", async ({ browser }) => {
  test.setTimeout(120_000);
  const ctx = await browser.newContext();
  const pages = await openTabs(ctx, TABS);
  await expect.poll(async () => (await holders(pages)).length, { timeout: 15000 }).toBe(1);

  const [leader] = await holders(pages);
  const rest = pages.filter((p) => p !== leader);
  const reopened = ctx.waitForEvent("request", {
    predicate: (r) => new URL(r.url()).pathname === "/_ipe/sse",
    timeout: 15000,
  });
  await leader.close();
  await reopened;

  await expect.poll(async () => (await holders(rest)).length, { timeout: 15000 }).toBe(1);
  for (const page of rest) {
    await expect(page.locator("html")).toHaveAttribute("data-ipe-live", "1", { timeout: 15000 });
  }
  // The freed connection serves a new tab.
  await openTabs(ctx, 1);
  await ctx.close();
});

test("a hidden tab holding the stream yields it to a visible tab", async ({ browser }) => {
  test.setTimeout(90_000);
  const ctx = await browser.newContext();
  // Each tab reports the visibility its `__ipeTestHidden` flag names.
  await ctx.addInitScript(() => {
    Object.defineProperty(Document.prototype, "visibilityState", {
      configurable: true,
      get() {
        return window.__ipeTestHidden ? "hidden" : "visible";
      },
    });
  });
  const pages = await openTabs(ctx, 2);
  await expect.poll(async () => (await holders(pages)).length, { timeout: 15000 }).toBe(1);
  const [leader] = await holders(pages);
  const other = pages.find((p) => p !== leader);

  await leader.evaluate(() => {
    window.__ipeTestHidden = true;
    document.dispatchEvent(new Event("visibilitychange"));
  });

  await expect.poll(() => holdsStream(other), { timeout: 30000 }).toBe(true);
  await expect.poll(() => holdsStream(leader), { timeout: 15000 }).toBe(false);
  await expect(other.locator("html")).toHaveAttribute("data-ipe-live", "1", { timeout: 15000 });
  await ctx.close();
});

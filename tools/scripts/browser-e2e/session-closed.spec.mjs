/**
 * Playwright behaviour spec for a session the server closes.
 *
 * The server ends a closed session's stream with one `closed` frame whose
 * data is the reason's tag. The page then shows its own notice for that tag
 * and stops: no stream reopen, no event post, no session probe, no reload.
 *
 *   1. A known tag: its fixed notice is shown, the page does not navigate
 *      within 5 s, and no further stream or event request is made, even when
 *      the reader clicks.
 *   2. An unknown tag: the generic notice, and the page is just as terminal.
 *   3. A tag carrying markup: no element is injected; the notice is the
 *      client's own text.
 *
 * The stream is served by the test (`page.route`), so the frame and its tag
 * are exact; the page itself is the geo-clipboard example's.
 *
 * Prerequisites and local run: see geo-clipboard.spec.mjs.
 */

import { test, expect } from "@playwright/test";

const PORT = process.env.IPE_GEO_CLIPBOARD_PORT ?? "18080";
const BASE = `http://127.0.0.1:${PORT}`;

/**
 * Open the page with its stream answered by one `closed` frame carrying
 * `tag`, and record every stream and event request and every navigation.
 */
async function openClosed(browser, tag) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const seen = { sse: 0, event: 0, navigations: 0 };
  page.on("request", (req) => {
    const url = new URL(req.url());
    if (url.pathname.endsWith("/_ipe/sse")) seen.sse += 1;
    if (url.pathname.endsWith("/_ipe/event")) seen.event += 1;
  });
  await page.route("**/_ipe/sse**", (route) =>
    route.fulfill({
      status: 200,
      headers: {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
      },
      body: `event: closed\ndata: ${tag}\n\n`,
    }),
  );
  await page.goto(BASE);
  page.on("framenavigated", (frame) => {
    if (frame === page.mainFrame()) seen.navigations += 1;
  });
  const status = page.locator('#__ipe-status[data-ipe-closed="1"]');
  await expect(status).toBeVisible({ timeout: 15000 });
  return { ctx, page, seen, status };
}

/** Wait 5 s, then assert the page made no request and no navigation since `before`. */
async function expectTerminal(page, seen, before) {
  await page.waitForTimeout(5000);
  expect(seen.navigations, "the page never navigates").toBe(0);
  expect(seen.sse, "the stream is never reopened").toBe(before.sse);
  expect(seen.event, "no event or probe is posted").toBe(before.event);
  await expect(page.locator("html")).toHaveAttribute("data-ipe-live", "0");
}

test("closed: the tag's fixed notice, and the page stays as it is", async ({
  browser,
}) => {
  const { ctx, page, seen, status } = await openClosed(browser, "over_ceiling");
  await expect(status).toHaveText(
    "This page grew past its session limit and was closed — reload to start over",
  );
  const before = { ...seen };
  expect(before.sse).toBe(1);
  await page.getByRole("button", { name: "Locate" }).click();
  await expectTerminal(page, seen, before);
  await ctx.close();
});

test("closed: an unknown tag gets the generic notice and is still terminal", async ({
  browser,
}) => {
  const { ctx, page, seen, status } = await openClosed(browser, "rebooting");
  await expect(status).toHaveText(
    "This session was closed — reload to start a new one",
  );
  const before = { ...seen };
  await expectTerminal(page, seen, before);
  await ctx.close();
});

test("closed: a tag carrying markup is never rendered as markup", async ({
  browser,
}) => {
  const hostile = '<img src=x onerror="window.__ipePwned=1"><b>owned</b>';
  const { ctx, page, status } = await openClosed(browser, hostile);
  await expect(status).toHaveText(
    "This session was closed — reload to start a new one",
  );
  await expect(status.locator("img, b")).toHaveCount(0);
  expect(await page.evaluate(() => window.__ipePwned)).toBeUndefined();
  expect(await page.locator("body").innerHTML()).not.toContain("owned");
  await ctx.close();
});

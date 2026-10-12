/**
 * Playwright Host-admission spec on the layout-fill app.
 *
 * Proves, in a real browser, that a DNS-rebound name reaches no route of an
 * app listener:
 *
 *   1. A Chromium whose resolver maps `attacker.example` to 127.0.0.1 loads
 *      `http://attacker.example:<port>/` and gets 421, and the context holds
 *      no `ipe_sid` cookie.
 *   2. The same browser loads the app at `127.0.0.1:<port>` and it goes live
 *      (the refusal is the host, not a dead server).
 *
 * Prerequisites (all satisfied by the CI `browser-e2e` job setup):
 *   - IPE_LAYOUT_FILL_PORT env var with the port the layout-fill binary
 *     listens on
 *   - Playwright installed  (`npm install @playwright/test`)
 *   - Chromium browser      (`npx playwright install chromium`)
 *
 * Run locally after building:
 *   bash tools/scripts/browser-e2e/run.sh
 */

import { test, expect, chromium } from "@playwright/test";

const PORT = process.env.IPE_LAYOUT_FILL_PORT ?? "18081";
const REBOUND = `http://attacker.example:${PORT}/`;
const LOOPBACK = `http://127.0.0.1:${PORT}/`;

test("a rebound host is refused before any session, the loopback literal serves", async () => {
  const browser = await chromium.launch({
    args: ["--host-resolver-rules=MAP attacker.example 127.0.0.1"],
  });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();

    const refused = await page.goto(REBOUND);
    expect(refused?.status()).toBe(421);
    expect(await refused?.text()).toContain("host_not_admitted");
    const cookies = await context.cookies();
    expect(cookies.filter((c) => c.name.endsWith("ipe_sid"))).toEqual([]);

    const served = await page.goto(LOOPBACK);
    expect(served?.status()).toBe(200);
    await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  } finally {
    await browser.close();
  }
});

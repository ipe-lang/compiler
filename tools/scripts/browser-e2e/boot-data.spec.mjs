/**
 * Playwright refusal spec: the live client boots only on the page's own boot data.
 *
 * A live page hands its client the session values and the client config in
 * one inert JSON block, `<script type="application/json" id="ipe-boot">`,
 * placed right before the client's own tag. The client reads that block once,
 * before anything else runs, and never boots on invented defaults:
 *
 *   1. Refusals — a page whose block is missing, is not JSON, or carries a
 *      field of the wrong shape halts the client with an `IpeBootError`, shows
 *      the offline banner, and never marks the page live.
 *   2. Decoys — an element of the app's, earlier in the page and carrying the
 *      block's id, never stands in for the block: the page still boots on the
 *      server's own values.
 *
 * Each case serves the real page with its HTML rewritten in flight.
 *
 * Prerequisites and local run: see geo-clipboard.spec.mjs.
 */

import { test, expect } from "@playwright/test";

const PORT = process.env.IPE_GEO_CLIPBOARD_PORT ?? "18080";
const BASE = `http://127.0.0.1:${PORT}`;

const BLOCK = /<script type="application\/json" id="ipe-boot">([\s\S]*?)<\/script>/;

/** A boot block whose body is `json`, escaped as the server escapes it. */
function blockOf(json) {
  const body = JSON.stringify(json)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026");
  return `<script type="application/json" id="ipe-boot">${body}</script>`;
}

/** The parsed boot block of `html`; throws when the page has none. */
function bootOf(html) {
  const m = html.match(BLOCK);
  if (!m) throw new Error("the served page carries no boot block");
  return JSON.parse(m[1]);
}

/**
 * Serve the page root through `rewrite(html) -> html`, recording the page's
 * uncaught errors. Returns the error list and the original page's boot data.
 */
async function serveRewritten(page, rewrite) {
  const errors = [];
  const original = {};
  page.on("pageerror", (e) => errors.push(e));
  await page.route(
    (url) => url.origin === BASE && url.pathname === "/",
    async (route) => {
      const response = await route.fetch();
      const html = await response.text();
      original.boot = bootOf(html);
      await route.fulfill({ response, body: rewrite(html) });
    },
  );
  await page.goto(BASE);
  return { errors, original };
}

/** Rewrite the boot block's JSON through `edit(boot)`. */
function editBoot(edit) {
  return (html) => {
    const boot = bootOf(html);
    edit(boot);
    return html.replace(BLOCK, () => blockOf(boot));
  };
}

const REFUSALS = [
  ["the block is missing", (html) => html.replace(BLOCK, "")],
  [
    "the block is not JSON",
    (html) => html.replace(BLOCK, '<script type="application/json" id="ipe-boot">{not json</script>'),
  ],
  ["sid is not a string", editBoot((b) => { b.sid = 7; })],
  ["epoch is absent", editBoot((b) => { delete b.epoch; })],
  ["cfg is an array", editBoot((b) => { b.cfg = []; })],
  ["a cfg boolean is a string", editBoot((b) => { b.cfg.bannerEnabled = "true"; })],
  ["a tuning key is absent", editBoot((b) => { delete b.cfg.tuning.RETRY_BASE_MS; })],
  ["a tuning value is negative", editBoot((b) => { b.cfg.tuning.EVENT_QUEUE_MAX = -1; })],
  ["a tuning value is fractional", editBoot((b) => { b.cfg.tuning.HEARTBEAT_TTL_MS = 1.5; })],
  [
    "sid is only inherited from a polluted prototype",
    editBoot((b) => { delete b.sid; }),
    () => { Object.prototype.sid = "inherited"; },
  ],
];

for (const [name, rewrite, init] of REFUSALS) {
  test(`refusal: ${name}`, async ({ page }) => {
    if (init) await page.addInitScript(init);
    const { errors } = await serveRewritten(page, rewrite);
    const banner = page.locator("#__ipe-status");
    await expect(banner).toHaveClass(/ipe-status--offline/, { timeout: 10000 });
    await expect(banner).toContainText("Page failed to start");
    const boot = errors.filter((e) => e.message.startsWith("Ipe boot data "));
    expect(boot.length, `an IpeBootError is raised: ${errors.map(String)}`).toBe(1);
    const live = await page.evaluate(() => document.documentElement.getAttribute("data-ipe-live"));
    expect(live).toBeNull();
    const sid = await page.evaluate(() =>
      Object.prototype.hasOwnProperty.call(window, "__IPE_SID"),
    );
    expect(sid).toBe(false);
  });
}

test("decoys: an earlier element with the block's id never stands in for it", async ({
  page,
}) => {
  const decoys =
    '<div id="ipe-boot"></div>' + blockOf({ sid: "decoy", epoch: "decoy", base: "", csrf: "decoy" });
  const { errors, original } = await serveRewritten(page, (html) =>
    html.replace(/<body([^>]*)>/, (open) => open + decoys),
  );
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  expect(errors.map(String)).toEqual([]);
  const sid = await page.evaluate(() => window.__IPE_SID);
  expect(sid).toBe(original.boot.sid);
  expect(sid).not.toBe("decoy");
});

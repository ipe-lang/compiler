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
 *      block's id, never stands in for the block, and an `<img
 *      name="currentScript">` never stands in for the client's own tag: the
 *      page still boots on the server's own values. An app element carrying
 *      the banner's id never hides the boot failure. App elements named after
 *      document members (`<form name="body">`, `<img name="addEventListener">`)
 *      never stand in for those members: the page boots, an event commits,
 *      and its patch lands.
 *   3. Navigation — an `ipe-nav` fetch of a full page splices only that page's
 *      `#ipe-root` contents, never its boot block and scripts.
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
      // The rewritten body has its own length and no encoding: drop the
      // original's framing headers so the browser reads all of it.
      const headers = { ...response.headers() };
      delete headers["content-length"];
      delete headers["content-encoding"];
      await route.fulfill({ response, headers, body: rewrite(html) });
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

// The banner's id on an app element must not hide the refusal.
const missing = REFUSALS[0][1];
REFUSALS.push([
  "the block is missing and an app element carries the banner's id",
  (html) => missing(html).replace(/<body([^>]*)>/, (open) => open + '<div id="__ipe-status"></div>'),
]);

for (const [name, rewrite, init] of REFUSALS) {
  test(`refusal: ${name}`, async ({ page }) => {
    if (init) await page.addInitScript(init);
    const { errors } = await serveRewritten(page, rewrite);
    const banner = page.locator("#__ipe-status.ipe-status--offline");
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

test("decoys: an <img name=currentScript> never stands in for the client's own tag", async ({
  page,
}) => {
  // A complete decoy block right before the image: a client that took the
  // document's `currentScript` property would boot on the decoy's values.
  const { errors, original } = await serveRewritten(page, (html) => {
    const decoy = { ...bootOf(html), sid: "decoy", csrf: "decoy" };
    return html.replace(
      /<body([^>]*)>/,
      (open) => open + blockOf(decoy) + '<img name="currentScript" alt="">',
    );
  });
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  expect(errors.map(String)).toEqual([]);
  const sid = await page.evaluate(() => window.__IPE_SID);
  expect(sid).toBe(original.boot.sid);
  expect(sid).not.toBe("decoy");
});

test("decoys: app elements named after document members never stand in for them", async ({
  page,
}) => {
  // Each named `form`/`img` shadows the document member of its name with
  // itself (an `img` only when it also carries an `id`); a client reading those
  // members off the document would bind its listeners to an image, patch into
  // the form, or throw at boot. They sit beside the root, which a render
  // replaces wholesale.
  const clobbers =
    '<form name="body"></form>' +
    '<img name="activeElement" id="decoy-activeElement" alt="">' +
    '<img name="getElementById" id="decoy-getElementById" alt="">' +
    '<img name="addEventListener" id="decoy-addEventListener" alt="">';
  const { errors } = await serveRewritten(page, (html) =>
    html.replace(/<div id="ipe-root">/, (open) => clobbers + open),
  );
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  const shadowed = await page.evaluate(() => ({
    body: document.body instanceof HTMLFormElement,
    active: document.activeElement instanceof HTMLImageElement,
    byId: document.getElementById instanceof HTMLImageElement,
    on: document.addEventListener instanceof HTMLImageElement,
  }));
  expect(shadowed, "the page's own lookup answers with the app's elements").toEqual({
    body: true,
    active: true,
    byId: true,
    on: true,
  });
  await expect(page.getByText("location: unknown")).toBeVisible();
  await page.getByRole("button", { name: "Locate" }).click();
  await expect(page.getByText(/location: error:/)).toBeVisible({ timeout: 10000 });
  expect(errors.map(String)).toEqual([]);
});

test("navigation: an ipe-nav fetch splices only the fetched page's root", async ({ page }) => {
  await serveRewritten(page, (html) =>
    html.replace("</body>", '<a ipe-nav href="/" id="ipe-e2e-nav">nav</a></body>'),
  );
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  // A marker the splice replaces, so the assertions run after the patch.
  await page.evaluate(() =>
    document.getElementById("ipe-root").insertAdjacentHTML("beforeend", '<i id="ipe-e2e-stale"></i>'),
  );
  await page.locator("#ipe-e2e-nav").click();
  await expect(page.locator("#ipe-e2e-stale")).toHaveCount(0, { timeout: 10000 });
  const counts = await page.evaluate(() => ({
    roots: document.querySelectorAll("#ipe-root").length,
    blocks: document.querySelectorAll("#ipe-root script").length,
    clients: document.querySelectorAll('script[src*="/_ipe/client."]').length,
  }));
  expect(counts).toEqual({ roots: 1, blocks: 0, clients: 1 });
});

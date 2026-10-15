/**
 * Playwright refusal spec: every live page carries a strict
 * `Content-Security-Policy`, and the browser enforces it.
 *
 *   1. Header — every HTML page the app serves carries one policy whose
 *      `script-src` holds no `'unsafe-inline'` and whose `script-src-attr` is
 *      `'none'`. No style directive but `style-src-attr` holds
 *      `'unsafe-inline'`; a session page admits its style elements by the
 *      nonce its markup carries.
 *   2. Refusals — an inline `<script>`, an inline event-handler attribute or
 *      an un-nonced `<style>` injected into the served page never takes
 *      effect, and the browser reports the violation, while the page's own
 *      client still boots.
 *   3. Render history — a full render of another history than the document's
 *      own (or one with no epoch) is never applied: the page reloads once, and
 *      a second such render within the reload window leaves the page as it is
 *      under the out-of-date banner, applying no later update.
 *   4. Patched styles — a style block a patch inserts, and one whose text a
 *      patch replaces, both apply (examples/shapes/web/csp-styles).
 *
 * Each refusal serves the real page, with its own headers, and its HTML
 * rewritten in flight.
 *
 * Prerequisites and local run: see geo-clipboard.spec.mjs.
 */

import { test, expect } from "@playwright/test";

const PORT = process.env.IPE_GEO_CLIPBOARD_PORT ?? "18080";
const BASE = `http://127.0.0.1:${PORT}`;
const STYLES_PORT = process.env.IPE_CSP_STYLES_PORT ?? "18083";
const STYLES = `http://127.0.0.1:${STYLES_PORT}`;
const STALE_BANNER = "Page is out of date \u2014 reload";

/** The sources of `directive` in policy `value`, or `null` when absent. */
function sourcesOf(value, directive) {
  for (const part of value.split(";")) {
    const [name, ...sources] = part.trim().split(/\s+/);
    if (name === directive) return sources;
  }
  return null;
}

for (const path of ["/", "/nope/x"]) {
  test(`header: ${path} carries a strict script policy`, async ({ request }) => {
    const response = await request.get(`${BASE}${path}`);
    const type = response.headers()["content-type"] ?? "";
    test.skip(!type.startsWith("text/html"), `${path} answers ${type}`);
    const policy = response.headers()["content-security-policy"];
    expect(policy, `${path} carries a content-security-policy`).toBeTruthy();
    const scripts = sourcesOf(policy, "script-src");
    expect(scripts, policy).not.toBeNull();
    expect(scripts).toContain("'self'");
    expect(scripts).not.toContain("'unsafe-inline'");
    expect(scripts).not.toContain("'unsafe-eval'");
    expect(sourcesOf(policy, "script-src-attr")).toEqual(["'none'"]);
    expect(sourcesOf(policy, "default-src")).toEqual(["'none'"]);
    for (const directive of ["style-src", "style-src-elem"]) {
      expect(sourcesOf(policy, directive), policy).not.toContain("'unsafe-inline'");
    }
    expect(sourcesOf(policy, "style-src-attr")).toEqual(["'unsafe-inline'"]);
  });
}

test("header: a session page admits its style elements by its markup nonce", async ({
  request,
}) => {
  const response = await request.get(`${STYLES}/`);
  const policy = response.headers()["content-security-policy"] ?? "";
  const html = await response.text();
  for (const directive of ["style-src", "style-src-elem"]) {
    const nonces = (sourcesOf(policy, directive) ?? []).filter((s) => s.startsWith("'nonce-"));
    expect(nonces, policy).toHaveLength(1);
  }
  const header = sourcesOf(policy, "style-src-elem").find((s) => s.startsWith("'nonce-"));
  const markup = [...html.matchAll(/<style[^>]* nonce="([0-9a-f]+)"/g)].map((m) => m[1]);
  expect(markup.length, html).toBeGreaterThan(0);
  for (const nonce of markup) expect(`'nonce-${nonce}'`).toBe(header);
});

/**
 * Serve the page root through `rewrite(html) -> html` with the server's own
 * headers, recording every policy violation the browser reports.
 */
async function serveRewritten(page, rewrite, base = BASE) {
  await page.addInitScript(() => {
    window.__e2eViolations = [];
    document.addEventListener("securitypolicyviolation", (e) => {
      window.__e2eViolations.push(e.effectiveDirective);
    });
  });
  await page.route(
    (url) => url.origin === base && url.pathname === "/",
    async (route) => {
      const response = await route.fetch();
      const html = await response.text();
      const headers = { ...response.headers() };
      delete headers["content-length"];
      delete headers["content-encoding"];
      await route.fulfill({ response, headers, body: rewrite(html) });
    },
  );
  await page.goto(base);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
}

test("refusal: an injected inline script never runs", async ({ page }) => {
  await serveRewritten(page, (html) =>
    html.replace("</body>", "<script>window.__e2eInjected = 1;</script></body>"),
  );
  await expect
    .poll(() => page.evaluate(() => window.__e2eViolations), { timeout: 5000 })
    .toContain("script-src-elem");
  expect(await page.evaluate(() => window.__e2eInjected)).toBeUndefined();
});

test("refusal: an injected inline event handler never runs", async ({ page }) => {
  await serveRewritten(page, (html) =>
    html.replace(
      "</body>",
      '<img src="/_ipe/e2e-missing.png" alt="" onerror="window.__e2eInjected = 1;"></body>',
    ),
  );
  await expect
    .poll(() => page.evaluate(() => window.__e2eViolations), { timeout: 5000 })
    .toContain("script-src-attr");
  expect(await page.evaluate(() => window.__e2eInjected)).toBeUndefined();
});

test("refusal: an injected un-nonced style element never applies", async ({ page }) => {
  await serveRewritten(
    page,
    (html) =>
      html.replace(
        "</body>",
        "<style>#card { outline: 7px solid rgb(1, 2, 3); }</style></body>",
      ),
    STYLES,
  );
  await expect
    .poll(() => page.evaluate(() => window.__e2eViolations), { timeout: 5000 })
    .toContain("style-src-elem");
  const card = page.locator("#card");
  expect(await card.evaluate((el) => getComputedStyle(el).outlineWidth)).not.toBe("7px");
  // The page's own nonced style blocks still apply.
  const own = await page.evaluate(() =>
    [...document.querySelectorAll("style")].some((el) => el.nonce !== "" && el.sheet !== null),
  );
  expect(own).toBe(true);
});

/** A complete SSE body of one `patch` frame carrying `fields`. */
function patchStream(fields) {
  const frame = { seq: 1, body: '<div id="e2e-foreign">foreign render</div>', ...fields };
  return `event: patch\ndata: ${JSON.stringify(frame)}\n\n`;
}

const FOREIGN_EPOCH = `${"0".repeat(31)}1.1`;

/**
 * Open the csp-styles page, answering the first `limit` stream opens with
 * `stream` instead of the live one, and count the document's navigations.
 */
async function openWithStream(page, stream, limit) {
  const loads = { count: 0 };
  page.on("request", (r) => {
    if (r.isNavigationRequest() && r.frame() === page.mainFrame()) loads.count += 1;
  });
  let opens = 0;
  await page.route(
    (url) => url.origin === STYLES && url.pathname === "/_ipe/sse",
    async (route) => {
      opens += 1;
      if (opens > limit) return route.continue();
      return route.fulfill({
        status: 200,
        headers: { "content-type": "text/event-stream", "cache-control": "no-store" },
        body: stream,
      });
    },
  );
  await page.goto(STYLES);
  return loads;
}

for (const [label, fields] of [
  ["another incarnation", { epoch: FOREIGN_EPOCH }],
  ["no epoch", {}],
]) {
  test(`render history: a full render of ${label} reloads once`, async ({ page }) => {
    const loads = await openWithStream(page, patchStream(fields), 1);
    await expect.poll(() => loads.count, { timeout: 15000 }).toBe(2);
    await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
    await page.waitForTimeout(2000);
    expect(loads.count).toBe(2);
    expect(await page.locator("#e2e-foreign").count()).toBe(0);
    expect(await page.locator("#card").count()).toBe(1);
  });
}

test("render history: a second foreign render shows the banner and applies nothing", async ({
  page,
}) => {
  const loads = await openWithStream(page, patchStream({ epoch: FOREIGN_EPOCH }), Infinity);
  await expect.poll(() => loads.count, { timeout: 15000 }).toBe(2);
  const banner = page.locator("#__ipe-status");
  await expect(banner).toContainText(STALE_BANNER, { timeout: 15000 });
  const before = await page.locator("#root").innerHTML();
  await page.locator("#show").click();
  await page.waitForTimeout(2000);
  expect(loads.count).toBe(2);
  expect(await page.locator("#e2e-foreign").count()).toBe(0);
  expect(await page.locator("#styled").count()).toBe(0);
  expect(await page.locator("#root").innerHTML()).toBe(before);
  await expect(banner).toContainText(STALE_BANNER);
});

/** The applied style element whose rules spell `color`: its nonce and mark. */
function styleRuling(color) {
  for (const el of document.querySelectorAll("style")) {
    const rules = el.sheet ? [...el.sheet.cssRules].map((r) => r.cssText).join(" ") : "";
    if (rules.includes(color)) {
      return { nonced: el.nonce.length === 32, mark: el.dataset.e2eMark ?? null };
    }
  }
  return null;
}

/** Mark the applied style element whose rules spell `color`. */
function markRuling(color) {
  for (const el of document.querySelectorAll("style")) {
    const rules = el.sheet ? [...el.sheet.cssRules].map((r) => r.cssText).join(" ") : "";
    if (rules.includes(color)) el.dataset.e2eMark = "inserted";
  }
}

test("patched styles: an inserted and a rewritten style block both apply", async ({ page }) => {
  await page.addInitScript(() => {
    window.__e2eViolations = [];
    document.addEventListener("securitypolicyviolation", (e) => {
      window.__e2eViolations.push(e.effectiveDirective);
    });
  });
  await page.goto(STYLES);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  const red = "rgb(220, 38, 38)";
  const green = "rgb(22, 163, 74)";

  await page.locator("#show").click();
  await page.waitForSelector("#styled", { timeout: 10000 });
  await expect
    .poll(() => page.evaluate(styleRuling, red), { timeout: 5000 })
    .toEqual({ nonced: true, mark: null });
  await page.evaluate(markRuling, red);

  await page.locator("#recolor").click();
  await expect
    .poll(() => page.evaluate(styleRuling, green), { timeout: 10000 })
    .toEqual({ nonced: true, mark: "inserted" });
  expect(await page.evaluate(styleRuling, red)).toBeNull();
  expect(await page.evaluate(() => window.__e2eViolations)).toEqual([]);
});

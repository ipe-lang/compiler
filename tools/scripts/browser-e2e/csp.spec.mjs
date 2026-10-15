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
 *      under the out-of-date banner, applying no later update. A navigation
 *      so answered, or one from a stale document, is a full browser load of
 *      its target. A patches frame either end of which is not an epoch of the
 *      document's history reloads the same way, and patches in an event
 *      answer, which no epoch orders, never apply.
 *   4. Patched styles — a style block a patch inserts, and one whose text a
 *      patch replaces, both apply (examples/shapes/web/csp-styles).
 *   5. Navigation — the URL follows the render on screen: an older answer to a
 *      navigation a later one superseded moves neither the DOM nor the URL,
 *      whichever order the answers arrive in; a popstate answer that applies
 *      after a link's answer names the URL; a render's `data-ipe-path` is one
 *      history entry that Back leaves; and a popstate whose fetch fails or
 *      whose answer is of no history is a full browser load of the entry it
 *      popped, even after a link's answer moved the URL meanwhile, unless the
 *      reader followed a later link. A document gone stale while a link's
 *      answer is pending loads that link, whether the stale document reloads
 *      or its answer lands on it.
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

  // A navigation link of the stale document is left to the browser.
  await page.evaluate(() => {
    const a = document.createElement("a");
    a.id = "e2e-nav";
    a.setAttribute("ipe-nav", "");
    a.href = "/e2e-stale-nav";
    a.textContent = "go";
    document.body.appendChild(a);
  });
  await page.locator("#e2e-nav").click();
  await page.waitForURL(`${STYLES}/e2e-stale-nav`, { timeout: 15000 });
});

test("render history: a navigation answered without an epoch loads its target", async ({
  page,
}) => {
  let navFetches = 0;
  await page.route(
    (url) => url.origin === STYLES && url.pathname === "/e2e-nav",
    async (route) => {
      if (route.request().headers()["x-ipe-nav"] !== "1") return route.continue();
      navFetches += 1;
      return route.fulfill({
        status: 200,
        headers: { "content-type": "text/html", "x-ipe-web": "1" },
        body: '<div id="e2e-foreign">foreign render</div>',
      });
    },
  );
  await serveRewritten(
    page,
    (html) => html.replace("</body>", '<a id="e2e-nav" ipe-nav href="/e2e-nav">go</a></body>'),
    STYLES,
  );
  await page.locator("#e2e-nav").click();
  await page.waitForURL(`${STYLES}/e2e-nav`, { timeout: 15000 });
  expect(navFetches).toBe(1);
  expect(await page.locator("#e2e-foreign").count()).toBe(0);
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

/** A complete SSE body of one `patches` frame carrying `fields`. */
function patchesStream(fields) {
  const frame = { globalSeq: 1, patches: [], ...fields };
  return `event: patches\ndata: ${JSON.stringify(frame)}\n\n`;
}

for (const [label, fields] of [
  ["no `from` and a `to` of another history", { to: FOREIGN_EPOCH }],
  ["a `from` that is no epoch", { from: 7, to: FOREIGN_EPOCH }],
]) {
  test(`render history: a patches frame with ${label} reloads once`, async ({ page }) => {
    const loads = await openWithStream(page, patchesStream(fields), 1);
    await expect.poll(() => loads.count, { timeout: 15000 }).toBe(2);
    await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
    await page.waitForTimeout(2000);
    expect(loads.count).toBe(2);
    expect(await page.locator("#card").count()).toBe(1);
  });
}

/** Open the csp-styles page live; its boot epoch and one of the same history 1000 renders on. */
async function openLive(page) {
  await page.goto(STYLES);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  const boot = await page.evaluate(() => window.__IPE_EPOCH);
  const [inc, n] = boot.split(".");
  return { boot, later: `${inc}.${Number(n) + 1000}` };
}

/** Append an `ipe-nav` link to `path` with id `e2e-link-<name>`. */
async function addNavLink(page, name, path) {
  await page.evaluate(
    ([name, path]) => {
      const a = document.createElement("a");
      a.id = `e2e-link-${name}`;
      a.setAttribute("ipe-nav", "");
      a.href = path;
      a.textContent = name;
      document.body.appendChild(a);
    },
    [name, path],
  );
}

/** A navigation answer at `epoch` whose render is `body`. */
function navAnswer(epoch, body) {
  return {
    status: 200,
    headers: { "content-type": "text/html", "x-ipe-web": "1", "x-ipe-epoch": epoch },
    body,
  };
}

test("render history: patches in an event answer never apply", async ({ page }) => {
  await openLive(page);
  const id = await page.evaluate(() =>
    document.querySelector("#ipe-root [ipe-id]").getAttribute("ipe-id"),
  );
  let answered = 0;
  await page.route(
    (url) => url.origin === STYLES && url.pathname === "/_ipe/event",
    async (route) => {
      answered += 1;
      return route.fulfill({
        status: 200,
        headers: { "content-type": "application/json", "x-ipe-web": "1" },
        body: JSON.stringify({
          seq: 1000000,
          patches: [{ id, html: '<div id="e2e-foreign">foreign patch</div>' }],
        }),
      });
    },
  );
  await page.locator("#show").click();
  await expect.poll(() => answered, { timeout: 10000 }).toBeGreaterThan(0);
  await page.waitForTimeout(1500);
  expect(await page.locator("#e2e-foreign").count()).toBe(0);
});

test("navigation: a superseded navigation's older answer moves neither the DOM nor the URL", async ({
  page,
}) => {
  const { boot, later } = await openLive(page);
  let release;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  await page.route(
    (url) => url.origin === STYLES && ["/e2e-first", "/e2e-second"].includes(url.pathname),
    async (route) => {
      if (route.request().headers()["x-ipe-nav"] !== "1") return route.continue();
      if (new URL(route.request().url()).pathname === "/e2e-first") {
        await held;
        return route.fulfill(navAnswer(boot, '<div id="e2e-foreign">older render</div>'));
      }
      return route.fulfill(navAnswer(later, '<div id="e2e-second">later render</div>'));
    },
  );
  await addNavLink(page, "first", "/e2e-first");
  await addNavLink(page, "second", "/e2e-second");
  await page.locator("#e2e-link-first").click();
  await page.locator("#e2e-link-second").click();
  await page.waitForSelector("#e2e-second", { timeout: 10000 });
  await expect(page).toHaveURL(`${STYLES}/e2e-second`);
  release();
  await page.waitForTimeout(2000);
  await expect(page).toHaveURL(`${STYLES}/e2e-second`);
  expect(await page.locator("#e2e-foreign").count()).toBe(0);
});

test("navigation: a popstate whose fetch fails loads the popped entry", async ({ page }) => {
  const loads = { count: 0 };
  page.on("request", (r) => {
    if (r.isNavigationRequest() && r.frame() === page.mainFrame()) loads.count += 1;
  });
  const { later } = await openLive(page);
  await page.route(
    (url) => url.origin === STYLES && ["/", "/e2e-away"].includes(url.pathname),
    async (route) => {
      if (route.request().headers()["x-ipe-nav"] !== "1") return route.continue();
      if (new URL(route.request().url()).pathname === "/") return route.abort();
      return route.fulfill(navAnswer(later, '<div id="e2e-away">away</div>'));
    },
  );
  await addNavLink(page, "away", "/e2e-away");
  await page.locator("#e2e-link-away").click();
  await page.waitForSelector("#e2e-away", { timeout: 10000 });
  await expect(page).toHaveURL(`${STYLES}/e2e-away`);
  expect(loads.count).toBe(1);
  await page.evaluate(() => history.back());
  await expect.poll(() => loads.count, { timeout: 15000 }).toBe(2);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  await expect(page).toHaveURL(`${STYLES}/`);
  expect(await page.locator("#e2e-away").count()).toBe(0);
});

/** A promise and the function that resolves it. */
function gate() {
  let open;
  const shut = new Promise((resolve) => {
    open = resolve;
  });
  return { shut, open };
}

test("navigation: a popstate answer applied after a link's answer names the URL", async ({
  page,
}) => {
  const { later } = await openLive(page);
  const [inc, n] = later.split(".");
  const at = (k) => `${inc}.${Number(n) + k}`;
  const link = gate();
  const home = gate();
  await page.route(
    (url) => url.origin === STYLES && ["/", "/e2e-away", "/e2e-link"].includes(url.pathname),
    async (route) => {
      if (route.request().headers()["x-ipe-nav"] !== "1") return route.continue();
      const path = new URL(route.request().url()).pathname;
      if (path === "/e2e-away") {
        return route.fulfill(navAnswer(later, '<div id="e2e-away">away</div>'));
      }
      if (path === "/e2e-link") {
        await link.shut;
        return route.fulfill(navAnswer(at(1), '<div id="e2e-link">link</div>'));
      }
      await home.shut;
      return route.fulfill(navAnswer(at(2), '<div id="e2e-home">home</div>'));
    },
  );
  await addNavLink(page, "away", "/e2e-away");
  await page.locator("#e2e-link-away").click();
  await page.waitForSelector("#e2e-away", { timeout: 10000 });
  await expect(page).toHaveURL(`${STYLES}/e2e-away`);
  await addNavLink(page, "link", "/e2e-link");
  await page.locator("#e2e-link-link").click();
  await page.evaluate(() => history.back());
  await expect(page).toHaveURL(`${STYLES}/`);
  link.open();
  await page.waitForSelector("#e2e-link", { timeout: 10000 });
  home.open();
  await page.waitForSelector("#e2e-home", { timeout: 10000 });
  await page.waitForTimeout(1000);
  await expect(page).toHaveURL(`${STYLES}/`);
  expect(await page.locator("#e2e-link").count()).toBe(0);
});

test("navigation: an answer older than one already applied leaves the URL on the applied one", async ({
  page,
}) => {
  const { later } = await openLive(page);
  const [inc, n] = later.split(".");
  const at = (k) => `${inc}.${Number(n) + k}`;
  const first = gate();
  const second = gate();
  let answered = 0;
  await page.route(
    (url) => url.origin === STYLES && ["/e2e-first", "/e2e-second"].includes(url.pathname),
    async (route) => {
      if (route.request().headers()["x-ipe-nav"] !== "1") return route.continue();
      // The driver entered the second route before the first, so the first
      // answer is the newer render.
      if (new URL(route.request().url()).pathname === "/e2e-first") {
        await first.shut;
        await route.fulfill(navAnswer(at(2), '<div id="e2e-first">first</div>'));
      } else {
        await second.shut;
        await route.fulfill(navAnswer(at(1), '<div id="e2e-second">second</div>'));
      }
      answered += 1;
    },
  );
  await addNavLink(page, "first", "/e2e-first");
  await addNavLink(page, "second", "/e2e-second");
  await page.locator("#e2e-link-first").click();
  await page.locator("#e2e-link-second").click();
  first.open();
  await page.waitForSelector("#e2e-first", { timeout: 10000 });
  await expect(page).toHaveURL(`${STYLES}/e2e-first`);
  second.open();
  await expect.poll(() => answered, { timeout: 10000 }).toBe(2);
  await page.waitForTimeout(1000);
  await expect(page).toHaveURL(`${STYLES}/e2e-first`);
  expect(await page.locator("#e2e-first").count()).toBe(1);
  expect(await page.locator("#e2e-second").count()).toBe(0);
});

test("navigation: a render's data-ipe-path is one history entry, and Back leaves it", async ({
  page,
}) => {
  const { later } = await openLive(page);
  const [inc, n] = later.split(".");
  const at = (k) => `${inc}.${Number(n) + k}`;
  await page.route(
    (url) => url.origin === STYLES && ["/", "/e2e-path"].includes(url.pathname),
    async (route) => {
      if (route.request().headers()["x-ipe-nav"] !== "1") return route.continue();
      if (new URL(route.request().url()).pathname === "/e2e-path") {
        return route.fulfill(
          navAnswer(at(1), '<div id="e2e-path" data-ipe-path="/e2e-path">path</div>'),
        );
      }
      return route.fulfill(navAnswer(at(2), '<div id="e2e-home">home</div>'));
    },
  );
  await addNavLink(page, "path", "/e2e-path");
  await page.locator("#e2e-link-path").click();
  await page.waitForSelector("#e2e-path", { timeout: 10000 });
  await expect(page).toHaveURL(`${STYLES}/e2e-path`);
  await page.evaluate(() => history.back());
  await page.waitForSelector("#e2e-home", { timeout: 10000 });
  await expect(page).toHaveURL(`${STYLES}/`);
  expect(await page.locator("#e2e-path").count()).toBe(0);
});

test("navigation: a popstate answer of no history loads the popped entry", async ({ page }) => {
  const loads = { count: 0 };
  page.on("request", (r) => {
    if (r.isNavigationRequest() && r.frame() === page.mainFrame()) loads.count += 1;
  });
  const { later } = await openLive(page);
  await page.route(
    (url) => url.origin === STYLES && ["/", "/e2e-away"].includes(url.pathname),
    async (route) => {
      if (route.request().headers()["x-ipe-nav"] !== "1") return route.continue();
      if (new URL(route.request().url()).pathname === "/") {
        return route.fulfill({
          status: 200,
          headers: { "content-type": "text/html", "x-ipe-web": "1" },
          body: '<div id="e2e-unstamped">no history</div>',
        });
      }
      return route.fulfill(navAnswer(later, '<div id="e2e-away">away</div>'));
    },
  );
  await addNavLink(page, "away", "/e2e-away");
  await page.locator("#e2e-link-away").click();
  await page.waitForSelector("#e2e-away", { timeout: 10000 });
  expect(loads.count).toBe(1);
  // A stale-document reload within its window is refused, so only the
  // popstate's own load can reach the entry.
  await page.evaluate(() => sessionStorage.setItem("__ipe_inc_reload", String(Date.now())));
  await page.evaluate(() => history.back());
  await expect.poll(() => loads.count, { timeout: 15000 }).toBe(2);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  await expect(page).toHaveURL(`${STYLES}/`);
  expect(await page.locator("#e2e-unstamped").count()).toBe(0);
  expect(await page.locator("#e2e-away").count()).toBe(0);
});

test("navigation: a popstate whose fetch fails after a link's answer moved the URL loads the popped entry", async ({
  page,
}) => {
  const loads = { count: 0 };
  page.on("request", (r) => {
    if (r.isNavigationRequest() && r.frame() === page.mainFrame()) loads.count += 1;
  });
  const { later } = await openLive(page);
  const [inc, n] = later.split(".");
  const at = (k) => `${inc}.${Number(n) + k}`;
  const link = gate();
  const home = gate();
  await page.route(
    (url) => url.origin === STYLES && ["/", "/e2e-away", "/e2e-link"].includes(url.pathname),
    async (route) => {
      if (route.request().headers()["x-ipe-nav"] !== "1") return route.continue();
      const path = new URL(route.request().url()).pathname;
      if (path === "/e2e-away") {
        return route.fulfill(navAnswer(later, '<div id="e2e-away">away</div>'));
      }
      if (path === "/e2e-link") {
        await link.shut;
        return route.fulfill(navAnswer(at(1), '<div id="e2e-link">link</div>'));
      }
      await home.shut;
      return route.abort();
    },
  );
  await addNavLink(page, "away", "/e2e-away");
  await page.locator("#e2e-link-away").click();
  await page.waitForSelector("#e2e-away", { timeout: 10000 });
  await addNavLink(page, "link", "/e2e-link");
  await page.locator("#e2e-link-link").click();
  await page.evaluate(() => history.back());
  await expect(page).toHaveURL(`${STYLES}/`);
  // The link's answer lands while the popped entry's fetch is pending: it
  // applies and records its URL.
  link.open();
  await page.waitForSelector("#e2e-link", { timeout: 10000 });
  await expect(page).toHaveURL(`${STYLES}/e2e-link`);
  expect(loads.count).toBe(1);
  home.open();
  await expect.poll(() => loads.count, { timeout: 15000 }).toBe(2);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  await expect(page).toHaveURL(`${STYLES}/`);
  expect(await page.locator("#e2e-link").count()).toBe(0);
});

test("navigation: a popstate whose fetch fails after a later link's answer loads nothing", async ({
  page,
}) => {
  const loads = { count: 0 };
  page.on("request", (r) => {
    if (r.isNavigationRequest() && r.frame() === page.mainFrame()) loads.count += 1;
  });
  const { later } = await openLive(page);
  const [inc, n] = later.split(".");
  const at = (k) => `${inc}.${Number(n) + k}`;
  const home = gate();
  await page.route(
    (url) => url.origin === STYLES && ["/", "/e2e-away", "/e2e-link"].includes(url.pathname),
    async (route) => {
      if (route.request().headers()["x-ipe-nav"] !== "1") return route.continue();
      const path = new URL(route.request().url()).pathname;
      if (path === "/e2e-away") {
        return route.fulfill(navAnswer(later, '<div id="e2e-away">away</div>'));
      }
      if (path === "/e2e-link") {
        return route.fulfill(navAnswer(at(1), '<div id="e2e-link">link</div>'));
      }
      await home.shut;
      return route.abort();
    },
  );
  await addNavLink(page, "away", "/e2e-away");
  await addNavLink(page, "link", "/e2e-link");
  await page.locator("#e2e-link-away").click();
  await page.waitForSelector("#e2e-away", { timeout: 10000 });
  await page.evaluate(() => history.back());
  await expect(page).toHaveURL(`${STYLES}/`);
  // The reader follows a link while the popped entry's fetch is pending: that
  // later navigation owns the location.
  await page.locator("#e2e-link-link").click();
  await page.waitForSelector("#e2e-link", { timeout: 10000 });
  await expect(page).toHaveURL(`${STYLES}/e2e-link`);
  home.open();
  await page.waitForTimeout(2000);
  expect(loads.count).toBe(1);
  await expect(page).toHaveURL(`${STYLES}/e2e-link`);
  expect(await page.locator("#e2e-link").count()).toBe(1);
});

/**
 * Open the csp-styles page with its first stream open held until `foreign`
 * opens, then answered with a full render of another incarnation; later opens
 * are the live stream. Resolves once the client has booted.
 */
async function openWithHeldForeignStream(page) {
  const foreign = gate();
  let opens = 0;
  await page.route(
    (url) => url.origin === STYLES && url.pathname === "/_ipe/sse",
    async (route) => {
      opens += 1;
      if (opens > 1) return route.continue();
      await foreign.shut;
      return route
        .fulfill({
          status: 200,
          headers: { "content-type": "text/event-stream", "cache-control": "no-store" },
          body: patchStream({ epoch: FOREIGN_EPOCH }),
        })
        .catch(() => {});
    },
  );
  await page.goto(STYLES);
  await page.waitForFunction(() => typeof window.__IPE_EPOCH === "string", null, {
    timeout: 15000,
  });
  const boot = await page.evaluate(() => window.__IPE_EPOCH);
  return { foreign, boot };
}

/** Answer `/e2e-pending` navigation fetches with `body()` once `answer` opens. */
async function holdPendingNav(page, answer, body) {
  await page.route(
    (url) => url.origin === STYLES && url.pathname === "/e2e-pending",
    async (route) => {
      if (route.request().headers()["x-ipe-nav"] !== "1") return route.continue();
      await answer.shut;
      return route.fulfill(body()).catch(() => {});
    },
  );
}

test("render history: a document gone stale while a link's answer is pending loads the link", async ({
  page,
}) => {
  const { foreign } = await openWithHeldForeignStream(page);
  const answer = gate();
  await holdPendingNav(page, answer, () => ({ status: 503, body: "" }));
  await addNavLink(page, "pending", "/e2e-pending");
  await page.locator("#e2e-link-pending").click();
  foreign.open();
  await page.waitForURL(`${STYLES}/e2e-pending`, { timeout: 15000 });
  answer.open();
});

test("render history: a link's answer landing on a stale document loads the link", async ({
  page,
}) => {
  const { foreign, boot } = await openWithHeldForeignStream(page);
  const [inc, n] = boot.split(".");
  const answer = gate();
  await holdPendingNav(page, answer, () =>
    navAnswer(`${inc}.${Number(n) + 1000}`, '<div id="e2e-pending">pending</div>'),
  );
  await addNavLink(page, "pending", "/e2e-pending");
  // A stale-document reload within its window is refused, so the document
  // stays, stale, under the banner.
  await page.evaluate(() => sessionStorage.setItem("__ipe_inc_reload", String(Date.now())));
  await page.locator("#e2e-link-pending").click();
  foreign.open();
  await expect(page.locator("#__ipe-status")).toContainText(STALE_BANNER, { timeout: 15000 });
  await expect(page).toHaveURL(`${STYLES}/`);
  answer.open();
  await page.waitForURL(`${STYLES}/e2e-pending`, { timeout: 15000 });
  expect(await page.locator("#e2e-pending").count()).toBe(0);
});

test("render history: a document gone stale while a link to its own fragment is pending reloads", async ({
  page,
}) => {
  const loads = { count: 0 };
  page.on("request", (r) => {
    if (r.isNavigationRequest() && r.frame() === page.mainFrame()) loads.count += 1;
  });
  const { foreign } = await openWithHeldForeignStream(page);
  const answer = gate();
  await page.route(
    (url) => url.origin === STYLES && url.pathname === "/",
    async (route) => {
      if (route.request().headers()["x-ipe-nav"] !== "1") return route.continue();
      await answer.shut;
      return route.fulfill({ status: 503, body: "" }).catch(() => {});
    },
  );
  await addNavLink(page, "frag", "/#e2e-frag");
  await page.locator("#e2e-link-frag").click();
  // Assigning `/#e2e-frag` from `/` is a fragment navigation: it would load
  // nothing, leaving a stale document with no banner.
  foreign.open();
  await expect.poll(() => loads.count, { timeout: 15000 }).toBe(2);
  answer.open();
});

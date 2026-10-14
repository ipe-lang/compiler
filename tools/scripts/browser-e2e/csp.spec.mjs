/**
 * Playwright refusal spec: every live page carries a strict
 * `Content-Security-Policy`, and the browser enforces it.
 *
 *   1. Header — every HTML page the app serves carries one policy whose
 *      `script-src` holds no `'unsafe-inline'` and whose `script-src-attr` is
 *      `'none'`.
 *   2. Refusals — an inline `<script>` or an inline event-handler attribute
 *      injected into the served page never runs, and the browser reports the
 *      violation, while the page's own client still boots.
 *
 * Each refusal serves the real page, with its own headers, and its HTML
 * rewritten in flight.
 *
 * Prerequisites and local run: see geo-clipboard.spec.mjs.
 */

import { test, expect } from "@playwright/test";

const PORT = process.env.IPE_GEO_CLIPBOARD_PORT ?? "18080";
const BASE = `http://127.0.0.1:${PORT}`;

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
  });
}

/**
 * Serve the page root through `rewrite(html) -> html` with the server's own
 * headers, recording every policy violation the browser reports.
 */
async function serveRewritten(page, rewrite) {
  await page.addInitScript(() => {
    window.__e2eViolations = [];
    document.addEventListener("securitypolicyviolation", (e) => {
      window.__e2eViolations.push(e.effectiveDirective);
    });
  });
  await page.route(
    (url) => url.origin === BASE && url.pathname === "/",
    async (route) => {
      const response = await route.fetch();
      const html = await response.text();
      const headers = { ...response.headers() };
      delete headers["content-length"];
      delete headers["content-encoding"];
      await route.fulfill({ response, headers, body: rewrite(html) });
    },
  );
  await page.goto(BASE);
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

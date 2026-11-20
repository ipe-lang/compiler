/**
 * Waits until the routes registered on a page that has already loaded catch
 * the page's own requests.
 *
 * Chromium hands an interception that starts after a document loaded to that
 * document's renderer asynchronously: `page.route` and `context.route` return
 * before the renderer takes it, and a request the page issues in between
 * reaches the server untouched. A route registered before `goto` has no such
 * window. After this returns, every later request of the page's main frame is
 * routed, since a renderer never drops an interception it has taken.
 */

import { expect } from "@playwright/test";

const PROBE = "/_ipe/__e2e-route-probe";
const MARK = "x-e2e-route-probe";

export async function untilRoutesLive(page) {
  await page.route(`**${PROBE}`, (route) => route.fulfill({ status: 204, headers: { [MARK]: "1" } }));
  await expect
    .poll(
      () =>
        page.evaluate(
          ([path, mark]) =>
            fetch(path, { cache: "no-store" }).then(
              (r) => r.headers.get(mark) === "1",
              () => false,
            ),
          [PROBE, MARK],
        ),
      { timeout: 10000 },
    )
    .toBe(true);
}

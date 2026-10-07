/**
 * Playwright refusal spec: a form's named controls never stand in for its members.
 *
 * A form element answers a property read with its control of that name, so
 * `<input name="addEventListener">` shadows `form.addEventListener` and
 * `<input name="elements">` shadows `form.elements`. The client reads every
 * form member it needs through the element prototypes, keeps its "already
 * bound" marks beside the elements, and prevents a bound submit before reading
 * anything: a submit is always the client's to send, never the browser's,
 * whose native GET would carry every field, a password included, in the URL.
 *
 * For each member name, a bound form carrying a control of that name is
 * submitted: the client posts the form's fields as an event, the browser never
 * navigates to the form's action, and the page raises no error.
 *
 * Runs against the geo-clipboard example. Prerequisites and local run: see
 * geo-clipboard.spec.mjs.
 */

import { test, expect } from "@playwright/test";

const PORT = process.env.IPE_GEO_CLIPBOARD_PORT ?? "18080";
const BASE = `http://127.0.0.1:${PORT}`;
const NATIVE = "/e2e-native-submit";

for (const name of ["addEventListener", "getAttribute", "__ipe_submit", "elements", "contains"]) {
  test(`a control named ${name} never breaks the bound submit`, async ({ page }) => {
    const errors = [];
    const native = [];
    page.on("pageerror", (e) => errors.push(e));
    page.on("request", (r) => {
      if (new URL(r.url()).pathname === NATIVE) native.push(r.url());
    });
    await page.route(
      (url) => url.origin === BASE && url.pathname === NATIVE,
      (route) => route.fulfill({ status: 200, contentType: "text/html", body: "native" }),
    );
    await page.goto(BASE);
    await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
    const start = page.url();

    // The form joins the page after boot, as a patch would add it; binding
    // it must not throw whatever its controls are named.
    const bound = await page.evaluate((control) => {
      document.getElementById("ipe-root").insertAdjacentHTML(
        "beforeend",
        '<form id="ipe-e2e-form" ipe-submit="e2e-submit" action="/e2e-native-submit" method="get">' +
          '<input name="secret" type="password" value="hunter2">' +
          `<input name="${control}" value="shadow">` +
          '<button type="submit" id="ipe-e2e-go">Go</button></form>',
      );
      try {
        window.__ipeBindEvents();
        return "ok";
      } catch (e) {
        return String(e);
      }
    }, name);
    expect(bound).toBe("ok");

    const posted = page.waitForRequest(
      (r) => r.method() === "POST" && new URL(r.url()).pathname === "/_ipe/event",
      { timeout: 5000 },
    );
    await page.locator("#ipe-e2e-go").click();
    const body = JSON.parse((await posted).postData() ?? "null");
    expect(body?.msg).toBe("e2e-submit");
    expect(body.args).toEqual([expect.objectContaining({ secret: "hunter2", [name]: "shadow" })]);

    await page.waitForTimeout(500);
    expect(native).toEqual([]);
    expect(page.url()).toBe(start);
    expect(errors.map(String)).toEqual([]);
  });
}

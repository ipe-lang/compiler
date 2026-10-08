/**
 * Playwright refusal spec: a patch never moves keyboard focus.
 *
 * The client rewrites the children of the container a patch targets. A focused
 * node inside it is dropped by that rewrite, and focus falls to `body`, where
 * a key handler bound on an ancestor no longer receives keys. The client
 * records the focused node's position and the server identity (`ipe-id`) of
 * it and of each ancestor at its depth, puts focus back on the nearest node on
 * that path whose whole chain from the container carries the identities and
 * tags recorded for each depth once the swap lands, else on its nearest
 * focusable ancestor, and never reads or writes
 * focus that sits outside the swapped container.
 *
 * The first mount focuses the root's `autofocus` only while the load's own
 * autofocus is still due; a later frame only puts lost focus back. A form's
 * named controls shadow its members, so every member read on a node that may
 * be a form goes through the element prototypes: one test per read proves it.
 *
 * No test sets focus from the page: focus moves by a real pointer click or a
 * key press. A key reaches the root's handler only while focus is below the
 * root, so a `keys: j` line proves focus survived the patch. A read no
 * fixture event reaches (the namespace the form's content is parsed in, a
 * script revived inside the form, a full re-render) is driven by calling the
 * client's own function from the page.
 *
 * Runs against the focus-across-patch example. Prerequisites and local run:
 * see geo-clipboard.spec.mjs.
 */

import { test, expect } from "@playwright/test";

const PORT = process.env.IPE_FOCUS_ACROSS_PATCH_PORT ?? "18082";
const BASE = `http://127.0.0.1:${PORT}`;

/** The id of the focused element, "" when focus is on `body`. */
const focusedId = (page) => page.evaluate(() => document.activeElement?.id ?? "");

async function open(page) {
  await page.goto(BASE);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
}

/**
 * Leaves the first-mount focus to the client alone. Every server-rendered node
 * stays unfocusable until the client script tag is parsed: an observer strips
 * `tabindex` from each added element, and its callbacks run as microtasks,
 * ahead of the rendering step where Chrome focuses an `autofocus` candidate.
 * Each scripted `focus()` is recorded, since Chrome may still focus the
 * patched root natively once it is inserted; the client focuses it in the same
 * task as the insertion, before that rendering step.
 */
function clientOwnsFirstFocus() {
  const focus = HTMLElement.prototype.focus;
  window.__testFocusCalls = [];
  HTMLElement.prototype.focus = function (...args) {
    window.__testFocusCalls.push(this.id);
    return focus.apply(this, args);
  };
  const client = /\/_ipe\/client\.[0-9a-f]+\.js$/;
  const observer = new MutationObserver((records) => {
    for (const record of records) {
      for (const node of record.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        if (node.tagName === "SCRIPT" && client.test(node.getAttribute("src") ?? "")) {
          observer.disconnect();
          return;
        }
        node.removeAttribute("tabindex");
        for (const inner of node.querySelectorAll("[tabindex]")) inner.removeAttribute("tabindex");
      }
    }
  });
  observer.observe(document, { childList: true, subtree: true });
}

test("focus-across-patch: first mount focuses autofocus root", async ({ page }) => {
  await page.addInitScript(clientOwnsFirstFocus);
  await open(page);
  await expect.poll(() => focusedId(page)).toBe("root");
  // The client, not the browser's own autofocus, focused the root.
  expect(await page.evaluate(() => window.__testFocusCalls)).toContain("root");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

test("focus-across-patch: button click keeps keys alive", async ({ page }) => {
  await open(page);
  await page.click("#add");
  // The panel gained a row: its children were swapped around the button.
  await expect(page.locator("#row")).toHaveCount(1);
  await expect.poll(() => focusedId(page)).toBe("add");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

test("focus-across-patch: removed focused node falls back to ancestor", async ({ page }) => {
  await open(page);
  await page.click("#drop");
  // The clicked button is gone from the swapped panel.
  await expect(page.locator("#drop")).toHaveCount(0);
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

test("focus-across-patch: another control at the focused position never takes focus", async ({ page }) => {
  await open(page);
  await page.click("#swap");
  // The clicked button's position now holds a different focusable control.
  await expect(page.locator("#swapped")).toHaveCount(1);
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

test("focus-across-patch: typing survives patch", async ({ page }) => {
  await open(page);
  // A compound selector: matching a descendant combinator walks `parentElement`
  // from every input, including those in the shadowing form below.
  const field = page.locator("input#note");
  await field.click();
  await page.keyboard.type("hello");
  // Let the debounced input event settle before the patch under test.
  await page.waitForTimeout(500);
  await page.keyboard.press("ArrowLeft");
  await page.keyboard.press("ArrowLeft");
  // Escape toggles the panel's row, which swaps the panel around the field.
  await page.keyboard.press("Escape");
  await expect(page.locator("#row")).toHaveCount(1);
  await expect(field).toBeFocused();
  await expect(field).toHaveValue("hello");
  expect(await field.evaluate((el) => [el.selectionStart, el.selectionEnd])).toEqual([3, 3]);
  // Typing continues at the caret in the same node.
  await page.keyboard.type("X");
  await expect(field).toHaveValue("helXlo");
});

test("focus-across-patch: no focus theft into body-level", async ({ page }) => {
  await open(page);
  await page.evaluate(() => {
    document.body.insertAdjacentHTML("beforeend", '<input id="outside" aria-label="outside">');
    // A pressed button takes focus; this one does not, so the click below
    // patches the tree while focus stays on the outside field.
    document.getElementById("add").addEventListener("mousedown", (e) => e.preventDefault());
  });
  await page.click("#outside");
  expect(await focusedId(page)).toBe("outside");
  await page.click("#add");
  await expect(page.locator("#row")).toHaveCount(1);
  expect(await focusedId(page)).toBe("outside");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText(/^keys:\s*$/);
});

test("focus-across-patch: a node whose key spells a former descendant identity never takes focus", async ({ page }) => {
  await open(page);
  await page.click("#kbutton");
  // The keyed item now has key `k_0_button`: its `ipe-id` is the one the
  // clicked button held one level lower, and it is focusable.
  await expect(page.locator("#ktail")).toHaveCount(1);
  await expect(page.locator("#kspoof")).toHaveCount(1);
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

/**
 * Clicks the centre of `selector` by coordinates. Playwright's own
 * actionability checks walk `parentElement` and read other members up from the
 * target, and the shadowing form's controls answer those reads on the form, so
 * every pointer action at or inside that form is driven this way.
 */
async function clickAt(page, selector) {
  const box = await page.locator(selector).boundingBox();
  expect(box).not.toBeNull();
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
}

/** The value of the field with `id`, read without the form's members. */
const valueOf = (page, id) => page.evaluate((x) => document.getElementById(x).value, id);

/** Every uncaught page error from here on. */
function pageErrors(page) {
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  return errors;
}

// The tests below each drive one read the client makes on a node that may be
// the shadowing form. A read that reverted to the form's own lookup would get
// the control of that name: a method call throws, an accessor answers with a
// node that is not the one asked for. Each test names the reads it proves.

test("focus-across-patch: a form whose controls shadow DOM members keeps its fields across a patch", async ({ page }) => {
  // Container reads on the form: `contains`, `querySelectorAll`, `firstChild`,
  // `removeChild`, `appendChild`. Each reverted one throws (`firstChild` names
  // a nested control, which `removeChild` refuses as not a child; the first
  // appended child holds the `appendChild` control, so the second append reads
  // it), the patch stops, and the form never gains its row.
  await open(page);
  await clickAt(page, "#typed");
  await page.keyboard.type("abc");
  // Let the debounced input event settle before the patch under test.
  await page.waitForTimeout(500);
  // Escape adds the form's row, which swaps the form's children around the field.
  await page.keyboard.press("Escape");
  await expect(page.locator("#formrow")).toHaveCount(1);
  expect(await focusedId(page)).toBe("typed");
  expect(await valueOf(page, "typed")).toBe("abc");
  await page.keyboard.type("X");
  expect(await valueOf(page, "typed")).toBe("abcX");
});

test("focus-across-patch: focus inside a form survives a swap of the form's parent", async ({ page }) => {
  // Reads on the form as an ancestor of the focused node: `getAttribute`
  // (reverted, it throws before the swap and the row never lands), `tagName`
  // (the recorded tag no longer matches and focus falls past the form),
  // `previousElementSibling` (the form's index counts the control's siblings,
  // so the path leaves the container), `firstElementChild` (the walk down
  // stops at the form, which takes focus). `replaceChild` on the new form: its
  // field is spliced into it, and reverted that throws.
  await open(page);
  await clickAt(page, "#fgrow");
  expect(await focusedId(page)).toBe("fgrow");
  await expect(page.locator("#hostrow")).toHaveCount(1);
  await expect.poll(() => focusedId(page)).toBe("fgrow");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

test("focus-across-patch: focus after a form survives a swap of the form's parent", async ({ page }) => {
  // Reads on the form as a sibling on the focused path: `previousElementSibling`
  // while counting the focused node's index, and `nextElementSibling` while
  // walking back down to it. Reverted, either one lands on another node and
  // focus falls back to the root.
  await open(page);
  await page.click("#nfocus");
  expect(await focusedId(page)).toBe("nfocus");
  await expect(page.locator("#hostrow")).toHaveCount(1);
  await expect.poll(() => focusedId(page)).toBe("nfocus");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

test("focus-across-patch: a focusable form takes focus back when its focused control leaves", async ({ page }) => {
  // `setAttribute` and `removeAttribute` on the form (its attributes change
  // with the control): reverted, either throws and the control stays.
  // `focus` on the form: reverted, the call throws, the form never takes focus
  // and focus falls past it to the root. `getAttribute` on the form as it loses
  // focus: reverted, the focusout handler throws.
  const errors = pageErrors(page);
  await open(page);
  await clickAt(page, "#fdrop");
  await expect(page.locator("#fdrop")).toHaveCount(0);
  expect(
    await page.evaluate(() => {
      const form = document.getElementById("form");
      return [form.hasAttribute("data-drop"), Element.prototype.getAttribute.call(form, "data-dropped")];
    }),
  ).toEqual([false, "yes"]);
  await expect.poll(() => focusedId(page)).toBe("form");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
  // Focus leaves the form for the root, the nearest focusable node above `#keys`.
  await page.click("#keys");
  expect(await focusedId(page)).toBe("root");
  expect(errors).toEqual([]);
});

test("focus-across-patch: a click inside a form whose control is named parentElement completes", async ({ page }) => {
  await open(page);
  // The click handler walks up from the target to find a link; through the
  // form, `parentElement` is the `parentElement` control, whose parent is the
  // form again, so a reverted read loops.
  await clickAt(page, "#formlabel");
  // The click focused the form, the nearest focusable node above the label.
  await expect.poll(() => focusedId(page)).toBe("form");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

test("focus-across-patch: a click whose target is the form completes", async ({ page }) => {
  // `closest` on the click target, which is the form itself: reverted, the
  // capture-phase handler throws.
  const errors = pageErrors(page);
  await open(page);
  await page.evaluate(() => HTMLElement.prototype.click.call(document.getElementById("form")));
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
  expect(errors).toEqual([]);
});

test("focus-across-patch: a form's content is parsed in the HTML namespace", async ({ page }) => {
  // `namespaceURI` on the form: reverted, the control is a namespace that is
  // not HTML's, and the markup is parsed as foreign content into a fragment.
  await open(page);
  const holder = await page.evaluate(() => {
    const t = __ipeParseFor(document.getElementById("form"), "<i>x</i>");
    return t instanceof Element ? t.tagName : "fragment";
  });
  expect(holder).toBe("DIV");
});

test("focus-across-patch: a script inside a form is revived", async ({ page }) => {
  // `replaceChild` on the script's parent, the form: reverted, it throws.
  await open(page);
  const revived = await page.evaluate(() => {
    const form = document.getElementById("form");
    const holder = document.createElement("template");
    holder.innerHTML = '<script src="/_ipe/e2e-absent.js"></script>';
    const old = holder.content.firstChild;
    Node.prototype.appendChild.call(form, old);
    __ipeReviveScripts(document.getElementById("ipe-root"));
    const fresh = Element.prototype.querySelector.call(form, "script");
    return [old.isConnected, fresh !== null && fresh !== old && fresh.hasAttribute("data-ipe-script-revived")];
  });
  expect(revived).toEqual([false, true]);
});

test("focus-across-patch: a node whose own id matches under a different chain never takes focus", async ({ page }) => {
  await open(page);
  await page.click("#xdeep");
  // The column gained a sibling: its items were swapped. `#ydeep` sits at the
  // clicked node's path with its id and tag; the item above it does not match.
  await expect(page.locator("#deeptail")).toHaveCount(1);
  await expect(page.locator("#ydeep")).toHaveCount(1);
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

test("focus-across-patch: a node with the focused id under another tag never takes focus", async ({ page }) => {
  await open(page);
  await page.click("#tbutton");
  // A `button:x` element now holds the id the `button` named `x` held.
  await expect(page.locator("#tspoof")).toHaveCount(1);
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
});

test("focus-across-patch: a fragment target keeps the first mount from autofocusing", async ({ page }) => {
  // The browser skips autofocus when the URL names a target element; so does
  // the client's first mount.
  await page.addInitScript(clientOwnsFirstFocus);
  await page.goto(`${BASE}/#keys`);
  await page.waitForSelector('html[data-ipe-live="1"]', { timeout: 15000 });
  await expect.poll(() => page.evaluate(() => window.__ipeMounted === true)).toBe(true);
  expect(await page.evaluate(() => window.__testFocusCalls)).not.toContain("root");
  expect(await focusedId(page)).toBe("");
});

test("focus-across-patch: a full re-render after the user acted never autofocuses", async ({ page }) => {
  await open(page);
  await page.evaluate(() => {
    document.body.insertAdjacentHTML("beforeend", '<div id="blank">blank</div>');
  });
  // A click on a node that takes no focus leaves focus on `body`.
  await page.click("#blank");
  expect(await focusedId(page)).toBe("");
  // A full-page patch the client has not yet counted as its first mount.
  await page.evaluate(() => {
    window.__ipeMounted = false;
    __ipePatch(document.getElementById("ipe-root").innerHTML);
  });
  expect(await focusedId(page)).toBe("");
});

test("focus-across-patch: a DOM member the browser lacks never stops the client", async ({ page }) => {
  // The client reads `nextElementSibling` only while putting focus back, and
  // `createRange` only to parse foreign (SVG, MathML) content.
  await page.addInitScript(() => {
    delete Element.prototype.nextElementSibling;
    delete Document.prototype.createRange;
  });
  await open(page);
  await page.keyboard.press("j");
  await expect
    .poll(() => page.evaluate(() => document.getElementById("keys").textContent))
    .toBe("keys: j");
});

test("focus-across-patch: a focused MathML element keeps focus across a patch", async ({ page }) => {
  await open(page);
  await page.click("#mfocus");
  expect(await focusedId(page)).toBe("mfocus");
  // `m` adds a row beside the element: its parent's children are swapped.
  await page.keyboard.press("m");
  await expect(page.locator("#mathrow")).toHaveCount(1);
  await expect.poll(() => focusedId(page)).toBe("mfocus");
});

test("focus-across-patch: a field whose name needs CSS escaping keeps its value across a patch", async ({ page }) => {
  // The field's `name` holds a backslash and a newline. Escape puts a row
  // ahead of it, so its `ipe-id` changes and the swap finds its slot by name.
  await open(page);
  const field = page.locator("input#escname");
  await field.click();
  await page.keyboard.type("abc");
  await page.waitForTimeout(500);
  await page.keyboard.press("Escape");
  await expect(page.locator("#escrow")).toHaveCount(1);
  await expect(field).toBeFocused();
  await expect(field).toHaveValue("abc");
});

test("focus-across-patch: a backward selection keeps its direction across a patch", async ({ page }) => {
  await open(page);
  const field = page.locator("input#note");
  await field.click();
  await page.keyboard.type("hello");
  await page.waitForTimeout(500);
  await page.keyboard.press("Shift+ArrowLeft");
  await page.keyboard.press("Shift+ArrowLeft");
  await page.keyboard.press("Escape");
  await expect(page.locator("#row")).toHaveCount(1);
  await expect(field).toBeFocused();
  expect(
    await field.evaluate((el) => [el.selectionStart, el.selectionEnd, el.selectionDirection]),
  ).toEqual([3, 5, "backward"]);
});

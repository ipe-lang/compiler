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
 * autofocus is still due; a later frame puts lost focus back, and moves focus
 * onto a newly `autofocus` field only when it answers this tab's own key,
 * applies as the next step, and focus has not moved since the key. A form's
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

test("focus-across-patch: a percent-encoded fragment target keeps the first mount from autofocusing", async ({ page }) => {
  await page.addInitScript(clientOwnsFirstFocus);
  await page.goto(`${BASE}/#ke%79s`);
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

/** Holds every patches frame the stream delivers until `deliverHeld`. */
async function holdPatches(page) {
  await page.evaluate(() => {
    window.__testDeliver = window.__ipeLiveFrames.patches;
    window.__testHeld = [];
    window.__ipeLiveFrames.patches = (text, relayed) => {
      window.__testHeld.push([text, relayed]);
    };
  });
}

/** Hands the held frames to the client in order and stops holding. */
async function deliverHeld(page) {
  await page.evaluate(() => {
    window.__ipeLiveFrames.patches = window.__testDeliver;
    for (const [text, relayed] of window.__testHeld) window.__testDeliver(text, relayed);
    window.__testHeld = [];
  });
}

/** Waits for the first held frame and returns it parsed, holding it still. */
async function firstHeld(page) {
  await expect.poll(() => page.evaluate(() => window.__testHeld.length)).toBeGreaterThan(0);
  return page.evaluate(() => JSON.parse(window.__testHeld[0][0]));
}

test("focus-across-patch: an autofocus field the user's key opens takes focus", async ({ page }) => {
  await open(page);
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("F2");
  await expect(page.locator("input#ask")).toHaveCount(1);
  await expect.poll(() => focusedId(page)).toBe("ask");
  await page.keyboard.type("abc");
  await expect(page.locator("input#ask")).toHaveValue("abc");
});

test("focus-across-patch: an autofocus field reopened by the user takes focus again", async ({ page }) => {
  await open(page);
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("F2");
  await expect.poll(() => focusedId(page)).toBe("ask");
  // The key reaches the root's handler from the field: the panel closes and
  // focus falls back to the root.
  await page.keyboard.press("F2");
  await expect(page.locator("input#ask")).toHaveCount(0);
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("F2");
  await expect(page.locator("input#ask")).toHaveCount(1);
  await expect.poll(() => focusedId(page)).toBe("ask");
});

test("focus-across-patch: typing in an autofocus field never moves its caret", async ({ page }) => {
  await open(page);
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("F2");
  await expect.poll(() => focusedId(page)).toBe("ask");
  const field = page.locator("input#ask");
  // Each key re-renders the root's key line while the field stays autofocus.
  await page.keyboard.type("hello");
  await page.waitForTimeout(500);
  await page.keyboard.press("ArrowLeft");
  await page.keyboard.press("ArrowLeft");
  await page.keyboard.type("X");
  await expect(page.locator("#keys")).toHaveText("keys: X");
  await expect(field).toBeFocused();
  await expect(field).toHaveValue("helXlo");
  expect(await field.evaluate((el) => [el.selectionStart, el.selectionEnd])).toEqual([4, 4]);
});

test("focus-across-patch: a render another tab's key caused never moves focus", async ({ browser }) => {
  const ctx = await browser.newContext();
  const a = await ctx.newPage();
  await open(a);
  await expect.poll(() => focusedId(a)).toBe("root");
  // Tab A has an answered event of its own, sent with focus where it still is.
  await a.keyboard.press("j");
  await expect(a.locator("#keys")).toHaveText("keys: j");
  const b = await ctx.newPage();
  await open(b);
  await expect.poll(() => focusedId(b)).toBe("root");
  await b.keyboard.press("F2");
  await expect.poll(() => focusedId(b)).toBe("ask");
  // The same render reaches tab A, which leaves its focus alone.
  await expect(a.locator("input#ask")).toHaveCount(1);
  expect(await focusedId(a)).toBe("root");
  await ctx.close();
});

test("focus-across-patch: a render a timer caused never moves focus", async ({ page }) => {
  await open(page);
  await expect.poll(() => focusedId(page)).toBe("root");
  // The key arms the timer; the tick's render adds the autofocus field.
  await page.keyboard.press("F3");
  await expect(page.locator("input#subask")).toHaveCount(1, { timeout: 5000 });
  expect(await focusedId(page)).toBe("root");
});

test("focus-across-patch: a render landing after the user moved focus never moves it", async ({ page }) => {
  await open(page);
  await expect.poll(() => focusedId(page)).toBe("root");
  await holdPatches(page);
  await page.keyboard.press("F2");
  const frame = await firstHeld(page);
  expect(typeof frame.focus).toBe("string");
  // The user clicks another field before the render lands.
  await page.click("input#note");
  expect(await focusedId(page)).toBe("note");
  await deliverHeld(page);
  await expect(page.locator("input#ask")).toHaveCount(1);
  expect(await focusedId(page)).toBe("note");
});

test("focus-across-patch: a frame behind the render on screen never moves focus", async ({ page }) => {
  await open(page);
  await expect.poll(() => focusedId(page)).toBe("root");
  await holdPatches(page);
  await page.keyboard.press("F2");
  const frame = await firstHeld(page);
  expect(frame.tab).toBe(await page.evaluate(() => window.__ipeTabId));
  expect(typeof frame.focus).toBe("string");
  // The same frame diffed from a later render than the one on screen, naming
  // a target already on screen: only the step gate keeps focus where it is.
  const note = await page.evaluate(() => document.getElementById("note").getAttribute("ipe-id"));
  expect(note).not.toBeNull();
  const [inc, n] = frame.to.split(".");
  const behind = {
    ...frame,
    focus: note,
    from: `${inc}.${Number(n) + 1}`,
    to: `${inc}.${Number(n) + 2}`,
  };
  await page.evaluate((text) => {
    window.__ipeLiveFrames.patches = window.__testDeliver;
    window.__ipeLiveFrames.patches(text, false);
  }, JSON.stringify(behind));
  // The client resyncs to the full current render, which shows the field.
  await expect(page.locator("input#ask")).toHaveCount(1, { timeout: 10000 });
  expect(await focusedId(page)).toBe("root");
});

test("focus-across-patch: a stale frame never moves focus", async ({ page }) => {
  await open(page);
  await expect.poll(() => focusedId(page)).toBe("root");
  await page.keyboard.press("j");
  await expect(page.locator("#keys")).toHaveText("keys: j");
  await holdPatches(page);
  await page.keyboard.press("F2");
  const frame = await firstHeld(page);
  expect(typeof frame.focus).toBe("string");
  const last = await page.evaluate(() => window.__ipeLastGlobalSeq);
  expect(last).toBeGreaterThan(0);
  // It names a target already on screen: only the stale gate keeps focus.
  const note = await page.evaluate(() => document.getElementById("note").getAttribute("ipe-id"));
  expect(note).not.toBeNull();
  const stale = { ...frame, globalSeq: last, focus: note };
  await page.evaluate((text) => {
    window.__testDeliver(text, false);
  }, JSON.stringify(stale));
  await expect(page.locator("input#ask")).toHaveCount(0);
  expect(await focusedId(page)).toBe("root");
  // The frame itself, in order, applies and focuses the field.
  await deliverHeld(page);
  await expect.poll(() => focusedId(page)).toBe("ask");
});

test("focus-across-patch: a target a later patch of the frame removes never takes focus", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e));
  await open(page);
  await expect.poll(() => focusedId(page)).toBe("root");
  const host = await page.evaluate(() => document.getElementById("askhost").getAttribute("ipe-id"));
  expect(host).not.toBeNull();
  await holdPatches(page);
  await page.keyboard.press("F2");
  const frame = await firstHeld(page);
  expect(typeof frame.focus).toBe("string");
  // A last patch empties the field's host.
  const emptied = { ...frame, patches: [...frame.patches, { id: host, html: "" }] };
  await page.evaluate((text) => {
    window.__ipeLiveFrames.patches = window.__testDeliver;
    window.__testHeld = [];
    window.__ipeLiveFrames.patches(text, false);
  }, JSON.stringify(emptied));
  await expect.poll(() => page.evaluate(() => window.__ipeEpoch)).toBe(frame.to);
  await expect(page.locator("input#ask")).toHaveCount(0);
  expect(await focusedId(page)).toBe("root");
  expect(errors).toEqual([]);
});

test("focus-across-patch: an event no frame answers never withholds focus from a later one", async ({ page }) => {
  await open(page);
  await expect.poll(() => focusedId(page)).toBe("root");
  // The answer to this key cannot be read, so the client abandons the event
  // and no frame ever answers it.
  let abandoned = false;
  await page.route(
    "**/_ipe/event",
    (route) => {
      abandoned = true;
      return route.fulfill({
        status: 409,
        headers: { "X-Ipe-Web": "1", "Content-Type": "application/json" },
        body: "{",
      });
    },
    { times: 1 },
  );
  await page.keyboard.press("j");
  await expect.poll(() => abandoned).toBe(true);
  // Focus moves after that event was sent, then comes back to the root.
  await page.click("input#note");
  expect(await focusedId(page)).toBe("note");
  await page.click("#keys");
  await expect.poll(() => focusedId(page)).toBe("root");
  // The next key's own render focuses its field.
  await page.keyboard.press("F2");
  await expect(page.locator("input#ask")).toHaveCount(1);
  await expect.poll(() => focusedId(page)).toBe("ask");
});

//! Client-WASM debugger overlay — message list + scrubber panel.
//!
//! Mounts a fixed-position panel into the page via CHECKED `web-sys` calls.
//! The panel is NOT part of the app's own view tree and does not perturb the
//! app DOM or ipe-id space: it is appended directly to `<body>` by overlay
//! code, never by `view`/diff/patch.
//!
//! ## Live vs scrubbed modes
//!
//! - **Live** (scrubber at the rightmost position): new messages append to the
//!   log and the message list updates; the app renders the live model as usual.
//! - **Scrubbed** (scrubber at any earlier position): incoming messages still
//!   record into the ring buffer (history is never corrupted), but the app view
//!   is re-rendered at the reconstructed model for the selected step and frozen
//!   there. Moving the scrubber back to the end resumes live mode and re-renders
//!   the current live model.
//!
//! ## No re-fire guarantee
//!
//! Scrubbing calls `RecordBuffer::reconstruct`, which is a pure re-fold over the
//! retained message log — every `Cmd` produced by `update` during reconstruction
//! is discarded. The overlay never enqueues or runs any `Cmd`.
//!
//! ## Secret redaction
//!
//! Message labels in the list pass through `IpeStringify::ipe_show`, which is
//! hand-implemented on `Secret` to always emit the fixed redacted placeholder.
//! A `Secret`-bearing `Msg` cannot implement `serde::Serialize`, so export is
//! compile-time unavailable for such types, but live display still works — every
//! rendered label is redacted at the `IpeStringify` layer, never in the clear.
//!
//! ## Zero residue without `--debugger`
//!
//! Every item in this file is `#[cfg(feature = "debugger")]`-gated. A build
//! without the feature includes none of this code.

#![cfg(feature = "debugger")]

use std::cell::Cell;
use std::rc::Rc;

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

// ── Constants ────────────────────────────────────────────────────────────────

/// Attribute written on the overlay root so nothing in the app's ipe-id
/// selector can accidentally match it.
const OVERLAY_ATTR: &str = "data-ipe-debugger";

/// The keyboard combo that toggles the panel open/closed, shown in the tip.
const TOGGLE_HINT: &str = "Ctrl+Shift+D";

/// Inline style applied to the overlay container — a FLOATING, DRAGGABLE window
/// pinned bottom-LEFT (the bottom-right corner is the dev "Console" link's, so
/// docking left avoids the overlap). Starts hidden (collapsed to the launcher
/// tab); the toggle flips `display`. Self-contained so no stylesheet is needed.
const OVERLAY_STYLE: &str = concat!(
    "position:fixed;bottom:12px;left:12px;width:320px;max-height:40vh;",
    "background:#1e1e1e;color:#d4d4d4;font:12px/1.4 monospace;",
    "border-radius:6px;overflow:hidden;",
    "box-shadow:0 2px 12px rgba(0,0,0,.5);z-index:2147483645;",
    "display:none;flex-direction:column;"
);

/// Style for the draggable header row — the grab handle plus the tip text.
const HEADER_STYLE: &str = concat!(
    "display:flex;align-items:center;justify-content:space-between;gap:8px;",
    "padding:4px 8px;background:#333;cursor:move;flex-shrink:0;",
    "user-select:none;"
);

/// Style for the collapsed launcher tab (bottom-left, above the panel's z so a
/// click always lands on it when the panel is closed).
const TAB_STYLE: &str = concat!(
    "position:fixed;bottom:12px;left:12px;z-index:2147483645;",
    "background:#252526;color:#d4d4d4;font:12px/1.4 monospace;",
    "padding:6px 10px;border-radius:6px;cursor:pointer;",
    "box-shadow:0 2px 8px rgba(0,0,0,.4);user-select:none;"
);

/// Style for the scrubber row.
const SCRUBBER_STYLE: &str =
    "display:flex;align-items:center;gap:6px;padding:4px 6px;background:#252526;flex-shrink:0;";

/// Style for the message list scrollable area.
const LIST_STYLE: &str = "overflow-y:auto;flex:1;padding:4px 0;";

/// Style for a single message row — normal (live) state.
const ROW_STYLE_LIVE: &str =
    "padding:1px 8px;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;";

/// Style for the selected (scrubbed) message row.
const ROW_STYLE_SELECTED: &str = "padding:1px 8px;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;background:#264f78;";

/// Maximum label length shown per message (keeps the panel readable).
const MAX_LABEL_LEN: usize = 80;

// ── Overlay state ─────────────────────────────────────────────────────────────

/// The state kept alongside the `App` for the overlay panel.
///
/// `scrub_step` is `None` in live mode; `Some(n)` when the user has selected
/// step `n` (0-indexed in the ring buffer's retained window). The driver checks
/// this to decide whether to re-render at the reconstructed model or let the
/// normal flush path render the live model.
pub(super) struct OverlayState {
    /// The overlay root element (the floating panel in `<body>`).
    root: web_sys::HtmlElement,
    /// The collapsed launcher tab (shown when the panel is closed).
    tab: web_sys::HtmlElement,
    /// The draggable header row — the drag handle for repositioning the panel.
    header: web_sys::HtmlElement,
    /// The `<input type=range>` scrubber.
    scrubber: web_sys::HtmlInputElement,
    /// The `<div>` that holds the message rows.
    list_el: web_sys::HtmlElement,
    /// `None` = live; `Some(n)` = viewing retained step n.
    pub(super) scrub_step: Cell<Option<usize>>,
    /// Whether the floating panel is currently open (else the tab shows).
    open: Cell<bool>,
}

impl OverlayState {
    /// The current scrub position, if any.
    pub(super) fn scrub_step(&self) -> Option<usize> {
        self.scrub_step.get()
    }
}

// ── Mount ────────────────────────────────────────────────────────────────────

/// Create and mount the overlay panel into `<body>`.
///
/// Returns `None` (with a console warning) on any DOM failure rather than
/// propagating errors into the app mount path.
pub(super) fn mount_overlay() -> Option<Rc<OverlayState>> {
    let result = try_mount_overlay();
    match result {
        Ok(state) => Some(Rc::new(state)),
        Err(msg) => {
            super::console_warn(&format!("debugger-overlay mount failed: {msg}"));
            None
        }
    }
}

fn try_mount_overlay() -> Result<OverlayState, String> {
    let window = web_sys::window().ok_or("no window")?;
    let document = window.document().ok_or("no document")?;
    let body: web_sys::HtmlElement = document.body().ok_or("no body")?;

    // ── Root container ────────────────────────────────────────────────────
    let root: web_sys::HtmlElement = document
        .create_element("div")
        .map_err(|e| format!("createElement(div): {e:?}"))?
        .dyn_into::<web_sys::HtmlElement>()
        .map_err(|_| "root cast to HtmlElement failed")?;

    root.set_attribute(OVERLAY_ATTR, "1")
        .map_err(|e| format!("setAttribute: {e:?}"))?;
    root.set_attribute("style", OVERLAY_STYLE)
        .map_err(|e| format!("setAttribute style: {e:?}"))?;

    // ── Header row (drag handle + tip) ────────────────────────────────────
    let header: web_sys::HtmlElement = document
        .create_element("div")
        .map_err(|e| format!("createElement header: {e:?}"))?
        .dyn_into::<web_sys::HtmlElement>()
        .map_err(|_| "header cast failed")?;
    header
        .set_attribute("style", HEADER_STYLE)
        .map_err(|e| format!("setAttribute header style: {e:?}"))?;
    header.set_attribute(OVERLAY_ATTR, "1").ok();

    let title: web_sys::HtmlElement = document
        .create_element("span")
        .map_err(|e| format!("createElement title: {e:?}"))?
        .dyn_into::<web_sys::HtmlElement>()
        .map_err(|_| "title cast failed")?;
    title.set_text_content(Some("⏱ Debugger"));
    title.set_attribute("style", "font-weight:bold;").ok();

    let tip: web_sys::HtmlElement = document
        .create_element("span")
        .map_err(|e| format!("createElement tip: {e:?}"))?
        .dyn_into::<web_sys::HtmlElement>()
        .map_err(|_| "tip cast failed")?;
    // Static tip text; set via text_content (never innerHTML) — no interpolation
    // of untrusted data, so no injection surface.
    tip.set_text_content(Some(&format!("drag to move · {TOGGLE_HINT} to close")));
    tip.set_attribute("style", "opacity:.6;font-size:11px;")
        .ok();

    header
        .append_child(&title)
        .map_err(|e| format!("appendTitle: {e:?}"))?;
    header
        .append_child(&tip)
        .map_err(|e| format!("appendTip: {e:?}"))?;
    root.append_child(&header)
        .map_err(|e| format!("appendHeader: {e:?}"))?;

    // ── Collapsed launcher tab ────────────────────────────────────────────
    let tab: web_sys::HtmlElement = document
        .create_element("div")
        .map_err(|e| format!("createElement tab: {e:?}"))?
        .dyn_into::<web_sys::HtmlElement>()
        .map_err(|_| "tab cast failed")?;
    tab.set_attribute(OVERLAY_ATTR, "1").ok();
    tab.set_attribute("style", TAB_STYLE)
        .map_err(|e| format!("setAttribute tab style: {e:?}"))?;
    tab.set_text_content(Some(&format!("⏱ Debugger ({TOGGLE_HINT})")));

    // ── Scrubber row ──────────────────────────────────────────────────────
    let scrubber_row: web_sys::HtmlElement = document
        .create_element("div")
        .map_err(|e| format!("createElement scrubber-row: {e:?}"))?
        .dyn_into::<web_sys::HtmlElement>()
        .map_err(|_| "scrubber-row cast failed")?;
    scrubber_row
        .set_attribute("style", SCRUBBER_STYLE)
        .map_err(|e| format!("setAttribute scrubber-row style: {e:?}"))?;

    // Label
    let label: web_sys::HtmlElement = document
        .create_element("span")
        .map_err(|e| format!("createElement span: {e:?}"))?
        .dyn_into::<web_sys::HtmlElement>()
        .map_err(|_| "label cast failed")?;
    label.set_text_content(Some("▶ Debugger"));
    label
        .set_attribute("style", "flex-shrink:0;opacity:.7;")
        .map_err(|e| format!("setAttribute label style: {e:?}"))?;

    // Range input
    let scrubber: web_sys::HtmlInputElement = document
        .create_element("input")
        .map_err(|e| format!("createElement input: {e:?}"))?
        .dyn_into::<web_sys::HtmlInputElement>()
        .map_err(|_| "input cast to HtmlInputElement failed")?;
    scrubber.set_type("range");
    scrubber.set_min("0");
    scrubber.set_max("0");
    scrubber.set_value("0");
    scrubber
        .set_attribute("style", "flex:1;min-width:0;")
        .map_err(|e| format!("setAttribute scrubber style: {e:?}"))?;

    scrubber_row
        .append_child(&label)
        .map_err(|e| format!("appendLabel: {e:?}"))?;
    scrubber_row
        .append_child(&scrubber)
        .map_err(|e| format!("appendScrubber: {e:?}"))?;

    // ── Message list ──────────────────────────────────────────────────────
    let list_el: web_sys::HtmlElement = document
        .create_element("div")
        .map_err(|e| format!("createElement list: {e:?}"))?
        .dyn_into::<web_sys::HtmlElement>()
        .map_err(|_| "list cast failed")?;
    list_el
        .set_attribute("style", LIST_STYLE)
        .map_err(|e| format!("setAttribute list style: {e:?}"))?;

    root.append_child(&scrubber_row)
        .map_err(|e| format!("appendScrubberRow: {e:?}"))?;
    root.append_child(&list_el)
        .map_err(|e| format!("appendList: {e:?}"))?;

    body.append_child(&root)
        .map_err(|e| format!("appendRoot: {e:?}"))?;
    body.append_child(&tab)
        .map_err(|e| format!("appendTab: {e:?}"))?;

    Ok(OverlayState {
        root,
        tab,
        header,
        scrubber,
        list_el,
        scrub_step: Cell::new(None),
        open: Cell::new(false),
    })
}

/// Apply the current open/closed visibility to the panel and the launcher tab:
/// exactly one of the two is shown.
fn apply_visibility(state: &OverlayState) {
    let open = state.open.get();
    let _ = state
        .root
        .style()
        .set_property("display", if open { "flex" } else { "none" });
    let _ = state
        .tab
        .style()
        .set_property("display", if open { "none" } else { "block" });
}

/// Flip the panel between open and closed.
fn toggle_open(state: &OverlayState) {
    state.open.set(!state.open.get());
    apply_visibility(state);
}

// ── Render ────────────────────────────────────────────────────────────────────

/// Rebuild the overlay panel contents from the current ring-buffer snapshot.
///
/// `labels` — pre-rendered string labels for retained steps (oldest first).
/// `len`    — total number of retained steps (equals `labels` count).
/// `selected` — which step index is currently selected (`None` = live = last).
///
/// This never touches the app DOM — it only mutates elements owned by the
/// overlay (`list_el`, `scrubber`).
pub(super) fn render_overlay(
    state: &OverlayState,
    labels: impl Iterator<Item = String>,
    len: usize,
    selected: Option<usize>,
) {
    let Some(document) = (|| web_sys::window()?.document())() else {
        return;
    };

    // ── Update scrubber range ─────────────────────────────────────────────
    // max = len (step past the last recorded step = live mode).
    // value = selected.unwrap_or(len) — live is at the end.
    let max_val = len.to_string();
    let cur_val = selected.unwrap_or(len).to_string();
    state.scrubber.set_max(&max_val);
    state.scrubber.set_value(&cur_val);

    // ── Rebuild message list ──────────────────────────────────────────────
    state.list_el.set_inner_html(""); // clear; bounded by ring-buffer cap

    let selected_step = selected.unwrap_or(len); // len means "past end" = live
    for (idx, label_raw) in labels.enumerate() {
        let label = truncate(label_raw, MAX_LABEL_LEN);
        let style = if idx == selected_step && selected.is_some() {
            ROW_STYLE_SELECTED
        } else {
            ROW_STYLE_LIVE
        };

        let row: web_sys::HtmlElement = match document
            .create_element("div")
            .ok()
            .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
        {
            Some(el) => el,
            None => continue,
        };
        let _ = row.set_attribute("style", style);
        let _ = row.set_attribute("data-ipe-dbg-step", &idx.to_string());
        row.set_text_content(Some(&label));

        let _ = state.list_el.append_child(&row);
    }

    // Auto-scroll to bottom when in live mode.
    if selected.is_none() {
        state.list_el.set_scroll_top(state.list_el.scroll_height());
    }
}

/// Truncate a string to at most `max` characters, appending `…` if cut.
fn truncate(mut s: String, max: usize) -> String {
    if s.chars().count() <= max {
        return s;
    }
    // Truncate at char boundary.
    let cut: usize = s.char_indices().nth(max).map(|(i, _)| i).unwrap_or(s.len());
    s.truncate(cut);
    s.push('…');
    s
}

// ── Event wiring ──────────────────────────────────────────────────────────────

/// Attach the scrubber `input` listener and the list `click` listener.
///
/// When the user moves the scrubber:
/// - If the new value equals `len` (rightmost), resume live mode.
/// - Otherwise, set `scrub_step = Some(n)` and call `on_scrub(n)`.
///
/// When the user clicks a message row:
/// - Read `data-ipe-dbg-step`, set the scrubber, call `on_scrub`.
///
/// The `on_scrub` callback is provided by the driver (`wasm/mod.rs`) and
/// triggers the reconstruct→re-render path WITHOUT running any `Cmd`.
pub(super) fn attach_overlay_listeners<F>(state: &Rc<OverlayState>, on_scrub: F)
where
    F: Fn(Option<usize>) + 'static,
{
    let on_scrub = Rc::new(on_scrub);

    // ── Scrubber input ────────────────────────────────────────────────────
    {
        let state2 = Rc::clone(state);
        let cb = Rc::clone(&on_scrub);
        let closure = Closure::<dyn Fn(web_sys::Event)>::new(move |ev: web_sys::Event| {
            let Some(input) = ev
                .target()
                .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
            else {
                return;
            };
            let val: usize = input.value().parse().unwrap_or(0);
            let max: usize = input.max().parse().unwrap_or(0);
            // `val == max` means "live" (past the last step).
            let step = if val >= max { None } else { Some(val) };
            state2.scrub_step.set(step);
            cb(step);
        });
        let _ = state
            .scrubber
            .add_event_listener_with_callback("input", closure.as_ref().unchecked_ref());
        closure.forget();
    }

    // ── List click ────────────────────────────────────────────────────────
    {
        let state2 = Rc::clone(state);
        let cb = Rc::clone(&on_scrub);
        let closure = Closure::<dyn Fn(web_sys::Event)>::new(move |ev: web_sys::Event| {
            // Walk up from the click target to find a row with data-ipe-dbg-step.
            let mut cur: Option<web_sys::Element> = ev
                .target()
                .and_then(|t| t.dyn_into::<web_sys::Element>().ok());
            while let Some(el) = cur {
                if let Some(attr) = el.get_attribute("data-ipe-dbg-step")
                    && let Ok(n) = attr.parse::<usize>()
                {
                    // Set the scrubber value to match.
                    state2.scrubber.set_value(&n.to_string());
                    state2.scrub_step.set(Some(n));
                    cb(Some(n));
                    return;
                }
                cur = el.parent_element();
            }
        });
        let _ = state
            .list_el
            .add_event_listener_with_callback("click", closure.as_ref().unchecked_ref());
        closure.forget();
    }

    // ── Launcher tab click: open the panel ─────────────────────────────────
    {
        let state2 = Rc::clone(state);
        let closure = Closure::<dyn Fn(web_sys::Event)>::new(move |_ev: web_sys::Event| {
            toggle_open(&state2);
        });
        let _ = state
            .tab
            .add_event_listener_with_callback("click", closure.as_ref().unchecked_ref());
        closure.forget();
    }

    // ── Ctrl+Shift+D toggle (window keydown) ───────────────────────────────
    // A discoverable shortcut to open/close the panel. Ignored while the user is
    // typing in a form field so it never steals a keystroke from the app.
    if let Some(window) = web_sys::window() {
        let state2 = Rc::clone(state);
        let closure =
            Closure::<dyn Fn(web_sys::KeyboardEvent)>::new(move |ev: web_sys::KeyboardEvent| {
                if !(ev.ctrl_key() && ev.shift_key()) {
                    return;
                }
                if !ev.key().eq_ignore_ascii_case("d") {
                    return;
                }
                if target_is_text_entry(&ev) {
                    return;
                }
                ev.prevent_default();
                toggle_open(&state2);
            });
        let _ =
            window.add_event_listener_with_callback("keydown", closure.as_ref().unchecked_ref());
        closure.forget();
    }

    // ── Drag the panel by its header ───────────────────────────────────────
    attach_drag(state);
}

/// Whether a keyboard event originated in a text-entry element, so the toggle
/// shortcut yields to the app's own typing (INPUT / TEXTAREA / SELECT, or any
/// `contenteditable` host).
fn target_is_text_entry(ev: &web_sys::KeyboardEvent) -> bool {
    let Some(el) = ev
        .target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlElement>().ok())
    else {
        return false;
    };
    if el.is_content_editable() {
        return true;
    }
    matches!(
        el.tag_name().to_ascii_uppercase().as_str(),
        "INPUT" | "TEXTAREA" | "SELECT"
    )
}

/// Make the panel draggable by its header: pointerdown on the header records the
/// grab offset, pointermove repositions the panel by `left`/`top` (clamped to the
/// viewport so it can never be dragged fully off-screen), pointerup releases.
fn attach_drag(state: &Rc<OverlayState>) {
    // Shared drag anchor: `Some((dx, dy))` while a drag is active, where dx/dy is
    // the pointer's offset from the panel's top-left at grab time.
    let anchor: Rc<Cell<Option<(f64, f64)>>> = Rc::new(Cell::new(None));

    // pointerdown on the header — begin a drag.
    {
        let state2 = Rc::clone(state);
        let anchor2 = Rc::clone(&anchor);
        let closure =
            Closure::<dyn Fn(web_sys::PointerEvent)>::new(move |ev: web_sys::PointerEvent| {
                let rect = state2.root.get_bounding_client_rect();
                anchor2.set(Some((
                    ev.client_x() as f64 - rect.left(),
                    ev.client_y() as f64 - rect.top(),
                )));
                // Pin the panel by top/left so the drag math is absolute; clear the
                // bottom anchor it mounted with.
                let _ = state2.root.style().set_property("bottom", "auto");
                let _ = state2
                    .root
                    .style()
                    .set_property("top", &format!("{}px", rect.top()));
                let _ = state2
                    .root
                    .style()
                    .set_property("left", &format!("{}px", rect.left()));
            });
        let _ = state
            .header
            .add_event_listener_with_callback("pointerdown", closure.as_ref().unchecked_ref());
        closure.forget();
    }

    // pointermove on window — reposition while dragging.
    if let Some(window) = web_sys::window() {
        let state2 = Rc::clone(state);
        let anchor2 = Rc::clone(&anchor);
        let closure =
            Closure::<dyn Fn(web_sys::PointerEvent)>::new(move |ev: web_sys::PointerEvent| {
                let Some((dx, dy)) = anchor2.get() else {
                    return;
                };
                let (vw, vh) = viewport();
                let rect = state2.root.get_bounding_client_rect();
                // Clamp so at least a sliver of the panel stays on-screen.
                let x = (ev.client_x() as f64 - dx).clamp(0.0, (vw - rect.width()).max(0.0));
                let y = (ev.client_y() as f64 - dy).clamp(0.0, (vh - rect.height()).max(0.0));
                let _ = state2.root.style().set_property("left", &format!("{x}px"));
                let _ = state2.root.style().set_property("top", &format!("{y}px"));
            });
        let _ = window
            .add_event_listener_with_callback("pointermove", closure.as_ref().unchecked_ref());
        closure.forget();
    }

    // pointerup on window — release the drag.
    if let Some(window) = web_sys::window() {
        let anchor2 = Rc::clone(&anchor);
        let closure =
            Closure::<dyn Fn(web_sys::PointerEvent)>::new(move |_ev: web_sys::PointerEvent| {
                anchor2.set(None);
            });
        let _ =
            window.add_event_listener_with_callback("pointerup", closure.as_ref().unchecked_ref());
        closure.forget();
    }
}

/// The viewport width/height, defaulting to `0.0` when unavailable (the clamp
/// then keeps the panel at the origin — never a panic).
fn viewport() -> (f64, f64) {
    let Some(window) = web_sys::window() else {
        return (0.0, 0.0);
    };
    let w = window
        .inner_width()
        .ok()
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let h = window
        .inner_height()
        .ok()
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    (w, h)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::truncate;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn truncate_short_string_unchanged() {
        let s = "hello".to_owned();
        assert_eq!(truncate(s.clone(), 10), s);
    }

    #[wasm_bindgen_test]
    fn truncate_long_string_appends_ellipsis() {
        let s = "abcdefghij".to_owned(); // 10 chars
        let t = truncate(s, 5);
        assert!(t.ends_with('…'), "must end with ellipsis");
        assert!(t.starts_with("abcde"));
    }

    #[wasm_bindgen_test]
    fn truncate_exact_boundary_unchanged() {
        let s = "hello".to_owned();
        assert_eq!(truncate(s, 5), "hello");
    }
}

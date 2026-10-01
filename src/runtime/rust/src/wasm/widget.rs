//! Browser-WASM `CustomElement.node` custom-element adapter — the client-target seam.
//!
//! The wasm sink runs the SAME `view → Html<M> → diff → Vec<Patch>` path the
//! server-driven wire runs, so a `CustomElement.node` node reaches the DOM as a
//! `ipe-ce-<hex>` element carrying a `state` value and an `OnWidget` up-handler.
//! What this module swaps is the two seam edges, matching the wasm-client glue
//! (`web::widget_assets`, transport `WasmClient`):
//!
//! * **Down-state as a decoded property.** Instead of writing the escaped `state`
//!   ATTRIBUTE the server path uses, the sink decodes the canonical-JSON down
//!   value with the browser's structured `JSON.parse` and assigns the resulting
//!   object to the element's `state` PROPERTY (via `js_sys::Reflect::set`). The
//!   glue's `set state(v)` setter forwards it to the author `mount`'s `onState`.
//!   The value crosses as structured data handed to a setter — never spliced into
//!   HTML/script, never `eval`ed. A malformed encoding decodes to `null` and is
//!   still delivered as the (empty) decoded value — the down direction is not the
//!   attacker-controlled edge, and our own encoder always emits valid JSON.
//!
//! * **Up-event as a typed `CustomEvent`.** The glue's `emit(up)` dispatches a
//!   bubbling `CustomEvent` named [`WIDGET_UP_CUSTOM_EVENT`] whose `detail` is the
//!   encoded `up` value (the exact bytes the server transport would POST). A
//!   single delegated listener on `<body>` reads `detail`, runs the generated,
//!   total, fail-closed seal up-decoder through the node's `OnWidget` handler, and
//!   folds the typed msg into the in-process TEA loop. A malformed/oversized
//!   `detail` is DROPPED whole (`Err → None`) — no partial value, no panic, no
//!   network hop.
//!
//! Casting discipline (shared with the sink): every JS→web-sys crossing uses the
//! CHECKED `dyn_into`/`dyn_ref`; a failed cast routes to a classified console
//! diagnostic, never a trap. One codec (the seal codec) governs both directions:
//! the down-encode ran once in `ui::widget::ui_widget_`, and the up-decode is the
//! same `OnWidget` closure the server path invokes.

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

use crate::ui::widget::{CUSTOM_ELEMENT_TAG_PREFIX, WIDGET_UP_CUSTOM_EVENT, WIDGET_UP_EVENT};

/// The event NAME the `OnWidget` up-handler is keyed under in the handler index
/// (`html::Event::name` returns this). The DOM `CustomEvent` arrives under the
/// distinct [`WIDGET_UP_CUSTOM_EVENT`] name, but the handler the view registered
/// is indexed by this wire name — so the sink resolves the up-`CustomEvent`
/// through `HandlerIndex::resolve(id, UP_WIRE_NAME, [detail])`, the SAME entry the
/// server POST path resolves.
pub const UP_WIRE_NAME: &str = WIDGET_UP_EVENT;

/// True when `tag` is a compiler-generated custom-element tag (`ipe-ce-…`). The
/// sink keys its adapter on this so it can never mistake an ordinary element for
/// a widget, nor miss a real one — the lowerer mints only tags of this shape.
#[must_use]
pub fn is_widget_tag(tag: &str) -> bool {
    tag.starts_with(CUSTOM_ELEMENT_TAG_PREFIX)
}

/// Deliver one widget node's down-state as a decoded PROPERTY, not an attribute.
///
/// `encoded` is the canonical-JSON `down` value the view produced. It is parsed
/// with the browser's structured `JSON.parse`, and the resulting `JsValue` is
/// assigned to the element's `state` property; the glue's `set state(v)` setter
/// forwards it to the author hook. The value never touches the DOM as markup or
/// script.
///
/// A parse failure (which our own always-valid encoder cannot produce, but a
/// third party could by tampering) yields `null`, which is still handed to the
/// setter as the decoded (empty) value — the down channel is not the
/// attacker-controlled edge, and a `null` state is strictly better than wedging
/// the element. `Reflect::set` failing (e.g. a frozen element) is logged and
/// dropped; it never traps.
pub fn set_widget_down_property(el: &web_sys::Element, encoded: &str) {
    // Structured decode — the SAME `JSON.parse` the glue's down-parse helper uses,
    // so the property path and the attribute path decode identically.
    let value = js_sys::JSON::parse(encoded).unwrap_or(JsValue::NULL);
    // Assign the decoded value to the `state` property. `Reflect::set` returns
    // `Ok(true)` on success; any `Err`/`Ok(false)` is a non-fatal DOM refusal we
    // log and drop rather than trap on.
    if js_sys::Reflect::set(el.as_ref(), &JsValue::from_str("state"), &value).is_err() {
        super::console_warn(&format!(
            "widget down-state property assignment refused on <{}>",
            el.tag_name().to_lowercase()
        ));
    }
}

/// Read the encoded up-value from a widget `CustomEvent`'s `detail`.
///
/// Returns `Some(json)` when `detail` is a string (the encoded `up` the glue put
/// there); `None` when the event is not a `CustomEvent`, carries no `detail`, or
/// carries a non-string `detail` — every one a clean drop (the caller's decoder
/// then never runs on a malformed carrier). A non-string `detail` is exactly the
/// adversarial case: a page script forging `dispatchEvent(new CustomEvent(
/// "ipe-widget-up", { detail: { __proto__: … } }))` yields `None` here, so no
/// object ever reaches the seal decoder.
#[must_use]
pub fn up_event_detail(ev: &web_sys::Event) -> Option<String> {
    let custom = ev.dyn_ref::<web_sys::CustomEvent>()?;
    custom.detail().as_string()
}

/// The widget up-event name the sink listens for on `<body>`. Re-exported so the
/// sink's listener registration and this module's contract stay one name.
#[must_use]
pub const fn up_event_name() -> &'static str {
    WIDGET_UP_CUSTOM_EVENT
}

/// Deliver the down-state PROPERTY to every widget node in `tree` from the DOM.
///
/// The initial mount paints via `set_inner_html`, which does NOT run through the
/// attribute-patch path (where [`set_widget_down_property`] intercepts `state`).
/// So after the first paint the sink calls this once: it walks the view tree,
/// and for each `ipe-ce-*` node with a `state` value, looks the live element up
/// by its stamped `ipe-id` and assigns the decoded property. Later state changes
/// ride the normal diff → attribute-patch → property route. Idempotent and
/// bounded by the widget count.
///
/// The walk is iterative (an explicit heap stack) so a deeply nested view cannot
/// overflow the wasm stack — the same discipline `dom::dispatch::walk` uses.
pub fn sync_widget_properties<M>(document: &web_sys::Document, tree: &crate::html::Html<M>) {
    use crate::html::{Attribute, Html};
    let mut stack: Vec<&Html<M>> = vec![tree];
    while let Some(node) = stack.pop() {
        if let Html::HElement(tag, attrs, kids) = node {
            if is_widget_tag(tag) {
                let mut ipe_id: Option<&str> = None;
                let mut state: Option<&str> = None;
                for a in attrs {
                    if let Attribute::Attr(k, v) = a {
                        match k.as_str() {
                            "ipe-id" => ipe_id = Some(v),
                            "state" => state = Some(v),
                            _ => {}
                        }
                    }
                }
                if let (Some(id), Some(encoded)) = (ipe_id, state) {
                    let selector = format!("[ipe-id=\"{}\"]", id.replace('"', "\\\""));
                    if let Ok(Some(el)) = document.query_selector(&selector) {
                        set_widget_down_property(&el, encoded);
                    }
                }
            }
            for c in kids {
                stack.push(c);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn widget_tag_detection_is_prefix_exact() {
        assert!(is_widget_tag("ipe-ce-cafef00d"));
        assert!(is_widget_tag("ipe-ce-0011223344556677"));
        assert!(!is_widget_tag("div"));
        assert!(!is_widget_tag("ipe-root"));
        // A near-miss that is NOT the compiler prefix must not be treated as a
        // widget (no `ipe-ce-` boundary).
        assert!(!is_widget_tag("ipe-cell"));
    }

    #[wasm_bindgen_test]
    fn up_event_name_is_the_shared_custom_event_constant() {
        assert_eq!(up_event_name(), "ipe-widget-up");
        assert_eq!(up_event_name(), WIDGET_UP_CUSTOM_EVENT);
    }
}

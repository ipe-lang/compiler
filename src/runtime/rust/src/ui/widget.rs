//! Server-driven `CustomElement.node` custom-element boundary (WP4).
//!
//! `CustomElement.node : CustomElement down up -> down -> (up -> msg) -> Element msg`
//! places one typed JS custom-element widget. This module holds the opaque
//! handle the reserved `CustomElement.fromFile` constructor produces and the emission
//! that renders the widget node.
//!
//! ## The seam, and its two fail-closed gates
//!
//! * **Down-state (Ipê → page).** The declared `down` value is encoded as
//!   canonical JSON and placed in a `state` ATTRIBUTE via
//!   [`Attribute::AttrAttribute`], which the `Ipe.Ui`→HTML lowering renders
//!   through the standard attribute ENTITY-ESCAPER (`html::render`'s
//!   `SafeAttrName` + attr-escape path) — never `HRaw`, never spliced into a
//!   script. This closes Security #1 (XSS via state serialisation): the state
//!   crosses only as an escaped attribute. State changes ride the existing
//!   attribute-delta patch mechanism (`Patch.attrs`), exactly as any other
//!   attribute value does.
//!
//! * **Up-event (page → Ipê).** The browser posts the encoded `up` value
//!   through the SAME `/_ipe/event` wire a click uses ([`Event::OnWidget`]);
//!   the generated closure runs [`seal_codec::seal_decode_serde`] — total and
//!   fail-closed — over the posted string and dispatches the typed `msg` only on
//!   a clean decode. A payload that does not decode to the declared `up` type is
//!   DROPPED whole (an observable log, no partial value), closing Security #2.
//!
//! The element tag is a compiler-generated content-addressed `ipe-ce-<hex>`
//! (see `custom_element_tag` in the lowerer); it never carries user input, so
//! `customElements.define`-style registration injection is impossible by
//! construction (Security #4). The generated JS glue and SRI-pinned serving land
//! in WP5; WP4 emits the Rust render + the wire and proves both compile.

#[cfg(feature = "json")]
use crate::html::{Attribute as HtmlAttribute, Event};
#[cfg(feature = "json")]
use crate::seal_codec::{SealDecodeError, SealLimits, seal_decode_serde};
#[cfg(feature = "json")]
use crate::ui::element::Attribute;
use crate::ui::element::{Description, Element};

/// The opaque handle a `CustomElement.fromFile "<js-path>"` constructor produces and
/// `CustomElement.node` consumes. It carries ONLY the generated content-addressed tag —
/// the value never crosses the seam, is never serialised, and is never stored in
/// a `Model` (the plain-Model gate rejects a `CustomElement`-typed field exactly
/// as it rejects a function). Its `down`/`up` seal types are phantom at runtime;
/// they drive the down-encode / up-decode codegen at the `CustomElement.node` call site,
/// not this handle's representation.
#[derive(Clone, Debug)]
pub struct IpeCustomElement {
    /// The generated `ipe-ce-<hex>` custom-element tag.
    tag: String,
}

crate::stringify::show_row!("CustomElement", Internals, [] IpeCustomElement, |_| "<Ipe.Ffi.Js.CustomElement>".to_owned());

/// The reserved `CustomElement.fromFile "<js-path>"` constructor. `tag` is the
/// compiler-minted content-addressed element tag; the constructor is a pure
/// wrapper — every path/containment seal already ran at compile time.
#[must_use]
pub fn custom_element_(tag: String) -> IpeCustomElement {
    IpeCustomElement { tag }
}

/// The wire event name a `CustomElement.node` up-event posts under. A fixed compiler
/// constant, never user-derived; the client posts the encoded `up` value as
/// `args[0]` under this name through `/_ipe/event`, the same path a click uses.
pub const WIDGET_UP_EVENT: &str = "ipe-widget";

/// The DOM `CustomEvent` type name a `WasmClient`-transport widget dispatches its
/// up-event under. Defined here (compiles on every target) so the native glue
/// generator (`web::widget_assets`) and the browser-WASM sink (`wasm::widget`)
/// reference ONE constant — the emitted glue's `dispatchEvent` name and the
/// sink's listener name can never drift. Distinct from [`WIDGET_UP_EVENT`] (the
/// server POST wire name) so a page carrying both transports never cross-wires.
pub const WIDGET_UP_CUSTOM_EVENT: &str = "ipe-widget-up";

/// The `ipe-ce-` prefix every compiler-generated custom-element tag carries. The
/// browser-WASM sink keys its down-property / up-CustomEvent adapter on this
/// prefix (a widget node is exactly a `TaggedNode` whose tag starts with it), and
/// the lowerer mints only tags of this shape — so the sink can never mistake an
/// ordinary element for a widget, nor miss a real one.
pub const CUSTOM_ELEMENT_TAG_PREFIX: &str = "ipe-ce-";

/// `CustomElement.node ce state on_up` — render the widget node.
///
/// Emits `<ipe-ce-… state="{escaped json}" …>` (an empty-child `TaggedNode`):
///
/// * `state` is the canonical-JSON encoding of `down`, carried as an
///   entity-escaped [`Attribute::AttrAttribute`] (never `HRaw`).
/// * the up-event handler is an [`Event::OnWidget`] whose closure decodes the
///   posted payload fail-closed into `Up` and maps it through `on_up`.
///
/// `Down: Serialize` and `Up: DeserializeOwned` are satisfied by the
/// `#[derive(serde::Serialize, serde::Deserialize)]` a seal-legal type carries
/// in a Web program; the emitter passes concrete types, so no `dyn`/reflection
/// is involved — one concrete monomorphisation per widget.
#[cfg(feature = "json")]
#[must_use]
pub fn ui_widget_<M, Down, Up, F>(ce: IpeCustomElement, state: Down, on_up: F) -> Element<M>
where
    Down: serde::Serialize,
    Up: serde::de::DeserializeOwned,
    F: Fn(Up) -> M + Send + Sync + 'static,
{
    // Encode the down-state canonically. Our own value always serialises; on the
    // impossible failure we emit an empty object rather than panic — a widget
    // that boots with empty state is strictly better than a crash, and the down
    // direction is not the attacker-controlled edge.
    let state_json = serde_json::to_string(&state).unwrap_or_else(|_| "{}".to_string());

    // The state rides a plain attribute, so it flows through the STANDARD
    // attribute entity-escaper on render — never `HRaw`. `AttrAttribute`'s
    // security contract (see `ui::element`) mandates exactly this lowering.
    let state_attr: Attribute<M> = Attribute::AttrAttribute("state".to_string(), state_json);

    // The up-event handler: decode the posted string fail-closed into `Up`, then
    // map through the author's `on_up`. A decode failure drops the event (logs,
    // no partial value) — the seal boundary's fail-closed contract.
    let up_attr: Attribute<M> = Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnWidget(
        WIDGET_UP_EVENT.to_string(),
        std::sync::Arc::new(move |payload: String| {
            match seal_decode_serde::<Up>(&payload, SealLimits::default()) {
                Ok(up) => Some(on_up(up)),
                Err(e) => {
                    crate::system::emit_runtime_log("widget", &up_event_dropped_line(&e));
                    None
                }
            }
        }),
    )));

    Element::TaggedNode(
        ce.tag,
        Description::NoDescription,
        vec![state_attr, up_attr],
        Vec::new(),
    )
}

/// The runtime-log line for an up-event the seal refused.
///
/// It names the refusal reason only: a [`SealDecodeError`] carries a length, a
/// ceiling, or a fixed phrase with at most a position, so no byte of the
/// browser-posted payload reaches the log.
#[cfg(feature = "json")]
fn up_event_dropped_line(refusal: &SealDecodeError) -> String {
    format!("up-event dropped: {refusal}")
}

/// Non-`json` builds have no seal-codec substrate, so the widget seam has no
/// transport. The node degrades to an empty-child tagged element with no state
/// attribute and no up-handler — inert, never a wrong render. A `CustomElement.node`
/// program is a Web-shape program (`web` implies `json`), so this fallback is
/// not reached by a real widget build; it exists to keep the runtime library
/// buildable under every feature set (the `symbol_resolution` tripwire walks
/// every `pub fn`).
#[cfg(not(feature = "json"))]
#[must_use]
pub fn ui_widget_<M, Down, Up, F>(ce: IpeCustomElement, _state: Down, _on_up: F) -> Element<M> {
    Element::TaggedNode(ce.tag, Description::NoDescription, Vec::new(), Vec::new())
}

#[cfg(all(test, feature = "json"))]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::ui::element::{Attribute, Element};

    #[derive(serde::Serialize)]
    struct DownState {
        text: String,
    }

    #[derive(serde::Deserialize)]
    enum UpEvent {
        Changed(String),
    }

    #[derive(Clone, Debug, PartialEq)]
    enum Msg {
        Edited(String),
    }

    // XSS (Security #1): the down-state MUST cross as an entity-escaped
    // attribute, NEVER as raw HTML. Assert the emitted node carries the state as
    // an `AttrAttribute` (which the `Ipe.Ui`→HTML lowering routes through the
    // standard attribute escaper) and NOT an `Element::Raw`/`HRaw`. A hostile
    // string in the down value therefore cannot break out of the attribute.
    #[test]
    fn down_state_is_an_escaped_attribute_not_raw() {
        let ce = custom_element_("ipe-ce-cafef00d".to_string());
        let hostile = DownState {
            text: "\"><script>alert(1)</script>".to_string(),
        };
        let el: Element<Msg> = ui_widget_(ce, hostile, |UpEvent::Changed(s)| Msg::Edited(s));

        let Element::TaggedNode(tag, _desc, attrs, kids) = &el else {
            panic!("CustomElement.node must render a TaggedNode");
        };
        assert_eq!(tag.as_str(), "ipe-ce-cafef00d");
        assert!(kids.is_empty(), "the widget node has no children in WP4");

        // The state rides an AttrAttribute — the escaped-attribute carrier — and
        // the JSON payload is present verbatim in the attribute VALUE (escaping
        // happens at render, over this exact value; it is never spliced raw).
        let state = attrs.iter().find_map(|a| match a {
            Attribute::AttrAttribute(k, v) if k == "state" => Some(v.clone()),
            _ => None,
        });
        let state = state.expect("state must be an AttrAttribute(\"state\", _)");
        assert!(
            state.contains("script"),
            "the raw JSON (pre-escape) carries the value; render escapes it: {state}"
        );

        // Crucially: NO attribute is a raw/unescaped carrier, and the node holds
        // no `Element::Raw`. There is exactly one escaped state attribute plus one
        // up-event handler.
        assert!(
            !attrs
                .iter()
                .any(|a| matches!(a, Attribute::AttrStyle(k, _) if k == "__raw")),
            "the widget must never emit a raw/unescaped state carrier"
        );
        let has_up = attrs.iter().any(|a| {
            matches!(
                a,
                Attribute::AttrEvent(crate::html::Attribute::EventAttr(
                    crate::html::Event::OnWidget(name, _)
                )) if name == WIDGET_UP_EVENT
            )
        });
        assert!(has_up, "the widget must wire an OnWidget up-event handler");
    }

    /// A serde-derived `up` type with a non-string field.
    #[derive(serde::Deserialize)]
    struct Counted {
        count: i64,
    }

    /// A unit-variant `up` type, whose unknown-variant error names the tag.
    #[derive(serde::Deserialize)]
    enum Saved {
        Saved,
    }

    /// The refusal a browser-posted `payload` meets when decoded into `Up`.
    fn refusal_of<Up: serde::de::DeserializeOwned>(payload: &str) -> Option<SealDecodeError> {
        seal_decode_serde::<Up>(payload, SealLimits::default()).err()
    }

    /// The text a refusal can surface: its detail and the logged line.
    fn surfaced(refusal: &SealDecodeError) -> [String; 2] {
        [format!("{refusal:?}"), up_event_dropped_line(refusal)]
    }

    // A payload value the seal refuses never reaches the refusal or the log:
    // serde's own `Display` quotes it (`invalid type: string "SENTINEL"`,
    // `unknown variant `SENTINEL``), so the seal renders a fixed phrase instead.
    #[test]
    fn a_refused_up_payload_value_is_not_echoed() {
        let mismatched = refusal_of::<Counted>(r#"{"count":"SENTINEL"}"#);
        let unknown_tag = refusal_of::<Saved>(r#""SENTINEL""#);
        for refusal in [mismatched, unknown_tag] {
            assert!(
                matches!(refusal, Some(SealDecodeError::TypeMismatch { .. })),
                "the payload must be refused as a type mismatch: {refusal:?}"
            );
            let Some(refusal) = refusal else { return };
            for text in surfaced(&refusal) {
                assert!(
                    !text.contains("SENTINEL"),
                    "the refused payload value reached the surfaced text: {text}"
                );
            }
        }
    }

    // A syntax error names a grammar phrase and a position, never the bad token.
    #[test]
    fn a_malformed_up_payload_is_not_echoed() {
        let refusal = refusal_of::<Counted>(r#"{"count": SENTINEL}"#);
        assert!(
            matches!(refusal, Some(SealDecodeError::Malformed { .. })),
            "a syntax error must be refused as malformed: {refusal:?}"
        );
        let Some(refusal) = refusal else { return };
        for text in surfaced(&refusal) {
            assert!(
                !text.contains("SENTINEL"),
                "the malformed payload reached the surfaced text: {text}"
            );
        }
    }

    // The wired handler drops a refused payload: no msg is dispatched.
    #[test]
    fn the_up_handler_drops_a_refused_payload() {
        let ce = custom_element_("ipe-ce-cafef00d".to_string());
        let down = DownState {
            text: String::new(),
        };
        let el: Element<i64> = ui_widget_(ce, down, |up: Counted| up.count);
        assert!(
            matches!(el, Element::TaggedNode(..)),
            "CustomElement.node must render a TaggedNode"
        );
        let Element::TaggedNode(_, _, attrs, _) = &el else {
            return;
        };
        let handler = attrs.iter().find_map(|a| match a {
            Attribute::AttrEvent(crate::html::Attribute::EventAttr(
                crate::html::Event::OnWidget(_, handler),
            )) => Some(handler.clone()),
            _ => None,
        });
        assert!(handler.is_some(), "the widget must wire an up handler");
        let Some(handler) = handler else { return };
        assert_eq!(handler(r#"{"count":"SENTINEL"}"#.to_string()), None);
        assert_eq!(handler(r#"{"count":7}"#.to_string()), Some(7));
    }
}

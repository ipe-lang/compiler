use crate::html::{Attribute, Event, FormData, Html};
use std::collections::HashMap;

/// Per-session handler index: maps `ipe-id` → (`event-name` → the cloneable
/// `Event` that owns the handler closure, via `Arc`).
///
/// Built once per `view` commit via [`build_index`]; thrown away and rebuilt
/// on every update cycle (the view function is the single source of truth).
///
/// The two-level shape lets [`Self::resolve`] / [`Self::resolve_form`] look up
/// by `&str` (`HashMap<String, _>: get(&str)` via `Borrow<str>`) without
/// heap-allocating throwaway key Strings on the wire-event hot path.
pub struct HandlerIndex<M> {
    map: HashMap<String, HashMap<String, Event<M>>>,
}

impl<M: Clone> HandlerIndex<M> {
    /// Resolve a wire event from the browser.
    ///
    /// - `OnMsg`   — returns the message directly (args ignored).
    /// - `OnString`— calls the closure with `args[0]` (or `""` if absent).
    /// - `OnBool`  — calls the closure with `args[0] == "true"` (or `false`).
    /// - `OnForm`  — dispatched via [`Self::resolve_form`]; returns `None` here.
    /// - `OnWidget`— a `CustomElement.node` up-event: runs the generated fail-closed seal
    ///   decode over `args[0]` (the posted encoded `up` value) and returns the
    ///   typed msg, or `None` when the payload does not decode to the declared
    ///   `up` type (the seal boundary's fail-closed drop — no partial value).
    ///
    /// Returns `None` when the ipe-id is unknown or the event name doesn't
    /// match any registered handler.
    #[must_use]
    pub fn resolve(&self, ipe_id: &str, event: &str, args: &[String]) -> Option<M> {
        match self.map.get(ipe_id)?.get(event)? {
            Event::OnMsg(_, m) => Some(m.clone()),
            Event::OnString(_, f) => Some(f(args.first().cloned().unwrap_or_default())),
            Event::OnBool(_, f) => Some(f(args.first().is_some_and(|s| s == "true"))),
            Event::OnForm(_, _) => None, // dispatched via resolve_form
            // `f` already returns `Option<M>` (`None` on a fail-closed seal
            // decode); a missing `args[0]` decodes the empty string, which the
            // total decoder rejects — still a clean drop, never a panic.
            Event::OnWidget(_, f) => f(args.first().cloned().unwrap_or_default()),
        }
    }

    /// Resolve a form-submit event. Distinct from [`Self::resolve`] because
    /// the `FormData` map arrives via the form-submission wire path, not the
    /// positional `args` slice.
    #[must_use]
    pub fn resolve_form(&self, ipe_id: &str, event: &str, fd: FormData) -> Option<M> {
        match self.map.get(ipe_id)?.get(event)? {
            Event::OnForm(_, f) => f(fd), // f already returns Option<M> (None on decode failure)
            _ => None,
        }
    }
}

/// Build a [`HandlerIndex`] by walking `root` and collecting every
/// `Attribute::Event` keyed by its element's `ipe-id` + event name.
///
/// Precondition: `assign_ipe_ids` must have been called on `root` first.
/// Elements without a `ipe-id` attribute (shouldn't happen after assignment)
/// are indexed under the empty-string key, which is harmless — no browser
/// event will carry an empty ipe-id.
#[must_use]
pub fn build_index<M: Clone>(root: &Html<M>) -> HandlerIndex<M> {
    let mut map = HashMap::new();
    walk(root, &mut map);
    HandlerIndex { map }
}

/// Walk the view tree iteratively with an explicit heap work-stack.
///
/// Native recursion here would overflow the (uncatchable) thread stack on a
/// deeply nested view — e.g. a comment/thread tree whose nesting depth scales
/// with attacker-influenced data. An explicit `Vec` work-list keeps
/// index-building O(nodes) in heap memory, bounded only by allocation.
fn walk<M: Clone>(root: &Html<M>, map: &mut HashMap<String, HashMap<String, Event<M>>>) {
    let mut stack: Vec<&Html<M>> = vec![root];
    while let Some(n) = stack.pop() {
        if let Html::HElement(_, attrs, kids) = n {
            let id = attrs
                .iter()
                .find_map(|a| match a {
                    Attribute::Attr(k, v) if k == "ipe-id" => Some(v.as_str()),
                    _ => None,
                })
                .unwrap_or_default();

            for a in attrs {
                if let Attribute::EventAttr(e) = a {
                    map.entry(id.to_string())
                        .or_default()
                        .insert(e.name().to_string(), e.clone());
                }
            }

            for c in kids {
                stack.push(c);
            }
        }
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::assign_ipe_ids;

    #[derive(Clone, Debug, PartialEq)]
    enum Msg {
        Inc,
        Typed(String),
    }

    fn tree() -> Html<Msg> {
        let mut t = Html::HElement(
            "div".into(),
            vec![],
            vec![
                Html::HElement(
                    "button".into(),
                    vec![Attribute::EventAttr(Event::OnMsg("click".into(), Msg::Inc))],
                    vec![],
                ),
                Html::HElement(
                    "input".into(),
                    vec![Attribute::EventAttr(Event::OnString(
                        "input".into(),
                        std::sync::Arc::new(Msg::Typed),
                    ))],
                    vec![],
                ),
            ],
        );
        assign_ipe_ids(&mut t, "r");
        t
    }

    #[test]
    fn resolves_onmsg_and_onstring() {
        let idx = build_index(&tree());
        assert_eq!(idx.resolve("r_0_button", "click", &[]), Some(Msg::Inc));
        assert_eq!(
            idx.resolve("r_1_input", "input", &["hi".into()]),
            Some(Msg::Typed("hi".into()))
        );
        assert_eq!(idx.resolve("r_0_button", "input", &[]), None); // wrong event
        assert_eq!(idx.resolve("nope", "click", &[]), None); // unknown id
    }

    #[test]
    fn resolves_onbool() {
        let mut t = Html::HElement(
            "input".into(),
            vec![Attribute::EventAttr(Event::OnBool(
                "change".into(),
                std::sync::Arc::new(|b| {
                    if b {
                        Msg::Inc
                    } else {
                        Msg::Typed("off".into())
                    }
                }),
            ))],
            vec![],
        );
        assign_ipe_ids(&mut t, "r");
        let idx = build_index(&t);
        assert_eq!(idx.resolve("r", "change", &["true".into()]), Some(Msg::Inc));
        assert_eq!(
            idx.resolve("r", "change", &["false".into()]),
            Some(Msg::Typed("off".into()))
        );
    }

    #[test]
    fn resolves_onform() {
        let mut t = Html::HElement(
            "form".into(),
            vec![Attribute::EventAttr(Event::OnForm(
                "submit".into(),
                std::sync::Arc::new(|fd: FormData| {
                    Some(Msg::Typed(fd.get("name").cloned().unwrap_or_default()))
                }),
            ))],
            vec![],
        );
        assign_ipe_ids(&mut t, "r");
        let idx = build_index(&t);

        // resolve() returns None for OnForm; resolve_form() dispatches it.
        assert_eq!(idx.resolve("r", "submit", &[]), None);

        let mut fd = FormData::new();
        fd.insert("name".into(), "alice".into());
        assert_eq!(
            idx.resolve_form("r", "submit", fd),
            Some(Msg::Typed("alice".into()))
        );
    }

    // ui_on_submit_ only has a real impl under the `live` or `wasm-client`
    // feature; without it the stub returns NoAttribute and the test would panic.
    #[cfg(any(feature = "web", feature = "wasm-client"))]
    #[test]
    fn ui_on_submit_dispatches_via_onform_not_onraw() {
        use crate::ui::element::Attribute as UiAttribute;

        #[derive(serde::Deserialize, Default, PartialEq, Debug)]
        #[serde(default)]
        struct Creds {
            email: String,
            password: String,
        }

        let attr = crate::ui::helpers::ui_on_submit_(|c: Creds| {
            Msg::Typed(format!("{}:{}", c.email, c.password))
        });
        let html_attr = match attr {
            UiAttribute::AttrEvent(a) => a,
            other => panic!("expected AttrEvent, got {other:?}"),
        };
        let mut t = Html::HElement("form".into(), vec![html_attr], vec![]);
        assign_ipe_ids(&mut t, "r");
        let idx = build_index(&t);

        // Must dispatch via resolve_form (Event::OnForm), NOT resolve()
        // (which returns None for a submit event with no positional args).
        assert_eq!(idx.resolve("r", "submit", &[]), None);

        let mut fd = FormData::new();
        fd.insert("email".into(), "a@b.com".into());
        fd.insert("password".into(), "hunter2".into());
        assert_eq!(
            idx.resolve_form("r", "submit", fd),
            Some(Msg::Typed("a@b.com:hunter2".into()))
        );
    }

    // The `CustomElement.node` up-event: an `OnWidget` handler composes the fail-closed
    // seal decode over the posted string. A payload that decodes to the declared
    // `up` type dispatches the typed msg; one that does NOT is dropped whole
    // (`None`) — no partial value, no panic. This is the runtime proof of the
    // up-event seam's fail-closed contract (WP4, Security #2).
    #[cfg(feature = "json")]
    #[test]
    fn onwidget_up_event_decodes_fail_closed() {
        use crate::seal_codec::{SealLimits, seal_decode_serde};

        // A closed-ADT up type with serde derives (what a seal-legal type emits
        // in a Web program).
        #[derive(serde::Deserialize, Clone, Debug, PartialEq)]
        enum Up {
            Changed(String),
            Saved,
        }

        // The generated `OnWidget` closure shape: decode fail-closed, then map.
        let handler: std::sync::Arc<dyn Fn(String) -> Option<Msg> + Send + Sync> =
            std::sync::Arc::new(|payload: String| {
                match seal_decode_serde::<Up>(&payload, SealLimits::default()) {
                    Ok(Up::Changed(s)) => Some(Msg::Typed(s)),
                    Ok(Up::Saved) => Some(Msg::Inc),
                    Err(_) => None,
                }
            });

        let mut t = Html::HElement(
            "ipe-ce-deadbeef".into(),
            vec![Attribute::EventAttr(Event::OnWidget(
                "ipe-widget".into(),
                handler,
            ))],
            vec![],
        );
        assign_ipe_ids(&mut t, "r");
        let idx = build_index(&t);

        // A well-formed `Changed "hi"` payload decodes and dispatches.
        assert_eq!(
            idx.resolve("r", "ipe-widget", &[r#"{"Changed":"hi"}"#.into()]),
            Some(Msg::Typed("hi".into()))
        );
        // The nullary `Saved` variant.
        assert_eq!(
            idx.resolve("r", "ipe-widget", &[r#""Saved""#.into()]),
            Some(Msg::Inc)
        );
        // A payload that does NOT decode to `Up` is DROPPED — no partial value,
        // no panic. (Wrong tag, wrong shape, and a non-JSON string all drop.)
        assert_eq!(
            idx.resolve("r", "ipe-widget", &[r#"{"Bogus":1}"#.into()]),
            None
        );
        assert_eq!(idx.resolve("r", "ipe-widget", &["not json".into()]), None);
        assert_eq!(idx.resolve("r", "ipe-widget", &["{".into()]), None);
        // A missing arg decodes the empty string — still a clean drop.
        assert_eq!(idx.resolve("r", "ipe-widget", &[]), None);
    }

    #[test]
    fn onstring_empty_args_gives_default() {
        let mut t = Html::HElement(
            "input".into(),
            vec![Attribute::EventAttr(Event::OnString(
                "input".into(),
                std::sync::Arc::new(Msg::Typed),
            ))],
            vec![],
        );
        assign_ipe_ids(&mut t, "r");
        let idx = build_index(&t);
        // No args → closure receives ""
        assert_eq!(
            idx.resolve("r", "input", &[]),
            Some(Msg::Typed(String::new()))
        );
    }
}

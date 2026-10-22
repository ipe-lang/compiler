use crate::html::{
    Attribute, ElementBody, Html, ParseContext, RenderCtx, RenderedElement, admit_rendered_in,
};
use std::collections::HashMap;

/// A single DOM patch emitted by `diff` (JSON: `id`, `text`, `html`, `attrs`,
/// `remove`).
///
/// `diff` is in the always-compiled `dom` data path, but `Patch` is serialized
/// only by the Web SSE wire / the browser-WASM sink — surfaces that imply the
/// `serde` feature. The `Serialize` derive (and its `#[serde(...)]` field skips)
/// are therefore gated on `serde`: a program that reaches neither still builds
/// `Patch` and runs `diff`, it simply cannot serialize the patch (no such call
/// exists in that config). Behaviour is byte-identical where serde is on.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Patch {
    pub id: String,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub text: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub html: Option<String>,
    /// Attribute delta: present key with non-empty value → set; empty value → remove.
    /// Convention: `""` means remove; `BoolAttr(k,true)` encodes as `{k:k}`.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "HashMap::is_empty"))]
    pub attrs: HashMap<String, String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "std::ops::Not::not"))]
    pub remove: bool,
}

impl Patch {
    fn for_id(id: &str) -> Self {
        Patch {
            id: id.into(),
            text: None,
            html: None,
            attrs: HashMap::new(),
            remove: false,
        }
    }
}

/// Structural diff between two `Html` trees that have already had `assign_ipe_ids`
/// applied. Returns the minimal list of `Patch` operations needed to update the
/// DOM from `old` to `new`:
/// - Same-node element pair (equal tag AND equal `ipe-id`): diff attributes +
///   events, then children.
/// - Tag/kind mismatch, server-identity (`ipe-id`) mismatch, child-count
///   change, or any mixed-child text change: whole-subtree `html` replace at
///   the parent, so every element in the DOM carries the `ipe-id` of the node
///   it now renders.
/// - Sole text-child change: `SetText` via `p.text` (fast path).
/// - Event handlers toggled on/off: `ipe-<event>` attr set/remove + `data-ipe-hid`.
/// - Keyed identity is carried by `assign_ipe_ids` (the `:{key}` segment): a
///   position whose key differs between the trees holds a different node, so
///   its parent's children are replaced rather than patched under the old id.
///
/// Every subtree a patch carries as markup is rendered under `stamp`, the
/// render context of the session the patches are sent to.
#[must_use]
pub fn diff<M>(old: &Html<M>, new: &Html<M>, stamp: &RenderCtx<'_>) -> Vec<Patch> {
    let mut out = vec![];
    // A root has no ancestor to hand an unaddressed change to. Every caller
    // stamps the root through `assign_ipe_ids` with a non-empty path, so the
    // root is addressable and its pair never reports `Unaddressed`.
    let (Reach::Patched | Reach::Unaddressed) =
        diff_node_depth(old, new, ParseContext::Data, &mut out, 0, stamp);
    out
}

/// The page events after which the load's own autofocus is spent: the user
/// pressed a key or the pointer, or focus moved, before the first paint could
/// focus anything. `client.js` listens for the same list at load; the wasm
/// loader hears them through [`autofocus_spent_listener_js`].
pub const AUTOFOCUS_SPENDING_EVENTS: [&str; 5] = [
    "focusin",
    "pointerdown",
    "mousedown",
    "touchstart",
    "keydown",
];

/// Whether every name is non-empty ASCII lowercase letters, which need no
/// escaping inside a JavaScript string in a `<script>`.
const fn spending_events_plain() -> bool {
    let mut names: &[&str] = &AUTOFOCUS_SPENDING_EVENTS;
    while let [name, rest @ ..] = names {
        let mut bytes = name.as_bytes();
        if bytes.is_empty() {
            return false;
        }
        while let [byte, tail @ ..] = bytes {
            if !byte.is_ascii_lowercase() {
                return false;
            }
            bytes = tail;
        }
        names = rest;
    }
    true
}
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if an autofocus-spending event name is empty or holds a byte other than an ASCII lowercase letter [ledger #boundary]
const _: () = assert!(spending_events_plain());

/// The page global the wasm loader sets once one of
/// [`AUTOFOCUS_SPENDING_EVENTS`] fires; the wasm first paint reads it.
pub const AUTOFOCUS_SPENT_GLOBAL: &str = "__ipeAutofocusSpent";

/// The `keyCode` a browser gives a key an input method takes for its
/// composition; neither client counts such a key as the user's act.
pub const COMPOSING_KEY_CODE: u32 = 229;

/// [`AUTOFOCUS_SPENDING_EVENTS`] as a JavaScript array literal.
#[must_use]
pub fn autofocus_spending_events_js() -> String {
    let mut out = String::from("[");
    for (i, name) in AUTOFOCUS_SPENDING_EVENTS.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push('"');
        crate::escape::json_str_body_into(name, &mut out);
        out.push('"');
    }
    out.push(']');
    out
}

/// The loader statements that set [`AUTOFOCUS_SPENT_GLOBAL`] on the first of
/// [`AUTOFOCUS_SPENDING_EVENTS`], each heard in the capture phase from the
/// moment the loader runs, before the wasm module is fetched.
#[must_use]
pub fn autofocus_spent_listener_js() -> String {
    let mut out = String::from("for (const type of ");
    out.push_str(&autofocus_spending_events_js());
    out.push_str(") {\n  document.addEventListener(type, () => { globalThis.");
    out.push_str(AUTOFOCUS_SPENT_GLOBAL);
    out.push_str(" = true; }, true);\n}\n");
    out
}

/// The server identity of a stamped element that a render asks to focus.
///
/// It is built only from the `ipe-id` the stamper wrote on an element of a
/// rendered tree, never from program text, so the client resolves it with the
/// same `[ipe-id=…]` lookup a patch uses.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(transparent))]
pub struct StampedId(String);

impl StampedId {
    /// The stamped `ipe-id`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The element a render moves keyboard focus onto, if any.
///
/// It is the first element of `new`, in document order, that is on the page,
/// carries a stamped `ipe-id` and an `autofocus` attribute, and whose identity
/// carried no `autofocus` in `old`. The answer depends only on the two trees,
/// never on how `diff` patches between them.
#[must_use]
pub fn focus_target<M>(old: &Html<M>, new: &Html<M>) -> Option<StampedId> {
    let mut before = std::collections::HashSet::new();
    for_each_autofocus(old, |id| {
        before.insert(id);
        false
    });
    let mut found = None;
    for_each_autofocus(new, |id| {
        if before.contains(id) {
            return false;
        }
        found = Some(StampedId(id.to_owned()));
        true
    });
    found
}

/// Whether `attrs` render an `autofocus` attribute.
///
/// A `BoolAttr(_, false)` renders nothing, so it neither adds nor removes one.
fn has_autofocus<M>(attrs: &[Attribute<M>]) -> bool {
    attrs.iter().any(|a| match a {
        Attribute::Attr(k, _) | Attribute::BoolAttr(k, true) => k.eq_ignore_ascii_case("autofocus"),
        Attribute::BoolAttr(_, false) | Attribute::EventAttr(_) | Attribute::NoAttr => false,
    })
}

/// Visit the stamped `ipe-id` of each autofocus element of `root`, in document
/// order, until `visit` returns true.
///
/// The walk admits nodes as the render sink does: a refused element is absent
/// with its subtree, the `Html.doctype` wrapper is no element of its own, a
/// raw-text body and the children of an RCDATA or RAWTEXT element are text, a
/// `<template>`'s children are not in the document, and `HText` and `HRaw` are
/// opaque. It stops at `MAX_HTML_DEPTH`, past which nothing is rendered, and
/// keeps its own worklist, so the tree's depth never reaches the thread stack.
fn for_each_autofocus<'a, M>(root: &'a Html<M>, mut visit: impl FnMut(&'a str) -> bool) {
    let mut work: Vec<(&'a Html<M>, ParseContext, usize)> = vec![(root, ParseContext::Data, 0)];
    while let Some((node, ctx, depth)) = work.pop() {
        if depth >= crate::html::MAX_HTML_DEPTH {
            continue;
        }
        let Html::HElement(tag, attrs, kids) = node else {
            continue;
        };
        let Ok(rendered) = admit_rendered_in(ctx, tag, kids) else {
            continue;
        };
        let child_ctx = match rendered {
            RenderedElement::Doctype => ctx,
            RenderedElement::Element(ElementBody::Script | ElementBody::Style) => continue,
            RenderedElement::Element(ElementBody::Markup) => {
                if has_autofocus(attrs)
                    && let Some(id) = address(node)
                    && visit(id)
                {
                    return;
                }
                if tag.eq_ignore_ascii_case("template") {
                    continue;
                }
                ctx.enter(tag)
            }
        };
        if child_ctx == ParseContext::RawOrRcdata {
            continue;
        }
        let child_depth = depth.saturating_add(1);
        work.extend(kids.iter().rev().map(|k| (k, child_ctx, child_depth)));
    }
}

/// Whether every change between an element pair reached the patch list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
enum Reach {
    /// Every change is in the patch list, or the pair has none.
    Patched,
    /// The pair differs, but the change lies at an element with no `ipe-id`,
    /// which no patch can address; the nearest addressable ancestor must
    /// replace its children.
    Unaddressed,
}

// ─── internal helpers ─────────────────────────────────────────────────────────

fn ipe_id<M>(n: &Html<M>) -> Option<&str> {
    if let Html::HElement(_, attrs, _) = n {
        for a in attrs {
            if let Attribute::Attr(k, v) = a
                && k == "ipe-id"
            {
                return Some(v);
            }
        }
    }
    None
}

/// The `ipe-id` a patch to `n` is sent to, or `None` when no patch can reach it.
fn address<M>(n: &Html<M>) -> Option<&str> {
    ipe_id(n).filter(|id| !id.is_empty())
}

/// True when `old` and `new` are the same node for in-place patching: both
/// elements with equal tags and equal server identity (`ipe-id`). An element
/// unstamped on both sides lies past the stamping depth ceiling, where the
/// renderer writes no node and `diff_node_depth` emits nothing, or was built
/// after the stamper ran, where `diff_node_depth` reports a change beneath it
/// as [`Reach::Unaddressed`].
fn same_node<M>(old: &Html<M>, new: &Html<M>) -> bool {
    match (old, new) {
        (Html::HElement(ot, _, _), Html::HElement(nt, _, _)) => {
            ot == nt && ipe_id(old) == ipe_id(new)
        }
        _ => false,
    }
}

/// Emit a replace of every child of the element at `id`.
///
/// With no `id` the replace cannot be addressed, so the change is handed to
/// the nearest addressable ancestor as [`Reach::Unaddressed`].
///
/// `parent_body` is how `admit_rendered_in` admitted that element and
/// `child_ctx` is the parse context it puts its children in. A markup body
/// is sent as `Patch.html`, which the client parses as markup. A `<script>` or
/// `<style>` body is a raw-text body: it is sent as `Patch.text`, which the
/// client assigns to `textContent` without parsing, so the element holds the
/// same neutralised bytes the first paint's raw-text parse produced. Sent as
/// `html`, the body would be parsed in a `<div>` context, where an
/// `<img onerror>` or a `<script src>` inside it is live markup and an entity
/// such as `&amp;` is decoded.
fn push_children_replace<M>(
    id: Option<&str>,
    parent_body: ElementBody,
    child_ctx: ParseContext,
    new_kids: &[Html<M>],
    out: &mut Vec<Patch>,
    stamp: &RenderCtx<'_>,
) -> Reach {
    let Some(id) = id else {
        return Reach::Unaddressed;
    };
    let mut p = Patch::for_id(id);
    let body = render_children(parent_body, child_ctx, new_kids, stamp);
    match parent_body {
        ElementBody::Markup => p.html = Some(body),
        ElementBody::Script | ElementBody::Style => p.text = Some(body),
    }
    out.push(p);
    Reach::Patched
}

/// True when `node`, written in `ctx`, is an element the render sink's
/// admission rule refuses, so the renderer leaves it out of the page.
fn is_refused_element<M>(ctx: ParseContext, node: &Html<M>) -> bool {
    match node {
        Html::HElement(tag, _, kids) => admit_rendered_in(ctx, tag, kids).is_err(),
        Html::HText(_) | Html::HRaw(_) => false,
    }
}

/// Bounded-descent diff. Stops at `MAX_HTML_DEPTH` (same ceiling as
/// `html.rs::render_into_ctx`) rather than recursing into an arbitrarily deep
/// Model-derived tree that would overflow the thread stack. `ctx` is the parse
/// context both nodes are written in, threaded from the root exactly as the
/// render sink threads it, and `stamp` is the session's render context.
///
/// A change at an element with no `ipe-id` is never dropped: it returns
/// [`Reach::Unaddressed`], and the first addressable ancestor replaces its
/// children, re-rendering the change.
fn diff_node_depth<M>(
    old: &Html<M>,
    new: &Html<M>,
    ctx: ParseContext,
    out: &mut Vec<Patch>,
    depth: usize,
    stamp: &RenderCtx<'_>,
) -> Reach {
    // Past the ceiling the renderer writes no node, so there is nothing to patch.
    if depth >= crate::html::MAX_HTML_DEPTH {
        return Reach::Patched;
    }
    let (ot, oa, ok, nt, na, nk) = match (old, new) {
        (Html::HElement(ot, oa, ok), Html::HElement(nt, na, nk)) if same_node(old, new) => {
            (ot, oa, ok, nt, na, nk)
        }
        // A tag, kind, or identity mismatch is handled by the parent's
        // per-position loop. A top-level mismatch has no parent to address,
        // so nothing is emitted; every caller stamps both trees from the same
        // root path, which a root's `ipe-id` equals, so a top-level identity
        // mismatch does not arise.
        _ => return Reach::Patched,
    };
    // SECURITY: the render sink's own admission rule. A refused element is
    // absent from the rendered page, so neither side of a refused pair has a
    // DOM node to patch; a parent whose child changes admission replaces its
    // whole subtree (see the per-position loop), which re-renders through the
    // same rule. The `Html.doctype` wrapper is admitted as markup, so a view
    // rooted at it is diffed through to its children.
    let (Ok(new_rendered), Ok(_)) = (
        admit_rendered_in(ctx, nt, nk),
        admit_rendered_in(ctx, ot, ok),
    ) else {
        return Reach::Patched;
    };
    let body = new_rendered.body();
    let child_ctx = ctx.enter(nt);
    // Patch id targets the element currently in the DOM: the OLD tree's id.
    // Borrowed: `Patch::for_id` copies it only when a Patch is actually built,
    // so an unchanged element pair allocates nothing here.
    let id = address(old);

    // Attribute + event delta.
    let mut p = Patch::for_id(id.unwrap_or_default());
    diff_attrs(oa, na, &mut p);
    if !p.attrs.is_empty() {
        if id.is_none() {
            return Reach::Unaddressed;
        }
        out.push(p);
    }

    // Sole text-child fast path (common for buttons / spans).
    if ok.len() == 1
        && nk.len() == 1
        && let (Some(Html::HText(o)), Some(Html::HText(n))) = (ok.first(), nk.first())
    {
        if o != n {
            let Some(id) = id else {
                return Reach::Unaddressed;
            };
            let mut tp = Patch::for_id(id);
            tp.text = Some(n.clone());
            out.push(tp);
        }
        return Reach::Patched;
    }

    // Child-count change → replace the whole subtree.
    if ok.len() != nk.len() {
        return push_children_replace(id, body, child_ctx, nk, out, stamp);
    }

    let child_depth = depth.saturating_add(1);
    // Per-position structural diff.
    for (oc, nc) in ok.iter().zip(nk.iter()) {
        match (oc, nc) {
            (Html::HText(o), Html::HText(n)) => {
                // Mixed-child text change → replace the whole subtree at the parent
                // (single-text is the fast path above; anything else is a
                // parent html-replace).
                if o != n {
                    return push_children_replace(id, body, child_ctx, nk, out, stamp);
                }
            }
            // A changed trusted raw body (a dynamic `styleNode`, an
            // `unsafeRaw` fragment) re-renders the parent's children through
            // the same body class the first paint used.
            (Html::HRaw(o), Html::HRaw(n)) => {
                if o != n {
                    return push_children_replace(id, body, child_ctx, nk, out, stamp);
                }
            }
            (Html::HElement(..), Html::HElement(..)) if same_node(oc, nc) => {
                // A child that gains or loses admission appears in or vanishes
                // from the page, so the parent's subtree is replaced.
                if is_refused_element(child_ctx, oc) != is_refused_element(child_ctx, nc) {
                    return push_children_replace(id, body, child_ctx, nk, out, stamp);
                }
                // A change the child cannot address is re-rendered here.
                if diff_node_depth(oc, nc, child_ctx, out, child_depth, stamp) == Reach::Unaddressed
                {
                    return push_children_replace(id, body, child_ctx, nk, out, stamp);
                }
            }
            // Tag / kind / identity mismatch → replace the subtree at the parent.
            _ => {
                return push_children_replace(id, body, child_ctx, nk, out, stamp);
            }
        }
    }
    Reach::Patched
}

/// Compute the attribute + event delta between `old` and `new`.
/// Keys changed or added → new value. Keys removed → `""` (signals removal).
/// `ipe-id` is excluded (never patched as an attribute).
fn diff_attrs<M>(old: &[Attribute<M>], new: &[Attribute<M>], p: &mut Patch) {
    // Borrowed maps: cloning every key AND value of every element into two
    // owned HashMaps per diff was the hottest allocation in the SSE path
    // (efficiency-audit §6 high). The changed/added/removed key set is
    // identical owned-or-borrowed; only `insert_safe_attr` (which already
    // copies, post-XSS-gate) allocates, and only for changed attrs.
    // (A named fn, not a closure — fn lifetime elision ties the borrowed map
    // to the argument slice; closure elision can't express that tie.)
    fn collect<M>(xs: &[Attribute<M>]) -> HashMap<&str, &str> {
        let mut m = HashMap::new();
        for a in xs {
            match a {
                Attribute::Attr(k, v) if k != "ipe-id" => {
                    m.insert(k.as_str(), v.as_str());
                }
                Attribute::BoolAttr(k, true) => {
                    // Key-as-value (`attr = k`) encodes a present boolean attr;
                    // "" is the remove sentinel only.
                    m.insert(k.as_str(), k.as_str());
                }
                _ => {}
            }
        }
        m
    }
    let (om, nm) = (collect(old), collect(new));
    for (k, v) in &nm {
        if om.get(k) != Some(v) {
            insert_safe_attr(p, k, v);
        }
    }
    for k in om.keys() {
        if !nm.contains_key(k) {
            // Signal removal with empty string.
            insert_safe_attr(p, k, "");
        }
    }
    diff_events(old, new, p);
}

/// Insert an attribute into a patch ONLY if it passes the same XSS policy the
/// first-paint renderer applies ([`crate::html::safe_patch_attr`]):
/// attribute-name gate (no `on*` handlers / `srcdoc` / structural-breakout
/// charset) + URL-scheme sanitisation of the value. SSE patches are applied by
/// the browser via `setAttribute`, which bypasses `render_into_ctx`'s gates, so
/// this is THE gate for the patch path. A name that fails policy is dropped.
fn insert_safe_attr(p: &mut Patch, key: &str, val: &str) {
    if let Some((k, v)) = crate::html::safe_patch_attr(key, val) {
        p.attrs.insert(k.to_string(), v.to_string());
    }
}

/// Event-handler delta: an element gaining a handler emits `ipe-<event>` =
/// `<event>` (the value the client posts back as `msg`, matching `render_html`)
/// plus a fresh `data-ipe-hid`; an element losing a handler emits
/// `ipe-<event>` = `""` (remove), and clears `data-ipe-hid` once the last
/// handler is gone. Without this, toggling a handler leaves a stale listener
/// marker and the user's gesture is silently dropped.
fn diff_events<M>(old: &[Attribute<M>], new: &[Attribute<M>], p: &mut Patch) {
    let names = |xs: &[Attribute<M>]| -> Vec<String> {
        xs.iter()
            .filter_map(|a| match a {
                Attribute::EventAttr(e) => Some(e.name().to_string()),
                _ => None,
            })
            .collect()
    };
    // Wire-marker key per event name — MUST match render_html's emission
    // (html.rs): file/image meta-events are already `ipe-`-prefixed and the
    // client reads them as `data-ipe-ev-<name>`; plain DOM events use
    // `ipe-<name>`. Render and diff disagreeing here = a dead listener or a
    // spurious patch.
    let ev_key = |ev: &str| -> String {
        if ev.starts_with("ipe-") {
            format!("data-ipe-ev-{ev}")
        } else {
            format!("ipe-{ev}")
        }
    };
    let (on, nn) = (names(old), names(new));
    let id = p.id.clone();
    let hid = crate::html::HANDLER_ID_ATTR;
    for ev in &nn {
        if !on.contains(ev) {
            insert_marker_attr(p, &ev_key(ev), ev);
            insert_marker_attr(p, hid, &id);
        }
    }
    for ev in &on {
        if !nn.contains(ev) {
            insert_marker_attr(p, &ev_key(ev), "");
            if nn.is_empty() {
                insert_marker_attr(p, hid, "");
            }
        }
    }
}

/// Insert a listener marker of the event delta through
/// [`crate::html::patch_marker_attr`]; a program-built attribute takes
/// [`insert_safe_attr`] instead, which refuses every runtime wire-marker name.
fn insert_marker_attr(p: &mut Patch, key: &str, val: &str) {
    if let Some((k, v)) = crate::html::patch_marker_attr(key, val) {
        p.attrs.insert(k.to_string(), v.to_string());
    }
}

/// Render `kids` into an HTML string for an SSE innerHTML replace.
///
/// The children render through `render_children_into` with the parent's
/// admitted body class, the same path the first-paint renderer takes, so a
/// `<script>`/`<style>` body is neutralised and a refused child is left out.
fn render_children<M>(
    parent_body: ElementBody,
    child_ctx: ParseContext,
    kids: &[Html<M>],
    stamp: &RenderCtx<'_>,
) -> String {
    let mut s = String::new();
    crate::html::render_children_into(parent_body, child_ctx, kids, &mut s, stamp);
    s
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::{Event, assign_ipe_ids};

    /// The diff of an unstamped render.
    fn plain<M>(old: &Html<M>, new: &Html<M>) -> Vec<Patch> {
        diff(old, new, &RenderCtx::Unstamped)
    }

    fn ids(h: &mut Html<()>) {
        assign_ipe_ids(h, "r");
    }

    #[test]
    fn diff_text_change() {
        let mut a: Html<()> = Html::HElement("p".into(), vec![], vec![Html::HText("1".into())]);
        let mut b: Html<()> = Html::HElement("p".into(), vec![], vec![Html::HText("2".into())]);
        ids(&mut a);
        ids(&mut b);
        let p = plain(&a, &b);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].id, "r");
        assert_eq!(p[0].text.as_deref(), Some("2"));
    }

    #[test]
    fn diff_attr_set_and_remove() {
        let mut a: Html<()> = Html::HElement(
            "div".into(),
            vec![Attribute::Attr("class".into(), "x".into())],
            vec![],
        );
        let mut b: Html<()> = Html::HElement(
            "div".into(),
            vec![
                Attribute::Attr("class".into(), "y".into()),
                Attribute::Attr("title".into(), "t".into()),
            ],
            vec![],
        );
        ids(&mut a);
        ids(&mut b);
        let p = plain(&a, &b);
        assert_eq!(p.len(), 1);
        let attrs = &p[0].attrs;
        assert_eq!(attrs.get("class").map(String::as_str), Some("y"));
        assert_eq!(attrs.get("title").map(String::as_str), Some("t"));
    }

    #[test]
    fn diff_drops_event_handler_attr_name_in_patch() {
        // SSE-patch XSS gate: an attacker-influenced attribute change to an
        // event-handler name (onerror) must be DROPPED from the patch — the
        // browser applies patches via setAttribute, bypassing the first-paint
        // render gate, so this is the only thing standing between the value and
        // an executing handler.
        let mut a: Html<()> = Html::HElement(
            "img".into(),
            vec![Attribute::Attr("src".into(), "/a.png".into())],
            vec![],
        );
        let mut b: Html<()> = Html::HElement(
            "img".into(),
            vec![
                Attribute::Attr("src".into(), "/a.png".into()),
                Attribute::Attr("onerror".into(), "alert(1)".into()),
            ],
            vec![],
        );
        ids(&mut a);
        ids(&mut b);
        let p = plain(&a, &b);
        // The onerror attr never reaches the patch; only the (unchanged) src is
        // absent too, so the patch carries no dangerous attribute.
        assert!(
            p.iter().all(|patch| !patch.attrs.contains_key("onerror")),
            "onerror must be gated out of the patch"
        );
    }

    #[test]
    fn diff_neutralises_javascript_url_in_patch() {
        // A href changing to a javascript: scheme must be neutralised to empty
        // in the patch (same policy as the render sink), not passed through to
        // setAttribute verbatim.
        let mut a: Html<()> = Html::HElement(
            "a".into(),
            vec![Attribute::Attr("href".into(), "/safe".into())],
            vec![],
        );
        let mut b: Html<()> = Html::HElement(
            "a".into(),
            vec![Attribute::Attr("href".into(), "javascript:alert(1)".into())],
            vec![],
        );
        ids(&mut a);
        ids(&mut b);
        let p = plain(&a, &b);
        assert_eq!(p.len(), 1);
        // href is still patched (the key passes the name gate) but the
        // dangerous value is neutralised to empty.
        assert_eq!(p[0].attrs.get("href").map(String::as_str), Some(""));
    }

    #[test]
    fn diff_identical_is_empty() {
        let mut a: Html<()> = Html::HElement("p".into(), vec![], vec![Html::HText("1".into())]);
        let mut b = a.clone();
        ids(&mut a);
        ids(&mut b);
        assert!(plain(&a, &b).is_empty());
    }

    #[test]
    fn diff_bool_attr_add_uses_key_as_value() {
        let mut a: Html<()> = Html::HElement("button".into(), vec![], vec![]);
        let mut b: Html<()> = Html::HElement(
            "button".into(),
            vec![Attribute::BoolAttr("disabled".into(), true)],
            vec![],
        );
        ids(&mut a);
        ids(&mut b);
        let p = plain(&a, &b);
        assert_eq!(p.len(), 1);
        // present BoolAttr encodes as {k: k}, NOT {k: ""}.
        assert_eq!(
            p[0].attrs.get("disabled").map(String::as_str),
            Some("disabled")
        );
    }

    #[test]
    fn diff_event_added_emits_marker_and_hid() {
        // <button> gains an onClick: client needs ipe-click + data-ipe-hid to bind.
        let mut a: Html<()> = Html::HElement("button".into(), vec![], vec![]);
        let mut b: Html<()> = Html::HElement(
            "button".into(),
            vec![Attribute::EventAttr(Event::OnMsg(
                "click".into(),
                Box::new(()),
            ))],
            vec![],
        );
        ids(&mut a);
        ids(&mut b);
        let p = plain(&a, &b);
        assert_eq!(p.len(), 1);
        assert_eq!(
            p[0].attrs.get("ipe-click").map(String::as_str),
            Some("click")
        );
        assert_eq!(
            p[0].attrs.get("data-ipe-hid").map(String::as_str),
            Some("r")
        );
    }

    #[test]
    fn diff_event_removed_clears_marker_and_hid() {
        let mut a: Html<()> = Html::HElement(
            "button".into(),
            vec![Attribute::EventAttr(Event::OnMsg(
                "click".into(),
                Box::new(()),
            ))],
            vec![],
        );
        let mut b: Html<()> = Html::HElement("button".into(), vec![], vec![]);
        ids(&mut a);
        ids(&mut b);
        let p = plain(&a, &b);
        assert_eq!(p.len(), 1);
        // Removal sentinel: empty string for both the marker and the (now-stale) hid.
        assert_eq!(p[0].attrs.get("ipe-click").map(String::as_str), Some(""));
        assert_eq!(p[0].attrs.get("data-ipe-hid").map(String::as_str), Some(""));
    }

    /// A program-built handler id is never patched onto an element: the
    /// client would post the element's gestures under that forged id.
    #[test]
    fn program_built_handler_id_is_never_patched() {
        let button = |hid: &str| -> Html<()> {
            Html::HElement(
                "button".into(),
                vec![
                    Attribute::Attr("data-ipe-hid".into(), hid.into()),
                    Attribute::EventAttr(Event::OnMsg("click".into(), Box::new(()))),
                ],
                vec![],
            )
        };
        let mut a = button("r_1_button");
        let mut b = button("r_9_button");
        ids(&mut a);
        ids(&mut b);
        assert!(plain(&a, &b).is_empty());
        let mut patch = Patch {
            id: "r".into(),
            text: None,
            html: None,
            attrs: HashMap::new(),
            remove: false,
        };
        diff_attrs::<()>(
            &[],
            &[Attribute::Attr("data-ipe-hid".into(), "r_9_button".into())],
            &mut patch,
        );
        assert!(patch.attrs.is_empty(), "{patch:?}");
    }

    #[test]
    fn diff_mixed_child_text_change_replaces_parent() {
        // Parent with [<span>, text]; the text child changes → parent html-replace
        // (the sole-text fast path doesn't apply to mixed children).
        let mk = |t: &str| -> Html<()> {
            Html::HElement(
                "div".into(),
                vec![],
                vec![
                    Html::HElement("span".into(), vec![], vec![]),
                    Html::HText(t.into()),
                ],
            )
        };
        let mut a = mk("x");
        let mut b = mk("y");
        ids(&mut a);
        ids(&mut b);
        let p = plain(&a, &b);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].id, "r");
        assert!(p[0].html.is_some(), "expected html replace, got {:?}", p[0]);
        assert!(p[0].text.is_none());
    }

    #[test]
    fn diff_child_count_change_replaces_parent() {
        let mut a: Html<()> = Html::HElement(
            "ul".into(),
            vec![],
            vec![Html::HElement("li".into(), vec![], vec![])],
        );
        let mut b: Html<()> = Html::HElement(
            "ul".into(),
            vec![],
            vec![
                Html::HElement("li".into(), vec![], vec![]),
                Html::HElement("li".into(), vec![], vec![]),
            ],
        );
        ids(&mut a);
        ids(&mut b);
        let p = plain(&a, &b);
        assert_eq!(p.len(), 1);
        assert!(p[0].html.is_some());
    }

    #[test]
    fn diff_bool_attr_remove_uses_empty_string() {
        let mut a: Html<()> = Html::HElement(
            "button".into(),
            vec![Attribute::BoolAttr("disabled".into(), true)],
            vec![],
        );
        let mut b: Html<()> = Html::HElement("button".into(), vec![], vec![]);
        ids(&mut a);
        ids(&mut b);
        let p = plain(&a, &b);
        assert_eq!(p.len(), 1);
        // Removal sentinel: empty string.
        assert_eq!(p[0].attrs.get("disabled").map(String::as_str), Some(""));
    }

    // RT-UI-001: depth cap — diff must return (not abort/stack-overflow) when
    // diffing two trees that are deeper than MAX_HTML_DEPTH (1024). We build
    // chains of depth 5000 and assert diff completes.
    #[test]
    fn diff_depth_cap_does_not_overflow() {
        const DEPTH: usize = 5_000;

        fn make_chain(depth: usize) -> Html<()> {
            let mut h: Html<()> = Html::HText("leaf".into());
            for _ in 0..depth {
                h = Html::HElement("div".into(), vec![], vec![h]);
            }
            h
        }

        let mut old = make_chain(DEPTH);
        let mut new = make_chain(DEPTH);
        assign_ipe_ids(&mut old, "r");
        assign_ipe_ids(&mut new, "r");
        // This call must return, not overflow the stack.
        let patches = plain(&old, &new);
        // Identical trees produce no patches (or only structural no-ops).
        // The exact count is less important than the call completing.
        let _ = patches;
    }

    // RT-SEC-001: SSE innerHTML-replace on a `<script>` element neutralises any
    // `</script>` sequence in a trusted raw child: the injected close-tag cannot
    // terminate the element early on the browser's HTML parser, even when the
    // patch is applied via `innerHTML`.
    #[test]
    fn diff_sse_script_replace_neutralises_close_tag() {
        // Child-count is 1 -> 2, so a whole-subtree innerHTML replace fires.
        let mut old: Html<()> =
            Html::HElement("script".into(), vec![], vec![Html::HRaw("// safe".into())]);
        let mut new: Html<()> = Html::HElement(
            "script".into(),
            vec![],
            vec![
                Html::HRaw("// safe".into()),
                Html::HRaw("</script><img onerror=alert(1)>".into()),
            ],
        );
        ids(&mut old);
        ids(&mut new);
        let p = plain(&old, &new);
        assert_eq!(p.len(), 1, "expected exactly one text-replace patch");
        let Some(patch) = p.first() else {
            return;
        };
        assert!(
            patch.html.is_none(),
            "raw-text body never rides html: {patch:?}"
        );
        let Some(text) = patch.text.as_deref() else {
            assert!(patch.text.is_some(), "expected a text patch: {patch:?}");
            return;
        };
        assert!(
            !text.to_ascii_lowercase().contains("</script"),
            "`</script` byte run must be neutralised; got: {text:?}"
        );
    }

    // RT-SEC-002: SSE innerHTML-replace on a `<style>` element strips any
    // `</style>` sequence in a trusted raw child and opens no markup.
    #[test]
    fn diff_sse_style_replace_strips_close_tag() {
        let mut old: Html<()> = Html::HElement(
            "style".into(),
            vec![],
            vec![Html::HRaw("body { color: red }".into())],
        );
        let mut new: Html<()> = Html::HElement(
            "style".into(),
            vec![],
            vec![
                Html::HRaw("body { color: red }".into()),
                Html::HRaw("</style><script>alert(1)</script>".into()),
            ],
        );
        ids(&mut old);
        ids(&mut new);
        let p = plain(&old, &new);
        assert_eq!(p.len(), 1, "expected exactly one text-replace patch");
        let Some(patch) = p.first() else {
            return;
        };
        assert!(
            patch.html.is_none(),
            "raw-text body never rides html: {patch:?}"
        );
        let Some(text) = patch.text.as_deref() else {
            assert!(patch.text.is_some(), "expected a text patch: {patch:?}");
            return;
        };
        assert!(
            !text.contains("</style"),
            "`</style` byte run must be stripped; got: {text:?}"
        );
        assert!(
            !text.contains("<script"),
            "no markup may open; got: {text:?}"
        );
    }

    /// A `<script>`/`<style>` whose body is text is refused by the shared tag
    /// gate, so the diff patches nothing into it: no `text` fast-path patch and
    /// no `html` replace carrying the text.
    #[test]
    fn diff_refused_raw_text_element_emits_no_patch() {
        for tag in ["script", "SCRIPT", "style", "Style"] {
            let mut old: Html<()> =
                Html::HElement(tag.into(), vec![], vec![Html::HText("a".into())]);
            let mut new: Html<()> = Html::HElement(
                tag.into(),
                vec![],
                vec![Html::HText("alert(document.cookie)".into())],
            );
            ids(&mut old);
            ids(&mut new);
            assert!(
                plain(&old, &new).is_empty(),
                "<{tag}> text body must not be patched"
            );
        }
    }

    /// A child `<script>` that turns from a trusted raw body into a text body
    /// leaves the page: the parent is replaced, and the replacement html holds
    /// no script element and no script text.
    #[test]
    fn diff_child_losing_admission_replaces_parent_without_it() {
        let script = |kid: Html<()>| Html::HElement("script".into(), vec![], vec![kid]);
        let mut old: Html<()> = Html::HElement(
            "div".into(),
            vec![],
            vec![script(Html::HRaw("init()".into()))],
        );
        let mut new: Html<()> = Html::HElement(
            "div".into(),
            vec![],
            vec![script(Html::HText("alert(document.cookie)".into()))],
        );
        ids(&mut old);
        ids(&mut new);
        let p = plain(&old, &new);
        assert_eq!(p.len(), 1, "expected exactly one html-replace patch");
        let html = p[0].html.as_deref().expect("expected html field on patch");
        assert!(
            !html.contains("<script"),
            "refused script must not render; got: {html:?}"
        );
        assert!(
            !html.contains("alert"),
            "refused body must not render; got: {html:?}"
        );
    }

    /// A patch that inserts a trusted script under an `svg` parent emits no
    /// script and none of its body, the verdict the first paint gives; under a
    /// `div` (the control) the same script is patched in.
    #[test]
    fn diff_patch_under_svg_refuses_script() {
        let script = || -> Html<()> {
            Html::HElement(
                "script".into(),
                vec![],
                vec![Html::HRaw("<img src=x onerror=alert(1)>".into())],
            )
        };
        for (parent, admitted) in [
            ("svg", false),
            ("math", false),
            ("textarea", false),
            ("noscript", false),
            ("div", true),
        ] {
            let mut old: Html<()> = Html::HElement(parent.into(), vec![], vec![]);
            let mut new: Html<()> = Html::HElement(parent.into(), vec![], vec![script()]);
            ids(&mut old);
            ids(&mut new);
            let patches = plain(&old, &new);
            assert_eq!(patches.len(), 1, "{parent}: {patches:?}");
            let [patch] = patches.as_slice() else {
                return;
            };
            let html = patch.html.as_deref().unwrap_or_default();
            assert_eq!(html.contains("<script"), admitted, "{parent}: {html}");
            assert_eq!(html.contains("<img"), admitted, "{parent}: {html}");
            let first_paint = crate::html::render_html(&new);
            assert_eq!(first_paint.contains("<script"), admitted, "{first_paint}");
        }
    }

    /// A patch two levels below `svg`, under its `foreignObject`, still treats
    /// the subtree as foreign content: no script is patched in.
    #[test]
    fn diff_patch_under_foreign_object_refuses_script() {
        let page = |kids: Vec<Html<()>>| -> Html<()> {
            let fo = Html::HElement("foreignObject".into(), vec![], kids);
            Html::HElement("svg".into(), vec![], vec![fo])
        };
        let script = Html::HElement(
            "script".into(),
            vec![],
            vec![Html::HRaw("<img src=x onerror=alert(1)>".into())],
        );
        let mut old = page(vec![]);
        let mut new = page(vec![script]);
        ids(&mut old);
        ids(&mut new);
        let patches = plain(&old, &new);
        assert_eq!(patches.len(), 1, "{patches:?}");
        for p in &patches {
            let html = p.html.as_deref().unwrap_or_default();
            assert!(!html.contains("<script"), "{html}");
            assert!(!html.contains("<img"), "{html}");
        }
        assert!(!crate::html::render_html(&new).contains("<script"));
    }

    /// A trusted script body that changes under an `svg` parent is not on the
    /// page, so the diff emits no patch for it.
    #[test]
    fn diff_changed_script_under_svg_emits_no_patch() {
        let page = |body: &str| -> Html<()> {
            let script = Html::HElement("script".into(), vec![], vec![Html::HRaw(body.into())]);
            Html::HElement("svg".into(), vec![], vec![script])
        };
        let mut old = page("a();");
        let mut new = page("<img src=x onerror=alert(1)>");
        ids(&mut old);
        ids(&mut new);
        assert!(plain(&old, &new).is_empty());
    }

    /// A child-count change that adds a text-bodied `<script>` (or an empty,
    /// not-yet-started one carrying a `src`) replaces the parent without it.
    #[test]
    fn diff_count_change_drops_refused_script_child() {
        let mut old: Html<()> = Html::HElement("div".into(), vec![], vec![]);
        let mut new: Html<()> = Html::HElement(
            "div".into(),
            vec![],
            vec![
                Html::HElement(
                    "script".into(),
                    vec![],
                    vec![Html::HText("alert(1)".into())],
                ),
                Html::HElement(
                    "script".into(),
                    vec![Attribute::Attr("src".into(), "/evil.js".into())],
                    vec![],
                ),
                Html::HElement("p".into(), vec![], vec![Html::HText("ok".into())]),
            ],
        );
        ids(&mut old);
        ids(&mut new);
        let p = plain(&old, &new);
        assert_eq!(p.len(), 1, "expected exactly one html-replace patch");
        let html = p[0].html.as_deref().expect("expected html field on patch");
        assert!(
            !html.contains("<script"),
            "refused scripts must not render; got: {html:?}"
        );
        assert!(
            html.contains("ok</p>"),
            "admitted sibling must render; got: {html:?}"
        );
    }

    /// A view rooted at `Html.doctype` is diffed through the wrapper the render
    /// sink admits, so a changed text deep inside it reaches the page.
    #[test]
    fn diff_doctype_root_patches_a_changed_text_child() {
        let page = |text: &str| -> Html<()> {
            let p = Html::HElement("p".into(), vec![], vec![Html::HText(text.into())]);
            let body = Html::HElement("body".into(), vec![], vec![p]);
            let html = Html::HElement("html".into(), vec![], vec![body]);
            Html::HElement(crate::html::DOCTYPE_WRAPPER_TAG.into(), vec![], vec![html])
        };
        let mut old = page("before");
        let mut new = page("after");
        ids(&mut old);
        ids(&mut new);
        let patches = plain(&old, &new);
        assert_eq!(patches.len(), 1, "expected one text patch; got {patches:?}");
        let Some(patch) = patches.first() else {
            return;
        };
        assert_eq!(patch.id, "r_0_html_0_body_0_p");
        assert_eq!(patch.text.as_deref(), Some("after"));
    }

    /// A doctype wrapper nested below the root is on the page too, so it is
    /// not a refused child: a text change inside it patches only that text.
    #[test]
    fn diff_nested_doctype_is_not_a_refused_child() {
        let tree = |text: &str| -> Html<()> {
            let p = Html::HElement("p".into(), vec![], vec![Html::HText(text.into())]);
            let doctype = Html::HElement(crate::html::DOCTYPE_WRAPPER_TAG.into(), vec![], vec![p]);
            Html::HElement("div".into(), vec![], vec![doctype])
        };
        let mut old = tree("before");
        let mut new = tree("after");
        ids(&mut old);
        ids(&mut new);
        let patches = plain(&old, &new);
        assert_eq!(patches.len(), 1, "expected one text patch; got {patches:?}");
        let Some(patch) = patches.first() else {
            return;
        };
        assert_eq!(patch.text.as_deref(), Some("after"));
        assert!(
            patch.html.is_none(),
            "no subtree replace expected: {patch:?}"
        );
    }

    /// True when `s` holds a `<` the HTML tokenizer would read as the start of
    /// a tag, end tag, comment or declaration.
    fn has_markup_opener(s: &str) -> bool {
        s.as_bytes().windows(2).any(|w| {
            matches!(w, [b'<', c] if c.is_ascii_alphabetic() || matches!(*c, b'/' | b'!' | b'?'))
        })
    }

    /// A trusted raw `<script>` body (an `unsafeJsonLd`/`unsafeScript` value
    /// holding user data but no `</script`) that changes is sent as text, the
    /// neutralised bytes the first paint wrote, never as html the client would
    /// parse into a live `<img onerror>` or `<script src>`.
    #[test]
    fn diff_changed_trusted_script_body_is_a_text_patch() {
        let script = |body: &str| -> Html<()> {
            Html::HElement("script".into(), vec![], vec![Html::HRaw(body.into())])
        };
        let body = r#"["<script src=//e><img src=x onerror=alert(1)>"]"#;
        let mut old: Html<()> = Html::HElement("div".into(), vec![], vec![script("null")]);
        let mut new: Html<()> = Html::HElement("div".into(), vec![], vec![script(body)]);
        ids(&mut old);
        ids(&mut new);
        let patches = plain(&old, &new);
        assert_eq!(patches.len(), 1, "expected one text patch; got {patches:?}");
        assert!(
            patches
                .iter()
                .all(|p| p.html.as_deref().is_none_or(|h| !has_markup_opener(h))),
            "no html patch may carry a markup opener: {patches:?}"
        );
        let Some(patch) = patches.first() else {
            return;
        };
        assert_eq!(patch.id, "r_0_script");
        assert!(patch.html.is_none(), "{patch:?}");
        assert_eq!(patch.text.as_deref(), Some(body), "{patch:?}");
        assert!(
            crate::html::render_html(&new).contains(body),
            "the text patch holds the first paint's body bytes"
        );
    }

    /// A trusted raw `<style>` body that changes between renders (a dynamic
    /// `styleNode`) is sent as its neutralised text, which keeps an entity such
    /// as `&amp;` as the bytes CSS reads instead of decoding it.
    #[test]
    fn diff_changed_trusted_style_body_replaces_it() {
        let style = |css: &str| -> Html<()> {
            Html::HElement("style".into(), vec![], vec![Html::HRaw(css.into())])
        };
        let mut old: Html<()> =
            Html::HElement("div".into(), vec![], vec![style("p { color: red }")]);
        let mut new: Html<()> = Html::HElement(
            "div".into(),
            vec![],
            vec![style(
                "p::after { content: \"&amp;\"; color: blue }</style><img src=x>",
            )],
        );
        ids(&mut old);
        ids(&mut new);
        let patches = plain(&old, &new);
        assert_eq!(patches.len(), 1, "expected one text patch; got {patches:?}");
        let Some(patch) = patches.first() else {
            return;
        };
        assert_eq!(patch.id, "r_0_style");
        assert!(
            patch.html.is_none(),
            "raw-text body never rides html: {patch:?}"
        );
        let Some(text) = patch.text.as_deref() else {
            assert!(patch.text.is_some(), "expected a text patch: {patch:?}");
            return;
        };
        assert!(
            text.contains("content: \"&amp;\"; color: blue"),
            "new body must arrive byte for byte; got {text:?}"
        );
        assert!(
            !text.contains("</style"),
            "close tag must be neutralised; got {text:?}"
        );
        assert!(!has_markup_opener(text), "no markup may open; got {text:?}");
        assert!(
            crate::html::render_html(&new).contains(text),
            "the text patch holds the first paint's body bytes"
        );
    }

    /// An unchanged trusted raw body produces no patch.
    #[test]
    fn diff_unchanged_trusted_raw_body_is_empty() {
        let tree = || -> Html<()> {
            Html::HElement(
                "div".into(),
                vec![],
                vec![Html::HRaw("<b>x</b>".into()), Html::HRaw("<i>y</i>".into())],
            )
        };
        let mut old = tree();
        let mut new = tree();
        ids(&mut old);
        ids(&mut new);
        assert!(plain(&old, &new).is_empty());
    }

    fn keyed_li(key: &str, text: &str) -> Html<()> {
        Html::HElement(
            "li".into(),
            vec![Attribute::Attr("ipe-key".into(), key.into())],
            vec![Html::HText(text.into())],
        )
    }

    /// A same-tag sibling whose key changes is a different node: the parent's
    /// children are replaced, so the DOM element carries the new `ipe-id`,
    /// and nothing is addressed to the old one.
    #[test]
    fn key_change_at_same_position_replaces_parent_children() {
        let mut old: Html<()> = Html::HElement("ul".into(), vec![], vec![keyed_li("a", "x")]);
        let mut new: Html<()> = Html::HElement("ul".into(), vec![], vec![keyed_li("b", "x")]);
        ids(&mut old);
        ids(&mut new);
        let patches = plain(&old, &new);
        assert_eq!(patches.len(), 1, "{patches:?}");
        let Some(patch) = patches.first() else {
            return;
        };
        assert_eq!(patch.id, "r");
        let Some(html) = patch.html.as_deref() else {
            assert!(patch.html.is_some(), "expected an html replace: {patch:?}");
            return;
        };
        assert!(
            html.contains("ipe-id=\"r_0_li:b\""),
            "the replace carries the new identity; got {html:?}"
        );
        assert!(
            patches.iter().all(|p| p.id != "r_0_li:a"),
            "no patch may address the old identity: {patches:?}"
        );
    }

    /// Control: the same key with changed text keeps the in-place fast path.
    #[test]
    fn same_key_text_change_patches_in_place() {
        let mut old: Html<()> = Html::HElement("ul".into(), vec![], vec![keyed_li("a", "x")]);
        let mut new: Html<()> = Html::HElement("ul".into(), vec![], vec![keyed_li("a", "y")]);
        ids(&mut old);
        ids(&mut new);
        let patches = plain(&old, &new);
        assert_eq!(patches.len(), 1, "{patches:?}");
        let Some(patch) = patches.first() else {
            return;
        };
        assert_eq!(patch.id, "r_0_li:a");
        assert_eq!(patch.text.as_deref(), Some("y"));
        assert!(patch.html.is_none(), "no html replace: {patch:?}");
    }

    /// Swapping two keyed items changes both ids at their positions, so the
    /// parent's children are replaced in one patch.
    #[test]
    fn keyed_swap_replaces_parent_children() {
        let list = |first: &str, second: &str| -> Html<()> {
            Html::HElement(
                "ul".into(),
                vec![],
                vec![keyed_li(first, first), keyed_li(second, second)],
            )
        };
        let mut old = list("a", "b");
        let mut new = list("b", "a");
        ids(&mut old);
        ids(&mut new);
        let patches = plain(&old, &new);
        assert_eq!(patches.len(), 1, "{patches:?}");
        let Some(patch) = patches.first() else {
            return;
        };
        assert_eq!(patch.id, "r");
        assert!(patch.html.is_some(), "html replace expected: {patch:?}");
    }

    /// A key change two levels down is replaced at the nearest parent that
    /// holds the changed child, never above it.
    #[test]
    fn nested_key_change_replaces_at_the_nearest_parent() {
        let tree = |key: &str| -> Html<()> {
            Html::HElement(
                "div".into(),
                vec![],
                vec![Html::HElement(
                    "ul".into(),
                    vec![],
                    vec![keyed_li(key, "x")],
                )],
            )
        };
        let mut old = tree("a");
        let mut new = tree("b");
        ids(&mut old);
        ids(&mut new);
        let patches = plain(&old, &new);
        assert_eq!(patches.len(), 1, "{patches:?}");
        let Some(patch) = patches.first() else {
            return;
        };
        assert_eq!(patch.id, "r_0_ul");
        let Some(html) = patch.html.as_deref() else {
            assert!(patch.html.is_some(), "expected an html replace: {patch:?}");
            return;
        };
        assert!(
            html.contains("ipe-id=\"r_0_ul_0_li:b\""),
            "the replace carries the new identity; got {html:?}"
        );
    }

    /// An inserted `<style>` carries the session's nonce only under that
    /// session's context, and a replaced style body never holds it.
    #[test]
    fn inserted_style_carries_the_session_nonce() {
        let nonce = crate::csp::StyleNonce::from_random_bytes([0xa7; 16]);
        let token = nonce.as_token();
        let style = |css: &str| -> Html<()> {
            Html::HElement("style".into(), vec![], vec![Html::HRaw(css.into())])
        };
        let mut old: Html<()> = Html::HElement("div".into(), vec![], vec![]);
        let mut new: Html<()> = Html::HElement("div".into(), vec![], vec![style("p{}")]);
        ids(&mut old);
        ids(&mut new);
        let stamped = diff(&old, &new, &RenderCtx::Session(&nonce));
        let html: Vec<&str> = stamped.iter().filter_map(|p| p.html.as_deref()).collect();
        assert_eq!(html.len(), 1, "{stamped:?}");
        let want = format!("nonce=\"{token}\"");
        assert!(html.iter().all(|h| h.contains(&want)), "{html:?}");
        let unstamped = plain(&old, &new);
        assert!(unstamped.iter().any(|p| p.html.is_some()), "{unstamped:?}");
        assert!(
            unstamped
                .iter()
                .filter_map(|p| p.html.as_deref())
                .all(|h| !h.contains("nonce")),
            "{unstamped:?}"
        );

        let mut old = Html::HElement("div".into(), vec![], vec![style("p{}")]);
        let mut new = Html::HElement("div".into(), vec![], vec![style("a{}")]);
        ids(&mut old);
        ids(&mut new);
        let patches = diff(&old, &new, &RenderCtx::Session(&nonce));
        let texts: Vec<&str> = patches.iter().filter_map(|p| p.text.as_deref()).collect();
        assert_eq!(texts, vec!["a{}"], "{patches:?}");
        assert!(
            patches
                .iter()
                .all(|p| p.html.is_none() && !p.attrs.values().any(|v| v.contains(&token))),
            "{patches:?}"
        );
    }

    /// An attribute delta that adds or drops a program-built `nonce` in any case
    /// yields no attribute operation, so no program can forge, overwrite or
    /// remove a stamp.
    #[test]
    fn author_nonce_is_never_patched() {
        for name in ["nonce", "NONCE", "Nonce"] {
            let mut old: Html<()> =
                Html::HElement("style".into(), vec![], vec![Html::HRaw("p{}".into())]);
            let mut new: Html<()> = Html::HElement(
                "style".into(),
                vec![Attribute::Attr(name.into(), "forged".into())],
                vec![Html::HRaw("p{}".into())],
            );
            ids(&mut old);
            ids(&mut new);
            for patches in [
                plain(&old, &new),
                plain(&new, &old),
                diff(
                    &old,
                    &new,
                    &RenderCtx::Session(&crate::csp::StyleNonce::from_random_bytes([0x11; 16])),
                ),
            ] {
                assert!(
                    patches.iter().all(|p| p
                        .attrs
                        .keys()
                        .all(|k| !k.eq_ignore_ascii_case("nonce"))
                        && p.html.as_deref().is_none_or(|h| !h.contains("forged"))),
                    "{name}: {patches:?}"
                );
            }
        }
    }

    /// A stamped `div` holding a stamped `p`, then `extra` appended after the
    /// stamper ran, so `extra` and everything beneath it carry no `ipe-id`.
    fn with_unstamped_child(extra: Html<()>) -> Html<()> {
        let mut tree: Html<()> = Html::HElement(
            "div".into(),
            vec![],
            vec![Html::HElement(
                "p".into(),
                vec![],
                vec![Html::HText("x".into())],
            )],
        );
        ids(&mut tree);
        if let Html::HElement(_, _, kids) = &mut tree {
            kids.push(extra);
        }
        tree
    }

    /// The one patch a pair yields, which must replace the children of the
    /// stamped root `r` with markup containing `needle`.
    fn assert_root_children_replace(patches: &[Patch], needle: &str) {
        assert_eq!(patches.len(), 1, "expected one replace; got {patches:?}");
        let Some(patch) = patches.first() else {
            return;
        };
        assert_eq!(patch.id, "r", "nearest addressed ancestor: {patch:?}");
        let Some(html) = patch.html.as_deref() else {
            assert!(
                patch.html.is_some(),
                "expected a children replace: {patch:?}"
            );
            return;
        };
        assert!(html.contains(needle), "the change is re-rendered: {html:?}");
    }

    fn raw_style(css: &str) -> Html<()> {
        Html::HElement("style".into(), vec![], vec![Html::HRaw(css.into())])
    }

    /// A raw-text body change beneath an unstamped element reaches the client
    /// as a replace at the nearest stamped ancestor, never as nothing.
    #[test]
    fn unaddressed_raw_body_change_replaces_at_nearest_addressed_ancestor() {
        let old = with_unstamped_child(raw_style("p{color:red}"));
        let new = with_unstamped_child(raw_style("p{color:green}"));
        assert_root_children_replace(&plain(&old, &new), "p{color:green}");
    }

    /// An attribute change on an unstamped element is re-rendered at the
    /// nearest stamped ancestor.
    #[test]
    fn unaddressed_attr_change_replaces_at_nearest_addressed_ancestor() {
        let span = |class: &str| -> Html<()> {
            Html::HElement(
                "span".into(),
                vec![Attribute::Attr("class".into(), class.into())],
                vec![],
            )
        };
        let old = with_unstamped_child(span("before"));
        let new = with_unstamped_child(span("after"));
        assert_root_children_replace(&plain(&old, &new), "after");
    }

    /// A sole-text change on an unstamped element is re-rendered at the
    /// nearest stamped ancestor.
    #[test]
    fn unaddressed_text_change_replaces_at_nearest_addressed_ancestor() {
        let span = |t: &str| -> Html<()> {
            Html::HElement("span".into(), vec![], vec![Html::HText(t.into())])
        };
        let old = with_unstamped_child(span("before"));
        let new = with_unstamped_child(span("after"));
        assert_root_children_replace(&plain(&old, &new), "after");
    }

    /// An unaddressed change climbs past every unstamped ancestor to the first
    /// stamped one.
    #[test]
    fn unaddressed_change_climbs_past_unstamped_ancestors() {
        let nest = |t: &str| -> Html<()> {
            Html::HElement(
                "section".into(),
                vec![],
                vec![Html::HElement(
                    "span".into(),
                    vec![],
                    vec![Html::HText(t.into())],
                )],
            )
        };
        let old = with_unstamped_child(nest("before"));
        let new = with_unstamped_child(nest("after"));
        assert_root_children_replace(&plain(&old, &new), "after");
    }

    /// An unchanged unstamped subtree yields no patch.
    #[test]
    fn unchanged_unaddressed_subtree_yields_no_patch() {
        let old = with_unstamped_child(raw_style("p{color:red}"));
        let new = with_unstamped_child(raw_style("p{color:red}"));
        let patches = plain(&old, &new);
        assert!(patches.is_empty(), "{patches:?}");
    }

    /// A change past the depth ceiling, where the renderer writes no node,
    /// still yields no patch: the unaddressed signal is not raised there.
    #[test]
    fn change_past_depth_ceiling_yields_no_patch() {
        fn chain(depth: usize, leaf: &str) -> Html<()> {
            let mut h: Html<()> = Html::HText(leaf.into());
            for _ in 0..depth {
                h = Html::HElement("div".into(), vec![], vec![h]);
            }
            h
        }
        let depth = crate::html::MAX_HTML_DEPTH + 5;
        let mut old = chain(depth, "before");
        let mut new = chain(depth, "after");
        ids(&mut old);
        ids(&mut new);
        let patches = plain(&old, &new);
        assert!(patches.is_empty(), "{patches:?}");
    }

    // ── focus_target ──────────────────────────────────────────────────────

    fn el(tag: &str, attrs: Vec<Attribute<()>>, kids: Vec<Html<()>>) -> Html<()> {
        Html::HElement(tag.into(), attrs, kids)
    }

    fn dom_id(id: &str) -> Attribute<()> {
        Attribute::Attr("id".into(), id.into())
    }

    fn autofocus() -> Attribute<()> {
        Attribute::Attr("autofocus".into(), String::new())
    }

    fn input(id: &str, focus: bool) -> Html<()> {
        let mut attrs = vec![dom_id(id)];
        if focus {
            attrs.push(autofocus());
        }
        el("input", attrs, vec![])
    }

    /// A tree stamped as every render is.
    fn stamped(mut h: Html<()>) -> Html<()> {
        ids(&mut h);
        h
    }

    /// The stamped `ipe-id` of the element whose `id` attribute is `id`.
    fn stamp_of(h: &Html<()>, id: &str) -> Option<String> {
        let mut work = vec![h];
        while let Some(node) = work.pop() {
            if let Html::HElement(_, attrs, kids) = node {
                let named = attrs
                    .iter()
                    .any(|a| matches!(a, Attribute::Attr(k, v) if k == "id" && v == id));
                if named {
                    return address(node).map(str::to_owned);
                }
                work.extend(kids.iter());
            }
        }
        None
    }

    fn target(old: &Html<()>, new: &Html<()>) -> Option<String> {
        focus_target(old, new).map(|s| s.as_str().to_owned())
    }

    /// U1: a stamped element that appears with `autofocus` is the target.
    #[test]
    fn focus_target_is_a_newly_appearing_autofocus_element() {
        let old = stamped(el("div", vec![], vec![input("other", false)]));
        let new = stamped(el(
            "div",
            vec![],
            vec![input("other", false), input("x", true)],
        ));
        let want = stamp_of(&new, "x");
        assert!(want.is_some(), "the fixture stamps the input");
        assert_eq!(target(&old, &new), want);
    }

    /// U2: a re-render that keeps an element's `autofocus`, as each keystroke
    /// in it does, moves no focus.
    #[test]
    fn focus_target_refuses_an_element_already_autofocused() {
        let typed = |value: &str| {
            stamped(el(
                "div",
                vec![],
                vec![el(
                    "input",
                    vec![
                        dom_id("x"),
                        autofocus(),
                        Attribute::Attr("value".into(), value.into()),
                    ],
                    vec![],
                )],
            ))
        };
        let old = typed("ab");
        let new = typed("abc");
        assert!(
            !plain(&old, &new).is_empty(),
            "the re-render patches the field"
        );
        assert_eq!(target(&old, &new), None);
    }

    /// U3: `autofocus` moved from one element to a new one targets the new one.
    #[test]
    fn focus_target_follows_autofocus_onto_a_new_element() {
        let old = stamped(el("div", vec![], vec![input("a", true)]));
        let new = stamped(el("div", vec![], vec![input("a", false), input("b", true)]));
        let want = stamp_of(&new, "b");
        assert!(want.is_some(), "the fixture stamps the input");
        assert_eq!(target(&old, &new), want);
    }

    /// U4: of two new targets the first in document order wins, a deeper one
    /// ahead of a shallower later sibling included.
    #[test]
    fn focus_target_takes_the_first_new_target_in_document_order() {
        let old = stamped(el("div", vec![], vec![]));
        let new = stamped(el(
            "div",
            vec![],
            vec![el("div", vec![], vec![input("a", true)]), input("b", true)],
        ));
        let want = stamp_of(&new, "a");
        assert!(want.is_some(), "the fixture stamps the input");
        assert_eq!(target(&old, &new), want);
    }

    /// U5: an `autofocus` spelled inside trusted raw markup, with an `ipe-id`
    /// of its own, is never a target.
    #[test]
    fn focus_target_refuses_autofocus_inside_raw_markup() {
        let old = stamped(el("div", vec![], vec![]));
        let new = stamped(el(
            "div",
            vec![],
            vec![Html::HRaw(r#"<input autofocus ipe-id="r">"#.into())],
        ));
        assert_eq!(target(&old, &new), None);
    }

    /// An element written below an RCDATA element is that element's text,
    /// never a page element.
    #[test]
    fn focus_target_refuses_an_element_below_rcdata() {
        let old = stamped(el("div", vec![], vec![el("textarea", vec![], vec![])]));
        let new = stamped(el(
            "div",
            vec![],
            vec![el("textarea", vec![], vec![input("x", true)])],
        ));
        assert!(
            stamp_of(&new, "x").is_some(),
            "the stamper reaches the input"
        );
        assert_eq!(target(&old, &new), None);
    }

    /// An element the render sink refuses is absent, its subtree included.
    #[test]
    fn focus_target_refuses_an_element_the_sink_refuses() {
        let old = stamped(el("div", vec![], vec![]));
        let new = stamped(el(
            "div",
            vec![],
            vec![el("plaintext", vec![autofocus()], vec![input("x", true)])],
        ));
        assert!(
            stamp_of(&new, "x").is_some(),
            "the stamper reaches the input"
        );
        assert_eq!(target(&old, &new), None);
    }

    /// A `<template>`'s children are not in the document.
    #[test]
    fn focus_target_refuses_an_element_inside_a_template() {
        let old = stamped(el("div", vec![], vec![]));
        let new = stamped(el(
            "div",
            vec![],
            vec![el("template", vec![], vec![input("x", true)])],
        ));
        assert!(
            stamp_of(&new, "x").is_some(),
            "the stamper reaches the input"
        );
        assert_eq!(target(&old, &new), None);
    }

    /// An element past the depth ceiling is not rendered, so it is no target.
    #[test]
    fn focus_target_refuses_an_element_past_the_depth_ceiling() {
        let mut deep = input("x", true);
        for _ in 0..crate::html::MAX_HTML_DEPTH {
            deep = el("div", vec![], vec![deep]);
        }
        let old = stamped(el("div", vec![], vec![]));
        let new = stamped(deep);
        assert_eq!(target(&old, &new), None);
    }

    /// The target is the stamper's identity, never an `ipe-id` the program
    /// wrote.
    #[test]
    fn focus_target_is_the_stamped_identity_not_program_text() {
        let old = stamped(el("div", vec![], vec![]));
        let new = stamped(el(
            "div",
            vec![],
            vec![el(
                "input",
                vec![
                    dom_id("x"),
                    Attribute::Attr("ipe-id".into(), "victim".into()),
                    autofocus(),
                ],
                vec![],
            )],
        ));
        let got = target(&old, &new);
        assert!(got.is_some(), "the input is a target");
        assert_ne!(got.as_deref(), Some("victim"));
        assert_eq!(got, stamp_of(&new, "x"));
    }

    /// U6: the same change answers the same whether `diff` sends it as an
    /// in-place attribute patch or as a subtree replace.
    #[test]
    fn focus_target_is_independent_of_patch_granularity() {
        let new = stamped(el("div", vec![], vec![input("x", true)]));
        let in_place = stamped(el("div", vec![], vec![input("x", false)]));
        let replaced = stamped(el("div", vec![], vec![]));
        let attr_patch = plain(&in_place, &new);
        assert!(
            attr_patch.iter().any(|p| p.attrs.contains_key("autofocus"))
                && attr_patch.iter().all(|p| p.html.is_none()),
            "{attr_patch:?}"
        );
        let html_patch = plain(&replaced, &new);
        assert!(
            html_patch.iter().any(|p| p.html.is_some()),
            "{html_patch:?}"
        );
        let want = stamp_of(&new, "x");
        assert!(want.is_some(), "the fixture stamps the input");
        assert_eq!(target(&in_place, &new), want);
        assert_eq!(target(&replaced, &new), want);
    }

    /// U7: `BoolAttr("autofocus", false)` renders nothing, so it is no target.
    #[test]
    fn focus_target_refuses_a_false_bool_autofocus() {
        let with = |on: bool| {
            stamped(el(
                "div",
                vec![],
                vec![el(
                    "input",
                    vec![dom_id("x"), Attribute::BoolAttr("autofocus".into(), on)],
                    vec![],
                )],
            ))
        };
        let old = stamped(el("div", vec![], vec![]));
        assert_eq!(target(&old, &with(false)), None);
        let on = with(true);
        assert!(stamp_of(&on, "x").is_some(), "the fixture stamps the input");
        assert_eq!(target(&old, &on), stamp_of(&on, "x"));
    }
}

use crate::html::{Attribute, ElementBody, Html, admit_element};
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
/// - Matched-tag element pair: diff attributes + events, then children.
/// - Tag/kind mismatch, child-count change, or any mixed-child text change:
///   whole-subtree `html` replace at the parent.
/// - Sole text-child change: `SetText` via `p.text` (fast path).
/// - Event handlers toggled on/off: `ipe-<event>` attr set/remove + `data-ipe-hid`.
/// - Keyed identity is carried by `assign_ipe_ids` (the `:{key}` segment) so a
///   reordered keyed item keeps its ipe-id and only its moved attrs patch.
#[must_use]
pub fn diff<M>(old: &Html<M>, new: &Html<M>) -> Vec<Patch> {
    let mut out = vec![];
    diff_node_depth(old, new, &mut out, 0);
    out
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

/// Emit a whole-subtree innerHTML replace at `id`.
///
/// `parent_body` is how `admit_element` admitted the element whose children
/// are being replaced, so a `<script>`/`<style>` body gets the same
/// neutralisation the first-paint renderer applies and the SSE replace cannot
/// smuggle a raw `</script>`/`</style>` into the DOM.
fn push_html_replace<M>(
    id: &str,
    parent_body: ElementBody,
    new_kids: &[Html<M>],
    out: &mut Vec<Patch>,
) {
    if id.is_empty() {
        return;
    }
    let mut p = Patch::for_id(id);
    p.html = Some(render_children(parent_body, new_kids));
    out.push(p);
}

/// True when `node` is an element the shared tag gate refuses, so the renderer
/// leaves it out of the page.
fn is_refused_element<M>(node: &Html<M>) -> bool {
    match node {
        Html::HElement(tag, _, kids) => admit_element(tag, kids).is_err(),
        Html::HText(_) | Html::HRaw(_) => false,
    }
}

/// Bounded-descent diff. Stops at `MAX_HTML_DEPTH` (same ceiling as
/// `html.rs::render_into_ctx`) rather than recursing into an arbitrarily deep
/// Model-derived tree that would overflow the thread stack.
fn diff_node_depth<M>(old: &Html<M>, new: &Html<M>, out: &mut Vec<Patch>, depth: usize) {
    if depth >= crate::html::MAX_HTML_DEPTH {
        return;
    }
    let (ot, oa, ok, nt, na, nk) = match (old, new) {
        (Html::HElement(ot, oa, ok), Html::HElement(nt, na, nk)) if ot == nt => {
            (ot, oa, ok, nt, na, nk)
        }
        // Tag/kind mismatch is handled by the parent (mixed-child / count branch).
        // A top-level mismatch has no parent to address, so nothing to emit.
        _ => return,
    };
    // SECURITY: the shared tag gate. A refused element is absent from the
    // rendered page, so neither side of a refused pair has a DOM node to patch;
    // a parent whose child changes admission replaces its whole subtree (see
    // the per-position loop), which re-renders through the same gate.
    let (Ok(body), Ok(_)) = (admit_element(nt, nk), admit_element(ot, ok)) else {
        return;
    };
    // Patch id targets the element currently in the DOM — the OLD tree's id
    // . Borrowed: `Patch::for_id` copies it only when
    // a Patch is actually built, so an unchanged element pair allocates
    // nothing here (efficiency-audit §6 medium).
    let id: &str = ipe_id(old).unwrap_or("");

    // Attribute + event delta.
    let mut p = Patch::for_id(id);
    diff_attrs(oa, na, &mut p);
    if !id.is_empty() && !p.attrs.is_empty() {
        out.push(p);
    }

    // Sole text-child fast path (common for buttons / spans).
    if ok.len() == 1
        && nk.len() == 1
        && let (Some(Html::HText(o)), Some(Html::HText(n))) = (ok.first(), nk.first())
    {
        if o != n && !id.is_empty() {
            let mut tp = Patch::for_id(id);
            tp.text = Some(n.clone());
            out.push(tp);
        }
        return;
    }

    // Child-count change → replace the whole subtree.
    if ok.len() != nk.len() {
        push_html_replace(id, body, nk, out);
        return;
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
                    push_html_replace(id, body, nk, out);
                    return;
                }
            }
            // Raw-vs-raw: changed raw content is not patched (no-op); avoid
            // emitting a spurious replace.
            (Html::HRaw(_), Html::HRaw(_)) => {}
            (Html::HElement(t1, _, _), Html::HElement(t2, _, _)) if t1 == t2 => {
                // A child that gains or loses admission appears in or vanishes
                // from the page, so the parent's subtree is replaced.
                if is_refused_element(oc) != is_refused_element(nc) {
                    push_html_replace(id, body, nk, out);
                    return;
                }
                diff_node_depth(oc, nc, out, child_depth);
            }
            // Tag / kind mismatch → replace the subtree at the parent.
            _ => {
                push_html_replace(id, body, nk, out);
                return;
            }
        }
    }
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
    for ev in &nn {
        if !on.contains(ev) {
            insert_safe_attr(p, &ev_key(ev), ev);
            insert_safe_attr(p, "data-ipe-hid", &id);
        }
    }
    for ev in &on {
        if !nn.contains(ev) {
            insert_safe_attr(p, &ev_key(ev), "");
            if nn.is_empty() {
                insert_safe_attr(p, "data-ipe-hid", "");
            }
        }
    }
}

/// Render `kids` into an HTML string for an SSE innerHTML replace.
///
/// The children render through `render_children_into` with the parent's
/// admitted body class, the same path the first-paint renderer takes, so a
/// `<script>`/`<style>` body is neutralised and a refused child is left out.
fn render_children<M>(parent_body: ElementBody, kids: &[Html<M>]) -> String {
    let mut s = String::new();
    crate::html::render_children_into(parent_body, kids, &mut s);
    s
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::{Event, assign_ipe_ids};

    fn ids(h: &mut Html<()>) {
        assign_ipe_ids(h, "r");
    }

    #[test]
    fn diff_text_change() {
        let mut a: Html<()> = Html::HElement("p".into(), vec![], vec![Html::HText("1".into())]);
        let mut b: Html<()> = Html::HElement("p".into(), vec![], vec![Html::HText("2".into())]);
        ids(&mut a);
        ids(&mut b);
        let p = diff(&a, &b);
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
        let p = diff(&a, &b);
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
        let p = diff(&a, &b);
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
        let p = diff(&a, &b);
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
        assert!(diff(&a, &b).is_empty());
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
        let p = diff(&a, &b);
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
            vec![Attribute::EventAttr(Event::OnMsg("click".into(), ()))],
            vec![],
        );
        ids(&mut a);
        ids(&mut b);
        let p = diff(&a, &b);
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
            vec![Attribute::EventAttr(Event::OnMsg("click".into(), ()))],
            vec![],
        );
        let mut b: Html<()> = Html::HElement("button".into(), vec![], vec![]);
        ids(&mut a);
        ids(&mut b);
        let p = diff(&a, &b);
        assert_eq!(p.len(), 1);
        // Removal sentinel: empty string for both the marker and the (now-stale) hid.
        assert_eq!(p[0].attrs.get("ipe-click").map(String::as_str), Some(""));
        assert_eq!(p[0].attrs.get("data-ipe-hid").map(String::as_str), Some(""));
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
        let p = diff(&a, &b);
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
        let p = diff(&a, &b);
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
        let p = diff(&a, &b);
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
        let patches = diff(&old, &new);
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
        let p = diff(&old, &new);
        assert_eq!(p.len(), 1, "expected exactly one html-replace patch");
        let html = p[0].html.as_deref().expect("expected html field on patch");
        assert!(
            !html.to_ascii_lowercase().contains("</script"),
            "`</script` byte run must be neutralised; got: {html:?}"
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
        let p = diff(&old, &new);
        assert_eq!(p.len(), 1, "expected exactly one html-replace patch");
        let html = p[0].html.as_deref().expect("expected html field on patch");
        assert!(
            !html.contains("</style"),
            "`</style` byte run must be stripped; got: {html:?}"
        );
        assert!(
            !html.contains("<script"),
            "no markup may open; got: {html:?}"
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
                diff(&old, &new).is_empty(),
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
        let p = diff(&old, &new);
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
        let p = diff(&old, &new);
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
}

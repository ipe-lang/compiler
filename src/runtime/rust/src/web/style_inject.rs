//! Ipe.Ui style-marker injection.
//!
//! The shared `Ipe.Ui` stdlib emits `data-ipe-{mq,pc,tr,anim}-*` marker
//! *attributes* on elements for `Ui.breakpoint` / `Ui.mediaQuery`,
//! `Background.hoverColor` / `Ui.onPseudo`, `Transition.attribute`, and
//! `Animation.attribute`, consumed into ipe-id-scoped
//! `<style>` blocks; without this pass the Rust backend rendered the markers
//! inert and produced zero CSS, so hover / breakpoint / media-query /
//! transition / animation were entirely dead.
//!
//! Pre-condition: `assign_ipe_ids` has stamped a `ipe-id` attr on every
//! element. Post-condition: every marker attr is stripped (even on no-match, so
//! an empty marker never leaks as an inert `data-*`) and a `<style>` child is
//! prepended (or sibling-hoisted after a void element).
//!
//! SECURITY: the `<style>` body is emitted as an `HRaw` node (CSS cannot be
//! entity-escaped without breaking it). The marker attrs are raw Strings a
//! caller can FORGE via `Ui.htmlAttribute` (bypassing every producer-side
//! `SafeCss*` gate), so the PRIMARY gate lives at THIS sink: every builder
//! below re-validates its marker payload through the shared `css_safety`
//! policy (`SafeCssMediaQuery` / `sink_safe_declaration_list` / `SafeCssValue`
//! / `sink_safe_keyframes_body`) and drops the block fail-closed on any
//! breakout. The close-tag strip applied to EVERY CSS fragment stays as
//! belt-and-braces and must never be dropped. The selector uses the element's
//! own already-sanitised ipe-id (assign_ipe_ids), never a user attr, so the
//! selector cannot be broken out of either.
//!
//! Idempotent: a second run finds the markers already stripped and is a no-op
//! (matches  idempotency contract), a belt-and-braces against a missed
//! call site.

use crate::html::{Attribute, Html, is_void};

/// True for elements a scoped `<style>` must NOT be prepended into as a child.
/// Covers void tags (they render no children) AND value-bearing tags whose
/// children ARE their content: a `<textarea>`'s children are its text value and
/// a `<select>`'s are its `<option>`s, so a child `<style>` would leak raw CSS
/// into the field value / option list. For all of these the injection pass
/// hoists the `<style>` to a sibling slot instead.
fn takes_no_style_child(tag: &str) -> bool {
    is_void(tag) || tag == "textarea" || tag == "select"
}

/// Every style marker attr this module consumes, across all four passes. Used to
/// strip a void TREE-ROOT's markers (see `apply_style_injections`). MUST stay in
/// sync with the per-pass marker lists below.
const ALL_MARKERS: &[&str] = &[
    "data-ipe-mq-q",
    "data-ipe-mq-rules",
    "data-ipe-pc-rules",
    "data-ipe-tr-rules",
    "data-ipe-tr-respect",
    "data-ipe-anim-rules",
];

/// Run every style-marker pass over the tree in  fixed order. Call
/// immediately after `assign_ipe_ids`, on the SAME tree that becomes both the
/// render output AND the diff baseline (applied before render + before
/// storing the tree, so the diff compares two already-injected trees and never
/// sees a marker-attr-vs-style-child asymmetry → no spurious replace).
/// Hard recursion-depth bound for the style-injection tree walk — same rationale
/// and value as html's MAX_HTML_DEPTH: a deeply-nested (attacker-influenced) tree
/// would overflow the thread stack. Past the cap we stop descending (deeper nodes
/// keep their markers) rather than abort the process.
const MAX_STYLE_DEPTH: usize = 1024;

pub fn apply_style_injections<M>(node: &mut Html<M>) {
    inject_pass(
        node,
        &["data-ipe-mq-q", "data-ipe-mq-rules"],
        "data-ipe-mq",
        &|id, a| build_mq(id, a),
        0,
    );
    inject_pass(
        node,
        &["data-ipe-pc-rules"],
        "data-ipe-pc",
        &|id, a| build_pc(id, a),
        0,
    );
    inject_pass(
        node,
        &["data-ipe-tr-rules", "data-ipe-tr-respect"],
        "data-ipe-tr",
        &|id, a| build_tr(id, a),
        0,
    );
    inject_pass(
        node,
        &["data-ipe-anim-rules"],
        "data-ipe-anim",
        &|id, a| build_anim(id, a),
        0,
    );
    // An element that takes no style child (void, or value-bearing
    // textarea/select) at the TREE ROOT is never self-handled (inject_pass skips
    // its self-build) and has no parent to hoist a sibling <style> after it. Its
    // markers would therefore survive every pass and leak as inert data-* attrs,
    // breaking the post-condition. Strip them here. The CSS is necessarily
    // dropped — such a root has nowhere to carry a <style> node. (The same node
    // WITH a parent is unaffected: the parent's loop still finds its markers
    // intact and hoists.)
    if let Html::HElement(t, attrs, _) = node
        && takes_no_style_child(t)
    {
        strip_markers(attrs, ALL_MARKERS);
    }
}

/// One style-injection pass over a subtree: self-handle (non-void prepends a
/// style child), then walk children splicing a sibling `<style>` after any void
/// child whose marker survived (the void child's own self-handler bails).
fn inject_pass<M>(
    node: &mut Html<M>,
    markers: &[&str],
    style_attr: &str,
    build: &impl Fn(&str, &[Attribute<M>]) -> String,
    depth: usize,
) {
    // Stack-overflow guard: stop descending a pathologically deep tree (deeper
    // nodes keep their markers — a truncated injection beats a process abort).
    if depth >= MAX_STYLE_DEPTH {
        return;
    }
    let (tag, attrs, kids) = match node {
        Html::HElement(t, a, k) => (t, a, k),
        _ => return,
    };
    // Style-child-bearing self: build + prepend the style child (build_style_node
    // strips the markers regardless of outcome). Elements that take no style child
    // (void, or value-bearing textarea/select) are hoisted by the parent below.
    if !takes_no_style_child(tag)
        && let Some(style) = build_style_node(attrs, markers, style_attr, build)
    {
        kids.insert(0, style);
    }
    // Walk children, recursing into each and hoisting a sibling style block
    // after any child that can't take a style child of its own but still
    // carries a marker.
    let mut out: Vec<Html<M>> = Vec::with_capacity(kids.len());
    for mut child in std::mem::take(kids) {
        inject_pass(&mut child, markers, style_attr, build, depth + 1);
        let hoist = match &mut child {
            Html::HElement(ct, ca, _) if takes_no_style_child(ct) => {
                build_style_node(ca, markers, style_attr, build)
            }
            _ => None,
        };
        out.push(child);
        if let Some(h) = hoist {
            out.push(h);
        }
    }
    *kids = out;
}

/// Build the `<style>` node for an element's markers and strip those markers
/// from its attrs. Returns `None` (markers still stripped) when there's no
/// ipe-id, no non-empty marker, or the built CSS is empty.
fn build_style_node<M>(
    attrs: &mut Vec<Attribute<M>>,
    markers: &[&str],
    style_attr: &str,
    build: &impl Fn(&str, &[Attribute<M>]) -> String,
) -> Option<Html<M>> {
    let ipe_id = match attr_get(attrs, "ipe-id") {
        Some(s) => s,
        None => {
            strip_markers(attrs, markers);
            return None;
        }
    };
    let has_any = markers
        .iter()
        .any(|m| attr_get(attrs, m).is_some_and(|v| !v.is_empty()));
    if !has_any {
        strip_markers(attrs, markers);
        return None;
    }
    let css = build(&ipe_id, attrs); // reads markers BEFORE they're stripped
    strip_markers(attrs, markers);
    if css.is_empty() {
        return None;
    }
    Some(Html::HElement(
        "style".to_string(),
        vec![Attribute::Attr(style_attr.to_string(), ipe_id)],
        vec![Html::HRaw(css)],
    ))
}

/// Read an attribute's value by key (owned clone — values are short and this
/// keeps the helper lifetime-free, which also dodges a false-positive in the
/// runtime indexing-precheck on `&'a [T]`).
fn attr_get<M>(attrs: &[Attribute<M>], key: &str) -> Option<String> {
    attrs.iter().find_map(|a| match a {
        Attribute::Attr(k, v) if k == key => Some(v.clone()),
        _ => None,
    })
}

fn strip_markers<M>(attrs: &mut Vec<Attribute<M>>, markers: &[&str]) {
    attrs.retain(|a| !matches!(a, Attribute::Attr(k, _) if markers.contains(&k.as_str())));
}

// `strip_style_close` moved to the shared `css_safety` module (design §Q5: one
// policy, one place). Imported below so the Ipe.Ui pseudo-class / media-query
// `<style>` path and the Ipe.Css / styleNode `<style>` sink share the identical
// close-tag stripper.
use super::super::css_safety::{
    SafeCssMediaQuery, SafeCssValue, sink_safe_declaration_list, sink_safe_keyframes_body,
    strip_style_close,
};

fn build_mq<M>(ipe_id: &str, attrs: &[Attribute<M>]) -> String {
    let query = attr_get(attrs, "data-ipe-mq-q").unwrap_or_default();
    let rules = attr_get(attrs, "data-ipe-mq-rules").unwrap_or_default();
    if query.is_empty() || rules.is_empty() {
        return String::new();
    }
    // Sink-side re-validation. The markers are raw String attributes a caller
    // can FORGE via `Ui.htmlAttribute`, bypassing the producer's
    // `SafeCssMediaQuery` / `SafeCssValue` gates — so validate at THIS boundary
    // and drop the whole block fail-closed on any breakout. `strip_style_close`
    // stays as sink-final belt-and-braces below.
    let (safe_query, safe_rules) = match (
        SafeCssMediaQuery::parse(&query),
        sink_safe_declaration_list(&rules),
    ) {
        (Some(q), Some(r)) => (q.as_str().to_owned(), strip_style_close(r)),
        _ => return String::new(),
    };
    // The layout renderer writes `display:flex` and its siblings as INLINE
    // `style=""` declarations, which outrank a normal stylesheet rule. A
    // breakpoint that re-lays-out an element (`display:none`, `align-items`, …)
    // must therefore mark its declarations `!important` to beat that inline
    // layout. This does not defeat a caller's own inline `!important`: an inline
    // important declaration still wins over a stylesheet important one, so an
    // author who deliberately pins a property inline keeps precedence.
    let important_rules = mark_declarations_important(&safe_rules);
    let selector = format!("[ipe-id=\"{ipe_id}\"]");
    format!("@media {safe_query} {{ {selector} {{ {important_rules} }} }}")
}

/// Append `!important` to each `;`-separated declaration in an already-safe
/// declaration list. A declaration that already carries `!important` (a caller
/// wrote it explicitly) is left untouched, so the output is idempotent. Empty
/// segments are dropped. Input MUST have passed `sink_safe_declaration_list`.
fn mark_declarations_important(rules: &str) -> String {
    let mut out = String::new();
    for decl in rules.split(';') {
        let d = decl.trim();
        if d.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push(';');
        }
        out.push_str(d);
        if !d.to_ascii_lowercase().contains("!important") {
            out.push_str(" !important");
        }
    }
    out
}

fn build_pc<M>(ipe_id: &str, attrs: &[Attribute<M>]) -> String {
    let encoded = attr_get(attrs, "data-ipe-pc-rules").unwrap_or_default();
    if encoded.is_empty() {
        return String::new();
    }
    let selector = format!("[ipe-id=\"{ipe_id}\"]");
    let mut out = String::new();
    for entry in encoded.split("||") {
        let (tag, css) = match entry.split_once('|') {
            Some(x) => x,
            None => continue,
        };
        if css.is_empty() {
            continue;
        }
        let (pseudo, hover_gated) = match pseudo_selector_for_tag(tag) {
            Some(x) => x,
            None => continue,
        };
        // Sink-side re-validation (forgeable marker — see `build_mq`). A
        // declaration that fails drops THIS pseudo-rule only; sibling rules and
        // the element still render.
        let safe_css = match sink_safe_declaration_list(css) {
            Some(c) => strip_style_close(c),
            None => continue,
        };
        if hover_gated {
            out.push_str(&format!(
                "@media (hover: hover) {{ {selector}{pseudo} {{ {safe_css} }} }} "
            ));
        } else {
            out.push_str(&format!("{selector}{pseudo} {{ {safe_css} }} "));
        }
    }
    out.trim().to_string()
}

/// Wire-format pseudo-class tag → (selector, hover-gated). Keep in lock-step
/// with `pseudoClassTag` in Ipe.Ui.ipe /  `pseudoSelectorForTag`.
fn pseudo_selector_for_tag(tag: &str) -> Option<(&'static str, bool)> {
    match tag {
        "h" => Some((":hover", true)),
        "f" => Some((":focus", false)),
        "v" => Some((":focus-visible", false)),
        "a" => Some((":active", false)),
        "d" => Some((":disabled", false)),
        _ => None,
    }
}

fn build_tr<M>(ipe_id: &str, attrs: &[Attribute<M>]) -> String {
    let rules = attr_get(attrs, "data-ipe-tr-rules").unwrap_or_default();
    if rules.is_empty() {
        return String::new();
    }
    let respect = attr_get(attrs, "data-ipe-tr-respect")
        .unwrap_or_default()
        .as_str()
        != "0";
    // Sink-side re-validation (forgeable marker — see `build_mq`). The
    // transition value is a single declaration value; a breakout drops the
    // whole block fail-closed.
    let safe_rules = match SafeCssValue::parse(&rules) {
        Some(v) => strip_style_close(v.as_str()),
        None => return String::new(),
    };
    let selector = format!("[ipe-id=\"{ipe_id}\"]");
    if respect {
        format!(
            "@media (prefers-reduced-motion: no-preference) {{ {selector} {{ transition: {safe_rules}; }} }}"
        )
    } else {
        format!("{selector} {{ transition: {safe_rules}; }}")
    }
}

fn build_anim<M>(ipe_id: &str, attrs: &[Attribute<M>]) -> String {
    let encoded = attr_get(attrs, "data-ipe-anim-rules").unwrap_or_default();
    if encoded.is_empty() {
        return String::new();
    }
    let ident = ipe_id_to_css_ident(ipe_id);
    let selector = format!("[ipe-id=\"{ipe_id}\"]");
    let mut keyframes = String::new();
    let mut gated: Vec<String> = vec![];
    let mut ungated: Vec<String> = vec![];

    for entry in encoded.split("@@") {
        let mut it = entry.splitn(4, "||");
        let (name, tail, body, respect) = match (it.next(), it.next(), it.next(), it.next()) {
            (Some(n), Some(t), Some(b), Some(r)) => (n, t, b, r),
            _ => continue,
        };
        if name.is_empty() || body.is_empty() {
            continue;
        }
        // Sink-side re-validation (forgeable marker — see `build_mq`). The
        // keyframes BODY legitimately contains `{ } ;`, so it goes through the
        // keyframe-grammar validator instead of the flat declaration policy;
        // the shorthand TAIL is a single declaration value. An entry that
        // fails either gate drops fail-closed (`continue` — sibling animations
        // and the element still render, same per-entry posture as `build_pc`).
        // `strip_style_close` stays as sink-final belt-and-braces.
        let safe_body = match sink_safe_keyframes_body(body) {
            Some(b) => strip_style_close(b),
            None => continue,
        };
        let safe_tail = match SafeCssValue::parse(tail) {
            Some(t) => strip_style_close(t.as_str()),
            None => continue,
        };
        let safe_name = sanitise_animation_name(name);
        if safe_name.is_empty() {
            continue;
        }
        let effective = format!("{safe_name}__{ident}");
        keyframes.push_str(&format!("@keyframes {effective} {{ {safe_body} }} "));
        let r = format!("{effective} {safe_tail}");
        if respect == "0" {
            ungated.push(r);
        } else {
            gated.push(r);
        }
    }

    if keyframes.is_empty() {
        return String::new();
    }
    let mut sb = keyframes;
    if !gated.is_empty() {
        sb.push_str(&format!(
            "@media (prefers-reduced-motion: no-preference) {{ {selector} {{ animation: {}; }} }} ",
            gated.join(", ")
        ));
    }
    if !ungated.is_empty() {
        sb.push_str(&format!(
            "{selector} {{ animation: {}; }} ",
            ungated.join(", ")
        ));
    }
    sb.trim().to_string()
}

/// ipe-id (`r.0.2#div`) → CSS-safe ident suffix (`r_0_2_div`) for @keyframes
/// names. Structural separators map to `_`; anything else outside the CSS-ident
/// charset is dropped ( `ipeIDToCSSIdent`).
fn ipe_id_to_css_ident(s: &str) -> String {
    s.chars()
        .filter_map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' => Some(c),
            '.' | '#' => Some('_'),
            _ => None,
        })
        .collect()
}

/// Strip chars that would break a CSS `@keyframes` ident (non-ident → `_`); a
/// leading digit is illegal so prefix `_` ( `sanitiseAnimationName`).
fn sanitise_animation_name(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let mut out: String = s
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' => c,
            _ => '_',
        })
        .collect();
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    fn attr(k: &str, v: &str) -> Attribute<()> {
        Attribute::Attr(k.to_string(), v.to_string())
    }

    fn count_styles(n: &Html<()>) -> usize {
        match n {
            Html::HElement(t, _, kids) => {
                (if t == "style" { 1 } else { 0 }) + kids.iter().map(count_styles).sum::<usize>()
            }
            _ => 0,
        }
    }

    // SECURITY regression: the close-tag strip must be TOTAL — no spelling of
    // `</style` survives, including mixed case and post-removal reconstruction.
    #[test]
    fn strip_style_close_is_total() {
        // plain
        assert!(
            !strip_style_close("a</style>b")
                .to_ascii_lowercase()
                .contains("</style")
        );
        // mixed case (HTML end-tags are ASCII-case-insensitive)
        assert!(
            !strip_style_close("a</StYle>b")
                .to_ascii_lowercase()
                .contains("</style")
        );
        assert!(
            !strip_style_close("a</STYLE>b")
                .to_ascii_lowercase()
                .contains("</style")
        );
        // reconstruction across the join seam after a single removal
        assert!(
            !strip_style_close("</sty</stylele>")
                .to_ascii_lowercase()
                .contains("</style")
        );
        assert!(
            !strip_style_close("</st</STYLEyle>")
                .to_ascii_lowercase()
                .contains("</style")
        );
        // benign content is untouched
        assert_eq!(strip_style_close("color: red;"), "color: red;");
    }

    // SECURITY regression: a `</style><script>` payload in any CSS fragment must
    // be neutralised by the close-tag strip so it cannot break out of the raw
    // <style> block (stored-XSS). One test per build fn that takes raw-ish CSS.
    #[test]
    fn pc_strips_style_close_breakout() {
        let attrs = vec![
            attr("ipe-id", "r_0_button"),
            attr(
                "data-ipe-pc-rules",
                "h|color: red } </style><script>alert(1)</script>",
            ),
        ];
        let css = build_pc("r_0_button", &attrs);
        // Sink hardening: the forged rule carries a ruleset
        // breakout (`}`) + `</style>`; `sink_safe_declaration_list` drops the
        // whole pseudo-rule FAIL-CLOSED (stronger than the old strip-only
        // contract that let the sanitised `:hover` block through).
        assert!(!css.contains("</style"), "breakout not stripped: {css}");
        assert!(
            !css.to_ascii_lowercase().contains("<script"),
            "script leaked: {css}"
        );
        assert_eq!(
            css, "",
            "forged breakout pseudo-rule must drop fail-closed: {css}"
        );
    }

    #[test]
    fn mq_strips_style_close_in_query_and_rules() {
        let attrs = vec![
            attr("data-ipe-mq-q", "(max-width: 600px) </style>"),
            attr(
                "data-ipe-mq-rules",
                "color: blue </style><script>x</script>",
            ),
        ];
        let css = build_mq("r0", &attrs);
        // Sink hardening: both markers carry a `</style>`
        // breakout, so `SafeCssMediaQuery` (query) and `sink_safe_declaration_list`
        // (rules) each reject and `build_mq` drops the whole @media block
        // fail-closed — stronger than the old strip-then-still-emit contract.
        assert!(!css.contains("</style"), "{css}");
        assert_eq!(
            css, "",
            "forged breakout @media block must drop fail-closed: {css}"
        );
    }

    // Snapshot port of ../ipe fixture `70-style-injection`: the exact raw
    // media-query breakout probe must be neutralised — no `</style>` survives and
    // no `</style><script` breakout sequence forms (the injected `<script>` is
    // trapped inert inside the `<style>` block).
    #[test]
    fn fixture70_mediaquery_breakout_probe_neutralised() {
        let attrs = vec![
            attr(
                "data-ipe-mq-q",
                "(min-width: 1px) </style><script>alert(1)</script>",
            ),
            attr("data-ipe-mq-rules", "background-color:rgb(1,2,3)"),
        ];
        let css = build_mq("r_2_el", &attrs);
        assert!(!css.to_ascii_lowercase().contains("</style"), "{css}");
        assert!(
            !css.to_ascii_lowercase().contains("</style><script"),
            "{css}"
        );
        // Sink hardening: the query carries a `</style><script>`
        // breakout → `SafeCssMediaQuery` rejects it → `build_mq` drops the whole
        // @media block fail-closed (even though the rules half is legit).
        assert_eq!(
            css, "",
            "forged breakout query must drop the whole @media block: {css}"
        );
    }

    #[test]
    fn anim_strips_breakout_and_sanitises_name() {
        let attrs = vec![attr(
            "data-ipe-anim-rules",
            "9bad name!||300ms ease||0% { opacity: 0 } </style>||1",
        )];
        let css = build_anim("r.0#div", &attrs);
        assert!(!css.contains("</style"), "{css}");
        // Sink hardening: the body carries trailing content
        // after the last keyframe block (`</style>`), so
        // `sink_safe_keyframes_body` rejects it and the whole entry drops
        // FAIL-CLOSED (stronger than the old strip-then-still-emit contract).
        assert_eq!(
            css, "",
            "forged breakout keyframes body must drop the entry: {css}"
        );
    }

    #[test]
    fn anim_sanitises_name_on_legit_entry() {
        // Name sanitisation (leading digit prefixed, non-ident chars → `_`,
        // ipe-id-derived ident suffix) still applies on the legit path.
        let attrs = vec![attr(
            "data-ipe-anim-rules",
            "9bad name!||300ms ease||0% { opacity: 0 } 100% { opacity: 1 }||1",
        )];
        let css = build_anim("r.0#div", &attrs);
        assert!(css.contains("@keyframes _9bad_name___r_0_div"), "{css}");
        assert!(
            css.contains("@media (prefers-reduced-motion: no-preference)"),
            "respect=1 must keep the reduced-motion gate: {css}"
        );
    }

    #[test]
    fn build_anim_sink_keeps_legit_entries_byte_identical() {
        let attrs = vec![attr(
            "data-ipe-anim-rules",
            "fadeIn||300ms ease-out 0ms 1 none||0% { opacity: 0; transform: translateY(10px) } 100% { opacity: 1; transform: translateY(0px) }||0",
        )];
        let css = build_anim("r.0", &attrs);
        assert!(
            css.contains(
                "@keyframes fadeIn__r_0 { 0% { opacity: 0; transform: translateY(10px) } \
                 100% { opacity: 1; transform: translateY(0px) } }"
            ),
            "legit keyframes must survive byte-identical: {css}"
        );
        assert!(
            css.contains("animation: fadeIn__r_0 300ms ease-out 0ms 1 none;"),
            "legit shorthand tail must survive: {css}"
        );
        assert!(
            !css.contains("prefers-reduced-motion"),
            "respect=0 must skip the media gate: {css}"
        );
    }

    #[test]
    fn build_anim_sink_drops_forged_body_breakout() {
        // Forged body: valid first block, then a close-and-inject page-wide
        // rule + at-rule — exactly what `strip_style_close` alone missed.
        let attrs = vec![attr(
            "data-ipe-anim-rules",
            "x||300ms||0% { opacity: 0 } } body { display:none } @import url(//evil/x.css) {||1",
        )];
        assert_eq!(
            build_anim("r.0", &attrs),
            "",
            "forged keyframes-body breakout must drop the entry fail-closed"
        );
    }

    #[test]
    fn build_anim_sink_drops_forged_tail_breakout() {
        let attrs = vec![attr(
            "data-ipe-anim-rules",
            "x||300ms; } [y] { color:red||0% { opacity: 0 }||1",
        )];
        assert_eq!(
            build_anim("r.0", &attrs),
            "",
            "forged shorthand-tail breakout must drop the entry fail-closed"
        );
    }

    #[test]
    fn build_anim_sink_drops_only_the_forged_entry() {
        // Per-entry fail-closed posture (same as build_pc): the forged entry
        // drops, the legit sibling animation still renders.
        let attrs = vec![attr(
            "data-ipe-anim-rules",
            "evil||300ms||0% { opacity: 0 } </style><script>alert(1)</script>||1\
             @@good||200ms linear||0% { opacity: 0 } 100% { opacity: 1 }||1",
        )];
        let css = build_anim("r.0", &attrs);
        assert!(!css.contains("evil__"), "forged entry must drop: {css}");
        assert!(
            !css.to_ascii_lowercase().contains("<script"),
            "script must never render: {css}"
        );
        assert!(
            css.contains("@keyframes good__r_0"),
            "legit sibling entry must survive: {css}"
        );
    }

    #[test]
    fn apply_prepends_style_child_and_strips_marker() {
        let mut tree: Html<()> = Html::HElement(
            "button".to_string(),
            vec![
                attr("ipe-id", "r"),
                attr("data-ipe-pc-rules", "h|color: red"),
            ],
            vec![Html::HText("x".to_string())],
        );
        apply_style_injections(&mut tree);
        match &tree {
            Html::HElement(_, attrs, kids) => {
                assert!(
                    !attrs
                        .iter()
                        .any(|a| matches!(a, Attribute::Attr(k, _) if k == "data-ipe-pc-rules")),
                    "marker must be stripped"
                );
                assert!(
                    matches!(kids.first(), Some(Html::HElement(t, _, _)) if t == "style"),
                    "style child must be prepended"
                );
            }
            _ => panic!("expected element"),
        }
    }

    #[test]
    fn void_element_hoists_style_to_sibling() {
        // An <input> (void) carrying a marker can't take a child <style>; it must
        // be hoisted to a sibling slot right after the input.
        let mut tree: Html<()> = Html::HElement(
            "div".to_string(),
            vec![attr("ipe-id", "r")],
            vec![Html::HElement(
                "input".to_string(),
                vec![
                    attr("ipe-id", "r_0_input"),
                    attr("data-ipe-pc-rules", "f|outline: none"),
                ],
                vec![],
            )],
        );
        apply_style_injections(&mut tree);
        if let Html::HElement(_, _, kids) = &tree {
            assert_eq!(kids.len(), 2, "input + hoisted style sibling");
            assert!(matches!(&kids[0], Html::HElement(t, _, _) if t == "input"));
            assert!(matches!(&kids[1], Html::HElement(t, _, _) if t == "style"));
        } else {
            panic!("expected element");
        }
    }

    #[test]
    fn textarea_pseudo_class_hoists_style_to_sibling_not_into_value() {
        use crate::html::render_html;
        // A <textarea>'s children ARE its text value, so a scoped <style> must be
        // hoisted to a sibling slot after it — never prepended as a child, which
        // would render raw CSS as the field's content. The user's typed value
        // (splice-as-content) must survive untouched.
        let mut tree: Html<()> = Html::HElement(
            "div".to_string(),
            vec![attr("ipe-id", "r")],
            vec![Html::HElement(
                "textarea".to_string(),
                vec![
                    attr("ipe-id", "r_0_textarea"),
                    attr("value", "user body"),
                    attr("data-ipe-pc-rules", "f|border-color: blue"),
                ],
                vec![],
            )],
        );
        apply_style_injections(&mut tree);
        if let Html::HElement(_, _, kids) = &tree {
            assert_eq!(kids.len(), 2, "textarea + hoisted style sibling");
            match &kids[0] {
                Html::HElement(t, _, ta_kids) => {
                    assert_eq!(t, "textarea");
                    assert!(
                        ta_kids.is_empty(),
                        "no <style> child may nest inside the textarea"
                    );
                }
                _ => panic!("expected textarea"),
            }
            assert!(matches!(&kids[1], Html::HElement(t, _, _) if t == "style"));
        } else {
            panic!("expected element");
        }
        // End-to-end HTML: the textarea's body is the user's value, NOT CSS.
        let s = render_html(&tree);
        assert!(
            s.contains(">user body</textarea>"),
            "textarea body must be the user's value: {s}"
        );
        assert!(
            !s.contains("<style") || s.find("<style").unwrap() > s.find("</textarea>").unwrap(),
            "the <style> must sit after (outside) the textarea, never in its value: {s}"
        );
        assert!(
            !s.contains("data-ipe-pc-rules"),
            "pseudo-class marker must be consumed into a style rule: {s}"
        );
    }

    #[test]
    fn void_root_strips_its_markers() {
        // A void element at the tree root has no parent to hoist a sibling style
        // and is never self-handled; its markers must still be stripped so they
        // don't leak as inert data-* attrs (post-condition).
        let mut tree: Html<()> = Html::HElement(
            "input".to_string(),
            vec![
                attr("ipe-id", "r"),
                attr("data-ipe-pc-rules", "f|outline: none"),
            ],
            vec![],
        );
        apply_style_injections(&mut tree);
        if let Html::HElement(_, attrs, _) = &tree {
            assert!(
                !attrs
                    .iter()
                    .any(|a| matches!(a, Attribute::Attr(k, _) if k == "data-ipe-pc-rules")),
                "void-root marker must be stripped"
            );
        } else {
            panic!("expected element");
        }
    }

    /// #113 spec §1.4 end-to-end: the FULL pipeline from a Rust
    /// `Attribute::AttrPseudoRule` (as `Background.hoverColor` constructs it)
    /// through `ui_layout` → `assign_ipe_ids` → `apply_style_injections` →
    /// `render_html` must produce a ipe-id-scoped `<style>` rule and leave NO
    /// `data-ipe-pc-rules` marker in the final HTML. Composes the whole
    /// pipeline, not just each half in isolation.
    #[test]
    fn end_to_end_ui_hover_color_renders_scoped_style_and_leaves_no_marker() {
        use crate::color::Color;
        use crate::html::{assign_ipe_ids, render_html};
        use crate::ui::element::Element;
        use crate::ui::helpers::ui_bg_hover_color_;
        use crate::ui::render::ui_layout;

        let attrs = vec![ui_bg_hover_color_::<()>(Color::rgba(0, 92, 215, 1.0))];
        let elem: Element<()> = Element::Text("hover me".to_owned());
        let mut html = ui_layout(attrs, elem);
        assign_ipe_ids(&mut html, "r");
        apply_style_injections(&mut html);
        let s = render_html(&html);
        assert!(
            !s.contains("data-ipe-pc-rules"),
            "marker must be consumed, never leak into final HTML: {s}"
        );
        assert!(
            s.contains("<style"),
            "scoped <style> block must render: {s}"
        );
        assert!(
            s.contains(":hover") && s.contains("background-color:rgba(0,92,215,1)"),
            "hover rule with the exact CSS must render: {s}"
        );
        assert!(
            s.contains("@media (hover: hover)"),
            "hover rules must be wrapped in the touch-device guard: {s}"
        );
    }

    /// UI CSS-escaping hardening (spec §6.2), the direct regression for
    /// Repro A: an adversarial `Font.family` value routed through
    /// `Ui.onPseudo` → `build_style_string` → `collect_html_attrs` →
    /// `apply_style_injections` must not survive into the emitted `<style>`
    /// block as a page-wide rule. The `}` breakout is dropped upstream in
    /// `build_style_string`, so no `body{`/`display:none` reaches the sink,
    /// while the scoped `:hover` rule + `@media (hover: hover)` guard stay.
    #[test]
    fn onpseudo_font_family_breakout_is_neutralised_end_to_end() {
        use crate::html::{assign_ipe_ids, render_html};
        use crate::ui::element::Element;
        use crate::ui::helpers::{ui_hover_, ui_on_pseudo_};
        use crate::ui::render::ui_layout;

        let evil = "s } body { display:none } .x:hover {".to_owned();
        let pseudo = ui_on_pseudo_::<()>(
            ui_hover_(),
            vec![crate::ui::element::Attribute::AttrFontFamily(evil)],
        );
        let mut html = ui_layout(vec![pseudo], Element::Text("hi".to_owned()));
        assign_ipe_ids(&mut html, "r");
        apply_style_injections(&mut html);
        let out = render_html(&html);
        assert!(
            !out.contains("body {") && !out.contains("body{") && !out.contains("display:none"),
            "page-wide selector must not survive the collector gate: {out}"
        );
    }

    /// Repro B: an `@import` breakout through `Background.image` inside
    /// `Ui.onPseudo` must not reach the emitted `<style>` block.
    #[test]
    fn onpseudo_bg_image_import_breakout_is_neutralised_end_to_end() {
        use crate::html::{assign_ipe_ids, render_html};
        use crate::ui::element::Element;
        use crate::ui::helpers::{ui_hover_, ui_on_pseudo_};
        use crate::ui::render::ui_layout;

        let evil = "x) } @import url(\"https://evil.example/x.css\") ; .y:hover { background:url(x"
            .to_owned();
        let pseudo = ui_on_pseudo_::<()>(
            ui_hover_(),
            vec![crate::ui::element::Attribute::AttrBgImage(evil)],
        );
        let mut html = ui_layout(vec![pseudo], Element::Text("hi".to_owned()));
        assign_ipe_ids(&mut html, "r");
        apply_style_injections(&mut html);
        let out = render_html(&html);
        assert!(
            !out.contains("@import"),
            "remote @import must not survive the collector gate: {out}"
        );
    }

    /// `Ui.mediaQuery` exact-output pin at the injector: the marker pair on a
    /// ipe-id-stamped element must expand to EXACTLY the upstream shape
    /// `<style data-ipe-mq="<sid>">@media <q> { [ipe-id="<sid>"] { <rules> } }</style>`
    /// prepended as the first child, with both markers stripped.
    #[test]
    fn media_query_markers_expand_to_exact_scoped_style_block() {
        use crate::html::render_html;

        let mut tree: Html<()> = Html::HElement(
            "div".to_string(),
            vec![
                attr("ipe-id", "mq0"),
                attr("data-ipe-mq-q", "(min-width: 768px)"),
                attr("data-ipe-mq-rules", "background-color:rgba(18,18,24,1)"),
            ],
            vec![Html::HText("responsive".to_string())],
        );
        apply_style_injections(&mut tree);
        let s = render_html(&tree);
        assert!(
            s.contains(
                "<style data-ipe-mq=\"mq0\">@media (min-width: 768px) { \
                 [ipe-id=\"mq0\"] { background-color:rgba(18,18,24,1) !important } }</style>"
            ),
            "exact <style data-ipe-mq=…> block must render (with !important so the \
             breakpoint beats inline layout): {s}"
        );
        assert!(
            !s.contains("data-ipe-mq-q") && !s.contains("data-ipe-mq-rules"),
            "markers must be consumed, never leak into final HTML: {s}"
        );
    }

    /// `Ui.mediaQuery` FULL-pipeline end-to-end (producer → consumer): the
    /// runtime helper's wrapper (`ui_media_query_`) through `ui_layout` →
    /// `assign_ipe_ids` → `apply_style_injections` → `render_html` must
    /// produce a ipe-id-scoped `@media` `<style>` block, leave no marker, and
    /// keep the rule keyed to the wrapper's own ipe-id so two media queries
    /// on one page cannot cross-contaminate.
    #[test]
    fn end_to_end_ui_media_query_renders_scoped_style_and_leaves_no_marker() {
        use crate::color::Color;
        use crate::html::{assign_ipe_ids, render_html};
        use crate::ui::element::{Attribute, Element};
        use crate::ui::helpers::ui_media_query_;
        use crate::ui::render::ui_layout;

        let elem = ui_media_query_::<()>(
            "(min-width: 768px)".to_owned(),
            vec![Attribute::AttrBgColor(Color::rgba(18, 18, 24, 1.0))],
            Element::Text("responsive".to_owned()),
        );
        let mut html = ui_layout(vec![], elem);
        assign_ipe_ids(&mut html, "r");
        apply_style_injections(&mut html);
        let s = render_html(&html);
        assert!(
            !s.contains("data-ipe-mq-q") && !s.contains("data-ipe-mq-rules"),
            "markers must be consumed, never leak into final HTML: {s}"
        );
        assert!(
            s.contains("<style data-ipe-mq=\""),
            "scoped <style data-ipe-mq=…> block must render: {s}"
        );
        assert!(
            s.contains("@media (min-width: 768px) { [ipe-id=\""),
            "@media rule must be ipe-id-scoped: {s}"
        );
        assert!(
            s.contains("background-color:rgba(18,18,24,1) !important } }"),
            "collector rules must land inside the scoped block, marked !important \
             so the breakpoint beats inline layout: {s}"
        );
    }

    /// Render-proof for the fillPortion + mediaQuery layout fixes: the exact
    /// repros through the full producer -> assign_ipe_ids ->
    /// apply_style_injections -> render_html pipeline. Emits the whole page
    /// HTML (printed under `--nocapture` for a live browser computed-style
    /// check) and asserts the load-bearing CSS: each `fillPortion` column
    /// carries `flex-grow:<n>` + `flex-basis:0` so the portion, not the
    /// content, drives its width inside the `flex-wrap:wrap` row; and the
    /// `display:none` media rule lands on the styled node's own selector AND
    /// carries `!important`, so it beats the element's inline `display:flex`.
    #[test]
    fn render_proof_fill_portion_and_media_query() {
        use crate::html::{assign_ipe_ids, render_html};
        use crate::ui::element::{Attribute, Element, Length};
        use crate::ui::helpers::{ui_column_, ui_el_, ui_media_query_, ui_row_, ui_wrapped_row_};
        use crate::ui::render::ui_layout;

        // Two fillPortion columns (7 / 3) inside a wrappedRow.
        let row: Element<()> = ui_wrapped_row_(
            vec![],
            vec![
                ui_el_(
                    vec![Attribute::AttrWidth(Length::fill_portion(7))],
                    Element::Text("left".to_owned()),
                ),
                ui_el_(
                    vec![Attribute::AttrWidth(Length::fill_portion(3))],
                    Element::Text("right".to_owned()),
                ),
            ],
        );
        // A nav hidden below 999px — its inline display:flex (from the row
        // marker) must lose to the media rule.
        let nav: Element<()> = ui_media_query_(
            "(max-width: 999px)".to_owned(),
            vec![Attribute::AttrStyle(
                "display".to_owned(),
                "none".to_owned(),
            )],
            ui_row_(vec![], vec![Element::Text("nav".to_owned())]),
        );

        let page = ui_column_(vec![], vec![row, nav]);
        let mut html = ui_layout(vec![], page);
        assign_ipe_ids(&mut html, "r");
        apply_style_injections(&mut html);
        let s = render_html(&html);
        println!("RENDER_PROOF_HTML_START\n{s}\nRENDER_PROOF_HTML_END");

        // Both portions drive width via flex-grow + flex-basis:0.
        assert!(
            s.contains("flex-grow:7") && s.contains("flex-grow:3"),
            "both fillPortion columns must emit their flex-grow: {s}"
        );
        assert!(
            s.matches("flex-basis:0").count() >= 2,
            "each fillPortion column must emit flex-basis:0 so the portion (not \
             content) drives width: {s}"
        );
        // The media rule targets a real node selector, is !important, and the
        // nav still carries its inline display:flex to be overridden.
        assert!(
            s.contains("@media (max-width: 999px) { [ipe-id=")
                && s.contains("display:none !important"),
            "breakpoint rule must be ipe-id-scoped and !important: {s}"
        );
        assert!(
            s.contains("display:flex"),
            "nav keeps its inline layout for the media rule to override: {s}"
        );
    }

    /// SECURITY end-to-end: a breakout media-query string through the real
    /// producer must be neutralised — the `SafeCssMediaQuery` gate drops the
    /// markers at construction, so the pipeline emits NO `@media`, NO
    /// `</style` breakout, and NO `<script>`, while the child still renders.
    #[test]
    fn end_to_end_ui_media_query_breakout_is_neutralised() {
        use crate::color::Color;
        use crate::html::{assign_ipe_ids, render_html};
        use crate::ui::element::{Attribute, Element};
        use crate::ui::helpers::ui_media_query_;
        use crate::ui::render::ui_layout;

        let elem = ui_media_query_::<()>(
            "(min-width: 1px) </style><script>alert(1)</script> { } @import url(evil)".to_owned(),
            vec![Attribute::AttrBgColor(Color::rgba(1, 2, 3, 1.0))],
            Element::Text("still here".to_owned()),
        );
        let mut html = ui_layout(vec![], elem);
        assign_ipe_ids(&mut html, "r");
        apply_style_injections(&mut html);
        let s = render_html(&html);
        let low = s.to_ascii_lowercase();
        assert!(
            !low.contains("</style><script"),
            "breakout must not form: {s}"
        );
        assert!(!low.contains("<script"), "script must never render: {s}");
        assert!(
            !low.contains("@media"),
            "gated query must emit no rule: {s}"
        );
        assert!(!low.contains("@import"), "at-rule must not survive: {s}");
        assert!(s.contains("still here"), "child must still render: {s}");
    }

    // ── Sink-side forgery gates ───────────────
    // The style markers are raw String attributes a caller can FORGE via
    // `Ui.htmlAttribute "data-ipe-mq-rules" "…"`, bypassing the producer's
    // SafeCssValue / SafeCssMediaQuery gates entirely. The sink builders must
    // re-validate (parse, don't validate at the real boundary) and drop the
    // block fail-closed. `strip_style_close` alone did NOT catch `{ } ; @import`.

    #[test]
    fn build_mq_sink_drops_forged_rules_breakout() {
        // Forged rules containing a ruleset breakout + at-rule injection.
        let attrs = vec![
            attr("data-ipe-mq-q", "screen"),
            attr(
                "data-ipe-mq-rules",
                "color:red } [ipe-id=\"x\"] { } @import url(//evil/x.css)",
            ),
        ];
        assert_eq!(
            build_mq("r.0", &attrs),
            "",
            "forged breakout rules must drop the whole @media block"
        );
    }

    #[test]
    fn build_mq_sink_drops_forged_query_breakout() {
        let attrs = vec![
            attr("data-ipe-mq-q", "screen { } [x] { }"),
            attr("data-ipe-mq-rules", "color:red"),
        ];
        assert_eq!(
            build_mq("r.0", &attrs),
            "",
            "forged breakout query must drop the whole @media block"
        );
    }

    #[test]
    fn build_mq_sink_keeps_legit_markers() {
        let attrs = vec![
            attr("data-ipe-mq-q", "(min-width: 768px)"),
            attr("data-ipe-mq-rules", "background-color:rgba(18,18,24,1)"),
        ];
        let out = build_mq("r.0", &attrs);
        assert!(
            out.contains("@media (min-width: 768px) { [ipe-id=\"r.0\"]"),
            "legit query + selector must survive: {out}"
        );
        assert!(
            out.contains("background-color:rgba(18,18,24,1) !important"),
            "legit rules must survive, marked !important to beat inline layout: {out}"
        );
    }

    #[test]
    fn build_mq_marks_declarations_important_and_respects_explicit_important() {
        // Every emitted declaration gets `!important` so the breakpoint beats
        // the inline layout props the renderer writes on `style=""`; a caller's
        // own `!important` is not doubled.
        let attrs = vec![
            attr("data-ipe-mq-q", "(max-width: 999px)"),
            attr("data-ipe-mq-rules", "display:none;color:red !important"),
        ];
        let out = build_mq("r.0", &attrs);
        assert!(
            out.contains("display:none !important;color:red !important"),
            "each declaration marked !important, existing !important not doubled: {out}"
        );
        assert!(
            !out.contains("!important !important"),
            "must never double an existing !important: {out}"
        );
    }

    #[test]
    fn build_tr_sink_drops_forged_breakout() {
        let attrs = vec![attr(
            "data-ipe-tr-rules",
            "x } [y] { color:red } @import url(evil)",
        )];
        assert_eq!(
            build_tr("r.0", &attrs),
            "",
            "forged transition breakout must drop the block"
        );
    }

    #[test]
    fn build_pc_sink_drops_forged_breakout() {
        let attrs = vec![attr(
            "data-ipe-pc-rules",
            "h|color:red } [x] { } @import url(evil)",
        )];
        assert_eq!(
            build_pc("r.0", &attrs),
            "",
            "forged pseudo-class breakout must drop that rule"
        );
    }

    /// SECURITY (appearance-hot-swap sink preservation, raw-CSS kernel): a
    /// `Ui.animate` keyframes body / shorthand tail that reaches the live
    /// `build_anim` sink from a dev-patched `LiteralTable` slot must be
    /// neutralised byte-identically to the same value baked as a direct literal.
    /// The hoist changes only WHERE the String originates; the sink
    /// (`sink_safe_keyframes_body` on the body, `SafeCssValue` on the tail,
    /// `sanitise_animation_name` on the name, `strip_style_close` belt-and-braces)
    /// is a pure function of the marker String, so dev == prod. Vectors probe the
    /// `}`/`@import`/`</style>` breakout and whitespace evasion of the body.
    #[test]
    fn animate_dev_patched_body_is_neutralised_identically_to_baked() {
        use crate::web::LiteralTable;

        // The marker the stdlib emits for `Ui.animate` is
        // `name||tail||body||respect`; the body is the position-2 String this
        // slice hoists. Each vector is an adversarial BODY.
        let bodies = [
            "0% { opacity: 0 } } body { display:none } @import url(//evil/x.css) {",
            "0% { opacity: 0 } </style><script>alert(1)</script>",
            "0% { opacity: 0 }   }   [x]{color:red",
        ];
        for body in bodies {
            let baked_marker = format!("anim||300ms ease||{body}||1");
            let baked = build_anim("r.0#div", &[attr("data-ipe-anim-rules", &baked_marker)]);

            // Dev-patched path: the body is read back from a patched table slot,
            // the exact emitted read shape, then encoded into the same marker.
            let mut table = LiteralTable::from_defaults(&["0% { opacity: 0 } 100% { opacity: 1 }"]);
            table.apply_patch(&[(0, body.to_owned())]);
            let patched_marker = format!("anim||300ms ease||{}||1", table.get(0));
            let patched = build_anim("r.0#div", &[attr("data-ipe-anim-rules", &patched_marker)]);

            assert_eq!(
                baked, patched,
                "dev-patched keyframes body must render identically to the baked \
                 literal (one sink, dev == prod) for body {body:?}"
            );
            // The sink drops the whole entry fail-closed on a breakout body.
            assert_eq!(
                patched, "",
                "adversarial keyframes body must drop fail-closed at the sink for {body:?}"
            );
        }
    }

    #[test]
    fn idempotent_second_run_adds_no_duplicate_style() {
        let mut tree: Html<()> = Html::HElement(
            "div".to_string(),
            vec![
                attr("ipe-id", "r"),
                attr("data-ipe-tr-rules", "color 200ms"),
            ],
            vec![],
        );
        apply_style_injections(&mut tree);
        let first = count_styles(&tree);
        apply_style_injections(&mut tree);
        assert_eq!(first, count_styles(&tree), "second run must be a no-op");
    }
}

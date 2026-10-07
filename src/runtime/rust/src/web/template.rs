//! Inert static-view-subtree template + its materializer.
//!
//! A [`Template`] is a fully-static `view` subtree reduced to data: element
//! tags, static attribute key/value string pairs, static text, and child
//! templates — nothing else. [`materialize_template`] rebuilds an [`Html`]
//! tree from a [`Template`] through the SAME constructors the normal render
//! path uses, so a materialized template renders byte-identically to the
//! original compiled subtree.
//!
//! Inert by construction (make-invalid-states-unrepresentable): the type has
//! no variant for raw/un-escaped markup (`HRaw`) and no variant for an event
//! handler / `Msg`. A `Template` therefore CANNOT smuggle markup past the
//! render sanitizer nor carry logic — its only payloads are `String` tags,
//! attribute keys/values, and text, all of which the render path escapes or
//! name-gates exactly as it does a compiled literal. There is no code path,
//! including deserialization, by which a `Template` yields unescaped HTML.

use crate::html::{Attribute, Html, admit_element};

/// The maximum template nesting depth accepted on decode and descended on
/// materialize. Shares the render/diff ceiling ([`crate::html::MAX_HTML_DEPTH`])
/// as a single source of truth: a template can never describe a tree deeper
/// than the renderer will walk, so materialize and render agree on the bound.
pub const MAX_TEMPLATE_DEPTH: usize = crate::html::MAX_HTML_DEPTH;

/// A static attribute as an inert key/value string pair. Carries only strings —
/// never an event handler — so an attribute in a template can never be logic.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TemplateAttr {
    /// Attribute name (name-gated by the render sink, exactly as a compiled attr).
    pub key: String,
    /// Attribute value (attribute-escaped by the render sink).
    pub value: String,
}

/// An inert, fully-static view subtree.
///
/// The two variants are the ONLY shapes a static subtree takes: an element
/// (tag + static attribute pairs + child templates) or a text node. There is
/// deliberately no raw-markup variant and no handler variant — that absence is
/// the security guarantee, enforced by the type rather than a runtime check.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Template {
    /// A static element: tag name, static attribute pairs, and child templates.
    Element {
        tag: String,
        attrs: Vec<TemplateAttr>,
        children: Vec<Template>,
    },
    /// A static text node. Rendered HTML-escaped, exactly like `Html::HText`.
    Text(String),
}

impl Drop for Template {
    /// Dismantle the tree iteratively so dropping a deeply nested template can
    /// never overflow the stack. A `Template` can be decoded from untrusted
    /// wire input, so it may nest arbitrarily deep; the derived recursive drop
    /// would abort the process on such a tree. Draining each element's children
    /// onto an explicit stack keeps the destructor bounded by the heap, not the
    /// native call stack.
    fn drop(&mut self) {
        let mut pending: Vec<Template> = match self {
            Template::Element { children, .. } => std::mem::take(children),
            Template::Text(_) => return,
        };
        while let Some(mut node) = pending.pop() {
            if let Template::Element { children, .. } = &mut node {
                pending.append(&mut std::mem::take(children));
            }
            // `node` (now child-free) drops here without recursion.
        }
    }
}

/// A malformed or out-of-bounds template, surfaced as a typed error rather than
/// a panic. A patched template arrives from the dev overlay transport as
/// untrusted input, so an over-deep tree is turned back here (bounded by
/// construction) instead of being allowed to exhaust the stack at materialize.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TemplateError {
    /// The template nests deeper than [`MAX_TEMPLATE_DEPTH`].
    TooDeep,
}

impl std::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateError::TooDeep => {
                write!(f, "template nests deeper than {MAX_TEMPLATE_DEPTH}")
            }
        }
    }
}

impl std::error::Error for TemplateError {}

impl Template {
    /// Validate a decoded template's shape: reject a tree deeper than the render
    /// ceiling before it is materialized. Total and allocation-free — walks the
    /// existing tree without recursion, so an adversarial decode cannot overflow
    /// the stack in the check itself.
    ///
    /// Call this on any template that crossed an untrusted boundary (the dev
    /// overlay transport) before handing it to [`materialize_template`].
    ///
    /// # Errors
    /// Returns [`TemplateError::TooDeep`] when the tree nests deeper than
    /// [`MAX_TEMPLATE_DEPTH`].
    pub fn check_bounds(&self) -> Result<(), TemplateError> {
        // Explicit stack, not recursion: the depth check must not itself be
        // bounded by the native call stack it is meant to protect.
        let mut stack: Vec<(&Template, usize)> = vec![(self, 0)];
        while let Some((node, depth)) = stack.pop() {
            if depth >= MAX_TEMPLATE_DEPTH {
                return Err(TemplateError::TooDeep);
            }
            if let Template::Element { children, .. } = node {
                for child in children {
                    stack.push((child, depth.saturating_add(1)));
                }
            }
        }
        Ok(())
    }
}

/// Rebuild an [`Html`] tree from a [`Template`], using the same node
/// constructors (`Html::HElement` / `Html::HText`) and attribute constructor
/// (`Attribute::Attr`) the normal render path emits, so the result renders
/// byte-identically to the original compiled subtree.
///
/// Bounded by construction: descent stops at [`MAX_TEMPLATE_DEPTH`] (the render
/// ceiling), so a deep template can never overflow the stack. A subtree at the
/// cap materializes to an empty text node — the same "stop, don't recurse
/// further" posture the renderer takes at its own depth cap — never a panic.
///
/// The produced tree is inert by construction: every element attribute is an
/// `Attribute::Attr` (never `EventAttr`), and every text node is `Html::HText`
/// (escaped on render, never `HRaw`). No input can make this emit raw markup
/// or a handler.
#[must_use]
pub fn materialize_template<M>(template: &Template) -> Html<M> {
    materialize_at(template, 0)
}

fn materialize_at<M>(template: &Template, depth: usize) -> Html<M> {
    if depth >= MAX_TEMPLATE_DEPTH {
        // Same bounded-descent posture as the renderer at its cap: stop
        // descending. An empty escaped text node is inert and well-formed.
        return Html::HText(String::new());
    }
    match template {
        Template::Text(s) => Html::HText(s.clone()),
        Template::Element {
            tag,
            attrs,
            children,
        } => {
            let html_attrs = attrs
                .iter()
                .map(|a| Attribute::Attr(a.key.clone(), a.value.clone()))
                .collect();
            let html_children: Vec<Html<M>> = children
                .iter()
                .map(|c| materialize_at(c, depth.saturating_add(1)))
                .collect();
            // SECURITY: the shared tag gate. A template holds only text and
            // elements, never trusted raw markup, so a `<script>`/`<style>`
            // (or `<plaintext>`, or an unsafe tag name) from a baked or patched
            // slot materializes to inert empty text.
            if admit_element(tag, &html_children).is_err() {
                return Html::HText(String::new());
            }
            Html::HElement(tag.clone(), html_attrs, html_children)
        }
    }
}

/// Decode a serialized [`Template`] and materialize it, through the dev overlay
/// transport (a JSON string). The string front door to [`materialize_template`]:
/// the emitted `view` reads its per-view slot (`__ipe_lit.get(N)`) and hands the
/// baked-default-or-patched JSON here, so prod (baked default) and dev (patched
/// slot) run the SAME materialize path — dev == prod by construction.
///
/// Fail-closed on hostile input, never a panic (the slot value crosses the
/// untrusted dev overlay boundary):
/// - a decode failure returns an inert empty text node (`Html::HText("")`);
/// - an over-deep decoded template ([`Template::check_bounds`]) returns the same
///   inert empty text node, so a decode cannot exhaust the stack at materialize.
///
/// Inert by construction: the [`Template`] type has no raw-markup and no handler
/// variant, so no JSON — however adversarial — decodes into unescaped markup or
/// logic. The produced [`Html`] carries only `HText` (escaped on render) and
/// `Attribute::Attr` (name-gated + escaped on render).
#[must_use]
pub fn materialize_template_str<M>(json: &str) -> Html<M> {
    // A malformed patch (or any non-`Template` JSON) degrades to an inert empty
    // text node rather than crashing the render: the slot value is untrusted.
    let Ok(template) = serde_json::from_str::<Template>(json) else {
        return Html::HText(String::new());
    };
    // A decoded template may nest arbitrarily deep; refuse an over-deep tree
    // (bounded by construction) before descending it.
    if template.check_bounds().is_err() {
        return Html::HText(String::new());
    }
    materialize_template(&template)
}

/// Build a [`Template`] from a static [`Html`] subtree — the inverse of
/// [`materialize_template`]. Fail-closed (parse, don't validate): any node that
/// is NOT provably static returns `None`, so a template is only ever built from
/// a subtree that materialize can reproduce byte-identically.
///
/// A node is non-static, and so refuses, when it is:
/// - `Html::HRaw` (un-escaped markup — never representable in a template);
/// - an element carrying an `Attribute::EventAttr` (a handler — logic);
/// - an element carrying an `Attribute::BoolAttr` or `Attribute::NoAttr`
///   (outside the static string-attr scope of this template form);
/// - nested deeper than [`MAX_TEMPLATE_DEPTH`].
///
/// Returns `None` in each of those cases rather than silently dropping the
/// offending part, so the caller (the conformance test and later emit) treats
/// a non-templatable subtree as "keep it compiled", never "template a lie".
#[must_use]
pub fn template_of<M>(node: &Html<M>) -> Option<Template> {
    template_of_at(node, 0)
}

fn template_of_at<M>(node: &Html<M>, depth: usize) -> Option<Template> {
    if depth >= MAX_TEMPLATE_DEPTH {
        return None;
    }
    match node {
        Html::HText(s) => Some(Template::Text(s.clone())),
        // Raw markup has no inert representation — refuse rather than smuggle it.
        Html::HRaw(_) => None,
        Html::HElement(tag, attrs, children) => {
            let mut template_attrs = Vec::with_capacity(attrs.len());
            for a in attrs {
                match a {
                    Attribute::Attr(k, v) => template_attrs.push(TemplateAttr {
                        key: k.clone(),
                        value: v.clone(),
                    }),
                    // A handler is logic; a bool/absent attr is outside this
                    // static string-attr scope. Either makes the subtree
                    // non-templatable → keep it compiled.
                    Attribute::EventAttr(_) | Attribute::BoolAttr(..) | Attribute::NoAttr => {
                        return None;
                    }
                }
            }
            let mut template_children = Vec::with_capacity(children.len());
            for child in children {
                template_children.push(template_of_at(child, depth.saturating_add(1))?);
            }
            Some(Template::Element {
                tag: tag.clone(),
                attrs: template_attrs,
                children: template_children,
            })
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::{
        MAX_TEMPLATE_DEPTH, Template, TemplateAttr, TemplateError, materialize_template,
        materialize_template_str, template_of,
    };
    use crate::html::{Attribute, Html, render_html};

    // Assert that round-tripping a static subtree through a template and its
    // materializer renders byte-identically to rendering the original — the
    // dev == prod soundness proof the whole structural-hot-swap subsystem rests
    // on. `template_of` + `materialize_template` compose to the identity on the
    // rendered bytes.
    fn assert_round_trip_byte_identical(subtree: &Html<()>) {
        let template = template_of(subtree).expect("static subtree must be templatable");
        let materialized: Html<()> = materialize_template(&template);
        assert_eq!(
            render_html(&materialized),
            render_html(subtree),
            "materialized template must render byte-identically to the original subtree"
        );
    }

    #[test]
    fn round_trip_single_element_with_static_attrs_and_text() {
        let subtree: Html<()> = Html::HElement(
            "div".to_string(),
            vec![
                Attribute::Attr("class".to_string(), "card".to_string()),
                Attribute::Attr("style".to_string(), "padding: 12px".to_string()),
            ],
            vec![Html::HText("Hello".to_string())],
        );
        assert_round_trip_byte_identical(&subtree);
    }

    #[test]
    fn round_trip_nested_elements_and_empty_children() {
        let subtree: Html<()> = Html::HElement(
            "section".to_string(),
            vec![Attribute::Attr("id".to_string(), "main".to_string())],
            vec![
                Html::HElement(
                    "h1".to_string(),
                    vec![],
                    vec![Html::HText("Title".to_string())],
                ),
                // An element with no attributes and no children.
                Html::HElement("hr".to_string(), vec![], vec![]),
                Html::HElement(
                    "p".to_string(),
                    vec![Attribute::Attr("class".to_string(), "lead".to_string())],
                    vec![Html::HText("Body".to_string())],
                ),
            ],
        );
        assert_round_trip_byte_identical(&subtree);
    }

    #[test]
    fn round_trip_deep_nesting() {
        // Deeply (but legally) nested wrapper chain — proves the materializer
        // reproduces depth exactly, well under the ceiling.
        let mut node: Html<()> = Html::HText("deep".to_string());
        for _ in 0..64 {
            node = Html::HElement("div".to_string(), vec![], vec![node]);
        }
        assert_round_trip_byte_identical(&node);
    }

    #[test]
    fn round_trip_escaped_text_stays_escaped_no_xss() {
        // Text with every HTML-special char. The template carries the RAW
        // string; the render path escapes it. A round trip must keep it escaped
        // — no path yields the raw `<script>` bytes.
        let raw = r#"<script>alert("x & 'y'")</script>"#;
        let subtree: Html<()> = Html::HElement(
            "div".to_string(),
            vec![],
            vec![Html::HText(raw.to_string())],
        );
        assert_round_trip_byte_identical(&subtree);

        let template = template_of(&subtree).expect("templatable");
        let rendered = render_html::<()>(&materialize_template(&template));
        // The dangerous raw sequence never appears verbatim in the output.
        assert!(
            !rendered.contains("<script>"),
            "escaped text must not yield a raw <script> tag: {rendered}"
        );
        assert!(
            rendered.contains("&lt;script&gt;"),
            "special chars must be entity-escaped: {rendered}"
        );
    }

    #[test]
    fn round_trip_special_chars_in_attribute_value() {
        // Attribute values with quotes/angle brackets must survive escaping
        // identically through the template.
        let subtree: Html<()> = Html::HElement(
            "a".to_string(),
            vec![Attribute::Attr(
                "title".to_string(),
                r#"a "quote" & <tag>"#.to_string(),
            )],
            vec![Html::HText("link".to_string())],
        );
        assert_round_trip_byte_identical(&subtree);
    }

    #[test]
    fn round_trip_reordered_attributes() {
        // The render path sorts attributes by key, so two subtrees differing
        // only in source attribute order render identically — and each still
        // round-trips byte-identically through its own template.
        let a: Html<()> = Html::HElement(
            "div".to_string(),
            vec![
                Attribute::Attr("data-b".to_string(), "2".to_string()),
                Attribute::Attr("data-a".to_string(), "1".to_string()),
            ],
            vec![],
        );
        let b: Html<()> = Html::HElement(
            "div".to_string(),
            vec![
                Attribute::Attr("data-a".to_string(), "1".to_string()),
                Attribute::Attr("data-b".to_string(), "2".to_string()),
            ],
            vec![],
        );
        assert_round_trip_byte_identical(&a);
        assert_round_trip_byte_identical(&b);
        // Both orderings render to the same bytes (render sorts by key).
        assert_eq!(
            render_html::<()>(&materialize_template(&template_of(&a).unwrap())),
            render_html::<()>(&materialize_template(&template_of(&b).unwrap())),
        );
    }

    // ── inert-by-construction refusals ──────────────────────────────────────

    #[test]
    fn raw_markup_node_is_refused() {
        // An `HRaw` node has no template representation — `template_of` refuses
        // it rather than smuggle un-escaped markup into an inert datum.
        let subtree: Html<()> = Html::HElement(
            "div".to_string(),
            vec![],
            vec![Html::HRaw("<b>trusted?</b>".to_string())],
        );
        assert_eq!(template_of(&subtree), None);
    }

    #[test]
    fn event_handler_attribute_is_refused() {
        // An element carrying a handler is logic, not a static subtree.
        let subtree: Html<i32> = Html::HElement(
            "button".to_string(),
            vec![Attribute::EventAttr(crate::html::Event::OnMsg(
                "click".to_string(),
                1,
            ))],
            vec![Html::HText("+".to_string())],
        );
        assert_eq!(template_of(&subtree), None);
    }

    #[test]
    fn bool_and_absent_attributes_are_refused() {
        let with_bool: Html<()> = Html::HElement(
            "input".to_string(),
            vec![Attribute::BoolAttr("disabled".to_string(), true)],
            vec![],
        );
        assert_eq!(template_of(&with_bool), None);

        let with_noattr: Html<()> =
            Html::HElement("div".to_string(), vec![Attribute::NoAttr], vec![]);
        assert_eq!(template_of(&with_noattr), None);
    }

    // ── bounded-by-construction decode ──────────────────────────────────────

    #[test]
    fn over_deep_template_fails_bounds_check() {
        let mut node = Template::Text("x".to_string());
        // Build a chain past the ceiling.
        for _ in 0..=MAX_TEMPLATE_DEPTH {
            node = Template::Element {
                tag: "div".to_string(),
                attrs: vec![],
                children: vec![node],
            };
        }
        assert_eq!(node.check_bounds(), Err(TemplateError::TooDeep));
    }

    #[test]
    fn legal_depth_passes_bounds_check() {
        let mut node = Template::Text("x".to_string());
        for _ in 0..16 {
            node = Template::Element {
                tag: "div".to_string(),
                attrs: vec![],
                children: vec![node],
            };
        }
        assert_eq!(node.check_bounds(), Ok(()));
    }

    // Iteratively measure an `Html` tree's nesting depth (no recursion, so the
    // measurement itself cannot overflow on a maximally deep tree).
    fn html_depth<M>(root: &Html<M>) -> usize {
        let mut max = 0usize;
        let mut stack = vec![(root, 1usize)];
        while let Some((node, depth)) = stack.pop() {
            max = max.max(depth);
            if let Html::HElement(_, _, kids) = node {
                for k in kids {
                    stack.push((k, depth.saturating_add(1)));
                }
            }
        }
        max
    }

    #[test]
    fn materialize_caps_descent_at_the_ceiling() {
        // Materialize is bounded by construction: given a template far deeper
        // than the cap, descent stops at `MAX_TEMPLATE_DEPTH`, so the produced
        // `Html` is never deeper than that ceiling — it can never recurse
        // unboundedly on a hostile deep template. Run on a large-stack thread
        // because building/measuring a ceiling-deep tree, like the renderer's
        // own descent, uses the native stack up to the same bound.
        let handle = std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let mut node = Template::Text("x".to_string());
                for _ in 0..(MAX_TEMPLATE_DEPTH + 500) {
                    node = Template::Element {
                        tag: "div".to_string(),
                        attrs: vec![],
                        children: vec![node],
                    };
                }
                let html: Html<()> = materialize_template(&node);
                html_depth(&html)
            })
            .expect("spawn measuring thread");
        let depth = handle.join().expect("measuring thread must not panic");
        // `html_depth` counts the root as 1, and descent stops at the cap
        // emitting one terminal leaf, so the bounded result is the cap plus that
        // leaf — never the input's 1500+ depth. The point is that materialize is
        // bounded by the ceiling, not by the (hostile) input depth.
        assert!(
            depth <= MAX_TEMPLATE_DEPTH + 1,
            "materialize must cap descent at the ceiling, got depth {depth}"
        );
        assert!(
            depth >= MAX_TEMPLATE_DEPTH,
            "the deep input should materialize right up to the ceiling, got {depth}"
        );
    }

    // ── serde round-trip ────────────────────────────────────────────────────

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_preserves_template() {
        let template = Template::Element {
            tag: "div".to_string(),
            attrs: vec![
                TemplateAttr {
                    key: "class".to_string(),
                    value: "card".to_string(),
                },
                TemplateAttr {
                    key: "data-x".to_string(),
                    value: r#"< & ">"#.to_string(),
                },
            ],
            children: vec![
                Template::Text("hi".to_string()),
                Template::Element {
                    tag: "span".to_string(),
                    attrs: vec![],
                    children: vec![],
                },
            ],
        };
        let json = serde_json::to_string(&template).expect("serialize");
        let decoded: Template = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, template);
        // And the decoded template renders identically to the original.
        assert_eq!(
            render_html::<()>(&materialize_template(&decoded)),
            render_html::<()>(&materialize_template(&template)),
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_decoded_template_is_still_inert() {
        // A serialized template is JSON with only tag/attr/text strings — there
        // is no field a patched payload could set to inject a handler or raw
        // markup, because the type has no such variant to deserialize into. A
        // decode of an unknown shape fails to a typed error, never a raw node.
        let json = r#"{"Text":"<b>x</b>"}"#;
        let decoded: Template = serde_json::from_str(json).expect("decode text");
        let rendered = render_html::<()>(&materialize_template(&decoded));
        assert!(
            !rendered.contains("<b>"),
            "text stays escaped even when decoded from the wire: {rendered}"
        );
        assert!(rendered.contains("&lt;b&gt;"));

        // A payload naming a non-existent "Raw"/handler variant simply fails to
        // decode — there is no inert-data path to a raw node.
        let bogus = r#"{"Raw":"<script>evil()</script>"}"#;
        assert!(serde_json::from_str::<Template>(bogus).is_err());
    }

    // ── materialize_template_str: the string front door (dev overlay transport) ──

    // dev == prod at the runtime level: the baked-default JSON string (what prod
    // holds AND what the emitted `view` reads via `__ipe_lit.get(N)`) materializes
    // byte-identically to rendering the original static subtree directly. This is
    // the structural-hot-swap conformance the emit rests on.
    #[test]
    fn str_materialize_matches_direct_render() {
        let subtree: Html<()> = Html::HElement(
            "section".to_string(),
            vec![Attribute::Attr("id".to_string(), "main".to_string())],
            vec![
                Html::HElement(
                    "h1".to_string(),
                    vec![],
                    vec![Html::HText("Title".to_string())],
                ),
                Html::HElement(
                    "p".to_string(),
                    vec![Attribute::Attr("class".to_string(), "lead".to_string())],
                    vec![Html::HText("Body".to_string())],
                ),
            ],
        );
        let template = template_of(&subtree).expect("templatable");
        let json = serde_json::to_string(&template).expect("serialize");
        // The baked default (prod) is exactly this JSON string.
        let via_str: Html<()> = materialize_template_str(&json);
        assert_eq!(
            render_html(&via_str),
            render_html(&subtree),
            "materialize_template_str over the baked default must render byte-identically"
        );
    }

    // A structural edit is a NEW JSON string in the same slot: adding a static
    // child changes the string's bytes but nothing else. The str materializer
    // renders the edited tree, so the runtime swap needs no structural machinery.
    #[test]
    fn str_materialize_reflects_a_structural_edit() {
        let before: Html<()> = Html::HElement(
            "ul".to_string(),
            vec![],
            vec![Html::HElement(
                "li".to_string(),
                vec![],
                vec![Html::HText("one".to_string())],
            )],
        );
        let after: Html<()> = Html::HElement(
            "ul".to_string(),
            vec![],
            vec![
                Html::HElement(
                    "li".to_string(),
                    vec![],
                    vec![Html::HText("one".to_string())],
                ),
                Html::HElement(
                    "li".to_string(),
                    vec![],
                    vec![Html::HText("two".to_string())],
                ),
            ],
        );
        let json_after = serde_json::to_string(&template_of(&after).unwrap()).unwrap();
        // Swapping the slot's JSON (the patch) renders the added child.
        let materialized: Html<()> = materialize_template_str(&json_after);
        assert_eq!(render_html(&materialized), render_html(&after));
        assert_ne!(render_html(&materialized), render_html(&before));
    }

    // A malformed slot value (a stale/hostile patch that is not a `Template`)
    // degrades to an inert empty text node — never a panic, never raw markup.
    #[test]
    fn str_materialize_malformed_json_is_inert_empty() {
        let out: Html<()> = materialize_template_str("this is not json");
        assert_eq!(render_html(&out), "");
        let bogus: Html<()> = materialize_template_str(r#"{"Raw":"<script>evil()</script>"}"#);
        let rendered = render_html(&bogus);
        assert!(!rendered.contains("<script>"), "no raw markup: {rendered}");
        assert_eq!(rendered, "");
    }

    // SECURITY: a template holds no trusted raw markup, so a `<script>`, a
    // `<style>` or a `<plaintext>` element (any ASCII case) from a baked or a
    // patched slot materializes to inert empty text through the shared tag
    // gate; an ordinary element beside it still renders.
    #[test]
    fn materialize_refuses_raw_text_and_executable_elements() {
        for tag in ["script", "SCRIPT", "style", "Style", "plaintext"] {
            let template = Template::Element {
                tag: "div".to_string(),
                attrs: vec![],
                children: vec![
                    Template::Element {
                        tag: tag.to_string(),
                        attrs: vec![TemplateAttr {
                            key: "src".to_string(),
                            value: "/x.js".to_string(),
                        }],
                        children: vec![Template::Text("alert(document.cookie)".to_string())],
                    },
                    Template::Element {
                        tag: "p".to_string(),
                        attrs: vec![],
                        children: vec![Template::Text("ok".to_string())],
                    },
                ],
            };
            let rendered = render_html(&materialize_template::<()>(&template));
            assert_eq!(rendered, "<div><p>ok</p></div>", "<{tag}> must be refused");
        }
    }

    // The patched-slot front door runs the same gate.
    #[test]
    fn str_materialize_refuses_a_script_element() {
        let json = r#"{"Element":{"tag":"script","attrs":[],"children":[{"Text":"alert(1)"}]}}"#;
        let out: Html<()> = materialize_template_str(json);
        assert_eq!(render_html(&out), "");
    }

    // A decoded template's text stays escaped through the string front door — no
    // JSON payload yields a raw `<script>`.
    #[test]
    fn str_materialize_keeps_text_escaped() {
        let json = r#"{"Text":"<script>alert(1)</script>"}"#;
        let out: Html<()> = materialize_template_str(json);
        let rendered = render_html(&out);
        assert!(
            !rendered.contains("<script>"),
            "must stay escaped: {rendered}"
        );
        assert!(rendered.contains("&lt;script&gt;"));
    }

    // An over-deep decoded template is refused (bounded by construction): the str
    // front door returns the inert empty node rather than descending a hostile
    // deep tree. Built on a large-stack thread because SERIALISING a
    // ceiling-deep template walks the native stack.
    #[test]
    fn str_materialize_over_deep_json_is_inert_empty() {
        let handle = std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let mut node = Template::Text("x".to_string());
                for _ in 0..(MAX_TEMPLATE_DEPTH + 10) {
                    node = Template::Element {
                        tag: "div".to_string(),
                        attrs: vec![],
                        children: vec![node],
                    };
                }
                let json = serde_json::to_string(&node).expect("serialize deep");
                let out: Html<()> = materialize_template_str(&json);
                render_html(&out)
            })
            .expect("spawn");
        let rendered = handle.join().expect("thread must not panic");
        assert_eq!(rendered, "", "an over-deep decoded template is inert");
    }
}

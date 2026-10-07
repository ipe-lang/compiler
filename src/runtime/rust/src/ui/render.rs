//! `Ipe.Ui` → `Html<M>` render kernel.
//!
//! This module is the ONLY place that converts a `Ipe.Ui` `Element<M>` tree to
//! `ipe_runtime::html::Html<M>`.  It is a runtime kernel (not compiled from Ipê)
//! because the render chain touches `any`-returning stdlib fields (`Raw any`,
//! `AttrEvent any`) that cannot be typed soundly in Ipê-over-Rust (spec §1.4).
//!
//! Security note — this file is T1/T3/T5-critical (spec §6):
//! - T1: never call `renderElement` from Ipê; keep it here as a typed Rust fn.
//! - T3: `AttrStyle`, `AttrBgImage`, `AttrAttribute` carry user-controlled strings
//!   entering `style="…"` / HTML-attribute sinks.  The CSS URL sanitiser
//!   (`sanitise_css_url`) gates `url(…)` payloads; HTML values pass through
//!   `html::render_html`'s existing `SafeAttrName` + `sanitise_url_attr` gates.
//! - T5: `AttrBorderWidthEach(t,r,b,l)` uses `saturating_add` throughout.
//!
//! ### Design rationale
//! `Ui.layout` emits an outer 100 vh flex-column wrapper (`VIEWPORT_WRAPPER_CSS`)
//! and, inside it, a root flex column (`ROOT_FILL_CSS`) that fills the wrapper
//! on both axes, so an author `fill` beneath it resolves against a definite box.
//! `Ui.layoutWith` additionally applies `wrapperAttrs` to the outer wrapper and
//! `rootAttrs` to the root column.

use super::super::css_safety::{CssValueOrigin, SafeCssPropertyName, SafeCssValue};
use super::super::html::{Attribute as HtmlAttribute, Html, admit_element};
use super::element::{Attribute, Description, Element, HAlign, Length, Location, Portion, VAlign};

// ── CSS boundary smart constructors ───────────────────────────────────────────
// `SafeCssPropertyName` / `SafeCssValue` moved to the shared `css_safety` module
// (design §Q5: one policy, one place). Imported above so the Ipe.Ui inline-style
// path and the Ipe.Css / styleNode sinks share the identical encoder.

/// Check whether a bare URL string (not yet wrapped in `url(…)`) carries a
/// dangerous scheme.  Used for `AttrBgImage` / `AttrBgGradient` before the
/// `url(…)` wrapper is emitted.
fn is_dangerous_url_scheme(url: &str) -> bool {
    let lower = url.trim_start().to_ascii_lowercase();
    lower.starts_with("javascript:")
        || lower.starts_with("vbscript:")
        || lower.starts_with("data:text/html")
        || lower.starts_with("data:application/")
}

// ── Attribute → (style entries, html attrs) ───────────────────────────────────

/// Collect the parent-independent CSS `key:value` pairs of an attribute list.
///
/// Values that fail the CSS security gate are silently dropped (T3). Size
/// attributes (`width` / `height`) are NOT collected here: their CSS depends
/// on the parent's flex axis, which this flat collector cannot see, so
/// [`size_css`] is their one emitter.
///
/// `pub(crate)` so `ui::helpers::ui_on_pseudo_` can reuse the identical
/// style-collection logic to build a pseudo-class rules-string (mirrors the
/// `../ipe` reference's `onPseudo pc attrs = AttrPseudoRule pc
/// (mediaQueryRulesCss attrs)`, which folds attrs through the SAME collector
/// used for the main `style=""` attribute — one collector, two call sites).
#[allow(clippy::too_many_lines)]
pub(crate) fn build_style_string<M>(attrs: &[Attribute<M>]) -> String {
    // Single shared buffer with a running `;` separator — replaces the former
    // per-declaration `Vec<String>` + `join(";")` (efficiency-audit §6 medium:
    // one String per CSS declaration + a join copy). Byte-identical output:
    // the first declaration is unprefixed and every later one prepends `;`,
    // exactly what `join(";")` produced. CSS security gates
    // (`SafeCssPropertyName`/`SafeCssValue`, dangerous-URL, saturating_add)
    // are untouched.
    use std::fmt::Write as _;
    let mut parts = String::new();
    macro_rules! decl {
        ($($arg:tt)*) => {{
            if !parts.is_empty() {
                parts.push(';');
            }
            let _ = write!(parts, $($arg)*);
        }};
    }

    for attr in attrs {
        match attr {
            // Size is parent-axis dependent: emitted by `size_css` instead.
            Attribute::AttrWidth(_) | Attribute::AttrHeight(_) => {}
            // `AttrAlignX` / `AttrAlignY` are layout-context-dependent: whether
            // an alignment is the CROSS axis (`align-self`) or the MAIN axis
            // (auto-margins) depends on the PARENT's flex direction, which this
            // flat per-attribute collector cannot see. They are emitted by the
            // parent-aware `alignment_css` folded in at `render_node_as` / the
            // `ui_layout` root instead — see A3.
            Attribute::AttrAlignX(_) | Attribute::AttrAlignY(_) => {}
            Attribute::AttrPadding(t, r, b, l) => {
                decl!("padding:{t}px {r}px {b}px {l}px");
            }
            Attribute::AttrSpacing(n) => {
                decl!("gap:{n}px");
            }
            Attribute::AttrStyle(k, v) => {
                // Internal direction markers injected by `ui_row_` / `ui_column_` /
                // `ui_wrapped_row_` in helpers.rs.  They carry layout semantics but
                // must NOT be emitted as literal CSS `__col:true` / `__row:true`.
                // Instead: map to the corresponding Flexbox CSS.
                match k.as_str() {
                    "__col" => {
                        decl!("display:flex");
                        decl!("flex-direction:column");
                    }
                    "__row" => {
                        decl!("display:flex");
                        decl!("flex-direction:row");
                    }
                    "__wrappedrow" => {
                        decl!("display:flex");
                        decl!("flex-direction:row");
                        decl!("flex-wrap:wrap");
                    }
                    "__grid" => {
                        decl!("display:grid");
                    }
                    "__paragraph" => {
                        // A `Ui.paragraph` `<p>`: its element children flow as
                        // inline runs, so the block itself needs no flex/grid —
                        // but an explicit `display:block` keeps it a block box
                        // even when nested inside another inline-block context.
                        decl!("display:block");
                    }
                    "__inline" => {
                        // Injected by `render_paragraph_child` onto a `Ui.el`
                        // child of a paragraph so its styled run flows inline
                        // with the surrounding text instead of breaking to its
                        // own line.
                        decl!("display:inline-block");
                        decl!("vertical-align:baseline");
                    }
                    "__inline_row" => {
                        // A `Ui.row` rendered inside a `Ui.paragraph` context.
                        // `display:inline-flex` keeps the flex container inline
                        // so the row does not force a block-level line break and
                        // the HTML parser does not auto-close the surrounding
                        // `<p>` around it.
                        decl!("display:inline-flex");
                        decl!("flex-direction:row");
                    }
                    "__inline_col" => {
                        // A `Ui.column` rendered inside a `Ui.paragraph` context.
                        // `display:inline-flex` keeps the flex container inline
                        // for the same reason as `__inline_row` above.
                        decl!("display:inline-flex");
                        decl!("flex-direction:column");
                    }
                    _ => {
                        // User-supplied CSS key+value.
                        // `SafeCssPropertyName` gates the key (charset policy);
                        // `SafeCssValue` gates the value (whole-string scan).
                        // Both are the SOLE validation boundary — no re-check
                        // downstream (PARSE, DON'T VALIDATE / T3/T4).
                        //
                        // A9: the value from `Ui.style k v` is a developer
                        // literal, so route it through `parse_reporting` — if the
                        // scan drops it, the developer gets a diagnostic naming
                        // the value + reason instead of a silent no-op. The KEY
                        // stays on the silent `parse` (a dropped key is a charset
                        // issue, covered by the value diagnostic on the same
                        // declaration when both fire).
                        if let (Some(pk), Some(pv)) = (
                            SafeCssPropertyName::parse(k),
                            SafeCssValue::parse_reporting(v, CssValueOrigin::DeveloperLiteral),
                        ) {
                            decl!("{}:{}", pk.as_str(), pv.as_str());
                        }
                        // else: dropped (loud for a developer literal via the
                        // diagnostic above; the security outcome is unchanged).
                    }
                }
            }
            Attribute::AttrFontSize(n) => {
                decl!("font-size:{n}px");
            }
            Attribute::AttrFontColor(c) => {
                decl!("color:{}", c.to_css_rgba());
            }
            Attribute::AttrFontFamily(f) => {
                // Value-as-data gate (UI CSS-escaping hardening): a raw Ipê
                // `String` reaching a CSS sink must pass the shared
                // `SafeCssValue` breakout scan (`;{}@import`, script sinks) —
                // drop on failure, same posture as `AttrStyle` /
                // `AttrBgGradient` below. Legit font stacks (commas, quotes,
                // spaces) pass untouched. See
                // `docs/adr/0003-security-render-and-data-access-invariants.md §2`.
                if let Some(v) = SafeCssValue::parse(f) {
                    decl!("font-family:{}", v.as_str());
                }
            }
            Attribute::AttrFontWeight(w) => {
                decl!("font-weight:{w}");
            }
            Attribute::AttrFontItalic => {
                decl!("font-style:italic");
            }
            Attribute::AttrFontUnderline => {
                decl!("text-decoration:underline");
            }
            Attribute::AttrFontDecoration(d) => {
                if let Some(v) = SafeCssValue::parse(d) {
                    decl!("text-decoration:{}", v.as_str());
                }
            }
            Attribute::AttrFontLetterSpacing(n) => {
                decl!("letter-spacing:{n}px");
            }
            Attribute::AttrFontWordSpacing(n) => {
                decl!("word-spacing:{n}px");
            }
            Attribute::AttrFontAlign(a) => {
                if let Some(v) = SafeCssValue::parse(a) {
                    decl!("text-align:{}", v.as_str());
                }
            }
            Attribute::AttrBgColor(c) => {
                decl!("background-color:{}", c.to_css_rgba());
            }
            Attribute::AttrBgImage(url) => {
                // T3: check the raw URL scheme before wrapping in url().
                // `sanitise_css_value` only fires on `url(` or `expression(` prefixes,
                // so we need the is_dangerous_url_scheme check here on the bare URL.
                if !is_dangerous_url_scheme(url) {
                    // BG-1 (spec §4.3): gate the COMPOSED `url({url})` value
                    // so a `)` closing `url(` early followed by `}`/`;`/
                    // `@import` is rejected by the shared breakout scan.
                    // Known, documented limitation: an inline base64 data
                    // URI (`url(data:image/png;base64,…)`) contains `;` and
                    // is dropped — Background.image takes a path/URL;
                    // data-URI backgrounds are unsupported through Ipe.Ui
                    // (BG-2 quoting is the upgrade if ever needed).
                    let composed = format!("url({url})");
                    // A9: `Background.image` can carry a Model-derived / dev-
                    // patched URL (the appearance hot-swap `LiteralTable` slot),
                    // so it is UNTRUSTED — a dropped one stays SILENT (a
                    // diagnostic keyed on attacker-influenceable input would be a
                    // log-spam / info-leak vector). Same security outcome as
                    // `parse`; the origin only suppresses the developer diagnostic.
                    if let Some(v) =
                        SafeCssValue::parse_reporting(&composed, CssValueOrigin::Untrusted)
                    {
                        decl!("background-image:{}", v.as_str());
                    }
                }
            }
            Attribute::AttrBgGradient(g) => {
                // Gradient CSS value — whole-string scan via SafeCssValue (T3).
                // Replaces the former prefix-only `sanitise_css_value` call,
                // closing the mid-value `expression()` / `url(javascript:…)`
                // bypass. A9: the gradient string is built by the developer's
                // `Background.linearGradient` call, so a dropped one is loud.
                if let Some(sv) = SafeCssValue::parse_reporting(g, CssValueOrigin::DeveloperLiteral)
                {
                    decl!("background-image:{}", sv.as_str());
                }
            }
            Attribute::AttrBorderWidth(n) => {
                decl!("border-width:{n}px");
            }
            Attribute::AttrBorderWidthEach(t, r, b, l) => {
                // T5: use saturating_add to avoid debug-mode overflow panics.
                let _total = (*t)
                    .saturating_add(*r)
                    .saturating_add(*b)
                    .saturating_add(*l);
                decl!("border-width:{t}px {r}px {b}px {l}px");
            }
            Attribute::AttrBorderColor(c) => {
                decl!("border-color:{}", c.to_css_rgba());
            }
            Attribute::AttrBorderRounded(n) => {
                decl!("border-radius:{n}px");
            }
            Attribute::AttrBorderStyle(s) => {
                if let Some(v) = SafeCssValue::parse(s) {
                    decl!("border-style:{}", v.as_str());
                }
            }
            Attribute::AttrBorderShadow(x, y, blur, spread, c) => {
                decl!(
                    "box-shadow:{x}px {y}px {blur}px {spread}px {}",
                    c.to_css_rgba()
                );
            }
            Attribute::AttrBorderInsetShadow(x, y, blur, spread, c) => {
                decl!(
                    "box-shadow:inset {x}px {y}px {blur}px {spread}px {}",
                    c.to_css_rgba()
                );
            }
            Attribute::AttrPointer => {
                decl!("cursor:pointer");
            }
            Attribute::AttrExplain => {
                // A7: the debug overlay is depth- and node-aware (hue by depth, a
                // padding band, a spacing tint, an overflow flag), so it cannot
                // be a context-free per-attribute declaration. It is emitted by
                // `explain_overlay_css` at `render_node_as`, which has the depth
                // and the node's padding / spacing / width. Nothing here.
            }
            Attribute::AttrOverflow(x, y) => {
                // Per-component gating: one bad axis drops alone, the other
                // legit axis still renders.
                if let Some(v) = SafeCssValue::parse(x) {
                    decl!("overflow-x:{}", v.as_str());
                }
                if let Some(v) = SafeCssValue::parse(y) {
                    decl!("overflow-y:{}", v.as_str());
                }
            }
            Attribute::AttrTransition(t, _respect_reduced) => {
                if let Some(v) = SafeCssValue::parse(t) {
                    decl!("transition:{}", v.as_str());
                }
            }
            Attribute::AttrGridTracks(cols, rows) => {
                // Fixed property names; user-supplied values go through SafeCssValue.
                if !cols.is_empty()
                    && let Some(pv) = SafeCssValue::parse(cols)
                {
                    decl!("grid-template-columns:{}", pv.as_str());
                }
                if !rows.is_empty()
                    && let Some(pv) = SafeCssValue::parse(rows)
                {
                    decl!("grid-template-rows:{}", pv.as_str());
                }
            }
            Attribute::AttrAnimation(name, spec, keyframes, _respect) => {
                // Emit animation name + spec; keyframes require a <style> block
                // which this render doesn't inject (no DOM).  The `name` +
                // `spec` provide the `animation:` property; keyframes are
                // dropped here.
                let _ = keyframes; // suppress unused-variable warning
                // Gate the composed `name spec` shorthand as ONE value.
                let shorthand = format!("{name} {spec}");
                if let Some(v) = SafeCssValue::parse(&shorthand) {
                    decl!("animation:{}", v.as_str());
                }
            }
            // Non-style attrs handled in `collect_html_attrs` below.
            Attribute::NoAttribute
            | Attribute::AttrNearby(_, _)
            | Attribute::AttrDescribe(_)
            | Attribute::AttrClass(_)
            | Attribute::AttrEvent(_)
            | Attribute::AttrAttribute(_, _)
            | Attribute::AttrPseudoRule(_, _) => {}
        }
    }

    parts
}

/// Collect HTML attributes (class, arbitrary attrs, event handlers, `nearby`
/// overlays) from a slice of `Attribute<M>`, producing a `Vec<HtmlAttribute<M>>`.
/// The returned vec does NOT include a `style` attribute — the caller prepends
/// `build_style_string` if non-empty.
///
/// Security: `AttrAttribute(k, v)` passes through with the key/value pair as
/// `HtmlAttribute::Attr(k, v)`, where `html::render_html`'s `SafeAttrName` gate
/// will drop dangerous attribute names (on*-events, srcdoc) and
/// `sanitise_url_attr` will drop dangerous URL values.  We do not double-gate
/// here; trust the render sink.
fn collect_html_attrs<M: Clone>(attrs: &[Attribute<M>]) -> Vec<HtmlAttribute<M>> {
    let mut out: Vec<HtmlAttribute<M>> = Vec::new();
    // `AttrPseudoRule` entries (from `Ui.onPseudo` and the `hoverColor` /
    // `focusColor` / `activeColor` / `disabledColor` sub-module helpers that
    // build on it) are collected into ONE `data-ipe-pc-rules` marker attr,
    // wire-format `"<tag>|<css>||<tag2>|<css2>"` — consumed by
    // `ipe_runtime::web::style_inject::build_pc` (called post-`assign_ipe_ids`
    // from the Ipe.Web / Ipe.WebView render pipelines), which expands it into
    // a ipe-id-scoped `<style>` block. Multiple entries with the SAME tag are
    // NOT merged (each keeps its own `tag|css` segment) — matches the `../ipe`
    // reference's `injectPseudoClassStyles` wire contract.
    let mut pseudo_rules: Vec<String> = Vec::new();
    for attr in attrs {
        match attr {
            Attribute::AttrClass(c) => {
                out.push(HtmlAttribute::Attr("class".to_owned(), c.clone()));
            }
            Attribute::AttrAttribute(k, v) => {
                // Pass through — the HTML render sink applies SafeAttrName + URL gates.
                out.push(HtmlAttribute::Attr(k.clone(), v.clone()));
            }
            Attribute::AttrEvent(html_attr) => {
                out.push(html_attr.clone());
            }
            Attribute::AttrDescribe(desc) => {
                // Emit ARIA roles / landmark attributes for semantic elements.
                // `pick_semantic_tag` handles the tag; these emit supplementary
                // aria attributes where the semantic tag alone is insufficient.
                match desc {
                    Description::DescLivePolite => {
                        out.push(HtmlAttribute::Attr(
                            "aria-live".to_owned(),
                            "polite".to_owned(),
                        ));
                    }
                    Description::DescLiveAssertive => {
                        out.push(HtmlAttribute::Attr(
                            "aria-live".to_owned(),
                            "assertive".to_owned(),
                        ));
                    }
                    Description::DescLabel(label) => {
                        out.push(HtmlAttribute::Attr("aria-label".to_owned(), label.clone()));
                    }
                    _ => {}
                }
            }
            Attribute::AttrPseudoRule(pc, css) if !css.is_empty() => {
                pseudo_rules.push(format!("{}|{css}", pc.wire_tag()));
            }
            // Style and nearby handled separately.
            _ => {}
        }
    }
    if !pseudo_rules.is_empty() {
        out.push(HtmlAttribute::Attr(
            "data-ipe-pc-rules".to_owned(),
            pseudo_rules.join("||"),
        ));
    }
    out
}

/// Nearby overlays (`AttrNearby(Location, Element)`) are rendered as absolutely-
/// positioned child elements.  Returns a vec of `Html<M>` overlay nodes.
fn render_nearby_overlays<M: Clone>(attrs: &[Attribute<M>]) -> Vec<Html<M>> {
    let mut overlays: Vec<Html<M>> = Vec::new();
    for attr in attrs {
        if let Attribute::AttrNearby(loc, child_elem) = attr {
            let position_style = match loc {
                Location::Above => "position:absolute;bottom:100%;left:0;right:0",
                Location::Below => "position:absolute;top:100%;left:0;right:0",
                Location::OnLeft => "position:absolute;right:100%;top:0;bottom:0",
                Location::OnRight => "position:absolute;left:100%;top:0;bottom:0",
                Location::InFront => "position:absolute;top:0;left:0;right:0;bottom:0",
                Location::Behind => "position:absolute;top:0;left:0;right:0;bottom:0;z-index:-1",
            };
            let overlay_node = render_element(child_elem.clone());
            overlays.push(Html::HElement(
                "div".into(),
                vec![HtmlAttribute::Attr("style".into(), position_style.into())],
                vec![overlay_node],
            ));
        }
    }
    overlays
}

// ── Description → semantic HTML tag ──────────────────────────────────────────

/// Pick the semantic HTML tag for a layout node based on its `Description`.
/// `NoDescription` defaults to `div`.  `TaggedNode` overrides this with an
/// explicit user-supplied tag (already validated by the Ipê stdlib).
fn tag_for_description(desc: &Description) -> &'static str {
    match desc {
        Description::NoDescription
        | Description::DescLivePolite
        | Description::DescLiveAssertive => "div",
        Description::DescMain => "main",
        Description::DescNavigation => "nav",
        Description::DescContentInfo => "footer",
        Description::DescComplementary => "aside",
        Description::DescHeading(n) => match n {
            1 => "h1",
            2 => "h2",
            3 => "h3",
            4 => "h4",
            5 => "h5",
            _ => "h6",
        },
        Description::DescLabel(_) => "label",
        Description::DescButton => "button",
        Description::DescParagraph => "p",
    }
}

// ── Element → Html (recursive) ───────────────────────────────────────────────

/// Depth-0 entry point. All callers outside this module use this wrapper.
fn render_element<M: Clone>(elem: Element<M>) -> Html<M> {
    render_element_depth(elem, 0)
}

/// Recursively convert a `Ipe.Ui` `Element<M>` to `Html<M>`.
///
/// Security: all attribute values flow through `build_style_string` /
/// `size_css` (which
/// calls `sanitise_css_value`) or `collect_html_attrs` (which passes values to
/// `html::Attribute::Attr` where `render_html` applies `SafeAttrName` +
/// `sanitise_url_attr`).  No value reaches the HTML sink without one of these gates.
///
/// Bounded descent: at `MAX_HTML_DEPTH` the subtree is dropped (empty text
/// node) rather than recursed into — a truncated render is strictly better than
/// overflowing the thread stack. Same ceiling as `html.rs::render_into_ctx` and
/// `html.rs::assign_ipe_ids_depth`.
fn render_element_depth<M: Clone>(elem: Element<M>, depth: usize) -> Html<M> {
    render_element_depth_in(elem, depth, FlexAxis::Block)
}

/// As `render_element_depth`, but told the flex direction its PARENT lays it out
/// along (`parent_axis`). A node uses this to emit its own size CSS
/// (`size_css`) and child-alignment CSS (`alignment_css`), both of which depend
/// on whether a dimension is the parent's main or cross axis.
fn render_element_depth_in<M: Clone>(
    elem: Element<M>,
    depth: usize,
    parent_axis: FlexAxis,
) -> Html<M> {
    if depth >= crate::html::MAX_HTML_DEPTH {
        return Html::HText(String::new());
    }
    // `Element` owns an iterative destructor (bounded teardown of a deep tree),
    // so its fields cannot be moved out by a by-value match. Take each field with
    // `mem::take` / `mem::replace` from a mutable binding instead; the emptied
    // `Element` then drops trivially at end of scope.
    let mut elem = elem;
    match &mut elem {
        Element::Empty => Html::HText(String::new()),
        Element::Text(s) => Html::HText(std::mem::take(s)),
        Element::Raw(html) => std::mem::replace(html, Html::HText(String::new())),
        // Compile-time shape gates (IPE-L0132 / IPE-L0153) prevent `Cells` from
        // reaching a Web or Cli render, so this arm is unreachable through the
        // normal pipeline. If a direct Rust construction routes cells here, drop
        // to empty text rather than abort — a missing subtree beats a panic.
        Element::Cells(_grid) => Html::HText(String::new()),
        Element::Node(desc, attrs, kids) => render_node_as(
            tag_for_description(desc),
            &std::mem::take(attrs),
            std::mem::take(kids),
            depth,
            parent_axis,
        ),
        Element::TaggedNode(tag, _desc, attrs, kids) => render_node_as(
            &std::mem::take(tag),
            &std::mem::take(attrs),
            std::mem::take(kids),
            depth,
            parent_axis,
        ),
    }
}

/// Build a single `HElement` from a tag name, attribute slice, and children,
/// weaving together the `style=""` attribute, class/event HTML attributes, and
/// any `AttrNearby` overlay children.
///
/// The structure is:
///
/// ```html
/// <{tag} style="{css}" {html_attrs}...>
///   {rendered children}
///   {nearby overlays (position:absolute)}
/// </{tag}>
/// ```
/// True when a node carries the `__paragraph` marker (`Ui.paragraph`), meaning
/// its element children must flow inline rather than as block boxes.
fn has_paragraph_marker<M>(attrs: &[Attribute<M>]) -> bool {
    attrs
        .iter()
        .any(|a| matches!(a, Attribute::AttrStyle(k, _) if k == "__paragraph"))
}

/// Render one child of a `Ui.paragraph`.
///
/// All `Element::Node(NoDescription, …)` children must render inline — a block
/// child inside `<p>` causes the HTML parser to auto-close the `<p>` and hoist
/// the block out, breaking the highlight-a-phrase pattern.
///
/// The adaptation depends on whether the child carries a flex-direction marker:
///
/// - Plain `Ui.el` (no `__row`/`__col`): becomes a `<span>` with `__inline`
///   (`display:inline-block`), so its styled run (e.g. `Font.bold`) flows
///   inline with the surrounding text.
///
/// - `Ui.row` (carries `__row`): `__row` is replaced by `__inline_row`
///   (`display:inline-flex;flex-direction:row`). The flex container stays
///   inline, preserving its internal row layout without breaking out of `<p>`.
///
/// - `Ui.column` (carries `__col`): `__col` is replaced by `__inline_col`
///   (`display:inline-flex;flex-direction:column`). Same rationale as row.
///
/// Every other child kind (text, `Ui.link`, `TaggedNode`, raw HTML) renders
/// unchanged via the normal path — they are already inline-compatible.
fn render_paragraph_child<M: Clone>(child: Element<M>, depth: usize) -> Html<M> {
    // `Element` owns an iterative destructor, so its fields cannot be moved out
    // by a by-value match; take them from a mutable binding and let the emptied
    // node drop trivially.
    let mut child = child;
    match &mut child {
        Element::Node(Description::NoDescription, attrs, kids) => {
            let (mut attrs, kids) = (std::mem::take(attrs), std::mem::take(kids));
            // Replace any flex-direction marker with its inline-flex equivalent.
            // A node carries at most one direction marker, always at position 0
            // (inserted by `ui_row_` / `ui_column_`). Mutating in place is safe
            // because `attrs` is owned (moved out of the `Element`).
            let made_inline_flex = attrs.iter_mut().any(|a| {
                if let Attribute::AttrStyle(k, _) = a {
                    match k.as_str() {
                        "__row" => {
                            *k = "__inline_row".to_owned();
                            true
                        }
                        "__col" => {
                            *k = "__inline_col".to_owned();
                            true
                        }
                        _ => false,
                    }
                } else {
                    false
                }
            });
            // Plain `Ui.el` has no flex-direction marker; give it `__inline` so
            // the span flows inline with the surrounding text.
            if !made_inline_flex {
                attrs.insert(
                    0,
                    Attribute::AttrStyle("__inline".to_owned(), "true".to_owned()),
                );
            }
            // A paragraph lays its children out as inline flow, not a flex
            // main/cross axis, so alignment is inert here — `Block` is the neutral
            // parent axis (no auto-margins, no align-self, no flex sizing).
            render_node_as("span", &attrs, kids, depth, FlexAxis::Block)
        }
        _ => render_element_depth(std::mem::replace(&mut child, Element::Empty), depth),
    }
}

/// Prepend `AttrExplain` to an element's attribute list so that the outline
/// propagates depth-first to all descendants.  Only `Node` and `TaggedNode`
/// carry attributes; `Empty`, `Text`, `Raw`, and `Cells` are left unchanged.
fn inject_explain<M: Clone>(mut elem: Element<M>) -> Element<M> {
    // Prepend in place: `Element` owns an iterative destructor, so its attribute
    // list is reached through a mutable borrow rather than moved out and rebuilt.
    match &mut elem {
        Element::Node(_, attrs, _) | Element::TaggedNode(_, _, attrs, _) => {
            attrs.insert(0, Attribute::AttrExplain);
        }
        Element::Empty | Element::Text(_) | Element::Raw(_) | Element::Cells(_) => {}
    }
    elem
}

/// The flex direction a layout node imposes on its own children.
///
/// Decoded from the internal direction marker (`__row` / `__col` /
/// `__wrappedrow`) prepended by `ui_row_` / `ui_column_` / `ui_wrapped_row_`.
/// A node without a marker (a plain `Ui.el`, a paragraph span) is `Block`: it
/// is not a flex container, so its children have no flex main axis.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FlexAxis {
    Row,
    Column,
    Block,
}

/// The dimension a parent's flex main axis runs along.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MainAxis {
    Width,
    Height,
    None,
}

/// Decode which dimension is the main axis of a child laid out by `parent`.
///
/// The one axis decoder shared by every parent-aware emitter (`size_css`,
/// `alignment_css`, `overconstrain_css`).
const fn main_dim(parent: FlexAxis) -> MainAxis {
    match parent {
        FlexAxis::Row => MainAxis::Width,
        FlexAxis::Column => MainAxis::Height,
        FlexAxis::Block => MainAxis::None,
    }
}

/// The size dimension an `AttrWidth` / `AttrHeight` controls.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Dim {
    Width,
    Height,
}

impl Dim {
    /// The CSS property name of this dimension.
    const fn css_name(self) -> &'static str {
        match self {
            Self::Width => "width",
            Self::Height => "height",
        }
    }
}

/// A `fill` length parsed once: its portion and the `minimum` / `maximum` px
/// bounds wrapped around it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct FillSpec {
    /// Flex portion, positive by type.
    portion: Portion,
    /// Largest `minimum` bound around the fill, in px.
    lower: Option<i64>,
    /// Smallest `maximum` bound around the fill, in px.
    upper: Option<i64>,
}

/// Parse a `Length` into its `FillSpec`, or `None` when it is not a `fill`.
///
/// `Min` / `Max` wrappers are unwrapped iteratively (bounded stack on any
/// nesting depth), matching the TUI's `fill_spec`.
fn fill_spec(len: &Length) -> Option<FillSpec> {
    let mut lower: Option<i64> = None;
    let mut upper: Option<i64> = None;
    let mut cur = len;
    loop {
        match cur {
            Length::Fill(portion) => {
                return Some(FillSpec {
                    portion: *portion,
                    lower,
                    upper,
                });
            }
            Length::Min(n, inner) => {
                lower = Some(lower.map_or(*n, |l| l.max(*n)));
                cur = inner;
            }
            Length::Max(n, inner) => {
                upper = Some(upper.map_or(*n, |u| u.min(*n)));
                cur = inner;
            }
            Length::Px(_) | Length::Content | Length::Vh(_) | Length::Vw(_) => return None,
        }
    }
}

/// True when the node's `height` is a `fill` (possibly bounded).
fn has_height_fill<M>(attrs: &[Attribute<M>]) -> bool {
    attrs
        .iter()
        .any(|a| matches!(a, Attribute::AttrHeight(len) if fill_spec(len).is_some()))
}

/// Emit the CSS of one size attribute laid out by a parent with main axis `main`.
///
/// - main-axis `fill`: the dimension, the portion growth, `flex-basis:0`, and
///   a `min-*` floor (the `minimum` bound, else 0) plus any `maximum` cap;
/// - cross-axis `fill` in a row: `align-self:stretch` plus its bounds, never
///   `height:100%` (inert in an auto-height row) nor a flex property;
/// - any other case: the dimension's `Length::css` value only.
fn dim_css(dim: Dim, len: &Length, main: MainAxis) -> String {
    use crate::length::CssUnit;
    use std::fmt::Write as _;
    let name = dim.css_name();
    let Some(fill) = fill_spec(len) else {
        return format!("{name}:{}", len.css());
    };
    let mut out = match (dim, main) {
        (Dim::Width, MainAxis::Width) | (Dim::Height, MainAxis::Height) => {
            let floor = fill
                .lower
                .map_or_else(|| "0".to_owned(), |l| CssUnit::Px.css(l));
            format!(
                "{name}:{};flex-grow:{};flex-basis:0;min-{name}:{floor}",
                len.css(),
                fill.portion.get()
            )
        }
        (Dim::Height, MainAxis::Width) => {
            let mut stretch = "align-self:stretch".to_owned();
            if let Some(l) = fill.lower {
                let _ = write!(stretch, ";min-{name}:{}", CssUnit::Px.css(l));
            }
            stretch
        }
        // `Length::css` already folds the bounds into `max()` / `min()`.
        (Dim::Width, MainAxis::Height | MainAxis::None) | (Dim::Height, MainAxis::None) => {
            return format!("{name}:{}", len.css());
        }
    };
    if let Some(u) = fill.upper {
        let _ = write!(out, ";max-{name}:{}", CssUnit::Px.css(u));
    }
    out
}

/// Emit the size CSS of a node laid out by a `parent` of the given flex axis.
///
/// The one emitter of `width`, `height`, `flex-grow`, `flex-basis` and the
/// `min-*` / `max-*` / `align-self:stretch` a `fill` implies: each size fact
/// lands only on the axis it controls, derived from the parent.
fn size_css<M>(attrs: &[Attribute<M>], parent: FlexAxis) -> String {
    let main = main_dim(parent);
    let mut out = String::new();
    for attr in attrs {
        let (dim, len) = match attr {
            Attribute::AttrWidth(len) => (Dim::Width, len),
            Attribute::AttrHeight(len) => (Dim::Height, len),
            _ => continue,
        };
        if !out.is_empty() {
            out.push(';');
        }
        out.push_str(&dim_css(dim, len, main));
    }
    out
}

/// The full inline style of a node with no flex parent: its size CSS, then
/// every parent-independent declaration.
///
/// `pub(crate)` for the context-free collectors in `ui::helpers`
/// (`ui_on_pseudo_`, `ui_media_query_`), which have no parent to size against:
/// a `fill` there emits the dimension only, never a flex portion.
pub(crate) fn block_style_string<M>(attrs: &[Attribute<M>]) -> String {
    join_style(
        &size_css(attrs, FlexAxis::Block),
        &build_style_string(attrs),
    )
}

fn flex_axis_of<M>(attrs: &[Attribute<M>]) -> FlexAxis {
    for a in attrs {
        if let Attribute::AttrStyle(k, _) = a {
            match k.as_str() {
                "__row" | "__wrappedrow" | "__inline_row" => return FlexAxis::Row,
                "__col" | "__inline_col" => return FlexAxis::Column,
                _ => {}
            }
        }
    }
    FlexAxis::Block
}

/// True when the node carries an explicit `width` (any `Length`, including
/// `fill`). Used by A1: a width-less layout element shrink-wraps by default.
fn has_explicit_width<M>(attrs: &[Attribute<M>]) -> bool {
    attrs.iter().any(|a| matches!(a, Attribute::AttrWidth(_)))
}

/// True when the node carries any nearby-overlay attribute (A2). Such a node
/// must become the positioned host (`position:relative`) so its
/// `position:absolute` overlay anchors to it rather than the page.
fn has_nearby_overlay<M>(attrs: &[Attribute<M>]) -> bool {
    attrs
        .iter()
        .any(|a| matches!(a, Attribute::AttrNearby(_, _)))
}

/// True when the node already declares `position` via a raw `AttrStyle`, so A2
/// must not clobber the author's choice.
fn has_explicit_position<M>(attrs: &[Attribute<M>]) -> bool {
    attrs
        .iter()
        .any(|a| matches!(a, Attribute::AttrStyle(k, _) if k.eq_ignore_ascii_case("position")))
}

/// True when a node carries a paragraph-inline direction marker (`__inline`,
/// `__inline_row`, `__inline_col`) injected by `render_paragraph_child`. Such a
/// box is already inline / inline-flex and content-sizes on its own, so A1's
/// `width:fit-content` is redundant on it.
fn is_inline_marked<M>(attrs: &[Attribute<M>]) -> bool {
    attrs.iter().any(|a| {
        matches!(a, Attribute::AttrStyle(k, _)
            if matches!(k.as_str(), "__inline" | "__inline_row" | "__inline_col"))
    })
}

/// True when a node carries an alignment attribute (either axis).
fn has_any_alignment<M>(attrs: &[Attribute<M>]) -> bool {
    attrs
        .iter()
        .any(|a| matches!(a, Attribute::AttrAlignX(_) | Attribute::AttrAlignY(_)))
}

/// True when a block `el` is promoted to a flex row by its aligned child.
///
/// A single-child block node whose only child carries an alignment becomes
/// `display:flex` (a row), so its child is laid out with parent axis `Row`.
fn is_promoted_el<M>(axis: FlexAxis, kids: &[Element<M>]) -> bool {
    axis == FlexAxis::Block
        && kids.len() == 1
        && matches!(
            kids.first(),
            Some(Element::Node(_, ca, _) | Element::TaggedNode(_, _, ca, _)) if has_any_alignment(ca)
        )
}

/// Compute the node-level layout-augmentation CSS declarations (A1/A2/A3-host)
/// from a node's own attributes + its children. These are properties of the
/// node itself, independent of the parent's direction.
///
/// Produced declarations (already `;`-joined, no leading `;`):
/// - A1 default shrink: a width-less layout element gets `width:fit-content` so
///   `el` / `button` / `link` / `image` content-size instead of stretching.
/// - A2 overlay anchor: a node hosting a nearby overlay gets `position:relative`.
/// - A3 el-container: a single-child `el` whose ONLY child carries an alignment
///   attribute becomes `display:flex` so the child's own `align-self` /
///   auto-margins (emitted by `alignment_css` with this `el` as parent) take
///   effect. A block `<div>` is not a flex container, so without this the child
///   alignment would be inert.
fn node_augmentations<M>(attrs: &[Attribute<M>], axis: FlexAxis, kids: &[Element<M>]) -> String
where
    M: Clone,
{
    use std::fmt::Write as _;
    let mut extra = String::new();
    macro_rules! push {
        ($($arg:tt)*) => {{
            if !extra.is_empty() {
                extra.push(';');
            }
            let _ = write!(extra, $($arg)*);
        }};
    }

    // ── A1: default width = shrink-wrap ──────────────────────────────────────
    // A layout element with no explicit `width` content-sizes. `fit-content`
    // shrink-wraps a block box AND a flex item's cross axis; an explicit
    // `width:` / `fill` declaration (emitted by `size_css`) is a
    // separate later property that overrides this in the cascade. Skipped for a
    // paragraph-inline child (`__inline*` markers): an inline / inline-flex box
    // already content-sizes, so `fit-content` would be a redundant declaration.
    if !has_explicit_width(attrs) && !is_inline_marked(attrs) {
        push!("width:fit-content");
    }

    // ── A2: overlay host anchors its absolutely-positioned overlays ──────────
    if has_nearby_overlay(attrs) && !has_explicit_position(attrs) {
        push!("position:relative");
    }

    // ── A3: an `el` with an aligned child must be a flex container ────────────
    // A `Ui.el` lowers to a block `<div>` (no direction marker). A block box is
    // not a flex container, so a child's `align-self` / auto-margins are inert.
    // If the sole child carries any alignment, make the `el` a flex row so the
    // child (a flex item) can be placed by `alignment_css` (which sees this `el`
    // as a Row parent). `min-height:0` keeps the child from forcing the row's
    // own shrink; `height` unset ⇒ the box still hugs its content.
    if is_promoted_el(axis, kids) {
        push!("display:flex");
    }

    extra
}

/// A3 (parent-aware child alignment): translate a node's own `AttrAlignX` /
/// `AttrAlignY` into CSS given its PARENT's flex direction. Whether an alignment
/// is the CROSS axis (`align-self`) or the MAIN axis (auto-margins) is decided by
/// the parent — the single fact a flat per-attribute collector cannot know.
///
/// - In a ROW parent: `AttrAlignX` is the main axis (auto-margins push the item
///   left/centre/right); `AttrAlignY` is the cross axis (`align-self`).
/// - In a COLUMN parent: `AttrAlignY` is the main axis (auto-margins push
///   top/centre/bottom); `AttrAlignX` is the cross axis (`align-self`).
///
/// An `el` container that has been promoted to `display:flex` (see
/// `is_promoted_el`) is a flex ROW, so its child is rendered with
/// `parent_axis = Row`. A `Block` parent keeps the row spelling (inert there).
///
/// A `fill` height in a ROW parent is a cross-axis stretch (emitted by
/// `size_css`), which overrides `alignY` as in elm-ui, so no `align-self` is
/// emitted for that node's `AttrAlignY`.
///
/// The auto-margin spelling matches elm-ui: a `centerX` item gets
/// `margin-left:auto;margin-right:auto`, an `alignRight` item `margin-left:auto`,
/// so a `[left, centerX, alignRight]` row spreads to the three thirds.
fn alignment_css<M>(attrs: &[Attribute<M>], parent_axis: FlexAxis) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    macro_rules! push {
        ($($arg:tt)*) => {{
            if !out.is_empty() {
                out.push(';');
            }
            let _ = write!(out, $($arg)*);
        }};
    }
    let main = main_dim(parent_axis);
    let row_like = match main {
        MainAxis::Width | MainAxis::None => true,
        MainAxis::Height => false,
    };
    let stretched = main == MainAxis::Width && has_height_fill(attrs);
    for a in attrs {
        match a {
            Attribute::AttrAlignX(h) => {
                if row_like {
                    // Main axis in a row → auto-margins.
                    match h {
                        HAlign::AlignLeft => push!("margin-right:auto"),
                        HAlign::CenterX => push!("margin-left:auto;margin-right:auto"),
                        HAlign::AlignRight => push!("margin-left:auto"),
                    }
                } else {
                    // Cross axis in a column → align-self.
                    let v = match h {
                        HAlign::AlignLeft => "flex-start",
                        HAlign::CenterX => "center",
                        HAlign::AlignRight => "flex-end",
                    };
                    push!("align-self:{v}");
                }
            }
            Attribute::AttrAlignY(v) if !stretched => {
                if row_like {
                    // Cross axis in a row → align-self.
                    let css = match v {
                        VAlign::AlignTop => "flex-start",
                        VAlign::CenterY => "center",
                        VAlign::AlignBottom => "flex-end",
                    };
                    push!("align-self:{css}");
                } else {
                    // Main axis in a column → auto-margins.
                    match v {
                        VAlign::AlignTop => push!("margin-bottom:auto"),
                        VAlign::CenterY => push!("margin-top:auto;margin-bottom:auto"),
                        VAlign::AlignBottom => push!("margin-top:auto"),
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// A8 (over-constrained rows honour width): a ROW child with an explicit fixed
/// px/vw width must NOT be compressed to fit an over-full row. `flex-shrink:0`
/// pins the declared width and lets the row overflow instead — matching elm-ui,
/// which keeps a fixed-width row child at its declared size. Scoped to a Row
/// parent (width = main axis): in a column the width is the cross axis, so
/// shrinking never compresses it and `flex-shrink:0` would wrongly pin
/// deeply-nested content that elm-ui lets reflow. `fill` has its own grow/basis
/// model; `min`/`max`/`content` keep the default shrink so an intrinsic bound
/// can still give.
fn overconstrain_css<M>(attrs: &[Attribute<M>], parent_axis: FlexAxis) -> &'static str {
    match main_dim(parent_axis) {
        MainAxis::Width => {}
        MainAxis::Height | MainAxis::None => return "",
    }
    let fixed_width = attrs
        .iter()
        .any(|a| matches!(a, Attribute::AttrWidth(Length::Px(_) | Length::Vw(_))));
    if fixed_width { "flex-shrink:0" } else { "" }
}

/// The largest uniform padding this node declares, in px (0 when none). Used by
/// A7 to size the translucent padding band.
fn max_padding<M>(attrs: &[Attribute<M>]) -> i64 {
    attrs
        .iter()
        .filter_map(|a| match a {
            Attribute::AttrPadding(t, r, b, l) => Some((*t).max(*r).max(*b).max(*l)),
            _ => None,
        })
        .max()
        .unwrap_or(0)
}

/// The spacing (flex `gap`) this node declares, in px (0 when none).
fn spacing_of<M>(attrs: &[Attribute<M>]) -> i64 {
    attrs
        .iter()
        .find_map(|a| match a {
            Attribute::AttrSpacing(n) => Some(*n),
            _ => None,
        })
        .unwrap_or(0)
}

/// True when this node carries a `background-color` / `background-image` so A7's
/// spacing tint must not paint over it.
fn has_background<M>(attrs: &[Attribute<M>]) -> bool {
    attrs.iter().any(|a| {
        matches!(
            a,
            Attribute::AttrBgColor(_) | Attribute::AttrBgImage(_) | Attribute::AttrBgGradient(_)
        )
    })
}

/// A short type tag for the verbose `Debug.explain` annotation.
fn explain_type_tag(axis: FlexAxis, tag: &str) -> &'static str {
    match tag {
        "button" => "button",
        "a" => "link",
        "img" => "image",
        "p" => "paragraph",
        _ => match axis {
            FlexAxis::Row => "row",
            FlexAxis::Column => "column",
            FlexAxis::Block => "el",
        },
    }
}

/// A7 (verbose): whether the opt-in verbose annotation is enabled. Read from the
/// `IPE_EXPLAIN_VERBOSE` environment variable (`1`/`true`/`on`, case-insensitive)
/// at render time — a dev-only, off-by-default switch that needs no ADT change.
fn explain_verbose_enabled() -> bool {
    super::super::system::read_env_var("IPE_EXPLAIN_VERBOSE")
        .ok()
        .is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "on"))
}

/// A7: the sophisticated `Debug.explain` dev overlay for one node, given its
/// depth, its own attributes, its flex axis, and whether it is over-constrained
/// (a fixed-width child of a row). Layout-neutral (only `outline` /
/// `box-shadow` / a tint on a bg-less node), so it never shifts the boxes it
/// annotates.
///
/// Signals, past the former uniform solid-blue outline:
/// - a DEPTH-hue-shifted outline (root and each nesting level a distinct hue),
///   solid on the explained root, so the box tree reads as a stack of frames;
/// - a translucent PADDING band (an inset ring sized to the node's padding);
/// - a TINTED spacing gap (a faint background on a spaced, bg-less container so
///   the flex gaps between its children become visible);
/// - a RED outer edge on a node flagged as over-constrained (a fixed-width row
///   child that A8 pins with `flex-shrink:0`, i.e. one that can overflow).
fn explain_overlay_css<M>(
    attrs: &[Attribute<M>],
    depth: usize,
    axis: FlexAxis,
    overflowing: bool,
) -> String {
    use std::fmt::Write as _;
    let mut css = String::new();
    macro_rules! push {
        ($($arg:tt)*) => {{
            if !css.is_empty() { css.push(';'); }
            let _ = write!(css, $($arg)*);
        }};
    }

    // Depth-hue outline: rotate the hue by a large coprime step per nesting
    // level so adjacent frames are clearly distinct; the explained root
    // (depth 0) is a saturated solid, descendants keep the same width but a
    // shifted hue. An `overflowing` node overrides the hue with a red edge.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let hue = ((depth as i64).wrapping_mul(47)).rem_euclid(360);
    if overflowing {
        push!("outline:2px solid rgba(220,20,20,0.9)");
    } else {
        push!("outline:2px solid hsl({hue},80%,45%)");
    }
    // A small per-depth offset keeps a child's outline from sitting exactly on
    // its parent's, so nesting stays legible.
    push!("outline-offset:{}px", 1 + (depth % 3));

    // Padding band: an inset ring the thickness of the node's padding, so the
    // content box vs the padding box is visible.
    let pad = max_padding(attrs);
    if pad > 0 {
        push!("box-shadow:inset 0 0 0 {pad}px rgba(255,140,0,0.18)");
    }

    // Spacing tint: a faint fill behind a spaced container (only when it has no
    // background of its own) so the flex gaps between children show through.
    if axis != FlexAxis::Block && spacing_of(attrs) > 0 && !has_background(attrs) {
        push!("background-color:rgba(0,140,255,0.08)");
    }

    css
}

/// A6: the native landmark tag for a `Description` carried by an `AttrDescribe`,
/// when one exists. Returns `None` for descriptions with no landmark tag
/// (labels, live regions, headings-are-handled-elsewhere) so the caller can fall
/// back to a `role="…"` attribute instead.
fn landmark_tag_for(desc: &Description) -> Option<&'static str> {
    match desc {
        Description::DescMain => Some("main"),
        Description::DescNavigation => Some("nav"),
        Description::DescContentInfo => Some("footer"),
        Description::DescComplementary => Some("aside"),
        Description::DescParagraph => Some("p"),
        Description::DescHeading(n) => Some(match n {
            1 => "h1",
            2 => "h2",
            3 => "h3",
            4 => "h4",
            5 => "h5",
            _ => "h6",
        }),
        _ => None,
    }
}

/// A6: the ARIA landmark role for a `Description` with no native tag equivalent
/// available in the current retag (used as the `role="…"` fallback).
fn landmark_role_for(desc: &Description) -> Option<&'static str> {
    match desc {
        Description::DescMain => Some("main"),
        Description::DescNavigation => Some("navigation"),
        Description::DescContentInfo => Some("contentinfo"),
        Description::DescComplementary => Some("complementary"),
        _ => None,
    }
}

fn render_node_as<M: Clone>(
    tag: &str,
    attrs: &[Attribute<M>],
    kids: Vec<Element<M>>,
    depth: usize,
    parent_axis: FlexAxis,
) -> Html<M> {
    // ── A6: `describe descMain`/`descNavigation`/… applies a landmark ────────
    // A landmark `AttrDescribe` on a plain `div` retags it to the semantic
    // element (`<main>`/`<nav>`/`<footer>`/`<aside>`/`<hN>`). A non-`div` tag
    // (`button`/`a`/`img`, or an already-semantic tag from the Node's own
    // Description) is never overridden — instead a `role="…"` attribute is
    // emitted so the landmark is still announced. `descLabel` → `aria-label`
    // continues to flow through `collect_html_attrs` untouched.
    let landmark = attrs.iter().find_map(|a| match a {
        Attribute::AttrDescribe(d) if landmark_tag_for(d).is_some() => Some(d.clone()),
        _ => None,
    });
    let (tag_owned, role_attr): (String, Option<&'static str>) = match &landmark {
        Some(desc) if tag == "div" => (landmark_tag_for(desc).unwrap_or("div").to_owned(), None),
        Some(desc) => (tag.to_owned(), landmark_role_for(desc)),
        None => (tag.to_owned(), None),
    };
    let tag: &str = &tag_owned;

    // Size first, so an author's raw `AttrStyle` for the same property wins.
    let mut style_str = join_style(&size_css(attrs, parent_axis), &build_style_string(attrs));
    let mut html_attrs = collect_html_attrs(attrs);
    if let Some(role) = role_attr {
        html_attrs.push(HtmlAttribute::Attr("role".to_owned(), role.to_owned()));
    }

    // ── elm-parity layout augmentations (A1/A2/A3/A8) ────────────────────────
    // Node-level (A1 shrink / A2 overlay-host / A3 el-container) plus this
    // node's OWN alignment relative to its parent's direction (A3 child align).
    let axis = flex_axis_of(attrs);
    let augment = node_augmentations(attrs, axis, &kids);
    let align = alignment_css(attrs, parent_axis);
    let overconstrain_flag = !overconstrain_css(attrs, parent_axis).is_empty();
    let overconstrain = if overconstrain_flag {
        "flex-shrink:0".to_owned()
    } else {
        String::new()
    };

    // `Debug.explain` propagates to every descendant: inject `AttrExplain`
    // into the direct children so they in turn inject it into their own
    // children (transitively), without touching the element data itself.
    let explain_active = attrs.iter().any(|a| matches!(a, Attribute::AttrExplain));
    // A7: the depth-/node-aware debug overlay for the explained subtree. An
    // over-constrained (fixed-width row child) node gets the red overflow edge.
    let explain = if explain_active {
        explain_overlay_css(attrs, depth, axis, overconstrain_flag)
    } else {
        String::new()
    };

    for chunk in [augment, align, overconstrain, explain] {
        if !chunk.is_empty() {
            if style_str.is_empty() {
                style_str = chunk;
            } else {
                style_str.push(';');
                style_str.push_str(&chunk);
            }
        }
    }

    if !style_str.is_empty() {
        // Prepend — style first so tests can pattern-match on it predictably.
        html_attrs.insert(0, HtmlAttribute::Attr("style".to_owned(), style_str));
    }

    // A7 (verbose): opt-in via `IPE_EXPLAIN_VERBOSE=1` — annotate each explained
    // box with a `title="type · w · pad"` tooltip. Dev-only and off by default,
    // so a normal explain render carries no annotation overhead.
    if explain_active && explain_verbose_enabled() {
        let w = attrs.iter().find_map(|a| match a {
            Attribute::AttrWidth(l) => Some(l.css()),
            _ => None,
        });
        let w = w.unwrap_or_else(|| "shrink".to_owned());
        let title = format!(
            "{} · w {} · pad {}",
            explain_type_tag(axis, tag),
            w,
            max_padding(attrs)
        );
        html_attrs.push(HtmlAttribute::Attr("title".to_owned(), title));
    }

    // A `Ui.paragraph` node's element children must flow inline: a bare
    // `Ui.el` lowers to `Element::Node(NoDescription, …)` (a block `<div>`),
    // which both breaks onto its own line and — as a `<div>` inside a `<p>` —
    // is invalid HTML5 that a browser auto-closes the `<p>` around. Inside a
    // paragraph, render each such child as an inline `<span>`.
    let inside_paragraph = has_paragraph_marker(attrs);

    // The flex direction THIS node imposes on its children is its own `axis`,
    // except that an aligned-child-promoted `el` (single aligned child ⇒ `display:flex`,
    // default row) lays its child out as a `Row`.
    let child_axis = if is_promoted_el(axis, &kids) {
        FlexAxis::Row
    } else {
        axis
    };
    // Rendered children in source order, each one level deeper.
    let child_depth = depth.saturating_add(1);
    let mut html_kids: Vec<Html<M>> = kids
        .into_iter()
        .map(|k| {
            // Propagate explain to children by injecting the attr.
            let k = if explain_active { inject_explain(k) } else { k };
            if inside_paragraph {
                render_paragraph_child(k, child_depth)
            } else {
                render_element_depth_in(k, child_depth, child_axis)
            }
        })
        .collect();

    // Nearby overlays appended after the regular children (they are absolutely
    // positioned, so their DOM order is irrelevant for layout).
    html_kids.extend(render_nearby_overlays(attrs));

    // SECURITY: the shared tag gate on the lowered children, so an element
    // that reached the tree without `ui_tagged_node_` still cannot render a
    // raw-text or executable body.
    if admit_element(tag, &html_kids).is_err() {
        return Html::HText(String::new());
    }
    Html::HElement(tag.to_owned(), html_attrs, html_kids)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Style of the outer page wrapper: a full-viewport flex column.
const VIEWPORT_WRAPPER_CSS: &str =
    "display:flex;flex-direction:column;height:100vh;width:100%;overflow:hidden";

/// Base style of the root div between the wrapper and the author's element.
///
/// It fills the wrapper on both axes (`flex:1 1 0` in the wrapper column,
/// `min-*:0` so it never overflows it), so an author `fill` beneath it
/// resolves against a definite box. `overflow:auto` scrolls an app taller than
/// the viewport instead of clipping it.
const ROOT_FILL_CSS: &str =
    "display:flex;flex-direction:column;flex:1 1 0;min-height:0;min-width:0;overflow:auto";

/// Join two `;`-separated declaration lists, either of which may be empty.
///
/// `extra` comes last, so its declarations win the cascade.
fn join_style(base: &str, extra: &str) -> String {
    match (base.is_empty(), extra.is_empty()) {
        (_, true) => base.to_owned(),
        (true, false) => extra.to_owned(),
        (false, false) => format!("{base};{extra}"),
    }
}

/// The author style of a runtime div laid out by a flex column parent.
fn column_child_style<M>(attrs: &[Attribute<M>]) -> String {
    join_style(
        &size_css(attrs, FlexAxis::Column),
        &build_style_string(attrs),
    )
}

/// Build the viewport wrapper and the root div around the author's element.
///
/// Both runtime-inserted divs carry a definite size on both axes, so the
/// author's root sits inside an unbroken size chain.
fn layout_shell<M: Clone>(
    wrapper_attrs: &[Attribute<M>],
    root_attrs: &[Attribute<M>],
    elem: Element<M>,
) -> Html<M> {
    // The wrapper is the root div's column parent.
    let root_style = join_style(ROOT_FILL_CSS, &column_child_style(root_attrs));
    let mut root_html_attrs = collect_html_attrs(root_attrs);
    root_html_attrs.insert(0, HtmlAttribute::Attr("style".to_owned(), root_style));
    // The root div is a flex column, so the author's element is its column child.
    let mut root_kids: Vec<Html<M>> = vec![render_element_depth_in(elem, 0, FlexAxis::Column)];
    root_kids.extend(render_nearby_overlays(root_attrs));
    let root_div = Html::HElement("div".to_owned(), root_html_attrs, root_kids);

    // `#ipe-root` (`web_page_core::BASE_CSS`) is the wrapper's column parent.
    let wrapper_style = join_style(VIEWPORT_WRAPPER_CSS, &column_child_style(wrapper_attrs));
    let mut wrapper_html_attrs = collect_html_attrs(wrapper_attrs);
    wrapper_html_attrs.insert(0, HtmlAttribute::Attr("style".to_owned(), wrapper_style));
    let mut wrapper_kids: Vec<Html<M>> = vec![root_div];
    wrapper_kids.extend(render_nearby_overlays(wrapper_attrs));
    Html::HElement("div".to_owned(), wrapper_html_attrs, wrapper_kids)
}

/// `Ui.layout : List (Attribute msg) -> Element msg -> Html msg`
///
/// Wraps the element in a full-viewport flex-column page wrapper, then renders
/// the root element with the given root attributes applied.
#[must_use]
pub fn ui_layout<M: Clone>(attrs: Vec<Attribute<M>>, elem: Element<M>) -> Html<M> {
    layout_shell(&[], &attrs, elem)
}

/// `Ui.layoutWith : { wrapperAttrs : List (Attribute msg), rootAttrs : List
/// (Attribute msg) } -> Element msg -> Html msg`
///
/// Applies `wrapper_attrs` to the outer viewport div and `root_attrs` to the
/// inner root element.
///
/// Called by the emitted code as
/// `ipe_runtime::ui::render::ui_layout_with_vecs::<M>(wrapper, root, elem)`.
/// The two `Vec<Attribute<M>>` arguments are extracted at the **emit site**
/// (field-extraction on the IR `Expr::Record` literal), so the cfg record struct
/// never needs to be materialised — closing IPE-I0001.
///
/// # Design note (MAKE INVALID STATES UNREPRESENTABLE)
///
/// There is deliberately no `ui_layout_with<M: Clone, C>(_cfg: C, elem)` shape:
/// a fn accepting any `C` and silently dropping it would produce wrong HTML
/// (exit-0-cargo-ok-but-wrong-output). The cfg's `wrapper_attrs`/`root_attrs`
/// are extracted at the emit site and passed here explicitly.
#[must_use]
pub fn ui_layout_with_vecs<M: Clone>(
    wrapper_attrs: Vec<Attribute<M>>,
    root_attrs: Vec<Attribute<M>>,
    elem: Element<M>,
) -> Html<M> {
    layout_shell(&wrapper_attrs, &root_attrs, elem)
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::color::Color;
    use crate::html::render_html;

    #[derive(Clone, Debug, PartialEq)]
    enum TestMsg {
        Click,
    }

    #[test]
    fn layout_empty_attrs_text_elem() {
        let elem: Element<TestMsg> = Element::Text("Hello".to_owned());
        let html = ui_layout(vec![], elem);
        let s = render_html(&html);
        assert!(
            s.contains("Hello"),
            "rendered output must contain text: {s}"
        );
        // Must be wrapped in the viewport div.
        assert!(
            s.contains("height:100vh"),
            "must contain viewport wrapper: {s}"
        );
    }

    #[test]
    fn layout_with_padding_attr() {
        let attrs = vec![Attribute::AttrPadding(8, 16, 8, 16)];
        let elem: Element<TestMsg> = Element::Text("body".to_owned());
        let html = ui_layout(attrs, elem);
        let s = render_html(&html);
        assert!(
            s.contains("padding:8px 16px 8px 16px"),
            "padding missing: {s}"
        );
    }

    #[test]
    fn layout_dangerous_style_attr_is_dropped() {
        let attrs = vec![Attribute::AttrStyle(
            "background".to_owned(),
            "expression(alert(1))".to_owned(),
        )];
        let elem: Element<TestMsg> = Element::Empty;
        let html = ui_layout(attrs, elem);
        let s = render_html(&html);
        assert!(
            !s.contains("expression("),
            "dangerous CSS expression must be dropped: {s}"
        );
    }

    #[test]
    fn layout_bg_image_javascript_url_dropped() {
        let attrs = vec![Attribute::AttrBgImage("javascript:alert(1)".to_owned())];
        let elem: Element<TestMsg> = Element::Empty;
        let html = ui_layout(attrs, elem);
        let s = render_html(&html);
        assert!(
            !s.contains("javascript:"),
            "javascript: in background-image must be dropped: {s}"
        );
    }

    #[test]
    fn border_width_each_saturating_add() {
        // Large values must not panic in debug mode — saturating_add is required.
        let attrs = vec![Attribute::AttrBorderWidthEach(
            i64::MAX,
            i64::MAX,
            i64::MAX,
            i64::MAX,
        )];
        let elem: Element<TestMsg> = Element::Empty;
        let html = ui_layout(attrs, elem);
        let s = render_html(&html);
        // The border-width property should still be present.
        assert!(s.contains("border-width:"), "border-width missing: {s}");
    }

    #[test]
    fn border_shadow_renders_box_shadow() {
        // `Border.shadow { offsetX = 0, offsetY = 1, blur = 2, spread = 0,
        //   color = Ui.rgb 0 0 0 }` must render the CSS box-shadow shape,
        // routing the colour through the same `Color::css` renderer as
        // `Border.color`. Exercises the `ui_border_shadow_` helper end to end.
        let attrs = vec![super::super::helpers::ui_border_shadow_(
            0,
            1,
            2,
            0,
            Color::rgba(0, 0, 0, 1.0),
        )];
        let elem: Element<TestMsg> = Element::Empty;
        let html = ui_layout(attrs, elem);
        let s = render_html(&html);
        assert!(
            s.contains("box-shadow:0px 1px 2px 0px rgba(0,0,0,1)"),
            "box-shadow missing/malformed: {s}"
        );
    }

    #[test]
    fn border_glow_renders_box_shadow() {
        // `Border.glow 4 (Ui.rgb 0 0 0)` is a convenience box-shadow with `(0, 0)`
        // offset and `0` spread — only blur + colour vary. It must render the CSS
        // `box-shadow: 0px 0px <blur>px 0px <colour>` shape via the generic
        // `AttrStyle` boundary, routing the colour through the same conversion as
        // `Border.color`. Exercises the `ui_border_glow_` helper end to end.
        let attrs = vec![super::super::helpers::ui_border_glow_(
            4,
            Color::rgba(0, 0, 0, 1.0),
        )];
        let elem: Element<TestMsg> = Element::Empty;
        let html = ui_layout(attrs, elem);
        let s = render_html(&html);
        assert!(
            s.contains("box-shadow:0px 0px 4px 0px rgba(0,0,0,1)"),
            "box-shadow (glow) missing/malformed: {s}"
        );
    }

    #[test]
    fn border_inner_shadow_renders_inset_box_shadow() {
        // `Border.innerShadow { offsetX = 0, offsetY = 1, blur = 2, spread = 0,
        //   color = Ui.rgb 0 0 0 }` must render the INSET CSS box-shadow shape,
        // routing the colour through the same `Color::css` renderer as
        // `Border.color`. Exercises the `ui_border_inner_shadow_` helper end to
        // end — identical to `Border.shadow` but prefixed with `inset`.
        let attrs = vec![super::super::helpers::ui_border_inner_shadow_(
            0,
            1,
            2,
            0,
            Color::rgba(0, 0, 0, 1.0),
        )];
        let elem: Element<TestMsg> = Element::Empty;
        let html = ui_layout(attrs, elem);
        let s = render_html(&html);
        assert!(
            s.contains("box-shadow:inset 0px 1px 2px 0px rgba(0,0,0,1)"),
            "inset box-shadow missing/malformed: {s}"
        );
    }

    #[test]
    fn nearby_overlay_renders() {
        let overlay: Element<TestMsg> = Element::Text("tooltip".to_owned());
        let attrs = vec![Attribute::AttrNearby(Location::Above, overlay)];
        let elem: Element<TestMsg> = Element::Text("base".to_owned());
        let html = ui_layout(attrs, elem);
        let s = render_html(&html);
        assert!(s.contains("tooltip"), "nearby overlay must render: {s}");
        assert!(
            s.contains("position:absolute"),
            "nearby must use absolute positioning: {s}"
        );
    }

    // ── elm-parity render layer (A1/A2/A3/A6/A7/A8) ──────────────────────────

    /// A1: a width-less `Ui.el` content-sizes (`width:fit-content`); an explicit
    /// width overrides (no `fit-content`).
    #[test]
    fn a1_widthless_el_shrink_wraps_but_explicit_width_overrides() {
        use crate::ui::helpers::{ui_el_, ui_width_};

        let shrink: Element<TestMsg> = ui_el_(vec![], Element::Text("x".to_owned()));
        let s = render_html(&render_element(shrink));
        assert!(
            s.contains("width:fit-content"),
            "width-less el must shrink-wrap: {s}"
        );

        let fixed: Element<TestMsg> = ui_el_(
            vec![ui_width_(Length::Px(200))],
            Element::Text("x".to_owned()),
        );
        let s = render_html(&render_element(fixed));
        assert!(s.contains("width:200px"), "explicit width must render: {s}");
        assert!(
            !s.contains("fit-content"),
            "an explicit width must suppress the shrink default: {s}"
        );
    }

    /// A2: an overlay-hosting node emits `position:relative` so the overlay's
    /// `position:absolute` anchors to it.
    #[test]
    fn a2_overlay_host_is_positioned_relative() {
        use crate::ui::helpers::ui_el_;

        let overlay: Element<TestMsg> = Element::Text("tip".to_owned());
        let host: Element<TestMsg> = ui_el_(
            vec![Attribute::AttrNearby(Location::InFront, overlay)],
            Element::Text("base".to_owned()),
        );
        let s = render_html(&render_element(host));
        assert!(
            s.contains("position:relative"),
            "overlay host must anchor via position:relative: {s}"
        );
        assert!(
            s.contains("position:absolute"),
            "overlay itself must be absolute: {s}"
        );
    }

    /// A3: in a ROW, `centerX` on a child is the MAIN axis → auto-margins;
    /// `alignRight` → `margin-left:auto`; a bare child gets neither. So a
    /// `[left, centerX, alignRight]` row spreads to thirds.
    #[test]
    fn a3_row_main_axis_alignment_uses_auto_margins() {
        use crate::ui::helpers::{ui_align_right_, ui_center_x_, ui_el_, ui_row_};

        let row: Element<TestMsg> = ui_row_(
            vec![],
            vec![
                ui_el_(vec![], Element::Text("left".to_owned())),
                ui_el_(vec![ui_center_x_()], Element::Text("mid".to_owned())),
                ui_el_(vec![ui_align_right_()], Element::Text("right".to_owned())),
            ],
        );
        let s = render_html(&render_element(row));
        assert!(
            s.contains("margin-left:auto;margin-right:auto"),
            "centerX in a row must be main-axis auto-margins: {s}"
        );
        assert!(
            s.matches("margin-left:auto").count() >= 2,
            "alignRight must also push via margin-left:auto: {s}"
        );
        assert!(
            !s.contains("align-self"),
            "a row's X-alignment is the main axis, never align-self: {s}"
        );
    }

    /// A3: in a COLUMN, `centerY` on a child is the MAIN axis → auto-margins;
    /// `centerX` is the CROSS axis → `align-self:center`.
    #[test]
    fn a3_column_axes_split_main_margins_from_cross_align_self() {
        use crate::ui::helpers::{ui_center_x_, ui_center_y_, ui_column_, ui_el_};

        let col: Element<TestMsg> = ui_column_(
            vec![],
            vec![ui_el_(
                vec![ui_center_x_(), ui_center_y_()],
                Element::Text("c".to_owned()),
            )],
        );
        let s = render_html(&render_element(col));
        assert!(
            s.contains("align-self:center"),
            "centerX is the cross axis of a column → align-self: {s}"
        );
        assert!(
            s.contains("margin-top:auto;margin-bottom:auto"),
            "centerY is the main axis of a column → auto-margins: {s}"
        );
    }

    /// A3: a single-child `el` whose child is aligned becomes a flex container so
    /// the child's alignment takes effect.
    #[test]
    fn a3_el_with_aligned_child_becomes_flex_container() {
        use crate::ui::helpers::{ui_align_right_, ui_el_};

        let outer: Element<TestMsg> = ui_el_(
            vec![],
            ui_el_(vec![ui_align_right_()], Element::Text("r".to_owned())),
        );
        let s = render_html(&render_element(outer));
        assert!(
            s.contains("display:flex"),
            "an el with an aligned child must be a flex container: {s}"
        );
    }

    /// A6: `describe descMain` on a plain `el` retags the `<div>` to `<main>`;
    /// `descNavigation` → `<nav>`; `descLabel` keeps `aria-label`.
    #[test]
    fn a6_describe_landmark_retags_div_and_keeps_label() {
        use crate::ui::helpers::{ui_describe_, ui_el_};

        let main_el: Element<TestMsg> = ui_el_(
            vec![ui_describe_(Description::DescMain)],
            Element::Text("m".to_owned()),
        );
        let s = render_html(&render_element(main_el));
        assert!(s.starts_with("<main"), "descMain must retag to <main>: {s}");

        let nav_el: Element<TestMsg> = ui_el_(
            vec![ui_describe_(Description::DescNavigation)],
            Element::Text("n".to_owned()),
        );
        let s = render_html(&render_element(nav_el));
        assert!(
            s.starts_with("<nav"),
            "descNavigation must retag to <nav>: {s}"
        );

        let labelled: Element<TestMsg> = ui_el_(
            vec![ui_describe_(Description::DescLabel("hello".to_owned()))],
            Element::Text("l".to_owned()),
        );
        let s = render_html(&render_element(labelled));
        assert!(
            s.contains("aria-label=\"hello\""),
            "descLabel must keep aria-label: {s}"
        );
    }

    /// A6: a landmark describe on a NON-div tag (a `button`) is not retagged;
    /// a `role=` attribute is emitted instead.
    #[test]
    fn a6_describe_landmark_on_non_div_emits_role() {
        // A `TaggedNode("button", …)` carrying descNavigation keeps <button>
        // and gains role="navigation".
        let btn: Element<TestMsg> = Element::TaggedNode(
            "button".to_owned(),
            Description::NoDescription,
            vec![Attribute::AttrDescribe(Description::DescNavigation)],
            vec![Element::Text("b".to_owned())],
        );
        let s = render_html(&render_element(btn));
        assert!(
            s.starts_with("<button"),
            "button tag must be preserved: {s}"
        );
        assert!(
            s.contains("role=\"navigation\""),
            "a landmark on a non-div must emit role=: {s}"
        );
    }

    /// A8: a fixed-px-width child of a ROW emits `flex-shrink:0` (honours the
    /// width, overflows); the same width in a COLUMN (cross axis) does not.
    #[test]
    fn a8_fixed_width_row_child_pins_but_column_child_does_not() {
        use crate::ui::helpers::{ui_column_, ui_el_, ui_row_, ui_width_};

        let row: Element<TestMsg> = ui_row_(
            vec![],
            vec![ui_el_(
                vec![ui_width_(Length::Px(150))],
                Element::Text("a".to_owned()),
            )],
        );
        let s = render_html(&render_element(row));
        assert!(
            s.contains("flex-shrink:0"),
            "a fixed-width row child must not shrink: {s}"
        );

        let col: Element<TestMsg> = ui_column_(
            vec![],
            vec![ui_el_(
                vec![ui_width_(Length::Px(150))],
                Element::Text("a".to_owned()),
            )],
        );
        let s = render_html(&render_element(col));
        assert!(
            !s.contains("flex-shrink:0"),
            "a fixed-width column child (cross axis) must NOT be pinned: {s}"
        );
    }

    /// A7: `Debug.explain` emits the sophisticated overlay — a depth-hued
    /// outline, a padding band, and a spacing tint on a bg-less container — not
    /// the former uniform solid blue.
    #[test]
    fn a7_explain_overlay_is_depth_hued_with_padding_and_spacing_bands() {
        use crate::ui::helpers::{ui_column_, ui_el_, ui_padding_, ui_spacing_};

        let tree: Element<TestMsg> = ui_column_(
            vec![Attribute::AttrExplain, ui_spacing_(10), ui_padding_(20)],
            vec![ui_el_(
                vec![ui_padding_(8)],
                Element::Text("one".to_owned()),
            )],
        );
        let s = render_html(&render_element(tree));
        assert!(
            s.contains("outline:2px solid hsl("),
            "explain must use a depth-hued outline, not solid blue: {s}"
        );
        assert!(
            !s.contains("rgba(0,100,255,0.5)"),
            "the old uniform blue outline must be gone: {s}"
        );
        assert!(
            s.contains("box-shadow:inset 0 0 0 20px"),
            "explain must draw a padding band sized to the padding: {s}"
        );
        assert!(
            s.contains("background-color:rgba(0,140,255,0.08)"),
            "a spaced bg-less container must get the gap tint: {s}"
        );
        // Depth propagates to the child, which gets its own overlay + band.
        assert!(
            s.contains("box-shadow:inset 0 0 0 8px"),
            "the nested el must carry its own padding band: {s}"
        );
    }

    /// A7 (overflow edge): an over-constrained fixed-width row child under
    /// explain gets the red overflow outline instead of the depth hue.
    #[test]
    fn a7_explain_flags_overconstrained_child_in_red() {
        use crate::ui::helpers::{ui_el_, ui_row_, ui_width_};

        let row: Element<TestMsg> = ui_row_(
            vec![Attribute::AttrExplain],
            vec![ui_el_(
                vec![ui_width_(Length::Px(150))],
                Element::Text("wide".to_owned()),
            )],
        );
        let s = render_html(&render_element(row));
        assert!(
            s.contains("outline:2px solid rgba(220,20,20,0.9)"),
            "an over-constrained explained child must get the red overflow edge: {s}"
        );
    }

    #[test]
    fn layout_with_wrapper_and_root_attrs() {
        let wrapper_attrs = vec![Attribute::AttrBgColor(Color::rgba(0, 0, 0, 1.0))];
        let root_attrs = vec![Attribute::AttrPadding(4, 4, 4, 4)];
        let elem: Element<TestMsg> = Element::Text("content".to_owned());
        let html = ui_layout_with_vecs(wrapper_attrs, root_attrs, elem);
        let s = render_html(&html);
        assert!(s.contains("rgba(0,0,0,1)"), "wrapper bg-color missing: {s}");
        assert!(
            s.contains("padding:4px 4px 4px 4px"),
            "root padding missing: {s}"
        );
        assert!(s.contains("content"), "content must render: {s}");
    }

    // ── Layout shell size chain ────────────────────────────────────────────

    /// The `style` attribute value of an `HElement`, if any.
    fn style_of<M>(html: &Html<M>) -> Option<&str> {
        let Html::HElement(_, attrs, _) = html else {
            return None;
        };
        attrs.iter().find_map(|a| match a {
            HtmlAttribute::Attr(k, v) if k == "style" => Some(v.as_str()),
            _ => None,
        })
    }

    /// The `index`-th child of an `HElement`, if any.
    fn child_of<M>(html: &Html<M>, index: usize) -> Option<&Html<M>> {
        let Html::HElement(_, _, kids) = html else {
            return None;
        };
        kids.get(index)
    }

    /// Both layout entry points put `ROOT_FILL_CSS` on the root div and exactly
    /// `VIEWPORT_WRAPPER_CSS` (plus any wrapper attrs) on the wrapper.
    #[test]
    fn layout_root_div_fills_wrapper() {
        let plain = ui_layout::<TestMsg>(vec![], Element::Text("a".to_owned()));
        assert_eq!(style_of(&plain), Some(VIEWPORT_WRAPPER_CSS));
        let root = child_of(&plain, 0);
        assert_eq!(root.and_then(style_of), Some(ROOT_FILL_CSS));

        let with = ui_layout_with_vecs::<TestMsg>(
            vec![Attribute::AttrPadding(1, 1, 1, 1)],
            vec![],
            Element::Text("b".to_owned()),
        );
        let want = format!("{VIEWPORT_WRAPPER_CSS};padding:1px 1px 1px 1px");
        assert_eq!(style_of(&with), Some(want.as_str()));
        let root = child_of(&with, 0);
        assert_eq!(root.and_then(style_of), Some(ROOT_FILL_CSS));
    }

    /// An author root-attr size is declared after `ROOT_FILL_CSS`, so it wins
    /// the cascade.
    #[test]
    fn layout_root_attrs_override_root_fill() {
        let html = ui_layout::<TestMsg>(
            vec![Attribute::AttrHeight(Length::Px(300))],
            Element::Text("a".to_owned()),
        );
        let root = child_of(&html, 0).and_then(style_of).unwrap_or_default();
        assert_eq!(
            root.find(ROOT_FILL_CSS),
            Some(0),
            "root style must start with ROOT_FILL_CSS: {root}"
        );
        assert!(
            root.find("height:300px")
                .is_some_and(|at| at > ROOT_FILL_CSS.len()),
            "author height must follow ROOT_FILL_CSS: {root}"
        );
    }

    /// The author's root element is laid out as a child of the root column, so
    /// its `height fill` is the column's main axis.
    #[test]
    fn layout_renders_author_root_as_column_child() {
        use crate::ui::helpers::ui_el_;
        let elem: Element<TestMsg> = ui_el_(
            vec![Attribute::AttrHeight(Length::Fill(Portion::ONE))],
            Element::Text("a".to_owned()),
        );
        let html = ui_layout(vec![], elem);
        let author = child_of(&html, 0)
            .and_then(|root| child_of(root, 0))
            .and_then(style_of)
            .unwrap_or_default();
        assert!(
            author.contains("flex-grow:1;flex-basis:0;min-height:0"),
            "author root must grow along the root column: {author}"
        );
    }

    // ── Axis-aware size emission ────────────────────────────────────────────

    /// Style of the first child of `parent [] [child]` rendered as a top node.
    fn first_child_style(parent: Element<TestMsg>) -> String {
        let html = render_element_depth_in(parent, 0, FlexAxis::Block);
        child_of(&html, 0)
            .and_then(style_of)
            .unwrap_or_default()
            .to_owned()
    }

    /// A `fill` width in a row is the row's main axis: the portion bytes.
    #[test]
    fn fill_width_in_row_is_main_axis() {
        use crate::ui::helpers::{ui_el_, ui_row_};
        let child = ui_el_(
            vec![Attribute::AttrWidth(Length::fill_portion(2))],
            Element::Text("a".to_owned()),
        );
        let s = first_child_style(ui_row_(vec![], vec![child]));
        assert!(
            s.contains("width:100%;flex-grow:2;flex-basis:0;min-width:0"),
            "row child width fill must be the main-axis portion: {s}"
        );
    }

    /// A `fill` height in a column is the column's main axis: the portion bytes.
    #[test]
    fn fill_height_in_column_is_main_axis() {
        use crate::ui::helpers::{ui_column_, ui_el_};
        let child = ui_el_(
            vec![Attribute::AttrHeight(Length::Fill(Portion::ONE))],
            Element::Text("a".to_owned()),
        );
        let s = first_child_style(ui_column_(vec![], vec![child]));
        assert!(
            s.contains("height:100%;flex-grow:1;flex-basis:0;min-height:0"),
            "column child height fill must be the main-axis portion: {s}"
        );
    }

    /// Refusal: a `fill` height in a row is a cross-axis stretch, never a
    /// flex portion (which would grow it horizontally and override its width).
    #[test]
    fn fill_height_in_row_emits_no_flex() {
        use crate::ui::helpers::{ui_el_, ui_row_};
        let child = ui_el_(
            vec![
                Attribute::AttrHeight(Length::Fill(Portion::ONE)),
                Attribute::AttrWidth(Length::Px(40)),
            ],
            Element::Text("a".to_owned()),
        );
        let s = first_child_style(ui_row_(vec![], vec![child]));
        assert!(s.contains("align-self:stretch"), "stretch expected: {s}");
        assert!(s.contains("width:40px"), "explicit width kept: {s}");
        assert!(!s.contains("flex-grow"), "no flex-grow on cross axis: {s}");
        assert!(
            !s.contains("flex-basis"),
            "no flex-basis on cross axis: {s}"
        );
        assert!(!s.contains("height:100%"), "no height:100% in a row: {s}");
    }

    /// Refusal: a `fill` width in a column is the cross axis — `width:100%`
    /// only, never a flex portion (which would grow it vertically).
    #[test]
    fn fill_width_in_column_emits_no_flex() {
        use crate::ui::helpers::{ui_column_, ui_el_};
        let child = ui_el_(
            vec![Attribute::AttrWidth(Length::Fill(Portion::ONE))],
            Element::Text("a".to_owned()),
        );
        let s = first_child_style(ui_column_(vec![], vec![child]));
        assert!(s.contains("width:100%"), "cross-axis fill width: {s}");
        assert!(!s.contains("flex-grow"), "no flex-grow on cross axis: {s}");
        assert!(
            !s.contains("flex-basis"),
            "no flex-basis on cross axis: {s}"
        );
    }

    /// Refusal: a `fill` under a block `el` (no flex parent) sizes the
    /// dimension only.
    #[test]
    fn fill_in_block_parent_emits_no_flex() {
        use crate::ui::helpers::ui_el_;
        let child = ui_el_(
            vec![
                Attribute::AttrWidth(Length::Fill(Portion::ONE)),
                Attribute::AttrHeight(Length::Fill(Portion::ONE)),
            ],
            Element::Text("a".to_owned()),
        );
        let s = first_child_style(ui_el_(vec![], child));
        assert!(
            s.starts_with("width:100%;height:100%"),
            "block child fill is the dimension only: {s}"
        );
        assert!(!s.contains("flex-"), "no flex property under a block: {s}");
        assert!(!s.contains("align-self"), "no stretch under a block: {s}");
    }

    /// Refusal: `fillPortion 0` and a negative portion are `shrink` — no flex
    /// growth, no `flex-basis:0`, no zero floor — so the node keeps its content
    /// size instead of collapsing to 0px.
    #[test]
    fn fill_portion_non_positive_is_shrink() {
        use crate::ui::helpers::{ui_fill_portion_, ui_shrink_};
        let shrink = size_css(
            &[Attribute::<TestMsg>::AttrWidth(ui_shrink_())],
            FlexAxis::Row,
        );
        assert_eq!(shrink, "width:auto");
        for n in [0, -3, i64::MIN] {
            assert_eq!(ui_fill_portion_(n), ui_shrink_(), "fillPortion {n}");
            for axis in [FlexAxis::Row, FlexAxis::Column, FlexAxis::Block] {
                let s = size_css(
                    &[Attribute::<TestMsg>::AttrWidth(ui_fill_portion_(n))],
                    axis,
                );
                let h = size_css(
                    &[Attribute::<TestMsg>::AttrHeight(ui_fill_portion_(n))],
                    axis,
                );
                assert!(!s.contains("flex-"), "fillPortion {n} width: {s}");
                assert!(!h.contains("flex-"), "fillPortion {n} height: {h}");
                assert!(!s.contains("min-width:0"), "fillPortion {n}: {s}");
                assert!(!h.contains("align-self"), "fillPortion {n}: {h}");
            }
            let row = size_css(
                &[Attribute::<TestMsg>::AttrWidth(ui_fill_portion_(n))],
                FlexAxis::Row,
            );
            assert_eq!(row, shrink, "fillPortion {n} renders as shrink");
        }
    }

    /// `fill` is one share, and a portion above `Portion::MAX` clamps to it.
    #[test]
    fn fill_portion_one_is_fill_and_huge_clamps() {
        use crate::ui::helpers::{ui_fill_, ui_fill_portion_};
        assert_eq!(ui_fill_portion_(1), ui_fill_());
        let one = size_css(
            &[Attribute::<TestMsg>::AttrWidth(ui_fill_())],
            FlexAxis::Row,
        );
        assert!(one.contains("flex-grow:1;"), "fill is one share: {one}");
        let max = size_css(
            &[Attribute::<TestMsg>::AttrWidth(ui_fill_portion_(i64::MAX))],
            FlexAxis::Row,
        );
        assert!(
            max.contains(&format!("flex-grow:{};", Portion::MAX.get())),
            "huge portion clamps: {max}"
        );
        assert_eq!(
            ui_fill_portion_(i64::from(Portion::MAX.get()) + 1),
            Length::Fill(Portion::MAX)
        );
    }

    /// A `fill` wrapped in `minimum` / `maximum` keeps its main-axis portion,
    /// and the bounds become the flex item's `min-*` / `max-*`.
    #[test]
    fn fill_inside_min_max_keeps_portion() {
        let min = size_css(
            &[Attribute::<TestMsg>::AttrWidth(Length::Min(
                100,
                Box::new(Length::Fill(Portion::ONE)),
            ))],
            FlexAxis::Row,
        );
        assert!(
            min.contains("flex-grow:1;flex-basis:0"),
            "min fill grows: {min}"
        );
        assert!(
            min.starts_with("width:max(100px,100%);"),
            "minimum is a lower bound: {min}"
        );
        assert!(min.ends_with("min-width:100px"), "minimum floors: {min}");

        let max = size_css(
            &[Attribute::<TestMsg>::AttrWidth(Length::Max(
                200,
                Box::new(Length::Fill(Portion::ONE)),
            ))],
            FlexAxis::Row,
        );
        assert!(
            max.contains("flex-grow:1;flex-basis:0;min-width:0"),
            "max fill grows: {max}"
        );
        assert!(
            max.starts_with("width:min(200px,100%);"),
            "maximum is an upper bound: {max}"
        );
        assert!(max.ends_with(";max-width:200px"), "maximum caps: {max}");

        let cross = size_css(
            &[Attribute::<TestMsg>::AttrHeight(Length::Max(
                8,
                Box::new(Length::Min(4, Box::new(Length::Fill(Portion::ONE)))),
            ))],
            FlexAxis::Row,
        );
        assert_eq!(
            cross, "align-self:stretch;min-height:4px;max-height:8px",
            "a bounded cross-axis fill stretches within its bounds"
        );
    }

    /// Nested bounds of one kind combine to the tightest: the largest floor and
    /// the smallest cap.
    #[test]
    fn fill_spec_combines_nested_bounds() {
        let len = Length::Min(
            10,
            Box::new(Length::Min(
                30,
                Box::new(Length::Max(
                    90,
                    Box::new(Length::Max(50, Box::new(Length::fill_portion(2)))),
                )),
            )),
        );
        assert_eq!(
            fill_spec(&len),
            Some(FillSpec {
                portion: Portion::from_int(2).expect("2 is a positive portion"),
                lower: Some(30),
                upper: Some(50),
            })
        );
        assert_eq!(fill_spec(&Length::Min(10, Box::new(Length::Px(5)))), None);
    }

    /// Refusal: `alignY` beside a `fill` height in a row yields to the stretch —
    /// exactly one `align-self`, and it is `stretch`.
    #[test]
    fn fill_height_in_row_overrides_align_y() {
        use crate::ui::helpers::{ui_el_, ui_row_};
        let child = ui_el_(
            vec![
                Attribute::AttrAlignY(VAlign::CenterY),
                Attribute::AttrHeight(Length::Fill(Portion::ONE)),
            ],
            Element::Text("a".to_owned()),
        );
        let s = first_child_style(ui_row_(vec![], vec![child]));
        assert_eq!(s.matches("align-self").count(), 1, "one align-self: {s}");
        assert!(s.contains("align-self:stretch"), "stretch wins: {s}");
    }

    /// An aligned-child-promoted `el` lays its child out as a row: the child's aligned
    /// `height fill` stretches instead of growing.
    #[test]
    fn promoted_el_child_sees_row() {
        use crate::ui::helpers::ui_el_;
        let child = ui_el_(
            vec![
                Attribute::AttrAlignX(HAlign::CenterX),
                Attribute::AttrHeight(Length::Fill(Portion::ONE)),
            ],
            Element::Text("a".to_owned()),
        );
        let s = first_child_style(ui_el_(vec![], child));
        assert!(s.contains("align-self:stretch"), "row cross stretch: {s}");
        assert!(!s.contains("flex-grow"), "no main-axis grow: {s}");
        assert!(
            s.contains("margin-left:auto;margin-right:auto"),
            "centerX is the row main axis: {s}"
        );
    }

    /// A fixed width is pinned (`flex-shrink:0`) only on a row's main axis.
    #[test]
    fn overconstrain_only_on_row_main_axis() {
        let attrs = [Attribute::<TestMsg>::AttrWidth(Length::Px(40))];
        assert_eq!(overconstrain_css(&attrs, FlexAxis::Row), "flex-shrink:0");
        assert_eq!(overconstrain_css(&attrs, FlexAxis::Column), "");
        assert_eq!(overconstrain_css(&attrs, FlexAxis::Block), "");
    }

    /// The context-free collectors (`onPseudo`, `mediaQuery`) size with no flex
    /// parent: a `fill` there never carries a portion.
    #[test]
    fn block_style_string_fill_has_no_portion() {
        let s = block_style_string(&[
            Attribute::<TestMsg>::AttrWidth(Length::fill_portion(3)),
            Attribute::AttrPadding(1, 1, 1, 1),
        ]);
        assert_eq!(s, "width:100%;padding:1px 1px 1px 1px");
    }

    /// The parent-independent collector never emits a size property.
    #[test]
    fn build_style_string_emits_no_size() {
        let s = build_style_string(&[
            Attribute::<TestMsg>::AttrWidth(Length::Fill(Portion::ONE)),
            Attribute::AttrHeight(Length::Px(9)),
        ]);
        assert_eq!(s, "");
    }

    /// An author raw style for a size property follows the typed size, so it
    /// wins the cascade.
    #[test]
    fn raw_style_follows_typed_size() {
        use crate::ui::helpers::{ui_el_, ui_row_};
        let child = ui_el_(
            vec![
                Attribute::AttrStyle("width".to_owned(), "7px".to_owned()),
                Attribute::AttrWidth(Length::Px(40)),
            ],
            Element::Text("a".to_owned()),
        );
        let s = first_child_style(ui_row_(vec![], vec![child]));
        assert!(s.starts_with("width:40px;width:7px"), "raw style last: {s}");
    }

    // ── Follow-up 3: CSS injection hardening tests (T3/T4) ───────────────────

    /// A mid-value `url(javascript:…)` payload (`;` breakout + dangerous URL)
    /// must be dropped entirely — the old prefix-only gate missed this.
    #[test]
    fn css_midvalue_injection_dropped() {
        let attrs = vec![Attribute::AttrStyle(
            "background".to_owned(),
            "0; background:url(javascript:alert(1))".to_owned(),
        )];
        let elem: Element<TestMsg> = Element::Empty;
        let html = ui_layout(attrs, elem);
        let s = render_html(&html);
        assert!(
            !s.contains("javascript:"),
            "mid-value javascript: must be dropped: {s}"
        );
        assert!(
            !s.contains("alert("),
            "mid-value injection must be dropped: {s}"
        );
    }

    /// A dangerous style KEY (contains `;` + injection payload) must be
    /// dropped — an unchecked key emitted verbatim would let a whole CSS rule
    /// be smuggled through the value gate.
    #[test]
    fn css_dangerous_key_dropped() {
        let attrs = vec![Attribute::AttrStyle(
            "x;background:url(javascript:alert(1))".to_owned(),
            "y".to_owned(),
        )];
        let elem: Element<TestMsg> = Element::Empty;
        let html = ui_layout(attrs, elem);
        let s = render_html(&html);
        assert!(
            !s.contains("javascript:"),
            "dangerous key must be dropped, no javascript: in output: {s}"
        );
        assert!(
            !s.contains("alert("),
            "dangerous key must be dropped, no alert( in output: {s}"
        );
    }

    /// A legitimate `AttrStyle("color", "red")` must still be emitted
    /// correctly after the smart-constructor hardening.
    #[test]
    fn css_safe_attr_style_emits_correctly() {
        let attrs = vec![Attribute::AttrStyle("color".to_owned(), "red".to_owned())];
        let elem: Element<TestMsg> = Element::Empty;
        let html = ui_layout(attrs, elem);
        let s = render_html(&html);
        assert!(
            s.contains("color:red"),
            "safe color:red must be emitted: {s}"
        );
    }

    #[test]
    fn empty_element_renders_empty_text_node() {
        let html: Html<TestMsg> = render_element(Element::Empty);
        assert_eq!(html, Html::HText(String::new()));
    }

    #[test]
    fn raw_element_passes_through() {
        let inner: Html<TestMsg> =
            Html::HElement("span".into(), vec![], vec![Html::HText("raw".into())]);
        let html = render_element(Element::Raw(inner.clone()));
        assert_eq!(html, inner);
    }

    #[test]
    fn event_attr_on_msg_registers_handler() {
        use crate::html::{Attribute as HtmlAttr, Event};
        // Constructs TestMsg::Click — suppresses the dead-code lint while adding
        // genuine coverage for the AttrEvent/Event::OnMsg path through
        // collect_html_attrs → render_html's data-ipe-on emission.
        let evt = HtmlAttr::EventAttr(Event::OnMsg("click".to_owned(), TestMsg::Click));
        let attrs = vec![Attribute::AttrEvent(evt)];
        let elem: Element<TestMsg> = Element::Text("press me".to_owned());
        let html = ui_layout(attrs, elem);
        let s = render_html(&html);
        assert!(
            s.contains("data-ipe-on=\"click\""),
            "click event handler must register in rendered HTML: {s}"
        );
        assert!(s.contains("press me"), "element text must render: {s}");
    }

    // ── kernel-wiring regressions ───────────────────────────────

    #[test]
    fn ui_padding_each_renders_four_distinct_sides() {
        // `Ui.paddingEach { top = 1, right = 2, bottom = 3, left = 4 }` — each
        // side distinct proves the record fields are NOT swapped/aliased.
        let attrs = vec![super::super::helpers::ui_padding_each_::<TestMsg>(
            1, 2, 3, 4,
        )];
        let elem: Element<TestMsg> = Element::Empty;
        let html = ui_layout(attrs, elem);
        let s = render_html(&html);
        assert!(
            s.contains("padding:1px 2px 3px 4px"),
            "paddingEach must render top/right/bottom/left in order: {s}"
        );
    }

    #[test]
    fn ui_clip_x_y_render_single_axis_clip_not_hidden() {
        // clipX = AttrOverflow "clip" "visible" (NOT "hidden"),
        // clipY = AttrOverflow "visible" "clip". Distinct from `Ui.clip` (which
        // uses "hidden" on both axes).
        let attrs_x = vec![super::super::helpers::ui_clip_x_::<TestMsg>()];
        let html_x = ui_layout(attrs_x, Element::Empty);
        let sx = render_html(&html_x);
        assert!(
            sx.contains("overflow-x:clip") && sx.contains("overflow-y:visible"),
            "clipX must be overflow-x:clip;overflow-y:visible (not hidden): {sx}"
        );

        let attrs_y = vec![super::super::helpers::ui_clip_y_::<TestMsg>()];
        let html_y = ui_layout(attrs_y, Element::Empty);
        let sy = render_html(&html_y);
        assert!(
            sy.contains("overflow-x:visible") && sy.contains("overflow-y:clip"),
            "clipY must be overflow-x:visible;overflow-y:clip: {sy}"
        );
    }

    #[test]
    fn ui_scrollbar_x_y_render_off_axis_hidden_not_visible() {
        // scrollbarX = AttrOverflow "auto" "hidden" (off-axis hidden, NOT visible
        // — a visible off-axis gets promoted to `auto` by CSS, producing an
        // unwanted second scrollbar).
        let attrs_x = vec![super::super::helpers::ui_scrollbar_x_::<TestMsg>()];
        let html_x = ui_layout(attrs_x, Element::Empty);
        let sx = render_html(&html_x);
        assert!(
            sx.contains("overflow-x:auto") && sx.contains("overflow-y:hidden"),
            "scrollbarX must be overflow-x:auto;overflow-y:hidden: {sx}"
        );

        let attrs_y = vec![super::super::helpers::ui_scrollbar_y_::<TestMsg>()];
        let html_y = ui_layout(attrs_y, Element::Empty);
        let sy = render_html(&html_y);
        assert!(
            sy.contains("overflow-x:hidden") && sy.contains("overflow-y:auto"),
            "scrollbarY must be overflow-x:hidden;overflow-y:auto: {sy}"
        );
    }

    #[test]
    fn ui_image_renders_img_src_alt_void() {
        let elem = super::super::helpers::ui_image_::<TestMsg>(
            vec![],
            "https://example.com/x.png".to_owned(),
            "a cat".to_owned(),
        );
        let html = ui_layout(vec![], elem);
        let s = render_html(&html);
        assert!(s.contains("<img"), "must render <img>: {s}");
        assert!(
            s.contains("src=\"https://example.com/x.png\""),
            "src attr missing: {s}"
        );
        assert!(s.contains("alt=\"a cat\""), "alt attr missing: {s}");
        assert!(
            !s.contains("</img>"),
            "img is a void element — no closing tag: {s}"
        );
    }

    #[test]
    fn background_linear_gradient_renders_css_gradient() {
        let attrs = vec![super::super::helpers::ui_background_linear_gradient_::<
            TestMsg,
        >(
            90.0,
            vec![
                (0.0, Color::rgba(255, 0, 0, 1.0)),
                (100.0, Color::rgba(0, 0, 255, 1.0)),
            ],
        )];
        let html = ui_layout(attrs, Element::Empty);
        let s = render_html(&html);
        assert!(
            s.contains(
                "background-image:linear-gradient(90deg, rgba(255,0,0,1) 0%, rgba(0,0,255,1) 100%)"
            ),
            "linear-gradient CSS malformed: {s}"
        );
    }

    #[test]
    fn ui_on_pseudo_emits_data_ipe_pc_rules_marker() {
        // `Ui.onPseudo Ui.hover [Background.color red]` must attach a
        // `data-ipe-pc-rules="h|background-color:rgba(255,0,0,1)"` marker —
        // the wire format `ipe_runtime::web::style_inject::build_pc` decodes
        // into a ipe-id-scoped `<style>` block post-`assign_ipe_ids`.
        let inner = vec![Attribute::AttrBgColor(Color::rgba(255, 0, 0, 1.0))];
        let pseudo_attr =
            super::super::helpers::ui_on_pseudo_(super::super::helpers::ui_hover_(), inner);
        let attrs = vec![pseudo_attr];
        let elem: Element<TestMsg> = Element::Text("hi".to_owned());
        let html = ui_layout(attrs, elem);
        let s = render_html(&html);
        assert!(
            s.contains("data-ipe-pc-rules=\"h|background-color:rgba(255,0,0,1)\""),
            "onPseudo(hover) marker missing/malformed: {s}"
        );
    }

    #[test]
    fn ui_media_query_emits_mq_markers_on_leaf_wrapper() {
        // A non-attributed leaf child (Text) has no attribute slot, so the
        // markers fall back onto a wrapper node carrying data-ipe-mq-q (the
        // verbatim query) + data-ipe-mq-rules (the attrs folded through
        // build_style_string) — the wire pair
        // `ipe_runtime::web::style_inject::build_mq` decodes into a
        // ipe-id-scoped <style> block post-`assign_ipe_ids`.
        let elem = super::super::helpers::ui_media_query_::<TestMsg>(
            "(min-width: 768px)".to_owned(),
            vec![Attribute::AttrBgColor(Color::rgba(18, 18, 24, 1.0))],
            Element::Text("responsive".to_owned()),
        );
        let html = ui_layout(vec![], elem);
        let s = render_html(&html);
        assert!(
            s.contains("data-ipe-mq-q=\"(min-width: 768px)\""),
            "mediaQuery query marker missing/malformed: {s}"
        );
        assert!(
            s.contains("data-ipe-mq-rules=\"background-color:rgba(18,18,24,1)\""),
            "mediaQuery rules marker missing/malformed: {s}"
        );
        assert!(s.contains("responsive"), "child must render: {s}");
    }

    #[test]
    fn ui_media_query_attaches_markers_to_attributed_child_no_wrapper() {
        // An attributed child (a Ui.column here) must carry the media-query
        // markers on its OWN attribute list — no extra wrapper node — so the
        // breakpoint rule targets the styled node and can re-lay-out its own
        // contents (e.g. align-items on the column itself).
        let child: Element<TestMsg> = super::super::helpers::ui_column_(
            vec![Attribute::AttrBgColor(Color::rgba(9, 9, 9, 1.0))],
            vec![Element::Text("col".to_owned())],
        );
        let elem = super::super::helpers::ui_media_query_::<TestMsg>(
            "(max-width: 999px)".to_owned(),
            vec![Attribute::AttrStyle(
                "align-items".to_owned(),
                "center".to_owned(),
            )],
            child,
        );
        // The returned element is the column itself (a Node), carrying the
        // markers directly — its children are the column's own contents
        // (the "col" text), NOT a re-wrapped column node.
        match &elem {
            Element::Node(_, attrs, kids) => {
                let has_marker = attrs.iter().any(|a| {
                    matches!(
                        a,
                        Attribute::AttrAttribute(k, _) if k == "data-ipe-mq-q"
                    )
                });
                assert!(has_marker, "markers must land on the child's own attrs");
                assert_eq!(kids.len(), 1, "column's own single child, no wrapper");
                assert!(
                    matches!(&kids[0], Element::Text(t) if t == "col"),
                    "returned node's child is the column's content, not a wrapped column: {:?}",
                    kids[0]
                );
            }
            other => panic!("expected the attributed child Node back, got {other:?}"),
        }
    }

    #[test]
    fn ui_breakpoint_delegates_to_media_query_markers() {
        // `Ui.breakpoint Ui.mobile [...] child` is upstream-defined as
        // `mediaQuery (breakpointToQuery bp) ...`; with Breakpoint = String
        // in this port the delegation must emit the same marker pair, not a
        // passthrough that drops the query.
        let elem = super::super::helpers::ui_breakpoint_::<TestMsg>(
            super::super::helpers::ui_mobile_(),
            vec![Attribute::AttrBgColor(Color::rgba(1, 2, 3, 1.0))],
            Element::Text("m".to_owned()),
        );
        let html = ui_layout(vec![], elem);
        let s = render_html(&html);
        assert!(
            s.contains("data-ipe-mq-q=\"(max-width: 767px)\""),
            "breakpoint must emit the Ui.mobile media-query marker: {s}"
        );
        assert!(
            s.contains("data-ipe-mq-rules=\"background-color:rgba(1,2,3,1)\""),
            "breakpoint rules marker missing: {s}"
        );
    }

    /// SECURITY: a breakout media-query string must be neutralised at the
    /// producer — the `SafeCssMediaQuery` gate drops BOTH markers (fail-closed:
    /// no styling), while the wrapper + child still render.
    #[test]
    fn ui_media_query_breakout_query_drops_markers_fail_closed() {
        let elem = super::super::helpers::ui_media_query_::<TestMsg>(
            "(min-width: 1px) { } </style><script>alert(1)</script> @import url(evil)".to_owned(),
            vec![Attribute::AttrBgColor(Color::rgba(18, 18, 24, 1.0))],
            Element::Text("safe".to_owned()),
        );
        let html = ui_layout(vec![], elem);
        let s = render_html(&html);
        assert!(
            !s.contains("data-ipe-mq-q") && !s.contains("data-ipe-mq-rules"),
            "breakout query must drop BOTH markers: {s}"
        );
        assert!(!s.contains("<script"), "script must never render: {s}");
        assert!(s.contains("safe"), "child must still render: {s}");
    }

    // ── UI CSS-escaping hardening (value-as-data attrs; spec §6.1) ─────────

    /// Every previously-ungated raw-string arm must DROP a value carrying the
    /// rule-breakout set (`}` / `;` / `@import`) — the page-wide-injection
    /// primitive once `Ui.onPseudo` routes the collector output into a
    /// `<style>` block (Repro A of the spec).
    #[test]
    fn value_as_data_attrs_drop_rule_breakout_payloads() {
        let cases: Vec<Attribute<TestMsg>> = vec![
            Attribute::AttrFontFamily("serif } body { display:none".to_owned()),
            Attribute::AttrFontFamily("x;color:red".to_owned()),
            Attribute::AttrFontDecoration("underline } .x{}".to_owned()),
            Attribute::AttrFontAlign("center;position:fixed".to_owned()),
            Attribute::AttrBorderStyle("solid } .x{color:red".to_owned()),
            Attribute::AttrTransition("all 1s } body{}".to_owned(), true),
            Attribute::AttrAnimation(
                "a } body {".to_owned(),
                "300ms".to_owned(),
                String::new(),
                true,
            ),
            Attribute::AttrBgImage("x) } @import url(evil)".to_owned()),
        ];
        for attr in cases {
            let css = build_style_string(std::slice::from_ref(&attr));
            assert!(
                !css.contains('}') && !css.contains("display:none") && !css.contains("@import"),
                "breakout payload must be dropped, got {css:?} for {attr:?}"
            );
        }
    }

    /// Per-component gating: one poisoned overflow axis drops alone; the
    /// sibling legit axis still renders.
    #[test]
    fn overflow_gates_each_axis_independently() {
        let attr: Attribute<TestMsg> =
            Attribute::AttrOverflow("auto }".to_owned(), "hidden".to_owned());
        let css = build_style_string(std::slice::from_ref(&attr));
        assert!(
            !css.contains("overflow-x"),
            "poisoned axis must drop: {css}"
        );
        assert!(
            css.contains("overflow-y:hidden"),
            "legit axis must stay: {css}"
        );
    }

    /// Legitimate values must render byte-for-byte — the gate's charset is
    /// permissive for everything a real single-declaration value contains
    /// (commas, quotes, spaces); zero legitimate loss.
    #[test]
    fn value_as_data_attrs_keep_legitimate_values() {
        let cases: Vec<(Attribute<TestMsg>, &str)> = vec![
            (
                Attribute::AttrFontFamily("\"Helvetica Neue\", Georgia, serif".to_owned()),
                "font-family:\"Helvetica Neue\", Georgia, serif",
            ),
            (
                Attribute::AttrTransition("all 200ms ease-in-out".to_owned(), true),
                "transition:all 200ms ease-in-out",
            ),
            (
                Attribute::AttrFontAlign("center".to_owned()),
                "text-align:center",
            ),
            (
                Attribute::AttrBorderStyle("dashed".to_owned()),
                "border-style:dashed",
            ),
            (
                Attribute::AttrFontDecoration("underline".to_owned()),
                "text-decoration:underline",
            ),
            (
                Attribute::AttrAnimation(
                    "fadeIn".to_owned(),
                    "300ms ease".to_owned(),
                    String::new(),
                    true,
                ),
                "animation:fadeIn 300ms ease",
            ),
            (
                Attribute::AttrOverflow("auto".to_owned(), "scroll".to_owned()),
                "overflow-x:auto;overflow-y:scroll",
            ),
            (
                Attribute::AttrBgImage("hero.png".to_owned()),
                "background-image:url(hero.png)",
            ),
        ];
        for (attr, want) in cases {
            let css = build_style_string(std::slice::from_ref(&attr));
            assert_eq!(css, want, "legit value must render verbatim for {attr:?}");
        }
    }

    /// SECURITY (appearance-hot-swap sink preservation): a `Background.image`
    /// URL that reaches its sink from a dev-patched `LiteralTable` slot must be
    /// neutralised byte-identically to the same URL baked as a direct literal.
    /// The hoist changes only WHERE the String originates (a `get(idx)` read
    /// versus a baked literal); the render sink (`AttrBgImage` →
    /// `is_dangerous_url_scheme` plus a composed-`url(..)` `SafeCssValue` scan) is
    /// a pure function of the String, so a dev-patched URL meets the identical
    /// wall a baked one does and cannot reach a less-sanitised sink (dev == prod).
    /// Vectors exercise the `javascript:` / non-media `data:` scheme, a `</style>`
    /// or `@import` breakout, and hex/whitespace evasion.
    #[cfg(feature = "web")] // `LiteralTable` (the dev-patch read path) is web-shape only
    #[test]
    fn bg_image_dev_patched_url_is_neutralised_identically_to_baked() {
        use crate::ui::helpers::ui_background_image_;
        use crate::web::LiteralTable;

        let vectors = [
            "javascript:alert(1)",
            "  JaVaScRiPt:alert(1)",             // whitespace + case evasion
            "data:text/html,<script>x</script>", // non-media data: URI
            "x) } @import url(//evil/x.css) ; a(",
            "x)</style><script>alert(1)</script>",
            "\\6a avascript:alert(1)", // CSS hex-escape evasion
        ];
        for vector in vectors {
            // Direct/baked path: the helper wraps the raw literal String.
            let baked = build_style_string(std::slice::from_ref(&ui_background_image_::<TestMsg>(
                vector.to_owned(),
            )));
            // Hoisted/dev-patched path: the SAME helper wraps a String read back
            // from a patched table slot — the exact emitted read shape.
            let mut table = LiteralTable::from_defaults(&["placeholder.png"]);
            table.apply_patch(&[(0, vector.to_owned())]);
            let patched = build_style_string(std::slice::from_ref(
                &ui_background_image_::<TestMsg>(table.get(0).to_owned()),
            ));

            assert_eq!(
                baked, patched,
                "dev-patched URL must render identically to the baked literal \
                 (one sink, dev == prod) for vector {vector:?}"
            );
            // And the shared sink actually neutralises the payload in both.
            assert!(
                !patched.to_ascii_lowercase().contains("javascript:")
                    && !patched.to_ascii_lowercase().contains("data:text/html")
                    && !patched.contains("</style")
                    && !patched.contains("@import")
                    && !patched.contains('}'),
                "adversarial URL must be neutralised at the sink, got {patched:?} \
                 for vector {vector:?}"
            );
        }
    }

    #[test]
    fn multiple_pseudo_rules_merge_into_one_marker() {
        // #113 spec §1.4: two pseudo-class sugars on ONE element must merge
        // into a single `data-ipe-pc-rules` marker with `||`-joined entries.
        // NB: `Border.focusColor` maps to `PseudoClass::FocusVisible` (wire
        // tag "v"), not `Focus` ("f") — see `ui_border_focus_color_`.
        let attrs: Vec<Attribute<TestMsg>> = vec![
            super::super::helpers::ui_bg_hover_color_(Color::rgba(255, 0, 0, 1.0)),
            super::super::helpers::ui_border_focus_color_(Color::rgba(0, 0, 255, 1.0)),
        ];
        let elem: Element<TestMsg> = Element::Text("hi".to_owned());
        let html = ui_layout(attrs, elem);
        let s = render_html(&html);
        assert!(s.contains("h|background-color:rgba(255,0,0,1)"), "{s}");
        assert!(s.contains("||"), "entries must be || joined: {s}");
        assert!(s.contains("v|border-color:rgba(0,0,255,1)"), "{s}");
        assert_eq!(
            s.matches("data-ipe-pc-rules").count(),
            1,
            "exactly ONE merged marker attr, not one per rule: {s}"
        );
    }

    #[test]
    fn ui_on_pseudo_all_five_constants_produce_distinct_wire_tags() {
        // hover→h, focus→f, focusVisible→v, active→a, disabled→d — MUST match
        // `ipe_runtime::web::style_inject::pseudo_selector_for_tag` and the
        // `../ipe` reference's `pseudoClassTag`.
        let cases: [(super::super::element::PseudoClass, &str); 5] = [
            (super::super::helpers::ui_hover_(), "h"),
            (super::super::helpers::ui_focus_(), "f"),
            (super::super::helpers::ui_focus_visible_(), "v"),
            (super::super::helpers::ui_active_(), "a"),
            (super::super::helpers::ui_disabled_(), "d"),
        ];
        for (pc, tag) in cases {
            let attr: Attribute<TestMsg> =
                super::super::helpers::ui_on_pseudo_(pc, vec![Attribute::AttrPointer]);
            let s = build_style_string_for_test(&attr);
            assert!(
                s.starts_with(&format!("{tag}|")),
                "pseudo-class {pc:?} must wire-tag as {tag:?}: {s}"
            );
        }
    }

    /// Test-only accessor: extract the `(tag, css)` payload of an
    /// `AttrPseudoRule` as `"tag|css"` for assertions above.
    fn build_style_string_for_test<M>(attr: &Attribute<M>) -> String {
        match attr {
            Attribute::AttrPseudoRule(pc, css) => format!("{}|{css}", pc.wire_tag()),
            _ => String::new(),
        }
    }

    #[test]
    fn ui_on_file_registers_ipe_file_wire_event() {
        use crate::html::{Attribute as HtmlAttr, Event};
        let attr =
            super::super::helpers::ui_on_file_::<TestMsg>(std::sync::Arc::new(|_s| TestMsg::Click));
        match attr {
            Attribute::AttrEvent(HtmlAttr::EventAttr(Event::OnString(name, _))) => {
                assert_eq!(name, "ipe-file", "onFile must wire as event name ipe-file");
            }
            other => {
                panic!("expected AttrEvent(EventAttr(OnString(\"ipe-file\", _))), got {other:?}")
            }
        }
    }

    #[test]
    fn paragraph_el_child_renders_inline_span_not_block_div() {
        // Mirrors `Ipe.Markdown.renderInline "a **bold** word"`:
        //   Ui.paragraph [] [ Ui.text "a "
        //                    , Ui.el [ Font.bold ] (Ui.text "bold")
        //                    , Ui.text " word" ]
        // The bold `Ui.el` lowers to Element::Node(NoDescription, [FontWeight
        // 700], [Text "bold"]). On the web backend it MUST render as an inline
        // <span>, not a block <div>, so the bold run flows inline and the markup
        // stays valid inside <p>.
        let para: Element<TestMsg> = super::super::helpers::ui_paragraph_(
            vec![],
            vec![
                Element::Text("a ".to_owned()),
                super::super::helpers::ui_el_(
                    vec![Attribute::AttrFontWeight(700)],
                    Element::Text("bold".to_owned()),
                ),
                Element::Text(" word".to_owned()),
            ],
        );
        let html = render_element(para);
        let s = render_html(&html);
        assert!(
            s.contains("<span style=\"display:inline-block;vertical-align:baseline;font-weight:700\">bold</span>"),
            "bold el child must render as an inline <span>: {s}"
        );
        assert!(
            !s.contains("<div"),
            "no block <div> may appear inside the paragraph: {s}"
        );
        assert!(
            s.starts_with("<p"),
            "the paragraph itself must render as <p>: {s}"
        );
    }

    // ── Ui.paragraph inline-child rendering ──────────────────────────────────

    /// Golden: the highlight-a-phrase pattern keeps every child inside `<p>`.
    ///
    /// `Ui.paragraph [] [ Ui.el [Font.bold] (Ui.text "X"), Ui.text " — rest" ]`
    ///
    /// The `Ui.el` child must render as an inline `<span>` (not a block `<div>`)
    /// so the HTML parser never auto-closes the `<p>` around it. The trailing
    /// text must stay INSIDE the same `<p>` element.
    #[test]
    fn paragraph_highlight_phrase_stays_inside_p_no_hoisting() {
        use crate::ui::helpers::{ui_el_, ui_paragraph_};

        let para: Element<TestMsg> = ui_paragraph_(
            vec![],
            vec![
                ui_el_(
                    vec![Attribute::AttrFontWeight(700)],
                    Element::Text("X".to_owned()),
                ),
                Element::Text(" — rest".to_owned()),
            ],
        );
        let html = render_element(para);
        let s = render_html(&html);

        // The paragraph wraps in <p>.
        assert!(s.starts_with("<p"), "outer element must be <p>: {s}");
        // The bold phrase renders as inline span, not block div — prevents
        // auto-close of <p> by the HTML parser.
        assert!(
            s.contains("<span") && s.contains("font-weight:700"),
            "bold child must render as <span> with font-weight:700: {s}"
        );
        assert!(
            !s.contains("<div"),
            "no block <div> may appear inside <p> (would be hoisted out): {s}"
        );
        // Both the span and the trailing text are children of the single <p>,
        // proven by the trailing text appearing before </p>.
        let p_close = s.rfind("</p>").expect("<p> must close");
        let rest_pos = s.find(" \u{2014} rest").expect("trailing text must appear");
        assert!(
            rest_pos < p_close,
            "trailing text must be inside <p>, not hoisted after </p>: {s}"
        );
    }

    /// Golden: `Ui.row` inside `Ui.paragraph` renders `display:inline-flex`,
    /// keeping the flex container inline and the `<p>` unclosed.
    #[test]
    fn paragraph_row_child_renders_inline_flex_not_block_flex() {
        use crate::ui::helpers::{ui_paragraph_, ui_row_};

        let para: Element<TestMsg> = ui_paragraph_(
            vec![],
            vec![
                Element::Text("before ".to_owned()),
                ui_row_(
                    vec![Attribute::AttrFontWeight(600)],
                    vec![Element::Text("inner".to_owned())],
                ),
                Element::Text(" after".to_owned()),
            ],
        );
        let html = render_element(para);
        let s = render_html(&html);

        assert!(s.starts_with("<p"), "outer element must be <p>: {s}");
        assert!(
            s.contains("display:inline-flex"),
            "row inside paragraph must emit display:inline-flex: {s}"
        );
        assert!(
            s.contains("flex-direction:row"),
            "row direction must be preserved: {s}"
        );
        // No block-level display:flex that would auto-close the <p>.
        assert!(
            !s.contains("display:flex;"),
            "no bare display:flex inside <p> (would force block context): {s}"
        );
        assert!(
            !s.contains("<div"),
            "no block <div> may appear inside <p>: {s}"
        );
    }

    /// Golden: `Ui.column` inside `Ui.paragraph` renders `display:inline-flex`.
    #[test]
    fn paragraph_column_child_renders_inline_flex_not_block_flex() {
        use crate::ui::helpers::{ui_column_, ui_paragraph_};

        let para: Element<TestMsg> = ui_paragraph_(
            vec![],
            vec![
                Element::Text("label ".to_owned()),
                ui_column_(
                    vec![Attribute::AttrFontColor(Color::rgba(0, 0, 255, 1.0))],
                    vec![Element::Text("stacked".to_owned())],
                ),
            ],
        );
        let html = render_element(para);
        let s = render_html(&html);

        assert!(s.starts_with("<p"), "outer element must be <p>: {s}");
        assert!(
            s.contains("display:inline-flex"),
            "column inside paragraph must emit display:inline-flex: {s}"
        );
        assert!(
            s.contains("flex-direction:column"),
            "column direction must be preserved: {s}"
        );
        assert!(
            !s.contains("display:flex;"),
            "no bare display:flex inside <p>: {s}"
        );
        assert!(
            !s.contains("<div"),
            "no block <div> may appear inside <p>: {s}"
        );
    }

    // ── Non-regression: outside-paragraph layouts are unchanged ──────────────

    /// `Ui.el` outside a paragraph renders as `<div>`, not `<span>`.
    #[test]
    fn el_outside_paragraph_renders_as_div_not_span() {
        use crate::ui::helpers::ui_el_;

        let elem: Element<TestMsg> = ui_el_(
            vec![Attribute::AttrFontWeight(700)],
            Element::Text("X".to_owned()),
        );
        let html = render_element(elem);
        let s = render_html(&html);

        assert!(
            s.starts_with("<div"),
            "Ui.el outside paragraph must render as <div>: {s}"
        );
        assert!(
            !s.contains("display:inline-block"),
            "outside paragraph, no inline-block injection: {s}"
        );
        assert!(
            !s.contains("<span"),
            "outside paragraph, no <span> injection: {s}"
        );
    }

    /// `Ui.row` outside a paragraph renders `display:flex` (not `inline-flex`).
    #[test]
    fn row_outside_paragraph_renders_flex_not_inline_flex() {
        use crate::ui::helpers::ui_row_;

        let elem: Element<TestMsg> = ui_row_(vec![], vec![Element::Text("item".to_owned())]);
        let html = render_element(elem);
        let s = render_html(&html);

        assert!(
            s.contains("display:flex"),
            "Ui.row outside paragraph must emit display:flex: {s}"
        );
        assert!(
            !s.contains("inline-flex"),
            "Ui.row outside paragraph must NOT emit inline-flex: {s}"
        );
        assert!(
            s.contains("flex-direction:row"),
            "row direction must be present: {s}"
        );
    }

    /// `Ui.column` outside a paragraph renders `display:flex` (not `inline-flex`).
    #[test]
    fn column_outside_paragraph_renders_flex_not_inline_flex() {
        use crate::ui::helpers::ui_column_;

        let elem: Element<TestMsg> = ui_column_(vec![], vec![Element::Text("item".to_owned())]);
        let html = render_element(elem);
        let s = render_html(&html);

        assert!(
            s.contains("display:flex"),
            "Ui.column outside paragraph must emit display:flex: {s}"
        );
        assert!(
            !s.contains("inline-flex"),
            "Ui.column outside paragraph must NOT emit inline-flex: {s}"
        );
        assert!(
            s.contains("flex-direction:column"),
            "column direction must be present: {s}"
        );
    }

    // RT-UI-001: depth cap — render_element must return (not abort/stack-overflow)
    // when given a tree deeper than MAX_HTML_DEPTH = 1024. We build a chain at
    // depth 1200 and run the render in a 48 MB thread (debug-mode frame sizes are
    // ~10–20× release-mode sizes, so the cap depth × frame needs a larger stack
    // than the 8 MB default to reach). The key property: render returns instead of
    // recursing forever; the cap silently truncates at depth 1024.
    #[test]
    fn render_element_depth_cap_does_not_overflow() {
        // Build Node([], [Node([], [Node([], [... Text("leaf") ...])])]) 1200 deep.
        const DEPTH: usize = 1_200;
        let is_valid = std::thread::Builder::new()
            .stack_size(48 * 1024 * 1024) // 48 MB — enough for debug-mode frames
            .spawn(|| {
                let mut elem: Element<TestMsg> = Element::Text("leaf".to_owned());
                for _ in 0..DEPTH {
                    elem = Element::Node(
                        super::super::element::Description::NoDescription,
                        vec![],
                        vec![elem],
                    );
                }
                // This call must return, not recurse forever. The depth cap at 1024
                // truncates the remaining 176 levels and returns an empty text node.
                let html = render_element(elem);
                // The rendered tree drops normally at end of scope: both
                // `Element` and `Html` carry an iterative destructor, so tearing
                // down a tree at this depth is bounded by the heap, never the
                // native stack — no leak, no overflow.
                matches!(
                    &html,
                    crate::html::Html::HElement(_, _, _) | crate::html::Html::HText(_)
                )
            })
            .expect("spawn thread")
            .join()
            .expect("thread did not panic");
        assert!(is_valid, "render_element must return a valid Html variant");
    }
}

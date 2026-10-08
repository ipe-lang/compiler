//! Shared `Ipe.Ui` element tree — the general UI abstraction.
//!
//! These types mirror `ipe-stdlib/Ipe/Ui.ipe`'s ADTs **variant-for-variant and
//! field-for-field**. They live in the runtime (not generated per-project) so
//! that every backend — Ipe.Web (→ HTML), Ipe.Tui (→ ANSI cells), Ipe.WebView
//! (→ native webview) — renders the SAME structured `Element` tree to its own
//! target (`
//! structured Element ADT directly; it never round-trips through CSS).
//!
//! The Rust codegen maps the Ipê `Ipe.Ui.*` types onto these via
//! `runtimeOpaqueTypes` (the same `{M}` mechanism that makes `Html` a shared
//! type), so `Ipe.Ui.column` etc. construct `ipe_runtime::ui::Element` and the
//! pure-Ipê render chain (`renderElement` → `Html`) pattern-matches them.
//!
//! INVARIANT (load-bearing): the variant names + field order MUST stay identical
//! to `Ipe.Ui.ipe:39-190`. The opaque alias hides any drift from the Rust
//! compiler, so a mismatch mis-renders at runtime rather than failing to build —
//! the byte-identical-HTML regression on the Web backend is the safety net.

use std::num::NonZeroU32;

use super::super::html::{Attribute as HtmlAttribute, Html};

/// `Ipe.Ui.Color` = `Rgba Int Int Int Float` (R/G/B 0-255 ints, alpha 0..1).
#[derive(Clone, Debug, PartialEq)]
pub enum Color {
    Rgba(i64, i64, i64, f64),
}

/// The share of a parent's leftover space a `fill` sibling claims: positive by
/// construction, at most [`Portion::MAX`].
///
/// Every backend reads the same value, so none can observe a zero or negative
/// portion. A program `Int` enters only through [`Length::fill_portion`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Portion(NonZeroU32);

impl Portion {
    /// One share: `Ui.fill`.
    pub const ONE: Self = Self(NonZeroU32::MIN);

    /// The largest portion. A larger `fillPortion` clamps to it on every
    /// backend: beside it a one-share sibling gets 1/100 000 of the leftover,
    /// below one terminal cell or one CSS pixel on any real canvas.
    pub const MAX: Self = match NonZeroU32::new(100_000) {
        Some(n) => Self(n),
        None => Self::ONE,
    };

    /// `Some` for a positive `n` (clamped to [`Portion::MAX`]), `None` for
    /// `n <= 0`.
    #[must_use]
    pub fn from_int(n: i64) -> Option<Self> {
        let clamped = u32::try_from(n.min(i64::from(Self::MAX.get()))).ok()?;
        NonZeroU32::new(clamped).map(Self)
    }

    /// The portion as a share count, in `1..=Portion::MAX`.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// `Ipe.Ui.Length`. `Min`/`Max` are self-recursive → `Box` (E0072 otherwise).
#[derive(Clone, Debug, PartialEq)]
pub enum Length {
    Px(i64),
    Content,
    Fill(Portion),
    Min(i64, Box<Length>),
    Max(i64, Box<Length>),
    Vh(i64),
    Vw(i64),
}

impl Length {
    /// `Ui.fillPortion n`: a fill of `n` shares, or `Content` (`Ui.shrink`) when
    /// `n <= 0`, so a non-positive portion is content-sized on every backend.
    #[must_use]
    pub fn fill_portion(n: i64) -> Self {
        Portion::from_int(n).map_or(Self::Content, Self::Fill)
    }

    /// Render this length to its CSS value string. The single renderer for the
    /// `Ipe.Ui.Length` domain, shared by the inline-style and stylesheet paths.
    ///
    /// `Fill(n)` renders `100%`; the flex sizing (`flex-grow:n`, `flex-basis:0`)
    /// that divides free space depends on the parent's flex axis, so the
    /// parent-aware `render::size_css` emits it, not this context-free renderer.
    ///
    /// `Min(n, l)` is a lower bound (CSS `max(npx, l)`, never below `n`) and
    /// `Max(n, l)` an upper bound (CSS `min(npx, l)`, never above `n`), the same
    /// bounds the TUI layout applies.
    ///
    /// The shared `Px`/`Vh`/`Vw` units are spelled by the one runtime renderer
    /// ([`crate::length::CssUnit`]); `Ipe.Ui`'s `Length` is a surface carrier
    /// that funnels those shared shapes into `ipe_runtime::length` rather than
    /// re-deriving the spelling. Byte-for-byte equivalence with the pure-Ipê
    /// `Ipe.Css.lengthToString` is enforced by the `css_length_color_ssot`
    /// equivalence test.
    #[must_use]
    pub(crate) fn css(&self) -> String {
        use crate::length::CssUnit;
        match self {
            Self::Px(n) => CssUnit::Px.css(*n),
            Self::Content => "auto".to_owned(),
            Self::Fill(_) => "100%".to_owned(),
            Self::Min(n, inner) => format!("max({},{})", CssUnit::Px.css(*n), inner.css()),
            Self::Max(n, inner) => format!("min({},{})", CssUnit::Px.css(*n), inner.css()),
            Self::Vh(n) => CssUnit::Vh.css(*n),
            Self::Vw(n) => CssUnit::Vw.css(*n),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HAlign {
    AlignLeft,
    CenterX,
    AlignRight,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum VAlign {
    AlignTop,
    CenterY,
    AlignBottom,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Location {
    Above,
    Below,
    OnRight,
    OnLeft,
    InFront,
    Behind,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PseudoClass {
    Hover,
    Focus,
    FocusVisible,
    Active,
    Disabled,
}

impl PseudoClass {
    /// Stable wire tag consumed by
    /// `ipe_runtime::web::style_inject::pseudo_selector_for_tag` when
    /// decoding the `data-ipe-pc-rules` marker attribute. MUST stay in
    /// lock-step with that function and with `pseudoClassTag` in
    /// `../ipe`'s `Ipe.Ui.ipe` (the shared wire-format contract).
    #[must_use]
    pub const fn wire_tag(self) -> &'static str {
        match self {
            Self::Hover => "h",
            Self::Focus => "f",
            Self::FocusVisible => "v",
            Self::Active => "a",
            Self::Disabled => "d",
        }
    }
}

/// A heading level, always at least 1; 1-6 have a native tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadingLevel(i64);

impl HeadingLevel {
    /// The level for a requested `n`; `n < 1` saturates to 1.
    #[must_use]
    pub const fn from_requested(n: i64) -> Self {
        Self(if n < 1 { 1 } else { n })
    }

    /// The level as a number, at least 1.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Description {
    NoDescription,
    DescMain,
    DescNavigation,
    DescContentInfo,
    DescComplementary,
    DescHeading(HeadingLevel),
    DescLabel(String),
    DescLivePolite,
    DescLiveAssertive,
    DescButton,
    DescParagraph,
    /// A document section; its first child may be its heading.
    DescSection,
    /// The heading of the enclosing section, ranked by section depth.
    DescSectionHeading,
    /// A preformatted block of code.
    DescCodeBlock,
    /// An inline run of code.
    DescCode,
    /// An inline run of keyboard input.
    DescKbd,
    /// A column of text blocks.
    DescTextColumn,
    /// A form that groups input controls.
    DescForm,
}

impl Description {
    /// The heading level this description requests, if it is a heading.
    #[must_use]
    pub const fn heading_level(&self) -> Option<HeadingLevel> {
        match self {
            Self::DescHeading(level) => Some(*level),
            Self::NoDescription
            | Self::DescMain
            | Self::DescNavigation
            | Self::DescContentInfo
            | Self::DescComplementary
            | Self::DescLabel(_)
            | Self::DescLivePolite
            | Self::DescLiveAssertive
            | Self::DescButton
            | Self::DescParagraph
            | Self::DescSection
            | Self::DescSectionHeading
            | Self::DescCodeBlock
            | Self::DescCode
            | Self::DescKbd
            | Self::DescTextColumn
            | Self::DescForm => None,
        }
    }
}

/// How a text box treats white-space and line breaks.
///
/// The CSS `white-space` keyword of each mode is its `css()` text; the terminal
/// renderer reads the same mode through `wraps()` and `preserves_newlines()`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum WhiteSpace {
    #[default]
    Normal,
    NoWrap,
    Pre,
    PreWrap,
    PreLine,
    BreakSpaces,
}

impl WhiteSpace {
    /// Every mode, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::Normal,
        Self::NoWrap,
        Self::Pre,
        Self::PreWrap,
        Self::PreLine,
        Self::BreakSpaces,
    ];

    /// The CSS `white-space` keyword of this mode.
    #[must_use]
    pub const fn css(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::NoWrap => "nowrap",
            Self::Pre => "pre",
            Self::PreWrap => "pre-wrap",
            Self::PreLine => "pre-line",
            Self::BreakSpaces => "break-spaces",
        }
    }

    /// True when a line longer than its box wraps.
    #[must_use]
    pub const fn wraps(self) -> bool {
        match self {
            Self::Normal | Self::PreWrap | Self::PreLine | Self::BreakSpaces => true,
            Self::NoWrap | Self::Pre => false,
        }
    }

    /// True when a newline in the text starts a new line.
    #[must_use]
    pub const fn preserves_newlines(self) -> bool {
        match self {
            Self::Pre | Self::PreWrap | Self::PreLine | Self::BreakSpaces => true,
            Self::Normal | Self::NoWrap => false,
        }
    }
}

/// True when two ASCII keywords are byte-equal.
const fn same_keyword(a: &str, b: &str) -> bool {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    loop {
        match (a.split_first(), b.split_first()) {
            (None, None) => return true,
            (Some((x, a_rest)), Some((y, b_rest))) => {
                if *x != *y {
                    return false;
                }
                a = a_rest;
                b = b_rest;
            }
            (Some(_), None) | (None, Some(_)) => return false,
        }
    }
}

/// True when the `css()` texts of `WhiteSpace::ALL` are pairwise distinct.
const fn white_space_texts_distinct() -> bool {
    let mut rest: &[WhiteSpace] = &WhiteSpace::ALL;
    while let Some((head, tail)) = rest.split_first() {
        let mut others = tail;
        while let Some((other, more)) = others.split_first() {
            if same_keyword(head.css(), other.css()) {
                return false;
            }
            others = more;
        }
        rest = tail;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if two `WhiteSpace` modes share a CSS keyword [ledger #boundary]
const _: () = assert!(white_space_texts_distinct());

/// `Ipe.Ui.LayoutContext` — the flex direction a parent imposes on its children.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LayoutContext {
    AsRow,
    AsColumn,
    AsEl,
    AsParagraph,
    AsTextColumn,
}

/// `Ipe.Ui.Attribute msg` — the typed layout/style/event attributes. Variant
/// order matches `Ipe.Ui.ipe:55-123` EXACTLY. `AttrEvent any` carries the
/// `Ipe.Html.Attributes.Attribute` (the codegen's existing any-carrier mapping);
/// `AttrNearby` is self-referential through `Element<M>`.
#[derive(Clone, Debug, PartialEq)]
pub enum Attribute<M> {
    NoAttribute,
    AttrWidth(Length),
    AttrHeight(Length),
    AttrAlignX(HAlign),
    AttrAlignY(VAlign),
    AttrNearby(Location, Element<M>),
    AttrPadding(i64, i64, i64, i64),
    AttrSpacing(i64),
    AttrStyle(String, String),
    AttrDescribe(Description),
    AttrClass(String),
    AttrEvent(HtmlAttribute<M>),
    /// `Ui.htmlAttribute name value` escape hatch — an arbitrary, possibly
    /// attacker-derived attribute name + value. The TUI renderer (the only
    /// current sink) emits ANSI cells, so there is no markup-injection surface.
    /// SECURITY CONTRACT for the Ipe.Ui→HTML lowering: an `AttrAttribute`
    /// MUST be lowered to a `html::Attribute::Attr` and emitted through
    /// `html::render` (whose `render_into_ctx` gates every name via
    /// `SafeAttrName` and every URL value via `sanitise_url_attr`). A bespoke
    /// renderer that bypasses that path would reintroduce the `onerror=` /
    /// `href="javascript:"` XSS class — do not write one.
    AttrAttribute(String, String),
    /// Native checkedness of a checkbox or radio; constructed only by
    /// `ui::input`, never an Ipê-visible constructor.
    AttrChecked(bool),
    AttrFontSize(i64),
    AttrFontColor(crate::color::Color),
    AttrFontFamily(String),
    AttrFontWeight(i64),
    AttrFontItalic,
    AttrFontUnderline,
    AttrFontDecoration(String),
    AttrFontLetterSpacing(f64),
    AttrFontWordSpacing(f64),
    AttrFontAlign(String),
    AttrBgColor(crate::color::Color),
    AttrBgImage(String),
    AttrBgGradient(String),
    AttrBorderWidth(i64),
    AttrBorderWidthEach(i64, i64, i64, i64),
    AttrBorderColor(crate::color::Color),
    AttrBorderRounded(i64),
    AttrBorderStyle(String),
    AttrBorderShadow(i64, i64, i64, i64, crate::color::Color),
    AttrBorderInsetShadow(i64, i64, i64, i64, crate::color::Color),
    AttrPointer,
    /// `Debug.explain` — draws visible outlines on this element and all
    /// descendants to make the invisible layout box tree visible during
    /// development.  Never changes layout; Web/WebView only.
    AttrExplain,
    AttrOverflow(String, String),
    AttrPseudoRule(PseudoClass, String),
    AttrTransition(String, bool),
    AttrGridTracks(String, String),
    AttrAnimation(String, String, String, bool),
    /// `Font.whiteSpace` — the closed white-space mode of a text box.
    AttrFontWhiteSpace(WhiteSpace),
}

/// `Ipe.Ui.Element msg` — the layout tree. Variant order matches
/// `Ipe.Ui.ipe:39-53`. `Raw any` carries a `Ipe.Html` node (the codegen's
/// any-carrier mapping) so user code can drop native HTML into the tree.
#[derive(Clone, Debug, PartialEq)]
pub enum Element<M> {
    Empty,
    Text(String),
    Node(Description, Vec<Attribute<M>>, Vec<Element<M>>),
    TaggedNode(String, Description, Vec<Attribute<M>>, Vec<Element<M>>),
    Raw(Html<M>),
    /// `Ui.cells`: a raw terminal cell grid (rows of characters), painted
    /// verbatim by the terminal backend and embeddable as an island inside an
    /// otherwise-structured `Ipe.Ui` view under `Tui.tea`.
    Cells(Vec<Vec<char>>),
}

/// Tagged elements that present a box of their own with no child content: an
/// image, a rule, a form control, or an embedded document, video or gauge.
/// `input` and `audio` are judged by `presents_itself`, and the other void
/// tags (`br`, `wbr`, and the metadata and table-column tags) present nothing.
const SELF_PRESENTING_TAGS: [&str; 12] = [
    "img", "hr", "embed", "textarea", "select", "iframe", "object", "canvas", "video", "progress",
    "meter", "input",
];

/// True when a tagged element presents a box of its own whatever its children:
/// a `SELF_PRESENTING_TAGS` member, except an `input` whose first `type`
/// attribute is `hidden`, and an `audio` only when it carries `controls` (an
/// `audio` without them renders nothing).
fn presents_itself<M>(tag: &str, attrs: &[Attribute<M>]) -> bool {
    if tag.eq_ignore_ascii_case("audio") {
        return attrs.iter().any(|a| {
            matches!(a, Attribute::AttrAttribute(name, _) if name.eq_ignore_ascii_case("controls"))
        });
    }
    if tag.eq_ignore_ascii_case("input") {
        let input_type = attrs.iter().find_map(|a| match a {
            Attribute::AttrAttribute(name, value) if name.eq_ignore_ascii_case("type") => {
                Some(value.as_str())
            }
            _ => None,
        });
        return !input_type.is_some_and(|t| t.trim().eq_ignore_ascii_case("hidden"));
    }
    SELF_PRESENTING_TAGS
        .iter()
        .any(|t| tag.eq_ignore_ascii_case(t))
}

/// True when an element renders something visible or announced.
///
/// An empty element, a text leaf of Unicode `White_Space` only, and a
/// container whose every child is itself empty have no content. A tagged
/// element that presents itself (`presents_itself`: an image, a visible input
/// control, a `textarea`, a `select`, embedded media), a node carrying an
/// `AttrNearby` overlay, raw markup and a cell grid have content. The walk is iterative and
/// stops at `MAX_HTML_DEPTH`, where it answers true so the render's own depth
/// ceiling decides.
#[must_use]
pub fn has_content<M>(elem: &Element<M>) -> bool {
    let mut pending: Vec<(&Element<M>, usize)> = vec![(elem, 0)];
    while let Some((node, depth)) = pending.pop() {
        if depth >= crate::html::MAX_HTML_DEPTH {
            return true;
        }
        let below = depth.saturating_add(1);
        match node {
            Element::Empty => {}
            Element::Text(s) => {
                if s.chars().any(|c| !c.is_whitespace()) {
                    return true;
                }
            }
            Element::Node(_, attrs, kids) => {
                if has_overlay(attrs) {
                    return true;
                }
                pending.extend(kids.iter().map(|k| (k, below)));
            }
            Element::TaggedNode(tag, _, attrs, kids) => {
                if presents_itself(tag, attrs) || has_overlay(attrs) {
                    return true;
                }
                pending.extend(kids.iter().map(|k| (k, below)));
            }
            Element::Raw(_) | Element::Cells(_) => return true,
        }
    }
    false
}

/// True when a node carries an `AttrNearby` overlay, which renders whatever
/// the node's own children are.
fn has_overlay<M>(attrs: &[Attribute<M>]) -> bool {
    attrs
        .iter()
        .any(|a| matches!(a, Attribute::AttrNearby(_, _)))
}

/// What the first child of a node contributes as a section heading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionHead {
    /// The node is not a `DescSection`, or its first child is not a
    /// `DescSectionHeading`.
    NoHeading,
    /// The section's first child is a heading with no content: it renders
    /// nothing and the heading level is kept.
    Empty,
    /// The section's first child is a heading with content: the section's
    /// descendants rank one level deeper.
    Present,
}

/// Classify a node's first child as its section heading. HTML and the terminal
/// share this one rule, so only a section's first child is ever its heading,
/// and only a `Node` heading: a `TaggedNode` renders its written tag and ranks
/// nothing below it.
///
/// Cost: each call walks the first child's subtree once (`has_content`, which
/// stops at the first content). A node lies inside at most `MAX_HTML_DEPTH / 2`
/// enclosing first-child headings, since a section and its heading take two
/// levels and both renderers stop at a depth of 1024, so a render walks each
/// node at most 512 times beyond its own visit.
#[must_use]
pub fn section_head<M>(desc: &Description, kids: &[Element<M>]) -> SectionHead {
    if !matches!(desc, Description::DescSection) {
        return SectionHead::NoHeading;
    }
    let Some(first) = kids.first() else {
        return SectionHead::NoHeading;
    };
    match first {
        Element::Node(Description::DescSectionHeading, _, _) => {
            if has_content(first) {
                SectionHead::Present
            } else {
                SectionHead::Empty
            }
        }
        Element::Node(_, _, _)
        | Element::TaggedNode(_, _, _, _)
        | Element::Empty
        | Element::Text(_)
        | Element::Raw(_)
        | Element::Cells(_) => SectionHead::NoHeading,
    }
}

/// Move every `Element` nested inside a node's attributes (an `AttrNearby`
/// overlay is the one attribute variant that carries an `Element`) onto the
/// worklist, so an overlay chain is dismantled iteratively alongside the child
/// chain rather than recursing. The attributes themselves are consumed here;
/// what remains after this call holds no further `Element`.
fn drain_nearby_overlays<M>(attrs: &mut Vec<Attribute<M>>, pending: &mut Vec<Element<M>>) {
    for attr in std::mem::take(attrs) {
        if let Attribute::AttrNearby(_, overlay) = attr {
            pending.push(overlay);
        }
        // Every other attribute (including `AttrEvent`, whose `Html` self-drops
        // iteratively) drops here without descending into an `Element`.
    }
}

impl<M> super::super::html::TrustedRawChild for Element<M> {
    /// Only a `Ui.html` wrapper around a trusted raw `Html` node counts; every
    /// other element is layout or text the safe surface built.
    fn is_trusted_raw(&self) -> bool {
        matches!(self, Element::Raw(Html::HRaw(_)))
    }
}

impl<M> Drop for Element<M> {
    /// Dismantle the layout tree iteratively so dropping a deeply nested
    /// `Element` can never overflow the native stack. An `Element` tree's depth
    /// is data-influenced (a materialized view or decoded template whose nesting
    /// tracks model or untrusted input), so the derived recursive destructor
    /// would abort the process on a deep tree. Draining each node's children —
    /// and the `Element` an `AttrNearby` overlay carries — onto an explicit heap
    /// worklist keeps teardown O(depth) heap and O(1) stack. A nested `Raw(Html)`
    /// carries its own iterative destructor, so it too drops without recursion
    /// once this node's fields fall.
    fn drop(&mut self) {
        let mut pending: Vec<Element<M>> = Vec::new();
        match self {
            Element::Node(_, attrs, children) | Element::TaggedNode(_, _, attrs, children) => {
                pending.append(&mut std::mem::take(children));
                drain_nearby_overlays(attrs, &mut pending);
            }
            Element::Empty | Element::Text(_) | Element::Raw(_) | Element::Cells(_) => return,
        }
        while let Some(mut node) = pending.pop() {
            match &mut node {
                Element::Node(_, attrs, children) | Element::TaggedNode(_, _, attrs, children) => {
                    pending.append(&mut std::mem::take(children));
                    drain_nearby_overlays(attrs, &mut pending);
                }
                Element::Empty | Element::Text(_) | Element::Raw(_) | Element::Cells(_) => {}
            }
            // `node` (now child- and overlay-free) drops here without recursion.
        }
    }
}

// ─── Show rows for the Ipe.Ui runtime types ─────────────────────────────────
// `Internals` leaves: a generated record or Model holding one renders the
// `<Module.Type>` marker, never the tree or its `M` payload.
crate::stringify::show_row!("Length", Internals, [] Length, |_| "<Ipe.Ui.Length>".to_owned());
crate::stringify::show_row!("HAlign", Internals, [] HAlign, |_| "<Ipe.Ui.HAlign>".to_owned());
crate::stringify::show_row!("VAlign", Internals, [] VAlign, |_| "<Ipe.Ui.VAlign>".to_owned());
crate::stringify::show_row!("Location", Internals, [] Location, |_| "<Ipe.Ui.Location>".to_owned());
crate::stringify::show_row!("PseudoClass", Internals, [] PseudoClass, |_| "<Ipe.Ui.PseudoClass>".to_owned());
crate::stringify::show_row!("Description", Internals, [] Description, |_| "<Ipe.Ui.Description>".to_owned());
crate::stringify::show_row!("LayoutContext", Internals, [] LayoutContext, |_| "<Ipe.Ui.LayoutContext>".to_owned());
crate::stringify::show_row!("UiAttribute", Internals, [M] Attribute<M>, |_| "<Ipe.Ui.Attribute>".to_owned());
crate::stringify::show_row!("Element", Internals, [M] Element<M>, |_| "<Ipe.Ui.Element>".to_owned());

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    // SSOT: the inline-style path, the `Ui.colorCss` kernel, and the direct
    // `Color::css` renderer must format one colour byte-identically. A second
    // renderer for the same value would break exactly this assertion.
    #[test]
    fn colour_renders_identically_across_paths() {
        let c = crate::color::Color::rgba(18, 52, 86, 0.5);
        let direct = c.to_css_rgba();
        let kernel = super::super::helpers::ui_color_css_(c);

        enum Msg {}
        let style = super::super::render::build_style_string(&[Attribute::<Msg>::AttrBgColor(c)]);

        assert_eq!(direct, "rgba(18,52,86,0.5)");
        assert_eq!(kernel, direct);
        assert_eq!(style, format!("background-color:{direct}"));
    }

    // SSOT: a length formats identically through the inline-style path (sized
    // with no flex parent) and the direct `Length::css` renderer, including the
    // recursive `Min`/`Max` arms.
    #[test]
    fn length_renders_identically_across_paths() {
        let len = Length::Max(320, Box::new(Length::Vh(80)));
        let direct = len.css();

        enum Msg {}
        let style =
            super::super::render::block_style_string(&[Attribute::<Msg>::AttrWidth(len.clone())]);

        assert_eq!(direct, "min(320px,80vh)");
        assert_eq!(style, format!("width:{direct}"));

        let floor = Length::Min(100, Box::new(Length::Fill(Portion::ONE)));
        assert_eq!(floor.css(), "max(100px,100%)", "minimum is a lower bound");
    }

    // Cross-language SSOT equivalence: `Length::css` output must be byte-for-byte
    // identical to `Ipe.Css.lengthToString` for every shared value shape.
    //
    // Shared shapes: `Px n`, `Vh n`, `Vw n`.
    // Out of scope (no `Ipe.Css` spelling): `Fill`/`Content`/`Min`/`Max` are
    // layout-intent lengths in `Ipe.Ui` with no counterpart in `Ipe.Css`.
    // The `.ipe` side of this assertion is exercised by the
    // `golden_css_length_color_ssot` fixture in the `g_stdui` integration suite.
    #[test]
    fn length_css_matches_ipe_css_length_to_string_for_shared_shapes() {
        assert_eq!(Length::Px(0).css(), "0px");
        assert_eq!(Length::Px(16).css(), "16px");
        assert_eq!(Length::Px(100).css(), "100px");
        assert_eq!(Length::Vh(50).css(), "50vh");
        assert_eq!(Length::Vh(100).css(), "100vh");
        assert_eq!(Length::Vw(50).css(), "50vw");
        assert_eq!(Length::Vw(100).css(), "100vw");
    }

    // Cross-language SSOT equivalence: `Color::css` output must be byte-for-byte
    // identical to `Ipe.Css.colorToString` for the shared `Rgba` shape.
    //
    // Alpha formatting: uses the `'g'`-format float rule.
    // For `1.0` that yields `"1"` (no trailing `.0`); for `0.5` it yields `"0.5"`.
    // The `.ipe` side of this assertion is exercised by the
    // `golden_css_length_color_ssot` fixture in the `g_stdui` integration suite.
    #[test]
    fn color_css_matches_ipe_css_color_to_string_for_rgba() {
        use crate::color::Color as C;
        assert_eq!(C::rgba(0, 0, 0, 1.0).to_css_rgba(), "rgba(0,0,0,1)");
        assert_eq!(C::rgba(255, 0, 0, 1.0).to_css_rgba(), "rgba(255,0,0,1)");
        assert_eq!(C::rgba(0, 128, 255, 1.0).to_css_rgba(), "rgba(0,128,255,1)");
        assert_eq!(C::rgba(0, 0, 0, 0.0).to_css_rgba(), "rgba(0,0,0,0)");
        assert_eq!(
            C::rgba(255, 128, 0, 0.5).to_css_rgba(),
            "rgba(255,128,0,0.5)"
        );
    }
}

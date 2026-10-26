//! Static-`Ipe.Ui`-subtree partition: recognise a provably-static `Ipe.Ui`
//! `view` subtree in the IR and reduce it to an inert serialized template the
//! runtime materializes at render — the `Ipe.Ui` analogue of
//! [`crate::emit_template`].
//!
//! A subtree is TEMPLATABLE (pure mode, [`ui_template_of_expr`]) iff it is built
//! entirely from the literal `Ipe.Ui` element node kernels (`UiNode` /
//! `UiTaggedNode` / `UiText` / `UiNone`) over literal arguments, an inert
//! attribute set, and a static role `Description`. Any `Model` read
//! ([`Expr::Var`] / [`Expr::Access`]), control flow ([`Expr::If`] /
//! [`Expr::Match`]), event handler, embedded raw HTML (`Ui.html`), record-config
//! builder (`Ui.button` / `Ui.link` / `Ui.image`), or non-literal argument
//! anywhere fails the match, so an unprovable subtree stays compiled — the
//! recompile path, conservative by construction.
//!
//! ## Holes ([`ui_template_of_expr_holes`])
//!
//! The hole-bearing partition admits a mostly-static subtree with `Model`-derived
//! **holes**, each replaced by a numbered marker plus a compiled fill:
//! - a `Model`-derived value leaf (`Ui.text (…model…)`) or control-flow
//!   ([`Expr::If`] / [`Expr::Match`]) in element position → a single
//!   [`CompileUiTemplate::Hole`] + an [`HoleKind::Element`] fill;
//! - a `List.map` comprehension in children-list position →
//!   [`CompileUiTemplate::ChildrenHole`] + an [`HoleKind::Children`] fill.
//!
//! Everything else stays as conservative as pure mode: a handler, raw markup, a
//! record-config builder, or a non-literal attribute still refuses the whole
//! subtree — a hole never covers a handler (that is the deferred, guardian-gated
//! increment). Hole indices are numbered per-KIND so the emit's two ordered fill
//! vecs land each fill where its marker names it.
//!
//! ## Conservative attribute scope
//!
//! The accepted attribute set covers the integer / string / marker attributes and
//! integer-valued `Length`s, plus the single-`Color` and single-`Float`
//! attributes: `Font.color` / `Background.color` / `Border.color` (each over a
//! literal `Ui.rgb` / `Ui.rgba` / `Ui.white` / `Ui.black` / `Ui.transparent`
//! color), and `Font.letterSpacing` / `Font.wordSpacing` (over a `Float`
//! literal). The float spelling in the baked JSON is produced by `ryu`
//! ([`push_f64`]) — the exact formatter `serde_json`'s `write_f64` uses — so it is
//! byte-identical to the runtime's serde form, single source of truth with no
//! hand-rolled float formatter to drift.
//!
//! Still refused (always safe — a refused attribute recompiles): the shadow
//! record attributes (`Border.shadow` / `Border.innerShadow`, whose
//! `{offsetX, offsetY, blur, spread, color}` record arg is a distinct reduction
//! shape), aspect ratio, gradients, a `Model`-derived color/float, and any
//! non-literal argument. The runtime datum carries the full set, so widening the
//! compiler accept set further needs no runtime change.
//!
//! ## Inert by construction
//!
//! A [`CompileUiTemplate`] carries only tag / attribute / text `String`s, `i64`s,
//! `f64` style values, and hole INDICES (`usize`) — it has no handler and no
//! raw-markup variant, mirroring the runtime `UiTemplate`. A hole is an inert
//! index, never logic: the `Model`-derived value it stands for is compiled
//! separately and passed to the materializer, so no template datum — however
//! patched — can smuggle a `Msg`, a handler, or unescaped markup. Its JSON
//! ([`CompileUiTemplate::to_json`]) is byte-identical to
//! the runtime `UiTemplate`'s serde form (pinned by a test), so the emitted
//! baked default decodes back into exactly the tree it described and
//! materializes byte-identically to the direct inline emit — dev == prod.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::emit_template::write_json_string;
use ipe_intern::Symbol;
use ipe_ir::{Callee, Expr, FuncId, KernelFn, Match};

/// The render/decode nesting ceiling, mirrored from the runtime
/// (`ipe_runtime::ui::template::MAX_UI_TEMPLATE_DEPTH`). Kept as a local constant
/// (the backend does not depend on the runtime crate outside tests); it equals
/// [`crate::emit_template::MAX_TEMPLATE_DEPTH`], the same HTML render depth cap.
pub const MAX_UI_TEMPLATE_DEPTH: usize = crate::emit_template::MAX_TEMPLATE_DEPTH;

/// A role `Description` reduced to inert data — the producible subset of the
/// runtime `ipe_runtime::ui::template::UiDescription`. The runtime's `DescButton`
/// has no templatable producing kernel (only `Ui.button`, a refused record
/// config, carries it), so it is deliberately absent here; every variant present
/// serializes to the same JSON the runtime decodes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileUiDesc {
    NoDescription,
    DescMain,
    DescNavigation,
    DescContentInfo,
    DescComplementary,
    DescHeading(i64),
    DescLabel(String),
    DescLivePolite,
    DescLiveAssertive,
    DescParagraph,
}

impl CompileUiDesc {
    fn write_json(&self, out: &mut String) {
        match self {
            Self::NoDescription => out.push_str("\"NoDescription\""),
            Self::DescMain => out.push_str("\"DescMain\""),
            Self::DescNavigation => out.push_str("\"DescNavigation\""),
            Self::DescContentInfo => out.push_str("\"DescContentInfo\""),
            Self::DescComplementary => out.push_str("\"DescComplementary\""),
            Self::DescHeading(n) => {
                out.push_str("{\"DescHeading\":");
                push_i64(*n, out);
                out.push('}');
            }
            Self::DescLabel(s) => {
                out.push_str("{\"DescLabel\":");
                write_json_string(s, out);
                out.push('}');
            }
            Self::DescLivePolite => out.push_str("\"DescLivePolite\""),
            Self::DescLiveAssertive => out.push_str("\"DescLiveAssertive\""),
            Self::DescParagraph => out.push_str("\"DescParagraph\""),
        }
    }
}

/// A `Color` reduced to inert data — the single `Rgba` shape. Mirrors the runtime
/// `ipe_runtime::ui::template::UiColor` field-for-field. The alpha channel is a
/// `Float`; it serializes through `serde_json` ([`push_f64`]) so the baked JSON is
/// byte-identical to the runtime's `#[derive(Serialize)]` form (single source of
/// truth for the float spelling — no hand-rolled float formatter to drift).
#[derive(Clone, Debug, PartialEq)]
pub struct CompileUiColor {
    pub r: i64,
    pub g: i64,
    pub b: i64,
    pub a: f64,
}

impl CompileUiColor {
    fn write_json(&self, out: &mut String) {
        out.push_str("{\"r\":");
        push_i64(self.r, out);
        out.push_str(",\"g\":");
        push_i64(self.g, out);
        out.push_str(",\"b\":");
        push_i64(self.b, out);
        out.push_str(",\"a\":");
        push_f64(self.a, out);
        out.push('}');
    }
}

/// A `Length` reduced to inert data — integer-valued shapes only. Mirrors the
/// runtime `UiLength`; the `Min` / `Max` recursive shapes carry an inner length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileUiLength {
    Px(i64),
    Content,
    Fill(i64),
    Min(i64, Box<Self>),
    Max(i64, Box<Self>),
    Vh(i64),
    Vw(i64),
}

impl CompileUiLength {
    fn write_json(&self, out: &mut String) {
        match self {
            Self::Px(n) => tagged_i64("Px", *n, out),
            Self::Content => out.push_str("\"Content\""),
            Self::Fill(n) => tagged_i64("Fill", *n, out),
            Self::Vh(n) => tagged_i64("Vh", *n, out),
            Self::Vw(n) => tagged_i64("Vw", *n, out),
            Self::Min(n, inner) => tagged_i64_len("Min", *n, inner, out),
            Self::Max(n, inner) => tagged_i64_len("Max", *n, inner, out),
        }
    }
}

/// An inert, static `Ipe.Ui` attribute — the integer / string / marker / color /
/// float subset of the runtime `UiTemplateAttr`. Each variant serializes to the
/// same JSON the runtime `UiTemplateAttr` decodes.
///
/// `Eq` is deliberately absent: the color and letter/word-spacing variants carry a
/// `Float`, which is not `Eq`. `PartialEq` (structural, including the float bits)
/// is enough for the byte-identity pins and the classifier's value diff.
#[derive(Clone, Debug, PartialEq)]
pub enum CompileUiAttr {
    Width(CompileUiLength),
    Height(CompileUiLength),
    AlignX(&'static str),
    AlignY(&'static str),
    Padding(i64, i64, i64, i64),
    Spacing(i64),
    Style(String, String),
    Describe(CompileUiDesc),
    Attribute(String, String),
    FontSize(i64),
    FontFamily(String),
    FontWeight(i64),
    FontItalic,
    FontUnderline,
    FontDecoration(&'static str),
    FontAlign(&'static str),
    FontColor(CompileUiColor),
    FontLetterSpacing(f64),
    FontWordSpacing(f64),
    BgColor(CompileUiColor),
    BorderWidth(i64),
    BorderRounded(i64),
    BorderStyle(&'static str),
    BorderColor(CompileUiColor),
    Pointer,
    Overflow(&'static str, &'static str),
    /// A model-dependent event handler reduced to an opaque HOLE: the DOM event
    /// wire name and a compile-time-stable hole id, never the `Msg`. Mirrors the
    /// runtime `UiTemplateAttr::HandlerHole`; the concrete `Msg` is resolved per
    /// render from the `UiHandlerMap` the emitted `view` supplies, so this inert
    /// datum carries no logic across the template transport.
    HandlerHole {
        event: &'static str,
        handler_id: u32,
    },
    /// A model-dependent numeric (`f64`) attribute value reduced to an opaque
    /// HOLE: the attribute discriminant name and a compile-time-stable hole id.
    /// Mirrors the runtime `UiTemplateAttr::AttrHoleFloat`. The concrete `f64`
    /// is resolved per render from the `float_attr_fills` slice the emitted
    /// `view` supplies — the model-dependent value lives only in that compiled
    /// expression, never in this inert datum.
    AttrHoleFloat {
        /// The attribute discriminant name the runtime uses to reconstruct the
        /// matching `Attribute` variant (`"font-letter-spacing"`, …).
        attr: &'static str,
        hole_id: u32,
    },
}

impl CompileUiAttr {
    fn write_json(&self, out: &mut String) {
        match self {
            Self::Width(l) => {
                out.push_str("{\"Width\":");
                l.write_json(out);
                out.push('}');
            }
            Self::Height(l) => {
                out.push_str("{\"Height\":");
                l.write_json(out);
                out.push('}');
            }
            Self::AlignX(v) => tagged_enum_str("AlignX", v, out),
            Self::AlignY(v) => tagged_enum_str("AlignY", v, out),
            Self::Padding(t, r, b, l) => {
                out.push_str("{\"Padding\":[");
                push_i64(*t, out);
                out.push(',');
                push_i64(*r, out);
                out.push(',');
                push_i64(*b, out);
                out.push(',');
                push_i64(*l, out);
                out.push_str("]}");
            }
            Self::Spacing(n) => tagged_i64("Spacing", *n, out),
            Self::Style(k, v) => tagged_two_strings("Style", k, v, out),
            Self::Describe(d) => {
                out.push_str("{\"Describe\":");
                d.write_json(out);
                out.push('}');
            }
            Self::Attribute(k, v) => tagged_two_strings("Attribute", k, v, out),
            Self::FontSize(n) => tagged_i64("FontSize", *n, out),
            Self::FontFamily(s) => tagged_string("FontFamily", s, out),
            Self::FontWeight(n) => tagged_i64("FontWeight", *n, out),
            Self::FontItalic => out.push_str("\"FontItalic\""),
            Self::FontUnderline => out.push_str("\"FontUnderline\""),
            Self::FontDecoration(v) => tagged_enum_static_str("FontDecoration", v, out),
            Self::FontAlign(v) => tagged_enum_static_str("FontAlign", v, out),
            Self::FontColor(c) => tagged_color("FontColor", c, out),
            Self::FontLetterSpacing(v) => tagged_f64("FontLetterSpacing", *v, out),
            Self::FontWordSpacing(v) => tagged_f64("FontWordSpacing", *v, out),
            Self::BgColor(c) => tagged_color("BgColor", c, out),
            Self::BorderWidth(n) => tagged_i64("BorderWidth", *n, out),
            Self::BorderRounded(n) => tagged_i64("BorderRounded", *n, out),
            Self::BorderStyle(v) => tagged_enum_static_str("BorderStyle", v, out),
            Self::BorderColor(c) => tagged_color("BorderColor", c, out),
            Self::Pointer => out.push_str("\"Pointer\""),
            Self::Overflow(x, y) => {
                out.push_str("{\"Overflow\":[");
                write_json_string(x, out);
                out.push(',');
                write_json_string(y, out);
                out.push_str("]}");
            }
            // `{"HandlerHole":{"event":"click","handler_id":N}}` — the runtime
            // `UiTemplateAttr::HandlerHole` struct-variant serde form.
            Self::HandlerHole { event, handler_id } => {
                out.push_str("{\"HandlerHole\":{\"event\":");
                write_json_string(event, out);
                out.push_str(",\"handler_id\":");
                push_i64(i64::from(*handler_id), out);
                out.push_str("}}");
            }
            // `{"AttrHoleFloat":{"attr":"font-letter-spacing","hole_id":N}}` —
            // the runtime `UiTemplateAttr::AttrHoleFloat` struct-variant serde form.
            Self::AttrHoleFloat { attr, hole_id } => {
                out.push_str("{\"AttrHoleFloat\":{\"attr\":");
                write_json_string(attr, out);
                out.push_str(",\"hole_id\":");
                push_i64(i64::from(*hole_id), out);
                out.push_str("}}");
            }
        }
    }
}

/// An inert, fully-static `Ipe.Ui` subtree reduced to data. Mirrors the runtime
/// `UiTemplate`: there is deliberately no `Raw`, no `Cells`, and no
/// handler-bearing attribute variant — that absence is the security guarantee,
/// enforced by the type (make-invalid-states-unrepresentable).
///
/// `Eq` is absent (an attribute may carry a `Float` alpha, which is not `Eq`),
/// matching the runtime `UiTemplate`; `PartialEq` is enough for the pins.
#[derive(Clone, Debug, PartialEq)]
pub enum CompileUiTemplate {
    Empty,
    Text(String),
    /// A single-element hole (index into the per-render element-fill slice): a
    /// `Model`-derived value leaf or an opaque control-flow result (when arms are
    /// not all individually templatizable). Inert — carries only an index; the
    /// fill is compiled separately.
    Hole(usize),
    /// A children hole (index into the per-render children-fill slice): a
    /// `List.map` comprehension expanding to a run of sibling elements.
    ChildrenHole(usize),
    /// A model-driven control-flow branch (`if` / `case`) whose every arm is
    /// itself a templatizable subtree. The compiled `view` resolves the branch and
    /// supplies the zero-based arm index; the runtime picks `arms[arm_index]` and
    /// materializes that subtree.
    ///
    /// Exhaustive by construction: every arm of the source `if`/`case` is
    /// captured (true→arm 0, false→arm 1 for `if`; source pattern order for
    /// `case`), so no reachable branch is missing from the template. An
    /// out-of-range arm index (stale template after an arm count edit) materializes
    /// to the inert empty element at the runtime layer — fail-closed.
    ControlFlowHole {
        /// Index into the per-render arm-selector vec. `cf_selectors[hole_id]` is
        /// the zero-based arm chosen this render.
        hole_id: usize,
        /// Templatized subtrees, one per source arm (true/false for `if`; pattern
        /// order for `case`).
        arms: Vec<Self>,
    },
    /// A `List.map f xs` comprehension in children position whose item function
    /// body is itself templatizable. The item template is compiled ONCE; the
    /// runtime materializes it per item, substituting each item's hole fills.
    /// `hole_id` indexes into the per-render list-item-fills slice.
    ///
    /// When the item body is non-templatizable, the whole `List.map` falls back
    /// to a [`Self::ChildrenHole`] — the compiled view pre-expands the children
    /// list and the runtime splices it in place, unchanged from before this step.
    ListHole {
        /// Index into the per-render list-item-fills slice. Index `hole_id` is
        /// the `Vec<ItemFills>` for this list position — one entry per item.
        hole_id: usize,
        /// Template compiled from the item function body with item-parameter
        /// reads replaced by numbered [`Self::Hole`] markers. The runtime
        /// materializes this template once per item, substituting that item's
        /// element fills.
        item_template: Box<Self>,
    },
    /// A model-chosen wrapping element around a fixed child subtree. The wrapper
    /// variant — `UiTaggedNode` or `UiNode` with its tag and attrs — is chosen
    /// at render from the per-render wrapper-fill slice; the child subtree is
    /// fixed and may itself carry holes.
    ///
    /// The recognizer admits an `if`/`case` in element position whose arms are
    /// ALL element-node calls (`UiTaggedNode` / `UiNode`) with IDENTICAL children
    /// and only the tag/attrs differing. Conservative: any arm whose tag/attrs are
    /// non-literal, or any arms with different children, refuses and falls back.
    WrapperHole {
        /// Index into the per-render wrapper-fill slice. Index `hole_id` is the
        /// wrapper template chosen for this position this render.
        hole_id: usize,
        /// The fixed child subtree, templatized once. May itself carry value,
        /// handler, control-flow, or list holes.
        child: Box<Self>,
    },
    Node {
        desc: CompileUiDesc,
        attrs: Vec<CompileUiAttr>,
        children: Vec<Self>,
    },
    TaggedNode {
        tag: String,
        desc: CompileUiDesc,
        attrs: Vec<CompileUiAttr>,
        children: Vec<Self>,
    },
}

impl CompileUiTemplate {
    /// Serialize to the JSON the runtime `UiTemplate` decodes — the externally
    /// tagged enum representation `serde_json` emits by default. Byte-identical
    /// to `serde_json::to_string(&UiTemplate)` (pinned by a backend test).
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out);
        out
    }

    fn write_json(&self, out: &mut String) {
        match self {
            Self::Empty => out.push_str("\"Empty\""),
            Self::Text(s) => tagged_string("Text", s, out),
            Self::Hole(n) => tagged_usize("Hole", *n, out),
            Self::ChildrenHole(n) => tagged_usize("ChildrenHole", *n, out),
            // `{"ControlFlowHole":{"hole_id":N,"arms":[...]}}` — the runtime
            // `UiTemplate::ControlFlowHole` struct-variant serde form.
            Self::ControlFlowHole { hole_id, arms } => {
                out.push_str("{\"ControlFlowHole\":{\"hole_id\":");
                let _ = write!(out, "{hole_id}");
                out.push_str(",\"arms\":[");
                write_children(arms, out);
                out.push_str("]}}");
            }
            // `{"ListHole":{"hole_id":N,"item_template":<template>}}` — mirrors
            // the runtime `UiTemplate::ListHole` struct-variant serde form.
            Self::ListHole {
                hole_id,
                item_template,
            } => {
                out.push_str("{\"ListHole\":{\"hole_id\":");
                let _ = write!(out, "{hole_id}");
                out.push_str(",\"item_template\":");
                item_template.write_json(out);
                out.push_str("}}");
            }
            // `{"WrapperHole":{"hole_id":N,"child":<template>}}` — mirrors
            // the runtime `UiTemplate::WrapperHole` struct-variant serde form.
            Self::WrapperHole { hole_id, child } => {
                out.push_str("{\"WrapperHole\":{\"hole_id\":");
                let _ = write!(out, "{hole_id}");
                out.push_str(",\"child\":");
                child.write_json(out);
                out.push_str("}}");
            }
            Self::Node {
                desc,
                attrs,
                children,
            } => {
                out.push_str("{\"Node\":{\"desc\":");
                desc.write_json(out);
                out.push_str(",\"attrs\":[");
                write_attrs(attrs, out);
                out.push_str("],\"children\":[");
                write_children(children, out);
                out.push_str("]}}");
            }
            Self::TaggedNode {
                tag,
                desc,
                attrs,
                children,
            } => {
                out.push_str("{\"TaggedNode\":{\"tag\":");
                write_json_string(tag, out);
                out.push_str(",\"desc\":");
                desc.write_json(out);
                out.push_str(",\"attrs\":[");
                write_attrs(attrs, out);
                out.push_str("],\"children\":[");
                write_children(children, out);
                out.push_str("]}}");
            }
        }
    }
}

fn write_attrs(attrs: &[CompileUiAttr], out: &mut String) {
    for (i, a) in attrs.iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        a.write_json(out);
    }
}

fn write_children(children: &[CompileUiTemplate], out: &mut String) {
    for (i, c) in children.iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        c.write_json(out);
    }
}

/// `serde_json` renders an `i64` as its plain decimal — total, no allocation.
fn push_i64(n: i64, out: &mut String) {
    use std::fmt::Write as _;
    let _ = write!(out, "{n}");
}

/// Append `f`'s JSON spelling exactly as the runtime's `#[derive(Serialize)]`
/// would — `serde_json`'s `write_f64` formats an `f64` with
/// `ryu::Buffer::format_finite`, so using `ryu` here yields byte-identical output
/// (single source of truth; no hand-rolled float formatter to drift from
/// `serde_json`'s shortest-round-trip form).
///
/// A non-finite `f64` (`NaN` / `±∞`) has no JSON number form and `format_finite`
/// is documented only for finite inputs. Every capture site refuses a non-finite
/// literal (an `is_finite` guard on each `Float` arm), so this function only ever
/// receives a finite value; the non-finite arm is a total fallback that emits
/// `0.0` (a finite, decodable value) rather than an undecodable token, keeping the
/// function total.
fn push_f64(f: f64, out: &mut String) {
    if f.is_finite() {
        let mut buf = ryu::Buffer::new();
        out.push_str(buf.format_finite(f));
    } else {
        out.push_str("0.0");
    }
}

fn tagged_f64(tag: &str, f: f64, out: &mut String) {
    out.push_str("{\"");
    out.push_str(tag);
    out.push_str("\":");
    push_f64(f, out);
    out.push('}');
}

/// `{"<tag>":{"r":R,"g":G,"b":B,"a":A}}` — the runtime `UiColor` struct form.
fn tagged_color(tag: &str, c: &CompileUiColor, out: &mut String) {
    out.push_str("{\"");
    out.push_str(tag);
    out.push_str("\":");
    c.write_json(out);
    out.push('}');
}

fn tagged_i64(tag: &str, n: i64, out: &mut String) {
    out.push_str("{\"");
    out.push_str(tag);
    out.push_str("\":");
    push_i64(n, out);
    out.push('}');
}

/// A single-newtype variant carrying a `usize` (a hole index). `serde_json`
/// renders a `usize` as its plain decimal — the same spelling the runtime
/// `UiTemplate::Hole(usize)` serde form decodes.
fn tagged_usize(tag: &str, n: usize, out: &mut String) {
    use std::fmt::Write as _;
    out.push_str("{\"");
    out.push_str(tag);
    out.push_str("\":");
    let _ = write!(out, "{n}");
    out.push('}');
}

fn tagged_i64_len(tag: &str, n: i64, inner: &CompileUiLength, out: &mut String) {
    out.push_str("{\"");
    out.push_str(tag);
    out.push_str("\":[");
    push_i64(n, out);
    out.push(',');
    inner.write_json(out);
    out.push_str("]}");
}

fn tagged_string(tag: &str, s: &str, out: &mut String) {
    out.push_str("{\"");
    out.push_str(tag);
    out.push_str("\":");
    write_json_string(s, out);
    out.push('}');
}

fn tagged_two_strings(tag: &str, a: &str, b: &str, out: &mut String) {
    out.push_str("{\"");
    out.push_str(tag);
    out.push_str("\":[");
    write_json_string(a, out);
    out.push(',');
    write_json_string(b, out);
    out.push_str("]}");
}

/// A single-newtype attr carrying a `String` variant tag (`AlignX(HAlign)` etc.)
/// — the payload is the runtime enum variant name as a plain JSON string.
fn tagged_enum_str(tag: &str, variant: &str, out: &mut String) {
    out.push_str("{\"");
    out.push_str(tag);
    out.push_str("\":\"");
    out.push_str(variant);
    out.push_str("\"}");
}

/// A single-newtype attr carrying a raw `String` payload built from a `&'static
/// str` (`FontDecoration(String)` etc.) — the payload is an ordinary JSON string
/// and must be escaped like any other.
fn tagged_enum_static_str(tag: &str, s: &str, out: &mut String) {
    tagged_string(tag, s, out);
}

/// A structural `Ipe.Ui` wrapper function's parameter symbols and lowered body.
///
/// Qualifies when the body is a single `UiNode` / `UiTaggedNode` / `UiText` /
/// `UiNone` kernel call over params and static descriptions — pure, no Model
/// read, no handler, no control flow, no capability. `el` / `row` / `column` /
/// `wrappedRow` / `grid` / `paragraph` / `textColumn` / `form` / `input` all
/// qualify. The params list is positional and matches the function signature;
/// `substitute_wrapper` replaces each param with the call-site argument.
pub type WrapperBody = (Vec<Symbol>, Expr);

/// One recognized hole and the `Model`-derived expression that fills it, in
/// index order. The emit compiles each `expr` in the surrounding element/child
/// position and passes the results to the runtime materializer, which splices
/// them at the matching `Hole` / `ChildrenHole` marker.
#[derive(Clone, Debug, PartialEq)]
pub struct HoleFill {
    /// The kind of runtime hole this fill supplies.
    pub kind: HoleKind,
    /// The original `Model`-derived expression, emitted by the caller in the
    /// hole's position (an `Element<M>` for a single hole, a `Vec<Element<M>>`
    /// for a children hole).
    pub expr: Expr,
}

/// Which runtime fill slice a [`HoleFill`] feeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoleKind {
    /// One `Element<M>` in a single position (a value leaf or an opaque
    /// control-flow result when arms are non-templatizable) — a
    /// [`CompileUiTemplate::Hole`].
    Element,
    /// A run of `Element<M>` spliced among a node's children (a `List.map`
    /// comprehension) — a [`CompileUiTemplate::ChildrenHole`].
    Children,
    /// A zero-based arm selector for a [`CompileUiTemplate::ControlFlowHole`]:
    /// the compiled `view` evaluates the condition / discriminant and produces
    /// the index of the arm to materialize (0 = true branch for `if`, pattern
    /// order for `case`). Feeds `cf_selectors[hole_id]` at the runtime layer.
    ControlFlow,
    /// A model-driven `f64` value for an [`CompileUiAttr::AttrHoleFloat`]: the
    /// compiled `view` evaluates the model expression and passes the concrete
    /// float to the runtime `float_attr_fills[hole_id]` slot. One fill per
    /// `AttrHoleFloat` in template order.
    FloatAttr,
}

/// Per-render fill for a [`CompileUiTemplate::ListHole`]: the list expression
/// (`xs`), the item parameter symbol, and one fill expression per value hole
/// in the item template (each may contain free references to `item_sym`).
///
/// The emit layer iterates `xs` and, per item bound to `item_sym`, evaluates
/// each `item_fills[i]` to produce that item's element-fill vector, then calls
/// the runtime materializer with those fills on the `item_template`.
#[derive(Clone, Debug, PartialEq)]
pub struct ListHoleFill {
    /// The list expression (`xs` in `List.map f xs`) iterated at render.
    pub xs: Expr,
    /// The symbol the item is bound to inside each `item_fills` expression.
    /// Corresponds to the single parameter of the source `Lambda`.
    pub item_sym: Symbol,
    /// One fill expression per [`CompileUiTemplate::Hole`] inside `item_template`,
    /// in hole-index order. Each expression may contain free references to
    /// [`Self::item_sym`]; the emit layer binds the current item before evaluating.
    pub item_fills: Vec<Expr>,
}

/// Per-render fill for a [`CompileUiTemplate::WrapperHole`]: the arm-selector
/// expression (evaluates to a `usize` arm index at render) and the arm wrapper
/// templates in source order — one per arm of the source `if`/`case`. The emit
/// layer evaluates the selector and passes `wrapper_arms[selector]` as the
/// wrapper-fill `UiTemplate` to the runtime materializer.
#[derive(Clone, Debug, PartialEq)]
pub struct WrapperHoleFill {
    /// Expression that evaluates to the zero-based arm index chosen this render.
    /// For an `if`: `if cond { 0usize } else { 1usize }`.
    pub selector_expr: Expr,
    /// The per-arm wrapper templates in source order. Each is a
    /// `CompileUiTemplate::TaggedNode` or `CompileUiTemplate::Node` with an
    /// empty `children` list — encoding only the wrapper tag / desc / attrs.
    /// The runtime materializer picks `wrapper_arms[selector]` and wraps the
    /// materialized child with it.
    pub wrapper_arms: Vec<CompileUiTemplate>,
}

/// The result of a hole-bearing partition: the (inert) template skeleton with
/// numbered hole markers, plus the compiled fills in index order.
#[derive(Clone, Debug, PartialEq)]
pub struct HolePartition {
    pub template: CompileUiTemplate,
    pub holes: Vec<HoleFill>,
    /// Model-dependent handler `Msg` expressions, in hole-id order. Each is
    /// emitted by the caller and passed to `UiHandlerMap::from_msgs`; a
    /// [`CompileUiAttr::HandlerHole`] with `handler_id` i resolves to index i.
    pub handlers: Vec<Expr>,
    /// Control-flow arm-selector expressions, in hole-id order. Each is emitted
    /// by the caller as a `usize`-typed expression (e.g. `if cond { 0usize } else
    /// { 1usize }`) and passed in the `cf_selectors` vec to the runtime
    /// materializer; a [`CompileUiTemplate::ControlFlowHole`] with `hole_id` i
    /// resolves to `cf_selectors[i]`.
    pub cf_holes: Vec<HoleFill>,
    /// List-hole fills, in hole-id order. Each [`ListHoleFill`] carries the list
    /// expression and per-item element-producer closures for a
    /// [`CompileUiTemplate::ListHole`] with `hole_id` i.
    pub list_holes: Vec<ListHoleFill>,
    /// Wrapper-hole fills, in hole-id order. Each [`WrapperHoleFill`] carries the
    /// arm-selector expression and per-arm wrapper templates for a
    /// [`CompileUiTemplate::WrapperHole`] with `hole_id` i.
    pub wrapper_holes: Vec<WrapperHoleFill>,
    /// Float-attr-hole fills, in hole-id order. Each [`HoleFill`] with kind
    /// [`HoleKind::FloatAttr`] carries the model-derived `f64` expression for
    /// the [`CompileUiAttr::AttrHoleFloat`] with `hole_id` i. The emitted `view`
    /// evaluates each and passes the concrete floats in order to the runtime's
    /// `float_attr_fills` parameter.
    pub float_attr_holes: Vec<HoleFill>,
}

/// The per-render capture accumulators threaded through the partition recursion:
/// the value/children hole fills, model-dependent handler `Msg` expressions,
/// control-flow arm-selector expressions, list-hole fills, and wrapper-hole fills
/// (each in hole-id order). All grow in place as the recursion records each hole,
/// handler capture, CF branch, list expansion, or wrapper selection.
#[derive(Default)]
struct Captures {
    /// Value / opaque-control-flow / `List.map` hole fills, in per-kind index order.
    holes: Vec<HoleFill>,
    /// Model-dependent handler `Msg` expressions, in hole-id order — index i is
    /// the `handler_id` of the [`CompileUiAttr::HandlerHole`] that captured it.
    handlers: Vec<Expr>,
    /// Control-flow arm-selector expressions, in hole-id order — index i is the
    /// `hole_id` of the [`CompileUiTemplate::ControlFlowHole`] that captured it.
    /// Each expression evaluates to a `usize` arm index at render.
    cf_holes: Vec<HoleFill>,
    /// List-hole fills, in hole-id order — index i is the [`ListHoleFill`] for
    /// the [`CompileUiTemplate::ListHole`] with `hole_id` i.
    list_holes: Vec<ListHoleFill>,
    /// Wrapper-hole fills, in hole-id order — index i is the [`WrapperHoleFill`]
    /// for the [`CompileUiTemplate::WrapperHole`] with `hole_id` i.
    wrapper_holes: Vec<WrapperHoleFill>,
    /// Float-attr-hole fills, in hole-id order — index i is the model-derived
    /// `f64` expression for the [`CompileUiAttr::AttrHoleFloat`] with `hole_id` i.
    float_attr_holes: Vec<HoleFill>,
}

/// The capture accumulator threaded through the partition recursion. `None` =
/// pure mode: holes and handler captures are disallowed, so a non-static
/// sub-expression (or any handler) refuses (`None`), exactly the shipped
/// behaviour. `Some` = capture mode: a `Model`-derived leaf, control-flow,
/// `List.map`, or model-dependent `onClick` handler is recorded and replaced by a
/// numbered marker / hole instead of refusing.
type Holes<'a> = Option<&'a mut Captures>;

/// Reduce a static `Ipe.Ui` `view` subtree to a [`CompileUiTemplate`] with NO
/// holes admitted (pure mode), or `None` when it is not provably fully static — a
/// `Model` read, control flow, or non-literal anywhere refuses. This is the
/// shipped, fully-static path; [`ui_template_of_expr_holes`] is the superset that
/// also admits `Model`-derived holes.
///
/// `wrappers` maps each recognized `Ipe.Ui` structural-wrapper [`FuncId`] to its
/// parameter list and lowered body. When `None`, wrapper resolution is skipped
/// (pure kernel path). A `Callee::Func` whose id is absent from `wrappers` falls
/// through to recompile — conservative, never a mis-hoist.
///
/// Test-only: the production emit uses [`ui_template_of_expr_holes`] and treats an
/// empty hole set as the pure case, so this convenience entry is exercised only by
/// the partition's own unit tests.
#[cfg(test)]
pub fn ui_template_of_expr(
    expr: &Expr,
    wrappers: Option<&BTreeMap<FuncId, WrapperBody>>,
) -> Option<CompileUiTemplate> {
    ui_template_of_expr_at(expr, wrappers, 0, &mut None)
}

/// Reduce a mostly-static `Ipe.Ui` `view` subtree to a template skeleton plus its
/// hole fills, or `None` when the subtree is not templatable even with holes.
///
/// A hole is admitted only in a hole-legal position and only for a shape the emit
/// can compile back byte-identically:
/// - a `Model`-derived value leaf or control-flow (`if` / `case`) in element
///   position → a single [`CompileUiTemplate::Hole`];
/// - a `List.map` comprehension in children-list position →
///   [`CompileUiTemplate::ChildrenHole`].
///
/// Everything else stays exactly as conservative as the pure path: a handler, raw
/// markup, a non-literal attribute, or an unrecognised callee still refuses the
/// whole subtree. A subtree with no holes yields an empty `holes` vec and the same
/// template the pure path would.
pub fn ui_template_of_expr_holes(
    expr: &Expr,
    wrappers: Option<&BTreeMap<FuncId, WrapperBody>>,
) -> Option<HolePartition> {
    let mut captures = Captures::default();
    let template = ui_template_of_expr_at(expr, wrappers, 0, &mut Some(&mut captures))?;
    Some(HolePartition {
        template,
        holes: captures.holes,
        handlers: captures.handlers,
        cf_holes: captures.cf_holes,
        list_holes: captures.list_holes,
        wrapper_holes: captures.wrapper_holes,
        float_attr_holes: captures.float_attr_holes,
    })
}

fn ui_template_of_expr_at(
    expr: &Expr,
    wrappers: Option<&BTreeMap<FuncId, WrapperBody>>,
    depth: usize,
    holes: &mut Holes,
) -> Option<CompileUiTemplate> {
    if depth >= MAX_UI_TEMPLATE_DEPTH {
        return None;
    }
    // A wrapper body may be lowered with a `let tmp = <expr> in <call>` for
    // intermediate computations (e.g. the cons prepend `style "k" "v" :: attrs`).
    // β-reduce the let: substitute `Var(name)` in `body` with `value`, then
    // recurse. Since wrapper bodies are one-level, the chain terminates quickly.
    if let Expr::Let { name, value, body } = expr {
        let reduced = subst_expr(body, &[*name], &[*value.clone()]);
        return ui_template_of_expr_at(&reduced, wrappers, depth, holes);
    }
    // A pre-clone run β-reduces the same way: each symbol's value is its own
    // clone.
    if let Expr::CaptureClones { syms, body } = expr {
        let clones: Vec<Expr> = syms.iter().copied().map(Expr::CloneVar).collect();
        let reduced = subst_expr(body, syms, &clones);
        return ui_template_of_expr_at(&reduced, wrappers, depth, holes);
    }
    // In hole mode, an element-position control-flow (`if` / `case`) over the
    // Model is classified by how far its arms templatize:
    //
    // - Every arm templatizable → `ControlFlowHole`: the arm subtrees ride the
    //   template, only the arm selector (a compiled `usize`) is the fill.
    // - Any arm non-templatizable → fall back to an opaque element hole: the
    //   whole conditional is compiled and its result spliced, exactly as before.
    //
    // In pure mode `holes` is `None`, so both paths are skipped and the
    // non-Call expression refuses below — the shipped behaviour unchanged.
    if let Expr::If { cond, then_, else_ } = expr {
        // Attempt wrapper hole first (more specific than CF hole): an `if` whose
        // arms are BOTH element-node builders differing only in tag/attrs over the
        // SAME children subtree. Falls through to CF hole on failure.
        if let Some(wh) = try_wrapper_hole_if(cond, then_, else_, wrappers, depth, holes) {
            return Some(wh);
        }
        return try_control_flow_hole_if(cond, then_, else_, wrappers, depth, holes);
    }
    if let Expr::Match(m) = expr {
        return try_control_flow_hole_match(m, wrappers, depth, holes);
    }
    let Expr::Call { callee, args, .. } = expr else {
        return None;
    };

    // Structural wrapper: a `Callee::Func` whose id resolves to a qualifying
    // `Ipe.Ui` layout builder. Inline the wrapper body by substituting the
    // call-site arguments for the parameters, then recurse on the result. An id
    // absent from `wrappers` falls through to the recompile return below.
    // A wrapper call whose arguments are non-literal causes `static_attrs` /
    // `static_children` / `static_desc` to refuse inside the recursion, keeping
    // the overall result `None` — conservative by construction.
    if let Callee::Func(id) = callee {
        if let Some((params, body)) = wrappers.and_then(|m| m.get(id)) {
            let inlined = substitute_wrapper(body, params, args);
            return ui_template_of_expr_at(&inlined, wrappers, depth, holes);
        }
        // An unrecognised `Callee::Func` (not a known structural wrapper) stays
        // compiled — never a mis-hoist.
        return None;
    }

    let Callee::Kernel(k) = callee else {
        // `Callee::Ffi` — not a static element node.
        return None;
    };
    // Exhaustive over the `Ipe.Ui` element-node kernels: the four static node
    // builders reduce; every other element-producing kernel (`UiHtml` embeds raw
    // `Html`, `UiCells` a raw grid, `UiButton`/`UiLink`/`UiImage` carry a record
    // config with a possible handler, the nearby `UiAbove`/… nest a sub-view,
    // `UiWidget` a live handler) refuses and stays compiled. A non-element kernel
    // (an attribute or value builder in element position) is a type error
    // upstream and also refuses here.
    match k {
        KernelFn::UiNone => match args.as_slice() {
            [] => Some(CompileUiTemplate::Empty),
            _ => None,
        },
        KernelFn::UiText => match args.as_slice() {
            [Expr::Str(s)] => Some(CompileUiTemplate::Text(s.clone())),
            // `Ui.text <Model-derived string>` — in hole mode the whole text
            // node is a single element hole (the compiled `Ui.text (…)` result is
            // spliced); in pure mode `push_element_hole` refuses (`holes` None).
            [_] => push_element_hole(expr, holes),
            _ => None,
        },
        // `ui_node_(desc, attrs, children)`.
        KernelFn::UiNode => match args.as_slice() {
            [desc, attrs, children] => Some(CompileUiTemplate::Node {
                desc: static_desc(desc)?,
                attrs: static_attrs(attrs, holes)?,
                children: static_children(children, wrappers, depth, holes)?,
            }),
            _ => None,
        },
        // `ui_tagged_node_(tag, desc, attrs, children)`.
        KernelFn::UiTaggedNode => match args.as_slice() {
            [Expr::Str(tag), desc, attrs, children] => Some(CompileUiTemplate::TaggedNode {
                tag: tag.clone(),
                desc: static_desc(desc)?,
                attrs: static_attrs(attrs, holes)?,
                children: static_children(children, wrappers, depth, holes)?,
            }),
            _ => None,
        },
        // Every other element-producing kernel that ISN'T a handler / raw / config
        // shape — refuse in pure mode, but in hole mode a `Model`-derived element
        // producer is a single element hole IF it is a safe, inert element value
        // (no handler variant reachable). Conservative: only the explicitly
        // hole-eligible producers below are admitted; everything else refuses.
        _ => None,
    }
}

/// Record `expr` as an element hole and return its numbered marker, or `None` in
/// pure mode (`holes` is `None`) — where a `Model`-derived element simply refuses,
/// exactly the shipped behaviour.
///
/// The marker index is per-KIND (the count of element holes already recorded),
/// because the runtime materializer indexes the element-fill slice and the
/// children-fill slice separately. So the emit that splits the combined hole list
/// back into two ordered vecs lands each fill at the index its marker names.
///
/// An element hole is only admitted when `expr` is provably a safe, inert
/// `Element`-producing shape the emit can compile: an `if` / `case`, or a
/// `Ui.text` over a non-literal. A handler-bearing or raw-markup producer is NOT
/// admitted here (those never reach this helper — the kernel match refuses them
/// before it), so a hole can never smuggle logic or unescaped markup.
fn push_element_hole(expr: &Expr, holes: &mut Holes) -> Option<CompileUiTemplate> {
    let acc = &mut holes.as_mut()?.holes;
    let idx = acc.iter().filter(|h| h.kind == HoleKind::Element).count();
    acc.push(HoleFill {
        kind: HoleKind::Element,
        expr: expr.clone(),
    });
    Some(CompileUiTemplate::Hole(idx))
}

/// Try to templatize an `if cond then_ else_` as a [`CompileUiTemplate::ControlFlowHole`]
/// by recursively templatizing BOTH arms. When both succeed the whole `if` is
/// represented as a CF hole (only the arm selector is compiled); when either arm
/// is non-templatizable, fall back to an opaque [`CompileUiTemplate::Hole`] with
/// the whole `if` expression as the fill — the same outcome as before this change,
/// so existing element-hole goldens degrade gracefully.
///
/// In pure mode (`holes` is `None`) both paths short-circuit to `None` —
/// the shipped static-only behaviour is unchanged.
fn try_control_flow_hole_if(
    cond: &Expr,
    then_: &Expr,
    else_: &Expr,
    wrappers: Option<&BTreeMap<FuncId, WrapperBody>>,
    depth: usize,
    holes: &mut Holes,
) -> Option<CompileUiTemplate> {
    // Pure mode — control flow always refuses (no captures accumulator).
    if holes.is_none() {
        return None;
    }

    // Attempt to templatize both arms into a SIDE accumulator so a failure in
    // the second arm leaves the primary `holes` accumulator clean.
    let mut arm_captures = Captures {
        holes: Vec::new(),
        handlers: Vec::new(),
        cf_holes: Vec::new(),
        list_holes: Vec::new(),
        wrapper_holes: Vec::new(),
        float_attr_holes: Vec::new(),
    };
    let arm_result = (|| -> Option<(CompileUiTemplate, CompileUiTemplate)> {
        let t = ui_template_of_expr_at(then_, wrappers, depth, &mut Some(&mut arm_captures))?;
        let e = ui_template_of_expr_at(else_, wrappers, depth, &mut Some(&mut arm_captures))?;
        Some((t, e))
    })();

    if let Some((then_tmpl, else_tmpl)) = arm_result {
        // Both arms templatized. Merge arm_captures into the primary acc.
        if let Some(acc) = holes.as_mut() {
            acc.holes.extend(arm_captures.holes);
            acc.handlers.extend(arm_captures.handlers);
            acc.cf_holes.extend(arm_captures.cf_holes);
            acc.list_holes.extend(arm_captures.list_holes);
            acc.wrapper_holes.extend(arm_captures.wrapper_holes);
            acc.float_attr_holes.extend(arm_captures.float_attr_holes);
        }
        // The arm-selector expression evaluates the condition and yields
        // 0 (true branch) or 1 (false branch). The emit layer casts the
        // integer fill to `usize`.
        let selector_expr = Expr::If {
            cond: Box::new(cond.clone()),
            then_: Box::new(Expr::Int(0)),
            else_: Box::new(Expr::Int(1)),
        };
        push_control_flow_hole(selector_expr, vec![then_tmpl, else_tmpl], holes)
    } else {
        // At least one arm is non-templatizable — arm_captures is dropped
        // here cleanly; the primary `holes` accumulator is unchanged.
        // Opaque element hole: compile the whole `if` expression.
        let if_expr = Expr::If {
            cond: Box::new(cond.clone()),
            then_: Box::new(then_.clone()),
            else_: Box::new(else_.clone()),
        };
        push_element_hole(&if_expr, holes)
    }
}

/// Try to templatize a `case` expression as a [`CompileUiTemplate::ControlFlowHole`]
/// by recursively templatizing EVERY arm body. When all arms succeed the whole
/// `case` is represented as a CF hole; when any arm is non-templatizable, fall back
/// to an opaque element hole covering the whole `Match` expression.
///
/// Arm order in `arms` matches source pattern order — the same order the runtime
/// evaluates and the compiler's arm-selector expression must reproduce.
/// Exhaustiveness is guaranteed by [`ipe_ir::Match`]'s construction invariant.
fn try_control_flow_hole_match(
    m: &Match,
    wrappers: Option<&BTreeMap<FuncId, WrapperBody>>,
    depth: usize,
    holes: &mut Holes,
) -> Option<CompileUiTemplate> {
    // Pure mode — refuse.
    if holes.is_none() {
        return None;
    }

    let arms_slice = m.arms();

    // Attempt to templatize every arm body into a side-accumulator so a failure
    // in any arm leaves the primary `holes` accumulator clean.
    let mut arm_captures = Captures {
        holes: Vec::new(),
        handlers: Vec::new(),
        cf_holes: Vec::new(),
        list_holes: Vec::new(),
        wrapper_holes: Vec::new(),
        float_attr_holes: Vec::new(),
    };
    let arm_templates: Option<Vec<CompileUiTemplate>> = arms_slice
        .iter()
        .map(|arm| ui_template_of_expr_at(&arm.body, wrappers, depth, &mut Some(&mut arm_captures)))
        .collect();

    match arm_templates {
        Some(arm_tmpls) if !arm_tmpls.is_empty() => {
            // All arms templatized. Merge arm_captures into primary acc.
            if let Some(acc) = holes.as_mut() {
                acc.holes.extend(arm_captures.holes);
                acc.handlers.extend(arm_captures.handlers);
                acc.cf_holes.extend(arm_captures.cf_holes);
                acc.list_holes.extend(arm_captures.list_holes);
                acc.wrapper_holes.extend(arm_captures.wrapper_holes);
                acc.float_attr_holes.extend(arm_captures.float_attr_holes);
            }
            // Build the arm-selector expression: a `Match` with Int bodies.
            let selector_expr = build_match_arm_selector(m);
            push_control_flow_hole(selector_expr, arm_tmpls, holes)
        }
        _ => {
            // Some arm non-templatizable, or zero arms. Fall back to opaque
            // element hole covering the whole `case`.
            push_element_hole(&Expr::Match(m.clone()), holes)
        }
    }
}

/// Build a `Match` expression with the same scrutinee and patterns but `Int`
/// bodies equal to each arm's zero-based source index. The produced expression
/// evaluates to a `usize`-castable integer index at render time, used as the
/// arm-selector fill for a [`CompileUiTemplate::ControlFlowHole`] over a `case`.
///
/// Pattern order is preserved so the arm index matches the index into `arms` in
/// the [`CompileUiTemplate::ControlFlowHole`] the compiler emitted — they are
/// built from the same ordered arm slice, so `arms[selector]` is always the arm
/// the source program selected.
fn build_match_arm_selector(m: &Match) -> Expr {
    let mut idx = 0usize;
    Expr::Match(m.clone().map_bodies(
        |scrutinee| scrutinee,
        |_pat, _body, guard| {
            let i = idx;
            idx = idx.saturating_add(1);
            (Expr::Int(i64::try_from(i).unwrap_or(i64::MAX)), guard)
        },
    ))
}

/// Record `arms` as a control-flow hole and return its numbered marker, or
/// `None` in pure mode. The selector `expr` (evaluating to a `usize` arm index)
/// is recorded in `cf_holes`.
fn push_control_flow_hole(
    selector_expr: Expr,
    arms: Vec<CompileUiTemplate>,
    holes: &mut Holes,
) -> Option<CompileUiTemplate> {
    let acc = holes.as_mut()?;
    let hole_id = acc.cf_holes.len();
    acc.cf_holes.push(HoleFill {
        kind: HoleKind::ControlFlow,
        expr: selector_expr,
    });
    Some(CompileUiTemplate::ControlFlowHole { hole_id, arms })
}

/// Try to recognize an `if cond then_ else_` as a
/// [`CompileUiTemplate::WrapperHole`]: an if whose arms are BOTH element-node
/// kernel calls (`UiTaggedNode` / `UiNode`) with IDENTICAL children and only the
/// tag / attrs differing. Conservative recognizer: requires literal tag strings,
/// static attrs (no `Model` read), and syntactically equal children expressions.
/// Anything unrecognized returns `None` so the caller falls through to the CF-hole
/// path, which in turn falls through to opaque element hole — byte-identical to
/// the pre-wrapper-hole behaviour.
///
/// In pure mode (`holes` is `None`) returns `None` immediately.
fn try_wrapper_hole_if(
    cond: &Expr,
    then_: &Expr,
    else_: &Expr,
    wrappers: Option<&BTreeMap<FuncId, WrapperBody>>,
    depth: usize,
    holes: &mut Holes,
) -> Option<CompileUiTemplate> {
    // Pure mode: no hole accumulator.
    holes.as_ref()?;

    // Extract wrapper arms: both must be UiTaggedNode or UiNode calls.
    let (then_wrapper, then_children) = extract_wrapper_arm(then_, wrappers)?;
    let (else_wrapper, else_children) = extract_wrapper_arm(else_, wrappers)?;

    // Children must be IDENTICAL expressions (syntactic equality). This is the
    // conservative guard: if the arms' children differ, the shape is not a pure
    // wrapper selection and must fall back to CF hole / opaque hole.
    if then_children != else_children {
        return None;
    }

    // Templatize the shared children into a SIDE accumulator so failure leaves
    // the primary holes accumulator clean.
    let mut child_captures = Captures::default();
    let child_template = static_children(
        then_children,
        wrappers,
        depth,
        &mut Some(&mut child_captures),
    )?;

    // Wrap the children in the simplest Node so we can store the child template.
    // There is always exactly one child subtree here (the shared children list).
    // We build a synthetic `Node { desc: NoDescription, attrs: [], children: child_template }`,
    // but actually we want to store the templatized children as the single child node.
    // The wrapper hole's `child` is the element that the wrapper wraps — i.e. the
    // shared children are the sub-elements of the wrapping node. To keep the
    // interface clean, build a synthetic static `Node` containing the templated children.
    //
    // Simpler: the child IS the shared children list wrapped in a synthetic node whose
    // desc/attrs are empty. But that adds spurious structure. Instead: the child is
    // the templatized version of `then_children` directly — a `Vec<CompileUiTemplate>`.
    // Since `WrapperHole.child` is a single `Box<CompileUiTemplate>`, and the children
    // list may be multi-element, we need a wrapping Node. Use a synthetic NoDescription
    // / no-attr `Node` to hold the child list.
    let child_node = if child_template.len() == 1 {
        // Single-child: use it directly.
        child_template.into_iter().next()?
    } else {
        // Multi-child: wrap in a synthetic node with no attrs/desc.
        CompileUiTemplate::Node {
            desc: CompileUiDesc::NoDescription,
            attrs: vec![],
            children: child_template,
        }
    };

    // Build the arm-selector expression.
    let selector_expr = Expr::If {
        cond: Box::new(cond.clone()),
        then_: Box::new(Expr::Int(0)),
        else_: Box::new(Expr::Int(1)),
    };

    // Merge child_captures into the primary accumulator.
    if let Some(acc) = holes.as_mut() {
        acc.holes.extend(child_captures.holes);
        acc.handlers.extend(child_captures.handlers);
        acc.cf_holes.extend(child_captures.cf_holes);
        acc.list_holes.extend(child_captures.list_holes);
        acc.wrapper_holes.extend(child_captures.wrapper_holes);
        acc.float_attr_holes.extend(child_captures.float_attr_holes);
    }

    push_wrapper_hole(
        selector_expr,
        vec![then_wrapper, else_wrapper],
        Box::new(child_node),
        holes,
    )
}

/// Extract the wrapper (tag/desc/attrs, no children) and the children expression
/// from an element-node call (`UiTaggedNode` / `UiNode`). Returns `None` for any
/// other callee or non-static attrs. The children expression is returned as-is
/// (to be compared for equality across arms).
///
/// Wrapper resolution is applied first: if the arm is a `Callee::Func` whose id
/// resolves in `wrappers`, the body is inlined and the result re-extracted.
fn extract_wrapper_arm<'e>(
    arm: &'e Expr,
    wrappers: Option<&BTreeMap<FuncId, WrapperBody>>,
) -> Option<(CompileUiTemplate, &'e Expr)> {
    // Beta-reduce a `Let` binder before inspecting the arm.
    if let Expr::Let { name, value, body } = arm {
        // Use a temp owned reduction; we cannot return a reference into a
        // temporary, so wrapper-arm extraction can only proceed if the let-reduced
        // result is itself a direct kernel call (no binder indirection). For the
        // common `if model.link then Ui.a [attrs] else Ui.span []` shape the arms
        // are direct calls, so this bails out on anything with an intermediate Let.
        let _ = (name, value, body);
        return None;
    }
    // Structural wrapper: inline if recognized.
    if let Expr::Call {
        callee: Callee::Func(id),
        args,
        ..
    } = arm
    {
        if let Some((params, body)) = wrappers.and_then(|m| m.get(id)) {
            let inlined = substitute_wrapper(body, params, args);
            return extract_wrapper_arm_inlined(&inlined, wrappers);
        }
        return None;
    }
    extract_wrapper_arm_direct(arm)
}

/// Attempt to extract a wrapper + children from an OWNED (inlined) expression.
/// Cannot return a reference to the inlined children (they live in a temporary),
/// so this path always returns `None` — conservative fallback to CF hole.
const fn extract_wrapper_arm_inlined(
    _inlined: &Expr,
    _wrappers: Option<&BTreeMap<FuncId, WrapperBody>>,
) -> Option<(CompileUiTemplate, &'static Expr)> {
    None
}

/// Extract wrapper + children from a direct kernel call.
fn extract_wrapper_arm_direct(arm: &Expr) -> Option<(CompileUiTemplate, &Expr)> {
    let Expr::Call { callee, args, .. } = arm else {
        return None;
    };
    let Callee::Kernel(k) = callee else {
        return None;
    };
    match (k, args.as_slice()) {
        (KernelFn::UiTaggedNode, [Expr::Str(tag), desc, attrs, children]) => {
            // Static desc and attrs only.
            let s_desc = static_desc(desc)?;
            let s_attrs = static_attrs(attrs, &mut None)?;
            let wrapper = CompileUiTemplate::TaggedNode {
                tag: tag.clone(),
                desc: s_desc,
                attrs: s_attrs,
                children: vec![],
            };
            Some((wrapper, children))
        }
        (KernelFn::UiNode, [desc, attrs, children]) => {
            let s_desc = static_desc(desc)?;
            let s_attrs = static_attrs(attrs, &mut None)?;
            let wrapper = CompileUiTemplate::Node {
                desc: s_desc,
                attrs: s_attrs,
                children: vec![],
            };
            Some((wrapper, children))
        }
        _ => None,
    }
}

/// Record `arms` as a wrapper hole and return its numbered marker, or `None` in
/// pure mode. The selector expression (evaluating to a `usize` arm index) and the
/// per-arm wrapper templates are recorded in `wrapper_holes`.
fn push_wrapper_hole(
    selector_expr: Expr,
    wrapper_arms: Vec<CompileUiTemplate>,
    child: Box<CompileUiTemplate>,
    holes: &mut Holes,
) -> Option<CompileUiTemplate> {
    let acc = holes.as_mut()?;
    let hole_id = acc.wrapper_holes.len();
    acc.wrapper_holes.push(WrapperHoleFill {
        selector_expr,
        wrapper_arms,
    });
    Some(CompileUiTemplate::WrapperHole { hole_id, child })
}

/// Try to templatize a `List.map f xs` call as a [`CompileUiTemplate::ListHole`]
/// by inlining and templatizing the item function body. `list_map_call` MUST
/// satisfy [`is_list_map_call`].
///
/// When `f` is a single-parameter `Expr::Lambda` whose body is fully
/// templatizable (possibly carrying value holes for item-parameter reads), the
/// function emits `ListHole { hole_id, item_template }` and records a
/// [`ListHoleFill`] with the list expression (`xs`) and per-item fill lambdas.
/// When `f` is not an inlineable lambda or the body is non-templatizable, falls
/// back to a [`CompileUiTemplate::ChildrenHole`] — identical to the existing
/// pre-list-hole behaviour.
///
/// In pure mode (`holes` is `None`) the list-hole path is skipped and the whole
/// call falls through to `push_children_hole` (conservative, unchanged).
fn try_list_hole(
    list_map_call: &Expr,
    wrappers: Option<&BTreeMap<FuncId, WrapperBody>>,
    depth: usize,
    holes: &mut Holes,
) -> Option<CompileUiTemplate> {
    // Pure mode — no captures accumulator; fall directly to children hole (which
    // also returns `None` in pure mode, refusing the whole subtree).
    if holes.is_none() {
        return push_children_hole(list_map_call, holes);
    }
    let Expr::Call { args, .. } = list_map_call else {
        return push_children_hole(list_map_call, holes);
    };
    // Extract `f` and `xs` from `List.map f xs`.
    let [f, xs] = args.as_slice() else {
        return push_children_hole(list_map_call, holes);
    };

    // Only inline a single-parameter `Lambda` whose body we can templatize.
    let Expr::Lambda {
        params,
        body: item_body,
        ..
    } = f
    else {
        return push_children_hole(list_map_call, holes);
    };
    let [(item_sym, _)] = params.as_slice() else {
        return push_children_hole(list_map_call, holes);
    };

    // Templatize the item body into a SIDE accumulator so failure leaves the
    // primary holes accumulator clean. Item-parameter reads become element holes
    // inside the item template (the fill expressions reference the item symbol).
    let mut item_captures = Captures::default();
    let item_template =
        ui_template_of_expr_at(item_body, wrappers, depth, &mut Some(&mut item_captures));

    match item_template {
        Some(tmpl) => {
            // Item body templatized. Only plain element holes are supported
            // inside an item template for this step; a children hole, handler
            // hole, CF hole, or nested list hole inside the item body would
            // require re-indexing across the outer accumulator — conservative
            // fallback to children hole when any non-element hole is present.
            let has_non_element_holes = item_captures
                .holes
                .iter()
                .any(|h| h.kind != HoleKind::Element)
                || !item_captures.handlers.is_empty()
                || !item_captures.cf_holes.is_empty()
                || !item_captures.list_holes.is_empty()
                || !item_captures.wrapper_holes.is_empty();

            if has_non_element_holes {
                return push_children_hole(list_map_call, holes);
            }

            // Collect item element-fill expressions in hole-index order —
            // each may contain free references to `item_sym`.
            let item_fills = item_captures.holes.into_iter().map(|h| h.expr).collect();

            push_list_hole(xs.clone(), *item_sym, item_fills, Box::new(tmpl), holes)
        }
        None => {
            // Item body not templatizable — fall back to children hole.
            push_children_hole(list_map_call, holes)
        }
    }
}

/// Record a list hole and return its numbered [`CompileUiTemplate::ListHole`]
/// marker, or `None` in pure mode.
fn push_list_hole(
    xs: Expr,
    item_sym: Symbol,
    item_fills: Vec<Expr>,
    item_template: Box<CompileUiTemplate>,
    holes: &mut Holes,
) -> Option<CompileUiTemplate> {
    let acc = holes.as_mut()?;
    let hole_id = acc.list_holes.len();
    acc.list_holes.push(ListHoleFill {
        xs,
        item_sym,
        item_fills,
    });
    Some(CompileUiTemplate::ListHole {
        hole_id,
        item_template,
    })
}

/// Record `expr` as a children hole (a `List.map` run) and return its per-kind
/// numbered marker, or `None` in pure mode.
fn push_children_hole(expr: &Expr, holes: &mut Holes) -> Option<CompileUiTemplate> {
    let acc = &mut holes.as_mut()?.holes;
    let idx = acc.iter().filter(|h| h.kind == HoleKind::Children).count();
    acc.push(HoleFill {
        kind: HoleKind::Children,
        expr: expr.clone(),
    });
    Some(CompileUiTemplate::ChildrenHole(idx))
}

/// Substitute call-site `args` for `params` in `body` — a minimal positional
/// substitution for the structural-wrapper inline path. Each param symbol that
/// appears as an `Expr::Var` or `Expr::CloneVar` in `body` is replaced by the
/// corresponding argument expression. The lowerer may introduce `Let`
/// bindings for intermediate expressions (e.g. the cons prepend in a wrapper
/// body); `subst_expr` descends into those so all parameter references are
/// replaced regardless of nesting depth.
fn substitute_wrapper(body: &Expr, params: &[Symbol], args: &[Expr]) -> Expr {
    subst_expr(body, params, args)
}

fn subst_expr(expr: &Expr, params: &[Symbol], args: &[Expr]) -> Expr {
    match expr {
        Expr::Var(sym) | Expr::CloneVar(sym) => {
            // Replace a parameter reference with its call-site argument.
            // A parameter with no corresponding argument is an arity mismatch —
            // leave as-is so the downstream static_* fns refuse (returning
            // None), which is the conservative outcome.
            params.iter().position(|p| p == sym).map_or_else(
                || expr.clone(),
                |pos| args.get(pos).cloned().unwrap_or_else(|| expr.clone()),
            )
        }

        // Structural descent: a wrapper body may contain kernel calls, list
        // literals, Cons prepend, and Let bindings (for intermediate exprs).
        Expr::Call {
            callee,
            args: call_args,
            pin,
            on_form,
        } => Expr::Call {
            callee: callee.clone(),
            args: call_args
                .iter()
                .map(|a| subst_expr(a, params, args))
                .collect(),
            pin: pin.clone(),
            on_form: *on_form,
        },

        Expr::List { elem, items } => Expr::List {
            elem: elem.clone(),
            items: items.iter().map(|i| subst_expr(i, params, args)).collect(),
        },

        Expr::Cons { head, tail } => Expr::Cons {
            head: Box::new(subst_expr(head, params, args)),
            tail: Box::new(subst_expr(tail, params, args)),
        },

        // The lowerer may bind an intermediate expression in a `Let`. Recurse
        // into both the bound value and the body so that any `Expr::Var(param)`
        // inside either arm is replaced. The let-bound name (`Let::name`) is a
        // local binder — it shadows any outer param with the same symbol, but
        // wrapper bodies are guaranteed not to shadow their own params (they are
        // a single return expression over the param list), so no shadowing check
        // is needed here.
        Expr::Let { name, value, body } => Expr::Let {
            name: *name,
            value: Box::new(subst_expr(value, params, args)),
            body: Box::new(subst_expr(body, params, args)),
        },

        // A pre-clone of a parameter binds its call-site argument instead, as
        // the self-clone `Let` it stands for would after substitution.
        Expr::CaptureClones { syms, body } => syms.iter().rev().fold(
            subst_expr(body, params, args),
            |body, sym| match subst_expr(&Expr::CloneVar(*sym), params, args) {
                Expr::CloneVar(s) if s == *sym => Expr::pre_clone(s, body),
                value => Expr::Let {
                    name: *sym,
                    value: Box::new(value),
                    body: Box::new(body),
                },
            },
        ),

        // Leaves and shapes not present in a structural wrapper body pass through.
        _ => expr.clone(),
    }
}

/// Reduce a child `Ipe.Ui` node list to templates (plus any holes), or `None`.
///
/// Two shapes reach here:
/// - a literal `Expr::List` of child elements — each item is recursed (a
///   `Model`-derived value leaf or control-flow item becomes an element hole in
///   hole mode; a `List.map` item becomes a children hole);
/// - the whole children expr being a single `List.map` comprehension (the common
///   `column [] (List.map itemView model.items)` shape) — one children hole for
///   the entire run.
///
/// In pure mode (`holes` is `None`) both hole paths refuse, leaving the shipped
/// static-only behaviour: only a literal list of provably-static children reduces.
fn static_children(
    children: &Expr,
    wrappers: Option<&BTreeMap<FuncId, WrapperBody>>,
    depth: usize,
    holes: &mut Holes,
) -> Option<Vec<CompileUiTemplate>> {
    // The whole children list is a `List.map` comprehension → attempt list hole,
    // falling back to children hole when the item body is non-templatizable.
    if is_list_map_call(children) {
        return Some(vec![try_list_hole(children, wrappers, depth, holes)?]);
    }
    let Expr::List { items, .. } = children else {
        return None;
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        // A `List.map` appearing as a list item: attempt list hole first.
        if is_list_map_call(item) {
            out.push(try_list_hole(item, wrappers, depth, holes)?);
        } else {
            out.push(ui_template_of_expr_at(
                item,
                wrappers,
                depth.saturating_add(1),
                holes,
            )?);
        }
    }
    Some(out)
}

/// Is `expr` a `List.map f xs` call? The comprehension shape a children hole
/// splices. Only the direct `List.map` kernel qualifies — a user helper aliasing
/// it (a `Callee::Func`) stays conservative and refuses (recompiles).
const fn is_list_map_call(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Call {
            callee: Callee::Kernel(KernelFn::ListMap),
            ..
        }
    )
}

/// Reduce a literal list of `Ipe.Ui` attributes to inert data, or `None` when
/// any element is not an accepted static attribute.
///
/// Accepts both `Expr::List` (the direct-kernel shape) and a `Expr::Cons` chain
/// (the shape a structural wrapper produces after substitution — e.g. the
/// `style "__row" "true" :: attrs` prepend in `Ui.row`'s lowered body).
fn static_attrs(attrs: &Expr, holes: &mut Holes) -> Option<Vec<CompileUiAttr>> {
    let mut out = Vec::new();
    collect_static_attrs(attrs, &mut out, holes)?;
    Some(out)
}

/// Append the static attrs in `expr` to `out`. Handles both a literal
/// `Expr::List` and a right-spine `Expr::Cons { head, tail }` chain whose
/// eventual tail is a `List`.
fn collect_static_attrs(
    expr: &Expr,
    out: &mut Vec<CompileUiAttr>,
    holes: &mut Holes,
) -> Option<()> {
    match expr {
        Expr::List { items, .. } => {
            for item in items {
                out.push(static_attr(item, holes)?);
            }
            Some(())
        }
        // A `Cons` head is one prepended attribute; the tail is recursed.
        Expr::Cons { head, tail } => {
            out.push(static_attr(head, holes)?);
            collect_static_attrs(tail, out, holes)
        }
        // Any other shape (a Var, a non-list call) is not a provably-static
        // attribute list — refuse.
        _ => None,
    }
}

/// Reduce one `Ipe.Ui` attribute expression to inert data, or `None`.
///
/// Fail-closed allowlist: only the integer / string / marker attribute kernels
/// below templatize. Every other attribute kernel — an event handler, a `Color`-
/// or `Float`-bearing attribute (deferred), a pseudo-rule, a nearby overlay, the
/// debug outline — returns `None`, so the subtree stays compiled rather than
/// mis-templated. A kernel absent from this allowlist defaults to refuse, which
/// is always safe (it merely recompiles).
#[allow(clippy::too_many_lines)]
fn static_attr(attr: &Expr, holes: &mut Holes) -> Option<CompileUiAttr> {
    let Expr::Call { callee, args, .. } = attr else {
        return None;
    };
    let Callee::Kernel(k) = callee else {
        return None;
    };
    // A model-dependent plain-message event (`Ui.onClick msg`, …) templatizes as a
    // HANDLER HOLE: the wire event name plus a hole id, with the captured `Msg`
    // expression recorded for per-render resolution. Only the pure `OnMsg`-shaped
    // Ui events qualify; the `OnString` / `OnBool` / `OnForm` events need a
    // runtime-supplied argument, so they are NOT a per-render `Msg` capture and
    // stay compiled (they fall through to the refuse arm). In pure mode
    // (`push_handler_hole` sees `None`) every handler refuses — the shipped
    // static-only behaviour, unchanged.
    if let (Some(event), [msg]) = (ui_on_msg_wire_name(*k), args.as_slice()) {
        return push_handler_hole(event, msg, holes);
    }
    match (k, args.as_slice()) {
        (KernelFn::UiSpacing, [Expr::Int(n)]) => Some(CompileUiAttr::Spacing(*n)),
        (KernelFn::UiPadding, [Expr::Int(n)]) => Some(CompileUiAttr::Padding(*n, *n, *n, *n)),
        (KernelFn::UiPaddingXY, [Expr::Int(x), Expr::Int(y)]) => {
            Some(CompileUiAttr::Padding(*y, *x, *y, *x))
        }
        (KernelFn::UiWidth, [len]) => Some(CompileUiAttr::Width(static_length(len)?)),
        (KernelFn::UiHeight, [len]) => Some(CompileUiAttr::Height(static_length(len)?)),
        (KernelFn::UiCenterX, []) => Some(CompileUiAttr::AlignX("CenterX")),
        (KernelFn::UiAlignLeft, []) => Some(CompileUiAttr::AlignX("AlignLeft")),
        (KernelFn::UiAlignRight, []) => Some(CompileUiAttr::AlignX("AlignRight")),
        (KernelFn::UiCenterY, []) => Some(CompileUiAttr::AlignY("CenterY")),
        (KernelFn::UiAlignTop, []) => Some(CompileUiAttr::AlignY("AlignTop")),
        (KernelFn::UiAlignBottom, []) => Some(CompileUiAttr::AlignY("AlignBottom")),
        (KernelFn::UiPointer, []) => Some(CompileUiAttr::Pointer),
        (KernelFn::UiClip, []) => Some(CompileUiAttr::Overflow("hidden", "hidden")),
        (KernelFn::UiClipX, []) => Some(CompileUiAttr::Overflow("clip", "visible")),
        (KernelFn::UiClipY, []) => Some(CompileUiAttr::Overflow("visible", "clip")),
        (KernelFn::UiScrollbars, []) => Some(CompileUiAttr::Overflow("auto", "auto")),
        (KernelFn::UiScrollbarX, []) => Some(CompileUiAttr::Overflow("auto", "hidden")),
        (KernelFn::UiScrollbarY, []) => Some(CompileUiAttr::Overflow("hidden", "auto")),
        (KernelFn::UiStyle, [Expr::Str(p), Expr::Str(v)]) => {
            Some(CompileUiAttr::Style(p.clone(), v.clone()))
        }
        (KernelFn::UiGridColumns, [Expr::Int(n)]) => Some(CompileUiAttr::Style(
            "--ipe-grid-columns".to_string(),
            n.to_string(),
        )),
        (KernelFn::UiName, [Expr::Str(v)]) => {
            Some(CompileUiAttr::Attribute("name".to_string(), v.clone()))
        }
        (KernelFn::UiHtmlAttribute, [Expr::Str(key), Expr::Str(value)]) => {
            Some(CompileUiAttr::Attribute(key.clone(), value.clone()))
        }
        (KernelFn::FontSize, [Expr::Int(n)]) => Some(CompileUiAttr::FontSize(*n)),
        (KernelFn::FontFamily, [Expr::Str(f)]) => Some(CompileUiAttr::FontFamily(f.clone())),
        (KernelFn::FontWeight, [Expr::Int(n)]) => Some(CompileUiAttr::FontWeight(*n)),
        (KernelFn::FontBold, []) => Some(CompileUiAttr::FontWeight(700)),
        (KernelFn::FontSemiBold, []) => Some(CompileUiAttr::FontWeight(600)),
        (KernelFn::FontRegular, []) => Some(CompileUiAttr::FontWeight(400)),
        (KernelFn::FontLight, []) => Some(CompileUiAttr::FontWeight(300)),
        (KernelFn::FontExtraBold, []) => Some(CompileUiAttr::FontWeight(800)),
        (KernelFn::FontBlack, []) => Some(CompileUiAttr::FontWeight(900)),
        (KernelFn::FontItalic, []) => Some(CompileUiAttr::FontItalic),
        (KernelFn::FontUnderline, []) => Some(CompileUiAttr::FontUnderline),
        (KernelFn::FontNoDecoration, []) => Some(CompileUiAttr::FontDecoration("none")),
        (KernelFn::FontLineThrough, []) => Some(CompileUiAttr::FontDecoration("line-through")),
        (KernelFn::FontAlignLeft, []) => Some(CompileUiAttr::FontAlign("left")),
        (KernelFn::FontAlignRight, []) => Some(CompileUiAttr::FontAlign("right")),
        (KernelFn::FontAlignCenter | KernelFn::FontCenter, []) => {
            Some(CompileUiAttr::FontAlign("center"))
        }
        (KernelFn::FontJustify, []) => Some(CompileUiAttr::FontAlign("justify")),
        (KernelFn::BorderWidth, [Expr::Int(n)]) => Some(CompileUiAttr::BorderWidth(*n)),
        (KernelFn::BorderRounded, [Expr::Int(n)]) => Some(CompileUiAttr::BorderRounded(*n)),
        (KernelFn::BorderSolid, []) => Some(CompileUiAttr::BorderStyle("solid")),
        (KernelFn::BorderDashed, []) => Some(CompileUiAttr::BorderStyle("dashed")),
        (KernelFn::BorderDotted, []) => Some(CompileUiAttr::BorderStyle("dotted")),
        (KernelFn::UiDescribe, [desc]) => Some(CompileUiAttr::Describe(static_desc(desc)?)),
        (KernelFn::RegionMainContent, []) => Some(CompileUiAttr::Describe(CompileUiDesc::DescMain)),
        (KernelFn::RegionNavigation, []) => {
            Some(CompileUiAttr::Describe(CompileUiDesc::DescNavigation))
        }
        (KernelFn::RegionFooter, []) => {
            Some(CompileUiAttr::Describe(CompileUiDesc::DescContentInfo))
        }
        (KernelFn::RegionAside, []) => {
            Some(CompileUiAttr::Describe(CompileUiDesc::DescComplementary))
        }
        (KernelFn::RegionHeading, [Expr::Int(n)]) => {
            Some(CompileUiAttr::Describe(CompileUiDesc::DescHeading(*n)))
        }
        (KernelFn::RegionLabel, [Expr::Str(s)]) => {
            Some(CompileUiAttr::Describe(CompileUiDesc::DescLabel(s.clone())))
        }
        (KernelFn::RegionAnnounce, []) => {
            Some(CompileUiAttr::Describe(CompileUiDesc::DescLivePolite))
        }
        (KernelFn::RegionAnnounceUrgently, []) => {
            Some(CompileUiAttr::Describe(CompileUiDesc::DescLiveAssertive))
        }
        // ── single-`Color` attributes over a literal color ────────────────
        (KernelFn::FontColor, [c]) => Some(CompileUiAttr::FontColor(static_color(c)?)),
        (KernelFn::BackgroundColor, [c]) => Some(CompileUiAttr::BgColor(static_color(c)?)),
        (KernelFn::BorderColor, [c]) => Some(CompileUiAttr::BorderColor(static_color(c)?)),
        // ── single-`Float` attributes over a literal ──────────────────────
        // A non-finite literal (a const-folded `1.0 / 0.0`) has no `serde_json`
        // number form — the compiled path emits `null` — so templatizing it would
        // diverge from the compiled arm. Refuse: keep the subtree compiled.
        (KernelFn::FontLetterSpacing, [Expr::Float(v)]) if v.is_finite() => {
            Some(CompileUiAttr::FontLetterSpacing(*v))
        }
        (KernelFn::FontWordSpacing, [Expr::Float(v)]) if v.is_finite() => {
            Some(CompileUiAttr::FontWordSpacing(*v))
        }
        // ── float-attr holes: model-driven float value ─────────────────────
        // A float-valued attribute whose argument is model-driven (not a literal)
        // reduces to an `AttrHoleFloat` hole in hole mode. The attr discriminant
        // name must match what the runtime's `resolve_float_attr` recognizes.
        // In pure mode (`push_float_attr_hole` sees `None`) refuses — shipped
        // static-only behaviour, unchanged.
        (KernelFn::FontLetterSpacing, [_]) => {
            push_float_attr_hole("font-letter-spacing", args.first()?, holes)
        }
        (KernelFn::FontWordSpacing, [_]) => {
            push_float_attr_hole("font-word-spacing", args.first()?, holes)
        }
        // Every other attribute kernel — a handler, a shadow record, an
        // aspect-ratio / gradient, a `Model`-derived color/float, a pseudo-rule, a
        // nearby overlay, the debug outline, or an unrecognised one — is not an
        // accepted inert attribute. Refuse: keep the subtree compiled.
        _ => None,
    }
}

/// Record `expr` (a model-driven float expression) as a float-attr hole and
/// return a [`CompileUiAttr::AttrHoleFloat`] carrying `attr` and the hole id,
/// or `None` in pure mode — where a non-literal float attribute simply refuses,
/// exactly the shipped static-only behaviour.
///
/// The hole id is the count of float-attr holes already recorded, matching the
/// order `float_attr_fills[hole_id]` will index at the runtime layer.
fn push_float_attr_hole(
    attr: &'static str,
    expr: &Expr,
    holes: &mut Holes,
) -> Option<CompileUiAttr> {
    let acc = &mut holes.as_mut()?.float_attr_holes;
    let hole_id = u32::try_from(acc.len()).ok()?;
    acc.push(HoleFill {
        kind: HoleKind::FloatAttr,
        expr: expr.clone(),
    });
    Some(CompileUiAttr::AttrHoleFloat { attr, hole_id })
}

/// The DOM wire event name for a pure plain-message (`OnMsg`) `Ipe.Ui` event
/// kernel, or `None` for any kernel that is not one of the five. Exactly the
/// events whose runtime builder emits `Event::OnMsg("<name>", msg)` — the shape a
/// handler hole resolves. The value-carrying events (`onInput` / `onChange` /
/// `onKeyDown` / `onKeyUp` / `onCheck` / `onFile` / `onSubmit`) build an
/// `Arc<dyn Fn(_) -> M>` closure over a runtime-supplied argument, so they are NOT
/// a per-render `Msg` capture and are deliberately absent.
const fn ui_on_msg_wire_name(k: KernelFn) -> Option<&'static str> {
    Some(match k {
        KernelFn::UiOnClick => "click",
        KernelFn::UiOnFocus => "focus",
        KernelFn::UiOnBlur => "blur",
        KernelFn::UiOnMouseOver => "mouseover",
        KernelFn::UiOnMouseOut => "mouseout",
        _ => return None,
    })
}

/// Record `msg` as a model-dependent handler capture and return a
/// [`CompileUiAttr::HandlerHole`] carrying the wire `event` and the capture's
/// hole id, or `None` in pure mode (`holes` is `None`) — where a handler simply
/// refuses, exactly the shipped static-only behaviour.
///
/// The hole id is the count of handler captures already recorded, matching the
/// order `UiHandlerMap::from_msgs` will index. The captured expression is the
/// `Msg` argument itself; it is emitted separately by the caller through the main
/// expression emitter and never appears in the inert template — the transported
/// datum carries only the event name and the id, never the `Msg` or a closure.
fn push_handler_hole(event: &'static str, msg: &Expr, holes: &mut Holes) -> Option<CompileUiAttr> {
    let acc = &mut holes.as_mut()?.handlers;
    let handler_id = u32::try_from(acc.len()).ok()?;
    acc.push(msg.clone());
    Some(CompileUiAttr::HandlerHole { event, handler_id })
}

/// Reduce a `Length`-producing kernel call over literal arguments to inert data,
/// or `None`. Only integer-valued `Length`s templatize; a `Model`-derived length
/// refuses.
fn static_length(expr: &Expr) -> Option<CompileUiLength> {
    let Expr::Call { callee, args, .. } = expr else {
        return None;
    };
    let Callee::Kernel(k) = callee else {
        return None;
    };
    match (k, args.as_slice()) {
        (KernelFn::UiPx, [Expr::Int(n)]) => Some(CompileUiLength::Px(*n)),
        (KernelFn::UiFill, []) => Some(CompileUiLength::Fill(1)),
        (KernelFn::UiFillPortion, [Expr::Int(n)]) => Some(CompileUiLength::Fill(*n)),
        (KernelFn::UiContent | KernelFn::UiShrink, []) => Some(CompileUiLength::Content),
        (KernelFn::UiVh, [Expr::Int(n)]) => Some(CompileUiLength::Vh(*n)),
        (KernelFn::UiVw, [Expr::Int(n)]) => Some(CompileUiLength::Vw(*n)),
        (KernelFn::UiMinimum, [Expr::Int(n), inner]) => {
            Some(CompileUiLength::Min(*n, Box::new(static_length(inner)?)))
        }
        (KernelFn::UiMaximum, [Expr::Int(n), inner]) => {
            Some(CompileUiLength::Max(*n, Box::new(static_length(inner)?)))
        }
        _ => None,
    }
}

/// Reduce a `Color`-producing kernel call over literal arguments to inert data,
/// or `None`. Only the literal color builders templatize; a `Model`-derived color
/// (a `Var` / `Access`) or a non-literal channel refuses and keeps the subtree
/// compiled. The alpha of `Ui.rgb` / the named colors matches the runtime helper
/// bodies (`ui_rgb_` → `a = 1.0`, `ui_transparent_` → `a = 0.0`).
const fn static_color(expr: &Expr) -> Option<CompileUiColor> {
    let Expr::Call { callee, args, .. } = expr else {
        return None;
    };
    let Callee::Kernel(k) = callee else {
        return None;
    };
    match (k, args.as_slice()) {
        (KernelFn::UiRgb, [Expr::Int(red), Expr::Int(green), Expr::Int(blue)]) => {
            Some(CompileUiColor {
                r: *red,
                g: *green,
                b: *blue,
                a: 1.0,
            })
        }
        (
            KernelFn::UiRgba,
            [
                Expr::Int(red),
                Expr::Int(green),
                Expr::Int(blue),
                Expr::Float(alpha),
            ],
        ) if alpha.is_finite() => Some(CompileUiColor {
            r: *red,
            g: *green,
            b: *blue,
            a: *alpha,
        }),
        (KernelFn::UiWhite, []) => Some(CompileUiColor {
            r: 255,
            g: 255,
            b: 255,
            a: 1.0,
        }),
        (KernelFn::UiBlack, []) => Some(CompileUiColor {
            r: 0,
            g: 0,
            b: 0,
            a: 1.0,
        }),
        (KernelFn::UiTransparent, []) => Some(CompileUiColor {
            r: 0,
            g: 0,
            b: 0,
            a: 0.0,
        }),
        // A `Model`-derived color, `Ui.colorCss` (a string form the runtime
        // `Color` variant does not carry), or any non-literal channel refuses.
        _ => None,
    }
}

/// Reduce a `Description`-producing kernel call to inert data, or `None`.
fn static_desc(expr: &Expr) -> Option<CompileUiDesc> {
    let Expr::Call { callee, args, .. } = expr else {
        return None;
    };
    let Callee::Kernel(k) = callee else {
        return None;
    };
    match (k, args.as_slice()) {
        (KernelFn::UiDescNone, []) => Some(CompileUiDesc::NoDescription),
        (KernelFn::UiDescParagraph, []) => Some(CompileUiDesc::DescParagraph),
        (KernelFn::UiDescMain, []) => Some(CompileUiDesc::DescMain),
        (KernelFn::UiDescNavigation, []) => Some(CompileUiDesc::DescNavigation),
        (KernelFn::UiDescContentInfo, []) => Some(CompileUiDesc::DescContentInfo),
        (KernelFn::UiDescComplementary, []) => Some(CompileUiDesc::DescComplementary),
        (KernelFn::UiDescLivePolite, []) => Some(CompileUiDesc::DescLivePolite),
        (KernelFn::UiDescLiveAssertive, []) => Some(CompileUiDesc::DescLiveAssertive),
        (KernelFn::UiDescHeading, [Expr::Int(n)]) => Some(CompileUiDesc::DescHeading(*n)),
        (KernelFn::UiDescLabel, [Expr::Str(s)]) => Some(CompileUiDesc::DescLabel(s.clone())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        CompileUiAttr, CompileUiColor, CompileUiDesc, CompileUiLength, CompileUiTemplate,
        WrapperBody, ui_template_of_expr,
    };
    use ipe_intern::Symbol;
    use ipe_ir::{CallPin, Callee, Expr, FuncId, IrType, KernelFn, OnFormKind, UiCtor};

    fn kcall(k: KernelFn, args: Vec<Expr>) -> Expr {
        Expr::Call {
            callee: Callee::Kernel(k),
            args,
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }
    }

    impl CompileUiAttr {
        /// Serialize a single attribute to its JSON — a test-only view of the
        /// private `write_json`, used by the byte-shape pins.
        fn attr_json(&self) -> String {
            let mut out = String::new();
            self.write_json(&mut out);
            out
        }
    }

    fn fcall(id: u32, args: Vec<Expr>) -> Expr {
        Expr::Call {
            callee: Callee::Func(FuncId::from_raw(id)),
            args,
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }
    }

    fn attr_list(items: Vec<Expr>) -> Expr {
        Expr::List {
            elem: IrType::Ui {
                ctor: UiCtor::HtmlAttribute,
                msg: Box::new(IrType::Int),
            },
            items,
        }
    }

    fn child_list(items: Vec<Expr>) -> Expr {
        Expr::List {
            elem: IrType::Ui {
                ctor: UiCtor::Element,
                msg: Box::new(IrType::Int),
            },
            items,
        }
    }

    fn desc_none() -> Expr {
        kcall(KernelFn::UiDescNone, vec![])
    }

    fn text(s: &str) -> Expr {
        kcall(KernelFn::UiText, vec![Expr::Str(s.to_string())])
    }

    fn sym(n: u32) -> Symbol {
        Symbol::from_raw(n)
    }

    /// Build a wrapper table with one entry: func id `id` with params `params`
    /// and body `body`.
    fn one_wrapper(id: u32, params: Vec<Symbol>, body: Expr) -> BTreeMap<FuncId, WrapperBody> {
        let mut m = BTreeMap::new();
        m.insert(FuncId::from_raw(id), (params, body));
        m
    }

    // ── acceptance: direct kernel calls ──────────────────────────────────────

    #[test]
    fn text_node_templates() {
        assert_eq!(
            ui_template_of_expr(&text("hi"), None),
            Some(CompileUiTemplate::Text("hi".to_string()))
        );
    }

    #[test]
    fn none_templates_to_empty() {
        assert_eq!(
            ui_template_of_expr(&kcall(KernelFn::UiNone, vec![]), None),
            Some(CompileUiTemplate::Empty)
        );
    }

    #[test]
    fn node_with_inert_attrs_and_children_templates() {
        // A `Ui.row`-equivalent shape lowered to
        // `ui_node_(descNone, [__row marker; spacing 8; width (px 16)], [text "a"])`.
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![
                    kcall(
                        KernelFn::UiStyle,
                        vec![
                            Expr::Str("__row".to_string()),
                            Expr::Str("true".to_string()),
                        ],
                    ),
                    kcall(KernelFn::UiSpacing, vec![Expr::Int(8)]),
                    kcall(
                        KernelFn::UiWidth,
                        vec![kcall(KernelFn::UiPx, vec![Expr::Int(16)])],
                    ),
                ]),
                child_list(vec![text("a")]),
            ],
        );
        let got = ui_template_of_expr(&node, None).expect("templatable");
        assert_eq!(
            got,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![
                    CompileUiAttr::Style("__row".to_string(), "true".to_string()),
                    CompileUiAttr::Spacing(8),
                    CompileUiAttr::Width(CompileUiLength::Px(16)),
                ],
                children: vec![CompileUiTemplate::Text("a".to_string())],
            }
        );
    }

    #[test]
    fn tagged_node_templates() {
        let node = kcall(
            KernelFn::UiTaggedNode,
            vec![
                Expr::Str("section".to_string()),
                kcall(KernelFn::UiDescMain, vec![]),
                attr_list(vec![kcall(KernelFn::FontSize, vec![Expr::Int(16)])]),
                child_list(vec![text("Body")]),
            ],
        );
        let got = ui_template_of_expr(&node, None).expect("templatable");
        assert_eq!(
            got,
            CompileUiTemplate::TaggedNode {
                tag: "section".to_string(),
                desc: CompileUiDesc::DescMain,
                attrs: vec![CompileUiAttr::FontSize(16)],
                children: vec![CompileUiTemplate::Text("Body".to_string())],
            }
        );
    }

    #[test]
    fn nested_min_max_length_templates() {
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![kcall(
                    KernelFn::UiWidth,
                    vec![kcall(
                        KernelFn::UiMaximum,
                        vec![Expr::Int(320), kcall(KernelFn::UiVh, vec![Expr::Int(80)])],
                    )],
                )]),
                child_list(vec![]),
            ],
        );
        let got = ui_template_of_expr(&node, None).expect("templatable");
        assert_eq!(
            got,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![CompileUiAttr::Width(CompileUiLength::Max(
                    320,
                    Box::new(CompileUiLength::Vh(80))
                ))],
                children: vec![],
            }
        );
    }

    // ── acceptance: structural wrapper resolution ─────────────────────────────

    /// `el attrs child = node descNone attrs [child]`
    /// — inlines to `Node { desc: NoDescription, attrs: [spacing 8], children: [text "hi"] }`.
    #[test]
    fn wrapper_el_inlines_to_node() {
        // params: (attrs_sym=10, child_sym=11)
        // body:   ui_node_(descNone, Var(10), List [Var(11)])
        let attrs_sym = sym(10);
        let child_sym = sym(11);
        let body = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                Expr::Var(attrs_sym),
                Expr::List {
                    elem: IrType::Ui {
                        ctor: UiCtor::Element,
                        msg: Box::new(IrType::Int),
                    },
                    items: vec![Expr::Var(child_sym)],
                },
            ],
        );
        let wrappers = one_wrapper(1, vec![attrs_sym, child_sym], body);

        // call: el [spacing 8] (text "hi")
        let call = fcall(
            1,
            vec![
                attr_list(vec![kcall(KernelFn::UiSpacing, vec![Expr::Int(8)])]),
                text("hi"),
            ],
        );
        let got = ui_template_of_expr(&call, Some(&wrappers)).expect("el templatizes");
        assert_eq!(
            got,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![CompileUiAttr::Spacing(8)],
                children: vec![CompileUiTemplate::Text("hi".to_string())],
            }
        );
    }

    /// `row attrs children = node descNone (style "__row" "true" :: attrs) children`
    /// — the Cons prepend of the marker attr is folded into the accepted attr list.
    #[test]
    fn wrapper_row_cons_prepend_templatizes() {
        // params: (attrs_sym=20, children_sym=21)
        // body:   ui_node_(descNone, Cons(style "__row" "true", Var(20)), Var(21))
        let attrs_sym = sym(20);
        let children_sym = sym(21);
        let marker = kcall(
            KernelFn::UiStyle,
            vec![
                Expr::Str("__row".to_string()),
                Expr::Str("true".to_string()),
            ],
        );
        let body = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                Expr::Cons {
                    head: Box::new(marker),
                    tail: Box::new(Expr::Var(attrs_sym)),
                },
                Expr::Var(children_sym),
            ],
        );
        let wrappers = one_wrapper(2, vec![attrs_sym, children_sym], body);

        // call: row [spacing 4] [text "a", text "b"]
        let call = fcall(
            2,
            vec![
                attr_list(vec![kcall(KernelFn::UiSpacing, vec![Expr::Int(4)])]),
                child_list(vec![text("a"), text("b")]),
            ],
        );
        let got = ui_template_of_expr(&call, Some(&wrappers)).expect("row templatizes");
        assert_eq!(
            got,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![
                    CompileUiAttr::Style("__row".to_string(), "true".to_string()),
                    CompileUiAttr::Spacing(4),
                ],
                children: vec![
                    CompileUiTemplate::Text("a".to_string()),
                    CompileUiTemplate::Text("b".to_string()),
                ],
            }
        );
    }

    /// `column attrs children = node descNone (style "__col" "true" :: attrs) children`
    #[test]
    fn wrapper_column_cons_prepend_templatizes() {
        let attrs_sym = sym(30);
        let children_sym = sym(31);
        let marker = kcall(
            KernelFn::UiStyle,
            vec![
                Expr::Str("__col".to_string()),
                Expr::Str("true".to_string()),
            ],
        );
        let body = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                Expr::Cons {
                    head: Box::new(marker),
                    tail: Box::new(Expr::Var(attrs_sym)),
                },
                Expr::Var(children_sym),
            ],
        );
        let wrappers = one_wrapper(3, vec![attrs_sym, children_sym], body);

        let call = fcall(3, vec![attr_list(vec![]), child_list(vec![text("x")])]);
        let got = ui_template_of_expr(&call, Some(&wrappers)).expect("column templatizes");
        assert_eq!(
            got,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![CompileUiAttr::Style(
                    "__col".to_string(),
                    "true".to_string()
                )],
                children: vec![CompileUiTemplate::Text("x".to_string())],
            }
        );
    }

    /// `text` is a kernel alias — the kernel path already handles `Ui.text`
    /// directly; the wrapper table is not consulted for a kernel callee.
    #[test]
    fn text_kernel_templatizes_without_wrapper_table() {
        assert_eq!(
            ui_template_of_expr(&text("hello"), None),
            Some(CompileUiTemplate::Text("hello".to_string()))
        );
    }

    // ── refusal: wrapper with non-literal / model-dependent args ─────────────

    /// A wrapper call whose attrs contain a `Model`-read (`Expr::Var`) refuses.
    #[test]
    fn wrapper_with_model_dependent_arg_refuses() {
        let attrs_sym = sym(40);
        let child_sym = sym(41);
        let body = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                Expr::Var(attrs_sym),
                Expr::List {
                    elem: IrType::Ui {
                        ctor: UiCtor::Element,
                        msg: Box::new(IrType::Int),
                    },
                    items: vec![Expr::Var(child_sym)],
                },
            ],
        );
        let wrappers = one_wrapper(4, vec![attrs_sym, child_sym], body);

        // Attrs list is a Var (Model-dependent) — must refuse.
        let call = fcall(
            4,
            vec![
                Expr::Var(sym(99)), // model-dependent attrs
                text("hi"),
            ],
        );
        assert_eq!(ui_template_of_expr(&call, Some(&wrappers)), None);
    }

    /// A wrapper call with a handler attribute refuses.
    #[test]
    fn wrapper_with_event_handler_refuses() {
        let attrs_sym = sym(50);
        let child_sym = sym(51);
        let body = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                Expr::Var(attrs_sym),
                Expr::List {
                    elem: IrType::Ui {
                        ctor: UiCtor::Element,
                        msg: Box::new(IrType::Int),
                    },
                    items: vec![Expr::Var(child_sym)],
                },
            ],
        );
        let wrappers = one_wrapper(5, vec![attrs_sym, child_sym], body);

        let call = fcall(
            5,
            vec![
                attr_list(vec![kcall(KernelFn::UiOnClick, vec![Expr::Var(sym(99))])]),
                text("hi"),
            ],
        );
        assert_eq!(ui_template_of_expr(&call, Some(&wrappers)), None);
    }

    /// An unrecognised `Callee::Func` (not in the wrapper table) refuses.
    #[test]
    fn unrecognised_func_callee_refuses() {
        let wrappers: BTreeMap<FuncId, WrapperBody> = BTreeMap::new();
        let call = fcall(99, vec![attr_list(vec![]), child_list(vec![])]);
        assert_eq!(ui_template_of_expr(&call, Some(&wrappers)), None);
    }

    /// A `Callee::Func` with `wrappers = None` refuses (no table — conservative).
    #[test]
    fn func_callee_without_wrapper_table_refuses() {
        let call = fcall(1, vec![attr_list(vec![]), child_list(vec![])]);
        assert_eq!(ui_template_of_expr(&call, None), None);
    }

    // ── refusal: not provably static ⇒ keep compiled (None) ──────────────────

    #[test]
    fn model_read_child_refuses() {
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![]),
                child_list(vec![Expr::Var(sym(1))]),
            ],
        );
        assert_eq!(ui_template_of_expr(&node, None), None);
    }

    #[test]
    fn embedded_raw_html_child_refuses() {
        // `Ui.html (...)` embeds a `Html` node — not a static `Ipe.Ui` node.
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![]),
                child_list(vec![kcall(KernelFn::UiHtml, vec![Expr::Var(sym(2))])]),
            ],
        );
        assert_eq!(ui_template_of_expr(&node, None), None);
    }

    #[test]
    fn event_handler_attribute_refuses() {
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![kcall(KernelFn::UiOnClick, vec![Expr::Var(sym(3))])]),
                child_list(vec![]),
            ],
        );
        assert_eq!(ui_template_of_expr(&node, None), None);
    }

    #[test]
    fn literal_color_bearing_attribute_templatizes() {
        // `Font.color (rgb 1 2 3)` is inert and over a literal color, so it
        // templatizes with the alpha defaulted to `1.0` (matching `ui_rgb_`). A
        // Model-derived color still refuses (`model_derived_color_refuses`).
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![kcall(
                    KernelFn::FontColor,
                    vec![kcall(
                        KernelFn::UiRgb,
                        vec![Expr::Int(1), Expr::Int(2), Expr::Int(3)],
                    )],
                )]),
                child_list(vec![]),
            ],
        );
        assert_eq!(
            ui_template_of_expr(&node, None),
            Some(CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![CompileUiAttr::FontColor(CompileUiColor {
                    r: 1,
                    g: 2,
                    b: 3,
                    a: 1.0,
                })],
                children: vec![],
            })
        );
    }

    #[test]
    fn non_literal_attr_value_refuses() {
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![kcall(
                    KernelFn::UiStyle,
                    vec![Expr::Str("color".to_string()), Expr::Var(sym(4))],
                )]),
                child_list(vec![]),
            ],
        );
        assert_eq!(ui_template_of_expr(&node, None), None);
    }

    #[test]
    fn non_literal_tag_refuses() {
        let node = kcall(
            KernelFn::UiTaggedNode,
            vec![
                Expr::Var(sym(5)),
                desc_none(),
                attr_list(vec![]),
                child_list(vec![]),
            ],
        );
        assert_eq!(ui_template_of_expr(&node, None), None);
    }

    #[test]
    fn button_record_config_refuses() {
        // `Ui.button` carries an `onPress` handler record — never a static node.
        assert_eq!(
            ui_template_of_expr(&kcall(KernelFn::UiButton, vec![]), None),
            None
        );
    }

    // ── acceptance: single-Color and single-Float attributes ─────────────────

    fn rgb(r: i64, g: i64, b: i64) -> Expr {
        kcall(
            KernelFn::UiRgb,
            vec![Expr::Int(r), Expr::Int(g), Expr::Int(b)],
        )
    }

    fn rgba(r: i64, g: i64, b: i64, a: f64) -> Expr {
        kcall(
            KernelFn::UiRgba,
            vec![Expr::Int(r), Expr::Int(g), Expr::Int(b), Expr::Float(a)],
        )
    }

    #[test]
    fn font_color_rgb_templatizes() {
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![kcall(KernelFn::FontColor, vec![rgb(10, 20, 30)])]),
                child_list(vec![]),
            ],
        );
        let got = ui_template_of_expr(&node, None).expect("font color templatizes");
        assert_eq!(
            got,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![CompileUiAttr::FontColor(super::CompileUiColor {
                    r: 10,
                    g: 20,
                    b: 30,
                    a: 1.0,
                })],
                children: vec![],
            }
        );
    }

    #[test]
    fn bg_and_border_color_rgba_templatize() {
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![
                    kcall(KernelFn::BackgroundColor, vec![rgba(1, 2, 3, 0.25)]),
                    kcall(
                        KernelFn::BorderColor,
                        vec![kcall(KernelFn::UiBlack, vec![])],
                    ),
                ]),
                child_list(vec![]),
            ],
        );
        let got = ui_template_of_expr(&node, None).expect("bg/border color templatize");
        assert_eq!(
            got,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![
                    CompileUiAttr::BgColor(super::CompileUiColor {
                        r: 1,
                        g: 2,
                        b: 3,
                        a: 0.25,
                    }),
                    CompileUiAttr::BorderColor(super::CompileUiColor {
                        r: 0,
                        g: 0,
                        b: 0,
                        a: 1.0,
                    }),
                ],
                children: vec![],
            }
        );
    }

    #[test]
    fn letter_and_word_spacing_float_templatize() {
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![
                    kcall(KernelFn::FontLetterSpacing, vec![Expr::Float(1.5)]),
                    kcall(KernelFn::FontWordSpacing, vec![Expr::Float(0.5)]),
                ]),
                child_list(vec![]),
            ],
        );
        let got = ui_template_of_expr(&node, None).expect("spacing templatizes");
        assert_eq!(
            got,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![
                    CompileUiAttr::FontLetterSpacing(1.5),
                    CompileUiAttr::FontWordSpacing(0.5),
                ],
                children: vec![],
            }
        );
    }

    #[test]
    fn non_finite_letter_spacing_literal_refuses() {
        // `Font.letterSpacing (1.0 / 0.0)` reaches the capture as `Expr::Float(∞)`
        // after const-folding. It has no `serde_json` number form (the compiled
        // path emits `null`), so templatizing it in pure mode must refuse rather
        // than bake a diverging `0.0`.
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![kcall(
                    KernelFn::FontLetterSpacing,
                    vec![Expr::Float(f64::INFINITY)],
                )]),
                child_list(vec![]),
            ],
        );
        assert_eq!(ui_template_of_expr(&node, None), None);
    }

    #[test]
    fn non_finite_rgba_alpha_literal_refuses() {
        // `Ui.rgba 1 2 3 (0.0 / 0.0)` — a NaN alpha has no JSON number form, so the
        // color capture refuses and the node stays compiled.
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![kcall(
                    KernelFn::FontColor,
                    vec![kcall(
                        KernelFn::UiRgba,
                        vec![
                            Expr::Int(1),
                            Expr::Int(2),
                            Expr::Int(3),
                            Expr::Float(f64::NAN),
                        ],
                    )],
                )]),
                child_list(vec![]),
            ],
        );
        assert_eq!(ui_template_of_expr(&node, None), None);
    }

    // ── refusal: Model-derived / non-literal color, colorCss, deferred shadow ─

    #[test]
    fn model_derived_color_refuses() {
        // `Font.color model.accent` — the color arg is a Model read, not a literal.
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![kcall(KernelFn::FontColor, vec![Expr::Var(sym(7))])]),
                child_list(vec![]),
            ],
        );
        assert_eq!(ui_template_of_expr(&node, None), None);
    }

    #[test]
    fn color_css_string_form_refuses() {
        // `Ui.colorCss "red"` is a string color the runtime `Color::Rgba` variant
        // does not carry — refuse, keep compiled.
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![kcall(
                    KernelFn::FontColor,
                    vec![kcall(
                        KernelFn::UiColorCss,
                        vec![Expr::Str("red".to_string())],
                    )],
                )]),
                child_list(vec![]),
            ],
        );
        assert_eq!(ui_template_of_expr(&node, None), None);
    }

    #[test]
    fn model_derived_letter_spacing_refuses() {
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![kcall(
                    KernelFn::FontLetterSpacing,
                    vec![Expr::Var(sym(8))],
                )]),
                child_list(vec![]),
            ],
        );
        assert_eq!(ui_template_of_expr(&node, None), None);
    }

    // ── holes: value / control-flow / list ───────────────────────────────────

    use super::{HoleFill, HoleKind, ui_template_of_expr_holes};

    /// A `Ui.text <non-literal>` — a value leaf that becomes an element hole.
    fn model_text(binder: u32) -> Expr {
        kcall(KernelFn::UiText, vec![Expr::Var(sym(binder))])
    }

    // A value hole: `column [] [text "count: ", text model.count]` — the static
    // text stays in the template, the model-derived text is `Hole(0)` + a fill.
    #[test]
    fn value_hole_partitions_and_collects_fill() {
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![]),
                child_list(vec![text("count: "), model_text(50)]),
            ],
        );
        let part = ui_template_of_expr_holes(&node, None).expect("value-hole subtree templatizes");
        assert_eq!(
            part.template,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![],
                children: vec![
                    CompileUiTemplate::Text("count: ".to_string()),
                    CompileUiTemplate::Hole(0),
                ],
            }
        );
        assert_eq!(
            part.holes,
            vec![HoleFill {
                kind: HoleKind::Element,
                expr: model_text(50),
            }]
        );
    }

    // A control-flow hole: an `if` whose both arms are templatizable becomes a
    // `ControlFlowHole` — the arm subtrees ride the template, only the arm
    // selector (`if cond { 0 } else { 1 }`) is compiled.
    #[test]
    #[allow(clippy::indexing_slicing)]
    fn control_flow_hole_if_both_arms_templatizable() {
        let cond = kcall(KernelFn::UiText, vec![Expr::Str("ignored".to_string())]);
        let iff = Expr::If {
            cond: Box::new(Expr::Var(sym(60))),
            then_: Box::new(text("on")),
            else_: Box::new(text("off")),
        };
        let node = kcall(
            KernelFn::UiNode,
            vec![desc_none(), attr_list(vec![]), child_list(vec![iff, cond])],
        );
        let part =
            ui_template_of_expr_holes(&node, None).expect("if with templatizable arms templatizes");
        // Template: ControlFlowHole(0) carries the two static arm subtrees.
        assert_eq!(
            part.template,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![],
                children: vec![
                    CompileUiTemplate::ControlFlowHole {
                        hole_id: 0,
                        arms: vec![
                            CompileUiTemplate::Text("on".to_string()),
                            CompileUiTemplate::Text("off".to_string()),
                        ],
                    },
                    CompileUiTemplate::Text("ignored".to_string()),
                ],
            }
        );
        // No element holes (the arms are in the template, not compiled fills).
        assert!(
            part.holes.is_empty(),
            "no element holes when both arms templatize"
        );
        // One CF hole: the arm-selector expression `if cond { 0 } else { 1 }`.
        assert_eq!(part.cf_holes.len(), 1);
        assert_eq!(part.cf_holes[0].kind, HoleKind::ControlFlow);
        let expected_selector = Expr::If {
            cond: Box::new(Expr::Var(sym(60))),
            then_: Box::new(Expr::Int(0)),
            else_: Box::new(Expr::Int(1)),
        };
        assert_eq!(part.cf_holes[0].expr, expected_selector);
    }

    // When at least one arm is non-templatizable the whole `if` falls back to an
    // opaque element hole — the pre-CF-hole behaviour.
    #[test]
    fn control_flow_hole_if_non_templatizable_arm_falls_back_to_element_hole() {
        // `else_` contains a model-read `Ui.text model.val` — non-templatizable in
        // pure/holes-only mode because it is a non-literal text leaf (element hole
        // shape), but for STRUCTURE we need the ELEMENT itself to be templatizable.
        // Actually model_text is templatizable (it becomes a value-Hole inside the
        // arm). To get a truly non-templatizable arm we use a raw HTML node.
        let cond_expr = Expr::Var(sym(61));
        let non_static_arm = kcall(KernelFn::UiHtml, vec![Expr::Var(sym(62))]);
        let iff = Expr::If {
            cond: Box::new(cond_expr),
            then_: Box::new(text("on")),
            else_: Box::new(non_static_arm),
        };
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![]),
                child_list(vec![iff.clone()]),
            ],
        );
        let part = ui_template_of_expr_holes(&node, None)
            .expect("if with non-templatizable arm still templatizes as element hole");
        // Falls back to opaque element hole: the whole `if` is the fill.
        assert_eq!(
            part.template,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![],
                children: vec![CompileUiTemplate::Hole(0)],
            }
        );
        assert_eq!(
            part.holes,
            vec![HoleFill {
                kind: HoleKind::Element,
                expr: iff,
            }]
        );
        assert!(part.cf_holes.is_empty());
    }

    // A list hole: the whole children arg is `List.map itemView model.items`.
    #[test]
    fn list_map_children_is_one_children_hole() {
        let listmap = kcall(
            KernelFn::ListMap,
            vec![Expr::Var(sym(70)), Expr::Var(sym(71))],
        );
        let node = kcall(
            KernelFn::UiNode,
            vec![desc_none(), attr_list(vec![]), listmap.clone()],
        );
        let part = ui_template_of_expr_holes(&node, None).expect("list-map templatizes");
        assert_eq!(
            part.template,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![],
                children: vec![CompileUiTemplate::ChildrenHole(0)],
            }
        );
        assert_eq!(
            part.holes,
            vec![HoleFill {
                kind: HoleKind::Children,
                expr: listmap,
            }]
        );
    }

    // Per-kind indexing: two element holes and one children hole, interleaved,
    // number 0/1 (elements) and 0 (children) within their own slice.
    #[test]
    fn holes_number_per_kind() {
        let listmap = kcall(
            KernelFn::ListMap,
            vec![Expr::Var(sym(80)), Expr::Var(sym(81))],
        );
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![]),
                child_list(vec![model_text(82), listmap, model_text(83)]),
            ],
        );
        let part = ui_template_of_expr_holes(&node, None).expect("mixed holes templatize");
        assert_eq!(
            part.template,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![],
                children: vec![
                    CompileUiTemplate::Hole(0),
                    CompileUiTemplate::ChildrenHole(0),
                    CompileUiTemplate::Hole(1),
                ],
            }
        );
        assert_eq!(part.holes.len(), 3);
    }

    // Pure mode still refuses a model-derived leaf (no holes admitted) — the
    // shipped conservative behaviour is unchanged for the no-hole entry.
    #[test]
    fn pure_mode_refuses_model_leaf() {
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![]),
                child_list(vec![model_text(90)]),
            ],
        );
        assert_eq!(ui_template_of_expr(&node, None), None);
    }

    // A model-dependent `onClick` templatizes as a handler hole: the click event
    // plus hole id 0, with the `Msg` argument captured in `handlers[0]`. The
    // captured expression is the `Msg` only — the inert attribute carries no logic.
    #[test]
    fn model_dependent_onclick_becomes_handler_hole() {
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![kcall(KernelFn::UiOnClick, vec![Expr::Var(sym(91))])]),
                child_list(vec![text("go")]),
            ],
        );
        let part =
            ui_template_of_expr_holes(&node, None).expect("handler-hole subtree templatizes");
        assert_eq!(
            part.template,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![CompileUiAttr::HandlerHole {
                    event: "click",
                    handler_id: 0,
                }],
                children: vec![CompileUiTemplate::Text("go".to_string())],
            }
        );
        assert_eq!(part.handlers, vec![Expr::Var(sym(91))]);
        assert!(part.holes.is_empty());
    }

    // Each pure `OnMsg` Ui event maps to its DOM wire name; handler ids number in
    // source order across a node's attribute list.
    #[test]
    fn onmsg_events_map_to_wire_names_and_number_in_order() {
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![
                    kcall(KernelFn::UiOnFocus, vec![Expr::Var(sym(1))]),
                    kcall(KernelFn::UiOnMouseOut, vec![Expr::Var(sym(2))]),
                ]),
                child_list(vec![]),
            ],
        );
        let part = ui_template_of_expr_holes(&node, None).expect("templatizes");
        assert_eq!(
            part.template,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![
                    CompileUiAttr::HandlerHole {
                        event: "focus",
                        handler_id: 0,
                    },
                    CompileUiAttr::HandlerHole {
                        event: "mouseout",
                        handler_id: 1,
                    },
                ],
                children: vec![],
            }
        );
        assert_eq!(part.handlers, vec![Expr::Var(sym(1)), Expr::Var(sym(2))]);
    }

    // A value-carrying event (`onInput`, an `Arc<dyn Fn(String)->M>` closure) is
    // NOT a per-render `Msg` capture, so it refuses the whole subtree — it is not
    // a handler hole and stays compiled.
    #[test]
    fn value_carrying_event_refuses() {
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![kcall(KernelFn::UiOnInput, vec![Expr::Var(sym(3))])]),
                child_list(vec![]),
            ],
        );
        assert_eq!(ui_template_of_expr_holes(&node, None), None);
    }

    // Pure mode (the no-capture entry) refuses a handler exactly as it refuses a
    // model leaf — the shipped static-only behaviour is unchanged.
    #[test]
    fn pure_mode_refuses_handler() {
        let node = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                attr_list(vec![kcall(KernelFn::UiOnClick, vec![Expr::Var(sym(4))])]),
                child_list(vec![]),
            ],
        );
        assert_eq!(ui_template_of_expr(&node, None), None);
    }

    // JSON shape for a handler hole — pinned against the runtime
    // `UiTemplateAttr::HandlerHole` struct-variant serde form.
    #[test]
    fn json_handler_hole_shape() {
        let mut out = String::new();
        CompileUiAttr::HandlerHole {
            event: "click",
            handler_id: 2,
        }
        .write_json(&mut out);
        assert_eq!(out, r#"{"HandlerHole":{"event":"click","handler_id":2}}"#);
    }

    // JSON shape for the hole markers — pinned against the runtime serde form.
    #[test]
    fn json_hole_marker_shapes() {
        assert_eq!(CompileUiTemplate::Hole(3).to_json(), r#"{"Hole":3}"#);
        assert_eq!(
            CompileUiTemplate::ChildrenHole(0).to_json(),
            r#"{"ChildrenHole":0}"#
        );
    }

    // ── JSON shape: byte-identical to the runtime `UiTemplate` serde form ─────
    //
    // Pinned literals (verified against `serde_json::to_string(&UiTemplate)` —
    // the runtime crate's `str_materialize_matches_direct_render` proves the
    // render-equivalence half). A drift in the serializer is caught here without
    // pulling the runtime `ui` crate into the backend's dev build.

    #[test]
    fn json_text_node_shape() {
        assert_eq!(
            CompileUiTemplate::Text("hi".to_string()).to_json(),
            r#"{"Text":"hi"}"#
        );
    }

    #[test]
    fn json_empty_node_shape() {
        assert_eq!(CompileUiTemplate::Empty.to_json(), r#""Empty""#);
    }

    #[test]
    fn json_tagged_node_full_shape() {
        let t = CompileUiTemplate::TaggedNode {
            tag: "section".to_string(),
            desc: CompileUiDesc::DescHeading(2),
            attrs: vec![
                CompileUiAttr::Width(CompileUiLength::Max(320, Box::new(CompileUiLength::Vh(80)))),
                CompileUiAttr::Padding(1, 2, 3, 4),
                CompileUiAttr::Style("k".to_string(), "v".to_string()),
                CompileUiAttr::AlignX("CenterX"),
                CompileUiAttr::Pointer,
                CompileUiAttr::FontAlign("center"),
                CompileUiAttr::FontColor(CompileUiColor {
                    r: 10,
                    g: 20,
                    b: 30,
                    a: 1.0,
                }),
                CompileUiAttr::BgColor(CompileUiColor {
                    r: 1,
                    g: 2,
                    b: 3,
                    a: 0.25,
                }),
                CompileUiAttr::FontLetterSpacing(1.5),
            ],
            children: vec![
                CompileUiTemplate::Text("hi".to_string()),
                CompileUiTemplate::Empty,
            ],
        };
        let expected = concat!(
            r#"{"TaggedNode":{"tag":"section","desc":{"DescHeading":2},"attrs":["#,
            r#"{"Width":{"Max":[320,{"Vh":80}]}},{"Padding":[1,2,3,4]},{"Style":["k","v"]},"#,
            r#"{"AlignX":"CenterX"},"Pointer",{"FontAlign":"center"},"#,
            r#"{"FontColor":{"r":10,"g":20,"b":30,"a":1.0}},"#,
            r#"{"BgColor":{"r":1,"g":2,"b":3,"a":0.25}},{"FontLetterSpacing":1.5}],"#,
            r#""children":[{"Text":"hi"},"Empty"]}}"#,
        );
        assert_eq!(t.to_json(), expected);
    }

    #[test]
    fn json_node_shape() {
        let t = CompileUiTemplate::Node {
            desc: CompileUiDesc::NoDescription,
            attrs: vec![CompileUiAttr::Spacing(8)],
            children: vec![],
        };
        assert_eq!(
            t.to_json(),
            r#"{"Node":{"desc":"NoDescription","attrs":[{"Spacing":8}],"children":[]}}"#
        );
    }

    // Byte-shape pin for the single-Color attributes: the `UiColor` struct form
    // `{"r":R,"g":G,"b":B,"a":A}` with the alpha in `ryu`'s shortest form
    // (`1.0` / `0.25`). Verified byte-identical to the runtime serde form by the
    // runtime pin `backend_baked_json_decodes_to_the_described_tree` (extended to
    // carry a color), so a drift on either side fails one of the two pins.
    #[test]
    fn json_color_attr_shape() {
        assert_eq!(
            CompileUiAttr::FontColor(CompileUiColor {
                r: 10,
                g: 20,
                b: 30,
                a: 1.0,
            })
            .attr_json(),
            r#"{"FontColor":{"r":10,"g":20,"b":30,"a":1.0}}"#
        );
        assert_eq!(
            CompileUiAttr::BgColor(CompileUiColor {
                r: 1,
                g: 2,
                b: 3,
                a: 0.25,
            })
            .attr_json(),
            r#"{"BgColor":{"r":1,"g":2,"b":3,"a":0.25}}"#
        );
    }

    // Byte-shape pin for the single-Float attributes: the alpha/spacing float in
    // `ryu` shortest form. `ryu` always renders a decimal point (`1.5`, `0.5`),
    // matching `serde_json`'s `write_f64`.
    #[test]
    fn json_float_attr_shape() {
        assert_eq!(
            CompileUiAttr::FontLetterSpacing(1.5).attr_json(),
            r#"{"FontLetterSpacing":1.5}"#
        );
        assert_eq!(
            CompileUiAttr::FontWordSpacing(0.5).attr_json(),
            r#"{"FontWordSpacing":0.5}"#
        );
    }

    // `ryu`'s float spelling matches `serde_json`'s exactly (serde_json's
    // `write_f64` calls `ryu::Buffer::format_finite`). This pins the equivalence
    // directly for the alpha values a template can carry, so the single-source-of-
    // truth claim is a standing check, not a comment.
    #[test]
    fn ryu_float_matches_serde_json() {
        for a in [1.0f64, 0.0, 0.5, 0.25, 0.18, 0.08, 0.9, 1.5, 100.0, 0.1] {
            let mut baked = String::new();
            super::push_f64(a, &mut baked);
            assert_eq!(
                baked,
                serde_json::to_string(&a).expect("serialize f64"),
                "ryu float spelling must equal serde_json for {a}"
            );
        }
    }

    /// `column [padding 8] [row [htmlAttr "class" "marker"] [text "uno"], text "two"]`
    /// — two wrappers, one nested as child of the other, both must templatize.
    /// Mirrors the exact fixture used in the wrapper SEAL test after the
    /// structural (add-child) edit.
    #[test]
    fn wrapper_column_containing_row_and_text_templatizes() {
        // row: id=2, params=(attrs_sym=20, children_sym=21)
        // body: node descNone (style "__row" "true" :: Var(20)) Var(21)
        let row_attrs_sym = sym(20);
        let row_children_sym = sym(21);
        let row_marker = kcall(
            KernelFn::UiStyle,
            vec![
                Expr::Str("__row".to_string()),
                Expr::Str("true".to_string()),
            ],
        );
        let row_body = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                Expr::Cons {
                    head: Box::new(row_marker),
                    tail: Box::new(Expr::Var(row_attrs_sym)),
                },
                Expr::Var(row_children_sym),
            ],
        );

        // column: id=3, params=(attrs_sym=30, children_sym=31)
        // body: node descNone (style "__col" "true" :: Var(30)) Var(31)
        let col_attrs_sym = sym(30);
        let col_children_sym = sym(31);
        let col_marker = kcall(
            KernelFn::UiStyle,
            vec![
                Expr::Str("__col".to_string()),
                Expr::Str("true".to_string()),
            ],
        );
        let col_body = kcall(
            KernelFn::UiNode,
            vec![
                desc_none(),
                Expr::Cons {
                    head: Box::new(col_marker),
                    tail: Box::new(Expr::Var(col_attrs_sym)),
                },
                Expr::Var(col_children_sym),
            ],
        );

        let mut wrappers: BTreeMap<FuncId, WrapperBody> = BTreeMap::new();
        wrappers.insert(
            FuncId::from_raw(2),
            (vec![row_attrs_sym, row_children_sym], row_body),
        );
        wrappers.insert(
            FuncId::from_raw(3),
            (vec![col_attrs_sym, col_children_sym], col_body),
        );

        // call: column [padding 8] [row [htmlAttr "class" "marker"] [text "uno"], text "two"]
        let row_call = fcall(
            2,
            vec![
                attr_list(vec![kcall(
                    KernelFn::UiHtmlAttribute,
                    vec![
                        Expr::Str("class".to_string()),
                        Expr::Str("marker".to_string()),
                    ],
                )]),
                child_list(vec![text("uno")]),
            ],
        );
        let col_call = fcall(
            3,
            vec![
                attr_list(vec![kcall(KernelFn::UiPadding, vec![Expr::Int(8)])]),
                child_list(vec![row_call, text("two")]),
            ],
        );

        let got = ui_template_of_expr(&col_call, Some(&wrappers))
            .expect("column(row(...), text) must templatize");
        assert_eq!(
            got,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![
                    CompileUiAttr::Style("__col".to_string(), "true".to_string()),
                    CompileUiAttr::Padding(8, 8, 8, 8),
                ],
                children: vec![
                    CompileUiTemplate::Node {
                        desc: CompileUiDesc::NoDescription,
                        attrs: vec![
                            CompileUiAttr::Style("__row".to_string(), "true".to_string()),
                            CompileUiAttr::Attribute("class".to_string(), "marker".to_string()),
                        ],
                        children: vec![CompileUiTemplate::Text("uno".to_string())],
                    },
                    CompileUiTemplate::Text("two".to_string()),
                ],
            }
        );
    }

    // ── list hole (Step 2) ───────────────────────────────────────────────────

    // `List.map (\item -> Ui.text item) xs` — item body is a templatizable
    // `Ui.text` leaf whose single arg is the item parameter. The whole children
    // arg becomes `ListHole(0)` with `item_template = Hole(0)` (one element
    // hole per item), and the list_holes fill captures `xs` + the raw fill
    // expression `Ui.text item` (containing free `Var(item_sym)`).
    #[test]
    fn list_map_lambda_with_templatizable_body_becomes_list_hole() {
        let item_sym = sym(100);
        let xs_sym = sym(101);
        // item body: `Ui.text item` — a templatizable leaf (item param is a
        // non-literal arg, so it becomes an element hole inside the item template).
        let item_body = kcall(KernelFn::UiText, vec![Expr::Var(item_sym)]);
        let lambda = Expr::Lambda {
            params: vec![(item_sym, IrType::Str)],
            ret: IrType::Ui {
                ctor: UiCtor::Element,
                msg: Box::new(IrType::Int),
            },
            body: Box::new(item_body.clone()),
        };
        let listmap = kcall(KernelFn::ListMap, vec![lambda, Expr::Var(xs_sym)]);
        let node = kcall(
            KernelFn::UiNode,
            vec![desc_none(), attr_list(vec![]), listmap],
        );
        let part = ui_template_of_expr_holes(&node, None)
            .expect("List.map with templatizable item body templatizes");
        // Template: one ListHole(0) child; item_template has a single Hole(0).
        assert_eq!(
            part.template,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![],
                children: vec![CompileUiTemplate::ListHole {
                    hole_id: 0,
                    item_template: Box::new(CompileUiTemplate::Hole(0)),
                }],
            }
        );
        // No element / children / CF holes at the outer level.
        assert!(part.holes.is_empty(), "no outer element holes");
        assert!(part.cf_holes.is_empty(), "no CF holes");
        // One list hole fill: xs + item_sym + one fill expr (the item_body).
        let lh = part.list_holes.first().expect("one list hole");
        assert_eq!(lh.xs, Expr::Var(xs_sym));
        assert_eq!(lh.item_sym, item_sym);
        assert_eq!(lh.item_fills, vec![item_body]);
    }

    // `List.map (\item -> text "static") xs` — item body has NO holes (fully
    // static). Becomes `ListHole(0)` with `item_template = Text("static")` and
    // `item_fills = []` (zero element holes).
    #[test]
    fn list_map_lambda_static_body_becomes_list_hole_no_fills() {
        let item_sym = sym(102);
        let xs_sym = sym(103);
        let lambda = Expr::Lambda {
            params: vec![(item_sym, IrType::Str)],
            ret: IrType::Ui {
                ctor: UiCtor::Element,
                msg: Box::new(IrType::Int),
            },
            body: Box::new(text("static")),
        };
        let listmap = kcall(KernelFn::ListMap, vec![lambda, Expr::Var(xs_sym)]);
        let node = kcall(
            KernelFn::UiNode,
            vec![desc_none(), attr_list(vec![]), listmap],
        );
        let part = ui_template_of_expr_holes(&node, None).expect("static item body templatizes");
        assert_eq!(
            part.template,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![],
                children: vec![CompileUiTemplate::ListHole {
                    hole_id: 0,
                    item_template: Box::new(CompileUiTemplate::Text("static".to_string())),
                }],
            }
        );
        assert!(
            part.list_holes
                .first()
                .expect("one list hole")
                .item_fills
                .is_empty()
        );
    }

    // `List.map f xs` where f is NOT a Lambda (a Var reference to an opaque
    // function) — falls back to `ChildrenHole`, the pre-Step-2 behaviour.
    #[test]
    fn list_map_opaque_fn_falls_back_to_children_hole() {
        let f_sym = sym(104);
        let xs_sym = sym(105);
        let listmap = kcall(KernelFn::ListMap, vec![Expr::Var(f_sym), Expr::Var(xs_sym)]);
        let node = kcall(
            KernelFn::UiNode,
            vec![desc_none(), attr_list(vec![]), listmap.clone()],
        );
        let part = ui_template_of_expr_holes(&node, None)
            .expect("opaque-fn list-map falls back to ChildrenHole");
        assert_eq!(
            part.template,
            CompileUiTemplate::Node {
                desc: CompileUiDesc::NoDescription,
                attrs: vec![],
                children: vec![CompileUiTemplate::ChildrenHole(0)],
            }
        );
        assert!(part.list_holes.is_empty(), "no list holes for opaque fn");
        assert_eq!(
            part.holes,
            vec![HoleFill {
                kind: HoleKind::Children,
                expr: listmap,
            }]
        );
    }

    // JSON shape for `ListHole` — byte-identical to the runtime
    // `UiTemplate::ListHole` serde form.
    #[test]
    fn json_list_hole_shape() {
        let t = CompileUiTemplate::ListHole {
            hole_id: 0,
            item_template: Box::new(CompileUiTemplate::Hole(0)),
        };
        assert_eq!(
            t.to_json(),
            r#"{"ListHole":{"hole_id":0,"item_template":{"Hole":0}}}"#
        );
    }

    // ── WrapperHole — JSON shape pin ─────────────────────────────────────────

    // `WrapperHole` serializes as `{"WrapperHole":{"hole_id":N,"child":<tmpl>}}`
    // — the runtime `UiTemplate::WrapperHole` struct-variant serde form. Pinned
    // here so a drift on either side fails both the backend and runtime pin.
    #[test]
    fn json_wrapper_hole_shape() {
        let t = CompileUiTemplate::WrapperHole {
            hole_id: 0,
            child: Box::new(CompileUiTemplate::Text("label".to_string())),
        };
        assert_eq!(
            t.to_json(),
            r#"{"WrapperHole":{"hole_id":0,"child":{"Text":"label"}}}"#
        );
    }

    // ── WrapperHole recognizer ───────────────────────────────────────────────

    // Helper: `UiTaggedNode(tag, descNone, attrs_expr, children)` kernel call.
    fn tagged_node(tag: &str, attrs_expr: Expr, children: Expr) -> Expr {
        kcall(
            KernelFn::UiTaggedNode,
            vec![
                Expr::Str(tag.to_string()),
                desc_none(),
                attrs_expr,
                children,
            ],
        )
    }

    // An `if` whose arms are `UiTaggedNode` calls with the SAME children and
    // different tags → recognized as a `WrapperHole`.
    #[test]
    fn wrapper_hole_if_with_same_children_recognized() {
        use super::ui_template_of_expr_holes;
        let shared_children = child_list(vec![text("label")]);

        let then_ = tagged_node("a", attr_list(vec![]), shared_children.clone());
        let else_ = tagged_node("span", attr_list(vec![]), shared_children);

        let expr = Expr::If {
            cond: Box::new(Expr::Var(sym(1))),
            then_: Box::new(then_),
            else_: Box::new(else_),
        };

        let result =
            ui_template_of_expr_holes(&expr, None).expect("should templatize as wrapper hole");
        assert!(
            matches!(
                result.template,
                CompileUiTemplate::WrapperHole { hole_id: 0, .. }
            ),
            "expected WrapperHole(0), got {:?}",
            result.template
        );
        assert_eq!(result.wrapper_holes.len(), 1, "one wrapper fill expected");
        let fill = result.wrapper_holes.first().expect("one wrapper fill");
        assert_eq!(fill.wrapper_arms.len(), 2, "two wrapper arm templates");
        // Arm 0 is the `a` tag, arm 1 is the `span` tag.
        assert!(
            matches!(fill.wrapper_arms.first().expect("arm 0"), CompileUiTemplate::TaggedNode { tag, .. } if tag == "a"),
            "arm 0 must be TaggedNode(a)"
        );
        assert!(
            matches!(fill.wrapper_arms.get(1).expect("arm 1"), CompileUiTemplate::TaggedNode { tag, .. } if tag == "span"),
            "arm 1 must be TaggedNode(span)"
        );
    }

    // An `if` whose arms have DIFFERENT children → NOT a wrapper hole; falls back
    // to CF hole (both arms are templatizable) or opaque element hole.
    #[test]
    fn wrapper_hole_if_with_different_children_not_recognized() {
        use super::ui_template_of_expr_holes;
        let children_a = child_list(vec![text("link")]);
        let children_b = child_list(vec![text("label")]);

        let then_ = tagged_node("a", attr_list(vec![]), children_a);
        let else_ = tagged_node("span", attr_list(vec![]), children_b);

        let expr = Expr::If {
            cond: Box::new(Expr::Var(sym(1))),
            then_: Box::new(then_),
            else_: Box::new(else_),
        };

        let result =
            ui_template_of_expr_holes(&expr, None).expect("should templatize (CF or element hole)");
        assert!(
            !matches!(result.template, CompileUiTemplate::WrapperHole { .. }),
            "different children must NOT produce a WrapperHole, got {:?}",
            result.template
        );
        assert!(result.wrapper_holes.is_empty(), "no wrapper holes expected");
    }

    // WrapperHole JSON serializes to the byte-identical serde form the runtime
    // decodes — the baked default round-trips through the runtime decoder.
    #[test]
    fn wrapper_hole_json_is_byte_identical_to_runtime_serde() {
        // The JSON the backend emits for a WrapperHole with a Text child.
        let backend_json = CompileUiTemplate::WrapperHole {
            hole_id: 0,
            child: Box::new(CompileUiTemplate::Text("label".to_string())),
        }
        .to_json();
        assert_eq!(
            backend_json, r#"{"WrapperHole":{"hole_id":0,"child":{"Text":"label"}}}"#,
            "backend JSON must match the runtime serde form"
        );
    }
}

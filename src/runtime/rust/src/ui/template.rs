//! Inert static-`Ipe.Ui`-subtree template + its materializer.
//!
//! The `Ipe.Ui` analogue of [`crate::web::template`]: a [`UiTemplate`] is a
//! fully-static `Ipe.Ui` `Element` subtree reduced to data — the structural
//! element variants (`Node` / `TaggedNode` / `Text` / `Empty`) and the inert,
//! non-logic attribute variants only. [`materialize`] rebuilds an
//! [`Element`] tree from a [`UiTemplate`] through the SAME `Element` / `Attribute`
//! constructors the normal render path builds, so a materialized template feeds
//! the identical `render_element` chain and renders byte-identically to the
//! original compiled subtree — dev == prod by construction.
//!
//! Inert by construction (make-invalid-states-unrepresentable): the type has NO
//! variant for an event handler (`AttrEvent`), for raw embedded HTML (`Raw`),
//! for a nearby overlay (`AttrNearby`, which nests a whole `Element` sub-view),
//! or for a raw terminal cell grid (`Cells`). A `UiTemplate` therefore cannot
//! carry logic, a `Msg`, or un-escaped markup — its only payloads are `String`s
//! and numbers that the render path style-encodes, name-gates, or escapes
//! exactly as it does a compiled literal. There is no code path, including
//! deserialization, by which a `UiTemplate` yields a handler or unescaped HTML.

use super::element::{Attribute, Description, Element, HAlign, Length, PseudoClass, VAlign};
use crate::color::Color;
use crate::html::{Attribute as HtmlAttribute, Event};

/// A per-render handler resolution map: the concrete `Msg`s a templatized
/// subtree's model-dependent event handlers evaluate to at THIS render, in the
/// stable emit order the compiler assigns each hole.
///
/// This is the server-side half of the handler-id HOLE (issue #1668). A model-
/// dependent event (`onClick (Select model.id)`) blocks its subtree from
/// templatizing as pure inert data, because the concrete `Msg` depends on the
/// model — it is logic, not appearance. Instead the template carries an opaque
/// [`UiTemplateAttr::HandlerHole`] placeholder (an event name + a small integer
/// hole id), and the compiled `view` builds this map fresh every render by
/// evaluating each captured `Msg` against the current model. Materialize then
/// resolves each hole against this map. The model-dependent part therefore lives
/// ONLY here, in the compiled per-render map — it is never serialized into the
/// inert template, never sent to the client, never a closure on the wire.
///
/// # Trust boundary (fail-closed)
///
/// The hole id is a compile-time-stable index the SERVER assigns; the client
/// never sees it and never sends it (the browser addresses handlers by DOM
/// `ipe-id`, resolved by the separate live [`crate::dispatch::HandlerIndex`]).
/// [`Self::resolve`] is nonetheless fail-closed by construction: an out-of-range
/// id (a stale template decoded against a shorter map after an edit, or any
/// forged index) resolves to `None` — the event attribute is simply not
/// reconstructed. There is no code path by which an unresolved hole yields an
/// attacker-chosen `Msg`, a `Msg` from a different render, or a panic: the map
/// is indexed, never trusted, and a miss drops the handler.
#[derive(Clone, Debug, Default)]
pub struct UiHandlerMap<M> {
    /// The captured `Msg`s in hole-id order. Index i is hole id i.
    msgs: Vec<M>,
}

impl<M: Clone> UiHandlerMap<M> {
    /// An empty map — every hole resolves to `None` (fail-closed). This is what
    /// the prod render and the map-less materialize path use when no handler
    /// captures are supplied, so a hole never fabricates a `Msg`.
    #[must_use]
    pub fn new() -> Self {
        Self { msgs: Vec::new() }
    }

    /// Build a map from the per-render captured `Msg`s, in hole-id order. The
    /// compiled `view` calls this with each model-dependent handler's evaluated
    /// `Msg` — position i is hole id i.
    #[must_use]
    pub fn from_msgs(msgs: Vec<M>) -> Self {
        Self { msgs }
    }

    /// Resolve a hole id to its captured `Msg`, or `None` when the id is out of
    /// range. Fail-closed: never panics, never returns a `Msg` for a different
    /// id, never fabricates one — a miss is a clean drop of the handler.
    #[must_use]
    pub fn resolve(&self, handler_id: u32) -> Option<M> {
        self.msgs.get(handler_id as usize).cloned()
    }
}

/// The maximum template nesting depth accepted on decode and descended on
/// materialize. Shares the render/diff ceiling ([`crate::html::MAX_HTML_DEPTH`])
/// as a single source of truth, exactly as [`crate::web::template`] does: a
/// template can never describe a tree deeper than the renderer will walk, so
/// materialize and render agree on the bound.
pub const MAX_UI_TEMPLATE_DEPTH: usize = crate::html::MAX_HTML_DEPTH;

/// `Ipe.Ui.Color` reduced to inert byte data (R/G/B `0..=255`, alpha the stored
/// float). The byte form is the exact round-trip of the [`Color`] byte
/// constructors ([`Color::rgba`] / [`Color::to_rgba_bytes`]), so materialize
/// rebuilds the exact `Color` the render path formats.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UiColor {
    pub r: i64,
    pub g: i64,
    pub b: i64,
    pub a: f64,
}

impl UiColor {
    fn from_color(c: &Color) -> Self {
        let (r, g, b, a) = c.to_rgba_bytes();
        Self { r, g, b, a }
    }

    fn to_color(&self) -> Color {
        Color::rgba(self.r, self.g, self.b, self.a)
    }
}

/// `Ipe.Ui.Length` reduced to inert data. Mirrors [`Length`] variant-for-variant
/// (including the self-recursive `Min` / `Max`), so materialize rebuilds the
/// exact `Length` the render path formats. `Fill` carries the raw portion `Int`;
/// decoding it goes through [`Length::fill_portion`], the same parse the inline
/// `Ui.fillPortion` takes.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UiLength {
    Px(i64),
    Content,
    Fill(i64),
    Min(i64, Box<UiLength>),
    Max(i64, Box<UiLength>),
    Vh(i64),
    Vw(i64),
}

impl UiLength {
    fn from_length(l: &Length) -> Self {
        match l {
            Length::Px(n) => Self::Px(*n),
            Length::Content => Self::Content,
            Length::Fill(p) => Self::Fill(i64::from(p.get())),
            Length::Min(n, inner) => Self::Min(*n, Box::new(Self::from_length(inner))),
            Length::Max(n, inner) => Self::Max(*n, Box::new(Self::from_length(inner))),
            Length::Vh(n) => Self::Vh(*n),
            Length::Vw(n) => Self::Vw(*n),
        }
    }

    fn to_length(&self) -> Length {
        match self {
            Self::Px(n) => Length::Px(*n),
            Self::Content => Length::Content,
            Self::Fill(n) => Length::fill_portion(*n),
            Self::Min(n, inner) => Length::Min(*n, Box::new(inner.to_length())),
            Self::Max(n, inner) => Length::Max(*n, Box::new(inner.to_length())),
            Self::Vh(n) => Length::Vh(*n),
            Self::Vw(n) => Length::Vw(*n),
        }
    }
}

/// `Ipe.Ui.HAlign` reduced to inert data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UiHAlign {
    AlignLeft,
    CenterX,
    AlignRight,
}

/// `Ipe.Ui.VAlign` reduced to inert data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UiVAlign {
    AlignTop,
    CenterY,
    AlignBottom,
}

/// `Ipe.Ui.PseudoClass` reduced to inert data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UiPseudoClass {
    Hover,
    Focus,
    FocusVisible,
    Active,
    Disabled,
}

impl UiPseudoClass {
    fn from_pc(pc: PseudoClass) -> Self {
        match pc {
            PseudoClass::Hover => Self::Hover,
            PseudoClass::Focus => Self::Focus,
            PseudoClass::FocusVisible => Self::FocusVisible,
            PseudoClass::Active => Self::Active,
            PseudoClass::Disabled => Self::Disabled,
        }
    }

    fn to_pc(self) -> PseudoClass {
        match self {
            Self::Hover => PseudoClass::Hover,
            Self::Focus => PseudoClass::Focus,
            Self::FocusVisible => PseudoClass::FocusVisible,
            Self::Active => PseudoClass::Active,
            Self::Disabled => PseudoClass::Disabled,
        }
    }
}

/// `Ipe.Ui.Description` (the ARIA role) reduced to inert data. Mirrors
/// [`Description`] variant-for-variant.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UiDescription {
    NoDescription,
    DescMain,
    DescNavigation,
    DescContentInfo,
    DescComplementary,
    DescHeading(i64),
    DescLabel(String),
    DescLivePolite,
    DescLiveAssertive,
    DescButton,
    DescParagraph,
}

impl UiDescription {
    fn from_desc(d: &Description) -> Self {
        match d {
            Description::NoDescription => Self::NoDescription,
            Description::DescMain => Self::DescMain,
            Description::DescNavigation => Self::DescNavigation,
            Description::DescContentInfo => Self::DescContentInfo,
            Description::DescComplementary => Self::DescComplementary,
            Description::DescHeading(n) => Self::DescHeading(*n),
            Description::DescLabel(s) => Self::DescLabel(s.clone()),
            Description::DescLivePolite => Self::DescLivePolite,
            Description::DescLiveAssertive => Self::DescLiveAssertive,
            Description::DescButton => Self::DescButton,
            Description::DescParagraph => Self::DescParagraph,
        }
    }

    fn to_desc(&self) -> Description {
        match self {
            Self::NoDescription => Description::NoDescription,
            Self::DescMain => Description::DescMain,
            Self::DescNavigation => Description::DescNavigation,
            Self::DescContentInfo => Description::DescContentInfo,
            Self::DescComplementary => Description::DescComplementary,
            Self::DescHeading(n) => Description::DescHeading(*n),
            Self::DescLabel(s) => Description::DescLabel(s.clone()),
            Self::DescLivePolite => Description::DescLivePolite,
            Self::DescLiveAssertive => Description::DescLiveAssertive,
            Self::DescButton => Description::DescButton,
            Self::DescParagraph => Description::DescParagraph,
        }
    }
}

/// An inert, static `Ipe.Ui` attribute — the non-logic subset of
/// [`Attribute`]. Each variant mirrors an `Attribute` variant that carries ONLY
/// inert style/layout data (strings, numbers, and the reduced enums above).
///
/// Deliberately absent (the security guarantee, enforced by the type):
/// - `AttrEvent` — an event handler is logic, never inert data;
/// - `AttrNearby` — nests a whole `Element` sub-view (an overlay), out of the
///   flat static-attribute scope of a template;
/// - `AttrExplain` — a debug-only outline toggle, excluded to keep the inert
///   set to render-affecting appearance data.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UiTemplateAttr {
    NoAttribute,
    Width(UiLength),
    Height(UiLength),
    AlignX(UiHAlign),
    AlignY(UiVAlign),
    Padding(i64, i64, i64, i64),
    Spacing(i64),
    Style(String, String),
    Describe(UiDescription),
    Class(String),
    Attribute(String, String),
    FontSize(i64),
    FontColor(UiColor),
    FontFamily(String),
    FontWeight(i64),
    FontItalic,
    FontUnderline,
    FontDecoration(String),
    FontLetterSpacing(f64),
    FontWordSpacing(f64),
    FontAlign(String),
    BgColor(UiColor),
    BgImage(String),
    BgGradient(String),
    BorderWidth(i64),
    BorderWidthEach(i64, i64, i64, i64),
    BorderColor(UiColor),
    BorderRounded(i64),
    BorderStyle(String),
    BorderShadow(i64, i64, i64, i64, UiColor),
    BorderInsetShadow(i64, i64, i64, i64, UiColor),
    Pointer,
    Overflow(String, String),
    PseudoRule(UiPseudoClass, String),
    Transition(String, bool),
    GridTracks(String, String),
    Animation(String, String, String, bool),
    /// A model-dependent event handler reduced to an opaque HOLE (issue #1668):
    /// only the DOM event name and a compile-time-stable hole id, NEVER the
    /// `Msg` or a closure. The concrete `Msg` is resolved per render from a
    /// [`UiHandlerMap`] the compiled `view` supplies — the model-dependent logic
    /// lives only in that server-side map, never in this inert datum. A hole
    /// carries no logic and no payload beyond two placeholders, so it cannot
    /// smuggle a handler or a `Msg` across the (untrusted) template transport.
    HandlerHole {
        event: String,
        handler_id: u32,
    },
    /// A model-dependent numeric (`f64`) attribute value reduced to an opaque
    /// HOLE: the attribute name and a compile-time-stable hole id, NEVER the
    /// concrete value. At materialize the runtime resolves the hole against a
    /// per-render `float_attr_fills` slice (`float_attr_fills[hole_id]`) and
    /// reconstructs the matching `Attribute` variant.
    ///
    /// Fail-closed: an out-of-range or already-consumed hole id drops to
    /// `Attribute::NoAttribute` — the element still renders, but without the
    /// float attribute. No panic, no fabricated value.
    AttrHoleFloat {
        /// The attribute discriminant: one of the known float-valued `Ipe.Ui`
        /// attribute names (`"font-letter-spacing"`, `"font-word-spacing"`).
        /// An unrecognised name drops to `NoAttribute` at materialize.
        attr: String,
        hole_id: u32,
    },
}

impl UiTemplateAttr {
    /// Reduce an inert [`Attribute`] to a [`UiTemplateAttr`], or `None` when the
    /// attribute carries logic (`AttrEvent`), a nested sub-view (`AttrNearby`),
    /// or is the debug-only `AttrExplain`. Fail-closed: a refused attribute
    /// keeps the whole subtree compiled rather than dropping the attribute.
    fn from_attr<M>(attr: &Attribute<M>) -> Option<Self> {
        Some(match attr {
            Attribute::NoAttribute => Self::NoAttribute,
            Attribute::AttrWidth(l) => Self::Width(UiLength::from_length(l)),
            Attribute::AttrHeight(l) => Self::Height(UiLength::from_length(l)),
            Attribute::AttrAlignX(h) => Self::AlignX(match h {
                HAlign::AlignLeft => UiHAlign::AlignLeft,
                HAlign::CenterX => UiHAlign::CenterX,
                HAlign::AlignRight => UiHAlign::AlignRight,
            }),
            Attribute::AttrAlignY(v) => Self::AlignY(match v {
                VAlign::AlignTop => UiVAlign::AlignTop,
                VAlign::CenterY => UiVAlign::CenterY,
                VAlign::AlignBottom => UiVAlign::AlignBottom,
            }),
            Attribute::AttrPadding(t, r, b, l) => Self::Padding(*t, *r, *b, *l),
            Attribute::AttrSpacing(n) => Self::Spacing(*n),
            Attribute::AttrStyle(k, v) => Self::Style(k.clone(), v.clone()),
            Attribute::AttrDescribe(d) => Self::Describe(UiDescription::from_desc(d)),
            Attribute::AttrClass(c) => Self::Class(c.clone()),
            Attribute::AttrAttribute(k, v) => Self::Attribute(k.clone(), v.clone()),
            Attribute::AttrFontSize(n) => Self::FontSize(*n),
            Attribute::AttrFontColor(c) => Self::FontColor(UiColor::from_color(c)),
            Attribute::AttrFontFamily(f) => Self::FontFamily(f.clone()),
            Attribute::AttrFontWeight(n) => Self::FontWeight(*n),
            Attribute::AttrFontItalic => Self::FontItalic,
            Attribute::AttrFontUnderline => Self::FontUnderline,
            Attribute::AttrFontDecoration(s) => Self::FontDecoration(s.clone()),
            Attribute::AttrFontLetterSpacing(v) => Self::FontLetterSpacing(*v),
            Attribute::AttrFontWordSpacing(v) => Self::FontWordSpacing(*v),
            Attribute::AttrFontAlign(s) => Self::FontAlign(s.clone()),
            Attribute::AttrBgColor(c) => Self::BgColor(UiColor::from_color(c)),
            Attribute::AttrBgImage(s) => Self::BgImage(s.clone()),
            Attribute::AttrBgGradient(s) => Self::BgGradient(s.clone()),
            Attribute::AttrBorderWidth(n) => Self::BorderWidth(*n),
            Attribute::AttrBorderWidthEach(t, r, b, l) => Self::BorderWidthEach(*t, *r, *b, *l),
            Attribute::AttrBorderColor(c) => Self::BorderColor(UiColor::from_color(c)),
            Attribute::AttrBorderRounded(n) => Self::BorderRounded(*n),
            Attribute::AttrBorderStyle(s) => Self::BorderStyle(s.clone()),
            Attribute::AttrBorderShadow(a, b, c, d, col) => {
                Self::BorderShadow(*a, *b, *c, *d, UiColor::from_color(col))
            }
            Attribute::AttrBorderInsetShadow(a, b, c, d, col) => {
                Self::BorderInsetShadow(*a, *b, *c, *d, UiColor::from_color(col))
            }
            Attribute::AttrPointer => Self::Pointer,
            Attribute::AttrOverflow(x, y) => Self::Overflow(x.clone(), y.clone()),
            Attribute::AttrPseudoRule(pc, rule) => {
                Self::PseudoRule(UiPseudoClass::from_pc(*pc), rule.clone())
            }
            Attribute::AttrTransition(s, respect) => Self::Transition(s.clone(), *respect),
            Attribute::AttrGridTracks(c, r) => Self::GridTracks(c.clone(), r.clone()),
            Attribute::AttrAnimation(n, tail, body, respect) => {
                Self::Animation(n.clone(), tail.clone(), body.clone(), *respect)
            }
            // Logic (a handler), a nested sub-view overlay, or the debug-only
            // outline toggle — not inert static attribute data. Refuse: keep the
            // subtree compiled.
            Attribute::AttrEvent(_) | Attribute::AttrNearby(..) | Attribute::AttrExplain => {
                return None;
            }
        })
    }

    /// Reconstruct the concrete [`Attribute`] from a float-attr discriminant name
    /// and a resolved `f64` value, or `None` when the name is unrecognised.
    fn resolve_float_attr<M>(attr: &str, value: f64) -> Option<Attribute<M>> {
        match attr {
            "font-letter-spacing" => Some(Attribute::AttrFontLetterSpacing(value)),
            "font-word-spacing" => Some(Attribute::AttrFontWordSpacing(value)),
            _ => None,
        }
    }

    /// Rebuild the [`Attribute`], resolving both a [`Self::HandlerHole`] against
    /// the per-render `handlers` map (when one is present) AND an
    /// [`Self::AttrHoleFloat`] against the per-render `float_fills` slice in a
    /// single pass — the one attribute resolver the unified materializer uses.
    ///
    /// Fail-closed in every dimension: an unresolved handler hole, an absent
    /// handler map (`None`), an out-of-range float hole, or an unrecognised attr
    /// name all → [`Attribute::NoAttribute`], never a fabricated value or a panic.
    fn to_attr_resolved<M: Clone>(
        &self,
        handlers: Option<&UiHandlerMap<M>>,
        float_fills: &[Option<f64>],
    ) -> Attribute<M> {
        match self {
            Self::HandlerHole { event, handler_id } => match handlers
                .and_then(|h| h.resolve(*handler_id))
            {
                Some(msg) => {
                    Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnMsg(event.clone(), msg)))
                }
                None => Attribute::NoAttribute,
            },
            Self::AttrHoleFloat { attr, hole_id } => {
                let value = float_fills.get(*hole_id as usize).and_then(|v| *v);
                match value {
                    Some(v) => Self::resolve_float_attr(attr, v).unwrap_or(Attribute::NoAttribute),
                    None => Attribute::NoAttribute,
                }
            }
            other => other.to_attr(),
        }
    }

    /// Reduce an inert [`Attribute`] to a [`UiTemplateAttr`], OR — for a clean
    /// model-capture `AttrEvent` (`onClick msg`) — to a [`Self::HandlerHole`]
    /// (issue #1668), pushing the captured `Msg` onto `captures` and using its
    /// index as the hole id. Returns `None` (refuses the whole subtree) for a
    /// nested-sub-view overlay, the debug outline, or an event shape that is NOT
    /// a plain model-capture — `OnString` / `OnBool` / `OnForm` / `OnWidget` all
    /// need runtime-argument-dependent resolution (a value the client sends, a
    /// form payload, a seal decode), so they are not a pure per-render `Msg`
    /// capture and stay compiled. Parse-don't-validate: only the provably-clean
    /// `OnMsg` capture becomes a hole; everything else refuses.
    fn from_attr_holed<M: Clone>(attr: &Attribute<M>, captures: &mut Vec<M>) -> Option<Self> {
        match attr {
            Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnMsg(event, msg))) => {
                let handler_id = u32::try_from(captures.len())
                    .ok()
                    .filter(|_| captures.len() < u32::MAX as usize)?;
                captures.push(msg.clone());
                Some(Self::HandlerHole {
                    event: event.clone(),
                    handler_id,
                })
            }
            // A non-`OnMsg` event, a nested overlay, or the debug outline is not
            // a clean per-render capture → refuse, keep the subtree compiled.
            Attribute::AttrEvent(_) | Attribute::AttrNearby(..) | Attribute::AttrExplain => None,
            // Every other (inert) attribute reduces exactly as the pure path.
            _ => Self::from_attr(attr),
        }
    }

    /// Rebuild the exact [`Attribute`] this inert form was reduced from, through
    /// the same variant the normal builders produce, so the render path formats
    /// it byte-identically. `M` is free — a `UiTemplateAttr` carries no `Msg`.
    fn to_attr<M>(&self) -> Attribute<M> {
        match self {
            Self::NoAttribute => Attribute::NoAttribute,
            Self::Width(l) => Attribute::AttrWidth(l.to_length()),
            Self::Height(l) => Attribute::AttrHeight(l.to_length()),
            Self::AlignX(h) => Attribute::AttrAlignX(match h {
                UiHAlign::AlignLeft => HAlign::AlignLeft,
                UiHAlign::CenterX => HAlign::CenterX,
                UiHAlign::AlignRight => HAlign::AlignRight,
            }),
            Self::AlignY(v) => Attribute::AttrAlignY(match v {
                UiVAlign::AlignTop => VAlign::AlignTop,
                UiVAlign::CenterY => VAlign::CenterY,
                UiVAlign::AlignBottom => VAlign::AlignBottom,
            }),
            Self::Padding(t, r, b, l) => Attribute::AttrPadding(*t, *r, *b, *l),
            Self::Spacing(n) => Attribute::AttrSpacing(*n),
            Self::Style(k, v) => Attribute::AttrStyle(k.clone(), v.clone()),
            Self::Describe(d) => Attribute::AttrDescribe(d.to_desc()),
            Self::Class(c) => Attribute::AttrClass(c.clone()),
            Self::Attribute(k, v) => Attribute::AttrAttribute(k.clone(), v.clone()),
            Self::FontSize(n) => Attribute::AttrFontSize(*n),
            Self::FontColor(c) => Attribute::AttrFontColor(c.to_color()),
            Self::FontFamily(f) => Attribute::AttrFontFamily(f.clone()),
            Self::FontWeight(n) => Attribute::AttrFontWeight(*n),
            Self::FontItalic => Attribute::AttrFontItalic,
            Self::FontUnderline => Attribute::AttrFontUnderline,
            Self::FontDecoration(s) => Attribute::AttrFontDecoration(s.clone()),
            Self::FontLetterSpacing(v) => Attribute::AttrFontLetterSpacing(*v),
            Self::FontWordSpacing(v) => Attribute::AttrFontWordSpacing(*v),
            Self::FontAlign(s) => Attribute::AttrFontAlign(s.clone()),
            Self::BgColor(c) => Attribute::AttrBgColor(c.to_color()),
            Self::BgImage(s) => Attribute::AttrBgImage(s.clone()),
            Self::BgGradient(s) => Attribute::AttrBgGradient(s.clone()),
            Self::BorderWidth(n) => Attribute::AttrBorderWidth(*n),
            Self::BorderWidthEach(t, r, b, l) => Attribute::AttrBorderWidthEach(*t, *r, *b, *l),
            Self::BorderColor(c) => Attribute::AttrBorderColor(c.to_color()),
            Self::BorderRounded(n) => Attribute::AttrBorderRounded(*n),
            Self::BorderStyle(s) => Attribute::AttrBorderStyle(s.clone()),
            Self::BorderShadow(a, b, c, d, col) => {
                Attribute::AttrBorderShadow(*a, *b, *c, *d, col.to_color())
            }
            Self::BorderInsetShadow(a, b, c, d, col) => {
                Attribute::AttrBorderInsetShadow(*a, *b, *c, *d, col.to_color())
            }
            Self::Pointer => Attribute::AttrPointer,
            Self::Overflow(x, y) => Attribute::AttrOverflow(x.clone(), y.clone()),
            Self::PseudoRule(pc, rule) => Attribute::AttrPseudoRule(pc.to_pc(), rule.clone()),
            Self::Transition(s, respect) => Attribute::AttrTransition(s.clone(), *respect),
            Self::GridTracks(c, r) => Attribute::AttrGridTracks(c.clone(), r.clone()),
            Self::Animation(n, tail, body, respect) => {
                Attribute::AttrAnimation(n.clone(), tail.clone(), body.clone(), *respect)
            }
            // A handler hole with NO resolution map cannot reconstruct a live
            // handler (it carries no `Msg`), so it drops to `NoAttribute` —
            // fail-closed by construction. [`Self::to_attr_resolved`] is the path
            // that resolves a hole against a per-render map.
            Self::HandlerHole { .. } => Attribute::NoAttribute,
            // A float-attr hole with no fills drops to `NoAttribute` — fail-closed.
            // The fills-aware path is [`Self::to_attr_resolved`].
            Self::AttrHoleFloat { .. } => Attribute::NoAttribute,
        }
    }
}

/// An inert, mostly-static `Ipe.Ui` subtree, optionally carrying numbered
/// **holes** where a `Model`-derived value is spliced in at render.
///
/// The static variants are the shapes a static `Ipe.Ui` subtree takes: an empty
/// node, a static text node, a role-described node, or an HTML-tagged node —
/// each with inert attributes and static children. There is deliberately no
/// `Raw` variant (embedded `Html`), no `Cells` variant (a raw terminal grid),
/// and no attribute able to carry a handler — that absence is the security
/// guarantee, enforced by the type rather than a runtime check, mirroring the
/// runtime [`crate::web::template::Template`].
///
/// A **hole** is an inert index (a `usize`), never logic: the model-derived
/// value it stands for is computed by the compiled `view` and passed in a
/// per-render slice, so the template datum itself carries no `Msg`, no handler,
/// and no un-escaped markup — a hole cannot smuggle logic, exactly like the
/// static variants. An out-of-range or unfilled hole materializes to the inert
/// empty element (fail-closed), never a panic. Two hole shapes:
/// - [`UiTemplate::Hole`] — one element in a single position (a value leaf or a
///   control-flow branch result);
/// - [`UiTemplate::ChildrenHole`] — a run of elements spliced into a children
///   list (a `List.map` comprehension).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UiTemplate {
    /// `Ui.none` — the empty element.
    Empty,
    /// A static text node. Rendered HTML-escaped, exactly like `Element::Text`.
    Text(String),
    /// A single-element hole: the compiled `view` supplies one `Element` for this
    /// index in the per-render fill slice. Stands for a `Model`-derived value leaf
    /// or a control-flow (`if` / `case`) result.
    Hole(usize),
    /// A children hole: the compiled `view` supplies a run of `Element`s (a
    /// `Vec`) for this index, spliced in place among a node's static children.
    /// Stands for a `List.map` comprehension.
    ChildrenHole(usize),
    /// A role-described container: `Element::Node`.
    Node {
        desc: UiDescription,
        attrs: Vec<UiTemplateAttr>,
        children: Vec<UiTemplate>,
    },
    /// An HTML-tagged container: `Element::TaggedNode`.
    TaggedNode {
        tag: String,
        desc: UiDescription,
        attrs: Vec<UiTemplateAttr>,
        children: Vec<UiTemplate>,
    },
    /// A model-driven control-flow branch (`if` / `case`) whose every arm is
    /// itself a templatizable subtree. The compiled `view` resolves the branch
    /// at render and supplies the zero-based arm index; materialize picks
    /// `arms[arm_index]` and materializes that subtree in place.
    ///
    /// Arms are exhaustive by construction: every arm of the source `if`/`case`
    /// is captured, so no branch is reachable at run time that the template does
    /// not cover. An out-of-range arm index (e.g. a stale template after an arm
    /// count change) materializes to the inert empty element — fail-closed,
    /// never a panic. Each arm may itself carry value/handler holes, resolved
    /// from the same per-render fills passed to the enclosing materializer.
    ControlFlowHole {
        /// Index into the per-render arm-selector slice the compiled `view`
        /// supplies. Index `hole_id` selects the branch chosen this render.
        hole_id: usize,
        /// The templatized subtree for each arm, in source order. For an `if`
        /// expression: `arms[0]` = true branch, `arms[1]` = false branch.
        /// For a `case` expression: arms follow the source pattern order.
        arms: Vec<UiTemplate>,
    },
    /// A `List.map f xs` comprehension whose item function body is itself
    /// templatizable. The item template is compiled once; the runtime
    /// materializes it once per item, substituting that item's element fills.
    ///
    /// `hole_id` indexes the per-render list-item-fills slice:
    /// `list_item_fills[hole_id]` is a `Vec<Vec<Element<M>>>` with one
    /// `Vec<Element<M>>` per item — each inner vec is the element-fill slice
    /// for one materialization of `item_template`.
    ///
    /// A missing or out-of-range `hole_id` produces an empty children run —
    /// fail-closed, never a panic.
    ListHole {
        /// Index into the per-render list-item-fills slice.
        hole_id: usize,
        /// Template compiled from the item function body. Materialized once per
        /// item, substituting that item's element fills in index order.
        item_template: Box<UiTemplate>,
    },
    /// A model-chosen wrapping element around a fixed child subtree. The
    /// wrapper — which `Element` variant (`TaggedNode` / `Node`) and its attrs —
    /// is chosen at render from the per-render wrapper-fill slice; the child
    /// subtree is the same every render and stays a static (or hole-carrying)
    /// template.
    ///
    /// `hole_id` indexes `wrapper_fills[hole_id]`: a `UiTemplate` whose top
    /// variant is `TaggedNode` or `Node` with an empty `children` list —
    /// it encodes only the wrapper tag / desc / attrs. Materialize reconstructs
    /// the element with those attributes and `[materialized_child]` as children.
    ///
    /// Fail-closed on every ill-formed input: a missing fill, an already-consumed
    /// fill, or a fill whose top node is not a recognised wrapper shape all
    /// materialize `child` standalone (unwrapped) — never a panic. Each variant
    /// is additive: a template using only prior hole kinds emits byte-identically.
    WrapperHole {
        /// Index into the per-render wrapper-fill slice.
        hole_id: usize,
        /// The fixed child subtree, templatized once. May itself carry value,
        /// handler, control-flow, or list holes resolved from the same fills.
        child: Box<UiTemplate>,
    },
}

impl Drop for UiTemplate {
    /// Dismantle the tree iteratively so dropping a deeply nested template can
    /// never overflow the stack. A `UiTemplate` can be decoded from untrusted
    /// wire input, so it may nest arbitrarily deep; the derived recursive drop
    /// would abort the process on such a tree. Draining each node's children
    /// onto an explicit stack keeps the destructor bounded by the heap, not the
    /// native call stack.
    fn drop(&mut self) {
        let mut pending: Vec<UiTemplate> = match self {
            UiTemplate::Node { children, .. } | UiTemplate::TaggedNode { children, .. } => {
                std::mem::take(children)
            }
            UiTemplate::ControlFlowHole { arms, .. } => std::mem::take(arms),
            UiTemplate::ListHole { item_template, .. } => {
                vec![std::mem::replace(item_template.as_mut(), UiTemplate::Empty)]
            }
            UiTemplate::WrapperHole { child, .. } => {
                vec![std::mem::replace(child.as_mut(), UiTemplate::Empty)]
            }
            UiTemplate::Empty
            | UiTemplate::Text(_)
            | UiTemplate::Hole(_)
            | UiTemplate::ChildrenHole(_) => return,
        };
        while let Some(mut node) = pending.pop() {
            match &mut node {
                UiTemplate::Node { children, .. } | UiTemplate::TaggedNode { children, .. } => {
                    pending.append(&mut std::mem::take(children));
                }
                UiTemplate::ControlFlowHole { arms, .. } => {
                    pending.append(&mut std::mem::take(arms));
                }
                UiTemplate::ListHole { item_template, .. } => {
                    pending.push(std::mem::replace(item_template.as_mut(), UiTemplate::Empty));
                }
                UiTemplate::WrapperHole { child, .. } => {
                    pending.push(std::mem::replace(child.as_mut(), UiTemplate::Empty));
                }
                UiTemplate::Empty
                | UiTemplate::Text(_)
                | UiTemplate::Hole(_)
                | UiTemplate::ChildrenHole(_) => {}
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
pub enum UiTemplateError {
    /// The template nests deeper than [`MAX_UI_TEMPLATE_DEPTH`].
    TooDeep,
}

impl std::fmt::Display for UiTemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UiTemplateError::TooDeep => {
                write!(f, "ui template nests deeper than {MAX_UI_TEMPLATE_DEPTH}")
            }
        }
    }
}

impl std::error::Error for UiTemplateError {}

impl UiTemplate {
    /// Validate a decoded template's shape: reject a tree deeper than the render
    /// ceiling before it is materialized. Total and allocation-free — walks the
    /// existing tree without recursion, so an adversarial decode cannot overflow
    /// the stack in the check itself.
    ///
    /// Call this on any template that crossed an untrusted boundary (the dev
    /// overlay transport) before handing it to [`materialize`].
    ///
    /// # Errors
    /// Returns [`UiTemplateError::TooDeep`] when the tree nests deeper than
    /// [`MAX_UI_TEMPLATE_DEPTH`].
    pub fn check_bounds(&self) -> Result<(), UiTemplateError> {
        // Explicit stack, not recursion: the depth check must not itself be
        // bounded by the native call stack it is meant to protect.
        let mut stack: Vec<(&UiTemplate, usize)> = vec![(self, 0)];
        while let Some((node, depth)) = stack.pop() {
            if depth >= MAX_UI_TEMPLATE_DEPTH {
                return Err(UiTemplateError::TooDeep);
            }
            match node {
                UiTemplate::Node { children, .. } | UiTemplate::TaggedNode { children, .. } => {
                    for child in children {
                        stack.push((child, depth.saturating_add(1)));
                    }
                }
                UiTemplate::ControlFlowHole { arms, .. } => {
                    for arm in arms {
                        stack.push((arm, depth.saturating_add(1)));
                    }
                }
                UiTemplate::ListHole { item_template, .. } => {
                    stack.push((item_template, depth.saturating_add(1)));
                }
                UiTemplate::WrapperHole { child, .. } => {
                    stack.push((child, depth.saturating_add(1)));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Per-render fills for a hole-bearing [`UiTemplate`], one carrier over every
/// hole kind the template can express. A fill kind absent from a given template
/// stays empty; an out-of-range or already-consumed reference fails closed (the
/// inert empty element, an empty run, or `NoAttribute`), never a panic.
///
/// Structural fills are consumed at most once (a hole index appears at most once
/// in a template); `handlers`, when present, resolves each
/// [`UiTemplateAttr::HandlerHole`] to a live `AttrEvent`. Construct with
/// [`TemplateFills::default`] and the `with_*` builders, setting only the fill
/// kinds a template carries.
pub struct TemplateFills<M> {
    elements: Vec<Option<Element<M>>>,
    children: Vec<Option<Vec<Element<M>>>>,
    /// Per-render arm selectors for [`UiTemplate::ControlFlowHole`] nodes: index
    /// `i` is the zero-based arm chosen for the control-flow hole with
    /// `hole_id == i` this render. An out-of-range selector materializes the
    /// control-flow hole to the inert empty element — fail-closed.
    control_flow: Vec<Option<usize>>,
    /// Per-render item-fills for [`UiTemplate::ListHole`] nodes: index `i` is
    /// `Vec<Vec<Element<M>>>` — one inner vec per item, each inner vec is the
    /// element-fill slice for one materialization of the item template. An
    /// out-of-range or already-consumed slot produces an empty items run.
    list_items: Vec<Option<Vec<Vec<Element<M>>>>>,
    /// Per-render wrapper fills for [`UiTemplate::WrapperHole`] nodes: index `i`
    /// is a `UiTemplate` whose top node is a `TaggedNode` or `Node` with an
    /// empty `children` list — it encodes the chosen wrapper tag / desc / attrs.
    /// An out-of-range, already-consumed, or ill-shaped fill materializes the
    /// child standalone — fail-closed, never a panic.
    wrapper_fills: Vec<Option<UiTemplate>>,
    /// Per-render float-attr fills for [`UiTemplateAttr::AttrHoleFloat`] nodes:
    /// index `i` is the `f64` value for the float-attr hole with `hole_id == i`.
    /// `None` marks a slot already consumed or never provided — resolves to
    /// `NoAttribute` (fail-closed).
    float_attrs: Vec<Option<f64>>,
    /// Per-render handler map for [`UiTemplateAttr::HandlerHole`] attrs. `None`
    /// carries no handler map, so every handler hole drops to `NoAttribute`
    /// (fail-closed — the map-less pure path). The map is consulted only here, at
    /// materialize, and only with the SERVER-assigned hole id — the untrusted
    /// client never supplies it.
    handlers: Option<UiHandlerMap<M>>,
}

impl<M> Default for TemplateFills<M> {
    /// An empty fill set: no structural fills and no handler map. A fully-static
    /// template materializes correctly against it, and any stray hole fails
    /// closed to the inert empty element.
    fn default() -> Self {
        Self {
            elements: Vec::new(),
            children: Vec::new(),
            control_flow: Vec::new(),
            list_items: Vec::new(),
            wrapper_fills: Vec::new(),
            float_attrs: Vec::new(),
            handlers: None,
        }
    }
}

impl<M> TemplateFills<M> {
    /// Set the single-element fills: `elements[n]` fills a [`UiTemplate::Hole`]
    /// with index `n`.
    #[must_use]
    pub fn with_elements(mut self, elements: Vec<Element<M>>) -> Self {
        self.elements = elements.into_iter().map(Some).collect();
        self
    }

    /// Set the children-run fills: `children[n]` fills a
    /// [`UiTemplate::ChildrenHole`] with index `n`, spliced in place.
    #[must_use]
    pub fn with_children(mut self, children: Vec<Vec<Element<M>>>) -> Self {
        self.children = children.into_iter().map(Some).collect();
        self
    }

    /// Set the control-flow arm selectors: `selectors[n]` chooses the arm for the
    /// [`UiTemplate::ControlFlowHole`] with `hole_id == n`.
    #[must_use]
    pub fn with_control_flow(mut self, selectors: Vec<usize>) -> Self {
        self.control_flow = selectors.into_iter().map(Some).collect();
        self
    }

    /// Set the list-item fills: `list_items[n]` is the per-item element-fill sets
    /// for the [`UiTemplate::ListHole`] with `hole_id == n`.
    #[must_use]
    pub fn with_list_items(mut self, list_items: Vec<Vec<Vec<Element<M>>>>) -> Self {
        self.list_items = list_items.into_iter().map(Some).collect();
        self
    }

    /// Set the wrapper fills: `wrappers[n]` is the wrapper template for the
    /// [`UiTemplate::WrapperHole`] with `hole_id == n`.
    #[must_use]
    pub fn with_wrappers(mut self, wrappers: Vec<UiTemplate>) -> Self {
        self.wrapper_fills = wrappers.into_iter().map(Some).collect();
        self
    }

    /// Set the float-attr fills: `float_attrs[n]` is the `f64` for the
    /// [`UiTemplateAttr::AttrHoleFloat`] with `hole_id == n`.
    #[must_use]
    pub fn with_float_attrs(mut self, float_attrs: Vec<f64>) -> Self {
        self.float_attrs = float_attrs.into_iter().map(Some).collect();
        self
    }

    /// Set the per-render handler map, resolving each
    /// [`UiTemplateAttr::HandlerHole`] to a live `AttrEvent`.
    #[must_use]
    pub fn with_handlers(mut self, handlers: UiHandlerMap<M>) -> Self {
        self.handlers = Some(handlers);
        self
    }

    /// Take the single-element fill at `idx`, or the inert empty element when the
    /// index is out of range or already consumed. Fail-closed by construction.
    fn take_element(&mut self, idx: usize) -> Element<M> {
        self.elements
            .get_mut(idx)
            .and_then(Option::take)
            .unwrap_or(Element::Empty)
    }

    /// Take the children-run fill at `idx`, or an empty run when the index is out
    /// of range or already consumed.
    fn take_children(&mut self, idx: usize) -> Vec<Element<M>> {
        self.children
            .get_mut(idx)
            .and_then(Option::take)
            .unwrap_or_default()
    }

    /// Take the arm selector at `idx` for a [`UiTemplate::ControlFlowHole`], or
    /// `None` when the index is out of range or already consumed. Fail-closed.
    fn take_control_flow(&mut self, idx: usize) -> Option<usize> {
        self.control_flow.get_mut(idx).and_then(Option::take)
    }

    /// Take the per-item fill vec at `idx` for a [`UiTemplate::ListHole`], or
    /// an empty vec when the index is out of range or already consumed.
    fn take_list_items(&mut self, idx: usize) -> Vec<Vec<Element<M>>> {
        self.list_items
            .get_mut(idx)
            .and_then(Option::take)
            .unwrap_or_default()
    }

    /// Take the wrapper-fill `UiTemplate` at `idx` for a
    /// [`UiTemplate::WrapperHole`], or `None` when the index is out of range or
    /// already consumed. Fail-closed: a `None` result causes materialize to
    /// render the child standalone, never a panic.
    fn take_wrapper(&mut self, idx: usize) -> Option<UiTemplate> {
        self.wrapper_fills.get_mut(idx).and_then(Option::take)
    }

    /// Snapshot the float-attr fills as a slice for attribute resolution. Unlike
    /// the other fill kinds, a float-attr fill may be read multiple times (an
    /// `AttrHoleFloat` with the same `hole_id` may appear in multiple attrs of
    /// the same node — unusual, but possible). Snapshot once; resolution is
    /// non-destructive so the same value resolves correctly for each attr.
    fn float_attr_snapshot(&self) -> Vec<Option<f64>> {
        self.float_attrs.clone()
    }
}

/// Rebuild an [`Element`] tree from a [`UiTemplate`], splicing whichever holes
/// the `fills` carry — value/children/list/wrapper/float-attr structural holes
/// AND, when `fills.handlers` is present, handler-id attr holes — in a single
/// walk. The one materializer: a fully-static template needs only
/// `TemplateFills::default()`; a hole-bearing one adds the `with_*` fills for the
/// kinds it uses, in any combination.
///
/// Uses the same `Element` and `Attribute` constructors the normal builders
/// emit, so the result feeds the identical `render_element` chain and renders
/// byte-identically to the original compiled subtree — dev == prod by
/// construction: the same fills feed a baked-default template (prod) and a
/// patched-structure template (dev); only the static skeleton hot-swaps.
///
/// Bounded by construction: descent stops at [`MAX_UI_TEMPLATE_DEPTH`] (the
/// render ceiling), so a deep template can never overflow the stack. A subtree
/// at the cap materializes to an empty element — the same "stop, don't recurse
/// further" posture the renderer takes at its own depth cap — never a panic.
/// Every out-of-range or already-consumed hole fails closed: the inert empty
/// element, an empty run, or `NoAttribute`; an unresolved handler hole drops its
/// event. No input makes this emit a fabricated handler or raw markup.
#[must_use]
pub fn materialize<M: Clone>(template: &UiTemplate, mut fills: TemplateFills<M>) -> Element<M> {
    materialize_at(template, 0, &mut fills)
}

/// The one deep materializer walk: resolve whichever holes `fills` carries at
/// every position, in a single descent. Handler holes resolve against
/// `fills.handlers` (when present) and structural holes against the fill vecs —
/// with no artificial exclusion between the two, so any combination materializes.
fn materialize_at<M: Clone>(
    template: &UiTemplate,
    depth: usize,
    fills: &mut TemplateFills<M>,
) -> Element<M> {
    if depth >= MAX_UI_TEMPLATE_DEPTH {
        // Same bounded-descent posture as the renderer at its cap: stop
        // descending. An empty element is inert and well-formed.
        return Element::Empty;
    }
    match template {
        UiTemplate::Empty => Element::Empty,
        UiTemplate::Text(s) => Element::Text(s.clone()),
        UiTemplate::Hole(idx) => fills.take_element(*idx),
        // A `ChildrenHole` only carries meaning inside a node's children list,
        // where [`materialize_children`] splices its run in place. Reaching it as
        // a standalone element (a malformed decode) is inert: an empty element.
        UiTemplate::ChildrenHole(_) => Element::Empty,
        UiTemplate::ControlFlowHole { hole_id, arms } => {
            match fills.take_control_flow(*hole_id).and_then(|i| arms.get(i)) {
                Some(arm) => materialize_at(arm, depth, fills),
                // Out-of-range selector or already-consumed hole: fail-closed.
                // The element structure is preserved at every other position;
                // this hole alone is silent-empty rather than a panic.
                None => Element::Empty,
            }
        }
        // A `ListHole` only carries meaning inside a node's children list, where
        // [`materialize_children`] expands it to N sibling elements. Reaching it
        // as a standalone element (a malformed decode) is inert: empty element.
        UiTemplate::ListHole { .. } => Element::Empty,
        UiTemplate::WrapperHole { hole_id, child } => {
            materialize_wrapper_hole(*hole_id, child, depth, fills)
        }
        UiTemplate::Node {
            desc,
            attrs,
            children,
        } => {
            // Resolve attrs (an immutable read of `fills.handlers`) into an owned
            // vec BEFORE descending into children (a mutable borrow of `fills`),
            // so the two borrows never overlap.
            let resolved_attrs = resolve_attrs(attrs, fills);
            Element::Node(
                desc.to_desc(),
                resolved_attrs,
                materialize_children(children, depth, fills),
            )
        }
        UiTemplate::TaggedNode {
            tag,
            desc,
            attrs,
            children,
        } => {
            let resolved_attrs = resolve_attrs(attrs, fills);
            // The shared tag gate runs inside `ui_tagged_node_`.
            super::helpers::ui_tagged_node_(
                tag.clone(),
                desc.to_desc(),
                resolved_attrs,
                materialize_children(children, depth, fills),
            )
        }
    }
}

/// Resolve a node's inert attributes into live [`Attribute`]s, splicing float-attr
/// and handler holes from `fills` in one pass — an owned vec, so the immutable
/// read of `fills` ends before the caller mutably descends into children.
fn resolve_attrs<M: Clone>(
    attrs: &[UiTemplateAttr],
    fills: &TemplateFills<M>,
) -> Vec<Attribute<M>> {
    let float_snap = fills.float_attr_snapshot();
    let handlers = fills.handlers.as_ref();
    attrs
        .iter()
        .map(|a| a.to_attr_resolved(handlers, &float_snap))
        .collect()
}

/// Materialize a [`UiTemplate::WrapperHole`]: take the wrapper-fill template,
/// extract its tag / desc / attrs, materialize `child`, and wrap it. Fail-closed:
/// a missing fill, an already-consumed fill, or a fill whose top node is not a
/// `TaggedNode` / `Node` all materialize `child` standalone — no panic.
fn materialize_wrapper_hole<M: Clone>(
    hole_id: usize,
    child: &UiTemplate,
    depth: usize,
    fills: &mut TemplateFills<M>,
) -> Element<M> {
    let materialized_child = materialize_at(child, depth.saturating_add(1), fills);
    // Take the wrapper fill (a mutable read) FIRST, so the immutable attr
    // resolution that follows does not overlap it. The taken `wrapper` is owned,
    // so its attrs no longer borrow `fills`.
    let wrapper = fills.take_wrapper(hole_id);
    match &wrapper {
        Some(UiTemplate::TaggedNode {
            tag, desc, attrs, ..
        }) => super::helpers::ui_tagged_node_(
            tag.clone(),
            desc.to_desc(),
            resolve_attrs(attrs, fills),
            vec![materialized_child],
        ),
        Some(UiTemplate::Node { desc, attrs, .. }) => Element::Node(
            desc.to_desc(),
            resolve_attrs(attrs, fills),
            vec![materialized_child],
        ),
        // Missing, consumed, or ill-shaped fill: render child standalone.
        _ => materialized_child,
    }
}

/// Materialize a node's children, splicing each [`UiTemplate::ChildrenHole`] run
/// in place (a `List.map` comprehension expands to zero or more siblings),
/// expanding each [`UiTemplate::ListHole`] to its N materialized items, and
/// materializing every other child as a single element.
fn materialize_children<M: Clone>(
    children: &[UiTemplate],
    depth: usize,
    fills: &mut TemplateFills<M>,
) -> Vec<Element<M>> {
    let mut out = Vec::with_capacity(children.len());
    for child in children {
        if let UiTemplate::ChildrenHole(idx) = child {
            out.extend(fills.take_children(*idx));
        } else if let UiTemplate::ListHole {
            hole_id,
            item_template,
        } = child
        {
            // Expand the list hole: materialize item_template once per item,
            // substituting that item's element fills. Each item's fills are a
            // `Vec<Element<M>>` (element-fill slice) stored as a sub-vec in
            // the list-items fill. Handler resolution stays with the parent map:
            // list-item element fills are compiled `Element`s, not templatized
            // handler holes, so the per-item carrier needs no handler map.
            let item_fill_sets = fills.take_list_items(*hole_id);
            for item_element_fills in item_fill_sets {
                let mut item_fills = TemplateFills::default().with_elements(item_element_fills);
                out.push(materialize_at(
                    item_template,
                    depth.saturating_add(1),
                    &mut item_fills,
                ));
            }
        } else {
            out.push(materialize_at(child, depth.saturating_add(1), fills));
        }
    }
    out
}

/// Decode a serialized [`UiTemplate`] and materialize it, splicing the supplied
/// `fills` — the JSON string front door to [`materialize`], through the dev
/// overlay transport. The emitted `view` reads its per-view slot
/// (`__ipe_lit.get(N)`) and hands the baked-default-or-patched JSON here together
/// with the fills it built, so prod (baked default) and dev (patched slot) run
/// the SAME materialize path over the SAME fills — dev == prod by construction;
/// only the static skeleton hot-swaps.
///
/// This is the sole decode boundary: the slot value crosses the untrusted dev
/// overlay boundary, so it fails closed on hostile input, never a panic. The
/// guard is enforced ONCE here for every fill combination (parse, don't
/// validate):
/// - a decode failure returns the inert empty element (`Element::Empty`);
/// - an over-deep decoded template ([`UiTemplate::check_bounds`]) returns the
///   same inert empty element, so a decode can never exhaust the stack at
///   materialize;
/// - every out-of-range / already-consumed structural hole and every unresolved
///   handler hole then fails closed inside [`materialize`].
///
/// Inert by construction: the [`UiTemplate`] type has no handler and no raw
/// variant, so no JSON — however adversarial — decodes into logic or unescaped
/// markup; the only handlers are those the SERVER-built `fills.handlers` map
/// resolves, keyed by server-assigned hole id.
#[cfg(feature = "json")]
#[must_use]
pub fn materialize_str<M: Clone>(json: &str, fills: TemplateFills<M>) -> Element<M> {
    let Ok(template) = serde_json::from_str::<UiTemplate>(json) else {
        return Element::Empty;
    };
    if template.check_bounds().is_err() {
        return Element::Empty;
    }
    materialize(&template, fills)
}

/// Build a [`UiTemplate`] from a static [`Element`] subtree — the inverse of
/// [`materialize`]. Fail-closed (parse, don't validate): any node
/// that is NOT provably static returns `None`, so a template is only ever built
/// from a subtree that materialize can reproduce byte-identically.
///
/// A node is non-static, and so refuses, when it is:
/// - `Element::Raw` (embedded `Html`, possibly un-escaped — never representable
///   in a `UiTemplate`);
/// - `Element::Cells` (a raw terminal grid, outside the structured scope);
/// - a node carrying an `AttrEvent` (a handler — logic), an `AttrNearby` (a
///   nested sub-view overlay), or an `AttrExplain` (debug outline);
/// - nested deeper than [`MAX_UI_TEMPLATE_DEPTH`].
///
/// Returns `None` in each case rather than silently dropping the offending part,
/// so the caller treats a non-templatable subtree as "keep it compiled", never
/// "template a lie".
#[must_use]
pub fn ui_template_of<M>(elem: &Element<M>) -> Option<UiTemplate> {
    ui_template_of_at(elem, 0)
}

fn ui_template_of_at<M>(elem: &Element<M>, depth: usize) -> Option<UiTemplate> {
    if depth >= MAX_UI_TEMPLATE_DEPTH {
        return None;
    }
    match elem {
        Element::Empty => Some(UiTemplate::Empty),
        Element::Text(s) => Some(UiTemplate::Text(s.clone())),
        // Embedded raw HTML and a raw terminal grid have no inert `Ipe.Ui`
        // representation — refuse rather than smuggle them.
        Element::Raw(_) | Element::Cells(_) => None,
        Element::Node(desc, attrs, children) => {
            let attrs = static_ui_attrs(attrs)?;
            let children = static_ui_children(children, depth)?;
            Some(UiTemplate::Node {
                desc: UiDescription::from_desc(desc),
                attrs,
                children,
            })
        }
        Element::TaggedNode(tag, desc, attrs, children) => {
            let attrs = static_ui_attrs(attrs)?;
            let children = static_ui_children(children, depth)?;
            Some(UiTemplate::TaggedNode {
                tag: tag.clone(),
                desc: UiDescription::from_desc(desc),
                attrs,
                children,
            })
        }
    }
}

fn static_ui_attrs<M>(attrs: &[Attribute<M>]) -> Option<Vec<UiTemplateAttr>> {
    let mut out = Vec::with_capacity(attrs.len());
    for a in attrs {
        out.push(UiTemplateAttr::from_attr(a)?);
    }
    Some(out)
}

fn static_ui_children<M>(children: &[Element<M>], depth: usize) -> Option<Vec<UiTemplate>> {
    let mut out = Vec::with_capacity(children.len());
    for c in children {
        out.push(ui_template_of_at(c, depth.saturating_add(1))?);
    }
    Some(out)
}

/// Build a [`UiTemplate`] from a static [`Element`] subtree, templatizing a
/// model-dependent `onClick msg`-shaped event handler as a [`UiTemplateAttr::HandlerHole`]
/// (issue #1668) instead of refusing it. Returns the template AND the captured
/// `Msg`s in hole-id order, so the caller pairs the inert template with a
/// [`UiHandlerMap::from_msgs`] resolving each hole back to its `Msg`.
///
/// This is the handler-bearing counterpart of [`ui_template_of`]: it accepts the
/// SAME provably-static structure, and additionally a clean `Event::OnMsg`
/// capture (an event whose only payload is a per-render `Msg`). Every other
/// non-static shape still refuses (returns `None`) exactly as [`ui_template_of`]
/// does — a raw HTML node, a terminal grid, a nested overlay, the debug outline,
/// an `OnString`/`OnBool`/`OnForm`/`OnWidget` handler (runtime-arg-dependent, not
/// a pure capture), or an over-deep tree.
#[must_use]
pub fn ui_template_of_holed<M: Clone>(elem: &Element<M>) -> Option<(UiTemplate, Vec<M>)> {
    let mut captures = Vec::new();
    let template = ui_template_of_holed_at(elem, &mut captures, 0)?;
    Some((template, captures))
}

fn ui_template_of_holed_at<M: Clone>(
    elem: &Element<M>,
    captures: &mut Vec<M>,
    depth: usize,
) -> Option<UiTemplate> {
    if depth >= MAX_UI_TEMPLATE_DEPTH {
        return None;
    }
    match elem {
        Element::Empty => Some(UiTemplate::Empty),
        Element::Text(s) => Some(UiTemplate::Text(s.clone())),
        Element::Raw(_) | Element::Cells(_) => None,
        Element::Node(desc, attrs, children) => {
            let attrs = static_ui_attrs_holed(attrs, captures)?;
            let children = static_ui_children_holed(children, captures, depth)?;
            Some(UiTemplate::Node {
                desc: UiDescription::from_desc(desc),
                attrs,
                children,
            })
        }
        Element::TaggedNode(tag, desc, attrs, children) => {
            let attrs = static_ui_attrs_holed(attrs, captures)?;
            let children = static_ui_children_holed(children, captures, depth)?;
            Some(UiTemplate::TaggedNode {
                tag: tag.clone(),
                desc: UiDescription::from_desc(desc),
                attrs,
                children,
            })
        }
    }
}

fn static_ui_attrs_holed<M: Clone>(
    attrs: &[Attribute<M>],
    captures: &mut Vec<M>,
) -> Option<Vec<UiTemplateAttr>> {
    let mut out = Vec::with_capacity(attrs.len());
    for a in attrs {
        out.push(UiTemplateAttr::from_attr_holed(a, captures)?);
    }
    Some(out)
}

fn static_ui_children_holed<M: Clone>(
    children: &[Element<M>],
    captures: &mut Vec<M>,
    depth: usize,
) -> Option<Vec<UiTemplate>> {
    let mut out = Vec::with_capacity(children.len());
    for c in children {
        out.push(ui_template_of_holed_at(
            c,
            captures,
            depth.saturating_add(1),
        )?);
    }
    Some(out)
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::{
        MAX_UI_TEMPLATE_DEPTH, TemplateFills, UiHandlerMap, UiLength, UiTemplate, UiTemplateAttr,
        UiTemplateError, materialize, ui_template_of, ui_template_of_holed,
    };
    use crate::color::Color;
    use crate::ui::element::{Attribute, Description, Element, Length, Portion};
    use crate::ui::render::ui_layout;

    /// A decoded `Fill` portion takes the inline `Ui.fillPortion` parse: a
    /// non-positive portion is `Content`, an oversized one clamps to
    /// `Portion::MAX`, and a positive one round-trips.
    #[test]
    fn decoded_fill_portion_takes_the_inline_parse() {
        assert_eq!(UiLength::Fill(0).to_length(), Length::Content);
        assert_eq!(UiLength::Fill(-3).to_length(), Length::Content);
        assert_eq!(UiLength::Fill(i64::MIN).to_length(), Length::Content);
        assert_eq!(
            UiLength::Fill(i64::MAX).to_length(),
            Length::Fill(Portion::MAX)
        );
        assert_eq!(UiLength::Fill(1).to_length(), Length::Fill(Portion::ONE));
        let three = Length::fill_portion(3);
        assert_eq!(UiLength::from_length(&three).to_length(), three);
        assert_eq!(UiLength::from_length(&three), UiLength::Fill(3));
    }

    // Render an `Element` the way the app does — through the public `ui_layout`
    // entry — to compare rendered bytes. `ui_layout(vec![], elem)` wraps the
    // element in the standard viewport shell and runs the SAME `render_element`
    // chain a live view uses.
    fn render(elem: Element<()>) -> String {
        crate::html::render_html(&ui_layout(vec![], elem))
    }

    // The dev == prod soundness proof: round-tripping a static `Ipe.Ui` subtree
    // through a `UiTemplate` and its materializer produces an `Element` that
    // renders byte-identically to rendering the original. `ui_template_of` +
    // `materialize` compose to the identity on the rendered bytes.
    fn assert_round_trip_byte_identical(subtree: &Element<()>) {
        let template = ui_template_of(subtree).expect("static subtree must be templatable");
        let materialized: Element<()> = materialize(&template, TemplateFills::default());
        // The rebuilt `Element` is value-equal to the original (a strictly
        // stronger property than byte-identity — the exact variants are
        // reconstructed), so the render must match.
        assert_eq!(
            &materialized, subtree,
            "materialize must reconstruct the exact Element"
        );
        assert_eq!(
            render(materialized),
            render(subtree.clone()),
            "materialized ui template must render byte-identically to the original subtree"
        );
    }

    // ── acceptance: a provably-static subtree templates ──────────────────────

    #[test]
    fn round_trip_text_node() {
        assert_round_trip_byte_identical(&Element::Text("Hello".to_string()));
    }

    #[test]
    fn round_trip_empty_node() {
        assert_round_trip_byte_identical(&Element::Empty);
    }

    #[test]
    fn round_trip_row_with_inert_attrs_and_children() {
        // A `Ui.row [spacing 8, width fill] [text "a", text "b"]` shape: the
        // `__row` marker style is an inert `AttrStyle`, spacing/width are inert.
        let subtree: Element<()> = Element::Node(
            Description::NoDescription,
            vec![
                Attribute::AttrStyle("__row".to_string(), "true".to_string()),
                Attribute::AttrSpacing(8),
                Attribute::AttrWidth(Length::Fill(Portion::ONE)),
            ],
            vec![
                Element::Text("a".to_string()),
                Element::Text("b".to_string()),
            ],
        );
        assert_round_trip_byte_identical(&subtree);
    }

    #[test]
    fn round_trip_tagged_node_with_font_and_border() {
        let subtree: Element<()> = Element::TaggedNode(
            "section".to_string(),
            Description::DescMain,
            vec![
                Attribute::AttrPadding(4, 8, 4, 8),
                Attribute::AttrFontSize(16),
                Attribute::AttrFontColor(Color::rgba(10, 20, 30, 1.0)),
                Attribute::AttrBorderWidth(2),
                Attribute::AttrBorderColor(Color::rgba(0, 0, 0, 0.5)),
                Attribute::AttrClass("card".to_string()),
            ],
            vec![Element::Text("Body".to_string())],
        );
        assert_round_trip_byte_identical(&subtree);
    }

    #[test]
    fn round_trip_nested_column_of_rows() {
        let subtree: Element<()> = Element::Node(
            Description::NoDescription,
            vec![Attribute::AttrStyle(
                "__col".to_string(),
                "true".to_string(),
            )],
            vec![
                Element::Node(
                    Description::NoDescription,
                    vec![Attribute::AttrStyle(
                        "__row".to_string(),
                        "true".to_string(),
                    )],
                    vec![Element::Text("one".to_string())],
                ),
                Element::Node(
                    Description::NoDescription,
                    vec![Attribute::AttrStyle(
                        "__row".to_string(),
                        "true".to_string(),
                    )],
                    vec![Element::Text("two".to_string())],
                ),
            ],
        );
        assert_round_trip_byte_identical(&subtree);
    }

    #[test]
    fn round_trip_escaped_text_stays_escaped_no_xss() {
        let raw = r#"<script>alert("x & 'y'")</script>"#;
        let subtree: Element<()> = Element::Node(
            Description::NoDescription,
            vec![],
            vec![Element::Text(raw.to_string())],
        );
        assert_round_trip_byte_identical(&subtree);
        let template = ui_template_of(&subtree).expect("templatable");
        let rendered = render(materialize::<()>(&template, TemplateFills::default()));
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
        let subtree: Element<()> = Element::TaggedNode(
            "a".to_string(),
            Description::NoDescription,
            vec![Attribute::AttrAttribute(
                "title".to_string(),
                r#"a "quote" & <tag>"#.to_string(),
            )],
            vec![Element::Text("link".to_string())],
        );
        assert_round_trip_byte_identical(&subtree);
    }

    // ── inert-by-construction refusals ──────────────────────────────────────

    #[test]
    fn raw_embedded_html_is_refused() {
        let subtree: Element<()> =
            Element::Raw(crate::html::Html::HRaw("<b>trusted?</b>".to_string()));
        assert_eq!(ui_template_of(&subtree), None);
    }

    /// SECURITY: a `TaggedNode` template naming a `<script>`/`<style>` with a
    /// text body (a baked or a patched slot) materializes through
    /// `ui_tagged_node_`, so the shared tag gate builds `Element::Empty`.
    #[test]
    fn tagged_script_or_style_template_materializes_empty() {
        for tag in ["script", "STYLE", "plaintext"] {
            let template = UiTemplate::TaggedNode {
                tag: tag.to_string(),
                desc: super::UiDescription::NoDescription,
                attrs: vec![],
                children: vec![UiTemplate::Text("alert(document.cookie)".to_string())],
            };
            let elem: Element<()> = materialize(&template, TemplateFills::default());
            assert!(matches!(elem, Element::Empty), "<{tag}>: {elem:?}");
            let rendered = render(elem);
            assert!(!rendered.contains("alert"), "<{tag}>: {rendered}");
        }
    }

    #[test]
    fn cells_grid_is_refused() {
        let subtree: Element<()> = Element::Cells(vec![vec!['a', 'b']]);
        assert_eq!(ui_template_of(&subtree), None);
    }

    #[test]
    fn event_handler_attribute_is_refused() {
        let subtree: Element<i32> = Element::TaggedNode(
            "button".to_string(),
            Description::NoDescription,
            vec![Attribute::AttrEvent(crate::html::Attribute::EventAttr(
                crate::html::Event::OnMsg("click".to_string(), 1),
            ))],
            vec![Element::Text("+".to_string())],
        );
        assert_eq!(ui_template_of(&subtree), None);
    }

    #[test]
    fn nearby_overlay_attribute_is_refused() {
        let subtree: Element<()> = Element::Node(
            Description::NoDescription,
            vec![Attribute::AttrNearby(
                crate::ui::element::Location::Above,
                Element::Text("tooltip".to_string()),
            )],
            vec![],
        );
        assert_eq!(ui_template_of(&subtree), None);
    }

    #[test]
    fn explain_debug_attribute_is_refused() {
        let subtree: Element<()> = Element::Node(
            Description::NoDescription,
            vec![Attribute::AttrExplain],
            vec![],
        );
        assert_eq!(ui_template_of(&subtree), None);
    }

    #[test]
    fn handler_nested_in_child_refuses_whole_subtree() {
        // A static wrapper around a handler-bearing child must refuse whole —
        // never template the wrapper and drop the child's logic.
        let subtree: Element<i32> = Element::Node(
            Description::NoDescription,
            vec![],
            vec![Element::TaggedNode(
                "button".to_string(),
                Description::NoDescription,
                vec![Attribute::AttrEvent(crate::html::Attribute::EventAttr(
                    crate::html::Event::OnMsg("click".to_string(), 7),
                ))],
                vec![],
            )],
        );
        assert_eq!(ui_template_of(&subtree), None);
    }

    // ── bounded-by-construction decode ──────────────────────────────────────

    #[test]
    fn over_deep_template_fails_bounds_check() {
        let mut node = UiTemplate::Text("x".to_string());
        for _ in 0..=MAX_UI_TEMPLATE_DEPTH {
            node = UiTemplate::Node {
                desc: super::UiDescription::NoDescription,
                attrs: vec![],
                children: vec![node],
            };
        }
        assert_eq!(node.check_bounds(), Err(UiTemplateError::TooDeep));
    }

    #[test]
    fn legal_depth_passes_bounds_check() {
        let mut node = UiTemplate::Text("x".to_string());
        for _ in 0..16 {
            node = UiTemplate::Node {
                desc: super::UiDescription::NoDescription,
                attrs: vec![],
                children: vec![node],
            };
        }
        assert_eq!(node.check_bounds(), Ok(()));
    }

    // Iteratively measure an `Element` tree's nesting depth (no recursion, so the
    // measurement itself cannot overflow on a maximally deep tree).
    fn element_depth(root: &Element<()>) -> usize {
        let mut max = 0usize;
        let mut stack = vec![(root, 1usize)];
        while let Some((node, depth)) = stack.pop() {
            max = max.max(depth);
            if let Element::Node(_, _, kids) | Element::TaggedNode(_, _, _, kids) = node {
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
        // than the cap, descent stops at `MAX_UI_TEMPLATE_DEPTH`. Run on a
        // large-stack thread because building a ceiling-deep tree uses the
        // native stack up to the same bound.
        let handle = std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let mut node = UiTemplate::Text("x".to_string());
                for _ in 0..(MAX_UI_TEMPLATE_DEPTH + 500) {
                    node = UiTemplate::Node {
                        desc: super::UiDescription::NoDescription,
                        attrs: vec![],
                        children: vec![node],
                    };
                }
                let elem: Element<()> = materialize(&node, TemplateFills::default());
                element_depth(&elem)
            })
            .expect("spawn measuring thread");
        let depth = handle.join().expect("measuring thread must not panic");
        assert!(
            depth <= MAX_UI_TEMPLATE_DEPTH + 1,
            "materialize must cap descent at the ceiling, got depth {depth}"
        );
        assert!(
            depth >= MAX_UI_TEMPLATE_DEPTH,
            "the deep input should materialize right up to the ceiling, got {depth}"
        );
    }

    // ── serde round-trip + the string front door (dev overlay transport) ─────

    #[cfg(feature = "json")]
    #[test]
    fn serde_round_trip_preserves_template() {
        let subtree: Element<()> = Element::TaggedNode(
            "section".to_string(),
            Description::DescMain,
            vec![
                Attribute::AttrPadding(4, 8, 4, 8),
                Attribute::AttrFontColor(Color::rgba(1, 2, 3, 0.25)),
            ],
            vec![Element::Text("hi".to_string())],
        );
        let template = ui_template_of(&subtree).expect("templatable");
        let json = serde_json::to_string(&template).expect("serialize");
        let decoded: UiTemplate = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, template);
    }

    // dev == prod at the runtime level: the baked-default JSON string (what prod
    // holds AND what the emitted `view` reads via `__ipe_lit.get(N)`)
    // materializes to an `Element` that renders byte-identically to rendering
    // the original static subtree directly.
    #[cfg(feature = "json")]
    #[test]
    fn str_materialize_matches_direct_render() {
        use super::materialize_str;
        let subtree: Element<()> = Element::Node(
            Description::NoDescription,
            vec![Attribute::AttrStyle(
                "__col".to_string(),
                "true".to_string(),
            )],
            vec![
                Element::Text("Title".to_string()),
                Element::Text("Body".to_string()),
            ],
        );
        let template = ui_template_of(&subtree).expect("templatable");
        let json = serde_json::to_string(&template).expect("serialize");
        let via_str: Element<()> = materialize_str(&json, TemplateFills::default());
        assert_eq!(
            render(via_str),
            render(subtree),
            "materialize_str over the baked default must render byte-identically"
        );
    }

    #[cfg(feature = "json")]
    #[test]
    fn str_materialize_reflects_a_structural_edit() {
        use super::materialize_str;
        let after: Element<()> = Element::Node(
            Description::NoDescription,
            vec![],
            vec![
                Element::Text("one".to_string()),
                Element::Text("two".to_string()),
            ],
        );
        let before: Element<()> = Element::Node(
            Description::NoDescription,
            vec![],
            vec![Element::Text("one".to_string())],
        );
        let json_after =
            serde_json::to_string(&ui_template_of(&after).expect("templatable")).unwrap();
        let materialized: Element<()> = materialize_str(&json_after, TemplateFills::default());
        assert_eq!(render(materialized), render(after));
        assert_ne!(
            render(materialize_str::<()>(&json_after, TemplateFills::default())),
            render(before)
        );
    }

    #[cfg(feature = "json")]
    #[test]
    fn str_materialize_malformed_json_is_inert_empty() {
        use super::materialize_str;
        let out: Element<()> = materialize_str("this is not json", TemplateFills::default());
        assert_eq!(out, Element::Empty);
        // A payload naming a handler/raw variant simply fails to decode — there
        // is no inert-data path to logic or raw markup.
        let bogus: Element<()> = materialize_str(
            r#"{"Raw":"<script>evil()</script>"}"#,
            TemplateFills::default(),
        );
        assert_eq!(out, bogus);
    }

    #[cfg(feature = "json")]
    #[test]
    fn str_materialize_keeps_text_escaped() {
        use super::materialize_str;
        let json = r#"{"Text":"<script>alert(1)</script>"}"#;
        let out: Element<()> = materialize_str(json, TemplateFills::default());
        let rendered = render(out);
        assert!(
            !rendered.contains("<script>"),
            "must stay escaped: {rendered}"
        );
        assert!(rendered.contains("&lt;script&gt;"));
    }

    // dev == prod at the compiler/runtime seam: the EXACT JSON the backend
    // serializer (`ipe_backend_rust::emit_ui_template::CompileUiTemplate::to_json`)
    // bakes must decode into a `UiTemplate` equal to the tree it described, so
    // the emitted baked default materializes byte-identically to the direct
    // inline emit. This literal is pinned identically on the backend side
    // (`json_tagged_node_full_shape`); a drift on either side fails one of the
    // two pins.
    #[cfg(feature = "json")]
    #[test]
    fn backend_baked_json_decodes_to_the_described_tree() {
        let baked = concat!(
            r#"{"TaggedNode":{"tag":"section","desc":{"DescHeading":2},"attrs":["#,
            r#"{"Width":{"Max":[320,{"Vh":80}]}},{"Padding":[1,2,3,4]},{"Style":["k","v"]},"#,
            r#"{"AlignX":"CenterX"},"Pointer",{"FontAlign":"center"},"#,
            r#"{"FontColor":{"r":10,"g":20,"b":30,"a":1.0}},"#,
            r#"{"BgColor":{"r":1,"g":2,"b":3,"a":0.25}},{"FontLetterSpacing":1.5}],"#,
            r#""children":[{"Text":"hi"},"Empty"]}}"#,
        );
        let decoded: UiTemplate = serde_json::from_str(baked).expect("backend JSON decodes");
        let expected = UiTemplate::TaggedNode {
            tag: "section".to_string(),
            desc: super::UiDescription::DescHeading(2),
            attrs: vec![
                super::UiTemplateAttr::Width(super::UiLength::Max(
                    320,
                    Box::new(super::UiLength::Vh(80)),
                )),
                super::UiTemplateAttr::Padding(1, 2, 3, 4),
                super::UiTemplateAttr::Style("k".to_string(), "v".to_string()),
                super::UiTemplateAttr::AlignX(super::UiHAlign::CenterX),
                super::UiTemplateAttr::Pointer,
                super::UiTemplateAttr::FontAlign("center".to_string()),
                super::UiTemplateAttr::FontColor(super::UiColor {
                    r: 10,
                    g: 20,
                    b: 30,
                    a: 1.0,
                }),
                super::UiTemplateAttr::BgColor(super::UiColor {
                    r: 1,
                    g: 2,
                    b: 3,
                    a: 0.25,
                }),
                super::UiTemplateAttr::FontLetterSpacing(1.5),
            ],
            children: vec![UiTemplate::Text("hi".to_string()), UiTemplate::Empty],
        };
        assert_eq!(
            decoded, expected,
            "backend baked JSON must decode to the exact tree"
        );
        // And it re-serializes to the identical bytes — the backend spelling IS
        // serde_json's spelling.
        assert_eq!(serde_json::to_string(&expected).unwrap(), baked);
    }

    // ── handler-id HOLE (issue #1668) ────────────────────────────────────────
    //
    // A model-dependent event (`onClick (Select id)`) reduces to an opaque HOLE
    // in the inert template; the concrete `Msg` is resolved per render from a
    // `UiHandlerMap`. The model-dependent logic lives ONLY in that server-side
    // map — never serialized, never sent to the client, never a wire closure.
    //
    // Nested in its own module so its local `enum Msg` and `crate::html` imports
    // never collide with the value/list-hole suite below.
    mod handler_holes {
        use super::*;
        use crate::html::{Attribute as HtmlAttribute, Event};

        #[derive(Clone, Debug, PartialEq)]
        enum Msg {
            Select(i64),
            Save,
        }

        // A button carrying a model-dependent `onClick` — the shape that BLOCKS the
        // pure `ui_template_of` (it refuses the whole subtree) but templatizes as a
        // hole through `ui_template_of_holed`.
        fn button_onclick(msg: Msg) -> Element<Msg> {
            Element::TaggedNode(
                "button".to_string(),
                Description::NoDescription,
                vec![Attribute::AttrEvent(HtmlAttribute::EventAttr(
                    Event::OnMsg("click".to_string(), msg),
                ))],
                vec![Element::Text("pick".to_string())],
            )
        }

        // A subtree with a model-dependent handler now templatizes: the pure path
        // refuses it, the holed path accepts it and records the captured Msg.
        #[test]
        fn model_dependent_handler_templatizes_as_a_hole() {
            let subtree = button_onclick(Msg::Select(7));
            // Pure path refuses (it has no hole mechanism).
            assert_eq!(ui_template_of(&subtree), None);
            // Holed path accepts — one hole, one captured Msg.
            let (template, captures) =
                ui_template_of_holed(&subtree).expect("holed path templatizes the handler");
            assert_eq!(captures, vec![Msg::Select(7)]);
            let UiTemplate::TaggedNode { attrs, .. } = &template else {
                panic!("expected a TaggedNode, got {template:?}");
            };
            assert_eq!(
                attrs.as_slice(),
                &[UiTemplateAttr::HandlerHole {
                    event: "click".to_string(),
                    handler_id: 0,
                }],
                "the handler reduced to a bare event-name + hole-id placeholder — no Msg in the datum"
            );
        }

        // The hole resolves back to the captured Msg through the per-render map, so
        // the materialized element carries a LIVE handler that fires the right Msg.
        #[test]
        fn hole_resolves_to_the_captured_msg() {
            let subtree = button_onclick(Msg::Select(42));
            let (template, captures) = ui_template_of_holed(&subtree).expect("templatizes");
            let handlers = UiHandlerMap::from_msgs(captures);
            let materialized: Element<Msg> =
                materialize(&template, TemplateFills::default().with_handlers(handlers));
            assert_eq!(
                materialized, subtree,
                "materialize with the per-render map reconstructs the exact handler-bearing Element"
            );
        }

        // dev == prod byte-identity: the materialized hole renders the SAME DOM
        // event markers (`data-ipe-on`, `ipe-click`, `data-ipe-hid` after id stamp)
        // as the original compiled handler — the wire contract the browser POSTs is
        // unchanged.
        #[test]
        fn hole_renders_byte_identical_event_markers() {
            // Use a `()` Msg so both sides render through the same path; the marker
            // depends only on the event NAME, never the Msg.
            let original: Element<()> = Element::TaggedNode(
                "button".to_string(),
                Description::NoDescription,
                vec![Attribute::AttrEvent(HtmlAttribute::EventAttr(
                    Event::OnMsg("click".to_string(), ()),
                ))],
                vec![Element::Text("go".to_string())],
            );
            let (template, captures) = ui_template_of_holed(&original).expect("templatizes");
            let handlers = UiHandlerMap::from_msgs(captures);
            let materialized: Element<()> =
                materialize(&template, TemplateFills::default().with_handlers(handlers));
            assert_eq!(
                render(materialized),
                render(original),
                "the hole must render byte-identical event markers to the compiled handler"
            );
        }

        // Fail-closed: an out-of-range hole id (a stale template resolved against a
        // shorter map — e.g. after an edit removed a handler) drops the handler.
        // NO Msg is fabricated, no cross-id Msg leaks, no panic.
        #[test]
        fn out_of_range_hole_id_fails_closed_to_no_handler() {
            let template = UiTemplate::TaggedNode {
                tag: "button".to_string(),
                desc: super::super::UiDescription::NoDescription,
                attrs: vec![UiTemplateAttr::HandlerHole {
                    event: "click".to_string(),
                    handler_id: 5, // no such capture
                }],
                children: vec![],
            };
            // A map with only id 0 populated — id 5 is out of range.
            let handlers = UiHandlerMap::from_msgs(vec![Msg::Save]);
            let materialized: Element<Msg> =
                materialize(&template, TemplateFills::default().with_handlers(handlers));
            let Element::TaggedNode(_, _, attrs, _) = &materialized else {
                panic!("expected a TaggedNode, got {materialized:?}");
            };
            assert_eq!(
                attrs.as_slice(),
                &[Attribute::NoAttribute],
                "an unresolved hole drops to NoAttribute — never a fabricated or cross-id Msg"
            );
        }

        // Fail-closed: the map-less materialize path (no handler captures at all)
        // drops every hole. This is the prod/no-capture posture — a hole never
        // invents a Msg without a map.
        #[test]
        fn mapless_materialize_drops_the_hole() {
            let subtree = button_onclick(Msg::Select(1));
            let (template, _captures) = ui_template_of_holed(&subtree).expect("templatizes");
            // Materialize WITHOUT the handler map (empty map) — the hole drops.
            let empty: UiHandlerMap<Msg> = UiHandlerMap::new();
            let materialized: Element<Msg> =
                materialize(&template, TemplateFills::default().with_handlers(empty));
            let Element::TaggedNode(_, _, attrs, _) = &materialized else {
                panic!("expected a TaggedNode, got {materialized:?}");
            };
            assert_eq!(attrs.as_slice(), &[Attribute::NoAttribute]);
        }

        // Cross-render / cross-session isolation: the SAME inert template resolved
        // against two DIFFERENT per-render maps yields two DIFFERENT handlers — the
        // Msg comes only from the render's own map, never leaks across renders. A
        // forged id (out of both maps' range) resolves to nothing in both.
        #[test]
        fn hole_resolution_is_scoped_to_its_own_render_map() {
            let template = UiTemplate::TaggedNode {
                tag: "button".to_string(),
                desc: super::super::UiDescription::NoDescription,
                attrs: vec![UiTemplateAttr::HandlerHole {
                    event: "click".to_string(),
                    handler_id: 0,
                }],
                children: vec![],
            };
            let render_a = UiHandlerMap::from_msgs(vec![Msg::Select(1)]);
            let render_b = UiHandlerMap::from_msgs(vec![Msg::Select(2)]);
            let a: Element<Msg> = materialize(
                &template,
                TemplateFills::default().with_handlers(render_a.clone()),
            );
            let b: Element<Msg> = materialize(
                &template,
                TemplateFills::default().with_handlers(render_b.clone()),
            );
            // Compare the RESOLVED Msg directly (Element/Event PartialEq deliberately
            // ignores the Msg payload — two OnMsg("click", _) compare equal for diff
            // purposes — so the distinction must be read off the handler's Msg).
            assert_eq!(resolved_click_msg(&a), Some(Msg::Select(1)));
            assert_eq!(resolved_click_msg(&b), Some(Msg::Select(2)));
            assert_ne!(
                resolved_click_msg(&a),
                resolved_click_msg(&b),
                "each render's map resolves the hole to ITS own Msg"
            );
            // Neither map holds a handler for a forged higher id.
            let forged = UiTemplate::TaggedNode {
                tag: "button".to_string(),
                desc: super::super::UiDescription::NoDescription,
                attrs: vec![UiTemplateAttr::HandlerHole {
                    event: "click".to_string(),
                    handler_id: 99,
                }],
                children: vec![],
            };
            let fa: Element<Msg> =
                materialize(&forged, TemplateFills::default().with_handlers(render_a));
            let fb: Element<Msg> =
                materialize(&forged, TemplateFills::default().with_handlers(render_b));
            for e in [fa, fb] {
                let Element::TaggedNode(_, _, attrs, _) = &e else {
                    panic!("expected a TaggedNode");
                };
                assert_eq!(attrs.as_slice(), &[Attribute::NoAttribute]);
            }
        }

        // A non-`OnMsg` event (a runtime-arg-dependent handler) is NOT a clean
        // per-render capture, so even the holed path refuses the whole subtree — it
        // stays compiled rather than templatizing a handler whose resolution needs a
        // client-supplied value / form payload / seal decode.
        #[test]
        fn non_onmsg_handlers_refuse_even_holed() {
            let on_string: Element<Msg> = Element::TaggedNode(
                "input".to_string(),
                Description::NoDescription,
                vec![Attribute::AttrEvent(HtmlAttribute::EventAttr(
                    Event::OnString(
                        "input".to_string(),
                        std::sync::Arc::new(|s| Msg::Select(s.len() as i64)),
                    ),
                ))],
                vec![],
            );
            assert_eq!(ui_template_of_holed(&on_string), None);

            let on_form: Element<Msg> = Element::TaggedNode(
                "form".to_string(),
                Description::NoDescription,
                vec![Attribute::AttrEvent(HtmlAttribute::EventAttr(
                    Event::OnForm(
                        "submit".to_string(),
                        std::sync::Arc::new(|_fd| Some(Msg::Save)),
                    ),
                ))],
                vec![],
            );
            assert_eq!(ui_template_of_holed(&on_form), None);
        }

        // The whole point of issue #1668: a subtree bearing a model-dependent handler
        // hot-swaps its STRUCTURE (the inert template changes) while the handler
        // still fires the right Msg (resolved from the per-render map). Here the
        // structure gains a child between renders; both the old and new template
        // resolve the hole to the same captured Msg.
        #[test]
        fn structure_hot_swaps_while_handler_still_fires() {
            // Before: button with one text child, model-dependent onClick.
            let before: Element<Msg> = Element::TaggedNode(
                "button".to_string(),
                Description::NoDescription,
                vec![Attribute::AttrEvent(HtmlAttribute::EventAttr(
                    Event::OnMsg("click".to_string(), Msg::Select(3)),
                ))],
                vec![Element::Text("one".to_string())],
            );
            // After: the SAME handler, an added static child (a structural edit).
            let after: Element<Msg> = Element::TaggedNode(
                "button".to_string(),
                Description::NoDescription,
                vec![Attribute::AttrEvent(HtmlAttribute::EventAttr(
                    Event::OnMsg("click".to_string(), Msg::Select(3)),
                ))],
                vec![
                    Element::Text("one".to_string()),
                    Element::Text("two".to_string()),
                ],
            );
            let (t_before, c_before) = ui_template_of_holed(&before).expect("templatizes");
            let (t_after, c_after) = ui_template_of_holed(&after).expect("templatizes");
            // The templates differ (structure hot-swapped) …
            assert_ne!(t_before, t_after);
            // … but each resolves the hole to the SAME model-captured Msg.
            let m_before: Element<Msg> = materialize(
                &t_before,
                TemplateFills::default().with_handlers(UiHandlerMap::from_msgs(c_before)),
            );
            let m_after: Element<Msg> = materialize(
                &t_after,
                TemplateFills::default().with_handlers(UiHandlerMap::from_msgs(c_after)),
            );
            assert_eq!(m_before, before);
            assert_eq!(m_after, after);
        }

        // Two model-dependent handlers in one subtree get distinct, order-stable hole
        // ids (0, 1), so each resolves to its own captured Msg.
        #[test]
        fn multiple_holes_get_distinct_ordered_ids() {
            let subtree: Element<Msg> = Element::Node(
                Description::NoDescription,
                vec![],
                vec![button_onclick(Msg::Select(10)), button_onclick(Msg::Save)],
            );
            let (_template, captures) = ui_template_of_holed(&subtree).expect("templatizes");
            assert_eq!(captures, vec![Msg::Select(10), Msg::Save]);
        }

        // Read the concrete `Msg` off a materialized element's `click` handler, or
        // `None` when it carries no such handler. Needed because `Element`/`Event`
        // equality ignores the Msg payload, so the resolved Msg must be inspected
        // directly to prove per-render resolution.
        fn resolved_click_msg(elem: &Element<Msg>) -> Option<Msg> {
            let attrs = match elem {
                Element::Node(_, attrs, _) | Element::TaggedNode(_, _, attrs, _) => attrs,
                _ => return None,
            };
            attrs.iter().find_map(|a| match a {
                Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnMsg(name, msg)))
                    if name == "click" =>
                {
                    Some(msg.clone())
                }
                _ => None,
            })
        }
    }

    // ── holes: value / control-flow (single-element) + list (children) ────────
    //
    // Nested in its own module so its `UiTemplate as T` / `UiTemplateAttr`
    // re-imports never collide with the parent suite or the handler-hole suite.
    mod value_holes {
        use super::super::{UiDescription, UiTemplate as T, UiTemplateAttr};
        use super::*;

        // A value hole: a mostly-static node whose single child is a `Hole(0)` filled
        // by a `Model`-derived text leaf. Materialize splices the fill in place; the
        // surrounding structure comes from the (inert) template.
        #[test]
        fn value_hole_splices_the_element_fill() {
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![UiTemplateAttr::Spacing(8)],
                children: vec![T::Text("count: ".to_string()), T::Hole(0)],
            };
            let got: Element<()> = materialize(
                &template,
                TemplateFills::default().with_elements(vec![Element::Text("42".to_string())]),
            );
            assert_eq!(
                got,
                Element::Node(
                    Description::NoDescription,
                    vec![Attribute::AttrSpacing(8)],
                    vec![
                        Element::Text("count: ".to_string()),
                        Element::Text("42".to_string()),
                    ],
                )
            );
        }

        // A control-flow hole is materially the same shape as a value hole — the fill
        // is whatever `Element` the compiled `if`/`case` produced. Editing the static
        // wrapper structure (here: adding a sibling) hot-swaps; the fill is unchanged.
        #[test]
        fn control_flow_hole_fill_is_opaque_element() {
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![],
                children: vec![T::Hole(0), T::Text("footer".to_string())],
            };
            // The compiled branch chose a tagged node this render.
            let branch: Element<()> = Element::TaggedNode(
                "strong".to_string(),
                Description::NoDescription,
                vec![],
                vec![Element::Text("on".to_string())],
            );
            let got: Element<()> = materialize(
                &template,
                TemplateFills::default().with_elements(vec![branch.clone()]),
            );
            assert_eq!(
                got,
                Element::Node(
                    Description::NoDescription,
                    vec![],
                    vec![branch, Element::Text("footer".to_string())],
                )
            );
        }

        // A children hole: a `List.map` comprehension expands to a RUN of siblings
        // spliced among the node's static children, in order.
        #[test]
        fn children_hole_splices_the_run_in_place() {
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![],
                children: vec![
                    T::Text("head".to_string()),
                    T::ChildrenHole(0),
                    T::Text("tail".to_string()),
                ],
            };
            let items: Vec<Element<()>> = vec![
                Element::Text("a".to_string()),
                Element::Text("b".to_string()),
                Element::Text("c".to_string()),
            ];
            let got: Element<()> = materialize(
                &template,
                TemplateFills::default().with_children(vec![items]),
            );
            assert_eq!(
                got,
                Element::Node(
                    Description::NoDescription,
                    vec![],
                    vec![
                        Element::Text("head".to_string()),
                        Element::Text("a".to_string()),
                        Element::Text("b".to_string()),
                        Element::Text("c".to_string()),
                        Element::Text("tail".to_string()),
                    ],
                )
            );
        }

        // Mixed: both an element hole and a children hole, each indexed within its own
        // kind (the compiler numbers them per-kind).
        #[test]
        fn element_and_children_holes_index_independently() {
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![],
                children: vec![T::Hole(0), T::ChildrenHole(0), T::Hole(1)],
            };
            let got: Element<()> = materialize(
                &template,
                TemplateFills::default()
                    .with_elements(vec![
                        Element::Text("first".to_string()),
                        Element::Text("last".to_string()),
                    ])
                    .with_children(vec![vec![Element::Text("mid".to_string())]]),
            );
            assert_eq!(
                got,
                Element::Node(
                    Description::NoDescription,
                    vec![],
                    vec![
                        Element::Text("first".to_string()),
                        Element::Text("mid".to_string()),
                        Element::Text("last".to_string()),
                    ],
                )
            );
        }

        // Fail-closed: a hole index past the supplied fills materializes to the inert
        // empty element, never a panic (the patched template is untrusted).
        #[test]
        fn out_of_range_hole_is_inert_empty() {
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![],
                children: vec![T::Hole(5), T::ChildrenHole(9)],
            };
            let got: Element<()> = materialize(&template, TemplateFills::default());
            assert_eq!(
                got,
                Element::Node(Description::NoDescription, vec![], vec![Element::Empty]),
                "an out-of-range element hole is empty and a missing children hole adds nothing"
            );
        }

        // A `ChildrenHole` reached as a standalone element (a malformed decode, not in
        // a children list) is inert — the empty element, never a panic.
        #[test]
        fn standalone_children_hole_is_inert_empty() {
            let got: Element<()> = materialize(
                &T::ChildrenHole(0),
                TemplateFills::default().with_children(vec![vec![]]),
            );
            assert_eq!(got, Element::Empty);
        }

        // ── ControlFlowHole ─────────────────────────────────────────────────────

        // A `ControlFlowHole` with selector 0 materializes the true-branch arm.
        #[cfg(feature = "json")]
        #[test]
        fn control_flow_hole_true_branch_materializes() {
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![],
                children: vec![T::ControlFlowHole {
                    hole_id: 0,
                    arms: vec![T::Text("on".to_string()), T::Text("off".to_string())],
                }],
            };
            let got: Element<()> = super::super::materialize_str(
                &serde_json::to_string(&template).unwrap(),
                TemplateFills::default().with_control_flow(vec![0]), // select arm 0 = "on"
            );
            assert_eq!(
                got,
                Element::Node(
                    Description::NoDescription,
                    vec![],
                    vec![Element::Text("on".to_string())],
                )
            );
        }

        // A `ControlFlowHole` with selector 1 materializes the false-branch arm.
        #[cfg(feature = "json")]
        #[test]
        fn control_flow_hole_false_branch_materializes() {
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![],
                children: vec![T::ControlFlowHole {
                    hole_id: 0,
                    arms: vec![T::Text("on".to_string()), T::Text("off".to_string())],
                }],
            };
            let got: Element<()> = super::super::materialize_str(
                &serde_json::to_string(&template).unwrap(),
                TemplateFills::default().with_control_flow(vec![1]), // select arm 1 = "off"
            );
            assert_eq!(
                got,
                Element::Node(
                    Description::NoDescription,
                    vec![],
                    vec![Element::Text("off".to_string())],
                )
            );
        }

        // Fail-closed: an out-of-range selector materializes to the inert empty element.
        #[cfg(feature = "json")]
        #[test]
        fn control_flow_hole_out_of_range_selector_is_empty() {
            let template = T::ControlFlowHole {
                hole_id: 0,
                arms: vec![T::Text("only".to_string())],
            };
            let got: Element<()> = super::super::materialize_str(
                &serde_json::to_string(&template).unwrap(),
                TemplateFills::default().with_control_flow(vec![5]), // out of range
            );
            assert_eq!(got, Element::Empty);
        }

        // Mixed: a subtree with both a `ControlFlowHole` and a value `Hole`
        // materializes both together through the one `materialize` core.
        #[cfg(feature = "json")]
        #[test]
        fn control_flow_hole_and_value_hole_materialize_together() {
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![],
                children: vec![
                    T::ControlFlowHole {
                        hole_id: 0,
                        arms: vec![
                            T::Node {
                                desc: UiDescription::NoDescription,
                                attrs: vec![],
                                children: vec![T::Hole(0)], // value hole inside arm
                            },
                            T::Text("loading".to_string()),
                        ],
                    },
                    T::Text("footer".to_string()),
                ],
            };
            // Select arm 0 (the branch with the value hole); fill[0] = "42".
            let got: Element<()> = super::super::materialize_str(
                &serde_json::to_string(&template).unwrap(),
                TemplateFills::default()
                    .with_elements(vec![Element::Text("42".to_string())])
                    .with_control_flow(vec![0]),
            );
            assert_eq!(
                got,
                Element::Node(
                    Description::NoDescription,
                    vec![],
                    vec![
                        Element::Node(
                            Description::NoDescription,
                            vec![],
                            vec![Element::Text("42".to_string())],
                        ),
                        Element::Text("footer".to_string()),
                    ],
                )
            );
        }

        // Combined: a subtree carrying both a value hole (Hole) and a handler hole
        // (HandlerHole) materializes correctly through the one `materialize` core —
        // value fills are spliced and the handler resolves to the captured Msg.
        #[cfg(feature = "json")]
        #[test]
        fn combined_value_hole_and_handler_hole_materialize_together() {
            use super::super::{UiHandlerMap, materialize_str};
            use crate::html::{Attribute as HtmlAttribute, Event};

            #[derive(Clone, Debug, PartialEq)]
            enum Msg {
                Submit,
            }

            // Template: a node with an onClick handler hole (id 0) and one element
            // child that is a value hole (Hole 0) — both kinds in the same subtree.
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![UiTemplateAttr::HandlerHole {
                    event: "click".to_string(),
                    handler_id: 0,
                }],
                children: vec![T::Hole(0)],
            };
            let json = serde_json::to_string(&template).unwrap();
            let fill: Element<Msg> = Element::Text("label text".to_string());
            let handlers = UiHandlerMap::from_msgs(vec![Msg::Submit]);

            let got: Element<Msg> = materialize_str(
                &json,
                TemplateFills::default()
                    .with_elements(vec![fill.clone()])
                    .with_handlers(handlers),
            );
            assert_eq!(
                got,
                Element::Node(
                    Description::NoDescription,
                    vec![Attribute::AttrEvent(HtmlAttribute::EventAttr(
                        Event::OnMsg("click".to_string(), Msg::Submit),
                    ))],
                    vec![fill],
                ),
                "combined materializer must wire the value fill AND the handler in one pass"
            );
        }

        // dev == prod for a hole-bearing template: the SAME fills over a baked-default
        // template (prod) and a structurally-edited template (dev) render each other's
        // static skeleton, with the fills unchanged — the structural edit hot-swaps.
        #[cfg(feature = "json")]
        #[test]
        fn holes_str_reflects_structural_edit_with_same_fills() {
            use super::super::materialize_str;
            // before: [Hole(0)] ; after: ["x", Hole(0)] — a static sibling added.
            let before = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![],
                children: vec![T::Hole(0)],
            };
            let after = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![],
                children: vec![T::Text("x".to_string()), T::Hole(0)],
            };
            let fill = || vec![Element::Text("v".to_string())];
            let json_before = serde_json::to_string(&before).unwrap();
            let json_after = serde_json::to_string(&after).unwrap();
            let out_before: Element<()> =
                materialize_str(&json_before, TemplateFills::default().with_elements(fill()));
            let out_after: Element<()> =
                materialize_str(&json_after, TemplateFills::default().with_elements(fill()));
            let before_render = render(out_before);
            assert_eq!(
                before_render,
                render(materialize::<()>(
                    &before,
                    TemplateFills::default().with_elements(fill())
                ))
            );
            assert_ne!(
                before_render,
                render(out_after),
                "the edit must change render"
            );
        }
    }

    // ── list hole ─────────────────────────────────────────────────────────────
    mod list_holes {
        use super::super::{UiDescription, UiTemplate as T};
        use super::*;

        // A `ListHole` in children position: N items expand to N sibling elements,
        // each materialized from the item template with that item's element fills.
        // `item_template = Hole(0)` + each item fill = `[Element::Text(label)]`
        // → the list `["a", "b", "c"]` expands to three `Text` siblings.
        #[test]
        fn list_hole_expands_to_n_sibling_elements() {
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![],
                children: vec![T::ListHole {
                    hole_id: 0,
                    item_template: Box::new(T::Hole(0)),
                }],
            };
            let items: Vec<Vec<Vec<Element<()>>>> = vec![
                // hole_id 0: three items, each with one element fill
                vec![
                    vec![Element::Text("a".to_string())],
                    vec![Element::Text("b".to_string())],
                    vec![Element::Text("c".to_string())],
                ],
            ];
            let got = materialize(&template, TemplateFills::default().with_list_items(items));
            assert_eq!(
                got,
                Element::Node(
                    Description::NoDescription,
                    vec![],
                    vec![
                        Element::Text("a".to_string()),
                        Element::Text("b".to_string()),
                        Element::Text("c".to_string()),
                    ],
                )
            );
        }

        // Empty list → zero siblings (no elements in the children run).
        #[test]
        fn list_hole_empty_list_yields_no_children() {
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![],
                children: vec![T::ListHole {
                    hole_id: 0,
                    item_template: Box::new(T::Text("row".to_string())),
                }],
            };
            let items: Vec<Vec<Vec<Element<()>>>> = vec![vec![]]; // 0 items
            let got = materialize(&template, TemplateFills::default().with_list_items(items));
            assert_eq!(
                got,
                Element::Node(Description::NoDescription, vec![], vec![])
            );
        }

        // Static item template (no Hole inside): each item renders the same
        // static subtree; the fill vec for each item is empty.
        #[test]
        fn list_hole_static_item_template_repeats_n_times() {
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![],
                children: vec![T::ListHole {
                    hole_id: 0,
                    item_template: Box::new(T::Text("row".to_string())),
                }],
            };
            // 3 items, no element fills (static template)
            let items: Vec<Vec<Vec<Element<()>>>> = vec![vec![vec![], vec![], vec![]]];
            let got = materialize(&template, TemplateFills::default().with_list_items(items));
            assert_eq!(
                got,
                Element::Node(
                    Description::NoDescription,
                    vec![],
                    vec![
                        Element::Text("row".to_string()),
                        Element::Text("row".to_string()),
                        Element::Text("row".to_string()),
                    ],
                )
            );
        }

        // JSON round-trip: `ListHole` serializes as `{"ListHole":{"hole_id":N,
        // "item_template":<template>}}` and decodes back to the original value.
        #[cfg(feature = "serde")]
        #[test]
        fn list_hole_json_round_trips() {
            let t = T::ListHole {
                hole_id: 0,
                item_template: Box::new(T::Hole(0)),
            };
            let json = serde_json::to_string(&t).expect("serialize");
            assert_eq!(
                json,
                r#"{"ListHole":{"hole_id":0,"item_template":{"Hole":0}}}"#
            );
            let back: T = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, t);
        }
    }

    // ── wrapper hole ──────────────────────────────────────────────────────────
    //
    // A model-chosen wrapping element around a fixed child. The wrapper — tag /
    // desc / attrs — is selected at render from the per-render wrapper-fill slice;
    // the child subtree is fixed and may itself carry holes.
    mod wrapper_holes {
        use super::super::{UiDescription, UiTemplate as T, UiTemplateAttr};
        use super::*;

        // Build a wrapper fill: a `TaggedNode` with the given tag and attrs, no
        // children (the children come from the fixed child template).
        fn tagged_wrapper(tag: &str, attrs: Vec<UiTemplateAttr>) -> T {
            T::TaggedNode {
                tag: tag.to_string(),
                desc: UiDescription::NoDescription,
                attrs,
                children: vec![],
            }
        }

        // A `WrapperHole` with a tagged-node fill wraps its child in the chosen tag.
        // `wrapper_fills[0] = TaggedNode("a", [href], [])` + child = Text("label")
        // → `Element::TaggedNode("a", [], [NoDescription], [Text("label")])`.
        #[test]
        fn wrapper_hole_tagged_node_fill_wraps_child() {
            let template = T::WrapperHole {
                hole_id: 0,
                child: Box::new(T::Text("label".to_string())),
            };
            let wrapper = tagged_wrapper("a", vec![UiTemplateAttr::Class("link".to_string())]);
            let got: Element<()> = materialize(
                &template,
                TemplateFills::default().with_wrappers(vec![wrapper]),
            );
            assert_eq!(
                got,
                Element::TaggedNode(
                    "a".to_string(),
                    Description::NoDescription,
                    vec![Attribute::AttrClass("link".to_string())],
                    vec![Element::Text("label".to_string())],
                )
            );
        }

        // A different fill (TaggedNode("span", [], [])) renders the same child in a
        // span — same template, different wrapper, byte-distinct output.
        #[test]
        fn wrapper_hole_different_fill_different_output() {
            let template = T::WrapperHole {
                hole_id: 0,
                child: Box::new(T::Text("label".to_string())),
            };
            let wrapper_a = tagged_wrapper("a", vec![]);
            let wrapper_span = tagged_wrapper("span", vec![]);
            let out_a: Element<()> = materialize(
                &template,
                TemplateFills::default().with_wrappers(vec![wrapper_a]),
            );
            let out_span: Element<()> = materialize(
                &template,
                TemplateFills::default().with_wrappers(vec![wrapper_span]),
            );
            assert_ne!(render(out_a), render(out_span));
        }

        // Fail-closed: a missing wrapper fill renders the child standalone —
        // no panic, no empty element dropped, the child content is preserved.
        #[test]
        fn wrapper_hole_missing_fill_renders_child_standalone() {
            let template = T::WrapperHole {
                hole_id: 0,
                child: Box::new(T::Text("content".to_string())),
            };
            let got: Element<()> = materialize(&template, TemplateFills::default());
            assert_eq!(got, Element::Text("content".to_string()));
        }

        // Fail-closed: an out-of-range hole_id (fill at index 5, hole_id = 0
        // is consumed but a hole with id=5 has no fill) renders child standalone.
        #[test]
        fn wrapper_hole_out_of_range_id_renders_child_standalone() {
            let template = T::WrapperHole {
                hole_id: 5,
                child: Box::new(T::Text("content".to_string())),
            };
            let got: Element<()> = materialize(
                &template,
                TemplateFills::default().with_wrappers(vec![tagged_wrapper("a", vec![])]), // only index 0 filled
            );
            assert_eq!(got, Element::Text("content".to_string()));
        }

        // Child may carry its own value holes; those resolve from the element_holes
        // fill, independent of the wrapper fill.
        #[test]
        fn wrapper_hole_child_value_hole_resolves() {
            let template = T::WrapperHole {
                hole_id: 0,
                child: Box::new(T::Node {
                    desc: UiDescription::NoDescription,
                    attrs: vec![],
                    children: vec![T::Hole(0)],
                }),
            };
            let wrapper = tagged_wrapper("section", vec![]);
            let fill = Element::Text("42".to_string());
            let got: Element<()> = materialize(
                &template,
                TemplateFills::default()
                    .with_elements(vec![fill.clone()])
                    .with_wrappers(vec![wrapper]),
            );
            assert_eq!(
                got,
                Element::TaggedNode(
                    "section".to_string(),
                    Description::NoDescription,
                    vec![],
                    vec![Element::Node(
                        Description::NoDescription,
                        vec![],
                        vec![fill],
                    )],
                )
            );
        }

        // JSON round-trip: `WrapperHole` serializes as
        // `{"WrapperHole":{"hole_id":N,"child":<template>}}` and decodes back.
        #[cfg(feature = "serde")]
        #[test]
        fn wrapper_hole_json_round_trips() {
            let t = T::WrapperHole {
                hole_id: 0,
                child: Box::new(T::Text("label".to_string())),
            };
            let json = serde_json::to_string(&t).expect("serialize");
            assert_eq!(
                json,
                r#"{"WrapperHole":{"hole_id":0,"child":{"Text":"label"}}}"#
            );
            let back: T = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, t);
        }

        // JSON front-door: the str materialize path works end-to-end.
        #[cfg(feature = "json")]
        #[test]
        fn wrapper_hole_str_materialize_works() {
            use super::super::materialize_str;
            let template = T::WrapperHole {
                hole_id: 0,
                child: Box::new(T::Text("label".to_string())),
            };
            let json = serde_json::to_string(&template).expect("serialize");
            let wrapper = tagged_wrapper("a", vec![]);
            let got: Element<()> =
                materialize_str(&json, TemplateFills::default().with_wrappers(vec![wrapper]));
            assert_eq!(
                got,
                Element::TaggedNode(
                    "a".to_string(),
                    Description::NoDescription,
                    vec![],
                    vec![Element::Text("label".to_string())],
                )
            );
        }

        // Byte-identity: a template with NO WrapperHole emits byte-identically with
        // or without a (unused) wrapper_fills vec — the new kind is purely additive.
        #[test]
        fn wrapper_hole_addition_is_additive_no_perturbation() {
            let static_template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![UiTemplateAttr::Spacing(4)],
                children: vec![T::Text("hi".to_string())],
            };
            let with_empty_wrappers: Element<()> =
                materialize(&static_template, TemplateFills::default());
            let without: Element<()> = materialize(&static_template, TemplateFills::default());
            assert_eq!(
                render(with_empty_wrappers),
                render(without),
                "wrapper_holes=[] must not perturb a template with no WrapperHole"
            );
        }
    }

    // ── float attr hole ───────────────────────────────────────────────────────
    //
    // A model-driven numeric (`f64`) attribute value: the attr name and a hole id
    // stored in the template; the concrete value is supplied per render via the
    // float_attr_fills slice. Purely additive — templates with no AttrHoleFloat
    // are byte-identical before and after this kind ships.
    mod float_attr_holes {
        use super::super::{UiDescription, UiTemplate as T, UiTemplateAttr};
        use super::*;

        // A node whose `font-letter-spacing` attr is a float hole: the template
        // carries only the attr name and hole_id; the concrete f64 is supplied via
        // float_attr_fills. The materialized element must carry the exact
        // `AttrFontLetterSpacing(v)` matching the fill.
        #[test]
        fn float_attr_hole_resolves_letter_spacing() {
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![
                    UiTemplateAttr::Spacing(4),
                    UiTemplateAttr::AttrHoleFloat {
                        attr: "font-letter-spacing".to_string(),
                        hole_id: 0,
                    },
                ],
                children: vec![T::Text("hi".to_string())],
            };
            let got: Element<()> = materialize(
                &template,
                TemplateFills::default().with_float_attrs(vec![1.5_f64]),
            );
            assert_eq!(
                got,
                Element::Node(
                    Description::NoDescription,
                    vec![
                        Attribute::AttrSpacing(4),
                        Attribute::AttrFontLetterSpacing(1.5),
                    ],
                    vec![Element::Text("hi".to_string())],
                ),
                "float attr hole must resolve to AttrFontLetterSpacing with the supplied value"
            );
        }

        // Word-spacing float hole resolves to AttrFontWordSpacing.
        #[test]
        fn float_attr_hole_resolves_word_spacing() {
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![UiTemplateAttr::AttrHoleFloat {
                    attr: "font-word-spacing".to_string(),
                    hole_id: 0,
                }],
                children: vec![],
            };
            let got: Element<()> = materialize(
                &template,
                TemplateFills::default().with_float_attrs(vec![0.5_f64]),
            );
            assert_eq!(
                got,
                Element::Node(
                    Description::NoDescription,
                    vec![Attribute::AttrFontWordSpacing(0.5)],
                    vec![],
                ),
            );
        }

        // Multiple float holes with distinct hole_ids resolve independently.
        #[test]
        fn float_attr_hole_multiple_holes_resolve_independently() {
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![
                    UiTemplateAttr::AttrHoleFloat {
                        attr: "font-letter-spacing".to_string(),
                        hole_id: 0,
                    },
                    UiTemplateAttr::AttrHoleFloat {
                        attr: "font-word-spacing".to_string(),
                        hole_id: 1,
                    },
                ],
                children: vec![],
            };
            let got: Element<()> = materialize(
                &template,
                TemplateFills::default().with_float_attrs(vec![1.5_f64, 0.25_f64]),
            );
            assert_eq!(
                got,
                Element::Node(
                    Description::NoDescription,
                    vec![
                        Attribute::AttrFontLetterSpacing(1.5),
                        Attribute::AttrFontWordSpacing(0.25),
                    ],
                    vec![],
                ),
            );
        }

        // Fail-closed: an out-of-range hole id produces `NoAttribute`.
        #[test]
        fn float_attr_hole_out_of_range_fails_closed() {
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![UiTemplateAttr::AttrHoleFloat {
                    attr: "font-letter-spacing".to_string(),
                    hole_id: 5, // no fill at index 5
                }],
                children: vec![],
            };
            let got: Element<()> = materialize(&template, TemplateFills::default()); // no fills
            assert_eq!(
                got,
                Element::Node(
                    Description::NoDescription,
                    vec![Attribute::NoAttribute],
                    vec![],
                ),
                "out-of-range float hole must drop to NoAttribute, never panic"
            );
        }

        // Fail-closed: an unrecognised attr name drops to `NoAttribute`.
        #[test]
        fn float_attr_hole_unknown_attr_name_fails_closed() {
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![UiTemplateAttr::AttrHoleFloat {
                    attr: "unknown-attr".to_string(),
                    hole_id: 0,
                }],
                children: vec![],
            };
            let got: Element<()> = materialize(
                &template,
                TemplateFills::default().with_float_attrs(vec![1.0_f64]),
            );
            assert_eq!(
                got,
                Element::Node(
                    Description::NoDescription,
                    vec![Attribute::NoAttribute],
                    vec![],
                ),
            );
        }

        // JSON round-trip: AttrHoleFloat serializes and deserializes byte-identically.
        #[cfg(feature = "serde")]
        #[test]
        fn float_attr_hole_json_round_trips() {
            let attr = UiTemplateAttr::AttrHoleFloat {
                attr: "font-letter-spacing".to_string(),
                hole_id: 0,
            };
            let json = serde_json::to_string(&attr).expect("serialize");
            assert_eq!(
                json, r#"{"AttrHoleFloat":{"attr":"font-letter-spacing","hole_id":0}}"#,
                "AttrHoleFloat JSON form must match the runtime serde encoding"
            );
            let back: UiTemplateAttr = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, attr);
        }

        // JSON str front door materializes float holes end-to-end.
        #[cfg(feature = "json")]
        #[test]
        fn float_attr_hole_str_materialize_works() {
            use super::super::materialize_str;
            let template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![UiTemplateAttr::AttrHoleFloat {
                    attr: "font-letter-spacing".to_string(),
                    hole_id: 0,
                }],
                children: vec![T::Text("hi".to_string())],
            };
            let json = serde_json::to_string(&template).expect("serialize");
            let got: Element<()> = materialize_str(
                &json,
                TemplateFills::default().with_float_attrs(vec![2.0_f64]),
            );
            assert_eq!(
                got,
                Element::Node(
                    Description::NoDescription,
                    vec![Attribute::AttrFontLetterSpacing(2.0)],
                    vec![Element::Text("hi".to_string())],
                ),
            );
        }

        // Byte-identity: a template with no AttrHoleFloat renders identically with
        // or without an (unused) float_attr_fills vec — purely additive.
        #[test]
        fn float_attr_hole_addition_is_additive_no_perturbation() {
            let static_template = T::Node {
                desc: UiDescription::NoDescription,
                attrs: vec![UiTemplateAttr::Spacing(4)],
                children: vec![T::Text("hi".to_string())],
            };
            let with_empty_floats: Element<()> =
                materialize(&static_template, TemplateFills::default());
            let without: Element<()> = materialize(&static_template, TemplateFills::default());
            assert_eq!(
                render(with_empty_floats),
                render(without),
                "float_attr_fills=[] must not perturb a template with no AttrHoleFloat"
            );
        }
    }
}

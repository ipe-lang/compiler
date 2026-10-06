//! Pure classification of a `Ipe.Ui` / `Ipe.Html` / `Web` / `Tui` / `WebView` /
//! console kernel into a [`UiEmitPlan`] — a description of what emitting the
//! call produces, carrying no codegen buffer and touching no [`EmitCtx`].
//!
//! [`ui_call_shape`] is a total function over [`KernelFn`]: `Some(plan)` for
//! every UI-family kernel, `None` for anything else. The interpreter that turns
//! a plan into emitted Rust lives in [`crate::emit_expr::emit_ui_plan`]; the two
//! together replace the single `match` that previously fused classification and
//! codegen in one arm per kernel.
//!
//! The split makes the dispatch a **total** function the type system forces to
//! cover every UI kernel: a kernel that is UI-family yet yields no plan is a
//! test failure at the classifier (see `exhaustiveness_partition`), not a
//! wrong-shape emission discovered downstream when the emitted Rust fails to
//! build.
//!
//! The uniform majority — a call to one runtime path with N positionally
//! emitted arguments — is [`ArgPlan::Positional`], pure data (a path string and
//! an arity). The capability and security leaves — event-handler wiring, inline
//! record configs, the `Html` serialiser, the `Ui.cells` web-shape seal, the
//! deferred-subtree eta wrappers, and the shape-router delegations — carry too
//! much bespoke emission to encode as data without reproducing it byte for
//! byte; each is named by an [`ArgPlan::Native`] tag the interpreter dispatches
//! to a dedicated emitter.
//!
//! The table is keyed by [`KernelFn`] and lives beside the enum so a UI
//! kernel's emit shape can later be hosted as a field on its descriptor row
//! rather than duplicated in a second table.

use ipe_ir::KernelFn;

/// What emitting one UI-family kernel call produces — a pure description with no
/// I/O and no codegen buffer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UiEmitPlan {
    /// How the kernel's Ipê arguments map onto the emitted Rust call.
    pub args: ArgPlan,
    /// A fail-closed guard that must hold before emission.
    pub guard: Guard,
}

/// How a kernel's arguments become the emitted call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArgPlan {
    /// `arity` arguments, each emitted in order and passed positionally to
    /// `path`, i.e. `path(a0, a1, …, a{arity-1})`. `arity == 0` emits `path()`.
    ///
    /// `path` is the fully-qualified runtime function, e.g.
    /// `"ipe_runtime::ui::helpers::ui_node_"`.
    Positional { path: &'static str, arity: u8 },
    /// The kernel's emission is bespoke — a callback carrier, an inline record
    /// config, the HTML serialiser, a predicate-keyed tag/attribute family, a
    /// deferred-subtree eta wrapper, or a shape-router delegation. The
    /// interpreter dispatches on the tag to the matching emitter.
    Native(NativeUiEmit),
}

/// The bespoke emitters the interpreter dispatches to for the capability and
/// security leaves. Each variant corresponds to one emitter in
/// [`crate::emit_expr`]; the classifier only names which one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NativeUiEmit {
    /// `Ui.layoutWith` — inline `{ wrapperAttrs, rootAttrs }` record config.
    LayoutWith,
    /// `Html.render` / `Html.toString` — the HTML serialiser (`render_html`).
    HtmlSerialise,
    /// `Ui.button` — inline `{ onPress, label }` record config.
    Button,
    /// `Ui.link` — inline `{ url, label }` record config.
    Link,
    /// `Ui.image` — inline `{ src, description }` record config.
    Image,
    /// `Ui.paddingEach` — inline `{ top, right, bottom, left }` record.
    PaddingEach,
    /// `Border.widthEach` — inline `{ top, right, bottom, left }` record.
    BorderWidthEach,
    /// `Border.shadow` — inline `{ offsetX, offsetY, blur, spread, color }`.
    BorderShadow,
    /// `Border.innerShadow` — inline `{ offsetX, offsetY, blur, spread, color }`.
    BorderInnerShadow,
    /// `Input.text` and its type siblings (email, username, search, passwords).
    InputText,
    /// `Input.multiline`.
    InputMultiline,
    /// `Input.checkbox`.
    InputCheckbox,
    /// `Input.slider`.
    InputSlider,
    /// `Input.radio`.
    InputRadio,
    /// `Input.radioRow`.
    InputRadioRow,
    /// `Html.voidNode` — a runtime-tag void element (empty children vec).
    HtmlVoidNode,
    /// `Ui.onInput` — string-carrying event handler, peel-hoisted Arc callback.
    OnInput,
    /// `Ui.onChange` — string-carrying event handler, peel-hoisted Arc callback.
    OnChange,
    /// `Ui.onKeyDown` — string-carrying event handler, inline Arc wrap.
    OnKeyDown,
    /// `Ui.onKeyUp` — string-carrying event handler, inline Arc wrap.
    OnKeyUp,
    /// `Ui.onFile` — string-carrying event handler, inline Arc wrap.
    OnFile,
    /// `Event.onBool` — bool-carrying event handler, inline Arc wrap.
    OnBool,
    /// `Ui.onSubmit` — form handler dispatched by its lowered `OnFormKind`.
    OnSubmit,
    /// An `Ipe.Html.Events` builder, keyed by `html_event_shape` /
    /// `html_event_wire_name`.
    HtmlEvent,
    /// `Lazy.lazy` — one-argument deferred subtree, eta-wrapped.
    LazyLazy,
    /// `Lazy.lazy2` — two-argument deferred subtree, eta-wrapped.
    LazyLazy2,
    /// `Lazy.lazy3` — three-argument deferred subtree, eta-wrapped.
    LazyLazy3,
    /// `Lazy.lazy4` — four-argument deferred subtree, eta-wrapped.
    LazyLazy4,
    /// `Lazy.lazy5` — five-argument deferred subtree, eta-wrapped.
    LazyLazy5,
    /// `PubSub.publish` / `PubSub.publishNoEcho` — turbofished Task kernel.
    PubSubPublish,
    /// `CustomElement.node` — the server-driven custom-element node. Bespoke because its
    /// handler argument must be re-wrapped to satisfy the runtime fn's
    /// `Send + Sync` bound (a boxed fn-value trait object is not `Sync`).
    Widget,
    /// A shape-router delegation to another emitter.
    Delegate(UiDelegate),
}

/// Which sibling emitter a [`NativeUiEmit::Delegate`] routes to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UiDelegate {
    /// `emit_web::emit_web_call` — the Web app-entry kernels.
    Web,
    /// `emit_tui::emit_tui_call` — `Tui.tea`.
    Tui,
    /// `emit_console::emit_console_call` — `Cli.tea`.
    Console,
    /// `emit_worker::emit_worker_call` — `Ipe.Tea.Worker.tea` (view-less).
    Worker,
}

/// A fail-closed guard the interpreter checks before emission.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Guard {
    /// No precondition.
    None,
    /// `Ui.cells` and peers paint raw terminal cells with no browser
    /// denotation; reject them in a Web / `WebView` build (fail-closed) rather
    /// than let the runtime helper degrade to plain text and render wrong.
    RejectInWebShape,
    /// `CustomElement.node` is the server-driven custom element: its up-event handler is
    /// carried over the seal codec, which exists only in a browser shape (`web`
    /// implies the `json` feature; `Terminal` / `Program` do not). Outside a
    /// browser shape the widget has NO transport — the node would be inert, a
    /// widget with no seam. Reject it fail-closed rather than emit a dead
    /// element (or trip the non-`json` runtime fallback's unconstrained type
    /// parameter). Admissible only under `Web.tea`.
    RejectInNonWebShape,
}

#[cfg(test)]
impl ArgPlan {
    /// The Ipê-level argument count this plan expects, when it is a positional
    /// call. `None` for a [`ArgPlan::Native`] plan, whose arity is checked
    /// inside its own emitter.
    pub const fn positional_arity(self) -> Option<u8> {
        match self {
            Self::Positional { arity, .. } => Some(arity),
            Self::Native(_) => None,
        }
    }
}

/// A positional plan with no guard — the uniform majority.
const fn pos(path: &'static str, arity: u8) -> UiEmitPlan {
    UiEmitPlan {
        args: ArgPlan::Positional { path, arity },
        guard: Guard::None,
    }
}

/// A positional plan carrying a fail-closed guard.
const fn guarded(path: &'static str, arity: u8, guard: Guard) -> UiEmitPlan {
    UiEmitPlan {
        args: ArgPlan::Positional { path, arity },
        guard,
    }
}

/// A plan dispatched to a bespoke native emitter.
const fn native(kind: NativeUiEmit) -> UiEmitPlan {
    UiEmitPlan {
        args: ArgPlan::Native(kind),
        guard: Guard::None,
    }
}

/// A bespoke native plan carrying a fail-closed shape guard.
const fn guarded_native(kind: NativeUiEmit, guard: Guard) -> UiEmitPlan {
    UiEmitPlan {
        args: ArgPlan::Native(kind),
        guard,
    }
}

/// A plan delegated to a sibling shape emitter.
const fn delegate(to: UiDelegate) -> UiEmitPlan {
    native(NativeUiEmit::Delegate(to))
}

/// The literal kind of an appearance-hoist-eligible argument position.
///
/// A `String`-valued position bakes and reads its value as a `String`; a typed
/// `Int`/`Float` position bakes the value's canonical decimal string (the
/// numeric constant the style ultimately renders) and reads it back through a
/// total `parse::<T>().unwrap_or(<literal>)`. The `LiteralTable` stays
/// `String`-only in every case — the read kind only decides how the emitted call
/// site consumes the slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LitKind {
    /// A `String` value: bakes as itself, reads back as a `String`.
    Str,
    /// An `Int` value: bakes as its canonical decimal string, reads back through
    /// `parse::<i64>().unwrap_or(<literal>)`.
    Int,
    /// A `Float` value: bakes as its `{}`-canonical string, reads back through
    /// `parse::<f64>().unwrap_or(<literal>)`.
    Float,
}

/// The single declarative appearance-literal registry for dev appearance
/// hot-swap — the one extension point across every appearance-only stdlib
/// surface (`Ipe.Ui`, `Ipe.Html`, `Ipe.Css`, and any future one).
///
/// A literal passed *directly* to one of these kernels, in one of the returned
/// `(arg_pos, kind)` positions, is **inert appearance data the compiled view
/// consumes without branching on it** — a style value, an attribute *value*
/// (never its key), a CSS property *value* (never a selector), or a static text
/// node. Swapping it changes no node identity, no control flow, no handler, and
/// no `Model`-dependent computation, so a value swap is a *complete* description
/// of the edit. Under `IPE_WATCH_HOT_APPEARANCE` such a literal is hoisted into a
/// per-view [`ipe_runtime::literal_table::LiteralTable`] so a dev edit can swap it as data;
/// the baked default is exactly the source value, so a prod build (never patched)
/// renders exactly as the direct emit — one render semantics, dev == prod.
///
/// Returned positions are 0-based indices into the kernel's *direct* arguments. A
/// kernel absent from this table has no hoist-eligible position, and an entry
/// only ever fires on a *direct literal* of the matching kind in that position —
/// a `Model`-dependent or computed argument emits directly and never hoists.
///
/// **Safe by construction.** Every arm is guarded by the dev == prod conformance
/// test (a baked-default render is byte-identical to the direct emit) and the
/// conservative classifier (an unprovable edit recompiles). A mis-marked arm
/// therefore either fails conformance or simply doesn't hoist — it can never
/// hot-swap a logic change. The classifier needs no change per arm: it is
/// emit-diff over the emitted value regions, already library-agnostic, so it
/// hot-swaps whatever this registry hoists regardless of the source module.
///
/// The rule for adding an arm: mark **only** a position that carries an
/// appearance *value* — never a structural or key argument (an attribute *key*,
/// a CSS *selector*, a tag name, a layout-structure arg). When unsure, leave it
/// out; the recompile fallback is merely slower, a false "appearance" would be a
/// correctness bug.
///
/// A `Length`/`Color` kernel whose arg is a *nested call* (`Ui.px n`,
/// `Ui.rgb r g b`) is covered by hoisting the inner literal args of that call,
/// not the outer kernel — the outer arg is not a direct literal and is correctly
/// excluded. The per-corner variants (`Ui.paddingEach`, `Border.widthEach`) build
/// their call through a bespoke native emitter, not the positional-hoist path, so
/// they are absent here rather than silently listed and never hoisted.
// One documented row per appearance kernel — arms that happen to share a body
// (e.g. several generic-attribute kernels marking their value position) are kept
// separate on purpose, each carrying its own kernel's signature and rationale.
#[allow(clippy::match_same_arms)]
#[allow(clippy::too_many_lines)] // the exhaustive, wildcard-free table IS the enforcement — every kernel classified
pub const fn appearance_literal_args(k: KernelFn) -> &'static [(usize, LitKind)] {
    use LitKind::{Float, Int, Str};
    match k {
        // ── Ipe.Ui — style values (String) ────────────────────────────────
        // `Font.family : String -> Attribute msg` — the font family list.
        KernelFn::FontFamily => &[(0, Str)],
        // `Ui.style : String -> String -> Attribute msg` — a raw CSS
        // property/value pair; both are inert style strings.
        KernelFn::UiStyle => &[(0, Str), (1, Str)],

        // ── Ipe.Ui — style values (typed Int) ─────────────────────────────
        // Single-`Int` style kernels: a spacing/padding amount, a font/border
        // size, or a `Length` constructor carrying pixels.
        KernelFn::UiSpacing
        | KernelFn::UiPadding
        // `Ipe.Ui.Tui.spacing / .padding : Int -> Attribute msg` — cells.
        | KernelFn::TuiUiSpacing
        | KernelFn::TuiUiPadding
        | KernelFn::FontSize
        | KernelFn::BorderWidth
        | KernelFn::BorderRounded
        | KernelFn::UiPx
        | KernelFn::UiFillPortion => &[(0, Int)],
        KernelFn::UiPaddingXY => &[(0, Int), (1, Int)],
        // Colour channels (`Int` 0..=255) of an `rgb` literal.
        KernelFn::UiRgb => &[(0, Int), (1, Int), (2, Int)],
        // `rgba`: three `Int` channels plus a `Float` alpha (opacity).
        KernelFn::UiRgba => &[(0, Int), (1, Int), (2, Int), (3, Float)],
        // `Ipe.Color.Ansi.rgb : Int -> Int -> Int -> AnsiColor` — three direct
        // channel literals, the truecolour path of the terminal palette.
        KernelFn::TermColorRgb => &[(0, Int), (1, Int), (2, Int)],
        // `Ipe.Color.Ansi.rgba : Int -> Int -> Int -> Float -> AnsiColor` — three
        // `Int` channels plus a `Float` alpha.
        KernelFn::TermColorRgba => &[(0, Int), (1, Int), (2, Int), (3, Float)],

        // ── Ipe.Ui — direct numeric appearance scalars ────────────────────
        // Each kernel's marked position is a *direct* `Int`/`Float` scalar the
        // style renders inertly, read back through the total
        // `parse::<T>().unwrap_or(<literal>)` path (the `FontSize`/`UiRgb`
        // precedent). A sibling `Length`/`Color`/`Vec` argument is a *nested*
        // call, never a direct literal — its inner literal hoists through its
        // own kernel's arm — so it is left unmarked here.
        //
        // `Font.weight : Int -> Attribute msg` — the numeric weight (100..900).
        KernelFn::FontWeight
        // `Font.hoverSize : Int -> Attribute msg` — the hover font-size in px.
        | KernelFn::FontHoverSize
        // `Border.hoverWidth : Int -> Attribute msg` — hover border width (px).
        | KernelFn::BorderHoverWidth
        // `Border.hoverRounded : Int -> Attribute msg` — hover radius (px).
        | KernelFn::BorderHoverRounded
        // `Ui.vh : Int -> Length` — a viewport-height percentage.
        | KernelFn::UiVh
        // `Ui.vw : Int -> Length` — a viewport-width percentage.
        | KernelFn::UiVw => &[(0, Int)],
        // `Font.letterSpacing : Float -> Attribute msg` — spacing in em.
        KernelFn::FontLetterSpacing
        // `Font.wordSpacing : Float -> Attribute msg` — spacing in em.
        | KernelFn::FontWordSpacing
        // `Ui.aspectRatio : Float -> Attribute msg` — the width/height ratio.
        | KernelFn::UiAspectRatio => &[(0, Float)],
        // `Ui.aspectRatioWH : Int -> Int -> Attribute msg` — width and height
        // integers of the ratio; both are direct inert numbers.
        KernelFn::UiAspectRatioWH => &[(0, Int), (1, Int)],
        // `Border.glow : Int -> Color -> Attribute msg` — mark only the blur
        // radius (position 0); the colour (position 1) is a nested `Color`.
        KernelFn::BorderGlow => &[(0, Int)],
        // `Ui.minimum : Int -> Length -> Length` — mark only the bound (position
        // 0); the wrapped `Length` (position 1) is a nested call.
        KernelFn::UiMinimum
        // `Ui.maximum : Int -> Length -> Length` — same shape as `minimum`.
        | KernelFn::UiMaximum => &[(0, Int)],
        // `Background.linearGradient : Float -> List (Float, Color) -> Attribute msg`
        // — mark only the angle (position 0); the stops list (position 1) is a
        // nested `Vec` whose inner literals are not direct arguments here.
        KernelFn::BackgroundLinearGradient => &[(0, Float)],

        // ── Ipe.Ui — attribute values + static text (String) ──────────────
        // `Ui.text : String -> Element msg` — a static text node's content. The
        // runtime escapes it at render, identically for a direct or hoisted
        // string, so baked == direct holds.
        KernelFn::UiText => &[(0, Str)],
        // `Ui.name : String -> Attribute msg` — the HTML `name=` attribute
        // value (position 0 is the value; there is no separate key arg).
        KernelFn::UiName => &[(0, Str)],
        // `Ui.htmlAttribute : String -> String -> Attribute msg` — a generic
        // `key value` attribute escape-hatch. Mark **only** the value
        // (position 1); the key (position 0) is structural.
        KernelFn::UiHtmlAttribute => &[(1, Str)],

        // ── Ipe.Html — attribute values, style-attr body + static text ────
        // `Html.text : String -> Html msg` — a static text node's content.
        KernelFn::HtmlTextNode => &[(0, Str)],
        // `Html.titleNode : String -> Html msg` — the `<title>` text.
        KernelFn::HtmlTitleNode => &[(0, Str)],
        // `Attr.attribute : String -> String -> Attribute msg` — a generic
        // `key value` attribute. Mark **only** the value (position 1); the key
        // (position 0) is structural.
        KernelFn::HtmlAttribute => &[(1, Str)],
        // `Html.styleNode : List Attr -> String -> Html msg` — the inline CSS
        // body (position 1). Position 0 is the attribute list, not a literal.
        // The runtime close-tag-neutralises the body at construction, identically
        // for a direct or hoisted string, so baked == direct holds.
        KernelFn::HtmlStyleNode => &[(1, Str)],

        // ── Ipe.Ui — raw-CSS / URL appearance values (direct String) ──────
        // Each String below is inert appearance data whose ONLY neutralisation
        // lives at the render sink, keyed on the built `Attribute` variant and a
        // pure function of the String bytes (`render::build_style_string` +
        // `web::style_inject`'s `build_tr` / `build_anim`). Hoisting changes only
        // WHERE the bytes originate — a `LiteralTable` slot read via
        // `__ipe_lit.get(N)` versus a baked literal — never WHICH sink processes
        // them: the emitted read is the SAME runtime-helper call on the slot
        // (`ui_background_image_(__ipe_lit.get(N).to_string())`), so the identical
        // `SafeCssValue` / `is_dangerous_url_scheme` / `sink_safe_keyframes_body`
        // gate runs on a dev-patched value exactly as on the compiled one. Baked
        // default == direct emit == dev-patched value: one sink, dev == prod —
        // the same argument that admits `Font.family` and the `Html.styleNode`
        // body. Every position here is a direct `String`; the trailing `bool`
        // structural args (`respect`) are excluded — they carry no appearance
        // value and gate reduced-motion behaviour, which is logic, not data.
        //
        // `Background.image : String -> Attribute msg` — the URL (position 0),
        // rendered as `background-image: url(<s>)`. The URL sink is the strictest
        // one here, and it stays strict on the hoisted read: `AttrBgImage`'s sink
        // rejects a `javascript:` / `vbscript:` / non-media `data:` scheme
        // (`is_dangerous_url_scheme`) AND breakout-scans the COMPOSED `url(<s>)`
        // through `SafeCssValue` (a `)`/`;`/`}`/`@import`/`</style>` breakout is
        // dropped). Both gates are pure over the String, so a dev-patched URL
        // meets the identical wall a baked one does — no path lets a patched value
        // reach the sink less sanitised than the compiled default.
        KernelFn::BackgroundImage => &[(0, Str)],
        // `Ui.transition : String -> Bool -> Attribute msg` — the raw CSS
        // `transition` shorthand (position 0). Position 1 is the `respect`
        // reduced-motion flag (`bool`, structural — excluded). The shorthand goes
        // through `SafeCssValue` at both the render sink and the live `build_tr`
        // injector, identically for a baked or hoisted string.
        KernelFn::UiTransitionRaw => &[(0, Str)],
        // `Ui.gridTracks : String -> String -> Attribute msg` — the raw CSS grid
        // `cols` (position 0) and `rows` (position 1). Both are style *values* on
        // fixed property names (`grid-template-columns` / `-rows`), each gated by
        // `SafeCssValue` at the render sink — a pure function of the String, so
        // baked == hoisted.
        KernelFn::UiGridTracksRaw => &[(0, Str), (1, Str)],
        // `Ui.animate : String -> String -> String -> Bool -> Attribute msg` —
        // the keyframe-animation `name` (position 0), the animation shorthand TAIL
        // (position 1), and the `@keyframes` BODY (position 2). Position 3 is the
        // `respect` reduced-motion flag (`bool`, structural — excluded). The live
        // `build_anim` sink re-derives the effective `@keyframes` name through
        // `sanitise_animation_name`, gates the tail through `SafeCssValue`, and
        // gates the body through `sink_safe_keyframes_body` (a `}`/`@import`/
        // `</style>` breakout drops the entry fail-closed) — each gate a pure
        // function of the String, so a dev-patched value is neutralised identically
        // to the baked one.
        KernelFn::UiAnimateRaw => &[(0, Str), (1, Str), (2, Str)],

        // ── Ipe.Css — hoisted on the generic path, not this positional site ─
        // `Ipe.Css` is compiled pure Ipê; its one free-string appearance sink
        // that reaches a Rust kernel is the value sanitizer
        // `CssSafety.safeValue : String -> Maybe String`. That kernel is `Pure`,
        // not UI-family, so it is emitted through the generic kernel-call path,
        // NOT this UI-plan positional hoist site — a registry arm here would be
        // dead (listed but never hoisted), so it correctly carries none. Its
        // appearance hot-swap is wired at the generic path instead
        // (`emit_expr::emit_css_value_call`): a direct *safe* literal is hoisted
        // through the SHARED `ipe_kernels::css_value_is_safe` policy and the
        // runtime `safe_value` wrapper is preserved, so the slot is always
        // re-sanitized — sanitize-before-hoist AND re-sanitize-on-read, dev ==
        // prod. The selector sanitizer (`safeSelector`) stays out permanently: a
        // selector changes what a rule targets — that is structure, not
        // appearance.
        // ── Every other kernel — no appearance-hoist position (`&[]`) ─────
        // Exhaustive on purpose: NO `_` wildcard. A newly added `KernelFn`
        // variant lands in neither the appearance arms above nor this list, so
        // it fails to compile until its author classifies it — the same forcing
        // function the stdlib kernel registry uses for feature registration. A
        // kernel here carries no direct-literal appearance value (or reaches a
        // non-UI-plan emit path, where a positional-hoist arm would be dead).
        KernelFn::LogInfo
        | KernelFn::LogDebug
        | KernelFn::LogWarn
        | KernelFn::LogError
        | KernelFn::LogInfoWith
        | KernelFn::LogDebugWith
        | KernelFn::LogWarnWith
        | KernelFn::LogErrorWith
        | KernelFn::StringFromInt
        | KernelFn::StringFromFloat
        | KernelFn::StringLength
        | KernelFn::StringIsEmpty
        | KernelFn::StringReverse
        | KernelFn::StringToUpper
        | KernelFn::StringToLower
        | KernelFn::StringCasefold
        | KernelFn::StringTrim
        | KernelFn::StringTrimStart
        | KernelFn::StringTrimEnd
        | KernelFn::StringToInt
        | KernelFn::StringToFloat
        | KernelFn::StringFromChar
        | KernelFn::StringFromBool
        | KernelFn::StringFromList
        | KernelFn::StringConcat
        | KernelFn::StringWords
        | KernelFn::StringLines
        | KernelFn::StringToList
        | KernelFn::StringIsEmail
        | KernelFn::StringIsUrl
        | KernelFn::StringAppend
        | KernelFn::StringContains
        | KernelFn::StringStartsWith
        | KernelFn::StringEndsWith
        | KernelFn::StringEqualFold
        | KernelFn::StringJoin
        | KernelFn::StringSplit
        | KernelFn::StringRepeat
        | KernelFn::StringDropLeft
        | KernelFn::StringDropRight
        | KernelFn::StringReplace
        | KernelFn::StringSlice
        | KernelFn::StringPadLeft
        | KernelFn::StringPadRight
        | KernelFn::StringContainsIn
        | KernelFn::StringStartsWithIn
        | KernelFn::StringEndsWithIn
        | KernelFn::StringLeft
        | KernelFn::StringRight
        | KernelFn::StringCons
        | KernelFn::StringUncons
        | KernelFn::StringPad
        | KernelFn::StringIndexes
        | KernelFn::StringMap
        | KernelFn::StringFilter
        | KernelFn::StringFoldl
        | KernelFn::StringFoldr
        | KernelFn::StringAny
        | KernelFn::StringAll
        | KernelFn::CharIsAlpha
        | KernelFn::CharIsDigit
        | KernelFn::CharIsLower
        | KernelFn::CharIsUpper
        | KernelFn::CharToLower
        | KernelFn::CharToUpper
        | KernelFn::CharToCode
        | KernelFn::CharFromCode
        | KernelFn::CharIsAlphaNum
        | KernelFn::CharIsHexDigit
        | KernelFn::CharIsOctDigit
        | KernelFn::ListMap
        | KernelFn::ListFilter
        | KernelFn::ListFoldl
        | KernelFn::ListFoldr
        | KernelFn::ListLength
        | KernelFn::ListHead
        | KernelFn::ListTail
        | KernelFn::ListMember
        | KernelFn::ListRange
        | KernelFn::ListReverse
        | KernelFn::ListAppend
        | KernelFn::ListConcat
        | KernelFn::ListTake
        | KernelFn::ListDrop
        | KernelFn::ListZip
        | KernelFn::ListCons
        | KernelFn::ListIsEmpty
        | KernelFn::ListConcatMap
        | KernelFn::ListIndexedMap
        | KernelFn::ListAny
        | KernelFn::ListAll
        | KernelFn::ListFind
        | KernelFn::ListFilterMap
        | KernelFn::ListSortBy
        | KernelFn::ListSort
        | KernelFn::ListSortWith
        | KernelFn::ListSingleton
        | KernelFn::ListRepeat
        | KernelFn::ListSum
        | KernelFn::ListProduct
        | KernelFn::ListMaximum
        | KernelFn::ListMinimum
        | KernelFn::ListUnique
        | KernelFn::ListIntersperse
        | KernelFn::ListPartition
        | KernelFn::ListUnzip
        | KernelFn::ListMap2
        | KernelFn::ListMap3
        | KernelFn::ListMap4
        | KernelFn::ListMap5
        | KernelFn::BasicsNot
        | KernelFn::BasicsIdentity
        | KernelFn::BasicsAlways
        | KernelFn::BasicsFst
        | KernelFn::BasicsSnd
        | KernelFn::BasicsModBy
        | KernelFn::Interpolate
        | KernelFn::BasicsClamp
        | KernelFn::BasicsNegate
        | KernelFn::BasicsAbs
        | KernelFn::BasicsSqrt
        | KernelFn::BasicsMin
        | KernelFn::BasicsMax
        | KernelFn::BasicsCompare
        | KernelFn::ErrorUnexpected
        | KernelFn::ErrorInvalidInput
        | KernelFn::ErrorIo
        | KernelFn::ErrorNetwork
        | KernelFn::ErrorFfi
        | KernelFn::ErrorDecode
        | KernelFn::ErrorConflict
        | KernelFn::ErrorUnavailable
        | KernelFn::ErrorTimeout
        | KernelFn::ErrorNotFound
        | KernelFn::ErrorPermissionDenied
        | KernelFn::ErrorToString
        | KernelFn::ErrorWithMessage
        | KernelFn::ErrorIsRetryable
        | KernelFn::ErrorWithDetails
        | KernelFn::ErrorKind
        | KernelFn::ErrorMessage
        | KernelFn::ErrorKindName
        | KernelFn::CssSafetySafeValue
        | KernelFn::CssSafetySafePropName
        | KernelFn::CssSafetySafeSelector
        | KernelFn::CssSafetyStripStyleClose
        | KernelFn::CssSafetySanitizeRawBody
        | KernelFn::MaybeWithDefault
        | KernelFn::MaybeMap
        | KernelFn::MaybeAndThen
        | KernelFn::MaybeMap2
        | KernelFn::MaybeMap3
        | KernelFn::MaybeMap4
        | KernelFn::MaybeMap5
        | KernelFn::MaybeAndMap
        | KernelFn::MaybeCombine
        | KernelFn::MaybeIsJust
        | KernelFn::MaybeIsNothing
        | KernelFn::ResultWithDefault
        | KernelFn::ResultMap
        | KernelFn::ResultAndThen
        | KernelFn::ResultMapError
        | KernelFn::ResultMap2
        | KernelFn::ResultMap3
        | KernelFn::ResultMap4
        | KernelFn::ResultMap5
        | KernelFn::ResultAndMap
        | KernelFn::ResultCombine
        | KernelFn::ResultTraverse
        | KernelFn::ResultToMaybe
        | KernelFn::ResultFromMaybe
        | KernelFn::ResultOkDefault
        | KernelFn::MathMin
        | KernelFn::MathMax
        | KernelFn::MathPi
        | KernelFn::MathE
        | KernelFn::MathPhi
        | KernelFn::MathSqrt2
        | KernelFn::MathInf
        | KernelFn::MathNan
        | KernelFn::MathIsNaN
        | KernelFn::MathAbs
        | KernelFn::MathSqrt
        | KernelFn::MathCbrt
        | KernelFn::MathExp
        | KernelFn::MathExp2
        | KernelFn::MathLog
        | KernelFn::MathLog2
        | KernelFn::MathLog10
        | KernelFn::MathSin
        | KernelFn::MathCos
        | KernelFn::MathTan
        | KernelFn::MathAsin
        | KernelFn::MathAcos
        | KernelFn::MathAtan
        | KernelFn::MathSinh
        | KernelFn::MathCosh
        | KernelFn::MathTanh
        | KernelFn::MathAsinh
        | KernelFn::MathAcosh
        | KernelFn::MathAtanh
        | KernelFn::MathFloor
        | KernelFn::MathCeil
        | KernelFn::MathRound
        | KernelFn::MathTrunc
        | KernelFn::MathPow
        | KernelFn::MathHypot
        | KernelFn::MathAtan2
        | KernelFn::MathMod
        | KernelFn::MathRemainder
        | KernelFn::BitwiseAnd
        | KernelFn::BitwiseOr
        | KernelFn::BitwiseXor
        | KernelFn::BitwiseComplement
        | KernelFn::BitwiseShiftLeftBy
        | KernelFn::BitwiseShiftRightBy
        | KernelFn::BitwiseShiftRightZfBy
        | KernelFn::RandomSeededInt
        | KernelFn::RandomSeededFloat
        | KernelFn::RandomSeededChoice
        | KernelFn::DictEmpty
        | KernelFn::DictIsEmpty
        | KernelFn::DictSize
        | KernelFn::DictKeys
        | KernelFn::DictValues
        | KernelFn::DictToList
        | KernelFn::DictFromList
        | KernelFn::DictGet
        | KernelFn::DictMember
        | KernelFn::DictRemove
        | KernelFn::DictUnion
        | KernelFn::DictMap
        | KernelFn::DictInsert
        | KernelFn::DictFoldl
        | KernelFn::DictSingleton
        | KernelFn::DictFoldr
        | KernelFn::DictFilter
        | KernelFn::DictPartition
        | KernelFn::DictIntersect
        | KernelFn::DictDiff
        | KernelFn::DictUpdate
        | KernelFn::SetEmpty
        | KernelFn::SetSize
        | KernelFn::SetToList
        | KernelFn::SetFromList
        | KernelFn::SetMember
        | KernelFn::SetInsert
        | KernelFn::SetRemove
        | KernelFn::SetUnion
        | KernelFn::SetIntersect
        | KernelFn::SetDiff
        | KernelFn::SetIsEmpty
        | KernelFn::SetSingleton
        | KernelFn::SetFoldl
        | KernelFn::SetFoldr
        | KernelFn::SetMap
        | KernelFn::SetFilter
        | KernelFn::SetPartition
        | KernelFn::BytesEmpty
        | KernelFn::BytesLength
        | KernelFn::BytesIsEmpty
        | KernelFn::BytesFromString
        | KernelFn::BytesToString
        | KernelFn::BytesFromHex
        | KernelFn::BytesToHex
        | KernelFn::BytesFromBase64
        | KernelFn::BytesToBase64
        | KernelFn::BytesAppend
        | KernelFn::BytesSlice
        | KernelFn::EncodingBase64Encode
        | KernelFn::EncodingBase64Decode
        | KernelFn::EncodingUrlEncode
        | KernelFn::EncodingUrlDecode
        | KernelFn::EncodingPercentDecode
        | KernelFn::EncodingHexEncode
        | KernelFn::EncodingHexDecode
        | KernelFn::JsonEncString
        | KernelFn::JsonEncInt
        | KernelFn::JsonEncFloat
        | KernelFn::JsonEncBool
        | KernelFn::JsonEncNull
        | KernelFn::JsonEncList
        | KernelFn::JsonEncObject
        | KernelFn::JsonEncEncode
        | KernelFn::JsonDecString
        | KernelFn::JsonDecInt
        | KernelFn::JsonDecFloat
        | KernelFn::JsonDecBool
        | KernelFn::JsonDecValue
        | KernelFn::JsonDecDecodeString
        | KernelFn::JsonDecDecodeValue
        | KernelFn::JsonDecField
        | KernelFn::JsonDecAt
        | KernelFn::JsonDecIndex
        | KernelFn::JsonDecList
        | KernelFn::JsonDecNullable
        | KernelFn::JsonDecMap
        | KernelFn::JsonDecAndThen
        | KernelFn::JsonDecSucceed
        | KernelFn::JsonDecFail
        | KernelFn::JsonDecOneOf
        | KernelFn::JsonDecMap2
        | KernelFn::JsonDecMap3
        | KernelFn::JsonDecMap4
        | KernelFn::JsonDecPRequired
        | KernelFn::JsonDecPOptional
        | KernelFn::JsonDecPCustom
        | KernelFn::JsonDecPRequiredAt
        | KernelFn::CryptoSha256
        | KernelFn::CryptoSha512
        | KernelFn::CryptoSha1
        | KernelFn::CryptoMd5
        | KernelFn::CryptoRsaSha256Sign
        | KernelFn::CryptoRsaSha256Verify
        | KernelFn::CryptoConstantTimeEqual
        | KernelFn::CryptoAesGcmEncrypt
        | KernelFn::CryptoAesGcmDecrypt
        | KernelFn::CryptoChacha20Encrypt
        | KernelFn::CryptoChacha20Decrypt
        | KernelFn::CryptoAesKeyFromPassword
        | KernelFn::CryptoChachaKeyFromPassword
        | KernelFn::CryptoRandomBytes
        | KernelFn::CryptoRandomToken
        | KernelFn::UuidV4
        | KernelFn::UuidV7
        | KernelFn::UuidParse
        | KernelFn::JwtEncodeHs256
        | KernelFn::JwtDecodeHs256
        | KernelFn::JwtEncodeRs256
        | KernelFn::JwtDecodeRs256
        | KernelFn::JwtClaims
        | KernelFn::JwtHs256
        | KernelFn::JwtRs256
        | KernelFn::JwtSubject
        | KernelFn::JwtIssuer
        | KernelFn::JwtAudience
        | KernelFn::JwtExpiresAt
        | KernelFn::JwtNotBefore
        | KernelFn::JwtIssuedAt
        | KernelFn::JwtJwtId
        | KernelFn::JwtWithClaim
        | KernelFn::JwtEncode
        | KernelFn::JwtDecode
        | KernelFn::TaskSucceed
        | KernelFn::TaskFail
        | KernelFn::TaskMap
        | KernelFn::TaskMap2
        | KernelFn::TaskMap3
        | KernelFn::TaskMap4
        | KernelFn::TaskMap5
        | KernelFn::TaskAttempt
        | KernelFn::TaskAndThen
        | KernelFn::TaskMapError
        | KernelFn::TaskOnError
        | KernelFn::TaskFromResult
        | KernelFn::TaskAndThenResult
        | KernelFn::TaskSequence
        | KernelFn::TaskParallel
        | KernelFn::TaskRun
        | KernelFn::TaskPerform
        | KernelFn::TaskLazy
        | KernelFn::TaskLoop
        | KernelFn::TaskRetryWith
        | KernelFn::TaskLinearBackoff
        | KernelFn::TaskExponentialBackoff
        | KernelFn::TaskWithJitter
        | KernelFn::TaskRetryOn
        | KernelFn::TaskWithRetryOn
        | KernelFn::TaskDefaultRetryPolicy
        | KernelFn::TaskWithMaxAttempts
        | KernelFn::TaskWithBaseMs
        | KernelFn::IoReadLine
        | KernelFn::IoReadSecret
        | KernelFn::IoWriteStdout
        | KernelFn::IoWriteStderr
        | KernelFn::IoPrintln
        | KernelFn::IoEprintln
        | KernelFn::DebugLog
        | KernelFn::DebugTodo
        | KernelFn::DebugExplain
        | KernelFn::TimeNow
        | KernelFn::TimeSleep
        | KernelFn::TimeUnixMillis
        | KernelFn::TimeTimeString
        | KernelFn::TimeIsLeapYear
        | KernelFn::TimeDaysInMonth
        | KernelFn::TimeFormat
        | KernelFn::TimeFormatHTTP
        | KernelFn::TimeFormatISO8601
        | KernelFn::TimeFormatRFC3339
        | KernelFn::TimeAddMillis
        | KernelFn::TimeDiffMillis
        | KernelFn::SystemArgs
        | KernelFn::SystemGetenv
        | KernelFn::SystemGetenvOr
        | KernelFn::SystemGetArg
        | KernelFn::SystemGetenvInt
        | KernelFn::SystemGetenvBool
        | KernelFn::SystemSetenv
        | KernelFn::SystemUnsetenv
        | KernelFn::SystemCwd
        | KernelFn::SystemGetcwd
        | KernelFn::SystemLoadEnv
        | KernelFn::SystemExit
        | KernelFn::RandomInt
        | KernelFn::RandomFloat
        | KernelFn::RandomChoice
        | KernelFn::RandomChoiceMaybe
        | KernelFn::RandomShuffle
        | KernelFn::RandomWeighted
        | KernelFn::FileReadFile
        | KernelFn::FileWriteFile
        | KernelFn::FileExists
        | KernelFn::FileRemove
        | KernelFn::FileMkdirAll
        | KernelFn::FileReadFileLimit
        | KernelFn::FileReadFileBytes
        | KernelFn::FileAppend
        | KernelFn::FileReadDir
        | KernelFn::FileIsDir
        | KernelFn::FileTempFile
        | KernelFn::FileTempDir
        | KernelFn::FileCopy
        | KernelFn::FileRename
        | KernelFn::FileDelete
        | KernelFn::FileWalk
        | KernelFn::FileWalkMatching
        | KernelFn::ProcessRun
        | KernelFn::ProcessRunWith
        | KernelFn::ProcessRunInPty
        | KernelFn::HttpGet
        | KernelFn::HttpPost
        | KernelFn::HttpRequest
        | KernelFn::HttpParseQuery
        | KernelFn::HttpDefaultRequest
        | KernelFn::HttpDefaultRequestFromString
        | KernelFn::HttpWithMethod
        | KernelFn::HttpWithTimeout
        | KernelFn::HttpWithBody
        | KernelFn::HttpWithHeader
        | KernelFn::HttpWithUrl
        | KernelFn::HttpWithRedirects
        | KernelFn::HttpMethodFromString
        | KernelFn::HttpMethodToString
        | KernelFn::DbConnect
        | KernelFn::DbOpen
        | KernelFn::DbClose
        | KernelFn::DsnParse
        | KernelFn::DsnBuild
        | KernelFn::DsnDriverTag
        | KernelFn::DsnHost
        | KernelFn::DsnPort
        | KernelFn::DsnDatabase
        | KernelFn::DsnUser
        | KernelFn::DsnTlsTag
        | KernelFn::DsnRedacted
        | KernelFn::DbConnOpen
        | KernelFn::DbConnClose
        | KernelFn::DbConnUnsafeExecRawOn
        | KernelFn::DbConnFindWhere
        | KernelFn::DbConnQueryDecode
        | KernelFn::DbConnGetById
        | KernelFn::DbExecRaw
        | KernelFn::DbExec
        | KernelFn::DbQuery
        | KernelFn::DbQueryDecode
        | KernelFn::DbGetString
        | KernelFn::DbGetInt
        | KernelFn::DbGetBool
        | KernelFn::DbGetField
        | KernelFn::DbInsertRow
        | KernelFn::DbGetById
        | KernelFn::DbUpdateById
        | KernelFn::DbDeleteById
        | KernelFn::DbFindOneByField
        | KernelFn::DbFindManyByField
        | KernelFn::DbFindByConditions
        | KernelFn::DbInsertFields
        | KernelFn::DbUpdateFields
        | KernelFn::DbInsertFieldsReturning
        | KernelFn::DbWithTransaction
        | KernelFn::DbMigrate
        | KernelFn::DbDefaultMigration
        | KernelFn::StoreEqCol
        | KernelFn::StoreJoin
        | KernelFn::StoreSelect
        | KernelFn::StoreLiteral
        | KernelFn::StoreUpper
        | KernelFn::StoreLower
        | KernelFn::StoreCoalesce
        | KernelFn::StoreAdd
        | KernelFn::StoreSub
        | KernelFn::StoreMul
        | KernelFn::StoreEqBy
        | KernelFn::StoreNeqCol
        | KernelFn::StoreNeqBy
        | KernelFn::StoreGtCol
        | KernelFn::StoreGtBy
        | KernelFn::StoreGteCol
        | KernelFn::StoreGteBy
        | KernelFn::StoreLtCol
        | KernelFn::StoreLtBy
        | KernelFn::StoreLteCol
        | KernelFn::StoreLteBy
        | KernelFn::StoreLike
        | KernelFn::StoreIsNull
        | KernelFn::StoreNotNull
        | KernelFn::StoreInListCol
        | KernelFn::StoreInListBy
        | KernelFn::StorePrimaryKey
        | KernelFn::StoreSerial
        | KernelFn::StoreUnique
        | KernelFn::StoreDefaultNow
        | KernelFn::StoreTouchOnUpdate
        | KernelFn::StoreDefaultText
        | KernelFn::StoreDefaultInt
        | KernelFn::StoreCompositePrimaryKey2
        | KernelFn::StoreCompositePrimaryKey3
        | KernelFn::StoreOwnerColumn
        | KernelFn::StoreImmutable
        | KernelFn::StoreMask
        | KernelFn::StoreCorrelate
        | KernelFn::StoreExistsIn
        | KernelFn::StoreOrderByLeft
        | KernelFn::StoreOrderByRight
        | KernelFn::DbDecString
        | KernelFn::DbDecInt
        | KernelFn::DbDecFloat
        | KernelFn::DbDecBool
        | KernelFn::DbDecNullable
        | KernelFn::DbDecMap
        | KernelFn::DbDecAndThen
        | KernelFn::DbDecSucceed
        | KernelFn::DbDecFail
        | KernelFn::DbDecMap2
        | KernelFn::DbDecMap3
        | KernelFn::DbDecMap4
        | KernelFn::DbDecRequired
        | KernelFn::DbDecOptional
        | KernelFn::DbDecMoney
        | KernelFn::DbDecDecimal
        | KernelFn::DbDecBytes
        | KernelFn::CmdNone
        | KernelFn::CmdBatch
        | KernelFn::CmdPerform
        | KernelFn::CmdMap
        | KernelFn::SubNone
        | KernelFn::SubBatch
        | KernelFn::SubEvery
        | KernelFn::TimeEvery
        | KernelFn::SubMap
        | KernelFn::TuiSubOnKey
        | KernelFn::CliSubOnLine
        | KernelFn::CmdPublish
        | KernelFn::CmdPublishNoEcho
        | KernelFn::SubSubscribeTopic
        | KernelFn::PubSubPublish
        | KernelFn::PubSubPublishNoEcho
        | KernelFn::PubSubTopic
        | KernelFn::ServerGet
        | KernelFn::ServerPost
        | KernelFn::ServerPut
        | KernelFn::ServerDelete
        | KernelFn::ServerAny
        | KernelFn::ServerApi
        | KernelFn::ServerStatic
        | KernelFn::ServerMountApp
        | KernelFn::ServerListen
        | KernelFn::ServerText
        | KernelFn::ServerJson
        | KernelFn::ServerHtml
        | KernelFn::ServerWithStatus
        | KernelFn::ServerWithHeader
        | KernelFn::ServerRedirect
        | KernelFn::ServerParam
        | KernelFn::ServerQueryParam
        | KernelFn::ServerHeader
        | KernelFn::ServerGetCookie
        | KernelFn::ServerBody
        | KernelFn::ServerPath
        | KernelFn::ServerMethod
        | KernelFn::ServerCookieNew
        | KernelFn::ServerWithCookie
        | KernelFn::ServerAuthConfig
        | KernelFn::ServerTokenBearer
        | KernelFn::ServerCookieToken
        | KernelFn::ServerWithRevocation
        | KernelFn::ServerGetAuthed
        | KernelFn::ServerPostAuthed
        | KernelFn::ServerPutAuthed
        | KernelFn::ServerDeleteAuthed
        | KernelFn::MiddlewareWithCors
        | KernelFn::MiddlewareWithLogging
        | KernelFn::MiddlewareWithBasicAuth
        | KernelFn::MiddlewareWithRateLimit
        | KernelFn::MiddlewareWithCsrf
        | KernelFn::RateLimitAllow
        | KernelFn::UiLayout
        | KernelFn::UiLayoutWith
        | KernelFn::HtmlRender
        | KernelFn::HtmlEscapeText
        | KernelFn::HtmlEscapeAttr
        | KernelFn::HtmlAttrToString
        | KernelFn::UiNone
        | KernelFn::UiHtml
        | KernelFn::UiCells
        | KernelFn::UiCellsNone
        | KernelFn::UiCellsText
        | KernelFn::UiCellsEl
        | KernelFn::UiCellsRow
        | KernelFn::UiCellsColumn
        | KernelFn::UiCellsCells
        | KernelFn::TuiUiAlignLeft
        | KernelFn::TuiUiAlignRight
        | KernelFn::TuiUiCenter
        | KernelFn::TuiUiBold
        | KernelFn::TuiUiUnderline
        | KernelFn::TuiUiDim
        | KernelFn::TuiUiReverse
        | KernelFn::TuiUiColor
        | KernelFn::TuiUiBg
        | KernelFn::CliUiNone
        | KernelFn::CliUiText
        | KernelFn::CliUiLine
        | KernelFn::CliUiLines
        | KernelFn::CliUiBold
        | KernelFn::CliUiUnderline
        | KernelFn::CliUiDim
        | KernelFn::CliUiReverse
        | KernelFn::CliUiColor
        | KernelFn::CliUiBg
        | KernelFn::TermColorBlack
        | KernelFn::TermColorRed
        | KernelFn::TermColorGreen
        | KernelFn::TermColorYellow
        | KernelFn::TermColorBlue
        | KernelFn::TermColorMagenta
        | KernelFn::TermColorCyan
        | KernelFn::TermColorWhite
        | KernelFn::TermColorBrightBlack
        | KernelFn::TermColorBrightRed
        | KernelFn::TermColorBrightGreen
        | KernelFn::TermColorBrightYellow
        | KernelFn::TermColorBrightBlue
        | KernelFn::TermColorBrightMagenta
        | KernelFn::TermColorBrightCyan
        | KernelFn::TermColorBrightWhite
        | KernelFn::TermColorDefault
        | KernelFn::UiWidget
        | KernelFn::UiNode
        | KernelFn::UiTaggedNode
        | KernelFn::UiButton
        | KernelFn::UiLink
        | KernelFn::UiImage
        | KernelFn::UiAbove
        | KernelFn::UiBelow
        | KernelFn::UiOnLeft
        | KernelFn::UiOnRight
        | KernelFn::UiInFront
        | KernelFn::UiBehind
        | KernelFn::UiPaddingEach
        | KernelFn::UiWidth
        | KernelFn::UiHeight
        | KernelFn::UiCenterX
        | KernelFn::UiCenterY
        | KernelFn::UiAlignLeft
        | KernelFn::UiAlignRight
        | KernelFn::UiAlignTop
        | KernelFn::UiAlignBottom
        | KernelFn::UiPointer
        | KernelFn::UiClip
        | KernelFn::UiClipX
        | KernelFn::UiClipY
        | KernelFn::UiScrollbars
        | KernelFn::UiScrollbarX
        | KernelFn::UiScrollbarY
        | KernelFn::UiGridColumns
        | KernelFn::UiFill
        | KernelFn::UiContent
        | KernelFn::UiShrink
        | KernelFn::UiWhite
        | KernelFn::UiBlack
        | KernelFn::UiTransparent
        | KernelFn::UiColorCss
        | KernelFn::BackgroundColor
        | KernelFn::BorderColor
        | KernelFn::BorderWidthEach
        | KernelFn::BorderShadow
        | KernelFn::BorderInnerShadow
        | KernelFn::FontColor
        | KernelFn::FontBold
        | KernelFn::FontItalic
        | KernelFn::HtmlRawNode
        | KernelFn::HtmlNode
        | KernelFn::HtmlVoidNode
        | KernelFn::HtmlDoctype
        | KernelFn::HtmlToString
        | KernelFn::HtmlScriptNode
        | KernelFn::HtmlBoolAttribute
        | KernelFn::HtmlNoAttr
        | KernelFn::WebApp
        | KernelFn::WebAppRouted
        | KernelFn::WebEmbed
        | KernelFn::WebRoute
        | KernelFn::WebRenderStatic
        | KernelFn::TerminalAppScreen
        | KernelFn::WebAppWith
        | KernelFn::AppFromEnv
        | KernelFn::AppFromEnvRequired
        | KernelFn::HostBind
        | KernelFn::LogLevelSetting
        | KernelFn::DbUrlSetting
        | KernelFn::ConsoleAdminToken
        | KernelFn::ConsoleIngestToken
        | KernelFn::ConsoleMetricsToken
        | KernelFn::WebCsrf
        | KernelFn::WebSessionTtl
        | KernelFn::WebAuthMaxLifetime
        | KernelFn::WebAuthSlideWindow
        | KernelFn::WebAuthRevocationMode
        | KernelFn::HostLoopback
        | KernelFn::HostAllInterfaces
        | KernelFn::HostEnvDriven
        | KernelFn::LevelDebug
        | KernelFn::LevelInfo
        | KernelFn::LevelWarn
        | KernelFn::LevelError
        | KernelFn::WebCsrfStrict
        | KernelFn::WebCsrfInherit
        | KernelFn::WebRevocationOff
        | KernelFn::WebRevocationStore
        | KernelFn::UiOnClick
        | KernelFn::UiOnFocus
        | KernelFn::UiOnBlur
        | KernelFn::UiOnMouseOver
        | KernelFn::UiOnMouseOut
        | KernelFn::UiOnInput
        | KernelFn::UiOnChange
        | KernelFn::UiOnKeyDown
        | KernelFn::UiOnKeyUp
        | KernelFn::UiOnBool
        | KernelFn::UiOnSubmit
        | KernelFn::UiOnFile
        | KernelFn::HtmlOnClick
        | KernelFn::HtmlOnFocus
        | KernelFn::HtmlOnBlur
        | KernelFn::HtmlOnMouseOver
        | KernelFn::HtmlOnMouseOut
        | KernelFn::HtmlOnSubmit
        | KernelFn::HtmlOnInput
        | KernelFn::HtmlOnChange
        | KernelFn::HtmlOnKeyDown
        | KernelFn::HtmlOnKeyUp
        | KernelFn::HtmlOnBool
        | KernelFn::UiSquare
        | KernelFn::UiWidescreen
        | KernelFn::UiCinemascope
        | KernelFn::UiBreakpoint
        | KernelFn::UiMediaQuery
        | KernelFn::UiMobile
        | KernelFn::UiTablet
        | KernelFn::UiDesktop
        | KernelFn::UiDarkMode
        | KernelFn::UiLightMode
        | KernelFn::UiReducedMotion
        | KernelFn::UiOnPseudo
        | KernelFn::UiHover
        | KernelFn::UiFocus
        | KernelFn::UiFocusVisible
        | KernelFn::UiActive
        | KernelFn::UiDisabled
        | KernelFn::BackgroundHoverColor
        | KernelFn::BackgroundFocusColor
        | KernelFn::BackgroundActiveColor
        | KernelFn::BackgroundDisabledColor
        | KernelFn::BorderSolid
        | KernelFn::BorderDashed
        | KernelFn::BorderDotted
        | KernelFn::BorderHoverColor
        | KernelFn::BorderFocusColor
        | KernelFn::BorderActiveColor
        | KernelFn::FontSemiBold
        | KernelFn::FontRegular
        | KernelFn::FontLight
        | KernelFn::FontExtraBold
        | KernelFn::FontBlack
        | KernelFn::FontUnderline
        | KernelFn::FontNoDecoration
        | KernelFn::FontLineThrough
        | KernelFn::FontAlignLeft
        | KernelFn::FontAlignRight
        | KernelFn::FontAlignCenter
        | KernelFn::FontCenter
        | KernelFn::FontJustify
        | KernelFn::FontSansSerif
        | KernelFn::FontSerif
        | KernelFn::FontMonospace
        | KernelFn::FontHoverColor
        | KernelFn::FontFocusColor
        | KernelFn::FontActiveColor
        | KernelFn::FontDisabledColor
        | KernelFn::TerminalAppLines
        | KernelFn::AuthHashPassword
        | KernelFn::AuthHashPasswordCost
        | KernelFn::AuthVerifyPassword
        | KernelFn::AuthPasswordStrength
        | KernelFn::AuthSignToken
        | KernelFn::AuthVerifyToken
        | KernelFn::AuthRegister
        | KernelFn::AuthLogin
        | KernelFn::AuthSetRole
        | KernelFn::AuthSubject
        | KernelFn::AuthClaim
        | KernelFn::AuthHasRole
        | KernelFn::AuthMemberOf
        | KernelFn::AuthRevocationRevokeUser
        | KernelFn::AuthRevocationRevokeSession
        | KernelFn::AuthRevocationRestoreUser
        | KernelFn::AuthRevocationIsRevoked
        | KernelFn::StreamStream
        | KernelFn::StreamEmit
        | KernelFn::StreamFinish
        | KernelFn::StreamWithContentType
        | KernelFn::HttpStreamOpen
        | KernelFn::HttpStreamForEachChunk
        | KernelFn::HttpStreamClose
        | KernelFn::HttpStreamChunks
        | KernelFn::WsDefaultCfg
        | KernelFn::WsWithOnConnect
        | KernelFn::WsWithOnMessage
        | KernelFn::WsWithOnClose
        | KernelFn::WsWithOnError
        | KernelFn::WsWithMaxMessageBytes
        | KernelFn::WsWithOriginPatterns
        | KernelFn::WsUpgrade
        | KernelFn::WsSendToClient
        | KernelFn::WsSendBinaryToClient
        | KernelFn::WsBroadcast
        | KernelFn::WsCloseClient
        | KernelFn::WebSocketConnect
        | KernelFn::WebSocketConnectWith
        | KernelFn::WebSocketSend
        | KernelFn::WebSocketSendBinary
        | KernelFn::WebSocketClose
        | KernelFn::WebSocketCloseWithCode
        | KernelFn::SubSubscribeWebSocket
        | KernelFn::JsSend
        | KernelFn::JsSubscribe
        | KernelFn::JsRequest
        | KernelFn::JsOpenSession
        | KernelFn::JsSessionFrames
        | KernelFn::JsSendToSession
        | KernelFn::JsCloseSession
        | KernelFn::EnvPublic
        | KernelFn::RegionMainContent
        | KernelFn::RegionNavigation
        | KernelFn::RegionFooter
        | KernelFn::RegionAside
        | KernelFn::RegionHeading
        | KernelFn::RegionLabel
        | KernelFn::RegionAnnounce
        | KernelFn::RegionAnnounceUrgently
        | KernelFn::UiDescribe
        | KernelFn::UiDescNone
        | KernelFn::UiDescParagraph
        | KernelFn::UiDescMain
        | KernelFn::UiDescNavigation
        | KernelFn::UiDescContentInfo
        | KernelFn::UiDescComplementary
        | KernelFn::UiDescLivePolite
        | KernelFn::UiDescLiveAssertive
        | KernelFn::UiDescHeading
        | KernelFn::UiDescLabel
        | KernelFn::InputLabelAbove
        | KernelFn::InputLabelBelow
        | KernelFn::InputLabelLeft
        | KernelFn::InputLabelRight
        | KernelFn::InputLabelHidden
        | KernelFn::InputPlaceholder
        | KernelFn::InputText
        | KernelFn::InputMultiline
        | KernelFn::InputEmail
        | KernelFn::InputUsername
        | KernelFn::InputSearch
        | KernelFn::InputCurrentPassword
        | KernelFn::InputNewPassword
        | KernelFn::InputCheckbox
        | KernelFn::InputSlider
        | KernelFn::InputOption
        | KernelFn::InputRadio
        | KernelFn::InputRadioRow
        | KernelFn::LazyLazy
        | KernelFn::LazyLazy2
        | KernelFn::LazyLazy3
        | KernelFn::LazyLazy4
        | KernelFn::LazyLazy5
        | KernelFn::KeyedColumn
        | KernelFn::KeyedRow
        | KernelFn::DecZero
        | KernelFn::DecOne
        | KernelFn::DecOneHundred
        | KernelFn::DecFromString
        | KernelFn::DecFromInt
        | KernelFn::DecFromFloat
        | KernelFn::DecFromMinor
        | KernelFn::DecToString
        | KernelFn::DecToStringFixed
        | KernelFn::DecToFloat
        | KernelFn::DecToInt
        | KernelFn::DecToMinor
        | KernelFn::DecAdd
        | KernelFn::DecSub
        | KernelFn::DecMul
        | KernelFn::DecDiv
        | KernelFn::DecMod
        | KernelFn::DecNeg
        | KernelFn::DecAbs
        | KernelFn::DecFloor
        | KernelFn::DecCeil
        | KernelFn::DecRound
        | KernelFn::DecRoundHalfUp
        | KernelFn::DecTruncate
        | KernelFn::DecCompare
        | KernelFn::DecEq
        | KernelFn::DecNeq
        | KernelFn::DecLt
        | KernelFn::DecLte
        | KernelFn::DecGt
        | KernelFn::DecGte
        | KernelFn::DecMin
        | KernelFn::DecMax
        | KernelFn::DecIsZero
        | KernelFn::DecIsPositive
        | KernelFn::DecIsNegative
        | KernelFn::DecPercentOf
        | KernelFn::DecAddPercent
        | KernelFn::DecSubPercent
        | KernelFn::DecFormatWith
        | KernelFn::MoneyMinorUnits
        | KernelFn::MoneySymbol
        | KernelFn::MoneyCurrencyName
        | KernelFn::MoneyIsKnownCurrency
        | KernelFn::MoneyFormat
        | KernelFn::MoneyFormatWithCode
        | KernelFn::MoneyAllocate
        | KernelFn::MoneySetRate
        | KernelFn::MoneyGetRate
        | KernelFn::MoneyHasRate
        | KernelFn::MoneyClearRates
        | KernelFn::SqlColumn
        | KernelFn::SqlUnsafeFragment
        | KernelFn::SqlParam
        | KernelFn::SqlInt
        | KernelFn::SqlString
        | KernelFn::SqlFloat
        | KernelFn::SqlBool
        | KernelFn::SqlEq
        | KernelFn::SqlNe
        | KernelFn::SqlGt
        | KernelFn::SqlLt
        | KernelFn::SqlGte
        | KernelFn::SqlLte
        | KernelFn::SqlAnd
        | KernelFn::SqlOr
        | KernelFn::SqlNot
        | KernelFn::SqlIsNull
        | KernelFn::SqlIsNotNull
        | KernelFn::SqlInList
        | KernelFn::SqlLike
        | KernelFn::SqlStartsWith
        | KernelFn::SqlExists
        | KernelFn::SqlMaskedColumn
        | KernelFn::DbFindWhere
        | KernelFn::DbFindWhereMasked
        | KernelFn::DbFindJoin
        | KernelFn::DbFindProjection
        | KernelFn::DbFindJoinOrdered
        | KernelFn::DbFindProjectionOrdered
        | KernelFn::DbDeleteWhere
        | KernelFn::DbUpdateWhere
        | KernelFn::DbUpsertFields
        | KernelFn::DbInsertFieldsChecked
        | KernelFn::DbUpdateWhereChecked
        | KernelFn::SecretFromString
        | KernelFn::SecretReveal
        | KernelFn::SecretUse
        | KernelFn::SecretRedacted
        | KernelFn::RegexCompile
        | KernelFn::RegexMatch
        | KernelFn::RegexFind
        | KernelFn::RegexFindAll
        | KernelFn::RegexReplace
        | KernelFn::RegexSplit
        | KernelFn::PathFromString
        | KernelFn::PathToString
        | KernelFn::PathBase
        | KernelFn::PathDir
        | KernelFn::PathExt
        | KernelFn::PathUnder
        | KernelFn::PathAbsolute
        | KernelFn::PathIsAbsolute
        | KernelFn::TraceSpan
        | KernelFn::TraceEvent
        | KernelFn::TraceAttr
        | KernelFn::CompressionGzip
        | KernelFn::CompressionGunzip
        | KernelFn::CompressionZstdCompress
        | KernelFn::CompressionZstdDecompress
        | KernelFn::CsvParse
        | KernelFn::CsvParseWithDelimiter
        | KernelFn::CsvEncode
        | KernelFn::CsvEncodeWithDelimiter
        | KernelFn::CsvParseStreamFromFile
        | KernelFn::CacheNewRaw
        | KernelFn::CacheGet
        | KernelFn::CachePut
        | KernelFn::CacheRemove
        | KernelFn::CacheClear
        | KernelFn::CacheSize
        | KernelFn::CacheStats
        | KernelFn::CacheDestroyRaw
        | KernelFn::ConfigString
        | KernelFn::ConfigInt
        | KernelFn::ConfigFloat
        | KernelFn::ConfigBool
        | KernelFn::ConfigNullable
        | KernelFn::ConfigField
        | KernelFn::ConfigAt
        | KernelFn::ConfigList
        | KernelFn::ConfigSucceed
        | KernelFn::ConfigFail
        | KernelFn::ConfigMap
        | KernelFn::ConfigAndThen
        | KernelFn::ConfigMap2
        | KernelFn::ConfigMap3
        | KernelFn::ConfigMap4
        | KernelFn::ConfigMap5
        | KernelFn::ConfigMap6
        | KernelFn::ConfigMap7
        | KernelFn::ConfigMap8
        | KernelFn::ConfigOneOf
        | KernelFn::ConfigIndex
        | KernelFn::ConfigKeyValuePairs
        | KernelFn::ConfigMaybe
        | KernelFn::ConfigDict
        | KernelFn::ConfigDecodeToml
        | KernelFn::ConfigDecodeYaml
        | KernelFn::ConfigDecodeJson
        | KernelFn::ConfigLoadFromFile
        | KernelFn::EmailSend
        | KernelFn::CryptoKeyFromString
        | KernelFn::CryptoKeyFromBytes
        | KernelFn::CryptoMacToHex
        | KernelFn::CryptoHmacSha256WithKey
        | KernelFn::CryptoHmacSha512WithKey
        | KernelFn::EmailAddressParse
        | KernelFn::EmailAddressToString
        | KernelFn::UrlFromString
        | KernelFn::UrlToString
        | KernelFn::UrlScheme
        | KernelFn::UrlHost
        | KernelFn::UrlPort
        | KernelFn::UrlPath
        | KernelFn::UrlQuery
        | KernelFn::UrlFragment
        | KernelFn::UrlSchemeShown
        | KernelFn::UrlBuildQuery
        | KernelFn::UrlRelativeParse
        | KernelFn::UrlRelativePath
        | KernelFn::UrlRelativeQuery
        | KernelFn::UrlRelativeFragment
        | KernelFn::UrlRelativeToString
        | KernelFn::LocaleFromTag
        | KernelFn::LocaleToTag
        | KernelFn::StringToUpperIn
        | KernelFn::StringToLowerIn
        // `Ipe.Color` constructors build an opaque `Color` value consumed by a
        // downstream attribute kernel; their literal channels are hoisted via the
        // inner-call rule at that consuming position, so no direct appearance arg
        // is marked here (conservative: a false appearance would be a correctness bug).
        | KernelFn::ColorRgb
        | KernelFn::ColorRgba
        | KernelFn::ColorHsl
        | KernelFn::ColorHsla
        | KernelFn::ColorWhite
        | KernelFn::ColorBlack
        | KernelFn::ColorRed
        | KernelFn::ColorGreen
        | KernelFn::ColorBlue
        | KernelFn::ColorTransparent
        | KernelFn::ColorToCss
        | KernelFn::ColorToCssRgba
        | KernelFn::ColorToHex
        | KernelFn::ColorLuminance
        | KernelFn::ColorWithAlpha
        | KernelFn::ColorMix
        | KernelFn::ColorBlend
        | KernelFn::ColorLighten
        | KernelFn::ColorDarken
        | KernelFn::ColorSaturate
        | KernelFn::ColorDesaturate
        | KernelFn::ColorRotateHue
        | KernelFn::ColorComplementary
        | KernelFn::ColorGrayscale
        // The `Ipe.Color` a11y/profile/parse kernels produce/consume opaque
        // colour values and scalars, with no appearance-hoist literal position.
        | KernelFn::ColorFromHex
        | KernelFn::ColorFromName
        | KernelFn::ColorTrueColorProfile
        | KernelFn::ColorAnsi256Profile
        | KernelFn::ColorAnsi16Profile
        | KernelFn::ColorNoColorProfile
        | KernelFn::ColorToAnsi
        | KernelFn::ColorWcagAa
        | KernelFn::ColorWcagAaa
        | KernelFn::ColorNormalText
        | KernelFn::ColorLargeText
        | KernelFn::ColorContrastRatio
        | KernelFn::ColorReadableTextOn
        | KernelFn::ColorMeetsWcag
        | KernelFn::ColorMaximumContrast
        | KernelFn::ColorProtanopia
        | KernelFn::ColorDeuteranopia
        | KernelFn::ColorTritanopia
        | KernelFn::ColorSimulate
        // The worker app-entry carries no appearance-hoist literal position.
        | KernelFn::TeaWorker => &[],
    }
}

/// Whether a kernel's appearance literal is a **terminal** appearance value — a
/// `Ipe.Ui.Tui.*` / `Ipe.Color.Ansi.*` literal a genuine `Tui.tea` / `Cli.tea`
/// view paints — as opposed to a web-DOM / CSS appearance value (`Ui.text`,
/// `Font.family`, `Ui.style`, every `Ipe.Html` / `Ipe.Css` value) that only a
/// web view emits.
///
/// This is the shape half of the hoist boundary: a web shape hoists every
/// appearance literal in [`appearance_literal_args`]; a terminal shape hoists
/// **only** the terminal-appearance kernels below, so a `Ui.*` web-content or
/// CSS literal reaching a tui shape emits directly and never routes through the
/// per-view table. The set is closed by construction — the terminal palette /
/// layout kernels are `Ipe.Ui.Tui` spacing/padding (cells) and the truecolour
/// `TermColor.rgb/rgba` channels; no web-DOM kernel appears, and a web view never
/// resolves these tui-only kernels — so the two shapes partition cleanly.
pub const fn is_tui_appearance_kernel(k: KernelFn) -> bool {
    matches!(
        k,
        KernelFn::TuiUiSpacing
            | KernelFn::TuiUiPadding
            | KernelFn::TermColorRgb
            | KernelFn::TermColorRgba
    )
}

/// The appearance-hoist-eligible positions for a kernel **in the current emit
/// shape** — the shape-aware wrapper over [`appearance_literal_args`].
///
/// * **Web shape** (`uses_web`) — every appearance literal hoists: the full
///   [`appearance_literal_args`] set, unchanged.
/// * **Terminal shape** (`uses_tui`, not web) — only a terminal-appearance kernel
///   ([`is_tui_appearance_kernel`]) hoists; a web-DOM / CSS literal that happens
///   to reach a tui shape returns `&[]` and emits its literal inline. A tui
///   appearance edit therefore hot-swaps its `Tui`/`TermColor` value while a
///   `Ui.text` content literal stays direct (dev == prod at the tui boundary).
/// * **Neither** — `&[]`: no dev-loop repaint surface, so nothing hoists.
///
/// The hoist itself is still additionally gated on `EmitCtx::hot_appearance`
/// (armed only under `ipe dev watch`) and on `hoist_style_literal`'s top-level /
/// direct-literal fences; this function only narrows *which kernels* are
/// hoist-eligible per shape.
pub const fn shape_appearance_literal_args(
    k: KernelFn,
    uses_web: bool,
    uses_tui: bool,
) -> &'static [(usize, LitKind)] {
    // A web shape hoists every appearance literal; a terminal shape hoists only a
    // terminal-appearance kernel; neither shape → nothing hoists.
    let hoist_eligible = uses_web || (uses_tui && is_tui_appearance_kernel(k));
    if hoist_eligible {
        appearance_literal_args(k)
    } else {
        &[]
    }
}

/// The appearance-hoist-eligible **record-config fields** of a record-native UI
/// kernel — the same declarative registry as [`appearance_literal_args`], but
/// keyed by config-record *field name* rather than positional argument index.
///
/// A record-native kernel (`ArgPlan::Native`, e.g. `Ui.image`) builds its call
/// from an inline `{ … }` config through [`crate::emit_expr::emit_cfg_record_call`],
/// not the positional-hoist path, so `appearance_literal_args` never fires for it.
/// This companion table names, per kernel, which config fields carry an inert
/// **appearance value** the compiled view consumes without branching on it — so a
/// *direct literal* in that field can be hoisted into the per-view
/// [`ipe_runtime::literal_table::LiteralTable`] and swapped as data, exactly as a positional
/// appearance literal is.
///
/// **Safe by construction, identically to the positional registry.** An arm fires
/// only on a direct literal of the named kind in the named field; a
/// `Model`-dependent or computed field emits directly and never hoists. The baked
/// default is exactly the source value, so a prod build (never patched) renders
/// exactly as the direct emit — one render semantics, dev == prod — pinned by the
/// same conformance test. The rule for adding a field is the positional rule: mark
/// **only** a field carrying an appearance *value*, never a structural one; when
/// unsure, leave it out (the recompile fallback is merely slower).
///
/// `Ui.image { src, description }` is the sole current entry. At this emit
/// boundary both fields are plain `String` attribute values (`ui_image_` renders
/// `<img src=… alt=…>`, escaping each identically at render), so both hoist as
/// `Str`. `description` (the alt text) is unambiguously appearance. `src` is a
/// plain-`String` attribute value here too — the emit contract carries no URL /
/// data-URI validation on this path (the runtime helper only sets the `src`
/// attribute) — so a hoisted literal `src` is exactly as validated as the compiled
/// one (both unvalidated at this boundary); and were a typed validating `src`
/// boundary to make the field a non-literal expression, the direct-literal guard
/// would simply stop matching and the field would recompile, never hot-swap an
/// unvalidated value.
///
/// A kernel absent here has no hoist-eligible config field; a positive `_ => &[]`
/// default is correct because the exhaustive forcing lives in the positional
/// [`appearance_literal_args`] / [`ui_call_shape`] classifiers — this table is a
/// focused companion for the record-native cfg kernels, not a second exhaustive
/// partition.
pub const fn appearance_literal_record_fields(k: KernelFn) -> &'static [(&'static str, LitKind)] {
    use LitKind::Str;
    match k {
        // `Ui.image : List (Attribute msg) -> { src : String, description : String }`
        // — both fields are inert `<img>` attribute values (`src=`, `alt=`), each
        // escaped identically at render, so both hoist as `Str`.
        KernelFn::UiImage => &[("src", Str), ("description", Str)],
        _ => &[],
    }
}

/// Classify one kernel into its emit plan.
///
/// Returns `None` for a non-UI-family kernel, preserving the caller's
/// early-return contract; `Some(plan)` for every kernel where
/// `is_ui() || is_web() || is_tui() || is_console()` holds. The
/// two properties — every UI-family kernel classified, no other kernel
/// classified — are the exhaustiveness partition the tests below assert.
#[allow(clippy::too_many_lines)] // one declarative row per UI kernel — the table is the point
pub const fn ui_call_shape(k: KernelFn) -> Option<UiEmitPlan> {
    use NativeUiEmit as N;
    let plan = match k {
        // ── Render entry + HTML serialiser ────────────────────────────────
        KernelFn::UiLayout => pos("ipe_runtime::ui::render::ui_layout", 2),
        KernelFn::UiLayoutWith => native(N::LayoutWith),
        KernelFn::HtmlRender | KernelFn::HtmlToString => native(N::HtmlSerialise),
        KernelFn::HtmlEscapeText => pos("ipe_runtime::html::html_escape_text_", 1),
        KernelFn::HtmlEscapeAttr => pos("ipe_runtime::html::html_escape_attr_", 1),
        KernelFn::HtmlAttrToString => pos("ipe_runtime::html::html_attr_to_string_", 1),

        // ── Ipe.Ui element builders ───────────────────────────────────────
        KernelFn::UiNone => pos("ipe_runtime::ui::helpers::ui_none_", 0),
        KernelFn::UiText => pos("ipe_runtime::ui::helpers::ui_text_", 1),
        KernelFn::UiHtml => pos("ipe_runtime::ui::helpers::ui_html_", 1),
        KernelFn::UiCells => guarded(
            "ipe_runtime::ui::helpers::ui_cells_",
            1,
            Guard::RejectInWebShape,
        ),
        // ── Ipe.Ui.Cells Cells-typed builders. No shape guard: the type system
        // rejects `Cells msg` where `Element msg` is expected (IPE-T0001).
        KernelFn::UiCellsNone => pos("ipe_runtime::tui::cells_none_", 0),
        KernelFn::UiCellsText => pos("ipe_runtime::tui::cells_text_", 1),
        KernelFn::UiCellsEl => pos("ipe_runtime::tui::cells_el_", 2),
        KernelFn::UiCellsRow => pos("ipe_runtime::tui::cells_row_", 2),
        KernelFn::UiCellsColumn => pos("ipe_runtime::tui::cells_column_", 2),
        KernelFn::UiCellsCells => pos("ipe_runtime::tui::cells_cells_", 1),
        // ── Ipe.Ui.Tui cell-native attribute builders. No shape guard: the
        // type system rejects a `TuiAttr msg` where a DOM `Attribute msg` is
        // expected (and vice-versa) via distinct type constructors (IPE-T0001).
        KernelFn::TuiUiSpacing => pos("ipe_runtime::tui::tui_spacing_", 1),
        KernelFn::TuiUiPadding => pos("ipe_runtime::tui::tui_padding_", 1),
        KernelFn::TuiUiAlignLeft => pos("ipe_runtime::tui::tui_align_left_", 0),
        KernelFn::TuiUiAlignRight => pos("ipe_runtime::tui::tui_align_right_", 0),
        KernelFn::TuiUiCenter => pos("ipe_runtime::tui::tui_center_", 0),
        KernelFn::TuiUiBold => pos("ipe_runtime::tui::tui_bold_", 0),
        KernelFn::TuiUiUnderline => pos("ipe_runtime::tui::tui_underline_", 0),
        KernelFn::TuiUiDim => pos("ipe_runtime::tui::tui_dim_", 0),
        KernelFn::TuiUiReverse => pos("ipe_runtime::tui::tui_reverse_", 0),
        KernelFn::TuiUiColor => pos("ipe_runtime::tui::tui_color_", 1),
        KernelFn::TuiUiBg => pos("ipe_runtime::tui::tui_bg_", 1),
        // ── Ipe.Ui.Cli line-oriented view + attribute builders ──
        KernelFn::CliUiNone => pos("ipe_runtime::tui::cli_none_", 0),
        KernelFn::CliUiText => pos("ipe_runtime::tui::cli_text_", 1),
        KernelFn::CliUiLine => pos("ipe_runtime::tui::cli_line_", 2),
        KernelFn::CliUiLines => pos("ipe_runtime::tui::cli_lines_", 1),
        KernelFn::CliUiBold => pos("ipe_runtime::tui::cli_bold_", 0),
        KernelFn::CliUiUnderline => pos("ipe_runtime::tui::cli_underline_", 0),
        KernelFn::CliUiDim => pos("ipe_runtime::tui::cli_dim_", 0),
        KernelFn::CliUiReverse => pos("ipe_runtime::tui::cli_reverse_", 0),
        KernelFn::CliUiColor => pos("ipe_runtime::tui::cli_color_", 1),
        KernelFn::CliUiBg => pos("ipe_runtime::tui::cli_bg_", 1),
        // ── Ipe.Color.Ansi palette constructors ──
        KernelFn::TermColorBlack => pos("ipe_runtime::tui::term_color_black_", 0),
        KernelFn::TermColorRed => pos("ipe_runtime::tui::term_color_red_", 0),
        KernelFn::TermColorGreen => pos("ipe_runtime::tui::term_color_green_", 0),
        KernelFn::TermColorYellow => pos("ipe_runtime::tui::term_color_yellow_", 0),
        KernelFn::TermColorBlue => pos("ipe_runtime::tui::term_color_blue_", 0),
        KernelFn::TermColorMagenta => pos("ipe_runtime::tui::term_color_magenta_", 0),
        KernelFn::TermColorCyan => pos("ipe_runtime::tui::term_color_cyan_", 0),
        KernelFn::TermColorWhite => pos("ipe_runtime::tui::term_color_white_", 0),
        KernelFn::TermColorBrightBlack => pos("ipe_runtime::tui::term_color_bright_black_", 0),
        KernelFn::TermColorBrightRed => pos("ipe_runtime::tui::term_color_bright_red_", 0),
        KernelFn::TermColorBrightGreen => pos("ipe_runtime::tui::term_color_bright_green_", 0),
        KernelFn::TermColorBrightYellow => pos("ipe_runtime::tui::term_color_bright_yellow_", 0),
        KernelFn::TermColorBrightBlue => pos("ipe_runtime::tui::term_color_bright_blue_", 0),
        KernelFn::TermColorBrightMagenta => pos("ipe_runtime::tui::term_color_bright_magenta_", 0),
        KernelFn::TermColorBrightCyan => pos("ipe_runtime::tui::term_color_bright_cyan_", 0),
        KernelFn::TermColorBrightWhite => pos("ipe_runtime::tui::term_color_bright_white_", 0),
        KernelFn::TermColorDefault => pos("ipe_runtime::tui::term_color_default_", 0),
        KernelFn::TermColorRgb => pos("ipe_runtime::tui::term_color_rgb_", 3),
        KernelFn::TermColorRgba => pos("ipe_runtime::tui::term_color_rgba_", 4),
        // `CustomElement.node ce state on_up` — the server-driven custom-element node.
        // A bespoke arm, not a plain positional call: `ui_widget_`'s handler
        // parameter carries `F: Fn(Up) -> M + Send + Sync + 'static`, which the
        // codegen's default `Box<dyn Fn + Send>` fn-value rendering does NOT
        // satisfy (a trait object is `Sync` only if its bound list says so). The
        // emitter re-wraps the handler in a fresh closure at the call site — the
        // same technique the `OnSubmit` / `String` / `Bool` event arms use.
        //
        // Guarded: the up-event handler rides the seal codec, present only in a
        // browser shape (`web`/`webview` force the `json` feature). In a
        // `Terminal` / `Program` build the widget has no transport, so it is a
        // fail-closed shape refusal rather than a dead node.
        KernelFn::UiWidget => guarded_native(N::Widget, Guard::RejectInNonWebShape),
        KernelFn::UiNode => pos("ipe_runtime::ui::helpers::ui_node_", 3),
        KernelFn::UiTaggedNode => pos("ipe_runtime::ui::helpers::ui_tagged_node_", 4),
        KernelFn::UiAbove => pos("ipe_runtime::ui::helpers::ui_above_", 1),
        KernelFn::UiBelow => pos("ipe_runtime::ui::helpers::ui_below_", 1),
        KernelFn::UiOnLeft => pos("ipe_runtime::ui::helpers::ui_on_left_", 1),
        KernelFn::UiOnRight => pos("ipe_runtime::ui::helpers::ui_on_right_", 1),
        KernelFn::UiInFront => pos("ipe_runtime::ui::helpers::ui_in_front_", 1),
        KernelFn::UiBehind => pos("ipe_runtime::ui::helpers::ui_behind_", 1),
        KernelFn::UiButton => native(N::Button),
        KernelFn::UiLink => native(N::Link),
        KernelFn::UiImage => native(N::Image),

        // ── Ipe.Ui attribute builders ─────────────────────────────────────
        KernelFn::UiSpacing => pos("ipe_runtime::ui::helpers::ui_spacing_", 1),
        KernelFn::UiPadding => pos("ipe_runtime::ui::helpers::ui_padding_", 1),
        KernelFn::UiPaddingXY => pos("ipe_runtime::ui::helpers::ui_padding_xy_", 2),
        KernelFn::UiPaddingEach => native(N::PaddingEach),
        KernelFn::UiWidth => pos("ipe_runtime::ui::helpers::ui_width_", 1),
        KernelFn::UiHeight => pos("ipe_runtime::ui::helpers::ui_height_", 1),
        KernelFn::UiCenterX => pos("ipe_runtime::ui::helpers::ui_center_x_", 0),
        KernelFn::UiCenterY => pos("ipe_runtime::ui::helpers::ui_center_y_", 0),
        KernelFn::UiAlignLeft => pos("ipe_runtime::ui::helpers::ui_align_left_", 0),
        KernelFn::UiAlignRight => pos("ipe_runtime::ui::helpers::ui_align_right_", 0),
        KernelFn::UiAlignTop => pos("ipe_runtime::ui::helpers::ui_align_top_", 0),
        KernelFn::UiAlignBottom => pos("ipe_runtime::ui::helpers::ui_align_bottom_", 0),
        KernelFn::UiPointer => pos("ipe_runtime::ui::helpers::ui_pointer_", 0),
        KernelFn::UiClip => pos("ipe_runtime::ui::helpers::ui_clip_", 0),
        KernelFn::UiClipX => pos("ipe_runtime::ui::helpers::ui_clip_x_", 0),
        KernelFn::UiClipY => pos("ipe_runtime::ui::helpers::ui_clip_y_", 0),
        KernelFn::UiScrollbars => pos("ipe_runtime::ui::helpers::ui_scrollbars_", 0),
        KernelFn::UiScrollbarX => pos("ipe_runtime::ui::helpers::ui_scrollbar_x_", 0),
        KernelFn::UiScrollbarY => pos("ipe_runtime::ui::helpers::ui_scrollbar_y_", 0),
        KernelFn::UiGridColumns => pos("ipe_runtime::ui::helpers::ui_grid_columns_", 1),

        // ── Length builders ───────────────────────────────────────────────
        KernelFn::UiPx => pos("ipe_runtime::ui::helpers::ui_px_", 1),
        KernelFn::UiFill => pos("ipe_runtime::ui::helpers::ui_fill_", 0),
        KernelFn::UiContent => pos("ipe_runtime::ui::helpers::ui_content_", 0),
        KernelFn::UiShrink => pos("ipe_runtime::ui::helpers::ui_shrink_", 0),
        KernelFn::UiFillPortion => pos("ipe_runtime::ui::helpers::ui_fill_portion_", 1),
        KernelFn::UiVh => pos("ipe_runtime::ui::helpers::ui_vh_", 1),
        KernelFn::UiVw => pos("ipe_runtime::ui::helpers::ui_vw_", 1),
        KernelFn::UiMinimum => pos("ipe_runtime::ui::helpers::ui_minimum_", 2),
        KernelFn::UiMaximum => pos("ipe_runtime::ui::helpers::ui_maximum_", 2),

        // ── Color builders ────────────────────────────────────────────────
        KernelFn::UiRgb => pos("ipe_runtime::ui::helpers::ui_rgb_", 3),
        KernelFn::UiRgba => pos("ipe_runtime::ui::helpers::ui_rgba_", 4),
        KernelFn::UiWhite => pos("ipe_runtime::ui::helpers::ui_white_", 0),
        KernelFn::UiBlack => pos("ipe_runtime::ui::helpers::ui_black_", 0),
        KernelFn::UiTransparent => pos("ipe_runtime::ui::helpers::ui_transparent_", 0),
        KernelFn::UiColorCss => pos("ipe_runtime::ui::helpers::ui_color_css_", 1),

        // ── Background sub-module ─────────────────────────────────────────
        KernelFn::BackgroundColor => pos("ipe_runtime::ui::helpers::ui_background_color_", 1),
        KernelFn::BackgroundImage => pos("ipe_runtime::ui::helpers::ui_background_image_", 1),
        KernelFn::BackgroundLinearGradient => pos(
            "ipe_runtime::ui::helpers::ui_background_linear_gradient_",
            2,
        ),

        // ── Border sub-module ─────────────────────────────────────────────
        KernelFn::BorderWidth => pos("ipe_runtime::ui::helpers::ui_border_width_", 1),
        KernelFn::BorderRounded => pos("ipe_runtime::ui::helpers::ui_border_rounded_", 1),
        KernelFn::BorderColor => pos("ipe_runtime::ui::helpers::ui_border_color_", 1),
        KernelFn::BorderWidthEach => native(N::BorderWidthEach),
        KernelFn::BorderShadow => native(N::BorderShadow),
        KernelFn::BorderGlow => pos("ipe_runtime::ui::helpers::ui_border_glow_", 2),
        KernelFn::BorderInnerShadow => native(N::BorderInnerShadow),

        // ── Font sub-module ───────────────────────────────────────────────
        KernelFn::FontSize => pos("ipe_runtime::ui::helpers::ui_font_size_", 1),
        KernelFn::FontColor => pos("ipe_runtime::ui::helpers::ui_font_color_", 1),
        KernelFn::FontFamily => pos("ipe_runtime::ui::helpers::ui_font_family_", 1),
        KernelFn::FontBold => pos("ipe_runtime::ui::helpers::ui_font_bold_", 0),
        KernelFn::FontItalic => pos("ipe_runtime::ui::helpers::ui_font_italic_", 0),

        // ── Aspect-ratio + misc Ui attrs ──────────────────────────────────
        KernelFn::UiSquare => pos("ipe_runtime::ui::helpers::ui_square_", 0),
        KernelFn::UiWidescreen => pos("ipe_runtime::ui::helpers::ui_widescreen_", 0),
        KernelFn::UiCinemascope => pos("ipe_runtime::ui::helpers::ui_cinemascope_", 0),
        KernelFn::UiName => pos("ipe_runtime::ui::helpers::ui_name_", 1),
        KernelFn::UiStyle => pos("ipe_runtime::ui::helpers::ui_style_", 2),
        KernelFn::UiTransitionRaw => pos("ipe_runtime::ui::helpers::ui_transition_raw_", 2),
        KernelFn::UiGridTracksRaw => pos("ipe_runtime::ui::helpers::ui_grid_tracks_raw_", 2),
        KernelFn::UiAnimateRaw => pos("ipe_runtime::ui::helpers::ui_animate_raw_", 4),
        KernelFn::UiAspectRatio => pos("ipe_runtime::ui::helpers::ui_aspect_ratio_", 1),
        KernelFn::UiAspectRatioWH => pos("ipe_runtime::ui::helpers::ui_aspect_ratio_wh_", 2),
        KernelFn::UiHtmlAttribute => pos("ipe_runtime::ui::helpers::ui_html_attribute_", 2),

        // ── Breakpoint + pseudo-class constants ───────────────────────────
        KernelFn::UiMobile => pos("ipe_runtime::ui::helpers::ui_mobile_", 0),
        KernelFn::UiTablet => pos("ipe_runtime::ui::helpers::ui_tablet_", 0),
        KernelFn::UiDesktop => pos("ipe_runtime::ui::helpers::ui_desktop_", 0),
        KernelFn::UiDarkMode => pos("ipe_runtime::ui::helpers::ui_dark_mode_", 0),
        KernelFn::UiLightMode => pos("ipe_runtime::ui::helpers::ui_light_mode_", 0),
        KernelFn::UiReducedMotion => pos("ipe_runtime::ui::helpers::ui_reduced_motion_", 0),
        KernelFn::UiHover => pos("ipe_runtime::ui::helpers::ui_hover_", 0),
        KernelFn::UiFocus => pos("ipe_runtime::ui::helpers::ui_focus_", 0),
        KernelFn::UiFocusVisible => pos("ipe_runtime::ui::helpers::ui_focus_visible_", 0),
        KernelFn::UiActive => pos("ipe_runtime::ui::helpers::ui_active_", 0),
        KernelFn::UiDisabled => pos("ipe_runtime::ui::helpers::ui_disabled_", 0),
        KernelFn::UiOnPseudo => pos("ipe_runtime::ui::helpers::ui_on_pseudo_", 2),
        KernelFn::UiBreakpoint => pos("ipe_runtime::ui::helpers::ui_breakpoint_", 3),
        KernelFn::UiMediaQuery => pos("ipe_runtime::ui::helpers::ui_media_query_", 3),

        // ── Background / Border / Font pseudo-class attrs ─────────────────
        KernelFn::BackgroundHoverColor => pos("ipe_runtime::ui::helpers::ui_bg_hover_color_", 1),
        KernelFn::BackgroundFocusColor => pos("ipe_runtime::ui::helpers::ui_bg_focus_color_", 1),
        KernelFn::BackgroundActiveColor => pos("ipe_runtime::ui::helpers::ui_bg_active_color_", 1),
        KernelFn::BackgroundDisabledColor => {
            pos("ipe_runtime::ui::helpers::ui_bg_disabled_color_", 1)
        }
        KernelFn::BorderSolid => pos("ipe_runtime::ui::helpers::ui_border_solid_", 0),
        KernelFn::BorderDashed => pos("ipe_runtime::ui::helpers::ui_border_dashed_", 0),
        KernelFn::BorderDotted => pos("ipe_runtime::ui::helpers::ui_border_dotted_", 0),
        KernelFn::BorderHoverColor => pos("ipe_runtime::ui::helpers::ui_border_hover_color_", 1),
        KernelFn::BorderFocusColor => pos("ipe_runtime::ui::helpers::ui_border_focus_color_", 1),
        KernelFn::BorderActiveColor => pos("ipe_runtime::ui::helpers::ui_border_active_color_", 1),
        KernelFn::BorderHoverWidth => pos("ipe_runtime::ui::helpers::ui_border_hover_width_", 1),
        KernelFn::BorderHoverRounded => {
            pos("ipe_runtime::ui::helpers::ui_border_hover_rounded_", 1)
        }
        KernelFn::FontWeight => pos("ipe_runtime::ui::helpers::ui_font_weight_", 1),
        KernelFn::FontSemiBold => pos("ipe_runtime::ui::helpers::ui_font_semi_bold_", 0),
        KernelFn::FontRegular => pos("ipe_runtime::ui::helpers::ui_font_regular_", 0),
        KernelFn::FontLight => pos("ipe_runtime::ui::helpers::ui_font_light_", 0),
        KernelFn::FontExtraBold => pos("ipe_runtime::ui::helpers::ui_font_extra_bold_", 0),
        KernelFn::FontBlack => pos("ipe_runtime::ui::helpers::ui_font_black_", 0),
        KernelFn::FontUnderline => pos("ipe_runtime::ui::helpers::ui_font_underline_", 0),
        KernelFn::FontNoDecoration => pos("ipe_runtime::ui::helpers::ui_font_no_decoration_", 0),
        KernelFn::FontLineThrough => pos("ipe_runtime::ui::helpers::ui_font_line_through_", 0),
        KernelFn::FontLetterSpacing => pos("ipe_runtime::ui::helpers::ui_font_letter_spacing_", 1),
        KernelFn::FontWordSpacing => pos("ipe_runtime::ui::helpers::ui_font_word_spacing_", 1),
        KernelFn::FontAlignLeft => pos("ipe_runtime::ui::helpers::ui_font_align_left_", 0),
        KernelFn::FontAlignRight => pos("ipe_runtime::ui::helpers::ui_font_align_right_", 0),
        KernelFn::FontAlignCenter => pos("ipe_runtime::ui::helpers::ui_font_align_center_", 0),
        KernelFn::FontCenter => pos("ipe_runtime::ui::helpers::ui_font_center_", 0),
        KernelFn::FontJustify => pos("ipe_runtime::ui::helpers::ui_font_justify_", 0),
        KernelFn::FontSansSerif => pos("ipe_runtime::ui::helpers::ui_font_sans_serif_", 0),
        KernelFn::FontSerif => pos("ipe_runtime::ui::helpers::ui_font_serif_", 0),
        KernelFn::FontMonospace => pos("ipe_runtime::ui::helpers::ui_font_monospace_", 0),
        KernelFn::FontHoverColor => pos("ipe_runtime::ui::helpers::ui_font_hover_color_", 1),
        KernelFn::FontFocusColor => pos("ipe_runtime::ui::helpers::ui_font_focus_color_", 1),
        KernelFn::FontActiveColor => pos("ipe_runtime::ui::helpers::ui_font_active_color_", 1),
        KernelFn::FontDisabledColor => pos("ipe_runtime::ui::helpers::ui_font_disabled_color_", 1),
        KernelFn::FontHoverSize => pos("ipe_runtime::ui::helpers::ui_font_hover_size_", 1),

        // ── Region / describe accessibility constructors ──────────────────
        KernelFn::RegionMainContent => pos("ipe_runtime::ui::helpers::ui_region_main_content_", 0),
        KernelFn::RegionNavigation => pos("ipe_runtime::ui::helpers::ui_region_navigation_", 0),
        KernelFn::RegionFooter => pos("ipe_runtime::ui::helpers::ui_region_footer_", 0),
        KernelFn::RegionAside => pos("ipe_runtime::ui::helpers::ui_region_aside_", 0),
        KernelFn::RegionHeading => pos("ipe_runtime::ui::helpers::ui_region_heading_", 1),
        KernelFn::RegionLabel => pos("ipe_runtime::ui::helpers::ui_region_label_", 1),
        KernelFn::RegionAnnounce => pos("ipe_runtime::ui::helpers::ui_region_announce_", 0),
        KernelFn::RegionAnnounceUrgently => {
            pos("ipe_runtime::ui::helpers::ui_region_announce_urgently_", 0)
        }
        KernelFn::UiDescribe => pos("ipe_runtime::ui::helpers::ui_describe_", 1),
        KernelFn::UiDescNone => pos("ipe_runtime::ui::helpers::ui_desc_none_", 0),
        KernelFn::UiDescParagraph => pos("ipe_runtime::ui::helpers::ui_desc_paragraph_", 0),
        KernelFn::UiDescMain => pos("ipe_runtime::ui::helpers::ui_desc_main_", 0),
        KernelFn::UiDescNavigation => pos("ipe_runtime::ui::helpers::ui_desc_navigation_", 0),
        KernelFn::UiDescContentInfo => pos("ipe_runtime::ui::helpers::ui_desc_content_info_", 0),
        KernelFn::UiDescComplementary => pos("ipe_runtime::ui::helpers::ui_desc_complementary_", 0),
        KernelFn::UiDescLivePolite => pos("ipe_runtime::ui::helpers::ui_desc_live_polite_", 0),
        KernelFn::UiDescLiveAssertive => {
            pos("ipe_runtime::ui::helpers::ui_desc_live_assertive_", 0)
        }
        KernelFn::UiDescHeading => pos("ipe_runtime::ui::helpers::ui_desc_heading_", 1),
        KernelFn::UiDescLabel => pos("ipe_runtime::ui::helpers::ui_desc_label_", 1),

        // ── Input label constructors + input builders ─────────────────────
        KernelFn::InputLabelAbove => pos("ipe_runtime::ui::input::input_label_above_", 2),
        KernelFn::InputLabelBelow => pos("ipe_runtime::ui::input::input_label_below_", 2),
        KernelFn::InputLabelLeft => pos("ipe_runtime::ui::input::input_label_left_", 2),
        KernelFn::InputLabelRight => pos("ipe_runtime::ui::input::input_label_right_", 2),
        KernelFn::InputLabelHidden => pos("ipe_runtime::ui::input::input_label_hidden_", 1),
        KernelFn::InputPlaceholder => pos("ipe_runtime::ui::input::input_placeholder_", 2),
        KernelFn::InputText
        | KernelFn::InputEmail
        | KernelFn::InputUsername
        | KernelFn::InputSearch
        | KernelFn::InputCurrentPassword
        | KernelFn::InputNewPassword => native(N::InputText),
        KernelFn::InputMultiline => native(N::InputMultiline),
        KernelFn::InputCheckbox => native(N::InputCheckbox),
        KernelFn::InputSlider => native(N::InputSlider),
        KernelFn::InputOption => pos("ipe_runtime::ui::input::input_option_", 2),
        KernelFn::InputRadio => native(N::InputRadio),
        KernelFn::InputRadioRow => native(N::InputRadioRow),

        // ── Ipe.Html element builders ─────────────────────────────────────
        KernelFn::HtmlTextNode => pos("ipe_runtime::ui::helpers::html_text_node_", 1),
        KernelFn::HtmlRawNode => pos("ipe_runtime::ui::helpers::html_raw_node_", 1),
        KernelFn::HtmlNode => pos("ipe_runtime::ui::helpers::html_node_", 3),
        KernelFn::HtmlVoidNode => native(N::HtmlVoidNode),
        KernelFn::HtmlDoctype => pos("ipe_runtime::ui::helpers::html_doctype_", 1),
        KernelFn::HtmlTitleNode => pos("ipe_runtime::ui::helpers::html_title_node_", 1),
        KernelFn::HtmlStyleNode => pos("ipe_runtime::ui::helpers::html_style_node_", 2),
        KernelFn::HtmlScriptNode => pos("ipe_runtime::ui::helpers::html_script_node_", 1),

        // ── Plain-message event attrs ─────────────────────────────────────
        KernelFn::UiOnClick => pos("ipe_runtime::ui::helpers::ui_on_click_", 1),
        KernelFn::UiOnFocus => pos("ipe_runtime::ui::helpers::ui_on_focus_", 1),
        KernelFn::UiOnBlur => pos("ipe_runtime::ui::helpers::ui_on_blur_", 1),
        KernelFn::UiOnMouseOver => pos("ipe_runtime::ui::helpers::ui_on_mouse_over_", 1),
        KernelFn::UiOnMouseOut => pos("ipe_runtime::ui::helpers::ui_on_mouse_out_", 1),

        // ── Callback-carrying event attrs ─────────────────────────────────
        KernelFn::UiOnInput => native(N::OnInput),
        KernelFn::UiOnChange => native(N::OnChange),
        KernelFn::UiOnKeyDown => native(N::OnKeyDown),
        KernelFn::UiOnKeyUp => native(N::OnKeyUp),
        KernelFn::UiOnFile => native(N::OnFile),
        KernelFn::UiOnBool => native(N::OnBool),
        KernelFn::UiOnSubmit => native(N::OnSubmit),

        // ── Generic HTML attributes ───────────────────────────────────────
        KernelFn::HtmlAttribute => pos("ipe_runtime::html::html_named_attr_", 2),
        KernelFn::HtmlBoolAttribute => pos("ipe_runtime::html::html_bool_named_attr_", 2),
        KernelFn::HtmlNoAttr => pos("ipe_runtime::html::html_no_attr_", 0),

        // ── Keyed diff-identity containers ────────────────────────────────
        KernelFn::KeyedColumn => pos("ipe_runtime::ui::keyed::keyed_column_", 2),
        KernelFn::KeyedRow => pos("ipe_runtime::ui::keyed::keyed_row_", 2),

        // ── Deferred-subtree helpers ──────────────────────────────────────
        KernelFn::LazyLazy => native(N::LazyLazy),
        KernelFn::LazyLazy2 => native(N::LazyLazy2),
        KernelFn::LazyLazy3 => native(N::LazyLazy3),
        KernelFn::LazyLazy4 => native(N::LazyLazy4),
        KernelFn::LazyLazy5 => native(N::LazyLazy5),

        // ── PubSub publish (Task-shaped, web bus) ─────────────────────────
        KernelFn::PubSubPublish | KernelFn::PubSubPublishNoEcho => native(N::PubSubPublish),

        // ── Shape-router delegations ──────────────────────────────────────
        KernelFn::WebApp
        | KernelFn::WebAppRouted
        | KernelFn::WebEmbed
        | KernelFn::WebAppWith
        | KernelFn::WebRoute
        | KernelFn::WebRenderStatic => delegate(UiDelegate::Web),
        KernelFn::TerminalAppScreen => delegate(UiDelegate::Tui),
        KernelFn::TerminalAppLines => delegate(UiDelegate::Console),
        KernelFn::TeaWorker => delegate(UiDelegate::Worker),

        // ── Debug.explain — dev-only, Web/WebView only ────────────────────
        // `Debug.explain : Attribute msg` draws visible outlines on the element
        // and all descendants without changing layout.  Reject in Terminal /
        // Program shapes (fail-closed) — there is no DOM to outline.
        KernelFn::DebugExplain => guarded(
            "ipe_runtime::ui::helpers::debug_explain_",
            0,
            Guard::RejectInNonWebShape,
        ),

        // ── Predicate-keyed HTML families ─────────────────────────────────
        _ if k.html_event_shape().is_some() => native(N::HtmlEvent),

        // Not a UI-family kernel — no plan.
        _ => return None,
    };
    Some(plan)
}

#[cfg(test)]
mod tests {
    use ipe_ir::KernelFn;

    use super::{ArgPlan, Guard, NativeUiEmit, UiDelegate, ui_call_shape};

    /// Every kernel `ui_call_shape` classifies as UI-family. Mirrors the
    /// `is_ui() || …` guard that fronts the emitter.
    fn is_ui_family(k: KernelFn) -> bool {
        k.is_ui() || k.is_web() || k.is_tui() || k.is_console() || k.is_worker()
    }

    /// A widget's plan is the positional shape the emitter renders as
    /// `path(args)`.
    #[test]
    fn positional_widgets_carry_path_and_arity() {
        let cases = [
            (KernelFn::UiText, "ipe_runtime::ui::helpers::ui_text_", 1u8),
            (KernelFn::UiNode, "ipe_runtime::ui::helpers::ui_node_", 3),
            (
                KernelFn::UiTaggedNode,
                "ipe_runtime::ui::helpers::ui_tagged_node_",
                4,
            ),
            (KernelFn::UiRgb, "ipe_runtime::ui::helpers::ui_rgb_", 3),
            (KernelFn::UiRgba, "ipe_runtime::ui::helpers::ui_rgba_", 4),
            (KernelFn::UiNone, "ipe_runtime::ui::helpers::ui_none_", 0),
            (KernelFn::UiLayout, "ipe_runtime::ui::render::ui_layout", 2),
            (
                KernelFn::KeyedColumn,
                "ipe_runtime::ui::keyed::keyed_column_",
                2,
            ),
            (
                KernelFn::InputOption,
                "ipe_runtime::ui::input::input_option_",
                2,
            ),
        ];
        for (k, path, arity) in cases {
            let plan = ui_call_shape(k).expect("UI kernel must classify");
            assert_eq!(
                plan.args,
                ArgPlan::Positional { path, arity },
                "{k:?} plan shape"
            );
            assert_eq!(plan.guard, Guard::None, "{k:?} guard");
        }
    }

    /// The capability and security leaves classify to their bespoke tag rather
    /// than a positional path.
    #[test]
    fn capability_leaves_classify_native() {
        let cases = [
            (KernelFn::UiButton, NativeUiEmit::Button),
            (KernelFn::UiLayoutWith, NativeUiEmit::LayoutWith),
            (KernelFn::HtmlRender, NativeUiEmit::HtmlSerialise),
            (KernelFn::HtmlToString, NativeUiEmit::HtmlSerialise),
            (KernelFn::UiOnInput, NativeUiEmit::OnInput),
            (KernelFn::UiOnSubmit, NativeUiEmit::OnSubmit),
            (KernelFn::InputText, NativeUiEmit::InputText),
            (KernelFn::InputEmail, NativeUiEmit::InputText),
            (KernelFn::BorderShadow, NativeUiEmit::BorderShadow),
            (KernelFn::LazyLazy, NativeUiEmit::LazyLazy),
            (KernelFn::PubSubPublish, NativeUiEmit::PubSubPublish),
            (KernelFn::WebApp, NativeUiEmit::Delegate(UiDelegate::Web)),
            (
                KernelFn::TerminalAppScreen,
                NativeUiEmit::Delegate(UiDelegate::Tui),
            ),
            (
                KernelFn::TerminalAppLines,
                NativeUiEmit::Delegate(UiDelegate::Console),
            ),
            (
                KernelFn::TeaWorker,
                NativeUiEmit::Delegate(UiDelegate::Worker),
            ),
        ];
        for (k, kind) in cases {
            let plan = ui_call_shape(k).expect("UI kernel must classify");
            assert_eq!(plan.args, ArgPlan::Native(kind), "{k:?} native tag");
        }
    }

    /// The `Ui.cells` seal is the guarded plan — fail-closed in a web shape.
    #[test]
    fn ui_cells_carries_web_shape_guard() {
        let plan = ui_call_shape(KernelFn::UiCells).expect("Ui.cells must classify");
        assert_eq!(plan.guard, Guard::RejectInWebShape);
        assert_eq!(
            plan.args,
            ArgPlan::Positional {
                path: "ipe_runtime::ui::helpers::ui_cells_",
                arity: 1,
            },
        );
    }

    /// The dispatch is a total partition: every UI-family kernel yields a plan,
    /// and no other kernel does. A UI kernel added without a plan arm fails
    /// here — at the classifier — rather than downstream when the emitted Rust
    /// fails to build.
    #[test]
    fn exhaustiveness_partition() {
        for &k in KernelFn::ALL {
            let classified = ui_call_shape(k).is_some();
            assert_eq!(
                classified,
                is_ui_family(k),
                "{k:?}: classified={classified} but is_ui_family={}",
                is_ui_family(k),
            );
        }
    }

    /// The web-shape guard set is exactly `UiCells` — the one kernel that
    /// produces `Element msg` but has no browser denotation. The `UiCells*`
    /// builders produce `Cells msg`; misuse is caught at the type level
    /// (IPE-T0001) rather than by a runtime guard.
    #[test]
    fn reject_in_web_shape_guard_is_exactly_ui_cells() {
        for &k in KernelFn::ALL {
            let guarded = ui_call_shape(k).is_some_and(|p| p.guard == Guard::RejectInWebShape);
            let expected = matches!(k, KernelFn::UiCells);
            assert_eq!(guarded, expected, "{k:?}: guarded={guarded}");
        }
    }

    /// The non-web-shape guard set covers kernels that have no denotation
    /// outside a browser shape: `CustomElement.node` (no up-event transport) and
    /// `Debug.explain` (no DOM to outline).  A new browser-only kernel that
    /// omits the guard fails here rather than silently emitting dead code.
    #[test]
    fn reject_in_non_web_shape_guard_is_exactly_browser_only_kernels() {
        for &k in KernelFn::ALL {
            let guarded = ui_call_shape(k).is_some_and(|p| p.guard == Guard::RejectInNonWebShape);
            let expected = matches!(k, KernelFn::UiWidget | KernelFn::DebugExplain);
            assert_eq!(guarded, expected, "{k:?}: non-web-guarded={guarded}");
        }
    }

    /// The emit dispatcher (`emit_expr_at`'s `Expr::Call` arm and its
    /// `call_has_kernel_special_case` mirror) routes `emit_ui_call` on the
    /// kernel's `KernelClass`, but the UI emitter domain — the set `ui_call_shape`
    /// (which `emit_ui_call` consults) classifies — is the single named predicate
    /// `is_ui_family`, spanning five classes: `Ui` / `Web` / `Terminal`, plus the
    /// `Tea` `TeaWorker` app-entry (`is_worker`) and the `Pure` `Ipe.Color.Ansi`
    /// palette constructors (`is_ui` by `TermColor` qualifier carve-out). Each of
    /// those predicates is now derived from `class` in `ipe_kernels` with its own
    /// coherence assert, so this test pins the ONE remaining cross-class relation:
    /// (a) every kernel `ui_call_shape` classifies is `is_ui_family`, and
    /// (b) `is_ui_family` is EXACTLY the set the class-routed dispatcher reaches
    /// through `emit_ui_call`. A UI kernel that lands in a class the dispatcher
    /// does not route to `emit_ui_call` — or an emitter gated on a set spanning a
    /// class the dispatcher splits — is a red here, not a silent emit ICE (#2733).
    #[test]
    fn ui_call_shape_domain_is_reached_by_the_dispatcher() {
        use ipe_ir::KernelClass;
        for &k in KernelFn::ALL {
            // (a) Every kernel `ui_call_shape` classifies is in the UI emitter
            // domain — the single named predicate `is_ui_family`, itself derived
            // from `is_ui` / `is_web` / `is_tui` / `is_console` / `is_worker`
            // (each now derived from `class` + a coherence assert in ipe_kernels).
            if ui_call_shape(k).is_some() {
                assert!(
                    is_ui_family(k),
                    "{k:?} is classified by ui_call_shape but is not is_ui_family — \
                     it would miss emit_ui_call and either ICE or lose its \
                     appearance-literal hoisting. Its class predicate (is_ui/is_web/\
                     is_tui/is_console/is_worker) must cover it.",
                );
            }
            // (b) The UI emitter domain is EXACTLY the set the class-routed
            // dispatcher reaches through emit_ui_call — the `Ui | Web | Terminal`
            // arm, the `Tea` arm for `TeaWorker`, and the `Pure` arm for the
            // `Ipe.Color.Ansi` palette constructors (`TermColor*`, whose
            // appearance literals hoist). Expressed once here, over `class`, so no
            // emitter can be gated on a set that silently spans a class the
            // dispatcher splits (the #2733 ICE class). A `TermColor` palette
            // constructor is `class = Pure` yet `is_ui` by qualifier carve-out, so
            // `is_ui_family` is true for it AND the `Pure` arm below reaches it.
            let class = k.def().class;
            let dispatcher_reaches_ui_call = match class {
                KernelClass::Ui | KernelClass::Web | KernelClass::Terminal => true,
                KernelClass::Tea => k == KernelFn::TeaWorker,
                KernelClass::Pure => k.def().qualifier == "TermColor",
                KernelClass::Db | KernelClass::Server | KernelClass::Ffi => false,
            };
            assert_eq!(
                is_ui_family(k),
                dispatcher_reaches_ui_call,
                "{k:?} (class={class:?}): is_ui_family={} but the emit dispatcher \
                 reaches emit_ui_call for it={} — the UI emitter domain has drifted \
                 from the class-routed dispatcher (the #2733 class↔domain split). \
                 Align the class arm (expr.rs + kernel_calls.rs) with the derived \
                 UI predicates.",
                is_ui_family(k),
                dispatcher_reaches_ui_call,
            );
        }
    }

    /// Every positional plan's arity equals the kernel's authoritative arity in
    /// its [`KernelDef`] descriptor row — the single source of truth. A plan
    /// that drifts from the declared arity fails here at test time rather than
    /// emitting a call with the wrong argument count.
    ///
    /// Native plans are exempt: their arity is enforced inside their own
    /// emitter (several destructure a config record rather than take positional
    /// args, so the Ipê-level arity and the emitted-call argument count differ).
    #[test]
    fn positional_arity_matches_kernel_def() {
        for &k in KernelFn::ALL {
            let Some(plan) = ui_call_shape(k) else {
                continue;
            };
            let Some(arity) = plan.args.positional_arity() else {
                continue;
            };
            assert_eq!(
                arity,
                k.def().arity,
                "{k:?}: plan arity {arity} != KernelDef arity {}",
                k.def().arity,
            );
        }
    }
}

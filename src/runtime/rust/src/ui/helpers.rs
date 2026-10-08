//! Helper functions backing the Ipe.Ui kernel dispatch in the Rust code-gen.
//!
//! Each function corresponds to one `KernelFn` variant wired in `ipe_lower` +
//! `ipe_backend_rust`. The signatures mirror `Ipe/Ui.ipe` exactly so that the
//! emitter can call them without any wrapping or unwrapping.
//!
//! Naming convention: every public function carries a trailing underscore to
//! match the `naming.rs` convention for kernel helpers (e.g. `ui_column_`)
//! and to avoid shadowing the runtime's own `element` type names.

use super::element::{
    Attribute, Description, Element, HAlign, HeadingLevel, Length, Location, Portion, PseudoClass,
    VAlign, WhiteSpace,
};
use crate::color::Color;
use crate::core::IpeMaybe;
use crate::html::{DOCTYPE_WRAPPER_TAG, Html, admit_element};

// ── Element builders ──────────────────────────────────────────────────────────

/// `Ui.node : Description -> List (Attribute msg) -> List (Element msg) -> Element msg`
///
/// The irreducible container-element constructor: an `Element::Node` carrying a
/// role `Description`, its attributes, and its children verbatim. The layout
/// builders (`el` / `row` / `column` / `wrappedRow` / `grid`) are pure Ipê over
/// this primitive with a fixed direction marker prepended.
#[must_use]
pub fn ui_node_<M>(
    desc: Description,
    attrs: Vec<Attribute<M>>,
    children: Vec<Element<M>>,
) -> Element<M> {
    Element::Node(desc, attrs, children)
}

/// `Ui.taggedNode : String -> Description -> List (Attribute msg) -> List (Element msg) -> Element msg`
///
/// The irreducible tagged-element constructor: an `Element::TaggedNode` fixing
/// the HTML tag, role `Description`, attributes, and children. The flow builders
/// (`paragraph` / `textColumn` / `form` / `input`) are pure Ipê over this
/// primitive with a fixed tag + marker.
///
/// SECURITY: the tag runs the shared `admit_element` gate. A refused element (an
/// unsafe tag name, `<plaintext>`, or a `<script>`/`<style>` whose children are
/// not all `Ui.html` over trusted raw markup) is built as `Element::Empty`, so
/// the safe surface cannot make data an executable or raw-text body.
#[must_use]
pub fn ui_tagged_node_<M>(
    tag: String,
    desc: Description,
    attrs: Vec<Attribute<M>>,
    children: Vec<Element<M>>,
) -> Element<M> {
    if admit_element(&tag, &children).is_err() {
        return Element::Empty;
    }
    Element::TaggedNode(tag, desc, attrs, children)
}

/// `Ui.none : Element msg`
#[must_use]
pub fn ui_none_<M>() -> Element<M> {
    Element::Empty
}

/// `Ui.text : String -> Element msg`
#[must_use]
pub fn ui_text_<M>(s: String) -> Element<M> {
    Element::Text(s)
}

/// `Ui.html : Html msg -> Element msg`
#[must_use]
pub fn ui_html_<M: Clone>(h: Html<M>) -> Element<M> {
    Element::Raw(h)
}

/// `Ui.cells : List (List Char) -> Element msg`
///
/// A raw terminal cell grid: each inner list is one row of characters. The
/// terminal backend paints it verbatim, one row per line; other backends
/// degrade it to its text rows (see `render_element`).
#[must_use]
pub fn ui_cells_<M>(grid: Vec<Vec<char>>) -> Element<M> {
    Element::Cells(grid)
}

/// `Ui.el : List (Attribute msg) -> Element msg -> Element msg`
#[must_use]
pub fn ui_el_<M: Clone>(attrs: Vec<Attribute<M>>, ch: Element<M>) -> Element<M> {
    Element::Node(Description::NoDescription, attrs, vec![ch])
}

/// `Ui.row : List (Attribute msg) -> List (Element msg) -> Element msg`
///
/// Prepends the `__row` row-direction marker matching `rowMarker` in
/// `Ipe/Ui.ipe`.
#[must_use]
pub fn ui_row_<M: Clone>(attrs: Vec<Attribute<M>>, children: Vec<Element<M>>) -> Element<M> {
    let mut full = Vec::with_capacity(attrs.len() + 1);
    full.push(Attribute::AttrStyle("__row".to_owned(), "true".to_owned()));
    full.extend(attrs);
    Element::Node(Description::NoDescription, full, children)
}

/// `Ui.column : List (Attribute msg) -> List (Element msg) -> Element msg`
///
/// Prepends the `__col` column-direction marker matching `colMarker` in
/// `Ipe/Ui.ipe`.
#[must_use]
pub fn ui_column_<M: Clone>(attrs: Vec<Attribute<M>>, children: Vec<Element<M>>) -> Element<M> {
    let mut full = Vec::with_capacity(attrs.len() + 1);
    full.push(Attribute::AttrStyle("__col".to_owned(), "true".to_owned()));
    full.extend(attrs);
    Element::Node(Description::NoDescription, full, children)
}

/// `Ui.wrappedRow : List (Attribute msg) -> List (Element msg) -> Element msg`
#[must_use]
pub fn ui_wrapped_row_<M: Clone>(
    attrs: Vec<Attribute<M>>,
    children: Vec<Element<M>>,
) -> Element<M> {
    let mut full = Vec::with_capacity(attrs.len() + 1);
    full.push(Attribute::AttrStyle(
        "__wrappedrow".to_owned(),
        "true".to_owned(),
    ));
    full.extend(attrs);
    Element::Node(Description::NoDescription, full, children)
}

/// `Ui.button : List (Attribute msg) -> { onPress : Maybe msg, label : Element msg } -> Element msg`
///
/// When `onPress` is `Just msg`, adds an `onclick` event attribute + `cursor: pointer`.
/// When `onPress` is `Nothing`, adds `disabled="true"` so the button is visually and
/// semantically disabled.
pub fn ui_button_<M: Clone>(
    attrs: Vec<Attribute<M>>,
    on_press: IpeMaybe<M>,
    label: Element<M>,
) -> Element<M> {
    use crate::html::{Attribute as HtmlAttribute, Event};
    let mut full = Vec::with_capacity(attrs.len() + 2);
    match on_press {
        IpeMaybe::Just(msg) => {
            full.push(Attribute::AttrEvent(HtmlAttribute::EventAttr(
                Event::OnMsg("click".into(), msg),
            )));
            full.push(Attribute::AttrPointer);
        }
        IpeMaybe::Nothing => {
            full.push(Attribute::AttrAttribute("disabled".into(), "true".into()));
        }
    }
    full.extend(attrs);
    Element::TaggedNode(
        "button".into(),
        Description::NoDescription,
        full,
        vec![label],
    )
}

/// `Ui.link : List (Attribute msg) -> { url : String, label : Element msg } -> Element msg`
/// Renders as `<a href=url>label</a>`.
///
/// SECURITY: a `target="_blank"` anchor grants the opened page `window.opener`,
/// a reverse-tabnabbing lever an untrusted `href` (e.g. a markdown link) can use
/// to navigate the opener. Any new-tab link therefore severs the opener by
/// construction: when the attrs carry `target="_blank"` and no explicit `rel`,
/// a `rel="noopener noreferrer"` is attached here — the single sink through
/// which every `Ui.link` flows — so no stdlib call site can emit a `_blank`
/// link without it.
#[must_use]
pub fn ui_link_<M: Clone>(attrs: Vec<Attribute<M>>, url: String, label: Element<M>) -> Element<M> {
    let opens_new_tab = attrs.iter().any(|a| {
        matches!(a, Attribute::AttrAttribute(name, value) if name == "target" && value == "_blank")
    });
    let has_rel = attrs
        .iter()
        .any(|a| matches!(a, Attribute::AttrAttribute(name, _) if name == "rel"));
    let extra = usize::from(opens_new_tab && !has_rel);
    let mut full = Vec::with_capacity(attrs.len() + 1 + extra);
    full.push(Attribute::AttrAttribute("href".into(), url));
    full.extend(attrs);
    if opens_new_tab && !has_rel {
        full.push(Attribute::AttrAttribute(
            "rel".into(),
            "noopener noreferrer".into(),
        ));
    }
    Element::TaggedNode("a".into(), Description::NoDescription, full, vec![label])
}

/// `Ui.image : List (Attribute msg) -> { src : String, description : String } -> Element msg`
/// (the `{ src, description }` record is destructured at the emit site into
/// two positional args, matching `Ui.link`'s `{ url, label }` handling).
/// Renders as `<img src=… alt=…>` (a void `TaggedNode`, no children) — mirrors
/// the `../ipe` reference: `AttrAttribute "src" cfg.src :: AttrAttribute "alt"
/// cfg.description :: attrs`.
#[must_use]
pub fn ui_image_<M: Clone>(
    attrs: Vec<Attribute<M>>,
    src: String,
    description: String,
) -> Element<M> {
    let mut full = Vec::with_capacity(attrs.len() + 2);
    full.push(Attribute::AttrAttribute("src".into(), src));
    full.push(Attribute::AttrAttribute("alt".into(), description));
    full.extend(attrs);
    Element::TaggedNode("img".into(), Description::NoDescription, full, vec![])
}

// ── Attribute builders ────────────────────────────────────────────────────────

/// `Ui.spacing : Int -> Attribute msg`
#[must_use]
pub fn ui_spacing_<M>(n: i64) -> Attribute<M> {
    Attribute::AttrSpacing(n)
}

/// `Ui.padding : Int -> Attribute msg`  (uniform padding on all four sides)
#[must_use]
pub fn ui_padding_<M>(n: i64) -> Attribute<M> {
    // AttrPadding(top, right, bottom, left)
    Attribute::AttrPadding(n, n, n, n)
}

/// `Ui.paddingXY : Int -> Int -> Attribute msg`
///
/// `x` = left/right padding, `y` = top/bottom padding.
#[must_use]
pub fn ui_padding_xy_<M>(x: i64, y: i64) -> Attribute<M> {
    Attribute::AttrPadding(y, x, y, x)
}

/// `Ui.paddingEach : { top : Int, right : Int, bottom : Int, left : Int } -> Attribute msg`
#[must_use]
pub fn ui_padding_each_<M>(top: i64, right: i64, bottom: i64, left: i64) -> Attribute<M> {
    Attribute::AttrPadding(top, right, bottom, left)
}

/// `Ui.width : Length -> Attribute msg`
#[must_use]
pub fn ui_width_<M>(l: Length) -> Attribute<M> {
    Attribute::AttrWidth(l)
}

/// `Ui.height : Length -> Attribute msg`
#[must_use]
pub fn ui_height_<M>(l: Length) -> Attribute<M> {
    Attribute::AttrHeight(l)
}

/// `Ui.centerX : Attribute msg`
#[must_use]
pub fn ui_center_x_<M>() -> Attribute<M> {
    Attribute::AttrAlignX(HAlign::CenterX)
}

/// `Ui.centerY : Attribute msg`
#[must_use]
pub fn ui_center_y_<M>() -> Attribute<M> {
    Attribute::AttrAlignY(VAlign::CenterY)
}

/// `Ui.alignLeft : Attribute msg`
#[must_use]
pub fn ui_align_left_<M>() -> Attribute<M> {
    Attribute::AttrAlignX(HAlign::AlignLeft)
}

/// `Ui.alignRight : Attribute msg`
#[must_use]
pub fn ui_align_right_<M>() -> Attribute<M> {
    Attribute::AttrAlignX(HAlign::AlignRight)
}

/// `Ui.alignTop : Attribute msg`
#[must_use]
pub fn ui_align_top_<M>() -> Attribute<M> {
    Attribute::AttrAlignY(VAlign::AlignTop)
}

/// `Ui.alignBottom : Attribute msg`
#[must_use]
pub fn ui_align_bottom_<M>() -> Attribute<M> {
    Attribute::AttrAlignY(VAlign::AlignBottom)
}

/// `Ui.pointer : Attribute msg`
#[must_use]
pub fn ui_pointer_<M>() -> Attribute<M> {
    Attribute::AttrPointer
}

/// `Debug.explain : Attribute msg` — draws a visible outline on this element
/// and all its descendants to reveal the invisible box tree.  Does not change
/// layout.  Web/WebView only; rejected in Terminal/Program at emit time.
#[must_use]
pub fn debug_explain_<M>() -> Attribute<M> {
    Attribute::AttrExplain
}

/// `Ui.clip : Attribute msg` — clip overflow on BOTH axes.
#[must_use]
pub fn ui_clip_<M>() -> Attribute<M> {
    Attribute::AttrOverflow("hidden".to_owned(), "hidden".to_owned())
}

/// `Ui.clipX : Attribute msg` — single-axis clip. Uses the CSS `clip` keyword
/// (not `hidden`) on the X axis: CSS promotes a `visible` off-axis to `auto`
/// (unwanted scrollbar) when the other axis is `hidden`/`auto`/`scroll` — but
/// NOT when it is `clip`. So `overflow-x:clip;overflow-y:visible` truly
/// leaves Y visible (matches the `../ipe` reference exactly).
#[must_use]
pub fn ui_clip_x_<M>() -> Attribute<M> {
    Attribute::AttrOverflow("clip".to_owned(), "visible".to_owned())
}

/// `Ui.clipY : Attribute msg` — single-axis clip on Y; see [`ui_clip_x_`].
#[must_use]
pub fn ui_clip_y_<M>() -> Attribute<M> {
    Attribute::AttrOverflow("visible".to_owned(), "clip".to_owned())
}

/// `Ui.scrollbars : Attribute msg` — scrollbars on BOTH axes.
#[must_use]
pub fn ui_scrollbars_<M>() -> Attribute<M> {
    Attribute::AttrOverflow("auto".to_owned(), "auto".to_owned())
}

/// `Ui.scrollbarX : Attribute msg` — single-axis scroller. The off-axis is
/// `hidden`, not `visible`: a `visible` off-axis gets promoted to `auto` by
/// CSS (an unwanted second scrollbar). Matches the `../ipe` reference.
#[must_use]
pub fn ui_scrollbar_x_<M>() -> Attribute<M> {
    Attribute::AttrOverflow("auto".to_owned(), "hidden".to_owned())
}

/// `Ui.scrollbarY : Attribute msg` — single-axis scroller on Y; see
/// [`ui_scrollbar_x_`].
#[must_use]
pub fn ui_scrollbar_y_<M>() -> Attribute<M> {
    Attribute::AttrOverflow("hidden".to_owned(), "auto".to_owned())
}

/// `Ui.gridColumns : Int -> Attribute msg`
#[must_use]
pub fn ui_grid_columns_<M>(n: i64) -> Attribute<M> {
    Attribute::AttrStyle("--ipe-grid-columns".to_owned(), n.to_string())
}

// ── Length builders ───────────────────────────────────────────────────────────

/// `Ui.px : Int -> Length`
#[must_use]
pub fn ui_px_(n: i64) -> Length {
    Length::Px(n)
}

/// `Ui.fill : Length`  (`fillPortion 1`)
#[must_use]
pub fn ui_fill_() -> Length {
    Length::Fill(Portion::ONE)
}

/// `Ui.content : Length`
#[must_use]
pub fn ui_content_() -> Length {
    Length::Content
}

/// `Ui.shrink : Length`  (alias for `Ui.content` in Ipê)
#[must_use]
pub fn ui_shrink_() -> Length {
    Length::Content
}

/// `Ui.fillPortion : Int -> Length` — `n <= 0` is `Ui.shrink`.
#[must_use]
pub fn ui_fill_portion_(n: i64) -> Length {
    Length::fill_portion(n)
}

/// `Ui.vh : Int -> Length`
#[must_use]
pub fn ui_vh_(n: i64) -> Length {
    Length::Vh(n)
}

/// `Ui.vw : Int -> Length`
#[must_use]
pub fn ui_vw_(n: i64) -> Length {
    Length::Vw(n)
}

/// `Ui.minimum : Int -> Length -> Length`
#[must_use]
pub fn ui_minimum_(n: i64, l: Length) -> Length {
    Length::Min(n, Box::new(l))
}

/// `Ui.maximum : Int -> Length -> Length`
#[must_use]
pub fn ui_maximum_(n: i64, l: Length) -> Length {
    Length::Max(n, Box::new(l))
}

// ── Color builders ────────────────────────────────────────────────────────────

/// `Ui.rgb : Int -> Int -> Int -> Color`  (alpha = 1.0)
#[must_use]
pub fn ui_rgb_(r: i64, g: i64, b: i64) -> Color {
    Color::rgb(r, g, b)
}

/// `Ui.rgba : Int -> Int -> Int -> Float -> Color`
#[must_use]
pub fn ui_rgba_(r: i64, g: i64, b: i64, a: f64) -> Color {
    Color::rgba(r, g, b, a)
}

/// `Ui.white : Color`
#[must_use]
pub fn ui_white_() -> Color {
    Color::white()
}

/// `Ui.black : Color`
#[must_use]
pub fn ui_black_() -> Color {
    Color::black()
}

/// `Ui.transparent : Color`
#[must_use]
pub fn ui_transparent_() -> Color {
    Color::transparent()
}

/// `Ui.colorCss : Color -> String` — convert a `Color` to its CSS string.
///
/// The `Ipe.Ui`/`Ipe.Css` surfaces always spell alpha (never collapse to
/// `rgb(..)`), so this routes through [`Color::to_css_rgba`] to stay byte-exact
/// with the pre-existing shared CSS goldens.
#[must_use]
pub fn ui_color_css_(c: Color) -> String {
    c.to_css_rgba()
}

// ── Background sub-module ─────────────────────────────────────────────────────

/// `Background.color : Color -> Attribute msg`
#[must_use]
pub fn ui_background_color_<M>(c: Color) -> Attribute<M> {
    Attribute::AttrBgColor(c)
}

/// `Background.image : String -> Attribute msg`
#[must_use]
pub fn ui_background_image_<M>(s: String) -> Attribute<M> {
    Attribute::AttrBgImage(s)
}

/// `Background.linearGradient : Float -> List (Float, Color) -> Attribute msg`
///
/// Renders `background-image: linear-gradient(<angle>deg, <c1> <p1>%, …);`
/// via the existing `AttrBgGradient` runtime variant (already rendered by
/// `render.rs`'s `build_style_string`). Float formatting matches
/// `String.fromFloat` via the shared `string_from_float` kernel (parity with
/// the `../ipe` reference's `String.fromFloat angle` / `String.fromFloat pct`).
#[must_use]
pub fn ui_background_linear_gradient_<M>(angle: f64, stops: Vec<(f64, Color)>) -> Attribute<M> {
    use crate::string::string_from_float;
    let joined = stops
        .into_iter()
        .map(|(pct, c)| format!("{} {}%", c.to_css_rgba(), string_from_float(pct)))
        .collect::<Vec<_>>()
        .join(", ");
    Attribute::AttrBgGradient(format!(
        "linear-gradient({}deg, {joined})",
        string_from_float(angle)
    ))
}

// ── Border sub-module ─────────────────────────────────────────────────────────

/// `Border.width : Int -> Attribute msg`
#[must_use]
pub fn ui_border_width_<M>(n: i64) -> Attribute<M> {
    Attribute::AttrBorderWidth(n)
}

/// `Border.rounded : Int -> Attribute msg`
#[must_use]
pub fn ui_border_rounded_<M>(n: i64) -> Attribute<M> {
    Attribute::AttrBorderRounded(n)
}

/// `Border.color : Color -> Attribute msg`
#[must_use]
pub fn ui_border_color_<M>(c: Color) -> Attribute<M> {
    Attribute::AttrBorderColor(c)
}

/// `Border.widthEach : { top : Int, right : Int, bottom : Int, left : Int } -> Attribute msg`
#[must_use]
pub fn ui_border_width_each_<M>(top: i64, right: i64, bottom: i64, left: i64) -> Attribute<M> {
    Attribute::AttrBorderWidthEach(top, right, bottom, left)
}

/// `Border.shadow : { offsetX : Int, offsetY : Int, blur : Int, spread : Int, color : Color } -> Attribute msg`
///
/// Mirrors the reference (`Ipe.Ui.Border.shadow` → `borderShadow`) which renders
/// the CSS `box-shadow: <ox>px <oy>px <blur>px <spread>px <colour>;` shape. Uses
/// the dedicated `AttrBorderShadow` runtime variant (rendered in `render.rs`) so
/// the colour flows through the same `Color::css` renderer as `Border.color`.
#[must_use]
pub fn ui_border_shadow_<M>(
    horiz: i64,
    vert: i64,
    blur: i64,
    spread: i64,
    c: Color,
) -> Attribute<M> {
    Attribute::AttrBorderShadow(horiz, vert, blur, spread, c)
}

/// `Border.glow : Int -> Color -> Attribute msg`
///
/// Convenience wrapper over `box-shadow`: a shadow with `(0, 0)` offset and `0`
/// spread, so the user supplies only a blur radius and a colour. Emits the CSS
/// `box-shadow: 0px 0px <blur>px 0px <colour>` via the generic `AttrStyle`
/// boundary (the colour flows through the same `Color::css` renderer as
/// `Border.color` / `Border.shadow`).
#[must_use]
pub fn ui_border_glow_<M>(blur: i64, c: Color) -> Attribute<M> {
    Attribute::AttrStyle(
        "box-shadow".into(),
        format!("0px 0px {blur}px 0px {}", c.to_css_rgba()),
    )
}

/// `Border.innerShadow : { offsetX : Int, offsetY : Int, blur : Int, spread : Int, color : Color } -> Attribute msg`
///
/// Same record shape as [`ui_border_shadow_`] but INSET: renders the CSS
/// `box-shadow: inset <ox>px <oy>px <blur>px <spread>px <colour>;`. Uses the
/// dedicated `AttrBorderInsetShadow` runtime variant (rendered in `render.rs`)
/// so the colour flows through the same `Color::css` renderer as `Border.color`.
#[must_use]
pub fn ui_border_inner_shadow_<M>(
    horiz: i64,
    vert: i64,
    blur: i64,
    spread: i64,
    c: Color,
) -> Attribute<M> {
    Attribute::AttrBorderInsetShadow(horiz, vert, blur, spread, c)
}

// ── Font sub-module ───────────────────────────────────────────────────────────

/// `Font.size : Int -> Attribute msg`
#[must_use]
pub fn ui_font_size_<M>(n: i64) -> Attribute<M> {
    Attribute::AttrFontSize(n)
}

/// `Font.color : Color -> Attribute msg`
#[must_use]
pub fn ui_font_color_<M>(c: Color) -> Attribute<M> {
    Attribute::AttrFontColor(c)
}

/// `Font.family : List String -> Attribute msg`
///
/// Passes the font-family CSS value string through as-is.
#[must_use]
pub fn ui_font_family_<M>(family: String) -> Attribute<M> {
    Attribute::AttrFontFamily(family)
}

/// `Font.bold : Attribute msg`
#[must_use]
pub fn ui_font_bold_<M>() -> Attribute<M> {
    Attribute::AttrFontWeight(700)
}

/// `Font.italic : Attribute msg`
#[must_use]
pub fn ui_font_italic_<M>() -> Attribute<M> {
    Attribute::AttrFontItalic
}

// ── Html element builders ─────────────────────────────────────────────────────
// These mirror `Ipe.Html`'s pure-Ipê constructors (`HText`, `HRaw`,
// `HElement`) without the `Ipê.Ffi` dependency that blocks compiling
// `Std/Html.ipe` from source in Ipê-Rust.

/// `Html.text : String -> Html msg`
#[must_use]
pub fn html_text_node_<M>(s: String) -> Html<M> {
    Html::HText(s)
}

/// `Html.unsafeRaw : String -> Html msg` — injects an un-escaped String
/// verbatim as HTML. The `unsafe` prefix names the XSS risk at the Ipê surface
/// so raw injection is greppable and never looks safe; user content goes
/// through `html_text_node_` (escaped by construction) instead.
#[must_use]
pub fn html_raw_node_<M>(s: String) -> Html<M> {
    Html::HRaw(s)
}

/// `Html.styleNode : List (Attribute msg) -> String -> Html msg`
///
/// SECURITY: `styleNode` is arity-2 `(attrs, css:String)`, not the arity-3
/// `html_node_`. It bakes injection safety into construction (parse, don't
/// validate): `neutralise_style_body` removes every `</style` and every other
/// markup opener exactly once, HERE, so the `HRaw` it produces can end neither
/// the `<style>` nor an RCDATA, RAWTEXT or foreign-content ancestor. The
/// `<style>` render sink (`html::render_into_ctx`) neutralises again (defence
/// in depth), so a breakout in a `Ipe.Css` value cannot reach the DOM.
#[must_use]
pub fn html_style_node_<M>(attrs: Vec<crate::html::Attribute<M>>, css: String) -> Html<M> {
    Html::HElement(
        "style".to_owned(),
        attrs,
        vec![Html::HRaw(crate::css_safety::neutralise_style_body(&css))],
    )
}

/// `Ipe.Html.Unsafe.unsafeScript : String -> Html msg` — an inline `<script>`
/// element whose JavaScript body is emitted VERBATIM.
///
/// SECURITY: a script body is trusted-code injection, so this is an escape hatch
/// homed in `Ipe.Html.Unsafe` (its import discloses the `unsafe` capability) and
/// named `unsafe*` — never on the safe `Ipe.Html` surface. There is no escaping a
/// script body admits: HTML-escaping it would corrupt the JavaScript, and the
/// body is executable code regardless of value-escaping, so the caller owns the
/// invariant that the body is trusted, author-controlled code. The one structural
/// breakout — a literal `</script` closing the element early — is neutralised
/// here at construction (parse, don't validate) by splitting the ASCII-case-
/// insensitive `</script` sequence with a backslash, exactly the belt-and-braces
/// shape `html_style_node_` uses for `</style`; the `<script>` render sink emits
/// the resulting `HRaw` child verbatim.
#[must_use]
pub fn html_script_node_<M>(body: String) -> Html<M> {
    Html::HElement(
        "script".to_owned(),
        vec![],
        vec![Html::HRaw(crate::css_safety::neutralise_script_close(
            &body,
        ))],
    )
}

/// `Html.node : String -> List (Attribute msg) -> List (Html msg) -> Html msg`
///
/// SECURITY: the tag runs the shared `admit_element` gate. A refused element (an
/// unsafe tag name, `<plaintext>`, or a `<script>`/`<style>` whose children are
/// not all trusted raw markup) is built as empty text, so `Html.script [] [
/// Html.text s ]` renders nothing instead of executing `s`. A trusted body comes
/// only from `Ipe.Html.Unsafe` or `Ipe.Html.styleNode`.
#[must_use]
pub fn html_node_<M>(
    tag: String,
    attrs: Vec<crate::html::Attribute<M>>,
    children: Vec<Html<M>>,
) -> Html<M> {
    if admit_element(&tag, &children).is_err() {
        return Html::HText(String::new());
    }
    Html::HElement(tag, attrs, children)
}

/// `Html.doctype : List (Html msg) -> Html msg` — wraps children in the
/// `!doctype-wrapper` pseudo-tag, which `ipe_runtime::html::admit_rendered`
/// recognises for the render sink and the SSE diff alike: it renders as
/// `<!DOCTYPE html>` and then the children directly.
#[must_use]
pub fn html_doctype_<M>(children: Vec<Html<M>>) -> Html<M> {
    Html::HElement(DOCTYPE_WRAPPER_TAG.to_owned(), Vec::new(), children)
}

/// `Html.titleNode : String -> Html msg` — wraps a raw string directly in
/// `<title>` (`HElement "title" [] [HText s]`).
#[must_use]
pub fn html_title_node_<M>(s: String) -> Html<M> {
    Html::HElement("title".to_owned(), Vec::new(), vec![Html::HText(s)])
}

// ── Event-attribute builders ───────────────────────────────────────
//
// These back the `UiOnClick`, `UiOnFocus`, … KernelFn variants.  They return
// `element::Attribute<M>` (same as all other Ui attribute builders) with the
// `AttrEvent` variant wrapping an `html::Attribute::EventAttr(Event::…)`.
//
// The two `Attribute` types are:
//   • `html::Attribute<M>` — raw HTML attribute (event, class, data-*, …)
//   • `element::Attribute<M>` — typed Ipe.Ui attribute; `AttrEvent` carries
//     an `html::Attribute` for event dispatch.
//
// Plain-message events (`OnMsg`) take the typed message value directly.
// String-carrying events (`OnString`) take an `Arc<dyn Fn(String)->M+…>`
// so the runtime can call the function from a send-safe dispatcher.
// Callers emit: `Arc::new(move |_x| (f)(_x))`.

use crate::html::{Attribute as HtmlAttribute, Event};

/// `Ui.onClick : msg -> Attribute msg`
pub fn ui_on_click_<M>(msg: M) -> Attribute<M> {
    Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnMsg("click".into(), msg)))
}

/// `Ui.onFocus : msg -> Attribute msg`
pub fn ui_on_focus_<M>(msg: M) -> Attribute<M> {
    Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnMsg("focus".into(), msg)))
}

/// `Ui.onBlur : msg -> Attribute msg`
pub fn ui_on_blur_<M>(msg: M) -> Attribute<M> {
    Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnMsg("blur".into(), msg)))
}

/// `Ui.onMouseOver : msg -> Attribute msg`
pub fn ui_on_mouse_over_<M>(msg: M) -> Attribute<M> {
    Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnMsg(
        "mouseover".into(),
        msg,
    )))
}

/// `Ui.onMouseOut : msg -> Attribute msg`
pub fn ui_on_mouse_out_<M>(msg: M) -> Attribute<M> {
    Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnMsg(
        "mouseout".into(),
        msg,
    )))
}

/// `Ui.onInput : (String -> msg) -> Attribute msg`
///
/// The callback is Arc-wrapped so the runtime can dispatch it from a
/// send-safe context.  Callers emit `std::sync::Arc::new(move |_x| (f)(_x))`
/// where `f` is the emitted Ipê function expression (T6 trap).
pub fn ui_on_input_<M>(f: std::sync::Arc<dyn Fn(String) -> M + Send + Sync>) -> Attribute<M> {
    Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnString("input".into(), f)))
}

/// `Ui.onChange : (String -> msg) -> Attribute msg`
pub fn ui_on_change_<M>(f: std::sync::Arc<dyn Fn(String) -> M + Send + Sync>) -> Attribute<M> {
    Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnString(
        "change".into(),
        f,
    )))
}

/// `Ui.onKeyDown : (String -> msg) -> Attribute msg`
pub fn ui_on_key_down_<M>(f: std::sync::Arc<dyn Fn(String) -> M + Send + Sync>) -> Attribute<M> {
    Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnString(
        "keydown".into(),
        f,
    )))
}

/// `Ui.onKeyUp : (String -> msg) -> Attribute msg`
pub fn ui_on_key_up_<M>(f: std::sync::Arc<dyn Fn(String) -> M + Send + Sync>) -> Attribute<M> {
    Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnString("keyup".into(), f)))
}

/// `Event.onBool : (Bool -> msg) -> Attribute msg`
///
/// Wires a boolean-carrying event (typically `change` on a checkbox) so that
/// the Ipê callback receives the DOM `checked` value as a Rust `bool`.
/// The `f` argument is arc-wrapped at the call site by the emitter (T6 trap).
pub fn ui_on_bool_<M>(f: std::sync::Arc<dyn Fn(bool) -> M + Send + Sync>) -> Attribute<M> {
    Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnBool("change".into(), f)))
}

/// `Ui.onFile : (String -> msg) -> Attribute msg` — wire event name
/// `"ipe-file"`. The browser-side driver reads the chosen file,
/// base64-encodes it as a data URL, and dispatches the URL string to the
/// handler (mirrors `Ipe.Html.Events.onFile`'s `EventAttr (OnString
/// "ipe-file" handler)` on the `../ipe` reference).
pub fn ui_on_file_<M>(f: std::sync::Arc<dyn Fn(String) -> M + Send + Sync>) -> Attribute<M> {
    Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnString(
        "ipe-file".into(),
        f,
    )))
}

// ── Tier 1: extended Ipe.Ui / Font / Background / Border builders ────────

// Ui namespace — aspect-ratio

/// `Ui.square : Attribute msg` — aspect-ratio 1 / 1.
#[must_use]
pub fn ui_square_<M>() -> Attribute<M> {
    Attribute::AttrStyle("aspect-ratio".into(), "1 / 1".into())
}

/// `Ui.widescreen : Attribute msg` — aspect-ratio 16 / 9.
#[must_use]
pub fn ui_widescreen_<M>() -> Attribute<M> {
    Attribute::AttrStyle("aspect-ratio".into(), "16 / 9".into())
}

/// `Ui.cinemascope : Attribute msg` — aspect-ratio 2.35 / 1 (anamorphic wide).
#[must_use]
pub fn ui_cinemascope_<M>() -> Attribute<M> {
    Attribute::AttrStyle("aspect-ratio".into(), "2.35 / 1".into())
}

/// `Ui.name : String -> Attribute msg` — HTML name= attribute (radio groups, form fields).
#[must_use]
pub fn ui_name_<M>(value: String) -> Attribute<M> {
    Attribute::AttrAttribute("name".into(), value)
}

/// `Ui.style : String -> String -> Attribute msg` — raw inline CSS property + value.
#[must_use]
pub fn ui_style_<M>(property: String, value: String) -> Attribute<M> {
    Attribute::AttrStyle(property, value)
}

/// `Ui.transition : String -> Bool -> Attribute msg` — the CSS `transition`
/// shorthand (built by `Ipe.Ui.Transition.buildShorthand`) plus a
/// respect-`prefers-reduced-motion` flag. `respect = True` (via
/// `Transition.attribute`) auto-gates the rule behind
/// `@media (prefers-reduced-motion: no-preference)` in the live style-injection
/// pass; `False` (via `attributeUnsafe`) fires unconditionally.
#[must_use]
pub fn ui_transition_raw_<M>(shorthand: String, respect: bool) -> Attribute<M> {
    Attribute::AttrTransition(shorthand, respect)
}

/// `Ui.gridTracks : String -> String -> Attribute msg` — CSS grid-template-columns
/// (first arg) and grid-template-rows (second arg).  Pass `""` for either axis to skip it.
#[must_use]
pub fn ui_grid_tracks_raw_<M>(cols: String, rows: String) -> Attribute<M> {
    Attribute::AttrGridTracks(cols, rows)
}

/// `Ui.animate : String -> String -> String -> Bool -> Attribute msg` — the
/// keyframe-animation `name`, the animation shorthand TAIL (built by
/// `Ipe.Ui.Animation.buildShorthandTail`: `<dur>ms <easing> <delay>ms <iter>
/// <fill>`, without the leading name token), the `@keyframes` BODY (built by
/// `Ipe.Ui.Animation.buildKeyframesBody`), and a respect-`prefers-reduced-motion`
/// flag. Mirrors `ui_transition_raw_`. The live style-injection pass
/// (`web::style_inject::build_anim`) auto-suffixes `name` with the element's
/// ipe-id (so two `"fadeIn"`s with different keyframes don't collide), gates the
/// rule behind `@media (prefers-reduced-motion: no-preference)` when `respect =
/// True`, and validates the keyframes body through `sink_safe_keyframes_body`.
#[must_use]
pub fn ui_animate_raw_<M>(
    name: String,
    shorthand_tail: String,
    keyframes_body: String,
    respect: bool,
) -> Attribute<M> {
    Attribute::AttrAnimation(name, shorthand_tail, keyframes_body, respect)
}

/// `Ui.aspectRatio : Float -> Attribute msg`
#[must_use]
pub fn ui_aspect_ratio_<M>(r: f64) -> Attribute<M> {
    Attribute::AttrStyle("aspect-ratio".into(), format!("{r}"))
}

/// `Ui.aspectRatioWH : Int -> Int -> Attribute msg`
#[must_use]
pub fn ui_aspect_ratio_wh_<M>(w: i64, h: i64) -> Attribute<M> {
    Attribute::AttrStyle("aspect-ratio".into(), format!("{w} / {h}"))
}

/// `Ui.htmlAttribute : String -> String -> Attribute msg`
#[must_use]
pub fn ui_html_attribute_<M>(key: String, value: String) -> Attribute<M> {
    Attribute::AttrAttribute(key, value)
}

// Background pseudo-class colour attrs

/// `Background.hoverColor : Color -> Attribute msg`
#[must_use]
pub fn ui_bg_hover_color_<M>(c: Color) -> Attribute<M> {
    Attribute::AttrPseudoRule(
        PseudoClass::Hover,
        format!("background-color:{}", c.to_css_rgba()),
    )
}

/// `Background.focusColor : Color -> Attribute msg`
#[must_use]
pub fn ui_bg_focus_color_<M>(c: Color) -> Attribute<M> {
    Attribute::AttrPseudoRule(
        PseudoClass::FocusVisible,
        format!("background-color:{}", c.to_css_rgba()),
    )
}

/// `Background.activeColor : Color -> Attribute msg`
#[must_use]
pub fn ui_bg_active_color_<M>(c: Color) -> Attribute<M> {
    Attribute::AttrPseudoRule(
        PseudoClass::Active,
        format!("background-color:{}", c.to_css_rgba()),
    )
}

/// `Background.disabledColor : Color -> Attribute msg`
#[must_use]
pub fn ui_bg_disabled_color_<M>(c: Color) -> Attribute<M> {
    Attribute::AttrPseudoRule(
        PseudoClass::Disabled,
        format!("background-color:{}", c.to_css_rgba()),
    )
}

// Border namespace — style keywords (nullary)

/// `Border.solid : Attribute msg`
#[must_use]
pub fn ui_border_solid_<M>() -> Attribute<M> {
    Attribute::AttrBorderStyle("solid".into())
}

/// `Border.dashed : Attribute msg`
#[must_use]
pub fn ui_border_dashed_<M>() -> Attribute<M> {
    Attribute::AttrBorderStyle("dashed".into())
}

/// `Border.dotted : Attribute msg`
#[must_use]
pub fn ui_border_dotted_<M>() -> Attribute<M> {
    Attribute::AttrBorderStyle("dotted".into())
}

// Border pseudo-class attrs

/// `Border.hoverColor : Color -> Attribute msg`
#[must_use]
pub fn ui_border_hover_color_<M>(c: Color) -> Attribute<M> {
    Attribute::AttrPseudoRule(
        PseudoClass::Hover,
        format!("border-color:{}", c.to_css_rgba()),
    )
}

/// `Border.focusColor : Color -> Attribute msg`
#[must_use]
pub fn ui_border_focus_color_<M>(c: Color) -> Attribute<M> {
    Attribute::AttrPseudoRule(
        PseudoClass::FocusVisible,
        format!("border-color:{}", c.to_css_rgba()),
    )
}

/// `Border.activeColor : Color -> Attribute msg`
#[must_use]
pub fn ui_border_active_color_<M>(c: Color) -> Attribute<M> {
    Attribute::AttrPseudoRule(
        PseudoClass::Active,
        format!("border-color:{}", c.to_css_rgba()),
    )
}

/// `Border.hoverWidth : Int -> Attribute msg`
#[must_use]
pub fn ui_border_hover_width_<M>(n: i64) -> Attribute<M> {
    Attribute::AttrPseudoRule(PseudoClass::Hover, format!("border-width:{n}px"))
}

/// `Border.hoverRounded : Int -> Attribute msg`
#[must_use]
pub fn ui_border_hover_rounded_<M>(n: i64) -> Attribute<M> {
    Attribute::AttrPseudoRule(PseudoClass::Hover, format!("border-radius:{n}px"))
}

// Font namespace — weight

/// `Font.weight : Int -> Attribute msg`
#[must_use]
pub fn ui_font_weight_<M>(n: i64) -> Attribute<M> {
    Attribute::AttrFontWeight(n)
}

/// `Font.semiBold : Attribute msg` (weight 600)
#[must_use]
pub fn ui_font_semi_bold_<M>() -> Attribute<M> {
    Attribute::AttrFontWeight(600)
}

/// `Font.regular : Attribute msg` (weight 400)
#[must_use]
pub fn ui_font_regular_<M>() -> Attribute<M> {
    Attribute::AttrFontWeight(400)
}

/// `Font.light : Attribute msg` (weight 300)
#[must_use]
pub fn ui_font_light_<M>() -> Attribute<M> {
    Attribute::AttrFontWeight(300)
}

/// `Font.extraBold : Attribute msg` (weight 800)
#[must_use]
pub fn ui_font_extra_bold_<M>() -> Attribute<M> {
    Attribute::AttrFontWeight(800)
}

/// `Font.black : Attribute msg` (weight 900)
#[must_use]
pub fn ui_font_black_<M>() -> Attribute<M> {
    Attribute::AttrFontWeight(900)
}

// Font namespace — decoration

/// `Font.underline : Attribute msg`
#[must_use]
pub fn ui_font_underline_<M>() -> Attribute<M> {
    Attribute::AttrFontUnderline
}

/// `Font.noDecoration : Attribute msg`
#[must_use]
pub fn ui_font_no_decoration_<M>() -> Attribute<M> {
    Attribute::AttrFontDecoration("none".into())
}

/// `Font.lineThrough : Attribute msg`
#[must_use]
pub fn ui_font_line_through_<M>() -> Attribute<M> {
    Attribute::AttrFontDecoration("line-through".into())
}

// Font namespace — spacing (Float → Attr)

/// `Font.letterSpacing : Float -> Attribute msg`
#[must_use]
pub fn ui_font_letter_spacing_<M>(v: f64) -> Attribute<M> {
    Attribute::AttrFontLetterSpacing(v)
}

/// `Font.wordSpacing : Float -> Attribute msg`
#[must_use]
pub fn ui_font_word_spacing_<M>(v: f64) -> Attribute<M> {
    Attribute::AttrFontWordSpacing(v)
}

// Font namespace — text alignment (nullary)

/// `Font.alignLeft : Attribute msg`
#[must_use]
pub fn ui_font_align_left_<M>() -> Attribute<M> {
    Attribute::AttrFontAlign("left".into())
}

/// `Font.alignRight : Attribute msg`
#[must_use]
pub fn ui_font_align_right_<M>() -> Attribute<M> {
    Attribute::AttrFontAlign("right".into())
}

/// `Font.alignCenter : Attribute msg`
#[must_use]
pub fn ui_font_align_center_<M>() -> Attribute<M> {
    Attribute::AttrFontAlign("center".into())
}

/// `Font.center : Attribute msg`
#[must_use]
pub fn ui_font_center_<M>() -> Attribute<M> {
    Attribute::AttrFontAlign("center".into())
}

/// `Font.justify : Attribute msg`
#[must_use]
pub fn ui_font_justify_<M>() -> Attribute<M> {
    Attribute::AttrFontAlign("justify".into())
}

// Font namespace — String constants (NOT Attribute; used as members of List String
// passed to Font.family)

/// `Font.sansSerif : String`
#[must_use]
pub fn ui_font_sans_serif_() -> String {
    "sans-serif".into()
}

/// `Font.serif : String`
#[must_use]
pub fn ui_font_serif_() -> String {
    "serif".into()
}

/// `Font.monospace : String`
#[must_use]
pub fn ui_font_monospace_() -> String {
    "monospace".into()
}

// Font namespace — pseudo-class colour attrs

/// `Font.hoverColor : Color -> Attribute msg`
#[must_use]
pub fn ui_font_hover_color_<M>(c: Color) -> Attribute<M> {
    Attribute::AttrPseudoRule(PseudoClass::Hover, format!("color:{}", c.to_css_rgba()))
}

/// `Font.focusColor : Color -> Attribute msg`
#[must_use]
pub fn ui_font_focus_color_<M>(c: Color) -> Attribute<M> {
    Attribute::AttrPseudoRule(
        PseudoClass::FocusVisible,
        format!("color:{}", c.to_css_rgba()),
    )
}

/// `Font.activeColor : Color -> Attribute msg`
#[must_use]
pub fn ui_font_active_color_<M>(c: Color) -> Attribute<M> {
    Attribute::AttrPseudoRule(PseudoClass::Active, format!("color:{}", c.to_css_rgba()))
}

/// `Font.disabledColor : Color -> Attribute msg`
#[must_use]
pub fn ui_font_disabled_color_<M>(c: Color) -> Attribute<M> {
    Attribute::AttrPseudoRule(PseudoClass::Disabled, format!("color:{}", c.to_css_rgba()))
}

/// `Font.hoverSize : Int -> Attribute msg`
#[must_use]
pub fn ui_font_hover_size_<M>(n: i64) -> Attribute<M> {
    Attribute::AttrPseudoRule(PseudoClass::Hover, format!("font-size:{n}px"))
}

// ── Ipe.Ui.Region ────────────────────────────────────────────────────

/// `Region.mainContent : Attribute msg`
#[must_use]
pub fn ui_region_main_content_<M>() -> Attribute<M> {
    Attribute::AttrDescribe(Description::DescMain)
}

/// `Region.navigation : Attribute msg`
#[must_use]
pub fn ui_region_navigation_<M>() -> Attribute<M> {
    Attribute::AttrDescribe(Description::DescNavigation)
}

/// `Region.footer : Attribute msg`
#[must_use]
pub fn ui_region_footer_<M>() -> Attribute<M> {
    Attribute::AttrDescribe(Description::DescContentInfo)
}

/// `Region.aside : Attribute msg`
#[must_use]
pub fn ui_region_aside_<M>() -> Attribute<M> {
    Attribute::AttrDescribe(Description::DescComplementary)
}

/// `Region.heading : Int -> Attribute msg`
#[must_use]
pub fn ui_region_heading_<M>(n: i64) -> Attribute<M> {
    Attribute::AttrDescribe(Description::DescHeading(HeadingLevel::from_requested(n)))
}

/// `Region.label : String -> Attribute msg`
#[must_use]
pub fn ui_region_label_<M>(s: String) -> Attribute<M> {
    Attribute::AttrDescribe(Description::DescLabel(s))
}

/// `Region.announce : Attribute msg`
#[must_use]
pub fn ui_region_announce_<M>() -> Attribute<M> {
    Attribute::AttrDescribe(Description::DescLivePolite)
}

/// `Region.announceUrgently : Attribute msg`
#[must_use]
pub fn ui_region_announce_urgently_<M>() -> Attribute<M> {
    Attribute::AttrDescribe(Description::DescLiveAssertive)
}

// ── Ui.input + Ui.describe + desc* constructors ────────────────────────────

/// `Ui.input : List (Attribute msg) -> Element msg`
///
/// Creates a real `<input>` void HTML element:
/// `TaggedNode "input" NoDescription attrs []`
#[must_use]
pub fn ui_input_<M>(attrs: Vec<Attribute<M>>) -> Element<M> {
    Element::TaggedNode("input".into(), Description::NoDescription, attrs, vec![])
}

/// `Ui.describe : Description -> Attribute msg`
#[must_use]
pub fn ui_describe_<M>(d: Description) -> Attribute<M> {
    Attribute::AttrDescribe(d)
}

/// The `NoDescription` role — the default carried by every layout builder that
/// takes no explicit ARIA role. Backs the module-local `descNone` in
/// `Ipe/Ui.ipe`.
#[must_use]
pub fn ui_desc_none_() -> Description {
    Description::NoDescription
}

/// The `DescParagraph` role — carried by `Ui.paragraph`. Backs the module-local
/// `descParagraph` in `Ipe/Ui.ipe`.
#[must_use]
pub fn ui_desc_paragraph_() -> Description {
    Description::DescParagraph
}

/// `Ui.descMain : Description`
#[must_use]
pub fn ui_desc_main_() -> Description {
    Description::DescMain
}

/// `Ui.descNavigation : Description`
#[must_use]
pub fn ui_desc_navigation_() -> Description {
    Description::DescNavigation
}

/// `Ui.descContentInfo : Description`
#[must_use]
pub fn ui_desc_content_info_() -> Description {
    Description::DescContentInfo
}

/// `Ui.descComplementary : Description`
#[must_use]
pub fn ui_desc_complementary_() -> Description {
    Description::DescComplementary
}

/// `Ui.descLivePolite : Description`
#[must_use]
pub fn ui_desc_live_polite_() -> Description {
    Description::DescLivePolite
}

/// `Ui.descLiveAssertive : Description`
#[must_use]
pub fn ui_desc_live_assertive_() -> Description {
    Description::DescLiveAssertive
}

/// `Ui.descHeading : Int -> Description`
#[must_use]
pub fn ui_desc_heading_(n: i64) -> Description {
    Description::DescHeading(HeadingLevel::from_requested(n))
}

/// `Ui.descLabel : String -> Description`
#[must_use]
pub fn ui_desc_label_(s: String) -> Description {
    Description::DescLabel(s)
}

/// The `DescSection` role — a document section.
#[must_use]
pub fn ui_desc_section_() -> Description {
    Description::DescSection
}

/// The `DescSectionHeading` role — the heading of the enclosing section.
#[must_use]
pub fn ui_desc_section_heading_() -> Description {
    Description::DescSectionHeading
}

/// The `DescCodeBlock` role — a preformatted block of code.
#[must_use]
pub fn ui_desc_code_block_() -> Description {
    Description::DescCodeBlock
}

/// The `DescCode` role — an inline run of code.
#[must_use]
pub fn ui_desc_code_() -> Description {
    Description::DescCode
}

/// The `DescKbd` role — an inline run of keyboard input.
#[must_use]
pub fn ui_desc_kbd_() -> Description {
    Description::DescKbd
}

/// The `DescTextColumn` role — a column of text blocks.
#[must_use]
pub fn ui_desc_text_column_() -> Description {
    Description::DescTextColumn
}

/// The `DescForm` role — a form that groups input controls.
#[must_use]
pub fn ui_desc_form_() -> Description {
    Description::DescForm
}

/// `Font.whiteSpace Font.Normal`
#[must_use]
pub const fn ui_font_white_space_normal_<M>() -> Attribute<M> {
    Attribute::AttrFontWhiteSpace(WhiteSpace::Normal)
}

/// `Font.whiteSpace Font.NoWrap`
#[must_use]
pub const fn ui_font_white_space_no_wrap_<M>() -> Attribute<M> {
    Attribute::AttrFontWhiteSpace(WhiteSpace::NoWrap)
}

/// `Font.whiteSpace Font.Pre`
#[must_use]
pub const fn ui_font_white_space_pre_<M>() -> Attribute<M> {
    Attribute::AttrFontWhiteSpace(WhiteSpace::Pre)
}

/// `Font.whiteSpace Font.PreWrap`
#[must_use]
pub const fn ui_font_white_space_pre_wrap_<M>() -> Attribute<M> {
    Attribute::AttrFontWhiteSpace(WhiteSpace::PreWrap)
}

/// `Font.whiteSpace Font.PreLine`
#[must_use]
pub const fn ui_font_white_space_pre_line_<M>() -> Attribute<M> {
    Attribute::AttrFontWhiteSpace(WhiteSpace::PreLine)
}

/// `Font.whiteSpace Font.BreakSpaces`
#[must_use]
pub const fn ui_font_white_space_break_spaces_<M>() -> Attribute<M> {
    Attribute::AttrFontWhiteSpace(WhiteSpace::BreakSpaces)
}

/// `Ui.paragraph : List (Attribute msg) -> List (Element msg) -> Element msg`
///
/// Mirrors `paragraph` in `Ipe/Ui.ipe`: a `<p>`-tagged node whose
/// `DescParagraph` role makes its children flow inline.
#[must_use]
pub fn ui_paragraph_<M: Clone>(attrs: Vec<Attribute<M>>, children: Vec<Element<M>>) -> Element<M> {
    Element::TaggedNode("p".to_owned(), Description::DescParagraph, attrs, children)
}

// ── Form ─────────────────────────────────────────────────────────────────────

/// `Ui.onSubmit : (a -> msg) -> Attribute msg`
///
/// Builds `Event::OnForm` directly: the handler `f`'s argument type `T` is
/// recovered by ordinary Rust generic inference from `f`'s own monomorphized
/// signature at the codegen call site (never type-erased at runtime). The
/// Ipe.Web dispatch layer (`HandlerIndex::resolve_form`) decodes the wire
/// `FormData` into `T` via a re-encoded x-www-form-urlencoded round trip
/// (`web::form::decode_form_or_warn` — type-directed per-field coercion, NOT
/// a JSON path), matching the  `json.Unmarshal` semantics at the
/// record-shape level (case-insensitive field-name match, missing field ⇒
/// zero value). `F: Fn(T) -> M + Send + Sync + 'static` is a strictly
/// narrower requirement than an `A: Any` bound.
///
/// `Send + Sync` is NOT automatically satisfied merely because the
/// underlying Ipê closure only captures `'static` enum constructors / owned
/// data — if the codegen's generic first-class-function-value rendering has
/// already boxed the closure as `Box<dyn Fn(T) -> M + Send + 'static>`
/// (deliberately `+Send`-only; most `Fn`-value consumers need no more) and
/// that box is forwarded to this function AS-IS, the call fails: a trait
/// object's auto-trait set is exactly its bound list, so the box is never
/// `Sync` no matter what it captures. The codegen call site
/// (`ipe_backend_rust::emit_expr`'s `KernelFn::UiOnSubmit` arm) closes this
/// by re-wrapping the boxed value in a freshly-declared closure at the call
/// site rather than forwarding the box itself.
#[cfg(any(feature = "web", feature = "wasm-client"))]
pub fn ui_on_submit_<M, T, F>(f: F) -> Attribute<M>
where
    T: serde::de::DeserializeOwned,
    F: Fn(T) -> M + Send + Sync + 'static,
{
    Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnForm(
        "submit".into(),
        std::sync::Arc::new(move |fd: crate::html::FormData| {
            crate::dom::form::decode_form_or_warn::<T>(fd).map(&f)
        }),
    )))
}

/// Non-`live` builds (Ipe.Tui without the HTTP form wire): `Ui.onSubmit` was
/// already inert everywhere before this fix, so this degrades to a
/// structural no-op — not a regression, Tui has no form-submit wire concept.
#[cfg(not(any(feature = "web", feature = "wasm-client")))]
pub fn ui_on_submit_<M, T, F: Fn(T) -> M>(_f: F) -> Attribute<M> {
    Attribute::NoAttribute
}

/// `Ui.onSubmit` BARE-VALUE shape — dispatch a FIXED `msg`, ignoring the
/// submitted `FormData`. The `Ipe.Ui` mirror of
/// [`crate::html::html_on_raw_fixed_`]: the "form fields are
/// already synced into Model via `onInput`/`onChange`; submit just triggers a
/// fixed action" idiom (`Ui.onSubmit DoSignUp` where `DoSignUp : Msg`, or a
/// `let`-bound `m : Msg`). Selected by the lowerer's type-directed
/// `OnFormKind::FixedValue` verdict when the handler's solved type is a
/// non-arrow value, so the codegen never emits a `(m)(_x)` call against a
/// non-callable value (which would be a cargo `E0618`).
///
/// Deliberately does NOT route through `decode_form_or_warn` — there is no
/// payload type to decode into, and a spurious decode failure on a real form's
/// fields would silently swallow the submit. Always fires. `M: Clone` is not a
/// new requirement — every Ipe.Web `Msg` is already `Clone` by construction.
#[cfg(any(feature = "web", feature = "wasm-client"))]
pub fn ui_on_submit_fixed_<M: Clone + Send + Sync + 'static>(msg: M) -> Attribute<M> {
    Attribute::AttrEvent(HtmlAttribute::EventAttr(Event::OnForm(
        "submit".into(),
        std::sync::Arc::new(move |_fd: crate::html::FormData| Some(msg.clone())),
    )))
}

/// Non-`live` builds — same degrade-to-no-op rationale as `ui_on_submit_`.
#[cfg(not(any(feature = "web", feature = "wasm-client")))]
pub fn ui_on_submit_fixed_<M>(_msg: M) -> Attribute<M> {
    Attribute::NoAttribute
}

// ── Nearby attribute builders ────────────────────────────────────────────────

/// `Ui.above : Element msg -> Attribute msg`
#[must_use]
pub fn ui_above_<M: Clone>(elem: Element<M>) -> Attribute<M> {
    Attribute::AttrNearby(Location::Above, elem)
}

/// `Ui.below : Element msg -> Attribute msg`
#[must_use]
pub fn ui_below_<M: Clone>(elem: Element<M>) -> Attribute<M> {
    Attribute::AttrNearby(Location::Below, elem)
}

/// `Ui.onLeft : Element msg -> Attribute msg`
#[must_use]
pub fn ui_on_left_<M: Clone>(elem: Element<M>) -> Attribute<M> {
    Attribute::AttrNearby(Location::OnLeft, elem)
}

/// `Ui.onRight : Element msg -> Attribute msg`
#[must_use]
pub fn ui_on_right_<M: Clone>(elem: Element<M>) -> Attribute<M> {
    Attribute::AttrNearby(Location::OnRight, elem)
}

/// `Ui.inFront : Element msg -> Attribute msg`
#[must_use]
pub fn ui_in_front_<M: Clone>(elem: Element<M>) -> Attribute<M> {
    Attribute::AttrNearby(Location::InFront, elem)
}

/// `Ui.behind : Element msg -> Attribute msg`
#[must_use]
pub fn ui_behind_<M: Clone>(elem: Element<M>) -> Attribute<M> {
    Attribute::AttrNearby(Location::Behind, elem)
}

// ── Breakpoint constants + wrapper ──────────────────────────────────────
//
// These functions support `Ui.breakpoint` / `Ui.mediaQuery` and the named
// `Breakpoint` constants (`Ui.mobile`, `Ui.tablet`, …).
//
// Sanctioned divergence: `Breakpoint` is an
// opaque struct that carries the CSS media-query string; in this Rust port we
// model `Breakpoint` as a plain `String` (the raw CSS query).  Since
// upstream's `breakpoint bp attrs child = mediaQuery (breakpointToQuery bp)
// attrs child` and `breakpointToQuery` is the identity under this typing,
// `ui_breakpoint_` delegates to `ui_media_query_` — both emit the
// `data-ipe-mq-q` / `data-ipe-mq-rules` marker pair consumed by
// `web::style_inject::build_mq` into a ipe-id-scoped
// `<style data-ipe-mq="<sid>">@media <q> { [ipe-id="<sid>"] { <rules> } }</style>`
// block.  (See docs/adr/0003-security-render-and-data-access-invariants.md.)

// NOTE: these six breakpoint constants return a bare `String` with NO `M` in
// the signature, so they take NO type parameter. A phantom `<M>` here would be
// a latent bug — an unconstrained type param can't be inferred and produces
// `E0282: type annotations needed` the moment the value flows into a real
// consumer (`ui_breakpoint_` delegates to `ui_media_query_` rather than
// ignoring its query arg, so it does flow). The codegen emits
// `ui_mobile_()` (no turbofish), so a non-generic fn is exactly what's needed.

/// `Ui.mobile : String` — CSS media query `(max-width: 767px)`.
#[must_use]
pub fn ui_mobile_() -> String {
    "(max-width: 767px)".to_owned()
}

/// `Ui.tablet : String` — CSS media query `(min-width: 768px) and (max-width: 1023px)`.
#[must_use]
pub fn ui_tablet_() -> String {
    "(min-width: 768px) and (max-width: 1023px)".to_owned()
}

/// `Ui.desktop : String` — CSS media query `(min-width: 1024px)`.
#[must_use]
pub fn ui_desktop_() -> String {
    "(min-width: 1024px)".to_owned()
}

/// `Ui.darkMode : String` — CSS media query `(prefers-color-scheme: dark)`.
#[must_use]
pub fn ui_dark_mode_() -> String {
    "(prefers-color-scheme: dark)".to_owned()
}

/// `Ui.lightMode : String` — CSS media query `(prefers-color-scheme: light)`.
#[must_use]
pub fn ui_light_mode_() -> String {
    "(prefers-color-scheme: light)".to_owned()
}

/// `Ui.reducedMotion : String` — CSS media query `(prefers-reduced-motion: reduce)`.
#[must_use]
pub fn ui_reduced_motion_() -> String {
    "(prefers-reduced-motion: reduce)".to_owned()
}

// ── PseudoClass opaque constants + Ui.onPseudo ───────────────────────────
//
// Typed-constant shortcuts so user code can write `Ui.hover` / `Ui.focus`
// without a fully-qualified constructor path — mirrors `Ui.white` / `Ui.black`
// (nullary `Color` constants) rather than the Breakpoint-as-`String`
// divergence, because `PseudoClass` is a genuine registered opaque runtime
// type (`ipe_runtime::ui::element::PseudoClass`), not a stand-in.

/// `Ui.hover : PseudoClass`
#[must_use]
pub fn ui_hover_() -> PseudoClass {
    PseudoClass::Hover
}

/// `Ui.focus : PseudoClass`
#[must_use]
pub fn ui_focus_() -> PseudoClass {
    PseudoClass::Focus
}

/// `Ui.focusVisible : PseudoClass`
#[must_use]
pub fn ui_focus_visible_() -> PseudoClass {
    PseudoClass::FocusVisible
}

/// `Ui.active : PseudoClass`
#[must_use]
pub fn ui_active_() -> PseudoClass {
    PseudoClass::Active
}

/// `Ui.disabled : PseudoClass` — distinct from the unrelated
/// `Attr.disabled : Bool -> Attribute msg` (HTML boolean attribute).
#[must_use]
pub fn ui_disabled_() -> PseudoClass {
    PseudoClass::Disabled
}

/// `Ui.onPseudo : PseudoClass -> List (Attribute msg) -> Attribute msg`
///
/// Generic escape hatch — folds `attrs` into one CSS rules-string via the SAME
/// style-collection logic used for the main `style=""` attribute
/// (`render::block_style_string`: no flex parent, so a `fill` sizes the
/// dimension only), and attaches it as `AttrPseudoRule(pc, css)`. Sub-module helpers (`Background.hoverColor`, `Font.hoverColor`,
/// etc.) build on this exact primitive on the `../ipe` reference; mirrored
/// here so both paths render through the identical collector + the
/// `data-ipe-pc-rules` marker consumed by
/// `ipe_runtime::web::style_inject::build_pc`.
#[must_use]
pub fn ui_on_pseudo_<M: Clone>(pc: PseudoClass, attrs: Vec<Attribute<M>>) -> Attribute<M> {
    Attribute::AttrPseudoRule(pc, super::render::block_style_string(&attrs))
}

/// `Ui.mediaQuery : String -> List (Attribute msg) -> Element msg -> Element msg`
///
/// Raw-CSS-media-query escape hatch (mirrors `../ipe` `Ipe.Ui.ipe`'s
/// `mediaQuery`): attaches to `child` the
/// `data-ipe-mq-q` (the query) + `data-ipe-mq-rules` (the attrs folded
/// through the SAME `render::block_style_string` collector as the inline
/// `style=""` path and `Ui.onPseudo`, so every value-as-data attr inherits
/// the `SafeCssValue` gate; a rule has no flex parent, so a `fill` there sizes
/// the dimension only) marker pair.  The markers land on the child's own
/// attribute list so the breakpoint rule targets the styled node (letting a
/// media rule re-lay-out that node's own contents); a non-attributed leaf
/// child falls back to a marker-carrying wrapper.  The Ipe.Web / Ipe.WebView render
/// pipelines consume the markers post-`assign_ipe_ids` via
/// `web::style_inject::apply_style_injections` (`build_mq`), emitting a
/// ipe-id-scoped `<style data-ipe-mq="<sid>">@media <q> {
/// [ipe-id="<sid>"] { <rules> } }</style>` child — two media queries on the
/// same page cannot cross-contaminate because each rule is keyed to its own
/// ipe-id.
///
/// SECURITY (fail-closed): the query string is attacker-influenceable and is
/// spliced into the `@media … {` position of a raw `<style>` body, so it is
/// gated here — at the sole producer — through
/// [`crate::css_safety::SafeCssMediaQuery`].  A query that fails
/// the gate (ruleset/declaration breakout `{ } ;`, `</` close-tag, `/*`
/// comment, `@import`, script sinks, or any CSS-hex-escaped spelling of
/// those) drops the ENTIRE media-query styling: the child renders unchanged,
/// carrying no marker attrs, so no `<style>` block is ever built.
/// `build_mq`'s `strip_style_close` at the sink stays as defence-in-depth, not
/// the primary gate.
#[must_use]
pub fn ui_media_query_<M: Clone>(
    query: String,
    attrs: Vec<Attribute<M>>,
    child: Element<M>,
) -> Element<M> {
    use crate::css_safety::SafeCssMediaQuery;

    let rules = super::render::block_style_string(&attrs);
    let markers = match SafeCssMediaQuery::parse(&query) {
        Some(q) if !rules.is_empty() => vec![
            Attribute::AttrAttribute("data-ipe-mq-q".to_owned(), q.as_str().to_owned()),
            Attribute::AttrAttribute("data-ipe-mq-rules".to_owned(), rules),
        ],
        // Gate failure or nothing to style → no markers (fail-closed drop of
        // the styling only; the child still renders unchanged).
        _ => vec![],
    };
    attach_markers_to_child(child, markers)
}

/// Attach media-query marker attributes to `child`'s OWN attribute list so the
/// breakpoint rule targets the styled node directly — a media rule can then
/// re-lay-out that node's own contents (e.g. `align-items` on a column). Only
/// `Node` / `TaggedNode` carry attributes; a childless variant (`Text`,
/// `Empty`, `Raw`, `Cells`) has no attribute slot, so it falls back to a
/// marker-carrying wrapper `Node` (the media rule then targets the wrapper,
/// which is the best available anchor for a non-attributed leaf). An empty
/// `markers` (gate failure) leaves the child untouched.
fn attach_markers_to_child<M: Clone>(
    mut child: Element<M>,
    markers: Vec<Attribute<M>>,
) -> Element<M> {
    if markers.is_empty() {
        return child;
    }
    // `Element` owns an iterative destructor, so an attributed node's list is
    // reached through a mutable borrow rather than moved out and rebuilt.
    match &mut child {
        Element::Node(_, attrs, _) | Element::TaggedNode(_, _, attrs, _) => {
            attrs.extend(markers);
            child
        }
        Element::Empty | Element::Text(_) | Element::Raw(_) | Element::Cells(_) => {
            Element::Node(Description::NoDescription, markers, vec![child])
        }
    }
}

/// `Ui.breakpoint : String -> List (Attribute msg) -> Element msg -> Element msg`
///
/// Upstream defines `breakpoint bp attrs child = mediaQuery
/// (breakpointToQuery bp) attrs child`; with `Breakpoint` typed as the raw
/// query `String` in this port, `breakpointToQuery` is the identity — so
/// this is a direct delegation to [`ui_media_query_`] (which also applies
/// the `SafeCssMediaQuery` gate; the named constants above all pass it).
#[must_use]
pub fn ui_breakpoint_<M: Clone>(
    query: String,
    attrs: Vec<Attribute<M>>,
    el: Element<M>,
) -> Element<M> {
    ui_media_query_(query, attrs, el)
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod script_node_tests {
    use super::html_script_node_;
    use crate::css_safety::neutralise_script_close;
    use crate::html::{Html, render_html};

    #[test]
    fn ordinary_script_body_passes_through_verbatim() {
        // A normal JavaScript body with `<`/`>`/`&` is NOT entity-escaped — it
        // is executable code, and escaping would corrupt it.
        let node: Html<()> = html_script_node_("console.log(1 < 2 && 3 > 2);".to_owned());
        let html = render_html(&node);
        assert_eq!(html, "<script>console.log(1 < 2 && 3 > 2);</script>");
    }

    #[test]
    fn close_tag_breakout_is_neutralised_case_insensitively() {
        // SECURITY: a literal `</script` in the body would end the element early
        // and let following bytes become live markup. It is split at
        // construction so no `</script` byte run survives, case-insensitively.
        assert_eq!(
            neutralise_script_close("a</script><img src=x onerror=alert(1)>"),
            "a<\\/script><img src=x onerror=alert(1)>"
        );
        // Case-insensitive match; the neutralised run is emitted as the fixed
        // lowercase literal (the exact casing of the code text is irrelevant —
        // only that no `</script` byte run of ANY case survives).
        assert_eq!(neutralise_script_close("b</SCRIPT >"), "b<\\/script >");
        // No surviving `</script` (any case) after neutralisation.
        let out = neutralise_script_close("x</script>y</ScRiPt>z");
        assert!(!out.to_ascii_lowercase().contains("</script"));

        // Non-breakout text (incl. multibyte UTF-8) is untouched.
        assert_eq!(neutralise_script_close("λ = 1; // ok"), "λ = 1; // ok");
    }

    #[test]
    fn script_node_renders_neutralised_breakout() {
        let node: Html<()> = html_script_node_("</script><b>x</b>".to_owned());
        let html = render_html(&node);
        assert!(
            !html.to_ascii_lowercase().contains("</script><b>"),
            "the breakout must not survive into the render: {html}"
        );
        assert!(html.starts_with("<script>") && html.ends_with("</script>"));
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tag_gate_tests {
    use super::{
        Description, Element, html_node_, html_raw_node_, html_script_node_, html_style_node_,
        html_text_node_, ui_html_, ui_tagged_node_,
    };
    use crate::html::{Attribute as HtmlAttribute, Html, render_html};
    use crate::ui::render::ui_layout;

    /// Every tag the shared gate refuses, in more than one ASCII case.
    const REFUSED_WITH_TEXT: [&str; 9] = [
        "script",
        "SCRIPT",
        "Script",
        "style",
        "STYLE",
        "sTyLe",
        "plaintext",
        "PLAINTEXT",
        "div><script",
    ];

    fn ui_render(el: Element<()>) -> String {
        render_html(&ui_layout(vec![], el))
    }

    /// SECURITY: `Html.node` (and so `Html.script`) refuses a raw-text or
    /// executable element whose body is data: the result is empty text, never
    /// an element.
    #[test]
    fn html_node_refuses_every_denied_tag() {
        for tag in REFUSED_WITH_TEXT {
            let node: Html<()> = html_node_(
                tag.to_owned(),
                vec![],
                vec![html_text_node_("alert(document.cookie)".to_owned())],
            );
            assert!(
                matches!(&node, Html::HText(t) if t.is_empty()),
                "<{tag}>: {node:?}"
            );
            assert_eq!(render_html(&node), "", "<{tag}>");
        }
        // An empty `<script>` is not started, so a later patch or its `src`
        // could run: refused too.
        let empty: Html<()> = html_node_(
            "script".to_owned(),
            vec![HtmlAttribute::Attr("src".into(), "/x.js".into())],
            vec![],
        );
        assert!(
            matches!(&empty, Html::HText(t) if t.is_empty()),
            "{empty:?}"
        );
        // A child element is not trusted raw markup either.
        let nested: Html<()> = html_node_(
            "style".to_owned(),
            vec![],
            vec![html_node_("b".to_owned(), vec![], vec![])],
        );
        assert!(
            matches!(&nested, Html::HText(t) if t.is_empty()),
            "{nested:?}"
        );
    }

    /// Controls: trusted raw bodies, `styleNode`, `unsafeScript`, an empty
    /// `<style>` and ordinary elements are still built and rendered.
    #[test]
    fn html_node_admits_trusted_bodies_and_ordinary_tags() {
        let raw_script: Html<()> = html_node_(
            "script".to_owned(),
            vec![],
            vec![html_raw_node_("x()".to_owned())],
        );
        assert_eq!(render_html(&raw_script), "<script>x()</script>");
        let unsafe_script: Html<()> = html_script_node_("y()".to_owned());
        assert_eq!(render_html(&unsafe_script), "<script>y()</script>");
        let style: Html<()> = html_style_node_(vec![], ".a{color:red}".to_owned());
        assert_eq!(render_html(&style), "<style>.a{color:red}</style>");
        let empty_style: Html<()> = html_node_("style".to_owned(), vec![], vec![]);
        assert_eq!(render_html(&empty_style), "<style></style>");
        for tag in ["div", "p", "title", "textarea", "noscript", "template"] {
            let node: Html<()> = html_node_(
                tag.to_owned(),
                vec![],
                vec![html_text_node_("<b>".to_owned())],
            );
            let escaped = crate::escape::html_text("<b>");
            assert_eq!(render_html(&node), format!("<{tag}>{escaped}</{tag}>"));
        }
    }

    /// SECURITY: `Ui.taggedNode` refuses the same tags: a text, element or
    /// `Ui.html (Html.text ..)` body builds `Element::Empty` and renders no
    /// element.
    #[test]
    fn ui_tagged_node_refuses_every_denied_tag() {
        let bodies: [fn() -> Vec<Element<()>>; 3] = [
            || vec![Element::Text("alert(document.cookie)".into())],
            || {
                vec![ui_html_(html_text_node_(
                    "alert(document.cookie)".to_owned(),
                ))]
            },
            || vec![Element::Node(Description::NoDescription, vec![], vec![])],
        ];
        for tag in REFUSED_WITH_TEXT {
            for body in &bodies {
                let el =
                    ui_tagged_node_(tag.to_owned(), Description::NoDescription, vec![], body());
                assert!(matches!(el, Element::Empty), "<{tag}>: {el:?}");
                let out = ui_render(el);
                assert!(
                    !out.to_ascii_lowercase().contains("<script"),
                    "<{tag}>: {out}"
                );
                assert!(!out.contains("alert"), "<{tag}>: {out}");
            }
        }
        let empty = ui_tagged_node_::<()>(
            "script".to_owned(),
            Description::NoDescription,
            vec![],
            vec![],
        );
        assert!(matches!(empty, Element::Empty), "{empty:?}");
    }

    /// Control: a `Ui.html` child over trusted raw markup is admitted.
    #[test]
    fn ui_tagged_node_admits_a_trusted_raw_body() {
        let el = ui_tagged_node_::<()>(
            "script".to_owned(),
            Description::NoDescription,
            vec![],
            vec![ui_html_(html_raw_node_("x()".to_owned()))],
        );
        assert!(
            matches!(&el, Element::TaggedNode(t, ..) if t == "script"),
            "{el:?}"
        );
        let out = ui_render(el);
        assert!(
            out.contains("<script") && out.contains(">x()</script>"),
            "{out}"
        );
    }

    /// SECURITY: an `Element::TaggedNode` that reached the tree without the
    /// constructor is refused again when `Ipe.Ui` lowers it to `Html`.
    #[test]
    fn ui_render_refuses_a_hand_built_script_element() {
        let el: Element<()> = Element::TaggedNode(
            "script".into(),
            Description::NoDescription,
            vec![],
            vec![Element::Text("alert(document.cookie)".into())],
        );
        // The lowered tree itself holds no script element and no script
        // text: the render sink refuses the element again, so asserting on the
        // rendered string alone would pass without the lowering gate.
        let lowered = ui_layout(vec![], el.clone());
        assert!(!has_element(&lowered, "script"), "{lowered:?}");
        assert!(!has_text(&lowered, "alert"), "{lowered:?}");
        assert!(has_text_exactly(&lowered, ""), "{lowered:?}");
        let out = ui_render(el);
        assert!(!out.contains("<script"), "{out}");
        assert!(!out.contains("alert"), "{out}");
    }

    /// True when `node` or a descendant is an element named `tag` (any case).
    fn has_element(node: &Html<()>, tag: &str) -> bool {
        match node {
            Html::HElement(t, _, kids) => {
                t.eq_ignore_ascii_case(tag) || kids.iter().any(|k| has_element(k, tag))
            }
            Html::HText(_) | Html::HRaw(_) => false,
        }
    }

    /// True when `node` or a descendant is a text or raw node holding `needle`.
    fn has_text(node: &Html<()>, needle: &str) -> bool {
        match node {
            Html::HElement(_, _, kids) => kids.iter().any(|k| has_text(k, needle)),
            Html::HText(t) | Html::HRaw(t) => t.contains(needle),
        }
    }

    /// True when `node` or a descendant is a text node equal to `text`.
    fn has_text_exactly(node: &Html<()>, text: &str) -> bool {
        match node {
            Html::HElement(_, _, kids) => kids.iter().any(|k| has_text_exactly(k, text)),
            Html::HText(t) => t == text,
            Html::HRaw(_) => false,
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod link_tests {
    use super::ui_link_;
    use super::{Attribute, Element};

    fn link_attrs(el: &Element<()>) -> &[Attribute<()>] {
        let Element::TaggedNode(tag, _, attrs, _) = el else {
            unreachable!("ui_link_ builds a TaggedNode");
        };
        assert_eq!(tag, "a");
        attrs
    }

    fn has_attr(attrs: &[Attribute<()>], name: &str, value: &str) -> bool {
        attrs
            .iter()
            .any(|a| matches!(a, Attribute::AttrAttribute(n, v) if n == name && v == value))
    }

    fn rel_count(attrs: &[Attribute<()>]) -> usize {
        attrs
            .iter()
            .filter(|a| matches!(a, Attribute::AttrAttribute(n, _) if n == "rel"))
            .count()
    }

    #[test]
    fn blank_target_link_gets_noopener_noreferrer() {
        // The untrusted-markdown new-tab link (Ipe/Markdown.ipe LinkSpan): a
        // `target="_blank"` over an attacker-chosen href must sever the opener.
        let el: Element<()> = ui_link_(
            vec![Attribute::AttrAttribute("target".into(), "_blank".into())],
            "https://attacker.example/".into(),
            Element::Text("label".into()),
        );
        let attrs = link_attrs(&el);
        assert!(
            has_attr(attrs, "rel", "noopener noreferrer"),
            "a _blank link must carry rel=noopener noreferrer: {attrs:?}"
        );
    }

    #[test]
    fn same_tab_link_gets_no_rel() {
        // No `target="_blank"` -> the link stays in the same tab, no opener to
        // sever, so no rel is fabricated.
        let el: Element<()> = ui_link_(
            vec![],
            "https://example.com/".into(),
            Element::Text("label".into()),
        );
        assert_eq!(rel_count(link_attrs(&el)), 0);
    }

    #[test]
    fn caller_supplied_rel_is_not_duplicated() {
        // A call site that already sets its own rel keeps it verbatim; the sink
        // never emits a second, conflicting `rel`.
        let el: Element<()> = ui_link_(
            vec![
                Attribute::AttrAttribute("target".into(), "_blank".into()),
                Attribute::AttrAttribute("rel".into(), "noopener".into()),
            ],
            "https://example.com/".into(),
            Element::Text("label".into()),
        );
        let attrs = link_attrs(&el);
        assert_eq!(rel_count(attrs), 1);
        assert!(has_attr(attrs, "rel", "noopener"));
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod white_space_helper_tests {
    use super::{
        ui_font_white_space_break_spaces_, ui_font_white_space_no_wrap_,
        ui_font_white_space_normal_, ui_font_white_space_pre_, ui_font_white_space_pre_line_,
        ui_font_white_space_pre_wrap_,
    };
    use crate::ui::element::{Attribute, WhiteSpace};

    /// Each `Font.whiteSpace` helper carries a distinct keyword and together
    /// they cover `WhiteSpace::ALL` in order (CI job `test`).
    #[test]
    fn white_space_helpers_map_one_to_one_onto_all() {
        let helpers: [Attribute<()>; 6] = [
            ui_font_white_space_normal_(),
            ui_font_white_space_no_wrap_(),
            ui_font_white_space_pre_(),
            ui_font_white_space_pre_wrap_(),
            ui_font_white_space_pre_line_(),
            ui_font_white_space_break_spaces_(),
        ];
        let carried: Vec<WhiteSpace> = helpers
            .iter()
            .filter_map(|a| match a {
                Attribute::AttrFontWhiteSpace(ws) => Some(*ws),
                _ => None,
            })
            .collect();
        assert_eq!(carried, WhiteSpace::ALL.to_vec());
    }
}

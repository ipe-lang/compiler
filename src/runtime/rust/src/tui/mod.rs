//! Ipe.Terminal — terminal (ANSI cell) backend for the Rust target.
//!
//! TEA-shaped (`Tui.tea cfg`): `view : Model -> Cells msg` lowered
//! to ANSI cells via the structured `Element<Msg>` tree inside `CellsView<M>`.

pub mod app;
pub mod cell;
pub mod diff; // accessed qualified (tui::diff::diff) — `diff` collides with live's
pub mod focus; // input registry + focusable model + key editing
pub mod key;
pub mod layout; // structured Element → ANSI cells
pub use app::{tui_app, tui_app_ui};
pub use cell::*;

use crate::color::{AnsiColor, Color};
use crate::ui::element::{Attribute, Element, HAlign};

/// A cell-native view attribute: the ONLY attributes a terminal `Screen` view
/// can carry.  Distinct from the DOM `ui::Attribute` — DOM-only affordances
/// (`onClick`, `scrollbars`, `inFront`, …) have no `TuiAttr` variant, so they
/// are unnameable in a terminal view rather than silently dropped at render.
///
/// Each variant translates to the honorable `ui::Attribute` the cell renderer
/// already interprets (`translate`), so the layout engine is unchanged.
#[derive(Clone, Debug, PartialEq)]
pub enum TuiAttr<M> {
    /// Gap between children, in whole terminal cells.
    Spacing(i64),
    /// Inner padding on all four sides, in whole terminal cells.
    Padding(i64),
    /// Horizontal alignment of the node's content.
    Align(HAlign),
    /// Bold text.
    Bold,
    /// Underlined text.
    Underline,
    /// Dim (faint) text.
    Dim,
    /// Reverse video (swap foreground and background).
    Reverse,
    /// Foreground (text) colour, from the terminal palette.
    FgColor(AnsiColor),
    /// Background colour, from the terminal palette.
    BgColor(AnsiColor),
    /// Uninhabited-in-practice marker carrying the message type so `TuiAttr`
    /// stays parametric in `M` even though no current variant holds an `M`.
    _Msg(core::marker::PhantomData<M>),
}

crate::stringify::show_row!("TuiAttribute", Internals, [M] TuiAttr<M>, |_| "<Ipe.Ui.Tui.Attribute>".to_owned());

impl<M> TuiAttr<M> {
    /// Lower a cell-native attribute to the honorable `ui::Attribute` the cell
    /// layout engine reads.  `bold` maps to a font weight the renderer treats
    /// as bold (`>= 600`).
    fn translate(self) -> Option<Attribute<M>> {
        match self {
            TuiAttr::Spacing(n) => Some(Attribute::AttrSpacing(n)),
            TuiAttr::Padding(n) => Some(Attribute::AttrPadding(n, n, n, n)),
            TuiAttr::Align(h) => Some(Attribute::AttrAlignX(h)),
            TuiAttr::Bold => Some(Attribute::AttrFontWeight(700)),
            TuiAttr::Underline => Some(Attribute::AttrFontUnderline),
            TuiAttr::Dim => Some(Attribute::AttrFontDecoration("dim".to_owned())),
            TuiAttr::Reverse => Some(Attribute::AttrFontDecoration("reverse".to_owned())),
            TuiAttr::FgColor(c) => Some(term_fg_attr(c)),
            TuiAttr::BgColor(c) => Some(term_bg_attr(c)),
            TuiAttr::_Msg(_) => None,
        }
    }
}

/// Lower a list of cell-native attributes to the honorable `ui::Attribute` set.
fn translate_attrs<M>(attrs: Vec<TuiAttr<M>>) -> Vec<Attribute<M>> {
    attrs.into_iter().filter_map(TuiAttr::translate).collect()
}

/// Lower a palette foreground colour to a renderer attribute. A named colour is
/// carried as a decoration string (`"fg:31"`) so the terminal `sgr` path emits
/// the portable SGR palette code; a truecolour takes the 24-bit `AttrFontColor`
/// path the renderer already interprets.
///
/// The terminal palette a program can name (`Ipe.Color.Ansi`) is exactly the
/// `Named` / `Default` / `Rgb` shapes; an `Indexed` entry is unreachable from
/// that surface, so it fails closed to the terminal default rather than
/// fabricating a channel that cannot round-trip through the palette decoration.
fn term_fg_attr<M>(c: AnsiColor) -> Attribute<M> {
    term_color_attr(c, true)
}

/// Lower a palette background colour to a renderer attribute (see `term_fg_attr`).
fn term_bg_attr<M>(c: AnsiColor) -> Attribute<M> {
    term_color_attr(c, false)
}

/// Shared foreground/background lowering. `fg` selects the palette-code family
/// (`3x`/`9x` vs `4x`/`10x`) and the truecolour attribute channel.
fn term_color_attr<M>(c: AnsiColor, fg: bool) -> Attribute<M> {
    match c {
        AnsiColor::Rgb(r, g, b) if fg => Attribute::AttrFontColor(Color::rgb(r, g, b)),
        AnsiColor::Rgb(r, g, b) => Attribute::AttrBgColor(Color::rgb(r, g, b)),
        palette => {
            let default = if fg { 39 } else { 49 };
            let prefix = if fg { "fg" } else { "bg" };
            let code = palette.named_sgr_code(fg).unwrap_or(default);
            Attribute::AttrFontDecoration(format!("{prefix}:{code}"))
        }
    }
}

/// Newtype wrapper: the Tui-only view type `Screen msg`.
///
/// Emitted code produces a `CellsView<M>` from every `Ipe.Ui.Tui.*`
/// builder call; `tui_app_ui` unwraps the inner `Element<M>` and passes it
/// to the ANSI-cell renderer.  The wrapper is the compile-time gate that
/// prevents Web-only `Element`-producing constructs from appearing inside a
/// `view : Model -> Screen Msg` function.
#[derive(Clone, Debug, PartialEq)]
pub struct CellsView<M>(pub Element<M>);

crate::stringify::show_row!("Cells", Internals, [M] CellsView<M>, |_| "<Ipe.Ui.Cells>".to_owned());

impl<M> CellsView<M> {
    /// Wrap an existing `Element` as a `Cells` view.
    pub fn new(inner: Element<M>) -> Self {
        Self(inner)
    }

    /// Consume the wrapper and return the inner `Element`.
    pub fn into_element(self) -> Element<M> {
        self.0
    }
}

// ── Ipe.Ui.Cells builder functions ───────────────────────────────────────────
// Each delegates to the corresponding `ui_*_` helper and wraps the result in
// `CellsView`.  The wrapper is the only compile-time evidence that a value
// came from a `Cells`-producing builder, making Web-only builders (which return
// bare `Element<M>`) an immediate type error inside a `view : M -> Cells Msg`
// function.

/// `Ipe.Ui.Cells.none : Cells msg`
#[must_use]
pub fn cells_none_<M>() -> CellsView<M> {
    CellsView::new(Element::Empty)
}

/// `Ipe.Ui.Cells.text : String -> Cells msg`
#[must_use]
pub fn cells_text_<M>(s: String) -> CellsView<M> {
    CellsView::new(Element::Text(s))
}

/// `Ipe.Ui.Cells.cells : List (List Char) -> Cells msg`
#[must_use]
pub fn cells_cells_<M>(grid: Vec<Vec<char>>) -> CellsView<M> {
    CellsView::new(Element::Cells(grid))
}

/// `Ipe.Ui.Tui.el : List (Attribute msg) -> Screen msg -> Screen msg`
#[must_use]
pub fn cells_el_<M: Clone>(attrs: Vec<TuiAttr<M>>, child: CellsView<M>) -> CellsView<M> {
    use crate::ui::element::Description;
    CellsView::new(Element::Node(
        Description::NoDescription,
        translate_attrs(attrs),
        vec![child.into_element()],
    ))
}

/// `Ipe.Ui.Tui.row : List (Attribute msg) -> List (Screen msg) -> Screen msg`
#[must_use]
pub fn cells_row_<M: Clone>(attrs: Vec<TuiAttr<M>>, children: Vec<CellsView<M>>) -> CellsView<M> {
    use crate::ui::element::Description;
    let mut full = Vec::with_capacity(attrs.len() + 1);
    full.push(Attribute::AttrStyle("__row".to_owned(), "true".to_owned()));
    full.extend(translate_attrs(attrs));
    let elems: Vec<Element<M>> = children.into_iter().map(CellsView::into_element).collect();
    CellsView::new(Element::Node(Description::NoDescription, full, elems))
}

/// `Ipe.Ui.Tui.column : List (Attribute msg) -> List (Screen msg) -> Screen msg`
#[must_use]
pub fn cells_column_<M: Clone>(
    attrs: Vec<TuiAttr<M>>,
    children: Vec<CellsView<M>>,
) -> CellsView<M> {
    use crate::ui::element::Description;
    let mut full = Vec::with_capacity(attrs.len() + 1);
    full.push(Attribute::AttrStyle("__col".to_owned(), "true".to_owned()));
    full.extend(translate_attrs(attrs));
    let elems: Vec<Element<M>> = children.into_iter().map(CellsView::into_element).collect();
    CellsView::new(Element::Node(Description::NoDescription, full, elems))
}

// ── Cell-native attribute builders (`Ipe.Ui.Tui.Attribute`) ───────────────
// Each returns a `TuiAttr<M>` — the terminal-honorable attribute surface.

/// `Ipe.Ui.Tui.spacing : Int -> Attribute msg` — gap between children, cells.
#[must_use]
pub fn tui_spacing_<M>(n: i64) -> TuiAttr<M> {
    TuiAttr::Spacing(n)
}

/// `Ipe.Ui.Tui.padding : Int -> Attribute msg` — inner padding, cells.
#[must_use]
pub fn tui_padding_<M>(n: i64) -> TuiAttr<M> {
    TuiAttr::Padding(n)
}

/// `Ipe.Ui.Tui.alignLeft : Attribute msg`
#[must_use]
pub fn tui_align_left_<M>() -> TuiAttr<M> {
    TuiAttr::Align(HAlign::AlignLeft)
}

/// `Ipe.Ui.Tui.alignRight : Attribute msg`
#[must_use]
pub fn tui_align_right_<M>() -> TuiAttr<M> {
    TuiAttr::Align(HAlign::AlignRight)
}

/// `Ipe.Ui.Tui.center : Attribute msg`
#[must_use]
pub fn tui_center_<M>() -> TuiAttr<M> {
    TuiAttr::Align(HAlign::CenterX)
}

/// `Ipe.Ui.Tui.bold : Attribute msg`
#[must_use]
pub fn tui_bold_<M>() -> TuiAttr<M> {
    TuiAttr::Bold
}

/// `Ipe.Ui.Tui.underline : Attribute msg`
#[must_use]
pub fn tui_underline_<M>() -> TuiAttr<M> {
    TuiAttr::Underline
}

/// `Ipe.Ui.Tui.dim : Attribute msg` — faint text.
#[must_use]
pub fn tui_dim_<M>() -> TuiAttr<M> {
    TuiAttr::Dim
}

/// `Ipe.Ui.Tui.reverse : Attribute msg` — reverse video.
#[must_use]
pub fn tui_reverse_<M>() -> TuiAttr<M> {
    TuiAttr::Reverse
}

/// `Ipe.Ui.Tui.color : AnsiColor -> Attribute msg` — foreground colour.
#[must_use]
pub fn tui_color_<M>(c: AnsiColor) -> TuiAttr<M> {
    TuiAttr::FgColor(c)
}

/// `Ipe.Ui.Tui.bg : AnsiColor -> Attribute msg` — background colour.
#[must_use]
pub fn tui_bg_<M>(c: AnsiColor) -> TuiAttr<M> {
    TuiAttr::BgColor(c)
}

// ── Ipe.Color.Ansi palette constructors ───────────────────────────────────────

/// The sixteen named palette entries carry their SGR index (`0..=15`): the
/// standard eight `0..=7` (`black`..`white`) and the bright eight `8..=15`
/// (`brightBlack`..`brightWhite`). `AnsiColor::named_sgr_code` maps each back to
/// the identical portable SGR code the palette rendered before.
/// `Ipe.Color.Ansi.black : AnsiColor`
#[must_use]
pub const fn term_color_black_() -> AnsiColor {
    AnsiColor::Named(0)
}
/// `Ipe.Color.Ansi.red : AnsiColor`
#[must_use]
pub const fn term_color_red_() -> AnsiColor {
    AnsiColor::Named(1)
}
/// `Ipe.Color.Ansi.green : AnsiColor`
#[must_use]
pub const fn term_color_green_() -> AnsiColor {
    AnsiColor::Named(2)
}
/// `Ipe.Color.Ansi.yellow : AnsiColor`
#[must_use]
pub const fn term_color_yellow_() -> AnsiColor {
    AnsiColor::Named(3)
}
/// `Ipe.Color.Ansi.blue : AnsiColor`
#[must_use]
pub const fn term_color_blue_() -> AnsiColor {
    AnsiColor::Named(4)
}
/// `Ipe.Color.Ansi.magenta : AnsiColor`
#[must_use]
pub const fn term_color_magenta_() -> AnsiColor {
    AnsiColor::Named(5)
}
/// `Ipe.Color.Ansi.cyan : AnsiColor`
#[must_use]
pub const fn term_color_cyan_() -> AnsiColor {
    AnsiColor::Named(6)
}
/// `Ipe.Color.Ansi.white : AnsiColor`
#[must_use]
pub const fn term_color_white_() -> AnsiColor {
    AnsiColor::Named(7)
}
/// `Ipe.Color.Ansi.brightBlack : AnsiColor`
#[must_use]
pub const fn term_color_bright_black_() -> AnsiColor {
    AnsiColor::Named(8)
}
/// `Ipe.Color.Ansi.brightRed : AnsiColor`
#[must_use]
pub const fn term_color_bright_red_() -> AnsiColor {
    AnsiColor::Named(9)
}
/// `Ipe.Color.Ansi.brightGreen : AnsiColor`
#[must_use]
pub const fn term_color_bright_green_() -> AnsiColor {
    AnsiColor::Named(10)
}
/// `Ipe.Color.Ansi.brightYellow : AnsiColor`
#[must_use]
pub const fn term_color_bright_yellow_() -> AnsiColor {
    AnsiColor::Named(11)
}
/// `Ipe.Color.Ansi.brightBlue : AnsiColor`
#[must_use]
pub const fn term_color_bright_blue_() -> AnsiColor {
    AnsiColor::Named(12)
}
/// `Ipe.Color.Ansi.brightMagenta : AnsiColor`
#[must_use]
pub const fn term_color_bright_magenta_() -> AnsiColor {
    AnsiColor::Named(13)
}
/// `Ipe.Color.Ansi.brightCyan : AnsiColor`
#[must_use]
pub const fn term_color_bright_cyan_() -> AnsiColor {
    AnsiColor::Named(14)
}
/// `Ipe.Color.Ansi.brightWhite : AnsiColor`
#[must_use]
pub const fn term_color_bright_white_() -> AnsiColor {
    AnsiColor::Named(15)
}
/// `Ipe.Color.Ansi.default : AnsiColor`
#[must_use]
pub const fn term_color_default_() -> AnsiColor {
    AnsiColor::Default
}
/// `Ipe.Color.Ansi.rgb : Int -> Int -> Int -> AnsiColor` — a 24-bit truecolour.
/// Channels are clamped to 0-255.
#[must_use]
pub fn term_color_rgb_(r: i64, g: i64, b: i64) -> AnsiColor {
    AnsiColor::Rgb(clamp_channel(r), clamp_channel(g), clamp_channel(b))
}
/// `Ipe.Color.Ansi.rgba : Int -> Int -> Int -> Float -> AnsiColor`. The alpha is
/// accepted for surface parity with `Ui.rgba`; a terminal cell has no alpha, so
/// the colour is applied opaque.
#[must_use]
pub fn term_color_rgba_(r: i64, g: i64, b: i64, _a: f64) -> AnsiColor {
    AnsiColor::Rgb(clamp_channel(r), clamp_channel(g), clamp_channel(b))
}

/// Clamp an `Int` colour channel into the representable `0..=255` byte range,
/// widened to the `i64` the shared `AnsiColor::Rgb` carrier holds.
fn clamp_channel(v: i64) -> i64 {
    v.clamp(0, 255)
}

// ── Ipe.Ui.Cli line-oriented view surface ────────────────────────────────

/// A line-native view attribute: the ONLY styles a `Lines` view can carry.
/// Distinct from both the DOM `ui::Attribute` and the cell-native `TuiAttr` —
/// 2D geometry (`spacing`, `padding`, alignment) has no `CliAttr` variant, so
/// it is unnameable in a `Lines` view rather than silently dropped.
#[derive(Clone, Debug, PartialEq)]
pub enum CliAttr<M> {
    /// Bold text.
    Bold,
    /// Underlined text.
    Underline,
    /// Dim (faint) text.
    Dim,
    /// Reverse video (swap foreground and background).
    Reverse,
    /// Foreground (text) colour, from the terminal palette.
    FgColor(AnsiColor),
    /// Background colour, from the terminal palette.
    BgColor(AnsiColor),
    /// Marker carrying the message type so `CliAttr` stays parametric in `M`.
    _Msg(core::marker::PhantomData<M>),
}

crate::stringify::show_row!("CliAttribute", Internals, [M] CliAttr<M>, |_| "<Ipe.Ui.Cli.Attribute>".to_owned());

impl<M> CliAttr<M> {
    /// Lower a line-native attribute to the honorable `ui::Attribute` the cell
    /// layout engine reads. A `Lines` view is rendered by the same styled-run
    /// engine as `Screen`, restricted to one column of lines.
    fn translate(self) -> Option<Attribute<M>> {
        match self {
            CliAttr::Bold => Some(Attribute::AttrFontWeight(700)),
            CliAttr::Underline => Some(Attribute::AttrFontUnderline),
            CliAttr::Dim => Some(Attribute::AttrFontDecoration("dim".to_owned())),
            CliAttr::Reverse => Some(Attribute::AttrFontDecoration("reverse".to_owned())),
            CliAttr::FgColor(c) => Some(term_fg_attr(c)),
            CliAttr::BgColor(c) => Some(term_bg_attr(c)),
            CliAttr::_Msg(_) => None,
        }
    }
}

fn translate_cli_attrs<M>(attrs: Vec<CliAttr<M>>) -> Vec<Attribute<M>> {
    attrs.into_iter().filter_map(CliAttr::translate).collect()
}

/// Newtype wrapper: the Cli-only line-oriented view type `Lines msg`.
///
/// A `Lines` view is a vertical stack of styled lines. It reuses the cell
/// layout engine (as a single column) so styling renders identically to a
/// `Screen`, but its builder surface admits only line-scoped attributes.
#[derive(Clone, Debug, PartialEq)]
pub struct LinesView<M>(pub Element<M>);

crate::stringify::show_row!("CliLines", Internals, [M] LinesView<M>, |_| "<Ipe.Ui.Cli.Lines>".to_owned());

impl<M> LinesView<M> {
    /// Wrap an existing `Element` as a `Lines` view.
    pub fn new(inner: Element<M>) -> Self {
        Self(inner)
    }

    /// Consume the wrapper and return the inner `Element`.
    pub fn into_element(self) -> Element<M> {
        self.0
    }
}

/// `Ipe.Ui.Cli.none : Lines msg`
#[must_use]
pub fn cli_none_<M>() -> LinesView<M> {
    LinesView::new(Element::Empty)
}

/// `Ipe.Ui.Cli.text : String -> Lines msg` — one unstyled line.
#[must_use]
pub fn cli_text_<M>(s: String) -> LinesView<M> {
    LinesView::new(Element::Text(s))
}

/// `Ipe.Ui.Cli.line : List (Attribute msg) -> String -> Lines msg`
#[must_use]
pub fn cli_line_<M: Clone>(attrs: Vec<CliAttr<M>>, s: String) -> LinesView<M> {
    use crate::ui::element::Description;
    LinesView::new(Element::Node(
        Description::NoDescription,
        translate_cli_attrs(attrs),
        vec![Element::Text(s)],
    ))
}

/// `Ipe.Ui.Cli.lines : List (Lines msg) -> Lines msg` — stack vertically.
#[must_use]
pub fn cli_lines_<M: Clone>(children: Vec<LinesView<M>>) -> LinesView<M> {
    use crate::ui::element::Description;
    let attrs = vec![Attribute::AttrStyle("__col".to_owned(), "true".to_owned())];
    let elems: Vec<Element<M>> = children.into_iter().map(LinesView::into_element).collect();
    LinesView::new(Element::Node(Description::NoDescription, attrs, elems))
}

/// `Ipe.Ui.Cli.bold : Attribute msg`
#[must_use]
pub fn cli_bold_<M>() -> CliAttr<M> {
    CliAttr::Bold
}
/// `Ipe.Ui.Cli.underline : Attribute msg`
#[must_use]
pub fn cli_underline_<M>() -> CliAttr<M> {
    CliAttr::Underline
}
/// `Ipe.Ui.Cli.dim : Attribute msg` — faint text.
#[must_use]
pub fn cli_dim_<M>() -> CliAttr<M> {
    CliAttr::Dim
}
/// `Ipe.Ui.Cli.reverse : Attribute msg` — reverse video.
#[must_use]
pub fn cli_reverse_<M>() -> CliAttr<M> {
    CliAttr::Reverse
}
/// `Ipe.Ui.Cli.color : AnsiColor -> Attribute msg` — foreground colour.
#[must_use]
pub fn cli_color_<M>(c: AnsiColor) -> CliAttr<M> {
    CliAttr::FgColor(c)
}
/// `Ipe.Ui.Cli.bg : AnsiColor -> Attribute msg` — background colour.
#[must_use]
pub fn cli_bg_<M>(c: AnsiColor) -> CliAttr<M> {
    CliAttr::BgColor(c)
}

/// Render a `Lines` view to the styled terminal string a line-oriented `Cli.tea`
/// writes to stdout.
///
/// A line-oriented surface occupies exactly the height of its own stacked lines,
/// so the frame is sized to the view's content height rather than the full
/// terminal window — a `Screen` paints a fixed rectangle, a `Lines` view paints
/// only its lines. Width still comes from the terminal so styled runs reflow to
/// the visible columns. The returned string carries no forced trailing newline:
/// the console loop owns the single terminating newline, matching the
/// no-trailing-newline write contract of the string-returning view it replaces.
#[must_use]
pub fn render_lines_view<M: Clone>(view: LinesView<M>) -> String {
    let element = view.into_element();
    let cols = match crossterm::terminal::size() {
        Ok((w, _)) if w > 0 => w as usize,
        _ => 80,
    };
    // Probe pass measures the content height; the paint pass sizes the frame to
    // exactly that height so no blank padding rows follow the last line.
    let content_h = layout::element_to_cells_height(&element, cols);
    let frame = layout::element_to_cells(&element, cols, content_h);
    frame.trim_end_matches('\n').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dim_and_reverse_translate_to_decoration_attributes() {
        assert!(matches!(
            TuiAttr::<()>::Dim.translate(),
            Some(Attribute::AttrFontDecoration(s)) if s == "dim"
        ));
        assert!(matches!(
            TuiAttr::<()>::Reverse.translate(),
            Some(Attribute::AttrFontDecoration(s)) if s == "reverse"
        ));
    }

    // The palette constructors carry the same portable SGR codes the terminal
    // rendered before the carrier moved to `AnsiColor`: `red` → 31/41,
    // `brightRed` → 91/101, `default` → 39/49, and the standard/bright endpoints.
    #[test]
    fn term_color_named_fg_and_bg_codes() {
        assert_eq!(term_color_red_().named_sgr_code(true), Some(31));
        assert_eq!(term_color_red_().named_sgr_code(false), Some(41));
        assert_eq!(term_color_bright_red_().named_sgr_code(true), Some(91));
        assert_eq!(term_color_bright_red_().named_sgr_code(false), Some(101));
        assert_eq!(term_color_black_().named_sgr_code(true), Some(30));
        assert_eq!(term_color_bright_white_().named_sgr_code(true), Some(97));
    }

    // `default` and the truecolour path have no single named SGR code: `default`
    // resets to the terminal's own colour, `rgb` emits a `38;2;…` sequence.
    #[test]
    fn default_and_rgb_have_no_named_code() {
        assert_eq!(term_color_default_().named_sgr_code(true), None);
        assert_eq!(term_color_rgb_(1, 2, 3).named_sgr_code(true), None);
        assert_eq!(term_color_rgb_(1, 2, 3).named_sgr_code(false), None);
    }

    #[test]
    fn named_palette_fg_translates_to_code_decoration() {
        assert!(matches!(
            term_fg_attr::<()>(term_color_red_()),
            Attribute::AttrFontDecoration(s) if s == "fg:31"
        ));
        assert!(matches!(
            term_bg_attr::<()>(term_color_blue_()),
            Attribute::AttrFontDecoration(s) if s == "bg:44"
        ));
    }

    // `default` reaches the palette-decoration branch and lowers to the reset
    // code (39 fg / 49 bg), the byte-identical spelling the old carrier emitted.
    #[test]
    fn default_translates_to_reset_code_decoration() {
        assert!(matches!(
            term_fg_attr::<()>(term_color_default_()),
            Attribute::AttrFontDecoration(s) if s == "fg:39"
        ));
        assert!(matches!(
            term_bg_attr::<()>(term_color_default_()),
            Attribute::AttrFontDecoration(s) if s == "bg:49"
        ));
    }

    #[test]
    fn truecolor_translates_to_font_color_attribute() {
        assert_eq!(
            term_fg_attr::<()>(term_color_rgb_(10, 20, 30)),
            Attribute::AttrFontColor(Color::rgb(10, 20, 30))
        );
    }

    #[test]
    fn cli_attr_line_styles_translate() {
        assert!(matches!(
            CliAttr::<()>::Bold.translate(),
            Some(Attribute::AttrFontWeight(700))
        ));
        assert!(matches!(
            CliAttr::<()>::FgColor(term_color_green_()).translate(),
            Some(Attribute::AttrFontDecoration(s)) if s == "fg:32"
        ));
    }

    #[test]
    fn rgb_channels_clamp_into_byte_range() {
        assert_eq!(term_color_rgb_(-5, 300, 128), AnsiColor::Rgb(0, 255, 128));
    }

    #[test]
    fn render_lines_view_emits_plain_text() {
        let out = render_lines_view(cli_text_::<()>("hello".to_owned()));
        assert!(out.contains("hello"));
    }

    // A single unstyled `text` line renders to exactly its own bytes — no
    // width-padding, no trailing newline, no SGR. This is the byte-for-byte
    // parity that lets a `Cli.tea` view migrate from `model -> String` to
    // `model -> Lines msg` (via `Cli.Ui.text`) with identical stdout.
    #[test]
    fn render_lines_view_text_is_byte_exact() {
        assert_eq!(
            render_lines_view(cli_text_::<()>("lines: 0".to_owned())),
            "lines: 0"
        );
    }

    #[test]
    fn render_lines_view_has_no_trailing_newline() {
        let out = render_lines_view(cli_text_::<()>("prompt > ".to_owned()));
        assert!(!out.ends_with('\n'));
    }

    #[test]
    fn render_lines_view_stacks_lines_top_to_bottom() {
        let out = render_lines_view(cli_lines_::<()>(vec![
            cli_text_("first".to_owned()),
            cli_text_("second".to_owned()),
        ]));
        let first = out.find("first").expect("first line present");
        let second = out.find("second").expect("second line present");
        assert!(first < second, "lines stack top-to-bottom");
    }

    #[test]
    fn render_lines_view_carries_line_styling() {
        let bold = render_lines_view(cli_line_::<()>(vec![CliAttr::Bold], "b".to_owned()));
        assert!(bold.contains("\u{1b}[") && bold.contains('1'));
        let dim = render_lines_view(cli_line_::<()>(vec![CliAttr::Dim], "d".to_owned()));
        assert!(dim.contains('2'));
        let reverse = render_lines_view(cli_line_::<()>(vec![CliAttr::Reverse], "r".to_owned()));
        assert!(reverse.contains('7'));
    }

    #[test]
    fn render_lines_view_carries_palette_color() {
        let out = render_lines_view(cli_line_::<()>(
            vec![CliAttr::FgColor(term_color_red_())],
            "c".to_owned(),
        ));
        assert!(out.contains("31"));
    }
}

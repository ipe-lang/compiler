//! Element → ANSI frame — the structured Ipe.Tui renderer + focus/input model.
//!
//! Walks the shared `ipe_runtime::ui::Element` tree (the SAME tree Ipe.Web
//! renders to HTML) and lays it out to terminal cells by reading the TYPED
//! attributes directly — never CSS. Recognises the
//! `Ipe.Ui.Input.*` widgets (`TaggedNode "input"/"textarea"/"button"` carrying
//! `AttrAttribute "type"/"value"/"placeholder"` + `AttrEvent`), collects them as
//! focusables in tab order, renders the focused one with a buffer + cursor, and
//! reports their positions for scroll-into-view.
//!
//! Logical-pixel canvas : a design surface (default 1280×720) maps to
//! the live terminal cell grid via `pxPerCell`.
//!
//! Scope: column / row / el / text / button + colour + spacing + padding + bold;
//! text/password/checkbox/radio/slider inputs; Tab focus; scroll-into-view.
//! Follow-on: mouse hit-testing, multiline cursor up/down, word-jumps, precise
//! slider value, Length(Fill/Min/Max). No panic vectors.

use super::super::html::Html;
use super::super::ui::{
    Attribute, Description, Element, HAlign, Length, Location, Portion, SectionHead, VAlign,
    WhiteSpace, section_head,
};
use super::cell::sanitize_rune;
use super::focus::{Focusable, InputRegistry};
use crate::color::Color;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

const CANVAS_W: usize = 1280;
const CANVAS_H: usize = 720;
/// Hard ceiling on any single program-controlled cell dimension. `Ui.px`/`Ui.vw`/
/// `Ui.vh` / `Ui.fillPortion` take an arbitrary Ipê `Int`, so a resolved cell
/// count must be clamped before it reaches a `.repeat()` / Vec allocation or a
/// fill loop — otherwise a well-typed Ipe.Tui view can request an OOM / capacity
/// panic. 100_000 is far above any real terminal.
const MAX_CELLS: usize = 100_000;

/// Slack factor applied on top of the live terminal row count when clamping
/// pad/gap row allocations. A pad block taller than a few screens serves no
/// display purpose; its area (rows × width) is the OOM vector. The factor of 4
/// permits scroll-region padding without permitting a 100k-row block on a
/// 24-row terminal.
const PAD_ROW_SLACK: usize = 4;

/// Cap a pad/gap row count terminal-proportionally. Used at every allocation
/// site that pushes blank rows (`apply_padding` top/bottom, `vstack` gap,
/// `apply_self_height` pad rows) so the product (rows × width) is bounded
/// to roughly `(canvas.rows × PAD_ROW_SLACK) × MAX_CELLS` — negligible.
fn clamp_pad_rows(rows: usize, canvas: Canvas) -> usize {
    rows.min(canvas.rows.saturating_mul(PAD_ROW_SLACK).max(PAD_ROW_SLACK))
}

/// Hard recursion-depth bound for the Element/Html tree walk. A deeply-nested
/// (program- or input-built) tree would otherwise overflow the native stack in
/// `render_node` / `extract_text` / `html_text` (no tail-call elimination). At the
/// limit the walk stops and emits nothing (empty block / empty string). 1024 is
/// far beyond any real UI nesting.
const MAX_RENDER_DEPTH: usize = 1024;
thread_local! {
    static RENDER_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
/// RAII depth guard shared by the three mutually/self-recursive tree walkers.
/// `enter()` returns `None` once `MAX_RENDER_DEPTH` is reached (caller stops
/// descending); otherwise it increments and decrements on drop (incl. unwind).
struct DepthGuard;
impl DepthGuard {
    fn enter() -> Option<DepthGuard> {
        RENDER_DEPTH.with(|d| {
            let n = d.get();
            if n >= MAX_RENDER_DEPTH {
                None
            } else {
                d.set(n + 1);
                Some(DepthGuard)
            }
        })
    }
}
impl Drop for DepthGuard {
    fn drop(&mut self) {
        RENDER_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

#[derive(Clone, Copy)]
struct Canvas {
    px_per_cell_x: f64,
    px_per_cell_y: f64,
    cols: usize,
    rows: usize,
}
impl Canvas {
    fn new(cols: usize, rows: usize) -> Canvas {
        Canvas {
            px_per_cell_x: (CANVAS_W as f64 / cols.max(1) as f64).max(1.0),
            px_per_cell_y: (CANVAS_H as f64 / rows.max(1) as f64).max(1.0),
            cols,
            rows,
        }
    }
    fn cells_x(self, px: i64) -> usize {
        if px <= 0 {
            return 0;
        }
        // DoS clamp: `px` is program-controlled (`Ui.px`/`Ui.vw : Int -> Length`),
        // so an arbitrary i64 could resolve to a cell count that overflows a
        // downstream `.repeat()` / Vec allocation (OOM / capacity panic). Cap at
        // MAX_CELLS — far above any real terminal, so no legitimate layout loses.
        (((px as f64 / self.px_per_cell_x).round() as i64).max(1) as usize).min(MAX_CELLS)
    }
    fn cells_y(self, px: i64) -> usize {
        if px <= 0 {
            return 0;
        }
        (((px as f64 / self.px_per_cell_y).round() as i64).max(1) as usize).min(MAX_CELLS)
    }
}

#[derive(Clone, Copy, Default, PartialEq)]
struct Style {
    fg: Option<(u8, u8, u8)>,
    bg: Option<(u8, u8, u8)>,
    /// A named-palette foreground SGR code (30-37 / 90-97 / 39). Takes precedence
    /// over `fg` (truecolour) so the portable palette path renders its own code.
    fg_palette: Option<u8>,
    /// A named-palette background SGR code (40-47 / 100-107 / 49).
    bg_palette: Option<u8>,
    bold: bool,
    dim: bool,
    italic: bool,
    underline: bool,
    overline: bool,
    strike: bool,
    reverse: bool,
    /// `Font.whiteSpace` — how a text run wraps and keeps its newlines.
    white_space: WhiteSpace,
}

#[derive(Clone, Copy, PartialEq)]
enum Dir {
    Column,
    Row,
}

/// A CSS-grid column track (the subset the terminal can size): a fixed `px`
/// width, an `fr` proportional share, or `auto` (treated as `1fr` of the
/// leftover). `repeat()`/`minmax()` are not parsed — the grid falls back to
/// auto-flow then.
#[derive(Clone, Copy)]
enum GridTrack {
    Px(i64),
    Fr(i64),
    Auto,
}

/// Parse a `grid-template-columns` value (`"1fr 200px 1fr"`). Returns empty if it
/// contains `repeat(`/`minmax(` (caller falls back to auto-flow).
fn parse_grid_tracks(css: &str) -> Vec<GridTrack> {
    if css.contains("repeat(") || css.contains("minmax(") {
        return Vec::new();
    }
    css.split_whitespace()
        .map(|t| {
            if let Some(n) = t.strip_suffix("fr") {
                GridTrack::Fr(n.trim().parse().unwrap_or(1))
            } else if let Some(n) = t.strip_suffix("px") {
                GridTrack::Px(n.trim().parse().unwrap_or(0))
            } else {
                GridTrack::Auto
            }
        })
        .collect()
}

struct Walked {
    dir: Dir,
    spacing_px: i64,
    pad_top: i64,
    pad_right: i64,
    pad_bottom: i64,
    pad_left: i64,
    /// The raw `Ui.width` `Length`, if any. `None` (or `Content`) → content-sized.
    /// Resolved to cells lazily (avail_w + canvas are only known at render time).
    width: Option<Length>,
    /// The raw `Ui.height` `Length`, if any. `None`/`Content` → content-sized;
    /// `Px`/`Vh`/`Min`/`Max` give a fixed row count (apply_self_height).
    height: Option<Length>,
    style: Style,
    /// `__grid` marker present (`Ui.grid`). Children flow row-major into auto-flow
    /// columns sized off `grid_min_px` (`Ui.gridColumns`).
    is_grid: bool,
    /// The `DescParagraph` / `DescTextColumn` role (`Ui.paragraph` /
    /// `Ui.textColumn`) or the `__textcolumn` marker. Text children are joined
    /// and word-wrapped to the available width.
    is_paragraph: bool,
    is_text_column: bool,
    /// `__gridMin` value — the minimum column WIDTH in logical px (set by
    /// `Ui.gridColumns N`). The actual column COUNT is `availW / cells_x(min)`.
    grid_min_px: i64,
    /// Explicit column tracks from `Ipe.Ui.Grid.columns`/`tracks`
    /// (`grid-template-columns`). Empty → auto-flow (`grid_min_px`). A
    /// `repeat()`/`minmax()` spec is left empty (falls back to auto-flow).
    grid_cols: Vec<GridTrack>,
    /// Border frame, present when `Border.width > 0`. See [`BorderSpec`].
    border: Option<BorderSpec>,
    /// `Ui.centerX`/`alignLeft`/`alignRight` (cross-axis in a column / self-align
    /// in an `el`). `None` → flush-left.
    align_x: Option<HAlign>,
    /// `Ui.centerY`/`alignTop`/`alignBottom` (cross-axis in a row). `None` → top.
    align_y: Option<VAlign>,
    /// `Font.alignCenter`/`alignRight`/`justify` — horizontal alignment of TEXT
    /// lines within this box's content width. `None` → flush-left.
    font_align: Option<HAlign>,
}

/// A border frame's `(colour, style)`. The colour is `None` when only width (no
/// `Border.color`) was given — glyphs then keep the inherited fg
/// `drawBorder` (which sets the glyph fg only when the border colour is set). The
/// style string is one of `solid` / `dashed` / `dotted` (anything else → solid).
/// `(colour, style, (top, right, bottom, left) present-flags)`. The per-side flags
/// let `Border.widthEach` draw a partial frame (e.g. a top rule only) instead of
/// a full box (audit #6); `Border.width` sets all four.
type BorderSpec = (Option<(u8, u8, u8)>, String, (bool, bool, bool, bool));

/// The root element's `Background.color`, if it sets one — the page background
/// painted across the whole frame rect. `None` when the root carries no bg
/// (blank cells stay terminal-default). Only the OUTERMOST node's bg is the
/// page fill; a child's bg belongs to that child's own box.
fn root_bg<M>(view: &Element<M>) -> Option<(u8, u8, u8)> {
    let attrs = match view {
        Element::Node(_, attrs, _) | Element::TaggedNode(_, _, attrs, _) => attrs,
        _ => return None,
    };
    attrs.iter().rev().find_map(|a| match a {
        Attribute::AttrBgColor(c) => bg_of(c),
        _ => None,
    })
}

/// The root element's `Ui.width` `Length`, if it sets one — drives whether the
/// page background fills to the frame's right edge (a full-width / unsized root) or
/// stops at the root box's own width (a narrower px / vw / capped root).
fn root_width<M>(view: &Element<M>) -> Option<Length> {
    match view {
        Element::Node(_, attrs, _) | Element::TaggedNode(_, _, attrs, _) => width_length(attrs),
        _ => None,
    }
}

/// The `Ui.width` `Length` on a node, if present.
fn width_length<M>(attrs: &[Attribute<M>]) -> Option<Length> {
    attrs.iter().find_map(|a| match a {
        Attribute::AttrWidth(l) => Some(l.clone()),
        _ => None,
    })
}

/// The `Ui.height` `Length` on a node, if present.
fn height_length<M>(attrs: &[Attribute<M>]) -> Option<Length> {
    attrs.iter().find_map(|a| match a {
        Attribute::AttrHeight(l) => Some(l.clone()),
        _ => None,
    })
}

/// Resolve a NON-fill height `Length` to explicit ROWS. `None` → content-sized.
/// The y-axis analogue of `resolve_fixed_w` (cells_y for px, canvas.rows for vh).
fn resolve_fixed_h(l: &Length, canvas: Canvas) -> Option<usize> {
    match l {
        Length::Px(n) => Some(canvas.cells_y(*n).max(1)),
        // Vh percentage is program-controlled (Ui.vh : Int -> Length): clamp the
        // resolved rows to MAX_CELLS so a huge percent can't drive an unbounded
        // pad-loop / Vec alloc (cells_x/y are already clamped; Vw/Vh bypass them).
        Length::Vh(p) => {
            Some((canvas.rows.saturating_mul((*p).max(0) as usize) / 100).min(MAX_CELLS))
        }
        Length::Content | Length::Fill(_) | Length::Vw(_) => None,
        Length::Min(n, inner) => {
            let mn = canvas.cells_y(*n);
            Some(resolve_fixed_h(inner, canvas).map_or(mn, |c| c.max(mn)))
        }
        Length::Max(n, inner) => {
            let mx = canvas.cells_y(*n);
            Some(resolve_fixed_h(inner, canvas).map_or(mx, |c| c.min(mx)))
        }
    }
}

/// `(portion, min_cells, max_cells)` for a fill child (see `fill_spec`).
type FillSpec = (Portion, Option<usize>, Option<usize>);

// The fill-distribution products `leftover * portion` stay in range because a
// portion never exceeds the cell ceiling; a portion at `Portion::MAX` already
// claims the entire leftover beside any realistic sibling set.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if `Portion::MAX` outgrows the TUI cell ceiling [ledger #boundary]
const _: () = assert!(Portion::MAX.get() as usize <= MAX_CELLS);

/// A fill portion as a share count for the distribution passes.
const fn portion_shares(p: Portion) -> usize {
    p.get() as usize
}

/// Distribution spec for a fill child: `Some((portion, min_cells, max_cells))`
/// when the length is `Fill` (possibly wrapped in `Min`/`Max`). Such a child is
/// sized by the parent ROW's fill-distribution pass, not by its own content.
fn fill_spec(l: &Length, canvas: Canvas) -> Option<FillSpec> {
    match l {
        // The portion is positive and at most `Portion::MAX` by type.
        Length::Fill(p) => Some((*p, None, None)),
        Length::Min(n, inner) => fill_spec(inner, canvas)
            .map(|(p, mn, mx)| (p, Some(mn.unwrap_or(0).max(canvas.cells_x(*n))), mx)),
        Length::Max(n, inner) => fill_spec(inner, canvas).map(|(p, mn, mx)| {
            let cap = canvas.cells_x(*n);
            (p, mn, Some(mx.map_or(cap, |x| x.min(cap))))
        }),
        _ => None,
    }
}

/// Resolve a NON-fill width `Length` to explicit cells given the available width.
/// `None` → content-sized (the caller measures children). `Min`/`Max` bounds
/// are correctly converted px→cells.
/// The fixed pixel height of `attrs` (`Ui.height (Ui.px n)`) in CELLS, when set.
/// Only `Px` yields a fixed row count (the multiline-textarea case); Fill/Content
/// auto-size and return `None`.
fn height_cells<M>(attrs: &[Attribute<M>], canvas: Canvas) -> Option<usize> {
    for a in attrs {
        if let Attribute::AttrHeight(Length::Px(n)) = a {
            return Some(canvas.cells_y(*n).max(1));
        }
    }
    None
}

fn resolve_fixed_w(l: &Length, available: usize, canvas: Canvas) -> Option<usize> {
    match l {
        Length::Px(n) => Some(canvas.cells_x(*n)),
        Length::Content => None,
        Length::Fill(_) => Some(available), // a direct ask claims all; the ROW pass overrides
        // Vw/Vh percentages are program-controlled: clamp to MAX_CELLS (see Vh in
        // resolve_fixed_h — these bypass the already-clamped cells_x/y path).
        Length::Vw(p) => {
            Some((canvas.cols.saturating_mul((*p).max(0) as usize) / 100).min(MAX_CELLS))
        }
        Length::Vh(p) => {
            Some((canvas.rows.saturating_mul((*p).max(0) as usize) / 100).min(MAX_CELLS))
        }
        Length::Min(n, inner) => {
            let mn = canvas.cells_x(*n);
            Some(resolve_fixed_w(inner, available, canvas).map_or(mn, |c| c.max(mn)))
        }
        Length::Max(n, inner) => {
            let mx = canvas.cells_x(*n);
            Some(resolve_fixed_w(inner, available, canvas).map_or(available.min(mx), |c| c.min(mx)))
        }
    }
}

#[derive(Clone)]
struct Run {
    text: String,
    style: Style,
}
impl Run {
    fn width(&self) -> usize {
        UnicodeWidthStr::width(self.text.as_str())
    }
}

#[derive(Clone, Default)]
struct Block {
    lines: Vec<Vec<Run>>,
}
impl Block {
    fn width(&self) -> usize {
        self.lines
            .iter()
            .map(|l| l.iter().map(Run::width).sum::<usize>())
            .max()
            .unwrap_or(0)
    }
    fn height(&self) -> usize {
        self.lines.len()
    }
    fn single(text: String, style: Style) -> Block {
        Block {
            lines: vec![vec![Run { text, style }]],
        }
    }
    /// Constrain every line to EXACTLY `w` display cells — pad shorter lines with
    /// `bg`-styled spaces, clip longer ones. For explicit `Ui.width (Ui.px n)`.
    fn set_width(&mut self, w: usize, bg: Option<(u8, u8, u8)>) {
        // Defence-in-depth: cap the target width so no caller (present or future)
        // can drive `" ".repeat(w)` to an OOM-sized count.
        let w = w.min(MAX_CELLS);
        for line in &mut self.lines {
            let lw: usize = line.iter().map(Run::width).sum();
            if lw > w {
                // Clip runs to `w` cells.
                let mut kept: Vec<Run> = Vec::new();
                let mut used = 0usize;
                for run in line.iter() {
                    if used >= w {
                        break;
                    }
                    let rw = run.width();
                    if used + rw <= w {
                        kept.push(run.clone());
                        used += rw;
                    } else {
                        let mut text = String::new();
                        let mut tw = 0usize;
                        for ch in run.text.chars() {
                            let cw = UnicodeWidthChar::width(ch).unwrap_or(0);
                            if used + tw + cw > w {
                                break;
                            }
                            text.push(ch);
                            tw += cw;
                        }
                        used += tw;
                        kept.push(Run {
                            text,
                            style: run.style,
                        });
                        break;
                    }
                }
                // A clip landing on a wide-char boundary can leave the kept
                // width one cell short of `w`; pad the remainder with
                // `bg`-styled spaces so the box always fills exactly `w`.
                if used < w {
                    kept.push(Run {
                        text: " ".repeat(w - used),
                        style: Style {
                            bg,
                            ..Style::default()
                        },
                    });
                }
                *line = kept;
            } else if lw < w {
                line.push(Run {
                    text: " ".repeat(w - lw),
                    style: Style {
                        bg,
                        ..Style::default()
                    },
                });
            }
        }
    }
    /// Constrain every line to EXACTLY `w` cells, filling the slack with the input
    /// TRACK (`░` in `track_fg` over `bg`) instead of plain spaces. The shaded
    /// track makes field bounds visible even when empty. Real content (clipped to
    /// `w`) stays painted over the track. The cursor run keeps its own style.
    fn fill_input_track(&mut self, w: usize, bg: Option<(u8, u8, u8)>, track_fg: (u8, u8, u8)) {
        let track_run = |n: usize| Run {
            text: "░".repeat(n),
            style: Style {
                fg: Some(track_fg),
                bg,
                ..Style::default()
            },
        };
        for line in &mut self.lines {
            let lw: usize = line.iter().map(Run::width).sum();
            if lw > w {
                // Clip to `w` cells (reuse the same per-rune walk as set_width).
                let mut kept: Vec<Run> = Vec::new();
                let mut used = 0usize;
                for run in line.iter() {
                    if used >= w {
                        break;
                    }
                    let rw = run.width();
                    if used + rw <= w {
                        kept.push(run.clone());
                        used += rw;
                    } else {
                        let mut text = String::new();
                        let mut tw = 0usize;
                        for ch in run.text.chars() {
                            let cw = UnicodeWidthChar::width(ch).unwrap_or(0);
                            if used + tw + cw > w {
                                break;
                            }
                            text.push(ch);
                            tw += cw;
                        }
                        used += tw;
                        kept.push(Run {
                            text,
                            style: run.style,
                        });
                        break;
                    }
                }
                if used < w {
                    kept.push(track_run(w - used));
                }
                *line = kept;
            } else if lw < w {
                line.push(track_run(w - lw));
            }
        }
    }
    /// Backfill the root element's background across the WHOLE frame rect.
    /// The run model has no "paint underneath" step, so a gap / padding /
    /// trailing cell that no child covered is left with the default (terminal)
    /// background instead of the root bg.
    ///
    /// Every cell whose bg is still unset (`None`) takes `root_bg`. A cell
    /// that ALREADY carries a bg was painted by its owning box (a header / card
    /// / input with its own `Background.color`) and is left untouched.
    ///
    /// `fill_to_edge` extends each line to the full `cols` width with `root_bg`
    /// so the page background reaches the right edge. A root with an explicit
    /// narrower width (`Ui.width (px/vw …)`) fills only to its own width and
    /// trailing columns stay terminal-default. Total — no index/panic.
    fn backfill_root_bg(&mut self, cols: usize, root_bg: (u8, u8, u8), fill_to_edge: bool) {
        let fill_style = Style {
            bg: Some(root_bg),
            ..Style::default()
        };
        for line in &mut self.lines {
            // Set the root bg on every run that has no bg of its own (a real glyph
            // on the root surface, or a blank gap/pad cell), preserving fg/flags.
            let mut width = 0usize;
            for run in line.iter_mut() {
                if run.style.bg.is_none() {
                    run.style.bg = Some(root_bg);
                }
                width += run.width();
            }
            // Extend the line to the full frame width with root-bg spaces (the page
            // background reaching the right edge). A line wider than `cols` is left
            // as-is — `emit_block` clips it to `cols` at paint time.
            if fill_to_edge && width < cols {
                line.push(Run {
                    text: " ".repeat(cols - width),
                    style: fill_style,
                });
            }
        }
    }

    /// Reverse-video the single display cell at `(line, col)` — the text-input
    /// cursor (rendered as reverse-video, never an inserted glyph). Rebuilds
    /// the line one char at a time, flagging the char at display
    /// column `col` (or appending a reverse space if the cursor sits past the
    /// content). Adjacent same-style chars re-coalesce into runs. Total — uses
    /// iterators + `.get`, never indexes or unwraps.
    fn reverse_cell_at(&mut self, line: usize, col: usize) {
        let Some(target_line) = self.lines.get_mut(line) else {
            return;
        };
        // Flatten to (char, style) cells, marking the cursor char's style reverse.
        let mut cells: Vec<(char, Style)> = Vec::new();
        let mut acc = 0usize;
        for run in target_line.iter() {
            for ch in run.text.chars() {
                let cw = UnicodeWidthChar::width(ch).unwrap_or(0);
                let style = if acc == col {
                    Style {
                        reverse: true,
                        ..run.style
                    }
                } else {
                    run.style
                };
                cells.push((ch, style));
                acc += cw;
            }
        }
        // Cursor past the end of the line content → append a reverse space.
        if acc <= col {
            // Pad any gap with normal spaces, then the reverse cursor space.
            for _ in acc..col {
                cells.push((' ', Style::default()));
            }
            cells.push((
                ' ',
                Style {
                    reverse: true,
                    ..Style::default()
                },
            ));
        }
        // Re-coalesce adjacent cells sharing a style into runs.
        let mut out: Vec<Run> = Vec::new();
        for (ch, style) in cells {
            match out.last_mut() {
                Some(last) if last.style == style => last.text.push(ch),
                _ => out.push(Run {
                    text: ch.to_string(),
                    style,
                }),
            }
        }
        *target_line = out;
    }
}

/// A rendered subtree plus the focusables it produced, each as
/// `(focusable index, line, col, width, height)` relative to this block's
/// top-left — composition shifts line/col to absolute frame coordinates.
struct Rendered {
    block: Block,
    hits: Vec<(usize, usize, usize, usize, usize)>,
}

/// Render-time context threaded through the walk.
struct Ctx<'a, M> {
    canvas: Canvas,
    focus_idx: usize,
    focusables: Vec<Focusable<M>>,
    inputs: &'a mut InputRegistry,
}

fn color_of(c: &Color) -> (u8, u8, u8) {
    let (r, g, b, _) = c.to_rgba_bytes();
    ((r & 0xff) as u8, (g & 0xff) as u8, (b & 0xff) as u8)
}

/// A BACKGROUND colour, honouring alpha: a fully-transparent colour
/// (`Ui.transparent` / any rgba with alpha 0) paints NOTHING (`None`) rather than
/// an opaque black box. The terminal cell model is 1-bit alpha — any non-zero
/// alpha is treated as fully opaque (no blending). (audit #10)
fn bg_of(c: &Color) -> Option<(u8, u8, u8)> {
    let (_, _, _, a) = c.to_rgba_bytes();
    if a <= 0.0 { None } else { Some(color_of(c)) }
}

/// Clamp-add `delta` to a channel. Saturating — no overflow.
fn lighten(c: u8, delta: i64) -> u8 {
    (c as i64 + delta).clamp(0, 255) as u8
}

/// The input track foreground: dim grey when the input has no bg, else the bg
/// lightened by 38 (the `paintInputBufferAdvanced` trackFg rule). The `░` shade
/// glyph rendered in this fg gives the field a visible groove.
fn input_track_fg(bg: Option<(u8, u8, u8)>) -> (u8, u8, u8) {
    match bg {
        Some((r, g, b)) => (lighten(r, 38), lighten(g, 38), lighten(b, 38)),
        None => (110, 110, 110),
    }
}

fn attr_str<'a, M>(attrs: &'a [Attribute<M>], key: &str) -> Option<&'a str> {
    attrs.iter().find_map(|a| match a {
        Attribute::AttrAttribute(k, v) if k == key => Some(v.as_str()),
        _ => None,
    })
}

fn walk_attrs<M>(attrs: &[Attribute<M>], inherited: Style) -> Walked {
    let mut w = Walked {
        dir: Dir::Column,
        spacing_px: 0,
        pad_top: 0,
        pad_right: 0,
        pad_bottom: 0,
        pad_left: 0,
        width: width_length(attrs),
        height: height_length(attrs),
        style: inherited,
        is_grid: false,
        is_paragraph: false,
        is_text_column: false,
        grid_min_px: 0,
        grid_cols: Vec::new(),
        border: None,
        align_x: None,
        align_y: None,
        font_align: None,
    };
    // Border accumulates across two attrs (width gate + colour); style defaults
    // to "solid". A frame is drawn only when width > 0 (borderWidth sum > 0).
    let mut border_width = 0i64;
    let mut border_color: Option<Color> = None;
    let mut border_style = String::from("solid");
    // Per-side presence (top, right, bottom, left). Border.width → all four;
    // Border.widthEach → only the sides with width > 0 (partial frame).
    let mut sides = (false, false, false, false);
    let mut rounded = false;
    for a in attrs {
        match a {
            Attribute::AttrStyle(k, _) if k == "__row" => w.dir = Dir::Row,
            Attribute::AttrStyle(k, _) if k == "__col" => w.dir = Dir::Column,
            Attribute::AttrStyle(k, _) if k == "__grid" => w.is_grid = true,
            // Ipe.Ui.Grid.columns/tracks → native AttrGridTracks(cols, rows).
            // Parse the column tracks; a non-empty parse turns this into an explicit
            // grid (audit #13). repeat()/minmax() → empty → auto-flow fallback.
            Attribute::AttrGridTracks(cols, _rows) => {
                let tracks = parse_grid_tracks(cols);
                if !tracks.is_empty() {
                    w.is_grid = true;
                    w.grid_cols = tracks;
                }
            }
            Attribute::AttrStyle(k, _) if k == "__textcolumn" => w.is_text_column = true,
            Attribute::AttrStyle(k, v) if k == "__gridMin" => {
                w.grid_min_px = v.trim().parse().unwrap_or(0);
            }
            Attribute::AttrSpacing(n) => w.spacing_px = *n,
            Attribute::AttrPadding(t, r, b, l) => {
                w.pad_top = *t;
                w.pad_right = *r;
                w.pad_bottom = *b;
                w.pad_left = *l;
            }
            Attribute::AttrFontColor(c) => w.style.fg = Some(color_of(c)),
            Attribute::AttrFontWhiteSpace(ws) => w.style.white_space = *ws,
            Attribute::AttrBgColor(c) => w.style.bg = bg_of(c),
            Attribute::AttrFontWeight(n) if *n >= 600 => w.style.bold = true,
            // Typography SGR .
            Attribute::AttrFontItalic => w.style.italic = true,
            Attribute::AttrFontUnderline => w.style.underline = true,
            Attribute::AttrFontDecoration(s) if s == "underline" => w.style.underline = true,
            Attribute::AttrFontDecoration(s) if s == "overline" => w.style.overline = true,
            Attribute::AttrFontDecoration(s) if s == "line-through" || s == "strike" => {
                w.style.strike = true
            }
            Attribute::AttrFontDecoration(s) if s == "dim" => w.style.dim = true,
            Attribute::AttrFontDecoration(s) if s == "reverse" => w.style.reverse = true,
            Attribute::AttrFontDecoration(s) if s.starts_with("fg:") => {
                w.style.fg_palette = parse_palette_code(s);
            }
            Attribute::AttrFontDecoration(s) if s.starts_with("bg:") => {
                w.style.bg_palette = parse_palette_code(s);
            }
            // Border frame (drawBorder — solid/dashed/dotted box). Width is
            // taken as present/absent (the frame is always 1 cell each side in the
            // terminal regardless of CSS px); colour + style drive the glyphs.
            Attribute::AttrBorderWidth(n) if *n > 0 => {
                border_width = *n;
                sides = (true, true, true, true);
            }
            Attribute::AttrBorderWidthEach(t, r, b, l)
                if t.saturating_add(*r).saturating_add(*b).saturating_add(*l) > 0 =>
            {
                // Saturating: each side is an arbitrary Ipê `Int`; a plain
                // `t + r + b + l` overflows i64 (debug panic) on large widths.
                border_width = t
                    .saturating_add(*r)
                    .saturating_add(*b)
                    .saturating_add(*l)
                    .max(1);
                sides = (*t > 0, *r > 0, *b > 0, *l > 0);
            }
            Attribute::AttrBorderColor(c) => border_color = Some(*c),
            Attribute::AttrBorderStyle(s) => border_style = s.clone(),
            // Border.rounded → rounded corner glyphs (╭╮╰╯) on a solid frame
            // (audit #18). Shadow/glow/inset-shadow can't render in cells and are
            // silently dropped (a stderr warn would corrupt the live TUI).
            Attribute::AttrBorderRounded(n) if *n > 0 => rounded = true,
            // Raw CSS escape hatch `Ui.style "border-style" "dashed"|"dotted"` —
            // the list-driven way the kitchen-sink picks a style. Without this the
            // value was dropped and dashed/dotted rendered as solid (border_glyphs
            // already supports ┄┆ / ┈┊).
            Attribute::AttrStyle(k, v) if k == "border-style" => border_style = v.clone(),
            // Alignment — cross-axis placement of a child within its parent's slot
            // (centerX/alignRight in a column, centerY/alignBottom in a row, both
            // for a single-child el). Was silently dropped → everything flush-left.
            Attribute::AttrAlignX(h) => w.align_x = Some(*h),
            Attribute::AttrAlignY(v) => w.align_y = Some(*v),
            // Font text-align: align the box's text lines (center/right; justify →
            // left in a terminal). Was dropped → text always flush-left (audit #7).
            Attribute::AttrFontAlign(s) => {
                w.font_align = match s.as_str() {
                    "center" => Some(HAlign::CenterX),
                    "right" => Some(HAlign::AlignRight),
                    _ => None, // left / justify → flush-left
                }
            }
            // Width / height are extracted by `width_length` / `height_length`
            // before this loop and stored in `w.width` / `w.height` above.
            Attribute::AttrWidth(_) | Attribute::AttrHeight(_) => {}
            // Nearby overlays (tooltips, dropdowns) have no terminal surface.
            Attribute::AttrNearby(_, _) => {}
            // Accessibility label — no terminal equivalent in cell renderer.
            Attribute::AttrDescribe(_) => {}
            // NoAttribute is a no-op sentinel from the Ipê runtime.
            Attribute::NoAttribute => {}
            // Web-only: HTML class attribute, no terminal equivalent.
            Attribute::AttrClass(_) => {}
            // HTML event handler — collected separately for input/button nodes
            // via `collect_events`; silently ignored on non-input layout nodes.
            Attribute::AttrEvent(_) => {}
            // HTML arbitrary attribute escape hatch; no terminal surface.
            Attribute::AttrAttribute(_, _) => {}
            // Read by `render_input` as the checkbox/radio state.
            Attribute::AttrChecked(_) => {}
            // CSS font-size in px — terminal cell size is fixed; ignored.
            Attribute::AttrFontSize(_) => {}
            // CSS font-family — terminal font is set by the emulator; ignored.
            Attribute::AttrFontFamily(_) => {}
            // CSS letter-spacing — no terminal equivalent.
            Attribute::AttrFontLetterSpacing(_) => {}
            // CSS word-spacing — no terminal equivalent.
            Attribute::AttrFontWordSpacing(_) => {}
            // Web-only: background image URL, no terminal equivalent.
            Attribute::AttrBgImage(_) => {}
            // Web-only: CSS gradient, no terminal equivalent.
            Attribute::AttrBgGradient(_) => {}
            // Web-only: box-shadow (noted above at AttrBorderRounded arm).
            Attribute::AttrBorderShadow(_, _, _, _, _) => {}
            // Web-only: inset box-shadow, no terminal equivalent.
            Attribute::AttrBorderInsetShadow(_, _, _, _, _) => {}
            // Web-only: pointer cursor, no terminal equivalent.
            Attribute::AttrPointer => {}
            // Web-only: Debug.explain visual outline, no terminal equivalent.
            Attribute::AttrExplain => {}
            // Web-only: CSS overflow property, no terminal equivalent.
            Attribute::AttrOverflow(_, _) => {}
            // Web-only: CSS hover/focus/active pseudo-class rules, no terminal equivalent.
            Attribute::AttrPseudoRule(_, _) => {}
            // Web-only: CSS transition animation, no terminal equivalent.
            Attribute::AttrTransition(_, _) => {}
            // Web-only: CSS @keyframes animation, no terminal equivalent.
            Attribute::AttrAnimation(_, _, _, _) => {}
            // A `Ui.style` key with no terminal meaning (not one of the `__*`
            // layout markers or `border-style` handled above) has no cell surface.
            Attribute::AttrStyle(_, _) => {}
            // A sub-bold font weight (< 600) is rendered as normal weight — a
            // terminal cell has only the bold/normal SGR distinction.
            Attribute::AttrFontWeight(_) => {}
            // A text-decoration value the terminal has no glyph for (handled
            // decorations are matched above with a guard).
            Attribute::AttrFontDecoration(_) => {}
            // A zero/absent border width draws no frame.
            Attribute::AttrBorderWidth(_) => {}
            // A zero-sum per-side border width draws no frame.
            Attribute::AttrBorderWidthEach(_, _, _, _) => {}
            // A zero/absent rounded radius leaves the frame square.
            Attribute::AttrBorderRounded(_) => {}
        }
    }
    if border_width > 0 {
        let style = if rounded && border_style == "solid" {
            "rounded".to_string()
        } else {
            border_style
        };
        w.border = Some((border_color.as_ref().map(color_of), style, sides));
    }
    w
}

fn vstack(
    children: Vec<Rendered>,
    gap: usize,
    bg: Option<(u8, u8, u8)>,
    canvas: Canvas,
) -> Rendered {
    // When the column carries a bg, the inter-child gap ROWS must take that bg too
    // (else they render terminal-default — the wrong-colour-gap bug, audit #5). A
    // bg gap row spans the stack width; with no bg, keep the empty row (default).
    // Terminal-proportional row clamp: `gap` derives from `Ui.spacing` (arbitrary
    // Ipê Int already converted to cells); cap it terminal-proportionally so the
    // row count × stack_w product cannot OOM.
    let gap = clamp_pad_rows(gap, canvas);
    let stack_w = children.iter().map(|r| r.block.width()).max().unwrap_or(0);
    let gap_row = |w: &mut Block| {
        for _ in 0..gap {
            match bg {
                Some(c) => w.lines.push(vec![Run {
                    text: " ".repeat(stack_w),
                    style: Style {
                        bg: Some(c),
                        ..Style::default()
                    },
                }]),
                None => w.lines.push(Vec::new()),
            }
        }
    };
    let mut block = Block::default();
    let mut hits = Vec::new();
    let mut line0 = 0usize;
    for (i, r) in children.into_iter().enumerate() {
        if i > 0 {
            gap_row(&mut block);
            line0 += gap;
        }
        for (idx, l, c, w, h) in r.hits {
            hits.push((idx, line0 + l, c, w, h)); // stacked vertically — col unchanged
        }
        let h = r.block.lines.len();
        block.lines.extend(r.block.lines);
        line0 += h;
    }
    Rendered { block, hits }
}

fn hstack(children: Vec<Rendered>, gap: usize, bg: Option<(u8, u8, u8)>) -> Rendered {
    // Gap columns + short-child filler take the row's bg when set (audit #5), else
    // terminal-default.
    let fill_style = Style {
        bg,
        ..Style::default()
    };
    let height = children.iter().map(|r| r.block.height()).max().unwrap_or(0);
    let mut block = Block {
        lines: vec![Vec::new(); height],
    };
    let mut hits = Vec::new();
    let mut col0 = 0usize;
    for (bi, r) in children.iter().enumerate() {
        let bw = r.block.width();
        if bi > 0 {
            col0 += gap;
        }
        for (idx, l, c, w, h) in &r.hits {
            hits.push((*idx, *l, col0 + *c, *w, *h)); // side by side — shift col
        }
        col0 += bw;
        for row in 0..height {
            if let Some(target) = block.lines.get_mut(row) {
                if bi > 0 && gap > 0 {
                    target.push(Run {
                        text: " ".repeat(gap),
                        style: fill_style,
                    });
                }
                match r.block.lines.get(row) {
                    Some(line) => {
                        let mut lw = 0;
                        for run in line {
                            lw += run.width();
                            target.push(run.clone());
                        }
                        if lw < bw {
                            target.push(Run {
                                text: " ".repeat(bw.saturating_sub(lw)),
                                style: fill_style,
                            });
                        }
                    }
                    None => target.push(Run {
                        text: " ".repeat(bw),
                        style: fill_style,
                    }),
                }
            }
        }
    }
    Rendered { block, hits }
}

/// Overlay `top` onto `base` at the top-left, cell by cell. `top_wins` → a
/// non-blank `top` cell covers the base (InFront); `false` → the base shows
/// through wherever it has a non-blank cell (Behind). Best-effort width-1 cell
/// model (wide glyphs in an overlay may misalign — overlays are rare). Used for
/// `Ui.inFront` / `Ui.behind` nearby overlays.
fn overlay_blocks(base: Rendered, top: Rendered, top_wins: bool) -> Rendered {
    fn to_cells(b: &Block) -> Vec<Vec<(char, Style)>> {
        b.lines
            .iter()
            .map(|line| {
                let mut row = Vec::new();
                for run in line {
                    for ch in run.text.chars() {
                        row.push((ch, run.style));
                    }
                }
                row
            })
            .collect()
    }
    let bc = to_cells(&base.block);
    let tc = to_cells(&top.block);
    let h = bc.len().max(tc.len());
    let mut out_lines = Vec::with_capacity(h);
    for i in 0..h {
        let brow = bc.get(i);
        let trow = tc.get(i);
        let w = brow.map_or(0, Vec::len).max(trow.map_or(0, Vec::len));
        let mut runs: Vec<Run> = Vec::new();
        for j in 0..w {
            let b = brow.and_then(|r| r.get(j)).copied();
            let t = trow.and_then(|r| r.get(j)).copied();
            let (ch, st) = match (t, b) {
                (Some(tcell), Some(bcell)) => {
                    if top_wins {
                        if tcell.0 == ' ' { bcell } else { tcell }
                    } else if bcell.0 == ' ' {
                        tcell
                    } else {
                        bcell
                    }
                }
                (Some(tcell), None) => tcell,
                (None, Some(bcell)) => bcell,
                (None, None) => (' ', Style::default()),
            };
            match runs.last_mut() {
                Some(last) if last.style == st => last.text.push(ch),
                _ => runs.push(Run {
                    text: ch.to_string(),
                    style: st,
                }),
            }
        }
        out_lines.push(runs);
    }
    let mut hits = base.hits;
    hits.extend(top.hits);
    Rendered {
        block: Block { lines: out_lines },
        hits,
    }
}

fn apply_padding(inner: Rendered, w: &Walked, canvas: Canvas, self_style: Style) -> Rendered {
    // Terminal-proportional row clamp: `cells_y` caps each dimension at MAX_CELLS,
    // but their product (rows × total_w) can still reach ~10 GB. Cap row counts to
    // a small multiple of the live terminal height so the area stays bounded.
    let top = clamp_pad_rows(canvas.cells_y(w.pad_top), canvas);
    let bottom = clamp_pad_rows(canvas.cells_y(w.pad_bottom), canvas);
    let left = canvas.cells_x(w.pad_left);
    let right = canvas.cells_x(w.pad_right);
    let inner_w = inner.block.width();
    // Saturating + clamped: `left`/`right` derive from `Ui.padding N` (arbitrary
    // Ipê Int); an unclamped `inner_w + left + right` can overflow usize and, at
    // any rate, feed `" ".repeat(total_w)` an OOM-sized count. MAX_CELLS is the
    // same ceiling every other repeat site uses.
    let total_w = inner_w
        .saturating_add(left)
        .saturating_add(right)
        .min(MAX_CELLS);
    let pad_run = |n: usize| Run {
        text: " ".repeat(n.min(MAX_CELLS)),
        style: self_style,
    };

    let mut block = Block::default();
    for _ in 0..top {
        block.lines.push(vec![pad_run(total_w)]);
    }
    for line in inner.block.lines {
        let mut row = Vec::new();
        if left > 0 {
            row.push(pad_run(left));
        }
        let lw: usize = line.iter().map(Run::width).sum();
        row.extend(line);
        let tail = right + inner_w.saturating_sub(lw);
        if tail > 0 {
            row.push(pad_run(tail));
        }
        block.lines.push(row);
    }
    for _ in 0..bottom {
        block.lines.push(vec![pad_run(total_w)]);
    }
    let hits = inner
        .hits
        .into_iter()
        .map(|(idx, l, c, w, h)| (idx, l + top, c + left, w, h))
        .collect();
    Rendered { block, hits }
}

/// Render an input widget (text/password/checkbox/radio/range) into a styled
/// single-line block, registering it as a focusable.
fn render_input<M: Clone>(
    attrs: &[Attribute<M>],
    inherited: Style,
    ctx: &mut Ctx<M>,
    avail_w: usize,
    is_multiline: bool,
) -> Rendered {
    // Fold the input's OWN visual attrs (Background.color / Font.color) on top of
    // the inherited style. An input is a leaf `TaggedNode` dispatched straight to
    // this fn, so its attrs were never walked by a parent — without this, the
    // input's `Background.color` track / text colour is silently dropped.
    let mut style = inherited;
    for a in attrs {
        match a {
            Attribute::AttrBgColor(c) => style.bg = bg_of(c),
            Attribute::AttrFontColor(c) => style.fg = Some(color_of(c)),
            // All other attrs are handled by walk_attrs or are not applicable
            // to the input's own style fold (events go through collect_events;
            // layout attrs are consumed by the parent walk_attrs call).
            Attribute::NoAttribute
            | Attribute::AttrWidth(_)
            | Attribute::AttrHeight(_)
            | Attribute::AttrAlignX(_)
            | Attribute::AttrAlignY(_)
            | Attribute::AttrNearby(_, _)
            | Attribute::AttrPadding(_, _, _, _)
            | Attribute::AttrSpacing(_)
            | Attribute::AttrStyle(_, _)
            | Attribute::AttrDescribe(_)
            | Attribute::AttrClass(_)
            | Attribute::AttrEvent(_)
            | Attribute::AttrAttribute(_, _)
            | Attribute::AttrChecked(_)
            | Attribute::AttrFontSize(_)
            | Attribute::AttrFontFamily(_)
            | Attribute::AttrFontWeight(_)
            | Attribute::AttrFontItalic
            | Attribute::AttrFontUnderline
            | Attribute::AttrFontDecoration(_)
            | Attribute::AttrFontLetterSpacing(_)
            | Attribute::AttrFontWordSpacing(_)
            | Attribute::AttrFontAlign(_)
            | Attribute::AttrBgImage(_)
            | Attribute::AttrBgGradient(_)
            | Attribute::AttrBorderWidth(_)
            | Attribute::AttrBorderWidthEach(_, _, _, _)
            | Attribute::AttrBorderColor(_)
            | Attribute::AttrBorderRounded(_)
            | Attribute::AttrBorderStyle(_)
            | Attribute::AttrBorderShadow(_, _, _, _, _)
            | Attribute::AttrBorderInsetShadow(_, _, _, _, _)
            | Attribute::AttrPointer
            | Attribute::AttrExplain
            | Attribute::AttrOverflow(_, _)
            | Attribute::AttrPseudoRule(_, _)
            | Attribute::AttrTransition(_, _)
            | Attribute::AttrGridTracks(_, _)
            | Attribute::AttrAnimation(_, _, _, _)
            | Attribute::AttrFontWhiteSpace(_) => {}
        }
    }
    // A `<textarea>` carries no `type` attr; mark it "textarea" so the cursor
    // renders multiline and the loop inserts `\n` on Enter (vs submit on input).
    let input_type = if is_multiline {
        "textarea".to_string()
    } else {
        attr_str(attrs, "type").unwrap_or("text").to_string()
    };
    // Sanitize value/placeholder: both are seeded from Ipê `Attr.value` /
    // `Attr.placeholder` (attacker-controllable model data) and rendered into the
    // terminal stream — an unescaped `\x1b` would inject ANSI/OSC sequences.
    let value: String = attr_str(attrs, "value")
        .unwrap_or("")
        .chars()
        .map(sanitize_rune)
        .collect();
    let placeholder: String = attr_str(attrs, "placeholder")
        .unwrap_or("")
        .chars()
        .map(sanitize_rune)
        .collect();
    // Checked detection. A checkbox uses `checked`/`value="true"`. A radio in the
    // common hand-rolled idiom (`value = if selected then val else ""`) signals
    // selection by a NON-EMPTY value — so a radio is checked when an explicit
    // `checked` attr is present OR its value is non-empty and not "false". Without
    // the radio clause the selected radio kept drawing ○ (the "radio doesn't work"
    // report — onClick fires, but there was no visual feedback).
    // A typed `AttrChecked` is authoritative over that heuristic.
    let explicit_checked = attrs.iter().find_map(|a| match a {
        Attribute::AttrChecked(b) => Some(*b),
        _ => None,
    });
    let checked = explicit_checked.unwrap_or_else(|| {
        attr_str(attrs, "checked").is_some()
            || value == "true"
            || (input_type == "radio" && !value.is_empty() && value != "false")
    });
    let events = super::focus::collect_events(attrs);

    let idx = ctx.focusables.len();
    let focused = idx == ctx.focus_idx;

    // The text-input cursor, as `(line, col)` to reverse-video AFTER the track
    // fill (so a cursor past the content lands on a track cell, ). `None`
    // for non-text / unfocused inputs.
    let mut cursor_marker: Option<(usize, usize)> = None;
    let mut block: Block = match input_type.as_str() {
        "checkbox" => {
            let g = if checked { "☑" } else { "☐" };
            Block::single(
                g.to_string(),
                Style {
                    reverse: focused,
                    ..style
                },
            )
        }
        "radio" => {
            let g = if checked { "●" } else { "○" };
            Block::single(
                g.to_string(),
                Style {
                    reverse: focused,
                    ..style
                },
            )
        }
        "range" => {
            // Track with the thumb positioned at value within [min, max]. Track
            // width follows `Ui.width` (was a fixed 12 — the slider rendered
            // narrower than its declared width); fall back to 12 when unsized.
            let min: f64 = attr_str(attrs, "min")
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0.0);
            let max: f64 = attr_str(attrs, "max")
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(100.0);
            let val: f64 = value.trim().parse().unwrap_or(min);
            let width = width_length(attrs)
                .and_then(|l| resolve_fixed_w(&l, avail_w, ctx.canvas))
                .unwrap_or(12)
                .max(3);
            let frac = if max > min {
                ((val - min) / (max - min)).clamp(0.0, 1.0)
            } else {
                0.0
            };
            // Inset the thumb to the INNER span [1, width-2] so it is never
            // overwritten by the `├`/`┤` end-glyphs (the "ball disappears at the
            // extremes" report — at val≈0/100 the thumb landed on position
            // 0 / width-1 and the bracket won the cell).
            let span = width - 3; // count of steps between the two inner ends
            let thumb = 1 + (frac * span as f64).round() as usize;
            let thumb = thumb.clamp(1, width - 2);
            let track: String = (0..width)
                .map(|i| {
                    if i == 0 {
                        '├'
                    } else if i == width - 1 {
                        '┤'
                    } else if i == thumb {
                        '●'
                    } else {
                        '─'
                    }
                })
                .collect();
            Block::single(
                track,
                Style {
                    reverse: focused,
                    ..style
                },
            )
        }
        _ => {
            // Text-like input (incl. textarea): sync the edit buffer to the model's
            // value, then render it (or placeholder). The cursor is a REVERSE-VIDEO
            // cell over the underlying char/track, NOT a glyph insert — so it
            // doesn't shift the track.
            ctx.inputs.sync_value(idx, &value);
            let st = ctx.inputs.get(idx);
            let masked = input_type == "password";
            let run_style = style; // field is NOT whole-reversed (only the cursor cell)
            let cursor_cell: Option<(usize, usize)> = if masked {
                // Masked single line: content hidden as bullets; cursor tracks the
                // EDIT position (st.cursor), not always the end — Left/Home/Ctrl-Left
                // move the caret and it must render where the caret actually is.
                let n = st.buffer.chars().count();
                if focused {
                    Some((0, st.cursor.min(n)))
                } else {
                    None
                }
            } else if st.buffer.is_empty() && !focused {
                None
            } else {
                let runes: Vec<char> = st.buffer.chars().collect();
                let cursor = st.cursor.min(runes.len());
                let (cl, cc) = cursor_line_col(&runes, cursor);
                if focused { Some((cl, cc)) } else { None }
            };
            let block = if masked {
                Block::single("•".repeat(st.buffer.chars().count()), run_style)
            } else if st.buffer.is_empty() && !focused {
                // Empty + unfocused: italic placeholder when present, else empty
                // line — the track fill paints the field bounds.
                if placeholder.is_empty() {
                    Block::single(String::new(), run_style)
                } else {
                    Block::single(
                        placeholder.clone(),
                        Style {
                            italic: true,
                            ..run_style
                        },
                    )
                }
            } else {
                let runes: Vec<char> = st.buffer.chars().collect();
                let mut out: Vec<Vec<Run>> = Vec::new();
                for seg in split_buffer_lines(&runes) {
                    out.push(vec![Run {
                        text: seg.into_iter().collect(),
                        style: run_style,
                    }]);
                }
                if out.is_empty() {
                    out.push(vec![Run {
                        text: String::new(),
                        style: run_style,
                    }]);
                }
                Block { lines: out }
            };
            // Stash the cursor cell so it's applied AFTER the track fill (the track
            // pads the line out, so reversing a cell past current content lands on a
            // track ░ — exactly the reverse-over-track cursor).
            cursor_marker = cursor_cell;
            block
        }
    };
    // Honour `Ui.width` on a text-like field so it renders at a fixed/fill width.
    // checkbox / radio are glyph-only (no track); range owns its slider track.
    // Text-like inputs (text / password / email / search / textarea) paint a SHADED
    // TRACK across their full width (the paintInputBufferAdvanced) so the field
    // bounds stay visible even when empty — dim grey when no bg, else the bg
    // lightened by 38; real content + cursor paint over the track.
    let is_text_like = !matches!(input_type.as_str(), "checkbox" | "radio" | "range");
    // Border frame spec — a bordered input draws a REAL 1-cell box (correct
    // Ipe.Ui: Border.width > 0 ⇒ a frame).
    let mut bw = 0i64;
    let mut bcolor: Option<Color> = None;
    let mut bsty = String::from("solid");
    for a in attrs {
        match a {
            Attribute::AttrBorderWidth(n) if *n > 0 => bw = *n,
            Attribute::AttrBorderWidthEach(t, r, b, l)
                if t.saturating_add(*r).saturating_add(*b).saturating_add(*l) > 0 =>
            {
                bw = t
                    .saturating_add(*r)
                    .saturating_add(*b)
                    .saturating_add(*l)
                    .max(1)
            }
            Attribute::AttrBorderColor(c) => bcolor = Some(*c),
            Attribute::AttrBorderStyle(s) => bsty = s.clone(),
            _ => {}
        }
    }
    let border_spec: Option<BorderSpec> = if bw > 0 {
        Some((
            bcolor.as_ref().map(color_of),
            bsty,
            (true, true, true, true),
        ))
    } else {
        None
    };
    // The frame consumes a 1-cell ring each side; reserve it so the OUTER box
    // still fits the requested `Ui.width` (border-box sizing, Elm-ui style).
    let frame_ring = if border_spec.is_some() { 2 } else { 0 };
    if input_type != "range" {
        // Resolve the field width: explicit `Ui.width` → its cells; else the
        // text-like field stretches to the parent's allocation so an unsized input
        // still shows a full-width groove.
        let cells = match width_length(attrs) {
            Some(l) if fill_spec(&l, ctx.canvas).is_some() => Some(avail_w),
            Some(l) => resolve_fixed_w(&l, avail_w, ctx.canvas),
            None if is_text_like => Some(avail_w),
            None => None,
        };
        if let Some(c) = cells {
            let target = c.saturating_sub(frame_ring).max(1);
            if is_text_like {
                block.fill_input_track(target, style.bg, input_track_fg(style.bg));
            } else {
                block.set_width(target, style.bg);
            }
        }
    }
    // Reverse-video the cursor cell (reverse-over-track cursor) — applied after the
    // track fill so a cursor at/after the content lands on a track ░.
    if let Some((cl, cc)) = cursor_marker {
        block.reverse_cell_at(cl, cc);
    }
    // Multiline: honour a fixed `Ui.height (px)` — normalise to EXACTLY that many
    // rows, scrolling the window to keep the cursor row visible (correct Ipe.Ui: a
    // fixed-height textarea scrolls internally; it neither grows with content nor
    // shrinks below its height).
    if is_multiline && let Some(rows) = height_cells(attrs, ctx.canvas) {
        let inner_rows = rows.saturating_sub(frame_ring).max(1);
        let total = block.lines.len();
        if total > inner_rows {
            let cur_line = cursor_marker.map(|(l, _)| l).unwrap_or(0);
            let start = cur_line
                .saturating_sub(inner_rows - 1)
                .min(total - inner_rows);
            let end = (start + inner_rows).min(block.lines.len());
            block.lines = block
                .lines
                .get(start..end)
                .map(<[Vec<Run>]>::to_vec)
                .unwrap_or_default();
        } else {
            // Pad with blank track rows so the box keeps its fixed height.
            let track_w = block.width();
            let tfg = input_track_fg(style.bg);
            while block.lines.len() < inner_rows {
                block.lines.push(vec![Run {
                    text: "░".repeat(track_w),
                    style: Style {
                        fg: Some(tfg),
                        bg: style.bg,
                        ..Style::default()
                    },
                }]);
            }
        }
    }
    let width = block.width();
    let height = block.height().max(1);
    ctx.focusables.push(Focusable {
        events,
        is_input: true,
        input_type,
        value,
        placeholder,
        line: 0,
        col: 0,
        width,
        height,
    });
    let rendered = Rendered {
        block,
        hits: vec![(idx, 0, 0, width, height)],
    };
    match &border_spec {
        Some(spec) => frame_rendered(rendered, spec, style),
        None => rendered,
    }
}

/// Map a flat char-cursor into `(line, col)` over a `'\n'`-separated buffer.
fn cursor_line_col(runes: &[char], cursor: usize) -> (usize, usize) {
    let mut line = 0usize;
    let mut col = 0usize;
    for c in runes.iter().take(cursor) {
        if *c == '\n' {
            line += 1;
            col = 0;
        } else {
            col += 1;
        }
    }
    (line, col)
}

/// Split a char buffer into visual lines on `'\n'` (always ≥ 1 line).
fn split_buffer_lines(runes: &[char]) -> Vec<Vec<char>> {
    let mut lines: Vec<Vec<char>> = vec![Vec::new()];
    for c in runes {
        if *c == '\n' {
            lines.push(Vec::new());
        } else if let Some(last) = lines.last_mut() {
            last.push(*c);
        }
    }
    lines
}

/// Render one Element node, cascading text style + collecting focusables.
/// `avail_w` is the cell width the parent allocated to this node (for `Fill`).
fn render_node<M: Clone>(
    node: &Element<M>,
    inherited: Style,
    ctx: &mut Ctx<M>,
    avail_w: usize,
) -> Rendered {
    // Bound recursion depth (stack-overflow guard on a deeply-nested tree).
    let _depth = match DepthGuard::enter() {
        Some(g) => g,
        None => {
            return Rendered {
                block: Block::default(),
                hits: vec![],
            };
        }
    };
    match node {
        Element::Empty => Rendered {
            block: Block::default(),
            hits: vec![],
        },
        Element::Text(t) => {
            let block = if inherited.white_space.preserves_newlines() {
                Block {
                    lines: t
                        .split('\n')
                        .map(|line| {
                            vec![Run {
                                text: line.chars().map(sanitize_rune).collect(),
                                style: inherited,
                            }]
                        })
                        .collect(),
                }
            } else {
                Block::single(t.chars().map(sanitize_rune).collect(), inherited)
            };
            Rendered {
                block,
                hits: vec![],
            }
        }
        Element::Cells(grid) => {
            // `Ui.cells`: a raw cell grid, painted verbatim — one row per line,
            // each rune sanitized like the `Element::Text` path. This restores
            // the full-screen raw-paint capability inside an `Ipe.Ui` view.
            let lines: Vec<Vec<Run>> = grid
                .iter()
                .map(|row| {
                    let text: String = row.iter().copied().map(sanitize_rune).collect();
                    vec![Run {
                        text,
                        style: inherited,
                    }]
                })
                .collect();
            Rendered {
                block: Block { lines },
                hits: vec![],
            }
        }
        Element::Raw(h) => {
            // `Ui.html` (Ipe.Html escape hatch): the terminal can't render markup,
            // so degrade to the node's TEXT content (word-wrapped) instead of a
            // blank region (audit #22). Empty → nothing.
            let text = html_text(h);
            if text.trim().is_empty() {
                Rendered {
                    block: Block::default(),
                    hits: vec![],
                }
            } else {
                let lines: Vec<Vec<Run>> = wrap_text(&text, avail_w.max(1))
                    .into_iter()
                    .map(|l| {
                        vec![Run {
                            text: l,
                            style: inherited,
                        }]
                    })
                    .collect();
                Rendered {
                    block: Block { lines },
                    hits: vec![],
                }
            }
        }
        Element::TaggedNode(tag, _desc, attrs, _kids) if tag == "input" || tag == "textarea" => {
            render_input(attrs, inherited, ctx, avail_w, tag == "textarea")
        }
        Element::TaggedNode(tag, _desc, attrs, kids) if tag == "button" => {
            // A button is focusable; render its label (kids), highlighted when
            // focused. Click is dispatched from its events in the loop.
            let events = super::focus::collect_events(attrs);
            let idx = ctx.focusables.len();
            let focused = idx == ctx.focus_idx;
            ctx.focusables.push(Focusable {
                events,
                is_input: false,
                input_type: String::new(),
                value: String::new(),
                placeholder: String::new(),
                line: 0,
                col: 0,
                width: 0,
                height: 1,
            });
            let w = walk_attrs(attrs, inherited);
            let content_avail = node_content_avail(avail_w, &w, ctx.canvas);
            let label_style = Style {
                reverse: focused,
                ..w.style
            };
            let child_blocks: Vec<Rendered> = kids
                .iter()
                .map(|k| render_node(k, label_style, ctx, content_avail))
                .collect();
            let mut inner = match w.dir {
                Dir::Column => vstack(child_blocks, 0, label_style.bg, ctx.canvas),
                Dir::Row => hstack(
                    child_blocks,
                    ctx.canvas.cells_x(w.spacing_px),
                    label_style.bg,
                ),
            };
            apply_self_width(&mut inner.block, &w, content_avail, ctx.canvas);
            let mut padded = apply_padding(inner, &w, ctx.canvas, label_style);
            // Force the focus reverse over the whole label row(s).
            if focused {
                for line in &mut padded.block.lines {
                    for run in line {
                        run.style.reverse = true;
                    }
                }
            }
            let h = padded.block.height().max(1);
            let bw = padded.block.width();
            // Record this button's hit (line/col resolved by the caller's compose).
            padded.hits.insert(0, (idx, 0, 0, bw, h));
            padded
        }
        Element::Node(desc, attrs, kids) | Element::TaggedNode(_, desc, attrs, kids) => {
            // A section whose first child is a heading with no visible content
            // lays that heading out as nothing, so an absent title leaves
            // neither a bold run nor a blank row (the rule HTML applies).
            let kids: &[Element<M>] = match section_head(desc, kids) {
                SectionHead::Empty => kids.get(1..).unwrap_or_default(),
                SectionHead::NoHeading | SectionHead::Present => kids,
            };
            // A code block keeps its newlines and spaces unless the author
            // sets another `Font.whiteSpace` on it.
            let base = if matches!(desc, Description::DescCodeBlock) {
                Style {
                    white_space: WhiteSpace::Pre,
                    ..inherited
                }
            } else {
                inherited
            };
            let mut w = walk_attrs(attrs, base);
            // The node's role: a heading reads bold (the style cascades to its
            // text children via `w.style`); a paragraph / text column joins and
            // wraps its text content.
            match desc {
                Description::DescHeading(_) | Description::DescSectionHeading => {
                    w.style.bold = true;
                }
                Description::DescParagraph => w.is_paragraph = true,
                Description::DescTextColumn => w.is_text_column = true,
                Description::NoDescription
                | Description::DescMain
                | Description::DescNavigation
                | Description::DescContentInfo
                | Description::DescComplementary
                | Description::DescLabel(_)
                | Description::DescLivePolite
                | Description::DescLiveAssertive
                | Description::DescButton
                | Description::DescSection
                | Description::DescCodeBlock
                | Description::DescCode
                | Description::DescKbd
                | Description::DescForm => {}
            }
            let content_avail = node_content_avail(avail_w, &w, ctx.canvas);
            // Paragraph / textColumn: join the element's text content and
            // word-wrap to the available width (the isParagraph/isTextColumn
            // branch in layoutElement, ~1474-1518). Each wrapped line is one
            // Text run; textColumn inserts a blank line between child paragraphs.
            let mut inner = if w.is_paragraph || w.is_text_column {
                let wrap_w = content_avail.max(1);
                let ws = w.style.white_space;
                let keep = ws.preserves_newlines();
                let mut lines: Vec<Vec<Run>> = Vec::new();
                if w.is_text_column {
                    for (i, k) in kids.iter().enumerate() {
                        if i > 0 {
                            lines.push(Vec::new());
                        }
                        for l in layout_text(&extract_text(k, keep), wrap_w, ws) {
                            lines.push(vec![Run {
                                text: l,
                                style: w.style,
                            }]);
                        }
                    }
                } else {
                    let joined = kids
                        .iter()
                        .map(|k| extract_text(k, keep))
                        .collect::<Vec<_>>()
                        .join(" ");
                    for l in layout_text(&joined, wrap_w, ws) {
                        lines.push(vec![Run {
                            text: l,
                            style: w.style,
                        }]);
                    }
                }
                if lines.is_empty() {
                    lines.push(Vec::new());
                }
                let mut block = Block { lines };
                // the paragraph/textColumn box width is `wrapW` (= the full
                // available content width when unsized), and its bg fills that whole
                // rect via `fillRect`. So a bg-carrying paragraph paints every
                // wrapped line out to `wrap_w`, not just to the text —
                // wide page-card fill (the styled-cell-grid `232837×41` divergence).
                if w.style.bg.is_some() {
                    block.set_width(wrap_w, w.style.bg);
                }
                Rendered {
                    block,
                    hits: vec![],
                }
            } else if w.is_grid {
                render_grid(kids, &w, ctx, content_avail)
            } else {
                // Render children IN ORDER (preserves focusable push order = Tab
                // order), pairing each with its fill spec, then drop empty blocks.
                let mut specs: Vec<Option<FillSpec>> = Vec::new();
                let mut h_specs: Vec<Option<FillSpec>> = Vec::new();
                let mut aligns: Vec<(Option<HAlign>, Option<VAlign>)> = Vec::new();
                let mut children: Vec<Rendered> = Vec::new();
                for k in kids.iter() {
                    let r = render_node(k, w.style, ctx, content_avail);
                    if r.block.height() > 0 {
                        specs.push(child_width_length(k).and_then(|l| fill_spec(&l, ctx.canvas)));
                        h_specs
                            .push(child_height_length(k).and_then(|l| fill_spec(&l, ctx.canvas)));
                        aligns.push(child_align(k));
                        children.push(r);
                    }
                }
                // In a ROW, fill children share the leftover width (column children
                // already span the full width). Post-pass: rewrite fill child widths.
                if w.dir == Dir::Row {
                    distribute_row_fill(
                        &mut children,
                        &specs,
                        content_avail,
                        ctx.canvas.cells_x(w.spacing_px),
                    );
                }
                // In a fixed-height COLUMN, height-fill children split the leftover
                // vertical space (audit #2/#4). Needs the column's resolved height.
                if w.dir == Dir::Column
                    && let Some(th) = w
                        .height
                        .as_ref()
                        .and_then(|l| resolve_fixed_h(l, ctx.canvas))
                {
                    distribute_col_fill(
                        &mut children,
                        &h_specs,
                        th,
                        ctx.canvas.cells_y(w.spacing_px),
                        w.style.bg,
                    );
                }
                // Cross-axis alignment: offset each child within the stack's cross
                // size per its Ui.alignX/alignY (was dropped → everything flush
                // top-left). Column cross-axis = horizontal (alignX); row cross-axis
                // = vertical (alignY). Applied before stacking.
                match w.dir {
                    Dir::Column => {
                        let target_w = if matches!(w.width, None | Some(Length::Content)) {
                            children.iter().map(|r| r.block.width()).max().unwrap_or(0)
                        } else {
                            content_avail
                        };
                        for (i, r) in children.iter_mut().enumerate() {
                            let ax = aligns.get(i).and_then(|a| a.0);
                            let off = halign_offset(ax, target_w.saturating_sub(r.block.width()));
                            pad_left_block(r, off, w.style.bg);
                        }
                    }
                    Dir::Row => {
                        let target_h = children.iter().map(|r| r.block.height()).max().unwrap_or(0);
                        for (i, r) in children.iter_mut().enumerate() {
                            let cw = r.block.width();
                            let ay = aligns.get(i).and_then(|a| a.1);
                            let off = valign_offset(ay, target_h.saturating_sub(r.block.height()));
                            pad_top_block(r, off, cw, w.style.bg);
                        }
                    }
                }
                let mut inner = if children.is_empty() {
                    Rendered {
                        block: Block {
                            lines: vec![Vec::new()],
                        },
                        hits: vec![],
                    }
                } else {
                    match w.dir {
                        Dir::Column => vstack(
                            children,
                            ctx.canvas.cells_y(w.spacing_px),
                            w.style.bg,
                            ctx.canvas,
                        ),
                        Dir::Row => hstack(children, ctx.canvas.cells_x(w.spacing_px), w.style.bg),
                    }
                };
                apply_self_width(&mut inner.block, &w, content_avail, ctx.canvas);
                apply_self_height(&mut inner.block, &w, ctx.canvas);
                inner
            };
            // Font text-align: shift each text line within the box's content width
            // (center/right). Only visible when the box is wider than the text — a
            // content-sized box has no slack, so it's a no-op there. (audit #7)
            if let Some(fa) = w.font_align {
                let sized = !matches!(w.width, None | Some(Length::Content));
                let target = if sized {
                    content_avail
                } else {
                    inner.block.width()
                };
                for line in &mut inner.block.lines {
                    let lw: usize = line.iter().map(Run::width).sum();
                    let off = halign_offset(Some(fa), target.saturating_sub(lw));
                    if off > 0 {
                        line.insert(
                            0,
                            Run {
                                text: " ".repeat(off),
                                style: Style {
                                    bg: w.style.bg,
                                    ..Style::default()
                                },
                            },
                        );
                    }
                }
            }
            let padded = apply_padding(inner, &w, ctx.canvas, w.style);
            // Border frame: wrap the padded block in a 1-cell box. The frame
            // consumes 1 cell on each side of the OUTER block, sitting outside
            // the padding ring (padding already applied; frame adds the border
            // ring outside it).
            let host = apply_border(padded, &w, w.style);
            // Nearby overlays (Ui.above/below/onLeft/onRight/inFront/behind) — were
            // silently dropped (audit #12/#16). Place each relative to the host:
            // directional ones stack; inFront/behind overlay at the top-left.
            let nearby: Vec<(Location, &Element<M>)> = attrs
                .iter()
                .filter_map(|a| match a {
                    Attribute::AttrNearby(loc, el) => Some((*loc, el)),
                    _ => None,
                })
                .collect();
            if nearby.is_empty() {
                host
            } else {
                let mut result = host;
                for (loc, el) in nearby {
                    let ov = render_node(el, w.style, ctx, content_avail);
                    result = match loc {
                        Location::Above => vstack(vec![ov, result], 0, w.style.bg, ctx.canvas),
                        Location::Below => vstack(vec![result, ov], 0, w.style.bg, ctx.canvas),
                        Location::OnLeft => hstack(vec![ov, result], 0, w.style.bg),
                        Location::OnRight => hstack(vec![result, ov], 0, w.style.bg),
                        Location::InFront => overlay_blocks(result, ov, true),
                        Location::Behind => overlay_blocks(result, ov, false),
                    };
                }
                result
            }
        }
    }
}

/// Flatten the visible text of a `Ipe.Html` node (for the `Ui.html` raw escape
/// hatch rendered in a terminal): concatenate `HText`/`HRaw` leaves, recursing
/// into elements. Markup/attrs are dropped — the terminal shows text only.
fn html_text<M>(h: &Html<M>) -> String {
    let _depth = match DepthGuard::enter() {
        Some(g) => g,
        None => return String::new(),
    };
    // Sanitize every leaf: this text is written straight to the terminal stream,
    // so an unescaped `\x1b` in attacker-controlled `Ui.html` content would inject
    // ANSI/OSC sequences (cursor moves, window-title, OSC-52 clipboard write).
    match h {
        Html::HText(t) => t.chars().map(sanitize_rune).collect(),
        Html::HRaw(r) => r.chars().map(sanitize_rune).collect(),
        Html::HElement(_, _, kids) => kids.iter().map(html_text).collect::<Vec<_>>().join(""),
    }
}

/// Extract the concatenated text content of an element subtree.
///
/// Flattens every `Text` leaf, space-joining nested ones. `keep_newlines`
/// keeps a `'\n'` as a line break; every other control becomes a space.
fn extract_text<M>(el: &Element<M>, keep_newlines: bool) -> String {
    let _depth = match DepthGuard::enter() {
        Some(g) => g,
        None => return String::new(),
    };
    match el {
        // Sanitize: paragraph/textColumn text flows here to the terminal stream;
        // an unescaped `\x1b` would inject ANSI/OSC sequences (same vector as the
        // Element::Text render path, which already sanitizes).
        Element::Text(t) => t
            .chars()
            .map(|c| {
                if keep_newlines && c == '\n' {
                    c
                } else {
                    sanitize_rune(c)
                }
            })
            .collect(),
        Element::Node(_, _, kids) | Element::TaggedNode(_, _, _, kids) => kids
            .iter()
            .map(|k| extract_text(k, keep_newlines))
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    }
}

/// Lay `text` out as lines under the white-space mode `ws`.
///
/// A wrapping mode word-wraps to `width` cells; a non-wrapping mode that keeps
/// newlines (`Pre`) keeps each line verbatim; `NoWrap` collapses whitespace
/// onto one line.
fn layout_text(text: &str, width: usize, ws: WhiteSpace) -> Vec<String> {
    if ws.wraps() {
        wrap_text(text, width)
    } else if ws.preserves_newlines() {
        text.split('\n').map(str::to_owned).collect()
    } else {
        vec![text.split_whitespace().collect::<Vec<_>>().join(" ")]
    }
}

/// Word-wrap `text` to `width` cells: soft-break on whitespace runs,
/// hard-break (char chunks) only
/// for words longer than the line; embedded `'\n'` forces a break. Always ≥ 1
/// line. Total + bounds-checked — no panics.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }
    let mut out: Vec<String> = Vec::new();
    for paragraph in text.split('\n') {
        wrap_paragraph_into(paragraph, width, &mut out);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

fn wrap_paragraph_into(text: &str, width: usize, out: &mut Vec<String>) {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.is_empty() {
        out.push(String::new());
        return;
    }
    let mut cur = String::new();
    let mut cur_w = 0usize;
    for word in words {
        let ww = UnicodeWidthStr::width(word);
        // Word wider than the line — flush, then hard-break into chunks.
        if ww > width {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
                cur_w = 0;
            }
            hard_break_chunks(word, width, out);
            continue;
        }
        let needed = if cur.is_empty() { ww } else { ww + 1 };
        if cur_w + needed > width {
            out.push(std::mem::take(&mut cur));
            cur.push_str(word);
            cur_w = ww;
        } else {
            if !cur.is_empty() {
                cur.push(' ');
                cur_w += 1;
            }
            cur.push_str(word);
            cur_w += ww;
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
}

/// Split a long word into chunks of at most `width` display cells.
/// Char-counted, total.
fn hard_break_chunks(word: &str, width: usize, out: &mut Vec<String>) {
    if width == 0 || word.is_empty() {
        out.push(word.to_string());
        return;
    }
    let mut cur = String::new();
    let mut cur_w = 0usize;
    for ch in word.chars() {
        let cw = UnicodeWidthChar::width(ch).unwrap_or(0);
        if cur_w + cw > width && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
            cur_w = 0;
        }
        cur.push(ch);
        cur_w += cw;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
}

/// Grid layout (the `gridLayout` branch, ~2518-2549). `grid_min_px` (from
/// `Ui.gridColumns N`) → min column cells; `ncols = avail / min` (≥1); cells flow
/// row-major into `ncols` per row, each column padded to `col_width`; rows stack
/// vertically with the spacing gap. Focusable hits are shifted to absolute coords.
fn render_grid<M: Clone>(
    kids: &[Element<M>],
    w: &Walked,
    ctx: &mut Ctx<M>,
    content_avail: usize,
) -> Rendered {
    // Explicit tracks (Ipe.Ui.Grid.columns/tracks) → size each column from its
    // px/fr/auto spec (audit #13); else auto-flow by grid_min_px.
    if !w.grid_cols.is_empty() {
        return render_grid_tracked(kids, w, ctx, content_avail);
    }
    let min_col = {
        let c = ctx.canvas.cells_x(w.grid_min_px);
        if c == 0 { 10 } else { c }
    };
    let avail = content_avail.max(1);
    let ncols = (avail / min_col).max(1);
    let col_width = (avail / ncols).max(1);
    let gap_y = ctx.canvas.cells_y(w.spacing_px);

    // Render every child at col_width (its own content fits within); collect into
    // a flat list (skipping empty blocks would break row-major alignment, so keep
    // ALL cells in order).
    let cells: Vec<Rendered> = kids
        .iter()
        .map(|k| render_node(k, w.style, ctx, col_width))
        .collect();

    // Chunk row-major into rows of `ncols`, hstack each row (no inter-cell gap —
    // each cell is padded to col_width, matching `x = innerCol + col*colWidth`),
    // vstack the rows with the spacing gap.
    let mut rows: Vec<Rendered> = Vec::new();
    for chunk in cells.chunks(ncols.max(1)) {
        let mut sized: Vec<Rendered> = Vec::new();
        for r in chunk {
            let mut r2 = Rendered {
                block: r.block.clone(),
                hits: r.hits.clone(),
            };
            // Pad the cell to col_width with the CELL's OWN bg, not the grid's:
            // the padding carries the cell colour so `Background.color` fills the
            // full column-width slot (the `3c3250×30` contiguous fill the
            // styled-cell-grid test expects). Fall back to the grid's bg for a
            // cell that declares none.
            let cell_bg = cell_block_bg(&r2.block).or(w.style.bg);
            r2.block.set_width(col_width, cell_bg);
            sized.push(r2);
        }
        rows.push(hstack(sized, 0, w.style.bg));
    }
    vstack(rows, gap_y, w.style.bg, ctx.canvas)
}

/// Explicit-track grid (`Ipe.Ui.Grid.columns`/`tracks`): size each column from its
/// px/fr/auto spec, lay children row-major into those columns with the spacing
/// gap. fr tracks split the leftover after px tracks + gaps; auto ≈ 1fr.
fn render_grid_tracked<M: Clone>(
    kids: &[Element<M>],
    w: &Walked,
    ctx: &mut Ctx<M>,
    content_avail: usize,
) -> Rendered {
    let canvas = ctx.canvas;
    let gap_x = canvas.cells_x(w.spacing_px);
    let gap_y = canvas.cells_y(w.spacing_px);
    let ncols = w.grid_cols.len().max(1);
    let avail = content_avail.max(1);
    let total_gap = gap_x.saturating_mul(ncols.saturating_sub(1));
    // Saturating folds, not `.sum()`: a well-typed Ipê `Grid.px N` / `Grid.fr N`
    // takes an arbitrary Int, so an unclamped sum of large track weights
    // overflows usize — in release that wraps to a tiny `fr_total` divisor →
    // huge per-track width → `" ".repeat(huge)` OOM/capacity panic (top-critical
    // audit finding). Each Fr weight is clamped at MAX_CELLS before summing, and
    // the fold saturates so the total can never wrap.
    let fixed: usize = w
        .grid_cols
        .iter()
        .map(|t| match t {
            GridTrack::Px(n) => canvas.cells_x(*n),
            _ => 0,
        })
        .fold(0usize, usize::saturating_add);
    let fr_total: usize = w
        .grid_cols
        .iter()
        .map(|t| match t {
            GridTrack::Fr(n) => ((*n).max(0) as usize).min(MAX_CELLS),
            GridTrack::Auto => 1,
            _ => 0,
        })
        .fold(0usize, usize::saturating_add)
        .max(1);
    let leftover = avail.saturating_sub(fixed + total_gap);
    let widths: Vec<usize> = w
        .grid_cols
        .iter()
        .map(|t| match t {
            GridTrack::Px(n) => canvas.cells_x(*n).max(1),
            GridTrack::Fr(n) => {
                (leftover.saturating_mul(((*n).max(0) as usize).min(MAX_CELLS)) / fr_total).max(1)
            }
            GridTrack::Auto => (leftover / fr_total).max(1),
        })
        .collect();

    let mut rows: Vec<Rendered> = Vec::new();
    for chunk in kids.chunks(ncols) {
        let mut sized: Vec<Rendered> = Vec::new();
        for (ci, k) in chunk.iter().enumerate() {
            let cw = widths.get(ci).copied().unwrap_or(1);
            let mut r = render_node(k, w.style, ctx, cw);
            let cell_bg = cell_block_bg(&r.block).or(w.style.bg);
            r.block.set_width(cw, cell_bg);
            sized.push(r);
        }
        rows.push(hstack(sized, gap_x, w.style.bg));
    }
    vstack(rows, gap_y, w.style.bg, canvas)
}

/// The cell's own background, read from its rendered runs — the bg a grid cell
/// painted on itself (via its `Background.color` cascading into `apply_padding` /
/// `set_width`). Returns the first run-level bg found scanning the block. `None`
/// when no run carries a bg (a cell with no `Background.color`), letting the caller
/// fall back to the grid's bg. Total — no index/unwrap.
fn cell_block_bg(block: &Block) -> Option<(u8, u8, u8)> {
    block.lines.iter().flatten().find_map(|run| run.style.bg)
}

/// Wrap a rendered block in a 1-cell border frame. The frame is only drawn when
/// `w.border` is set AND the block is ≥ 2×2. Corners ┌┐└┘, edges ─│ per
/// style; the border colour (when set) overrides the glyph fg. Hits + content
/// shift down/right by 1.
fn apply_border(inner: Rendered, w: &Walked, self_style: Style) -> Rendered {
    match &w.border {
        Some(spec) => frame_rendered(inner, spec, self_style),
        None => inner,
    }
}

/// Wrap a `Rendered` in a 1-cell box-drawing frame from a `BorderSpec`. Shared by
/// box borders (`apply_border`) and bordered inputs (`render_input`). Shifts the
/// inner content + focusable hits +1 line / +1 col (the frame's top-left).
fn frame_rendered(inner: Rendered, spec: &BorderSpec, self_style: Style) -> Rendered {
    let (border_fg, style, (s_top, s_right, s_bottom, s_left)) = (spec.0, spec.1.as_str(), spec.2);
    let inner_w = inner.block.width();
    let (hor, vert, tl, tr, bl, br) = border_glyphs(style);
    // Border runs inherit the frame fg (when set) but keep the node's bg so the
    // box reads as one filled rect.
    let bstyle = Style {
        fg: border_fg.or(self_style.fg),
        ..self_style
    };
    let edge = |ch: &str, n: usize| Run {
        text: ch.repeat(n),
        style: bstyle,
    };
    let corner = |ch: &str| Run {
        text: ch.to_string(),
        style: bstyle,
    };

    // A horizontal edge row carries a corner only where a vertical side also
    // meets it; otherwise the edge glyph runs the full width (a partial border —
    // e.g. a lone top rule — is just a horizontal line, no corners). audit #6.
    let h_edge_row = |left_glyph: &str, right_glyph: &str| -> Vec<Run> {
        let mut row = Vec::new();
        if s_left {
            row.push(corner(left_glyph));
        }
        if inner_w > 0 {
            row.push(edge(hor, inner_w));
        }
        if s_right {
            row.push(corner(right_glyph));
        }
        row
    };

    let mut block = Block::default();
    if s_top {
        block.lines.push(h_edge_row(tl, tr));
    }
    for line in &inner.block.lines {
        let mut row = Vec::new();
        if s_left {
            row.push(corner(vert));
        }
        let lw: usize = line.iter().map(Run::width).sum();
        row.extend(line.iter().cloned());
        if lw < inner_w {
            row.push(Run {
                text: " ".repeat(inner_w - lw),
                style: self_style,
            });
        }
        if s_right {
            row.push(corner(vert));
        }
        block.lines.push(row);
    }
    if s_bottom {
        block.lines.push(h_edge_row(bl, br));
    }
    // Content + focusables shift by the present top/left edges.
    let dl = usize::from(s_top);
    let dc = usize::from(s_left);
    let hits = inner
        .hits
        .into_iter()
        .map(|(idx, l, c, ww, hh)| (idx, l + dl, c + dc, ww, hh))
        .collect();
    Rendered { block, hits }
}

/// Box-drawing glyphs `(hor, vert, tl, tr, bl, br)` for a border style:
/// dashed ┄┆, dotted ┈┊, rounded ╭╮╰╯, everything else solid ─│.
fn border_glyphs(
    style: &str,
) -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
) {
    match style {
        "dashed" => ("┄", "┆", "┌", "┐", "└", "┘"),
        "dotted" => ("┈", "┊", "┌", "┐", "└", "┘"),
        "rounded" => ("─", "│", "╭", "╮", "╰", "╯"),
        _ => ("─", "│", "┌", "┐", "└", "┘"),
    }
}

/// Content width available to a node's children = the node's allocation minus its
/// horizontal padding (and the 1-cell-each-side border ring, when present).
fn node_content_avail(avail_w: usize, w: &Walked, canvas: Canvas) -> usize {
    let pad = canvas.cells_x(w.pad_left)
        + canvas.cells_x(w.pad_right)
        + if w.border.is_some() { 2 } else { 0 };
    let base = match &w.width {
        None => avail_w,
        Some(l) => {
            if let Some((_, mn, mx)) = fill_spec(l, canvas) {
                // fill → the parent-allocated width, clamped to its own min/max
                // (a ROW parent re-distributes the final width over this).
                let mut t = avail_w;
                if let Some(m) = mn {
                    t = t.max(m);
                }
                if let Some(m) = mx {
                    t = t.min(m);
                }
                t
            } else {
                // Px / Vw / Min / Max → resolved cells; Content → avail.
                resolve_fixed_w(l, avail_w, canvas).unwrap_or(avail_w)
            }
        }
    };
    base.saturating_sub(pad)
}

/// Constrain a node's inner block to its `Ui.width` directive. `Auto` keeps the
/// natural content width (byte-identical to the pre-Fill behaviour); `Fill`
/// expands to the content allocation; `Px` sets the exact cell width.
fn apply_self_width(block: &mut Block, w: &Walked, content_avail: usize, _canvas: Canvas) {
    // `content_avail` is already the node's resolved inner width (node_content_avail
    // applied Px/Vw/Min/Max/Fill). So a sized node takes content_avail; an Auto /
    // Content node keeps its natural content width. A fill child in a row has its
    // final width re-set by the parent's distribution pass (which overrides this).
    let sized = !matches!(w.width, None | Some(Length::Content));
    if sized {
        block.set_width(content_avail, w.style.bg);
    }
}

/// Hold a box to its declared `Ui.height` (Px/Vh/Min/Max): pad short blocks with
/// bg-filled blank rows, clip tall ones. A `None`/`Content`/`Fill` height is
/// content-sized (no change). Was missing entirely → fixed-height boxes collapsed
/// to their content height (audit #1/#15).
fn apply_self_height(block: &mut Block, w: &Walked, canvas: Canvas) {
    let rows = match &w.height {
        Some(l) => match resolve_fixed_h(l, canvas) {
            Some(r) => r,
            None => return,
        },
        None => return,
    };
    // Terminal-proportional clamp: `resolve_fixed_h` → `cells_y` caps at MAX_CELLS
    // but `rows × width` can still reach ~10 GB. Cap the pad-row count the same way
    // as `apply_padding` top/bottom so the product stays bounded.
    let rows = clamp_pad_rows(rows, canvas);
    let width = block.width();
    if block.lines.len() > rows {
        block.lines.truncate(rows.max(1));
    } else {
        let blank = vec![Run {
            text: " ".repeat(width),
            style: Style {
                bg: w.style.bg,
                ..Style::default()
            },
        }];
        while block.lines.len() < rows {
            block.lines.push(blank.clone());
        }
    }
}

/// The `Ui.width` `Length` declared on a child element, if any.
fn child_width_length<M>(el: &Element<M>) -> Option<Length> {
    match el {
        Element::Node(_, attrs, _) | Element::TaggedNode(_, _, attrs, _) => width_length(attrs),
        _ => None,
    }
}

/// The `Ui.height` `Length` declared on a child element, if any.
fn child_height_length<M>(el: &Element<M>) -> Option<Length> {
    match el {
        Element::Node(_, attrs, _) | Element::TaggedNode(_, _, attrs, _) => height_length(attrs),
        _ => None,
    }
}

/// Height-fill distribution for a fixed-height COLUMN: fill children (`specs[i]`
/// `Some`) split `total_h` minus the non-fill heights and inter-child gaps, by
/// portion. Each fill child's block is padded (with `bg` blank rows) or clipped
/// to its share. Non-fill children keep their height. The y-axis analogue of
/// `distribute_row_fill`. (audit #2/#4)
fn distribute_col_fill(
    children: &mut [Rendered],
    specs: &[Option<FillSpec>],
    total_h: usize,
    gap: usize,
    bg: Option<(u8, u8, u8)>,
) {
    let n = children.len();
    if n == 0 {
        return;
    }
    let is_fill = |i: usize| specs.get(i).copied().flatten().is_some();
    let portion = |i: usize| {
        specs
            .get(i)
            .copied()
            .flatten()
            .map_or(1usize, |(p, _, _)| portion_shares(p))
    };
    let fill_idx: Vec<usize> = (0..n).filter(|i| is_fill(*i)).collect();
    if fill_idx.is_empty() {
        return;
    }
    let gaps = gap.saturating_mul(n.saturating_sub(1));
    let fixed: usize = children
        .iter()
        .enumerate()
        .filter(|(i, _)| !is_fill(*i))
        .map(|(_, r)| r.block.height())
        .sum();
    let leftover = total_h.saturating_sub(fixed + gaps);
    // Saturating fold: each portion is at most `Portion::MAX`, but a column with
    // many fill children could still wrap with plain `.sum()`.
    let portion_total: usize = fill_idx
        .iter()
        .map(|i| portion(*i))
        .fold(0usize, usize::saturating_add)
        .max(1);
    let last = fill_idx.last().copied().unwrap_or(0);
    let mut used = 0usize;
    for &i in &fill_idx {
        let share = if i == last {
            leftover.saturating_sub(used)
        } else {
            // saturating_mul: `portion(i)` ≤ MAX_CELLS; `leftover` ≤ total_h which
            // derives from `cells_y` (already ≤ MAX_CELLS). The product fits within
            // usize on any realistic canvas; saturation guards against extremes.
            leftover.saturating_mul(portion(i)) / portion_total
        };
        used += share;
        if let Some(child) = children.get_mut(i) {
            let cw = child.block.width();
            let cur = child.block.height();
            if cur > share {
                child.block.lines.truncate(share.max(1));
            } else {
                let blank = vec![Run {
                    text: " ".repeat(cw),
                    style: Style {
                        bg,
                        ..Style::default()
                    },
                }];
                while child.block.lines.len() < share {
                    child.block.lines.push(blank.clone());
                }
            }
        }
    }
}

/// The `(Ui.alignX, Ui.alignY)` a child declares, read by its PARENT to place it
/// on the cross axis. `(None, None)` → flush top-left.
fn child_align<M>(el: &Element<M>) -> (Option<HAlign>, Option<VAlign>) {
    match el {
        Element::Node(_, attrs, _) | Element::TaggedNode(_, _, attrs, _) => {
            let mut ax = None;
            let mut ay = None;
            for a in attrs {
                match a {
                    Attribute::AttrAlignX(h) => ax = Some(*h),
                    Attribute::AttrAlignY(v) => ay = Some(*v),
                    _ => {}
                }
            }
            (ax, ay)
        }
        _ => (None, None),
    }
}

/// Cross-axis offset for an alignment within `slack` free cells: center → half,
/// right/bottom → all, left/top/unset → 0.
fn halign_offset(a: Option<HAlign>, slack: usize) -> usize {
    match a {
        Some(HAlign::CenterX) => slack / 2,
        Some(HAlign::AlignRight) => slack,
        _ => 0,
    }
}
fn valign_offset(a: Option<VAlign>, slack: usize) -> usize {
    match a {
        Some(VAlign::CenterY) => slack / 2,
        Some(VAlign::AlignBottom) => slack,
        _ => 0,
    }
}

/// Left-pad every line of `r` by `off` cells (carrying `bg`) and shift its hits —
/// places the content at horizontal offset `off` within its slot (column cross-axis
/// alignment / el self-align).
fn pad_left_block(r: &mut Rendered, off: usize, bg: Option<(u8, u8, u8)>) {
    if off == 0 {
        return;
    }
    let pad = Run {
        text: " ".repeat(off),
        style: Style {
            bg,
            ..Style::default()
        },
    };
    for line in &mut r.block.lines {
        line.insert(0, pad.clone());
    }
    for h in &mut r.hits {
        h.2 += off;
    }
}

/// Prepend `off` blank `width`-wide lines to `r` and shift its hits — places the
/// content at vertical offset `off` within its slot (row cross-axis alignment).
fn pad_top_block(r: &mut Rendered, off: usize, width: usize, bg: Option<(u8, u8, u8)>) {
    if off == 0 {
        return;
    }
    let blank = vec![Run {
        text: " ".repeat(width),
        style: Style {
            bg,
            ..Style::default()
        },
    }];
    let mut lines = Vec::with_capacity(off + r.block.lines.len());
    for _ in 0..off {
        lines.push(blank.clone());
    }
    lines.append(&mut r.block.lines);
    r.block.lines = lines;
    for h in &mut r.hits {
        h.1 += off;
    }
}

/// Fill-distribution pass for a ROW. `children[i]` aligns with `specs[i]`; a
/// `Some((portion, min, max))` spec marks a fill child. Non-fill children keep
/// their already-rendered width; the leftover (`content_avail` − non-fill widths
/// − gaps) is split among fill children by portion and clamped to each child's
/// min/max. Children are already rendered (focusables pushed), so this only
/// resizes the fill blocks — last fill child absorbs the rounding remainder.
fn distribute_row_fill(
    children: &mut [Rendered],
    specs: &[Option<FillSpec>],
    content_avail: usize,
    gap: usize,
) {
    // Each portion is at most `Portion::MAX`; saturating-fold the sum so a
    // pathological all-max-portion row cannot wrap `total_portion` to a tiny
    // divisor and drive per-child widths to ~usize::MAX.
    let total_portion: usize = specs
        .iter()
        .filter_map(|s| s.map(|(p, _, _)| portion_shares(p)))
        .fold(0usize, usize::saturating_add)
        .max(1);
    let n = children.len();
    // saturating_mul/add: `gap` derives from `Ui.spacing` (caller-controlled), so
    // `(n - 1) * gap` and `non_fill + gaps` can overflow usize. The result only
    // feeds `saturating_sub`, so saturating here never changes a valid layout.
    let gaps = if n > 1 { gap.saturating_mul(n - 1) } else { 0 };
    let non_fill: usize = children
        .iter()
        .zip(specs)
        .filter(|(_, s)| s.is_none())
        .map(|(r, _)| r.block.width())
        .sum();
    let remaining = content_avail.saturating_sub(non_fill.saturating_add(gaps));
    let fill_count = specs.iter().filter(|s| s.is_some()).count();
    let mut used = 0usize;
    let mut done = 0usize;
    for (r, s) in children.iter_mut().zip(specs) {
        if let Some((p, mn, mx)) = s {
            done += 1;
            let p_usize = portion_shares(*p);
            let share = if done == fill_count {
                remaining.saturating_sub(used)
            } else {
                remaining.saturating_mul(p_usize) / total_portion
            };
            used = used.saturating_add(share);
            let mut target = share;
            if let Some(m) = mn {
                target = target.max(*m);
            }
            if let Some(m) = mx {
                target = target.min(*m);
            }
            // Preserve the fill child's own bg when padding out to `target`.
            let bg = r
                .block
                .lines
                .first()
                .and_then(|l| l.last())
                .and_then(|run| run.style.bg);
            r.block.set_width(target.max(1), bg);
        }
    }
}

const SGR_RESET: &str = "\x1b[0m";

/// Honour the `NO_COLOR` convention (https://no-color.org): when the env var is
/// present and non-empty, suppress all COLOUR output (fg/bg) — text attributes
/// (bold/italic/underline/…) are kept, only colour is dropped. Cached once.
fn no_color() -> bool {
    static NC: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *NC.get_or_init(|| {
        crate::system::read_env_var_os("NO_COLOR")
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    })
}

/// Parse a `"fg:<code>"` / `"bg:<code>"` palette decoration into its SGR code.
/// The `<code>` is produced by the terminal-attribute lowering from
/// [`crate::color::AnsiColor::named_sgr_code`] (plus the `39`/`49` reset), so it
/// is always a valid `u8`; a malformed string yields `None` (no colour, never a
/// panic).
fn parse_palette_code(s: &str) -> Option<u8> {
    s.split_once(':')
        .and_then(|(_, code)| code.parse::<u8>().ok())
}

/// SGR codes for one truecolour cell colour, down-sampled to the resolved
/// terminal profile through the ONE colour degradation point
/// ([`crate::color::Color::to_ansi`]). `fg` selects the foreground escape
/// family (`38`/`3x`/`9x`) vs the background (`48`/`4x`/`10x`).
///
/// A [`crate::color::AnsiColor::Default`] contributes no code (the cell keeps the
/// terminal default), matching the previous behaviour for a fully-transparent bg.
fn ansi_sgr_codes(rgb: (u8, u8, u8), profile: crate::color::TermProfile, fg: bool) -> Vec<String> {
    use crate::color::AnsiColor;
    let (r, g, b) = rgb;
    let color = crate::color::Color::rgb(i64::from(r), i64::from(g), i64::from(b));
    match color.to_ansi(profile) {
        AnsiColor::Default => Vec::new(),
        AnsiColor::Rgb(r, g, b) => {
            let intro = if fg { 38 } else { 48 };
            vec![format!("{intro};2;{r};{g};{b}")]
        }
        AnsiColor::Indexed(i) => {
            let intro = if fg { 38 } else { 48 };
            vec![format!("{intro};5;{i}")]
        }
        // The 16-colour palette maps index `0..=7` to the standard SGR base
        // (30-37 fg / 40-47 bg) and `8..=15` to the bright base (90-97 / 100-107),
        // via the one palette-code SSOT.
        named @ AnsiColor::Named(_) => named
            .named_sgr_code(fg)
            .map(|code| vec![code.to_string()])
            .unwrap_or_default(),
    }
}

#[cfg(test)]
fn sgr(style: Style) -> String {
    // Auto-detect the terminal colour capability at the single `resolve_term_profile`
    // point; cell colours then degrade through `Color::to_ansi`. The rendering path
    // (`emit_block`) threads an explicit profile via `sgr_with_profile` instead.
    sgr_with_profile(style, crate::color::resolve_term_profile())
}

/// SGR body with an explicit [`crate::color::TermProfile`], so a caller can pin the
/// colour capability (deterministic rendering). `sgr` supplies the auto-detected
/// profile in production.
fn sgr_with_profile(style: Style, profile: crate::color::TermProfile) -> String {
    let mut codes: Vec<String> = Vec::new();
    if style.bold {
        codes.push("1".to_string());
    }
    if style.dim {
        codes.push("2".to_string());
    }
    if style.italic {
        codes.push("3".to_string());
    }
    if style.underline {
        codes.push("4".to_string());
    }
    if style.overline {
        codes.push("53".to_string());
    }
    if style.strike {
        codes.push("9".to_string());
    }
    if style.reverse {
        codes.push("7".to_string());
    }
    if !no_color() {
        // A named-palette code takes precedence over truecolour: the portable
        // path emits its own SGR code (30-37 / 90-97 / 39), else the cell colour
        // degrades through `Color::to_ansi`.
        if let Some(code) = style.fg_palette {
            codes.push(code.to_string());
        } else if let Some(rgb) = style.fg {
            codes.extend(ansi_sgr_codes(rgb, profile, true));
        }
        if let Some(code) = style.bg_palette {
            codes.push(code.to_string());
        } else if let Some(rgb) = style.bg {
            codes.extend(ansi_sgr_codes(rgb, profile, false));
        }
    }
    if codes.is_empty() {
        String::new()
    } else {
        format!("\x1b[{}m", codes.join(";"))
    }
}

fn emit_block(
    block: &Block,
    cols: usize,
    scroll_y: usize,
    rows: usize,
    profile: crate::color::TermProfile,
) -> String {
    let mut out = String::new();
    // Lines are CRLF-separated, but the SEPARATOR goes BEFORE each line after the
    // first — NOT a trailing CRLF after the last visible row. A trailing CRLF on a
    // full-height frame (visible lines == terminal rows) advances the cursor past
    // the bottom row and scrolls the whole screen up by one, dropping the top row
    // (the root padding). `paint()` issues ESC[2J + home first, so a
    // leading-separator model lands every row correctly.
    for (i, line) in block.lines.iter().skip(scroll_y).take(rows).enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        let mut col = 0usize;
        for run in line {
            if col >= cols {
                break;
            }
            let mut text = String::new();
            let mut w = 0usize;
            for ch in run.text.chars() {
                let cw = UnicodeWidthChar::width(ch).unwrap_or(0);
                if col + w + cw > cols {
                    break;
                }
                text.push(ch);
                w += cw;
            }
            let esc = sgr_with_profile(run.style, profile);
            if esc.is_empty() {
                out.push_str(&text);
            } else {
                out.push_str(&esc);
                out.push_str(&text);
                out.push_str(SGR_RESET);
            }
            col += w;
        }
    }
    out
}

/// Render the view, returning the ANSI frame (scrolled to `scroll_y`), the
/// discovered focusables (with absolute line positions), and the full content
/// height. The loop uses the focusables to dispatch input/click Msgs and to keep
/// the focused element on screen.
pub fn render_with_focus<M: Clone>(
    view: &Element<M>,
    cols: usize,
    rows: usize,
    focus_idx: usize,
    inputs: &mut InputRegistry,
    scroll_y: usize,
) -> (String, Vec<Focusable<M>>, usize) {
    // Production: auto-detect the terminal colour capability at the single
    // `resolve_term_profile` point.
    render_with_focus_profiled(
        view,
        cols,
        rows,
        focus_idx,
        inputs,
        scroll_y,
        crate::color::resolve_term_profile(),
    )
}

/// `render_with_focus` with an explicit [`crate::color::TermProfile`], so a caller
/// (e.g. a test) can pin the colour capability for a deterministic frame.
#[allow(clippy::too_many_arguments)]
fn render_with_focus_profiled<M: Clone>(
    view: &Element<M>,
    cols: usize,
    rows: usize,
    focus_idx: usize,
    inputs: &mut InputRegistry,
    scroll_y: usize,
    profile: crate::color::TermProfile,
) -> (String, Vec<Focusable<M>>, usize) {
    let canvas = Canvas::new(cols, rows);
    let mut ctx = Ctx {
        canvas,
        focus_idx,
        focusables: Vec::new(),
        inputs,
    };
    let mut rendered = render_node(view, Style::default(), &mut ctx, cols);
    // Backfill the root element's page background across the full frame rect — the
    // gap / padding / trailing cells no child covered take the root bg. Without
    // this the page background stops at the content's right edge + inter-element
    // gaps read as terminal-default.
    if let Some(bg) = root_bg(view) {
        // The page bg reaches the right edge only when the root box spans the full
        // width — i.e. it has no explicit width, or a width that resolves to the
        // whole frame (root `width == innerMaxW == cols`). An explicitly
        // NARROWER root (px / vw / a capped max / capped fill) fills only its own
        // resolved width; the trailing columns stay terminal-default.
        let fill_to_edge = match root_width(view) {
            None | Some(Length::Content) => true,
            Some(Length::Fill(_)) => true,
            Some(l) => resolve_fixed_w(&l, cols, canvas).is_none_or(|cells| cells >= cols),
        };
        rendered.block.backfill_root_bg(cols, bg, fill_to_edge);
    }
    let content_h = rendered.block.height();
    // Write back absolute positions onto the focusables (for scroll + hit-test).
    for (idx, line, col, width, h) in rendered.hits {
        if let Some(f) = ctx.focusables.get_mut(idx) {
            f.line = line;
            f.col = col;
            f.width = width;
            f.height = h;
        }
    }
    let frame = emit_block(&rendered.block, cols, scroll_y, rows, profile);
    (frame, ctx.focusables, content_h)
}

/// `Ipe.Ui` Element → ANSI frame, no focus (used by the layout tests + any
/// caller that doesn't need the input model).
pub fn element_to_cells<M: Clone>(view: &Element<M>, cols: usize, rows: usize) -> String {
    let mut inputs = InputRegistry::new();
    render_with_focus(view, cols, rows, usize::MAX, &mut inputs, 0).0
}

/// The content height an Element lays out to at the given width — the number of
/// rows its lines occupy, independent of any frame the caller paints it into.
/// A line-oriented caller sizes its frame to this so it emits exactly the view's
/// own lines with no trailing blank rows.
pub fn element_to_cells_height<M: Clone>(view: &Element<M>, cols: usize) -> usize {
    let mut inputs = InputRegistry::new();
    render_with_focus(view, cols, usize::MAX, usize::MAX, &mut inputs, 0).2
}

/// Test-only [`element_to_cells`] that pins the terminal colour profile, so
/// assertions over the raw SGR sequence are independent of the ambient `TERM`
/// (production still auto-detects via `element_to_cells` / `render_with_focus`).
#[cfg(test)]
fn element_to_cells_profiled<M: Clone>(
    view: &Element<M>,
    cols: usize,
    rows: usize,
    profile: crate::color::TermProfile,
) -> String {
    let mut inputs = InputRegistry::new();
    render_with_focus_profiled(view, cols, rows, usize::MAX, &mut inputs, 0, profile).0
}

#[cfg(test)]
mod tests {
    use super::super::super::ui::Description;
    use super::*;
    use crate::color::TermProfile;

    /// Render a view with the colour profile pinned to TrueColor, so raw
    /// `38;2;`/`48;2;` assertions do not depend on the ambient terminal.
    fn cells_true<M: Clone>(view: &Element<M>, cols: usize, rows: usize) -> String {
        element_to_cells_profiled(view, cols, rows, TermProfile::TrueColor)
    }

    fn rgb(r: i64, g: i64, b: i64) -> Color {
        Color::rgb(r, g, b)
    }
    fn node<M>(attrs: Vec<Attribute<M>>, kids: Vec<Element<M>>) -> Element<M> {
        Element::Node(Description::NoDescription, attrs, kids)
    }
    /// A `Ui.paragraph`-shaped node: `<p>` carrying the `DescParagraph` role.
    fn para<M>(attrs: Vec<Attribute<M>>, kids: Vec<Element<M>>) -> Element<M> {
        Element::TaggedNode("p".into(), Description::DescParagraph, attrs, kids)
    }
    fn input<M>(ty: &str, value: &str) -> Element<M> {
        Element::TaggedNode(
            "input".into(),
            Description::NoDescription,
            vec![
                Attribute::AttrAttribute("type".into(), ty.into()),
                Attribute::AttrAttribute("value".into(), value.into()),
            ],
            vec![],
        )
    }

    #[test]
    fn text_with_fg() {
        let t: Element<()> = node(
            vec![Attribute::AttrFontColor(rgb(255, 0, 0))],
            vec![Element::Text("hi".into())],
        );
        let frame = cells_true(&t, 80, 24);
        assert!(frame.contains("38;2;255;0;0"));
        assert!(frame.contains("hi"));
    }

    #[test]
    fn column_stacks_vertically() {
        let t: Element<()> = node(
            vec![Attribute::AttrSpacing(16)],
            vec![
                node(vec![], vec![Element::Text("a".into())]),
                node(vec![], vec![Element::Text("b".into())]),
            ],
        );
        let frame = element_to_cells(&t, 80, 24);
        assert!(frame.find('a').unwrap_or(99) < frame.find('b').unwrap_or(0));
    }

    #[test]
    fn checkbox_glyphs_track_checked() {
        let unchecked: Element<()> = input("checkbox", "false");
        assert!(element_to_cells(&unchecked, 80, 24).contains('☐'));
        let checked: Element<()> = input("checkbox", "true");
        assert!(element_to_cells(&checked, 80, 24).contains('☑'));
    }

    /// A typed `AttrChecked(false)` beats the `value="true"` heuristic, and
    /// `AttrChecked(true)` beats an empty value. Red without the override in
    /// `render_input`.
    #[test]
    fn attr_checked_overrides_value_heuristic() {
        let with = |ty: &str, value: &str, checked: bool| -> Element<()> {
            Element::TaggedNode(
                "input".into(),
                Description::NoDescription,
                vec![
                    Attribute::AttrAttribute("type".into(), ty.into()),
                    Attribute::AttrAttribute("value".into(), value.into()),
                    Attribute::AttrChecked(checked),
                ],
                vec![],
            )
        };
        let off = element_to_cells(&with("checkbox", "true", false), 80, 24);
        assert!(off.contains('☐') && !off.contains('☑'));
        let on = element_to_cells(&with("checkbox", "", true), 80, 24);
        assert!(on.contains('☑') && !on.contains('☐'));
        let radio_off = element_to_cells(&with("radio", "pick", false), 80, 24);
        assert!(radio_off.contains('○') && !radio_off.contains('●'));
    }

    /// A checkbox with a left label stays on one terminal row, because the
    /// `label` wrapper honours the `__row` marker. Red if `attach_label` stops
    /// emitting the axis marker on the wrapper.
    #[test]
    fn label_wrapper_keeps_row_axis() {
        use crate::ui::input::{input_checkbox_, input_label_left_};

        let el: Element<()> = input_checkbox_(
            Vec::new(),
            std::sync::Arc::new(|_b: bool| ()),
            std::sync::Arc::new(|_b: bool| Element::Empty),
            true,
            input_label_left_(Vec::new(), Element::Text("Agree".into())),
        );
        assert_eq!(element_to_cells_height(&el, 80), 1);
        let frame = element_to_cells(&el, 80, 24);
        assert!(frame.contains("Agree") && frame.contains('☑'), "{frame}");
    }

    /// A radio group draws exactly its selected option as filled, because the
    /// typed `AttrChecked` overrides the non-empty-value heuristic. Red without
    /// `AttrChecked` on each radio.
    #[test]
    fn ui_radio_draws_only_the_selected_option() {
        use crate::ui::input::{input_label_hidden_, input_option_, input_radio_};

        let options = ["a", "b", "c"]
            .into_iter()
            .map(|v| input_option_(v.to_owned(), Element::Text(v.to_uppercase())))
            .collect();
        let el: Element<()> = input_radio_(
            Vec::new(),
            std::sync::Arc::new(|_s: String| ()),
            options,
            "b".to_owned(),
            input_label_hidden_("Pick".to_owned()),
        );
        let frame = element_to_cells(&el, 80, 24);
        assert_eq!(frame.matches('●').count(), 1, "{frame}");
        assert_eq!(frame.matches('○').count(), 2, "{frame}");
    }

    #[test]
    fn focusables_collected_in_order() {
        let t: Element<()> = node(
            vec![],
            vec![
                input("text", "a"),
                input("checkbox", "false"),
                input("radio", "x"),
            ],
        );
        let mut reg = InputRegistry::new();
        let (_f, focusables, _h) = render_with_focus(&t, 80, 24, usize::MAX, &mut reg, 0);
        assert_eq!(focusables.len(), 3);
        assert_eq!(focusables[0].input_type, "text");
        assert_eq!(focusables[1].input_type, "checkbox");
    }

    #[test]
    fn focused_input_reverses() {
        let t: Element<()> = node(vec![], vec![input("text", "hi")]);
        let mut reg = InputRegistry::new();
        let (frame, _f, _h) = render_with_focus(&t, 80, 24, 0, &mut reg, 0);
        assert!(
            frame.contains("\x1b[7"),
            "focused input reverse-video: {frame:?}"
        );
    }

    #[test]
    fn fill_width_expands_to_avail() {
        let t: Element<()> = node(
            vec![
                Attribute::AttrWidth(Length::Fill(Portion::ONE)),
                Attribute::AttrBgColor(rgb(5, 6, 7)),
            ],
            vec![Element::Text("x".into())],
        );
        let frame = element_to_cells(&t, 20, 24);
        let first = frame.split("\r\n").next().unwrap_or("");
        let spaces = first.matches(' ').count();
        assert!(
            spaces >= 15,
            "fill expanded toward 20 cols: {first:?} ({spaces} spaces)"
        );
    }

    #[test]
    fn explicit_px_width_pads_box() {
        // canvas px_per_cell_x = 1280/80 = 16 → 160px ≈ 10 cells.
        let t: Element<()> = node(
            vec![
                Attribute::AttrWidth(Length::Px(160)),
                Attribute::AttrBgColor(rgb(1, 2, 3)),
            ],
            vec![Element::Text("hi".into())],
        );
        let frame = element_to_cells(&t, 80, 24);
        let first = frame.split("\r\n").next().unwrap_or("");
        // The bg fill extends the 2-char text toward ~10 cells.
        let visible_spaces = first.matches(' ').count();
        assert!(visible_spaces >= 5, "px width padded with bg: {first:?}");
    }

    #[test]
    fn vw_width_resolves_to_viewport_fraction() {
        // Vw(50) on 80 cols → ~40 cells of bg.
        let t: Element<()> = node(
            vec![
                Attribute::AttrWidth(Length::Vw(50)),
                Attribute::AttrBgColor(rgb(9, 9, 9)),
            ],
            vec![Element::Text("x".into())],
        );
        let frame = element_to_cells(&t, 80, 24);
        let first = frame.split("\r\n").next().unwrap_or("");
        let spaces = first.matches(' ').count();
        assert!(
            (30..=45).contains(&spaces),
            "Vw(50)≈40 cols: {first:?} ({spaces} spaces)"
        );
    }

    #[test]
    fn min_width_floors_content() {
        // Min(160, Content): content "hi" (2 cells) floored to 160px ≈ 10 cells.
        let t: Element<()> = node(
            vec![
                Attribute::AttrWidth(Length::Min(160, Box::new(Length::Content))),
                Attribute::AttrBgColor(rgb(4, 4, 4)),
            ],
            vec![Element::Text("hi".into())],
        );
        let frame = element_to_cells(&t, 80, 24);
        let first = frame.split("\r\n").next().unwrap_or("");
        assert!(
            first.matches(' ').count() >= 5,
            "min floored padding: {first:?}"
        );
    }

    #[test]
    fn max_width_caps_fill() {
        // Max(160, Fill): fill would claim 80 cols, capped to 160px ≈ 10 cells.
        let t: Element<()> = node(
            vec![
                Attribute::AttrWidth(Length::Max(160, Box::new(Length::Fill(Portion::ONE)))),
                Attribute::AttrBgColor(rgb(2, 2, 2)),
            ],
            vec![Element::Text("x".into())],
        );
        let frame = element_to_cells(&t, 80, 24);
        let first = frame.split("\r\n").next().unwrap_or("");
        let spaces = first.matches(' ').count();
        assert!(
            (3..=15).contains(&spaces),
            "Max caps fill at ~10 cols: {first:?} ({spaces})"
        );
    }

    /// Refusal: `fillPortion 0` and a negative portion are `shrink` — the
    /// layout pass gives them no fill spec, so they never take a share.
    #[test]
    fn fill_portion_non_positive_is_shrink() {
        use crate::ui::helpers::{ui_fill_, ui_fill_portion_, ui_shrink_};
        let canvas = Canvas::new(20, 24);
        assert!(fill_spec(&ui_fill_(), canvas).is_some());
        for n in [0, -3, i64::MIN] {
            assert_eq!(ui_fill_portion_(n), ui_shrink_(), "fillPortion {n}");
            assert_eq!(
                fill_spec(&ui_fill_portion_(n), canvas),
                None,
                "fillPortion {n}"
            );
        }
    }

    /// Refusal: in a row, a `fillPortion 0` child stays content-width beside a
    /// `fill` sibling, which takes the whole leftover.
    #[test]
    fn row_fill_portion_zero_keeps_content_width() {
        use crate::ui::helpers::{ui_fill_, ui_fill_portion_, ui_shrink_};
        let row_of = |left: Length| -> Element<()> {
            node(
                vec![Attribute::AttrStyle("__row".into(), String::new())],
                vec![
                    node(
                        vec![
                            Attribute::AttrWidth(left),
                            Attribute::AttrBgColor(rgb(10, 0, 0)),
                        ],
                        vec![Element::Text("x".into())],
                    ),
                    node(
                        vec![
                            Attribute::AttrWidth(ui_fill_()),
                            Attribute::AttrBgColor(rgb(0, 10, 0)),
                        ],
                        vec![Element::Text("y".into())],
                    ),
                ],
            )
        };
        let shrink = cells_true(&row_of(ui_shrink_()), 20, 24);
        let even = cells_true(&row_of(ui_fill_()), 20, 24);
        assert_ne!(shrink, even, "a fill sibling pair splits the row");
        for n in [0, -3] {
            let zero = cells_true(&row_of(ui_fill_portion_(n)), 20, 24);
            assert_eq!(zero, shrink, "fillPortion {n} lays out as shrink");
        }
    }

    /// `fill` is `fillPortion 1`, and a portion above `Portion::MAX` clamps.
    #[test]
    fn fill_portion_one_is_fill_and_huge_clamps() {
        use crate::ui::helpers::{ui_fill_, ui_fill_portion_};
        let canvas = Canvas::new(20, 24);
        assert_eq!(ui_fill_portion_(1), ui_fill_());
        assert_eq!(
            fill_spec(&ui_fill_(), canvas),
            Some((Portion::ONE, None, None))
        );
        assert_eq!(
            fill_spec(&ui_fill_portion_(i64::MAX), canvas),
            Some((Portion::MAX, None, None))
        );
        assert_eq!(
            fill_spec(&ui_fill_portion_(i64::from(Portion::MAX.get()) + 1), canvas),
            Some((Portion::MAX, None, None))
        );
    }

    #[test]
    fn row_fill_splits_width() {
        // A row of two equal-portion fill children each take ~half of 20 cols.
        let child = |c: Color| -> Element<()> {
            node(
                vec![
                    Attribute::AttrWidth(Length::Fill(Portion::ONE)),
                    Attribute::AttrBgColor(c),
                ],
                vec![Element::Text("x".into())],
            )
        };
        let row: Element<()> = node(
            vec![Attribute::AttrStyle("__row".into(), String::new())],
            vec![child(rgb(10, 0, 0)), child(rgb(0, 10, 0))],
        );
        let frame = cells_true(&row, 20, 24);
        let first = frame.split("\r\n").next().unwrap_or("");
        // Both fills present; neither claimed the whole row (would overflow pre-fix).
        assert!(
            first.contains("48;2;10;0;0"),
            "left fill bg present: {first:?}"
        );
        assert!(
            first.contains("48;2;0;10;0"),
            "right fill bg present: {first:?}"
        );
    }

    #[test]
    fn textarea_renders_multiline_with_cursor() {
        let t: Element<()> = Element::TaggedNode(
            "textarea".into(),
            Description::NoDescription,
            vec![Attribute::AttrAttribute("value".into(), "ab\ncd".into())],
            vec![],
        );
        let mut reg = InputRegistry::new();
        let (frame, _f, _h) = render_with_focus(&t, 80, 24, 0, &mut reg, 0);
        let a = frame.find("ab");
        let c = frame.find("cd");
        assert!(
            a.is_some() && c.is_some(),
            "both visual lines render: {frame:?}"
        );
        assert!(a < c, "first line above second: {frame:?}");
        // Cursor is a reverse-video cell , not an inserted glyph.
        assert!(
            frame.contains("\x1b[7"),
            "reverse-video cursor present (focused): {frame:?}"
        );
        assert!(!frame.contains('▏'), "no inserted cursor glyph: {frame:?}");
    }

    #[test]
    fn wrap_text_breaks_on_whitespace() {
        let lines = wrap_text("the quick brown fox", 9);
        assert_eq!(lines, vec!["the quick", "brown fox"]);
    }

    #[test]
    fn wrap_text_hard_breaks_long_word() {
        // A 12-char word exceeds width 5 → char-chunks of ≤5.
        let lines = wrap_text("abcdefghijkl", 5);
        assert_eq!(lines, vec!["abcde", "fghij", "kl"]);
    }

    #[test]
    fn wrap_text_honours_newlines_and_zero_width() {
        assert_eq!(wrap_text("a\nb", 10), vec!["a", "b"]);
        assert_eq!(wrap_text("anything", 0), vec![""]);
        assert_eq!(wrap_text("", 10), vec![""]);
    }

    #[test]
    fn paragraph_word_wraps() {
        // A paragraph node carrying long text wraps to the canvas width.
        let t: Element<()> = para(
            vec![],
            vec![Element::Text(
                "alpha beta gamma delta epsilon zeta eta theta iota".into(),
            )],
        );
        // 20 cols → multiple wrapped lines.
        let frame = element_to_cells(&t, 20, 24);
        let body_lines: Vec<&str> = frame
            .split("\r\n")
            .filter(|l| l.contains("alpha") || l.contains("zeta"))
            .collect();
        assert!(frame.contains("alpha"), "first word present: {frame:?}");
        // The text spans more than one line (not a single truncated line).
        assert!(
            frame.matches("\r\n").count() >= 2,
            "wrapped onto ≥2 lines: {frame:?}"
        );
        let _ = body_lines;
    }

    #[test]
    fn grid_flows_row_major() {
        // gridColumns 80 px ≈ 5 cells min → on 60 cols, ncols = 60/5 = 12 → all
        // six single-char cells land on one row.
        let cell = |s: &str| -> Element<()> { node(vec![], vec![Element::Text(s.into())]) };
        let g: Element<()> = node(
            vec![
                Attribute::AttrStyle("__grid".into(), "true".into()),
                Attribute::AttrStyle("__gridMin".into(), "80".into()),
            ],
            vec![
                cell("G1"),
                cell("G2"),
                cell("G3"),
                cell("G4"),
                cell("G5"),
                cell("G6"),
            ],
        );
        let frame = element_to_cells(&g, 60, 24);
        let first = frame.split("\r\n").next().unwrap_or("");
        assert!(first.contains("G1"), "G1 on row 0: {first:?}");
        assert!(
            first.contains("G6"),
            "G6 on the SAME row 0 (row-major flow): {first:?}"
        );
    }

    #[test]
    fn reverse_cell_marks_one_cell() {
        let mut b = Block::single("hello".into(), Style::default());
        b.reverse_cell_at(0, 2); // reverse the 'l' at col 2
        let line = b.lines.first().expect("one line");
        // Rebuilds as before("he") + reverse("l") + after("lo").
        let rev: Vec<&Run> = line.iter().filter(|r| r.style.reverse).collect();
        assert_eq!(rev.len(), 1, "exactly one reverse run");
        assert_eq!(rev.first().map(|r| r.text.as_str()), Some("l"));
        let full: String = line.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(full, "hello", "content unchanged, only style split");
    }

    #[test]
    fn reverse_cell_past_content_appends_space() {
        let mut b = Block::single("hi".into(), Style::default());
        b.reverse_cell_at(0, 5); // cursor past "hi"
        let line = b.lines.first().expect("one line");
        let full: String = line.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(full, "hi    ", "padded to col 5 + reverse space");
        assert!(
            line.iter().any(|r| r.style.reverse),
            "reverse cursor appended"
        );
    }

    #[test]
    fn focused_empty_input_has_no_glyph_just_reverse_track() {
        // A focused empty text input shows a reverse-video track cell, not a ▏ glyph.
        let inp: Element<()> = Element::TaggedNode(
            "input".into(),
            Description::NoDescription,
            vec![
                Attribute::AttrWidth(Length::Px(160)),
                Attribute::AttrAttribute("type".into(), "text".into()),
            ],
            vec![],
        );
        let mut reg = InputRegistry::new();
        let (frame, _f, _h) = render_with_focus(&inp, 80, 24, 0, &mut reg, 0);
        assert!(!frame.contains('▏'), "no inserted cursor glyph: {frame:?}");
        assert!(
            frame.contains("\x1b[7"),
            "reverse-video cursor cell: {frame:?}"
        );
        assert!(frame.contains('░'), "track still present: {frame:?}");
    }

    #[test]
    fn input_paints_shaded_track() {
        // A bg-coloured text input with explicit width fills its full width with
        // the ░ track (lightened bg fg), not plain spaces.
        let inp: Element<()> = Element::TaggedNode(
            "input".into(),
            Description::NoDescription,
            vec![
                Attribute::AttrWidth(Length::Px(160)),
                Attribute::AttrBgColor(rgb(30, 36, 60)),
                Attribute::AttrAttribute("type".into(), "text".into()),
            ],
            vec![],
        );
        let frame = cells_true(&inp, 80, 24);
        assert!(frame.contains('░'), "shaded track present: {frame:?}");
        // track fg = lighten(bg, 38) = (68, 74, 98).
        assert!(
            frame.contains("38;2;68;74;98"),
            "track fg = lightened bg: {frame:?}"
        );
        // bg of the field present too.
        assert!(
            frame.contains("48;2;30;36;60"),
            "field bg present: {frame:?}"
        );
    }

    #[test]
    fn input_track_no_bg_is_dim_grey() {
        let inp: Element<()> = Element::TaggedNode(
            "input".into(),
            Description::NoDescription,
            vec![
                Attribute::AttrWidth(Length::Px(160)),
                Attribute::AttrAttribute("type".into(), "text".into()),
            ],
            vec![],
        );
        let frame = cells_true(&inp, 80, 24);
        assert!(frame.contains('░'), "track present without bg: {frame:?}");
        assert!(
            frame.contains("38;2;110;110;110"),
            "dim-grey track: {frame:?}"
        );
    }

    #[test]
    fn border_frames_a_box() {
        let t: Element<()> = node(
            vec![
                Attribute::AttrBorderWidth(1),
                Attribute::AttrBorderColor(rgb(100, 130, 180)),
            ],
            vec![Element::Text("hi".into())],
        );
        let frame = element_to_cells(&t, 80, 24);
        assert!(
            frame.contains('┌') && frame.contains('┐'),
            "top corners: {frame:?}"
        );
        assert!(
            frame.contains('└') && frame.contains('┘'),
            "bottom corners: {frame:?}"
        );
        assert!(
            frame.contains('│') && frame.contains('─'),
            "edges: {frame:?}"
        );
        assert!(frame.contains("hi"), "content inside frame: {frame:?}");
    }

    #[test]
    fn border_style_picks_dashed_dotted_glyphs() {
        let mk = |style: &str| -> Element<()> {
            node(
                vec![
                    Attribute::AttrBorderWidth(1),
                    Attribute::AttrBorderStyle(style.into()),
                ],
                vec![Element::Text("x".into())],
            )
        };
        assert!(element_to_cells(&mk("dashed"), 80, 24).contains('┄'));
        assert!(element_to_cells(&mk("dotted"), 80, 24).contains('┈'));
    }

    #[test]
    fn frame_has_no_trailing_newline() {
        // A full-height frame must NOT end with CRLF — a trailing newline on the
        // bottom row scrolls the screen up one (drops the top row). Build a frame
        // with as many lines as terminal rows.
        let kids: Vec<Element<()>> = (0..10)
            .map(|i| node(vec![], vec![Element::Text(format!("r{i}"))]))
            .collect();
        let t: Element<()> = node(vec![], kids);
        let frame = element_to_cells(&t, 80, 10);
        assert!(!frame.ends_with("\r\n"), "no trailing CRLF: {frame:?}");
        // Still CRLF-separated between rows.
        assert_eq!(
            frame.matches("\r\n").count(),
            9,
            "9 separators for 10 rows: {frame:?}"
        );
    }

    #[test]
    fn root_bg_fills_full_width_and_gaps() {
        // The root box's bg fills the WHOLE frame rect, so trailing columns +
        // inter-element gaps the content didn't cover read as the page bg, not
        // terminal-default. A root column (bg set, no explicit width) with a
        // child narrower than the frame must still paint bg to the right edge.
        let t: Element<()> = node(
            vec![Attribute::AttrBgColor(rgb(18, 22, 38))],
            vec![node(vec![], vec![Element::Text("x".into())])],
        );
        let frame = cells_true(&t, 20, 3);
        let first = frame.split("\r\n").next().unwrap_or("");
        // The page bg SGR reaches the row; the glyph 'x' sits on it and the
        // remaining cells to col 20 carry the same bg (one fill run to the edge).
        assert!(
            first.contains("48;2;18;22;38"),
            "page bg present: {first:?}"
        );
        // Count visible spaces after 'x' — the bg-filled tail to col 20.
        let spaces = first.matches(' ').count();
        assert!(
            spaces >= 15,
            "bg fills toward the right edge: {first:?} ({spaces})"
        );
    }

    #[test]
    fn root_bg_none_leaves_cells_default() {
        // No root bg → nothing is backfilled (matches the empty cell grid); the
        // frame carries no 48;2 background SGR at all.
        let t: Element<()> = node(vec![], vec![node(vec![], vec![Element::Text("x".into())])]);
        let frame = cells_true(&t, 20, 3);
        assert!(
            !frame.contains("48;2;"),
            "no bg backfilled without a root bg: {frame:?}"
        );
    }

    #[test]
    fn grid_cell_bg_fills_column_not_grid_bg() {
        // Each grid cell is padded to col_width with that CELL's own bg. A grid
        // with a page bg whose cells carry a different bg must show the CELL bg
        // across each column (contiguous), not the grid bg between content + edge.
        let cell = |s: &str| -> Element<()> {
            node(
                vec![Attribute::AttrBgColor(rgb(60, 50, 80))],
                vec![Element::Text(s.into())],
            )
        };
        let g: Element<()> = node(
            vec![
                Attribute::AttrBgColor(rgb(18, 22, 38)),
                Attribute::AttrStyle("__grid".into(), "true".into()),
                Attribute::AttrStyle("__gridMin".into(), "80".into()),
            ],
            vec![cell("G1"), cell("G2")],
        );
        let frame = cells_true(&g, 60, 4);
        let first = frame.split("\r\n").next().unwrap_or("");
        // The cell bg (60,50,80 = 3c3250) is present and fills past the 2-char
        // label toward its column width.
        assert!(
            first.contains("48;2;60;50;80"),
            "grid cell bg present: {first:?}"
        );
    }

    #[test]
    fn paragraph_bg_fills_wrap_width() {
        // A bg-carrying paragraph paints every wrapped line out to the wrap width
        // (the paragraph box width = wrapW), not just to the text.
        let t: Element<()> = para(
            vec![Attribute::AttrBgColor(rgb(35, 40, 55))],
            vec![Element::Text("alpha beta gamma delta epsilon".into())],
        );
        let frame = cells_true(&t, 20, 6);
        // Every text row carries the paragraph bg filling to ~20 cells.
        let body: Vec<&str> = frame
            .split("\r\n")
            .filter(|l| l.contains("48;2;35;40;55"))
            .collect();
        assert!(
            !body.is_empty(),
            "paragraph bg present on wrapped lines: {frame:?}"
        );
        let first = body.first().copied().unwrap_or("");
        // The bg run pads the wrapped line out (≥ several trailing bg spaces).
        assert!(
            first.matches(' ').count() >= 3,
            "paragraph bg pads to wrap width: {first:?}"
        );
    }

    #[test]
    fn scroll_offsets_content() {
        let kids: Vec<Element<()>> = (0..40)
            .map(|i| node(vec![], vec![Element::Text(format!("row{i}"))]))
            .collect();
        let t: Element<()> = node(vec![], kids);
        let mut reg = InputRegistry::new();
        let (frame, _f, h) = render_with_focus(&t, 80, 10, usize::MAX, &mut reg, 20);
        assert!(h >= 40);
        assert!(frame.contains("row20"), "scrolled to row20: {frame:?}");
        assert!(!frame.contains("row0\r\n"), "row0 scrolled off");
    }

    // Three `fillPortion i64::MAX` siblings must render without panic: the
    // portion clamps to `Portion::MAX` and the distribution folds saturate.
    #[test]
    fn fill_portion_max_i64_does_not_overflow() {
        let child = |label: &'static str| {
            node(
                vec![Attribute::AttrWidth(Length::fill_portion(i64::MAX))],
                vec![Element::Text(label.into())],
            )
        };
        // Wrap children in an explicit row (AttrSpacing 0 to stay minimal).
        // The default column direction is fine here — distribute_col_fill fires.
        let row: Element<()> = node(
            vec![
                Attribute::AttrWidth(Length::fill_portion(i64::MAX)),
                Attribute::AttrSpacing(0),
            ],
            vec![child("A"), child("B"), child("C")],
        );
        // 80×24 canvas — small enough to be fast, large enough to exercise layout.
        let frame = element_to_cells(&row, 80, 24);
        // The frame must be a valid (non-empty, bounded) ANSI string.
        // Any non-crash result means the fix held.
        assert!(
            frame.len() <= 80 * 24 * 16,
            "frame too large — likely unbounded allocation: {} bytes",
            frame.len()
        );
    }

    // RT-TUI-002: padding area product — huge AttrPadding values on a small canvas
    // must not cause an OOM / str::repeat panic. The terminal-proportional clamp
    // (clamp_pad_rows) gates each allocation so total rows stay ≤ canvas.rows *
    // PAD_ROW_SLACK.
    #[test]
    fn huge_padding_does_not_oom() {
        const COLS: usize = 80;
        const ROWS: usize = 24;
        let t: Element<()> = node(
            // AttrPadding(top, right, bottom, left) — all huge values.
            vec![Attribute::AttrPadding(
                3_000_000, 1_600_000, 3_000_000, 1_600_000,
            )],
            vec![Element::Text("hi".into())],
        );
        // This call must return; if the clamp is missing it allocates ~10 GB and
        // either panics (capacity overflow) or gets OOM-killed.
        let frame = element_to_cells(&t, COLS, ROWS);
        // The resulting frame must fit within a small multiple of the canvas.
        // PAD_ROW_SLACK = 4, so rendered block rows ≤ ROWS * 4 = 96.
        let line_count = frame.lines().count();
        assert!(
            line_count <= ROWS * (PAD_ROW_SLACK + 2),
            "frame line count {line_count} exceeded terminal-proportional cap on {ROWS}-row canvas"
        );
    }

    // RT-TUI-002 (spacing variant): Ui.spacing with a huge gap value inside a column
    // must also be bounded via clamp_pad_rows in vstack.
    #[test]
    fn huge_spacing_does_not_oom() {
        const COLS: usize = 80;
        const ROWS: usize = 24;
        let t: Element<()> = node(
            vec![Attribute::AttrSpacing(3_000_000)],
            vec![
                node(vec![], vec![Element::Text("a".into())]),
                node(vec![], vec![Element::Text("b".into())]),
            ],
        );
        let frame = element_to_cells(&t, COLS, ROWS);
        let line_count = frame.lines().count();
        assert!(
            line_count <= ROWS * (PAD_ROW_SLACK + 2),
            "frame line count {line_count} exceeded terminal-proportional cap on {ROWS}-row canvas (spacing)"
        );
    }

    #[test]
    fn sgr_emits_named_palette_codes() {
        let fg = sgr(Style {
            fg_palette: Some(31),
            ..Style::default()
        });
        assert!(
            fg.contains("31"),
            "named fg must emit its SGR code, got {fg:?}"
        );
        assert!(
            !fg.contains("38;2"),
            "a named palette fg must not emit a truecolour sequence, got {fg:?}"
        );
        let bg = sgr(Style {
            bg_palette: Some(44),
            ..Style::default()
        });
        assert!(
            bg.contains("44"),
            "named bg must emit its SGR code, got {bg:?}"
        );
    }

    #[test]
    fn parse_palette_code_reads_the_trailing_number() {
        assert_eq!(parse_palette_code("fg:31"), Some(31));
        assert_eq!(parse_palette_code("bg:100"), Some(100));
        assert_eq!(parse_palette_code("fg:notanumber"), None);
    }

    #[test]
    fn sgr_emits_dim_and_reverse() {
        let dim = sgr(Style {
            dim: true,
            ..Style::default()
        });
        assert!(dim.contains('2'), "dim style must emit SGR 2, got {dim:?}");
        let reverse = sgr(Style {
            reverse: true,
            ..Style::default()
        });
        assert!(
            reverse.contains('7'),
            "reverse style must emit SGR 7, got {reverse:?}"
        );
    }

    fn role<M>(desc: Description, attrs: Vec<Attribute<M>>, kids: Vec<Element<M>>) -> Element<M> {
        Element::Node(desc, attrs, kids)
    }

    fn ws_para(ws: WhiteSpace, text: &str) -> Element<()> {
        para(
            vec![Attribute::AttrFontWhiteSpace(ws)],
            vec![Element::Text(text.into())],
        )
    }

    /// `NoWrap` keeps a paragraph on one row; `Normal` (the control) wraps it.
    ///
    /// CI job `runtime-full-features`.
    #[test]
    fn nowrap_paragraph_stays_on_one_row() {
        let text = "alpha beta gamma delta epsilon";
        assert_eq!(
            element_to_cells_height(&ws_para(WhiteSpace::NoWrap, text), 12),
            1
        );
        assert!(element_to_cells_height(&ws_para(WhiteSpace::Normal, text), 12) > 1);
    }

    /// `Pre` keeps a newline as a row break; `Normal` (the control) folds it.
    ///
    /// CI job `runtime-full-features`.
    #[test]
    fn pre_paragraph_keeps_newlines_and_normal_folds_them() {
        assert_eq!(
            element_to_cells_height(&ws_para(WhiteSpace::Pre, "a\nb"), 20),
            2
        );
        assert_eq!(
            element_to_cells_height(&ws_para(WhiteSpace::PreWrap, "a\nb"), 20),
            2
        );
        assert_eq!(
            element_to_cells_height(&ws_para(WhiteSpace::Normal, "a\nb"), 20),
            1
        );
    }

    /// A code block keeps its newlines by default; a plain node (the control)
    /// folds them, and no control byte reaches the frame.
    ///
    /// CI job `runtime-full-features`.
    #[test]
    fn code_block_keeps_newlines_by_default() {
        let kids = || vec![Element::Text("a\nb\x1b[31m".into())];
        let code: Element<()> = role(Description::DescCodeBlock, vec![], kids());
        let plain: Element<()> = role(Description::NoDescription, vec![], kids());
        assert_eq!(element_to_cells_height(&code, 20), 2);
        assert_eq!(element_to_cells_height(&plain, 20), 1);
        assert!(!cells_true(&code, 20, 4).contains("\x1b[31m"));
    }

    /// A section heading reads bold; plain text (the control) does not.
    ///
    /// CI job `runtime-full-features`.
    #[test]
    fn section_heading_is_bold() {
        let heading: Element<()> = role(
            Description::DescSectionHeading,
            vec![],
            vec![Element::Text("Title".into())],
        );
        let plain: Element<()> = node(vec![], vec![Element::Text("Title".into())]);
        assert!(cells_true(&heading, 20, 2).contains("\x1b[1m"));
        assert!(!cells_true(&plain, 20, 2).contains("\x1b[1m"));
    }

    /// A section whose heading has no visible content shows neither a bold run
    /// nor a blank row; a heading with content (the control) takes its row.
    ///
    /// CI job `runtime-full-features`.
    #[test]
    fn empty_section_heading_lays_out_as_nothing() {
        let section = |title: &str| -> Element<()> {
            role(
                Description::DescSection,
                vec![],
                vec![
                    role(
                        Description::DescSectionHeading,
                        vec![],
                        vec![Element::Text(title.into())],
                    ),
                    Element::Text("body".into()),
                ],
            )
        };
        let empty = section(" \t\n");
        assert_eq!(element_to_cells_height(&empty, 20), 1);
        assert!(!cells_true(&empty, 20, 2).contains("\x1b[1m"));
        assert_eq!(element_to_cells_height(&section("Title"), 20), 2);
    }

    /// Only a section's first child is its heading: an empty heading anywhere
    /// else lays out as the node HTML renders, taking its row; the same heading
    /// as the first child (the control) takes none.
    ///
    /// CI job `runtime-full-features`.
    #[test]
    fn empty_heading_off_a_section_head_lays_out() {
        let empty_heading =
            || -> Element<()> { role(Description::DescSectionHeading, vec![], vec![]) };
        let body = || -> Element<()> { Element::Text("body".into()) };
        let later: Element<()> = role(
            Description::DescSection,
            vec![],
            vec![body(), empty_heading()],
        );
        assert_eq!(element_to_cells_height(&later, 20), 2);
        let bare: Element<()> = node(vec![], vec![body(), empty_heading()]);
        assert_eq!(element_to_cells_height(&bare, 20), 2);
        let first: Element<()> = role(
            Description::DescSection,
            vec![],
            vec![empty_heading(), body()],
        );
        assert_eq!(element_to_cells_height(&first, 20), 1);
    }
}

//! Ipe.Tui — terminal cell grid + total rune sanitisation.
//!
//! Pure (no terminal I/O): the building block for the cell renderer. Every
//! access is total — out-of-bounds writes are no-ops, reads return `None`, and
//! `sanitize_rune` maps every display hazard to a space — so no Ipê-reachable
//! path can panic or index out of bounds (the `#![cfg_attr(not(test), deny(...))]`
//! gate), and no display sink holds a character that reorders or splits a line.

use core::ops::RangeInclusive;
use unicode_width::UnicodeWidthChar;

/// A single terminal cell. `width` is display columns: 1 (normal), 2 (wide CJK
/// / emoji), or 0 (the trailing half of a wide char — renders nothing).
#[derive(Clone, PartialEq, Debug)]
pub struct Cell {
    pub ch: char,
    pub width: u8,
    pub fg: Option<(u8, u8, u8)>,
    pub bg: Option<(u8, u8, u8)>,
    pub bold: bool,
    pub underline: bool,
    pub dim: bool,
    pub reverse: bool,
}

impl Cell {
    pub fn blank() -> Self {
        Cell {
            ch: ' ',
            width: 1,
            fg: None,
            bg: None,
            bold: false,
            underline: false,
            dim: false,
            reverse: false,
        }
    }
}

impl Default for Cell {
    fn default() -> Self {
        Cell::blank()
    }
}

/// The bidi controls and line separators a terminal draws as reordered or broken text.
///
/// Each one makes a terminal show a line in an order other than its bytes', or
/// split it where the program wrote no line break, so untrusted text carrying
/// one could display as text the program never printed. The compiler's
/// `ipe_diagnostics::terminal::SOURCE_DISPLAY_HAZARDS` names the same set
/// beside its control roles; a test in `ipe_backend_rust` pins the two equal.
pub const BIDI_AND_SEPARATOR_HAZARDS: &[RangeInclusive<char>] = &[
    '\u{061C}'..='\u{061C}', // ARABIC LETTER MARK
    '\u{200E}'..='\u{200F}', // LEFT-TO-RIGHT MARK, RIGHT-TO-LEFT MARK
    '\u{2028}'..='\u{2029}', // LINE SEPARATOR, PARAGRAPH SEPARATOR
    '\u{202A}'..='\u{202E}', // LRE, RLE, PDF, LRO, RLO
    '\u{2066}'..='\u{2069}', // LRI, RLI, FSI, PDI
];

/// Whether a terminal would run `c` as a command or draw it as reordered or broken text.
///
/// The `Cc` controls (C0, `DEL` and C1) and every [`BIDI_AND_SEPARATOR_HAZARDS`]
/// character.
#[must_use]
pub fn is_display_hazard(c: char) -> bool {
    c.is_control()
        || BIDI_AND_SEPARATOR_HAZARDS
            .iter()
            .any(|range| range.contains(&c))
}

/// Map a display hazard to a space, every other character to itself.
///
/// Every text a Cli `Line` or a Tui view shows passes through here, so a
/// control, a bidi control or a line separator never reaches the terminal.
#[must_use]
pub fn sanitize_rune(c: char) -> char {
    if is_display_hazard(c) { ' ' } else { c }
}

/// Make text whose line breaks are structure safe to draw, keeping its rows.
///
/// The runtime's one line model for drawn text: a `'\n'`, or a `"\r\n"` pair,
/// is a row break and comes out as `'\n'`; every other character, a lone
/// `'\r'` included, goes through [`sanitize_rune`]. A paragraph, a textarea's
/// value and its edits, and a String view's frame all read rows this way.
#[must_use]
pub fn sanitize_text_keeping_newlines(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\n' => out.push('\n'),
            '\r' if chars.peek() == Some(&'\n') => {}
            other => out.push(sanitize_rune(other)),
        }
    }
    out
}

/// Make a whole text frame safe to write to a raw-mode terminal.
///
/// The rows [`sanitize_text_keeping_newlines`] keeps, each break written
/// `"\r\n"` because raw mode moves the cursor down without returning it; the
/// frame carries no control sequence, bidi control or line separator of its
/// own.
#[must_use]
pub fn sanitize_frame(s: &str) -> String {
    sanitize_text_keeping_newlines(s).replace('\n', "\r\n")
}

/// Display width of a char, clamped to [0, 2]. A control char (no width) reads
/// as 1 (it is sanitised to a space upstream).
pub fn char_width(c: char) -> u8 {
    UnicodeWidthChar::width(c).unwrap_or(1).min(2) as u8
}

/// A row-major terminal cell grid. All accesses are bounds-checked and total.
pub struct Grid {
    pub cols: usize,
    pub rows: usize,
    cells: Vec<Cell>,
}

impl Grid {
    pub fn new(cols: usize, rows: usize) -> Self {
        Grid {
            cols,
            rows,
            cells: vec![Cell::blank(); cols.saturating_mul(rows)],
        }
    }

    fn idx(&self, col: usize, row: usize) -> Option<usize> {
        if col < self.cols && row < self.rows {
            Some(row.saturating_mul(self.cols).saturating_add(col))
        } else {
            None
        }
    }

    pub fn get(&self, col: usize, row: usize) -> Option<&Cell> {
        self.idx(col, row).and_then(|i| self.cells.get(i))
    }

    /// Total write — a position outside the grid is a no-op.
    pub fn set(&mut self, col: usize, row: usize, cell: Cell) {
        if let Some(i) = self.idx(col, row)
            && let Some(slot) = self.cells.get_mut(i)
        {
            *slot = cell;
        }
    }

    /// Reset every cell to blank (e.g. before re-rendering a frame).
    pub fn clear(&mut self) {
        for c in self.cells.iter_mut() {
            *c = Cell::blank();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_maps_controls_to_space() {
        assert_eq!(sanitize_rune('\n'), ' ');
        assert_eq!(sanitize_rune('\x1b'), ' '); // ESC
        assert_eq!(sanitize_rune('\x7f'), ' '); // DEL
        assert_eq!(sanitize_rune('A'), 'A');
        assert_eq!(sanitize_rune('é'), 'é');
    }

    /// The sanitiser blanks exactly the `Cc` controls and the bidi and separator table.
    ///
    /// CI job `runtime-full-features-run`.
    #[test]
    fn sanitize_blanks_exactly_controls_and_the_bidi_table() -> Result<(), String> {
        for c in char::MIN..=char::MAX {
            let listed = BIDI_AND_SEPARATOR_HAZARDS
                .iter()
                .any(|range| range.contains(&c));
            let want = if c.is_control() || listed { ' ' } else { c };
            if sanitize_rune(c) != want {
                return Err(format!("U+{:04X} sanitises wrongly", u32::from(c)));
            }
        }
        Ok(())
    }

    /// A bidi control or a separator in a Tui text never reaches the frame.
    ///
    /// CI job `runtime-full-features-run`.
    #[test]
    fn bidi_override_never_reaches_a_cell() -> Result<(), String> {
        use super::super::layout::element_to_cells;
        use crate::ui::Element;
        for c in BIDI_AND_SEPARATOR_HAZARDS.iter().flat_map(Clone::clone) {
            let view: Element<()> = Element::Text(format!("a{c}b"));
            let frame = element_to_cells(&view, 20, 2);
            if frame.contains(c) {
                return Err(format!("U+{:04X} reached a frame", u32::from(c)));
            }
            if !frame.contains("a b") {
                return Err(format!("U+{:04X} was not blanked", u32::from(c)));
            }
        }
        Ok(())
    }

    /// A frame keeps its row breaks as `"\r\n"` and blanks every other hazard.
    ///
    /// CI job `runtime-full-features-run`.
    #[test]
    fn sanitize_frame_keeps_rows_and_blanks_hazards() {
        assert_eq!(
            sanitize_frame("a\x1b]0;x\x07\u{202E}b\nc\r\nd\re"),
            "a ]0;x  b\r\nc\r\nd e"
        );
        assert_eq!(sanitize_frame(""), "");
        assert_eq!(sanitize_frame("\n"), "\r\n");
        assert_eq!(sanitize_frame("\r"), " ");
    }

    /// Every character but the row break leaves a frame as [`sanitize_rune`] maps it.
    ///
    /// CI job `runtime-full-features-run`.
    #[test]
    fn sanitize_frame_agrees_with_the_rune_sanitiser() -> Result<(), String> {
        for c in char::MIN..=char::MAX {
            if c == '\n' {
                continue;
            }
            let framed = sanitize_frame(&c.to_string());
            if framed != sanitize_rune(c).to_string() {
                return Err(format!("U+{:04X} frames as {framed:?}", u32::from(c)));
            }
            if sanitize_text_keeping_newlines(&c.to_string()) != sanitize_rune(c).to_string() {
                return Err(format!("U+{:04X} kept-newline text differs", u32::from(c)));
            }
        }
        if sanitize_text_keeping_newlines("\n") == "\n" {
            Ok(())
        } else {
            Err("the kept line break was blanked".to_owned())
        }
    }

    /// A `"\r\n"` is one row break in kept-newline text, as it is in a frame;
    /// a lone `'\r'` is blanked in both.
    ///
    /// CI job `runtime-full-features-run`.
    #[test]
    fn kept_newline_text_reads_rows_like_a_frame() {
        assert_eq!(sanitize_text_keeping_newlines("a\r\nb\rc\n"), "a\nb c\n");
        assert_eq!(sanitize_text_keeping_newlines("\r\r\n"), " \n");
        for text in ["a\r\nb", "a\nb\r", "\r\r\n\x1b\n", "x\u{2028}y\r\n"] {
            assert_eq!(
                sanitize_frame(text),
                sanitize_text_keeping_newlines(text).replace('\n', "\r\n")
            );
        }
    }

    #[test]
    fn widths() {
        assert_eq!(char_width('A'), 1);
        assert_eq!(char_width('中'), 2); // wide CJK
        assert_eq!(char_width(' '), 1);
    }

    #[test]
    fn grid_is_total() {
        let mut g = Grid::new(3, 2);
        g.set(
            1,
            1,
            Cell {
                ch: 'x',
                ..Cell::blank()
            },
        );
        assert_eq!(g.get(1, 1).map(|c| c.ch), Some('x'));
        assert_eq!(g.get(0, 0).map(|c| c.ch), Some(' '));
        // out of bounds: write is a no-op, read is None
        g.set(
            99,
            99,
            Cell {
                ch: 'z',
                ..Cell::blank()
            },
        );
        assert_eq!(g.get(99, 99), None);
        assert_eq!(g.get(3, 0), None); // col == cols (boundary)
        g.clear();
        assert_eq!(g.get(1, 1).map(|c| c.ch), Some(' '));
    }
}

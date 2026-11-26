//! Ipe.Tui — terminal cell grid + total rune sanitisation.
//!
//! Pure (no terminal I/O): the building block for the cell renderer. Every
//! access is total — out-of-bounds writes are no-ops, reads return `None`, and
//! `sanitize_rune` maps control bytes to a space — so no Ipê-reachable path can
//! panic or index out of bounds (the `#![cfg_attr(not(test), deny(...))]` gate).

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

/// Map a control byte to a space — total. C0 controls (< 0x20), DEL (0x7f),
/// and C1 controls (0x80..=0x9f) become ' '.
pub fn sanitize_rune(c: char) -> char {
    let u = c as u32;
    if u < 0x20 || u == 0x7f || (0x80..=0x9f).contains(&u) {
        ' '
    } else {
        c
    }
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

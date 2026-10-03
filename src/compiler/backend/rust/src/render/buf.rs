//! The layout buffer: a rope of shared pieces, each carrying its [`Shape`], so a
//! kept layout is appended again without copying its bytes and every measure a
//! layout decision reads of the buffer is answered without scanning its text.
//!
//! The buffer keeps, per top-level piece, its measure and a Fenwick tree over the
//! measures, so the measure of any suffix is a logarithmic fold and the measure of
//! the whole buffer is kept as it grows. Every run of `' '` an appended text
//! begins or ends with is a [`Piece::Spaces`] of its own, so no other piece begins
//! or ends with a space: the trailing-space run a break trims, and the offsets a
//! render marks before and after it, fall on piece boundaries. The spaces inside a
//! text stay in its one piece, so a text costs a bounded number of pieces however
//! many spaces it holds. An offset inside a piece is still served, by splitting it.

use std::cell::OnceCell;
use std::rc::Rc;

use super::shape::Shape;

/// One piece of a rendered text.
#[derive(Clone)]
enum Piece {
    /// A run of `' '`.
    Spaces(usize),
    /// One byte of an ASCII character other than `' '`.
    Ascii(u8),
    /// A segment neither beginning nor ending with `' '`.
    Leaf(Rc<str>),
    /// A kept layout, shared by every buffer that appends it.
    Node(Rc<Node>),
}

/// A kept run of pieces with its length and measure.
struct Node {
    pieces: Vec<Piece>,
    len: usize,
    shape: Shape,
    /// The bytes it holds (see [`Node::held_of`]).
    held: usize,
    /// The first line through its newline, built once when first asked for.
    first_line: OnceCell<(Piece, Shape)>,
}

impl Node {
    /// What a node of `pieces` holds: its own record, a slot per piece, the text
    /// of each leaf and what each nested node holds, counted once per parent.
    fn held_of(pieces: &[Piece]) -> usize {
        pieces
            .iter()
            .map(|piece| {
                size_of::<Piece>().saturating_add(match piece {
                    Piece::Leaf(text) => text.len(),
                    Piece::Node(node) => node.held,
                    Piece::Spaces(_) | Piece::Ascii(_) => 0,
                })
            })
            .fold(size_of::<Self>(), usize::saturating_add)
    }
}

impl Piece {
    fn len(&self) -> usize {
        match self {
            Self::Spaces(n) => *n,
            Self::Ascii(_) => 1,
            Self::Leaf(text) => text.len(),
            Self::Node(node) => node.len,
        }
    }

    /// What the piece costs a buffer holding it at the top level: its slot, its
    /// end and its three measures, plus the text of a leaf or what a kept layout
    /// holds. A shared kept layout is charged at every place it is appended, which
    /// over-counts, never under-counts.
    fn held_bytes(&self) -> usize {
        let slot = size_of::<Self>()
            .saturating_add(size_of::<usize>())
            .saturating_add(size_of::<Shape>().saturating_mul(3));
        slot.saturating_add(match self {
            Self::Leaf(text) => text.len(),
            Self::Node(node) => node.held,
            Self::Spaces(_) | Self::Ascii(_) => 0,
        })
    }

    /// The measure of the piece, reading the text of a leaf.
    fn shape(&self) -> Shape {
        match self {
            Self::Spaces(n) => Shape::spaces(*n),
            Self::Ascii(byte) => {
                let text = [*byte];
                std::str::from_utf8(&text).map_or(Shape::EMPTY, Shape::of)
            }
            Self::Leaf(text) => Shape::of(text),
            Self::Node(node) => node.shape,
        }
    }

    /// Append the text of the piece to `out`.
    fn write_to(&self, out: &mut String) {
        let mut stack: Vec<&[Self]> = vec![core::array::from_ref(self)];
        while let Some(top) = stack.last_mut() {
            let Some((piece, rest)) = top.split_first() else {
                stack.pop();
                continue;
            };
            *top = rest;
            match piece {
                Self::Spaces(n) => out.extend(std::iter::repeat_n(' ', *n)),
                Self::Ascii(byte) => out.push(char::from(*byte)),
                Self::Leaf(text) => out.push_str(text),
                Self::Node(node) => stack.push(&node.pieces),
            }
        }
    }

    /// The text of the piece.
    fn text(&self) -> String {
        let mut out = String::with_capacity(self.len());
        self.write_to(&mut out);
        out
    }

    /// The piece up to and including its first newline, with its measure, for a
    /// piece that holds one.
    ///
    /// A kept layout builds its first line once, sharing every piece before the
    /// piece that holds the newline; the walk down to that piece is iterative.
    fn first_line(&self) -> (Self, Shape) {
        let mut path: Vec<(&Rc<Node>, usize)> = Vec::new();
        let mut piece = self;
        let mut line = loop {
            match piece {
                Self::Node(node) => {
                    if let Some(line) = node.first_line.get() {
                        break line.clone();
                    }
                    let at = node
                        .pieces
                        .iter()
                        .position(|child| child.shape().newlines() > 0);
                    let Some(child) = at.and_then(|at| node.pieces.get(at)) else {
                        break (piece.clone(), node.shape);
                    };
                    path.push((node, at.unwrap_or_default()));
                    piece = child;
                }
                Self::Leaf(text) => {
                    let end = text
                        .find('\n')
                        .map_or(text.len(), |nl| nl.saturating_add(1));
                    let head = text.get(..end).unwrap_or_default();
                    break (Self::Leaf(Rc::from(head)), Shape::of(head));
                }
                Self::Spaces(_) | Self::Ascii(_) => break (piece.clone(), piece.shape()),
            }
        };
        while let Some((node, at)) = path.pop() {
            let before = node.pieces.get(..at).unwrap_or_default();
            let mut pieces = Vec::with_capacity(at.saturating_add(1));
            let mut shape = Shape::EMPTY;
            let mut len = 0usize;
            for child in before {
                shape = shape.then(&child.shape());
                len = len.saturating_add(child.len());
                pieces.push(child.clone());
            }
            shape = shape.then(&line.1);
            len = len.saturating_add(line.0.len());
            pieces.push(line.0);
            let held = Node::held_of(&pieces);
            let built = (
                Self::Node(Rc::new(Node {
                    pieces,
                    len,
                    shape,
                    held,
                    first_line: OnceCell::new(),
                })),
                shape,
            );
            line = node.first_line.get_or_init(|| built).clone();
        }
        line
    }
}

/// Whether a text's leading spaces join a run of spaces the buffer ends with.
#[derive(Clone, Copy)]
enum Join {
    /// They join it, keeping one piece per run.
    Spaces,
    /// They start a piece of their own, so the offset between stays a boundary.
    Apart,
}

/// The lowest set bit of `i`, the span a Fenwick entry at `i` covers.
const fn low_bit(i: usize) -> usize {
    i.isolate_lowest_one()
}

/// A rendered text under construction.
pub(super) struct Buf {
    pieces: Vec<Piece>,
    /// The length of the text through each piece.
    ends: Vec<usize>,
    /// The measure of each piece.
    shapes: Vec<Shape>,
    /// The measure of the text through each piece.
    totals: Vec<Shape>,
    /// Entry `i - 1` is the measure of pieces `i - low_bit(i) .. i`.
    tree: Vec<Shape>,
    /// The work done since it was last taken: bytes measured plus pieces placed.
    work: usize,
    /// The sum of [`Piece::held_bytes`] over `pieces`.
    held: usize,
}

impl Buf {
    pub(super) const fn new() -> Self {
        Self {
            pieces: Vec::new(),
            ends: Vec::new(),
            shapes: Vec::new(),
            totals: Vec::new(),
            tree: Vec::new(),
            work: 0,
            held: 0,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.ends.last().copied().unwrap_or_default()
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.pieces.is_empty()
    }

    /// The measure of the whole text.
    pub(super) fn total(&self) -> &Shape {
        self.totals.last().unwrap_or(&Shape::EMPTY)
    }

    /// The work done since the last call, which it resets.
    pub(super) fn take_work(&mut self) -> usize {
        std::mem::take(&mut self.work)
    }

    /// Place one piece of measure `shape` at the end.
    fn place(&mut self, piece: Piece, shape: &Shape) {
        if piece.len() == 0 {
            return;
        }
        let at = self.pieces.len().saturating_add(1);
        let low = at.saturating_sub(low_bit(at));
        let mut span = *shape;
        let mut j = at.saturating_sub(1);
        while j > low {
            span = self
                .tree
                .get(j.saturating_sub(1))
                .unwrap_or(&Shape::EMPTY)
                .then(&span);
            j = j.saturating_sub(low_bit(j));
        }
        let total = self.total().then(shape);
        let end = self.len().saturating_add(piece.len());
        self.held = self.held.saturating_add(piece.held_bytes());
        self.pieces.push(piece);
        self.ends.push(end);
        self.shapes.push(*shape);
        self.totals.push(total);
        self.tree.push(span);
        self.work = self.work.saturating_add(1);
    }

    /// Remove the last piece.
    fn unplace(&mut self) -> Option<Piece> {
        self.ends.pop();
        self.shapes.pop();
        self.totals.pop();
        self.tree.pop();
        let piece = self.pieces.pop()?;
        self.held = self.held.saturating_sub(piece.held_bytes());
        Some(piece)
    }

    /// The measure of pieces `from .. to`.
    fn span(&self, from: usize, to: usize) -> Shape {
        let mut acc = Shape::EMPTY;
        let mut j = to;
        while j > from {
            let low = j.saturating_sub(low_bit(j));
            let (part, next) = if low >= from {
                (self.tree.get(j.saturating_sub(1)), low)
            } else {
                (self.shapes.get(j.saturating_sub(1)), j.saturating_sub(1))
            };
            acc = part.unwrap_or(&Shape::EMPTY).then(&acc);
            j = next;
        }
        acc
    }

    /// The index of the piece holding byte `at`, and the offset of `at` in it.
    fn locate(&self, at: usize) -> (usize, usize) {
        let index = self.ends.partition_point(|&end| end <= at);
        let start = index
            .checked_sub(1)
            .and_then(|before| self.ends.get(before))
            .copied()
            .unwrap_or_default();
        (index, at.saturating_sub(start))
    }

    /// Append `text`, as at most three pieces: its leading spaces, the segment
    /// between, and its trailing spaces.
    pub(super) fn push_str(&mut self, text: &str) {
        self.push_text(text, Join::Spaces);
    }

    /// [`Buf::push_str`], its leading spaces joining a run already at the end only
    /// under [`Join::Spaces`].
    fn push_text(&mut self, text: &str, join: Join) {
        self.work = self.work.saturating_add(text.len());
        let body = text.trim_start_matches(' ');
        let lead = text.len().saturating_sub(body.len());
        match join {
            Join::Spaces => self.push_spaces(lead),
            Join::Apart if lead > 0 => self.place(Piece::Spaces(lead), &Shape::spaces(lead)),
            Join::Apart => {}
        }
        let segment = body.trim_end_matches(' ');
        match segment.as_bytes() {
            [] => {}
            [byte] if byte.is_ascii() => {
                let piece = Piece::Ascii(*byte);
                let shape = piece.shape();
                self.place(piece, &shape);
            }
            _ => self.place(Piece::Leaf(Rc::from(segment)), &Shape::of(segment)),
        }
        self.push_spaces(body.len().saturating_sub(segment.len()));
    }

    /// The bytes the buffer's top-level pieces hold (see [`Piece::held_bytes`]).
    pub(super) const fn held_bytes(&self) -> usize {
        self.held
    }

    /// Append `c`.
    pub(super) fn push(&mut self, c: char) {
        let mut bytes = [0; 4];
        self.push_str(c.encode_utf8(&mut bytes));
    }

    /// Append `n` spaces, joining a run of spaces already at the end.
    pub(super) fn push_spaces(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        self.work = self.work.saturating_add(1);
        let run = match self.pieces.last() {
            Some(Piece::Spaces(before)) => {
                let before = *before;
                self.unplace();
                before.saturating_add(n)
            }
            _ => n,
        };
        self.place(Piece::Spaces(run), &Shape::spaces(run));
    }

    /// Shorten the text to `len` bytes.
    pub(super) fn truncate(&mut self, len: usize) {
        while self.len() > len {
            let start = self
                .ends
                .len()
                .checked_sub(2)
                .and_then(|before| self.ends.get(before))
                .copied()
                .unwrap_or_default();
            let Some(last) = self.unplace() else {
                return;
            };
            if start >= len {
                continue;
            }
            let keep = len.saturating_sub(start);
            match last {
                Piece::Spaces(_) => self.push_spaces(keep),
                Piece::Ascii(_) => {}
                Piece::Leaf(text) => self.push_str(text.get(..keep).unwrap_or_default()),
                Piece::Node(node) => {
                    for child in &node.pieces {
                        self.place(child.clone(), &child.shape());
                    }
                }
            }
        }
    }

    pub(super) fn clear(&mut self) {
        self.truncate(0);
    }

    /// The measure of the text from byte `at` on.
    pub(super) fn shape_from(&self, at: usize) -> Shape {
        if at >= self.len() {
            return Shape::EMPTY;
        }
        let (index, offset) = self.locate(at);
        let rest = self.span(index.saturating_add(1), self.pieces.len());
        let Some(piece) = self.pieces.get(index) else {
            return Shape::EMPTY;
        };
        let head = if offset == 0 {
            self.shapes.get(index).copied().unwrap_or(Shape::EMPTY)
        } else if let Piece::Spaces(n) = piece {
            Shape::spaces(n.saturating_sub(offset))
        } else {
            Shape::of(piece.text().get(offset..).unwrap_or_default())
        };
        head.then(&rest)
    }

    /// The measure of the text before byte `at`.
    pub(super) fn shape_before(&self, at: usize) -> Shape {
        if at >= self.len() {
            return *self.total();
        }
        let (index, offset) = self.locate(at);
        let before = index
            .checked_sub(1)
            .and_then(|before| self.totals.get(before))
            .copied()
            .unwrap_or(Shape::EMPTY);
        if offset == 0 {
            return before;
        }
        let head = match self.pieces.get(index) {
            Some(Piece::Spaces(_)) => Shape::spaces(offset),
            Some(piece) => Shape::of(piece.text().get(..offset).unwrap_or_default()),
            None => Shape::EMPTY,
        };
        before.then(&head)
    }

    /// Make byte `at` a piece boundary, splitting the piece across it.
    fn split_at(&mut self, at: usize) {
        let (index, offset) = self.locate(at);
        if offset == 0 || index >= self.pieces.len() {
            return;
        }
        let after: Vec<Piece> = self
            .pieces
            .get(index.saturating_add(1)..)
            .unwrap_or_default()
            .to_vec();
        let Some(piece) = self.pieces.get(index).cloned() else {
            return;
        };
        let start = at.saturating_sub(offset);
        self.truncate(start);
        match piece {
            Piece::Spaces(n) => {
                self.place(Piece::Spaces(offset), &Shape::spaces(offset));
                let rest = n.saturating_sub(offset);
                self.place(Piece::Spaces(rest), &Shape::spaces(rest));
            }
            other => {
                let text = other.text();
                let (head, tail) = text.split_at_checked(offset).unwrap_or((&text, ""));
                self.push_str(head);
                self.push_text(tail, Join::Apart);
            }
        }
        for piece in after {
            let shape = piece.shape();
            self.place(piece, &shape);
        }
    }

    /// Keep the text from byte `base` on as one [`Frozen`] layout, which the buffer
    /// then holds in place of the pieces it was written as.
    pub(super) fn freeze(&mut self, base: usize) -> Frozen {
        self.split_at(base);
        let (first, _) = self.locate(base);
        let region = self.pieces.get(first..).unwrap_or_default();
        let lead_pieces = region
            .iter()
            .take_while(|piece| matches!(piece, Piece::Spaces(_)))
            .count();
        let trail_pieces = region
            .get(lead_pieces..)
            .unwrap_or_default()
            .iter()
            .rev()
            .take_while(|piece| matches!(piece, Piece::Spaces(_)))
            .count();
        let sum = |pieces: &[Piece]| pieces.iter().map(Piece::len).sum::<usize>();
        let lead = sum(region.get(..lead_pieces).unwrap_or_default());
        let core_from = first.saturating_add(lead_pieces);
        let core_to = self.pieces.len().saturating_sub(trail_pieces);
        let trail = sum(self.pieces.get(core_to..).unwrap_or_default());
        let core = match self.pieces.get(core_from..core_to).unwrap_or_default() {
            [] => None,
            [piece] => Some((
                piece.clone(),
                self.shapes.get(core_from).copied().unwrap_or(Shape::EMPTY),
            )),
            pieces => {
                let shape = self.span(core_from, core_to);
                let node = Node {
                    pieces: pieces.to_vec(),
                    len: sum(pieces),
                    shape,
                    held: Node::held_of(pieces),
                    first_line: OnceCell::new(),
                };
                Some((Piece::Node(Rc::new(node)), shape))
            }
        };
        let frozen = Frozen::new(lead, core, trail);
        self.truncate(base);
        self.push_frozen(&frozen);
        frozen
    }

    /// Append a kept layout.
    pub(super) fn push_frozen(&mut self, layout: &Frozen) {
        self.push_spaces(layout.lead);
        if let Some((piece, shape)) = &layout.core {
            self.place(piece.clone(), shape);
        }
        self.push_spaces(layout.trail);
    }

    /// The whole text.
    pub(super) fn into_string(self) -> String {
        let mut out = String::with_capacity(self.len());
        for piece in &self.pieces {
            piece.write_to(&mut out);
        }
        out
    }
}

/// A kept layout: a run of spaces, a core piece neither beginning nor ending with
/// one, and a run of spaces.
#[derive(Clone)]
pub(super) struct Frozen {
    lead: usize,
    core: Option<(Piece, Shape)>,
    trail: usize,
    /// The measure of everything after the leading spaces.
    body: Shape,
}

impl Frozen {
    fn new(lead: usize, core: Option<(Piece, Shape)>, trail: usize) -> Self {
        let body = core
            .as_ref()
            .map_or(Shape::EMPTY, |(_, shape)| *shape)
            .then(&Shape::spaces(trail));
        Self {
            lead,
            core,
            trail,
            body,
        }
    }

    /// The pieces the layout holds besides its spaces.
    pub(super) const fn pieces(&self) -> usize {
        if self.core.is_some() { 1 } else { 0 }
    }

    /// The measure of the layout from byte `at` on, for `at` within its leading
    /// spaces.
    pub(super) const fn shape_after(&self, at: usize) -> Shape {
        Shape::spaces(self.lead.saturating_sub(at)).then(&self.body)
    }

    /// The measure of the whole layout.
    pub(super) const fn shape(&self) -> Shape {
        self.shape_after(0)
    }

    /// The layout up to and including its first newline, or all of it when it
    /// holds none.
    pub(super) fn first_line(&self) -> Self {
        match &self.core {
            Some((piece, shape)) if !shape.is_single_line() => {
                Self::new(self.lead, Some(piece.first_line()), 0)
            }
            _ => self.clone(),
        }
    }

    /// The bytes the layout itself writes besides the kept layouts it shares, plus
    /// the piece slots it holds.
    pub(super) fn own_bytes(&self) -> usize {
        let node = match &self.core {
            Some((Piece::Node(node), _)) => node,
            Some((Piece::Leaf(text), _)) => return text.len().saturating_add(size_of::<Self>()),
            Some((Piece::Spaces(_) | Piece::Ascii(_), _)) | None => return size_of::<Self>(),
        };
        node.pieces
            .iter()
            .map(|piece| match piece {
                Piece::Leaf(text) => text.len(),
                _ => 0,
            })
            .sum::<usize>()
            .saturating_add(node.pieces.len().saturating_mul(size_of::<Piece>()))
            .saturating_add(size_of::<Node>())
            .saturating_add(size_of::<Self>())
    }

    /// The text of the layout.
    #[cfg(test)]
    pub(super) fn text(&self) -> String {
        let mut out = " ".repeat(self.lead);
        if let Some((piece, _)) = &self.core {
            piece.write_to(&mut out);
        }
        out.push_str(&" ".repeat(self.trail));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{Buf, Piece, Shape};

    /// A buffer and the text it must hold, driven through the same edits.
    struct Model {
        buf: Buf,
        text: String,
    }

    impl Model {
        fn check(&self) {
            let text = Buf::into_string(self.clone_buf());
            assert_eq!(text, self.text);
            assert_eq!(self.buf.len(), self.text.len());
            assert_eq!(*self.buf.total(), Shape::of(&self.text));
            let summed = self.buf.pieces.iter().map(Piece::held_bytes).sum::<usize>();
            assert_eq!(self.buf.held_bytes(), summed, "{:?}", self.text);
            for at in 0..=self.text.len() {
                if !self.text.is_char_boundary(at) {
                    continue;
                }
                let (head, tail) = self.text.split_at(at);
                assert_eq!(
                    self.buf.shape_from(at),
                    Shape::of(tail),
                    "{:?} from {at}",
                    self.text
                );
                assert_eq!(
                    self.buf.shape_before(at),
                    Shape::of(head),
                    "{:?} to {at}",
                    self.text
                );
            }
        }

        fn clone_buf(&self) -> Buf {
            let mut copy = Buf::new();
            for piece in &self.buf.pieces {
                copy.place(piece.clone(), &piece.shape());
            }
            copy
        }
    }

    const EDITS: &[&str] = &[
        "let x = ",
        "  ",
        "f(",
        "\n",
        "    ",
        "a, b",
        "é ",
        "{ \"s p\" }",
        ")",
        " ",
        "\n  // c\n",
    ];

    /// Every edit sequence leaves the buffer holding exactly the text a `String`
    /// driven the same way holds, with every measure equal to the text's.
    #[test]
    fn buf_tracks_a_string_through_every_edit() {
        let mut seed = 0x9e37_79b9_u32;
        for round in 0..300 {
            let mut model = Model {
                buf: Buf::new(),
                text: String::new(),
            };
            let mut frozen = Vec::new();
            for _ in 0..(round % 23) {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let pick = usize::try_from(seed >> 8).unwrap_or_default();
                match pick % 6 {
                    0..=2 => {
                        let edit = EDITS.get(pick % EDITS.len()).copied().unwrap_or_default();
                        model.buf.push_str(edit);
                        model.text.push_str(edit);
                    }
                    3 => {
                        let len = model.text.len().saturating_sub(pick % 5);
                        if model.text.is_char_boundary(len) {
                            model.buf.truncate(len);
                            model.text.truncate(len);
                        }
                    }
                    4 => {
                        let base = model.text.len().saturating_sub(pick % 9);
                        if model.text.is_char_boundary(base) {
                            let layout = model.buf.freeze(base);
                            assert_eq!(layout.text(), model.text.get(base..).unwrap_or_default());
                            assert_eq!(layout.shape(), Shape::of(&layout.text()));
                            let first = layout.first_line();
                            let whole = layout.text();
                            let end = whole.find('\n').map_or(whole.len(), |nl| nl + 1);
                            assert_eq!(first.text(), whole.get(..end).unwrap_or_default());
                            assert_eq!(first.shape(), Shape::of(&first.text()));
                            frozen.push(layout);
                        }
                    }
                    _ => {
                        if let Some(layout) = frozen.get(pick % frozen.len().max(1)) {
                            model.buf.push_frozen(layout);
                            model.text.push_str(&layout.text());
                        }
                    }
                }
                model.check();
            }
        }
    }

    /// The refusal: a text costs at most three pieces however many spaces it
    /// holds, so its spaces cannot multiply the per-piece measures the buffer
    /// keeps.
    #[test]
    fn spaced_text_costs_bounded_pieces() {
        for (words, edge) in [(1, ""), (2, " "), (1000, "  "), (100_000, " ")] {
            let text = format!("{edge}{}x{edge}", "a ".repeat(words));
            let mut buf = Buf::new();
            buf.push_str(&text);
            assert!(
                buf.pieces.len() <= 3,
                "{words} words: {} pieces",
                buf.pieces.len()
            );
            assert_eq!(buf.len(), text.len());
            assert_eq!(*buf.total(), Shape::of(&text));
            assert_eq!(Buf::into_string(buf), text);
        }
    }
}

//! Constant-size measures of rendered text that compose over concatenation.
//!
//! A layout decision reads how a child's text is shaped: its line widths, its
//! indentation, its trailing spaces, whether a line is an unbreakable atom. It
//! never needs the text itself. [`Shape::of`] measures a text once, and
//! [`Shape::then`] measures a concatenation from the measures of its parts, so a
//! join costs O(1) whatever the parts' length. Each reader equals the text read
//! in the parent module it stands for; the tests below prove it over every split
//! of a corpus.

use std::num::NonZeroU32;

/// The lowest relative `<>` depth a [`DepthWindow`] records exactly.
const WINDOW_LOW: i32 = -64;

/// The highest relative `<>` depth a [`DepthWindow`] records exactly.
const WINDOW_HIGH: i32 = 63;

/// The window bit of relative depth zero, the top level of a line.
const TOP_LEVEL_BIT: u128 = 1_u128 << 0_i32.abs_diff(WINDOW_LOW);

/// The relative `<>` depths at which a segment holds an unquoted space.
///
/// Bit `k` stands for depth `k + WINDOW_LOW`. A space outside the window sets
/// `overflow`, which reads as "may be at the top level": the conservative answer,
/// since a top-level space makes a line breakable, never an atom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DepthWindow {
    bits: u128,
    overflow: bool,
}

impl DepthWindow {
    /// No space recorded.
    const EMPTY: Self = Self {
        bits: 0,
        overflow: false,
    };

    /// This window with a space recorded at relative `depth`.
    const fn with_space(self, depth: i32) -> Self {
        match depth {
            WINDOW_LOW..=WINDOW_HIGH => Self {
                bits: self.bits | (1_u128 << depth.abs_diff(WINDOW_LOW)),
                overflow: self.overflow,
            },
            _ => Self {
                bits: self.bits,
                overflow: true,
            },
        }
    }

    /// This window with every depth moved by `delta`; a depth pushed out of the
    /// window sets `overflow`.
    const fn shifted(self, delta: i32) -> Self {
        let by = delta.unsigned_abs();
        if by == 0 {
            return self;
        }
        let (bits, lost) = if by >= u128::BITS {
            (0, self.bits)
        } else if delta > 0 {
            (self.bits << by, self.bits >> (u128::BITS - by))
        } else {
            (self.bits >> by, self.bits & ((1_u128 << by) - 1))
        };
        Self {
            bits,
            overflow: self.overflow || lost != 0,
        }
    }

    /// The depths of both windows.
    const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
            overflow: self.overflow || other.overflow,
        }
    }

    /// Whether a recorded space may sit at relative depth zero.
    const fn may_hold_top_level(self) -> bool {
        self.overflow || (self.bits & TOP_LEVEL_BIT) != 0
    }
}

/// Where the atom scan of a line stands between two characters.
///
/// Only what decides the rest of the scan is kept: the last character matters
/// outside a string (a `-` before `>` makes `->`, not a closer), and inside a
/// string only an unconsumed `\` does, since the closing `"` resets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanState {
    /// Still skipping the line's leading whitespace (`char::is_whitespace`).
    LineStart,
    /// Outside a string literal; `after_dash` when the last character was `-`.
    Code { after_dash: bool },
    /// Inside a string literal; `escaped` when the last character was a `\`
    /// that escapes the next one.
    Str { escaped: bool },
}

/// One character outside a string, or `None` at a break point (a group opener
/// or a `,`).
const fn code_char(
    after_dash: bool,
    c: char,
    depth: &mut i32,
    spaces: &mut DepthWindow,
) -> Option<ScanState> {
    match c {
        '"' => return Some(ScanState::Str { escaped: false }),
        '(' | '[' | '{' | ',' => return None,
        ' ' => *spaces = spaces.with_space(*depth),
        '<' => *depth = depth.saturating_add(1),
        '>' if !after_dash => *depth = depth.saturating_sub(1),
        _ => {}
    }
    Some(ScanState::Code {
        after_dash: c == '-',
    })
}

/// One character inside a string.
const fn str_char(escaped: bool, c: char) -> ScanState {
    match (escaped, c) {
        (false, '\\') => ScanState::Str { escaped: true },
        (false, '"') => ScanState::Code { after_dash: false },
        _ => ScanState::Str { escaped: false },
    }
}

/// What a segment does to an atom scan entering it in one state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Run {
    /// The state the scan leaves the segment in.
    exit: ScanState,
    /// The `<>` depth the segment adds.
    depth_delta: i32,
    /// The relative depths of the segment's unquoted spaces.
    spaces: DepthWindow,
}

/// The atom scan of a segment from one entry state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The segment holds a break point: the line is not an atom.
    Breaks,
    /// The segment holds no break point; the scan goes on.
    Runs(Run),
}

impl Outcome {
    /// A segment that leaves the scan in `exit`, adding no depth and no space.
    const fn passing(exit: ScanState) -> Self {
        Self::Runs(Run {
            exit,
            depth_delta: 0,
            spaces: DepthWindow::EMPTY,
        })
    }

    /// The scan through this segment, then through the segment `next` measures.
    const fn then(&self, next: &AtomScan) -> Self {
        let Self::Runs(run) = self else {
            return Self::Breaks;
        };
        let Self::Runs(after) = next.on_entry(run.exit) else {
            return Self::Breaks;
        };
        Self::Runs(Run {
            exit: after.exit,
            depth_delta: run.depth_delta.saturating_add(after.depth_delta),
            spaces: run.spaces.union(after.spaces.shifted(run.depth_delta)),
        })
    }
}

/// The scan of one segment from `entry`, depths relative to its start.
fn scan_from(entry: ScanState, text: &str) -> Outcome {
    let mut state = entry;
    let mut depth: i32 = 0;
    let mut spaces = DepthWindow::EMPTY;
    for c in text.chars() {
        let next = match state {
            ScanState::LineStart if c.is_whitespace() => Some(ScanState::LineStart),
            ScanState::LineStart => code_char(false, c, &mut depth, &mut spaces),
            ScanState::Code { after_dash } => code_char(after_dash, c, &mut depth, &mut spaces),
            ScanState::Str { escaped } => Some(str_char(escaped, c)),
        };
        let Some(next) = next else {
            return Outcome::Breaks;
        };
        state = next;
    }
    Outcome::Runs(Run {
        exit: state,
        depth_delta: depth,
        spaces,
    })
}

/// An exact finite-state summary of `line_is_unbreakable_atom` over a segment.
///
/// It holds the segment's [`Outcome`] for every entry state, so the summary of a
/// concatenation is a table lookup per state, never a rescan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AtomScan {
    line_start: Outcome,
    code: Outcome,
    code_after_dash: Outcome,
    string: Outcome,
    string_escaped: Outcome,
}

impl AtomScan {
    /// The summary of the empty segment: every scan passes through unchanged.
    const EMPTY: Self = Self {
        line_start: Outcome::passing(ScanState::LineStart),
        code: Outcome::passing(ScanState::Code { after_dash: false }),
        code_after_dash: Outcome::passing(ScanState::Code { after_dash: true }),
        string: Outcome::passing(ScanState::Str { escaped: false }),
        string_escaped: Outcome::passing(ScanState::Str { escaped: true }),
    };

    /// The summary of `n` spaces, without scanning them: leading whitespace is
    /// skipped, a space outside a string is one at the top level, and a space in
    /// a string consumes any pending escape.
    const fn spaces(n: usize) -> Self {
        if n == 0 {
            return Self::EMPTY;
        }
        let code = Outcome::Runs(Run {
            exit: ScanState::Code { after_dash: false },
            depth_delta: 0,
            spaces: DepthWindow::EMPTY.with_space(0),
        });
        let string = Outcome::passing(ScanState::Str { escaped: false });
        Self {
            line_start: Outcome::passing(ScanState::LineStart),
            code,
            code_after_dash: code,
            string,
            string_escaped: string,
        }
    }

    /// The summary of `text`, a segment holding no newline.
    fn of(text: &str) -> Self {
        Self {
            line_start: scan_from(ScanState::LineStart, text),
            code: scan_from(ScanState::Code { after_dash: false }, text),
            code_after_dash: scan_from(ScanState::Code { after_dash: true }, text),
            string: scan_from(ScanState::Str { escaped: false }, text),
            string_escaped: scan_from(ScanState::Str { escaped: true }, text),
        }
    }

    /// The outcome of a scan entering the segment in `entry`.
    const fn on_entry(&self, entry: ScanState) -> &Outcome {
        match entry {
            ScanState::LineStart => &self.line_start,
            ScanState::Code { after_dash: false } => &self.code,
            ScanState::Code { after_dash: true } => &self.code_after_dash,
            ScanState::Str { escaped: false } => &self.string,
            ScanState::Str { escaped: true } => &self.string_escaped,
        }
    }

    /// The summary of this segment followed by `next`.
    const fn then(&self, next: &Self) -> Self {
        Self {
            line_start: self.line_start.then(next),
            code: self.code.then(next),
            code_after_dash: self.code_after_dash.then(next),
            string: self.string.then(next),
            string_escaped: self.string_escaped.then(next),
        }
    }

    /// Whether the segment, read as a whole line, is an unbreakable atom.
    ///
    /// A blank line is not one; a space past the window reads as top-level.
    const fn is_atom(&self) -> bool {
        match &self.line_start {
            Outcome::Breaks => false,
            Outcome::Runs(run) => {
                !matches!(run.exit, ScanState::LineStart) && !run.spaces.may_hold_top_level()
            }
        }
    }
}

/// The wider of two widths.
const fn wider(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

/// The measure of one line fragment, a text holding no newline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Frag {
    /// Its length in bytes.
    width: usize,
    /// The bytes of its leading run of `' '`.
    leading_spaces: usize,
    /// The bytes of its leading run of `char::is_whitespace` characters.
    leading_blank: usize,
    /// The bytes of its trailing run of `' '`.
    trailing_spaces: usize,
    /// The bytes of its trailing run of `' '`, `(`, `{` and `[`: what a width
    /// verdict on its line leaves open.
    trailing_neutral: usize,
    /// The bytes of its trailing run of `(`, `{` and `[`.
    trailing_openers: usize,
    /// Its last character that is not whitespace.
    last_char: Option<char>,
    /// Its atom scan.
    atom: AtomScan,
}

/// The length of the run at the end of a concatenation, from the runs and widths
/// of its two parts.
const fn trailing_run(head_run: usize, next_run: usize, next_width: usize) -> usize {
    if next_run == next_width {
        next_width.saturating_add(head_run)
    } else {
        next_run
    }
}

impl Frag {
    /// The measure of `line`, a text holding no newline.
    pub(super) fn of(line: &str) -> Self {
        let width = line.len();
        Self {
            width,
            leading_spaces: width.saturating_sub(line.trim_start_matches(' ').len()),
            leading_blank: width.saturating_sub(line.trim_start().len()),
            trailing_spaces: width.saturating_sub(line.trim_end_matches(' ').len()),
            trailing_neutral: width
                .saturating_sub(line.trim_end_matches([' ', '(', '{', '[']).len()),
            trailing_openers: width.saturating_sub(line.trim_end_matches(['(', '{', '[']).len()),
            last_char: line.trim_end().chars().next_back(),
            atom: AtomScan::of(line),
        }
    }

    /// The measure of `n` spaces.
    pub(super) const fn spaces(n: usize) -> Self {
        Self {
            width: n,
            leading_spaces: n,
            leading_blank: n,
            trailing_spaces: n,
            trailing_neutral: n,
            trailing_openers: 0,
            last_char: None,
            atom: AtomScan::spaces(n),
        }
    }

    /// The measure of this fragment followed by `next` on the same line.
    pub(super) const fn then(&self, next: &Self) -> Self {
        let width = self.width.saturating_add(next.width);
        Self {
            width,
            leading_spaces: if self.leading_spaces == self.width {
                self.width.saturating_add(next.leading_spaces)
            } else {
                self.leading_spaces
            },
            leading_blank: if self.leading_blank == self.width {
                self.width.saturating_add(next.leading_blank)
            } else {
                self.leading_blank
            },
            trailing_spaces: trailing_run(self.trailing_spaces, next.trailing_spaces, next.width),
            trailing_neutral: trailing_run(
                self.trailing_neutral,
                next.trailing_neutral,
                next.width,
            ),
            trailing_openers: trailing_run(
                self.trailing_openers,
                next.trailing_openers,
                next.width,
            ),
            last_char: if next.last_char.is_some() {
                next.last_char
            } else {
                self.last_char
            },
            atom: self.atom.then(&next.atom),
        }
    }

    /// Its length in bytes.
    pub(super) const fn width(&self) -> usize {
        self.width
    }

    /// The bytes of its leading run of `' '`.
    pub(super) const fn leading_spaces(&self) -> usize {
        self.leading_spaces
    }

    /// The bytes of its leading run of `char::is_whitespace` characters.
    pub(super) const fn leading_blank(&self) -> usize {
        self.leading_blank
    }

    /// The bytes of its trailing run of `' '`, `(`, `{` and `[`.
    pub(super) const fn trailing_neutral(&self) -> usize {
        self.trailing_neutral
    }

    /// The bytes of its trailing run of `(`, `{` and `[`.
    pub(super) const fn trailing_openers(&self) -> usize {
        self.trailing_openers
    }

    /// Its last character that is not whitespace.
    pub(super) const fn last_char(&self) -> Option<char> {
        self.last_char
    }

    /// The bytes of its trailing run of `' '`, which a break trims.
    pub(super) const fn trailing_spaces(&self) -> usize {
        self.trailing_spaces
    }

    /// Whether it holds only `' '` (an empty fragment does).
    pub(super) const fn is_blank_line(&self) -> bool {
        self.leading_spaces == self.width
    }

    /// Its length without leading whitespace.
    const fn content_len(&self) -> usize {
        self.width.saturating_sub(self.leading_blank)
    }

    /// Its length without leading whitespace nor the trailing `' '` a break trims.
    pub(super) const fn content_width(&self) -> usize {
        if self.leading_blank == self.width {
            0
        } else {
            self.content_len().saturating_sub(self.trailing_spaces)
        }
    }

    /// Whether it, read as a whole line, is an unbreakable atom.
    pub(super) const fn is_atom(&self) -> bool {
        self.atom.is_atom()
    }

    /// Whether it, read as a whole line, is an atom wider than `max_width`.
    const fn overflows_atom(&self, max_width: usize) -> bool {
        self.width > max_width && self.is_atom()
    }
}

/// The measure of the lines that sit wholly between a text's first and last
/// newline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Interior {
    /// The widest such line without leading whitespace.
    content: usize,
    /// The widest such line without leading whitespace nor trailing `' '`.
    trimmed: usize,
    /// The widest such line that is an unbreakable atom, or zero.
    atom: usize,
}

impl Interior {
    /// No line.
    const EMPTY: Self = Self {
        content: 0,
        trimmed: 0,
        atom: 0,
    };

    /// The one whole line `line` measures.
    const fn line(line: &Frag) -> Self {
        Self {
            content: line.content_len(),
            trimmed: line.content_width(),
            atom: if line.is_atom() { line.width } else { 0 },
        }
    }

    /// The lines of both.
    const fn union(self, other: Self) -> Self {
        Self {
            content: wider(self.content, other.content),
            trimmed: wider(self.trimmed, other.trimmed),
            atom: wider(self.atom, other.atom),
        }
    }
}

/// What follows a text's first newline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tail {
    /// The newlines, saturating.
    newlines: NonZeroU32,
    /// The lines between the first and the last newline.
    interior: Interior,
    /// The line after the last newline.
    last: Frag,
}

impl Tail {
    /// The tail of one newline followed by `last`.
    const fn open(last: &Frag) -> Self {
        Self {
            newlines: NonZeroU32::MIN,
            interior: Interior::EMPTY,
            last: *last,
        }
    }

    /// This tail followed by a newline and `last`.
    const fn push(&self, last: &Frag) -> Self {
        Self {
            newlines: self.newlines.saturating_add(1),
            interior: self.interior.union(Interior::line(&self.last)),
            last: *last,
        }
    }
}

/// The O(1)-sized measure of a rendered text that a layout decision reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Shape {
    /// The line before the first newline.
    first: Frag,
    /// Everything after the first newline, or `None` for a single line.
    tail: Option<Tail>,
    /// Whether the text holds a `{`.
    has_brace: bool,
    /// The text's first byte.
    first_byte: Option<u8>,
}

impl Shape {
    /// The measure of the empty text.
    pub(super) const EMPTY: Self = Self {
        first: Frag {
            width: 0,
            leading_spaces: 0,
            leading_blank: 0,
            trailing_spaces: 0,
            trailing_neutral: 0,
            trailing_openers: 0,
            last_char: None,
            atom: AtomScan::EMPTY,
        },
        tail: None,
        has_brace: false,
        first_byte: None,
    };

    /// The measure of `n` spaces, without writing them.
    pub(super) const fn spaces(n: usize) -> Self {
        Self {
            first: Frag::spaces(n),
            tail: None,
            has_brace: false,
            first_byte: if n == 0 { None } else { Some(b' ') },
        }
    }

    /// The measure of `text`.
    pub(super) fn of(text: &str) -> Self {
        let mut lines = text.split('\n');
        let first = Frag::of(lines.next().unwrap_or_default());
        let mut tail: Option<Tail> = None;
        for line in lines {
            let last = Frag::of(line);
            tail = Some(tail.map_or_else(|| Tail::open(&last), |open| open.push(&last)));
        }
        Self {
            first,
            tail,
            has_brace: text.contains('{'),
            first_byte: text.bytes().next(),
        }
    }

    /// The measure of this text followed by `next`.
    pub(super) const fn then(&self, next: &Self) -> Self {
        let (first, tail) = match (&self.tail, &next.tail) {
            (None, None) => (self.first.then(&next.first), None),
            (None, Some(after)) => (self.first.then(&next.first), Some(*after)),
            (Some(before), None) => (
                self.first,
                Some(Tail {
                    newlines: before.newlines,
                    interior: before.interior,
                    last: before.last.then(&next.first),
                }),
            ),
            (Some(before), Some(after)) => (
                self.first,
                Some(Tail {
                    newlines: before.newlines.saturating_add(after.newlines.get()),
                    interior: before
                        .interior
                        .union(Interior::line(&before.last.then(&next.first)))
                        .union(after.interior),
                    last: after.last,
                }),
            ),
        };
        Self {
            first,
            tail,
            has_brace: self.has_brace || next.has_brace,
            first_byte: if self.first_byte.is_some() {
                self.first_byte
            } else {
                next.first_byte
            },
        }
    }

    /// Whether the text is empty.
    pub(super) const fn is_empty(&self) -> bool {
        self.tail.is_none() && self.first.width == 0
    }

    /// Whether the text holds no newline.
    pub(super) const fn is_single_line(&self) -> bool {
        self.tail.is_none()
    }

    /// The newlines the text holds, saturating.
    pub(super) fn newlines(&self) -> u32 {
        self.tail.as_ref().map_or(0, |tail| tail.newlines.get())
    }

    /// The line before the first newline.
    pub(super) const fn first(&self) -> &Frag {
        &self.first
    }

    /// The line after the last newline: the line a cursor ends on.
    pub(super) fn last(&self) -> &Frag {
        self.tail.as_ref().map_or(&self.first, |tail| &tail.last)
    }

    /// The widest line after the first, without its leading whitespace.
    pub(super) fn widest_tail(&self) -> usize {
        self.tail.as_ref().map_or(0, |tail| {
            wider(tail.interior.content, tail.last.content_len())
        })
    }

    /// The widest line after the first, without its leading whitespace nor the
    /// trailing `' '` a break trims; zero for a single line.
    pub(super) fn widest_trimmed_tail(&self) -> usize {
        self.tail.as_ref().map_or(0, |tail| {
            wider(tail.interior.trimmed, tail.last.content_width())
        })
    }

    /// Whether some line is an unbreakable atom wider than `max_width`.
    #[cfg(test)]
    pub(super) fn any_line_overflows_atom(&self, max_width: usize) -> bool {
        self.any_line_overflows_atom_after(&Frag::spaces(0), max_width)
    }

    /// Whether some line of the text, its first line read after `line`, is an
    /// unbreakable atom wider than `max_width`.
    pub(super) fn any_line_overflows_atom_after(&self, line: &Frag, max_width: usize) -> bool {
        line.then(&self.first).overflows_atom(max_width)
            || self.tail.as_ref().is_some_and(|tail| {
                tail.interior.atom > max_width || tail.last.overflows_atom(max_width)
            })
    }

    /// The width of the last line when it holds only `' '`: the indent a break
    /// there keys off.
    pub(super) fn current_line_indent(&self) -> Option<usize> {
        let last = self.last();
        last.is_blank_line().then_some(last.width)
    }

    /// Whether the text holds a `{`.
    pub(super) const fn has_brace(&self) -> bool {
        self.has_brace
    }

    /// The text's first byte.
    pub(super) const fn first_byte(&self) -> Option<u8> {
        self.first_byte
    }
}

#[cfg(test)]
mod tests {
    use super::super::reference::{
        BodyShape, Cursor, FlatMeasure, content_width, current_line_indent,
        line_is_unbreakable_atom, widest_tail,
    };
    use super::{AtomScan, Frag, Shape};

    /// Single lines covering every scan transition: strings and escapes, `->`,
    /// nested `<>`, NBSP and tab, openers, separators, indent and blank lines.
    const LINES: &[&str] = &[
        "",
        "   ",
        "\t x",
        "foo",
        "  foo",
        "a b",
        "x = y",
        "f(a)",
        "[1]",
        "{",
        "a, b",
        "\"a b\"",
        "\"x\\\" y\"",
        "\"esc\\\\\" z",
        "\"unterminated a b",
        "-> T",
        "f -> g",
        "a->b",
        "Vec<Option<T>>",
        "a<b c>",
        "HashMap<K V>",
        "<<a b>>",
        "a>b c",
        "a >> b",
        "x-> <y z>",
        "<a -> b c>",
        "\u{a0}x y",
        "x\u{a0}y",
        "  \u{a0} ",
        "'a b",
        "\"(\" a",
        "\"a\"b<c d>",
        "\\\" x",
        "Box<dyn Fn(A) -> B>",
    ];

    /// Multi-line texts: indents, blank and space-only lines, trailing spaces,
    /// NBSP, braces, a leading `(`, an empty text and a lone newline.
    const TEXTS: &[&str] = &[
        "",
        "\n",
        "\n\n",
        "foo(\n    bar,\n)",
        "  {\n  x\n}  ",
        "  \n\n  a  ",
        " x\u{a0} \ny",
        "let a = \"s\n t\";\n    longatom_ident\nb {",
        "(a)\n\t\tb c\n   ",
        "x\n\u{a0} y\n",
        "ab\n\ncd  \n  ",
        "    very_long_path::to::item\n    short\n  Vec<A, B>\n",
    ];

    /// Every char boundary of `text`, both ends included.
    fn boundaries(text: &str) -> Vec<usize> {
        text.char_indices()
            .map(|(at, _)| at)
            .chain(std::iter::once(text.len()))
            .collect()
    }

    #[test]
    fn atom_scan_composes_exactly() {
        let mut atoms = 0;
        for &line in LINES {
            let whole = AtomScan::of(line);
            let expected = line_is_unbreakable_atom(line);
            atoms += usize::from(expected);
            assert_eq!(Frag::of(line).is_atom(), expected, "{line:?}");
            let cuts = boundaries(line);
            for &cut in &cuts {
                let (head, rest) = line.split_at(cut);
                let joined = AtomScan::of(head).then(&AtomScan::of(rest));
                assert_eq!(joined, whole, "{head:?} + {rest:?}");
                assert_eq!(
                    Frag::of(head).then(&Frag::of(rest)).is_atom(),
                    expected,
                    "{head:?} + {rest:?}"
                );
                for &inner in cuts.iter().filter(|&&inner| inner >= cut) {
                    let (mid, end) = rest.split_at(inner - cut);
                    let right = AtomScan::of(mid).then(&AtomScan::of(end));
                    assert_eq!(
                        AtomScan::of(head).then(&right),
                        whole,
                        "{head:?} + {mid:?} + {end:?}"
                    );
                }
            }
        }
        assert!(
            atoms > 0 && atoms < LINES.len(),
            "the corpus must hold both atoms and breakable lines"
        );
    }

    #[test]
    fn atom_scan_window_overflow_is_not_atom() {
        let open = "<".repeat(70);
        let close = ">".repeat(70);
        let deep = format!("{open}a b{close}");
        assert!(
            line_is_unbreakable_atom(&deep),
            "the space sits at depth 70, below the top level"
        );
        assert!(
            !Frag::of(&deep).is_atom(),
            "a space past the window reads as top-level"
        );
        let joined = Frag::of(&open).then(&Frag::of(&format!("a b{close}")));
        assert!(
            !joined.is_atom(),
            "a space shifted past the window reads as top-level"
        );
        let below = format!("{close} a");
        assert!(line_is_unbreakable_atom(&below));
        assert!(
            !Frag::of(&below).is_atom(),
            "a depth below the window reads as top-level"
        );
        let shallow = format!("{}a b{}", "<".repeat(8), ">".repeat(8));
        assert!(line_is_unbreakable_atom(&shallow));
        assert!(
            Frag::of(&shallow).is_atom(),
            "a depth inside the window stays exact"
        );
    }

    /// Assert every reader of `shape` equals the text read on `text` it replaces.
    fn assert_reads(text: &str, shape: &Shape) {
        assert_eq!(shape.widest_tail(), widest_tail(text), "{text:?}");
        let body = BodyShape::of(text);
        assert_eq!(
            usize::try_from(shape.newlines()).ok(),
            Some(body.newlines),
            "{text:?}"
        );
        assert_eq!(shape.first().last_char(), body.first_end, "{text:?}");
        assert_eq!(shape.first().width(), body.first_width, "{text:?}");
        let cursor = Cursor::of(text);
        assert_eq!(shape.is_empty(), cursor.empty, "{text:?}");
        assert_eq!(shape.last().width(), cursor.line_len, "{text:?}");
        assert_eq!(shape.last().is_blank_line(), cursor.blank_line, "{text:?}");
        assert_eq!(
            shape.last().trailing_spaces(),
            cursor.trailing_spaces,
            "{text:?}"
        );
        assert_eq!(
            shape.current_line_indent(),
            current_line_indent(text),
            "{text:?}"
        );
        let flat = FlatMeasure::of(text);
        assert_eq!(shape.is_single_line(), flat.single_line, "{text:?}");
        assert_eq!(shape.first().width(), flat.first_len, "{text:?}");
        assert_eq!(
            shape.first_byte() == Some(b'('),
            flat.starts_paren,
            "{text:?}"
        );
        assert_eq!(shape.has_brace(), text.contains('{'), "{text:?}");
        let last_line = text.rsplit('\n').next().unwrap_or_default();
        assert_eq!(
            shape.last().content_width(),
            content_width(last_line),
            "{text:?}"
        );
        let run = |line: &str, set: &[char]| line.len() - line.trim_end_matches(set).len();
        assert_eq!(
            shape.last().trailing_neutral(),
            run(last_line, &[' ', '(', '{', '[']),
            "{text:?}"
        );
        assert_eq!(
            shape.last().trailing_openers(),
            run(last_line, &['(', '{', '[']),
            "{text:?}"
        );
        let first_line = text.split('\n').next().unwrap_or_default();
        assert_eq!(
            shape.first().leading_spaces(),
            first_line.len() - first_line.trim_start_matches(' ').len(),
            "{text:?}"
        );
        assert_eq!(
            shape.first().leading_blank(),
            first_line.len() - first_line.trim_start().len(),
            "{text:?}"
        );
        assert_eq!(
            shape.widest_trimmed_tail(),
            text.split('\n')
                .skip(1)
                .map(content_width)
                .max()
                .unwrap_or_default(),
            "{text:?}"
        );
        for max_width in [0, 1, 2, 4, 8, 16, 100] {
            let expected = text
                .split('\n')
                .any(|line| line.len() > max_width && line_is_unbreakable_atom(line));
            assert_eq!(
                shape.any_line_overflows_atom(max_width),
                expected,
                "{text:?} at {max_width}"
            );
        }
    }

    /// A run of spaces measured without writing it is the measure of the written
    /// run, alone and after any text; the empty measure is the empty text's.
    #[test]
    fn spaces_measure_like_written_spaces() {
        assert_eq!(Shape::EMPTY, Shape::of(""));
        for n in 0..=130 {
            let written = " ".repeat(n);
            assert_eq!(Shape::spaces(n), Shape::of(&written), "{n}");
            assert_eq!(Frag::spaces(n), Frag::of(&written), "{n}");
            for &text in TEXTS.iter().chain(LINES) {
                let joined = format!("{text}{written}");
                assert_eq!(
                    Shape::of(text).then(&Shape::spaces(n)),
                    Shape::of(&joined),
                    "{text:?} + {n}"
                );
                let joined = format!("{written}{text}");
                assert_eq!(
                    Shape::spaces(n).then(&Shape::of(text)),
                    Shape::of(&joined),
                    "{n} + {text:?}"
                );
            }
        }
    }

    /// A line read before a text joins the text's first line in the atom test.
    #[test]
    fn overflow_after_a_line_reads_the_joined_line() {
        for &line in LINES {
            for &text in TEXTS.iter().chain(LINES) {
                let joined = Shape::of(&format!("{line}{text}"));
                for max_width in [0, 2, 4, 8, 100] {
                    assert_eq!(
                        Shape::of(text).any_line_overflows_atom_after(&Frag::of(line), max_width),
                        joined.any_line_overflows_atom(max_width),
                        "{line:?} + {text:?} at {max_width}"
                    );
                }
            }
        }
    }

    #[test]
    fn frag_and_interior_compose_exactly() {
        let joined = LINES.join("\n");
        let texts = TEXTS
            .iter()
            .copied()
            .chain(LINES.iter().copied())
            .chain(std::iter::once(joined.as_str()));
        let mut overflowing = 0;
        let mut multi_line = 0;
        for text in texts {
            let whole = Shape::of(text);
            assert_reads(text, &whole);
            overflowing += usize::from(whole.any_line_overflows_atom(4));
            multi_line += usize::from(!whole.is_single_line());
            let cuts = boundaries(text);
            for &cut in &cuts {
                let (head, rest) = text.split_at(cut);
                for &inner in cuts.iter().filter(|&&inner| inner >= cut) {
                    let (mid, end) = rest.split_at(inner - cut);
                    let (head, mid, end) = (Shape::of(head), Shape::of(mid), Shape::of(end));
                    let left = head.then(&mid).then(&end);
                    assert_eq!(left, whole, "{text:?} cut at {cut}, {inner}");
                    assert_eq!(
                        head.then(&mid.then(&end)),
                        whole,
                        "{text:?} cut at {cut}, {inner}"
                    );
                }
            }
        }
        assert!(
            overflowing > 0,
            "some text must hold an overflowing atom line"
        );
        assert!(multi_line > 0, "some text must span several lines");
    }
}

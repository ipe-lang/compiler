//! The one position mapper: compiler byte offsets ↔ LSP line/character
//! positions.
//!
//! Compiler [`Span`]s are byte offsets into a module's UTF-8 source; LSP
//! positions count lines plus characters in a client-negotiated encoding
//! (UTF-16 code units by default, UTF-8 bytes when negotiated). Every
//! span↔range crossing in the LSP goes through this module — there is no
//! second conversion path to drift.
//!
//! Every function is total: out-of-range offsets, positions past the end of a
//! line or file, and mid-code-point byte offsets all clamp to the nearest
//! valid boundary instead of panicking.
//!
//! A line ends at `\n`, at a `\r\n` pair, or at a lone `\r` — the three breaks
//! an LSP client counts. The lexer refuses a lone `\r`, so a source the
//! compiler accepted only ever holds the first two; the mapper still counts the
//! third so its line numbers match the client's on any buffer it is handed. A
//! byte offset between the `\r` and the `\n` of a pair is not a position and
//! clamps down to the `\r`.

use ipe_diagnostics::Span;
use lsp_types::{Position, Range};

/// The negotiated character-counting unit for LSP positions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PositionEncoding {
    /// Characters are UTF-8 bytes (the identity for compiler spans).
    Utf8,
    /// Characters are UTF-16 code units (the LSP default, mandatory).
    Utf16,
}

impl PositionEncoding {
    /// The width of `ch` in this encoding's units.
    const fn width(self, ch: char) -> usize {
        match self {
            Self::Utf8 => ch.len_utf8(),
            Self::Utf16 => ch.len_utf16(),
        }
    }
}

/// The largest char boundary `<= byte` (and `<= text.len()`).
fn floor_char_boundary(text: &str, byte: usize) -> usize {
    let mut b = byte.min(text.len());
    while b > 0 && !text.is_char_boundary(b) {
        b -= 1;
    }
    b
}

/// The largest position boundary `<= byte`: a char boundary not inside a `\r\n` pair.
fn floor_position_boundary(text: &str, byte: usize) -> usize {
    let b = floor_char_boundary(text, byte);
    let bytes = text.as_bytes();
    let inside_pair = b
        .checked_sub(1)
        .is_some_and(|prev| bytes.get(prev) == Some(&b'\r') && bytes.get(b) == Some(&b'\n'));
    if inside_pair { b - 1 } else { b }
}

/// The byte range of the first line break in `text`: `\r\n`, `\n` or a lone `\r`.
fn first_line_break(text: &str) -> Option<(usize, usize)> {
    let at = text.find(['\n', '\r'])?;
    let pair = text.as_bytes().get(at..at.saturating_add(2)) == Some(b"\r\n");
    Some((at, at + if pair { 2 } else { 1 }))
}

/// The byte offset just past each line break in `text`, in order.
fn line_break_ends(text: &str) -> impl Iterator<Item = usize> {
    let mut start = 0usize;
    std::iter::from_fn(move || {
        let (_, end) = first_line_break(text.get(start..)?)?;
        start += end;
        Some(start)
    })
}

/// The `(line, column)` of position boundary `byte`, counting breaks in its prefix.
fn line_and_column(text: &str, byte: usize, encoding: PositionEncoding) -> Position {
    let before = text.get(..byte).unwrap_or("");
    let (line, line_start) =
        line_break_ends(before).fold((0usize, 0usize), |(n, _), end| (n + 1, end));
    let column: usize = before
        .get(line_start..)
        .unwrap_or("")
        .chars()
        .map(|ch| encoding.width(ch))
        .sum();
    Position {
        line: u32::try_from(line).unwrap_or(u32::MAX),
        character: u32::try_from(column).unwrap_or(u32::MAX),
    }
}

/// A one-pass index of a document's line-start byte offsets.
///
/// A feature that converts many spans in one request resolves each in
/// `O(log lines)` plus a within-line scan, rather than rescanning the whole
/// prefix from byte 0 per conversion (which is `O(items × file_len)` across a
/// diagnostics / symbols / inlay-hints loop). Build it once per file text and
/// reuse it for every conversion in the request.
pub struct LineIndex<'a> {
    text: &'a str,
    /// Byte offset of each line's first character. Always starts with `0`.
    line_starts: Vec<usize>,
}

impl<'a> LineIndex<'a> {
    /// Build the index over `text` in one linear pass.
    #[must_use]
    pub fn new(text: &'a str) -> Self {
        let line_starts = std::iter::once(0).chain(line_break_ends(text)).collect();
        Self { text, line_starts }
    }

    /// Convert a byte offset to an LSP position, clamping like
    /// [`offset_to_position`] but using the prebuilt line table.
    #[must_use]
    pub fn position_of(&self, byte: usize, encoding: PositionEncoding) -> Position {
        let byte = floor_position_boundary(self.text, byte);
        // The containing line is the last line start `<= byte`.
        let line = match self.line_starts.binary_search(&byte) {
            Ok(l) => l,
            Err(i) => i.saturating_sub(1),
        };
        let line_start = self.line_starts.get(line).copied().unwrap_or(0);
        let column: usize = self
            .text
            .get(line_start..byte)
            .unwrap_or("")
            .chars()
            .map(|ch| encoding.width(ch))
            .sum();
        Position {
            line: u32::try_from(line).unwrap_or(u32::MAX),
            character: u32::try_from(column).unwrap_or(u32::MAX),
        }
    }

    /// Convert a compiler [`Span`] to an LSP range using the prebuilt table.
    #[must_use]
    pub fn range_of(&self, span: Span, encoding: PositionEncoding) -> Range {
        let start = self.position_of(span.lo as usize, encoding);
        let end_byte = (span.hi as usize).max(span.lo as usize);
        let end = self.position_of(end_byte, encoding);
        Range { start, end }
    }
}

/// Convert a byte offset into `text` to an LSP position.
///
/// Out-of-range, mid-code-point and mid-`\r\n` offsets clamp down to the
/// nearest position boundary.
#[must_use]
pub fn offset_to_position(text: &str, byte: usize, encoding: PositionEncoding) -> Position {
    line_and_column(text, floor_position_boundary(text, byte), encoding)
}

/// Convert an LSP position to a byte offset into `text`. A line past the end
/// of the file clamps to `text.len()`; a character past the end of its line
/// clamps to the end of that line (before its line break).
#[must_use]
pub fn position_to_offset(text: &str, position: Position, encoding: PositionEncoding) -> usize {
    let mut line_start = 0usize;
    for _ in 0..position.line {
        match text.get(line_start..).and_then(first_line_break) {
            Some((_, end)) => line_start += end,
            None => return text.len(),
        }
    }
    let rest = text.get(line_start..).unwrap_or("");
    let line_end = first_line_break(rest).map_or(rest.len(), |(at, _)| at);
    let line_text = rest.get(..line_end).unwrap_or("");

    let target = position.character as usize;
    let mut units = 0usize;
    let mut byte = 0usize;
    for ch in line_text.chars() {
        if units >= target {
            break;
        }
        units += encoding.width(ch);
        byte += ch.len_utf8();
    }
    line_start + byte
}

/// Convert a compiler [`Span`] (byte offsets into `text`) to an LSP range.
/// An inverted span clamps to an empty range at its start.
#[must_use]
pub fn span_to_range(text: &str, span: Span, encoding: PositionEncoding) -> Range {
    let start = offset_to_position(text, span.lo as usize, encoding);
    let end_byte = (span.hi as usize).max(span.lo as usize);
    let end = offset_to_position(text, end_byte, encoding);
    Range { start, end }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NASTY: &[&str] = &[
        "",
        "\n",
        "plain ascii\nsecond line\n",
        "no trailing newline",
        "crlf line one\r\nsecond\r\n",
        "emoji 😀 astral\nsecond 😀😀 line\n",
        "cjk 漢字テスト\nмежду строк\n",
        "combining e\u{301} mark\ne\u{301}\u{301}\n",
        "mixed 😀漢e\u{301}x\r\ntail",
        "\u{10FFFF}\n\u{10FFFF}ascii",
        "lone\rcr\r",
        "\r",
        "\r\r\n\n\r",
        "mixed\nall\r\nthree\rends 😀",
    ];

    /// Whether `byte` is a position: a char boundary not between a `\r` and its `\n`.
    fn is_position_boundary(text: &str, byte: usize) -> bool {
        let bytes = text.as_bytes();
        let inside_pair =
            byte > 0 && bytes.get(byte - 1) == Some(&b'\r') && bytes.get(byte) == Some(&b'\n');
        text.is_char_boundary(byte) && !inside_pair
    }

    /// The client's reading of `byte`: every break normalised to `\n`, then counted.
    fn oracle_position(text: &str, byte: usize, encoding: PositionEncoding) -> Position {
        let prefix = text
            .get(..byte)
            .unwrap_or("")
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        let line = prefix.matches('\n').count();
        let last_line = prefix.rsplit('\n').next().unwrap_or("");
        let column: usize = last_line.chars().map(|ch| encoding.width(ch)).sum();
        Position {
            line: u32::try_from(line).unwrap(),
            character: u32::try_from(column).unwrap(),
        }
    }

    #[test]
    fn line_index_matches_the_scalar_mapper_everywhere() {
        // The bulk `LineIndex` path must agree byte-for-byte with the scalar
        // `offset_to_position` on every char boundary of the nasty corpus, so a
        // feature can switch to it with no observable change.
        for text in NASTY {
            let index = LineIndex::new(text);
            for encoding in [PositionEncoding::Utf8, PositionEncoding::Utf16] {
                for byte in 0..=text.len() {
                    assert_eq!(
                        index.position_of(byte, encoding),
                        offset_to_position(text, byte, encoding),
                        "LineIndex disagreed at byte {byte} of {text:?} ({encoding:?})"
                    );
                }
            }
        }
    }

    #[test]
    fn round_trip_identity_on_every_char_boundary() {
        for text in NASTY {
            for encoding in [PositionEncoding::Utf8, PositionEncoding::Utf16] {
                for byte in 0..=text.len() {
                    if !is_position_boundary(text, byte) {
                        continue;
                    }
                    let pos = offset_to_position(text, byte, encoding);
                    let back = position_to_offset(text, pos, encoding);
                    assert_eq!(
                        back, byte,
                        "round trip failed at byte {byte} of {text:?} ({encoding:?})"
                    );
                }
            }
        }
    }

    #[test]
    fn mid_code_point_offsets_clamp_down() {
        let text = "a😀b";
        // Bytes 2, 3, 4 are inside the 4-byte emoji starting at byte 1.
        for encoding in [PositionEncoding::Utf8, PositionEncoding::Utf16] {
            for mid in 2..=4 {
                let pos = offset_to_position(text, mid, encoding);
                assert_eq!(pos, offset_to_position(text, 1, encoding));
            }
        }
    }

    #[test]
    fn out_of_range_positions_clamp() {
        let text = "one\ntwo\n";
        for encoding in [PositionEncoding::Utf8, PositionEncoding::Utf16] {
            // Line past EOF → end of text.
            let past_line = Position {
                line: 99,
                character: 0,
            };
            assert_eq!(position_to_offset(text, past_line, encoding), text.len());
            // Character past end of line → end of that line, before `\n`.
            let past_col = Position {
                line: 0,
                character: 99,
            };
            assert_eq!(position_to_offset(text, past_col, encoding), 3);
            // Byte offset past EOF → last position.
            let end = offset_to_position(text, 9999, encoding);
            assert_eq!(position_to_offset(text, end, encoding), text.len());
        }
    }

    #[test]
    fn utf16_counts_astral_pairs() {
        let text = "😀x";
        let pos = offset_to_position(text, 4, PositionEncoding::Utf16);
        assert_eq!(
            pos,
            Position {
                line: 0,
                character: 2
            }
        );
        let pos8 = offset_to_position(text, 4, PositionEncoding::Utf8);
        assert_eq!(
            pos8,
            Position {
                line: 0,
                character: 4
            }
        );
    }

    #[test]
    fn span_to_range_spans_lines() {
        let text = "ab\ncd\n";
        let range = span_to_range(text, Span::new(1, 4), PositionEncoding::Utf16);
        assert_eq!(
            range.start,
            Position {
                line: 0,
                character: 1
            }
        );
        assert_eq!(
            range.end,
            Position {
                line: 1,
                character: 1
            }
        );
    }

    #[test]
    fn inverted_span_clamps_to_empty() {
        let text = "abcdef";
        let range = span_to_range(text, Span { lo: 4, hi: 2 }, PositionEncoding::Utf16);
        assert_eq!(range.start, range.end);
    }

    /// Every text over `a`, `\r`, `\n` and an astral char up to six chars long.
    fn every_short_text() -> Vec<String> {
        let alphabet = ['a', '\r', '\n', '😀'];
        let mut texts = vec![String::new()];
        let mut frontier = vec![String::new()];
        for _ in 0..6 {
            frontier = frontier
                .iter()
                .flat_map(|t| alphabet.iter().map(move |ch| format!("{t}{ch}")))
                .collect();
            texts.extend(frontier.iter().cloned());
        }
        texts
    }

    /// On every mix of the three line breaks, both mappers read each position as
    /// a client does, the round trip is the identity, and mid-pair bytes clamp.
    #[test]
    fn every_mix_of_line_breaks_maps_like_a_client() {
        for text in every_short_text() {
            let index = LineIndex::new(&text);
            for encoding in [PositionEncoding::Utf8, PositionEncoding::Utf16] {
                for byte in 0..=text.len() {
                    if !text.is_char_boundary(byte) {
                        continue;
                    }
                    let scalar = offset_to_position(&text, byte, encoding);
                    assert_eq!(
                        index.position_of(byte, encoding),
                        scalar,
                        "{text:?} @ {byte}"
                    );
                    if is_position_boundary(&text, byte) {
                        assert_eq!(
                            scalar,
                            oracle_position(&text, byte, encoding),
                            "{text:?} @ {byte}"
                        );
                        assert_eq!(
                            position_to_offset(&text, scalar, encoding),
                            byte,
                            "{text:?} @ {byte}"
                        );
                    } else {
                        assert_eq!(
                            scalar,
                            offset_to_position(&text, byte - 1, encoding),
                            "{text:?} @ {byte}"
                        );
                    }
                }
            }
        }
    }

    /// A position past a lone `\r` is on the next line and round-trips.
    #[test]
    fn a_lone_carriage_return_ends_a_line() {
        let text = "a\rb\r\nc";
        for encoding in [PositionEncoding::Utf8, PositionEncoding::Utf16] {
            let b = Position {
                line: 1,
                character: 0,
            };
            let c = Position {
                line: 2,
                character: 0,
            };
            assert_eq!(offset_to_position(text, 2, encoding), b);
            assert_eq!(position_to_offset(text, b, encoding), 2);
            assert_eq!(offset_to_position(text, 5, encoding), c);
            assert_eq!(position_to_offset(text, c, encoding), 5);
            // A character past the end of line 0 stops before its `\r`.
            let past = Position {
                line: 0,
                character: 9,
            };
            assert_eq!(position_to_offset(text, past, encoding), 1);
            // The byte between the `\r` and `\n` of a pair clamps to the `\r`.
            assert_eq!(
                offset_to_position(text, 4, encoding),
                offset_to_position(text, 3, encoding)
            );
        }
    }
}

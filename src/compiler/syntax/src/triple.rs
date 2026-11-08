//! The two forms of a `"""` string, judged once from source.
//!
//! A one-line string `"""text"""` opens and closes on one line, and its value
//! is the text between the quotes. A block string's opening `"""` ends its
//! line and its closing `"""` stands alone on its own line in the opener's
//! column, the margin; its value is the lines between the two with the first
//! `margin - 1` columns removed, joined by `\n`. Every other shape is a
//! [`TripleStringDefect`], so a [`TripleStr`] in the AST is always one of the
//! two forms and its value is never guessed.

use std::borrow::Cow;
use std::num::NonZeroU32;
use std::ops::Range;

use ipe_diagnostics::{OpenerText, Span, TripleStringDefect};

/// The `"""` delimiter both forms open and close with.
const QUOTES: &str = "\"\"\"";

/// A 1-based source column, counted in Unicode scalar values.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Column(NonZeroU32);

impl Column {
    /// The first column of a line.
    pub const FIRST: Self = Self(NonZeroU32::MIN);

    /// The column numbered `n`.
    #[must_use]
    pub const fn new(n: NonZeroU32) -> Self {
        Self(n)
    }

    /// The column's 1-based number.
    #[must_use]
    pub const fn get(self) -> NonZeroU32 {
        self.0
    }

    /// The number of columns left of this one.
    const fn width_before(self) -> u32 {
        self.0.get().saturating_sub(1)
    }
}

/// A `"""` string in one of its two forms.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TripleStr(Form);

/// The two forms; private so no other shape is representable.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Form {
    /// `"""text"""`: the text and the source offset it starts at.
    OneLine { text: String, lo: u32 },
    /// The block's margin column and its body lines, margin removed.
    Block {
        margin: Column,
        lines: Vec<BodyLine>,
    },
}

/// One block body line: its text right of the margin, and where that text
/// starts in source. The text runs to the line's terminator, so the
/// terminator sits at `lo + text.len()`.
#[derive(Clone, PartialEq, Eq, Debug)]
struct BodyLine {
    text: String,
    lo: u32,
}

/// Why a `"""` opener does not start a string.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TripleRefusal {
    /// No closing `"""` before the end of the file at `eof`.
    Unterminated { eof: u32 },
    /// The string fits neither form; the lexer resumes at `end`, past its
    /// closing `"""`.
    Malformed {
        defect: TripleStringDefect,
        end: u32,
    },
}

/// A judged string and the source offset just past its closing `"""`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Judged {
    /// The string in its form.
    pub string: TripleStr,
    /// The offset just past the closing `"""`.
    pub end: u32,
}

/// Where a `"""` opener sits in its source.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Opener {
    /// The byte offset of the opening `"""`.
    pub lo: u32,
    /// The 1-based line the opener stands on.
    pub line: NonZeroU32,
    /// The opener's column, which is a block's margin.
    pub column: Column,
}

/// The offset `rel` bytes after `base`, saturating at the largest offset.
fn offset(base: u32, rel: usize) -> u32 {
    base.saturating_add(u32::try_from(rel).unwrap_or(u32::MAX))
}

/// The byte range of a `"""` string opening at `lo`: up to and including the
/// first `"""` after the opener, or `None` when none follows.
#[must_use]
pub fn extent(src: &str, lo: u32) -> Option<Range<usize>> {
    let start = usize::try_from(lo).ok()?;
    let content_lo = start.checked_add(QUOTES.len())?;
    let closer_rel = src.get(content_lo..)?.find(QUOTES)?;
    let end = content_lo
        .checked_add(closer_rel)?
        .checked_add(QUOTES.len())?;
    Some(start..end)
}

/// Judge the `"""` string opening at `opener` into its form, or refuse it.
///
/// # Errors
///
/// [`TripleRefusal::Unterminated`] when no `"""` follows the opener;
/// [`TripleRefusal::Malformed`] with the first defect in source order when
/// the string fits neither form.
pub fn judge(src: &str, opener: Opener) -> Result<Judged, TripleRefusal> {
    let unterminated = TripleRefusal::Unterminated {
        eof: offset(0, src.len()),
    };
    let Some(range) = extent(src, opener.lo) else {
        return Err(unterminated);
    };
    let content_lo = range.start.saturating_add(QUOTES.len());
    let closer_lo = range.end.saturating_sub(QUOTES.len());
    let Some(inner) = src.get(content_lo..closer_lo) else {
        return Err(unterminated);
    };
    let end = offset(0, range.end);
    let malformed = |defect: TripleStringDefect| TripleRefusal::Malformed { defect, end };
    let inner_lo = offset(0, content_lo);
    let closer = Span::new(offset(0, closer_lo), end);

    let after_opener = if inner.starts_with('\n') {
        1
    } else if inner.starts_with("\r\n") {
        2
    } else {
        let Some(first_break) = inner.find('\n') else {
            return Ok(Judged {
                string: TripleStr(Form::OneLine {
                    text: inner.to_owned(),
                    lo: inner_lo,
                }),
                end,
            });
        };
        let first = inner.get(..first_break).unwrap_or_default();
        let first = first.strip_suffix('\r').unwrap_or(first);
        let text = if first.chars().all(char::is_whitespace) {
            OpenerText::Whitespace
        } else {
            OpenerText::Content
        };
        return Err(malformed(TripleStringDefect::TextAfterOpener {
            span: Span::new(inner_lo, offset(inner_lo, first.len())),
            text,
        }));
    };

    let margin = opener.column;
    // `inner` holds at least the opener's line break, so it has a last `\n`.
    let last_break = inner.rfind('\n').unwrap_or_default();
    let closer_line = inner
        .get(last_break.saturating_add(1)..)
        .unwrap_or_default();
    let closer_line_lo = offset(inner_lo, last_break.saturating_add(1));
    judge_closer_line(closer_line, closer_line_lo, closer, opener).map_err(&malformed)?;

    let mut lines = Vec::new();
    let body_end = last_break.saturating_add(1);
    if after_opener < body_end {
        let body = inner.get(after_opener..body_end).unwrap_or_default();
        let mut line_lo = offset(inner_lo, after_opener);
        let mut line_no = opener.line;
        for raw in body.split_inclusive('\n') {
            line_no = line_no.saturating_add(1);
            let content = raw.strip_suffix('\n').unwrap_or(raw);
            let content = content.strip_suffix('\r').unwrap_or(content);
            lines.push(judge_body_line(content, line_lo, line_no, margin).map_err(&malformed)?);
            line_lo = offset(line_lo, raw.len());
        }
    }
    Ok(Judged {
        string: TripleStr(Form::Block { margin, lines }),
        end,
    })
}

/// Judge the text left of a block's closing `"""`: blank, spaces only, and
/// exactly as wide as the margin.
fn judge_closer_line(
    prefix: &str,
    prefix_lo: u32,
    closer: Span,
    opener: Opener,
) -> Result<(), TripleStringDefect> {
    let margin = opener.column.get();
    if prefix.chars().any(|c| c != ' ' && c != '\t') {
        return Err(TripleStringDefect::CloserEndsContentLine {
            span: closer,
            margin,
        });
    }
    let width = offset(0, prefix.chars().count());
    if width != opener.column.width_before() {
        return Err(TripleStringDefect::Misaligned {
            span: closer,
            opener: Span::new(opener.lo, offset(opener.lo, QUOTES.len())),
            closer_col: NonZeroU32::MIN.saturating_add(width),
            margin,
        });
    }
    match prefix.find('\t') {
        Some(tab) => {
            let lo = offset(prefix_lo, tab);
            Err(TripleStringDefect::TabInMargin {
                span: Span::new(lo, offset(lo, 1)),
                margin,
            })
        }
        None => Ok(()),
    }
}

/// Judge one block body line against the margin and strip it.
fn judge_body_line(
    content: &str,
    lo: u32,
    line: NonZeroU32,
    margin: Column,
) -> Result<BodyLine, TripleStringDefect> {
    let width = usize::try_from(margin.width_before()).unwrap_or(usize::MAX);
    for (byte, c) in content.char_indices().take(width) {
        let at = offset(lo, byte);
        match c {
            ' ' => {}
            '\t' => {
                return Err(TripleStringDefect::TabInMargin {
                    span: Span::new(at, offset(at, 1)),
                    margin: margin.get(),
                });
            }
            _ => {
                return Err(TripleStringDefect::LineUnderMargin {
                    span: Span::new(lo, offset(at, c.len_utf8())),
                    line,
                    margin: margin.get(),
                });
            }
        }
    }
    // Every column left of the margin is a one-byte space, so the margin's
    // byte width is its column width; a shorter spaces-only line is empty.
    let cut = width.min(content.len());
    Ok(BodyLine {
        text: content.get(cut..).unwrap_or_default().to_owned(),
        lo: offset(lo, cut),
    })
}

impl TripleStr {
    /// The string's value: the one-line text, or the block's lines joined by
    /// `\n`.
    #[must_use]
    pub fn value(&self) -> Cow<'_, str> {
        match &self.0 {
            Form::OneLine { text, .. } => Cow::Borrowed(text),
            Form::Block { lines, .. } => match lines.as_slice() {
                [] => Cow::Borrowed(""),
                [only] => Cow::Borrowed(&only.text),
                many => Cow::Owned(
                    many.iter()
                        .map(|line| line.text.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            },
        }
    }

    /// The source offset of byte `at` of the value: a byte of text maps to
    /// where it stands in source, a joining `\n` to the line terminator it
    /// replaces (the `\r` of a `\r\n`), and the value's end to the end of its
    /// last text. `None` past the value's end or for an empty block.
    #[must_use]
    pub fn source_offset(&self, at: usize) -> Option<u32> {
        match &self.0 {
            Form::OneLine { text, lo } => (at <= text.len()).then(|| offset(*lo, at)),
            Form::Block { lines, .. } => {
                let mut start = 0usize;
                for line in lines {
                    let end = start.checked_add(line.text.len())?;
                    if at <= end {
                        return Some(offset(line.lo, at.checked_sub(start)?));
                    }
                    start = end.checked_add(1)?;
                }
                None
            }
        }
    }

    /// The source span of the value's byte range `range`, when both ends map.
    #[must_use]
    pub fn source_span(&self, range: Range<usize>) -> Option<Span> {
        Some(Span::new(
            self.source_offset(range.start)?,
            self.source_offset(range.end)?,
        ))
    }

    /// The block's margin column; `None` for a one-line string.
    #[must_use]
    pub const fn margin(&self) -> Option<Column> {
        match &self.0 {
            Form::OneLine { .. } => None,
            Form::Block { margin, .. } => Some(*margin),
        }
    }

    /// The string's lines, margin removed: the one text of a one-line string,
    /// or each body line of a block.
    pub fn lines(&self) -> impl Iterator<Item = &str> {
        let (one, block): (Option<&str>, &[BodyLine]) = match &self.0 {
            Form::OneLine { text, .. } => (Some(text), &[]),
            Form::Block { lines, .. } => (None, lines),
        };
        one.into_iter()
            .chain(block.iter().map(|line| line.text.as_str()))
    }
}

/// One piece of a `"""` string's value, split at its `{{expr}}` markers.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Piece {
    /// Literal text with its escapes resolved (`\{{` reads `{{`, `\\` reads
    /// `\`), and the value bytes it was read from.
    Text { text: String, range: Range<usize> },
    /// The value bytes between a `{{` and its `}}`, unparsed.
    Interp { range: Range<usize> },
}

/// Split a `"""` string's value into literal text and `{{expr}}` bodies.
///
/// `\{{` is a literal `{{`, `\\` a literal `\`, and any other backslash is
/// kept as written. A `{{` with no `}}` after it is literal text through the
/// end of the value, its escapes unresolved. A `{{` always ends the text before
/// it, so the text pieces are exactly the stretches between markers.
#[must_use]
pub fn interpolation_pieces(value: &str) -> Vec<Piece> {
    let mut pieces = Vec::new();
    let mut text = String::new();
    let mut text_lo = 0;
    let mut at = 0;
    while let Some(tail) = value.get(at..).filter(|tail| !tail.is_empty()) {
        if tail.starts_with("\\{{") {
            text.push_str("{{");
            at = at.saturating_add(3);
        } else if tail.starts_with("\\\\") {
            text.push('\\');
            at = at.saturating_add(2);
        } else if tail.starts_with("{{") {
            if !text.is_empty() {
                pieces.push(Piece::Text {
                    text: std::mem::take(&mut text),
                    range: text_lo..at,
                });
            }
            let open_lo = at;
            let body_lo = at.saturating_add(2);
            let close = value.get(body_lo..).and_then(|body| body.find("}}"));
            if let Some(len) = close {
                let body_hi = body_lo.saturating_add(len);
                pieces.push(Piece::Interp {
                    range: body_lo..body_hi,
                });
                at = body_hi.saturating_add(2);
                text_lo = at;
            } else {
                text.push_str(tail);
                text_lo = open_lo;
                at = value.len();
            }
        } else {
            let c = tail.chars().next().unwrap_or_default();
            text.push(c);
            at = at.saturating_add(c.len_utf8());
        }
    }
    if !text.is_empty() {
        pieces.push(Piece::Text {
            text,
            range: text_lo..value.len(),
        });
    }
    pieces
}

#[cfg(test)]
mod tests {
    use super::{Column, Judged, Opener, Piece, TripleRefusal, interpolation_pieces, judge};
    use ipe_diagnostics::{OpenerText, Span, TripleStringDefect};
    use std::num::NonZeroU32;

    /// Judge the first `"""` of `src`, reading its line and column from the
    /// text before it.
    fn judge_first(src: &str) -> Result<Judged, TripleRefusal> {
        let lo = src.find("\"\"\"").unwrap_or_default();
        let before = src.get(..lo).unwrap_or_default();
        let line = before.matches('\n').count().saturating_add(1);
        let column = before
            .rsplit('\n')
            .next()
            .map_or(0, |l| l.chars().count())
            .saturating_add(1);
        let nz = |n: usize| {
            NonZeroU32::new(u32::try_from(n).unwrap_or(u32::MAX)).unwrap_or(NonZeroU32::MIN)
        };
        judge(
            src,
            Opener {
                lo: u32::try_from(lo).unwrap_or(u32::MAX),
                line: nz(line),
                column: Column::new(nz(column)),
            },
        )
    }

    fn nz(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap_or(NonZeroU32::MIN)
    }

    fn value(src: &str) -> Option<String> {
        judge_first(src).ok().map(|j| j.string.value().into_owned())
    }

    fn defect(src: &str) -> Option<TripleStringDefect> {
        match judge_first(src) {
            Err(TripleRefusal::Malformed { defect, .. }) => Some(defect),
            _ => None,
        }
    }

    /// The source text a span covers.
    fn text(src: &str, span: Span) -> &str {
        src.get(span.lo as usize..span.hi as usize)
            .unwrap_or("<out of range>")
    }

    #[test]
    fn one_line_value_is_its_text() {
        assert_eq!(
            value("x = \"\"\"a \"b\" c\"\"\""),
            Some("a \"b\" c".to_owned())
        );
        assert_eq!(value("x = \"\"\"\"\"\""), Some(String::new()));
    }

    #[test]
    fn block_value_strips_the_margin_and_drops_the_last_break() {
        let src = "x =\n    \"\"\"\n    a\n      b\n\n    \"\"\"\n";
        assert_eq!(value(src), Some("a\n  b\n".to_owned()));
    }

    #[test]
    fn block_with_no_body_lines_is_empty() {
        assert_eq!(value("x =\n    \"\"\"\n    \"\"\""), Some(String::new()));
    }

    #[test]
    fn spaces_only_line_shorter_than_the_margin_is_empty() {
        let src = "x =\n    \"\"\"\n    a\n  \n    b\n    \"\"\"";
        assert_eq!(value(src), Some("a\n\nb".to_owned()));
    }

    #[test]
    fn crlf_block_value_joins_with_line_feed() {
        let src = "x =\r\n    \"\"\"\r\n    a\r\n    b\r\n    \"\"\"\r\n";
        assert_eq!(value(src), Some("a\nb".to_owned()));
    }

    #[test]
    fn block_at_column_one_keeps_every_column() {
        assert_eq!(value("\"\"\"\n  a\nb\n\"\"\""), Some("  a\nb".to_owned()));
    }

    #[test]
    fn every_value_byte_maps_back_to_its_source_byte() {
        for src in [
            "x =\n    \"\"\"\n    ab\n      c\u{e9}d\n\n    \"\"\"\n",
            "x =\r\n    \"\"\"\r\n    ab\r\n\r\n      cd\r\n    \"\"\"\r\n",
            "x = \"\"\"one {{n}} line\"\"\"",
        ] {
            let judged = judge_first(src);
            assert!(judged.is_ok(), "{src:?} must judge: {judged:?}");
            let Ok(judged) = judged else { return };
            let value = judged.string.value();
            for (at, c) in value.char_indices() {
                let lo = judged.string.source_offset(at).unwrap_or(u32::MAX) as usize;
                let source = src.get(lo..).and_then(|s| s.chars().next());
                if c == '\n' {
                    assert!(
                        matches!(source, Some('\n' | '\r')),
                        "{src:?}: join {at} maps to {source:?}"
                    );
                } else {
                    assert_eq!(source, Some(c), "{src:?}: value byte {at}");
                }
            }
            assert!(judged.string.source_offset(value.len()).is_some());
            assert_eq!(
                judged.string.source_offset(value.len().saturating_add(1)),
                None
            );
        }
    }

    #[test]
    fn source_span_covers_the_value_slice() {
        let src = "x =\n    \"\"\"\n    say {{name}}\n    \"\"\"";
        let judged = judge_first(src);
        assert!(judged.is_ok(), "{judged:?}");
        let Ok(judged) = judged else { return };
        let value = judged.string.value();
        let at = value.find("name").unwrap_or_default();
        let span = judged.string.source_span(at..at.saturating_add(4));
        assert_eq!(span.map(|s| text(src, s)), Some("name"));
    }

    #[test]
    fn end_is_just_past_the_closer() {
        let src = "x = \"\"\"a\"\"\" ++ y";
        assert!(matches!(judge_first(src), Ok(Judged { end: 11, .. })));
    }

    #[test]
    fn extent_ends_at_the_first_closer() {
        let src = "x = \"\"\"a\"\"\"\"";
        assert_eq!(super::extent(src, 4), Some(4..11));
        assert_eq!(super::extent("\"\"\"\"\"", 0), None);
    }

    #[test]
    fn no_closer_is_unterminated_at_end_of_file() {
        let src = "x =\n    \"\"\"\n    a\n";
        assert_eq!(
            judge_first(src),
            Err(TripleRefusal::Unterminated { eof: 18 })
        );
    }

    #[test]
    fn text_after_a_block_opener_is_refused_at_that_text() {
        let src = "x =\n    \"\"\"Hello,\n    world\n    \"\"\"";
        let found = defect(src);
        assert!(
            matches!(found, Some(TripleStringDefect::TextAfterOpener { .. })),
            "{found:?}"
        );
        let Some(TripleStringDefect::TextAfterOpener { span, text: kind }) = found else {
            return;
        };
        assert_eq!(text(src, span), "Hello,");
        assert_eq!(kind, OpenerText::Content);
    }

    #[test]
    fn trailing_whitespace_after_the_opener_is_refused_as_whitespace() {
        let src = "x =\n    \"\"\"  \r\n    a\r\n    \"\"\"";
        let found = defect(src);
        assert!(
            matches!(found, Some(TripleStringDefect::TextAfterOpener { .. })),
            "{found:?}"
        );
        let Some(TripleStringDefect::TextAfterOpener { span, text: kind }) = found else {
            return;
        };
        assert_eq!(text(src, span), "  ");
        assert_eq!(kind, OpenerText::Whitespace);
    }

    #[test]
    fn closer_ending_a_content_line_is_refused_at_the_closer() {
        let src = "x =\n    \"\"\"\n    Hello\"\"\"\n";
        assert_eq!(
            defect(src),
            Some(TripleStringDefect::CloserEndsContentLine {
                span: Span::new(21, 24),
                margin: nz(5),
            })
        );
    }

    #[test]
    fn misaligned_closer_names_both_columns_and_the_opener() {
        let src = "x =\n    \"\"\"\n    a\n      \"\"\"";
        let found = defect(src);
        assert!(
            matches!(found, Some(TripleStringDefect::Misaligned { .. })),
            "{found:?}"
        );
        let Some(TripleStringDefect::Misaligned {
            span,
            opener,
            closer_col,
            margin,
        }) = found
        else {
            return;
        };
        assert_eq!(span, Span::new(24, 27));
        assert_eq!(opener, Span::new(8, 11));
        assert_eq!((closer_col, margin), (nz(7), nz(5)));
    }

    #[test]
    fn closer_left_of_the_margin_is_misaligned() {
        let src = "x =\n    \"\"\"\n    a\n  \"\"\"";
        assert!(matches!(
            defect(src),
            Some(TripleStringDefect::Misaligned { closer_col, .. }) if closer_col == nz(3)
        ));
    }

    #[test]
    fn tab_left_of_the_closer_is_refused_at_the_tab() {
        let src = "x =\n    \"\"\"\n    a\n \t  \"\"\"";
        assert_eq!(
            defect(src),
            Some(TripleStringDefect::TabInMargin {
                span: Span::new(19, 20),
                margin: nz(5),
            })
        );
    }

    #[test]
    fn line_left_of_the_margin_is_refused_through_its_first_character() {
        let src = "x =\n    \"\"\"\n    a\n  world\n    \"\"\"";
        let found = defect(src);
        assert!(
            matches!(found, Some(TripleStringDefect::LineUnderMargin { .. })),
            "{found:?}"
        );
        let Some(TripleStringDefect::LineUnderMargin { span, line, margin }) = found else {
            return;
        };
        assert_eq!(text(src, span), "  w");
        assert_eq!((line, margin), (nz(4), nz(5)));
    }

    #[test]
    fn tab_in_a_body_line_margin_is_refused_at_the_tab() {
        let src = "x =\n    \"\"\"\n  \t a\n    \"\"\"";
        let found = defect(src);
        assert!(
            matches!(found, Some(TripleStringDefect::TabInMargin { .. })),
            "{found:?}"
        );
        let Some(TripleStringDefect::TabInMargin { span, .. }) = found else {
            return;
        };
        assert_eq!(text(src, span), "\t");
    }

    #[test]
    fn tab_right_of_the_margin_is_content() {
        let src = "x =\n    \"\"\"\n    \ta\n    \"\"\"";
        assert_eq!(value(src), Some("\ta".to_owned()));
    }

    #[test]
    fn closer_defects_precede_body_defects() {
        let src = "x =\n    \"\"\"\n  a\n  \"\"\"";
        assert!(matches!(
            defect(src),
            Some(TripleStringDefect::Misaligned { .. })
        ));
    }

    #[test]
    fn first_body_defect_in_source_order_wins() {
        let src = "x =\n    \"\"\"\n  a\n\t\n    \"\"\"";
        assert!(matches!(
            defect(src),
            Some(TripleStringDefect::LineUnderMargin { line, .. }) if line == nz(3)
        ));
    }

    #[test]
    fn malformed_string_resumes_past_its_closer() {
        let src = "x =\n    \"\"\"\n  a\n    \"\"\" y";
        assert!(matches!(
            judge_first(src),
            Err(TripleRefusal::Malformed { end: 23, .. })
        ));
    }

    /// Each remedy a diagnostic names, applied to its refused source, judges.
    #[test]
    fn every_named_fix_yields_a_judged_string() {
        for (refused, fixed) in [
            (
                "x =\n    \"\"\"Hello,\n    world\n    \"\"\"",
                "x =\n    \"\"\"\n    Hello,\n    world\n    \"\"\"",
            ),
            (
                "x =\n    \"\"\"  \n    a\n    \"\"\"",
                "x =\n    \"\"\"\n    a\n    \"\"\"",
            ),
            (
                "x =\n    \"\"\"\n    Hello\"\"\"",
                "x =\n    \"\"\"\n    Hello\n    \"\"\"",
            ),
            (
                "x =\n    \"\"\"\n    a\n      \"\"\"",
                "x =\n    \"\"\"\n    a\n    \"\"\"",
            ),
            (
                "x =\n    \"\"\"\n    a\n  world\n    \"\"\"",
                "x =\n    \"\"\"\n    a\n    world\n    \"\"\"",
            ),
            (
                "x =\n    \"\"\"\n  \t a\n    \"\"\"",
                "x =\n    \"\"\"\n     a\n    \"\"\"",
            ),
        ] {
            assert!(defect(refused).is_some(), "{refused:?} must be refused");
            assert!(judge_first(fixed).is_ok(), "{fixed:?} must judge");
        }
    }

    #[test]
    fn lines_and_margin_expose_the_form() {
        let block = judge_first("x =\n  \"\"\"\n  a\n   b\n  \"\"\"");
        assert!(block.is_ok(), "{block:?}");
        let Ok(block) = block else { return };
        assert_eq!(block.string.margin().map(|c| c.get()), Some(nz(3)));
        assert_eq!(block.string.lines().collect::<Vec<_>>(), ["a", " b"]);
        let one = judge_first("x = \"\"\"a\"\"\"");
        assert!(one.is_ok(), "{one:?}");
        let Ok(one) = one else { return };
        assert_eq!(one.string.margin(), None);
        assert_eq!(one.string.lines().collect::<Vec<_>>(), ["a"]);
    }

    #[test]
    fn pieces_split_text_and_interpolation_bodies_by_value_range() {
        let value = "a {{ x }}b{{y}}";
        assert_eq!(
            interpolation_pieces(value),
            [
                Piece::Text {
                    text: "a ".to_owned(),
                    range: 0..2
                },
                Piece::Interp { range: 4..7 },
                Piece::Text {
                    text: "b".to_owned(),
                    range: 9..10
                },
                Piece::Interp { range: 12..13 },
            ]
        );
    }

    #[test]
    fn pieces_resolve_brace_and_backslash_escapes() {
        assert_eq!(
            interpolation_pieces(r"p \{{a}} \\ \n"),
            [Piece::Text {
                text: r"p {{a}} \ \n".to_owned(),
                range: 0..14
            }]
        );
    }

    #[test]
    fn unclosed_marker_is_text_through_the_end() {
        assert_eq!(
            interpolation_pieces("a{{b \\\\"),
            [
                Piece::Text {
                    text: "a".to_owned(),
                    range: 0..1
                },
                Piece::Text {
                    text: "{{b \\\\".to_owned(),
                    range: 1..7
                },
            ]
        );
    }

    #[test]
    fn interpolation_body_maps_to_its_source_name() {
        let src = "x =\n    \"\"\"\n    hi\n      {{ name }}\n    \"\"\"";
        let judged = judge_first(src);
        assert!(judged.is_ok(), "{judged:?}");
        let Ok(judged) = judged else { return };
        let value = judged.string.value();
        let body = interpolation_pieces(&value)
            .into_iter()
            .find_map(|piece| match piece {
                Piece::Interp { range } => Some(range),
                Piece::Text { .. } => None,
            });
        let span = body.and_then(|range| judged.string.source_span(range));
        assert_eq!(span.map(|s| text(src, s)), Some(" name "));
    }
}

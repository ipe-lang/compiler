//! The single source of truth for rendering text into emitted Rust source.
//!
//! Every non-constant text a compiler stage splices into emitted Rust goes
//! through one of four renderers here, each total over every scalar value:
//! [`rust_str_lit`] (a string literal), [`rust_char_lit`] (a char literal),
//! [`rust_fmt_str_lit`] (text inside a `format!` string literal) and
//! [`rust_comment_text`] (the body of a `//` line comment).
//! [`find_lexer_hazard`] is the output-side check: it finds any character the
//! Rust lexer refuses raw, so a site that bypassed the renderers fails `ipe`,
//! never `cargo`.

use core::fmt;

/// The `CompilerBug` site name of every refusal [`find_lexer_hazard`] drives.
pub const EMIT_LEXABLE: &str = "emit.lexable";

/// Render `s` as a Rust double-quoted string literal through Rust's own
/// `Debug` grammar for `str`.
///
/// `{s:?}` escapes every character the Rust string-literal grammar cannot
/// carry raw: `\`, `"`, a lone CR, and every non-printable scalar (controls,
/// format characters, bidi overrides) as `\u{..}`. A raw bidi override in an
/// emitted literal trips rustc's deny-by-default
/// `text_direction_codepoint_in_literal` lint and a raw lone CR is a lexer
/// error, so a hand-picked `\`/`"`-only escaper would let an `ipe`-accepted
/// program fail `cargo`. On printable ASCII, `Debug` escapes exactly `\` and
/// `"`.
#[must_use]
pub fn rust_str_lit(s: &str) -> String {
    format!("{s:?}")
}

/// Render `c` as a Rust single-quoted char literal through Rust's own `Debug`
/// grammar for `char`.
///
/// `{c:?}` escapes `'`, `\`, every control and every non-printable scalar
/// (bidi controls included), so the literal always lexes.
#[must_use]
pub fn rust_char_lit(c: char) -> String {
    format!("{c:?}")
}

/// Render `s` as a Rust `format!` string literal that prints `s` verbatim.
///
/// `{` and `}` are doubled to `{{`/`}}` BEFORE the `Debug` render: a brace in
/// `s` would otherwise open a format placeholder, and doubling AFTER the render
/// would corrupt the `\u{..}` escapes `Debug` writes for non-printable scalars.
#[must_use]
pub fn rust_fmt_str_lit(s: &str) -> String {
    let mut doubled = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '{' => doubled.push_str("{{"),
            '}' => doubled.push_str("}}"),
            other => doubled.push(other),
        }
    }
    rust_str_lit(&doubled)
}

/// Render `s` as text safe inside a Rust `//` line comment.
///
/// `escape_debug` turns a newline or CR (which would end the comment or fail
/// to lex), every bidi control (which trips rustc's deny-by-default
/// `text_direction_codepoint_in_comment`) and every non-printable scalar into
/// an escape. Printable ASCII other than `\`, `'` and `"` passes unchanged.
/// Line comments only: `*/` is not escaped.
#[must_use]
pub fn rust_comment_text(s: &str) -> String {
    s.escape_debug().to_string()
}

/// rustc's text-flow-control codepoints.
///
/// rustc refuses each raw in a literal (`text_direction_codepoint_in_literal`),
/// in a comment (`text_direction_codepoint_in_comment`) and as a lex error
/// anywhere else.
const TEXT_FLOW_CONTROLS: [char; 9] = [
    '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}',
    '\u{2069}',
];

/// Which raw character the Rust lexer refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LexerHazardKind {
    /// One of rustc's nine text-flow-control (bidi) codepoints.
    TextFlowControl,
    /// A carriage return not followed by a line feed.
    BareCarriageReturn,
}

/// A character the Rust lexer refuses raw, found by [`find_lexer_hazard`].
///
/// Built only by [`find_lexer_hazard`], so `codepoint` always belongs to
/// `kind`'s set. Its [`fmt::Display`] names the codepoint as `U+XXXX` and the
/// byte offset, never the raw character, so the hazard cannot reach a terminal
/// through the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LexerHazard {
    byte_offset: usize,
    codepoint: char,
    kind: LexerHazardKind,
}

impl LexerHazard {
    /// The byte offset of the hazard in the scanned text.
    #[must_use]
    pub const fn byte_offset(&self) -> usize {
        self.byte_offset
    }

    /// The refused codepoint.
    #[must_use]
    pub const fn codepoint(&self) -> char {
        self.codepoint
    }

    /// Which refused set the codepoint belongs to.
    #[must_use]
    pub const fn kind(&self) -> LexerHazardKind {
        self.kind
    }
}

impl fmt::Display for LexerHazard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            LexerHazardKind::TextFlowControl => "a text-direction control",
            LexerHazardKind::BareCarriageReturn => "a carriage return not followed by a line feed",
        };
        write!(
            f,
            "U+{:04X} ({what}) at byte {}",
            u32::from(self.codepoint),
            self.byte_offset
        )
    }
}

/// Find the first character in emitted Rust source the Rust lexer refuses raw.
///
/// The set is exactly rustc's: the nine text-flow-control codepoints
/// (`U+202A`..`U+202E`, `U+2066`..`U+2069`) and a bare CR (a CR not followed
/// by LF). Other format characters (`U+200E`, `U+FEFF`) and CRLF are accepted, as rustc
/// accepts them.
#[must_use]
pub fn find_lexer_hazard(text: &str) -> Option<LexerHazard> {
    let mut chars = text.char_indices().peekable();
    while let Some((byte_offset, c)) = chars.next() {
        let kind = if TEXT_FLOW_CONTROLS.contains(&c) {
            LexerHazardKind::TextFlowControl
        } else if c == '\r' && chars.peek().map(|&(_, next)| next) != Some('\n') {
            LexerHazardKind::BareCarriageReturn
        } else {
            continue;
        };
        return Some(LexerHazard {
            byte_offset,
            codepoint: c,
            kind,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        LexerHazardKind, TEXT_FLOW_CONTROLS, find_lexer_hazard, rust_char_lit, rust_comment_text,
        rust_fmt_str_lit, rust_str_lit,
    };

    /// Every scalar rustc refuses raw inside a string literal leaves escaped:
    /// the quote and backslash that would close or escape it, a lone CR, and
    /// all nine bidi controls.
    #[test]
    fn rust_str_lit_escapes_every_scalar_a_literal_cannot_carry_raw() {
        assert_eq!(rust_str_lit("a\u{202E}\"b\\"), r#""a\u{202e}\"b\\""#);
        assert_eq!(rust_str_lit("a\rb"), r#""a\rb""#);
        for bidi in TEXT_FLOW_CONTROLS {
            let lit = rust_str_lit(&format!("x{bidi}y"));
            assert!(
                !lit.contains(bidi),
                "{bidi:?} reached the literal raw: {lit}"
            );
            assert_eq!(find_lexer_hazard(&lit), None, "{lit}");
        }
        assert_eq!(rust_str_lit("plain ascii"), "\"plain ascii\"");
    }

    /// A char literal escapes the quote, the backslash, a CR and every bidi
    /// control.
    #[test]
    fn rust_char_lit_escapes_every_scalar_a_char_literal_cannot_carry_raw() {
        assert_eq!(rust_char_lit('\''), r"'\''");
        assert_eq!(rust_char_lit('\\'), r"'\\'");
        assert_eq!(rust_char_lit('\r'), r"'\r'");
        assert_eq!(rust_char_lit('a'), "'a'");
        for bidi in TEXT_FLOW_CONTROLS {
            let lit = rust_char_lit(bidi);
            assert!(!lit.contains(bidi), "{bidi:?} reached the literal raw");
            assert_eq!(find_lexer_hazard(&lit), None, "{lit}");
        }
    }

    /// Braces are doubled before the `Debug` render, so the `\u{..}` escape of
    /// a bidi control stays intact and a brace never opens a placeholder.
    #[test]
    fn rust_fmt_str_lit_doubles_braces_before_escaping() {
        assert_eq!(rust_fmt_str_lit("a{b}\u{202E}"), "\"a{{b}}\\u{202e}\"");
        assert_eq!(rust_fmt_str_lit("\"\\\r"), r#""\"\\\r""#);
        for bidi in TEXT_FLOW_CONTROLS {
            let lit = rust_fmt_str_lit(&format!("{{{bidi}}}"));
            assert!(!lit.contains(bidi), "{bidi:?} reached the literal raw");
            assert_eq!(find_lexer_hazard(&lit), None, "{lit}");
        }
    }

    /// Comment text cannot end the line comment or carry a bidi control or a
    /// bare CR raw.
    #[test]
    fn rust_comment_text_escapes_line_ends_and_bidi_controls() {
        assert_eq!(rust_comment_text("a\nb\rc"), r"a\nb\rc");
        assert_eq!(rust_comment_text("pkg/path-1.0"), "pkg/path-1.0");
        for bidi in TEXT_FLOW_CONTROLS {
            let text = rust_comment_text(&format!("x{bidi}y"));
            assert!(!text.contains(bidi), "{bidi:?} reached the comment raw");
            assert_eq!(find_lexer_hazard(&text), None, "{text}");
        }
    }

    /// Each of the ten hazards is found at its byte offset and reported as
    /// `U+XXXX`, never raw.
    #[test]
    fn find_lexer_hazard_finds_each_hazard_at_its_byte_offset() {
        for bidi in TEXT_FLOW_CONTROLS {
            let text = format!("é{bidi}z");
            let hazard = find_lexer_hazard(&text);
            assert!(hazard.is_some(), "{bidi:?} not found");
            let Some(hazard) = hazard else { return };
            assert_eq!(hazard.byte_offset(), 'é'.len_utf8());
            assert_eq!(hazard.codepoint(), bidi);
            assert_eq!(hazard.kind(), LexerHazardKind::TextFlowControl);
            let shown = hazard.to_string();
            assert!(
                shown.starts_with(&format!("U+{:04X} ", u32::from(bidi))),
                "{shown:?}"
            );
            assert!(shown.ends_with(" at byte 2"), "{shown:?}");
            assert!(!shown.contains(bidi), "{shown:?}");
        }
        for text in ["a\rb", "a\r", "a\r\r\n"] {
            let hazard = find_lexer_hazard(text);
            assert!(hazard.is_some(), "bare CR not found in {text:?}");
            let Some(hazard) = hazard else { return };
            assert_eq!(hazard.byte_offset(), 1, "{text:?}");
            assert_eq!(hazard.kind(), LexerHazardKind::BareCarriageReturn);
            assert!(hazard.to_string().starts_with("U+000D "), "{hazard}");
        }
    }

    /// One step past the set: CRLF, other format characters, non-ASCII letters
    /// and astral text are accepted, as rustc accepts them.
    #[test]
    fn find_lexer_hazard_accepts_text_rustc_accepts() {
        for text in [
            "a\r\nb",
            "\u{200E}",
            "\u{FEFF}",
            "é",
            "\u{1F600}",
            "\u{2029}\u{202F}\u{2065}\u{206A}",
            "",
        ] {
            assert_eq!(find_lexer_hazard(text), None, "{text:?}");
        }
    }
}

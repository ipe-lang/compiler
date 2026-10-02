//! The single source of truth for rendering text as a Rust string literal,
//! shared by every compiler stage that splices text into emitted Rust.

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

#[cfg(test)]
mod tests {
    use super::rust_str_lit;

    /// Every scalar rustc refuses raw inside a string literal leaves escaped:
    /// the quote and backslash that would close or escape it, a lone CR, and
    /// all nine bidi controls.
    #[test]
    fn rust_str_lit_escapes_every_scalar_a_literal_cannot_carry_raw() {
        assert_eq!(rust_str_lit("a\u{202E}\"b\\"), r#""a\u{202e}\"b\\""#);
        assert_eq!(rust_str_lit("a\rb"), r#""a\rb""#);
        for bidi in [
            '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}',
            '\u{2068}', '\u{2069}',
        ] {
            let lit = rust_str_lit(&format!("x{bidi}y"));
            assert!(
                !lit.contains(bidi),
                "{bidi:?} reached the literal raw: {lit}"
            );
        }
        assert_eq!(rust_str_lit("plain ascii"), "\"plain ascii\"");
    }
}

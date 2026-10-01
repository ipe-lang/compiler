//! Ipe.Char kernels — the std-only single-code-point helpers.
//!
//! A Ipê `Char` lowers to a Rust `char` (one Unicode scalar value), so these
//! kernels take/return `char` directly — no `any` boxing. Everything here
//! resolves through Rust std alone (ASCII ranges + `char::to_lowercase` /
//! `to_uppercase` / `from_u32`), so the module is always compiled.
//!
//! The `General_Category`-keyed predicates (`isAlpha` / `isDigit` / `isLower` /
//! `isUpper` / `isAlphaNum`) — the only `Ipe.Char` kernels that need the
//! `unicode-general-category` table — live in the feature-gated `char_category`
//! sibling. A program that reaches none of them drops that crate.
//!
//! * `toLower`/`toUpper` return a single-rune **String** (the kernel registry
//!   shape is `Char -> String`).
//! * `fromCode` out of the valid scalar range (negative, > 0x10FFFF, or a
//!   surrogate D800–DFFF that `char` cannot hold) yields the Unicode
//!   replacement character `'\u{FFFD}'`.

/// `isHexDigit` — an ASCII hexadecimal digit (`0-9`, `a-f`, `A-F`). Matches
/// Elm's code-point ranges exactly (ASCII only, never Unicode digits).
#[must_use]
pub fn char_is_hex_digit(c: char) -> bool {
    c.is_ascii_hexdigit()
}

/// `isOctDigit` — an ASCII octal digit (`0-7`). Matches Elm's code-point range
/// exactly (ASCII only).
#[must_use]
pub fn char_is_oct_digit(c: char) -> bool {
    ('0'..='7').contains(&c)
}

#[must_use]
pub fn char_to_lower(c: char) -> String {
    c.to_lowercase().to_string()
}
#[must_use]
pub fn char_to_upper(c: char) -> String {
    c.to_uppercase().to_string()
}

/// `toCode 'A' -> 65` — the Unicode code point as an integer.
#[must_use]
pub fn char_to_code(c: char) -> i64 {
    i64::from(c as u32)
}

/// `fromCode 65 -> 'A'`. Out-of-range / surrogate -> U+FFFD.
#[must_use]
pub fn char_from_code(n: i64) -> char {
    if !(0..=0x0010_FFFF).contains(&n) {
        return '\u{FFFD}';
    }
    char::from_u32(n as u32).unwrap_or('\u{FFFD}')
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn case_conversion_returns_string() {
        assert_eq!(char_to_lower('A'), "a");
        assert_eq!(char_to_upper('a'), "A");
    }

    #[test]
    fn code_roundtrip() {
        assert_eq!(char_to_code('A'), 65);
        assert_eq!(char_from_code(65), 'A');
        assert_eq!(char_from_code(0x1F600), '\u{1F600}'); // 😀
    }

    #[test]
    fn from_code_out_of_range_is_replacement() {
        assert_eq!(char_from_code(-1), '\u{FFFD}');
        assert_eq!(char_from_code(0x0011_0000), '\u{FFFD}');
        assert_eq!(char_from_code(0xD800), '\u{FFFD}'); // lone surrogate
    }

    #[test]
    fn hex_oct_match_elm() {
        // isHexDigit: 0-9 a-f A-F only (ASCII).
        assert!(char_is_hex_digit('0'));
        assert!(char_is_hex_digit('9'));
        assert!(char_is_hex_digit('a'));
        assert!(char_is_hex_digit('F'));
        assert!(!char_is_hex_digit('g'));
        assert!(!char_is_hex_digit('G'));

        // isOctDigit: 0-7 only.
        assert!(char_is_oct_digit('0'));
        assert!(char_is_oct_digit('7'));
        assert!(!char_is_oct_digit('8'));
        assert!(!char_is_oct_digit('9'));
        assert!(!char_is_oct_digit('a'));
    }
}

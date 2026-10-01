//! Ipe.Char predicates keyed off the Unicode `General_Category` — the half of
//! the `Ipe.Char` surface that needs the `unicode-general-category` table.
//!
//! A Ipê `Char` lowers to a Rust `char` (one Unicode scalar value), so these
//! predicates take `char` directly. Each keys off a precise `General_Category`
//! (GC), narrower than Rust std's `char` predicates, which fold in extra
//! categories and would diverge:
//!
//! | Ipê      | GC(s)                    | Rust std (rejected)                       |
//! |----------|--------------------------|-------------------------------------------|
//! | isDigit  | `Nd`                     | `is_numeric` = `Nd|Nl|No` (catches `'²'`) |
//! | isLower  | `Ll`                     | `is_lowercase` adds `Other_Lowercase`     |
//! | isUpper  | `Lu`                     | `is_uppercase` adds `Other_Uppercase`     |
//! | isAlpha  | `Lu|Ll|Lt|Lm|Lo` (`L*`)  | `is_alphabetic` adds `Nl|Other_Alphabetic`|
//!
//! Concretely: `'²'`/`'½'` → isDigit **false** (No, not Nd); `'ª'` → isLower
//! **false** (Lo, the feminine ordinal — `is_lowercase` wrongly counts its
//! `Other_Lowercase` property); `'é'` → isAlpha **true** (Ll ⊂ L*). The exact GC
//! comes from `unicode_general_category::get_general_category`.
//!
//! The std-only `Ipe.Char` kernels (`isHexDigit` / `isOctDigit` / `toLower` /
//! `toUpper` / `toCode` / `fromCode`) live in the always-compiled `char_kernel`
//! sibling and never reach this crate.

use unicode_general_category::{GeneralCategory, get_general_category};

/// `isDigit` = `General_Category` `Nd` (decimal digit) only.
#[must_use]
pub fn char_is_digit(c: char) -> bool {
    matches!(get_general_category(c), GeneralCategory::DecimalNumber)
}

/// `isLower` = `General_Category` `Ll` only.
#[must_use]
pub fn char_is_lower(c: char) -> bool {
    matches!(get_general_category(c), GeneralCategory::LowercaseLetter)
}

/// `isUpper` = `General_Category` `Lu` only.
#[must_use]
pub fn char_is_upper(c: char) -> bool {
    matches!(get_general_category(c), GeneralCategory::UppercaseLetter)
}

/// `isAlpha` = the letter categories `L*` (`Lu | Ll | Lt | Lm | Lo`).
#[must_use]
pub fn char_is_alpha(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::UppercaseLetter
            | GeneralCategory::LowercaseLetter
            | GeneralCategory::TitlecaseLetter
            | GeneralCategory::ModifierLetter
            | GeneralCategory::OtherLetter
    )
}

/// `isAlphaNum` — a letter or a digit. Mirrors Elm's
/// `isUpper || isLower || isDigit`, here expressed over the existing
/// category-based `isAlpha`/`isDigit` so Unicode letters/digits classify
/// consistently with the rest of this module.
#[must_use]
pub fn char_is_alpha_num(c: char) -> bool {
    char_is_alpha(c) || char_is_digit(c)
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn predicates() {
        assert!(char_is_alpha('A'));
        assert!(!char_is_alpha('1'));
        assert!(char_is_digit('7'));
        assert!(!char_is_digit('A'));
        assert!(char_is_lower('a'));
        assert!(!char_is_lower('A'));
        assert!(char_is_upper('Z'));
        assert!(!char_is_upper('z'));
    }

    /// Exact-General_Category classification — the cases where Rust std's broader
    /// predicates would diverge.
    #[test]
    fn predicates_match_general_categories() {
        // isDigit = Nd only.
        // U+00B2 SUPERSCRIPT TWO and U+00BD VULGAR FRACTION ONE HALF are
        // category No — rejected; Rust `is_numeric` would accept.
        assert!(!char_is_digit('\u{00B2}'));
        assert!(!char_is_digit('\u{00BD}'));
        // U+2167 SMALL ROMAN NUMERAL EIGHT is Nl, not Nd.
        assert!(!char_is_digit('\u{2167}'));
        // U+0664 ARABIC-INDIC DIGIT FOUR is Nd.
        assert!(char_is_digit('\u{0664}'));

        // isLower = Ll only.
        // U+00AA FEMININE ORDINAL INDICATOR is Lo with the Other_Lowercase
        // property — rejected; Rust `is_lowercase` would accept.
        assert!(!char_is_lower('\u{00AA}'));
        // U+00E9 LATIN SMALL LETTER E WITH ACUTE is Ll.
        assert!(char_is_lower('\u{00E9}'));

        // isUpper = Lu only.
        // U+2160 ROMAN NUMERAL ONE is Nl, not Lu.
        assert!(!char_is_upper('\u{2160}'));
        // U+00C9 LATIN CAPITAL LETTER E WITH ACUTE is Lu.
        assert!(char_is_upper('\u{00C9}'));

        // isAlpha = L* (Lu | Ll | Lt | Lm | Lo).
        // U+00E9 is Ll, U+01C5 (LATIN CAPITAL LETTER D WITH SMALL LETTER Z
        // WITH CARON) is Lt, U+30AB KATAKANA LETTER KA is Lo — all letters.
        assert!(char_is_alpha('\u{00E9}'));
        assert!(char_is_alpha('\u{01C5}'));
        assert!(char_is_alpha('\u{30AB}'));
        // U+00B2 SUPERSCRIPT TWO is No, not a letter.
        assert!(!char_is_alpha('\u{00B2}'));
    }

    #[test]
    fn alpha_num_matches_elm() {
        // isAlphaNum: letters + digits, not punctuation/space.
        assert!(char_is_alpha_num('a'));
        assert!(char_is_alpha_num('Z'));
        assert!(char_is_alpha_num('7'));
        assert!(!char_is_alpha_num('-'));
        assert!(!char_is_alpha_num(' '));
    }
}

//! `Ipe.Locale` — opaque BCP-47 locale handle + locale-aware case mapping.
//!
//! Default `String.toUpper`/`toLower`/`casefold` remain locale-independent
//! (Rust std `to_uppercase`/`to_lowercase`).  This module adds an explicit-
//! locale surface so callers that need correct case conversion for a specific
//! language (the motivating example: Turkish dotted/dotless `i`) can opt in.
//!
//! Construction: `Locale.fromTag : String -> Maybe Locale`.  An invalid BCP-47
//! tag is a typed absence (`Nothing`), never a silent fallback to an arbitrary
//! locale.  The validated tag is stored verbatim inside the opaque wrapper;
//! `Locale.toTag : Locale -> String` recovers it.
//!
//! The ICU4X `CaseMapper` uses compiled data bundled at link time (no separate
//! data-provider call required).  This module is gated behind the `locale`
//! feature so programs that never import `Ipe.Locale` pay no compile-time or
//! link-time cost.

#[cfg(feature = "locale")]
use icu_casemap::CaseMapper;
#[cfg(feature = "locale")]
use icu_locale_core::Locale as IcuLocale;

use crate::IpeMaybe;

/// Opaque, parse-validated BCP-47 locale handle.
///
/// The ONLY constructor is [`locale_from_tag`] (`Locale.fromTag`), which
/// returns `Nothing` for any string that is not a structurally valid BCP-47
/// language tag.  A bare `String` can never silently coerce to `Locale` —
/// passing an invalid tag where a `Locale` is expected is an Ipê type error,
/// not a silent default-locale substitution.
///
/// `Clone + PartialEq`: locales are compared (e.g. in locale-keyed caches).
/// `Debug`: the BCP-47 tag string is not a secret — safe to print.
#[derive(Clone, PartialEq, Debug)]
pub struct Locale(String);

impl std::fmt::Display for Locale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl crate::stringify::IpeStringify for Locale {
    fn ipe_show(&self) -> String {
        self.0.clone()
    }
}

/// `Locale.fromTag : String -> Maybe Locale` — the single parse boundary.
///
/// Returns `Nothing` when the string is not a structurally valid BCP-47
/// language tag.  The ICU4X parser is used when the `locale` feature is
/// enabled; the unconditionally-compiled stub (features off) always returns
/// `Nothing` so the type is sound even in a non-locale build.
#[must_use]
pub fn locale_from_tag(tag: String) -> IpeMaybe<Locale> {
    #[cfg(feature = "locale")]
    {
        if tag.parse::<IcuLocale>().is_ok() {
            return IpeMaybe::Just(Locale(tag));
        }
        IpeMaybe::Nothing
    }
    #[cfg(not(feature = "locale"))]
    {
        // Without the locale feature the parse is a stub that always fails
        // closed.  The ONLY way to reach this is via `--features` without
        // `locale` AND with `Ipe.Locale` imported — which the kernel
        // capability gate prevents at compile time.  The stub is here so
        // the type resolves in a default-features build of the runtime
        // crate itself (e.g. `cargo check`).
        let _ = tag;
        IpeMaybe::Nothing
    }
}

/// `Locale.toTag : Locale -> String` — recover the BCP-47 tag string.
#[must_use]
pub fn locale_to_tag(locale: Locale) -> String {
    locale.0
}

/// `String.toUpperIn : Locale -> String -> String` — locale-correct upper-case.
///
/// For most locales this matches `String.toUpper`.  The motivating divergence is
/// Turkish/Azerbaijani: `toUpperIn (Locale.fromTag "tr") "i"` → `"İ"` (capital
/// dotted I, U+0130), whereas `toUpper "i"` → `"I"` (Latin capital I, U+0049).
#[must_use]
pub fn string_to_upper_in(locale: Locale, s: String) -> String {
    #[cfg(feature = "locale")]
    {
        if let Ok(icu_locale) = locale.0.parse::<IcuLocale>() {
            let mapper = CaseMapper::new();
            return mapper.uppercase_to_string(&s, &icu_locale.id).into_owned();
        }
        // Parsed locale is guaranteed valid by construction — this branch is
        // unreachable on well-typed input.  Fall through to the stdlib default
        // rather than panicking (belt-and-braces).
        s.to_uppercase()
    }
    #[cfg(not(feature = "locale"))]
    {
        let _ = locale;
        s.to_uppercase()
    }
}

/// `String.toLowerIn : Locale -> String -> String` — locale-correct lower-case.
///
/// The motivating divergence is Turkish/Azerbaijani: `toLowerIn (Locale.fromTag
/// "tr") "I"` → `"ı"` (dotless i, U+0131), whereas `toLower "I"` → `"i"`.
#[must_use]
pub fn string_to_lower_in(locale: Locale, s: String) -> String {
    #[cfg(feature = "locale")]
    {
        if let Ok(icu_locale) = locale.0.parse::<IcuLocale>() {
            let mapper = CaseMapper::new();
            return mapper.lowercase_to_string(&s, &icu_locale.id).into_owned();
        }
        // Same belt-and-braces fallback as `string_to_upper_in`.
        s.to_lowercase()
    }
    #[cfg(not(feature = "locale"))]
    {
        let _ = locale;
        s.to_lowercase()
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    // ── Locale.fromTag parse boundary ────────────────────────────────────────

    #[cfg(feature = "locale")]
    #[test]
    fn locale_from_valid_tag_is_just() {
        assert!(matches!(
            locale_from_tag("en".to_owned()),
            IpeMaybe::Just(_)
        ));
        assert!(matches!(
            locale_from_tag("tr".to_owned()),
            IpeMaybe::Just(_)
        ));
        assert!(matches!(
            locale_from_tag("en-US".to_owned()),
            IpeMaybe::Just(_)
        ));
        assert!(matches!(
            locale_from_tag("zh-Hant-TW".to_owned()),
            IpeMaybe::Just(_)
        ));
    }

    #[test]
    fn locale_from_invalid_tag_is_nothing() {
        // Empty string and clearly invalid tags are typed absence.
        assert!(matches!(locale_from_tag("".to_owned()), IpeMaybe::Nothing));
        assert!(matches!(
            locale_from_tag("not a tag".to_owned()),
            IpeMaybe::Nothing
        ));
        assert!(matches!(
            locale_from_tag("!!!".to_owned()),
            IpeMaybe::Nothing
        ));
    }

    #[cfg(feature = "locale")]
    #[test]
    fn locale_round_trip() {
        if let IpeMaybe::Just(loc) = locale_from_tag("en-US".to_owned()) {
            assert_eq!(locale_to_tag(loc), "en-US");
        } else {
            panic!("en-US should parse as a valid BCP-47 tag");
        }
    }

    // ── Turkish-i locale-correctness (the motivating test) ───────────────────

    #[cfg(feature = "locale")]
    #[test]
    fn to_upper_in_turkish_dotted_i() {
        // Turkish/Azerbaijani: lowercase dotted i → capital dotted I (U+0130).
        // This is the canonical locale-correctness check that differs from the
        // default ASCII-heritage `toUpper "i"` → "I".
        let tr = match locale_from_tag("tr".to_owned()) {
            IpeMaybe::Just(l) => l,
            IpeMaybe::Nothing => panic!("\"tr\" must parse as a valid BCP-47 tag"),
        };
        let result = string_to_upper_in(tr, "i".to_owned());
        assert_eq!(
            result, "İ",
            "Turkish uppercase of 'i' must be 'İ' (U+0130), got {result:?}"
        );
        // Verify it differs from the locale-independent default.
        assert_ne!(
            result, "I",
            "Turkish toUpperIn must differ from stdlib toUpper"
        );
    }

    #[cfg(feature = "locale")]
    #[test]
    fn to_lower_in_turkish_dotless_i() {
        // Turkish/Azerbaijani: capital I → dotless i (U+0131).
        let tr = match locale_from_tag("tr".to_owned()) {
            IpeMaybe::Just(l) => l,
            IpeMaybe::Nothing => panic!("\"tr\" must parse as a valid BCP-47 tag"),
        };
        let result = string_to_lower_in(tr, "I".to_owned());
        assert_eq!(
            result, "ı",
            "Turkish lowercase of 'I' must be 'ı' (U+0131), got {result:?}"
        );
        assert_ne!(
            result, "i",
            "Turkish toLowerIn must differ from stdlib toLower"
        );
    }

    #[cfg(feature = "locale")]
    #[test]
    fn to_upper_in_english_matches_stdlib() {
        // For plain Latin / English, locale-aware and locale-independent results
        // must agree so we haven't broken the common case.
        let en = match locale_from_tag("en".to_owned()) {
            IpeMaybe::Just(l) => l,
            IpeMaybe::Nothing => panic!("\"en\" must parse as a valid BCP-47 tag"),
        };
        assert_eq!(
            string_to_upper_in(en, "hello".to_owned()),
            "hello".to_uppercase()
        );
    }

    #[cfg(feature = "locale")]
    #[test]
    fn to_lower_in_english_matches_stdlib() {
        let en = match locale_from_tag("en".to_owned()) {
            IpeMaybe::Just(l) => l,
            IpeMaybe::Nothing => panic!("\"en\" must parse as a valid BCP-47 tag"),
        };
        assert_eq!(
            string_to_lower_in(en, "HELLO".to_owned()),
            "HELLO".to_lowercase()
        );
    }
}

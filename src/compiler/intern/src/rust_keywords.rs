//! The single source of truth for Rust keyword identifiers, shared by every
//! compiler stage that must refuse, mangle, or escape an emitted name that
//! collides with one.

/// Every identifier that cannot be written bare in edition-2024 Rust.
///
/// Exactly the strict keywords plus the reserved keywords of edition 2024.
/// Weak keywords (`union`, `macro_rules`, `raw`, `safe`, `'static`) are legal
/// identifiers and are deliberately absent: refusing or renaming them would
/// reject valid Rust paths and silently change serde wire keys.
///
/// `self` / `Self` / `crate` / `super` are included: they are strict keywords
/// too, even though they additionally cannot be written as raw identifiers
/// (`r#self` etc. are themselves rejected by the Rust grammar) — a caller that
/// needs the raw-identifier escape handles those four separately.
#[rustfmt::skip]
pub const RUST_KEYWORDS: &[&str] = &[
    // Strict keywords (2015 edition).
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for",
    "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where",
    "while",
    // Strict keywords added in the 2018 edition.
    "async", "await", "dyn",
    // Reserved for future use.
    "abstract", "become", "box", "do", "final", "macro", "override", "priv", "try", "typeof",
    "unsized", "virtual", "yield",
    // Reserved in the 2024 edition.
    "gen",
];

/// Whether `s` is a Rust keyword identifier — see [`RUST_KEYWORDS`].
#[must_use]
pub fn is_rust_keyword(s: &str) -> bool {
    RUST_KEYWORDS.contains(&s)
}

#[cfg(test)]
mod tests {
    use super::{RUST_KEYWORDS, is_rust_keyword};

    #[test]
    fn every_listed_keyword_is_recognized() {
        for kw in RUST_KEYWORDS {
            assert!(is_rust_keyword(kw), "{kw} should be recognized");
        }
    }

    #[test]
    fn ordinary_identifiers_are_not_keywords() {
        for name in ["value", "match_", "r#match", "union_", "genesis"] {
            assert!(!is_rust_keyword(name), "{name} should not be recognized");
        }
    }

    #[test]
    fn weak_keywords_are_not_keywords() {
        for name in ["union", "macro_rules", "raw", "safe", "static_"] {
            assert!(
                !is_rust_keyword(name),
                "{name} is a legal identifier and must not be recognized"
            );
        }
    }

    #[test]
    fn no_duplicate_entries() {
        let mut sorted = RUST_KEYWORDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            RUST_KEYWORDS.len(),
            "RUST_KEYWORDS has a duplicate entry"
        );
    }
}

//! Compile-time validation for a literal path in source (IPE-P0063).
//!
//! The algorithm is NOT defined here — it lives once in the dependency-free
//! `ipe_path_core` crate, which the runtime `Path.fromString` seal
//! (`ipe_runtime::path`) also consumes. This module re-exports that single
//! source of truth, so the compile-time gate and the runtime seal can never
//! drift.
//!
//! [`PathLitText::seal`] is the all-targets compile-time gate: the compiler does
//! not know the final target OS, so it seals a literal under EVERY separator
//! regime and refuses it when any regime refuses. An accepted literal carries
//! each regime's sealed form.

pub use ipe_path_core::{LiteralRefusal, PathLitText, Regime, SealRefusal, seal};

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(raw: &str) -> Option<LiteralRefusal> {
        PathLitText::seal(raw).err()
    }

    fn escape(regime: Regime, cleaned: &str) -> LiteralRefusal {
        LiteralRefusal {
            regime,
            why: SealRefusal::Escape {
                cleaned: cleaned.to_string(),
            },
        }
    }

    fn windows(why: SealRefusal) -> LiteralRefusal {
        LiteralRefusal {
            regime: Regime::Windows,
            why,
        }
    }

    // ── accepted paths carry each regime's sealed form ───────────────────────

    #[test]
    fn plain_relative_accepted_in_each_regime_form() {
        let lit = PathLitText::seal("src/Main.ipe");
        assert_eq!(
            lit.as_ref().map(|l| l.sealed(Regime::Unix)),
            Ok("src/Main.ipe")
        );
        assert_eq!(
            lit.as_ref().map(|l| l.sealed(Regime::Windows)),
            Ok("src\\Main.ipe")
        );
        assert_eq!(lit.as_ref().map(PathLitText::raw), Ok("src/Main.ipe"));
    }

    #[test]
    fn interior_dotdot_that_stays_in_bounds_accepted() {
        let lit = PathLitText::seal("a/b/../c");
        assert_eq!(lit.as_ref().map(|l| l.sealed(Regime::Unix)), Ok("a/c"));
        assert_eq!(lit.as_ref().map(|l| l.sealed(Regime::Windows)), Ok("a\\c"));
    }

    #[test]
    fn rooted_dotdot_cannot_escape_accepted() {
        let lit = PathLitText::seal("/a/../../b");
        assert_eq!(lit.as_ref().map(|l| l.sealed(Regime::Unix)), Ok("/b"));
    }

    #[test]
    fn empty_cleans_to_dot() {
        let lit = PathLitText::seal("");
        assert_eq!(lit.as_ref().map(|l| l.sealed(Regime::Unix)), Ok("."));
        assert_eq!(lit.as_ref().map(|l| l.sealed(Regime::Windows)), Ok("."));
    }

    #[test]
    fn each_form_is_that_regimes_seal() {
        for raw in ["src/Main.ipe", "a//b/./c/", "/abs/x", "C:\\x\\y", "a\\b"] {
            let lit = PathLitText::seal(raw);
            assert!(lit.is_ok(), "{raw:?} must be accepted");
            let Ok(lit) = lit else {
                return;
            };
            for regime in [Regime::Unix, Regime::Windows] {
                assert_eq!(seal(raw, regime).as_deref(), Ok(lit.sealed(regime)));
            }
        }
    }

    // ── refused under the Unix regime ────────────────────────────────────────

    #[test]
    fn nul_byte_rejected() {
        assert_eq!(
            refusal("safe\0bad"),
            Some(LiteralRefusal {
                regime: Regime::Unix,
                why: SealRefusal::Nul
            })
        );
    }

    #[test]
    fn leading_dotdot_rejected() {
        assert_eq!(
            refusal("../secret"),
            Some(escape(Regime::Unix, "../secret"))
        );
    }

    #[test]
    fn bare_dotdot_rejected() {
        assert_eq!(refusal(".."), Some(escape(Regime::Unix, "..")));
    }

    #[test]
    fn dotdot_that_resolves_to_escape_rejected() {
        assert_eq!(refusal("a/../../etc"), Some(escape(Regime::Unix, "../etc")));
    }

    // ── refused only under the Windows regime — the all-targets guarantee ────
    //    Each is a Unix-clean no-op (`\` is a plain byte on Unix) yet a
    //    traversal on Windows; the gate refuses it and names the Windows regime.

    #[test]
    fn win_backslash_traversal_rejected() {
        assert_eq!(
            refusal("..\\secret"),
            Some(escape(Regime::Windows, "..\\secret"))
        );
    }

    #[test]
    fn win_drive_relative_dotdot_rejected() {
        assert!(refusal("C:..\\x").is_some_and(|r| r.regime == Regime::Windows));
    }

    #[test]
    fn win_trailing_dot_space_disguise_rejected() {
        assert_eq!(
            refusal(".. \\x"),
            Some(windows(SealRefusal::DisguisedParent))
        );
    }

    #[test]
    fn win_triple_dot_disguise_rejected() {
        assert_eq!(
            refusal("a/..."),
            Some(windows(SealRefusal::DisguisedParent))
        );
    }

    // A leading all-dots element is refused under Unix first: the escape
    // check's glued-dot layer fails closed before Windows is tried.
    #[test]
    fn leading_triple_dot_rejected_under_unix_first() {
        assert_eq!(refusal("..."), Some(escape(Regime::Unix, "...")));
    }

    #[test]
    fn win_mixed_separator_traversal_rejected() {
        assert!(refusal("a\\..\\..\\b").is_some_and(|r| r.regime == Regime::Windows));
    }
}

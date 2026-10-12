//! Numeric literal spelling, the single source for every emitted Int/Float leaf.
//!
//! Every function here renders one Rust PRIMARY expression, so no surrounding
//! operator or method-receiver position can rebind a leading minus (e.g.
//! `-5i64.ipe_wrapping_add(r)` would parse as `-(5i64.ipe_wrapping_add(r))`,
//! the wrong value). `int_pattern` is the one exception: a match-pattern
//! position is never a receiver, so it stays unsuffixed and unparenthesised.

/// Render an `i64` as a Rust expression literal, parenthesised when negative.
///
/// `(-5i64)` rather than `-5i64`, so the leaf stays a primary expression in
/// every surrounding position (operator operand, method receiver). This also
/// covers `i64::MIN`: rustc's `overflowing_literals` lint only accepts a
/// negated literal against `i64::MIN`, never a bare suffixed one.
pub fn int_literal(n: i64) -> String {
    if n >= 0 {
        format!("{n}i64")
    } else {
        format!("({n}i64)")
    }
}

/// Render an `i64` as an unsuffixed Rust pattern literal.
///
/// A literal pattern is never a receiver, so it needs no parentheses; its
/// type comes from the `i64` scrutinee, and suffixing would churn every
/// golden with an Int pattern for no soundness gain.
pub fn int_pattern(n: i64) -> String {
    n.to_string()
}

/// Render an `f64` as a Rust literal that is guaranteed to TYPE as `f64`.
///
/// Rust's default `f64` Display drops the decimal point for a whole number
/// (`3.0` prints as `3`), and a bare `3` types as an integer — so a whole-
/// number float literal must keep (or regain) a decimal point. The shortest
/// round-trip Display is used (so the emitted literal parses back to the
/// same bit pattern), and `.0` is appended only when the rendering carries no
/// `.`/`e` exponent marker. A negative finite value is parenthesised for the
/// same primary-expression reason as [`int_literal`]. A non-finite value (an
/// over-range lexeme reads back as `inf`) has no decimal literal, so it
/// renders through the `f64` associated constants — already a primary
/// expression, so it needs no parentheses — keeping the emission total and
/// valid Rust.
pub fn float_literal(f: f64) -> String {
    if f.is_nan() {
        return "f64::NAN".to_owned();
    }
    if f.is_infinite() {
        return if f < 0.0 {
            "f64::NEG_INFINITY"
        } else {
            "f64::INFINITY"
        }
        .to_owned();
    }
    let s = format!("{f}");
    let lit = if s.bytes().any(|b| b == b'.' || b == b'e' || b == b'E') {
        s
    } else {
        format!("{s}.0")
    };
    if f.is_sign_negative() {
        format!("({lit})")
    } else {
        lit
    }
}

#[cfg(test)]
mod tests {
    use super::{float_literal, int_literal, int_pattern};

    #[test]
    fn int_literal_min_is_parenthesised() {
        assert_eq!(int_literal(i64::MIN), "(-9223372036854775808i64)");
    }

    #[test]
    fn int_literal_negative_is_parenthesised() {
        assert_eq!(int_literal(-1), "(-1i64)");
    }

    #[test]
    fn int_literal_zero_is_unparenthesised() {
        assert_eq!(int_literal(0), "0i64");
    }

    #[test]
    fn int_literal_max_is_unparenthesised() {
        assert_eq!(int_literal(i64::MAX), "9223372036854775807i64");
    }

    #[test]
    fn int_pattern_min_is_unsuffixed() {
        assert_eq!(int_pattern(i64::MIN), "-9223372036854775808");
    }

    #[test]
    fn float_literal_negative_is_parenthesised() {
        assert_eq!(float_literal(-1.5), "(-1.5)");
    }

    #[test]
    fn float_literal_negative_zero_is_parenthesised() {
        assert_eq!(float_literal(-0.0), "(-0.0)");
    }

    #[test]
    fn float_literal_neg_infinity_is_a_bare_path() {
        assert_eq!(float_literal(f64::NEG_INFINITY), "f64::NEG_INFINITY");
    }
}

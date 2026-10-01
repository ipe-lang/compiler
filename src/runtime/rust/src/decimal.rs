//! `Ipe.Decimal` kernels — arbitrary-precision decimal arithmetic backed by
//! `rust_decimal::Decimal` (96-bit mantissa + scale).

use super::IpeResult;
use rust_decimal::{Decimal as RD, prelude::FromPrimitive};

/// Opaque Ipê `Decimal` — newtype around `rust_decimal::Decimal`. The serde
/// derives are gated on the `serde` feature; `serde` in turn weakly enables
/// `rust_decimal/serde` (`rust_decimal?/serde`) so the inner `RD` gains its serde
/// impls only when both `decimal` and `serde` are selected, so this type carries
/// no serde impls when the `serde` feature is off. (The `rust_decimal` crate's
/// own default features still link `serde`; dropping that crate for a
/// decimal-only program needs `default-features = false` — a separate dep-shrink.)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Decimal(pub RD);

use rust_decimal::RoundingStrategy;
use rust_decimal::prelude::ToPrimitive;
use std::str::FromStr;

// Constructors

#[must_use]
pub fn decimal_from_string<E: From<String>>(s: String) -> IpeResult<E, Decimal> {
    match RD::from_str(&s) {
        Ok(d) => IpeResult::Ok(Decimal(d)),
        Err(e) => IpeResult::Err(format!("Ipe.Decimal: parse: {e}").into()),
    }
}
#[must_use]
pub fn decimal_from_int(n: i64) -> Decimal {
    Decimal(RD::from(n))
}
#[must_use]
pub fn decimal_from_float(f: f64) -> Decimal {
    Decimal(RD::from_f64(f).unwrap_or(RD::ZERO))
}
// Ipe.Decimal.fromMinor places minor  (e.g. fromMinor 2 12345 -> 123.45).
// Arg order is (places, minor): places is the scale, minor is the integer
// value in minor units. Mantissa = minor, scale = places.
#[must_use]
pub fn decimal_from_minor(places: i64, minor: i64) -> Decimal {
    // rust_decimal's MAX_SCALE is 28; `RD::new` PANICS above it. Clamp the
    // user-supplied scale and use the checked constructor so a well-typed Ipê
    // call (`Ipe.Decimal.fromMinor 30 1`) can never abort.
    // Clamp on i64 FIRST, then narrow: `as u32` on an i64 >= 2^32 truncates
    // (wraps) BEFORE any u32-domain `.min`, so a huge scale could alias to a
    // small wrong value. Clamping in i64 makes the narrowing monotonic.
    let scale = places.clamp(0, i64::from(RD::MAX_SCALE)) as u32;
    Decimal(RD::try_new(minor, scale).unwrap_or(RD::ZERO))
}
#[must_use]
pub fn decimal_zero() -> Decimal {
    Decimal(RD::ZERO)
}
#[must_use]
pub fn decimal_one() -> Decimal {
    Decimal(RD::ONE)
}
#[must_use]
pub fn decimal_one_hundred() -> Decimal {
    Decimal(RD::from(100))
}

// Conversions

#[must_use]
pub fn decimal_to_string(d: Decimal) -> String {
    d.0.normalize().to_string()
}
#[must_use]
pub fn decimal_to_string_fixed(places: i64, d: Decimal) -> String {
    // Clamp to MAX_SCALE: digits beyond the decimal's max scale are all zeros,
    // so a huge `places` (e.g. 1e9) would only force a multi-GB allocation for
    // trailing zeros. Cap the format width to keep the kernel bounded.
    let p = places.clamp(0, i64::from(RD::MAX_SCALE)) as u32;
    // Use half-away-from-zero rounding (not banker's rounding) so tie values
    // (e.g. "2.545" at 2 dp → "2.55") behave as expected by callers.
    let r =
        d.0.round_dp_with_strategy(p, RoundingStrategy::MidpointAwayFromZero);
    format!("{:.*}", p as usize, r)
}
#[must_use]
pub fn decimal_to_float(d: Decimal) -> f64 {
    d.0.to_f64().unwrap_or(0.0)
}
#[must_use]
pub fn decimal_to_int(d: Decimal) -> i64 {
    // Saturate at the i64 boundary on out-of-range: `to_i64` returns None for a
    // magnitude beyond ±i64, so `unwrap_or(0)` would map a huge value to 0.
    d.0.trunc().to_i64().unwrap_or(if d.0.is_sign_negative() {
        i64::MIN
    } else {
        i64::MAX
    })
}
#[must_use]
pub fn decimal_to_minor(scale: i64, d: Decimal) -> i64 {
    // Clamp on i64 FIRST, then narrow (see decimal_from_minor): a bare
    // `as u32` truncates an i64 >= 2^32 before any clamp.
    let p = scale.clamp(0, i64::from(RD::MAX_SCALE)) as u32;
    // `10_i64.pow(19)` overflows i64 → panic (debug) / wrap (release). Use
    // checked_pow with a saturating fallback so the kernel stays total.
    let factor = 10_i64.checked_pow(p).unwrap_or(i64::MAX);
    // checked_mul: saturate to MAX/MIN (overflow not possible in practice for
    // normal monetary values, but guards the extreme edge without panicking).
    let sat = if d.0.is_sign_negative() {
        RD::MIN
    } else {
        RD::MAX
    };
    let scaled = d.0.checked_mul(RD::from(factor)).unwrap_or(sat);
    // `scaled` may be RD::MAX/MIN (mul-overflow) or otherwise exceed ±i64, both
    // of which make `to_i64` return None — saturate to the signed i64 extreme
    // matching the value's sign rather than collapsing to 0.
    scaled
        .trunc()
        .to_i64()
        .unwrap_or(if scaled.is_sign_negative() {
            i64::MIN
        } else {
            i64::MAX
        })
}

// Arithmetic

// Saturating arithmetic: rust_decimal's std ops panic on 96-bit mantissa
// On overflow we saturate toward the mathematically correct signed extreme
// rather than panicking — only observable at values near ±7.9e28.
#[must_use]
pub fn decimal_add(a: Decimal, b: Decimal) -> Decimal {
    Decimal(a.0.checked_add(b.0).unwrap_or_else(|| {
        if a.0.is_sign_negative() && b.0.is_sign_negative() {
            RD::MIN
        } else {
            RD::MAX
        }
    }))
}
#[must_use]
pub fn decimal_sub(a: Decimal, b: Decimal) -> Decimal {
    Decimal(a.0.checked_sub(b.0).unwrap_or_else(|| {
        // a - b overflows positive when a is very large positive and b very negative
        if b.0.is_sign_negative() {
            RD::MAX
        } else {
            RD::MIN
        }
    }))
}
#[must_use]
pub fn decimal_mul(a: Decimal, b: Decimal) -> Decimal {
    Decimal(a.0.checked_mul(b.0).unwrap_or_else(|| {
        // result sign = sign(a) XOR sign(b)
        if a.0.is_sign_negative() == b.0.is_sign_negative() {
            RD::MAX
        } else {
            RD::MIN
        }
    }))
}
#[must_use]
pub fn decimal_div<E: From<String>>(a: Decimal, b: Decimal) -> IpeResult<E, Decimal> {
    if b.0.is_zero() {
        return IpeResult::Err("Ipe.Decimal: divide by zero".to_string().into());
    }
    // checked_div, NOT the bare `/`: rust_decimal's `Div` panics ("Division
    // overflowed") on 96-bit mantissa overflow during scale-alignment — a panic
    // reachable from a well-typed `Ipe.Decimal.div`. Post zero-guard, `None` is
    // overflow → saturate to the signed extreme (sign = sign(a) XOR sign(b)),
    // matching decimal_add/sub/mul.
    let quotient = a.0.checked_div(b.0).unwrap_or_else(|| {
        if a.0.is_sign_negative() == b.0.is_sign_negative() {
            RD::MAX
        } else {
            RD::MIN
        }
    });
    // Cap the quotient to 16 decimal places with half-away-from-zero rounding.
    // Exact fractions with ≤16 dp are unaffected; non-terminating quotients
    // (1/3, 2/3, 1/7, …) round at 16 dp.
    IpeResult::Ok(Decimal(
        quotient.round_dp_with_strategy(16, RoundingStrategy::MidpointAwayFromZero),
    ))
}
#[must_use]
pub fn decimal_mod<E: From<String>>(a: Decimal, b: Decimal) -> IpeResult<E, Decimal> {
    if b.0.is_zero() {
        return IpeResult::Err("Ipe.Decimal: mod by zero".to_string().into());
    }
    // checked_rem, NOT the bare `%`: rust_decimal's `Rem` also panics on overflow.
    // Post zero-guard, `None` is overflow → 0 (a sound saturating remainder).
    IpeResult::Ok(Decimal(a.0.checked_rem(b.0).unwrap_or(RD::ZERO)))
}
#[must_use]
pub fn decimal_neg(d: Decimal) -> Decimal {
    Decimal(-d.0)
}
#[must_use]
pub fn decimal_abs(d: Decimal) -> Decimal {
    Decimal(d.0.abs())
}

// Rounding / truncation

#[must_use]
pub fn decimal_round(places: i64, d: Decimal) -> Decimal {
    // Clamp on i64 first, then narrow: a bare `as u32` truncates an i64 >= 2^32
    // to a small wrong value. round_dp beyond MAX_SCALE is a no-op anyway.
    let p = places.clamp(0, i64::from(RD::MAX_SCALE)) as u32;
    Decimal(d.0.round_dp_with_strategy(p, RoundingStrategy::MidpointNearestEven))
}
#[must_use]
pub fn decimal_round_half_up(places: i64, d: Decimal) -> Decimal {
    let p = places.clamp(0, i64::from(RD::MAX_SCALE)) as u32;
    Decimal(d.0.round_dp_with_strategy(p, RoundingStrategy::MidpointAwayFromZero))
}
#[must_use]
pub fn decimal_truncate(places: i64, d: Decimal) -> Decimal {
    let p = places.clamp(0, i64::from(RD::MAX_SCALE)) as u32;
    Decimal(d.0.round_dp_with_strategy(p, RoundingStrategy::ToZero))
}
#[must_use]
pub fn decimal_floor(d: Decimal) -> Decimal {
    Decimal(d.0.floor())
}
#[must_use]
pub fn decimal_ceil(d: Decimal) -> Decimal {
    Decimal(d.0.ceil())
}

// Comparison

#[must_use]
pub fn decimal_compare(a: Decimal, b: Decimal) -> i64 {
    use std::cmp::Ordering;
    match a.0.cmp(&b.0) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

// Ipe.Decimal completion (15 kernels)

// === Bool comparisons ===
#[must_use]
pub fn decimal_eq(a: Decimal, b: Decimal) -> bool {
    a.0 == b.0
}
#[must_use]
pub fn decimal_neq(a: Decimal, b: Decimal) -> bool {
    a.0 != b.0
}
#[must_use]
pub fn decimal_lt(a: Decimal, b: Decimal) -> bool {
    a.0 < b.0
}
#[must_use]
pub fn decimal_lte(a: Decimal, b: Decimal) -> bool {
    a.0 <= b.0
}
#[must_use]
pub fn decimal_gt(a: Decimal, b: Decimal) -> bool {
    a.0 > b.0
}
#[must_use]
pub fn decimal_gte(a: Decimal, b: Decimal) -> bool {
    a.0 >= b.0
}

// === min / max ===
#[must_use]
pub fn decimal_min(a: Decimal, b: Decimal) -> Decimal {
    if a.0 <= b.0 { a } else { b }
}
#[must_use]
pub fn decimal_max(a: Decimal, b: Decimal) -> Decimal {
    if a.0 >= b.0 { a } else { b }
}

// === sign predicates ===
#[must_use]
pub fn decimal_is_zero(d: Decimal) -> bool {
    d.0.is_zero()
}
#[must_use]
pub fn decimal_is_positive(d: Decimal) -> bool {
    d.0 > RD::ZERO
}
#[must_use]
pub fn decimal_is_negative(d: Decimal) -> bool {
    d.0 < RD::ZERO
}

// === percent ===
// Use the saturating helpers so an extreme pct/base combo doesn't panic.
#[must_use]
pub fn decimal_percent_of(pct: Decimal, of_: Decimal) -> Decimal {
    decimal_div_raw(decimal_mul(pct, of_), Decimal(RD::from(100)))
}
#[must_use]
pub fn decimal_add_percent(pct: Decimal, base: Decimal) -> Decimal {
    decimal_add(
        base,
        decimal_div_raw(decimal_mul(pct, base), Decimal(RD::from(100))),
    )
}
#[must_use]
pub fn decimal_sub_percent(pct: Decimal, base: Decimal) -> Decimal {
    decimal_sub(
        base,
        decimal_div_raw(decimal_mul(pct, base), Decimal(RD::from(100))),
    )
}

// Internal helper: divide without returning a Result (denominator is always
// a compile-time constant 100 in the percent helpers, never zero).
#[inline]
fn decimal_div_raw(a: Decimal, b: Decimal) -> Decimal {
    if b.0.is_zero() {
        return Decimal(RD::ZERO);
    }
    // checked_div (see decimal_div) — saturate on mantissa overflow, never panic.
    Decimal(a.0.checked_div(b.0).unwrap_or_else(|| {
        if a.0.is_sign_negative() == b.0.is_sign_negative() {
            RD::MAX
        } else {
            RD::MIN
        }
    }))
}

// === formatWith — Ipê source: formatWith thousandsSep decimalSep places d ===
// (group every 3 digits right-to-left)
#[must_use]
pub fn decimal_format_with(grp_sep: String, dec_sep: String, places: i64, d: Decimal) -> String {
    // Clamp to MAX_SCALE: digits past the decimal's max scale are zeros anyway,
    // so a huge `places` only inflates the format-width allocation (DoS) without
    // adding precision.
    let p = places.clamp(0, i64::from(RD::MAX_SCALE)) as u32;
    // Use half-away-from-zero rounding (not banker's rounding) so tie values
    // (e.g. "2.545" at 2 dp → "2.55") behave as expected.
    let rounded = if p > 0 {
        d.0.round_dp_with_strategy(p, RoundingStrategy::MidpointAwayFromZero)
    } else {
        d.0.round_dp_with_strategy(0, RoundingStrategy::MidpointAwayFromZero)
    };
    // StringFixed-equivalent: pad trailing zeros to `p` places.
    let fixed = format!("{:.*}", p as usize, rounded);
    let neg = fixed.starts_with('-');
    let unsigned: &str = if neg { &fixed[1..] } else { &fixed[..] };
    let (int_part, frac_part) = match unsigned.find('.') {
        Some(i) => (&unsigned[..i], &unsigned[i + 1..]),
        None => (unsigned, ""),
    };
    // Group the integer part with grp_sep every 3 digits from the right.
    let chars: Vec<char> = int_part.chars().rev().collect();
    let mut grouped_rev = String::new();
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && i % 3 == 0 && !grp_sep.is_empty() {
            grouped_rev.push_str(&grp_sep.chars().rev().collect::<String>());
        }
        grouped_rev.push(*c);
    }
    let grouped: String = grouped_rev.chars().rev().collect();
    let sign = if neg { "-" } else { "" };
    if p == 0 {
        format!("{sign}{grouped}")
    } else {
        format!("{sign}{grouped}{dec_sep}{frac_part}")
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn d(s: &str) -> Decimal {
        Decimal(RD::from_str(s).unwrap())
    }

    #[test]
    fn test_from_string() {
        let r: IpeResult<String, Decimal> = decimal_from_string("12.345".to_string());
        assert!(matches!(r, IpeResult::Ok(_)));
        let r2: IpeResult<String, Decimal> = decimal_from_string("not a number".to_string());
        assert!(matches!(r2, IpeResult::Err(_)));
    }

    #[test]
    fn test_arith() {
        assert_eq!(decimal_to_string(decimal_add(d("1.5"), d("2.25"))), "3.75");
        assert_eq!(decimal_to_string(decimal_sub(d("5"), d("2.5"))), "2.5");
        assert_eq!(decimal_to_string(decimal_mul(d("1.5"), d("4"))), "6");
        let div: IpeResult<String, Decimal> = decimal_div(d("10"), d("4"));
        assert_eq!(
            decimal_to_string(match div {
                IpeResult::Ok(v) => v,
                IpeResult::Err(_) => panic!(),
            }),
            "2.5"
        );
        let div_zero: IpeResult<String, Decimal> = decimal_div(d("1"), d("0"));
        assert!(matches!(div_zero, IpeResult::Err(_)));
    }

    #[test]
    fn test_round_banker() {
        // Banker's rounding: ties go to even
        assert_eq!(decimal_to_string(decimal_round(0, d("0.5"))), "0");
        assert_eq!(decimal_to_string(decimal_round(0, d("1.5"))), "2");
        assert_eq!(decimal_to_string(decimal_round(0, d("2.5"))), "2");
        assert_eq!(decimal_to_string(decimal_round(0, d("3.5"))), "4");
    }

    #[test]
    fn test_compare() {
        assert_eq!(decimal_compare(d("1"), d("2")), -1);
        assert_eq!(decimal_compare(d("2"), d("2")), 0);
        assert_eq!(decimal_compare(d("3"), d("2")), 1);
    }

    // completion tests

    #[test]
    fn test_decimal_comparisons() {
        let a = d("3");
        let b = d("5");
        assert!(decimal_lt(a, b));
        assert!(decimal_lte(a, b));
        assert!(!decimal_gt(a, b));
        assert!(!decimal_gte(a, b));
        assert!(decimal_eq(a, a));
        assert!(decimal_neq(a, b));
        assert!(decimal_lte(d("5"), d("5"))); // equal
        assert!(decimal_gte(d("5"), d("5"))); // equal
    }

    #[test]
    fn test_decimal_min_max() {
        assert!(decimal_eq(decimal_min(d("3"), d("5")), d("3")));
        assert!(decimal_eq(decimal_max(d("3"), d("5")), d("5")));
        assert!(decimal_eq(decimal_min(d("-2"), d("-5")), d("-5")));
    }

    #[test]
    fn test_decimal_sign_predicates() {
        assert!(decimal_is_zero(decimal_zero()));
        assert!(!decimal_is_zero(d("1")));
        assert!(decimal_is_positive(d("1")));
        assert!(!decimal_is_positive(decimal_zero()));
        assert!(!decimal_is_positive(d("-1")));
        assert!(decimal_is_negative(d("-1")));
        assert!(!decimal_is_negative(decimal_zero()));
    }

    #[test]
    fn test_decimal_percent() {
        // 10% of 100 = 10
        assert!(decimal_eq(decimal_percent_of(d("10"), d("100")), d("10")));
        // 100 + 10% = 110
        assert!(decimal_eq(decimal_add_percent(d("10"), d("100")), d("110")));
        // 100 - 10% = 90
        assert!(decimal_eq(decimal_sub_percent(d("10"), d("100")), d("90")));
    }

    #[test]
    fn test_decimal_format_with() {
        // "1050000.5" -> "1,050,000.50" with 2 places, "." dec, "," group
        assert_eq!(
            decimal_format_with(",".to_string(), ".".to_string(), 2, d("1050000.5")),
            "1,050,000.50"
        );
        // Negative + grouping
        assert_eq!(
            decimal_format_with(",".to_string(), ".".to_string(), 2, d("-1234.5")),
            "-1,234.50"
        );
        // Zero places, no grouping
        assert_eq!(
            decimal_format_with(String::new(), ".".to_string(), 0, d("12345")),
            "12345"
        );
        // European convention: ',' decimal, '.' grouping
        assert_eq!(
            decimal_format_with(".".to_string(), ",".to_string(), 2, d("1234.56")),
            "1.234,56"
        );
    }
}

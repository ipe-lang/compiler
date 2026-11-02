//! Ipe.Math kernels.
//!
//! Signatures from src/Ipê/Type/Constrain/Expression.hs:
//!   abs    : Int -> Int                  (integer abs)
//!   min    : a -> a -> a                 (polymorphic; monomorphised at call site)
//!   max    : a -> a -> a
//!   sqrt   : Float -> Float
//!   pow    : Float -> Float -> Float
//!   floor  : Float -> Int
//!   ceil   : Float -> Int
//!   round  : Float -> Int
//!
//! An `Int` result outside the 64-bit range, and a `Float` to `Int` conversion
//! of NaN or an infinity, end in a typed [`RuntimeTrip`], never a wrapped,
//! saturated or truncated value.

use crate::core::{FloatToIntOp, IntOp, RuntimeTrip, trip};

#[must_use]
pub fn math_pi() -> f64 {
    std::f64::consts::PI
}
#[must_use]
pub fn math_e() -> f64 {
    std::f64::consts::E
}
/// Golden ratio φ = (1 + √5) / 2 ≈ 1.6180339887…
/// (`std::f64::consts::PHI` is nightly-only; use the literal for stable Rust.)
#[must_use]
pub fn math_phi() -> f64 {
    1.618_033_988_749_895_f64
}
/// √2 ≈ 1.4142135623…
#[must_use]
pub fn math_sqrt2() -> f64 {
    std::f64::consts::SQRT_2
}
/// Positive infinity (IEEE 754).
#[must_use]
pub fn math_inf() -> f64 {
    f64::INFINITY
}
/// Not-a-number (IEEE 754). Note: NaN ≠ NaN by IEEE 754.
#[must_use]
pub fn math_nan() -> f64 {
    f64::NAN
}

/// Returns `true` if `x` is NaN (IEEE 754).  Ipê `Math.isNaN : Float -> Bool`.
#[must_use]
pub fn math_is_nan(x: f64) -> bool {
    x.is_nan()
}

/// Ipê `Math.abs : Int -> Int`, a delegate of the one `abs` definition `basics_abs`.
///
/// `abs i64::MIN` trips `IntOverflow`, exactly as `Basics.abs` does.
#[must_use]
pub fn math_abs(x: i64) -> i64 {
    crate::basics::basics_abs(x)
}

/// The exact Ipê `Int` sum, or `None` when it leaves the 64-bit range.
///
/// The in-range half of `+`: every caller that must not decide the overflow
/// edge itself (the compiler's constant folder) reads this, never a
/// `wrapping_*` copy.
#[must_use]
pub const fn ipe_int_exact_add(a: i64, b: i64) -> Option<i64> {
    a.checked_add(b)
}

/// The exact Ipê `Int` difference, or `None` when it leaves the 64-bit range.
#[must_use]
pub const fn ipe_int_exact_sub(a: i64, b: i64) -> Option<i64> {
    a.checked_sub(b)
}

/// The exact Ipê `Int` product, or `None` when it leaves the 64-bit range.
#[must_use]
pub const fn ipe_int_exact_mul(a: i64, b: i64) -> Option<i64> {
    a.checked_mul(b)
}

/// The exact Ipê `Int` truncating quotient, or `None` for a zero divisor or
/// `i64::MIN / -1`.
#[must_use]
pub const fn ipe_int_exact_div(a: i64, b: i64) -> Option<i64> {
    a.checked_div(b)
}

/// Integer addition for Ipê's `+` operator on `Int` operands.
///
/// The exact sum; a sum outside the 64-bit range trips `IntOverflow`,
/// regardless of any Cargo `overflow-checks` setting.
#[must_use]
pub fn ipe_int_add(a: i64, b: i64) -> i64 {
    ipe_int_exact_add(a, b).unwrap_or_else(|| trip(RuntimeTrip::IntOverflow { op: IntOp::Add }))
}

/// Integer subtraction for Ipê's `-` operator on `Int` operands.
///
/// The exact difference; one outside the 64-bit range trips `IntOverflow`.
#[must_use]
pub fn ipe_int_sub(a: i64, b: i64) -> i64 {
    ipe_int_exact_sub(a, b).unwrap_or_else(|| trip(RuntimeTrip::IntOverflow { op: IntOp::Sub }))
}

/// Integer multiplication for Ipê's `*` operator on `Int` operands.
///
/// The exact product; one outside the 64-bit range trips `IntOverflow`.
#[must_use]
pub fn ipe_int_mul(a: i64, b: i64) -> i64 {
    ipe_int_exact_mul(a, b).unwrap_or_else(|| trip(RuntimeTrip::IntOverflow { op: IntOp::Mul }))
}

/// Integer division for Ipê's `//` operator.
///
/// The truncating quotient (toward zero). `i64::MIN // -1`, whose exact
/// quotient `2^63` is outside the 64-bit range, trips `IntOverflow`.
///
/// # Panics
///
/// Panics when `b == 0`, the Ipê integer division-by-zero abort: the standard
/// "attempt to divide by zero" message the panic hook classifies as
/// `DivisionByZero` (exit 101, empty stdout), as the
/// `intdiv_by_zero_aborts_exit_101` golden pins.
//
// `clippy::panic` is suppressed here deliberately: this panic IS the
// DivisionByZero abort, a classified, tested, intentional one.
#[allow(clippy::panic)]
#[must_use]
pub fn ipe_int_div(a: i64, b: i64) -> i64 {
    // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — this abort IS the modeled integer division-by-zero semantics, classified and golden-tested (exit 101) [ledger #boundary]
    assert!(b != 0, "attempt to divide by zero");
    ipe_int_exact_div(a, b).unwrap_or_else(|| trip(RuntimeTrip::IntOverflow { op: IntOp::Div }))
}

// CONTRACT (documented deliberately): `min`/`max` use a real `PartialOrd`
// compare on the typed values — not a polymorphic any-path that routes floats
// through `AsInt` and compares truncated ints. NaN tie-break is fixed and
// total: `min(NaN, x)` / `max(NaN, x)` return the SECOND argument (`<=`/`>=`
// is false for any NaN), never panic.
pub fn math_min<T: PartialOrd>(a: T, b: T) -> T {
    if a <= b { a } else { b }
}
pub fn math_max<T: PartialOrd>(a: T, b: T) -> T {
    if a >= b { a } else { b }
}

#[must_use]
pub fn math_sqrt(x: f64) -> f64 {
    x.sqrt()
}
#[must_use]
pub fn math_pow(base: f64, exp: f64) -> f64 {
    base.powf(exp)
}

/// The `Int` an integral `Float` names, for conversion `op`.
///
/// NaN or an infinity trips `NonFiniteToInt`; a finite value outside the
/// 64-bit range trips `IntOverflow`. The narrowing itself is
/// [`crate::narrow::f64_trunc_to_i64`], exact on an integral value in range.
fn float_to_int(integral: f64, op: FloatToIntOp) -> i64 {
    if !integral.is_finite() {
        trip(RuntimeTrip::NonFiniteToInt { op });
    }
    crate::narrow::f64_trunc_to_i64(integral).unwrap_or_else(|| {
        trip(RuntimeTrip::IntOverflow {
            op: IntOp::FromFloat(op),
        })
    })
}

/// Ipê `floor : Float -> Int`, the greatest `Int` not above `x`.
#[must_use]
pub fn math_floor(x: f64) -> i64 {
    float_to_int(x.floor(), FloatToIntOp::Floor)
}

/// Ipê `ceil : Float -> Int`, the least `Int` not below `x`.
#[must_use]
pub fn math_ceil(x: f64) -> i64 {
    float_to_int(x.ceil(), FloatToIntOp::Ceiling)
}

/// Ipê `round : Float -> Int`, half away from zero.
#[must_use]
pub fn math_round(x: f64) -> i64 {
    float_to_int(x.round(), FloatToIntOp::Round)
}

/// Ipê `trunc : Float -> Int`, toward zero.
#[must_use]
pub fn math_trunc(x: f64) -> i64 {
    float_to_int(x.trunc(), FloatToIntOp::Truncate)
}

// Exponential / logarithmic (Ipe.Math: exp, exp2, log [natural], log2, log10).
#[must_use]
pub fn math_exp(x: f64) -> f64 {
    x.exp()
}
#[must_use]
pub fn math_exp2(x: f64) -> f64 {
    x.exp2()
}
#[must_use]
pub fn math_log(x: f64) -> f64 {
    x.ln()
}
#[must_use]
pub fn math_log2(x: f64) -> f64 {
    x.log2()
}
#[must_use]
pub fn math_log10(x: f64) -> f64 {
    x.log10()
}
#[must_use]
pub fn math_cbrt(x: f64) -> f64 {
    x.cbrt()
}
#[must_use]
pub fn math_hypot(a: f64, b: f64) -> f64 {
    a.hypot(b)
}

// Trigonometric.
#[must_use]
pub fn math_sin(x: f64) -> f64 {
    x.sin()
}
#[must_use]
pub fn math_cos(x: f64) -> f64 {
    x.cos()
}
#[must_use]
pub fn math_tan(x: f64) -> f64 {
    x.tan()
}
#[must_use]
pub fn math_asin(x: f64) -> f64 {
    x.asin()
}
#[must_use]
pub fn math_acos(x: f64) -> f64 {
    x.acos()
}
#[must_use]
pub fn math_atan(x: f64) -> f64 {
    x.atan()
}
#[must_use]
pub fn math_atan2(y: f64, x: f64) -> f64 {
    y.atan2(x)
}

// Hyperbolic.
#[must_use]
pub fn math_sinh(x: f64) -> f64 {
    x.sinh()
}
#[must_use]
pub fn math_cosh(x: f64) -> f64 {
    x.cosh()
}
#[must_use]
pub fn math_tanh(x: f64) -> f64 {
    x.tanh()
}
#[must_use]
pub fn math_asinh(x: f64) -> f64 {
    x.asinh()
}
#[must_use]
pub fn math_acosh(x: f64) -> f64 {
    x.acosh()
}
#[must_use]
pub fn math_atanh(x: f64) -> f64 {
    x.atanh()
}

// Modulo + remainder (parity with  math.Mod / math.Remainder).
/// Float modulo — result has the sign of x (the dividend).
/// Equivalent to  `math.Mod(x, y)` and C's `fmod(x, y)`.
/// Rust's `x % y` is identical to C fmod for f64.
#[must_use]
pub fn math_mod(x: f64, y: f64) -> f64 {
    x % y
}
/// IEEE 754 balanced remainder — equivalent to  `math.Remainder(x, y)`.
/// The result satisfies `x = n*y + remainder` where `n` is the nearest integer
/// to `x/y` (rounded half-to-even), so `|remainder| <= |y|/2`.
///
/// Uses fmod-based argument reduction (a direct port of
/// `math.Remainder`) so it stays exact for large-magnitude operands. A naive
/// `x - (x / y).round_ties_even() * y` loses precision once `|x/y|` exceeds
/// 2^53 (the quotient rounds away the low integer bits), diverging from the
/// true IEEE 754 remainder — this reduction avoids that.
#[must_use]
pub fn math_remainder(x: f64, y: f64) -> f64 {
    // Twice the smallest positive normal double (0x0020000000000000).
    const TINY: f64 = f64::MIN_POSITIVE * 2.0;
    let half_max = f64::MAX / 2.0;

    if x.is_nan() || y.is_nan() || x.is_infinite() || y == 0.0 {
        return f64::NAN;
    }
    if y.is_infinite() {
        return x;
    }

    let sign = x < 0.0;
    let mut x = x.abs();
    let y = y.abs();

    // Exact equality on abs-reduced values is intentional in IEEE 754 remainder
    // argument reduction (ported from  math.Remainder).
    #[allow(clippy::float_cmp)]
    if x == y {
        return if sign { -0.0 } else { 0.0 };
    }
    if y <= half_max {
        x %= y + y; // fmod; now x < 2y
    }
    if y < TINY {
        if x + x > y {
            x -= y;
            if x + x >= y {
                x -= y;
            }
        }
    } else {
        let y_half = 0.5 * y;
        if x > y_half {
            x -= y;
            if x >= y_half {
                x -= y;
            }
        }
    }
    if sign {
        x = -x;
    }
    x
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::core::runtime_trip;

    /// The value `f` returns, or the `RuntimeTrip` it unwinds with.
    fn outcome<T>(
        f: impl FnOnce() -> T + std::panic::UnwindSafe,
    ) -> Result<T, Option<RuntimeTrip>> {
        std::panic::catch_unwind(f).map_err(|payload| runtime_trip(payload.as_ref()))
    }

    /// The `IntOverflow` trip of `op`, as [`outcome`] reports it.
    const fn overflow<T>(op: IntOp) -> Result<T, Option<RuntimeTrip>> {
        Err(Some(RuntimeTrip::IntOverflow { op }))
    }

    #[test]
    fn ipe_int_add_trips_at_max() {
        assert_eq!(outcome(|| ipe_int_add(i64::MAX, 1)), overflow(IntOp::Add));
        assert_eq!(ipe_int_add(0, 0), 0);
        assert_eq!(ipe_int_add(3, 4), 7);
    }

    #[test]
    fn ipe_int_sub_trips_at_min() {
        assert_eq!(outcome(|| ipe_int_sub(i64::MIN, 1)), overflow(IntOp::Sub));
        assert_eq!(ipe_int_sub(10, 3), 7);
        assert_eq!(ipe_int_sub(0, 0), 0);
    }

    #[test]
    fn ipe_int_mul_trips_on_overflow() {
        assert_eq!(outcome(|| ipe_int_mul(i64::MAX, 2)), overflow(IntOp::Mul));
        assert_eq!(ipe_int_mul(3, 4), 12);
        assert_eq!(ipe_int_mul(0, i64::MAX), 0);
    }

    // `i64::MIN // -1` has no 64-bit quotient: it trips, never wraps to `MIN`.
    #[test]
    fn ipe_int_div_min_by_neg_one_trips() {
        assert_eq!(outcome(|| ipe_int_div(i64::MIN, -1)), overflow(IntOp::Div));
        assert_eq!(ipe_int_div(i64::MIN, 1), i64::MIN);
        assert_eq!(ipe_int_div(-7, 2), -3);
    }

    // The `IpeWrapping*` trait impls (generic `Number a` bodies) and the
    // `ipe_int_*` operators (monomorphic `Int` bodies) agree at every edge:
    // the same value in range, the same typed `IntOverflow` trip outside it.
    #[test]
    fn int_overflow_trips_typed() {
        use crate::basics::{IpeWrappingAdd, IpeWrappingMul, IpeWrappingSub};
        let edges = [i64::MIN, -1, 0, 1, i64::MAX];
        let mut trips = 0_usize;
        for a in edges {
            for b in edges {
                let cases = [
                    (
                        outcome(|| a.ipe_wrapping_add(b)),
                        outcome(|| ipe_int_add(a, b)),
                        ipe_int_exact_add(a, b),
                        IntOp::Add,
                    ),
                    (
                        outcome(|| a.ipe_wrapping_sub(b)),
                        outcome(|| ipe_int_sub(a, b)),
                        ipe_int_exact_sub(a, b),
                        IntOp::Sub,
                    ),
                    (
                        outcome(|| a.ipe_wrapping_mul(b)),
                        outcome(|| ipe_int_mul(a, b)),
                        ipe_int_exact_mul(a, b),
                        IntOp::Mul,
                    ),
                ];
                for (generic, int, exact, op) in cases {
                    assert_eq!(generic, int, "{a} {op:?} {b}");
                    match exact {
                        Some(value) => assert_eq!(int, Ok(value), "{a} {op:?} {b}"),
                        None => {
                            trips += 1;
                            assert_eq!(int, overflow(op), "{a} {op:?} {b}");
                        }
                    }
                }
            }
        }
        assert!(trips > 0, "the edge table reaches the overflow arm");
    }

    // The exact half refuses every out-of-range edge and agrees with the
    // operator wherever it answers, so a reader of it never decides the edge.
    #[test]
    fn int_exact_refuses_out_of_range_and_agrees_in_range() {
        assert_eq!(ipe_int_exact_add(i64::MAX, 1), None);
        assert_eq!(ipe_int_exact_sub(i64::MIN, 1), None);
        assert_eq!(ipe_int_exact_mul(i64::MIN, -1), None);
        assert_eq!(ipe_int_exact_div(i64::MIN, -1), None);
        assert_eq!(ipe_int_exact_div(7, 0), None);
        let edges = [
            i64::MIN,
            i64::MIN + 1,
            -7,
            -1,
            0,
            1,
            7,
            i64::MAX - 1,
            i64::MAX,
        ];
        for a in edges {
            for b in edges {
                if let Some(v) = ipe_int_exact_add(a, b) {
                    assert_eq!(v, ipe_int_add(a, b), "{a} + {b}");
                }
                if let Some(v) = ipe_int_exact_sub(a, b) {
                    assert_eq!(v, ipe_int_sub(a, b), "{a} - {b}");
                }
                if let Some(v) = ipe_int_exact_mul(a, b) {
                    assert_eq!(v, ipe_int_mul(a, b), "{a} * {b}");
                }
                if let Some(v) = ipe_int_exact_div(a, b) {
                    assert_eq!(v, ipe_int_div(a, b), "{a} // {b}");
                }
            }
        }
    }

    // `Math.abs` and `Basics.abs` share one definition, edges included:
    // `abs i64::MIN` trips `IntOverflow` through both.
    #[test]
    fn abs_kernels_agree_on_min() {
        for x in [i64::MIN, i64::MIN + 1, -7, -1, 0, 1, 7, i64::MAX] {
            assert_eq!(
                outcome(|| math_abs(x)),
                outcome(|| crate::basics::basics_abs(x)),
                "abs {x}"
            );
        }
        assert_eq!(outcome(|| math_abs(i64::MIN)), overflow(IntOp::Abs));
        assert_eq!(math_abs(i64::MIN + 1), i64::MAX);
    }

    #[test]
    fn test_math_abs_positive() {
        assert_eq!(math_abs(5), 5);
    }
    #[test]
    fn test_math_abs_negative() {
        assert_eq!(math_abs(-5), 5);
    }
    #[test]
    fn test_math_abs_zero() {
        assert_eq!(math_abs(0), 0);
    }

    #[test]
    fn test_math_min_max_i64() {
        assert_eq!(math_min::<i64>(3, 5), 3);
        assert_eq!(math_max::<i64>(3, 5), 5);
        assert_eq!(math_min::<i64>(-2, -5), -5);
    }

    #[test]
    // 3.5, 2.25, 3.0, 1024.0 are all exactly representable IEEE 754 values.
    #[allow(clippy::float_cmp)]
    fn test_math_min_max_f64() {
        assert_eq!(math_min::<f64>(3.5, 2.25), 2.25);
        assert_eq!(math_max::<f64>(3.5, 2.25), 3.5);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_math_sqrt() {
        assert_eq!(math_sqrt(9.0), 3.0);
    }
    #[test]
    #[allow(clippy::float_cmp)]
    fn test_math_pow() {
        assert_eq!(math_pow(2.0, 10.0), 1024.0);
    }

    #[test]
    fn test_math_floor_ceil_round() {
        assert_eq!(math_floor(3.7), 3);
        assert_eq!(math_floor(-3.2), -4);
        assert_eq!(math_ceil(3.2), 4);
        assert_eq!(math_ceil(-3.7), -3);
        assert_eq!(math_round(3.5), 4);
        assert_eq!(math_round(-3.5), -4); // half-away-from-zero
        assert_eq!(math_round(2.4), 2);
        assert_eq!(math_trunc(-3.7), -3);
    }

    // A non-finite value trips `NonFiniteToInt`; a finite value past either
    // end of the `Int` range trips `IntOverflow`; the last in-range values
    // convert exactly.
    #[test]
    fn float_to_int_trips_typed() {
        let convs: [(fn(f64) -> i64, FloatToIntOp); 4] = [
            (math_floor, FloatToIntOp::Floor),
            (math_ceil, FloatToIntOp::Ceiling),
            (math_round, FloatToIntOp::Round),
            (math_trunc, FloatToIntOp::Truncate),
        ];
        for (conv, op) in convs {
            for x in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
                assert_eq!(
                    outcome(|| conv(x)),
                    Err(Some(RuntimeTrip::NonFiniteToInt { op })),
                    "{op:?} {x}"
                );
            }
            for x in [
                9_223_372_036_854_775_808.0,
                -9_223_372_036_854_777_856.0,
                1.0e300,
            ] {
                assert_eq!(
                    outcome(|| conv(x)),
                    overflow(IntOp::FromFloat(op)),
                    "{op:?} {x}"
                );
            }
            assert_eq!(conv(-9_223_372_036_854_775_808.0), i64::MIN, "{op:?}");
            assert_eq!(
                conv(9_223_372_036_854_774_784.0),
                9_223_372_036_854_774_784,
                "{op:?}"
            );
        }
    }

    // ── go-parity regression tests ──────────────────────

    #[test]
    fn test_math_phi() {
        let phi = math_phi();
        assert!((phi - 1.618_033_988_749_895_f64).abs() < 1e-14);
    }

    #[test]
    fn test_math_sqrt2() {
        let s = math_sqrt2();
        assert!((s - std::f64::consts::SQRT_2).abs() < 1e-15);
    }

    #[test]
    fn test_math_inf() {
        assert!(math_inf().is_infinite() && math_inf() > 0.0);
    }

    #[test]
    fn test_math_nan() {
        let n = math_nan();
        assert!(n.is_nan());
        // IEEE 754: NaN != NaN
        #[allow(clippy::eq_op, clippy::float_cmp)]
        {
            assert_ne!(n, n);
        }
    }

    #[test]
    fn test_math_is_nan() {
        assert!(math_is_nan(f64::NAN));
        assert!(!math_is_nan(0.0));
        assert!(!math_is_nan(f64::INFINITY));
        assert!(!math_is_nan(1.0));
    }

    #[test]
    // 1.5 is exactly representable; these are the exact the spec values.
    #[allow(clippy::float_cmp)]
    fn test_math_mod() {
        assert_eq!(math_mod(5.5, 2.0), 1.5);
        assert_eq!(math_mod(-5.5, 2.0), -1.5); // sign of dividend
        assert_eq!(math_mod(5.5, -2.0), 1.5);
    }

    #[test]
    fn test_math_remainder() {
        let r = math_remainder(5.5, 2.0);
        assert!((r - (-0.5_f64)).abs() < 1e-14, "expected -0.5, got {r}");
        // round_ties_even: x/y = 2.75 → nearest even integer = 2, so 5.5 - 2*2.0 = 1.5
        let r2 = math_remainder(5.5, 4.0);
        assert!((r2 - 1.5_f64).abs() < 1e-14, "expected 1.5, got {r2}");
    }
}

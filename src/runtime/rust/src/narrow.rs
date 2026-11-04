//! Narrowing conversions: the one home of every integer and float narrowing
//! the runtime performs.
//!
//! Each fn is total, and none fails toward a success value: an input outside
//! the target range either saturates to the bound that keeps its order, or is
//! refused with `None`. Every proof here holds on each target CI builds,
//! wasm32 included, where `usize` is 32 bits wide; a `usize` width is never
//! the argument.
#![deny(clippy::as_conversions)]

/// The least `f64` inside `i64`: `-2^63`, exactly `i64::MIN`.
const I64_FLOOR: f64 = -9_223_372_036_854_775_808.0;

/// The least `f64` past `i64::MAX`: `2^63`, exactly.
const I64_CEIL: f64 = 9_223_372_036_854_775_808.0;

/// Converts a collection count to an Ipê `Int`, saturating at `i64::MAX`.
///
/// A non-zero-sized allocation holds at most `isize::MAX` items, so only a
/// zero-sized `Vec<()>` can reach the saturation.
#[must_use]
pub fn count_to_int(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// Converts a `u64` count (a database row count) to an Ipê `Int`, saturating.
///
/// A count past `i64::MAX` reads as `i64::MAX`, never as a negative count.
#[must_use]
pub fn count_to_int_u64(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// Converts an Ipê `Int` count to a `usize`, saturating at both ends.
///
/// A count `<= 0` is `0`; a count past `usize::MAX` is `usize::MAX`, so the
/// order of two counts survives the conversion on every target width.
#[must_use]
pub fn count_from_int(n: i64) -> usize {
    saturating_count(n, usize::MAX)
}

/// Converts an Ipê `Int` count into any unsigned width whose largest value is
/// `max`: `<= 0` is `0`, past the width is `max`.
///
/// [`count_from_int`] is its `usize` instance; being width-generic, it is
/// proven at 32 bits by a `u32` instance on every host, not only on wasm32.
fn saturating_count<T: TryFrom<i64> + Default>(n: i64, max: T) -> T {
    if n <= 0 {
        return T::default();
    }
    T::try_from(n).unwrap_or(max)
}

/// The longest delay, in milliseconds, one browser timer honours.
///
/// `setTimeout` and `setInterval` read their delay as a signed 32-bit `long`,
/// and `gloo-timers` narrows its `u32` delay `as i32`, so a delay past
/// `i32::MAX` wraps negative and fires at once. Every browser timer the
/// runtime arms is bounded by this one value.
pub const BROWSER_TIMER_MAX_MS: u32 = i32::MAX.unsigned_abs();

/// Converts an Ipê `Int` to a foreign byte, clamping into `0..=255`.
///
/// This is the rule the FFI scalar coercion (`ipe_ffi::num_coerce::num_saturate`)
/// renders for a `u8` parameter, so a byte in a foreign slice and a scalar `u8`
/// argument narrow alike. The `ipe` crate's `ffi_byte_narrow_parity` test links
/// both and pins their agreement.
#[must_use]
pub fn byte_saturating(n: i64) -> u8 {
    u8::try_from(n.clamp(0, i64::from(u8::MAX))).unwrap_or(u8::MAX)
}

/// Converts a `u128` clock count to `u64`, saturating at `u64::MAX`.
///
/// A nanosecond count since the epoch saturates in the year 2554; every
/// coarser unit saturates later still.
#[must_use]
pub fn u128_saturating_u64(n: u128) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Truncates a float toward zero into an `i64`, refusing what does not fit.
///
/// `None` for NaN, either infinity, and every value outside `[-2^63, 2^63)`;
/// a caller that needs `floor`/`ceil`/`round` applies it first.
#[must_use]
pub fn f64_trunc_to_i64(f: f64) -> Option<i64> {
    if (I64_FLOOR..I64_CEIL).contains(&f) {
        // The guard is false for NaN and both infinities and bounds `f`
        // strictly inside `i64`, so truncation toward zero is exact.
        #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
        let n = f as i64;
        Some(n)
    } else {
        None
    }
}

/// Rounds an Ipê `Int` to the nearest `f64`, ties to even.
///
/// Exact whenever `|n| <= 2^53`; past that the nearest representable float,
/// so the result is never NaN and never infinite.
#[must_use]
// IEEE 754 round-to-nearest-even on every target: the precision loss past
// 2^53 is the documented semantics of `toFloat`.
#[allow(clippy::as_conversions, clippy::cast_precision_loss)] // IPE-RUST-AUDIT:ACCEPTED — the one i64 -> f64 rounding home
pub fn int_to_f64(n: i64) -> f64 {
    n as f64
}

/// The time since the Unix epoch on a host clock; zero for a clock before it.
#[cfg(not(all(target_arch = "wasm32", feature = "wasm-client")))]
fn since_epoch() -> std::time::Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

/// Reads the wall clock as Unix milliseconds, saturating at `i64::MAX`.
///
/// A clock before the epoch reads as `0`.
#[cfg(not(all(target_arch = "wasm32", feature = "wasm-client")))]
#[must_use]
pub fn unix_millis() -> i64 {
    i64::try_from(since_epoch().as_millis()).unwrap_or(i64::MAX)
}

/// Reads the wall clock as Unix seconds, saturating at `i64::MAX`.
///
/// A clock before the epoch reads as `0`.
#[cfg(not(all(target_arch = "wasm32", feature = "wasm-client")))]
#[must_use]
pub fn unix_secs() -> i64 {
    i64::try_from(since_epoch().as_secs()).unwrap_or(i64::MAX)
}

/// Reads the browser clock (`Date.now()`) as Unix milliseconds.
///
/// `Date.now()` is a finite integral count; a value it could not hold reads
/// as `0`, as a host clock before the epoch does.
#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
#[must_use]
pub fn unix_millis() -> i64 {
    f64_trunc_to_i64(js_sys::Date::now()).unwrap_or(0)
}

/// Reads the browser clock as Unix seconds.
///
/// The seconds floor the milliseconds, so the two reads agree.
#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
#[must_use]
pub fn unix_secs() -> i64 {
    unix_millis().div_euclid(1000)
}

// The wasm-floor cell scan admits no test module outside `src/wasm/` into the
// wasm32 library test binary.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::{
        I64_CEIL, I64_FLOOR, byte_saturating, count_from_int, count_to_int, count_to_int_u64,
        f64_trunc_to_i64, int_to_f64, saturating_count, u128_saturating_u64,
    };

    /// `2^32`: the first value a 32-bit narrowing wraps back to zero.
    const WRAP: i64 = 1 << 32;

    #[test]
    fn count_to_int_saturates() {
        assert_eq!(count_to_int(0), 0);
        assert_eq!(count_to_int(7), 7);
        assert_eq!(
            count_to_int(usize::MAX),
            i64::try_from(usize::MAX).unwrap_or(i64::MAX)
        );
        assert!(count_to_int(usize::MAX) > 0);
        assert_eq!(count_to_int_u64(u64::MAX), i64::MAX);
        assert_eq!(count_to_int_u64(i64::MAX.unsigned_abs()), i64::MAX);
        assert_eq!(count_to_int_u64(i64::MAX.unsigned_abs() + 1), i64::MAX);
        assert_eq!(count_to_int_u64(41), 41);
    }

    /// The 32-bit proof, run on every host: `2^32 + 5` saturates, never wraps
    /// to `5`, and the last value the width holds stays exact.
    #[test]
    fn saturating_count_saturates_at_32_bits() {
        let at32 = |n: i64| saturating_count(n, u32::MAX);
        assert_eq!(at32(i64::MIN), 0);
        assert_eq!(at32(-1), 0);
        assert_eq!(at32(0), 0);
        assert_eq!(at32(7), 7);
        assert_eq!(at32(WRAP - 1), u32::MAX);
        assert_eq!(at32(WRAP), u32::MAX);
        assert_eq!(at32(WRAP + 5), u32::MAX);
        assert_eq!(at32(i64::MAX), u32::MAX);
    }

    /// Exact where `usize` holds the count, `usize::MAX` where it does not:
    /// `2^32 + 5` is never `5`, on a 32-bit target or any other.
    #[test]
    fn count_from_int_saturates_at_both_ends() {
        assert_eq!(count_from_int(-1), 0);
        assert_eq!(count_from_int(i64::MIN), 0);
        assert_eq!(count_from_int(0), 0);
        assert_eq!(count_from_int(3), 3);
        for n in [WRAP - 1, WRAP, WRAP + 5, i64::MAX] {
            let got = count_from_int(n);
            assert!(
                usize::try_from(n).map_or(got == usize::MAX, |exact| got == exact),
                "count_from_int({n}) = {got}"
            );
        }
    }

    /// The `u8` rule `ipe_ffi::num_coerce::num_saturate` renders, evaluated.
    // The clamp bounds `n` to `0..=255`, so the rendered cast is exact.
    #[allow(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn scalar_ffi_u8(n: i64) -> u8 {
        n.clamp(0, i64::from(u8::MAX)) as u8
    }

    #[test]
    fn byte_saturating_matches_the_scalar_ffi_rule() {
        assert_eq!(byte_saturating(256), 255);
        assert_eq!(byte_saturating(-1), 0);
        assert_eq!(byte_saturating(255), 255);
        assert_eq!(byte_saturating(0), 0);
        for n in [
            i64::MIN,
            -256,
            -1,
            0,
            1,
            127,
            128,
            255,
            256,
            257,
            300,
            WRAP,
            i64::MAX,
        ] {
            assert_eq!(byte_saturating(n), scalar_ffi_u8(n), "byte {n}");
        }
    }

    #[test]
    fn u128_saturates_at_u64_max() {
        assert_eq!(u128_saturating_u64(u128::from(u64::MAX)), u64::MAX);
        assert_eq!(u128_saturating_u64(u128::from(u64::MAX) + 1), u64::MAX);
        assert_eq!(u128_saturating_u64(u128::MAX), u64::MAX);
        assert_eq!(u128_saturating_u64(9), 9);
    }

    #[test]
    fn int_to_f64_is_exact_to_2_pow_53_then_rounds_to_even() {
        const EXACT: i64 = 1 << 53;
        assert_eq!(int_to_f64(0), 0.0);
        assert_eq!(int_to_f64(-7), -7.0);
        assert_eq!(int_to_f64(EXACT), 9_007_199_254_740_992.0);
        assert_eq!(int_to_f64(-EXACT), -9_007_199_254_740_992.0);
        // `2^53 + 1` is a tie between `2^53` and `2^53 + 2`; the even one wins.
        assert_eq!(int_to_f64(EXACT + 1), 9_007_199_254_740_992.0);
        assert_eq!(int_to_f64(EXACT + 3), 9_007_199_254_740_996.0);
        assert_eq!(int_to_f64(i64::MAX), I64_CEIL);
        assert_eq!(int_to_f64(i64::MIN), I64_FLOOR);
    }

    #[test]
    fn f64_trunc_refuses_what_i64_cannot_hold() {
        for f in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            9.3e18,
            I64_CEIL,
            -9.3e18,
        ] {
            assert_eq!(f64_trunc_to_i64(f), None, "{f}");
        }
        // The next `f64` below `-2^63`.
        assert_eq!(f64_trunc_to_i64(-9_223_372_036_854_777_856.0), None);
        assert_eq!(f64_trunc_to_i64(I64_FLOOR), Some(i64::MIN));
        // The greatest `f64` below `2^63`.
        assert_eq!(
            f64_trunc_to_i64(9_223_372_036_854_774_784.0),
            Some(9_223_372_036_854_774_784)
        );
        assert_eq!(f64_trunc_to_i64(-1.5), Some(-1));
        assert_eq!(f64_trunc_to_i64(2.9), Some(2));
        assert_eq!(f64_trunc_to_i64(-0.0), Some(0));
    }

    #[test]
    fn unix_clock_reads_agree() {
        let secs = super::unix_secs();
        let millis = super::unix_millis();
        // Later than 2023-11-14, the far side of any plausible host clock.
        assert!(secs > 1_700_000_000, "secs {secs}");
        assert!(
            millis.div_euclid(1000) >= secs,
            "millis {millis} secs {secs}"
        );
        assert!(
            millis.div_euclid(1000) - secs <= 5,
            "millis {millis} secs {secs}"
        );
    }
}

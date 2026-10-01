//! Soundness + behaviour coverage for arithmetic / random / decimal kernels.
//! Emphasis on the panic-prone sites (mod/div by zero, empty-list choice,
//! out-of-domain math) — each asserts the kernel is TOTAL (defined result,
//! never a Rust panic) plus the expected value, and the seeded-random kernels
//! assert determinism (same seed ⇒ same output).
#![cfg(not(target_arch = "wasm32"))]

// The crate-root glob supplies the unqualified `IpeMaybe` / `IpeError` /
// `with_default` names the `random`- and `decimal`-gated tests use; the other
// tests fully qualify their kernel paths, so the glob is dead without either
// feature.
#[cfg(any(feature = "random", feature = "decimal"))]
use ipe_runtime_rust::*;
use proptest::prelude::*;

// ── basics_mod_by — Elm positive-modulo, divisor 0 guarded ─────────────────

#[test]
fn mod_by_zero_returns_zero_not_panic() {
    assert_eq!(ipe_runtime_rust::basics::basics_mod_by(0, 7), 0);
    assert_eq!(ipe_runtime_rust::basics::basics_mod_by(0, -7), 0);
    assert_eq!(ipe_runtime_rust::basics::basics_mod_by(0, 0), 0);
}

#[test]
fn mod_by_positive_divisor_is_always_nonnegative() {
    assert_eq!(ipe_runtime_rust::basics::basics_mod_by(3, 7), 1);
    assert_eq!(ipe_runtime_rust::basics::basics_mod_by(3, -1), 2); // Elm: positive result
    assert_eq!(ipe_runtime_rust::basics::basics_mod_by(3, -4), 2);
    assert_eq!(ipe_runtime_rust::basics::basics_mod_by(5, 0), 0);
}

#[test]
fn mod_by_negative_divisor_matches_go() {
    // Basics_modByT(divisor, n): `r := n % divisor; if r < 0 { r += divisor }`.
    // basics_mod_by(-3, 7): 7 % -3 = 1 (Rust % takes the dividend's sign);
    //   r=1 not < 0 ⇒ 1.
    assert_eq!(ipe_runtime_rust::basics::basics_mod_by(-3, 7), 1);
    // basics_mod_by(-3, -7): -7 % -3 = -1; r<0 ⇒ -1 + (-3) = -4.
    assert_eq!(ipe_runtime_rust::basics::basics_mod_by(-3, -7), -4);
}

#[test]
fn basics_fst_snd_identity_always() {
    assert_eq!(
        ipe_runtime_rust::basics::basics_fst((1i64, "x".to_string())),
        1
    );
    assert_eq!(
        ipe_runtime_rust::basics::basics_snd((1i64, "x".to_string())),
        "x".to_string()
    );
    assert_eq!(ipe_runtime_rust::basics::basics_identity(42i64), 42);
    assert_eq!(
        ipe_runtime_rust::basics::basics_always(7i64, "ignored".to_string()),
        7
    );
}

proptest! {
    #[test]
    fn prop_mod_by_positive_divisor_in_range(d in 1i64..1_000_000, n in any::<i64>()) {
        let r = ipe_runtime_rust::basics::basics_mod_by(d, n);
        prop_assert!(r >= 0 && r < d);
    }

    #[test]
    fn prop_mod_by_zero_never_panics(n in any::<i64>()) {
        prop_assert_eq!(ipe_runtime_rust::basics::basics_mod_by(0, n), 0);
    }
}

// ── math — out-of-domain inputs are defined (NaN/inf), never panic ─────────

#[test]
// Exact-equality comparisons here are intentional: sqrt(4) and pow(2,10)
// produce exact IEEE 754 results (2.0 and 1024.0 respectively).
#[allow(clippy::float_cmp)]
fn math_out_of_domain_is_total() {
    assert!(ipe_runtime_rust::math::math_sqrt(-1.0).is_nan());
    assert_eq!(ipe_runtime_rust::math::math_sqrt(4.0), 2.0);
    assert!(ipe_runtime_rust::math::math_log(0.0).is_infinite());
    assert!(ipe_runtime_rust::math::math_log(-1.0).is_nan());
    // round of a non-finite / huge float saturates into i64 (defined `as` cast).
    let _ = ipe_runtime_rust::math::math_round(f64::NAN);
    let _ = ipe_runtime_rust::math::math_round(f64::INFINITY);
    assert_eq!(ipe_runtime_rust::math::math_round(2.5), 3);
    assert_eq!(ipe_runtime_rust::math::math_pow(2.0, 10.0), 1024.0);
}

proptest! {
    #[test]
    fn prop_math_round_never_panics(x in any::<f64>()) {
        let _ = ipe_runtime_rust::math::math_round(x); // must not panic for any f64
    }
    #[test]
    fn prop_math_sqrt_never_panics(x in any::<f64>()) {
        let _ = ipe_runtime_rust::math::math_sqrt(x);
    }
}

// ── seeded random — deterministic, in-range, empty-safe ────────────────────
// The `Ipe.Random` surface (`random.rs`) is behind the `random` feature; these
// fixtures compile only when it is selected (CI's `--features full` includes it).

#[cfg(feature = "random")]
#[test]
fn seeded_int_is_deterministic_and_in_range() {
    let (v1, s1) = ipe_runtime_rust::random::random_seeded_int(12345, 10, 20);
    let (v2, s2) = ipe_runtime_rust::random::random_seeded_int(12345, 10, 20);
    assert_eq!((v1, s1), (v2, s2), "same seed must give same output");
    assert!((10..=20).contains(&v1));
}

#[cfg(feature = "random")]
#[test]
fn seeded_int_hi_le_lo_returns_lo() {
    let (v, _) = ipe_runtime_rust::random::random_seeded_int(7, 5, 5);
    assert_eq!(v, 5);
    let (v2, _) = ipe_runtime_rust::random::random_seeded_int(7, 9, 1); // hi < lo
    assert_eq!(v2, 9);
}

#[cfg(feature = "random")]
#[test]
fn seeded_choice_empty_is_nothing_not_panic() {
    let (m, _): (IpeMaybe<i64>, i64) = ipe_runtime_rust::random::random_seeded_choice(42, vec![]);
    assert!(m.is_nothing());
}

#[cfg(feature = "random")]
#[test]
fn seeded_choice_picks_in_bounds_deterministically() {
    let items = vec!["a", "b", "c", "d"];
    let (m1, _) = ipe_runtime_rust::random::random_seeded_choice(999, items.clone());
    let (m2, _) = ipe_runtime_rust::random::random_seeded_choice(999, items.clone());
    assert!(m1.is_just());
    assert_eq!(m1, m2);
}

#[cfg(feature = "random")]
#[test]
fn seeded_float_in_unit_interval() {
    let (f, _) = ipe_runtime_rust::random::random_seeded_float(123);
    assert!((0.0..1.0).contains(&f));
}

#[cfg(feature = "random")]
proptest! {
    #[test]
    fn prop_seeded_int_always_in_range(seed in any::<i64>(), lo in -1000i64..1000, span in 0i64..1000) {
        let hi = lo + span;
        let (v, _) = ipe_runtime_rust::random::random_seeded_int(seed, lo, hi);
        prop_assert!(v >= lo && v <= hi);
    }
}

// ── #2639 — a range wider than 2^31 must be able to produce its UPPER half ───
// The old reduction (`>> 33`) kept only the top 31 bits of the draw, so every
// offset ≥ 2^31 was impossible: over half of a declared inclusive [lo, hi] whose
// width exceeds 2^31 could NEVER be produced. Sweep deterministic seeds over a
// range spanning the whole non-negative i64 axis and assert some draw lands in
// the upper half (offset ≥ 2^62). Fails on the `>> 33` code (max offset < 2^31).
#[cfg(feature = "random")]
#[test]
fn seeded_int_wide_range_reaches_upper_half() {
    let lo = 0i64;
    let hi = i64::MAX; // width = 2^63, far past 2^31
    let midpoint = 1i64 << 62; // start of the upper quarter — unreachable under `>> 33`
    let mut saw_upper = false;
    for seed in 0i64..2000 {
        let (v, _) = ipe_runtime_rust::random::random_seeded_int(seed, lo, hi);
        assert!((lo..=hi).contains(&v), "draw {v} escaped [{lo}, {hi}]");
        if v >= midpoint {
            saw_upper = true;
            break;
        }
    }
    assert!(
        saw_upper,
        "no draw reached the upper half of a >2^31-wide range — the reduction \
         drops high bits and makes half the declared range unreachable"
    );
}

// ── #2641 — no modulo bias on a range comparable to the sample space ─────────
// (function name kept for tracker continuity — the range is now large, not small)
// Modulo bias only shows measurably when `width` is a large fraction of the
// 2^64 draw space (for a small width the skew is ~width/2^64 — negligible). Use
// width = 3·2^62 = 0xC000_0000_0000_0000: since 2^64 = 1·width + 2^62, naive
// `sample % width` maps two distinct samples onto every residue in the low third
// [0, 2^62) but only one onto every residue in the upper two-thirds — so the low
// third is hit ~2× as often as it should be. The production rejection sampler
// discards the biasing tail and keeps all three thirds equiprobable. The OLD
// `(next >> 33) % width` code is even worse: a 31-bit sample is always < width,
// so `% width` is a no-op and every draw lands far inside the low third — the
// upper thirds get ~zero. Bucket the draws into thirds and assert each third is
// within tolerance of 1/3; the naive-`%` and the `>> 33` reductions both fail it.
#[cfg(feature = "random")]
#[test]
fn seeded_int_no_modulo_bias_over_small_range() {
    // width = 3·2^62 needs a span past i64::MAX, so anchor at lo = i64::MIN and
    // let hi land in the negative axis — the inclusive [lo, hi] width (computed in
    // i128 by the kernel) is what governs the bias, not hi's sign. 2^64 % width =
    // 2^62 ≠ 0, so the residues in the low third [0, 2^62) are the double-counted ones.
    let lo = i64::MIN;
    let width: i128 = 3i128 << 62; // 0xC000_0000_0000_0000
    let hi = (i128::from(lo) + width - 1) as i64;
    let third = (width / 3) as u128; // 2^62 — boundary between buckets
    let draws = 60_000usize;
    let mut counts = [0usize; 3]; // low / middle / high third
    for seed in 0..draws as i64 {
        let (v, _) = ipe_runtime_rust::random::random_seeded_int(seed, lo, hi);
        assert!((lo..=hi).contains(&v), "draw {v} escaped [{lo}, {hi}]");
        let off = (i128::from(v) - i128::from(lo)) as u128;
        let bucket = (off / third).min(2) as usize;
        if let Some(c) = counts.get_mut(bucket) {
            *c += 1;
        }
    }
    let expected = draws as f64 / 3.0;
    // 12% tolerance: comfortably wide for the sampling noise of 60k seeded draws,
    // yet far tighter than the ~2× skew naive `%` puts on the low third (and the
    // ~all-in-low-third collapse of the `>> 33` reduction).
    for (i, &c) in counts.iter().enumerate() {
        let dev = (c as f64 - expected).abs() / expected;
        assert!(
            dev < 0.12,
            "third {i} count {c} deviates {:.1}% from uniform {expected:.0} — modulo bias",
            dev * 100.0
        );
    }
}

// ── #2642 — an overflowing (inf-total) weight set must NOT collapse to last ───
// `total = sum(weights)` overflows to +inf for huge finite weights, making the
// scaled `r` non-finite so `r < cum` never fires: the pre-fix code then falls
// through and returns the LAST entry on EVERY draw — a silent, non-proportional
// result that always yields one fixed value. The production guard replaces that
// with a uniform pick over the positive entries, so across many draws the
// non-last entries appear too. Give three DISTINCT values whose weights each
// overflow the sum to +inf and draw many times: a correct uniform fallback must
// produce the two NON-LAST values (10 and 20) as well as the last (30); the
// collapse bug produces ONLY 30, so seeing any non-last value falsifies it.
// (The bug is data-independent — it returns last for every seed — so no run of
// the reverted code can pass, however the wall-clock LCG happens to be seeded.)
#[cfg(all(feature = "random", feature = "tokio"))]
#[test]
fn weighted_huge_weights_stay_proportional() {
    use ipe_runtime_rust::*;
    fn draw(items: Vec<(f64, i64)>) -> IpeMaybe<i64> {
        let t: IpeTask<IpeError, IpeMaybe<i64>> =
            ipe_runtime_rust::random::random_weighted::<IpeError, i64>(items);
        let r = task_run(t);
        // random_weighted is total (never Err); assert that, then take the value.
        assert!(r.is_ok(), "random_weighted is total — never Err");
        r.with_default(IpeMaybe::Nothing)
    }
    // Every weight is f64::MAX, so the total overflows to +inf. The last entry is
    // 30; the collapse-to-last bug would return 30 for every one of these draws.
    let weights = vec![(f64::MAX, 10i64), (f64::MAX, 20i64), (f64::MAX, 30i64)];
    let trials = 400usize;
    let mut saw_10 = false;
    let mut saw_20 = false;
    let mut saw_30 = false;
    for _ in 0..trials {
        let v = draw(weights.clone());
        assert!(
            matches!(v, IpeMaybe::Just(10 | 20 | 30)),
            "inf-total weighted draw returned an invalid value: {v:?}"
        );
        match v {
            IpeMaybe::Just(10) => saw_10 = true,
            IpeMaybe::Just(20) => saw_20 = true,
            _ => saw_30 = true,
        }
    }
    // The two NON-LAST values must both appear — impossible under collapse-to-last,
    // near-certain (each ~1/3) under the uniform fallback across 400 draws.
    assert!(
        saw_10 && saw_20,
        "inf-total weight set collapsed to the last entry: saw_10={saw_10} \
         saw_20={saw_20} saw_30={saw_30} — the non-finite-total guard is not firing"
    );
}

// ── decimal — divide/modulo by zero returns Err, never panics ──────────────
// `decimal.rs` is behind the `decimal` feature, so these tests are too.

#[cfg(feature = "decimal")]
#[test]
fn decimal_div_by_zero_is_err() {
    let a = ipe_runtime_rust::decimal::decimal_from_int(10);
    let zero = ipe_runtime_rust::decimal::decimal_from_int(0);
    let r = ipe_runtime_rust::decimal::decimal_div::<IpeError>(a, zero);
    assert!(r.is_err());
}

#[cfg(feature = "decimal")]
#[test]
fn decimal_mod_by_zero_is_err() {
    let a = ipe_runtime_rust::decimal::decimal_from_int(10);
    let zero = ipe_runtime_rust::decimal::decimal_from_int(0);
    let r = ipe_runtime_rust::decimal::decimal_mod::<IpeError>(a, zero);
    assert!(r.is_err());
}

#[cfg(feature = "decimal")]
#[test]
fn decimal_div_normal_is_ok() {
    let a = ipe_runtime_rust::decimal::decimal_from_int(10);
    let b = ipe_runtime_rust::decimal::decimal_from_int(4);
    let r = ipe_runtime_rust::decimal::decimal_div::<IpeError>(a, b);
    assert!(r.is_ok());
    let q = r.with_default(ipe_runtime_rust::decimal::decimal_from_int(0));
    assert_eq!(ipe_runtime_rust::decimal::decimal_to_string(q), "2.5");
}

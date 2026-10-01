//! Soundness coverage for `ipe_runtime_rust::core` — the coercion primitives that
//! every generated FFI wrapper and kernel call routes through. The existential
//! guarantee ("no runtime panic from well-typed Ipê code") lives or dies here,
//! so each test asserts BOTH the happy path AND that the failure path returns
//! `IpeResult::Err` rather than panicking / wrapping / indexing out of bounds.
#![cfg(not(target_arch = "wasm32"))]

use ipe_runtime_rust::*;
use proptest::prelude::*;

// ── byte <-> List Int round-trips ──────────────────────────────────────────

#[test]
fn to_u8_vec_from_u8_slice_roundtrip_in_range() {
    let bytes: Vec<u8> = vec![0, 1, 65, 127, 200, 255];
    let as_ints = ipe_runtime_rust::core::from_u8_slice(&bytes);
    assert_eq!(as_ints, vec![0i64, 1, 65, 127, 200, 255]);
    let back = ipe_runtime_rust::core::to_u8_vec(&as_ints);
    assert_eq!(back, bytes);
}

#[test]
fn to_u8_vec_truncates_out_of_range_without_panic() {
    // `x as u8` is defined (wrapping) for any i64 — never a panic.
    assert_eq!(ipe_runtime_rust::core::to_u8_vec(&[256]), vec![0u8]);
    assert_eq!(ipe_runtime_rust::core::to_u8_vec(&[257]), vec![1u8]);
    assert_eq!(ipe_runtime_rust::core::to_u8_vec(&[-1]), vec![255u8]);
    assert_eq!(
        ipe_runtime_rust::core::to_u8_vec(&[i64::MAX, i64::MIN]),
        vec![255u8, 0u8]
    );
    assert_eq!(ipe_runtime_rust::core::to_u8_vec(&[]), Vec::<u8>::new());
}

// ── fixed-size array coercion: length mismatch MUST be Err, never panic ─────

#[test]
fn to_u8_array_exact_length_ok() {
    let r = ipe_runtime_rust::core::to_u8_array::<IpeError, 3>(&[1, 2, 3]);
    assert!(r.is_ok());
    assert_eq!(r.with_default([0, 0, 0]), [1u8, 2, 3]);
}

#[test]
fn to_u8_array_too_short_is_err_not_panic() {
    let r = ipe_runtime_rust::core::to_u8_array::<IpeError, 3>(&[1, 2]);
    assert!(r.is_err(), "short input must be Err, never a panic");
}

#[test]
fn to_u8_array_too_long_is_err_not_panic() {
    let r = ipe_runtime_rust::core::to_u8_array::<IpeError, 3>(&[1, 2, 3, 4, 5]);
    assert!(r.is_err(), "long input must be Err, never a panic");
}

#[test]
fn to_u8_array_zero_length_ok_on_empty_err_on_nonempty() {
    assert!(ipe_runtime_rust::core::to_u8_array::<IpeError, 0>(&[]).is_ok());
    assert!(ipe_runtime_rust::core::to_u8_array::<IpeError, 0>(&[1]).is_err());
}

#[test]
fn to_array_generic_exact_ok_mismatch_err() {
    let ok = ipe_runtime_rust::core::to_array::<IpeError, String, 2>(&[
        "a".to_string(),
        "b".to_string(),
    ]);
    assert!(ok.is_ok());
    assert_eq!(
        ok.with_default([String::new(), String::new()]),
        ["a".to_string(), "b".to_string()]
    );

    let short = ipe_runtime_rust::core::to_array::<IpeError, String, 2>(&["a".to_string()]);
    assert!(short.is_err());
    let long = ipe_runtime_rust::core::to_array::<IpeError, i64, 2>(&[1, 2, 3]);
    assert!(long.is_err());
}

// ── IpeMaybe combinators — both variants ───────────────────────────────────

#[test]
fn ipe_maybe_map_and_then_with_default() {
    let just = IpeMaybe::Just(10i64);
    let nothing: IpeMaybe<i64> = IpeMaybe::Nothing;

    assert!(just.is_just() && !just.is_nothing());
    assert!(nothing.is_nothing() && !nothing.is_just());

    assert_eq!(
        ipe_runtime_rust::core::ipe_maybe_map(IpeMaybe::Just(10i64), |x| x + 1),
        IpeMaybe::Just(11)
    );
    assert_eq!(
        ipe_runtime_rust::core::ipe_maybe_map(IpeMaybe::Nothing, |x: i64| x + 1),
        IpeMaybe::Nothing
    );

    assert_eq!(
        ipe_runtime_rust::core::ipe_maybe_and_then(IpeMaybe::Just(10i64), |x| IpeMaybe::Just(
            x * 2
        )),
        IpeMaybe::Just(20)
    );
    assert_eq!(
        ipe_runtime_rust::core::ipe_maybe_and_then(IpeMaybe::Just(10i64), |_: i64| {
            IpeMaybe::<i64>::Nothing
        }),
        IpeMaybe::Nothing
    );
    assert_eq!(
        ipe_runtime_rust::core::ipe_maybe_and_then(IpeMaybe::Nothing, |x: i64| IpeMaybe::Just(x)),
        IpeMaybe::Nothing
    );

    assert_eq!(IpeMaybe::Just(7i64).with_default(0), 7);
    assert_eq!(IpeMaybe::<i64>::Nothing.with_default(0), 0);
    assert_eq!(
        ipe_runtime_rust::core::maybe_with_default(99i64, IpeMaybe::Nothing),
        99
    );
    assert_eq!(
        ipe_runtime_rust::core::maybe_with_default(99i64, IpeMaybe::Just(1)),
        1
    );
}

// ── IpeResult combinators — both variants ──────────────────────────────────

#[test]
fn ipe_result_map_and_then_with_default() {
    let ok: IpeResult<IpeError, i64> = IpeResult::Ok(10);
    let err: IpeResult<IpeError, i64> = IpeResult::Err(str_err("boom"));

    assert!(ok.is_ok() && !ok.is_err());
    assert!(err.is_err() && !err.is_ok());

    let mapped =
        ipe_runtime_rust::core::ipe_result_map(IpeResult::<IpeError, i64>::Ok(10), |x| x + 5);
    assert_eq!(mapped.with_default(0), 15);
    let mapped_err = ipe_runtime_rust::core::ipe_result_map(
        IpeResult::<IpeError, i64>::Err(str_err("e")),
        |x| x + 5,
    );
    assert!(mapped_err.is_err());

    let chained =
        ipe_runtime_rust::core::ipe_result_and_then(IpeResult::<IpeError, i64>::Ok(10), |x| {
            IpeResult::Ok(x * 3)
        });
    assert_eq!(chained.with_default(0), 30);
    let chained_to_err =
        ipe_runtime_rust::core::ipe_result_and_then(IpeResult::<IpeError, i64>::Ok(10), |_| {
            IpeResult::<IpeError, i64>::Err(str_err("downstream"))
        });
    assert!(chained_to_err.is_err());
    // and_then on Err must NOT run the function (short-circuit).
    let not_run = ipe_runtime_rust::core::ipe_result_and_then(
        IpeResult::<IpeError, i64>::Err(str_err("upstream")),
        |_: i64| -> IpeResult<IpeError, i64> { panic!("must not be called on Err") },
    );
    assert!(not_run.is_err());

    assert_eq!(
        ipe_runtime_rust::core::result_with_default(0i64, IpeResult::<IpeError, i64>::Ok(42)),
        42
    );
    assert_eq!(
        ipe_runtime_rust::core::result_with_default(
            0i64,
            IpeResult::<IpeError, i64>::Err(str_err("x"))
        ),
        0
    );
}

// ── result_traverse: all-ok collects; first Err short-circuits ─────────────

#[test]
fn result_traverse_all_ok_collects_in_order() {
    let r = ipe_runtime_rust::core::result_traverse::<i64, i64, IpeError>(
        |x| IpeResult::Ok(x * 10),
        vec![1, 2, 3],
    );
    assert_eq!(r.with_default(vec![]), vec![10, 20, 30]);
}

#[test]
fn result_traverse_short_circuits_on_first_err() {
    let r = ipe_runtime_rust::core::result_traverse::<i64, i64, IpeError>(
        |x| {
            if x == 2 {
                IpeResult::Err(str_err("two"))
            } else {
                IpeResult::Ok(x)
            }
        },
        vec![1, 2, 3],
    );
    assert!(r.is_err());
}

#[test]
fn result_traverse_empty_is_ok_empty() {
    let r = ipe_runtime_rust::core::result_traverse::<i64, i64, IpeError>(IpeResult::Ok, vec![]);
    assert_eq!(r.with_default(vec![99]), Vec::<i64>::new());
}

// ── ipe_maybe_to_option: FFI Option-param bridge (Just->Some, Nothing->None) ─

#[test]
fn ipe_maybe_to_option_both_variants() {
    assert_eq!(
        ipe_runtime_rust::core::ipe_maybe_to_option(IpeMaybe::Just(5i64)),
        Some(5)
    );
    assert_eq!(
        ipe_runtime_rust::core::ipe_maybe_to_option(IpeMaybe::<i64>::Nothing),
        None
    );
    // The .as_deref() path the codegen uses for Option<&str> is sound.
    let just = ipe_runtime_rust::core::ipe_maybe_to_option(IpeMaybe::Just("hi".to_string()));
    assert_eq!(just.as_deref(), Some("hi"));
    let none: Option<String> = ipe_runtime_rust::core::ipe_maybe_to_option(IpeMaybe::Nothing);
    assert_eq!(none.as_deref(), None);
    // The numeric-narrowing path (.map(|x| x as u16)).
    // Intentional wrapping truncation: the test exercises the defined `as` cast
    // semantics (no panic), not type-safe narrowing.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let n = ipe_runtime_rust::core::ipe_maybe_to_option(IpeMaybe::Just(70000i64)).map(|x| x as u16);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let expected = 70000i64 as u16;
    assert_eq!(n, Some(expected)); // defined wrapping cast, no panic
}

// ── property: byte/array coercion never panics for ANY input ───────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    #[test]
    fn prop_to_u8_array_never_panics(xs in proptest::collection::vec(any::<i64>(), 0..32)) {
        // Whatever the length, the result is total: Ok iff len==4, else Err.
        let r = ipe_runtime_rust::core::to_u8_array::<IpeError, 4>(&xs);
        prop_assert_eq!(r.is_ok(), xs.len() == 4);
    }

    #[test]
    fn prop_to_u8_vec_from_slice_roundtrip(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        let ints = ipe_runtime_rust::core::from_u8_slice(&bytes);
        let back = ipe_runtime_rust::core::to_u8_vec(&ints);
        prop_assert_eq!(back, bytes);
    }

    #[test]
    fn prop_result_traverse_preserves_length_when_all_ok(xs in proptest::collection::vec(any::<i64>(), 0..50)) {
        let n = xs.len();
        let r = ipe_runtime_rust::core::result_traverse::<i64, i64, IpeError>(IpeResult::Ok, xs);
        prop_assert_eq!(r.with_default(vec![]).len(), n);
    }
}

//! A byte inside a foreign `&[u8]` / `Vec<u8>` / `[u8; N]` parameter narrows
//! exactly as a scalar `u8` FFI argument does.
//!
//! The scalar rule is rendered as text by `ipe_ffi::num_coerce::num_saturate`;
//! the sequence rule is the runtime's `narrow::byte_saturating`, reached through
//! `core::to_u8_vec` / `core::to_u8_array`. This crate links both, so the two
//! real functions are compared here: the rendered scalar text is pinned, that
//! text is evaluated over the edge set, and every runtime byte path must agree.

use ipe_runtime_rust::core::{to_u8_array, to_u8_vec};
use ipe_runtime_rust::narrow::byte_saturating;

/// The exact form `num_saturate` renders for a `u8` parameter bound to `x`.
const SCALAR_U8_FORM: &str = "(x).clamp(0, u8::MAX as i64) as u8";

/// `SCALAR_U8_FORM`, evaluated. The clamp bounds `x` to `0..=255`, so the
/// rendered cast is exact.
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless
)] // evaluates the emitted cast form verbatim — the cast IS the subject
fn scalar_u8(x: i64) -> u8 {
    (x).clamp(0, u8::MAX as i64) as u8
}

/// Each out-of-range edge sits on the far side of a wrap: `256` and `2^32`
/// wrap to `0`, `-1` to `255`, `257` to `1`, `300` to `44`.
const EDGES: [i64; 13] = [
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
    1 << 32,
    i64::MAX,
];

#[test]
fn scalar_u8_rendering_is_the_evaluated_form() {
    assert_eq!(
        ipe_ffi::num_coerce::num_saturate(ipe_ffi::num_coerce::NumWidth::U8, "x"),
        SCALAR_U8_FORM,
        "the scalar u8 FFI rule changed: update `scalar_u8` and the runtime \
         `narrow::byte_saturating` together"
    );
}

#[test]
fn byte_paths_narrow_like_a_scalar_u8_argument() {
    let scalar: Vec<u8> = EDGES.iter().copied().map(scalar_u8).collect();
    let helper: Vec<u8> = EDGES.iter().copied().map(byte_saturating).collect();
    assert_eq!(helper, scalar, "narrow::byte_saturating");
    assert_eq!(to_u8_vec(&EDGES), scalar, "core::to_u8_vec");
    let arr = to_u8_array::<String, 13>(&EDGES);
    assert!(arr.is_ok(), "an in-length array must be Ok");
    assert_eq!(
        arr.with_default([7; 13]).to_vec(),
        scalar,
        "core::to_u8_array"
    );
}

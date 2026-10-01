//! Ipe.Bitwise kernels — bitwise operations on `Int`.
//!
//! `Int` lowers to Rust `i64`, so these operate on 64-bit two's-complement
//! integers. Elm's `Bitwise` is specified on 32-bit ints (JavaScript's `| 0`
//! coercion); Ipê's wider `Int` means `complement` and `shiftRightZfBy` cover
//! the full 64-bit width rather than wrapping at 32 bits — a sanctioned
//! sanctioned divergence from Elm's 32-bit spec.
//!
//! Shift amounts are masked to `0..=63` (`& 63`) before shifting: a raw Rust
//! shift by `>= 64` is undefined-behaviour-adjacent (it panics in debug, is
//! target-defined in release), so masking keeps every draw total and matches
//! the hardware shift-count semantics on x86/ARM.

#[must_use]
pub fn bitwise_and(a: i64, b: i64) -> i64 {
    a & b
}

#[must_use]
pub fn bitwise_or(a: i64, b: i64) -> i64 {
    a | b
}

#[must_use]
pub fn bitwise_xor(a: i64, b: i64) -> i64 {
    a ^ b
}

#[must_use]
pub fn bitwise_complement(a: i64) -> i64 {
    !a
}

/// Arithmetic left shift by `offset & 63` bits.
#[must_use]
pub fn bitwise_shift_left_by(offset: i64, a: i64) -> i64 {
    a.wrapping_shl((offset & 63) as u32)
}

/// Arithmetic (sign-preserving) right shift by `offset & 63` bits.
#[must_use]
pub fn bitwise_shift_right_by(offset: i64, a: i64) -> i64 {
    a.wrapping_shr((offset & 63) as u32)
}

/// Zero-fill (logical) right shift by `offset & 63` bits: the sign bit is not
/// replicated. Done in `u64` so vacated high bits fill with zero regardless of
/// `a`'s sign.
#[must_use]
pub fn bitwise_shift_right_zf_by(offset: i64, a: i64) -> i64 {
    ((a as u64).wrapping_shr((offset & 63) as u32)) as i64
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn logical_ops() {
        assert_eq!(bitwise_and(0b1100, 0b1010), 0b1000);
        assert_eq!(bitwise_or(0b1100, 0b1010), 0b1110);
        assert_eq!(bitwise_xor(0b1100, 0b1010), 0b0110);
    }

    #[test]
    fn complement_is_full_width() {
        assert_eq!(bitwise_complement(0), -1);
        assert_eq!(bitwise_complement(-1), 0);
    }

    #[test]
    fn shifts_match_elm_arg_order() {
        // shiftLeftBy offset value
        assert_eq!(bitwise_shift_left_by(1, 5), 10);
        assert_eq!(bitwise_shift_right_by(1, 32), 16);
        // arithmetic right shift keeps the sign bit
        assert_eq!(bitwise_shift_right_by(1, -8), -4);
        // zero-fill right shift does not
        assert_eq!(bitwise_shift_right_zf_by(1, -8), (u64::MAX >> 1) as i64 - 3);
    }

    #[test]
    fn oversized_shift_is_masked_not_panicking() {
        // offset 64 masks to 0 → no shift, no panic
        assert_eq!(bitwise_shift_left_by(64, 7), 7);
        assert_eq!(bitwise_shift_right_by(64, 7), 7);
        assert_eq!(bitwise_shift_right_zf_by(64, 7), 7);
    }
}

// Constant-time equality — the single byte-comparison predicate every
// secret/tag/key newtype in this runtime uses for `PartialEq`.
//
// Length is treated as non-secret metadata (mismatch short-circuits); the
// per-byte comparison, when lengths match, is constant-time via
// `subtle::ConstantTimeEq`.

use subtle::ConstantTimeEq;

/// The canonical constant-time byte equality predicate.
///
/// Returns `true` iff `a` and `b` have the same length AND every byte is
/// equal, with the byte comparison taking time independent of the content
/// (not the length). Use this as the sole equality body for any newtype
/// wrapping secret or MAC material.
#[inline]
#[must_use]
pub fn ct_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Emit a constant-time `PartialEq` impl for a newtype `$t` whose inner field
/// exposes `.as_bytes()` (a `String` or a `MacTag`).
///
/// The generated impl delegates to [`ct_bytes_eq`] over the `.as_bytes()`
/// of the inner field (accessed as `self.0`). A type that invokes
/// this macro MUST NOT also carry `#[derive(PartialEq)]`: the two impls
/// conflict (E0119), making the timing-unsafe derive a hard compile error —
/// the structural guarantee that the class stays closed.
macro_rules! impl_ct_eq {
    ($t:ty) => {
        impl PartialEq for $t {
            fn eq(&self, other: &Self) -> bool {
                $crate::ct_eq::ct_bytes_eq(self.0.as_bytes(), other.0.as_bytes())
            }
        }
    };
}

pub(crate) use impl_ct_eq;

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::ct_bytes_eq;

    #[test]
    fn equal_slices_return_true() {
        assert!(ct_bytes_eq(b"hello", b"hello"));
    }

    #[test]
    fn equal_length_differing_content_returns_false() {
        assert!(!ct_bytes_eq(b"hello", b"world"));
    }

    #[test]
    fn different_length_returns_false() {
        assert!(!ct_bytes_eq(b"short", b"much-longer"));
    }

    #[test]
    fn both_empty_returns_true() {
        assert!(ct_bytes_eq(b"", b""));
    }

    #[test]
    fn one_empty_returns_false() {
        assert!(!ct_bytes_eq(b"", b"x"));
        assert!(!ct_bytes_eq(b"x", b""));
    }

    /// Verifies that a single differing byte at each position returns false —
    /// no partial-match leak from the implementation.
    #[test]
    fn single_byte_diff_at_any_position_returns_false() {
        let base = b"abcdefgh";
        for i in 0..base.len() {
            let mut other = *base;
            other[i] = other[i].wrapping_add(1);
            assert!(!ct_bytes_eq(base, &other));
        }
    }
}

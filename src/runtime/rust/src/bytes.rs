//! `Ipe.Bytes` kernels — arbitrary byte buffer (`Vec<u8>`).
//!
//! Divergence from Ipê: Ipê defines `type alias Bytes = String` ( `string`
//! is a byte sequence, making the alias cost-free). Rust's `String` is
//! constrained to valid UTF-8; mapping `Bytes` to `String` would be unsound for
//! non-UTF-8 binary payloads. Ipê-Rust makes `Bytes` a distinct primitive
//! lowering to `Vec<u8>` — lossless for arbitrary binary, with explicit UTF-8
//! conversion via `bytes_from_string` / `bytes_to_string`.
//!
//! All functions are total: no `unwrap` / `expect` / `panic` / raw indexing.
//! Fallible operations return `IpeMaybe<T>` (Ipê's `Maybe`).

use base64::{Engine, engine::general_purpose::STANDARD as B64};

use super::IpeMaybe;

// ── Arity-0 ──────────────────────────────────────────────────────────────

/// `Bytes.empty : Bytes` — the empty byte buffer.
#[must_use]
pub fn bytes_empty() -> Vec<u8> {
    Vec::new()
}

// ── Arity-1 ──────────────────────────────────────────────────────────────

/// `Bytes.length : Bytes -> Int` — the number of bytes in the buffer.
#[must_use]
pub fn bytes_length(b: Vec<u8>) -> i64 {
    b.len() as i64
}

/// `Bytes.isEmpty : Bytes -> Bool`.
#[must_use]
pub fn bytes_is_empty(b: Vec<u8>) -> bool {
    b.is_empty()
}

/// `Bytes.fromString : String -> Bytes` — UTF-8-encode a Ipê string into bytes.
///
/// Every Ipê `String` is valid UTF-8 (the Ipê type system enforces this), so
/// this conversion is total and always succeeds.
#[must_use]
pub fn bytes_from_string(s: String) -> Vec<u8> {
    s.into_bytes()
}

/// `Bytes.toString : Bytes -> Maybe String` — UTF-8-decode bytes into a string.
///
/// Returns `Just s` when the buffer is valid UTF-8, `Nothing` otherwise.
#[must_use]
pub fn bytes_to_string(b: Vec<u8>) -> IpeMaybe<String> {
    match String::from_utf8(b) {
        Ok(s) => IpeMaybe::Just(s),
        Err(_) => IpeMaybe::Nothing,
    }
}

/// `Bytes.fromHex : String -> Maybe Bytes` — decode a hex string into bytes.
///
/// Accepts lowercase and uppercase hex digits. Returns `Nothing` when the
/// input has an odd number of characters or contains any non-hex character.
#[must_use]
pub fn bytes_from_hex(s: String) -> IpeMaybe<Vec<u8>> {
    // Odd-length inputs can never be valid hex (every byte needs two digits).
    if !s.len().is_multiple_of(2) {
        return IpeMaybe::Nothing;
    }
    match hex::decode(&s) {
        Ok(bytes) => IpeMaybe::Just(bytes),
        Err(_) => IpeMaybe::Nothing,
    }
}

/// `Bytes.toHex : Bytes -> String` — hex-encode bytes (lowercase output).
#[must_use]
pub fn bytes_to_hex(b: Vec<u8>) -> String {
    hex::encode(b)
}

/// `Bytes.fromBase64 : String -> Maybe Bytes` — standard (RFC 4648) base-64 decode.
///
/// Returns `Nothing` on invalid padding or non-base-64 characters.
#[must_use]
pub fn bytes_from_base64(s: String) -> IpeMaybe<Vec<u8>> {
    match B64.decode(s.as_bytes()) {
        Ok(bytes) => IpeMaybe::Just(bytes),
        Err(_) => IpeMaybe::Nothing,
    }
}

/// `Bytes.toBase64 : Bytes -> String` — standard (RFC 4648) base-64 encode.
#[must_use]
pub fn bytes_to_base64(b: Vec<u8>) -> String {
    B64.encode(b)
}

// ── Arity-2 ──────────────────────────────────────────────────────────────

/// `Bytes.append : Bytes -> Bytes -> Bytes` — concatenate two byte buffers.
#[must_use]
pub fn bytes_append(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    let mut out = a;
    out.extend_from_slice(&b);
    out
}

// ── Arity-3 ──────────────────────────────────────────────────────────────

/// `Bytes.slice : Int -> Int -> Bytes -> Bytes` — byte-indexed slice.
///
/// Mirrors `String.slice` semantics:
/// - Negative indices count from the end of the buffer.
/// - Out-of-range indices are clamped to the buffer boundaries.
/// - `start >= end` (after normalisation) returns the empty buffer.
///
/// No `panic` / raw indexing — all bounds are validated before slicing.
#[must_use]
pub fn bytes_slice(start: i64, end: i64, b: Vec<u8>) -> Vec<u8> {
    let len = b.len() as i64;

    // Normalise negative indices to their from-end equivalents.
    let norm = |i: i64| -> i64 {
        if i < 0 {
            // e.g. -1 on a 5-byte buffer → 4.  Saturate at 0 if still negative.
            (len + i).max(0)
        } else {
            i.min(len) // clamp to [0, len]
        }
    };

    let s = norm(start) as usize;
    let e = norm(end) as usize;

    if s >= e {
        return Vec::new();
    }
    // Safety: s and e are both ≤ len (clamped above), and s < e.
    // Use `.get(s..e)` to satisfy the no-indexing clippy gate; the bounds
    // check above guarantees this never returns None.
    b.get(s..e).map(<[u8]>::to_vec).unwrap_or_default()
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    // ── empty / length / isEmpty ─────────────────────────────────────────

    #[test]
    fn empty_has_length_zero() {
        let b = bytes_empty();
        assert_eq!(bytes_length(b.clone()), 0);
        assert!(bytes_is_empty(b));
    }

    #[test]
    fn non_empty_is_not_empty() {
        let b = bytes_from_string("hi".to_string());
        assert!(!bytes_is_empty(b.clone()));
        assert_eq!(bytes_length(b), 2);
    }

    // ── fromString / toString ────────────────────────────────────────────

    #[test]
    fn from_string_is_utf8_bytes() {
        let b = bytes_from_string("Hi!".to_string());
        assert_eq!(b, vec![0x48, 0x69, 0x21]);
    }

    #[test]
    fn to_string_roundtrips_ascii() {
        let b = bytes_from_string("Hi!".to_string());
        assert!(matches!(bytes_to_string(b), IpeMaybe::Just(ref s) if s == "Hi!"));
    }

    #[test]
    fn to_string_nothing_on_invalid_utf8() {
        // 0x9e alone is not a valid UTF-8 sequence.
        let b = vec![0x9e_u8];
        assert!(matches!(bytes_to_string(b), IpeMaybe::Nothing));
    }

    // ── fromHex / toHex ─────────────────────────────────────────────────

    #[test]
    fn to_hex_ascii() {
        let b = bytes_from_string("Hi!".to_string());
        assert_eq!(bytes_to_hex(b), "486921");
    }

    #[test]
    fn from_hex_ascii_roundtrip() {
        let b = bytes_from_hex("486921".to_string());
        assert!(matches!(b, IpeMaybe::Just(ref v) if *v == vec![0x48, 0x69, 0x21]));
    }

    #[test]
    fn from_hex_odd_length_nothing() {
        assert!(matches!(
            bytes_from_hex("abc".to_string()),
            IpeMaybe::Nothing
        ));
    }

    #[test]
    fn from_hex_non_hex_char_nothing() {
        assert!(matches!(
            bytes_from_hex("zz".to_string()),
            IpeMaybe::Nothing
        ));
    }

    #[test]
    fn binary_hex_roundtrip() {
        // 0x9e 0xfe — high bytes that are not valid UTF-8.
        let b = bytes_from_hex("9efe".to_string());
        match b {
            IpeMaybe::Just(v) => {
                assert_eq!(v, vec![0x9e, 0xfe]);
                assert_eq!(bytes_to_hex(v), "9efe");
            }
            IpeMaybe::Nothing => panic!("expected Just"),
        }
    }

    // ── fromBase64 / toBase64 ────────────────────────────────────────────

    #[test]
    fn to_base64_ascii() {
        let b = bytes_from_string("Hi!".to_string());
        assert_eq!(bytes_to_base64(b), "SGkh");
    }

    #[test]
    fn from_base64_ascii_roundtrip() {
        let b = bytes_from_base64("SGkh".to_string());
        assert!(matches!(b, IpeMaybe::Just(ref v) if *v == vec![0x48, 0x69, 0x21]));
    }

    #[test]
    fn from_base64_invalid_nothing() {
        assert!(matches!(
            bytes_from_base64("not valid base64!@#".to_string()),
            IpeMaybe::Nothing
        ));
    }

    #[test]
    fn binary_base64_roundtrip() {
        let orig = vec![0x9e_u8, 0xfe_u8];
        let b64 = bytes_to_base64(orig.clone());
        assert_eq!(b64, "nv4=");
        match bytes_from_base64(b64) {
            IpeMaybe::Just(v) => assert_eq!(v, orig),
            IpeMaybe::Nothing => panic!("expected Just"),
        }
    }

    // ── append ───────────────────────────────────────────────────────────

    #[test]
    fn append_two_buffers() {
        let a = bytes_from_string("Hi".to_string());
        let b = bytes_from_string("!".to_string());
        assert_eq!(bytes_append(a, b), vec![0x48, 0x69, 0x21]);
    }

    #[test]
    fn append_with_empty_is_identity() {
        let b = bytes_from_string("Hi!".to_string());
        assert_eq!(bytes_append(b.clone(), bytes_empty()), b);
        assert_eq!(bytes_append(bytes_empty(), b.clone()), b);
    }

    // ── slice ────────────────────────────────────────────────────────────

    #[test]
    fn slice_basic() {
        let b = bytes_from_string("Hello".to_string()); // [72,101,108,108,111]
        // slice(1, 3) -> "el"
        let s = bytes_slice(1, 3, b);
        assert_eq!(s, vec![0x65, 0x6c]); // 'e', 'l'
    }

    #[test]
    fn slice_negative_end() {
        // slice(0, -2) on [H,e,l,l,o] -> [H,e,l] (drops last 2)
        let b = bytes_from_string("Hello".to_string());
        let s = bytes_slice(0, -2, b);
        assert_eq!(s, vec![0x48, 0x65, 0x6c]); // 'H', 'e', 'l'
    }

    #[test]
    fn slice_start_ge_end_is_empty() {
        let b = bytes_from_string("Hi".to_string());
        assert!(bytes_slice(3, 1, b.clone()).is_empty());
        assert!(bytes_slice(2, 2, b).is_empty());
    }

    #[test]
    fn slice_oob_clamped() {
        let b = bytes_from_string("Hi".to_string());
        // start beyond end: clamps to full buffer
        let s = bytes_slice(-100, 100, b.clone());
        assert_eq!(s, vec![0x48, 0x69]);
    }

    // ── 49-bytes-core equivalent ─────────────────────────────────────────
    // Cross-checks the key values the runtime e2e test 49-bytes-core expects.

    #[test]
    fn corpus_ascii_surface() {
        let ascii = bytes_from_string("Hi!".to_string());
        assert_eq!(bytes_to_hex(ascii.clone()), "486921");
        assert_eq!(bytes_to_base64(ascii.clone()), "SGkh");
        assert_eq!(bytes_length(ascii.clone()), 3);
        assert!(matches!(bytes_to_string(ascii), IpeMaybe::Just(ref s) if s == "Hi!"));
    }

    #[test]
    fn corpus_binary_surface() {
        let binary = match bytes_from_hex("9efe".to_string()) {
            IpeMaybe::Just(v) => v,
            IpeMaybe::Nothing => panic!("expected Just"),
        };
        assert_eq!(bytes_to_hex(binary.clone()), "9efe");
        assert_eq!(bytes_to_base64(binary.clone()), "nv4=");
        assert_eq!(bytes_length(binary.clone()), 2);
        assert!(matches!(bytes_to_string(binary.clone()), IpeMaybe::Nothing));

        // round-trip binary through base64 back to hex
        let b64 = bytes_to_base64(binary.clone());
        match bytes_from_base64(b64) {
            IpeMaybe::Just(v) => assert_eq!(bytes_to_hex(v), "9efe"),
            IpeMaybe::Nothing => panic!("expected Just from base64 roundtrip"),
        }
    }
}

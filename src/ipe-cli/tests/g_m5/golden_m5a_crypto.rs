//! `Ipe.Crypto` parity gate — hashes, HMAC, AEAD, key-derivation,
//! constant-time comparison, and random primitives.
//!
//! Every test compiles a Ipê program through `ipe`, builds the emitted Rust
//! project with the shared cargo target, runs the binary, and asserts its stdout
//! matches the cached oracle (`tests/golden/m5a_crypto_*/expected_go.txt`).
//! All tests are gated on `IPE_E2E=1`; without it they return early.
//!
//! ## Golden catalogue
//!
//! * `crypto_sha_hash` — `sha256` / `sha512` / `sha1` / `md5` of `"abc"`;
//!   known standard test vectors; byte-identical output.
//!
//! * `crypto_hmac` — `hmacSha256` / `hmacSha512` (typed, `Key` argument) with
//!   RFC 4231 case-1 key (`0x0b × 20` via `keyFromBytes`) and message `"Hi
//!   There"`; known test vectors; byte-parity.
//!
//! * `crypto_constant_time` — `constantTimeEqual "abc" "abc"` → `true`;
//!   `constantTimeEqual "abc" "abd"` → `false`.
//!
//! * `crypto_aes_roundtrip` — `aesGcmEncrypt` then `aesGcmDecrypt` recovers
//!   the plaintext.  Nonce is random so ciphertext differs per run; only `"ok"`
//!   is checked.
//!
//! * `crypto_chacha_roundtrip` — `chacha20Encrypt` then `chacha20Decrypt`
//!   recovers the plaintext.  Same round-trip shape as AES.
//!
//! * `crypto_keyfrompassword` — `aesKeyFromPassword` is deterministic:
//!   derive the key twice; encrypt with the first, decrypt with the second;
//!   both keys must agree.
//!
//! * `crypto_random_bytes` — `Crypto.randomBytes 16` compiles and the
//!   program exits cleanly (`"ok"`).
//!
//! * `crypto_random_token` — `Crypto.randomToken 8` compiles and the
//!   program exits cleanly (`"ok"`).
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m5a
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe`, build the emitted Cargo project,
/// run it, and assert its stdout matches the cached oracle.  Gated on
/// `IPE_E2E=1`.
fn assert_runs_and_matches_oracle(name: &str) {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = crate::support::expect_runtime(name, ipe::resolve_runtime());
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

// ── sha256 / sha512 / sha1 / md5 ────────────────────────────────────────────

/// `Crypto.sha256 "abc"` → the standard SHA-256 hex digest; likewise for
/// sha512, sha1, and md5.  All four values are well-known test vectors and are
/// byte-for-byte identical to the well-known test vectors.
#[test]
fn crypto_sha_hash() {
    assert_runs_and_matches_oracle("crypto_sha_hash");
}

// ── HMAC-SHA256 / HMAC-SHA512 ────────────────────────────────────────────────

/// `Crypto.hmacSha256 key "Hi There"` and `Crypto.hmacSha512 key "Hi There"`
/// with the RFC 4231 test-case-1 key (`0x0b` × 20, constructed via
/// `Crypto.keyFromBytes`) produce the standard known MAC values (RFC 4231
/// test vectors).
#[test]
fn crypto_hmac() {
    assert_runs_and_matches_oracle("crypto_hmac");
}

// ── constantTimeEqual ────────────────────────────────────────────────────────

/// `Crypto.constantTimeEqual "abc" "abc"` → `"true"`;
/// `Crypto.constantTimeEqual "abc" "abd"` → `"false"`.
/// Output: `"true false"`.
#[test]
fn crypto_constant_time() {
    assert_runs_and_matches_oracle("crypto_constant_time");
}

// ── AES-GCM round-trip ───────────────────────────────────────────────────────

/// `Crypto.aesGcmEncrypt key plaintext` followed by `Crypto.aesGcmDecrypt key
/// ciphertext` recovers the original plaintext.  The nonce is random so the
/// ciphertext differs each run; only `"ok"` is asserted.
#[test]
fn crypto_aes_roundtrip() {
    assert_runs_and_matches_oracle("crypto_aes_roundtrip");
}

// ── ChaCha20-Poly1305 round-trip ─────────────────────────────────────────────

/// `Crypto.chacha20Encrypt key plaintext` followed by `Crypto.chacha20Decrypt
/// key ciphertext` recovers the original plaintext.  Nonce is random; only
/// `"ok"` is asserted.
#[test]
fn crypto_chacha_roundtrip() {
    assert_runs_and_matches_oracle("crypto_chacha_roundtrip");
}

// ── Key-from-password determinism ────────────────────────────────────────────

/// `Crypto.aesKeyFromPassword` is deterministic: deriving the key twice from
/// the same password and salt produces the same bytes.  Encrypt with key1 and
/// decrypt with independently-derived key2; if they match, the round-trip
/// succeeds and `"ok"` is printed.
#[test]
fn crypto_keyfrompassword() {
    assert_runs_and_matches_oracle("crypto_keyfrompassword");
}

// ── randomBytes ──────────────────────────────────────────────────────────────

/// `Crypto.randomBytes 16` compiles and the program exits cleanly.  The result
/// is discarded; `"ok"` is printed.
#[test]
fn crypto_random_bytes() {
    assert_runs_and_matches_oracle("crypto_random_bytes");
}

// ── randomToken ──────────────────────────────────────────────────────────────

/// `Crypto.randomToken 8` compiles and the program exits cleanly.  The result
/// is discarded; `"ok"` is printed.
#[test]
fn crypto_random_token() {
    assert_runs_and_matches_oracle("crypto_random_token");
}

// ── String-as-key type-error seals ───────────────────────────────────────────

/// Compile `tests/golden/<name>/Main.ipe` and assert `ipe` REJECTS it — the
/// program passes a bare `String` where a typed `Key` is required (or treats a
/// derived `Key` as a `String`), which must be a compile-time type error.  Not
/// gated on `IPE_E2E`: rejection happens at type-check, before any emit/build.
fn assert_rejected(name: &str) {
    let root = repo_root();
    let entry = golden_dir(&root, name).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = crate::support::expect_runtime(name, ipe::resolve_runtime());
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_err(),
        "{name}: a raw-String-key crypto call must be a type error, but ipe accepted it: {built:?}"
    );
}

/// Passing a bare `String` where `Crypto.hmacSha256` expects a `Key` is a
/// compile-time type error — the `Key` newtype makes message-as-key impossible.
#[test]
fn crypto_hmac_string_key_is_type_error() {
    assert_rejected("crypto_hmac_string_key_rejected");
}

/// `aesGcmEncrypt` requires a `Key`; a bare `String` in the key position is a
/// compile-time type error, so plaintext/password-as-key is unrepresentable.
#[test]
fn crypto_aesgcm_encrypt_string_key_is_type_error() {
    assert_rejected("crypto_aesgcm_encrypt_string_key_rejected");
}

/// `aesGcmDecrypt` requires a `Key`; a bare `String` in the key position is a
/// compile-time type error.
#[test]
fn crypto_aesgcm_decrypt_string_key_is_type_error() {
    assert_rejected("crypto_aesgcm_decrypt_string_key_rejected");
}

/// `chacha20Encrypt` requires a `Key`; a bare `String` in the key position is a
/// compile-time type error.
#[test]
fn crypto_chacha20_encrypt_string_key_is_type_error() {
    assert_rejected("crypto_chacha20_encrypt_string_key_rejected");
}

/// `chacha20Decrypt` requires a `Key`; a bare `String` in the key position is a
/// compile-time type error.
#[test]
fn crypto_chacha20_decrypt_string_key_is_type_error() {
    assert_rejected("crypto_chacha20_decrypt_string_key_rejected");
}

/// `aesKeyFromPassword` returns an opaque `Key`, never a raw `String`; using the
/// derived value as a `String` is a compile-time type error, so a derived key
/// cannot leak into logs or flow into a `String`-typed sink.
#[test]
fn crypto_aeskeyfrompassword_returns_key_not_string() {
    assert_rejected("crypto_aeskeyfrompassword_returns_key_not_string");
}

/// `chachaKeyFromPassword` returns an opaque `Key`, never a raw `String`; using
/// the derived value as a `String` is a compile-time type error.
#[test]
fn crypto_chachakeyfrompassword_returns_key_not_string() {
    assert_rejected("crypto_chachakeyfrompassword_returns_key_not_string");
}

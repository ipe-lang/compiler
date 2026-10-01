//! `Ipe.Encoding` parity gate — base64 / URL / hex encode-decode
//! kernels with byte-for-byte golden parity.
//!
//! These golden tests exercise the `Ipe.Encoding` kernel family end-to-end:
//!
//! * `Encoding.base64Encode` / `Encoding.base64Decode` roundtrip (standard
//!   alphabet with `=` padding, NOT URL-safe):
//!   `"hello"` → `"aGVsbG8="` → `"hello"` → `"aGVsbG8= hello"`.
//!   (`encoding_base64`)
//!
//! * `Encoding.urlEncode` / `Encoding.urlDecode` roundtrip (`QueryEscape`
//!   semantics: space → `+`, `&` → `%26`):
//!   `"a b&c"` → `"a+b%26c"` → `"a b&c"` → `"a+b%26c a b&c"`.
//!   (`encoding_url`)
//!
//! * `Encoding.urlEncode` over the ASCII unreserved set: leaves `A-Za-z0-9`
//!   plus the four marks `-` `_` `.` `~` verbatim while escaping `+` → `%2B`
//!   and `@` → `%40`. Pins parity over both shapes.
//!   (`encoding_url_unreserved`)
//!
//! * `Encoding.percentDecode` (RFC 3986: `+` stays literal) against
//!   `Encoding.urlDecode` (form: `+` → space), plus the malformed-escape
//!   refusals `%zz` and a truncated `%2`: `"a+b|+|/t/a+b.db|a b|refused|refused"`.
//!   (`encoding_percent`)
//!
//! * `Encoding.hexEncode` / `Encoding.hexDecode` roundtrip — lowercase hex:
//!   `"Hi!"` → `"486921"` → `"Hi!"` → `"486921 Hi!"`.
//!   (`encoding_hex`)
//!
//! * `Encoding.base64Decode` of an invalid input → `Err _` branch taken →
//!   `"invalid"` (`encoding_invalid`).
//!
//! * `Encoding.base64Encode` / `hexEncode` over non-ASCII text → golden-verified
//!   UTF-8 bytes (`encoding_nonascii`).
//!
//! ## Oracle-divergence flags (per golden)
//!
//! The ENCODE roundtrips (`encoding_base64`, `encoding_url`,
//! `encoding_url_unreserved`, `encoding_hex`, `encoding_nonascii`)
//! carry `oracle_divergence = false`: the `Encoding.*` text codecs encode a
//! String's UTF-8 bytes, byte-identical to the golden reference for BOTH ASCII and
//! non-ASCII (no Latin-1 truncation).
//!
//! `encoding_invalid` carries `oracle_divergence = true` (upstream-failure kind):
//! a prior backend panicked with `CoerceFailure` when narrowing the `Result` of a
//! decode kernel inside a top-level `case … of Ok _ … Err _ …`, so it could not
//! produce a reference for this shape. Ipê handles it correctly (`"invalid"`),
//! which `refresh-oracle` caches. TRACKED: re-verify this golden against the live
//! oracle once the upstream CoerceFailure-on-decode-Result narrowing is fixed
//! (`refresh-oracle encoding_invalid`) — the flag should flip back to `false`.
//! The base64/url/hex DECODE oracles decode from a let-bound `case` whose `Err _`
//! arm yields a String literal (a different routing shape), so they stay
//! parity-clean — re-verified against the live oracle.
//!
//! Every test is gated on `IPE_E2E=1`; without it the test returns early. Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m4f
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe`, build the emitted Cargo project,
/// run it, and assert its stdout matches the cached oracle.  Gated on
/// `IPE_E2E=1`.
fn assert_runs_and_matches_oracle(name: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

// ── base64Encode + base64Decode ──────────────────────────────────────────────

/// `Encoding.base64Encode "hello"` → `"aGVsbG8="`; `Encoding.base64Decode
/// "aGVsbG8="` → `Ok "hello"`.  Output: `"aGVsbG8= hello"`.
#[test]
fn encoding_base64_roundtrip() {
    assert_runs_and_matches_oracle("encoding_base64");
}

// ── urlEncode + urlDecode ────────────────────────────────────────────────────

/// `Encoding.urlEncode "a b&c"` → `"a+b%26c"` (`QueryEscape`: space → `+`);
/// `Encoding.urlDecode "a+b%26c"` → `Ok "a b&c"`.  Output: `"a+b%26c a b&c"`.
#[test]
fn encoding_url_roundtrip() {
    assert_runs_and_matches_oracle("encoding_url");
}

/// `Encoding.urlEncode "a-b_c.d~e"` → `"a-b_c.d~e"` (unreserved set verbatim);
/// `Encoding.urlEncode "user+name@example.com"` → `"user%2Bname%40example.com"`
/// (`+` → `%2B`, `@` → `%40`).  Locks the `QueryEscape` unreserved set.
#[test]
fn encoding_url_unreserved() {
    assert_runs_and_matches_oracle("encoding_url_unreserved");
}

// ── percentDecode ────────────────────────────────────────────────────────────

/// `Encoding.percentDecode` keeps `+` literal (`"a+b"`, `"/t/a+b.db"`) and
/// decodes `%2B` → `+`, where `Encoding.urlDecode "a+b"` → `"a b"`; `%zz` and a
/// truncated `%2` are refused.  Output: `"a+b|+|/t/a+b.db|a b|refused|refused"`.
#[test]
fn encoding_percent_keeps_plus_and_refuses_malformed() {
    assert_runs_and_matches_oracle("encoding_percent");
}

// ── hexEncode + hexDecode ────────────────────────────────────────────────────

/// `Encoding.hexEncode "Hi!"` → `"486921"` (lowercase hex, golden parity);
/// `Encoding.hexDecode "486921"` → `Ok "Hi!"`.  Output: `"486921 Hi!"`.
#[test]
fn encoding_hex_roundtrip() {
    assert_runs_and_matches_oracle("encoding_hex");
}

// ── non-ASCII byte-model divergence ──────────────────────────────────────────

/// `Encoding.base64Encode "café"` / `hexEncode "café"` over non-ASCII text.
/// Recorded `divergence:` — the Rust runtime's Latin-1 char-as-byte model
/// differs for codepoints ≥ 0x80 (Latin-1 vs UTF-8 byte model).  Expected holds
/// the Ipê-Rust output (`café Y2Fm6Q== 636166e9`); see divergence-policy.md.
#[test]
fn encoding_nonascii() {
    assert_runs_and_matches_oracle("encoding_nonascii");
}

// ── base64Decode of invalid input ────────────────────────────────────────────

/// `Encoding.base64Decode "not-valid-base64!!"` → `Err _`.  Output: `"invalid"`.
#[test]
fn encoding_base64_invalid() {
    assert_runs_and_matches_oracle("encoding_invalid");
}

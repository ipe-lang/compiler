//! `Ipe.Bytes` parity gate — `Bytes` as a distinct `Vec<u8>` primitive.
//!
//! These golden tests exercise the `Ipe.Bytes` kernel family end-to-end:
//!
//! * `Bytes.length` / `Bytes.isEmpty` on `Bytes.empty` and a non-empty buffer
//!   → `"0 5 1 0"` (`bytes_length`)
//! * `Bytes.toHex` / `Bytes.fromHex` roundtrip, including a non-UTF-8 buffer
//!   → `"486921 486921 9efe"` (`bytes_hex`)
//! * `Bytes.toBase64` / `Bytes.fromBase64` roundtrip, including a non-UTF-8 buffer
//!   → `"SGkh 486921 nv4="` (`bytes_base64`)
//! * `Bytes.toString` (UTF-8 decode — `Just` for ASCII, `Nothing` for binary)
//!   + `Bytes.append` → `"Hi! <invalid> 486921486921"` (`bytes_roundtrip`)
//! * `Bytes.slice` — half-open interval, clamp on out-of-bounds, empty on
//!   zero-length range → `"656c6c 0 4"` (`bytes_slice`)
//!
//! All five goldens carry `oracle_divergence = true` because Ipê-Rust maps
//! `Bytes` to `Vec<u8>` for proper lossless arbitrary-binary handling under
//! Rust's UTF-8-constrained `String` (a sanctioned divergence). See
//! `docs/architecture/divergence-policy.md`.
//!
//! Every test is gated on `IPE_E2E=1`; without it the test returns early. Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m4e
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

// ── Bytes.length + Bytes.isEmpty ─────────────────────────────────────────────

/// `Bytes.length Bytes.empty` → 0; `Bytes.length (Bytes.fromString "Hello")` → 5;
/// `Bytes.isEmpty Bytes.empty` → 1 (true); `Bytes.isEmpty (Bytes.fromString "x")`
/// → 0 (false).  Output: `"0 5 1 0"`.
#[test]
fn bytes_length_and_is_empty() {
    assert_runs_and_matches_oracle("bytes_length");
}

// ── Bytes.toHex + Bytes.fromHex ───────────────────────────────────────────────

/// Hex encode/decode roundtrip: `"Hi!" → "486921"`, decode `"486921" → "486921"`,
/// non-UTF-8 buffer `"9efe"` survives hex roundtrip unchanged.
/// Output: `"486921 486921 9efe"`.
#[test]
fn bytes_hex_roundtrip() {
    assert_runs_and_matches_oracle("bytes_hex");
}

// ── Bytes.toBase64 + Bytes.fromBase64 ────────────────────────────────────────

/// Base-64 encode/decode roundtrip: `"Hi!" → "SGkh"`, decode `"SGkh" → "486921"`,
/// non-UTF-8 `[0x9e, 0xfe]` base-64 round-trips as `"nv4="`.
/// Output: `"SGkh 486921 nv4="`.
#[test]
fn bytes_base64_roundtrip() {
    assert_runs_and_matches_oracle("bytes_base64");
}

// ── Bytes.toString — UTF-8 decode ────────────────────────────────────────────

/// `Bytes.toString (Bytes.fromString "Hi!")` → `Just "Hi!"`; binary `[0x9e,
/// 0xfe]` → `Nothing`; `Bytes.append` of two `"Hi!"` buffers → hex
/// `"486921486921"`.  Output: `"Hi! <invalid> 486921486921"`.
#[test]
fn bytes_roundtrip_and_append() {
    assert_runs_and_matches_oracle("bytes_roundtrip");
}

// ── Bytes.slice ───────────────────────────────────────────────────────────────

/// `Bytes.slice 1 4 "Hello!"` → hex `"656c6c"` (`"ell"`); `slice 3 3` → 0
/// bytes; `slice 2 100` clamps to buffer end → 4 bytes.
/// Output: `"656c6c 0 4"`.
#[test]
fn bytes_slice() {
    assert_runs_and_matches_oracle("bytes_slice");
}

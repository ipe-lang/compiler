//! `Ipe.Codec` round-trip soundness gate.
//!
//! Proves the design's core guarantee — `fromJson codec (toJson codec x) == Ok
//! x` — for a representative value type that exercises every codec shape at
//! once: a nested record, a `Maybe`, a `List`, a nullary `enum`, a
//! data-carrying tagged union, and a lossless `Decimal`. The fixture also
//! asserts the two failure paths: malformed JSON decodes to a typed `Err`
//! (never a panic), and `fromJsonSafe` rejects oversize input before decoding.
//!
//! The fixture prints a single `codec-roundtrip-ok` line iff all three hold, so
//! the oracle is one line and any regression flips it to `-FAIL` (or a decode
//! error), failing the seal loudly.
//!
//! Gated on `IPE_E2E=1` (build-and-run); without it the test returns early.
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test g_m4 golden_codec_roundtrip
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe`, build the emitted Cargo project, run
/// it, and assert its stdout matches the cached oracle. Gated on `IPE_E2E=1`.
fn assert_runs_and_matches_oracle(name: &str) {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

/// The whole codec surface (invariant `Codec`, `map` bijection, primitives,
/// inline object/enum/union codecs, `fromJson`/`fromJsonSafe`) round-trips a
/// representative value and rejects malformed + oversize input.
/// Output: `codec-roundtrip-ok`.
#[test]
fn codec_roundtrip() {
    assert_runs_and_matches_oracle("codec_roundtrip");
}

/// `Codec.auto` derives a record codec (scalar fields, a `List` field, a nested
/// record) that both round-trips AND encodes byte-identically to the equivalent
/// hand-written direct-form codec — the type-driven derive adds no emit the
/// hand-written codec does not already exercise (THE SEAL by construction).
/// Output: `codec-auto-ok`.
#[test]
fn codec_auto() {
    assert_runs_and_matches_oracle("codec_auto");
}

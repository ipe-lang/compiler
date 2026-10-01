//! `Ipe.Codec` DB-shape gate.
//!
//! Proves the storage half of the invariant codec: every codec carries a
//! dialect-neutral `Shape`, so one codec drives the JSON round-trip AND the DB
//! column list. The fixture asserts, in one program:
//!
//! * scalar codecs report their `SScalar` column type; a `maybe` over a scalar
//!   reports a NULLABLE column (`CNull`); a `list`/`dict` reports a blob;
//! * a direct-form record codec reports its `SRecord` column list (the same keys
//!   the JSON round-trip uses) and round-trips a value;
//! * `decimal` and `money` round-trip LOSSLESSLY (a value a `Float` would
//!   corrupt); `decimal` uses a `CDecimal` column, `money` uses a `CMoney` column.
//!
//! The fixture prints one `codec-shape-ok` line iff every fact holds, so the
//! oracle is one line and any regression flips it loudly.
//!
//! Gated on `IPE_E2E=1` (build-and-run); without it the test returns early.
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test g_m4 golden_codec_shape
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe`, build the emitted Cargo project, run
/// it, and assert its stdout matches the cached oracle. Gated on `IPE_E2E=1`.
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

/// Accept + emit gate (always): the DB-shape program must be accepted and
/// lowered. A resolution/type/lower regression fails HERE, in the fast path.
#[test]
fn codec_shape_accepts_and_emits() {
    let root = repo_root();
    let entry = golden_dir(&root, "codec_shape").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_codec_shape_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "the `Ipe.Codec` DB-shape surface must be accepted + emitted, got: {built:?}"
    );
}

/// The DB-shape surface (`Shape`/`ColType`, `shape`, `columnOf`, nullable
/// columns, `decimal` → `CDecimal`, `money` → `CMoney`) reports the expected columns and
/// round-trips a record and both exact-decimal scalars.
/// Output: `codec-shape-ok`.
#[test]
fn codec_shape() {
    assert_runs_and_matches_oracle("codec_shape");
}

/// Prove-the-refusal for the `Timestamp` role behind `CTime`: a field typed
/// `reviewedAt : Timestamp` filled with a raw `Int` millis is a type mismatch
/// (`IPE_T0001`), rejected at type-check with no Rust emitted. The role lives in
/// the type — a bare count is not a moment in time — so the swap `Codec.timestamp`
/// / `SqlTime` would otherwise silently accept has no representation.
#[test]
fn codec_timestamp_role_rejects_raw_int() {
    let root = repo_root();
    let entry = golden_dir(&root, "codec_timestamp_role_reject").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_codec_timestamp_role_reject_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(ipe::CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0001),
        "a raw Int where a Timestamp is expected must be IPE_T0001, got: {built:?}"
    );

    let emitted = out.join("src").join("main.rs");
    assert!(
        !emitted.exists(),
        "no Rust must be emitted on a type-check failure, but {} exists",
        emitted.display()
    );
}

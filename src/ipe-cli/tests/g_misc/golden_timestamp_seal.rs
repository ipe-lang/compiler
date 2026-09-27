//! SEAL: a program that constructs a `Timestamp` via `fromUnixMillis`, shifts it
//! with `Timestamp.add`, and measures the span with `Timestamp.diff` must compile
//! and produce the expected output.
//!
//! This is the load-bearing proof that `Timestamp` and `Duration` are distinct
//! types whose operations compose correctly end-to-end.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("timestamp_seal")
        .join("Main.ipe")
}

/// Emit-only gate: the seal program must be accepted by the compiler.
#[test]
fn timestamp_seal_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("timestamp_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "timestamp_seal: must compile cleanly; got: {built:?}"
    );
}

/// E2E SEAL: compile, cargo-build, run, assert expected output.
/// Gated on `IPE_E2E=1`.
#[test]
fn timestamp_seal_builds_and_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_timestamp_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "timestamp_seal: build must succeed: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("timestamp_seal", &out);
    crate::support::assert_go_parity(
        "timestamp_seal",
        &root.join("tests").join("golden").join("timestamp_seal"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

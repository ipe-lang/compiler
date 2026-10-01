//! `Timestamp` arithmetic gate: the typed `Ipe.Time.Timestamp` + `Ipe.Duration`
//! surface compiles and round-trips correctly.
//!
//! `Timestamp.add (Duration.seconds 30) base` shifts the instant by 30 s;
//! `Timestamp.diff shifted base` recovers the 30 000 ms span.
//! Both are pure compile-time operations backed by the opaque newtype — no
//! runtime kernel involved, so the test is fast and deterministic.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("timestamp_arithmetic")
        .join("Main.ipe")
}

/// Emit-only gate: the frontend must accept the typed Timestamp arithmetic
/// program (no type mismatch, no missing-import, clean emit).
#[test]
fn timestamp_arithmetic_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("timestamp_arithmetic_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "timestamp_arithmetic: typed Timestamp+Duration arithmetic must emit cleanly; got: {built:?}"
    );
}

/// E2E: build the emitted Cargo project and assert the output matches the
/// expected round-trip values. Gated on `IPE_E2E=1`.
#[test]
fn timestamp_arithmetic_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_timestamp_arithmetic_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "timestamp_arithmetic: build must succeed: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("timestamp_arithmetic", &out);
    crate::support::assert_go_parity(
        "timestamp_arithmetic",
        &root
            .join("tests")
            .join("golden")
            .join("timestamp_arithmetic"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

//! Round-trip gate for `Time.fromMillis` / `Time.toMillis`.
//!
//! `Time.fromMillis ms |> Time.toMillis` must equal `ms` (identity law).
//! `Time.add (Duration.seconds 5) t |> Time.toMillis` must equal `ms + 5000`
//! (shift law).  `Time.diff shifted t |> Duration.toMillis` must equal `5000`
//! (diff law).
//!
//! All three verify the parse-boundary (`fromMillis`) and unparse-boundary
//! (`toMillis`) at the `Ipe.Time` module surface, complementing the lower-level
//! `Ipe.Time.Timestamp` tests that cover the same laws via the `Timestamp`
//! module directly.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("time_from_to_millis")
        .join("Main.ipe")
}

/// Emit-only gate: `Time.fromMillis` / `Time.toMillis` must be accepted by
/// the compiler (no unknown-member, no type error).
#[test]
fn time_from_to_millis_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("time_from_to_millis_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "time_from_to_millis: Time.fromMillis/toMillis must emit cleanly; got: {built:?}"
    );
}

/// E2E: build the emitted project and assert the round-trip output.
/// Gated on `IPE_E2E=1`.
#[test]
fn time_from_to_millis_builds_and_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_time_from_to_millis_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "time_from_to_millis: build must succeed: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("time_from_to_millis", &out);
    crate::support::assert_go_parity(
        "time_from_to_millis",
        &root
            .join("tests")
            .join("golden")
            .join("time_from_to_millis"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

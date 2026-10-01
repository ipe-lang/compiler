//! Type-safety proof for `Timestamp` / `Duration` distinctness.
//!
//! `Timestamp.add` has type `Duration -> Timestamp -> Timestamp`.  Passing a
//! second `Timestamp` in place of the required `Duration` is a type mismatch
//! (IPE-T0001).  This test proves that the confusable combination — adding two
//! instants together — does NOT typecheck, so the Ipê type system enforces the
//! semantic distinction at compile time.

use std::path::PathBuf;

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// The negative fixture: `Timestamp.add other base` where both `other` and
/// `base` are `Timestamp` values — the first argument must be `Duration`.
#[test]
fn adding_two_timestamps_is_ipe_t0001() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("timestamp_add_two_ts_rejected")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("timestamp_add_two_ts_rejected_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    let got_code = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got_code,
        Some(ipe_diagnostics::IPE_T0001),
        "adding two Timestamps must be a type mismatch (IPE-T0001); \
         got build result: {built:?}"
    );
}

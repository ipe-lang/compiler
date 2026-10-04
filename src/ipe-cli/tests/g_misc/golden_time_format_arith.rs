//! End-to-end gate: the six newly registered `Ipe.Time` kernels —
//! `format`, `formatHTTP`, `formatISO8601`, `formatRFC3339`, `addMillis`,
//! `diffMillis` — must be accepted by `ipe` and (behind `IPE_E2E=1`) the
//! emitted project must build and print the expected fixed-timestamp output.
//!
//! A fixed epoch-ms is used (2023-11-14 22:13:20 UTC) so the test is
//! deterministic without reading the system clock.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("time_format_arith")
        .join("Main.ipe")
}

#[test]
fn time_format_arith_accepted_by_ipe() {
    let root = repo_root();
    let entry = entry(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("time_format_arith_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe must accept the time format/arith program: {:?}",
        built.err()
    );
}

/// Full spine: compile, build the emitted Cargo project, run it, and assert
/// the six Time kernels produce the expected fixed-timestamp output.
/// Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn time_format_arith_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry(&root);
    let out = crate::support::scratch_root().join("ipec_time_format_arith_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("time_format_arith", &out);
    crate::support::assert_go_parity(
        "time_format_arith",
        &root.join("tests").join("golden").join("time_format_arith"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

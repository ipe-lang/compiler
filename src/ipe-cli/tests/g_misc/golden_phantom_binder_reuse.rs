//! Phantom-typed binder reuse gate: a `let` binder whose type keeps a variable
//! the solver left unconstrained, read twice.
//!
//! `e = Result.mapError String.length (Err "boom")` leaves the `Ok` payload
//! phantom. The ownership disciplines classify it through a defaulted stand-in
//! that never reaches emission. `ipe` must emit `main.rs` byte-identical to the
//! checked-in golden, and (behind `IPE_E2E=1`) the emitted project must build
//! and print its `expected.txt`.
use std::path::{Path, PathBuf};

use crate::support::repo_root;

const MAP_ERROR_GOLDEN: &str = "phantom_map_error_binder_reuse";

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Emit `name`'s `Main.ipe` and byte-compare it against the golden dir.
fn assert_emits_golden(name: &str) {
    let root = repo_root();
    let dir = golden_dir(&root, name);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve: {:?}", runtime.err());
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&dir.join("Main.ipe"), &out, &runtime);
    assert!(built.is_ok(), "{name}: build failed: {:?}", built.err());

    crate::support::assert_emitted_project_matches_golden_dir(&out, &dir);
}

/// Build and run `name`'s emitted project and check its stdout, behind `IPE_E2E=1`.
fn assert_runs_golden(name: &str) {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = golden_dir(&root, name);
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&dir.join("Main.ipe"), &out, &runtime);
    assert!(built.is_ok(), "{name}: build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "{name}: exit 0");
}

#[test]
fn map_error_binder_emits_byte_identical_main_rs() {
    assert_emits_golden(MAP_ERROR_GOLDEN);
}

#[test]
fn map_error_binder_end_to_end_prints_err_twice() {
    assert_runs_golden(MAP_ERROR_GOLDEN);
}

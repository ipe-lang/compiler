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

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = crate::support::build_golden(&dir, &out, &runtime);
    assert!(built.is_ok(), "{name}: build failed: {:?}", built.err());

    crate::support::assert_emitted_project_matches_golden_dir(&out, &dir);
}

/// Build and run `name`'s emitted project and check its stdout, behind `IPE_E2E=1`.
fn assert_runs_golden(name: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = golden_dir(&root, name);
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&dir, &out, &runtime);
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

/// The phantom `Ok` payload reads as `JsonVal` in `Result.mapError`'s pin, but
/// an argument names that parameter, so the pin never renders: the emitted
/// project must not pull the JSON aliases or the `json` runtime feature in.
#[test]
fn map_error_binder_unrendered_pin_pulls_in_no_json() {
    let root = repo_root();
    let dir = golden_dir(&root, MAP_ERROR_GOLDEN);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("phantom_map_error_no_json_emit");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&dir, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());
    let main_rs = std::fs::read_to_string(out.join("src").join("main.rs")).unwrap_or_default();
    assert!(!main_rs.is_empty(), "main.rs was not emitted");
    for json in ["JsonVal", "Decoder<", "ipe_runtime::json"] {
        assert!(!main_rs.contains(json), "main.rs names `{json}`");
    }
    let manifest = std::fs::read_to_string(out.join("Cargo.toml")).unwrap_or_default();
    assert!(!manifest.is_empty(), "Cargo.toml was not emitted");
    assert!(
        !manifest.contains("\"json\""),
        "Cargo.toml selects the `json` feature"
    );
}

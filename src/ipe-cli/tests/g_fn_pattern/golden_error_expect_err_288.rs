//! E2E — the `Ipe.Error` inspector surface (`Error.kind` / `Error.message` /
//! `Error.kindName`) is reachable from compiled Ipê source and drives
//! `Ipe.Test.expectErr` / `Ipe.Test.kindName`.
//!
//! The golden program constructs classified errors, inspects each error's kind
//! and message, renders a kind's stable label, and asserts an expected kind via
//! `Test.expectErr`. All three tests pass, so the emitted binary prints the
//! summary line and exits 0 — proving the inspectors round-trip through the
//! real `ipe_runtime::error::IpeError` enum end to end.
//!
//! Gated on `IPE_E2E=1`. Run:
//! `IPE_E2E=1 cargo test -p ipe --test golden_error_expect_err_288`.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

fn compile_golden(name: &str) -> PathBuf {
    let root = repo_root();
    let entry = golden_dir(&root, name).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());
    out
}

/// The inspector-driven `Test.runMain` program compiles, runs, prints the
/// pass/fail summary for three passing tests, and exits 0.
#[test]
fn error_inspectors_drive_expect_err() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_golden("error_expect_err_288");
    let out = crate::support::build_and_run_emitted("error_expect_err_288", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "expected a clean exit; got {:?}",
        out.exit_code
    );
    assert_eq!(out.stdout.trim(), "3 passed, 0 failed (3 total)");
}

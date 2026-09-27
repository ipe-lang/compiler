//! Regression — `Ipe.Test.runMain` must print the pass/fail SUMMARY line
//! to stdout, matching the golden reference.
//!
//! `Ipe.Test.summarise` prints exactly one line,
//! `"<pass> passed, <fail> failed (<total> total)"`, before `runMain` picks the
//! exit code. The Rust fork's `summarise` was simplified to a pure predicate
//! with NO output, so a `Test.runMain tests` program (e.g. example
//! `00-standard-libs`) exited 0 with EMPTY stdout — a stdout divergence from the
//! golden oracle. This test pins the summary line so the divergence cannot return.
//!
//! Gated on `IPE_E2E=1`. Run:
//! `IPE_E2E=1 cargo test -p ipe --test golden_test_summary_line_219`.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
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

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else {
        return out;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());
    out
}

fn e2e_enabled() -> bool {
    std::env::var("IPE_E2E").is_ok()
}

/// A `Test.runMain` program with three passing tests prints the summary line
/// and exits 0.
#[test]
fn test_runmain_prints_summary_line() {
    if !e2e_enabled() {
        return;
    }
    let dir = compile_golden("test_summary_line_219");
    let out = crate::support::build_and_run_emitted("test_summary_line_219", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "expected a clean exit; got {:?}",
        out.exit_code
    );
    assert_eq!(out.stdout.trim(), "3 passed, 0 failed (3 total)");
}

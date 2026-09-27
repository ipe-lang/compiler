//! The `Result.toMaybe` / `Result.fromMaybe` bridges are CALLABLE from user
//! code and produce Elm-matching results.
//!
//! Exercises both in one program (`tests/golden/result_bridges/Main.ipe`),
//! building and running the emitted binary and asserting the stdout line — the
//! SEAL guarantee plus behaviour parity with `elm/core`'s `Result`.
//!
//! Gated on `IPE_E2E=1`. Run:
//! `IPE_E2E=1 cargo test -p ipe --test golden_result_bridges`.

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

#[test]
fn result_bridges_run_with_parity() {
    if !e2e_enabled() {
        return;
    }
    let dir = compile_golden("result_bridges");
    let out = crate::support::build_and_run_emitted("result_bridges", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "expected a clean exit; got {:?}",
        out.exit_code
    );
    // toMaybe (Ok 5) → Just 5 (=5); toMaybe (Err _) → Nothing (default 0);
    // fromMaybe _ (Just 7) → Ok 7 (=7); fromMaybe _ Nothing → Err (default 99).
    assert_eq!(out.stdout.trim(), "5 0 7 99");
}

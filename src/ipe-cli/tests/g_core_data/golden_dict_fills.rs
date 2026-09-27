//! The `elm/core` Dict fills (`singleton` / `update` / `foldr` / `filter` /
//! `partition` / `intersect` / `diff`) are CALLABLE from user code and produce
//! Elm-matching results.
//!
//! Exercises all seven in one program (`tests/golden/dict_fills/Main.ipe`),
//! building and running the emitted binary and asserting the stdout line.
//!
//! Gated on `IPE_E2E=1`. Run:
//! `IPE_E2E=1 cargo test -p ipe --test golden_dict_fills`.

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
fn dict_fills_run_with_parity() {
    if !e2e_enabled() {
        return;
    }
    let dir = compile_golden("dict_fills");
    let out = crate::support::build_and_run_emitted("dict_fills", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "expected a clean exit; got {:?}",
        out.exit_code
    );
    // foldr sum=10; filter even size=2; partition (>2) big size=2;
    // intersect size=2; diff size=2; singleton size=1;
    // update "a" bump → 101; update "new" bump (absent) → 1.
    assert_eq!(out.stdout.trim(), "10 2 2 2 2 1 101 1");
}

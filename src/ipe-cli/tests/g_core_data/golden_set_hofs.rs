//! The `elm/core` Set HOF fills (`isEmpty` / `singleton` / `foldl` / `foldr` /
//! `map` / `filter` / `partition`) are CALLABLE from user code and produce
//! Elm-matching results.
//!
//! Exercises all seven in one program (`tests/golden/set_hofs/Main.ipe`),
//! building and running the emitted binary and asserting the stdout line.
//!
//! Gated on `IPE_E2E=1`. Run:
//! `IPE_E2E=1 cargo test -p ipe --test golden_set_hofs`.

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

#[test]
fn set_hofs_run_with_parity() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_golden("set_hofs");
    let out = crate::support::build_and_run_emitted("set_hofs", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "expected a clean exit; got {:?}",
        out.exit_code
    );
    // Over {1..6}: foldl sum=21; foldr sum=21; map (*2) size=6;
    // filter even size=3; partition (>3) big size=3; singleton size=1;
    // isEmpty (filter >100) → 1.
    assert_eq!(out.stdout.trim(), "21 21 6 3 3 1 1");
}

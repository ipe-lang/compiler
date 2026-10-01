//! The `elm/core` Char predicate fills (`isAlphaNum` / `isHexDigit` /
//! `isOctDigit`) are CALLABLE from user code and produce Elm-matching results.
//!
//! Counts predicate hits over a sample string
//! (`tests/golden/char_predicates/Main.ipe`), building and running the emitted
//! binary and asserting the stdout line.
//!
//! Gated on `IPE_E2E=1`. Run:
//! `IPE_E2E=1 cargo test -p ipe --test golden_char_predicates`.

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
fn char_predicates_run_with_parity() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_golden("char_predicates");
    let out = crate::support::build_and_run_emitted("char_predicates", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "expected a clean exit; got {:?}",
        out.exit_code
    );
    // Over "aF9 z8-7Gx": isHexDigit → {a,F,9,8,7}=5; isOctDigit → {7}=1;
    // isAlphaNum → {a,F,9,z,8,7,G,x}=8.
    assert_eq!(out.stdout.trim(), "5 1 8");
}

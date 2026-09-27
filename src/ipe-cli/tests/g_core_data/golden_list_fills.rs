//! The `elm/core` List fills are CALLABLE from user code and produce
//! Elm-matching results.
//!
//! Exercises `List.sum` / `product` / `maximum` / `minimum` / `singleton` /
//! `repeat` / `intersperse` / `partition` / `unzip` / `sort` / `sortWith` /
//! `sortBy` / `filterMap` / `unique` in
//! one program (`tests/golden/list_fills/Main.ipe`), building and running the
//! emitted binary and asserting the stdout line — the SEAL guarantee (ipe exit
//! 0 ⇒ emitted Rust builds and runs) plus behaviour parity with `elm/core`.
//!
//! Gated on `IPE_E2E=1`. Run:
//! `IPE_E2E=1 cargo test -p ipe --test golden_list_fills`.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe` into an emitted Rust project and
/// return its directory. Fails the test loudly on a compile error.
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
fn list_fills_run_with_parity() {
    if !e2e_enabled() {
        return;
    }
    let dir = compile_golden("list_fills");
    let out = crate::support::build_and_run_emitted("list_fills", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "expected a clean exit; got {:?}",
        out.exit_code
    );
    // sum [3,1,4,1,5,9,2,6]=31; product [1,2,3,4]=24; maximum=9; minimum=1;
    // sum (singleton 7)=7; sum (repeat 4 2)=8; length (intersperse 0 [1,2,3])=5;
    // length (fst (partition (>3)))=4; unzip key-sum=6, val-sum=60;
    // head (sort)=1; head (sortWith descending)=9;
    // sum (map2 (+) [1,2,3] [10,20])=33; sum (map3 (+) …)=333;
    // head (sortBy negate)=9; sum (filterMap halve-evens [4,2,6]→[2,1,3])=6;
    // sum (unique [1,1,2,3,2,1]→[1,2,3])=6.
    assert_eq!(out.stdout.trim(), "31 24 9 1 7 8 5 4 6 60 1 9 33 333 9 6 6");
}

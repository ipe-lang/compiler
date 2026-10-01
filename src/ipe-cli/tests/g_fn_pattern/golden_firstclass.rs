//! First-class-function gate: `ipe` must emit `main.rs`
//! byte-identical to the checked-in golden for higher-order functions (a
//! function-typed parameter applied inside the callee), a top-level function
//! passed as a value by name, and a top-level function returned as a value —
//! and (behind `IPE_E2E=1`) the emitted project must build and print `51`.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `51\n`, exit 0 — verified by running it in a temp dir:
//!
//! ```text
//! $ ipe run tests/golden/firstclass/Main.ipe
//! 51
//! ```
//!
//! `applyTwice : (Int -> Int) -> Int -> Int` applies its function-typed
//! parameter twice: `applyTwice (\n -> n + 3) 1` is `(1+3)+3 = 7` (a lambda
//! passed as a value) and `applyTwice inc 1` is `(1+1)+1 = 3` (the top-level
//! `inc` passed by name — reified into a boxed closure). `makeInc 0` returns the
//! top-level `inc` as a value, bound to `g`; `g 40` is `41`. The entry's total
//! is `7 + 3 + 41 = 51`. Running the toolchain inside `cargo test` is
//! impractical (it needs the `ipe` binary plus a toolchain), so the
//! hand-computed value is the in-test oracle, documented here against the
//! equivalent command.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("firstclass")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("firstclass")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m1_firstclass_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    // Directory-diff the emitted project against the golden dir (byte-compares
    // the emitted `src/main.rs` against the golden `main.rs`). Replaces the
    // former hand-rolled `read_to_string` + `assert_eq!` pair with the shared
    // harness helper.
    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// Full spine: compile, build the emitted Cargo project, run it, and assert the
/// first-class-function arithmetic prints `51` — the same value the backend
/// produces. Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_fifty_one() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m1_firstclass_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("firstclass", &out);
    crate::support::assert_go_parity(
        "firstclass",
        &repo_root().join("tests").join("golden").join("firstclass"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

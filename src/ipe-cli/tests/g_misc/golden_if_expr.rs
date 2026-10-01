//! `if … then … else` gate: `ipe` must emit `main.rs`
//! byte-identical to the checked-in golden for inline, multi-way (`else if`),
//! and nested `if`s, and (behind `IPE_E2E=1`) the emitted project must build
//! and print `10`.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `10\n`, exit 0:
//!
//! ```text
//! $ ipe run tests/golden/if_expr/Main.ipe
//! 10
//! ```
//!
//! `absVal (0 - 7) = 7` (the `n < 0` branch negates); `classify 5 = 1` (the
//! leading `n > 0` branch); `classify (0 - 3) = 2` (the `else if n < 0`
//! branch); the entry's `total = 7 + 1 + 2 = 10`. The `end_to_end_*` test
//! below asserts the Rust backend reaches the identical `10`. Running the golden
//! toolchain inside `cargo test` is impractical (it needs the reference compiler `ipe`
//! binary plus a toolchain), so the hand-computed value is the in-test
//! oracle, documented here against the equivalent command.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("if_expr")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("if_expr")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m1_if_emit");
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
/// `if`-driven arithmetic prints `10` — the expected value.
/// Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_ten() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m1_if_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("if_expr", &out);
    crate::support::assert_go_parity(
        "if_expr",
        &repo_root().join("tests").join("golden").join("if_expr"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

//! `let … in` gate: `ipe` must emit `main.rs` byte-identical to the
//! checked-in golden for single- and multi-binding `let`s, and (behind
//! `IPE_E2E=1`) the emitted project must build and print `22`.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `22\n`, exit 0:
//!
//! ```text
//! $ ipe run tests/golden/let_in/Main.ipe
//! 22
//! ```
//!
//! `double 5 = 5 + 5 = 10`; `triple 4`'s multi-binding let computes `a = 4 + 4 =
//! 8`, then `b = a + 4 = 12` (a later binding reads an earlier one); the entry's
//! inline `let total = double 5 + triple 4` is `10 + 12 = 22`. The Rust
//! `end_to_end_*` test below asserts the Rust backend reaches the identical `22`.
//! Running the toolchain inside `cargo test` is impractical (it needs the
//! the `ipe` binary plus a toolchain), so the hand-computed value is the
//! in-test oracle, documented here against the equivalent command.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("let_in")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("let_in")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m1_let_emit");
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
/// `let`-bound arithmetic prints `22` — the expected value.
/// Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_twenty_two() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m1_let_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("let_in", &out);
    crate::support::assert_go_parity(
        "let_in",
        &repo_root().join("tests").join("golden").join("let_in"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

//! Partial / over-application gate: `ipe` must emit `main.rs`
//! byte-identical to the checked-in golden for curried partial application
//! (eta-expansion) and over-application (saturation), and (behind `IPE_E2E=1`)
//! the emitted project must build and print `15`.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `15\n`, exit 0:
//!
//! ```text
//! $ ipe dev run tests/golden/partial/Main.ipe
//! 15
//! ```
//!
//! `let f = add 2 in f 3` partially applies the two-parameter `add`: `add 2`
//! eta-expands to `\eta_0 -> add(2, eta_0)`, and `f 3` → `5`. `over 1 2`
//! over-applies the one-parameter `over : Int -> Int -> Int` (`over a = \b ->
//! a + b`): the first arg saturates `over(1)` and the surplus `2` applies to the
//! returned closure → `3`. `applyTwice (add 1) 5` passes the partial `add 1` as
//! a first-class function and applies it twice: `add 1 (add 1 5)` → `7`. The
//! entry prints `p + o + h = 5 + 3 + 7 = 15`. Running the toolchain inside
//! `cargo test` is impractical (it needs the full `ipe` toolchain),
//! so the hand-computed value is the in-test oracle, documented here
//! against the equivalent command.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("partial")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("partial")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m1_partial_emit");
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
/// partial/over-application arithmetic prints `15` — the same value the golden
/// backend produces. Gated on `IPE_E2E=1` so the default `cargo test` stays
/// fast.
#[test]
fn end_to_end_builds_and_prints_fifteen() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m1_partial_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("partial", &out);
    crate::support::assert_go_parity(
        "partial",
        &repo_root().join("tests").join("golden").join("partial"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

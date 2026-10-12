//! Tuple gate: `ipe` must emit `main.rs` byte-identical to the
//! checked-in golden for a program that constructs tuple values and compares
//! them, and (behind `IPE_E2E=1`) the emitted project must build and print `1`.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `1\n`, exit 0 in a temp dir (so the
//! build artifacts never touch the reference tree):
//!
//! ```text
//! $ cd "$(mktemp -d)" && ipe dev run Main.ipe
//! 1
//! ```
//!
//! `same = if (1, 2) == (1, 2) then 1 else 0 = 1` (the tuples are equal);
//! `diff = if (1, 2) == (1, 3) then 10 else 0 = 0` (the second elements
//! differ); the entry prints `same + diff = 1`. The `end_to_end_*` test below
//! asserts the Rust backend reaches the identical `1`. Running the toolchain
//! inside `cargo test` is impractical (it needs the `ipe` binary plus a
//! the toolchain), so the hand-verified value is the in-test oracle, documented
//! here against the equivalent command.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("tuples")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("tuples")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m1_tuples_emit");
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
/// tuple-equality program prints `1` — the expected value.
/// Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_one() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m1_tuples_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("tuples", &out);
    crate::support::assert_go_parity(
        "tuples",
        &repo_root().join("tests").join("golden").join("tuples"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

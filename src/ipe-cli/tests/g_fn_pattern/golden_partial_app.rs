//! IPE-L0110 seal — partial + over-application of a first-class function
//! VALUE. `ipe` must emit `main.rs` byte-identical to the checked-in golden,
//! and (behind `IPE_E2E=1`) the emitted project must build and print
//! `6\n33\n103\n`, exit 0 — the same values (hand-verified).
//!
//! The named-callee path already eta-expands a partial application (`add 2` ->
//! `\n -> add(2, n)`). This fixture pins the VALUE path: the reference
//! (`../ipe`) emits function values as curried single-arg closures, so applying
//! one arg at a time is a plain call; our IR flattens the curried chain into one
//! multi-parameter closure, so a value applied to too-few args must be
//! eta-expanded into a residual closure `\eta... -> (value)(supplied..., eta...)`.
//!
//! Three shapes exercised (see `Main.ipe`):
//!   * bound partial `g = f 1; h = g 2` -> `6`   (1 + 2 + 3),
//!   * over-application `(f 10 20) 3`   -> `33`  (10 + 20 + 3),
//!   * pipe partial `100 |> add3 1 2`   -> `103` (1 + 2 + 100).
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `6\n33\n103\n`, exit 0:
//!
//! ```text
//! $ ipe dev run tests/golden/partial_app/Main.ipe
//! 6
//! 33
//! 103
//! ```
//!
//! Running the reference compiler `ipe` toolchain inside `cargo test` is impractical, so
//! the hand-computed values are the in-test oracle, documented here against the
//! equivalent command.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("partial_app")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("partial_app")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i216_partial_app_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// Full spine: compile, build the emitted Cargo project, run it, and assert the
/// partial/over-application arithmetic prints `6\n33\n103` — the same values the
/// the backend produces. Gated on `IPE_E2E=1` so the default `cargo test` stays
/// fast.
#[test]
fn end_to_end_builds_and_prints_partial_app_values() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i216_partial_app_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("partial_app", &out);
    assert_eq!(
        outcome.stdout, "6\n33\n103\n",
        "value partial + over + pipe partial application, matching golden"
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

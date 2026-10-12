//! Equatable-bound parity gate: a generic function whose body
//! compares its arguments with `==` / `/=` (`eq2 p q = p == q`) generalises to a
//! Rust generic bounded by `PartialEq` — and, unlike the Number / Comparable
//! paths, carries NO `Copy`, because `PartialEq::eq` borrows its operands.
//!
//! `eq2 : a -> a -> Bool` emits `pub fn main_eq2<T1: PartialEq>(p: T1, q: T1) ->
//! bool`. It is used at `Int` (`eq2 21 21`) for the runtime output and
//! instantiated at `Bool` (through the annotated forwarder `eqBool`) so the
//! bound is exercised at two types in one module — `main.rs` must be
//! byte-identical to the checked-in golden, and (behind `IPE_E2E=1`) the emitted
//! project must build and print `42`.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `42\n`, exit 0:
//!
//! ```text
//! $ cd "$(mktemp -d)" && ipe dev run Main.ipe
//! 42
//! ```

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("equality")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("equality")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m2d1_equality_emit");
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
/// Equatable-generic program prints `42` — the expected backend produces.
/// Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_forty_two() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m2d1_equality_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("equality", &out);
    crate::support::assert_go_parity(
        "equality",
        &repo_root().join("tests").join("golden").join("equality"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

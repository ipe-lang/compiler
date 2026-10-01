//! Number-bound parity gate: a generic function whose body adds
//! its argument to itself (`double x = x + x`) generalises to a Rust generic
//! bounded by the `Add` operator trait plus `Copy`, not the rigid-skolem
//! rejection a structurally-parametric variable would get.
//!
//! `double : a -> a` emits
//! `pub fn main_double<T1: ::core::ops::Add<Output = T1> + Copy>(x: T1) -> T1`.
//! It is used at `Int` (`double 21`) for the runtime output and instantiated at
//! `Float` (through the annotated forwarder `doubleFloat`) so the bound is
//! exercised at both numeric types in one module — `main.rs` must be
//! byte-identical to the checked-in golden, and (behind `IPE_E2E=1`) the emitted
//! project must build and print `42`.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `42\n`, exit 0:
//!
//! ```text
//! $ cd "$(mktemp -d)" && ipe run Main.ipe
//! 42
//! ```

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("number_typeclass")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("number_typeclass")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m2d1_number_emit");
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
/// Number-generic program prints `42` — the expected backend produces.
/// Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_forty_two() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m2d1_number_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("number_typeclass", &out);
    crate::support::assert_go_parity(
        "number_typeclass",
        &repo_root()
            .join("tests")
            .join("golden")
            .join("number_typeclass"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

//! Comparable-bound parity gate: a generic function whose body
//! orders its arguments (`maxOf p q = if p > q then p else q`) generalises to a
//! Rust generic bounded by `PartialOrd` plus `Copy`.
//!
//! `maxOf : a -> a -> a` emits
//! `pub fn main_max_of<T1: PartialOrd + Copy>(p: T1, q: T1) -> T1`. It is used at
//! TWO distinct primitive types in one module — `maxOf 3 7` (`Int`) and
//! `maxOf 'a' 'z'` (`Char`) — so the one bounded generic is monomorphised at
//! both. `main.rs` must be byte-identical to the checked-in golden, and (behind
//! `IPE_E2E=1`) the emitted project must build and print `7`.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `7\n`, exit 0:
//!
//! ```text
//! $ cd "$(mktemp -d)" && ipe run Main.ipe
//! 7
//! ```

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("comparable")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("comparable")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m2d1_comparable_emit");
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
/// Comparable-generic program prints `7` — the expected backend produces.
/// Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_seven() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m2d1_comparable_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("comparable", &out);
    crate::support::assert_go_parity(
        "comparable",
        &repo_root().join("tests").join("golden").join("comparable"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

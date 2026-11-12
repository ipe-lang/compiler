//! A CONCRETE record use straddling two distinct generic siblings (regression
//! for IPE-I0001).
//!
//! Alongside the two generic shapes of `i1346` — `{ q : a }` and
//! `{ q : ( a, a ) }` — this source adds two CONCRETE uses: `concreteScalar`
//! surfaces `{ q : Int }` and `concretePair` surfaces `{ q : ( Int, Int ) }`.
//!
//! The concrete pair instantiates BOTH generic shapes at once, so no choice
//! between per-shape structs can be right for every flow. Every occurrence of
//! `{q}` here unifies with `{ q : a }`, so all four share ONE struct whose
//! template is their least general generalization, `struct RecQ<T1> { q: T1 }`:
//! `concreteScalar` emits `RecQ { q: 100 }` and `concretePair` emits
//! `RecQ { q: (40, 2) }`.
//!
//! `ipe` must emit `main.rs` byte-identical to the checked-in golden — exactly
//! ONE struct for `{q}` — and behind `IPE_E2E=1` the emitted project must build
//! and print `145` (`wrapOne 1 + firstOfPair 2 + concreteScalar 100 +
//! concretePair 42`).
//!
//! Oracle: Ipe's own output. `1 + 2 + 100 + 42` is `145\n`, exit 0 — the value
//! checked into `expected.txt`.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const NAME: &str = "i1349_concrete_record_straddles_two_generic_templates";

fn example_dir(root: &Path) -> PathBuf {
    root.join("tests").join("golden").join(NAME)
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let dir = example_dir(&root);
    let golden_project = root.join("tests").join("golden").join(NAME);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{NAME}_emit"));
    e2e_support::scratch::fresh(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = crate::support::build_golden(&dir, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    crate::support::assert_emitted_project_matches_golden_dir(&out, &golden_project);
}

/// Full spine: compile, build the emitted Cargo project, run it, and assert the
/// program prints `145`. Gated on `IPE_E2E=1` so the default `cargo test` stays
/// fast.
#[test]
fn end_to_end_builds_and_prints_one_four_five() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = example_dir(&root);
    let out = crate::support::scratch_root().join(format!("{NAME}_e2e"));
    e2e_support::scratch::fresh(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&dir, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(NAME, &out);
    crate::support::assert_self_regression(
        NAME,
        &repo_root().join("tests").join("golden").join(NAME),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

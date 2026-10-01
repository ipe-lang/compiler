//! A CONCRETE record use straddling two distinct generic siblings (regression
//! for IPE-I0001).
//!
//! Alongside the two generic shapes of `i1346` — `{ q : a }` (`RecQ`) and
//! `{ q : ( a, a ) }` (`RecQ2`), which share the field-name set `{q}` yet are
//! genuinely distinct — this source adds two CONCRETE uses: `concreteScalar`
//! surfaces `{ q : Int }` and `concretePair` surfaces `{ q : ( Int, Int ) }`.
//!
//! The concrete pair `{ q : ( Int, Int ) }` instantiation-matches BOTH generic
//! templates at once — `RecQ` binds `a := ( Int, Int )`, and `RecQ2` binds
//! `a := Int`. A "first duplicate is ambiguous" resolution rule surfaced this as
//! `Diagnostic::CompilerBug` → IPE-I0001 ("record shape {q} matched more than one
//! synthesised struct") on well-typed source — an ICE, a Principle-3 soundness
//! violation.
//!
//! The fix resolves the straddle to the MOST-SPECIFIC template: the one whose
//! field skeleton carries the most concrete constructors. `{ q : ( a, a ) }`
//! (specificity 1: its `Tuple` node) outranks `{ q : a }` (specificity 0), so the
//! concrete pair emits with `RecQ2` — the struct whose `q` field really is a
//! `(Int, Int)` pair — never the over-general `RecQ` (which would type `q` as the
//! whole tuple and read the wrong field types). The concrete scalar
//! `{ q : Int }` matches only `RecQ` (it is not a tuple) and emits with `RecQ`.
//!
//! `ipe` must emit `main.rs` byte-identical to the checked-in golden — exactly
//! TWO generic structs, no spurious duplication — with `concreteScalar` using
//! `RecQ { q: 100 }` and `concretePair` using `RecQ2 { q: (40, 2) }`. Behind
//! `IPE_E2E=1` the emitted project must build and print `145`
//! (`wrapOne 1 + firstOfPair 2 + concreteScalar 100 + concretePair 42`).
//!
//! Oracle: Ipe's own output. `1 + 2 + 100 + 42` is `145\n`, exit 0 — the value
//! checked into `expected.txt`.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const NAME: &str = "i1349_concrete_record_straddles_two_generic_templates";

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(NAME)
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root.join("tests").join("golden").join(NAME).join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{NAME}_emit"));
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
/// program prints `145`. Gated on `IPE_E2E=1` so the default `cargo test` stays
/// fast.
#[test]
fn end_to_end_builds_and_prints_one_four_five() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join(format!("{NAME}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(NAME, &out);
    crate::support::assert_self_regression(
        NAME,
        &repo_root().join("tests").join("golden").join(NAME),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

//! Two distinct generic record shapes sharing one field-name set (regression for
//! IPE-I0001).
//!
//! `wrapOne : a -> a` surfaces the body-local generic shape `{ q : a }`;
//! `firstOfPair : a -> a` surfaces `{ q : ( a, a ) }`. Both records share the
//! field-name set `{q}` yet are GENUINELY DISTINCT (not alpha-equivalent). Before
//! the fix, `reconcile_shapes` assumed a parametric record's field-name set names
//! it uniquely and raised `Diagnostic::CompilerBug` → IPE-I0001 ("record field
//! set {q} maps to two non-alpha-equivalent generic shapes") on this well-typed
//! source — an ICE, a Principle-3 soundness violation.
//!
//! The fix keys each distinct generic occurrence by its `skeleton_key` (the
//! alpha-equivalence normal form) and emits ONE struct per skeleton, mirroring
//! the monomorphic-sibling path that already disambiguates concrete records
//! sharing a field-name set. `ipe` must emit `main.rs` byte-identical to the
//! checked-in golden — TWO generic structs `struct RecQ<T1> { q: T1 }` and
//! `struct RecQ2<T1> { q: (T1, T1) }`, disambiguated at their use sites by the
//! solved field-type shape — and (behind `IPE_E2E=1`) the emitted project must
//! build and print `10` (`wrapOne 7 + firstOfPair 3`).
//!
//! Alpha-EQUIVALENT occurrences of one shape still fold to a single struct: the
//! sibling `body_local_generic_record` golden (whose `{ q : a }` appears once)
//! stays exactly one struct — this fix disambiguates only genuinely-distinct
//! shapes, it does not duplicate.
//!
//! Oracle: Ipe's own output. `wrapOne 7` is `7`, `firstOfPair 3` is `3`, so
//! `main` prints `10\n`, exit 0 — the value checked into `expected.txt`.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("i1346_generic_record_field_name_collision")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("i1346_generic_record_field_name_collision")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("i1346_generic_record_field_name_collision_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve: {:?}", runtime.err());
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// Full spine: compile, build the emitted Cargo project, run it, and assert the
/// two-distinct-generic-record program prints `10`. Gated on `IPE_E2E=1` so the
/// default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_ten() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("i1346_generic_record_field_name_collision_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome =
        crate::support::build_and_run_emitted("i1346_generic_record_field_name_collision", &out);
    crate::support::assert_self_regression(
        "i1346_generic_record_field_name_collision",
        &repo_root()
            .join("tests")
            .join("golden")
            .join("i1346_generic_record_field_name_collision"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

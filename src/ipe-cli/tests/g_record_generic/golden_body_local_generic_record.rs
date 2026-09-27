//! Body-local generic single-field record gate (regression for IPE-I0001).
//!
//! `wrap : a -> a` constructs and reads a single-field record `{ q : a }`
//! entirely inside its body — the shape appears in NO signature. Before the fix
//! the lowerer skipped every var-bearing record when surfacing body-local shapes
//! (a var there has no live per-def poly context to name it), a skip that is
//! sound only for a generic record that ALSO reaches the backend through a
//! signature. A body-local generic literal breaks that premise: the backend
//! found no synthesised struct for `{q}` and raised
//! `IPE-I0001` ("no synthesised struct for record shape {q}"). An ICE on
//! well-typed source is a soundness violation — a record of any arity (one field
//! included) is valid Ipe.
//!
//! The fix surfaces the shape from the lowered body's type-carrying slots, where
//! it already carries its solved `IrType::Generic(a)`. `ipe` must emit `main.rs`
//! byte-identical to the checked-in golden — a GENERIC Rust struct
//! `struct RecQ<T1> { q: T1 }`, with `wrap` rendered at `RecQ<T1>` and the
//! `wrap 7` use site instantiating it at `i64` — and (behind `IPE_E2E=1`) the
//! emitted project must build and print `7`.
//!
//! Oracle: Ipe's own output. `wrap 7` returns `7`, so `main` prints `7\n`,
//! exit 0 — the value checked into `expected.txt`.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("body_local_generic_record")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("body_local_generic_record")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("body_local_generic_record_emit");
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
/// body-local generic single-field record program prints `7`. Gated on
/// `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_seven() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("body_local_generic_record_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("body_local_generic_record", &out);
    crate::support::assert_self_regression(
        "body_local_generic_record",
        &repo_root()
            .join("tests")
            .join("golden")
            .join("body_local_generic_record"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

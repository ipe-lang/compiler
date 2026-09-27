//! Carrier normalization (Phase 1, records): a function stored in a record field
//! is carried as `Arc<dyn Fn>` ([`ipe_ir::IrType::SharedFun`]) — always, as a
//! total function of the record's shape, not a containment-gated promotion. So a
//! dispatch-table record of functions builds: read a field out, call it, reuse
//! the whole table. The synthesised struct gets a hand-written `impl Clone`
//! (an `Arc::clone` refcount bump per fn slot) and renders a `<fn>` placeholder
//! in its `IpeStringify`.
//!
//! `run ops 4` = `ops.add 4 + ops.mul 4` = `(4 + 10) + (4 * 3)` = `14 + 12`
//! = `26`.
//!
//! Fail-closed constraints (a record embedding a function narrows what you can
//! DO with it, at the operation, not the definition):
//!   * `==` on a fn-embedding record is a compile-time error (not Equatable) —
//!     no runtime crash path, strictly better than Elm.
//!   * a fn-embedding record used as a `Dict` KEY is a compile-time error (no
//!     `Ord`). `Dict` VALUES are fine.
//!   * a fn-carrying Model is excluded at the serialization frontier — the Web
//!     model gate classifies `SharedFun` as `ModelLeaf::Function`
//!     (`emit_model_gate::leaf_of_bounded`), unchanged and deliberately so.

use std::path::{Path, PathBuf};

use ipe::CliError;

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("fn_record_field_dispatch")
        .join("Main.ipe")
}

#[test]
fn dispatch_table_emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("fn_record_field_dispatch")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fn_record_field_dispatch_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

#[test]
fn dispatch_table_end_to_end_prints_twenty_six() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_fn_record_field_dispatch_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("fn_record_field_dispatch", &out);
    assert_eq!(outcome.stdout, "26\n", "dispatch table prints its sum");
    assert_eq!(outcome.exit_code, Some(0), "exit 0 (THE SEAL)");
}

/// Build a one-file program to a fresh temp dir. Returns `None` when the test
/// environment cannot set up (runtime unavailable / filesystem error) so the
/// caller skips rather than falsely fails; `Some` carries the driver result.
fn build_source(name: &str, source: &str) -> Option<Result<(), CliError>> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let entry = dir.join("Main.ipe");
    std::fs::write(&entry, source).ok()?;
    let out = dir.join("out");
    let runtime = ipe::resolve_runtime().ok()?;
    Some(ipe::build(&entry, &out, &runtime))
}

#[test]
fn equality_on_a_fn_embedding_record_is_rejected() {
    // Comparing two records that embed a function has no sound `PartialEq` — a
    // compile-time error, never a runtime crash on function equality.
    let src = "module Main exposing (main)\n\
               import Ipe.Io as Io\n\
               type alias Ops = { add : Int -> Int }\n\
               same : Ops -> Ops -> Bool\n\
               same a b = a == b\n\
               main =\n\
               \x20   let r = { add = \\n -> n + 1 } in\n\
               \x20   Io.println (if same r r then \"y\" else \"n\")\n";
    let Some(built) = build_source("fn_record_eq_gate", src) else {
        return;
    };
    assert!(
        matches!(&built, Err(CliError::Pipeline { .. })),
        "== on a fn-embedding record must fail closed, got: {built:?}"
    );
}

#[test]
fn a_fn_embedding_record_dict_key_is_rejected() {
    // A `Dict` key must be comparable; a record embedding a function is not, so
    // keying on one is a compile-time error. `Dict` VALUES stay fine.
    let src = "module Main exposing (main)\n\
               import Ipe.Io as Io\n\
               import Ipe.Dict as Dict\n\
               type alias Ops = { add : Int -> Int }\n\
               main =\n\
               \x20   let d = Dict.singleton { add = \\n -> n + 1 } 5 in\n\
               \x20   Io.println \"x\"\n";
    let Some(built) = build_source("fn_record_dict_key_gate", src) else {
        return;
    };
    assert!(
        matches!(&built, Err(CliError::Pipeline { .. })),
        "a fn-embedding record Dict key must fail closed, got: {built:?}"
    );
}

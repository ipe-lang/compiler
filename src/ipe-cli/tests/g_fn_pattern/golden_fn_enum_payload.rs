//! Carrier normalization (Phase 2, enum variant payloads): a function stored in
//! a user-enum constructor payload is carried as `Arc<dyn Fn>`
//! ([`ipe_ir::IrType::SharedFun`]) — always, as a total function of the type
//! tree, mirroring the Phase-1 record rule. So a variant-of-functions builds:
//! construct a variant carrying a lambda, `case`-match it out, and call it. The
//! synthesised enum gets a hand-written `impl Clone` (an `Arc::clone` refcount
//! bump per fn slot) and renders a `<fn>` placeholder in its `IpeStringify`, so
//! the enum is duplicable — a `Box` carrier would fail closed at `cargo build`
//! (E0599) the moment the value is cloned.
//!
//! `useTwice (OnClick (\n -> n + 100))` clones the enum (`let dup = h`) and runs
//! both copies: `runHandler h 3 + runHandler dup 4` = `(3 + 100) + (4 + 100)`
//! = `103 + 104` = `207`.
//!
//! Fail-closed constraints (an enum embedding a function narrows what you can DO
//! with it, at the operation, not the definition — unchanged from Phase 1):
//!   * `==` on a fn-embedding enum is a compile-time error (not Equatable).
//!   * a fn-embedding enum used as a `Dict` KEY is a compile-time error (no
//!     `Ord`). `Dict` VALUES are fine.
//!   * a fn-carrying Web Model is excluded at the serialization frontier — the
//!     model gate classifies `SharedFun` as `ModelLeaf::Function`, unchanged.

use std::path::{Path, PathBuf};

use ipe::CliError;

use crate::support::{normalize_rustfmt_whitespace, repo_root};

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("fn_enum_payload_dispatch")
        .join("Main.ipe")
}

/// The emitted enum stores its function payload on the `Arc<dyn Fn>` carrier and
/// carries a hand-written `impl Clone` (no `Box<dyn Fn>` payload, which would be
/// a non-`Clone` `cargo build` break the moment the enum is duplicated).
#[test]
fn enum_payload_emits_arc_carrier_and_clone() {
    let root = repo_root();
    let entry = example_entry(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fn_enum_payload_dispatch_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let main_rs = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    let norm = normalize_rustfmt_whitespace(&main_rs);

    // The payload is the shared `Arc<dyn Fn>` carrier, not a bare `Box<dyn Fn>`.
    assert!(
        norm.contains("OnClick(::std::sync::Arc<dynFn(i64)->T1+Send+Sync+'static>)"),
        "the fn payload must be carried on the Arc<dyn Fn> carrier; got:\n{main_rs}"
    );
    // The enum is `Clone` via a hand-written impl (the derive is demoted because
    // the payload is not Debug/PartialEq), so the cloned duplicate compiles.
    assert!(
        norm.contains("CloneforMainHandler"),
        "a fn-carrying enum must get a hand-written impl Clone; got:\n{main_rs}"
    );
    // The generic parameter outlives 'static (the trait-object payload requires
    // it), so the generic enum type-checks.
    assert!(
        norm.contains("pubenumMainHandler<T1:'static>"),
        "a fn-storing generic enum bounds its type parameter ': 'static'; got:\n{main_rs}"
    );
}

#[test]
fn enum_payload_end_to_end_prints_two_hundred_seven() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_fn_enum_payload_dispatch_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("fn_enum_payload_dispatch", &out);
    assert_eq!(
        outcome.stdout, "207\n",
        "the variant-of-functions dispatch prints its sum"
    );
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
fn equality_on_a_fn_embedding_enum_is_rejected() {
    // Comparing two enums that embed a function has no sound `PartialEq` — a
    // compile-time error, never a runtime crash on function equality.
    let src = "module Main exposing (main)\n\
               import Ipe.Io as Io\n\
               type Handler a = OnClick (Int -> a) | Plain a\n\
               same : Handler Int -> Handler Int -> Bool\n\
               same a b = a == b\n\
               main =\n\
               \x20   let r = OnClick (\\n -> n + 1) in\n\
               \x20   Io.println (if same r r then \"y\" else \"n\")\n";
    let Some(built) = build_source("fn_enum_eq_gate", src) else {
        return;
    };
    assert!(
        matches!(&built, Err(CliError::Pipeline { .. })),
        "== on a fn-embedding enum must fail closed, got: {built:?}"
    );
}

#[test]
fn a_fn_embedding_enum_dict_key_is_rejected() {
    // A `Dict` key must be comparable; an enum embedding a function is not, so
    // keying on one is a compile-time error. `Dict` VALUES stay fine.
    let src = "module Main exposing (main)\n\
               import Ipe.Io as Io\n\
               import Ipe.Dict as Dict\n\
               type Handler a = OnClick (Int -> a) | Plain a\n\
               main =\n\
               \x20   let d = Dict.singleton (OnClick (\\n -> n + 1)) 5 in\n\
               \x20   Io.println \"x\"\n";
    let Some(built) = build_source("fn_enum_dict_key_gate", src) else {
        return;
    };
    assert!(
        matches!(&built, Err(CliError::Pipeline { .. })),
        "a fn-embedding enum Dict key must fail closed, got: {built:?}"
    );
}

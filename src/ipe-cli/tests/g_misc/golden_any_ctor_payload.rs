//! IPE-L0102 regression — `any` as a union-constructor payload field.
//!
//! ## Root cause
//!
//! `type Msg = … | CartTopicReceived any` has `any` as a **union-ctor payload
//! field**.  If `lower_enum` Gate 1 collected the `any` type variable via
//! `collect_type_vars`, found it absent from `union.vars` (monomorphic `Msg`
//! has no type params), and raised `Feature::Polymorphism` (IPE-L0102), it
//! would block examples 27 (`MessageReceived any`) and 37
//! (`CartTopicReceived any`).
//!
//! ## Fix
//!
//! * `constrain.rs` — `pin_any_in_ty` substitutes `any` `Ty::Var`s in ctor
//!   schemes with `Dict String String` (the pub/sub wire carrier) so every
//!   instantiation site sees a concrete type.
//! * `lower.rs` `lower_enum` Gate 1 — excludes `any` from the unbound-var
//!   check (mirrors reference `(/= "any") freeVars` filter).
//! * `lower.rs` `ir_type_from_canon` — maps an `any` Var to
//!   `IrType::Dict(Str, Str)` before the generic-var check.
//! * `ipe/src/lib.rs` `source_for_span` — adds union ctor spans to the
//!   attribution heuristic so ctor-based lower errors (IPE-L0114, etc.) render
//!   against the owning dep file, not the entry file.
//!
//! ## Tests
//!
//! 1. `any_ctor_payload_ipe_and_cargo_zero` — build-only seal: `BroadcastMsg
//!    any` compiles (ipe exit 0) and the emitted Rust builds (cargo exit 0).
//!    Without the fix, IPE-L0102.
//!
//! 2. `any_ctor_payload_fail_closed` — using the `any` payload as a `String`
//!    must surface `IPE-T0001` at ipe, never silently cargo-fail.
//!
//! 3. `ctor_span_attr_dep_module` — a dep-module enum wrapping a
//!    `List (Int -> Int)` lowers and runs: the collection element carries its
//!    function on the `Arc<dyn Fn>` carrier, so the payload is a storable value.

use std::path::{Path, PathBuf};

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

fn fixture_src_entry(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(name)
        .join("src")
        .join("Main.ipe")
}

/// Build-only seal: `BroadcastMsg any` — ipe exit 0 AND cargo build green.
/// Without the fix, IPE-L0102 (`Feature::Polymorphism` in `lower_enum` Gate 1).
#[test]
fn any_ctor_payload_ipec_and_cargo_zero() {
    let root = repo_root();
    let entry = fixture_entry(&root, "any_ctor_payload");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("l0102_any_ctor_payload_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipec must accept `BroadcastMsg any` (was IPE-L0102 pre-fix): {:?}",
        built.err()
    );

    // Cargo build seal: the emitted Rust must compile.
    // Gated on IPE_E2E so the default test run stays fast.
    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("any_ctor_payload", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "binary must exit 0; stdout:\n{}",
            outcome.stdout
        );
        assert!(
            outcome.stdout.contains("ignored"),
            "handleMsg Ignored must print 'ignored'; got:\n{}",
            outcome.stdout
        );
    }
}

/// Fail-closed guard: using the `any`-ctor payload as a String must produce
/// IPE-T0001 at ipe time, never silently cargo-fail.
#[test]
fn any_ctor_payload_fail_closed() {
    let root = repo_root();
    let entry = fixture_entry(&root, "any_ctor_fail_closed");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("l0102_any_ctor_fail_closed_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0001),
        "using an `any`-ctor payload as String must surface IPE-T0001, got: {built:?}"
    );
}

/// A user enum in a DEP module wrapping a `List (Int -> Int)`: the collection
/// element carries its function on the `Clone` `Arc<dyn Fn>` carrier, so the enum
/// is a storable value and the cross-module program lowers cleanly and runs.
#[test]
fn ctor_span_attr_dep_module() {
    let root = repo_root();
    let entry = fixture_src_entry(&root, "ctor_span_attr");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("l0102_ctor_span_attr_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let result = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        result.is_ok(),
        "a dep-module enum wrapping a `List (Int -> Int)` must lower and build: {:?}",
        result.err()
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("ctor_span_attr", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "binary must exit 0; stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(outcome.stdout.trim(), "22");
    }
}

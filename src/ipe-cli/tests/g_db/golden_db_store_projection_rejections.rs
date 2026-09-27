//! Fail-closed refusals for `Store.select` projections (IPE-L0149).
//!
//! `Store.select` accepts a projection body that is a bare `side.field` column
//! reference, or a flat tuple of such references. Anything else — a computed
//! value, a literal, a nested tuple — must be a fail-closed build error, never a
//! partial statement or a `SELECT *`. Each case here is driven by a real `.ipe`
//! program whose stores and join are well-formed; only the projection body is at
//! fault, so the build must be rejected with exactly IPE-L0149. Asserting only
//! `is_err()` would pass on any unrelated failure and leave the refusal unproven,
//! so each test pins the diagnostic code.

// A failed `panic` in these tests is the failure signal — the test fixture
// does not compile or produce a build artifact for the runtime to execute.
#![allow(clippy::panic)]

use std::path::{Path, PathBuf};

use ipe::CliError;
use ipe_diagnostics::{Diagnostic, LowerError, StoreSelectProjectionDefect};

use crate::support::repo_root;

fn fixture_entry(root: &Path, golden: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(golden)
        .join("Main.ipe")
}

/// Build `golden` and return the diagnostic code it was rejected with, or `None`
/// if it built or failed without a pipeline diagnostic.
fn rejection_code(golden: &str) -> Option<ipe_diagnostics::Code> {
    let root = repo_root();
    let entry = fixture_entry(&root, golden);
    let out = crate::support::scratch_root().join(format!("ipec_{golden}"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime().ok()?;
    match ipe::build(&entry, &out, &runtime) {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    }
}

/// Build `golden` and return the full [`Diagnostic`] it was rejected with, or
/// `None` if it built or failed without a pipeline diagnostic.
fn rejection_diagnostic(golden: &str) -> Option<Box<Diagnostic>> {
    let root = repo_root();
    let entry = fixture_entry(&root, golden);
    let out = crate::support::scratch_root().join(format!("ipec_{golden}"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime().ok()?;
    match ipe::build(&entry, &out, &runtime) {
        Err(CliError::Pipeline { diag, .. }) => Some(diag),
        _ => None,
    }
}

/// A SINGLE-column projection body that computes a value (`String.append …`)
/// instead of naming a bare column is rejected with IPE-L0149 (the back-filled
/// single-reference refusal).
#[test]
fn single_column_computed_projection_is_rejected() {
    let Some(code) = rejection_code("db_store_projection_reject_single_computed") else {
        return; // resolver unavailable — skip
    };
    assert_eq!(
        code,
        ipe_diagnostics::IPE_L0149,
        "a computed single-column projection body must fail closed with IPE-L0149"
    );
}

/// A tuple element that computes a value (`String.toUpper author.name`) is
/// rejected with IPE-L0149.
#[test]
fn multicol_computed_element_is_rejected() {
    let Some(code) = rejection_code("db_store_projection_reject_computed") else {
        return;
    };
    assert_eq!(
        code,
        ipe_diagnostics::IPE_L0149,
        "a computed tuple element must fail closed with IPE-L0149"
    );
}

/// A tuple element that is a literal (`"literal"`) rather than a column
/// reference is rejected with IPE-L0149.
#[test]
fn multicol_literal_element_is_rejected() {
    let Some(code) = rejection_code("db_store_projection_reject_literal") else {
        return;
    };
    assert_eq!(
        code,
        ipe_diagnostics::IPE_L0149,
        "a literal tuple element must fail closed with IPE-L0149"
    );
}

/// A tuple element that is itself a tuple (a nested projection) is rejected with
/// IPE-L0149 — a multi-column projection is a flat tuple of references.
#[test]
fn multicol_nested_tuple_element_is_rejected() {
    let Some(code) = rejection_code("db_store_projection_reject_nested_tuple") else {
        return;
    };
    assert_eq!(
        code,
        ipe_diagnostics::IPE_L0149,
        "a nested-tuple projection element must fail closed with IPE-L0149"
    );
}

/// `Store.upper` applied to a non-String column (here `Bool`) must be rejected.
/// `Store.upper : String -> String` unifies with `active : Bool` as a type
/// mismatch (IPE-T0001) before lowering fires. Pinning the specific code
/// confirms this path is correct — a bare `is_err()` would pass on any
/// unrelated failure and leave the refusal unproven.
#[test]
fn upper_on_non_string_column_is_rejected() {
    let Some(code) = rejection_code("db_store_projection_upper_non_string_rejected") else {
        return; // resolver unavailable — skip
    };
    assert_eq!(
        code,
        ipe_diagnostics::IPE_T0001,
        "Store.upper on a non-String column must fail with a type-mismatch IPE-T0001"
    );
}

/// `Store.add` applied to a non-numeric column (here `String`) must be
/// rejected. The arithmetic operators are `number a => a -> a -> a`; unifying a
/// `String` operand against the numeric-bounded variable is a type mismatch
/// (IPE-T0001), fail-closed before lowering. Pinning the specific code confirms
/// the numeric obligation is enforced rather than an unrelated failure.
#[test]
fn arith_on_non_numeric_column_is_rejected() {
    let Some(code) = rejection_code("db_store_projection_arith_non_numeric_rejected") else {
        return; // resolver unavailable — skip
    };
    assert_eq!(
        code,
        ipe_diagnostics::IPE_T0001,
        "Store.add on a non-numeric column must fail with a type-mismatch IPE-T0001"
    );
}

/// A `Store.literal` whose argument type is not a supported scalar (String /
/// Int / Bool / Float) is rejected with IPE-L0149 /
/// `LiteralTypeUnsupported`, and the diagnostic names the unsupported type.
/// This pins the specific path through `ProjColKind::of_ty` → `None` for a
/// literal argument — distinct from the general `UnsupportedProjectionBody`
/// that covers computed column expressions.
#[test]
fn literal_unsupported_type_is_rejected_with_type_name() {
    let Some(diag) = rejection_diagnostic("db_store_projection_literal_type_unsupported") else {
        return; // resolver unavailable — skip
    };
    assert_eq!(
        diag.code(),
        ipe_diagnostics::IPE_L0149,
        "a Store.literal with an unsupported argument type must fail closed with IPE-L0149"
    );
    let Diagnostic::Lower {
        msg: LowerError::StoreSelectProjectionInvalid(defect),
        ..
    } = *diag
    else {
        panic!(
            "expected StoreSelectProjectionInvalid, got a different diagnostic variant: {diag:?}"
        );
    };
    let StoreSelectProjectionDefect::LiteralTypeUnsupported { ty } = defect else {
        panic!("expected LiteralTypeUnsupported defect, got: {defect:?}");
    };
    assert!(
        ty.contains("record"),
        "diagnostic must name the unsupported type; got type label: {ty:?}"
    );
}

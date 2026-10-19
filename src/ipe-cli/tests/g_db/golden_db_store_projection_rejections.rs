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

fn fixture_project(root: &Path, golden: &str) -> PathBuf {
    root.join("tests").join("golden").join(golden)
}

/// Build `golden` and return the diagnostic code it was rejected with.
fn rejection_code(golden: &str) -> ipe_diagnostics::Code {
    rejection_diagnostic(golden).code()
}

/// Build `golden` and return the pipeline [`Diagnostic`] it was rejected with.
///
/// A build that succeeds, or fails without a pipeline diagnostic, fails the
/// test: the refusal is the property under proof. Every caller gets the
/// no-emission proof for free: a rejected build must never have written
/// `src/main.rs`, so the diagnostic is proven to have stopped the pipeline
/// before codegen, not merely to have been returned alongside an emitted
/// crate.
fn rejection_diagnostic(golden: &str) -> Diagnostic {
    let root = repo_root();
    let entry = fixture_project(&root, golden);
    let out = crate::support::scratch_root().join(format!("ipec_{golden}"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let diag = match crate::support::build_golden(&entry, &out, &runtime) {
        Err(CliError::Pipeline { diag, .. }) => *diag,
        other => panic!("{golden}: must be rejected with a pipeline diagnostic, got {other:?}"),
    };

    let emitted = out.join("src").join("main.rs");
    assert!(
        !emitted.exists(),
        "{golden}: a rejected build must emit no Rust, but {} exists",
        emitted.display()
    );
    diag
}

/// A SINGLE-column projection body that computes a value (`String.append …`)
/// instead of naming a bare column is rejected with IPE-L0149 (the back-filled
/// single-reference refusal).
#[test]
fn single_column_computed_projection_is_rejected() {
    let code = rejection_code("db_store_projection_reject_single_computed");
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
    let code = rejection_code("db_store_projection_reject_computed");
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
    let code = rejection_code("db_store_projection_reject_literal");
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
    let code = rejection_code("db_store_projection_reject_nested_tuple");
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
    let code = rejection_code("db_store_projection_upper_non_string_rejected");
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
    let code = rejection_code("db_store_projection_arith_non_numeric_rejected");
    assert_eq!(
        code,
        ipe_diagnostics::IPE_T0001,
        "Store.add on a non-numeric column must fail with a type-mismatch IPE-T0001"
    );
}

/// `Store.sub` applied to a non-numeric column (here `String`) must be
/// rejected. `sub` shares `add`'s numeric-bounded type variable, so unifying
/// a `String` operand against it is a type mismatch (IPE-T0001), fail-closed
/// before lowering.
#[test]
fn sub_on_non_numeric_column_is_rejected() {
    let code = rejection_code("db_store_projection_sub_non_numeric_rejected");
    assert_eq!(
        code,
        ipe_diagnostics::IPE_T0001,
        "Store.sub on a non-numeric column must fail with a type-mismatch IPE-T0001"
    );
}

/// `Store.mul` applied to a non-numeric column (here `Bool`) must be
/// rejected. `mul` shares `add`'s numeric-bounded type variable, so unifying
/// a `Bool` operand against it is a type mismatch (IPE-T0001), fail-closed
/// before lowering.
#[test]
fn mul_on_non_numeric_column_is_rejected() {
    let code = rejection_code("db_store_projection_mul_non_numeric_rejected");
    assert_eq!(
        code,
        ipe_diagnostics::IPE_T0001,
        "Store.mul on a non-numeric column must fail with a type-mismatch IPE-T0001"
    );
}

/// `Store.add` applied to two numeric columns of DIFFERENT numeric types
/// (`Int` against `Float`) must be rejected. `add` shares ONE type variable
/// across both operands, so an `Int`/`Float` pairing is a type mismatch
/// (IPE-T0001) even though each operand alone is within the numeric bound.
/// This proves the obligation ties both operands to the SAME numeric type,
/// not merely to "numeric" independently.
#[test]
fn arith_mixed_numeric_operands_is_rejected() {
    let code = rejection_code("db_store_projection_arith_mixed_numeric_rejected");
    assert_eq!(
        code,
        ipe_diagnostics::IPE_T0001,
        "Store.add over an Int operand and a Float operand must fail with a type-mismatch IPE-T0001"
    );
}

/// `Store.coalesce` applied to two operands of DIFFERENT scalar types
/// (`String` against `Bool`) must be rejected. `coalesce` shares ONE type
/// variable across both operands, so a mismatched pair is a type mismatch
/// (IPE-T0001) — this pins the docs' claim that `coalesce`'s operands must
/// share one scalar type.
#[test]
fn coalesce_operand_type_mismatch_is_rejected() {
    let code = rejection_code("db_store_projection_coalesce_mismatch_rejected");
    assert_eq!(
        code,
        ipe_diagnostics::IPE_T0001,
        "Store.coalesce over mismatched operand types must fail with a type-mismatch IPE-T0001"
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
    let diag = rejection_diagnostic("db_store_projection_literal_type_unsupported");
    assert_eq!(
        diag.code(),
        ipe_diagnostics::IPE_L0149,
        "a Store.literal with an unsupported argument type must fail closed with IPE-L0149"
    );
    let Diagnostic::Lower {
        msg: LowerError::StoreSelectProjectionInvalid(defect),
        ..
    } = diag
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

/// Build `golden`, require IPE-L0149, and return its `Store.select` projection defect.
///
/// `None` when the rejection is not a `StoreSelectProjectionInvalid` lowering
/// diagnostic, so the caller's equality assertion names the mismatch.
fn projection_defect(golden: &str) -> Option<StoreSelectProjectionDefect> {
    let diag = rejection_diagnostic(golden);
    assert_eq!(
        diag.code(),
        ipe_diagnostics::IPE_L0149,
        "{golden}: must fail closed with IPE-L0149, got {diag:?}"
    );
    match diag {
        Diagnostic::Lower {
            msg: LowerError::StoreSelectProjectionInvalid(defect),
            ..
        } => Some(defect),
        _ => None,
    }
}

/// `let readAll = Store.selectToList db in readAll sel` is a partial
/// application: no projection is visible where it is built, so it is refused
/// with `SelectToNotSaturated` rather than running the placeholder body.
#[test]
fn select_to_partial_let_rejected() {
    assert_eq!(
        projection_defect("db_store_select_to_partial_let_rejected"),
        Some(StoreSelectProjectionDefect::SelectToNotSaturated)
    );
}

/// `List.map (Store.selectToList db) sels` passes a partial application as a
/// function value and is refused with `SelectToNotSaturated`.
#[test]
fn select_to_partial_map_rejected() {
    assert_eq!(
        projection_defect("db_store_select_to_partial_map_rejected"),
        Some(StoreSelectProjectionDefect::SelectToNotSaturated)
    );
}

/// `Task.andThen (Store.selectToMaybe db) task` passes a `selectToMaybe`
/// partial application as a function value and is refused with
/// `SelectToNotSaturated`.
#[test]
fn select_to_maybe_partial_rejected() {
    assert_eq!(
        projection_defect("db_store_select_to_maybe_partial_rejected"),
        Some(StoreSelectProjectionDefect::SelectToNotSaturated)
    );
}

/// `apply Store.selectToList db sel` passes the bare binding as a function
/// value and is refused with `SelectToNotSaturated` at the reference.
#[test]
fn select_to_point_free_rejected() {
    assert_eq!(
        projection_defect("db_store_select_to_point_free_rejected"),
        Some(StoreSelectProjectionDefect::SelectToNotSaturated)
    );
}

/// A `Select` bound to a name and piped into `Store.selectToList` hides its
/// projected column types. After the pipe collapses to the direct call, it is
/// refused with `SelectArgNotProjection`.
#[test]
fn select_to_let_bound_select_rejected() {
    assert_eq!(
        projection_defect("db_store_select_to_let_bound_select_rejected"),
        Some(StoreSelectProjectionDefect::SelectArgNotProjection)
    );
}

/// A `Select` taken as a parameter hides its projected column types and is
/// refused with `SelectArgNotProjection`.
#[test]
fn select_to_param_select_rejected() {
    assert_eq!(
        projection_defect("db_store_select_to_param_select_rejected"),
        Some(StoreSelectProjectionDefect::SelectArgNotProjection)
    );
}

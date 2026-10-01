//! Regression: a let-bound record literal with a bare function field and no
//! type annotation must be rejected with IPE-L0107, not reach struct synthesis
//! and ICE with IPE-I0001.
//!
//! The shape — `let rec = { shouldRetry = \n -> n + 1 }` inside `main` with no
//! type annotation on `rec` — has its solved record type only in the solver's
//! region map, never in any top-level binding's inferred type (`SolvedTypes::env`).
//! The backend's signature scan therefore registers no struct for the shape; the
//! lowerer's `collect_records_in_ty` G-b gate skips it; and `record_struct_by_key`
//! raises a `CompilerBug` ICE (IPE-I0001) when the backend tries to emit the
//! record literal.
//!
//! Fix: the `reject_function_valued_field` gate in the `Expr_::Record` lowering
//! arm detects that the region type has a bare `Ty::Fun` field whose field-name
//! set does not appear in any env type, and emits IPE-L0107 before struct
//! synthesis is reached.
//!
//! Boundary: a record with a function field whose type IS declared in a top-level
//! binding annotation (e.g. `guard : Guard` with `type alias Guard = { shouldRetry
//! : Int -> Int }`) still compiles — the backend registers its struct from the
//! function signature.

use std::path::{Path, PathBuf};

use ipe::CliError;

use crate::support::repo_root;

fn fixture(root: &Path, dir: &str) -> PathBuf {
    root.join("tests").join("golden").join(dir).join("Main.ipe")
}

/// Assert that building `<golden dir>/Main.ipe` fails closed with IPE-L0107.
fn assert_rejects_l0107(dir: &str) {
    let root = repo_root();
    let entry = fixture(&root, dir);
    let out = crate::support::scratch_root().join(format!("ipec_{dir}"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_L0107),
        "`{dir}` must fail closed with IPE-L0107 (not ICE with IPE-I0001, not \
         accept-then-cargo-fail); got build result: {built:?}"
    );
}

/// An unannotated let-bound record literal with a bare function field must
/// be rejected with IPE-L0107 — not ICE with IPE-I0001.
#[test]
fn fn_field_let_record_rejects_with_l0107() {
    assert_rejects_l0107("i1139_fn_field_record_literal");
}

/// SEAL: a function-field record literal whose field-NAME set collides with a
/// signature record of DIFFERENT field types (`{ run : Int }` covering a
/// `{ run = \n -> … }` literal) must be rejected with IPE-L0107 — never
/// field-NAME-only "covered", which would emit an `Arc<dyn Fn>` value into the
/// backend's `i64` field and fail the emitted `cargo build` (accept-then-fail).
#[test]
fn fn_field_record_key_set_collision_rejects_with_l0107() {
    assert_rejects_l0107("i1139_fn_field_record_key_collision");
}

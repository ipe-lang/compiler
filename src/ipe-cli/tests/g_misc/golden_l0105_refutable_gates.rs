//! IPE-L0105 refutable parameter patterns — the negative surface. A
//! parameter (or `let` binder) is a BINDING position: it must match every value
//! of its type. A refutable param must therefore be a clean, span-carrying
//! compile-time error — never a runtime match failure (upstream Ipe's
//! `panic!("non-exhaustive … function argument")` is REJECTED here as a
//! soundness + `DoS` hole).
//!
//! Two fail-closed phases cover the whole refutable class:
//!
//! * **IPE-T0015** (the new irrefutability gate, type/exhaustiveness phase) —
//!   for the shapes that PARSE as a parameter yet are refutable: a constructor
//!   pattern (`\(Just x) ->`, `f (Just x) =`), a tuple with a refutable element
//!   (`\(a, Just x) ->`), a cons pattern (`\(x :: xs) ->`). This gate is the one
//!   this task adds — those params reach the checker, so the checker must reject
//!   them before lowering.
//! * **IPE-P0001** (the pre-existing parser grammar) — a bare literal (`\1 ->`)
//!   or bracket-list (`\[a] ->`) param is not admitted in binding position at
//!   all, so it fails even earlier. Recorded here so the coverage is honest: the
//!   refutable class is closed by BOTH gates, and no refutable param reaches
//!   codegen.

use std::path::PathBuf;

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Build the named golden fixture and assert it surfaces exactly `expected` as a
/// pipeline diagnostic — never a panic / internal compiler bug. A skip occurs
/// only when the runtime cannot be resolved.
fn assert_gate(fixture: &str, out_suffix: &str, expected: ipe_diagnostics::Code) {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out_suffix);
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(expected),
        "fixture {fixture}: expected {expected:?}, got build result {built:?}"
    );
}

#[test]
fn ctor_lambda_param_is_ipe_t0015() {
    assert_gate(
        "neg_ctor_lambda",
        "l0105_neg_ctor_lambda_emit",
        ipe_diagnostics::IPE_T0015,
    );
}

#[test]
fn ctor_def_head_param_is_ipe_t0015() {
    assert_gate(
        "neg_ctor_def",
        "l0105_neg_ctor_def_emit",
        ipe_diagnostics::IPE_T0015,
    );
}

#[test]
fn tuple_param_with_refutable_element_is_ipe_t0015() {
    assert_gate(
        "neg_nested_tuple",
        "l0105_neg_nested_tuple_emit",
        ipe_diagnostics::IPE_T0015,
    );
}

#[test]
fn cons_lambda_param_is_ipe_t0015() {
    assert_gate(
        "neg_cons_lambda",
        "l0105_neg_cons_lambda_emit",
        ipe_diagnostics::IPE_T0015,
    );
}

#[test]
fn bare_int_literal_lambda_param_is_parse_rejected() {
    assert_gate(
        "neg_int_lambda",
        "l0105_neg_int_lambda_emit",
        ipe_diagnostics::IPE_P0001,
    );
}

#[test]
fn bare_list_lambda_param_is_parse_rejected() {
    assert_gate(
        "neg_list_lambda",
        "l0105_neg_list_lambda_emit",
        ipe_diagnostics::IPE_P0001,
    );
}

/// Negative regression for Std/Money.ipe fix: a single-ctor union param
/// `amount (Money d _) = d` must still be rejected as IPE-T0015.
/// Proves the stdlib fix did not relax the irrefutability rule.
#[test]
fn single_ctor_union_def_param_is_ipe_t0015() {
    assert_gate(
        "neg_money_ctor_param",
        "l0105_neg_money_ctor_param_emit",
        ipe_diagnostics::IPE_T0015,
    );
}

/// Positive regression: single-ctor union accessor via `case` compiles clean.
/// Guards the seal: ipe exit-0 → emitted Rust cargo-builds without error.
#[test]
fn single_ctor_case_accessor_compiles() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("money_ctor_accessor_case")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("money_ctor_accessor_case_emit");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "single-ctor case accessor must compile: {:?}",
        built.err()
    );
}

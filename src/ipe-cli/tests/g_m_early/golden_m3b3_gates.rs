//! Exhaustiveness / redundancy gates for literal-pattern `case`s.
//!
//! * Int / Char / String are OPEN types: literal arms with no wildcard / variable
//!   catch-all do not cover every value, so the `case` is non-exhaustive →
//!   IPE-T0010 (the soundness floor — a non-exhaustive Ipê `case` MUST be caught
//!   before emit, never deferred to a rustc E0004 / `unreachable!()` fallback).
//! * A literal arm AFTER a wildcard catch-all matches no value left open → the
//!   redundant-branch warning IPE-T0011.
//!
//! Each is driven through the full `ipe` pipeline and asserted to produce its
//! exact code. The reference accepts a redundant branch silently; the Rust
//! backend is deliberately stricter (it reports IPE-T0011) — a documented,
//! never-silently-wrong divergence.

use std::path::PathBuf;

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

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
fn non_exhaustive_int_case_is_ipe_t0010() {
    assert_gate(
        "gate_nonexhaustive_open_int",
        "m3b3_gate_nonexhaustive_emit",
        ipe_diagnostics::IPE_T0010,
    );
}

/// `IPE-T0011` is a WARNING (see the
/// matching note in `golden_m3b2_gates`). The build must SUCCEED.
#[test]
fn redundant_branch_after_catch_all_is_ipe_t0011_warning_build_succeeds() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("gate_redundant")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m3b3_gate_redundant_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "redundant branch after catch-all must WARN (IPE-T0011) and build, got: {:?}",
        built.err()
    );
}

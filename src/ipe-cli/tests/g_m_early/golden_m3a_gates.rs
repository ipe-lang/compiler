//! Fail-closed gates: each unmodelled ADT shape must surface a
//! clean, span-carrying diagnostic — never a panic, an internal compiler bug, or
//! silent cargo-failing Rust.
//!
//! * a constructor pattern binding the wrong number of payload fields →
//!   IPE-T0013 (a type error).
//!
//! (Two `case` arms head-matching the same constructor with a refutable nested
//! payload — `Som (Som x)` then `Som Non` — is now SUPPORTED: each arm lowers to
//! its own Rust `match` arm in source order. Its positive regression lives in
//! `golden_m3b4_nested` / `golden_m3b4_two_same_ctor`.)
//!
//! Note: the partial-ctor-application gap (formerly IPE-L0113) is closed.
//! Positive regressions live in `golden_i147_ctor_as_fn_seal`.
//!
//! Each is driven through the full `ipe` pipeline and asserted to produce its
//! exact code, locking the gap so it can never regress into a worse failure mode.

use std::path::PathBuf;

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Build the named golden fixture and assert it surfaces exactly `expected` as a
/// pipeline diagnostic. A build that succeeds, or fails with any other error,
/// makes `got` differ from `Some(expected)` and fails with a descriptive message
/// — never a panic. A skip occurs only when the runtime cannot be resolved.
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
fn ctor_pattern_arity_is_ipe_t0013() {
    assert_gate(
        "gate_arity",
        "m3a_gate_arity_emit",
        ipe_diagnostics::IPE_T0013,
    );
}

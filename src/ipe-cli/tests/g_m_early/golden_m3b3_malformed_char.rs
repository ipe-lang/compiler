//! Soundness floor for malformed character literals.
//!
//! An unrecognised escape inside a char literal (e.g. `'\q'`) resolves to
//! backslash + char — two scalar values — which violates the single-character
//! invariant the char backend relies on. The lexer rejects it at lex time as
//! IPE-P0015 (`MalformedChar`) with NO emit, in BOTH pattern position and
//! scrutinee position. Recognised escapes (`\n \t \r \\ \" \' \0`) and plain
//! chars are all exactly one scalar value, so no valid program regresses.
//!
//! Each fixture is driven through the full `ipe` pipeline and asserted to
//! produce its exact code AND to leave no `main.rs` behind (exit-1, no emit).

use std::path::PathBuf;

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn assert_malformed_char(fixture: &str, out_suffix: &str) {
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
        Some(ipe_diagnostics::IPE_P0015),
        "fixture {fixture}: expected IPE-P0015, got build result {built:?}"
    );

    // Soundness floor: a rejected program emits nothing.
    let emitted = out.join("src").join("main.rs");
    assert!(
        !emitted.exists(),
        "fixture {fixture}: expected no emit, but {} was written",
        emitted.display()
    );
}

#[test]
fn unrecognised_escape_in_pattern_position_is_ipe_p0015() {
    assert_malformed_char(
        "gate_malformed_char_pattern",
        "m3b3_gate_malformed_char_pattern_emit",
    );
}

#[test]
fn unrecognised_escape_in_scrutinee_position_is_ipe_p0015() {
    assert_malformed_char(
        "gate_malformed_char_scrutinee",
        "m3b3_gate_malformed_char_scrutinee_emit",
    );
}

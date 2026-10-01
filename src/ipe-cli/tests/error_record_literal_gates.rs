//! Negative gates for the SEAL fix
//! (`docs/adr/0001-language-semantics-and-types.md`): a bare record literal
//! must NOT construct the nominal error-payload types `PanicInfo` / `TypeInfo` /
//! `ErrorInfo`. Under structural registration each fixture would be an
//! exit-0-then-cargo-fail (well-typed in ipe, but the emitted Rust passes a
//! project-local synthesized record struct where the runtime's concrete
//! `IpePanicInfo`/`IpeTypeInfo`/`IpeErrorInfo` is required — E0308). They
//! are ordinary IPE-T0001 type mismatches at `ipe` time.
//!
//! Companion positive golden: `crates/ipe/tests/
//! golden_error_nominal_payload.rs` (field access + nominal-annotated helpers
//! stay green).
//!
//! Compile-only: these fixtures never run (the program is ill-typed), so
//! there is no oracle / `IPE_E2E` gate here.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Build the named golden fixture and assert it surfaces exactly `expected` as
/// a pipeline diagnostic — never a panic, never a silent accept.
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
        Err(ipe::CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(expected),
        "fixture {fixture}: expected {expected:?}, got build result {built:?}"
    );
}

/// `FfiPanic { message = "boom", stack = [] }` — the RED repro from the filed
/// backlog row, verbatim.
#[test]
fn panic_info_record_literal_is_rejected() {
    assert_gate(
        "error_record_literal_panicinfo",
        "error_record_literal_panicinfo_emit",
        ipe_diagnostics::IPE_T0001,
    );
}

/// `TypeMismatch { expected = "Int", actual = "String" }`.
#[test]
fn type_info_record_literal_is_rejected() {
    assert_gate(
        "error_record_literal_typeinfo",
        "error_record_literal_typeinfo_emit",
        ipe_diagnostics::IPE_T0001,
    );
}

/// `Error Io { message = "disk full", details = Nothing }` — direct `Error`
/// construction with a record-literal `ErrorInfo`; the sanctioned path is the
/// `Error.io`/… smart constructors.
#[test]
fn error_info_record_literal_is_rejected() {
    assert_gate(
        "error_record_literal_errorinfo",
        "error_record_literal_errorinfo_emit",
        ipe_diagnostics::IPE_T0001,
    );
}

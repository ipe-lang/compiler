//! Backlog the — the real `Error ErrorKind ErrorInfo` ADT (ported from
//! the `ipe-stdlib/Ipe/Core/Error.ipe` design).
//!
//! Proves the whole pipeline end-to-end: construction (`Error.io`,
//! `Error.timeout`), the ctor-scheme fix (pattern matching
//! `case e of Error kind info -> ...` and `case kind of Io -> ... `),
//! `Error.toString` (kind-classified `"<Kind>: <message>"` rendering, not the
//! prior string-identity slice's verbatim echo), `Error.isRetryable`
//! (kind-based classification), and `Error.withMessage` (replaces message,
//! keeps kind).
//!
//! ```text
//! # compile-only check (fast, no IPE_E2E needed):
//! cargo test -p ipe --test golden_error_adt_roundtrip
//!
//! # full E2E (run the emitted binary, assert stdout):
//! IPE_E2E=1 cargo test -p ipe --test golden_error_adt_roundtrip
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn error_adt_roundtrip_compiles() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("error_adt_roundtrip")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("error_adt_roundtrip_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for error_adt_roundtrip: {:?}",
        built.err()
    );
}

#[test]
fn error_adt_roundtrip_runs_and_prints_expected_output() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("error_adt_roundtrip")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_error_adt_roundtrip_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for error_adt_roundtrip: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("error_adt_roundtrip", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "error_adt_roundtrip: must exit 0; stdout:\n{}",
        outcome.stdout
    );

    let expected = [
        "Io: disk full",      // Error.toString e1 -- kind-classified, not a bare echo
        "disk full",          // info.message from the Error kind info pattern (closes #160)
        "Io",                 // case kind of Io -> "Io" -- ErrorKind pattern match
        "not-retryable",      // Error.isRetryable e1 (Io) -- false
        "retryable",          // Error.isRetryable e2 (Timeout) -- true
        "Io: custom message", // Error.withMessage keeps the kind, replaces the message
        "done",
    ];
    for line in expected {
        assert!(
            outcome.stdout.contains(line),
            "error_adt_roundtrip: stdout must contain {line:?}; got:\n{}",
            outcome.stdout
        );
    }
}

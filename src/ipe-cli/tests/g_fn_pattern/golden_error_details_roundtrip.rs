//! `ErrorInfo.details : Maybe ErrorDetails` + the
//! 5-variant `ErrorDetails`/`PanicInfo`/`TypeInfo` union, layered on top of
//! the core `Error ErrorKind ErrorInfo` ADT (see
//! `crates/ipe/tests/golden_error_adt_roundtrip.rs`).
//!
//! Proves the whole pipeline end-to-end: construction (`Error.withDetails`),
//! the ctor-scheme registration for `ErrorDetails`'s 5 variants (closing the
//! same canon/lowerer ctor-scheme gap class closed for `ErrorKind`,
//! applied here to `FfiPanic`/`TypeMismatch`/`HttpStatus`/`JsonDecode`/
//! `Custom`), field access on `ErrorInfo.details` (a `Maybe ErrorDetails`),
//! and exhaustive pattern matching over all 5 `ErrorDetails` variants.
//!
//! ```text
//! # compile-only check (fast, no IPE_E2E needed):
//! cargo test -p ipe --test golden_error_details_roundtrip
//!
//! # full E2E (run the emitted binary, assert stdout):
//! IPE_E2E=1 cargo test -p ipe --test golden_error_details_roundtrip
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn error_details_roundtrip_compiles() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("error_details_roundtrip")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("error_details_roundtrip_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for error_details_roundtrip: {:?}",
        built.err()
    );
}

#[test]
fn error_details_roundtrip_runs_and_prints_expected_output() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("error_details_roundtrip")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_error_details_roundtrip_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for error_details_roundtrip: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("error_details_roundtrip", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "error_details_roundtrip: must exit 0; stdout:\n{}",
        outcome.stdout
    );

    let expected = [
        "Io: disk full | details=none",           // base — no details attached
        "Io: disk full | details=HttpStatus 404", // Error.withDetails (HttpStatus 404)
        "Io: disk full | details=JsonDecode unexpected token", // Error.withDetails (JsonDecode ..)
        "Io: disk full | details=Custom custom detail", // Error.withDetails (Custom ..)
        "done",
    ];
    for line in expected {
        assert!(
            outcome.stdout.contains(line),
            "error_details_roundtrip: stdout must contain {line:?}; got:\n{}",
            outcome.stdout
        );
    }
}

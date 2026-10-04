//! SEAL fix (`docs/adr/0001-language-semantics-and-types.md`) — positive
//! golden for the NOMINAL `PanicInfo` / `TypeInfo` / `ErrorInfo` payload types.
//!
//! Pins the coherence half (the negative half lives in
//! `crates/ipe/tests/error_record_literal_gates.rs`):
//!
//! * the three names are annotatable builtins (`describePanic : PanicInfo ->
//!   String` resolves and compiles);
//! * a pattern-bound payload and a helper parameter naming (or inferring) the
//!   same nominal type agree on ONE Rust type (`ipe_runtime::error::
//!   IpePanicInfo` etc.) — without the fix, this exact shape was an
//!   exit-0-then-cargo-fail (the helper's parameter lowered to a
//!   project-local synthesized record struct);
//! * field access on all six fixed fields resolves through `ipe_types`'
//!   `ErrorRecordFields` table and emits pub-field reads of the runtime
//!   structs.
//!
//! ```text
//! # compile-only check (fast, no IPE_E2E needed):
//! cargo test -p ipe --test golden_error_nominal_payload
//!
//! # full E2E (run the emitted binary, assert stdout):
//! IPE_E2E=1 cargo test -p ipe --test golden_error_nominal_payload
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn error_nominal_payload_compiles() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("error_nominal_payload")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("error_nominal_payload_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for error_nominal_payload: {:?}",
        built.err()
    );
}

#[test]
fn error_nominal_payload_runs_and_prints_expected_output() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("error_nominal_payload")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_error_nominal_payload_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for error_nominal_payload: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("error_nominal_payload", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "error_nominal_payload: must exit 0; stdout:\n{}",
        outcome.stdout
    );

    let expected = [
        "plain: disk full",     // no details — unannotated describeInfo path
        "Custom custom detail", // Error.withDetails (Custom ..)
        "done",
    ];
    for line in expected {
        assert!(
            outcome.stdout.contains(line),
            "error_nominal_payload: stdout must contain {line:?}; got:\n{}",
            outcome.stdout
        );
    }
}

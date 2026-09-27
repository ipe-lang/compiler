//! Regression for the `RetryPolicy` struct-synthesis ICE (IPE-I0001).
//!
//! Accessing a `RetryPolicy` field (`policy.maxAttempts`, `.strategy`, `.baseMs`,
//! ...) or passing a predicate lambda to `retryOn` / `withRetryOn` triggered
//! IPE-I0001 when the solver left the type parameter `e` of `RetryPolicy e` as
//! a free `Ty::Var`.  The root cause: `collect_records_in_ty`'s
//! `!ty_contains_var` guard skipped the `RetryPolicy` record entirely (because
//! `shouldRetry : e -> Bool` contains `e`), so no struct was registered in
//! the synthesis table.  The backend's `record_struct_by_key` then could not
//! find it and raised a `CompilerBug` ICE.
//!
//! Fix: before the `ty_contains_var` guard, detect the exact 4-field closed
//! `RetryPolicy` shape and register its concrete IR with `e` fixed to
//! `IrType::Error` (the only runtime instantiation).  The struct is then
//! found by all retry-kernel paths in `emit_task_retry_call`.
//!
//! The guard is scoped to the KERNEL instantiation (`shouldRetry` type is a
//! free `Ty::Var` or `Error -> Bool`).  A user record with a different concrete
//! predicate type (e.g. `Int -> Bool`) is not the kernel type and does not take
//! this path; see `golden_i979_retry_policy_exact_shape_user_record` for the
//! positive boundary.  A near-miss subset (lone `shouldRetry` field only) still
//! fails closed with IPE-L0107; see `retry_policy_nearmiss_still_rejects`.

use std::path::{Path, PathBuf};

use ipe::CliError;

use crate::support::repo_root;

fn fixture(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("retry_policy_field_access_ice")
        .join("Main.ipe")
}

fn fixture_named(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

fn built(root: &Path, out: &Path) -> Option<Result<(), CliError>> {
    let _ = std::fs::remove_dir_all(out);
    let runtime = ipe::resolve_runtime().ok()?;
    Some(ipe::build(&fixture(root), out, &runtime))
}

/// The fix must not regress: a user record with a lone `shouldRetry` field is
/// NOT the `RetryPolicy` shape and must still fail closed with IPE-L0107.
#[test]
fn retry_policy_nearmiss_still_rejects() {
    let root = repo_root();
    let entry = fixture_named(&root, "retry_policy_shape_nearmiss");
    let out = crate::support::scratch_root().join("ipec_i963_nearmiss_guard");
    let _ = std::fs::remove_dir_all(&out);
    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_L0107),
        "a user `{{ shouldRetry : Int -> Int }}` record must still fail closed \
         with IPE-L0107 after the fix — the RetryPolicy exemption is scoped to \
         the exact 4-field closed shape; got: {built:?}"
    );
}

/// The frontend must accept the fixture (no ICE, no spurious IPE-L* rejection).
#[test]
fn retry_policy_field_access_ice_emits() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_i963_emit");
    let Some(result) = built(&root, &out) else {
        return;
    };
    assert!(
        result.is_ok(),
        "RetryPolicy field access and predicate-lambda retryOn must compile \
         without ICE (IPE-I0001); the RetryPolicy struct must be registered in \
         the synthesis table even when the `e` type parameter is a free Ty::Var; \
         got: {result:?}"
    );
}

/// Under `IPE_E2E=1`: the emitted crate must `cargo build` and run, printing
/// field values and `ok` on stdout.
#[test]
fn retry_policy_field_access_ice_builds_and_runs() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_i963_e2e");
    let Some(result) = built(&root, &out) else {
        return;
    };
    assert!(
        result.is_ok(),
        "RetryPolicy field access fixture must be accepted; got: {result:?}"
    );

    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let outcome = crate::support::build_and_run_emitted("retry_policy_field_access_ice", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "emitted crate must build and run successfully; stdout:\n{}",
        outcome.stdout
    );
    // The fixture prints "withRetryOn ok" then "ok" (two successful Task chains).
    let stdout = outcome.stdout.trim();
    assert!(
        stdout.contains("ok"),
        "emitted program must print 'ok' from the retryWith chain"
    );
}

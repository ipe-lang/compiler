//! Regression for the `RetryPolicy` struct-synthesis ICE (IPE-I0001).
//!
//! Accessing a `RetryPolicy` field (`policy.maxAttempts`, `.strategy`, `.baseMs`,
//! ...) or passing a predicate lambda to `retryOn` / `withRetryOn` triggered
//! IPE-I0001 when the solver left the type parameter `e` of `RetryPolicy e` as
//! a free `Ty::Var`.  The root cause: `collect_records_in_ty`'s
//! `!ty_fields_mention_var` guard skipped the `RetryPolicy` record entirely (because
//! `shouldRetry : e -> Bool` contains `e`), so no struct was registered in
//! the synthesis table.  The backend's `record_struct_by_key` then could not
//! find it and raised a `CompilerBug` ICE.
//!
//! Fix: before the `ty_fields_mention_var` guard, detect the exact 4-field closed
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
}

fn fixture_named(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

fn built(root: &Path, out: &Path) -> Result<(), CliError> {
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    crate::support::build_golden(&fixture(root), out, &runtime)
}

/// The fix must not regress: a user record with a lone `shouldRetry` field is
/// NOT the `RetryPolicy` shape and must still fail closed with IPE-L0107.
#[test]
fn retry_policy_nearmiss_still_rejects() {
    let root = repo_root();
    let golden_dir = fixture_named(&root, "retry_policy_shape_nearmiss");
    let out = crate::support::scratch_root().join("ipec_i963_nearmiss_guard");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&golden_dir, &out, &runtime);
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
    let result = built(&root, &out);
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
    let result = built(&root, &out);
    assert!(
        result.is_ok(),
        "RetryPolicy field access fixture must be accepted; got: {result:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
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
}

/// A policy built only from retry kernels: no signature or body type slot names the record.
///
/// `Task.retryOn pred Task.defaultRetryPolicy` passed straight to
/// `Task.retryWith` mentions `RetryPolicy` in no function signature, record
/// literal, or lambda type, so the record shape must survive the dead-type
/// prune through the retry kernels' own use of its struct.
const KERNEL_ONLY_POLICY: &str = r#"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Io as Io
import Ipe.String
import Ipe.Task as Task


main : Task Error ()
main =
    Task.andThen
        (\n -> Io.println (String.fromInt n))
        (Task.retryWith
            (Task.retryOn (\_ -> False) Task.defaultRetryPolicy)
            (Task.succeed 4)
        )
"#;

fn built_kernel_only_policy(name: &str) -> (Result<(), CliError>, PathBuf) {
    let fixture = crate::root_fixture::main(KERNEL_ONLY_POLICY);
    let out = crate::support::scratch_root().join(name);
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    (crate::root_fixture::build(&fixture, &out, &runtime), out)
}

/// A policy named by retry kernels alone passes ipe (no IPE-I0001 for a pruned struct).
#[test]
fn kernel_only_retry_policy_emits() {
    let (result, _) = built_kernel_only_policy("ipec_i963_kernel_only_policy");
    assert!(
        result.is_ok(),
        "a policy built only from `retryOn` and `defaultRetryPolicy` must keep its \
         `RetryPolicy` struct; got: {result:?}"
    );
}

/// Under `IPE_E2E=1`: the kernel-only policy builds and runs the retried task.
#[test]
fn kernel_only_retry_policy_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (result, out) = built_kernel_only_policy("ipec_i963_kernel_only_policy_e2e");
    assert!(result.is_ok(), "the build must succeed: {result:?}");
    let outcome = crate::support::build_and_run_emitted("retry_policy_kernel_only_policy", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "the kernel-only policy must build and exit 0; stdout: {:?}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim(),
        "4",
        "the retried task's result prints"
    );
}

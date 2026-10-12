//! Regression: `Task.retryOn` / `Task.withRetryOn` used in a pipe were
//! type-checked (ipe exit 0) but then rejected by `ipe dev build` with IPE-L0107
//! (storing a function value in a record field).
//!
//! `Task.retryOn : (e -> Bool) -> RetryPolicy e -> RetryPolicy e` returns a
//! `RetryPolicy e` — an anonymous record carrying a `shouldRetry` predicate
//! FUNCTION. A pipe
//! (`Task.linearBackoff 5 (Duration.millis 1) |> Task.retryOn (\_ -> False)`)
//! lowers `retryOn` through the value-callee (`Expr::Apply`) arm, whose
//! fn-in-derive-carrier gate saw a fn-typed parameter plus a fn-carrying result
//! record and rejected the application. That gate lacked the `RetryPolicy`
//! exemption its sibling gates already carry: the `RetryPolicy` struct is
//! kernel-managed (`emit_task_retry_call` emits `shouldRetry` as an
//! `Arc<dyn Fn>` field and skips the `Clone`/`PartialEq` derives), so it is a
//! sound end-to-end path, not a generic derive carrier. The gate exempts
//! exactly the closed four-field shape; a user record that merely names a
//! `shouldRetry` field, or any near-miss, still fails closed.
//!
//! This golden is the end-to-end SEAL lock: the emitted crate must `cargo
//! build` and print the retried Task's value `x`.

use std::path::{Path, PathBuf};

use ipe::CliError;

use crate::support::repo_root;

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("retry_policy_value_callee")
        .join("Main.ipe")
}

fn fixture_entry_named(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

/// Build the fixture; return whether the frontend accepted + emitted it.
fn built(root: &Path, out: &Path) -> Result<(), ipe::CliError> {
    let entry = fixture_entry(root);
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, out, &runtime)
}

/// Emit assertion (default gate): the frontend must accept the piped
/// `retryOn` program and emit its crate — the exit-0-then-cargo-fail this
/// regression closed was invisible here (the failure was at emit/`ipe dev build`,
/// not at type-check), so an accept alone is not enough; see the SEAL test.
#[test]
fn retry_policy_value_callee_emits() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_retry_policy_value_callee_emit");
    let built = built(&root, &out);
    assert!(
        built.is_ok(),
        "retry_policy_value_callee: piped `Task.retryOn` must be accepted + \
         emitted (the value-callee fn-carrier gate exempts the `RetryPolicy` \
         `shouldRetry` record), got: {built:?}"
    );
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, actually `cargo build` the
/// emitted crate and run it. The `RetryPolicy` struct's `shouldRetry:
/// Arc<dyn Fn>` field must emit soundly; the crate builds and prints `x` (the
/// value of the succeeding, non-retried Task).
#[test]
fn retry_policy_value_callee_builds_and_runs() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_retry_policy_value_callee_e2e");
    let built = built(&root, &out);
    assert!(
        built.is_ok(),
        "retry_policy_value_callee: must be accepted, got: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("retry_policy_value_callee", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "retry_policy_value_callee: emitted crate must build and exit 0 (the \
         `RetryPolicy` `shouldRetry` fn field emits as an `Arc<dyn Fn>` on a \
         kernel-managed struct); stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(
            outcome.stdout.trim(),
            "x",
            "wrong runtime output — the succeeding Task carries the value `x`"
        );
    }
}

/// SEAL negative: the `RetryPolicy` exemption must be scoped to the FULL closed
/// `{ baseMs, maxAttempts, shouldRetry, strategy }` shape, never a lone
/// `shouldRetry` key. A USER record `{ shouldRetry : Int -> Int }` threaded
/// through the value-callee path is NOT that kernel record — exempting it would
/// route its fn field onto the kernel-struct `Arc` carrier while the ordinary
/// record-literal emitter supplies a `Box` value, an `ipe`-accept-then-`cargo`-
/// fail (E0308). The gate must fail closed with IPE-L0107 so the near-miss can
/// never regress into a SEAL breach. Runs WITHOUT `IPE_E2E` — the assertion is
/// the gate itself, not an emitted build.
#[test]
fn retry_policy_shape_nearmiss_rejects() {
    let root = repo_root();
    let entry = fixture_entry_named(&root, "retry_policy_shape_nearmiss");
    let out = crate::support::scratch_root().join("ipec_retry_policy_shape_nearmiss");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_L0107),
        "a user `{{ shouldRetry : Int -> Int }}` record is NOT the closed \
         RetryPolicy shape and must fail closed with IPE-L0107 (never accept + \
         cargo-fail); got build result {built:?}"
    );
}

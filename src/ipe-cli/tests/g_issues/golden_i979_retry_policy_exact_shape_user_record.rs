//! Positive boundary test for the `RetryPolicy` exact-shape guard.
//!
//! A USER record that shares three of the four `RetryPolicy` field names
//! (`baseMs`, `maxAttempts`, `shouldRetry`) but uses a different fourth field
//! (`mode : Int` instead of `strategy : BackoffStrategy`) COMPILES AND RUNS
//! correctly.  This is NOT a bypass of IPE-L0107: the fn-value-reuse
//! `Arc<dyn Fn>` carrier handles the function field; the generic DERIVE carrier
//! is never involved, so L0107 does not apply.
//!
//! The test documents the intended boundary: the kernel `RetryPolicy` exemption
//! matches exactly the four-field closed shape `{ baseMs, maxAttempts,
//! shouldRetry, strategy }`. A record with even one different field name is a
//! plain user record and goes through the standard fn-value-reuse path.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("retry_policy_exact_shape_user_record")
        .join("Main.ipe")
}

/// The frontend must accept the user record with `shouldRetry : Int -> Bool`
/// and a different fourth field — no IPE-L0107, no ICE.
#[test]
fn retry_policy_exact_shape_user_record_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i979_exact_shape_emit");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a user record with `shouldRetry : Int -> Bool` and a non-matching fourth \
         field must be accepted and emitted — fn-value-reuse carrier handles the \
         function field, L0107 does not apply; got: {built:?}"
    );
}

/// Under `IPE_E2E=1`: build and run the emitted crate.
/// `makePolicy 3 1` produces a policy with `maxAttempts=3`.
/// `applyPolicy p 1` → `"retry"` (1 < 3 = true).
/// `applyPolicy p 5` → `"done"` (5 < 3 = false).
/// `p.maxAttempts` → `"3"`.
/// Expected output: `"retry,done,3"`.
#[test]
fn retry_policy_exact_shape_user_record_builds_and_runs() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i979_exact_shape_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "retry_policy_exact_shape_user_record: must be accepted; got: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome =
            crate::support::build_and_run_emitted("retry_policy_exact_shape_user_record", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "emitted crate must build and exit 0; stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(
            outcome.stdout.trim(),
            "retry,done,3",
            "wrong runtime output — `applyPolicy p 1` = retry, `applyPolicy p 5` = done, \
         `p.maxAttempts` = 3"
        );
    }
}

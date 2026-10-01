//! SEAL test for the `BackoffStrategy` ADT.
//!
//! Verifies that all four strategies are correctly built by their respective
//! constructors: `linearBackoff` → `Linear`, `exponentialBackoff` →
//! `Exponential`, `withJitter` upgrades each to its jitter variant.
//! `retryWith` accepts a policy with any strategy and runs the task.
//! Field access on `p.strategy` and chained `withMaxAttempts`/`withBaseMs`
//! all emit and execute correctly.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("backoff_strategy_adt")
        .join("Main.ipe")
}

/// The frontend must accept all four `BackoffStrategy` variants used via the
/// builder functions, field access on `p.strategy`, and `retryWith` — no
/// IPE-L0107, no ICE.
#[test]
fn backoff_strategy_adt_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i1421_backoff_strategy_emit");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "BackoffStrategy builders and retryWith must be accepted and emitted; \
         got: {built:?}"
    );
}

/// Under `IPE_E2E=1`: build and run the emitted crate.
///
/// All six retry policies succeed immediately (Task.succeed) and chain through
/// to the final `Io.println "ok"` + `Io.println "5"` sequence.
/// Expected output: `"5\nok"`.
#[test]
fn backoff_strategy_adt_builds_and_runs() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i1421_backoff_strategy_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "backoff_strategy_adt: must be accepted; got: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("backoff_strategy_adt", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "emitted crate must build and exit 0; stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(
            outcome.stdout.trim(),
            "5\nok",
            "wrong runtime output — expected maxAttempts=5 from withMaxAttempts then 'ok'"
        );
    }
}

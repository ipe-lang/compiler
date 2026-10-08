//! A database failure reaches Ipê code as a typed `DbFailure`.
//!
//! The `db_failure_typed` golden triggers a real unique violation, a trigger
//! `RAISE(ABORT, …)` and a read-only write against a live `sqlite::memory:`
//! database and prints the `DbFailure` each carries in `ErrorInfo.details`,
//! with an accepted insert before and after as controls.
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test g_db golden_db_failure_typed
//! ```

use crate::support::repo_root;

const GOLDEN: &str = "db_failure_typed";

/// Build and run the `db_failure_typed` golden under `IPE_E2E=1`, asserting its
/// stdout matches the oracle.
///
/// Each failure line names the variant `case` read from the details, so a
/// misclassified code, a dropped `Database` carrier, or a failure that no
/// longer fails turns its line red. Under `IPE_E2E=1` the emitted project is
/// built and run, so `ipe` accepting a match over `DbFailure` is proven to
/// `cargo build`.
#[test]
fn db_failure_matches_oracle() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let dir = root.join("tests").join("golden").join(GOLDEN);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "build failed for {GOLDEN}: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
    crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

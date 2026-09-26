//! `Store.insertIfAbsent`: the first write of a key wins.
//!
//! The `db_store_insert_if_absent_guard` golden drives the refusals (a store
//! with no primary key and no `unique` column, a key the database fills) and
//! the accepted shape (a composite key: the first insert of a key affects one
//! row, a second insert of that key affects none and leaves the stored row
//! unchanged, a key differing in one column is inserted) against a live
//! `sqlite::memory:` database, one oracle line each.
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test g_db golden_db_store_insert_if_absent
//! ```

use crate::support::repo_root;

const GOLDEN: &str = "db_store_insert_if_absent_guard";

/// Build and run the `db_store_insert_if_absent_guard` golden under
/// `IPE_E2E=1`, asserting its stdout matches the oracle.
///
/// Every refusal line is pinned on Store's own message naming
/// `insertIfAbsent`, and the refusal stores are never created, so a refusal
/// that reached SQL surfaces as a missing-table error and the line goes red.
#[test]
fn insert_if_absent_matches_oracle() {
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

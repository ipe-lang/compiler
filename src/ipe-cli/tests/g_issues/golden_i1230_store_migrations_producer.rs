//! Regression guard: the REAL `Store.migrations` producer must fold a
//! multi-op store to the exact ordered ledger (frozen create + rename entries),
//! and must reject a no-op rename with `Err`.
//!
//! Scenario:
//!   `Store.fromColumns "users" [textColumn "id", textColumn "name", intColumn "age"]`
//!   `|> Result.map (StoreU.primaryKey "id")`
//!   `|> Result.map (Store.renameColumn "name" "full_name")`
//!   `|> Result.map (Store.renameTable "accounts")`
//!   `|> Result.andThen Store.migrations`
//!
//! Expected ledger (in order):
//!   1. `create_users` — `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT, age INTEGER)`
//!   2. `rename_column_users_name_to_full_name` — `ALTER TABLE users RENAME COLUMN name TO full_name`
//!   3. `rename_table_users_to_accounts` — `ALTER TABLE users RENAME TO accounts`
//!
//! Fail-closed: a no-op rename (`from == to`) must yield `Err`, not an empty-or-wrong ledger.
//!
//! Gated on `IPE_E2E=1`; the program is built and RUN (stdout matched against
//! the checked-in `expected.txt`) — a build-only pass does not exercise the
//! producer.

use std::path::{Path, PathBuf};

const GOLDEN: &str = "i1230_store_migrations_producer";

fn fixture_dir(root: &Path) -> PathBuf {
    root.join("tests").join("golden").join(GOLDEN)
}

/// Build and run the golden under `IPE_E2E=1`, asserting stdout matches
/// the checked-in `expected.txt` byte-for-byte.
#[test]
fn store_migrations_producer_runs_and_matches() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = crate::support::repo_root();
    let dir = fixture_dir(&root);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe dev build must accept the migrations producer program, got: {built:?}"
    );

    let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
    crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "{GOLDEN}: must exit 0");
}

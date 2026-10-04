//! Regression guard: `Store.renameColumn` is one mapping over the whole store.
//!
//! Against an in-memory `SQLite` database the golden proves that, after a rename:
//!   * a raw-column store still OMITS its `defaultNow` / `touchOnUpdate` columns
//!     on `insert` and `update`, so a client value never overwrites them;
//!   * a codec store binds the renamed columns, keys `update` / `get` on the
//!     renamed primary key, and decodes `insertReturning` / `findBy` rows;
//!   * every query-layer name is the declared name emitted as the current
//!     column: a `Cond` accessor, `orderDesc`, `findBy`, a join key, a join
//!     filter, a join sort column, and a `select` projection;
//!   * a current name that is not a declared one is refused with a typed error
//!     by `orderAsc` and `findBy`;
//!   * `createSql` is the frozen create entry (frozen table + frozen columns),
//!     identical to the first `migrations` entry;
//!   * an index on a renamed column targets the current table and column;
//!   * a rename of an unknown column, or onto an existing one, is refused by
//!     `migrations` and leaves the current columns unchanged.
//!
//! The emit gate always runs; under `IPE_E2E=1` the program is built and RUN
//! and its stdout matched against the checked-in `expected.txt`.

use std::path::{Path, PathBuf};

const GOLDEN: &str = "db_store_rename_column";

fn fixture_dir(root: &Path) -> PathBuf {
    root.join("tests").join("golden").join(GOLDEN)
}

/// Emit gate: the frontend must accept the rename program.
#[test]
fn db_store_rename_column_emits() {
    let root = crate::support::repo_root();
    let entry = fixture_dir(&root).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe dev build must accept the rename program, got: {built:?}"
    );
}

/// Build and run the golden under `IPE_E2E=1`, asserting stdout matches the
/// checked-in `expected.txt` byte-for-byte.
#[test]
fn db_store_rename_column_runs_and_matches() {
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
        "{GOLDEN}: ipe dev build must accept the rename program, got: {built:?}"
    );

    let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
    crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "{GOLDEN}: must exit 0");
}

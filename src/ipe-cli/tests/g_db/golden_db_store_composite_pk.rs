//! Composite primary keys in the `Store` `Draft` model.
//!
//! A composite key's column list is parsed once, at declaration, into a typed
//! key. The runtime refusals (an empty or one-column list, an invalid
//! identifier, an unknown or repeated column, a second key declaration) are
//! driven end to end by the `db_store_composite_pk_guard` golden, whose oracle
//! pins one `:rejected` line per refusal. The `db_store_composite_pk_ops` golden
//! drives the database-backed refusals: by-key operations on a composite store,
//! every key column dropped from an `updateWhere` SET, and every operation on a
//! store with an illegal key declaration. An accessor naming a field the row
//! type lacks never reaches the runtime: it is an ipe-time `IPE-T0012`.
//!
//! ```text
//! # gate check only (fast):
//! cargo test -p ipe --test g_db golden_db_store_composite_pk
//! # full (cargo build + run the guard fixture):
//! IPE_E2E=1 cargo test -p ipe --test g_db golden_db_store_composite_pk
//! ```

use std::path::{Path, PathBuf};

use ipe::CliError;

use crate::support::repo_root;

fn golden_dir(root: &Path, golden: &str) -> PathBuf {
    root.join("tests").join("golden").join(golden)
}

/// Build and run `golden` under `IPE_E2E=1`, asserting its stdout matches the oracle.
fn assert_golden_e2e(golden: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let dir = golden_dir(&root, golden);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{golden}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "build failed for {golden}: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted(golden, &out);
    crate::support::assert_go_parity(golden, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

/// Every composite-key refusal returns its typed `Err` from `createSql`.
///
/// The accessor forms lower through the intercept and a single-column key is
/// unaffected — one oracle line each. Under `IPE_E2E=1` the emitted project is
/// built and run, so `ipe` accepting the accessor forms is also proven to
/// `cargo build`.
#[test]
fn composite_pk_refusals_match_oracle() {
    assert_golden_e2e("db_store_composite_pk_guard");
}

/// Composite and illegal keys fail closed against a live `sqlite::memory:` table.
///
/// The by-key operations on a composite store fail with the composite-key
/// error; `updateWhere` on a composite store leaves every key column untouched;
/// every read and write on a store whose key declaration is illegal fails with
/// the recorded error, and `secured` refuses it — with a final snapshot proving
/// no refused operation reached the database.
#[test]
fn composite_pk_db_refusals_match_oracle() {
    assert_golden_e2e("db_store_composite_pk_ops");
}

/// A `compositePrimaryKey2` accessor naming a field the row type does not have
/// MUST be rejected at ipe time with `IPE-T0012` — a key over a column the table
/// lacks is unrepresentable, not a runtime `Err`.
#[test]
fn composite_pk_unknown_field_accessor_is_rejected() {
    const GOLDEN: &str = "db_store_composite_pk_unknown_field_rejected";
    let root = repo_root();
    let entry = golden_dir(&root, GOLDEN).join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_db_store_composite_pk_unknown_field");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0012),
        "a composite-key accessor naming a missing field MUST be rejected with \
         IPE-T0012; got: {built:?}"
    );
}

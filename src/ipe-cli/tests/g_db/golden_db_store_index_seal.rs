//! End-to-end SEAL for `Store.index` and `Store.indexNamed` — declares
//! single-column, composite, and named performance indexes on a codec-derived
//! store and exercises them through `Store.create`. Every identifier (index name,
//! table, each column) is validated through `validSqlIdent` and cross-checked
//! against the store's codec-derived column list before it reaches any DDL string.
//!
//! THE SEAL: `ipe` accepting the `index`/`indexNamed` program (exit 0) must
//! imply a buildable emitted crate. Under `IPE_E2E=1` the emitted crate must
//! `cargo build` (no live database is needed — the index DDL is assembled,
//! never executed in this test).
//!
//! Security invariants verified:
//!   * Every identifier (index name, table, each column) is validated through
//!     `validSqlIdent` before it can reach any DDL string.
//!   * Each column is cross-checked against the store's codec-derived column
//!     list (parse-don't-validate: an unknown column fails closed).
//!   * DDL-only: no values are involved, no parameter surface exists for indexes.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "db_store_index_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept the `Store.index` / `Store.indexNamed`
/// program — the index combinators, DDL generation, and `Store.create` with
/// index entries all resolve, scheme, lower, and emit.
#[test]
fn db_store_index_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_index_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "`Store.index` / `Store.indexNamed` on a codec store must be accepted \
         and emitted, got: {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate — the
/// `CREATE INDEX` DDL migration entries, the `foldIndexes` validation path, and
/// the `Db.migrate` call must all compile to valid Rust.
#[test]
fn db_store_index_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_index_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

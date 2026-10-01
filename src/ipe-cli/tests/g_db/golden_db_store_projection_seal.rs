//! End-to-end SEAL for the typed single-column projection over a two-store inner
//! join (`Store.join` / `Store.select` / `Store.selectToList`). Two
//! `Codec.auto`-derived stores join on `books.author_id = authors.id`; `select`
//! projects one column (`author.name`), so the join lowers to ONE parameterized
//! statement that selects exactly that column (`SELECT a1.name AS p0 FROM …`,
//! column pushdown) over the two-table `FROM`. Each projected row comes back as a
//! `Row` keyed by the output name `p0`; the projected identifier is re-validated
//! at the runtime boundary, and the filter value binds as a parameter — never
//! interpolated.
//!
//! THE SEAL: `ipe` accepting the projected program (exit 0) must imply a
//! buildable emitted crate. Under `IPE_E2E=1` the emitted crate must
//! `cargo build` (no live database or network is needed — the projection is
//! assembled, never executed).

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "db_store_projection_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept the `Store.select` / `Store.selectToList`
/// program (the `Select` type, the `Store_select` projection intercept, and the
/// `Db.findProjection` kernel all resolve, scheme, lower, and emit).
#[test]
fn db_store_projection_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_projection_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a `Store.select` single-column projection run through `selectToList` \
         must be accepted and emitted, got: {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate — the
/// single-column `SELECT alias.column AS p0` projection over the two-table
/// `FROM` and the `p0`-keyed row decode must all compile.
#[test]
fn db_store_projection_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_projection_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

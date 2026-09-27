//! End-to-end SEAL for the typed two-store inner join (`Store.join` /
//! `joinFilterRight` / `joinToList`). Two `Codec.auto`-derived stores join on
//! `books.author_id = authors.id`; the join lowers to ONE parameterized
//! statement over a two-table `FROM` (`Db.findJoin`), and each matched pair is
//! decoded through its own store codec. Every identifier (both tables, both
//! aliases, every projected column) is re-validated at the runtime boundary, and
//! the filter value binds as a parameter — never interpolated.
//!
//! THE SEAL: `ipe` accepting the joined program (exit 0) must imply a buildable
//! emitted crate. Under `IPE_E2E=1` the emitted crate must `cargo build` (no live
//! database or network is needed — the join is assembled, never executed).

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "db_store_join_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept the `Store.join` / `joinFilterRight` /
/// `joinToList` program (the `Joined a b` type, the `Store_join` accessor
/// intercept, and the `Db.findJoin` kernel all resolve, scheme, lower, and
/// emit).
#[test]
fn db_store_join_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_join_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable — skip
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a `Store.join` inner join projected through `joinToList` must be \
         accepted and emitted, got: {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate — the
/// two-table `FROM`, the `alias__column` projection split, and the paired-map
/// codec decode must all compile.
#[test]
fn db_store_join_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_join_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

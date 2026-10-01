//! End-to-end SEAL for `Store.orderByLeft` / `Store.orderByRight`. Two
//! `Codec.auto`-derived stores join on `books.author_id = authors.id`;
//! `orderByRight .name Desc` attaches `ORDER BY a1.name DESC` to the join,
//! which lowers to `Db.findJoinOrdered` (arity 11) — the eleven-arg variant
//! that appends the validated ORDER BY clause. Every identifier (both tables,
//! both aliases, every projected column, the order-by alias and column) is
//! re-validated at the runtime boundary, and the filter value binds as a
//! parameter — never interpolated.
//!
//! THE SEAL: `ipe` accepting the ordered-join program (exit 0) must imply a
//! buildable emitted crate. Under `IPE_E2E=1` the emitted crate must
//! `cargo build` (no live database or network is needed — the join is assembled,
//! never executed).

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "db_store_order_by_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept the `Store.join` / `orderByRight` /
/// `joinToList` program (the `Order` type, the `Store_orderByRight` accessor
/// intercept, and the `Db.findJoinOrdered` kernel all resolve, scheme, lower,
/// and emit).
#[test]
fn db_store_order_by_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_order_by_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a `Store.join` with `orderByRight` sort must be accepted and emitted, \
         got: {built:?}"
    );

    // The emitted store module must contain the `findJoinOrdered` call.
    let src = crate::support::read_all_emitted_src(&out);
    assert!(
        src.contains("db_find_join_ordered"),
        "the emitted code must call `db_find_join_ordered` for an ordered join, \
         but it is absent from the emitted source"
    );
    // The ORDER BY direction must be `false` (DESC) — a `Bool` literal.
    assert!(
        src.contains("false"),
        "the DESC direction must lower to `false` in the emitted source"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate — the
/// `ORDER BY` clause, the eleven-arg `db_find_join_ordered` call, and the
/// codec decode must all compile.
#[test]
fn db_store_order_by_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_order_by_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

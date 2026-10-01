//! End-to-end SEAL for `Store.add` / `Store.sub` / `Store.mul` in typed
//! projection bodies. Three `Store.select` calls:
//!
//! - `Store.add item.quantity (Store.literal 1)` — column + literal.
//! - `Store.sub item.price item.discount` — two column operands.
//! - `Store.mul item.price (Store.literal 2)` — column + literal.
//!
//! Each must lower to SQL with a parenthesised arithmetic expression, and the
//! emitted crate must `cargo build` under `IPE_E2E=1`.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "db_store_projection_arith_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept all three arithmetic projection shapes,
/// build the descriptor terms, and emit the row decoders.
#[test]
fn db_store_projection_arith_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_projection_arith_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "Store.add/sub/mul projections must be accepted and emitted, got: {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, `cargo build` the emitted crate — the
/// `(a0.quantity + ?)`, `(a0.price - a0.discount)`, and `(a0.price * ?)`
/// projection terms, the descriptor term list, and the row decoders must all
/// compile.
#[test]
fn db_store_projection_arith_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_projection_arith_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

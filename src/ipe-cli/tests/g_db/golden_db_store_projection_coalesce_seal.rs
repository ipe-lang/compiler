//! End-to-end SEAL for `Store.coalesce` in typed projection bodies.
//! Two `Store.select` calls:
//!
//! - `Store.coalesce author.name (Store.literal "unknown")` — column + literal fallback.
//! - `Store.coalesce book.title author.name` — two column operands.
//!
//! Both must lower to SQL with `COALESCE(…)`, and the emitted crate
//! must `cargo build` under `IPE_E2E=1`.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "db_store_projection_coalesce_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept both `Store.coalesce` projection shapes
/// (column + literal and column + column), build the descriptor triples, and
/// emit the row decoders.
#[test]
fn db_store_projection_coalesce_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_projection_coalesce_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable — skip
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "Store.coalesce projections must be accepted and emitted, got: {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, `cargo build` the emitted crate — the
/// `COALESCE(a1.name, ?)` and `COALESCE(a0.title, a1.name)` projection terms,
/// the descriptor triple list, and the row decoders must all compile.
#[test]
fn db_store_projection_coalesce_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_projection_coalesce_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

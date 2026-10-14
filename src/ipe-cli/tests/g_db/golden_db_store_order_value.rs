//! End-to-end SEAL for a value of type `Store.Order` in a user annotation.
//!
//! `Ipe.Db.Store` declares `type Order = Asc | Desc`, a distinct head from the
//! builtin comparison `Order` (`LT | EQ | GT`). A binding annotated
//! `Store.Order` and a `case` over it must lower to the Store enum its
//! constructors build; lowering the annotation to the builtin `IpeOrder`
//! carrier would leave the `match` arms building `IpeDbStoreOrder` against an
//! `IpeOrder` scrutinee, an `E0308` after `ipe` exits 0.
//!
//! THE SEAL: under `IPE_E2E=1` the emitted crate must `cargo build`, run, and
//! print `desc`.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "db_store_order_value";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate: the frontend accepts and emits the `Store.Order` value program.
#[test]
fn db_store_order_value_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_order_value_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a `Store.Order` annotation must be accepted and emitted, got: {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, `cargo build` and run the emitted crate.
#[test]
fn db_store_order_value_seal_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_order_value_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{GOLDEN} must cargo-build and exit 0; stdout: {:?}",
        outcome.stdout
    );
    assert_eq!(outcome.stdout.trim(), "desc", "{GOLDEN} stdout mismatch");
}

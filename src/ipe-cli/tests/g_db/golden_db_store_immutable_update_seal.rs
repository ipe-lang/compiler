//! SEAL + emit-content proof that a secured `Store.updateAs` enforces an
//! `immutable` policy column: an authed route mints a `Principal` (sole minter:
//! the fail-closed auth middleware) and its handler updates a secured store as
//! that caller. The store's policy marks `.createdAt` immutable, so the emitted
//! `updateAs` routes its SET binds through the immutable-drop before building the
//! UPDATE — the caller's value for the immutable column never reaches the SET, so
//! it cannot change after insert.
//!
//! Two proofs:
//!   * emit-content — the emitted `Ipe.Db.Store` module's `update_as` calls
//!     `drop_immutable_columns` on the SET binds (the load-bearing omission), so
//!     the immutable column can never be written by an update;
//!   * THE SEAL — under `IPE_E2E=1` the emitted crate must `cargo build` (the
//!     `jwt`/`db` features the authed + store-update surface requires are
//!     selected; no live database or network is needed — the route builder is
//!     assembled, never served).

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "db_store_immutable_update_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate + immutable-drop content: the frontend must accept the authed-route
/// `updateAs` program and emit a `Ipe.Db.Store` module whose `update_as` drops
/// the policy's immutable columns from the SET before building the UPDATE.
#[test]
fn immutable_update_drops_immutable_column_from_set() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_immutable_update_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable — skip
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "an authed route whose handler calls `Store.updateAs` on a store with an \
         `immutable` policy column must be accepted and emitted, got: {built:?}"
    );

    let store_mod = out
        .join("src")
        .join("ipe_mods")
        .join("ipe_mod_ipe_db_store.rs");
    let src = std::fs::read_to_string(&store_mod).expect("emitted store module must exist");

    // The update path must route its SET binds through the immutable-drop. Without
    // this call an update would write the immutable column, breaking the
    // `immutable` guarantee — so its presence is the enforcement point.
    assert!(
        src.contains("user_ipe_db_store_drop_immutable_columns"),
        "emitted `update_as` must drop immutable-policy columns from the SET \
         (call to `drop_immutable_columns` absent) — the immutable column would \
         otherwise be writable by an update"
    );
    // Prove the drop is wired INTO the update path, not merely defined.
    let update_as = src
        .split_once("fn user_ipe_db_store_update_as")
        .and_then(|(_, rest)| rest.split_once("\npub(crate) fn ").map(|(body, _)| body))
        .unwrap_or(&src);
    assert!(
        update_as.contains("user_ipe_db_store_drop_immutable_columns"),
        "the immutable-drop must be applied inside `update_as`'s SET projection, \
         not only defined elsewhere"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate — `ipe`
/// accepting the program (exit 0) must imply a buildable emitted crate, with the
/// features the authed + store-update surface requires selected.
#[test]
fn immutable_update_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_immutable_update_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

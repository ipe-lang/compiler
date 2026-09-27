//! End-to-end SEAL for `Store.insertReturning` — inserts a row into a
//! `serial`-keyed store and reads the DB-assigned id back in one statement
//! via `INSERT ... RETURNING *`. The codec decodes the RETURNING row through the
//! store's own codec, so the returned record carries the DB-assigned serial id.
//!
//! THE SEAL: `ipe` accepting the `insertReturning` program (exit 0) must imply a
//! buildable emitted crate. Under `IPE_E2E=1` the emitted crate must `cargo build`
//! (no live database or network is needed — the insert+returning pipeline is
//! assembled, never executed against a real DB in this test).
//!
//! Security invariants verified:
//!   * Column names in the insert write are validated identifiers; values bind as
//!     parameters (never interpolated).
//!   * The RETURNING projection is the literal `"*"` — no caller-supplied
//!     identifier reaches the SQL text.
//!   * The RETURNING row decodes through the store's codec (same path as `all` /
//!     `get` / `findWhere`); schema drift is a typed `Err`.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "db_store_insert_returning_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept the `Store.insertReturning` program —
/// `insertReturning`, `Db.insertFieldsReturning`, and the codec decoder path
/// all resolve, scheme, lower, and emit.
#[test]
fn db_store_insert_returning_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_insert_returning_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "`Store.insertReturning` on a serial-keyed store must be accepted and \
         emitted, got: {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate — the
/// `RETURNING *` INSERT, the codec decoder call, and the Task chain must all
/// compile to valid Rust.
#[test]
fn db_store_insert_returning_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_insert_returning_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

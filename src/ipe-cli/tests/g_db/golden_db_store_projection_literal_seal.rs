//! End-to-end SEAL for `Store.literal` in a typed projection body. A mixed
//! projection — `( Store.literal "fiction", author.name )` — lowers to
//! `SELECT ? AS p0, a1.name AS p1 FROM …`: the literal value binds as a SQL
//! parameter at the `p0` position, the column reference projects to `p1`.
//!
//! THE SEAL: `ipe` accepting the program (exit 0) must imply a buildable
//! emitted crate. Under `IPE_E2E=1` the emitted crate must `cargo build` —
//! the mixed projection, its sentinel-pair list, and the concrete
//! `projectionDecode2` decode for `( String, String )` must all compile.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "db_store_projection_literal_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept the `Store.select` body that contains a
/// `Store.literal` call (the `StoreLiteral` kernel, the sentinel-pair list, and
/// the `extraBinds` record field all resolve, scheme, lower, and emit).
#[test]
fn db_store_projection_literal_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_projection_literal_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable — skip
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a `Store.literal` mixed-projection must be accepted and emitted, got: {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate — the
/// `( Store.literal "fiction", author.name )` mixed projection, the
/// `SELECT ? AS p0, a1.name AS p1` statement builder, and the
/// `projectionDecode2` row decoder must all compile.
#[test]
fn db_store_projection_literal_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_projection_literal_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

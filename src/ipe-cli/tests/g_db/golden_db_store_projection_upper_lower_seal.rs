//! End-to-end SEAL for `Store.upper` and `Store.lower` in typed projection
//! bodies. Two `Store.select` calls:
//!
//! - `Store.upper author.name` — single column, upper-cased.
//! - `( Store.lower book.title, author.name )` — two columns, first lower-cased.
//!
//! Both must lower to SQL with `UPPER(…)` / `LOWER(…)`, and the emitted crate
//! must `cargo build` under `IPE_E2E=1`.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "db_store_projection_upper_lower_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept both `Store.upper` and `Store.lower`
/// projection bodies (kernels pre-resolved, sentinel pairs built, decode emitted).
#[test]
fn db_store_projection_upper_lower_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_projection_upper_lower_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "Store.upper / Store.lower projections must be accepted and emitted, got: {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, `cargo build` the emitted crate — the
/// `UPPER(a1.name)` and `LOWER(a0.title)` projection terms, the sentinel-pair
/// list, and the row decoders must all compile.
#[test]
fn db_store_projection_upper_lower_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_projection_upper_lower_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

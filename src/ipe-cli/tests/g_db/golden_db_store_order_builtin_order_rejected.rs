//! `Store.Order` and the builtin `Order` are distinct types.
//!
//! `Ipe.Db.Store` declares `type Order = Asc | Desc` for a join's sort
//! direction; the builtin `Order` is `LT | EQ | GT`. The names agree, the
//! constructors do not, so `Store.Asc == LT` is a `TYPE MISMATCH` (IPE-T0001)
//! at ipe time — never accepted and left to fail in the emitted Rust.

use std::path::{Path, PathBuf};

use ipe::CliError;

use crate::support::repo_root;

fn fixture_entry(root: &Path, golden: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(golden)
        .join("Main.ipe")
}

/// Comparing `Store.Asc` with `LT` MUST be rejected at ipe time with IPE-T0001.
#[test]
fn store_order_compared_with_builtin_order_is_rejected() {
    const GOLDEN: &str = "db_store_order_builtin_order_rejected";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_db_store_order_builtin_order_rejected");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    // Pin the reason, not just the failure: an unrelated build error must not
    // stand in for the head-identity refusal.
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0001),
        "`Store.Asc == LT` MUST be rejected with IPE-T0001 (`Store.Order` and the \
         builtin `Order` are distinct types); got: {built:?}"
    );
}

//! Deny-by-default: querying an UNCLASSIFIED `Draft` must be an ipe-time type
//! error — never accepted.
//!
//! `Store.fromCodec` returns a `Draft a` (a table whose schema is known but
//! whose access intent is not declared). The read and write operations
//! (`all` / `get` / `insert` / …) accept only a classified `Store a`, reachable
//! solely through `Store.public` / `Store.secured`. Passing a `Draft` straight
//! to `Store.all` — the "forgot to classify this table" mistake — is a
//! `TYPE MISMATCH` (IPE-T0001): the unqueryable-by-construction guarantee that
//! makes the unsecured-by-accident state unrepresentable.

use std::path::{Path, PathBuf};

use crate::golden_app_settings_front_door::{emitted_rust, judge_rejection};
use crate::support::repo_root;

fn fixture_entry(root: &Path, golden: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(golden)
        .join("Main.ipe")
}

/// A read (`Store.all`) applied to an unclassified `Draft` MUST be rejected at
/// ipe time — the only path to a queryable `Store a` is `public` / `secured`.
#[test]
fn draft_query_without_classification_is_rejected() {
    const GOLDEN: &str = "db_store_draft_query_rejected";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_db_store_draft_query_rejected");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    // Pin the REASON, not just the failure: a `Draft` read is a type mismatch
    // (Store expected, Draft found) — IPE-T0001. Asserting only `is_err()` would
    // pass on any unrelated build failure, leaving the deny-by-default guarantee
    // unproven; the `Draft` fragment proves the mismatch is the unclassified
    // table, not some other T0001 in the fixture.
    assert_eq!(
        judge_rejection(&built, ipe_diagnostics::IPE_T0001, Some("Draft")),
        Ok(()),
        "querying an unclassified `Draft` with `Store.all` MUST be rejected with \
         IPE-T0001 (Store expected, Draft found) — a table is unqueryable until \
         classified with `Store.public` or `Store.secured` (deny-by-default); got: {built:?}"
    );
    assert_eq!(
        emitted_rust(&out),
        None,
        "{GOLDEN}: a rejected build must emit no Rust"
    );
}

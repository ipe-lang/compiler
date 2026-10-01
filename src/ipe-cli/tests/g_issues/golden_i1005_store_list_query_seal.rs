//! SEAL: `Ipe.Db.Store` list-returning queries emit `decodeRows`, a generic
//! helper over the row type `a`.  The helper builds a
//! `Box<dyn Fn(Vec<T1>) -> Vec<T1> + Send + Sync + 'static>` closure that
//! captures a `T1` value, so the enclosing function must carry
//! `where T1: Send + Sync`.  Without the propagated bound the emitted crate
//! is accepted by ipe (exit 0) but fails `cargo build` with E0277 — a SEAL
//! violation affecting every `Store.all` / `Store.findWhere` call site.
//!
//! Root cause: the bound-propagation pass in the lowerer walked only
//! function-level *params* for the capture-of-generic-by-closure check; it
//! did not see the `Ok value ->` match-arm local whose type is `Generic(a)`
//! — that local is captured by the `\more -> value :: more` lambda passed to
//! `Task.map`.  The fix keys the `Sync` obligation on the CLOSURE's own
//! signature: `body_move_closure_captures_generic` fires on any
//! `Lambda`/`SharedLambda` whose param/return type `reaches_bare` the tvar AND
//! that move-captures a free value carrying the tvar bare (a bare-value
//! capture, or a read of a transparent field whose type reaches the tvar).
//!
//! The load-bearing proof is the SEAL check: under `IPE_E2E=1` the emitted
//! crate must `cargo build` (no database connection required — the fixture
//! never executes a query at runtime).

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "store_list_query_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate + byte-identity golden: the frontend must accept a `Store.all`
/// call and emit the checked-in `main.rs` byte-for-byte (the
/// `T1: 'static + Send + Sync + Clone` bound on the row-type var — set by
/// `decodeRows`'s continuation-lambda capture of a match-arm local — is
/// locked in).
#[test]
fn store_list_query_emits_byte_identical() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("main.rs");
    let out = crate::support::scratch_root().join("ipec_i1005_store_list_query_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a `Store.all` call with a generic row decoder must be accepted and \
         emitted (the `T1: Send + Sync` bound must be propagated onto the \
         row-type var), got: {built:?}"
    );

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate.
/// Before the fix this was ipe-accept then `cargo` E0277 (`T1 cannot be
/// shared between threads safely`) — the continuation lambda capturing the
/// match-arm `Ok value` local forced `T1: Sync` but the generic carried no
/// such bound.
#[test]
fn store_list_query_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i1005_store_list_query_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

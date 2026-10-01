//! SEAL: a generic recursive helper whose continuation lambda builds its
//! `List a` result with `List.append [ value ] more` — NO `Cons` node at all —
//! from a captured match-arm local `value : a`.  The emitter writes a
//! `Box<dyn Fn(Vec<T1>) -> Vec<T1> + Send + Sync + 'static>` closure that
//! move-captures `value`, so the enclosing generic must carry
//! `where T1: Send + Sync`.  Without the propagated bound the emitted crate is
//! accepted by ipe (exit 0) but fails `cargo build` with E0277.
//!
//! This is the no-`Cons` shape: the closure body is a `List.append` call, not
//! an `Expr::Cons`.  The `Sync` obligation is keyed on the CLOSURE's own
//! signature (`Vec<T1>` reaches bare `T1`) plus a bare-capture walk, so it fires
//! whatever combinator the body uses.
//!
//! The load-bearing proof is the SEAL check: under `IPE_E2E=1` the emitted
//! crate must `cargo build`.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "generic_capture_append_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate + byte-identity golden: the frontend must accept the
/// `List.append`-building helper and emit the checked-in `main.rs`
/// byte-for-byte (the `T1: 'static + Send + Sync + Clone` bound — set by the
/// closure signature's bare-`T1` reach through `Vec<T1>` — is locked in).
#[test]
fn generic_capture_append_emits_byte_identical() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("main.rs");
    let out = crate::support::scratch_root().join("ipec_i1005_generic_capture_append_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a `List.append`-building continuation lambda over a generic element \
         must be accepted and emitted (the `T1: Send + Sync` bound must be \
         propagated), got: {built:?}"
    );

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate.
/// Before the general capture-site fix this was ipe-accept then `cargo` E0277
/// (`T1 cannot be shared between threads safely`) — the closure captured the
/// match-arm `value` local into a `+ Sync` trait object but the generic
/// carried no `Sync` bound.
#[test]
fn generic_capture_append_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i1005_generic_capture_append_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

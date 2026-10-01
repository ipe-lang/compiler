//! SEAL: a FULLY UNANNOTATED message-free view helper defaults its `msg` to `()`,
//! including one that takes view content as arguments.
//!
//! `nav_` / `content_` carry no message and have no signature, so each infers to
//! `Html msg` with `msg` a free variable generalized at the module boundary.
//! `layout` takes two such views as arguments and is itself unannotated.
//!
//! Before the fix the free variable lowered to a Rust generic with a `'static`
//! bound the caller cannot satisfy -- `fn nav_<T1: 'static + Clone>() -> Html<T1>`
//! (E0310 / E0283) -- and `fn layout<T1: Clone>(navEl: Html<T1>, ...)` mixed the
//! `Html<T1>` arguments with `Html<()>` message-free nodes (E0308). ipe accepted
//! (exit 0) but the emitted `cargo build` rejected it -- a SEAL break.
//!
//! The annotated-helper counterpart is `golden_i1309_unconstrained_msg_defaulting_seal`
//! (`page : Html msg`); this one closes the gap for the unannotated /
//! argument-position shape.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "i1338_unannotated_view_arg_msg_defaulting_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept the unannotated free-`msg` helpers and
/// emit them (each `msg` defaulted to `()`).
#[test]
fn i1338_unannotated_view_arg_msg_defaulting_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root()
        .join("ipec_i1338_unannotated_view_arg_msg_defaulting_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "an unannotated message-free view helper (including one taking view \
         content as arguments) must be accepted and emitted with its `msg` \
         defaulted to `()`, got: {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate.
/// Before the defaulting fix this was ipe-accept then `cargo` E0310 / E0283 /
/// E0308 (`fn nav_<T1: 'static + Clone>() -> Html<T1>` and a `layout` whose
/// generic arguments mismatched its `Html<()>` body nodes).
#[test]
fn i1338_unannotated_view_arg_msg_defaulting_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root()
        .join("ipec_i1338_unannotated_view_arg_msg_defaulting_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

//! SEAL / regression: a CROSS-MODULE, message-free, unannotated view helper
//! used at a SINGLE monomorphic type (threaded into another message-free helper)
//! must DEFAULT its `msg` to `()`, not stay generic.
//!
//! `Lib.sharedRow = Html.div [] [ Html.text "shared" ]` generalizes its phantom
//! `msg` at the module boundary. Its ONLY cross-module use is `Wrap.wrapped =
//! Html.div [] [ sharedRow, Html.text "wrap" ]`, itself unannotated and
//! message-free. So the shared helper is pinned to exactly ONE type -- the
//! wrapper's own `msg`, which is never fixed to a concrete `Msg` and defaults to
//! `()`. This is a single monomorphic use, NOT cross-module message-polymorphism
//! (contrast `golden_i1338_cross_module_msg_polymorphic_helper_seal`, embedded
//! at TWO DISTINCT concrete `Msg` types, which stays generic).
//!
//! The coarse "appears across a module boundary" proxy kept it generic: `fn
//! lib_shared_row<T1: 'static + Clone>() -> Html<T1>`, threaded through `fn
//! wrap_wrapped<T1>() -> Html<T1>` and rendered -- `T1` never fixed, an E0283 at
//! the emitted `cargo build` after ipe exit 0, a SEAL break. Reading the
//! per-binding discharge outcome (≤1 distinct concrete pin -> default) emits
//! both helpers as concrete `Html<()>`.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "i1347_cross_module_monomorphic_view_msg_defaulting_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("src")
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept the single-monomorphic cross-module
/// helper chain and emit both helpers with their `msg` DEFAULTED to `()`, not as
/// Rust generics.
#[test]
fn i1347_cross_module_monomorphic_view_msg_defaulting_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root()
        .join("ipec_i1347_cross_module_monomorphic_view_msg_defaulting_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable -- skip
    };
    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a cross-module message-free helper used at a single monomorphic type \
         (threaded into another message-free helper) must be accepted and \
         emitted with its `msg` defaulted to `()`, got: {built:?}"
    );

    // The decisive assertion: the shared helper is NOT a Rust generic.
    let emitted = std::fs::read_to_string(out.join("src").join("ipe_mods").join("ipe_mod_lib.rs"))
        .unwrap_or_default();
    assert!(
        emitted.contains("fn lib_shared_row()"),
        "the single-monomorphic cross-module helper must default its `msg` to \
         `()` (`fn lib_shared_row() -> Html<()>`), not stay a generic \
         `fn lib_shared_row<T1>() -> Html<T1>`; emitted:\n{emitted}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate. Before
/// the discharge-outcome fix both helpers were kept generic while their single
/// monomorphic use fixed nothing concrete -- ipe-accept then `cargo` E0283.
#[test]
fn i1347_cross_module_monomorphic_view_msg_defaulting_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root()
        .join("ipec_i1347_cross_module_monomorphic_view_msg_defaulting_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

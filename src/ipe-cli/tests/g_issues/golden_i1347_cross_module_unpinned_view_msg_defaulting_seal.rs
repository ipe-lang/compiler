//! SEAL / regression: a CROSS-MODULE, message-free, unannotated view helper
//! whose only cross-module use pins NOTHING (it is rendered directly via
//! `Html.render`) must DEFAULT its `msg` to `()` (`Html<()>`), not stay generic.
//!
//! `Lib.sharedRow = Html.div [] [ Html.text "shared" ]` has no signature and no
//! message, so its phantom `msg` generalizes at the module boundary. It is
//! exported and used from ONE other module, rendered directly:
//! `Html.render sharedRow`. `Html.render : Html msg -> String` fixes nothing, so
//! the cross-module discharge outcome is Unpinned.
//!
//! The genuinely-polymorphic counterpart
//! (`golden_i1338_cross_module_msg_polymorphic_helper_seal`) is embedded in two
//! views at two DISTINCT concrete `Msg` types and correctly stays generic. The
//! coarse "appears across a module boundary" proxy kept BOTH generic, so this
//! Unpinned helper emitted `fn lib_shared_row<T1: 'static + Clone>() ->
//! Html<T1>` with no site to fix `T1` -- an E0283 at the emitted `cargo build`
//! after ipe exit 0, a SEAL break. Reading the per-binding discharge outcome
//! (Unpinned vs pinned) defaults this helper's `msg` to `()`, closing the hole.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "i1347_cross_module_unpinned_view_msg_defaulting_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("src")
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept the cross-module unpinned helper and emit
/// it with its `msg` DEFAULTED to `()` -- `fn lib_shared_row() -> Html<()>`, not
/// a generic `fn lib_shared_row<T1>() -> Html<T1>`.
#[test]
fn i1347_cross_module_unpinned_view_msg_defaulting_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root()
        .join("ipec_i1347_cross_module_unpinned_view_msg_defaulting_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable -- skip
    };
    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a cross-module, message-free unannotated view helper whose only \
         cross-module use pins nothing (rendered directly) must be accepted and \
         emitted with its `msg` defaulted to `()`, got: {built:?}"
    );

    // The decisive assertion: the helper is NOT a Rust generic. A regression
    // (keeping the coarse cross-module skip) would emit
    // `fn lib_shared_row<T1: 'static + Clone>() -> ... Html<T1>`.
    let emitted = std::fs::read_to_string(out.join("src").join("ipe_mods").join("ipe_mod_lib.rs"))
        .unwrap_or_default();
    assert!(
        emitted.contains("fn lib_shared_row()"),
        "the unpinned cross-module helper must default its `msg` to `()` \
         (`fn lib_shared_row() -> Html<()>`), not stay a generic \
         `fn lib_shared_row<T1>() -> Html<T1>`; emitted:\n{emitted}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate. Before
/// the discharge-outcome fix the helper was kept generic while its only use
/// (`Html.render`) fixed nothing -- ipe-accept then `cargo` E0283.
#[test]
fn i1347_cross_module_unpinned_view_msg_defaulting_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root()
        .join("ipec_i1347_cross_module_unpinned_view_msg_defaulting_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

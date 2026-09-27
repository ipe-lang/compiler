//! SEAL / regression: a CROSS-MODULE, message-free, ATTRIBUTE-FREE, unannotated
//! view helper used at TWO DISTINCT concrete `Msg` types must stay GENERIC
//! (`Html<T1>`), never default to `Html<()>`.
//!
//! `Lib.sharedRow = Html.div [] [ Html.text "shared" ]` has no signature, no
//! message, and no attributes, so its phantom `msg` generalizes at the module
//! boundary. It is exported and used from two OTHER modules: `viewA : Html MsgA`
//! (in `ModA`) and `viewB : Html MsgB` (in `Main`) each embed it.
//! `promote_untyped_boundaries` discharges each cross-module use through a fresh
//! instantiation of the helper's scheme, so its shared root legitimately stays a
//! free variable -- it is message-POLYMORPHIC across the boundary, not
//! message-free.
//!
//! The counterpart same-module golden
//! (`golden_i1338_unannotated_view_arg_msg_defaulting_seal`) correctly defaults
//! such a helper to `Html<()>`. The un-annotated-UI-msg defaulting must NOT fire
//! HERE: pinning the helper's `msg` to `()` emits `fn lib_shared_row() ->
//! Html<()>` while the callers instantiate it at `Html<MsgA>` / `Html<MsgB>` --
//! an E0308 at the emitted `cargo build` after ipe exit 0, a SEAL break. The
//! helper must instead emit `fn lib_shared_row<T1: 'static + Clone>() ->
//! Html<T1>`, which every caller instantiates at its own concrete message type.
//! `Flex` here means "cross-module-polymorphic", not "message-free".
//!
//! This is the exact shape the guardian's over-fire probe used; it is a
//! permanent tripwire against re-widening the untyped defaulting past the
//! cross-module boundary.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "i1338_cross_module_msg_polymorphic_helper_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("src")
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept the cross-module helper and emit it
/// GENERIC (msg NOT defaulted to `()`), so both callers can instantiate it at
/// their own concrete message type.
#[test]
fn i1338_cross_module_msg_polymorphic_helper_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root()
        .join("ipec_i1338_cross_module_msg_polymorphic_helper_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable -- skip
    };
    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a cross-module, message-free, attribute-free unannotated view helper \
         used at two distinct concrete `Msg` types must be accepted and emitted \
         GENERIC (not defaulted to `Html<()>`), got: {built:?}"
    );

    // The decisive assertion: the helper stays a Rust generic. A regression
    // (over-firing the untyped msg defaulting past the module boundary) would
    // emit `fn lib_shared_row() -> ... Html<()>` instead.
    let emitted = std::fs::read_to_string(out.join("src").join("ipe_mods").join("ipe_mod_lib.rs"))
        .unwrap_or_default();
    assert!(
        emitted.contains("fn lib_shared_row<"),
        "the shared helper must emit as a Rust generic \
         (`fn lib_shared_row<T1: 'static + Clone>() -> Html<T1>`), not a \
         defaulted `fn lib_shared_row() -> Html<()>`; emitted:\n{emitted}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate. Before
/// the over-fire fix the helper was defaulted to `Html<()>` while both callers
/// instantiated it at `Html<MsgA>` / `Html<MsgB>` -- ipe-accept then `cargo`
/// E0308.
#[test]
fn i1338_cross_module_msg_polymorphic_helper_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root()
        .join("ipec_i1338_cross_module_msg_polymorphic_helper_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

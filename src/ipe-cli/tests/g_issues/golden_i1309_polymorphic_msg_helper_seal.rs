//! SEAL regression: unconstrained-message defaulting must NOT over-fire.
//!
//! `sharedRow : Html msg` is a message-free zero-argument helper -- the same
//! shape as the defect's `page` -- but it is used at TWO different concrete
//! message types (`viewA : Html MsgA`, `viewB : Html MsgB`). Each use pins `msg`
//! to a concrete `Msg`, so the variable is genuinely polymorphic and must emit a
//! real `fn shared_row<T1>() -> Html<T1>`. `wrap : Html msg -> Html msg` threads
//! its `msg` through a parameter -- another shape that stays generic.
//!
//! If defaulting fired here it would emit `Html<()>` where `viewA` needs
//! `Html<MsgA>` -- an E0308 SEAL break in the opposite direction. This fixture
//! locks in that a pinned message variable keeps its generic and still builds.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "polymorphic_msg_helper_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate: the genuinely-polymorphic helpers must be accepted and emitted
/// (the `<T1>` generics are NOT collapsed to `()`).
#[test]
fn polymorphic_msg_helper_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_polymorphic_msg_helper_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable -- skip
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a message-polymorphic helper used at two concrete msg types must keep \
         its generic and emit, got: {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate -- a
/// genuine `Html<T1>` helper used at two concrete msg types compiles. Guards the
/// over-fire direction: had defaulting collapsed the generic to `Html<()>`, the
/// `viewA : Html MsgA` use site would fail cargo with E0308.
#[test]
fn polymorphic_msg_helper_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_polymorphic_msg_helper_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

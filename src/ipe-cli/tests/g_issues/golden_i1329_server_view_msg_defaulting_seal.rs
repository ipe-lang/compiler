//! SEAL: a `Server.listen` web app renders its views through the idiomatic DSL.
//!
//! Route handlers reach `Server.html` (which takes a `String`) through two view
//! paths, each carrying a free, unconstrained UI message variable:
//!
//!   * `Ipe.Ui` (the primary UI story): `Ui.layout` lifts an `Element msg` to an
//!     `Html msg`, then `Html.render` renders it to a `String`.
//!   * `Ipe.Html` (the secondary path): a helper builds an `Html msg` directly
//!     and `Html.render` renders it.
//!
//! A server has no TEA `update` to pin `msg`, so each view's `msg` stays free and
//! must default to `()`. `Server.listen` returns `Task ()` whether or not an
//! `Ipe.Html`- or `Ipe.Ui`-bearing module is in the closure -- its return type
//! resolves deterministically, so the program must not ICE (IPE-I0001) or leave a
//! residual polymorphic value (IPE-L0102).
//!
//! Before the message-defaulting fix, the free variable lowered to a Rust generic
//! that ipe accepted (exit 0) but the emitted `cargo build` rejected (E0283
//! uninferable / E0308 node mismatch) -- exit-0-then-cargo-fail, a SEAL break.
//! The `golden_i1309_*` fixtures pin the same defaulting through a bare
//! `Io.println (Html.render page)`; this one pins it through a live
//! `Server.listen` route so the server return-type path is covered too.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "i1329_server_view_msg_defaulting_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept the server whose `Ipe.Ui` and `Ipe.Html`
/// views carry a free `msg` (each defaulted to `()`) and emit it.
#[test]
fn server_view_msg_defaulting_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out =
        crate::support::scratch_root().join("ipec_i1329_server_view_msg_defaulting_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable -- skip
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a `Server.listen` app whose `Ipe.Ui`/`Ipe.Html` views carry a free `msg` \
         must be accepted and emitted with each `msg` defaulted to `()`, got: {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate.
/// Guards against the server return-type path re-introducing an uninferable
/// generic (E0283) or an `Html<()>`/`Html<T1>` node mismatch (E0308).
#[test]
fn server_view_msg_defaulting_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i1329_server_view_msg_defaulting_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

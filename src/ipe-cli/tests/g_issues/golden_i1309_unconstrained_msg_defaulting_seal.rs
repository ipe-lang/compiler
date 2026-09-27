//! SEAL: an unconstrained UI message variable defaults to `()`.
//!
//! A view helper whose body carries no message -- only `Html.text` / `Attr.class`,
//! no event handler -- infers to `Html msg` with `msg` a FREE, unconstrained type
//! variable. `page : Html msg` reaches its only use through the polymorphic
//! `Html.render`, so nothing pins `msg` to a concrete `Msg`. The type checker
//! records the variable as message-defaulted (`SolvedTypes::msg_defaulted_vars`)
//! and the lowerer emits `Html<()>` for the signature, the return, and every body
//! node.
//!
//! Before the fix the free variable lowered to a Rust generic -- `fn page<T1>()
//! -> Html<T1>` -- that ipe accepted (exit 0) but the emitted `cargo build`
//! rejected: `T1` is uninferable at the call (E0283) and the helper's `Html<()>`
//! internal nodes mismatch the `Html<T1>` signature (E0308). Exit-0-then-cargo-
//! fail -- a SEAL break.
//!
//! The companion `golden_i1309_polymorphic_msg_helper_seal` proves the defaulting
//! does NOT over-fire on a genuinely message-polymorphic helper.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "unconstrained_msg_defaulting_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept the free-`msg` helper and emit it (its
/// `msg` defaulted to `()`).
#[test]
fn unconstrained_msg_defaulting_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_unconstrained_msg_defaulting_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable -- skip
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a message-free `page : Html msg` must be accepted and emitted with its \
         `msg` defaulted to `()`, got: {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate.
/// Before the defaulting fix this was ipe-accept then `cargo` E0283 / E0308
/// (`fn page<T1>() -> Html<T1>`, an uninferable generic whose internal
/// `Html<()>` nodes mismatched the signature).
#[test]
fn unconstrained_msg_defaulting_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_unconstrained_msg_defaulting_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

//! SEAL / regression: a GENUINELY message-polymorphic view helper whose `msg`
//! appears in a PARAMETER position must keep that slot generic in BOTH its
//! signature return AND every body ui-node call -- never default it to `()`.
//!
//! `box_ : Element msg -> Element msg = \child -> Ui.el [] child` takes an
//! `Element msg` argument, so `msg` is instantiated by the caller through the
//! argument: the emitted `fn box_<T1>(child: Element<T1>)` keeps its parameter
//! generic, and the result slot must stay the same `T1`.
//!
//! The unpinnable-slot defaulting (which lowers a var occurring ONLY in a result
//! position to `()`) wrongly captured this var too, emitting `fn box_<T1>(child:
//! Element<T1>) -> Element<()>` with a body building `Element<()>` nodes -- an
//! E0308/E0283 at the emitted `cargo build` after `ipe` exit 0, a SEAL break.
//! The same hole reached the default `Ipe.Ui` helpers (`el` / `column`), whose
//! `msg` likewise occurs in their `List (Attribute msg)` / `Element msg`
//! parameters. Excluding any ui-msg var that occurs in a parameter position from
//! the defaulting candidates keeps the helper honestly generic and closes the
//! hole.
//!
//! The message-FREE / result-only defaulting cases (i1309 / i1329 / i1338 /
//! i1347) are unaffected: their `msg` never occurs in a parameter, so it still
//! defaults to `()`. The two policies compose.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "i1353_generic_view_helper_body_msg_tvar_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("src")
        .join("Main.ipe")
}

/// Emit gate: the frontend must accept the generic helper and emit it with its
/// `msg` KEPT generic in the return -- `fn box_<T1>(..) -> ... Element<T1>`, not
/// `-> Element<()>`.
#[test]
fn i1353_generic_view_helper_body_msg_tvar_emits_generic_return() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out =
        crate::support::scratch_root().join("ipec_i1353_generic_view_helper_body_msg_tvar_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable -- skip
    };
    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a genuinely message-polymorphic view helper (`msg` in a parameter \
         position) must be accepted and emitted with its result slot kept \
         generic, got: {built:?}"
    );

    // The decisive assertion: the helper's return slot is the SAME generic as
    // its parameter. A regression (defaulting a parameter-position ui-msg var)
    // would emit `-> ... Element<()>` over an `Element<T1>` parameter.
    let emitted = std::fs::read_to_string(out.join("src").join("ipe_mods").join("ipe_mod_main.rs"))
        .unwrap_or_default();
    assert!(
        emitted.contains("fn main_box_<T1")
            && !emitted.contains("child: ipe_runtime::ui::element::Element<T1>,\n) -> ipe_runtime::ui::element::Element<()>"),
        "the generic helper must keep its result slot at its own tvar \
         (`fn box_<T1>(child: Element<T1>) -> Element<T1>`), not default it to \
         `Element<()>`; emitted:\n{emitted}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate. Before
/// the parameter-position exclusion, the helper's return (and the default
/// `Ipe.Ui.el` body it delegates to) defaulted to `()` under an `<T1>`
/// parameter -- ipe-accept then `cargo` E0308/E0283.
#[test]
fn i1353_generic_view_helper_body_msg_tvar_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out =
        crate::support::scratch_root().join("ipec_i1353_generic_view_helper_body_msg_tvar_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

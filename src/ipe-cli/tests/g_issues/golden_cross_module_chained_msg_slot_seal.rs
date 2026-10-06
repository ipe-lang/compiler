//! SEAL: message-free view helpers of `Lib` used only inside a helper of `Mid`
//! whose own message slot a third module pins (`Main.view : Html Msg`). Each
//! `Lib` helper's message slot is reached by the concrete `Msg` only through
//! the `Mid` helper's, so the pair must agree on its message type in the
//! emitted Rust: a `Lib` helper defaulted to `Html<()>` under a generic
//! `fn mid_wrap<T1>() -> Html<T1>` is an E0308 after ipe exit 0. The shapes:
//! an unannotated helper inside an unannotated one (`nav` in `wrap`), an
//! annotated `Html msg` helper inside an unannotated one (`badge` in `wrap`),
//! and an unannotated helper inside an annotated generic one (`menu` in
//! `frame`).

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "cross_module_chained_msg_slot_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("src")
        .join("Main.ipe")
}

/// Emit gate: every `Lib` helper stays generic, threading its enclosing `Mid`
/// helper's message type.
#[test]
fn cross_module_chained_msg_slot_emits_generic_helpers() -> Result<(), String> {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_cross_module_chained_msg_slot_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build_loose_file(&entry, &out, &runtime)
        .map_err(|e| format!("{GOLDEN} must be accepted, got: {e:?}"))?;
    let lib_rs = out.join("src").join("ipe_mods").join("ipe_mod_lib.rs");
    let emitted =
        std::fs::read_to_string(&lib_rs).map_err(|e| format!("read {}: {e}", lib_rs.display()))?;
    for helper in ["lib_nav", "lib_badge", "lib_menu"] {
        assert!(
            emitted.contains(&format!("fn {helper}<")),
            "`{helper}` reaches a concrete `Msg` only through an enclosing generic \
             helper, so it must stay generic, not default to `Html<()>`; \
             emitted:\n{emitted}"
        );
    }
    Ok(())
}

/// THE SEAL: the chain is accepted and, under `IPE_E2E=1`, the emitted crate
/// `cargo build`s.
#[test]
fn cross_module_chained_msg_slot_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_cross_module_chained_msg_slot_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}

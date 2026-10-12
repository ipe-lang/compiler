//! SEAL: a same-module reference to an untyped binding is the one shared
//! type variable, so a message-free helper and every same-module helper
//! referencing it own ONE message slot. The slot's `Unit` default is decided
//! for that shared slot, never for one of its owners: `Lib.nav`, which no
//! other module references, must not pin the slot `Lib.wrap` / `Lib.b` share
//! with it while an importer keeps theirs generic. Pinning it for `nav` emits
//! `fn lib_wrap() -> Html<()>` (and `fn lib_b(x: ())`) under a caller's
//! `Html<Msg>`: E0308 after ipe exit 0. The shapes: the importer pins the
//! sharing helpers directly (`shared_msg_class_seal`, `b` keeping the slot
//! generic through a value parameter too), or only through a middle module's
//! generic helper (`shared_msg_class_middle_seal`).
//!
//! A message slot wrapped in a user constructor that no use fixes
//! (`wrapped_threaded_msg_seal`) stays fail-closed: refused at ipe time as a
//! fully polymorphic value, never an uninferable emitted generic.

use std::path::{Path, PathBuf};

use ipe::CliError;

use crate::support::repo_root;

fn fixture_entry(root: &Path, golden: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(golden)
        .join("src")
        .join("Main.ipe")
}

/// Emit `golden` and return the emitted `Lib` module's Rust.
fn emitted_lib(golden: &str) -> Result<String, String> {
    let entry = fixture_entry(&repo_root(), golden);
    let out = crate::support::scratch_root().join(format!("ipec_{golden}_emit"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build_loose_file(&entry, &out, &runtime)
        .map_err(|e| format!("{golden} must be accepted, got: {e:?}"))?;
    let lib_rs = out.join("src").join("ipe_mods").join("ipe_mod_lib.rs");
    std::fs::read_to_string(&lib_rs).map_err(|e| format!("read {}: {e}", lib_rs.display()))
}

fn assert_generic(golden: &str, emitted: &str, helpers: &[&str]) {
    for helper in helpers {
        assert!(
            emitted.contains(&format!("fn {helper}<")),
            "{golden}: `{helper}` shares a message slot an importer keeps generic, so it \
             must stay generic, not default to `Html<()>`; emitted:\n{emitted}"
        );
    }
}

/// THE SEAL: `golden` is accepted and, under `IPE_E2E=1`, the emitted crate
/// `cargo build`s.
fn assert_seal(golden: &str) {
    let entry = fixture_entry(&repo_root(), golden);
    let out = crate::support::scratch_root().join(format!("ipec_{golden}_e2e"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(built.is_ok(), "{golden} must be accepted, got: {built:?}");
    crate::support::assert_seal_builds(golden, &out);
}

/// Every owner of the shared slot stays generic, whether pinned directly or
/// through a value parameter.
#[test]
fn shared_msg_class_emits_generic_owners() -> Result<(), String> {
    let golden = "shared_msg_class_seal";
    let emitted = emitted_lib(golden)?;
    assert_generic(golden, &emitted, &["lib_nav", "lib_wrap", "lib_b"]);
    Ok(())
}

#[test]
fn shared_msg_class_seal_builds() {
    assert_seal("shared_msg_class_seal");
}

/// The shared slot pinned only through a middle module stays generic too.
#[test]
fn shared_msg_class_middle_emits_generic_owners() -> Result<(), String> {
    let golden = "shared_msg_class_middle_seal";
    let emitted = emitted_lib(golden)?;
    assert_generic(golden, &emitted, &["lib_nav", "lib_wrap"]);
    Ok(())
}

#[test]
fn shared_msg_class_middle_seal_builds() {
    assert_seal("shared_msg_class_middle_seal");
}

/// A wrapped message slot no use fixes is refused at ipe time.
#[test]
fn wrapped_threaded_msg_is_refused() {
    let golden = "wrapped_threaded_msg_seal";
    let entry = fixture_entry(&repo_root(), golden);
    let out = crate::support::scratch_root().join(format!("ipec_{golden}_emit"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build_loose_file(&entry, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_L0102),
        "{golden}: a wrapped message slot no use fixes must fail closed at ipe time, \
         got {built:?}"
    );
}

//! SEAL: a kernel whose runtime signature bounds a scheme variable `Sync` obliges the caller's generic.
//!
//! `Input.checkbox` / `Input.radio` / `Input.radioRow` emit `input_checkbox_` /
//! `input_radio_` / `input_radio_row_`, each `M: Clone + Send + Sync`. A view
//! helper generic over `msg` exposes `msg` only inside its `onChange` callback
//! and its `Element msg` result, never bare, so the obligation is keyed on the
//! kernel's scheme variable (`sync_obliged_scheme_vars`) and read off the solved
//! call-site type. Without it the helper's `T1` is `Send`-only and the emitted
//! crate is ipe-accepted but fails `cargo build` with E0277.
//!
//! The emit gate asserts the bound on every helper's signature; under
//! `IPE_E2E=1` the emitted crate must `cargo build`.

use std::path::{Path, PathBuf};

const GOLDEN: &str = "generic_msg_input_sync_seal";

/// The helpers generic over `msg`, one per `Sync`-bounding Input kernel.
const HELPERS: [&str; 3] = ["checkboxOf", "radioOf", "radioRowOf"];

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// The emitted signature line of the `Main` function spelled `ipe_name`.
///
/// Matches the emitted `main_<snake_case>` name with its underscores removed
/// against the lower-cased Ipê name, so the check does not re-derive the
/// backend's snake-casing.
fn signature_of<'a>(emitted: &'a str, ipe_name: &str) -> Option<&'a str> {
    let wanted = format!("main{}", ipe_name.to_lowercase());
    emitted.lines().find(|line| {
        line.split_once("fn ").is_some_and(|(_, rest)| {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .filter(|c| *c != '_')
                .collect();
            name == wanted
        })
    })
}

/// Emit gate: every helper's generic `T1` must be bounded by `Sync`.
#[test]
fn generic_msg_input_sync_bounds_emitted() {
    let root = crate::support::repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe dev build must accept the program, got: {built:?}"
    );

    // `Main`'s functions land in `src/main.rs` for a single-home program and in
    // `src/ipe_mods/ipe_mod_main.rs` once the program spans several module
    // homes, so the lookup reads the whole emitted source.
    let emitted = crate::support::read_all_emitted_src(&out);
    for name in HELPERS {
        let signature = signature_of(&emitted, name);
        assert!(
            signature.is_some_and(|line| line.contains("T1: 'static + Send + Sync")),
            "{GOLDEN}: `{name}`'s T1 must carry `Send + Sync` (its Input kernel's \
             runtime function bounds the message type `Sync`), got signature: {signature:?}"
        );
    }
}

/// THE SEAL: under `IPE_E2E=1` the emitted crate must `cargo build`.
#[test]
fn generic_msg_input_sync_seal_builds() {
    let root = crate::support::repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe dev build must accept the program, got: {built:?}"
    );

    crate::support::assert_seal_builds(GOLDEN, &out);
}

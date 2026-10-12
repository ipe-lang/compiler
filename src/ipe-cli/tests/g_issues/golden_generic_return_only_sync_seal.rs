//! SEAL: a callee generic bounded `Sync` only in its return type obliges every caller instantiating it.
//!
//! `emptyList : Decoder (List a)` captures `[] : List a` behind
//! `decode_succeed`'s `Send + Sync` factory; `checkboxOf`'s `msg` is bounded by
//! `input_checkbox_`. A caller generic over the same variable references them
//! where no argument carries the generic — a `oneOf` element, a `let` value, a
//! point-free function value, a second return-only hop — so the obligation is
//! read off each reference's solved instantiation, aligned against the callee's
//! whole signature. Without it the callers' `T1` is `Send`-only and the emitted
//! crate is ipe-accepted but fails `cargo build` with E0277.
//!
//! The emit gate asserts the bound on every caller's signature; under
//! `IPE_E2E=1` the emitted crate must `cargo build`.

use std::path::{Path, PathBuf};

const GOLDEN: &str = "generic_return_only_sync_seal";

/// Every caller instantiating a return-only `Sync` generic, plus the helpers themselves.
const OBLIGED: [&str; 8] = [
    "emptyList",
    "emptyWhen",
    "emptyAgain",
    "nonTail",
    "viaLet",
    "viaPointFree",
    "twoHop",
    "togglePanel",
];

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

/// The bound clause of generic `T1` in an emitted signature (`'static + Send + Sync`).
fn t1_bounds(signature: &str) -> Option<&str> {
    let (_, rest) = signature.split_once("<T1:")?;
    rest.split([',', '>', '(']).next()
}

/// Emit gate: every obliged function's generic `T1` must be bounded by `Send + Sync`.
#[test]
fn generic_return_only_sync_bounds_emitted() {
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
    for name in OBLIGED {
        let signature = signature_of(&emitted, name);
        let bounds = signature.and_then(t1_bounds);
        assert!(
            bounds.is_some_and(|b| b.contains("Send") && b.contains("Sync")),
            "{GOLDEN}: `{name}`'s T1 must carry `Send + Sync` (it instantiates a \
             return-only `Sync` generic), got signature: {signature:?}"
        );
    }
}

/// THE SEAL: under `IPE_E2E=1` the emitted crate must `cargo build`.
#[test]
fn generic_return_only_sync_seal_builds() {
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

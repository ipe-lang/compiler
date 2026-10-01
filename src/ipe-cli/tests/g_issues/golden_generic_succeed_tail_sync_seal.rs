//! SEAL: a sync-capturing kernel obliges `Sync` on its generic wherever it sits.
//!
//! Generic decoder combinators `succeed` with a match-arm local `decoded : a`
//! — no parameter — in five positions: a closure's tail (`rewrap`), a `let`
//! binding (`viaLet`), a `oneOf` element (`viaOneOf`), a `map2` argument
//! (`viaMap2`), and a record field (`viaField`). The emitter moves the value
//! into a `Box<dyn Fn() -> T1 + Send + Sync>` factory, so each enclosing generic
//! must carry `T1: Send + Sync`; the bound comes from the kernel's solved
//! instantiation at the call site, independent of position. Without it the
//! emitted crate is ipe-accepted but fails `cargo build` with E0277.
//!
//! The emit gate asserts the bound on every emitted signature; under
//! `IPE_E2E=1` the program is built, run, and its stdout matched against
//! `expected.txt`.

use std::path::{Path, PathBuf};

const GOLDEN: &str = "generic_succeed_tail_sync_seal";

/// The generic combinators whose `T1` a captured `succeed` value obliges `Sync`.
const COMBINATORS: [&str; 5] = ["rewrap", "viaLet", "viaOneOf", "viaMap2", "viaField"];

fn fixture_dir(root: &Path) -> PathBuf {
    root.join("tests").join("golden").join(GOLDEN)
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

/// Emit gate: every combinator's generic `T1` must be bounded by `Sync`.
#[test]
fn generic_succeed_capture_sync_bounds_emitted() {
    let root = crate::support::repo_root();
    let entry = fixture_dir(&root).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe build must accept the program, got: {built:?}"
    );

    // `Main`'s functions land in `src/main.rs` for a single-home program and in
    // `src/ipe_mods/ipe_mod_main.rs` once the program spans several module
    // homes, so the lookup reads the whole emitted source.
    let emitted = crate::support::read_all_emitted_src(&out);
    for name in COMBINATORS {
        let signature = signature_of(&emitted, name);
        assert!(
            signature.is_some_and(|line| line.contains("T1: 'static + Send + Sync")),
            "{GOLDEN}: `{name}`'s T1 must carry `Send + Sync` (its value is captured \
             by a `decode_succeed` factory), got signature: {signature:?}"
        );
    }
}

/// THE SEAL: under `IPE_E2E=1` the emitted crate must build and print every decoded value.
#[test]
fn generic_succeed_tail_sync_seal_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = crate::support::repo_root();
    let dir = fixture_dir(&root);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe build must accept the program, got: {built:?}"
    );

    let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
    crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "{GOLDEN}: must exit 0");
}

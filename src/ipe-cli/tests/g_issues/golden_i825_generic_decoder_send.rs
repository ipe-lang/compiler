//! SEAL — a generic decoder combinator whose return type is `Decoder a` (the
//! tvar `a` inside a `Decoder` node in the emitted signature) must carry `Send +
//! 'static` on `a`, or the emitted crate fails `cargo build` E0277.
//!
//! `withDefault : a -> Decoder a -> Decoder a` is the minimal shape: both the
//! second parameter and the return carry `Decoder a`, so `ir_type_generic_in_decoder`
//! fires on both and stamps `Send + 'static` on `T1`. Without that obligation
//! the emitted `fn main_with_default<T1: Clone>` has no `T1: Send`, but the
//! `decode_one_of` combinator it delegates to stores `T1` in a `Decoder<_, T1>`,
//! whose runtime bound requires `T1: Send`. The SEAL proof is the E2E build: the
//! emitted crate must `cargo build` and exit 0.
//!
//! ```text
//! cargo test -p ipe --test g_issues golden_i825_generic_decoder_send
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_i825_generic_decoder_send
//! ```

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "generic_decoder_send";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Accept + emit gate (always): the generic decoder combinator must be accepted
/// and lowered with `Send + 'static` on the generic type parameter. A
/// lower/backend regression fails HERE, in the fast path.
#[test]
fn generic_decoder_send_emits_byte_identical() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("main.rs");
    let out = crate::support::scratch_root().join("ipec_i825_generic_decoder_send_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a generic decoder combinator (`withDefault : a -> Decoder a -> Decoder a`) \
         must be accepted and emitted with `T1: Send + 'static` on the generic \
         (the tvar appears inside a `Decoder` node in both a param and the return), \
         got: {built:?}"
    );

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` and run the emitted
/// crate. `ipe`-accept must imply `cargo`-build — a generic `Decoder a`
/// combinator missing `T1: Send` would cargo-fail E0277 (a SEAL violation).
#[test]
fn generic_decoder_send_builds_and_runs() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i825_generic_decoder_send_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "emitted crate must build and exit 0 — a generic `Decoder a` combinator \
         must not be `ipe`-accept-then-`cargo`-fail; stdout:\n{}",
        outcome.stdout
    );
    let dir = root.join("tests").join("golden").join(GOLDEN);
    crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
}

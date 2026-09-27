//! Seal (READ frontier) — a function READ OUT of a record/enum/collection field
//! (a `SharedFun` `Arc<dyn Fn>` carrier) and passed into an ordinary
//! monomorphized higher-order parameter (`FN0: Fn(..)`) was `ipe`-accepted (exit
//! 0) but the emitted crate failed `cargo build` with `E0277`
//! (`Arc<dyn Fn> !impl Fn`) — a latent SEAL breach in the READ direction, the
//! mirror of the fill-direction fix.
//!
//! The fill side stores a fn value INTO a `SharedFun` slot by eta-promoting it
//! onto `Arc`; this READ side is the dual: a stored-function read that flows into
//! a DIRECT higher-order parameter (a `Fn`/generic slot, which an `Arc<dyn Fn>`
//! does not satisfy) is eta-DEMOTED back onto the direct `Box<dyn Fn>` carrier at
//! the argument boundary (`move |eta_0, …| (read)(eta_0, …)`). The two frontiers
//! agree by construction: a stored slot carries `Arc`, a direct HOF argument
//! carries `Box`, and the read edge converts between them with a total O(1)
//! eta-adapter.
//!
//! `applyIt runner.run 7` = `(runner.run) 7` = `(7 + 1)` = `8`.
//!
//! The load-bearing proof is the SEAL: under `IPE_E2E=1` the emitted crate must
//! `cargo build`, run, and exit 0.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("fcf_record_fn_read")
        .join("Main.ipe")
}

/// Emit gate + byte-identity golden: the frontend must accept the record-field
/// fn-read program and re-emit the checked-in `main.rs` byte-for-byte (the
/// `move |eta_0| (…run.clone())(eta_0)` demotion is locked in the golden). The
/// `E0277` this closed was a `cargo`-time failure invisible to an accept-only
/// check, so this alone is not the SEAL proof — see the E2E test.
#[test]
fn record_fn_read_emits_byte_identical() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("fcf_record_fn_read")
        .join("main.rs");
    let out = crate::support::scratch_root().join("ipec_i793_fcf_record_fn_read_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable — skip, matches the other goldens
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a record-field fn read passed into a higher-order parameter must be \
         accepted + emitted (the `Arc<dyn Fn>` read is demoted onto the direct \
         `Box<dyn Fn>` carrier at the argument boundary), got: {built:?}"
    );

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` and run the emitted crate.
/// Before the fix this was `ipe`-accept then `cargo` `E0277` (`Arc<dyn Fn>` into
/// a generic `FN0: Fn(..)` slot).
#[test]
fn record_fn_read_builds_and_runs() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i793_fcf_record_fn_read_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "fcf_record_fn_read must be accepted, got: {built:?}"
    );

    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let outcome = crate::support::build_and_run_emitted("fcf_record_fn_read", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "emitted crate must build and exit 0 — a `SharedFun` record read into a \
         higher-order parameter must not be `ipe`-accept-then-`cargo`-fail; \
         stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim(),
        "8",
        "wrong runtime output — the demoted `runner.run` read computes `(7 + 1)`"
    );
}

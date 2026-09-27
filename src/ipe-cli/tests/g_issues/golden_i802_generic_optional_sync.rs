//! Seal — a GENERIC combinator over a free type var `a` threaded through an
//! optional decoder slot (`JsonDecP.optional` / `Db.Decode.optional`) was
//! `ipe`-accepted (exit 0) but the emitted crate failed `cargo build` with
//! `E0277`: `a` (emitted `T1`) `cannot be shared between threads safely`. The
//! optional-decoder runtime slots capture the element DEFAULT behind a
//! thread-shared carrier, so their element param is bounded `Send + Sync`
//! (`decode_pipeline_optional` / `db_decode_optional`), yet the emitted-generic
//! bound synthesizer added only `Send + 'static + Clone`, never `Sync`.
//!
//! The fix propagates `Sync` alongside `Send`: a type var detected as the bare
//! arg-2 default of an optional kernel call gains the `Sync` bound. It is
//! exactly-tight — the result var `b` (which never appears bare) gains no `Sync`,
//! and a var that reaches only a `Send`-bounded slot (`decode_list`) keeps `Send`
//! and gains no `Sync` either.
//!
//! The fixture exercises BOTH optional slots: `JsonDecP.optional` at two element
//! instantiations (`Int` and `String`) and `Db.Decode.optional` at `Int`, proving
//! the propagated `Sync` bound holds across monomorphisations and across both the
//! JSON and DB paths:
//! `Bob|0 / Cara|25 / Dan#none / Eve#E / Alice|30`.
//!
//! The load-bearing proof is the SEAL: under `IPE_E2E=1` the emitted crate must
//! `cargo build`, run, and exit 0.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "generic_optional_decoder";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate + byte-identity golden: the frontend must accept the generic
/// optional combinators and re-emit the checked-in `main.rs` byte-for-byte (the
/// `T1: 'static + Send + Sync + Clone` bound on the element var — and the ABSENCE
/// of `Sync` on the result var `T2` — are locked in the golden). The `cargo`-time
/// `E0277` this closed was invisible to an accept-only check, so this alone is
/// not the SEAL proof — see the E2E test.
#[test]
fn generic_optional_sync_emits_byte_identical() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("main.rs");
    let out = crate::support::scratch_root().join("ipec_i802_generic_optional_sync_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable — skip, matches the other goldens
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a generic combinator threading a type var through `JsonDecP.optional` / \
         `Db.Decode.optional` must be accepted + emitted (the `Sync` bound is \
         propagated onto the element var, never onto the result var), got: {built:?}"
    );

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` and run the emitted crate,
/// asserting the multi-instantiation JSON + DB output. Before the fix this was
/// `ipe`-accept then `cargo` `E0277` (the element var lacked `Sync`).
#[test]
fn generic_optional_sync_builds_and_runs() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i802_generic_optional_sync_e2e");
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
        "emitted crate must build and exit 0 — a generic combinator threading a \
         type var through an optional decoder slot must not be \
         `ipe`-accept-then-`cargo`-fail; stdout:\n{}",
        outcome.stdout
    );
    let dir = root.join("tests").join("golden").join(GOLDEN);
    crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
}

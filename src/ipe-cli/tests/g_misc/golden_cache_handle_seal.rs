//! Regression for the opaque `Ipe.Cache` HANDLE SEAL breach — the sibling of
//! `golden_cache_module_seal` that pins the OTHER half of the `uses_cache` gate.
//!
//! The stdlib `type Cache k v = Cache Int` exposes its constructor publicly and
//! is backed by the runtime `IpeCacheHandle` (its `EnumDef` suppressed). A
//! program can NAME the handle in a signature, CONSTRUCT it (`Cache 7`), and
//! PATTERN-MATCH it (`case c of Cache raw -> …`) with NO `Cache.*` kernel call
//! and NO `CacheCfg` / `CacheStats` mention. Every such position emits an
//! `IpeCacheHandle` reference resolved through the `cache` runtime module, so the
//! `uses_cache` gate must fire on the handle type-mention — the
//! `ir_type_mentions_cache_handle` scan folded into `uses_cache` — not only on a
//! `CacheCfg` / `CacheStats` mention. Without the handle scan the gate would rely
//! on the incidental `CacheCfg`-in-env masking (an imported `Ipe.Cache` drags a
//! `CacheCfg`-typed binding into the solved env); the handle scan makes the gate
//! correct by construction, independent of that artifact.
//!
//! The unit-level fail-before/pass-after proof lives in `ipe_lower`
//! (`cache_handle_in_signature_selects_cache`, which asserts the plain
//! CacheCfg/CacheStats guard does NOT cover the handle). This golden is the
//! end-to-end SEAL lock: the emitted crate must `cargo build` and print `7`.
//!
//! ## Why the emit assertion runs in the DEFAULT gate
//!
//! `IPE_E2E`-gated tests do not run in the default `cargo nextest` gate. The
//! first test asserts the frontend emits the crate (ipe exit 0); the second is
//! the `IPE_E2E`-gated cargo-build-and-run proof.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("cache_handle_seal")
        .join("Main.ipe")
}

/// Build the fixture; return whether the frontend accepted + emitted it.
fn built(root: &Path, out: &Path) -> Result<(), ipe::CliError> {
    let entry = fixture_entry(root);
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, out, &runtime)
}

/// Emit assertion (default gate): the frontend must accept the handle-only
/// `Ipe.Cache` program and emit its crate.
#[test]
fn cache_handle_seal_emits() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_cache_handle_seal_emit");
    let built = built(&root, &out);
    assert!(
        built.is_ok(),
        "cache_handle_seal: must be accepted + emitted, got: {built:?}"
    );
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, actually `cargo build` the
/// emitted crate and run it. The handle-only program references `IpeCacheHandle`;
/// with the `cache` module gated in via the handle scan it builds and prints `7`
/// (the `Int` inside `Cache 7`).
#[test]
fn cache_handle_seal_builds_and_runs() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_cache_handle_seal_e2e");
    let built = built(&root, &out);
    assert!(
        built.is_ok(),
        "cache_handle_seal: must be accepted, got: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("cache_handle_seal", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "cache_handle_seal: emitted crate must build and exit 0 (the opaque \
         `IpeCacheHandle` must resolve through the gated `cache` module); stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(
            outcome.stdout.trim(),
            "7",
            "wrong runtime output — `unwrap (Cache 7)` is 7"
        );
    }
}

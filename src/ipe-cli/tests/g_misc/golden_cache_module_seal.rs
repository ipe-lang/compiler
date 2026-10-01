//! Regression for the `Ipe.Cache` SEAL breach: a program that reaches the
//! `Ipe.Cache` surface type-checks (`ipe` exit 0) but the emitted crate failed
//! `cargo build`. The emitted `ipe_mods/ipe_mod_ipe_cache.rs` references
//! `cache_new_raw` / `cache_get` / `cache_put` / `cache_size`, the `CacheCfg`
//! struct, and the `IpeCacheHandle` enum — all defined in the `cache` runtime
//! module. The emitter never selected that module (no `uses_cache` gate), so the
//! dependency-model manifest never enabled the `cache_kernel` runtime feature and
//! the runtime crate compiled `cache.rs` out, leaving those symbols undefined in
//! scope (E0422/E0425/E0433 at `cargo build`).
//!
//! The `uses_cache` gate — an `Ipe.Cache` kernel OR a `CacheCfg` / `CacheStats`
//! type-mention (the pure-Ipê `defaultCfg` / `with*` builders construct a
//! `CacheCfg` with no kernel call) — selects the `cache` module + the
//! `cache_kernel` feature, closing the hole.
//!
//! ## Why the emit assertion runs in the DEFAULT gate
//!
//! `IPE_E2E`-gated tests do not run in the default `cargo nextest` gate. The
//! first test asserts the frontend emits the crate (ipe exit 0), so it pins the
//! regression even when `IPE_E2E` is unset; the second is the `IPE_E2E`-gated
//! cargo-build-and-run proof that the emitted crate actually compiles AND prints
//! the empty-cache size (`0`).

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("cache_module_seal")
        .join("Main.ipe")
}

/// Build the fixture; return whether the frontend accepted + emitted it.
fn built(root: &Path, out: &Path) -> Result<(), ipe::CliError> {
    let entry = fixture_entry(root);
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, out, &runtime)
}

/// Emit assertion (default gate): the frontend must accept the `Ipe.Cache`
/// program and emit its crate. A regression that drops the `cache` module gate
/// still emits here (the frontend is unchanged); the SEAL half below is what
/// catches the `cargo build` breach.
#[test]
fn cache_module_seal_emits() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_cache_module_seal_emit");
    let built = built(&root, &out);
    assert!(
        built.is_ok(),
        "cache_module_seal: must be accepted + emitted, got: {built:?}"
    );
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, actually `cargo build` the
/// emitted crate and run it. Pre-fix the build failed with an undeclared
/// `IpeCacheHandle` / `cache_new_raw` / `CacheCfg`; with the `cache` module gated
/// in, it builds and prints `0` (the freshly created cache is empty).
#[test]
fn cache_module_seal_builds_and_runs() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_cache_module_seal_e2e");
    let built = built(&root, &out);
    assert!(
        built.is_ok(),
        "cache_module_seal: must be accepted, got: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("cache_module_seal", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "cache_module_seal: emitted crate must build and exit 0 (pre-fix: \
         undeclared `IpeCacheHandle` / `cache_new_raw` / `CacheCfg`); stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(
            outcome.stdout.trim(),
            "0",
            "wrong runtime output — a fresh cache has size 0"
        );
    }
}

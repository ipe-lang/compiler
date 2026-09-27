//! Regression for a non-Copy `Ipe.Cache` HANDLE reused across two Task steps.
//!
//! `Cache.put cache …` takes the `IpeCacheHandle` (which is not `Copy`) by
//! value, so it MOVES the handle. When a `Task.andThen` continuation reads the
//! SAME `cache` again (`Cache.size cache`), the emitter renders
//! `task_and_then(effect, cont)` and Rust evaluates the effect (the first
//! argument) BEFORE it builds the continuation closure. The effect's move then
//! leaves the continuation borrowing a moved value — `E0382: use of moved
//! value: cache` at `cargo build`, an ipe-exit-0-then-cargo-fail SEAL breach.
//!
//! The fix clones the reused handle at the effect use site, mirroring the
//! `Db` connection-handle discipline and the `TaskSeq` continuation rewrite: the
//! effect's `cache` becomes `cache.clone()`, so the original survives into the
//! continuation's own capture-clone. This golden is the end-to-end SEAL lock:
//! the emitted crate must `cargo build` and print `1` (the entry count after a
//! single `Cache.put`).

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("cache_handle_task_reuse")
        .join("Main.ipe")
}

/// Build the fixture; return whether the frontend accepted + emitted it. `None`
/// when the runtime resolver is unavailable in this environment (mirrors the
/// resolve-skip convention every other golden in this suite uses).
fn built(root: &Path, out: &Path) -> Option<Result<(), ipe::CliError>> {
    let entry = fixture_entry(root);
    let _ = std::fs::remove_dir_all(out);
    let runtime = ipe::resolve_runtime().ok()?;
    Some(ipe::build(&entry, out, &runtime))
}

/// Emit assertion (default gate): the frontend must accept the handle-reuse
/// program and emit its crate.
#[test]
fn cache_handle_task_reuse_emits() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_cache_handle_task_reuse_emit");
    let Some(built) = built(&root, &out) else {
        return; // resolver unavailable — skip, matches the other goldens
    };
    assert!(
        built.is_ok(),
        "cache_handle_task_reuse: must be accepted + emitted, got: {built:?}"
    );
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, actually `cargo build` the
/// emitted crate and run it. The reused `IpeCacheHandle` must be cloned at the
/// effect use site so the continuation can read it; the crate builds and prints
/// `1` (the entry count after one `Cache.put`).
#[test]
fn cache_handle_task_reuse_builds_and_runs() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_cache_handle_task_reuse_e2e");
    let Some(built) = built(&root, &out) else {
        return;
    };
    assert!(
        built.is_ok(),
        "cache_handle_task_reuse: must be accepted, got: {built:?}"
    );

    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let outcome = crate::support::build_and_run_emitted("cache_handle_task_reuse", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "cache_handle_task_reuse: emitted crate must build and exit 0 (the reused \
         non-Copy `IpeCacheHandle` must be cloned at the effect use site); stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim(),
        "1",
        "wrong runtime output — one `Cache.put` leaves `Cache.size` at 1"
    );
}

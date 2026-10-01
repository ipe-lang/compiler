//! Shared helpers for the backend SEAL end-to-end tests.
//!
//! Each SEAL test emits an Ipê program, vendors the runtime source tree beside
//! it, and runs `cargo build` (and optionally the resulting binary) to prove the
//! emitted crate compiles and produces the expected output.
//!
//! This module is NOT a test binary — cargo treats a directory-with-mod.rs as a
//! library module and excludes it from the test-binary discovery pass.

use std::path::{Path, PathBuf};
use std::process::Command;

use e2e_support::child_shared_target_from_env;
use ipe_backend::EmittedProject;
use ipe_diagnostics::{DResult, Diagnostic};

/// Recursively copy the runtime source tree `src` into `dst`.
///
/// `src` is the flat `src/runtime/rust/src/` directory; `dst` is the emitted
/// crate's `src/ipe_runtime/` target. Subdirectories are copied recursively.
pub fn copy_dir(src: &Path, dst: &Path) -> DResult<()> {
    std::fs::create_dir_all(dst).map_err(|e| io_bug(dst, &e))?;
    for entry in std::fs::read_dir(src).map_err(|e| io_bug(src, &e))? {
        let entry = entry.map_err(|e| io_bug(src, &e))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let file_type = entry.file_type().map_err(|e| io_bug(&from, &e))?;
        if file_type.is_dir() {
            copy_dir(&from, &to)?;
        } else {
            std::fs::copy(&from, &to).map_err(|e| io_bug(&from, &e))?;
        }
    }
    Ok(())
}

/// Write `emitted` into a fresh temp directory named `slot`, vendor the runtime
/// beside it, run `cargo <subcmd>`, and return the process exit status.
#[allow(dead_code)]
///
/// Callers pass `"build"` or `"run"` as `subcmd` and `runtime` from
/// `e2e_support::require_runtime`.
pub fn vendor_and_run(
    emitted: &EmittedProject,
    runtime: &Path,
    slot: &str,
    subcmd: &str,
) -> DResult<std::io::Result<std::process::ExitStatus>> {
    let out = ipe_test_temp::temp_root().join(slot);
    let _ = std::fs::remove_dir_all(&out);
    let src = out.join("src");
    std::fs::create_dir_all(&src).map_err(|e| io_bug(&src, &e))?;

    copy_dir(runtime, &src.join("ipe_runtime"))?;

    let cargo_toml = out.join("Cargo.toml");
    std::fs::write(&cargo_toml, &emitted.cargo_toml).map_err(|e| io_bug(&cargo_toml, &e))?;
    for (rel, contents) in &emitted.files {
        let path = out.join(rel.as_str());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io_bug(parent, &e))?;
        }
        std::fs::write(&path, contents).map_err(|e| io_bug(&path, &e))?;
    }

    // Forward the warm shared target when CI exports `IPE_ORACLE_SHARED_TARGET`,
    // else fall back to an isolated per-slot target so a bare local run stays
    // hermetic. The shared target lets heavy dep crates (tokio, axum, runtime)
    // reuse already-compiled artifacts rather than cold-building per test.
    let shared = child_shared_target_from_env();
    let target_dir = shared
        .as_deref()
        .map_or_else(|| out.join("target"), PathBuf::from);
    let status = Command::new("cargo")
        .arg(subcmd)
        .current_dir(&out)
        .env("CARGO_TARGET_DIR", &target_dir)
        .status();
    // Only prune an isolated per-slot target; the shared warm target is owned
    // by the harness and must not be removed here.
    if shared.is_none() {
        let _ = std::fs::remove_dir_all(&target_dir);
    }
    Ok(status)
}

/// Resolve the `CARGO_TARGET_DIR` for a hand-rolled emitted-crate build.
///
/// When CI exports `IPE_ORACLE_SHARED_TARGET` (an absolute path), returns that
/// path so the emitted crate's deps link against the warm shared tree rather than
/// cold-building. Falls back to an ambient `CARGO_TARGET_DIR` a local lane set,
/// then to `out_dir.join("target")` for a bare local run (hermetic, isolated).
///
/// Callers that prune the target after the build must check whether the returned
/// path equals `out_dir.join("target")` before removing it — the shared warm
/// target must never be pruned here.
///
/// This is the BUILD-ONLY target: use it only for a SEAL test that builds an
/// emitted crate and never executes the resulting binary. A test that RUNS
/// `debug/ipe-app` and asserts its output must instead use
/// [`emitted_run_target_dir`] — the shared target holds a single, fixed-name
/// `debug/ipe-app`, so under parallel nextest one run-output test would execute
/// a binary a concurrent sibling just overwrote.
#[must_use]
#[allow(dead_code)]
pub fn emitted_target_dir(out_dir: &Path) -> PathBuf {
    child_shared_target_from_env().map_or_else(|| out_dir.join("target"), PathBuf::from)
}

/// Resolve the `CARGO_TARGET_DIR` for a SEAL test that RUNS the emitted binary
/// and asserts its stdout/exit.
///
/// ALWAYS an isolated per-slot `out_dir/target`, never the shared warm target:
/// every emitted crate builds a fixed-name `ipe-app`, so the shared target's
/// `debug/ipe-app` is a single file that concurrent tests clobber. A run-output
/// test must execute ITS OWN binary — a path no sibling can write — or it can
/// read a clobbered binary's output (a false red, or the worse false green where
/// the wrong binary happens to print the expected value, masking an emit bug).
/// The shared warm target's dep-cache speedup is reserved for build-only tests
/// (see [`emitted_target_dir`]); a run-output test cold-builds its deps, which is
/// the price of an un-clobberable binary path.
#[must_use]
#[allow(dead_code)]
pub fn emitted_run_target_dir(out_dir: &Path) -> PathBuf {
    out_dir.join("target")
}

/// Wrap a filesystem error as a `CompilerBug` diagnostic.
pub fn io_bug(path: &Path, e: &std::io::Error) -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: "seal e2e io",
        detail: format!("{}: {e}", path.display()),
    }
}

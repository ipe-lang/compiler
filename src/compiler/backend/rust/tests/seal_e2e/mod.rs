//! Shared helpers for the backend SEAL end-to-end tests.
//!
//! Each SEAL test emits an Ipê program, vendors the runtime source tree beside
//! it, and runs `cargo build` (and optionally the resulting binary) to prove the
//! emitted crate compiles and produces the expected output.
//!
//! This module is NOT a test binary — cargo treats a directory-with-mod.rs as a
//! library module and excludes it from the test-binary discovery pass.

use std::path::{Path, PathBuf};

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

/// Write `emitted` into a fresh temp directory named `slot` and vendor the
/// runtime source tree beside it. Returns the project root.
///
/// Exposed for the rare caller that must drive `e2e_support::target`'s
/// low-level `cargo_command`/`isolated` directly rather than
/// [`build_emitted`]/[`build_and_run_emitted`] — e.g. a test whose own
/// assertion depends on the package keeping its EXACT emitted name, which
/// `e2e_support`'s per-golden rename would otherwise mask.
pub fn vendor_into(emitted: &EmittedProject, runtime: &Path, slot: &str) -> DResult<PathBuf> {
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
    Ok(out)
}

/// Vendor `emitted` into a fresh temp directory named `slot` and build it
/// through the one typed build decision point (`e2e_support::target`), never a
/// hand-rolled `Command::new("cargo")`. The base emit template
/// (`backend/rust/templates/Cargo.toml`) declares no explicit `[[bin]]` and no
/// `autobins = false`, so cargo's implicit convention ties the binary name to
/// `[package] name` — and `e2e_support` renames the package per golden, so a
/// shared target's binary artifact can never collide with a sibling's.
///
/// Build-only: use this for a SEAL test that proves the emitted crate
/// `cargo build`s without executing the resulting binary. Use
/// [`build_and_run_emitted`] for a test that also runs it.
#[allow(dead_code)] // only some SEAL test binaries that `mod seal_e2e;` build-only
pub fn build_emitted(
    emitted: &EmittedProject,
    runtime: &Path,
    slot: &str,
) -> DResult<Result<e2e_support::SharedBuild, String>> {
    let out = vendor_into(emitted, runtime, slot)?;
    Ok(e2e_support::build_rust_binary(slot, &out))
}

/// Vendor `emitted` into a fresh temp directory named `slot`, build it, and run
/// the resulting binary — through `e2e_support::build_and_run_rust`, the one
/// typed build-and-run decision point. See [`build_emitted`] for why the
/// per-golden package rename makes this safe under a shared target.
#[allow(dead_code)] // only some SEAL test binaries that `mod seal_e2e;` build-and-run
pub fn build_and_run_emitted(
    emitted: &EmittedProject,
    runtime: &Path,
    slot: &str,
) -> DResult<Result<e2e_support::RunResult, String>> {
    let out = vendor_into(emitted, runtime, slot)?;
    Ok(e2e_support::build_and_run_rust(slot, &out))
}

/// [`build_and_run_emitted`], with `envs` additionally set on the `cargo
/// build` invocation (e.g. `RUSTFLAGS` for an overflow-checks SEAL).
#[allow(dead_code)] // only the one SEAL test binary that needs a build-time env var
pub fn build_and_run_emitted_with_env(
    emitted: &EmittedProject,
    runtime: &Path,
    slot: &str,
    envs: &[(&str, &str)],
) -> DResult<Result<e2e_support::RunResult, String>> {
    let out = vendor_into(emitted, runtime, slot)?;
    Ok(e2e_support::build_and_run_rust_with_env(slot, &out, envs))
}

/// Wrap a filesystem error as a `CompilerBug` diagnostic.
pub fn io_bug(path: &Path, e: &std::io::Error) -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: "seal e2e io",
        detail: format!("{}: {e}", path.display()),
    }
}

/// Wrap an `e2e_support` build/run failure (its `String` error) as a
/// `CompilerBug` diagnostic, so a caller can propagate it with `?` instead of
/// `.unwrap()`/`.expect()`/`panic!`.
#[allow(dead_code)] // only the SEAL test binaries that convert a build/run Err use this
pub const fn build_bug(e: String) -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: "seal e2e build",
        detail: e,
    }
}

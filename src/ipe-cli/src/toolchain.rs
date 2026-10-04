//! Fail-closed presence check for the Rust toolchain the driver shells out to.
//!
//! Ipê compiles a program to a Cargo project and then invokes `cargo` (which in
//! turn drives `rustc`) to build, run, and test it. When that toolchain is
//! absent the raw spawn fails with an opaque OS error (`No such file or
//! directory`) that never names the real cause. This module resolves `cargo` on
//! the `PATH` exactly once, and — when it is missing — produces a typed
//! [`ToolchainMissing`] carrying enough context for [`crate::CliError`] to
//! render a message that names the root cause, says why Ipê needs the
//! toolchain, and gives the fix.
//!
//! A resolved [`CargoBin`] is the parse-don't-validate token that the toolchain
//! was found: a call site holding one is statically past the check and reuses
//! the resolved path for the real invocation, so the toolchain is located once
//! and a bare `Command::new("cargo")` that could yield the cryptic error is
//! unreachable.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::style::TerminalSafe;

/// A `cargo` executable resolved on the `PATH`.
///
/// Holding one is proof the toolchain-presence check passed; the wrapped path is
/// reused verbatim for the actual invocation so the toolchain is located once,
/// not per spawn.
#[derive(Debug, Clone)]
pub struct CargoBin(PathBuf);

impl CargoBin {
    /// The resolved absolute path to `cargo`, ready to hand to `Command::new`.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// A stand-in `cargo` at `path`, for a test driving a stub.
    #[cfg(test)]
    pub(crate) const fn stub(path: PathBuf) -> Self {
        Self(path)
    }
}

/// What a command was trying to do when it needed the toolchain.
///
/// Selecting the intent lets the rendered message name THIS command's task
/// (build vs run vs test vs the browser bundle) rather than a generic one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolIntent {
    /// `ipe dev build` — compile the program to a native artifact.
    Build,
    /// `ipe dev run` — compile and execute the program.
    Run,
    /// `ipe dev build --target wasm` — compile and bundle the browser artifact.
    BundleWasm,
    /// `ipe verify` — compile and run the project's test entry.
    Test,
    /// `ipe dev watch` — rebuild and re-run on every source change.
    Watch,
}

impl ToolIntent {
    /// The task phrase for this command, completing "Ipê needs Cargo to …".
    pub(crate) const fn task_phrase(self) -> &'static str {
        match self {
            Self::Build => "compile this program to a native artifact",
            Self::Run => "compile and run this program",
            Self::BundleWasm => "compile this program to a WebAssembly bundle",
            Self::Test => "compile and run this project's tests",
            Self::Watch => "rebuild and re-run this program as it changes",
        }
    }
}

/// Whether the toolchain is absent everywhere or merely off the `PATH`.
///
/// The two cases have different fixes, so they are distinct values rather than
/// one "missing" flag: install it, versus expose the copy already on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// `cargo` is on neither the `PATH` nor a known install location — Rust is
    /// not installed. The fix is to install it.
    NotInstalled,
    /// `cargo` was found at a known install location but is not on the `PATH`,
    /// so the driver cannot invoke it. The fix is to add that directory to the
    /// `PATH`. Carries the directory the copy was found in, as terminal-safe
    /// display text: the message interpolates it, so a hostile directory name
    /// cannot reach the terminal raw.
    NotOnPath { found_in: TerminalSafe },
}

/// The typed "toolchain absent" error.
///
/// Carries which command needed the toolchain and why it could not be reached.
/// Rendered by [`crate::CliError`]'s `Display`.
#[derive(Debug, Clone)]
pub struct ToolchainMissing {
    /// What the command was trying to do.
    pub intent: ToolIntent,
    /// Not installed at all, versus installed but unreachable.
    pub disposition: Disposition,
}

impl std::fmt::Display for ToolchainMissing {
    /// Render the human-facing message through the CLI's look SSOT
    /// ([`crate::style`]): a failure glyph, the root cause, why Ipê needs the
    /// toolchain (naming THIS command's task), and the per-disposition fix.
    /// Self-guttered — the caller prints it as-is, without re-wrapping.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::style::{self, GUTTER};
        let task = self.intent.task_phrase();
        write!(
            f,
            "{GUTTER}{} Rust and Cargo were not found.\n\
             {GUTTER}    Ipê compiles your program to Rust and then runs Cargo to {task},\n\
             {GUTTER}    so it needs the Rust toolchain installed and reachable.\n",
            style::outcome_glyph(style::Outcome::Failure)
        )?;
        match &self.disposition {
            Disposition::NotInstalled => write!(
                f,
                "{GUTTER}    Install it once with rustup, then try again:\n\
                 {GUTTER}        https://rustup.rs"
            ),
            Disposition::NotOnPath { found_in } => write!(
                f,
                "{GUTTER}    Cargo is installed at {found_in} but that directory is not on your PATH.\n\
                 {GUTTER}    Add it to your PATH, then try again:\n\
                 {GUTTER}        export PATH=\"{found_in}:$PATH\""
            ),
        }
    }
}

/// The executable name of `cargo` for the host platform.
#[cfg(windows)]
const CARGO_EXE: &str = "cargo.exe";
/// The executable name of `cargo` for the host platform.
#[cfg(not(windows))]
const CARGO_EXE: &str = "cargo";

/// Resolve `cargo`, or produce a typed [`ToolchainMissing`].
///
/// The error's [`Disposition`] distinguishes "not installed" from "installed but
/// not on the `PATH`"; `intent` records what the caller was about to do so the
/// rendered message names this command's task. Fail-closed: a caller must hold
/// the returned [`CargoBin`] to reach a real invocation, so a missing toolchain
/// can never fall through to the opaque OS spawn error.
///
/// # Errors
/// [`ToolchainMissing`] when no `cargo` executable is found on the `PATH`.
pub fn require_cargo(intent: ToolIntent) -> Result<CargoBin, ToolchainMissing> {
    let path_var = ipe_env::var_os("PATH").unwrap_or_default();
    match resolve(&path_var, &known_install_dirs()) {
        Resolution::Found(path) => Ok(CargoBin(path)),
        Resolution::Missing(disposition) => Err(ToolchainMissing {
            intent,
            disposition,
        }),
    }
}

/// The outcome of a diagnostic probe for `cargo`: the resolved path, or why it
/// is absent.
///
/// This is the read-only sibling of [`require_cargo`]: `ipe health` reports the
/// toolchain's presence without an intent (it is not about to invoke `cargo`),
/// so it needs the resolution outcome, not a fail-closed [`CargoBin`] token.
#[derive(Debug, Clone)]
pub enum Probe {
    /// `cargo` was found on the `PATH` at this path.
    Found(PathBuf),
    /// `cargo` was not on the `PATH`; this is why.
    Missing(Disposition),
}

/// Probe for `cargo` without an [`ToolIntent`], for a diagnostic report.
///
/// Shares the exact search [`require_cargo`] uses (the `PATH`, then the known
/// install directories), so `health`'s verdict and a real build's verdict can
/// never disagree.
#[must_use]
pub fn probe_cargo() -> Probe {
    let path_var = ipe_env::var_os("PATH").unwrap_or_default();
    match resolve(&path_var, &known_install_dirs()) {
        Resolution::Found(path) => Probe::Found(path),
        Resolution::Missing(disposition) => Probe::Missing(disposition),
    }
}

/// The outcome of searching for `cargo`: the resolved path, or why it is absent.
/// A pure value over its inputs so the resolution logic is testable without
/// mutating the process environment.
enum Resolution {
    /// `cargo` was found on the `PATH` at this path.
    Found(PathBuf),
    /// `cargo` was not on the `PATH`; this is why.
    Missing(Disposition),
}

/// Search `path_var` (an OS `PATH` string) for `cargo`; when absent, fall back
/// to `install_dirs` to tell "not installed" from "installed but not on the
/// `PATH`". Pure over its inputs — it reads only the filesystem, never the
/// environment — so callers and tests supply the search space explicitly.
fn resolve(path_var: &OsString, install_dirs: &[PathBuf]) -> Resolution {
    if let Some(found) = std::env::split_paths(path_var)
        .map(|dir| dir.join(CARGO_EXE))
        .find(|candidate| is_executable_file(candidate))
    {
        return Resolution::Found(found);
    }
    let disposition = install_dirs
        .iter()
        .find(|dir| is_executable_file(&dir.join(CARGO_EXE)))
        .map_or(Disposition::NotInstalled, |dir| Disposition::NotOnPath {
            found_in: TerminalSafe::sanitize(&dir.display().to_string()),
        });
    Resolution::Missing(disposition)
}

/// The directories `rustup` installs `cargo` into by default.
///
/// Probing these lets the check tell "Rust is not installed" apart from "Rust is
/// installed but its `bin` directory is not on the `PATH`" — the latter has a
/// different fix.
fn known_install_dirs() -> Vec<PathBuf> {
    // The rustup default: `$CARGO_HOME/bin`, or `~/.cargo/bin` when unset. A
    // relative `CARGO_HOME` names no directory to probe; this is a read-only
    // hint for the "not on the `PATH`" diagnosis, so it is skipped rather than
    // reported here.
    let home = crate::env_dir::home().ok();
    let mut dirs: Vec<PathBuf> = crate::env_dir::tool_home("CARGO_HOME", home.as_ref(), ".cargo")
        .ok()
        .flatten()
        .map(|cargo_home| cargo_home.join("bin"))
        .into_iter()
        .collect();
    if let Some(default) = home.map(|home| home.join(".cargo").join("bin"))
        && !dirs.contains(&default)
    {
        dirs.push(default);
    }
    dirs
}

/// Whether `path` is a regular file the OS would run.
///
/// On Unix an executable bit must be set; on other platforms being a file is
/// sufficient (the loader decides). A directory named like the executable never
/// counts.
#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && (meta.permissions().mode() & 0o111 != 0))
}

/// Whether `path` is a regular file that could be executed. See the Unix
/// variant for the executable-bit rationale.
#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temp directory holding a dummy `cargo` executable, cleaned on drop.
    struct ProbeDir(PathBuf);

    impl ProbeDir {
        /// Create a fresh directory containing an executable named `cargo`.
        fn with_cargo(tag: &str) -> Self {
            let dir =
                ipe_test_temp::temp_root().join(format!("ipe_tc_{tag}_{}", std::process::id()));
            let created = std::fs::create_dir_all(&dir);
            assert!(created.is_ok(), "create probe dir: {created:?}");
            let cargo = dir.join(CARGO_EXE);
            let wrote = std::fs::write(&cargo, b"#!/bin/sh\n");
            assert!(wrote.is_ok(), "write dummy cargo: {wrote:?}");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let set = std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o755));
                assert!(set.is_ok(), "chmod dummy cargo: {set:?}");
            }
            Self(dir)
        }

        fn dir(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ProbeDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    #[allow(clippy::panic)] // a wrong resolution variant in a unit test IS the failure
    fn no_cargo_anywhere_is_not_installed() {
        // An empty PATH and no install dirs: cargo is nowhere, so the
        // resolution is NotInstalled — never a fall-through to a spawn.
        match resolve(&OsString::from(""), &[]) {
            Resolution::Missing(Disposition::NotInstalled) => {}
            Resolution::Missing(other) => panic!("expected NotInstalled, got {other:?}"),
            Resolution::Found(p) => panic!("expected missing, resolved {p:?}"),
        }
    }

    #[test]
    #[allow(clippy::panic)] // a wrong resolution variant in a unit test IS the failure
    fn cargo_in_an_install_dir_but_off_path_is_not_on_path() {
        let probe = ProbeDir::with_cargo("offpath");
        let install_dirs = [probe.dir().to_path_buf()];
        // Empty PATH, but the install dir holds cargo → NotOnPath naming it.
        match resolve(&OsString::from(""), &install_dirs) {
            Resolution::Missing(Disposition::NotOnPath { found_in }) => {
                assert_eq!(found_in.as_str(), probe.dir().display().to_string());
            }
            Resolution::Missing(other) => panic!("expected NotOnPath, got {other:?}"),
            Resolution::Found(p) => panic!("expected NotOnPath, resolved {p:?}"),
        }
    }

    #[test]
    #[allow(clippy::panic)] // a wrong resolution variant in a unit test IS the failure
    fn cargo_on_path_resolves_to_that_path() {
        let probe = ProbeDir::with_cargo("onpath");
        let path_var = OsString::from(probe.dir());
        match resolve(&path_var, &[]) {
            Resolution::Found(found) => assert_eq!(found, probe.dir().join(CARGO_EXE)),
            Resolution::Missing(d) => panic!("expected a resolved cargo, got {d:?}"),
        }
    }

    #[test]
    fn every_intent_has_a_task_phrase() {
        for intent in [
            ToolIntent::Build,
            ToolIntent::Run,
            ToolIntent::BundleWasm,
            ToolIntent::Test,
            ToolIntent::Watch,
        ] {
            assert!(!intent.task_phrase().is_empty());
        }
    }
}

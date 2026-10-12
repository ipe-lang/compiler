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

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::OnceLock;

use crate::remote_ingest::{
    LocalCeiling, LocalRefusal, LocalSource, RUSTC_QUERY_LIMITS, RunError, Stream, run_local,
};
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

/// The active toolchain's `rustc -vV` report, parsed once.
///
/// Holding one is proof the report was read within [`RUSTC_QUERY_LIMITS`] and
/// matched the grammar: a `rustc ` banner, then `key: value` lines, each key
/// once, `release` and `host` present, no control character but the line feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustcVersion {
    verbatim: Vec<u8>,
    release: String,
    host: String,
}

/// Why a `rustc -vV` report does not match the grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustcVersionRefusal {
    /// The report is not UTF-8.
    NotUtf8,
    /// The first line does not start with `rustc `.
    NoBanner,
    /// No `release` line.
    MissingRelease,
    /// No `host` line.
    MissingHost,
    /// A key appears on more than one line.
    DuplicateKey,
    /// A control character other than the line feed.
    ControlChar,
    /// A non-empty line past the banner that is not `key: value`.
    MalformedLine,
}

/// Why the `rustc -vV` child produced no report, its I/O errors kept as their kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustcRunFailure {
    /// The child could not be started.
    Spawn(ErrorKind),
    /// Waiting on the child failed.
    Wait(ErrorKind),
    /// Measuring the child's output failed.
    Measure(ErrorKind),
    /// The child crossed its ceiling and was killed.
    Exceeded(LocalRefusal),
    /// A process the child started held this pipe open past the grace.
    PipeDrainTimeout(Stream),
    /// Reading this pipe failed.
    PipeRead(Stream, ErrorKind),
}

impl From<RunError<LocalRefusal>> for RustcRunFailure {
    fn from(error: RunError<LocalRefusal>) -> Self {
        match error {
            RunError::Spawn(e) => Self::Spawn(e.kind()),
            RunError::Wait(e) => Self::Wait(e.kind()),
            RunError::Measure(_, e) => Self::Measure(e.kind()),
            RunError::Exceeded(refusal) => Self::Exceeded(refusal),
            RunError::PipeDrainTimeout(stream) => Self::PipeDrainTimeout(stream),
            RunError::PipeRead(stream, kind) => Self::PipeRead(stream, kind),
        }
    }
}

/// Why the active toolchain's version could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustcQueryRefusal {
    /// The child failed to run or crossed its ceiling.
    Run(RustcRunFailure),
    /// The child exited unsuccessfully.
    Exit(ExitStatus),
    /// The child's report does not match the grammar.
    Parse(RustcVersionRefusal),
}

impl RustcVersion {
    /// Parse a `rustc -vV` report.
    ///
    /// # Errors
    /// The [`RustcVersionRefusal`] naming the first rule `stdout` breaks.
    pub fn parse(stdout: &[u8]) -> Result<Self, RustcVersionRefusal> {
        let text = std::str::from_utf8(stdout).map_err(|_| RustcVersionRefusal::NotUtf8)?;
        if text.chars().any(|c| c != '\n' && c.is_control()) {
            return Err(RustcVersionRefusal::ControlChar);
        }
        let mut lines = text.split('\n');
        if !lines.next().unwrap_or_default().starts_with("rustc ") {
            return Err(RustcVersionRefusal::NoBanner);
        }
        let mut keys = BTreeSet::new();
        let mut release = None;
        let mut host = None;
        for line in lines.filter(|line| !line.is_empty()) {
            let (key, value) = line
                .split_once(": ")
                .filter(|(key, value)| is_report_key(key) && is_report_value(value))
                .ok_or(RustcVersionRefusal::MalformedLine)?;
            if !keys.insert(key) {
                return Err(RustcVersionRefusal::DuplicateKey);
            }
            match key {
                "release" => release = Some(value),
                "host" => host = Some(value),
                _ => {}
            }
        }
        let release = release.ok_or(RustcVersionRefusal::MissingRelease)?;
        let host = host.ok_or(RustcVersionRefusal::MissingHost)?;
        Ok(Self {
            verbatim: stdout.to_vec(),
            release: release.to_owned(),
            host: host.to_owned(),
        })
    }

    /// The version of the `rustc` on the `PATH`, queried once per process.
    ///
    /// # Errors
    /// The [`RustcQueryRefusal`] of the one query, returned again on every call.
    pub fn active() -> Result<&'static Self, RustcQueryRefusal> {
        static ACTIVE: OnceLock<Result<RustcVersion, RustcQueryRefusal>> = OnceLock::new();
        ACTIVE
            .get_or_init(|| Self::query(Command::new("rustc"), RUSTC_QUERY_LIMITS))
            .as_ref()
            .map_err(Clone::clone)
    }

    /// Run `rustc` with `-vV` under `ceiling` and parse its report.
    ///
    /// # Errors
    /// [`RustcQueryRefusal::Run`] when the child fails or crosses `ceiling`,
    /// [`RustcQueryRefusal::Exit`] when it exits unsuccessfully, and
    /// [`RustcQueryRefusal::Parse`] when its report breaks the grammar.
    pub fn query(mut rustc: Command, ceiling: LocalCeiling) -> Result<Self, RustcQueryRefusal> {
        rustc.arg("-vV");
        let captured = run_local(rustc, ceiling, LocalSource::RustcQuery)
            .map_err(|e| RustcQueryRefusal::Run(e.into()))?;
        if !captured.status.success() {
            return Err(RustcQueryRefusal::Exit(captured.status));
        }
        Self::parse(&captured.stdout).map_err(RustcQueryRefusal::Parse)
    }

    /// The report's exact bytes.
    #[must_use]
    pub fn verbatim(&self) -> &[u8] {
        &self.verbatim
    }

    /// The `release` value, such as `1.80.0`.
    #[must_use]
    pub fn release(&self) -> &str {
        &self.release
    }

    /// The `host` value, the toolchain's own target triple.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
}

/// Whether `key` is a report key: an ASCII letter, then letters, digits, `-` or inner spaces.
fn is_report_key(key: &str) -> bool {
    key.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && !key.ends_with(' ')
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == ' ')
}

/// Whether `value` is a report value: non-empty, with no surrounding whitespace.
fn is_report_value(value: &str) -> bool {
    !value.is_empty() && value.trim() == value
}

/// A directory holding an executable `rustc` script, removed on drop.
#[cfg(all(test, unix))]
pub struct StubRustc(PathBuf);

#[cfg(all(test, unix))]
impl StubRustc {
    /// Create a stub `rustc` whose body is the `sh` script `body`.
    ///
    /// # Errors
    /// The I/O error that kept the directory or the script from being written.
    pub fn new(tag: &str, body: &str) -> std::io::Result<Self> {
        use std::os::unix::fs::PermissionsExt as _;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir = ipe_test_temp::temp_root().join(format!(
            "ipe_stub_rustc_{tag}_{}_{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)?;
        let stub = Self(dir);
        let script = stub.0.join("rustc");
        std::fs::write(&script, format!("#!/bin/sh\n{body}\n"))?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))?;
        Ok(stub)
    }

    /// A `PATH` that finds this stub first, then the process's own `PATH`.
    ///
    /// # Errors
    /// The error of joining a `PATH` entry that holds the separator.
    pub fn path(&self) -> Result<OsString, std::env::JoinPathsError> {
        let inherited = ipe_env::var_os("PATH").unwrap_or_default();
        std::env::join_paths(
            std::iter::once(self.0.clone()).chain(std::env::split_paths(&inherited)),
        )
    }
}

#[cfg(all(test, unix))]
impl Drop for StubRustc {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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

    /// A `rustc 1.98.1 -vV` report, byte for byte.
    const REAL_VV: &[u8] = b"rustc 1.98.1 (48a229cea 2026-09-01)\n\
        binary: rustc\n\
        commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985\n\
        commit-date: 2026-09-01\n\
        host: x86_64-unknown-linux-gnu\n\
        release: 1.98.1\n\
        LLVM version: 22.1.8\n";

    fn refusal(report: &[u8]) -> Option<RustcVersionRefusal> {
        RustcVersion::parse(report).err()
    }

    #[test]
    fn rustc_version_parses_the_real_vv_output() {
        let parsed = RustcVersion::parse(REAL_VV);
        assert!(parsed.is_ok(), "{parsed:?}");
        let Ok(version) = parsed else { return };
        assert_eq!(version.release(), "1.98.1");
        assert_eq!(version.host(), "x86_64-unknown-linux-gnu");
        assert_eq!(version.verbatim(), REAL_VV);
    }

    #[test]
    fn a_non_utf8_report_is_refused() {
        assert_eq!(
            refusal(b"rustc 1.0 \xff\nhost: h\nrelease: 1.0\n"),
            Some(RustcVersionRefusal::NotUtf8)
        );
    }

    #[test]
    fn a_report_without_the_rustc_banner_is_refused() {
        assert_eq!(
            refusal(b"cargo 1.0\nhost: h\nrelease: 1.0\n"),
            Some(RustcVersionRefusal::NoBanner)
        );
        assert_eq!(refusal(b""), Some(RustcVersionRefusal::NoBanner));
    }

    #[test]
    fn a_report_without_release_is_refused() {
        assert_eq!(
            refusal(b"rustc 1.0\nhost: x86_64-unknown-linux-gnu\n"),
            Some(RustcVersionRefusal::MissingRelease)
        );
    }

    #[test]
    fn a_report_without_host_is_refused() {
        assert_eq!(
            refusal(b"rustc 1.0\nrelease: 1.0\n"),
            Some(RustcVersionRefusal::MissingHost)
        );
    }

    #[test]
    fn a_duplicated_host_is_refused() {
        assert_eq!(
            refusal(b"rustc 1.0\nhost: a-b-c\nhost: d-e-f\nrelease: 1.0\n"),
            Some(RustcVersionRefusal::DuplicateKey)
        );
    }

    #[test]
    fn an_escape_byte_is_refused() {
        assert_eq!(
            refusal(b"rustc 1.0\nhost: x86\x1b[31m\nrelease: 1.0\n"),
            Some(RustcVersionRefusal::ControlChar)
        );
        assert_eq!(
            refusal(b"rustc 1.0\r\nhost: h\r\nrelease: 1.0\r\n"),
            Some(RustcVersionRefusal::ControlChar)
        );
    }

    #[test]
    fn a_line_that_is_not_key_colon_value_is_refused() {
        for report in [
            b"rustc 1.0\nhost x86\nrelease: 1.0\n".as_slice(),
            b"rustc 1.0\nhost: \nrelease: 1.0\n",
            b"rustc 1.0\nhost:  h\nrelease: 1.0\n",
            b"rustc 1.0\nho_st: h\nrelease: 1.0\n",
            b"rustc 1.0\n: h\nrelease: 1.0\n",
        ] {
            assert_eq!(
                refusal(report),
                Some(RustcVersionRefusal::MalformedLine),
                "{}",
                String::from_utf8_lossy(report)
            );
        }
    }

    /// A `rustc` command that resolves to `stub`.
    #[cfg(unix)]
    #[allow(clippy::expect_used)] // a test temp path holds no `PATH` separator
    fn stubbed(stub: &StubRustc) -> Command {
        let mut rustc = Command::new("rustc");
        rustc.env("PATH", stub.path().expect("join the stub PATH"));
        rustc
    }

    /// A stub `rustc` running `body`.
    #[cfg(unix)]
    #[allow(clippy::expect_used)] // the test temp root is writable
    fn stub_rustc(tag: &str, body: &str) -> StubRustc {
        StubRustc::new(tag, body).expect("write the stub rustc")
    }

    #[cfg(unix)]
    #[test]
    fn a_stub_rustc_printing_a_valid_report_is_read() {
        let stub = stub_rustc(
            "valid",
            "printf 'rustc 1.0 (x)\\nhost: a-b-c\\nrelease: 1.0\\n'",
        );
        let version = RustcVersion::query(stubbed(&stub), RUSTC_QUERY_LIMITS);
        assert!(version.is_ok(), "{version:?}");
        let Ok(version) = version else { return };
        assert_eq!(version.host(), "a-b-c");
        assert_eq!(version.release(), "1.0");
    }

    #[cfg(unix)]
    #[test]
    fn a_flooding_rustc_is_refused() {
        let stub = stub_rustc("flood", "head -c 70000 /dev/zero\nsleep 30\nexit 0");
        let started = std::time::Instant::now();
        let version = RustcVersion::query(stubbed(&stub), RUSTC_QUERY_LIMITS);
        assert!(
            matches!(
                version,
                Err(RustcQueryRefusal::Run(RustcRunFailure::Exceeded(
                    LocalRefusal {
                        source: LocalSource::RustcQuery,
                        limit: crate::remote_ingest::IngestLimit::Bytes(_),
                        ..
                    }
                )))
            ),
            "{version:?}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_rustc_is_refused_by_its_exit() {
        let stub = stub_rustc(
            "exit",
            "printf 'rustc 1.0 (x)\\nhost: a-b-c\\nrelease: 1.0\\n'\nexit 3",
        );
        let version = RustcVersion::query(stubbed(&stub), RUSTC_QUERY_LIMITS);
        assert!(
            matches!(version, Err(RustcQueryRefusal::Exit(status)) if status.code() == Some(3)),
            "{version:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_unparsable_rustc_report_is_refused() {
        let stub = stub_rustc("garbage", "printf 'not a rustc report\\n'");
        let version = RustcVersion::query(stubbed(&stub), RUSTC_QUERY_LIMITS);
        assert_eq!(
            version,
            Err(RustcQueryRefusal::Parse(RustcVersionRefusal::NoBanner))
        );
    }
}

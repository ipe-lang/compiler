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
use ipe_sandbox::host_tool::{self, HostTool};

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
    /// `ipe dev build web client` — compile and bundle the browser artifact.
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

/// A host program the driver shells out to, resolved on the `PATH` before use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// `cargo`, which drives `rustc`.
    Cargo,
    /// The `wasm-bindgen` CLI a `web client` bundle runs after its wasm link,
    /// at the exact `version` the runtime's `wasm-bindgen` crate pins.
    WasmBindgen {
        /// The pinned `wasm-bindgen-cli` version.
        version: &'static str,
    },
}

impl Tool {
    /// The program's file name before the host's executable suffix.
    const fn program(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::WasmBindgen { .. } => "wasm-bindgen",
        }
    }

    /// The program's executable file name on this host.
    fn exe(self) -> String {
        crate::health::exe_name(self.program(), ipe_path_core::HOST)
    }

    /// The program in the closed set the one `PATH` resolver admits.
    const fn host_tool(self) -> HostTool {
        match self {
            Self::Cargo => HostTool::Cargo,
            Self::WasmBindgen { .. } => HostTool::WasmBindgen,
        }
    }
}

/// The typed "toolchain absent" error.
///
/// Carries which program is absent, which command needed it, and why it could
/// not be reached. Rendered by [`crate::CliError`]'s `Display`.
#[derive(Debug, Clone)]
pub struct ToolchainMissing {
    /// The program that was not found.
    pub tool: Tool,
    /// What the command was trying to do.
    pub intent: ToolIntent,
    /// Not installed at all, versus installed but unreachable.
    pub disposition: Disposition,
}

impl std::fmt::Display for ToolchainMissing {
    /// Render the human-facing message through the CLI's look SSOT
    /// ([`crate::style`]): a failure glyph, the root cause, why Ipê needs the
    /// program (naming THIS command's task), and the per-disposition fix.
    /// Self-guttered — the caller prints it as-is, without re-wrapping.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::style::{self, GUTTER};
        let task = self.intent.task_phrase();
        let glyph = style::outcome_glyph(style::Outcome::Failure);
        let name = match self.tool {
            Tool::Cargo => {
                write!(
                    f,
                    "{GUTTER}{glyph} Rust and Cargo were not found.\n\
                     {GUTTER}    Ipê compiles your program to Rust and then runs Cargo to {task},\n\
                     {GUTTER}    so it needs the Rust toolchain installed and reachable.\n"
                )?;
                "Cargo"
            }
            Tool::WasmBindgen { version } => {
                write!(
                    f,
                    "{GUTTER}{glyph} wasm-bindgen was not found.\n\
                     {GUTTER}    Ipê runs the wasm-bindgen CLI after Cargo to {task},\n\
                     {GUTTER}    so it needs wasm-bindgen-cli {version}, the version the runtime pins.\n"
                )?;
                "wasm-bindgen"
            }
        };
        match (&self.disposition, self.tool) {
            (Disposition::NotInstalled, Tool::Cargo) => write!(
                f,
                "{GUTTER}    Install it once with rustup, then try again:\n\
                 {GUTTER}        https://rustup.rs"
            ),
            (Disposition::NotInstalled, Tool::WasmBindgen { version }) => write!(
                f,
                "{GUTTER}    Install it once, then try again:\n\
                 {GUTTER}        cargo install wasm-bindgen-cli --version {version} --locked"
            ),
            (Disposition::NotOnPath { found_in }, Tool::Cargo | Tool::WasmBindgen { .. }) => {
                write!(
                    f,
                    "{GUTTER}    {name} is installed at {found_in} but that directory is not on your PATH.\n\
                     {GUTTER}    Add it to your PATH, then try again:\n\
                     {GUTTER}        export PATH=\"{found_in}:$PATH\""
                )
            }
        }
    }
}

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
    require(Tool::Cargo, intent).map(CargoBin)
}

/// A `wasm-bindgen` executable resolved on the `PATH`.
///
/// Holding one is proof the presence check passed before the wasm build
/// started; the wrapped path is the one the bundle step runs.
#[derive(Debug, Clone)]
pub struct WasmBindgenBin(PathBuf);

impl WasmBindgenBin {
    /// The resolved absolute path to `wasm-bindgen`, ready to hand to `Command::new`.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// Resolve the `wasm-bindgen` CLI a `web client` bundle runs, or produce a
/// typed [`ToolchainMissing`] naming it and its pinned `version`.
///
/// Searched exactly as [`require_cargo`] searches for `cargo`: `cargo install`
/// places the CLI in the same `bin` directory.
///
/// # Errors
/// [`ToolchainMissing`] when no `wasm-bindgen` executable is found on the `PATH`.
pub fn require_wasm_bindgen(version: &'static str) -> Result<WasmBindgenBin, ToolchainMissing> {
    require(Tool::WasmBindgen { version }, ToolIntent::BundleWasm).map(WasmBindgenBin)
}

/// Resolve `tool` on the `PATH`, or the typed [`ToolchainMissing`] for `intent`.
fn require(tool: Tool, intent: ToolIntent) -> Result<PathBuf, ToolchainMissing> {
    let path_var = ipe_env::var_os("PATH").unwrap_or_default();
    match resolve(tool, &path_var, &known_install_dirs()) {
        Resolution::Found(path) => Ok(path),
        Resolution::Missing(disposition) => Err(ToolchainMissing {
            tool,
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
    match resolve(Tool::Cargo, &path_var, &known_install_dirs()) {
        Resolution::Found(path) => Probe::Found(path),
        Resolution::Missing(disposition) => Probe::Missing(disposition),
    }
}

/// The outcome of searching for a program: the resolved path, or why it is absent.
/// A pure value over its inputs so the resolution logic is testable without
/// mutating the process environment.
enum Resolution {
    /// The program was found on the `PATH` at this path.
    Found(PathBuf),
    /// The program was not on the `PATH`; this is why.
    Missing(Disposition),
}

/// Search `path_var` (an OS `PATH` string) for `tool` through the one `PATH`
/// resolver, which admits only absolute entries; when absent, fall back to
/// `install_dirs` to tell "not installed" from "installed but not on the
/// `PATH`". Pure over its inputs — it reads only the filesystem, never the
/// environment — so callers and tests supply the search space explicitly.
fn resolve(tool: Tool, path_var: &OsString, install_dirs: &[PathBuf]) -> Resolution {
    if let Ok(found) = host_tool::resolve_in(path_var, tool.host_tool(), ipe_path_core::HOST) {
        return Resolution::Found(found.as_path());
    }
    let exe = tool.exe();
    let disposition = install_dirs
        .iter()
        .find(|dir| is_executable_file(&dir.join(&exe)))
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

/// A Rust release number, `major.minor.patch`, ordered the way cargo judges a
/// manifest's `rust-version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustRelease {
    major: u32,
    minor: u32,
    patch: u32,
}

impl RustRelease {
    /// Parse `major.minor.patch`, optionally followed by a `-<channel>` tag
    /// (`1.99.0-nightly`).
    ///
    /// The tag is dropped, as cargo drops it when it compares a toolchain
    /// with a `rust-version`. `None` for anything else: a missing or extra
    /// component, a non-digit, an empty tag, or a component past `u32::MAX`.
    #[must_use]
    pub const fn parse(text: &[u8]) -> Option<Self> {
        let Some((major, rest)) = leading_number(text) else {
            return None;
        };
        let Some((b'.', rest)) = rest.split_first() else {
            return None;
        };
        let Some((minor, rest)) = leading_number(rest) else {
            return None;
        };
        let Some((b'.', rest)) = rest.split_first() else {
            return None;
        };
        let Some((patch, rest)) = leading_number(rest) else {
            return None;
        };
        match rest.split_first() {
            None => {}
            Some((b'-', tag)) if !tag.is_empty() => {}
            Some(_) => return None,
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

impl std::fmt::Display for RustRelease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The decimal number at the start of `text` and the bytes after it.
///
/// `None` when `text` does not start with a digit or the number passes
/// `u32::MAX`.
const fn leading_number(text: &[u8]) -> Option<(u32, &[u8])> {
    let mut value: u32 = 0;
    let mut digits = 0usize;
    let mut rest = text;
    while let Some((byte, tail)) = rest.split_first() {
        if !byte.is_ascii_digit() {
            break;
        }
        let Some(shifted) = value.checked_mul(10) else {
            return None;
        };
        let Some(next) = shifted.checked_add(byte.wrapping_sub(b'0') as u32) else {
            return None;
        };
        value = next;
        digits = digits.saturating_add(1);
        rest = tail;
    }
    if digits == 0 {
        return None;
    }
    Some((value, rest))
}

/// The pinned release every emitted manifest declares as its `rust-version`,
/// parsed from the backend's [`ipe_backend_rust::RUST_VERSION_FLOOR`].
///
/// The fallback is the highest release, which refuses every toolchain; the
/// assertion below makes it unreachable by failing the build instead.
pub const PINNED_RELEASE: RustRelease =
    match RustRelease::parse(ipe_backend_rust::RUST_VERSION_FLOOR.as_bytes()) {
        Some(release) => release,
        None => RustRelease {
            major: u32::MAX,
            minor: u32::MAX,
            patch: u32::MAX,
        },
    };

// The pin parses as a release, so the floor the driver judges is the one the
// emitted manifests declare.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the toolchain pin is not a `major.minor.patch` release [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    RustRelease::parse(ipe_backend_rust::RUST_VERSION_FLOOR.as_bytes()).is_some(),
    "the `rust-toolchain.toml` channel must be a `major.minor.patch` release"
);

/// Why the toolchain a build would use was refused before cargo ran.
#[derive(Debug, Clone)]
pub struct ToolchainFloorRefusal {
    /// The release the emitted manifests require.
    pub required: RustRelease,
    /// What the build's `rustc` reported instead.
    pub found: FloorReading,
}

/// What the build's `rustc` reported, when it does not meet the floor.
#[derive(Debug, Clone)]
pub enum FloorReading {
    /// A release below the floor.
    Below(RustRelease),
    /// A `release` value that is not a Rust release number.
    Unparsed(TerminalSafe),
    /// No report: `rustc -vV` failed, or its report broke the grammar.
    Unread(RustcQueryRefusal),
}

impl ToolchainFloorRefusal {
    /// The refusal's body: what was found, what is required, and the fix.
    ///
    /// Shown inside the host-toolchain diagnostic (`IPE-E0013`).
    #[must_use]
    pub fn detail(&self) -> String {
        let required = self.required;
        let found = match &self.found {
            FloorReading::Below(release) => format!(
                "The build would use Rust {release}, but Ipê's emitted crates need Rust {required} or newer."
            ),
            FloorReading::Unparsed(release) => format!(
                "The build's `rustc` reports release `{}`, which is not a Rust release number, \
                 so Ipê cannot confirm it is Rust {required} or newer.",
                release.as_str()
            ),
            FloorReading::Unread(why) => format!(
                "Ipê could not read the version of the build's `rustc` (`rustc -vV` {}), \
                 so it cannot confirm it is Rust {required} or newer.",
                unread_phrase(why)
            ),
        };
        format!(
            "{found}\n\
             Update the toolchain, then try again:\n    \
             rustup update stable\n\
             Or build with the pinned release:\n    \
             rustup toolchain install {required}\n    \
             RUSTUP_TOOLCHAIN={required} ipe <command>"
        )
    }
}

impl std::fmt::Display for ToolchainFloorRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail())
    }
}

impl std::error::Error for ToolchainFloorRefusal {}

/// How a `rustc -vV` query failed, for the refusal's prose.
fn unread_phrase(why: &RustcQueryRefusal) -> String {
    match why {
        RustcQueryRefusal::Run(_) => String::from("could not run"),
        RustcQueryRefusal::Exit(status) => format!("exited with {status}"),
        RustcQueryRefusal::Parse(_) => String::from("printed a report Ipê cannot read"),
    }
}

/// Judge a `rustc -vV` query against the floor `required`.
///
/// Fails closed: a failed query or a release that does not parse is refused,
/// never admitted.
///
/// # Errors
/// The [`ToolchainFloorRefusal`] naming the release found, or why none was.
pub fn judge_floor(
    report: Result<RustcVersion, RustcQueryRefusal>,
    required: RustRelease,
) -> Result<(), ToolchainFloorRefusal> {
    let found = match report {
        Err(why) => FloorReading::Unread(why),
        Ok(version) => match RustRelease::parse(version.release().as_bytes()) {
            Some(release) if release >= required => return Ok(()),
            Some(release) => FloorReading::Below(release),
            None => FloorReading::Unparsed(TerminalSafe::sanitize(version.release())),
        },
    };
    Err(ToolchainFloorRefusal { required, found })
}

/// Refuse a build in `crate_dir` whose toolchain is older than the pin.
///
/// `rustc -vV` runs in `crate_dir`, the directory cargo runs in, so rustup
/// resolves the same toolchain for the query as for the build (a
/// `rust-toolchain.toml` above it, an override, `RUSTUP_TOOLCHAIN`, or the
/// default). The last directory admitted is remembered, so a watch session's
/// rebuilds query once.
///
/// # Errors
/// The [`ToolchainFloorRefusal`] of [`judge_floor`].
pub fn require_floor(crate_dir: &Path) -> Result<(), ToolchainFloorRefusal> {
    static ADMITTED: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);
    let remembered = ADMITTED
        .lock()
        .is_ok_and(|admitted| admitted.as_deref() == Some(crate_dir));
    if remembered {
        return Ok(());
    }
    let mut rustc = Command::new("rustc");
    rustc.current_dir(crate_dir);
    judge_floor(
        RustcVersion::query(rustc, RUSTC_QUERY_LIMITS),
        PINNED_RELEASE,
    )?;
    if let Ok(mut admitted) = ADMITTED.lock() {
        *admitted = Some(crate_dir.to_path_buf());
    }
    Ok(())
}

/// The active toolchain's sysroot, read from `rustc --print sysroot`.
///
/// Holding one is proof the report was read within [`RUSTC_QUERY_LIMITS`] and
/// was one UTF-8 line naming an absolute path, with no control character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustcSysroot(PathBuf);

/// Why the active toolchain's sysroot could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustcSysrootRefusal {
    /// The child failed to run or crossed its ceiling.
    Run(RustcRunFailure),
    /// The child exited unsuccessfully.
    Exit(ExitStatus),
    /// The report is not one UTF-8 line naming an absolute path.
    Malformed,
}

impl RustcSysroot {
    /// Parse a `rustc --print sysroot` report: one line, its trailing line ending dropped.
    ///
    /// # Errors
    /// [`RustcSysrootRefusal::Malformed`] when `stdout` is not UTF-8, holds a
    /// control character or a second line, or names a relative path.
    pub fn parse(stdout: &[u8]) -> Result<Self, RustcSysrootRefusal> {
        let text = std::str::from_utf8(stdout).map_err(|_| RustcSysrootRefusal::Malformed)?;
        let line = text
            .strip_suffix('\n')
            .map_or(text, |rest| rest.strip_suffix('\r').unwrap_or(rest));
        let path = Path::new(line);
        if line.is_empty() || line.chars().any(char::is_control) || !path.is_absolute() {
            return Err(RustcSysrootRefusal::Malformed);
        }
        Ok(Self(path.to_path_buf()))
    }

    /// The sysroot of the `rustc` on the `PATH`, queried once per process.
    ///
    /// # Errors
    /// The [`RustcSysrootRefusal`] of the one query, returned again on every call.
    pub fn active() -> Result<&'static Self, RustcSysrootRefusal> {
        static ACTIVE: OnceLock<Result<RustcSysroot, RustcSysrootRefusal>> = OnceLock::new();
        ACTIVE
            .get_or_init(|| Self::query(Command::new("rustc"), RUSTC_QUERY_LIMITS))
            .as_ref()
            .map_err(Clone::clone)
    }

    /// Run `rustc` with `--print sysroot` under `ceiling` and parse its report.
    ///
    /// # Errors
    /// [`RustcSysrootRefusal::Run`] when the child fails or crosses `ceiling`,
    /// [`RustcSysrootRefusal::Exit`] when it exits unsuccessfully, and
    /// [`RustcSysrootRefusal::Malformed`] when its report breaks the grammar.
    pub fn query(mut rustc: Command, ceiling: LocalCeiling) -> Result<Self, RustcSysrootRefusal> {
        rustc.args(["--print", "sysroot"]);
        let captured = run_local(rustc, ceiling, LocalSource::RustcSysroot)
            .map_err(|e| RustcSysrootRefusal::Run(e.into()))?;
        if !captured.status.success() {
            return Err(RustcSysrootRefusal::Exit(captured.status));
        }
        Self::parse(&captured.stdout)
    }

    /// The sysroot directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
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

    /// The executable file name of `cargo` on this host.
    fn cargo_exe() -> String {
        Tool::Cargo.exe()
    }

    /// A temp directory holding a dummy `cargo` executable, cleaned on drop.
    struct ProbeDir(PathBuf);

    impl ProbeDir {
        /// Create a fresh directory containing an executable named `cargo`.
        fn with_cargo(tag: &str) -> Self {
            let dir =
                ipe_test_temp::temp_root().join(format!("ipe_tc_{tag}_{}", std::process::id()));
            let created = std::fs::create_dir_all(&dir);
            assert!(created.is_ok(), "create probe dir: {created:?}");
            let cargo = dir.join(cargo_exe());
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
        match resolve(Tool::Cargo, &OsString::from(""), &[]) {
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
        match resolve(Tool::Cargo, &OsString::from(""), &install_dirs) {
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
        match resolve(Tool::Cargo, &path_var, &[]) {
            Resolution::Found(found) => assert_eq!(found, probe.dir().join(cargo_exe())),
            Resolution::Missing(d) => panic!("expected a resolved cargo, got {d:?}"),
        }
    }

    /// A relative `PATH` entry is never searched: a program there is the
    /// working directory's, which may be an untrusted project's.
    #[test]
    #[allow(clippy::panic)] // a wrong resolution variant in a unit test IS the failure
    fn cargo_under_a_relative_path_entry_is_not_resolved() {
        let probe = ProbeDir::with_cargo("relative");
        let cwd = std::env::current_dir();
        let Ok(cwd) = cwd else {
            panic!("working directory: {cwd:?}");
        };
        // `../` up to the root, then the probe's absolute path below it: a
        // relative entry that names the probe from the working directory.
        let mut relative = PathBuf::new();
        for _ in cwd.components().skip(1) {
            relative.push("..");
        }
        relative.extend(probe.dir().components().skip(1));
        assert!(
            relative.is_relative() && relative.join(cargo_exe()).is_file(),
            "the relative entry {relative:?} names the probe"
        );
        match resolve(Tool::Cargo, &relative.into_os_string(), &[]) {
            Resolution::Missing(Disposition::NotInstalled) => {}
            Resolution::Missing(other) => panic!("expected NotInstalled, got {other:?}"),
            Resolution::Found(p) => panic!("a relative PATH entry resolved {p:?}"),
        }
    }

    /// `wasm-bindgen` is searched by its own name: a `PATH` holding only
    /// `cargo` does not resolve it.
    #[test]
    #[allow(clippy::panic)] // a wrong resolution variant in a unit test IS the failure
    fn wasm_bindgen_beside_cargo_only_is_not_installed() {
        let probe = ProbeDir::with_cargo("bindgen-absent");
        let path_var = OsString::from(probe.dir());
        let bindgen = Tool::WasmBindgen { version: "0.2.126" };
        match resolve(bindgen, &path_var, &[]) {
            Resolution::Missing(Disposition::NotInstalled) => {}
            Resolution::Missing(other) => panic!("expected NotInstalled, got {other:?}"),
            Resolution::Found(p) => panic!("expected missing, resolved {p:?}"),
        }
    }

    /// A missing `wasm-bindgen` names the tool, its pinned version and the
    /// install command — never a missing source file.
    #[test]
    fn a_missing_wasm_bindgen_names_the_tool_and_its_install() {
        let missing = ToolchainMissing {
            tool: Tool::WasmBindgen { version: "0.2.126" },
            intent: ToolIntent::BundleWasm,
            disposition: Disposition::NotInstalled,
        };
        let text = missing.to_string();
        assert!(text.contains("wasm-bindgen was not found"), "{text}");
        assert!(text.contains("wasm-bindgen-cli 0.2.126"), "{text}");
        assert!(
            text.contains("cargo install wasm-bindgen-cli --version 0.2.126 --locked"),
            "{text}"
        );
        assert!(!text.contains("source file"), "{text}");
        assert!(!text.contains("Rust and Cargo"), "{text}");
        let off_path = ToolchainMissing {
            disposition: Disposition::NotOnPath {
                found_in: TerminalSafe::sanitize("/home/u/.cargo/bin"),
            },
            ..missing
        };
        let text = off_path.to_string();
        assert!(
            text.contains("wasm-bindgen is installed at /home/u/.cargo/bin"),
            "{text}"
        );
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

    /// The report of a `rustc` at `release`.
    fn reporting(release: &str) -> Result<RustcVersion, RustcQueryRefusal> {
        RustcVersion::parse(
            format!("rustc {release} (x)\nhost: a-b-c\nrelease: {release}\n").as_bytes(),
        )
        .map_err(RustcQueryRefusal::Parse)
    }

    /// The release `text` parses to, or a test failure.
    #[allow(clippy::panic)] // an unparsed fixture release IS the failure
    fn release(text: &str) -> RustRelease {
        let Some(release) = RustRelease::parse(text.as_bytes()) else {
            panic!("fixture release {text:?} does not parse");
        };
        release
    }

    #[test]
    fn the_pin_is_the_toolchain_channel() {
        assert_eq!(
            PINNED_RELEASE,
            release(ipe_backend_rust::RUST_VERSION_FLOOR),
            "the driver's floor and the emitted `rust-version` share one source"
        );
        assert_ne!(PINNED_RELEASE.major, u32::MAX);
    }

    #[test]
    fn a_toolchain_one_minor_below_the_pin_is_refused() {
        let pin = release("1.98.1");
        let refused = judge_floor(reporting("1.97.1"), pin);
        assert!(
            matches!(&refused, Err(ToolchainFloorRefusal { required, found: FloorReading::Below(found) })
                if *required == pin && *found == release("1.97.1")),
            "{refused:?}"
        );
        let refused = judge_floor(reporting("1.98.0"), pin);
        assert!(
            matches!(
                &refused,
                Err(ToolchainFloorRefusal {
                    found: FloorReading::Below(_),
                    ..
                })
            ),
            "one patch below: {refused:?}"
        );
    }

    #[test]
    fn the_pin_and_later_releases_are_admitted() {
        let pin = release("1.98.1");
        for found in [
            "1.98.1",
            "1.98.2",
            "1.99.0",
            "1.100.0-nightly",
            "1.98.1-beta.3",
            "2.0.0",
        ] {
            let judged = judge_floor(reporting(found), pin);
            assert!(judged.is_ok(), "{found}: {judged:?}");
        }
    }

    #[test]
    fn an_unparseable_release_is_refused_not_admitted() {
        let pin = release("1.98.1");
        for found in [
            "1.98",
            "1.98.1.0",
            "1.98.x",
            "v1.98.1",
            "1.98.1-",
            "99999999999.0.0",
            "1.98.1+local",
        ] {
            let judged = judge_floor(reporting(found), pin);
            assert!(
                matches!(
                    &judged,
                    Err(ToolchainFloorRefusal {
                        found: FloorReading::Unparsed(_),
                        ..
                    })
                ),
                "{found}: {judged:?}"
            );
        }
        let judged = judge_floor(
            Err(RustcQueryRefusal::Parse(RustcVersionRefusal::NoBanner)),
            pin,
        );
        assert!(
            matches!(
                &judged,
                Err(ToolchainFloorRefusal {
                    found: FloorReading::Unread(_),
                    ..
                })
            ),
            "{judged:?}"
        );
    }

    #[test]
    fn the_refusal_names_found_required_and_remedy() {
        let refused = judge_floor(reporting("1.97.1"), release("1.98.1"));
        let detail = refused.err().map(|r| r.detail()).unwrap_or_default();
        for needle in [
            "Rust 1.97.1",
            "Rust 1.98.1 or newer",
            "rustup update stable",
            "RUSTUP_TOOLCHAIN=1.98.1",
        ] {
            assert!(detail.contains(needle), "{needle}: {detail}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_stub_rustc_below_the_pin_is_refused_through_the_query() {
        let stub = stub_rustc(
            "floor",
            "printf 'rustc 1.97.1 (x)\\nhost: a-b-c\\nrelease: 1.97.1\\n'",
        );
        let judged = judge_floor(
            RustcVersion::query(stubbed(&stub), RUSTC_QUERY_LIMITS),
            release("1.98.1"),
        );
        assert!(
            matches!(
                &judged,
                Err(ToolchainFloorRefusal {
                    found: FloorReading::Below(_),
                    ..
                })
            ),
            "{judged:?}"
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

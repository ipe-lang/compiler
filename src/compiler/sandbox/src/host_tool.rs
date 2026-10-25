//! The one resolver of a host program `ipe` spawns.
//!
//! Every program the compiler runs on the host — a jail primitive, the Rust
//! toolchain, a packaging helper — is a [`HostTool`], a closed enum, and it
//! reaches `Command::new` only as a [`ToolPath`]. A `ToolPath` has one
//! constructor, [`resolve_in`]: it walks the `PATH` entries, skips every entry
//! that is not absolute (a bare name, `.`, an empty entry), and admits a
//! candidate only when it is an executable regular file. A relative entry is
//! never joined, so the working directory — an untrusted project checkout —
//! cannot supply the program; a jail tool planted there would otherwise run
//! unjailed, as the invoker, before any jail exists.
//!
//! The file is not canonicalised: a rustup shim and a busybox applet dispatch
//! on the name they are run as, so the resolved path keeps the directory the
//! entry named and the file name the tool has.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

use ipe_path_core::Regime;

/// A host program `ipe` may spawn.
///
/// Closed: a program outside this list has no path to `Command::new`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostTool {
    /// Bubblewrap, the Linux jail.
    Bwrap,
    /// `prlimit`, the Linux jail's resource caps.
    Prlimit,
    /// `timeout`, the Linux jail's wall clock.
    Timeout,
    /// `sandbox-exec`, the macOS Seatbelt jail.
    SandboxExec,
    /// `jail(8)`, the FreeBSD jail.
    Jail,
    /// `rctl(8)`, the FreeBSD jail's process cap.
    Rctl,
    /// `chown(8)`, the FreeBSD jail's scratch ownership.
    Chown,
    /// `mount_nullfs(8)`, the FreeBSD jail's read-only root view.
    MountNullfs,
    /// `mount(8)`, the FreeBSD jail's devfs mount.
    Mount,
    /// `umount(8)`, the FreeBSD jail's teardown.
    Umount,
    /// Windows PowerShell, the probe interpreter the Windows jail runs.
    PowerShell,
    /// `cargo`.
    Cargo,
    /// `rustc`.
    Rustc,
    /// `rustup`.
    Rustup,
    /// `rustfmt`.
    Rustfmt,
    /// `cargo-deny`.
    CargoDeny,
    /// `sccache`.
    Sccache,
    /// The FFI inspector `ipe` ships beside itself.
    FfiInspector,
    /// `wasm-bindgen`.
    WasmBindgen,
    /// `wasm-opt`.
    WasmOpt,
    /// `git`.
    Git,
    /// `curl`.
    Curl,
    /// The POSIX shell.
    Sh,
}

impl HostTool {
    /// The program's name without any platform suffix.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bwrap => "bwrap",
            Self::Prlimit => "prlimit",
            Self::Timeout => "timeout",
            Self::SandboxExec => "sandbox-exec",
            Self::Jail => "jail",
            Self::Rctl => "rctl",
            Self::Chown => "chown",
            Self::MountNullfs => "mount_nullfs",
            Self::Mount => "mount",
            Self::Umount => "umount",
            Self::PowerShell => "powershell",
            Self::Cargo => "cargo",
            Self::Rustc => "rustc",
            Self::Rustup => "rustup",
            Self::Rustfmt => "rustfmt",
            Self::CargoDeny => "cargo-deny",
            Self::Sccache => "sccache",
            Self::FfiInspector => "ipe-ffi-inspector",
            Self::WasmBindgen => "wasm-bindgen",
            Self::WasmOpt => "wasm-opt",
            Self::Git => "git",
            Self::Curl => "curl",
            Self::Sh => "sh",
        }
    }

    /// The file name the program has under `regime`: the name, plus `.exe`
    /// under the Windows regime.
    #[must_use]
    pub fn file_name(self, regime: Regime) -> OsString {
        let mut file = OsString::from(self.name());
        if regime.is_windows() {
            file.push(".exe");
        }
        file
    }
}

/// The resolved location of a [`HostTool`]: an absolute directory and the
/// tool's file name, admitted by [`resolve_in`] alone.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ToolPath {
    dir: PathBuf,
    file: OsString,
}

impl ToolPath {
    /// The tool in `dir`, when `dir` is absolute and holds it as an executable
    /// regular file.
    fn admitted(dir: &Path, file: &OsStr) -> Option<Self> {
        if !dir.is_absolute() || !is_executable_file(&dir.join(file)) {
            return None;
        }
        Some(Self {
            dir: dir.to_path_buf(),
            file: file.to_owned(),
        })
    }

    /// The full path, directory joined with file name.
    #[must_use]
    pub fn as_path(&self) -> PathBuf {
        self.dir.join(&self.file)
    }

    /// The absolute directory the tool was found in.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The tool's file name, as it dispatches on it.
    #[must_use]
    pub fn file_name(&self) -> &OsStr {
        &self.file
    }

    /// The full path as one `OsString`, for an argv.
    #[must_use]
    pub fn into_os_string(self) -> OsString {
        self.as_path().into_os_string()
    }

    /// A command that runs this tool.
    #[must_use]
    pub fn command(&self) -> Command {
        Command::new(self.as_path())
    }

    /// A tool assumed to live in `dir`, with no file check, for tests that
    /// render an argv without spawning.
    ///
    /// # Errors
    ///
    /// [`ToolRefusal::NotFound`] when `dir` is not absolute: a relative
    /// location has no representation even here.
    #[cfg(any(test, feature = "assumed-tool-path"))]
    pub fn assumed(dir: &Path, tool: HostTool) -> Result<Self, ToolRefusal> {
        if !dir.is_absolute() {
            return Err(ToolRefusal::NotFound {
                tool,
                relative_entries_skipped: 1,
            });
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            file: tool.file_name(ipe_path_core::HOST),
        })
    }
}

impl From<ToolPath> for OsString {
    fn from(tool: ToolPath) -> Self {
        tool.into_os_string()
    }
}

impl From<ToolPath> for PathBuf {
    fn from(tool: ToolPath) -> Self {
        tool.as_path()
    }
}

/// Why a [`HostTool`] did not resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolRefusal {
    /// The `PATH` variable is not set.
    NoPath {
        /// The tool looked for.
        tool: HostTool,
    },
    /// No absolute `PATH` entry holds the tool as an executable regular file.
    NotFound {
        /// The tool looked for.
        tool: HostTool,
        /// How many entries were not absolute and so were never joined; an
        /// empty entry counts, since a shell reads it as the working directory.
        relative_entries_skipped: usize,
    },
}

impl ToolRefusal {
    /// The tool that did not resolve.
    #[must_use]
    pub const fn tool(&self) -> HostTool {
        match self {
            Self::NoPath { tool } | Self::NotFound { tool, .. } => *tool,
        }
    }
}

impl fmt::Display for ToolRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPath { tool } => {
                write!(f, "`{}` cannot be found: PATH is not set", tool.name())
            }
            Self::NotFound {
                tool,
                relative_entries_skipped: 0,
            } => write!(
                f,
                "`{}` is not an executable file in any PATH directory",
                tool.name()
            ),
            Self::NotFound {
                tool,
                relative_entries_skipped,
            } => write!(
                f,
                "`{}` is not an executable file in any absolute PATH directory ({} relative \
                 PATH entries were skipped: a program is never taken from the working directory)",
                tool.name(),
                relative_entries_skipped
            ),
        }
    }
}

impl std::error::Error for ToolRefusal {}

/// Whether `candidate` is a regular file the current user may execute.
///
/// A symlink is followed, so a `bin/cargo -> ../toolchains/.../cargo` link
/// admits; a directory or a non-executable file does not.
fn is_executable_file(candidate: &Path) -> bool {
    std::fs::metadata(candidate).is_ok_and(|meta| meta.is_file() && is_executable(&meta))
}

#[cfg(unix)]
fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    meta.permissions().mode() & 0o111 != 0
}

/// Off Unix the mode carries no execute bit; being a regular file is the whole
/// admission.
#[cfg(not(unix))]
const fn is_executable(_meta: &std::fs::Metadata) -> bool {
    true
}

/// Resolve `tool` through the `PATH` value `path_var`, admitting only
/// absolute entries whose candidate is an executable regular file.
///
/// Entries are tried in order; the first admitted one wins. Every entry that
/// is not absolute is skipped and counted, never joined.
///
/// # Errors
///
/// [`ToolRefusal::NotFound`] when no absolute entry holds the tool, carrying
/// the number of relative entries skipped.
pub fn resolve_in(
    path_var: &OsStr,
    tool: HostTool,
    regime: Regime,
) -> Result<ToolPath, ToolRefusal> {
    let file = tool.file_name(regime);
    let mut relative_entries_skipped = 0usize;
    for dir in std::env::split_paths(path_var) {
        if !dir.is_absolute() {
            relative_entries_skipped = relative_entries_skipped.saturating_add(1);
            continue;
        }
        if let Some(found) = ToolPath::admitted(&dir, &file) {
            return Ok(found);
        }
    }
    Err(ToolRefusal::NotFound {
        tool,
        relative_entries_skipped,
    })
}

/// Resolve `tool` through a `PATH` value that may be unset.
///
/// # Errors
///
/// [`ToolRefusal::NoPath`] when `path_var` is `None`; otherwise as
/// [`resolve_in`].
pub fn resolve_from(
    path_var: Option<&OsStr>,
    tool: HostTool,
    regime: Regime,
) -> Result<ToolPath, ToolRefusal> {
    path_var.map_or(Err(ToolRefusal::NoPath { tool }), |path_var| {
        resolve_in(path_var, tool, regime)
    })
}

/// Resolve `tool` through the process's `PATH` under the host regime.
///
/// # Errors
///
/// As [`resolve_from`].
pub fn resolve(tool: HostTool) -> Result<ToolPath, ToolRefusal> {
    resolve_from(
        ipe_env::var_os("PATH").as_deref(),
        tool,
        ipe_path_core::HOST,
    )
}

/// Resolve `tool` through the given directories, under the same admission as
/// [`resolve_in`]: a relative directory is skipped and counted, never joined.
///
/// # Errors
///
/// [`ToolRefusal::NotFound`] when no absolute directory holds the tool.
pub fn resolve_in_dirs(
    dirs: &[PathBuf],
    tool: HostTool,
    regime: Regime,
) -> Result<ToolPath, ToolRefusal> {
    let file = tool.file_name(regime);
    let mut relative_entries_skipped = 0usize;
    for dir in dirs {
        if !dir.is_absolute() {
            relative_entries_skipped = relative_entries_skipped.saturating_add(1);
            continue;
        }
        if let Some(found) = ToolPath::admitted(dir, &file) {
            return Ok(found);
        }
    }
    Err(ToolRefusal::NotFound {
        tool,
        relative_entries_skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_dir::TestDir;

    /// A fresh directory holding `tools`, each an executable regular file.
    fn dir_with(label: &str, tools: &[HostTool]) -> TestDir {
        let dir = TestDir::new(label).expect("test dir");
        for tool in tools {
            plant(dir.path(), tool.file_name(Regime::Unix).as_os_str(), 0o755);
        }
        dir
    }

    /// Write `file` under `dir` with `mode` (the mode applies on Unix only).
    fn plant(dir: &Path, file: &OsStr, mode: u32) {
        let path = dir.join(file);
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("plant");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("mode");
        }
        #[cfg(not(unix))]
        let _ = mode;
    }

    /// A `PATH` value joining `entries` with the host separator; a relative
    /// spelling is kept as given.
    fn path_var(entries: &[&OsStr]) -> OsString {
        std::env::join_paths(entries).expect("no separator inside an entry")
    }

    fn skipped(refusal: &ToolRefusal) -> Option<usize> {
        match refusal {
            ToolRefusal::NotFound {
                relative_entries_skipped,
                ..
            } => Some(*relative_entries_skipped),
            ToolRefusal::NoPath { .. } => None,
        }
    }

    #[test]
    fn a_relative_first_entry_is_skipped() {
        let t = dir_with("host-tool-relative-first", &[HostTool::Bwrap]);
        let path = path_var(&[OsStr::new("."), t.path().as_os_str()]);
        let found = resolve_in(&path, HostTool::Bwrap, Regime::Unix).expect("bwrap in t");
        assert_eq!(found.dir(), t.path());
        assert_eq!(found.file_name(), OsStr::new("bwrap"));
        assert_eq!(found.as_path(), t.path().join("bwrap"));
    }

    #[test]
    fn only_relative_entries_refuse() {
        let path = path_var(&[OsStr::new("."), OsStr::new("bin"), OsStr::new("")]);
        let refusal = resolve_in(&path, HostTool::Bwrap, Regime::Unix).expect_err("no absolute");
        assert_eq!(
            refusal,
            ToolRefusal::NotFound {
                tool: HostTool::Bwrap,
                relative_entries_skipped: 3,
            }
        );
        assert_eq!(refusal.tool(), HostTool::Bwrap);
        assert!(refusal.to_string().contains("3 relative"), "{refusal}");
    }

    #[test]
    fn an_empty_entry_is_relative() {
        let path = path_var(&[OsStr::new(""), OsStr::new("/nonexistent")]);
        let refusal = resolve_in(&path, HostTool::Prlimit, Regime::Unix).expect_err("absent");
        assert_eq!(skipped(&refusal), Some(1));
        // An empty variable is one empty entry: the working directory, skipped.
        let refusal =
            resolve_in(OsStr::new(""), HostTool::Prlimit, Regime::Unix).expect_err("empty");
        assert_eq!(skipped(&refusal), Some(1));
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_tool_in_the_cwd_never_wins() {
        let r = TestDir::new("host-tool-planted").expect("test dir");
        let planted = r.path().join("planted");
        let real = r.path().join("real");
        std::fs::create_dir_all(&planted).expect("planted dir");
        std::fs::create_dir_all(&real).expect("real dir");
        plant(&planted, OsStr::new("timeout"), 0o755);
        plant(&real, OsStr::new("timeout"), 0o755);
        let path = path_var(&[OsStr::new("planted"), real.as_os_str()]);
        let found = resolve_in(&path, HostTool::Timeout, Regime::Unix).expect("real timeout");
        assert_eq!(found.dir(), real.as_path());
        let refusal = resolve_in(OsStr::new("planted"), HostTool::Timeout, Regime::Unix)
            .expect_err("relative");
        assert_eq!(skipped(&refusal), Some(1));
    }

    #[cfg(unix)]
    #[test]
    fn a_non_executable_file_is_refused() {
        let t = TestDir::new("host-tool-mode").expect("test dir");
        plant(t.path(), OsStr::new("rustc"), 0o644);
        let refusal = resolve_in(t.path().as_os_str(), HostTool::Rustc, Regime::Unix)
            .expect_err("mode 644 is not executable");
        assert_eq!(skipped(&refusal), Some(0));
        assert!(!refusal.to_string().contains("relative"), "{refusal}");
    }

    #[test]
    fn a_directory_named_like_the_tool_is_refused() {
        let t = TestDir::new("host-tool-dir").expect("test dir");
        std::fs::create_dir_all(t.path().join("cargo")).expect("dir named cargo");
        let refusal = resolve_in(t.path().as_os_str(), HostTool::Cargo, Regime::Unix)
            .expect_err("a directory is not a program");
        assert_eq!(skipped(&refusal), Some(0));
    }

    #[test]
    fn windows_regime_appends_exe() {
        assert_eq!(
            HostTool::Bwrap.file_name(Regime::Windows),
            OsString::from("bwrap.exe")
        );
        assert_eq!(
            HostTool::Bwrap.file_name(Regime::Unix),
            OsString::from("bwrap")
        );
        assert_eq!(
            HostTool::PowerShell.file_name(Regime::Windows),
            OsString::from("powershell.exe")
        );
        let t = dir_with("host-tool-exe", &[HostTool::Cargo]);
        assert!(resolve_in(t.path().as_os_str(), HostTool::Cargo, Regime::Unix).is_ok());
        let refusal = resolve_in(t.path().as_os_str(), HostTool::Cargo, Regime::Windows)
            .expect_err("`cargo` is not `cargo.exe`");
        assert_eq!(skipped(&refusal), Some(0));
    }

    /// A rooted entry without a drive (`\tools`) is relative to the current
    /// drive, so it is skipped like `.`; compiled by the Windows check job.
    #[cfg(windows)]
    #[test]
    fn a_rooted_windows_entry_without_drive_is_relative() {
        let refusal = resolve_in(OsStr::new(r"\tools"), HostTool::Cargo, Regime::Windows)
            .expect_err("drive-relative");
        assert_eq!(skipped(&refusal), Some(1));
    }

    #[test]
    fn tool_path_has_no_relative_constructor() {
        let refusal = ToolPath::assumed(Path::new("rel"), HostTool::Bwrap).expect_err("relative");
        assert_eq!(skipped(&refusal), Some(1));
        let t = TestDir::new("host-tool-assumed").expect("test dir");
        let assumed = ToolPath::assumed(t.path(), HostTool::Bwrap).expect("absolute");
        assert_eq!(assumed.dir(), t.path());
        assert_eq!(
            assumed.file_name(),
            HostTool::Bwrap.file_name(ipe_path_core::HOST).as_os_str()
        );
        let as_os: OsString = assumed.clone().into();
        assert_eq!(as_os, assumed.as_path().into_os_string());
        let as_path: PathBuf = assumed.clone().into();
        assert_eq!(as_path, assumed.as_path());
        assert_eq!(
            assumed.command().get_program(),
            assumed.as_path().as_os_str()
        );
    }

    #[test]
    fn no_path_variable_is_a_typed_refusal() {
        assert_eq!(
            resolve_from(None, HostTool::Git, Regime::Unix),
            Err(ToolRefusal::NoPath {
                tool: HostTool::Git
            })
        );
        let refusal = ToolRefusal::NoPath {
            tool: HostTool::Git,
        };
        assert_eq!(refusal.tool(), HostTool::Git);
        assert!(refusal.to_string().contains("PATH is not set"), "{refusal}");
        let t = dir_with("host-tool-from", &[HostTool::Git]);
        let found = resolve_from(Some(t.path().as_os_str()), HostTool::Git, Regime::Unix)
            .expect("git in t");
        assert_eq!(found.dir(), t.path());
    }

    #[test]
    fn the_first_absolute_entry_holding_the_tool_wins() {
        let first = dir_with("host-tool-first", &[HostTool::Rustup]);
        let second = dir_with("host-tool-second", &[HostTool::Rustup]);
        let empty = TestDir::new("host-tool-empty").expect("test dir");
        let path = path_var(&[
            empty.path().as_os_str(),
            first.path().as_os_str(),
            second.path().as_os_str(),
        ]);
        let found = resolve_in(&path, HostTool::Rustup, Regime::Unix).expect("rustup");
        assert_eq!(found.dir(), first.path());
    }

    #[test]
    fn explicit_dirs_follow_the_same_admission() {
        let t = dir_with("host-tool-dirs", &[HostTool::Cargo]);
        let dirs = vec![
            PathBuf::from("rel/bin"),
            PathBuf::from(""),
            t.path().to_path_buf(),
        ];
        let found = resolve_in_dirs(&dirs, HostTool::Cargo, Regime::Unix).expect("cargo in t");
        assert_eq!(found.dir(), t.path());
        let refusal = resolve_in_dirs(&dirs[..2], HostTool::Cargo, Regime::Unix)
            .expect_err("only relative dirs");
        assert_eq!(skipped(&refusal), Some(2));
        let refusal = resolve_in_dirs(&[], HostTool::Cargo, Regime::Unix).expect_err("no dirs");
        assert_eq!(skipped(&refusal), Some(0));
    }

    #[test]
    fn every_tool_has_a_bare_name() {
        const TOOLS: [HostTool; 23] = [
            HostTool::Bwrap,
            HostTool::Prlimit,
            HostTool::Timeout,
            HostTool::SandboxExec,
            HostTool::Jail,
            HostTool::Rctl,
            HostTool::Chown,
            HostTool::MountNullfs,
            HostTool::Mount,
            HostTool::Umount,
            HostTool::PowerShell,
            HostTool::Cargo,
            HostTool::Rustc,
            HostTool::Rustup,
            HostTool::Rustfmt,
            HostTool::CargoDeny,
            HostTool::Sccache,
            HostTool::FfiInspector,
            HostTool::WasmBindgen,
            HostTool::WasmOpt,
            HostTool::Git,
            HostTool::Curl,
            HostTool::Sh,
        ];
        for tool in TOOLS {
            let name = tool.name();
            assert!(!name.is_empty());
            assert!(
                !name.contains(['/', '\\', '.']),
                "{name}: a name is a file name, never a path or a suffixed file"
            );
        }
    }
}

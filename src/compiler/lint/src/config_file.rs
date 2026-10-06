//! The one bounded reader for an untrusted workspace file, and the `lint.ipe`
//! loader built on it.
//!
//! A workspace file is found by convention, not named by the user, and a
//! cloned repository is attacker-shaped: the name may be a symlink to a
//! device or to a file outside the workspace, a FIFO, a directory, or a
//! multi-GiB blob, swapped between any two path lookups. So
//! [`read_workspace_file`] opens it through `ipe_fs_open`: once, relative to
//! the held directory, never following a link at its name and never
//! blocking; the opened handle is proven a regular file and read under a
//! [`ByteCap`].

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use ipe_fs_open::{ByteCap, EntryName, HeldDir, OpenRefusal};

use crate::config::{ConfigError, LINT_CONFIG_FILE, LINT_CONFIG_MAX_BYTES, LintConfig};

/// The read ceiling for `lint.ipe`.
const LINT_CONFIG_CAP: ByteCap =
    ByteCap::from_nonzero(NonZeroU64::MIN.saturating_add(LINT_CONFIG_MAX_BYTES - 1));

/// Why [`read_workspace_file`] yielded no text.
#[derive(Debug)]
pub enum WorkspaceReadError {
    /// The entry is a link, or the opened handle is not a regular file (a
    /// directory, FIFO, socket, or device).
    NotAFile,
    /// The file could not be opened, inspected, or read.
    Unreadable(std::io::Error),
    /// The file holds more than the caller's cap, in bytes.
    TooLarge {
        /// The cap the file exceeded.
        max: u64,
    },
    /// The file is not valid UTF-8.
    NotUtf8,
}

impl std::fmt::Display for WorkspaceReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAFile => f.write_str("not a regular file"),
            Self::Unreadable(e) => write!(f, "unreadable: {e}"),
            Self::TooLarge { max } => write!(f, "exceeds {max} bytes"),
            Self::NotUtf8 => f.write_str("not valid UTF-8"),
        }
    }
}

impl std::error::Error for WorkspaceReadError {}

/// Read the entry `name` of `dir` as text, bounded by `max` bytes.
///
/// `Ok(None)` when `dir` or its entry `name` does not exist. A link at
/// `name` is refused, never followed. The regular-file proof is taken on the
/// opened handle, so no swap between check and read is possible; at most one
/// byte past `max` is read. A file exactly at the cap is accepted; one byte
/// over is refused.
///
/// # Errors
/// [`WorkspaceReadError`] when the entry is a link or not a regular file,
/// the open or read fails, the content is over `max`, or it is not UTF-8.
pub fn read_workspace_file(
    dir: &Path,
    name: &EntryName,
    max: ByteCap,
) -> Result<Option<String>, WorkspaceReadError> {
    let held = match HeldDir::open_root(dir) {
        Ok(held) => held,
        Err(OpenRefusal::Absent) => return Ok(None),
        Err(refusal) => return Err(WorkspaceReadError::Unreadable(refusal.into_io())),
    };
    held.open_regular(name)
        .and_then(|file| file.read_utf8(max))
        .map_or_else(refused_read, |text| Ok(Some(text)))
}

/// The answer [`read_workspace_file`] gives for a refused open or read of the entry.
fn refused_read(refusal: OpenRefusal) -> Result<Option<String>, WorkspaceReadError> {
    match refusal {
        OpenRefusal::Absent => Ok(None),
        OpenRefusal::Link | OpenRefusal::NotRegular(_) | OpenRefusal::BadName => {
            Err(WorkspaceReadError::NotAFile)
        }
        OpenRefusal::TooLarge(cap) => Err(WorkspaceReadError::TooLarge { max: cap.get() }),
        OpenRefusal::NotUtf8 => Err(WorkspaceReadError::NotUtf8),
        OpenRefusal::Denied
        | OpenRefusal::InUse
        | OpenRefusal::TooManyEntries(_)
        | OpenRefusal::Io(_) => Err(WorkspaceReadError::Unreadable(refusal.into_io())),
    }
}

/// Why [`load_lint_config`] yielded no configuration.
#[derive(Debug)]
pub enum LintConfigLoadError {
    /// `lint.ipe` exists but could not be read within bounds.
    Read(WorkspaceReadError),
    /// `lint.ipe` was read but is not a valid configuration.
    Invalid(ConfigError),
}

impl std::fmt::Display for LintConfigLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(e) => write!(f, "{LINT_CONFIG_FILE}: {e}"),
            Self::Invalid(e) => std::fmt::Display::fmt(e, f),
        }
    }
}

impl std::error::Error for LintConfigLoadError {}

/// The directory holding the `lint.ipe` of the project anchored at `anchor`.
///
/// `anchor` is the project's resolved manifest or loose entry file. `ipe lint`
/// and the language server both name the directory through this function, so
/// the editor and the batch linter read one `lint.ipe`.
#[must_use]
pub fn lint_config_dir(anchor: &Path) -> PathBuf {
    anchor
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Load the [`LintConfig`] from the `lint.ipe` in `dir`.
///
/// An absent file is the default configuration. Every other outcome goes
/// through [`read_workspace_file`] with [`LINT_CONFIG_MAX_BYTES`], so a
/// symlink, FIFO, device, directory, or oversized file is refused, never
/// followed, waited on, or buffered.
///
/// # Errors
/// [`LintConfigLoadError`] when the file cannot be read within bounds or does
/// not parse as a configuration.
pub fn load_lint_config(dir: &Path) -> Result<LintConfig, LintConfigLoadError> {
    let path = dir.join(LINT_CONFIG_FILE);
    EntryName::parse(std::ffi::OsStr::new(LINT_CONFIG_FILE))
        .map_or_else(refused_read, |name| {
            read_workspace_file(dir, &name, LINT_CONFIG_CAP)
        })
        .map_err(LintConfigLoadError::Read)?
        .map_or_else(
            || Ok(LintConfig::default()),
            |text| {
                crate::config::read_lint_config(&text, &path.display().to_string())
                    .map_err(LintConfigLoadError::Invalid)
            },
        )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use ipe_fs_open::{ByteCap, EntryName};

    use super::{LintConfigLoadError, WorkspaceReadError, load_lint_config, read_workspace_file};
    use crate::config::{LINT_CONFIG_FILE, LINT_CONFIG_MAX_BYTES};

    /// The entry name `name`.
    fn entry(name: &str) -> EntryName {
        EntryName::new(std::ffi::OsStr::new(name)).expect("a plain entry name")
    }

    /// A cap of `bytes`.
    fn cap(bytes: u64) -> ByteCap {
        ByteCap::new(bytes).expect("a nonzero cap")
    }

    /// A fresh, empty scratch directory for one test.
    fn scratch(name: &str) -> PathBuf {
        let dir = ipe_test_temp::temp_root()
            .join(format!("ipe-lint-wsread-{}-{name}", std::process::id()));
        if dir.exists() {
            assert!(std::fs::remove_dir_all(&dir).is_ok(), "clear {dir:?}");
        }
        assert!(std::fs::create_dir_all(&dir).is_ok(), "create {dir:?}");
        dir
    }

    #[test]
    fn an_absent_file_is_none_and_the_default_config() {
        let dir = scratch("absent");
        assert!(matches!(
            read_workspace_file(&dir, &entry("nope"), cap(16)),
            Ok(None)
        ));
        assert!(load_lint_config(&dir).is_ok());
        assert!(matches!(
            read_workspace_file(&dir.join("no-dir"), &entry("f"), cap(16)),
            Ok(None)
        ));
    }

    #[test]
    fn a_file_exactly_at_the_cap_is_read() {
        let dir = scratch("at-cap");
        assert!(std::fs::write(dir.join("f"), [b'a'; 16]).is_ok());
        assert!(
            matches!(read_workspace_file(&dir, &entry("f"), cap(16)), Ok(Some(t)) if t.len() == 16)
        );
    }

    #[test]
    fn a_file_one_byte_over_the_cap_is_refused() {
        let dir = scratch("over-cap");
        assert!(std::fs::write(dir.join("f"), [b'a'; 17]).is_ok());
        assert!(matches!(
            read_workspace_file(&dir, &entry("f"), cap(16)),
            Err(WorkspaceReadError::TooLarge { max: 16 })
        ));
    }

    #[test]
    fn an_oversized_lint_config_is_refused() {
        let dir = scratch("lint-over-cap");
        let over = usize::try_from(LINT_CONFIG_MAX_BYTES.saturating_add(1));
        assert!(
            matches!(over, Ok(n) if std::fs::write(dir.join(LINT_CONFIG_FILE), vec![b' '; n]).is_ok())
        );
        assert!(matches!(
            load_lint_config(&dir),
            Err(LintConfigLoadError::Read(
                WorkspaceReadError::TooLarge { .. }
            ))
        ));
    }

    #[test]
    fn a_directory_is_refused() {
        let dir = scratch("dir");
        assert!(std::fs::create_dir_all(dir.join(LINT_CONFIG_FILE)).is_ok());
        let refused = load_lint_config(&dir);
        #[cfg(unix)]
        assert!(matches!(
            refused,
            Err(LintConfigLoadError::Read(WorkspaceReadError::NotAFile))
        ));
        #[cfg(not(unix))]
        assert!(matches!(refused, Err(LintConfigLoadError::Read(_))));
    }

    #[test]
    fn non_utf8_is_refused() {
        let dir = scratch("non-utf8");
        assert!(std::fs::write(dir.join("f"), [0xff, 0xfe]).is_ok());
        assert!(matches!(
            read_workspace_file(&dir, &entry("f"), cap(16)),
            Err(WorkspaceReadError::NotUtf8)
        ));
    }

    /// Run `load_lint_config(dir)` on a helper thread and require an answer
    /// within a deadline, so a regression that blocks fails instead of hanging.
    #[cfg(unix)]
    fn load_promptly(dir: PathBuf) -> Option<Result<crate::LintConfig, LintConfigLoadError>> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .spawn(move || {
                let _ = tx.send(load_lint_config(&dir));
            })
            .expect("spawn test thread");
        rx.recv_timeout(Duration::from_secs(10)).ok()
    }

    /// Create a FIFO at `path` with the system `mkfifo`.
    #[cfg(unix)]
    fn mkfifo(path: &std::path::Path) {
        let made = std::process::Command::new("mkfifo").arg(path).status();
        assert!(
            matches!(made, Ok(s) if s.success()),
            "mkfifo {path:?}: {made:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_lint_ipe_is_refused_not_hung() {
        let dir = scratch("fifo");
        mkfifo(&dir.join(LINT_CONFIG_FILE));
        assert!(matches!(
            load_promptly(dir),
            Some(Err(LintConfigLoadError::Read(WorkspaceReadError::NotAFile)))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_regular_file_is_refused_not_followed() {
        let dir = scratch("regular-link");
        let target = dir.join("elsewhere.ipe");
        assert!(std::fs::write(&target, "").is_ok());
        assert!(std::os::unix::fs::symlink(&target, dir.join(LINT_CONFIG_FILE)).is_ok());
        assert!(matches!(
            load_lint_config(&dir),
            Err(LintConfigLoadError::Read(WorkspaceReadError::NotAFile))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_is_refused_not_absent() {
        let dir = scratch("dangling-link");
        assert!(
            std::os::unix::fs::symlink(dir.join("missing"), dir.join(LINT_CONFIG_FILE)).is_ok()
        );
        assert!(matches!(
            load_lint_config(&dir),
            Err(LintConfigLoadError::Read(WorkspaceReadError::NotAFile))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_device_is_refused() {
        let dir = scratch("device-link");
        assert!(std::os::unix::fs::symlink("/dev/null", dir.join(LINT_CONFIG_FILE)).is_ok());
        assert!(matches!(
            load_lint_config(&dir),
            Err(LintConfigLoadError::Read(WorkspaceReadError::NotAFile))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_device_named_directly_is_refused() {
        assert!(matches!(
            read_workspace_file(std::path::Path::new("/dev"), &entry("null"), cap(16)),
            Err(WorkspaceReadError::NotAFile)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_fifo_is_refused_without_blocking() {
        let dir = scratch("fifo-link");
        let fifo = dir.join("pipe");
        mkfifo(&fifo);
        assert!(std::os::unix::fs::symlink(&fifo, dir.join(LINT_CONFIG_FILE)).is_ok());
        assert!(matches!(
            load_promptly(dir),
            Some(Err(LintConfigLoadError::Read(WorkspaceReadError::NotAFile)))
        ));
    }
}

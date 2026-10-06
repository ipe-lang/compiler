//! Bounded file-I/O utilities for the CLI/FFI layer.
//!
//! Every CLI or FFI-cache file turned into a `String` is opened on a held
//! handle from [`ipe_fs_open`] and read under a ceiling: never blocking on a
//! FIFO, never taking a terminal as the controlling one, refusing anything but
//! a regular file by the type of the handle it opened, and never following a
//! symlink in the final component. A file found by convention (`ipe.lock`, an
//! index entry, a trust policy, `src/Main.ipe`) is read by [`read_in`],
//! [`read_named_in`], [`read_beneath`] or [`read_leaf_capped`], all no-follow;
//! a path the invoking user named is read by [`read_user_named`], the one open
//! that follows a final symlink. Every caller picks one of them by who named
//! the path; none inherits a policy from a shared default.
//!
//! Cap constants are declared here as the single source of truth so a new call
//! site cannot silently introduce a different ceiling.

use std::fs::File;
use std::num::NonZeroU64;
use std::path::{Component, Path};

use ipe_fs_open::{ByteCap, EntryName, HeldDir, OpenRefusal, RegularFile};

use crate::CliError;

// ── Per-surface read caps ─────────────────────────────────────────────────────

/// Maximum bytes for a `package.ipe` or legacy `ipe.toml` manifest file.
///
/// 512 KiB is generous for any real manifest while refusing a device node or a
/// multi-GiB file that would exhaust memory.
pub const MANIFEST_READ_CAP: u64 = 512 * 1024;

/// Maximum bytes for a single Ipê source file (`*.ipe`).
///
/// 8 MiB matches the runtime's file-read ceiling and is well above any
/// realistic source file.
pub const SOURCE_READ_CAP: u64 = 8 * 1024 * 1024;

/// Maximum bytes for an FFI cache artifact (JSON / Rust source fragments
/// stored under `.ipe/cache/ffi/rust/`).
///
/// 4 MiB is sufficient for any generated bindings file while refusing a
/// device node or accidentally-swapped large binary.
pub const FFI_CACHE_READ_CAP: u64 = 4 * 1024 * 1024;

/// Maximum bytes for one build-cache entry (an emitted project or lowered IR, as JSON).
///
/// 64 MiB holds the emitted Rust of a large program; an entry past it is never
/// stored, and a planted one past it is a cache miss, never buffered whole.
pub const BUILD_CACHE_ENTRY_CAP: u64 = 64 * 1024 * 1024;

/// Maximum bytes for a recorded session trace (`session.ipelog`) shown by
/// `ipe dev run --replay`.
///
/// 16 MiB holds a full recorder ring of large-model steps while refusing a
/// planted multi-GiB file before it is buffered.
pub const SESSION_TRACE_READ_CAP: u64 = 16 * 1024 * 1024;

/// Maximum bytes for miscellaneous small CLI-internal files (lock files,
/// index entries, OAuth tokens, Cargo profile fragments, etc.).
pub const SMALL_FILE_READ_CAP: u64 = 1024 * 1024;

/// Maximum bytes for a deployed release app binary (`ipe-app`, or a prebuilt
/// `ipe-wrapper` carrying an embedded app) scanned for its capability floor.
///
/// 512 MiB is far above any statically-linked app while refusing a planted
/// device node or multi-GiB file before it is buffered whole.
pub const RELEASE_APP_READ_CAP: u64 = ipe_sandbox::run_jail::APP_READ_CAP;

/// The [`ByteCap`] of `BYTES`; a `BYTES` of zero underflows and fails the build.
const fn held_cap<const BYTES: u64>() -> ByteCap {
    ByteCap::from_nonzero(const { NonZeroU64::MIN.saturating_add(BYTES - 1) })
}

/// [`SOURCE_READ_CAP`] as a [`ByteCap`].
pub const SOURCE_CAP: ByteCap = held_cap::<SOURCE_READ_CAP>();

/// [`FFI_CACHE_READ_CAP`] as a [`ByteCap`].
pub const FFI_CACHE_CAP: ByteCap = held_cap::<FFI_CACHE_READ_CAP>();

/// [`SMALL_FILE_READ_CAP`] as a [`ByteCap`].
pub const SMALL_FILE_CAP: ByteCap = held_cap::<SMALL_FILE_READ_CAP>();

/// [`MANIFEST_READ_CAP`] as a [`ByteCap`].
pub const MANIFEST_CAP: ByteCap = held_cap::<MANIFEST_READ_CAP>();

/// [`SESSION_TRACE_READ_CAP`] as a [`ByteCap`].
pub const SESSION_TRACE_CAP: ByteCap = held_cap::<SESSION_TRACE_READ_CAP>();

// ── Regular-file open ─────────────────────────────────────────────────────────

/// Why a path was refused before any of it was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceRefusal {
    /// The path names a FIFO, device, socket or directory, not a regular file.
    NotRegularFile,
    /// The process may not open the path, or search a directory leading to it.
    AccessDenied,
    /// The path, or a directory a no-follow walk met on the way to it, is a symlink.
    Symlink,
}

/// How [`open_regular`] treats a symlink in the path's final component.
///
/// Refusal is the only mode: the one open that follows a final symlink is
/// [`read_user_named`], so no path-based open can follow one by a flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalLink {
    /// Refuse it as [`SourceRefusal::NotRegularFile`]: the path came from a no-follow walk.
    Refuse,
}

/// Open `path` read-only as a regular file, refusing a final symlink, or refuse it with a typed error.
///
/// On unix the open is `O_NONBLOCK | O_NOCTTY | O_NOFOLLOW`, so a FIFO swapped
/// in for a file never blocks it, a terminal never becomes the controlling
/// one, and a final symlink is refused; the file type is then checked on the
/// opened handle (`fstat`), so no swap after a path check can hand the reader
/// a non-regular file. A socket (which `open` refuses with `ENXIO`) is refused
/// the same way. On Windows a final reparse point is refused on the opened
/// handle's attributes, never by a path check made before the open.
///
/// # Errors
///
/// - [`CliError::SourceRefused`] with [`SourceRefusal::NotRegularFile`] when
///   the opened file is not a regular file, or its final component is a
///   symlink (on Windows, any reparse point).
/// - [`CliError::SourceRefused`] with [`SourceRefusal::AccessDenied`] when
///   the open is denied permission.
/// - [`CliError::Io`] for any other open or `fstat` failure.
pub fn open_regular(path: &Path, final_link: FinalLink) -> Result<File, CliError> {
    let FinalLink::Refuse = final_link;
    let file = open_nonblocking(path)?;
    regular_file(file, path)
}

/// Keep `file` only when its handle is a regular file.
///
/// For callers that opened the handle themselves (a no-follow walk beneath
/// a directory handle); `path` only names the file in errors.
///
/// # Errors
///
/// [`CliError::SourceRefused`] with [`SourceRefusal::NotRegularFile`] when it
/// is not; [`CliError::Io`] when the `fstat` fails.
pub fn regular_file(file: File, path: &Path) -> Result<File, CliError> {
    let meta = file.metadata().map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if meta.is_file() {
        Ok(file)
    } else {
        Err(source_refused(path, SourceRefusal::NotRegularFile))
    }
}

/// The typed error for an open of `path` that failed with `source`.
///
/// A permission failure is [`SourceRefusal::AccessDenied`]; on unix an
/// `ELOOP` (a final symlink under `O_NOFOLLOW`) or `ENXIO` (a socket) is
/// [`SourceRefusal::NotRegularFile`]; anything else stays [`CliError::Io`].
#[must_use]
pub fn open_error(path: &Path, source: std::io::Error) -> CliError {
    #[cfg(unix)]
    let names_non_regular = matches!(
        source
            .raw_os_error()
            .map(rustix::io::Errno::from_raw_os_error),
        Some(rustix::io::Errno::LOOP | rustix::io::Errno::NXIO)
    );
    #[cfg(not(unix))]
    let names_non_regular = false;
    if names_non_regular {
        source_refused(path, SourceRefusal::NotRegularFile)
    } else {
        access_error(path, source)
    }
}

/// The typed error for a read or listing of `path` that failed with `source`.
///
/// A permission failure is [`SourceRefusal::AccessDenied`]; anything else
/// stays [`CliError::Io`].
#[must_use]
pub fn access_error(path: &Path, source: std::io::Error) -> CliError {
    if source.kind() == std::io::ErrorKind::PermissionDenied {
        source_refused(path, SourceRefusal::AccessDenied)
    } else {
        CliError::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

/// The [`CliError::SourceRefused`] for `path`.
#[must_use]
pub fn source_refused(path: &Path, reason: SourceRefusal) -> CliError {
    CliError::SourceRefused {
        path: path.to_path_buf(),
        reason,
    }
}

/// The typed error for a held-handle open or read of `path` refused with `refusal`.
///
/// An [`OpenRefusal::Absent`] keeps the [`CliError::Io`] of kind `NotFound`
/// that callers treat as "no such file".
#[must_use]
pub fn refusal_error(path: &Path, refusal: OpenRefusal) -> CliError {
    match refusal {
        OpenRefusal::Link => source_refused(path, SourceRefusal::Symlink),
        OpenRefusal::NotRegular(_) | OpenRefusal::BadName => {
            source_refused(path, SourceRefusal::NotRegularFile)
        }
        OpenRefusal::Denied => source_refused(path, SourceRefusal::AccessDenied),
        OpenRefusal::TooLarge(cap) => CliError::FileTooLarge {
            path: path.to_path_buf(),
            max: cap.get(),
        },
        OpenRefusal::Absent
        | OpenRefusal::InUse
        | OpenRefusal::TooManyEntries(_)
        | OpenRefusal::NotUtf8
        | OpenRefusal::Io(_) => CliError::Io {
            path: path.to_path_buf(),
            source: refusal.into_io(),
        },
    }
}

/// Open `path` read-only without blocking, without taking a controlling terminal, refusing a final symlink.
#[cfg(unix)]
fn open_nonblocking(path: &Path) -> Result<File, CliError> {
    use rustix::fs::{Mode, OFlags};
    let flags =
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    rustix::fs::open(path, flags, Mode::empty())
        .map(File::from)
        .map_err(|errno| open_error(path, errno.into()))
}

/// Open `path` read-only, refusing a final reparse point on the opened handle.
///
/// The open carries `FILE_FLAG_OPEN_REPARSE_POINT`, so a final reparse point
/// of any tag (symlink, junction, or other) is opened itself rather than its
/// target, and the handle's attributes then refuse it: no swap between a path
/// check and the open can slip one past.
#[cfg(windows)]
fn open_nonblocking(path: &Path) -> Result<File, CliError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    /// `FILE_FLAG_OPEN_REPARSE_POINT`: opens a reparse point itself, never its target.
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    /// `FILE_ATTRIBUTE_REPARSE_POINT`.
    const ATTR_REPARSE_POINT: u32 = 0x400;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|source| open_error(path, source))?;
    let attributes = file
        .metadata()
        .map_err(|source| CliError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .file_attributes();
    if attributes & ATTR_REPARSE_POINT != 0 {
        return Err(source_refused(path, SourceRefusal::NotRegularFile));
    }
    Ok(file)
}

// ── Held-handle reads ─────────────────────────────────────────────────────────

/// Read the regular file `rel` spells below `dir` to a `String` under `cap`.
///
/// `dir` itself is opened following links (it is the root the caller already
/// trusts, such as a project root or `$IPE_HOME`); every level of `rel` is
/// opened through the held level above it, refusing a symlink, and the file is
/// opened non-blocking and proven regular on its own handle.
///
/// # Errors
///
/// - [`CliError::Io`] of kind `NotFound` when `dir` or an entry of `rel` is absent.
/// - [`CliError::SourceRefused`] with [`SourceRefusal::Symlink`] for a symlink
///   below `dir`, [`SourceRefusal::NotRegularFile`] for a FIFO, device, socket
///   or directory, [`SourceRefusal::AccessDenied`] when the open is denied.
/// - [`CliError::FileTooLarge`] past `cap`.
/// - [`CliError::Io`] for content that is not UTF-8 or any other failure.
pub fn read_in(dir: &Path, rel: &[EntryName], cap: ByteCap) -> Result<String, CliError> {
    let path = rel
        .iter()
        .fold(dir.to_path_buf(), |path, name| path.join(name.as_os_str()));
    let file = HeldDir::open_root(dir)
        .and_then(|root| root.open_rel(rel))
        .map_err(|refusal| refusal_error(&path, refusal))?;
    read_proven(file, &path, cap)
}

/// [`read_in`] for a relative path spelled as text, one entry name per level.
///
/// # Errors
///
/// [`CliError::SourceRefused`] with [`SourceRefusal::NotRegularFile`] for a
/// level that is not one plain entry name; otherwise as [`read_in`].
pub fn read_named_in(dir: &Path, names: &[&str], cap: ByteCap) -> Result<String, CliError> {
    let rel = names
        .iter()
        .map(|name| EntryName::parse(std::ffi::OsStr::new(name)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|refusal| {
            let path = names
                .iter()
                .fold(dir.to_path_buf(), |path, name| path.join(name));
            refusal_error(&path, refusal)
        })?;
    read_in(dir, &rel, cap)
}

/// [`read_in`] for a `path` below `root`, spelled under `root` as written or as canonicalised.
///
/// For a convention file whose full path was derived from a trusted root (a
/// manifest's source root, a containment-checked project file): every level
/// below `root` is opened through the held level above it and never followed,
/// so a link swapped in after the path was derived is refused.
///
/// # Errors
///
/// [`CliError::SourceRefused`] with [`SourceRefusal::NotRegularFile`] when
/// `path` is not below `root` or a level is not one plain entry name;
/// otherwise as [`read_in`].
pub fn read_beneath(root: &Path, path: &Path, cap: ByteCap) -> Result<String, CliError> {
    let not_below = || refusal_error(path, OpenRefusal::BadName);
    let (base, rel) = match path.strip_prefix(root) {
        Ok(rel) => (root.to_path_buf(), rel),
        Err(_) => {
            let canonical = std::fs::canonicalize(root).map_err(|_| not_below())?;
            let rel = path.strip_prefix(&canonical).map_err(|_| not_below())?;
            (canonical, rel)
        }
    };
    let names = rel
        .components()
        .filter(|component| !matches!(component, Component::CurDir))
        .map(|component| match component {
            Component::Normal(name) => EntryName::parse(name),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => Err(OpenRefusal::BadName),
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|refusal| refusal_error(path, refusal))?;
    if names.is_empty() {
        return Err(not_below());
    }
    read_in(&base, &names, cap)
}

/// Read the file the invoking user named at `path` to a `String` under `cap`.
///
/// The one open that follows a final symlink: the user named that exact path
/// and may link a file on purpose. It is still opened non-blocking and proven
/// regular, so a FIFO or device named there is refused, never waited on.
///
/// # Errors
///
/// As [`read_in`], except that a final symlink is followed rather than refused.
pub fn read_user_named(path: &Path, cap: ByteCap) -> Result<String, CliError> {
    let file =
        RegularFile::open_user_named(path).map_err(|refusal| refusal_error(path, refusal))?;
    read_proven(file, path, cap)
}

/// Prove a handle the caller opened itself a regular file, for [`read_proven`].
///
/// `path` only names the file in errors.
///
/// # Errors
///
/// [`CliError::SourceRefused`] when the handle is not a regular file;
/// [`CliError::Io`] when it cannot be stat'd.
pub fn prove_regular(file: File, path: &Path) -> Result<RegularFile, CliError> {
    RegularFile::prove(file).map_err(|refusal| refusal_error(path, refusal))
}

/// Read a file already proven regular on its own handle to a `String` under a `max`-byte budget.
///
/// The budget twin of [`read_proven`] for a running byte budget: a `max` of
/// zero admits only an empty file.
///
/// # Errors
///
/// [`CliError::FileTooLarge`] past `max`; [`CliError::Io`] for content that
/// is not UTF-8 or a failed read.
pub fn read_proven_within(file: RegularFile, path: &Path, max: u64) -> Result<String, CliError> {
    utf8(read_handle_bytes(file, path, max)?, path)
}

/// Read a file already proven regular on its own handle to a `String` under `cap`.
///
/// For callers that opened and vetted the handle themselves (an owner-checked
/// secret); `path` only names the file in errors.
///
/// # Errors
///
/// [`CliError::FileTooLarge`] past `cap`; [`CliError::Io`] for content that is
/// not UTF-8 or a failed read.
pub fn read_proven(file: RegularFile, path: &Path, cap: ByteCap) -> Result<String, CliError> {
    file.read_utf8(cap)
        .map_err(|refusal| refusal_error(path, refusal))
}

/// Open the final component of `path` beneath its parent, never following it, proven regular.
fn open_leaf(path: &Path) -> Result<RegularFile, CliError> {
    let leaf = path
        .file_name()
        .ok_or(OpenRefusal::BadName)
        .and_then(EntryName::parse)
        .map_err(|refusal| refusal_error(path, refusal))?;
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    HeldDir::open_root(parent)
        .and_then(|dir| dir.open_regular(&leaf))
        .map_err(|refusal| refusal_error(path, refusal))
}

/// Read `file` as raw bytes, refusing (never truncating) one past `max` bytes.
///
/// A `max` of zero admits only an empty file.
fn read_handle_bytes(file: RegularFile, path: &Path, max: u64) -> Result<Vec<u8>, CliError> {
    let too_large = || CliError::FileTooLarge {
        path: path.to_path_buf(),
        max,
    };
    /// The smallest cap, read under a `max` of zero so one byte past it is still seen.
    const ONE_BYTE: ByteCap = ByteCap::from_nonzero(NonZeroU64::MIN);
    let cap = ByteCap::new(max).unwrap_or(ONE_BYTE);
    let bytes = file.read_bytes(cap).map_err(|refusal| match refusal {
        OpenRefusal::TooLarge(_) => too_large(),
        other => refusal_error(path, other),
    })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max {
        return Err(too_large());
    }
    Ok(bytes)
}

// ── Capped reader ─────────────────────────────────────────────────────────────

/// Read the file a no-follow walk or a convention found at `path` to a `String` under `max` bytes.
///
/// Never for a path the invoking user named: that is [`read_user_named`].
/// The file is opened beneath its parent directory, never following a final
/// symlink and never blocking, and proven regular on its own handle (as
/// [`read_in`] with one entry); past `max` it is a typed
/// [`CliError::FileTooLarge`], never an allocation without a ceiling. A file
/// exactly at the cap succeeds; one byte over fails. Call it with a
/// [`MANIFEST_READ_CAP`] / [`SOURCE_READ_CAP`] / [`FFI_CACHE_READ_CAP`] /
/// [`SMALL_FILE_READ_CAP`] constant, never an ad-hoc number.
///
/// # Errors
///
/// - [`CliError::SourceRefused`] if the path is a symlink, not a regular file, or may not be opened.
/// - [`CliError::Io`] if the file cannot otherwise be opened or read.
/// - [`CliError::FileTooLarge`] if the file exceeds `max` bytes.
/// - [`CliError::Io`] (kind `InvalidData`) if the content is not valid UTF-8.
pub fn read_leaf_capped(path: &Path, max: u64) -> Result<String, CliError> {
    let file = open_leaf(path)?;
    utf8(read_handle_bytes(file, path, max)?, path)
}

/// Read a source file a no-follow walk found, refusing a final symlink swapped in since.
///
/// Capped at [`SOURCE_READ_CAP`] and opened as [`read_leaf_capped`] opens.
///
/// # Errors
///
/// As [`read_leaf_capped`].
pub fn read_walked_source(path: &Path) -> Result<String, CliError> {
    read_leaf_capped(path, SOURCE_READ_CAP)
}

/// Read the file a no-follow walk or a convention found at `path` as raw bytes under `max` bytes.
///
/// The byte twin of [`read_leaf_capped`] for binaries (no UTF-8 check),
/// opened the same no-follow way; never for a path the invoking user named.
///
/// # Errors
///
/// - [`CliError::SourceRefused`] if the path is a symlink, not a regular file, or may not be opened.
/// - [`CliError::Io`] if the file cannot otherwise be opened or read.
/// - [`CliError::FileTooLarge`] if the file exceeds `max` bytes.
pub fn read_leaf_bytes_capped(path: &Path, max: u64) -> Result<Vec<u8>, CliError> {
    let file = open_leaf(path)?;
    read_handle_bytes(file, path, max)
}

/// `bytes` as UTF-8 text, or the typed `InvalidData` error naming `path`.
fn utf8(bytes: Vec<u8>, path: &Path) -> Result<String, CliError> {
    String::from_utf8(bytes).map_err(|e| CliError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(name: &str, content: &[u8]) -> std::path::PathBuf {
        let p =
            ipe_test_temp::temp_root().join(format!("ipe_iob_{name}_{}.bin", std::process::id()));
        std::fs::write(&p, content).expect("write temp");
        p
    }

    #[test]
    fn under_cap_reads_full_content() {
        let p = write_temp("under", b"hello world");
        let result = read_leaf_capped(&p, SMALL_FILE_READ_CAP);
        let _ = std::fs::remove_file(&p);
        assert_eq!(result.expect("under cap must succeed"), "hello world");
    }

    #[test]
    fn exactly_at_cap_is_ok() {
        let content = vec![b'a'; 16];
        let p = write_temp("exact", &content);
        let result = read_leaf_capped(&p, 16);
        let _ = std::fs::remove_file(&p);
        assert_eq!(result.expect("exactly at cap must succeed").len(), 16);
    }

    #[test]
    fn one_byte_over_cap_is_typed_error() {
        let content = vec![b'a'; 17];
        let p = write_temp("over", &content);
        let result = read_leaf_capped(&p, 16);
        let _ = std::fs::remove_file(&p);
        assert!(
            matches!(result, Err(CliError::FileTooLarge { .. })),
            "one byte over cap must be FileTooLarge, got: {result:?}"
        );
    }

    #[test]
    fn manifest_cap_refuses_gigabyte_device_node_simulation() {
        // Simulate oversized input: write a file just past the manifest cap.
        // 512 KiB + 1 byte; the literal avoids a u64→usize cast lint in tests.
        let content = vec![b'x'; 512 * 1024 + 1];
        let p = write_temp("manifest_over", &content);
        let result = read_leaf_capped(&p, MANIFEST_READ_CAP);
        let _ = std::fs::remove_file(&p);
        assert!(
            matches!(result, Err(CliError::FileTooLarge { .. })),
            "file over manifest cap must be FileTooLarge"
        );
    }

    #[test]
    fn bytes_capped_reads_non_utf8_at_cap_and_refuses_one_over() {
        let at = write_temp("bytes_at", &[0xff; 16]);
        let at_result = read_leaf_bytes_capped(&at, 16);
        let over = write_temp("bytes_over", &[0xff; 17]);
        let over_result = read_leaf_bytes_capped(&over, 16);
        let _ = std::fs::remove_file(&at);
        let _ = std::fs::remove_file(&over);
        assert_eq!(at_result.expect("at cap must succeed"), vec![0xff; 16]);
        assert!(
            matches!(over_result, Err(CliError::FileTooLarge { max: 16, .. })),
            "one byte over cap must be FileTooLarge, got: {over_result:?}"
        );
    }

    #[test]
    fn missing_file_is_io_error() {
        let p = std::path::PathBuf::from("/nonexistent/path/that/cannot/exist");
        let result = read_leaf_capped(&p, 1024);
        assert!(
            matches!(result, Err(CliError::Io { .. })),
            "missing file must be Io error"
        );
    }

    /// A scratch directory unique to this test process.
    #[allow(clippy::expect_used)] // test fixture: an unwritable temp dir IS the failure
    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir =
            ipe_test_temp::temp_root().join(format!("ipe_iob_dir_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    /// Make `path` a FIFO.
    #[cfg(unix)]
    #[allow(clippy::expect_used)] // test fixture: a failed `mkfifo` IS the failure
    fn make_fifo(path: &Path) {
        let made = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo creates the fixture");
    }

    /// A FIFO entry returns the typed refusal at once instead of blocking on a writer.
    ///
    /// The open is non-blocking, so no writer is needed for this test to finish.
    #[cfg(unix)]
    #[test]
    fn fifo_is_refused_without_blocking() {
        let dir = scratch_dir("fifo");
        let fifo = dir.join("Main.ipe");
        make_fifo(&fifo);
        let convention = read_leaf_capped(&fifo, SOURCE_READ_CAP);
        let walked = read_walked_source(&fifo);
        let held = read_in(&dir, &[entry("Main.ipe")], SOURCE_CAP);
        let named = read_user_named(&fifo, SOURCE_CAP);
        let _ = std::fs::remove_dir_all(&dir);
        for result in [convention, walked, held, named] {
            assert!(
                matches!(
                    result,
                    Err(CliError::SourceRefused {
                        reason: SourceRefusal::NotRegularFile,
                        ..
                    })
                ),
                "a FIFO must be refused as not a regular file, got: {result:?}"
            );
        }
    }

    /// A directory named as a source file is refused as not a regular file.
    #[test]
    fn directory_is_refused_as_not_a_regular_file() {
        let dir = scratch_dir("isdir");
        let result = read_leaf_capped(&dir, SOURCE_READ_CAP);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(
                result,
                Err(CliError::SourceRefused {
                    reason: SourceRefusal::NotRegularFile,
                    ..
                })
            ),
            "a directory must be refused as not a regular file, got: {result:?}"
        );
    }

    /// One plain entry name.
    #[allow(clippy::expect_used)] // test fixture: every literal here is one plain name
    fn entry(name: &str) -> EntryName {
        EntryName::new(std::ffi::OsStr::new(name)).expect("one plain entry name")
    }

    /// Whether `result` is the symlink refusal.
    fn is_symlink_refusal<T>(result: &Result<T, CliError>) -> bool {
        matches!(
            result,
            Err(CliError::SourceRefused {
                reason: SourceRefusal::Symlink,
                ..
            })
        )
    }

    /// A convention-file read refuses a symlink at the file's name, or at a directory below the root.
    ///
    /// Every no-follow entry point is driven: the path-split read, the walked
    /// read, the byte read, and the held read through an intermediate level.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: an unwritable scratch dir IS the failure
    fn a_convention_read_refuses_a_final_symlink() {
        let dir = scratch_dir("convention_link");
        let real_dir = dir.join("real");
        std::fs::create_dir_all(&real_dir).expect("make real dir");
        let target = real_dir.join("ipe.lock");
        std::fs::write(&target, "version = 1\n").expect("write target");
        let link = dir.join("ipe.lock");
        std::os::unix::fs::symlink(&target, &link).expect("link the file");
        std::os::unix::fs::symlink(&real_dir, dir.join("linked")).expect("link the dir");
        let convention = read_leaf_capped(&link, SMALL_FILE_READ_CAP);
        let walked = read_walked_source(&link);
        let bytes = read_leaf_bytes_capped(&link, SMALL_FILE_READ_CAP);
        let held = read_in(&dir, &[entry("ipe.lock")], SMALL_FILE_CAP);
        let through_dir = read_in(&dir, &[entry("linked"), entry("ipe.lock")], SMALL_FILE_CAP);
        let real = read_in(&dir, &[entry("real"), entry("ipe.lock")], SMALL_FILE_CAP);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            is_symlink_refusal(&convention),
            "path-split read: {convention:?}"
        );
        assert!(is_symlink_refusal(&walked), "walked read: {walked:?}");
        assert!(is_symlink_refusal(&bytes), "byte read: {bytes:?}");
        assert!(is_symlink_refusal(&held), "held read: {held:?}");
        assert!(
            is_symlink_refusal(&through_dir),
            "held read through a linked dir: {through_dir:?}"
        );
        assert_eq!(real.ok().as_deref(), Some("version = 1\n"));
    }

    /// A user-named read follows the same final symlink a convention read refuses.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: an unwritable scratch dir IS the failure
    fn a_user_named_read_follows_it() {
        let dir = scratch_dir("user_named_link");
        let target = dir.join("Real.ipe");
        let link = dir.join("Link.ipe");
        std::fs::write(&target, "module Real exposing (..)\n").expect("write target");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");
        let named = read_user_named(&link, SOURCE_CAP);
        let convention = read_leaf_capped(&link, SOURCE_READ_CAP);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(named.ok().as_deref(), Some("module Real exposing (..)\n"));
        assert!(
            is_symlink_refusal(&convention),
            "convention read: {convention:?}"
        );
    }

    /// The proven-handle read takes only a [`RegularFile`], which a FIFO handle never becomes.
    ///
    /// The type is the refusal: [`read_proven`] has no `File` or `Read`
    /// parameter, so a held token handle reaches it only through
    /// [`RegularFile::prove`], and the proof turns a FIFO away.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: an unwritable scratch dir IS the failure
    fn login_read_takes_only_a_proven_file() {
        use rustix::fs::{Mode, OFlags};
        let dir = scratch_dir("proven");
        let fifo = dir.join("token");
        make_fifo(&fifo);
        let token = dir.join("token.plain");
        std::fs::write(&token, "secret-token").expect("write token");
        let fifo_handle = rustix::fs::open(&fifo, OFlags::RDONLY | OFlags::NONBLOCK, Mode::empty())
            .map(std::fs::File::from)
            .expect("open the FIFO without blocking");
        let refused = RegularFile::prove(fifo_handle);
        let plain = std::fs::File::open(&token).expect("open token");
        let read = RegularFile::prove(plain)
            .map_err(|refusal| refusal_error(&token, refusal))
            .and_then(|file| read_proven(file, &token, SMALL_FILE_CAP));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(
                refused,
                Err(OpenRefusal::NotRegular(ipe_fs_open::FileKind::Fifo))
            ),
            "a FIFO handle is never proven regular: {refused:?}"
        );
        assert_eq!(read.ok().as_deref(), Some("secret-token"));
    }

    /// A walked source whose final component is a file symlink is refused on the handle; a named one is followed.
    ///
    /// Skipped when the process may not create a symlink (no privilege, no developer mode).
    #[cfg(windows)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: an unwritable scratch dir IS the failure
    fn walked_source_refuses_a_final_reparse_point_that_a_named_path_follows() {
        let dir = scratch_dir("reparse");
        let target = dir.join("Real.ipe");
        let link = dir.join("Link.ipe");
        std::fs::write(&target, "module Real exposing (..)\n").expect("write target");
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let named = read_user_named(&link, SOURCE_CAP);
        let walked = read_walked_source(&link);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            named.is_ok(),
            "a named path follows its reparse point: {named:?}"
        );
        assert!(
            is_symlink_refusal(&walked),
            "a walked path refuses a final reparse point, got: {walked:?}"
        );
    }

    /// A walked path whose final component is a junction is refused, never read through.
    #[cfg(windows)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: an unwritable scratch dir IS the failure
    fn walked_source_refuses_a_final_junction() {
        let dir = scratch_dir("junction");
        let victim = dir.join("victim");
        let junction = dir.join("Main.ipe");
        std::fs::create_dir_all(&victim).expect("make victim");
        std::fs::create_dir_all(&junction).expect("make junction dir");
        crate::output_dir::test_links::junction_in_place(&junction, &victim);
        let walked = read_walked_source(&junction);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            is_symlink_refusal(&walked),
            "a walked path refuses a final junction, got: {walked:?}"
        );
    }

    /// A file without the read bit is refused as access denied, not a raw I/O error.
    ///
    /// Skipped when the process can read it anyway (running as root).
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: an unwritable scratch dir IS the failure
    fn unreadable_file_is_refused_as_access_denied() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("noread");
        let file = dir.join("Main.ipe");
        std::fs::write(&file, "module Main exposing (..)\n").expect("write file");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000))
            .expect("drop the read bit");
        let privileged = std::fs::File::open(&file).is_ok();
        let result = read_leaf_capped(&file, SOURCE_READ_CAP);
        let _ = std::fs::remove_dir_all(&dir);
        if privileged {
            return;
        }
        assert!(
            matches!(
                result,
                Err(CliError::SourceRefused {
                    reason: SourceRefusal::AccessDenied,
                    ..
                })
            ),
            "an unreadable file must be refused as access denied, got: {result:?}"
        );
    }
}

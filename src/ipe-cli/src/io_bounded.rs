//! Bounded file-I/O utilities for the CLI/FFI layer.
//!
//! Every CLI or FFI-cache file that must be turned into a `String` goes through
//! [`read_to_string_capped`] — the single capped reader. This mirrors the
//! runtime's own `file.rs` ceiling and closes the same defect class for the
//! compile-time surfaces: an unbounded `std::fs::read_to_string` is not
//! reachable from this crate's public paths.
//!
//! Every such file is opened by [`open_regular`] — the single open: never
//! blocking on a FIFO, never taking a terminal as the controlling one, and
//! refusing anything but a regular file by the type of the handle it opened,
//! so no path can hang or stream endlessly into a read.
//!
//! Cap constants are declared here as the single source of truth so a new call
//! site cannot silently introduce a different ceiling.

use std::fs::File;
use std::io::Read as _;
use std::path::Path;

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

// ── Regular-file open ─────────────────────────────────────────────────────────

/// Why a path was refused before any of it was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceRefusal {
    /// The path names a FIFO, device, socket, directory or refused symlink, not a regular file.
    NotRegularFile,
    /// The process may not open the path, or search a directory leading to it.
    AccessDenied,
    /// The path, or a directory leading to it, is a symlink the no-follow walk refuses.
    Symlink,
}

/// Whether [`open_regular`] follows a symlink in the path's final component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalLink {
    /// Follow it: the path was named by the user, who may link a file on purpose.
    Follow,
    /// Refuse it as [`SourceRefusal::NotRegularFile`]: the path came from a no-follow walk.
    Refuse,
}

/// Open `path` read-only as a regular file, or refuse it with a typed error.
///
/// On unix the open is `O_NONBLOCK | O_NOCTTY`, so a FIFO swapped in for a
/// file never blocks it and a terminal never becomes the controlling one;
/// the file type is then checked on the opened handle (`fstat`), so no swap
/// after a path check can hand the reader a non-regular file. A socket
/// (which `open` refuses with `ENXIO`) is refused the same way. On Windows
/// a final reparse point under [`FinalLink::Refuse`] is refused on the opened
/// handle's attributes, never by a path check made before the open.
///
/// # Errors
///
/// - [`CliError::SourceRefused`] with [`SourceRefusal::NotRegularFile`] when
///   the opened file is not a regular file, or its final component is a
///   symlink (on Windows, any reparse point) under [`FinalLink::Refuse`].
/// - [`CliError::SourceRefused`] with [`SourceRefusal::AccessDenied`] when
///   the open is denied permission.
/// - [`CliError::Io`] for any other open or `fstat` failure.
pub fn open_regular(path: &Path, final_link: FinalLink) -> Result<File, CliError> {
    let file = open_nonblocking(path, final_link)?;
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

/// Open `path` read-only without blocking and without taking a controlling terminal.
#[cfg(unix)]
fn open_nonblocking(path: &Path, final_link: FinalLink) -> Result<File, CliError> {
    use rustix::fs::{Mode, OFlags};
    let mut flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    if final_link == FinalLink::Refuse {
        flags |= OFlags::NOFOLLOW;
    }
    rustix::fs::open(path, flags, Mode::empty())
        .map(File::from)
        .map_err(|errno| open_error(path, errno.into()))
}

/// Open `path` read-only, refusing a final reparse point on the opened handle under [`FinalLink::Refuse`].
///
/// Under [`FinalLink::Refuse`] the open carries `FILE_FLAG_OPEN_REPARSE_POINT`,
/// so a final reparse point of any tag (symlink, junction, or other) is
/// opened itself rather than its target, and the handle's attributes then
/// refuse it: no swap between a path check and the open can slip one past.
/// Under [`FinalLink::Follow`] the open resolves reparse points, as for any
/// user-named path.
#[cfg(windows)]
fn open_nonblocking(path: &Path, final_link: FinalLink) -> Result<File, CliError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    /// `FILE_FLAG_OPEN_REPARSE_POINT`: opens a reparse point itself, never its target.
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    /// `FILE_ATTRIBUTE_REPARSE_POINT`.
    const ATTR_REPARSE_POINT: u32 = 0x400;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    if final_link == FinalLink::Refuse {
        options.custom_flags(OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|source| open_error(path, source))?;
    if final_link == FinalLink::Refuse {
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
    }
    Ok(file)
}

// ── Capped reader ─────────────────────────────────────────────────────────────

/// Read a file to a `String`, refusing past `max` bytes with a typed
/// [`CliError::FileTooLarge`] instead of allocating without a ceiling.
///
/// Reads `max + 1` bytes in one pass via [`std::io::Read::take`] and checks
/// the actual byte count, so it never buffers more than the cap. A file
/// exactly at the cap succeeds; a file one byte over fails.
///
/// This is the ONLY approved path for turning a CLI/FFI-cache file path into a
/// `String`. Call it with the appropriate [`MANIFEST_READ_CAP`] /
/// [`SOURCE_READ_CAP`] / [`FFI_CACHE_READ_CAP`] / [`SMALL_FILE_READ_CAP`]
/// constant — never pass an ad-hoc magic number. The file is opened by
/// [`open_regular`], following a final symlink.
///
/// # Errors
///
/// - [`CliError::SourceRefused`] if the path is not a regular file or may not be opened.
/// - [`CliError::Io`] if the file cannot otherwise be opened or read.
/// - [`CliError::FileTooLarge`] if the file exceeds `max` bytes.
/// - [`CliError::Io`] (kind `InvalidData`) if the content is not valid UTF-8.
pub fn read_to_string_capped(path: &Path, max: u64) -> Result<String, CliError> {
    let f = open_regular(path, FinalLink::Follow)?;
    read_opened_capped(f, path, max)
}

/// Read a source file a no-follow walk found, refusing a final symlink swapped in since.
///
/// Capped at [`SOURCE_READ_CAP`] and opened by [`open_regular`] with
/// [`FinalLink::Refuse`].
///
/// # Errors
///
/// As [`read_to_string_capped`]; a final symlink is [`CliError::SourceRefused`].
pub fn read_walked_source(path: &Path) -> Result<String, CliError> {
    let f = open_regular(path, FinalLink::Refuse)?;
    read_opened_capped(f, path, SOURCE_READ_CAP)
}

/// Read an already-opened `reader` to a `String` under the same `max`-byte
/// ceiling as [`read_to_string_capped`]: the single cap implementation.
///
/// For callers that vetted the handle itself (an `fstat` after an
/// `O_NOFOLLOW` open, or a held, owner-checked handle) and must read from
/// THAT handle, not reopen the path. `path` only names the file in errors.
///
/// # Errors
///
/// - [`CliError::Io`] if the reader fails.
/// - [`CliError::FileTooLarge`] if it yields more than `max` bytes.
/// - [`CliError::Io`] (kind `InvalidData`) if the content is not valid UTF-8.
pub fn read_opened_capped(
    reader: impl std::io::Read,
    path: &Path,
    max: u64,
) -> Result<String, CliError> {
    let buf = read_opened_bytes_capped(reader, path, max)?;
    String::from_utf8(buf).map_err(|e| CliError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
    })
}

/// Read the file at `path` as raw bytes under a `max`-byte ceiling: the
/// byte twin of [`read_to_string_capped`] for binaries (no UTF-8 check).
/// Opened by [`open_regular`], following a final symlink.
///
/// # Errors
///
/// - [`CliError::SourceRefused`] if the path is not a regular file or may not be opened.
/// - [`CliError::Io`] if the file cannot otherwise be opened or read.
/// - [`CliError::FileTooLarge`] if the file exceeds `max` bytes.
pub fn read_bytes_capped(path: &Path, max: u64) -> Result<Vec<u8>, CliError> {
    let f = open_regular(path, FinalLink::Follow)?;
    read_opened_bytes_capped(f, path, max)
}

/// The single cap implementation: read at most `max` bytes from `reader`,
/// refusing (never truncating) a source that yields more.
fn read_opened_bytes_capped(
    reader: impl std::io::Read,
    path: &Path,
    max: u64,
) -> Result<Vec<u8>, CliError> {
    let mut buf = Vec::new();
    reader
        .take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| CliError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    if buf.len() as u64 > max {
        return Err(CliError::FileTooLarge {
            path: path.to_path_buf(),
            max,
        });
    }
    Ok(buf)
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
        let result = read_to_string_capped(&p, SMALL_FILE_READ_CAP);
        let _ = std::fs::remove_file(&p);
        assert_eq!(result.expect("under cap must succeed"), "hello world");
    }

    #[test]
    fn exactly_at_cap_is_ok() {
        let content = vec![b'a'; 16];
        let p = write_temp("exact", &content);
        let result = read_to_string_capped(&p, 16);
        let _ = std::fs::remove_file(&p);
        assert_eq!(result.expect("exactly at cap must succeed").len(), 16);
    }

    #[test]
    fn one_byte_over_cap_is_typed_error() {
        let content = vec![b'a'; 17];
        let p = write_temp("over", &content);
        let result = read_to_string_capped(&p, 16);
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
        let result = read_to_string_capped(&p, MANIFEST_READ_CAP);
        let _ = std::fs::remove_file(&p);
        assert!(
            matches!(result, Err(CliError::FileTooLarge { .. })),
            "file over manifest cap must be FileTooLarge"
        );
    }

    #[test]
    fn bytes_capped_reads_non_utf8_at_cap_and_refuses_one_over() {
        let at = write_temp("bytes_at", &[0xff; 16]);
        let at_result = read_bytes_capped(&at, 16);
        let over = write_temp("bytes_over", &[0xff; 17]);
        let over_result = read_bytes_capped(&over, 16);
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
        let result = read_to_string_capped(&p, 1024);
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
        let followed = read_to_string_capped(&fifo, SOURCE_READ_CAP);
        let walked = read_walked_source(&fifo);
        let _ = std::fs::remove_dir_all(&dir);
        for result in [followed, walked] {
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
        let result = read_to_string_capped(&dir, SOURCE_READ_CAP);
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

    /// A walked source whose final component became a symlink is refused; a named one is followed.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: an unwritable scratch dir IS the failure
    fn walked_source_refuses_a_final_symlink_that_a_named_path_follows() {
        let dir = scratch_dir("link");
        let target = dir.join("Real.ipe");
        let link = dir.join("Link.ipe");
        std::fs::write(&target, "module Real exposing (..)\n").expect("write target");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");
        let followed = read_to_string_capped(&link, SOURCE_READ_CAP);
        let walked = read_walked_source(&link);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            followed.is_ok(),
            "a named path follows its symlink: {followed:?}"
        );
        assert!(
            matches!(
                walked,
                Err(CliError::SourceRefused {
                    reason: SourceRefusal::NotRegularFile,
                    ..
                })
            ),
            "a walked path refuses a final symlink, got: {walked:?}"
        );
    }

    /// A walked source whose final component is a file symlink is refused on the handle; a named one is followed.
    ///
    /// Skipped when the process may not create a symlink (no privilege, no developer mode).
    #[cfg(windows)]
    #[test]
    fn walked_source_refuses_a_final_reparse_point_that_a_named_path_follows() {
        let dir = scratch_dir("reparse");
        let target = dir.join("Real.ipe");
        let link = dir.join("Link.ipe");
        std::fs::write(&target, "module Real exposing (..)\n").expect("write target");
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let followed = read_to_string_capped(&link, SOURCE_READ_CAP);
        let walked = read_walked_source(&link);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            followed.is_ok(),
            "a named path follows its reparse point: {followed:?}"
        );
        assert!(
            matches!(
                walked,
                Err(CliError::SourceRefused {
                    reason: SourceRefusal::NotRegularFile,
                    ..
                })
            ),
            "a walked path refuses a final reparse point, got: {walked:?}"
        );
    }

    /// A walked path whose final component is a junction is refused, never read through.
    #[cfg(windows)]
    #[test]
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
            matches!(
                walked,
                Err(CliError::SourceRefused {
                    reason: SourceRefusal::NotRegularFile,
                    ..
                })
            ),
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
        let result = read_to_string_capped(&file, SOURCE_READ_CAP);
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

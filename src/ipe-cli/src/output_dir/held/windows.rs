//! Windows write-side primitives: handle-relative creates and deletes, and path acts under a pin.
//!
//! Opening, classifying, and identifying a held level live in [`ipe_fs_open`].
//! Creating a file and removing a non-directory name one entry relative to the
//! held directory handle (`NtCreateFile` with a root directory, through
//! `cap-primitives`), with `FILE_FLAG_OPEN_REPARSE_POINT` so a reparse point at
//! the entry is removed as itself, never traversed. A handle-relative delete
//! never admits a directory: it opens without backup semantics, which makes the
//! open fail on any directory.
//!
//! Creating a subdirectory, removing one, renaming, and listing have no
//! handle-relative form without raw system calls, so they name the entry by the
//! held directory's proven real path. A directory is removed only by
//! `RemoveDirectoryW`, which removes nothing but an empty directory or a
//! directory reparse point as itself — a file or a populated tree swapped in at
//! the name is refused. Each runs under a [`Pin`]: a sentinel file created through
//! the handle and held open without delete sharing. NTFS sets a reparse point on
//! an empty directory only, and the sentinel cannot be removed while held, so
//! for the act's duration the held directory cannot turn into a junction; the
//! pin re-reads the handle's attributes after it is placed, refusing a
//! directory that already became one. The directories above cannot be renamed
//! while a handle below them is open, and they are not empty, so the real path
//! keeps naming the held directory throughout.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::windows::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cap_primitives::fs::{OpenOptions, OpenOptionsExt as _};
use ipe_fs_open::{EntryName, HeldDir, OpenRefusal};

/// `FILE_FLAG_BACKUP_SEMANTICS`: allows opening a directory handle.
const BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// `FILE_FLAG_OPEN_REPARSE_POINT`: opens a reparse point itself, never its target.
const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// `FILE_FLAG_DELETE_ON_CLOSE`: removes the entry when its last handle closes.
const DELETE_ON_CLOSE: u32 = 0x0400_0000;
/// `FILE_SHARE_READ`.
const SHARE_READ: u32 = 0x1;
/// `FILE_SHARE_READ | FILE_SHARE_WRITE`, without `FILE_SHARE_DELETE`.
const SHARE_NO_DELETE: u32 = 0x1 | 0x2;
/// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`.
const SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
/// `FILE_ATTRIBUTE_DIRECTORY`.
const ATTR_DIRECTORY: u32 = 0x10;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
const ATTR_REPARSE_POINT: u32 = 0x400;
/// `FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY`, for the pin sentinel.
const ATTR_HIDDEN_TEMPORARY: u32 = 0x2 | 0x100;
/// `ERROR_REPARSE_POINT_ENCOUNTERED`: the typed refusal of a reparse point.
const ERROR_REPARSE_POINT_ENCOUNTERED: i32 = 4395;
/// `ERROR_SHARING_VIOLATION`: another open handle denies the access asked for.
const ERROR_SHARING_VIOLATION: i32 = 32;
/// `ERROR_LOCK_VIOLATION`: another process has locked a region of the file.
const ERROR_LOCK_VIOLATION: i32 = 33;
/// `ERROR_ACCESS_DENIED`: also the answer for an open of a name pending deletion.
const ERROR_ACCESS_DENIED: i32 = 5;
/// The name prefix of a pin sentinel; entries carrying it are never listed.
const PIN_PREFIX: &str = ".ipe-pin-";
/// How many sentinel names a pin tries before giving up.
const PIN_ATTEMPTS: u32 = 8;

/// The error for a reparse point met where a plain entry was required.
fn reparse_point() -> io::Error {
    io::Error::from_raw_os_error(ERROR_REPARSE_POINT_ENCOUNTERED)
}

/// Whether `error` is the refusal of a reparse point met where a plain directory was required.
#[must_use]
pub fn is_reparse_refusal(error: &io::Error) -> bool {
    error.raw_os_error() == Some(ERROR_REPARSE_POINT_ENCOUNTERED)
}

/// Whether `error` reports an entry another program holds open or locked.
///
/// An editor, a file indexer, or antivirus holding an entry without delete
/// sharing makes a removal or a rename over it fail this way until it lets go.
#[must_use]
pub fn is_in_use(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
    )
}

/// The [`io::Error`] a refused re-proof of a held directory stands for.
///
/// A held directory that became a reparse point answers the raw reparse
/// refusal ([`is_reparse_refusal`]) and one held elsewhere the raw sharing
/// violation ([`is_in_use`]), so callers classify both as before.
fn reproof_error(refusal: OpenRefusal) -> io::Error {
    match refusal {
        OpenRefusal::Link => reparse_point(),
        OpenRefusal::InUse => io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION),
        OpenRefusal::Absent
        | OpenRefusal::NotRegular(_)
        | OpenRefusal::Denied
        | OpenRefusal::TooLarge(_)
        | OpenRefusal::TooManyEntries(_)
        | OpenRefusal::BadName
        | OpenRefusal::NotUtf8
        | OpenRefusal::Io(_) => refusal.into_io(),
    }
}

/// Options opening any entry for its attributes only, never following a reparse point.
fn stat_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .access_mode(0)
        .share_mode(SHARE_ALL)
        .custom_flags(BACKUP_SEMANTICS | OPEN_REPARSE_POINT);
    options
}

/// Options removing the opened non-directory when the handle closes, never following a reparse point.
///
/// Without backup semantics the open carries `FILE_NON_DIRECTORY_FILE`, so it
/// fails on any directory: a handle-relative delete can never remove one.
fn delete_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .access_mode(0)
        .share_mode(SHARE_NO_DELETE)
        .custom_flags(DELETE_ON_CLOSE | OPEN_REPARSE_POINT);
    options
}

/// Whether `name` is a pin sentinel, which a listing never shows.
fn is_pin_name(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.starts_with(PIN_PREFIX))
}

/// Open the entry `name` of `dir` relative to its handle.
fn open_at(dir: &HeldDir, name: &EntryName, options: &OpenOptions) -> io::Result<File> {
    cap_primitives::fs::open(dir.handle(), Path::new(name.as_os_str()), options)
}

/// The real path of the entry `name` of `dir`.
fn entry_path(dir: &HeldDir, name: &EntryName) -> PathBuf {
    dir.real_path().join(name.as_os_str())
}

/// A sentinel file held open inside a directory, which keeps it from becoming a reparse point.
///
/// The sentinel is created through the directory handle, shares neither write
/// nor delete, and is removed when the pin drops.
#[derive(Debug)]
struct Pin {
    _sentinel: File,
}

/// Sequence number that keeps concurrent pins of one process apart.
static PIN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Pin `dir` for the duration of a path act.
///
/// # Errors
/// A reparse refusal when the directory already is a reparse point; another
/// error when no sentinel can be created.
fn pin(dir: &HeldDir) -> io::Result<Pin> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .share_mode(SHARE_READ)
        .attributes(ATTR_HIDDEN_TEMPORARY)
        .custom_flags(DELETE_ON_CLOSE | OPEN_REPARSE_POINT);
    let mut last = io::Error::from(io::ErrorKind::AlreadyExists);
    for _ in 0..PIN_ATTEMPTS {
        let sequence = PIN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!("{PIN_PREFIX}{}-{sequence}", std::process::id());
        let name = EntryName::parse(OsStr::new(&name)).map_err(OpenRefusal::into_io)?;
        match open_at(dir, &name, &options) {
            Ok(sentinel) => {
                let pin = Pin {
                    _sentinel: sentinel,
                };
                dir.reprove().map_err(reproof_error)?;
                return Ok(pin);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// The attributes of the entry `name` of `dir`, read without following a reparse point; `None` when absent.
fn attributes(dir: &HeldDir, name: &EntryName) -> io::Result<Option<u32>> {
    match open_at(dir, name, &stat_options()) {
        Ok(file) => Ok(Some(file.metadata()?.file_attributes())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Create the subdirectory `name` of `dir`.
pub fn mkdir(dir: &HeldDir, name: &EntryName) -> io::Result<()> {
    let path = entry_path(dir, name);
    let _pin = pin(dir)?;
    std::fs::create_dir(path)
}

/// Exclusively create the new file `name` in `dir` for writing.
pub fn create_new(dir: &HeldDir, name: &EntryName) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .custom_flags(OPEN_REPARSE_POINT);
    open_at(dir, name, &options)
}

/// Options opening the claim file to read, write, and lock, sharing every access and never following a reparse point.
///
/// Delete sharing lets the holder unlink the name while another claimant
/// still has it open.
fn claim_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .share_mode(SHARE_ALL)
        .custom_flags(OPEN_REPARSE_POINT);
    options
}

/// Exclusively create the claim file `name` in `dir`, open to read, write, and lock.
pub fn create_claim(dir: &HeldDir, name: &EntryName) -> io::Result<File> {
    let mut options = claim_options();
    options.create_new(true);
    open_at(dir, name, &options)
}

/// Open the existing claim file `name` in `dir` to read, write, and lock, never through a reparse point.
pub fn open_claim(dir: &HeldDir, name: &EntryName) -> io::Result<File> {
    open_at(dir, name, &claim_options())
}

/// Whether `error` reports a claim name another claimant is deleting.
///
/// An open of a name pending deletion answers access denied until its last
/// handle closes; the claim then retries.
#[must_use]
pub fn is_claim_pending(error: &io::Error) -> bool {
    error.raw_os_error() == Some(ERROR_ACCESS_DENIED)
}

/// Rename the entry `from` over the entry `to`, both in `dir`.
pub fn rename(dir: &HeldDir, from: &EntryName, to: &EntryName) -> io::Result<()> {
    let (from, to) = (entry_path(dir, from), entry_path(dir, to));
    let _pin = pin(dir)?;
    std::fs::rename(from, to)
}

/// Remove the non-directory entry `name` of `dir`; a reparse point is removed as itself.
///
/// A directory junction or directory link is removed as the link it is; a
/// plain directory is refused. A non-directory is removed through an open
/// that fails on any directory, so a directory swapped in after the check is
/// never removed; a directory reparse point is removed by
/// [`remove_directory`], so a file or a populated tree swapped in for it is
/// never removed either.
pub fn unlink(dir: &HeldDir, name: &EntryName) -> io::Result<()> {
    let attributes =
        attributes(dir, name)?.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    if attributes & ATTR_DIRECTORY == 0 {
        drop(open_at(dir, name, &delete_options())?);
        Ok(())
    } else if attributes & ATTR_REPARSE_POINT != 0 {
        remove_directory(dir, name)
    } else {
        Err(io::ErrorKind::IsADirectory.into())
    }
}

/// Remove the empty subdirectory `name` of `dir`, refusing anything else found there.
///
/// A reparse point is refused ([`is_reparse_refusal`]) and a non-directory
/// with [`io::ErrorKind::NotADirectory`] before any removal; the removal
/// itself fails on a non-empty directory
/// ([`io::ErrorKind::DirectoryNotEmpty`]) and on a file swapped in after the
/// check, so it can only ever remove an empty directory.
pub fn rmdir(dir: &HeldDir, name: &EntryName) -> io::Result<()> {
    let attributes =
        attributes(dir, name)?.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    if attributes & ATTR_REPARSE_POINT != 0 {
        Err(reparse_point())
    } else if attributes & ATTR_DIRECTORY == 0 {
        Err(io::ErrorKind::NotADirectory.into())
    } else {
        remove_directory(dir, name)
    }
}

/// Remove the entry `name` of `dir` with `RemoveDirectoryW`, under a pin.
///
/// `RemoveDirectoryW` opens the entry as a directory without following a
/// reparse point: it removes an empty directory, or a directory reparse
/// point as itself, and fails on a file and on a non-empty directory.
fn remove_directory(dir: &HeldDir, name: &EntryName) -> io::Result<()> {
    let path = entry_path(dir, name);
    let _pin = pin(dir)?;
    std::fs::remove_dir(path)
}

/// The names of the entries of `dir`, pin sentinels excluded.
///
/// The listing handle is opened under a pin; once open it enumerates the
/// directory object it holds.
pub fn names(dir: &HeldDir) -> io::Result<impl Iterator<Item = io::Result<OsString>>> {
    let entries = {
        let _pin = pin(dir)?;
        std::fs::read_dir(dir.real_path())?
    };
    Ok(entries.filter_map(|entry| match entry {
        Ok(entry) => {
            let name = entry.file_name();
            (!is_pin_name(&name)).then_some(Ok(name))
        }
        Err(e) => Some(Err(e)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh, empty scratch directory unique to this test process.
    fn scratch(tag: &str) -> PathBuf {
        let dir =
            ipe_test_temp::temp_root().join(format!("ipe_held_win_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("make scratch");
        dir
    }

    /// Hold `dir` open.
    fn held(dir: &Path) -> HeldDir {
        HeldDir::open_root(dir).unwrap()
    }

    /// The entry name `name`.
    fn name(name: &str) -> EntryName {
        EntryName::parse(OsStr::new(name)).unwrap()
    }

    #[test]
    fn pin_sentinels_are_hidden_from_listings() {
        assert!(is_pin_name(OsStr::new(".ipe-pin-12-3")));
        assert!(!is_pin_name(OsStr::new(".ipe-output")));
    }

    #[test]
    fn a_pin_leaves_no_sentinel_behind() {
        let dir = scratch("pin");
        let held = held(dir.as_path());
        mkdir(&held, &name("sub")).unwrap();
        let names: Vec<_> = names(&held).unwrap().map(Result::unwrap).collect();
        assert_eq!(names, vec![OsString::from("sub")]);
        let on_disk: Vec<_> = std::fs::read_dir(dir.as_path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(on_disk, vec![OsString::from("sub")]);
    }

    #[test]
    fn rmdir_refuses_a_non_empty_directory_and_removes_an_empty_one() {
        let dir = scratch("rmdir");
        std::fs::create_dir(dir.as_path().join("full")).unwrap();
        std::fs::write(dir.as_path().join("full").join("keep.txt"), b"keep").unwrap();
        std::fs::create_dir(dir.as_path().join("empty")).unwrap();
        let held = held(dir.as_path());
        let refused = rmdir(&held, &name("full"));
        assert!(
            matches!(&refused, Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty),
            "{refused:?}"
        );
        assert!(dir.as_path().join("full").join("keep.txt").is_file());
        rmdir(&held, &name("empty")).unwrap();
        assert!(!dir.as_path().join("empty").exists());
    }

    #[test]
    fn rmdir_refuses_a_regular_file_and_leaves_it() {
        let dir = scratch("rmdir_file");
        std::fs::write(dir.as_path().join("file.txt"), b"keep").unwrap();
        let held = held(dir.as_path());
        let refused = rmdir(&held, &name("file.txt"));
        assert!(
            matches!(&refused, Err(e) if e.kind() == io::ErrorKind::NotADirectory),
            "{refused:?}"
        );
        assert_eq!(
            std::fs::read(dir.as_path().join("file.txt"))
                .ok()
                .as_deref(),
            Some(&b"keep"[..])
        );
    }

    #[test]
    fn remove_directory_never_removes_a_file() {
        let dir = scratch("remove_directory_file");
        std::fs::write(dir.as_path().join("file.txt"), b"keep").unwrap();
        let held = held(dir.as_path());
        let refused = remove_directory(&held, &name("file.txt"));
        assert!(refused.is_err(), "{refused:?}");
        assert!(dir.as_path().join("file.txt").is_file());
    }

    #[test]
    fn rmdir_of_a_directory_held_open_elsewhere_is_reported_in_use() {
        use std::os::windows::fs::OpenOptionsExt as _;
        let dir = scratch("rmdir_in_use");
        std::fs::create_dir(dir.as_path().join("busy")).unwrap();
        let other = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(SHARE_NO_DELETE)
            .custom_flags(BACKUP_SEMANTICS)
            .open(dir.as_path().join("busy"))
            .unwrap();
        let held = held(dir.as_path());
        let refused = rmdir(&held, &name("busy"));
        assert!(matches!(&refused, Err(e) if is_in_use(e)), "{refused:?}");
        assert!(dir.as_path().join("busy").is_dir());
        drop(other);
        rmdir(&held, &name("busy")).unwrap();
        assert!(!dir.as_path().join("busy").exists());
    }

    #[test]
    fn unlink_refuses_a_plain_directory() {
        let dir = scratch("unlink");
        std::fs::create_dir(dir.as_path().join("sub")).unwrap();
        let held = held(dir.as_path());
        let refused = unlink(&held, &name("sub"));
        assert!(
            matches!(&refused, Err(e) if e.kind() == io::ErrorKind::IsADirectory),
            "{refused:?}"
        );
        assert!(dir.as_path().join("sub").is_dir());
    }
}

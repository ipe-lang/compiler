//! Unix write-side primitives: every act is an `*at` call on a held descriptor, never following a link.
//!
//! Opening, classifying, and identifying a held level live in [`ipe_fs_open`];
//! what stays here creates, renames, unlinks, and lists through its handle.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt as _;

use ipe_fs_open::{EntryName, HeldDir};
use rustix::fs::{AtFlags, Mode, OFlags};

use super::Listed;

/// Flags for exclusively creating a new file that is never a link.
fn new_file_flags() -> OFlags {
    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// Flags for exclusively creating the claim file, which is read and locked as well as written.
fn new_claim_flags() -> OFlags {
    OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// Flags for opening an existing claim file, never through a link, a FIFO, or a terminal.
fn claim_flags() -> OFlags {
    OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC
}

/// Permission bits a new file is created with, before the umask.
fn file_mode() -> Mode {
    Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH
}

/// Permission bits the claim file is created with: its owner's only.
///
/// Whoever can open the claim file can hold its lock, and a lock needs only
/// read access: a claim file another user can open lets that user keep every
/// claim on the directory waiting.
fn claim_mode() -> Mode {
    Mode::RUSR | Mode::WUSR
}

/// Permission bits a new directory is created with, before the umask.
fn dir_mode() -> Mode {
    Mode::RWXU | Mode::RWXG | Mode::RWXO
}

/// Create the subdirectory `name` of `dir`.
pub fn mkdir(dir: &HeldDir, name: &EntryName) -> io::Result<()> {
    Ok(rustix::fs::mkdirat(
        dir.handle(),
        name.as_os_str(),
        dir_mode(),
    )?)
}

/// Exclusively create the new file `name` in `dir` for writing.
pub fn create_new(dir: &HeldDir, name: &EntryName) -> io::Result<File> {
    let fd = rustix::fs::openat(
        dir.handle(),
        name.as_os_str(),
        new_file_flags(),
        file_mode(),
    )?;
    Ok(File::from(fd))
}

/// Exclusively create the claim file `name` in `dir`, open to read, write, and lock.
pub fn create_claim(dir: &HeldDir, name: &EntryName) -> io::Result<File> {
    let fd = rustix::fs::openat(
        dir.handle(),
        name.as_os_str(),
        new_claim_flags(),
        claim_mode(),
    )?;
    Ok(File::from(fd))
}

/// Open the existing claim file `name` in `dir` to read, write, and lock, never following a link.
pub fn open_claim(dir: &HeldDir, name: &EntryName) -> io::Result<File> {
    let fd = rustix::fs::openat(dir.handle(), name.as_os_str(), claim_flags(), Mode::empty())?;
    Ok(File::from(fd))
}

/// Whether `error`, met opening the claim name of a directory, reports a name another claimant is deleting; never on Unix.
#[must_use]
pub const fn is_claim_pending(_dir: &HeldDir, _name: &EntryName, _error: &io::Error) -> bool {
    false
}

/// Rename the entry `from` over the entry `to`, both in `dir`.
pub fn rename(dir: &HeldDir, from: &EntryName, to: &EntryName) -> io::Result<()> {
    Ok(rustix::fs::renameat(
        dir.handle(),
        from.as_os_str(),
        dir.handle(),
        to.as_os_str(),
    )?)
}

/// Rename the entry `from` to the absent name `to`, both in `dir`, never replacing an entry there.
///
/// Linux refuses an existing `to` atomically (`RENAME_NOREPLACE`). Elsewhere,
/// and on a Linux filesystem without the flag, the caller has proven `to`
/// absent and a plain `renameat` follows: in that window an empty directory
/// planted at `to` is replaced, and anything else there refuses the rename.
pub fn rename_noreplace(dir: &HeldDir, from: &EntryName, to: &EntryName) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    match rustix::fs::renameat_with(
        dir.handle(),
        from.as_os_str(),
        dir.handle(),
        to.as_os_str(),
        rustix::fs::RenameFlags::NOREPLACE,
    ) {
        Err(rustix::io::Errno::INVAL | rustix::io::Errno::NOSYS) => {}
        other => return other.map_err(io::Error::from),
    }
    rename(dir, from, to)
}

/// Swap the entries `a` and `b` of `dir` in one atomic step.
///
/// `Ok(false)` when the filesystem has no exchange (`RENAME_EXCHANGE`), with
/// nothing changed.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn exchange(dir: &HeldDir, a: &EntryName, b: &EntryName) -> io::Result<bool> {
    match rustix::fs::renameat_with(
        dir.handle(),
        a.as_os_str(),
        dir.handle(),
        b.as_os_str(),
        rustix::fs::RenameFlags::EXCHANGE,
    ) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::INVAL | rustix::io::Errno::NOSYS) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Swap the entries `a` and `b` of `dir` in one atomic step; this platform has none, so `Ok(false)`.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub const fn exchange(_dir: &HeldDir, _a: &EntryName, _b: &EntryName) -> io::Result<bool> {
    Ok(false)
}

/// Unlink the non-directory entry `name` of `dir`; a link is removed, never followed.
pub fn unlink(dir: &HeldDir, name: &EntryName) -> io::Result<()> {
    Ok(rustix::fs::unlinkat(
        dir.handle(),
        name.as_os_str(),
        AtFlags::empty(),
    )?)
}

/// Remove the empty subdirectory `name` of `dir`.
pub fn rmdir(dir: &HeldDir, name: &EntryName) -> io::Result<()> {
    Ok(rustix::fs::unlinkat(
        dir.handle(),
        name.as_os_str(),
        AtFlags::REMOVEDIR,
    )?)
}

/// The entries of `dir`, `.` and `..` excluded, each name parsed once into a [`Listed`].
pub fn names(dir: &HeldDir) -> io::Result<impl Iterator<Item = io::Result<Listed>>> {
    let entries = rustix::fs::Dir::read_from(dir.handle())?;
    Ok(entries.filter_map(|entry| match entry {
        Ok(entry) => {
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            (name != "." && name != "..").then(|| Ok(Listed::of(name)))
        }
        Err(e) => Some(Err(e.into())),
    }))
}

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

/// Exclusively create the new file `name` in `dir` for writing, readable by its owner only.
pub fn create_private(dir: &HeldDir, name: &EntryName) -> io::Result<File> {
    let fd = rustix::fs::openat(
        dir.handle(),
        name.as_os_str(),
        new_file_flags(),
        claim_mode(),
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
/// Linux (`RENAME_NOREPLACE`) and Apple systems (`RENAME_EXCL`) refuse an
/// existing `to` atomically. Elsewhere, and on a filesystem without the flag,
/// the caller has proven `to` absent and a plain `renameat` follows: in that
/// window an entry of `from`'s kind planted at `to` is replaced (a file over a
/// file, a directory over an empty directory). A regular file is placed
/// through [`rename_file_noreplace`], which closes that window wherever the
/// filesystem has hard links.
pub fn rename_noreplace(dir: &HeldDir, from: &EntryName, to: &EntryName) -> io::Result<()> {
    if renamed_exclusively(dir, from, to)? {
        return Ok(());
    }
    rename(dir, from, to)
}

/// Rename the regular file `from` to the absent name `to`, both in `dir`, never replacing an entry there.
///
/// Where the rename cannot refuse an existing `to` itself, `from` is
/// hard-linked at `to` (a link never replaces an entry) and then unlinked.
/// Only on a filesystem with neither does the caller's absence proof stand
/// alone, as for [`rename_noreplace`].
pub fn rename_file_noreplace(dir: &HeldDir, from: &EntryName, to: &EntryName) -> io::Result<()> {
    if renamed_exclusively(dir, from, to)? {
        return Ok(());
    }
    if link_noreplace(dir, from, to)? {
        // `to` holds the file now; a failed unlink leaves only a second name for it under the staged name.
        let _ = unlink(dir, from);
        return Ok(());
    }
    rename(dir, from, to)
}

/// Rename `from` to `to` through the system's own refusal of an existing `to`.
///
/// `Ok(false)` when the system or filesystem has no such rename, with nothing changed.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn renamed_exclusively(dir: &HeldDir, from: &EntryName, to: &EntryName) -> io::Result<bool> {
    match rustix::fs::renameat_with(
        dir.handle(),
        from.as_os_str(),
        dir.handle(),
        to.as_os_str(),
        rustix::fs::RenameFlags::NOREPLACE,
    ) {
        Ok(()) => Ok(true),
        Err(errno) if exclusive_rename_unsupported(errno) => Ok(false),
        Err(errno) => Err(errno.into()),
    }
}

/// Rename `from` to `to` through the system's own refusal of an existing `to`; this system has none.
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
const fn renamed_exclusively(
    _dir: &HeldDir,
    _from: &EntryName,
    _to: &EntryName,
) -> io::Result<bool> {
    Ok(false)
}

/// Whether `errno` says the exclusive rename is unsupported, rather than refused.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn exclusive_rename_unsupported(errno: rustix::io::Errno) -> bool {
    [rustix::io::Errno::INVAL, rustix::io::Errno::NOSYS].contains(&errno)
}

/// Whether `errno` says the exclusive rename is unsupported, rather than refused.
#[cfg(target_vendor = "apple")]
fn exclusive_rename_unsupported(errno: rustix::io::Errno) -> bool {
    [
        rustix::io::Errno::INVAL,
        rustix::io::Errno::NOSYS,
        rustix::io::Errno::NOTSUP,
    ]
    .contains(&errno)
}

/// Hard-link the regular file `from` at the absent name `to`, both in `dir`, never replacing an entry there.
///
/// `Ok(false)` when the filesystem gives the file no further link, with
/// nothing changed; an entry at `to` is [`io::ErrorKind::AlreadyExists`].
pub fn link_noreplace(dir: &HeldDir, from: &EntryName, to: &EntryName) -> io::Result<bool> {
    match rustix::fs::linkat(
        dir.handle(),
        from.as_os_str(),
        dir.handle(),
        to.as_os_str(),
        AtFlags::empty(),
    ) {
        Ok(()) => Ok(true),
        Err(errno) if link_unsupported(errno) => Ok(false),
        Err(errno) => Err(errno.into()),
    }
}

/// Whether `errno` says the filesystem gives no further hard link, rather than refusing this one.
fn link_unsupported(errno: rustix::io::Errno) -> bool {
    [
        rustix::io::Errno::PERM,
        rustix::io::Errno::OPNOTSUPP,
        rustix::io::Errno::MLINK,
        rustix::io::Errno::NOTSUP,
    ]
    .contains(&errno)
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

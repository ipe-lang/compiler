//! Unix write-side primitives: every act is an `*at` call on a held descriptor, never following a link.
//!
//! Opening, classifying, and identifying a held level live in [`ipe_fs_open`];
//! what stays here creates, renames, unlinks, and lists through its handle.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt as _;

use ipe_fs_open::{EntryName, HeldDir};
use rustix::fs::{AtFlags, Mode, OFlags};

/// Flags for exclusively creating a new file that is never a link.
fn new_file_flags() -> OFlags {
    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// Permission bits a new file is created with, before the umask.
fn file_mode() -> Mode {
    Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH
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

/// Rename the entry `from` over the entry `to`, both in `dir`.
pub fn rename(dir: &HeldDir, from: &EntryName, to: &EntryName) -> io::Result<()> {
    Ok(rustix::fs::renameat(
        dir.handle(),
        from.as_os_str(),
        dir.handle(),
        to.as_os_str(),
    )?)
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

/// The names of the entries of `dir`, `.` and `..` excluded.
pub fn names(dir: &HeldDir) -> io::Result<impl Iterator<Item = io::Result<OsString>>> {
    let entries = rustix::fs::Dir::read_from(dir.handle())?;
    Ok(entries.filter_map(|entry| match entry {
        Ok(entry) => {
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            (name != "." && name != "..").then(|| Ok(name.to_os_string()))
        }
        Err(e) => Some(Err(e.into())),
    }))
}

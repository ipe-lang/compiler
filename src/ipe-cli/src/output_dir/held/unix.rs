//! Unix directory primitives: every act is an `*at` call on a held descriptor, never following a link.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags};

use super::{DirId, EntryKind};

/// An open directory descriptor.
#[derive(Debug)]
pub struct Dir(File);

/// Flags for opening a directory handle.
fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC
}

/// Flags for opening an existing file for reading, never through a link.
fn read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
}

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

/// The identity carried by `meta`.
fn id_of(meta: &std::fs::Metadata) -> DirId {
    DirId {
        dev: meta.dev(),
        ino: meta.ino(),
    }
}

/// Open `path` as a directory, following links on the way.
///
/// # Errors
/// [`io::ErrorKind::NotFound`] when absent; [`io::ErrorKind::NotADirectory`]
/// for a non-directory; another error on another failure.
pub fn open_following(path: &Path) -> io::Result<Dir> {
    let fd = rustix::fs::openat(CWD, path, dir_flags(), Mode::empty())?;
    Ok(Dir(File::from(fd)))
}

/// The identity of the directory looking `path` up now reaches, following links.
///
/// # Errors
/// When `path` cannot be stat'd.
pub fn id_of_path(path: &Path) -> io::Result<DirId> {
    std::fs::metadata(path).map(|meta| id_of(&meta))
}

impl Dir {
    /// Open the subdirectory `name`, failing on a link or a non-directory.
    pub fn open_dir(&self, name: &OsStr) -> io::Result<Self> {
        let flags = dir_flags() | OFlags::NOFOLLOW;
        let fd = rustix::fs::openat(&self.0, name, flags, Mode::empty())?;
        Ok(Self(File::from(fd)))
    }

    /// Classify the entry `name` without following a link.
    pub fn kind(&self, name: &OsStr) -> io::Result<EntryKind> {
        match rustix::fs::statat(&self.0, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => EntryKind::Directory,
                FileType::Symlink => EntryKind::Symlink,
                FileType::RegularFile
                | FileType::Fifo
                | FileType::Socket
                | FileType::CharacterDevice
                | FileType::BlockDevice
                | FileType::Unknown => EntryKind::Other,
            }),
            Err(e) if e == rustix::io::Errno::NOENT => Ok(EntryKind::Absent),
            Err(e) => Err(e.into()),
        }
    }

    /// Create the subdirectory `name`.
    pub fn mkdir(&self, name: &OsStr) -> io::Result<()> {
        Ok(rustix::fs::mkdirat(&self.0, name, dir_mode())?)
    }

    /// Exclusively create the new file `name` for writing.
    pub fn create_new(&self, name: &OsStr) -> io::Result<File> {
        let fd = rustix::fs::openat(&self.0, name, new_file_flags(), file_mode())?;
        Ok(File::from(fd))
    }

    /// Open the existing entry `name` for reading, failing on a link.
    pub fn open_file(&self, name: &OsStr) -> io::Result<File> {
        let fd = rustix::fs::openat(&self.0, name, read_flags(), Mode::empty())?;
        Ok(File::from(fd))
    }

    /// Rename the entry `from` over the entry `to`, both in this directory.
    pub fn rename(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        Ok(rustix::fs::renameat(&self.0, from, &self.0, to)?)
    }

    /// Unlink the non-directory entry `name`; a link is removed, never followed.
    pub fn unlink(&self, name: &OsStr) -> io::Result<()> {
        Ok(rustix::fs::unlinkat(&self.0, name, AtFlags::empty())?)
    }

    /// Remove the empty subdirectory `name`.
    pub fn rmdir(&self, name: &OsStr) -> io::Result<()> {
        Ok(rustix::fs::unlinkat(&self.0, name, AtFlags::REMOVEDIR)?)
    }

    /// The names of this directory's entries, `.` and `..` excluded.
    pub fn names(&self) -> io::Result<impl Iterator<Item = io::Result<OsString>>> {
        let entries = rustix::fs::Dir::read_from(&self.0)?;
        Ok(entries.filter_map(|entry| match entry {
            Ok(entry) => {
                let name = OsStr::from_bytes(entry.file_name().to_bytes());
                (name != "." && name != "..").then(|| Ok(name.to_os_string()))
            }
            Err(e) => Some(Err(e.into())),
        }))
    }

    /// Open the directory above this one through `..`; `None` at the root.
    pub fn parent(&self) -> io::Result<Option<Self>> {
        let fd = rustix::fs::openat(&self.0, "..", dir_flags(), Mode::empty())?;
        let parent = Self(File::from(fd));
        Ok((parent.id()? != self.id()?).then_some(parent))
    }

    /// The identity of this directory.
    pub fn id(&self) -> io::Result<DirId> {
        self.0.metadata().map(|meta| id_of(&meta))
    }
}

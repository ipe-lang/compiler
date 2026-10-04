//! Unix primitives: every entry open is an `openat` on a held descriptor, never following a final link.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::Path;

use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::{EntryName, FileId, FileKind, OpenRefusal};

/// A held directory descriptor.
#[derive(Debug)]
pub struct Dir(File);

/// Flags for opening a directory handle.
fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC
}

/// Flags for opening a file to read: non-blocking, so a FIFO cannot stall the open, and never a controlling terminal.
fn read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC
}

/// Whether `errno` reports a link met where none is followed.
///
/// Linux and most systems answer `ELOOP`; FreeBSD answers `EMLINK` for an
/// `O_NOFOLLOW` open of a link, and NetBSD `EFTYPE`.
fn is_link_errno(errno: Errno) -> bool {
    #[cfg(target_os = "freebsd")]
    if errno == Errno::MLINK {
        return true;
    }
    #[cfg(target_os = "netbsd")]
    if errno == Errno::FTYPE {
        return true;
    }
    errno == Errno::LOOP
}

/// The refusal an `errno` from an open or a stat stands for.
fn refusal(errno: Errno) -> OpenRefusal {
    if errno == Errno::NOENT {
        OpenRefusal::Absent
    } else if is_link_errno(errno) {
        OpenRefusal::Link
    } else if errno == Errno::NXIO {
        OpenRefusal::NotRegular(FileKind::Socket)
    } else if errno == Errno::ACCESS || errno == Errno::PERM {
        OpenRefusal::Denied
    } else {
        OpenRefusal::Io(io::Error::from(errno).kind())
    }
}

/// The refusal an [`io::Error`] from a standard-library call stands for.
fn refusal_of(error: &io::Error) -> OpenRefusal {
    error.raw_os_error().map_or_else(
        || OpenRefusal::Io(error.kind()),
        |raw| refusal(Errno::from_raw_os_error(raw)),
    )
}

/// The kind a stat file type carries.
const fn kind_of_stat_type(file_type: FileType) -> FileKind {
    match file_type {
        FileType::RegularFile => FileKind::Regular,
        FileType::Directory => FileKind::Dir,
        FileType::Symlink => FileKind::Symlink,
        FileType::Fifo => FileKind::Fifo,
        FileType::Socket => FileKind::Socket,
        FileType::CharacterDevice | FileType::BlockDevice => FileKind::Device,
        FileType::Unknown => FileKind::Other,
    }
}

/// The kind a standard-library file type carries.
fn kind_of_type(file_type: std::fs::FileType) -> FileKind {
    if file_type.is_file() {
        FileKind::Regular
    } else if file_type.is_dir() {
        FileKind::Dir
    } else if file_type.is_symlink() {
        FileKind::Symlink
    } else if file_type.is_fifo() {
        FileKind::Fifo
    } else if file_type.is_socket() {
        FileKind::Socket
    } else if file_type.is_char_device() || file_type.is_block_device() {
        FileKind::Device
    } else {
        FileKind::Other
    }
}

/// The identity carried by `meta`.
fn id_of(meta: &std::fs::Metadata) -> FileId {
    FileId {
        dev: meta.dev(),
        ino: meta.ino(),
    }
}

/// The kind and length of the object `file` holds, read from that handle.
pub fn kind_and_len(file: &File) -> Result<(FileKind, u64), OpenRefusal> {
    let meta = file.metadata().map_err(|e| refusal_of(&e))?;
    Ok((kind_of_type(meta.file_type()), meta.len()))
}

/// The identity of the object looking `path` up now reaches, following links.
pub fn id_of_path(path: &Path) -> Result<FileId, OpenRefusal> {
    std::fs::metadata(path)
        .map(|meta| id_of(&meta))
        .map_err(|e| refusal_of(&e))
}

/// Open the path the invoking user named, following links, without blocking.
pub fn open_user_named(path: &Path) -> Result<File, OpenRefusal> {
    rustix::fs::openat(CWD, path, read_flags(), Mode::empty())
        .map(File::from)
        .map_err(refusal)
}

impl Dir {
    /// Open `path` as a directory, following links.
    pub fn open_root(path: &Path) -> Result<Self, OpenRefusal> {
        match rustix::fs::openat(CWD, path, dir_flags(), Mode::empty()) {
            Ok(fd) => Ok(Self(File::from(fd))),
            Err(errno) if errno == Errno::NOTDIR => Err(std::fs::metadata(path).map_or_else(
                |e| refusal_of(&e),
                |meta| OpenRefusal::NotRegular(kind_of_type(meta.file_type())),
            )),
            Err(errno) => Err(refusal(errno)),
        }
    }

    /// Open the subdirectory `name`, never following a link.
    ///
    /// A failure that may stand for a link or a non-directory is classified
    /// by a no-follow stat of `name` on the held handle.
    pub fn child_dir(&self, name: &EntryName) -> Result<Self, OpenRefusal> {
        let flags = dir_flags() | OFlags::NOFOLLOW;
        match rustix::fs::openat(&self.0, name.as_os_str(), flags, Mode::empty()) {
            Ok(fd) => Ok(Self(File::from(fd))),
            Err(errno) if errno == Errno::NOTDIR || is_link_errno(errno) => {
                Err(match self.kind_of(name)? {
                    None => OpenRefusal::Absent,
                    Some(FileKind::Symlink) => OpenRefusal::Link,
                    Some(FileKind::Dir) => refusal(errno),
                    Some(kind) => OpenRefusal::NotRegular(kind),
                })
            }
            Err(errno) => Err(refusal(errno)),
        }
    }

    /// Open the entry `name` to read, never following a link and never blocking.
    pub fn open_regular(&self, name: &EntryName) -> Result<File, OpenRefusal> {
        let flags = read_flags() | OFlags::NOFOLLOW;
        rustix::fs::openat(&self.0, name.as_os_str(), flags, Mode::empty())
            .map(File::from)
            .map_err(refusal)
    }

    /// What the entry `name` is, read without following a link; `None` when absent.
    pub fn kind_of(&self, name: &EntryName) -> Result<Option<FileKind>, OpenRefusal> {
        match rustix::fs::statat(&self.0, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(kind_of_stat_type(FileType::from_raw_mode(
                stat.st_mode,
            )))),
            Err(errno) if errno == Errno::NOENT => Ok(None),
            Err(errno) => Err(refusal(errno)),
        }
    }

    /// The names of this directory's entries, `.` and `..` excluded.
    pub fn names(
        &self,
    ) -> Result<impl Iterator<Item = Result<EntryName, OpenRefusal>>, OpenRefusal> {
        let entries = rustix::fs::Dir::read_from(&self.0).map_err(refusal)?;
        Ok(entries.filter_map(|entry| match entry {
            Ok(entry) => {
                let name = OsStr::from_bytes(entry.file_name().to_bytes());
                (name != "." && name != "..").then(|| EntryName::parse(name))
            }
            Err(errno) => Some(Err(refusal(errno))),
        }))
    }

    /// Open the directory above this one through `..`; `None` at the root.
    pub fn parent(&self) -> Result<Option<Self>, OpenRefusal> {
        let fd = rustix::fs::openat(&self.0, "..", dir_flags(), Mode::empty()).map_err(refusal)?;
        let parent = Self(File::from(fd));
        Ok((parent.id()? != self.id()?).then_some(parent))
    }

    /// The identity of this directory.
    pub fn id(&self) -> Result<FileId, OpenRefusal> {
        self.0
            .metadata()
            .map(|meta| id_of(&meta))
            .map_err(|e| refusal_of(&e))
    }

    /// The held descriptor.
    pub const fn handle(&self) -> &File {
        &self.0
    }
}

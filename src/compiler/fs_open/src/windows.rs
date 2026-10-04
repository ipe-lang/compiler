//! Windows primitives: every entry open is relative to a held directory handle, never through a reparse point.
//!
//! Every open and classification names one entry relative to the held
//! directory handle (`NtCreateFile` with a root directory, through
//! `cap-primitives`), with `FILE_FLAG_OPEN_REPARSE_POINT` so a reparse point
//! at the entry is refused as itself, never traversed. A reparse point set on
//! the held directory afterwards does not redirect those opens: they start
//! from the directory object the handle holds, not from a path. A file is
//! opened without backup semantics, so the open fails on any directory.
//!
//! Listing has no handle-relative form without raw system calls, so it reads
//! the held directory's proven real path, then re-reads the held handle's
//! attributes: a directory that became a junction meanwhile is refused, and
//! every listed name is opened handle-relative afterwards.

use std::fs::File;
use std::io;
use std::os::windows::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use cap_primitives::fs::{OpenOptions, OpenOptionsExt as _};

use crate::{EntryName, FileId, FileKind, HintedKind, OpenRefusal};

/// `FILE_FLAG_BACKUP_SEMANTICS`: allows opening a directory handle.
const BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// `FILE_FLAG_OPEN_REPARSE_POINT`: opens a reparse point itself, never its target.
const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// `FILE_SHARE_READ | FILE_SHARE_WRITE`, without `FILE_SHARE_DELETE`.
const SHARE_NO_DELETE: u32 = 0x1 | 0x2;
/// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`.
const SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
/// `FILE_ATTRIBUTE_DIRECTORY`.
const ATTR_DIRECTORY: u32 = 0x10;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
const ATTR_REPARSE_POINT: u32 = 0x400;
/// `FILE_ATTRIBUTE_DEVICE`.
const ATTR_DEVICE: u32 = 0x40;
/// `ERROR_REPARSE_POINT_ENCOUNTERED`: the typed refusal of a reparse point.
const ERROR_REPARSE_POINT_ENCOUNTERED: i32 = 4395;
/// `ERROR_SHARING_VIOLATION`: another open handle denies the access asked for.
const ERROR_SHARING_VIOLATION: i32 = 32;
/// `ERROR_LOCK_VIOLATION`: another process has locked a region of the file.
const ERROR_LOCK_VIOLATION: i32 = 33;

/// A held directory handle and the reparse-free path proven to name it.
#[derive(Debug)]
pub struct Dir {
    file: File,
    real: PathBuf,
}

/// The refusal an [`io::Error`] stands for.
fn refusal_of(error: &io::Error) -> OpenRefusal {
    match (error.raw_os_error(), error.kind()) {
        (Some(ERROR_REPARSE_POINT_ENCOUNTERED), _) => OpenRefusal::Link,
        (Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION), _) => OpenRefusal::InUse,
        (_, io::ErrorKind::NotFound) => OpenRefusal::Absent,
        (_, io::ErrorKind::PermissionDenied) => OpenRefusal::Denied,
        (_, kind) => OpenRefusal::Io(kind),
    }
}

/// The kind `attributes` name, before the handle's device type is consulted.
const fn kind_of_attributes(attributes: u32) -> Option<FileKind> {
    if attributes & ATTR_REPARSE_POINT != 0 {
        Some(FileKind::Symlink)
    } else if attributes & ATTR_DIRECTORY != 0 {
        Some(FileKind::Dir)
    } else {
        None
    }
}

/// The hint find-data `attributes` carry: a reparse point is a link, never a directory.
///
/// A directory listing of a volume holds files, directories and reparse
/// points; an entry marked a device is another kind, and any other entry is a
/// regular file.
pub const fn hint_of_attributes(attributes: u32) -> HintedKind {
    if attributes & ATTR_REPARSE_POINT != 0 {
        HintedKind::Link
    } else if attributes & ATTR_DIRECTORY != 0 {
        HintedKind::Dir
    } else if attributes & ATTR_DEVICE != 0 {
        HintedKind::Other
    } else {
        HintedKind::Regular
    }
}

/// The name and hint of one listed entry, read from the find data the listing already holds.
fn hinted_entry(
    entry: io::Result<std::fs::DirEntry>,
) -> Result<(EntryName, HintedKind), OpenRefusal> {
    let entry = entry.map_err(|e| refusal_of(&e))?;
    let name = EntryName::parse(&entry.file_name())?;
    let attributes = entry
        .metadata()
        .map_err(|e| refusal_of(&e))?
        .file_attributes();
    Ok((name, hint_of_attributes(attributes)))
}

/// The kind and length of the object `file` holds, read from that handle.
pub fn kind_and_len(file: &File) -> Result<(FileKind, u64), OpenRefusal> {
    let meta = file.metadata().map_err(|e| refusal_of(&e))?;
    if let Some(kind) = kind_of_attributes(meta.file_attributes()) {
        return Ok((kind, meta.len()));
    }
    let device = winapi_util::file::typ(file).map_err(|e| refusal_of(&e))?;
    let kind = if device.is_disk() {
        FileKind::Regular
    } else if device.is_pipe() {
        FileKind::Fifo
    } else if device.is_char() {
        FileKind::Device
    } else {
        FileKind::Other
    };
    Ok((kind, meta.len()))
}

/// Refuse `file` unless it holds a plain directory, never a reparse point.
fn require_plain_dir(file: &File) -> Result<(), OpenRefusal> {
    let attributes = file
        .metadata()
        .map_err(|e| refusal_of(&e))?
        .file_attributes();
    match kind_of_attributes(attributes) {
        Some(FileKind::Dir) => Ok(()),
        Some(FileKind::Symlink) => Err(OpenRefusal::Link),
        Some(kind) => Err(OpenRefusal::NotRegular(kind)),
        None => Err(OpenRefusal::NotRegular(FileKind::Regular)),
    }
}

/// Options opening a directory handle that denies delete sharing and never follows a reparse point.
fn dir_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(SHARE_NO_DELETE)
        .custom_flags(BACKUP_SEMANTICS | OPEN_REPARSE_POINT);
    options
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

/// Options opening a file to read, never through a reparse point; without backup semantics a directory fails to open.
fn read_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(OPEN_REPARSE_POINT);
    options
}

/// Open `real` by path as a directory handle, never through a reparse point at its final component.
fn open_dir_at(real: PathBuf) -> Result<Dir, OpenRefusal> {
    use std::os::windows::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(SHARE_NO_DELETE)
        .custom_flags(BACKUP_SEMANTICS | OPEN_REPARSE_POINT)
        .open(&real)
        .map_err(|e| refusal_of(&e))?;
    require_plain_dir(&file)?;
    Ok(Dir { file, real })
}

/// The volume serial number and file index of the object `file` holds.
fn id_of(file: &File) -> Result<FileId, OpenRefusal> {
    let info = winapi_util::file::information(file).map_err(|e| refusal_of(&e))?;
    Ok(FileId {
        dev: info.volume_serial_number(),
        ino: info.file_index(),
    })
}

/// The identity of the object looking `path` up now reaches, following links.
pub fn id_of_path(path: &Path) -> Result<FileId, OpenRefusal> {
    use std::os::windows::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(BACKUP_SEMANTICS)
        .open(path)
        .map_err(|e| refusal_of(&e))?;
    id_of(&file)
}

/// Open the path the invoking user named, following links.
pub fn open_user_named(path: &Path) -> Result<File, OpenRefusal> {
    File::open(path).map_err(|e| refusal_of(&e))
}

impl Dir {
    /// Open `path` as a directory, following links on the way.
    ///
    /// The canonical path is walked again from the volume root, each level
    /// opened through the held level above it without following a reparse
    /// point, so the returned handle is the one its real path names.
    pub fn open_root(path: &Path) -> Result<Self, OpenRefusal> {
        let real = std::fs::canonicalize(path).map_err(|e| refusal_of(&e))?;
        let mut parts = real.components();
        let (Some(Component::Prefix(prefix)), Some(Component::RootDir)) =
            (parts.next(), parts.next())
        else {
            return Err(OpenRefusal::Io(io::ErrorKind::InvalidInput));
        };
        let mut root = PathBuf::from(prefix.as_os_str());
        root.push(Component::RootDir.as_os_str());
        let mut dir = open_dir_at(root)?;
        for part in parts {
            let Component::Normal(name) = part else {
                return Err(OpenRefusal::Io(io::ErrorKind::InvalidInput));
            };
            dir = dir.child_dir(&EntryName::parse(name)?)?;
        }
        Ok(dir)
    }

    /// Open the entry `name` relative to this handle.
    fn open_at(&self, name: &EntryName, options: &OpenOptions) -> io::Result<File> {
        cap_primitives::fs::open(&self.file, Path::new(name.as_os_str()), options)
    }

    /// Open the subdirectory `name`, refusing a reparse point or a non-directory.
    pub fn child_dir(&self, name: &EntryName) -> Result<Self, OpenRefusal> {
        let file = self
            .open_at(name, &dir_options())
            .map_err(|e| refusal_of(&e))?;
        require_plain_dir(&file)?;
        Ok(Self {
            file,
            real: self.real.join(name.as_os_str()),
        })
    }

    /// Open the entry `name` to read, never through a reparse point.
    ///
    /// A denied open is classified by an attribute-only open of `name`: a
    /// directory or a reparse point answers access denied to a file open. A
    /// sharing or lock violation is decided by its code first, so a file
    /// another program holds open stays in use whatever kind it reports.
    pub fn open_regular(&self, name: &EntryName) -> Result<File, OpenRefusal> {
        match self.open_at(name, &read_options()) {
            Ok(file) => Ok(file),
            Err(e) if refusal_of(&e) == OpenRefusal::Denied => Err(match self.kind_of(name)? {
                None => OpenRefusal::Absent,
                Some(FileKind::Symlink) => OpenRefusal::Link,
                Some(FileKind::Regular) => OpenRefusal::Denied,
                Some(kind) => OpenRefusal::NotRegular(kind),
            }),
            Err(e) => Err(refusal_of(&e)),
        }
    }

    /// What the entry `name` is, read without following a reparse point; `None` when absent.
    ///
    /// Every reparse point counts as a link.
    pub fn kind_of(&self, name: &EntryName) -> Result<Option<FileKind>, OpenRefusal> {
        match self.open_at(name, &stat_options()) {
            Ok(file) => kind_and_len(&file).map(|(kind, _)| Some(kind)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(refusal_of(&e)),
        }
    }

    /// The names of this directory's entries with the hint their find data carries; never opens an entry.
    ///
    /// The listing reads the real path, then the held handle is re-proven, so
    /// a directory that turned into a reparse point before the listing was
    /// read is refused rather than listed through.
    pub fn hinted_names(
        &self,
    ) -> Result<impl Iterator<Item = Result<(EntryName, HintedKind), OpenRefusal>>, OpenRefusal>
    {
        let entries = std::fs::read_dir(&self.real).map_err(|e| refusal_of(&e))?;
        self.reprove()?;
        Ok(entries.map(hinted_entry))
    }

    /// Open the directory above this one; `None` at the volume root.
    ///
    /// The parent holds this directory, so it is not empty and cannot become
    /// a reparse point, and it cannot be renamed while this handle is open.
    pub fn parent(&self) -> Result<Option<Self>, OpenRefusal> {
        self.real
            .parent()
            .map(|parent| open_dir_at(parent.to_path_buf()))
            .transpose()
    }

    /// The identity of this directory.
    pub fn id(&self) -> Result<FileId, OpenRefusal> {
        id_of(&self.file)
    }

    /// The held handle.
    pub const fn handle(&self) -> &File {
        &self.file
    }

    /// The reparse-free real path proven to name this directory.
    pub fn real_path(&self) -> &Path {
        &self.real
    }

    /// Re-read the held handle's attributes, refusing a directory that became a reparse point.
    pub fn reprove(&self) -> Result<(), OpenRefusal> {
        require_plain_dir(&self.file)
    }
}

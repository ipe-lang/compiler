//! Files opened through held directory handles and read under a typed byte bound.
//!
//! A path an untrusted party can influence names a file only at the instant
//! it is resolved: a check on the path followed by an open of the path leaves
//! a window in which a component can be swapped for a link, a FIFO, or a
//! device. This crate closes that window by construction. A [`HeldDir`] is a
//! directory handle; every entry is opened once, relative to it, by a single
//! [`EntryName`], never following a link at the final component, and opened
//! non-blocking so a FIFO cannot stall the open. The opened handle is then
//! proven a regular file by `fstat` on that same handle, and only then becomes
//! a [`RegularFile`] — the one type the capped readers accept. Nothing outside
//! this crate can build a [`RegularFile`] from an arbitrary [`File`]: its
//! fields are private and it has no `From<File>`.
//!
//! A read never trusts the length the proof saw: [`RegularFile::read_bytes`]
//! reads at most one byte past its [`ByteCap`], so a file that grows after the
//! proof is refused as too large, never read without bound.
//!
//! The one open that follows a final link is
//! [`RegularFile::open_user_named`], for a path the invoking user named on the
//! command line: following it is what the user asked for, and the result is
//! still proven regular and read under a cap.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};

mod name;
pub mod win32_name;

pub use name::{EntryName, is_one_spelled_name};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as sys;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as sys;
#[cfg(not(any(unix, windows)))]
compile_error!("held directory handles are implemented for Unix and Windows only");

/// The most bytes one read may return; a file holding more is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteCap(NonZeroU64);

impl ByteCap {
    /// A cap of `bytes`, or `None` for zero.
    #[must_use]
    pub fn new(bytes: u64) -> Option<Self> {
        NonZeroU64::new(bytes).map(Self)
    }

    /// A cap of `bytes`.
    #[must_use]
    pub const fn from_nonzero(bytes: NonZeroU64) -> Self {
        Self(bytes)
    }

    /// The cap in bytes.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// The most entries one directory listing may return; a directory holding more is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryCap(NonZeroU32);

impl EntryCap {
    /// A cap of `entries`, or `None` for zero.
    #[must_use]
    pub fn new(entries: u32) -> Option<Self> {
        NonZeroU32::new(entries).map(Self)
    }

    /// A cap of `entries`.
    #[must_use]
    pub const fn from_nonzero(entries: NonZeroU32) -> Self {
        Self(entries)
    }

    /// The cap in entries.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// What a filesystem object is, read from its own handle or without following a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileKind {
    /// A regular file.
    Regular,
    /// A directory.
    Dir,
    /// A symbolic link (on Windows, any reparse point).
    Symlink,
    /// A FIFO (on Windows, a pipe).
    Fifo,
    /// A Unix-domain socket.
    Socket,
    /// A character or block device.
    Device,
    /// Anything else.
    Other,
}

impl fmt::Display for FileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Regular => "a regular file",
            Self::Dir => "a directory",
            Self::Symlink => "a symbolic link",
            Self::Fifo => "a FIFO",
            Self::Socket => "a socket",
            Self::Device => "a device",
            Self::Other => "a special file",
        })
    }
}

/// Why an entry was not opened or read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenRefusal {
    /// No entry by that name.
    Absent,
    /// A link (on Windows, a reparse point) stands where none is followed.
    Link,
    /// The entry is not the kind asked for: this is what it is.
    NotRegular(FileKind),
    /// The entry exists but may not be opened.
    Denied,
    /// Another program holds the entry open or locked without sharing the access asked for (Windows).
    InUse,
    /// The content is longer than this cap.
    TooLarge(ByteCap),
    /// The directory holds more entries than this cap.
    TooManyEntries(EntryCap),
    /// The name is not one plain entry name.
    BadName,
    /// The content is not valid UTF-8.
    NotUtf8,
    /// Another filesystem failure, of this kind.
    Io(io::ErrorKind),
}

impl fmt::Display for OpenRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => f.write_str("it does not exist"),
            Self::Link => f.write_str("it is a symbolic link, which is never followed here"),
            Self::NotRegular(kind) => write!(f, "it is {kind}, not the kind expected"),
            Self::Denied => f.write_str("permission denied"),
            Self::InUse => f.write_str("another program holds it open"),
            Self::TooLarge(cap) => write!(f, "it is larger than {} bytes", cap.get()),
            Self::TooManyEntries(cap) => write!(f, "it holds more than {} entries", cap.get()),
            Self::BadName => f.write_str("it is not one plain entry name"),
            Self::NotUtf8 => f.write_str("it is not valid UTF-8"),
            Self::Io(kind) => write!(f, "{kind}"),
        }
    }
}

impl std::error::Error for OpenRefusal {}

impl OpenRefusal {
    /// The [`io::ErrorKind`] closest to this refusal.
    #[must_use]
    pub const fn kind(self) -> io::ErrorKind {
        match self {
            Self::Absent => io::ErrorKind::NotFound,
            Self::Denied => io::ErrorKind::PermissionDenied,
            Self::InUse => io::ErrorKind::ResourceBusy,
            Self::NotRegular(FileKind::Dir) => io::ErrorKind::IsADirectory,
            Self::TooLarge(_) => io::ErrorKind::FileTooLarge,
            Self::NotUtf8 => io::ErrorKind::InvalidData,
            Self::Link | Self::NotRegular(_) | Self::BadName | Self::TooManyEntries(_) => {
                io::ErrorKind::InvalidInput
            }
            Self::Io(kind) => kind,
        }
    }

    /// This refusal as an [`io::Error`] of [`OpenRefusal::kind`], carrying the refusal as its source.
    #[must_use]
    pub fn into_io(self) -> io::Error {
        match self {
            Self::Io(kind) => io::Error::from(kind),
            refusal => io::Error::new(refusal.kind(), refusal),
        }
    }
}

/// The volume and file number of a filesystem object, its identity across lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    dev: u64,
    ino: u64,
}

impl FileId {
    /// The identity of the object looking `path` up now reaches, following links.
    ///
    /// # Errors
    /// The [`OpenRefusal`] for a `path` that cannot be looked up.
    pub fn of_path(path: &Path) -> Result<Self, OpenRefusal> {
        sys::id_of_path(path)
    }
}

/// An open directory handle every entry act is relative to.
#[derive(Debug)]
pub struct HeldDir {
    dir: sys::Dir,
}

impl HeldDir {
    /// Open `path` as a directory, following links on the way, its final component included.
    ///
    /// The empty path names the working directory. Used only for a directory
    /// this program does not own the levels of; every level below it is
    /// opened with [`HeldDir::child_dir`].
    ///
    /// # Errors
    /// [`OpenRefusal::Absent`]; [`OpenRefusal::NotRegular`] for a
    /// non-directory; [`OpenRefusal::Link`] for a reparse point on the way
    /// (Windows); another refusal on another failure.
    pub fn open_root(path: &Path) -> Result<Self, OpenRefusal> {
        let target = if path.as_os_str().is_empty() {
            Path::new(".")
        } else {
            path
        };
        sys::Dir::open_root(target).map(|dir| Self { dir })
    }

    /// Open the subdirectory `name`, never following a link.
    ///
    /// # Errors
    /// [`OpenRefusal::Absent`]; [`OpenRefusal::Link`] for a link;
    /// [`OpenRefusal::NotRegular`] for a non-directory; [`OpenRefusal::InUse`]
    /// for a directory another program holds open (Windows); another refusal
    /// on another failure.
    pub fn child_dir(&self, name: &EntryName) -> Result<Self, OpenRefusal> {
        self.dir.child_dir(name).map(|dir| Self { dir })
    }

    /// Open the entry `name` as a regular file, never following a link and never blocking.
    ///
    /// # Errors
    /// [`OpenRefusal::Absent`]; [`OpenRefusal::Link`] for a link;
    /// [`OpenRefusal::NotRegular`] for a directory, FIFO, socket, or device;
    /// [`OpenRefusal::Denied`]; [`OpenRefusal::InUse`] for a file another
    /// program holds open (Windows); another refusal on another failure.
    pub fn open_regular(&self, name: &EntryName) -> Result<RegularFile, OpenRefusal> {
        self.dir.open_regular(name).and_then(RegularFile::prove)
    }

    /// Open the regular file `names` spells below this directory, each level held in turn.
    ///
    /// Every level but the last is opened with [`HeldDir::child_dir`], the
    /// last with [`HeldDir::open_regular`].
    ///
    /// # Errors
    /// [`OpenRefusal::BadName`] for an empty `names`; any refusal of the level
    /// it met.
    pub fn open_rel(&self, names: &[EntryName]) -> Result<RegularFile, OpenRefusal> {
        let Some((last, above)) = names.split_last() else {
            return Err(OpenRefusal::BadName);
        };
        let Some((first, rest)) = above.split_first() else {
            return self.open_regular(last);
        };
        let mut level = self.child_dir(first)?;
        for name in rest {
            level = level.child_dir(name)?;
        }
        level.open_regular(last)
    }

    /// What the entry `name` is, read without following a link; `None` when absent.
    ///
    /// # Errors
    /// The refusal of a failure other than absence.
    pub fn kind_of(&self, name: &EntryName) -> Result<Option<FileKind>, OpenRefusal> {
        self.dir.kind_of(name)
    }

    /// The target the link `name` stores, read relative to this handle; never followed.
    ///
    /// # Errors
    /// [`OpenRefusal::Absent`]; [`OpenRefusal::NotRegular`] for an entry that
    /// is not a link; another refusal on another failure.
    pub fn read_link(&self, name: &EntryName) -> Result<PathBuf, OpenRefusal> {
        self.dir.read_link(name)
    }

    /// Every entry of this directory and its kind, `.` and `..` excluded.
    ///
    /// An entry that vanishes between the listing and its classification is
    /// left out.
    ///
    /// # Errors
    /// [`OpenRefusal::TooManyEntries`] past `cap`; [`OpenRefusal::Link`] when
    /// the held directory turned into a reparse point (Windows);
    /// [`OpenRefusal::BadName`] for a listed name no handle-relative open can
    /// take; another refusal on another failure.
    pub fn entries(&self, cap: EntryCap) -> Result<Vec<(EntryName, FileKind)>, OpenRefusal> {
        let mut found = Vec::new();
        let mut seen: u32 = 0;
        for name in self.dir.names()? {
            let name = name?;
            seen = seen.saturating_add(1);
            if seen > cap.get() {
                return Err(OpenRefusal::TooManyEntries(cap));
            }
            if let Some(kind) = self.dir.kind_of(&name)? {
                found.push((name, kind));
            }
        }
        Ok(found)
    }

    /// Open the directory above this one through the handle, not a path; `None` at the root.
    ///
    /// # Errors
    /// The refusal of a parent that cannot be opened or identified.
    pub fn parent(&self) -> Result<Option<Self>, OpenRefusal> {
        self.dir.parent().map(|dir| dir.map(|dir| Self { dir }))
    }

    /// The identity of the directory this handle holds.
    ///
    /// # Errors
    /// The refusal of a handle that cannot be stat'd.
    pub fn id(&self) -> Result<FileId, OpenRefusal> {
        self.dir.id()
    }

    /// The held handle, for an entry act this crate does not provide.
    #[must_use]
    pub const fn handle(&self) -> &File {
        self.dir.handle()
    }

    /// The reparse-free real path proven to name this directory.
    #[cfg(windows)]
    #[must_use]
    pub fn real_path(&self) -> &Path {
        self.dir.real_path()
    }

    /// Re-read the held handle's attributes, refusing a directory that became a reparse point.
    ///
    /// # Errors
    /// [`OpenRefusal::Link`] for a reparse point; another refusal when the
    /// attributes cannot be read.
    #[cfg(windows)]
    pub fn reprove(&self) -> Result<(), OpenRefusal> {
        self.dir.reprove()
    }
}

/// An open file proven regular from its own handle, with the length that proof saw.
#[derive(Debug)]
pub struct RegularFile {
    file: File,
    len: u64,
}

impl RegularFile {
    /// Open the file the invoking user named at `path`, following a final link.
    ///
    /// The one open in this crate that follows a final component: the user
    /// named that exact path. It is still opened non-blocking and proven
    /// regular, so a FIFO or a device named there is refused.
    ///
    /// # Errors
    /// [`OpenRefusal::Absent`]; [`OpenRefusal::NotRegular`]; [`OpenRefusal::Denied`];
    /// another refusal on another failure.
    pub fn open_user_named(path: &Path) -> Result<Self, OpenRefusal> {
        sys::open_user_named(path).and_then(Self::prove)
    }

    /// Prove `file` regular from its own handle.
    ///
    /// # Errors
    /// [`OpenRefusal::Link`] for a link opened as itself (Windows);
    /// [`OpenRefusal::NotRegular`] for anything else; another refusal when the
    /// handle cannot be stat'd.
    pub fn prove(file: File) -> Result<Self, OpenRefusal> {
        match sys::kind_and_len(&file)? {
            (FileKind::Regular, len) => Ok(Self { file, len }),
            (FileKind::Symlink, _) => Err(OpenRefusal::Link),
            (kind, _) => Err(OpenRefusal::NotRegular(kind)),
        }
    }

    /// How many directory entries name this file now; more than one is a hard link.
    ///
    /// # Errors
    /// The refusal of a handle that cannot be stat'd.
    pub fn link_count(&self) -> Result<u64, OpenRefusal> {
        sys::link_count(&self.file)
    }

    /// The length the proof saw; the file may have changed since.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether the proof saw an empty file.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The whole content, refused when longer than `cap`.
    ///
    /// At most one byte past `cap` is read, so a file that grew after the
    /// proof is refused, never read without bound.
    ///
    /// # Errors
    /// [`OpenRefusal::TooLarge`]; [`OpenRefusal::Io`] on a read failure.
    pub fn read_bytes(self, cap: ByteCap) -> Result<Vec<u8>, OpenRefusal> {
        if self.len > cap.get() {
            return Err(OpenRefusal::TooLarge(cap));
        }
        let mut content = Vec::with_capacity(usize::try_from(self.len).unwrap_or(0));
        self.file
            .take(cap.get().saturating_add(1))
            .read_to_end(&mut content)
            .map_err(|e| OpenRefusal::Io(e.kind()))?;
        let read = u64::try_from(content.len()).unwrap_or(u64::MAX);
        if read > cap.get() {
            return Err(OpenRefusal::TooLarge(cap));
        }
        Ok(content)
    }

    /// The whole content as UTF-8 text, refused when longer than `cap`.
    ///
    /// # Errors
    /// As [`RegularFile::read_bytes`]; [`OpenRefusal::NotUtf8`] for content
    /// that is not valid UTF-8.
    pub fn read_utf8(self, cap: ByteCap) -> Result<String, OpenRefusal> {
        String::from_utf8(self.read_bytes(cap)?).map_err(|_| OpenRefusal::NotUtf8)
    }

    /// At most the first `cap` bytes; a longer file is not refused.
    ///
    /// # Errors
    /// [`OpenRefusal::Io`] on a read failure.
    pub fn read_prefix(self, cap: ByteCap) -> Result<Vec<u8>, OpenRefusal> {
        let mut head = Vec::new();
        self.file
            .take(cap.get())
            .read_to_end(&mut head)
            .map_err(|e| OpenRefusal::Io(e.kind()))?;
        Ok(head)
    }

    /// A reader over the content that fails once it passes `cap`.
    #[must_use]
    pub fn into_reader(self, cap: ByteCap) -> CappedReader {
        CappedReader {
            inner: self.file.take(cap.get().saturating_add(1)),
            cap,
            read: 0,
        }
    }
}

/// A reader over a [`RegularFile`] that fails with [`io::ErrorKind::FileTooLarge`] past its cap.
#[derive(Debug)]
pub struct CappedReader {
    inner: io::Take<File>,
    cap: ByteCap,
    read: u64,
}

impl Read for CappedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read = self
            .read
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if self.read > self.cap.get() {
            return Err(OpenRefusal::TooLarge(self.cap).into_io());
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests;

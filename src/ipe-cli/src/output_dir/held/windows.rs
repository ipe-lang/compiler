//! Windows directory primitives: handle-relative opens, and path acts under a pin.
//!
//! Every open, classification, create, and removal names one entry relative to
//! the held directory handle (`NtCreateFile` with a root directory, through
//! `cap-primitives`), with `FILE_FLAG_OPEN_REPARSE_POINT` so a reparse point at
//! the entry is refused or removed as itself, never traversed. A reparse point
//! set on the held directory afterwards does not redirect those acts: they start
//! from the directory object the handle holds, not from a path.
//!
//! Creating a subdirectory, renaming, and listing have no handle-relative form
//! without raw system calls, so they name the entry by the held directory's
//! proven real path. Each runs under a [`Pin`]: a sentinel file created through
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
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cap_primitives::fs::{OpenOptions, OpenOptionsExt as _};

use super::{DirId, EntryKind};

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
/// The name prefix of a pin sentinel; entries carrying it are never listed.
const PIN_PREFIX: &str = ".ipe-pin-";
/// How many sentinel names a pin tries before giving up.
const PIN_ATTEMPTS: u32 = 8;
/// Device names Windows reserves in every directory, whatever the extension.
const RESERVED_DEVICE_NAMES: [&str; 30] = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM0",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "COM\u{b9}",
    "COM\u{b2}",
    "COM\u{b3}",
    "LPT0",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "LPT\u{b9}",
    "LPT\u{b2}",
    "LPT\u{b3}",
];

/// A held directory handle and the reparse-free path proven to name it.
#[derive(Debug)]
pub struct Dir {
    file: File,
    real: PathBuf,
}

/// The error for a reparse point met where a plain entry was required.
fn reparse_point() -> io::Error {
    io::Error::from_raw_os_error(ERROR_REPARSE_POINT_ENCOUNTERED)
}

/// Whether `error` is the refusal of a reparse point met where a plain directory was required.
#[must_use]
pub fn is_reparse_refusal(error: &io::Error) -> bool {
    error.raw_os_error() == Some(ERROR_REPARSE_POINT_ENCOUNTERED)
}

/// Check that `file` holds a plain directory, never a reparse point.
fn require_plain_dir(file: &File) -> io::Result<()> {
    let attributes = file.metadata()?.file_attributes();
    if attributes & ATTR_REPARSE_POINT != 0 {
        Err(reparse_point())
    } else if attributes & ATTR_DIRECTORY == 0 {
        Err(io::ErrorKind::NotADirectory.into())
    } else {
        Ok(())
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

/// Options removing the opened entry when the handle closes, never following a reparse point.
///
/// Without `directories`, the open fails on a directory.
fn delete_options(directories: bool) -> OpenOptions {
    let flags = if directories {
        DELETE_ON_CLOSE | OPEN_REPARSE_POINT | BACKUP_SEMANTICS
    } else {
        DELETE_ON_CLOSE | OPEN_REPARSE_POINT
    };
    let mut options = OpenOptions::new();
    options
        .access_mode(0)
        .share_mode(SHARE_NO_DELETE)
        .custom_flags(flags);
    options
}

/// Open `real` by path as a directory handle, never through a reparse point at its final component.
fn open_dir_at(real: PathBuf) -> io::Result<Dir> {
    use std::os::windows::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(SHARE_NO_DELETE)
        .custom_flags(BACKUP_SEMANTICS | OPEN_REPARSE_POINT)
        .open(&real)?;
    require_plain_dir(&file)?;
    Ok(Dir { file, real })
}

/// Open `path` as a directory, following links on the way.
///
/// The canonical path is walked again from the volume root, each level opened
/// through the held level above it without following a reparse point, so the
/// returned handle is the one its real path names.
///
/// # Errors
/// [`io::ErrorKind::NotFound`] when absent; [`io::ErrorKind::NotADirectory`]
/// for a non-directory; a reparse refusal ([`is_reparse_refusal`]) for a level
/// that is a reparse point; another error on another failure.
pub fn open_following(path: &Path) -> io::Result<Dir> {
    let real = std::fs::canonicalize(path)?;
    let mut parts = real.components();
    let (Some(Component::Prefix(prefix)), Some(Component::RootDir)) = (parts.next(), parts.next())
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no volume root", real.display()),
        ));
    };
    let mut root = PathBuf::from(prefix.as_os_str());
    root.push(Component::RootDir.as_os_str());
    let mut dir = open_dir_at(root)?;
    for part in parts {
        let Component::Normal(name) = part else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a canonical path", real.display()),
            ));
        };
        dir = dir.open_dir(name)?;
    }
    Ok(dir)
}

/// The identity of the directory looking `path` up now reaches, following links.
///
/// # Errors
/// When `path` cannot be opened.
pub fn id_of_path(path: &Path) -> io::Result<DirId> {
    use std::os::windows::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(BACKUP_SEMANTICS)
        .open(path)?;
    id_of(&file)
}

/// The volume serial number and file index of the object `file` holds.
fn id_of(file: &File) -> io::Result<DirId> {
    let info = winapi_util::file::information(file)?;
    Ok(DirId {
        dev: info.volume_serial_number(),
        ino: info.file_index(),
    })
}

/// Whether `name` is a single plain entry name.
///
/// A separator, `.`, `..`, a `:` (which would address an alternate data
/// stream), or a reserved device name (`CON`, `NUL`, `COM1.txt`, ...) is not.
pub fn is_plain_name(name: &OsStr) -> bool {
    let text = name.to_string_lossy();
    !text.is_empty()
        && text != "."
        && text != ".."
        && !text.chars().any(|c| {
            c.is_control() || matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        })
        && !is_reserved_device_name(&text)
}

/// Whether `text` names a reserved device: its stem before the first inner `.`, trailing spaces trimmed.
fn is_reserved_device_name(text: &str) -> bool {
    let stem = text
        .char_indices()
        .skip(1)
        .find(|&(_, c)| c == '.')
        .and_then(|(at, _)| text.get(..at))
        .unwrap_or(text);
    let stem = stem.trim_end().to_uppercase();
    RESERVED_DEVICE_NAMES.contains(&stem.as_str())
}

/// The error refusing `name` as not a plain entry name.
fn not_plain(name: &OsStr) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{} is not a plain entry name", name.to_string_lossy()),
    )
}

/// Whether `name` is a pin sentinel, which a listing never shows.
fn is_pin_name(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.starts_with(PIN_PREFIX))
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

impl Dir {
    /// Open the entry `name` relative to this handle.
    fn open_at(&self, name: &OsStr, options: &OpenOptions) -> io::Result<File> {
        if is_plain_name(name) {
            cap_primitives::fs::open(&self.file, Path::new(name), options)
        } else {
            Err(not_plain(name))
        }
    }

    /// The real path of the entry `name`, which must be a plain name.
    fn entry(&self, name: &OsStr) -> io::Result<PathBuf> {
        if is_plain_name(name) {
            Ok(self.real.join(name))
        } else {
            Err(not_plain(name))
        }
    }

    /// Pin this directory for the duration of a path act.
    ///
    /// # Errors
    /// A reparse refusal when the directory already is a reparse point; another
    /// error when no sentinel can be created.
    fn pin(&self) -> io::Result<Pin> {
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
            match self.open_at(OsStr::new(&name), &options) {
                Ok(sentinel) => {
                    let pin = Pin {
                        _sentinel: sentinel,
                    };
                    require_plain_dir(&self.file)?;
                    return Ok(pin);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = e,
                Err(e) => return Err(e),
            }
        }
        Err(last)
    }

    /// The attributes of the entry `name`, read without following a reparse point; `None` when absent.
    fn attributes(&self, name: &OsStr) -> io::Result<Option<u32>> {
        match self.open_at(name, &stat_options()) {
            Ok(file) => Ok(Some(file.metadata()?.file_attributes())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Open the subdirectory `name`, failing on a reparse point or a non-directory.
    pub fn open_dir(&self, name: &OsStr) -> io::Result<Self> {
        let file = self.open_at(name, &dir_options())?;
        require_plain_dir(&file)?;
        Ok(Self {
            file,
            real: self.real.join(name),
        })
    }

    /// Classify the entry `name` without following a reparse point.
    ///
    /// Every reparse point counts as a link.
    pub fn kind(&self, name: &OsStr) -> io::Result<EntryKind> {
        Ok(self
            .attributes(name)?
            .map_or(EntryKind::Absent, |attributes| {
                if attributes & ATTR_REPARSE_POINT != 0 {
                    EntryKind::Symlink
                } else if attributes & ATTR_DIRECTORY != 0 {
                    EntryKind::Directory
                } else {
                    EntryKind::Other
                }
            }))
    }

    /// Create the subdirectory `name`.
    pub fn mkdir(&self, name: &OsStr) -> io::Result<()> {
        let path = self.entry(name)?;
        let _pin = self.pin()?;
        std::fs::create_dir(path)
    }

    /// Exclusively create the new file `name` for writing.
    pub fn create_new(&self, name: &OsStr) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .custom_flags(OPEN_REPARSE_POINT);
        self.open_at(name, &options)
    }

    /// Open the existing entry `name` for reading, failing on a reparse point.
    pub fn open_file(&self, name: &OsStr) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(OPEN_REPARSE_POINT);
        let file = self.open_at(name, &options)?;
        if file.metadata()?.file_attributes() & ATTR_REPARSE_POINT != 0 {
            return Err(reparse_point());
        }
        Ok(file)
    }

    /// Rename the entry `from` over the entry `to`, both in this directory.
    pub fn rename(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        let (from, to) = (self.entry(from)?, self.entry(to)?);
        let _pin = self.pin()?;
        std::fs::rename(from, to)
    }

    /// Remove the non-directory entry `name`; a reparse point is removed as itself.
    ///
    /// A directory junction or directory link is removed as the link it is; a
    /// plain directory is refused. A non-directory is removed through an open
    /// that fails on any directory, so a directory swapped in after the check is
    /// never removed; a directory reparse point is removed through an open that
    /// admits directories, so an empty directory swapped in for it in that
    /// window is removed in its place.
    pub fn unlink(&self, name: &OsStr) -> io::Result<()> {
        let attributes = self
            .attributes(name)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        if attributes & ATTR_DIRECTORY == 0 {
            drop(self.open_at(name, &delete_options(false))?);
            Ok(())
        } else if attributes & ATTR_REPARSE_POINT != 0 {
            drop(self.open_at(name, &delete_options(true))?);
            Ok(())
        } else {
            Err(io::ErrorKind::IsADirectory.into())
        }
    }

    /// Remove the empty subdirectory `name`.
    ///
    /// The removal is requested on the handle and takes effect when it closes;
    /// a non-empty directory survives the close, which a second open detects
    /// and reports as [`io::ErrorKind::DirectoryNotEmpty`].
    pub fn rmdir(&self, name: &OsStr) -> io::Result<()> {
        let doomed = self.open_at(name, &delete_options(true))?;
        let id = id_of(&doomed)?;
        drop(doomed);
        match self.open_at(name, &stat_options()) {
            Ok(survivor) if id_of(&survivor)? == id => Err(io::ErrorKind::DirectoryNotEmpty.into()),
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// The names of this directory's entries, pin sentinels excluded.
    ///
    /// The listing handle is opened under a pin; once open it enumerates the
    /// directory object it holds.
    pub fn names(&self) -> io::Result<impl Iterator<Item = io::Result<OsString>>> {
        let entries = {
            let _pin = self.pin()?;
            std::fs::read_dir(&self.real)?
        };
        Ok(entries.filter_map(|entry| match entry {
            Ok(entry) => {
                let name = entry.file_name();
                (!is_pin_name(&name)).then_some(Ok(name))
            }
            Err(e) => Some(Err(e)),
        }))
    }

    /// Open the directory above this one; `None` at the volume root.
    ///
    /// The parent holds this directory, so it is not empty and cannot become a
    /// reparse point, and it cannot be renamed while this handle is open.
    pub fn parent(&self) -> io::Result<Option<Self>> {
        self.real
            .parent()
            .map(|parent| open_dir_at(parent.to_path_buf()))
            .transpose()
    }

    /// The identity of this directory.
    pub fn id(&self) -> io::Result<DirId> {
        id_of(&self.file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh, empty scratch directory unique to this test process.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ipe_held_win_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("make scratch");
        dir
    }

    #[test]
    fn plain_names_are_accepted() {
        for name in [
            "out",
            "a.txt",
            ".ipe-output",
            "console.log",
            "COM10",
            "nul-ish",
            "é.txt",
        ] {
            assert!(is_plain_name(OsStr::new(name)), "{name}");
        }
    }

    #[test]
    fn non_plain_names_are_refused() {
        for name in [
            "",
            ".",
            "..",
            "a\\b",
            "a/b",
            "a:stream",
            "C:",
            "a*",
            "a?",
            "a\"",
            "a<",
            "a>",
            "a|",
            "a\u{1}",
            "CON",
            "con",
            "NUL.txt",
            "nul .txt",
            "Com1",
            "LPT9.log",
            "COM\u{b9}",
            "AUX ",
        ] {
            assert!(!is_plain_name(OsStr::new(name)), "{name:?}");
        }
    }

    #[test]
    fn pin_sentinels_are_hidden_from_listings() {
        assert!(is_pin_name(OsStr::new(".ipe-pin-12-3")));
        assert!(!is_pin_name(OsStr::new(".ipe-output")));
    }

    #[test]
    fn a_non_plain_name_is_refused_before_any_open() {
        let dir = scratch("nonplain");
        let held = open_following(dir.as_path()).unwrap();
        for name in ["..", "a:stream", "NUL", "x\\..\\y"] {
            let refused = held.kind(OsStr::new(name));
            assert!(
                matches!(&refused, Err(e) if e.kind() == io::ErrorKind::InvalidInput),
                "{name}: {refused:?}"
            );
        }
    }

    #[test]
    fn a_pin_leaves_no_sentinel_behind() {
        let dir = scratch("pin");
        let held = open_following(dir.as_path()).unwrap();
        held.mkdir(OsStr::new("sub")).unwrap();
        let names: Vec<_> = held.names().unwrap().map(Result::unwrap).collect();
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
        let held = open_following(dir.as_path()).unwrap();
        let refused = held.rmdir(OsStr::new("full"));
        assert!(
            matches!(&refused, Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty),
            "{refused:?}"
        );
        assert!(dir.as_path().join("full").join("keep.txt").is_file());
        held.rmdir(OsStr::new("empty")).unwrap();
        assert!(!dir.as_path().join("empty").exists());
    }

    #[test]
    fn unlink_refuses_a_plain_directory() {
        let dir = scratch("unlink");
        std::fs::create_dir(dir.as_path().join("sub")).unwrap();
        let held = open_following(dir.as_path()).unwrap();
        let refused = held.unlink(OsStr::new("sub"));
        assert!(
            matches!(&refused, Err(e) if e.kind() == io::ErrorKind::IsADirectory),
            "{refused:?}"
        );
        assert!(dir.as_path().join("sub").is_dir());
    }
}

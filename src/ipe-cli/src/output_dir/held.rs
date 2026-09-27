//! Directory handles held open, so every act names one entry of a proven directory.
//!
//! A path-based check followed by a path-based act leaves a window in which a
//! level can be swapped for a symbolic link. Here every level is opened through
//! the held level above it without following a link, and every create, rename,
//! and unlink names a single entry of a held handle — a link planted at any
//! level is refused, never traversed, and a level swapped after it was opened
//! no longer matters because the held handle still names the real one. The
//! per-platform primitives live in `unix` (descriptor-relative `*at` calls) and
//! `windows` (handle-relative opens; path acts run under a sentinel pin).

use std::ffi::OsStr;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use super::{
    MARKER_HEADER, MARKER_READ_CAP, MARKER_TEXT, OWNERSHIP_MARKER, OutputRefusal, temp_suffix,
};
use crate::{CliError, io_err};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as sys;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as sys;
#[cfg(not(any(unix, windows)))]
compile_error!("held output-directory handles are implemented for Unix and Windows only");

/// Deepest directory nesting [`HeldDir::remove_entry`] descends.
///
/// Each level keeps two handles open (the directory and its listing), so the
/// ceiling also bounds handle use.
pub const MAX_REMOVE_DEPTH: usize = 128;

/// The volume and file number of a directory, its identity across path lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirId {
    dev: u64,
    ino: u64,
}

/// What an entry of a held directory is, read without following a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// No entry by that name.
    Absent,
    /// A directory.
    Directory,
    /// A symbolic link (on Windows, any reparse point).
    Symlink,
    /// Anything else: a regular file, a FIFO, a socket, a device.
    Other,
}

/// An open directory handle and the path it was reached by.
///
/// The path serves diagnostics only; every act goes through the handle.
#[derive(Debug)]
pub struct HeldDir {
    dir: sys::Dir,
    path: PathBuf,
}

impl HeldDir {
    /// Open `path` as a directory, following links on the way.
    ///
    /// Used only for the ancestors of an owned directory, which ipe does not
    /// own; the owned directory itself is always opened with [`HeldDir::open`].
    /// `Ok(None)` when absent.
    ///
    /// # Errors
    /// [`OutputRefusal::NotADirectory`] when `path` is not a directory;
    /// [`OutputRefusal::ReparsePoint`] when a level of it is a reparse point
    /// (Windows); [`CliError::Io`] on another failure.
    pub fn open_following(path: &Path) -> Result<Option<Self>, CliError> {
        let target = if path.as_os_str().is_empty() {
            Path::new(".")
        } else {
            path
        };
        match sys::open_following(target) {
            Ok(dir) => Ok(Some(Self {
                dir,
                path: path.to_path_buf(),
            })),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotADirectory => {
                Err(OutputRefusal::NotADirectory(path.to_path_buf()).into())
            }
            #[cfg(windows)]
            Err(e) if sys::is_reparse_refusal(&e) => {
                Err(OutputRefusal::ReparsePoint(path.to_path_buf()).into())
            }
            Err(e) => Err(io_err(path, e)),
        }
    }

    /// Open `path` as a directory whose final component is never a link.
    ///
    /// The parent is reached following links (it is not ipe's); the final
    /// component is opened through it without following a link. `Ok(None)`
    /// when `path` or its parent is absent.
    ///
    /// # Errors
    /// [`OutputRefusal::Symlink`] or [`OutputRefusal::NotADirectory`] for a
    /// link or a non-directory; [`CliError::Io`] on another failure.
    pub fn open(path: &Path) -> Result<Option<Self>, CliError> {
        let Some(name) = path.file_name() else {
            return Self::open_following(path);
        };
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        Self::open_following(parent)?.map_or(Ok(None), |parent| parent.child(name))
    }

    /// The path this handle was reached by.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The identity of the directory this handle holds.
    ///
    /// # Errors
    /// [`CliError::Io`] when the handle cannot be stat'd.
    pub fn id(&self) -> Result<DirId, CliError> {
        self.dir.id().map_err(|e| io_err(&self.path, e))
    }

    /// Classify the entry `name` without following a link.
    ///
    /// # Errors
    /// [`CliError::Io`] on a failure other than absence.
    pub fn kind_of(&self, name: &OsStr) -> Result<EntryKind, CliError> {
        self.dir
            .kind(name)
            .map_err(|e| io_err(&self.path.join(name), e))
    }

    /// Open the subdirectory `name`, refusing a link or a non-directory.
    ///
    /// `Ok(None)` when absent.
    ///
    /// # Errors
    /// [`OutputRefusal::Symlink`] or [`OutputRefusal::NotADirectory`]; [`CliError::Io`]
    /// on another failure.
    pub fn child(&self, name: &OsStr) -> Result<Option<Self>, CliError> {
        let path = self.path.join(name);
        match self.dir.open_dir(name) {
            Ok(dir) => Ok(Some(Self { dir, path })),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => match self.kind_of(name)? {
                EntryKind::Symlink => Err(OutputRefusal::Symlink(path).into()),
                EntryKind::Other => Err(OutputRefusal::NotADirectory(path).into()),
                EntryKind::Absent | EntryKind::Directory => Err(io_err(&path, e)),
            },
        }
    }

    /// Open the subdirectory `name`, creating it when absent.
    ///
    /// The flag is `true` when this call created it.
    ///
    /// # Errors
    /// As [`HeldDir::child`].
    pub fn create_child(&self, name: &OsStr) -> Result<(Self, bool), CliError> {
        let path = self.path.join(name);
        let created = match self.dir.mkdir(name) {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
            Err(e) => return Err(io_err(&path, e)),
        };
        self.child(name)?.map_or_else(
            || Err(io_err(&path, io::ErrorKind::NotFound.into())),
            |child| Ok((child, created)),
        )
    }

    /// Whether this directory carries a genuine ownership marker.
    ///
    /// The marker must be a regular file (never a link) whose first line is
    /// [`MARKER_HEADER`].
    ///
    /// # Errors
    /// [`CliError::Io`] on a read failure other than absence.
    pub fn has_marker(&self) -> Result<bool, CliError> {
        let name = OsStr::new(OWNERSHIP_MARKER);
        let path = self.path.join(name);
        let file = match self.dir.open_file(name) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => {
                return match self.kind_of(name)? {
                    EntryKind::Symlink | EntryKind::Absent => Ok(false),
                    EntryKind::Directory | EntryKind::Other => Err(io_err(&path, e)),
                };
            }
        };
        let meta = file.metadata().map_err(|e| io_err(&path, e))?;
        if !meta.is_file() {
            return Ok(false);
        }
        let mut head = Vec::new();
        file.take(MARKER_READ_CAP)
            .read_to_end(&mut head)
            .map_err(|e| io_err(&path, e))?;
        Ok(head.starts_with(MARKER_HEADER.as_bytes()))
    }

    /// Whether this directory holds nothing but the marker or an in-flight marker temp file.
    ///
    /// # Errors
    /// [`CliError::Io`] when the directory cannot be listed.
    pub fn is_empty(&self) -> Result<bool, CliError> {
        let names = self.dir.names().map_err(|e| io_err(&self.path, e))?;
        for name in names {
            let name = name.map_err(|e| io_err(&self.path, e))?;
            if !super::is_marker_name(&name.to_string_lossy()) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Mark this directory ipe-owned, or refuse it as user territory.
    ///
    /// Already marked: nothing to do. Empty: the marker is written. Anything
    /// else is refused with [`OutputRefusal::NotIpeOwned`] and left untouched.
    ///
    /// # Errors
    /// [`OutputRefusal::NotIpeOwned`]; [`CliError::Io`] on a filesystem failure.
    pub fn adopt(&self) -> Result<(), CliError> {
        if self.has_marker()? {
            Ok(())
        } else if self.is_empty()? {
            self.write_marker()
        } else {
            Err(OutputRefusal::NotIpeOwned(self.path.clone()).into())
        }
    }

    /// Write the marker atomically through a uniquely named temp file and a rename.
    ///
    /// The temp name (`.ipe-output.<pid>.<n>.tmp`) is the one other name
    /// [`HeldDir::is_empty`] tolerates, so a claim in flight never makes the
    /// directory look user-owned.
    ///
    /// # Errors
    /// [`CliError::Io`] on a filesystem failure.
    pub fn write_marker(&self) -> Result<(), CliError> {
        let tmp = format!("{OWNERSHIP_MARKER}.{}.tmp", temp_suffix());
        self.replace_file(
            OsStr::new(OWNERSHIP_MARKER),
            OsStr::new(&tmp),
            None,
            |file| file.write_all(MARKER_TEXT.as_bytes()),
        )
    }

    /// Replace the file `name` with the result of `fill`, atomically.
    ///
    /// A link at `name` is refused. The content goes to an exclusively created
    /// temp file (`.<name>.ipe-tmp.<pid>.<n>`) that is renamed over `name`, so
    /// nothing is ever written through an existing entry.
    ///
    /// # Errors
    /// [`OutputRefusal::Symlink`]; [`CliError::Io`] on a filesystem failure.
    pub fn write_file(
        &self,
        name: &OsStr,
        permissions: Option<std::fs::Permissions>,
        fill: impl FnOnce(&mut std::fs::File) -> io::Result<()>,
    ) -> Result<(), CliError> {
        if self.kind_of(name)? == EntryKind::Symlink {
            return Err(OutputRefusal::Symlink(self.path.join(name)).into());
        }
        let tmp = format!(".{}.ipe-tmp.{}", name.to_string_lossy(), temp_suffix());
        self.replace_file(name, OsStr::new(&tmp), permissions, fill)
    }

    /// Fill the new file `tmp`, then rename it over `name`; `tmp` is removed on failure.
    fn replace_file(
        &self,
        name: &OsStr,
        tmp: &OsStr,
        permissions: Option<std::fs::Permissions>,
        fill: impl FnOnce(&mut std::fs::File) -> io::Result<()>,
    ) -> Result<(), CliError> {
        let tmp_path = self.path.join(tmp);
        let mut staged = self.dir.create_new(tmp).map_err(|e| io_err(&tmp_path, e))?;
        let filled = fill(&mut staged).and_then(|()| {
            permissions.map_or(Ok(()), |permissions| staged.set_permissions(permissions))
        });
        drop(staged);
        let result = filled.map_err(|e| io_err(&tmp_path, e)).and_then(|()| {
            self.dir
                .rename(tmp, name)
                .map_err(|e| io_err(&self.path.join(name), e))
        });
        if result.is_err() {
            let _ = self.dir.unlink(tmp);
        }
        result
    }

    /// Remove the entry `name` — a whole directory tree or a single file.
    ///
    /// An absent entry is already removed. A link at `name` is refused; a link
    /// met inside the tree is removed as the link it is, never followed.
    ///
    /// # Errors
    /// [`OutputRefusal::Symlink`]; [`OutputRefusal::TooDeep`] for a tree nested
    /// deeper than [`MAX_REMOVE_DEPTH`]; [`CliError::Io`] on a filesystem failure.
    pub fn remove_entry(&self, name: &OsStr) -> Result<(), CliError> {
        match self.kind_of(name)? {
            EntryKind::Absent => Ok(()),
            EntryKind::Symlink => Err(OutputRefusal::Symlink(self.path.join(name)).into()),
            EntryKind::Directory => self.remove_dir(name, 0),
            EntryKind::Other => self.unlink(name),
        }
    }

    /// Unlink the non-directory entry `name`; a link is removed, never followed.
    ///
    /// An absent entry is already removed.
    ///
    /// # Errors
    /// [`CliError::Io`] on a filesystem failure, a directory at `name` included.
    pub fn unlink(&self, name: &OsStr) -> Result<(), CliError> {
        match self.dir.unlink(name) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(&self.path.join(name), e)),
        }
    }

    /// Empty the subdirectory `name` at nesting `depth`, then remove it.
    ///
    /// The subdirectory's handle is released before the removal, since a held
    /// directory cannot be removed on every platform.
    fn remove_dir(&self, name: &OsStr, depth: usize) -> Result<(), CliError> {
        let path = self.path.join(name);
        if depth >= MAX_REMOVE_DEPTH {
            return Err(OutputRefusal::TooDeep {
                path,
                limit: MAX_REMOVE_DEPTH,
            }
            .into());
        }
        if let Some(child) = self.child(name)? {
            child.remove_contents(depth)?;
        }
        match self.dir.rmdir(name) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(&path, e)),
        }
    }

    /// Remove every entry of this directory, which sits at nesting `depth`.
    fn remove_contents(&self, depth: usize) -> Result<(), CliError> {
        let names = self.dir.names().map_err(|e| io_err(&self.path, e))?;
        for name in names {
            let name = match name {
                Ok(name) => name,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(io_err(&self.path, e)),
            };
            match self.kind_of(&name)? {
                EntryKind::Absent => {}
                EntryKind::Directory => self.remove_dir(&name, depth.saturating_add(1))?,
                EntryKind::Symlink | EntryKind::Other => self.unlink(&name)?,
            }
        }
        Ok(())
    }

    /// Open the directory above this one through the handle, not the logical path.
    ///
    /// `Ok(None)` at the filesystem root.
    ///
    /// # Errors
    /// [`CliError::Io`] when the parent cannot be opened or stat'd.
    pub fn parent(&self) -> Result<Option<Self>, CliError> {
        let path = self.path.parent().unwrap_or(&self.path).to_path_buf();
        match self.dir.parent() {
            Ok(dir) => Ok(dir.map(|dir| Self { dir, path })),
            Err(e) => Err(io_err(&path, e)),
        }
    }

    /// Whether looking `path` up now reaches this very directory.
    ///
    /// # Errors
    /// [`CliError::Io`] when `path` cannot be stat'd or the handle cannot be.
    pub fn is_at(&self, path: &Path) -> Result<bool, CliError> {
        let found = sys::id_of_path(path).map_err(|e| io_err(path, e))?;
        Ok(found == self.id()?)
    }

    /// Empty the held subdirectory `child`, then remove the entry `name` it was opened as.
    ///
    /// The contents are removed through `child`'s own handle, so a swap of
    /// `name` after it was opened cannot redirect them; the final removal
    /// re-proves that `name` still names `child` before unlinking it.
    ///
    /// # Errors
    /// [`OutputRefusal::Replaced`] when `name` no longer names `child`;
    /// [`OutputRefusal::Symlink`] for a link there; [`OutputRefusal::TooDeep`];
    /// [`CliError::Io`] on a filesystem failure.
    pub fn remove_proven(&self, name: &OsStr, child: Self) -> Result<(), CliError> {
        child.remove_contents(0)?;
        self.release_proven(name, child)?;
        self.dir
            .rmdir(name)
            .map_err(|e| io_err(&self.path.join(name), e))
    }

    /// Remove the held subdirectory `child`, opened as `name`, when it is empty.
    ///
    /// `false` when it is not: emptiness is proven through `child`'s own
    /// handle, so a non-empty directory is kept without a removal attempt. An
    /// empty one is removed once `name` is re-proven to name it; one refilled
    /// in between is kept.
    ///
    /// # Errors
    /// [`OutputRefusal::Replaced`] when `name` no longer names `child`;
    /// [`OutputRefusal::Symlink`] for a link there; [`CliError::Io`] on another
    /// filesystem failure.
    pub fn remove_empty_dir(&self, name: &OsStr, child: Self) -> Result<bool, CliError> {
        if !child.holds_no_entries()? {
            return Ok(false);
        }
        self.release_proven(name, child)?;
        match self.dir.rmdir(name) {
            Ok(()) => Ok(true),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::AlreadyExists
                ) =>
            {
                Ok(false)
            }
            Err(e) => Err(io_err(&self.path.join(name), e)),
        }
    }

    /// Re-prove that `name` still names the held subdirectory `child`, then release it.
    ///
    /// Every handle to `child` is closed on return, since a held directory
    /// cannot be removed on every platform.
    ///
    /// # Errors
    /// [`OutputRefusal::Replaced`] when `name` no longer names `child`;
    /// [`OutputRefusal::Symlink`] or [`OutputRefusal::NotADirectory`] for a
    /// link or a non-directory there; [`CliError::Io`] on a filesystem failure.
    fn release_proven(&self, name: &OsStr, child: Self) -> Result<(), CliError> {
        let same = match self.child(name)? {
            Some(now) => now.id()? == child.id()?,
            None => false,
        };
        drop(child);
        if same {
            Ok(())
        } else {
            Err(OutputRefusal::Replaced(self.path.join(name)).into())
        }
    }

    /// Whether this directory has no entries at all.
    ///
    /// # Errors
    /// [`CliError::Io`] when the directory cannot be listed.
    fn holds_no_entries(&self) -> Result<bool, CliError> {
        let mut names = self.dir.names().map_err(|e| io_err(&self.path, e))?;
        names.next().map_or(Ok(true), |name| {
            name.map(|_| false).map_err(|e| io_err(&self.path, e))
        })
    }

    /// Unlink every non-directory entry under this directory whose relative path `keep` rejects.
    ///
    /// `rel` is this directory's path relative to the root `keep` judges and is
    /// restored on return. Directories are descended through held handles and
    /// kept; a link is judged and removed as the link it is, never followed.
    ///
    /// # Errors
    /// [`OutputRefusal::TooDeep`] past `max_depth`; [`OutputRefusal::Symlink`]
    /// when a subdirectory is swapped for a link mid-walk; [`CliError::Io`] on a
    /// filesystem failure.
    pub fn prune<F: Fn(&Path) -> bool>(
        &self,
        rel: &mut PathBuf,
        keep: &F,
        depth: usize,
        max_depth: usize,
    ) -> Result<(), CliError> {
        if depth > max_depth {
            return Err(OutputRefusal::TooDeep {
                path: self.path.clone(),
                limit: max_depth,
            }
            .into());
        }
        let names = self.dir.names().map_err(|e| io_err(&self.path, e))?;
        for name in names {
            let name = match name {
                Ok(name) => name,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(io_err(&self.path, e)),
            };
            rel.push(&name);
            let result = match self.kind_of(&name) {
                Ok(EntryKind::Absent) => Ok(()),
                Ok(EntryKind::Directory) => self.child(&name).and_then(|child| {
                    child.map_or(Ok(()), |child| {
                        level_held(child.path());
                        child.prune(rel, keep, depth.saturating_add(1), max_depth)
                    })
                }),
                Ok(EntryKind::Symlink | EntryKind::Other) => {
                    if keep(rel) {
                        Ok(())
                    } else {
                        self.unlink(&name)
                    }
                }
                Err(e) => Err(e),
            };
            rel.pop();
            result?;
        }
        Ok(())
    }

    /// Whether the entry `name` is a regular file holding exactly `contents`.
    ///
    /// A link, a non-file, an absent entry, or any read failure counts as not
    /// holding them, so the caller rewrites.
    #[must_use]
    pub fn holds_contents(&self, name: &OsStr, contents: &[u8]) -> bool {
        let Ok(file) = self.dir.open_file(name) else {
            return false;
        };
        let Ok(len) = u64::try_from(contents.len()) else {
            return false;
        };
        if !file
            .metadata()
            .is_ok_and(|meta| meta.is_file() && meta.len() == len)
        {
            return false;
        }
        let mut existing = Vec::with_capacity(contents.len());
        file.take(len.saturating_add(1))
            .read_to_end(&mut existing)
            .is_ok_and(|_| existing == contents)
    }
}

/// Test-only hook run after each level of an owned-path walk is held.
#[cfg(test)]
pub type LevelHook = Box<dyn FnMut(&Path)>;

#[cfg(test)]
thread_local! {
    static LEVEL_HOOK: std::cell::RefCell<Option<LevelHook>> = const { std::cell::RefCell::new(None) };
}

/// Install (or clear) the hook run after each level of an owned-path walk is held.
///
/// It lets a test swap a level for a link in the window between opening one
/// level and acting through it.
#[cfg(test)]
pub fn set_level_hook(hook: Option<LevelHook>) {
    LEVEL_HOOK.with(|slot| *slot.borrow_mut() = hook);
}

/// Run the test hook, if any, for the level at `path`.
#[cfg(test)]
pub fn level_held(path: &Path) {
    let taken = LEVEL_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(mut hook) = taken {
        hook(path);
        LEVEL_HOOK.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_none() {
                *slot = Some(hook);
            }
        });
    }
}

/// Outside tests there is no hook: holding a level has no side effect.
#[cfg(not(test))]
pub const fn level_held(_path: &Path) {}

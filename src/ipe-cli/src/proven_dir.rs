//! Directories held open by a handle, every ancestor proven on the way down.
//!
//! A path names a directory only at the instant it is resolved: between a
//! check on `/a/b` and a later open of `/a/b/f`, anyone who can write an
//! ancestor can swap a component for a link elsewhere. [`ProvenDir`] closes
//! that gap by construction. It walks the path from `/` one component at a
//! time through held directory handles, opening each with `O_NOFOLLOW |
//! O_DIRECTORY`, and checks the owner and mode of each handle by `fstat`:
//! every ancestor passes [`crate::owner_trust::container_breach`] and the
//! final directory passes [`crate::owner_trust::breach`]. Every later
//! operation — creating, opening, renaming, linking or removing an entry —
//! acts relative to the held handle on a single-component [`EntryName`], so
//! no path is resolved again after the proof.
//!
//! A symbolic link standing for an ancestor is followed only when it lies in
//! a directory already proven and root or the invoker owns it
//! ([`crate::owner_trust::link_owner_admitted`]); its target is then walked
//! under the same checks. A link at the final component is refused. Hosts
//! without Unix ownership (Windows) have nothing to prove a directory by, so
//! both constructors refuse with [`ProvenDirError::Unsupported`] and no
//! handle exists there to misuse.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use crate::owner_trust::Breach;

/// The most symbolic links one walk follows before it is refused.
pub const MAX_LINK_HOPS: usize = 40;

/// The most directories one walk may hold open at once.
pub const MAX_DEPTH: usize = 256;

/// What a walk does on meeting a symbolic link.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinkStep {
    /// The link is the final component, which is never followed.
    RefuseLeaf,
    /// Another user owns the link, so its target is not theirs to choose.
    RefuseUntrusted,
    /// The link is walked to its target under the same checks.
    Follow,
}

/// The step a walk takes at a link owned by `owner`, given whether it is the final component.
#[cfg(unix)]
const fn link_step(owner: u32, invoker: crate::owner_trust::Invoker, is_leaf: bool) -> LinkStep {
    if is_leaf {
        LinkStep::RefuseLeaf
    } else if crate::owner_trust::link_owner_admitted(owner, invoker) {
        LinkStep::Follow
    } else {
        LinkStep::RefuseUntrusted
    }
}

/// One plain path component, the only name a [`ProvenDir`] entry operation takes.
///
/// It is the name every handle-relative open shares, so an operation can name
/// only an entry directly inside the proven directory.
pub use ipe_fs_open::EntryName;

/// Why a directory was not proven, or an entry operation inside one failed.
#[derive(Debug)]
pub enum ProvenDirError {
    /// This host has no file ownership to prove a directory by.
    Unsupported,
    /// The path is relative, so there is no fixed root to walk it from.
    NotAbsolute(PathBuf),
    /// A component is absent and the walk was not asked to create it.
    Absent(PathBuf),
    /// A component is not a directory.
    NotADirectory(PathBuf),
    /// The final component is a symbolic link.
    SymlinkLeaf(PathBuf),
    /// An ancestor is a symbolic link neither root nor the invoker owns.
    UntrustedLink(PathBuf),
    /// A user other than the invoker could write or replace entries in a component.
    Untrusted {
        /// The refused component.
        path: PathBuf,
        /// Who else could write it.
        breach: Breach,
    },
    /// The walk followed more than [`MAX_LINK_HOPS`] symbolic links.
    TooManyLinks(PathBuf),
    /// The walk would hold more than [`MAX_DEPTH`] directories open.
    TooDeep(PathBuf),
    /// An entry opened as a file is a directory, FIFO, device or socket.
    NotRegularFile(PathBuf),
    /// A filesystem call failed.
    Io {
        /// The component the call acted on.
        path: PathBuf,
        /// The failure.
        source: io::Error,
    },
}

impl ProvenDirError {
    /// The component a refusal names, when it names one.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Unsupported => None,
            Self::NotAbsolute(path)
            | Self::Absent(path)
            | Self::NotADirectory(path)
            | Self::SymlinkLeaf(path)
            | Self::UntrustedLink(path)
            | Self::TooManyLinks(path)
            | Self::TooDeep(path)
            | Self::NotRegularFile(path)
            | Self::Untrusted { path, .. }
            | Self::Io { path, .. } => Some(path),
        }
    }

    /// The I/O error this refusal stands for, its path dropped.
    #[must_use]
    pub fn into_io(self) -> io::Error {
        match self {
            Self::Io { source, .. } => source,
            Self::Unsupported => io::ErrorKind::Unsupported.into(),
            Self::NotAbsolute(_) | Self::NotRegularFile(_) => io::ErrorKind::InvalidInput.into(),
            Self::Absent(_) => io::ErrorKind::NotFound.into(),
            Self::NotADirectory(_) => io::ErrorKind::NotADirectory.into(),
            Self::SymlinkLeaf(_) | Self::UntrustedLink(_) | Self::Untrusted { .. } => {
                io::ErrorKind::PermissionDenied.into()
            }
            Self::TooManyLinks(_) => sys::link_loop_error(),
            Self::TooDeep(_) => sys::too_deep_error(),
        }
    }
}

/// Whether a walk creates the components it finds absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Walk {
    /// Every component must already exist.
    Existing,
    /// An absent component is created mode `0700`.
    Create,
}

/// The permissions an entry created by [`ProvenDir::create_file`] requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewFileMode {
    /// Mode `0600`: read and write for the owner alone.
    OwnerOnly,
    /// Mode `0644`: written by the owner, readable by every user.
    WorldReadable,
}

/// A directory held open, with its every ancestor proven unwritable by other users.
#[derive(Debug)]
pub struct ProvenDir {
    /// The held handle every entry operation acts through.
    handle: sys::Handle,
    /// The path the directory was asked for, for diagnostics.
    path: PathBuf,
}

impl ProvenDir {
    /// Hold the existing directory `path` open once every component is proven.
    ///
    /// # Errors
    /// A [`ProvenDirError`] naming the first component that failed its proof.
    pub fn open(path: &Path) -> Result<Self, ProvenDirError> {
        Self::walk(path, Walk::Existing)
    }

    /// Hold the directory `path` open, creating absent components mode `0700`.
    ///
    /// # Errors
    /// A [`ProvenDirError`] naming the first component that failed its proof.
    pub fn create(path: &Path) -> Result<Self, ProvenDirError> {
        Self::walk(path, Walk::Create)
    }

    /// Walk `path` from `/` under `walk`, holding the final directory.
    fn walk(path: &Path, walk: Walk) -> Result<Self, ProvenDirError> {
        let handle = sys::walk(path, walk)?;
        Ok(Self {
            handle,
            path: path.to_path_buf(),
        })
    }

    /// The path the directory was asked for.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The path of the entry `name` inside this directory, for diagnostics.
    #[must_use]
    pub fn path_of(&self, name: &EntryName) -> PathBuf {
        self.path.join(name.as_os_str())
    }

    /// Create the new file `name` for writing, exclusively.
    ///
    /// An existing entry there, a symbolic link included, is refused, never
    /// truncated or followed.
    ///
    /// # Errors
    /// The failed `openat`.
    pub fn create_file(&self, name: &EntryName, mode: NewFileMode) -> io::Result<File> {
        sys::create_file(&self.handle, name, mode)
    }

    /// Open the regular file `name` read-only, never through a link.
    ///
    /// The entry is inspected without following a link before it is opened,
    /// so a device, FIFO or socket is refused without the side effects an
    /// open of it could have; the opened handle is inspected again, so an
    /// entry swapped in between is refused too.
    ///
    /// # Errors
    /// [`ProvenDirError::NotRegularFile`] when `name` is not a regular file,
    /// or [`ProvenDirError::Io`] when inspecting or opening it failed.
    pub fn open_file(&self, name: &EntryName) -> Result<File, ProvenDirError> {
        sys::open_file(&self.handle, name, &self.path_of(name))
    }

    /// Rename the entry `from` to `to`, both inside this directory.
    ///
    /// # Errors
    /// The failed `renameat`.
    pub fn rename(&self, from: &EntryName, to: &EntryName) -> io::Result<()> {
        sys::rename(&self.handle, from, to)
    }

    /// Hard-link the entry `from` to the unused name `to`, both inside this directory.
    ///
    /// # Errors
    /// The failed `linkat`; an existing `to` is refused.
    pub fn hard_link(&self, from: &EntryName, to: &EntryName) -> io::Result<()> {
        sys::hard_link(&self.handle, from, to)
    }

    /// Remove the non-directory entry `name`.
    ///
    /// # Errors
    /// The failed `unlinkat`.
    pub fn remove_file(&self, name: &EntryName) -> io::Result<()> {
        sys::remove_file(&self.handle, name)
    }

    /// Whether nothing, not even a dangling link, holds the name `name`.
    ///
    /// # Errors
    /// The failed `fstatat`, other than the entry being absent.
    pub fn is_vacant(&self, name: &EntryName) -> io::Result<bool> {
        sys::is_vacant(&self.handle, name)
    }
}

/// The walk and entry operations of a host with Unix ownership.
#[cfg(unix)]
mod sys {
    use std::collections::VecDeque;
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io;
    use std::os::fd::AsFd as _;
    use std::os::unix::ffi::OsStringExt as _;
    use std::path::{Component, Path, PathBuf};

    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    use rustix::io::Errno;

    use super::{
        EntryName, LinkStep, MAX_DEPTH, MAX_LINK_HOPS, NewFileMode, ProvenDirError, Walk, link_step,
    };
    use crate::owner_trust::{Invoker, Stamp, breach, container_breach};

    /// A held directory handle.
    pub type Handle = File;

    /// One step of a walk.
    enum Step {
        /// Descend into the named entry.
        Name(OsString),
        /// Return to the parent of the current directory.
        Parent,
    }

    /// A directory the walk holds open, and the path it was reached by.
    struct Held {
        dir: File,
        path: PathBuf,
    }

    /// What `fstatat` without following a link found at a name.
    enum Found {
        /// Nothing holds the name.
        Absent,
        /// A symbolic link owned by the carried uid.
        Link(u32),
        /// Any other entry.
        Other,
    }

    /// The error of a walk that followed too many links.
    pub fn link_loop_error() -> io::Error {
        Errno::LOOP.into()
    }

    /// The error of a walk nested too deep.
    pub fn too_deep_error() -> io::Error {
        Errno::NAMETOOLONG.into()
    }

    /// Flags for opening one directory component, never through a link.
    fn dir_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    /// The walk steps of `path`: its normal components and `..`, with `/` and `.` dropped.
    fn steps_of(path: &Path) -> Vec<Step> {
        path.components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(Step::Name(name.to_os_string())),
                Component::ParentDir => Some(Step::Parent),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
            })
            .collect()
    }

    /// The I/O refusal of `errno` on `path`.
    fn io_at(path: &Path, errno: Errno) -> ProvenDirError {
        ProvenDirError::Io {
            path: path.to_path_buf(),
            source: errno.into(),
        }
    }

    /// Refuse the held `dir` at `path` when `rule` finds another user could write it.
    fn prove(
        dir: &File,
        path: &Path,
        invoker: Invoker,
        rule: fn(Stamp, Invoker) -> Option<crate::owner_trust::Breach>,
    ) -> Result<(), ProvenDirError> {
        let meta = dir.metadata().map_err(|source| ProvenDirError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        rule(Stamp::of(&meta), invoker).map_or(Ok(()), |breach| {
            Err(ProvenDirError::Untrusted {
                path: path.to_path_buf(),
                breach,
            })
        })
    }

    /// What holds `name` under `parent`, without following a link.
    fn find(parent: &Held, name: &OsStr, shown: &Path) -> Result<Found, ProvenDirError> {
        match rustix::fs::statat(parent.dir.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink => {
                Ok(Found::Link(stat.st_uid))
            }
            Ok(_) => Ok(Found::Other),
            Err(errno) if errno == Errno::NOENT => Ok(Found::Absent),
            Err(errno) => Err(io_at(shown, errno)),
        }
    }

    /// Open the directory `name` under `parent`, never through a link.
    fn open_dir(parent: &Held, name: &OsStr, shown: &Path) -> Result<File, ProvenDirError> {
        match rustix::fs::openat(parent.dir.as_fd(), name, dir_flags(), Mode::empty()) {
            Ok(fd) => Ok(File::from(fd)),
            Err(errno) if errno == Errno::NOENT => Err(ProvenDirError::Absent(shown.to_path_buf())),
            Err(errno) if errno == Errno::NOTDIR => {
                Err(ProvenDirError::NotADirectory(shown.to_path_buf()))
            }
            Err(errno) => Err(io_at(shown, errno)),
        }
    }

    /// Create the directory `name` under `parent` mode `0700`; one already there is kept.
    fn make_dir(parent: &Held, name: &OsStr, shown: &Path) -> Result<(), ProvenDirError> {
        match rustix::fs::mkdirat(parent.dir.as_fd(), name, Mode::RWXU) {
            Ok(()) => Ok(()),
            Err(errno) if errno == Errno::EXIST => Ok(()),
            Err(errno) => Err(io_at(shown, errno)),
        }
    }

    /// The target of the link `name` under `parent`.
    fn read_link(parent: &Held, name: &OsStr, shown: &Path) -> Result<PathBuf, ProvenDirError> {
        rustix::fs::readlinkat(parent.dir.as_fd(), name, Vec::new())
            .map(|target| PathBuf::from(OsString::from_vec(target.into_bytes())))
            .map_err(|errno| io_at(shown, errno))
    }

    /// Hold `/` open once it passes the ancestor rule.
    fn open_root(invoker: Invoker) -> Result<Held, ProvenDirError> {
        let path = PathBuf::from("/");
        let dir = rustix::fs::open(path.as_path(), dir_flags(), Mode::empty())
            .map(File::from)
            .map_err(|errno| io_at(&path, errno))?;
        prove(&dir, &path, invoker, container_breach)?;
        Ok(Held { dir, path })
    }

    /// Walk the absolute `path` from `/` through held handles, returning the final one.
    ///
    /// Each directory is opened relative to its already-proven parent and
    /// proven on its own handle: every ancestor against
    /// [`container_breach`], the final directory against [`breach`]. The
    /// walk is bounded: at most [`MAX_LINK_HOPS`] links are followed, each
    /// target is at most one kernel `PATH_MAX`, and at most [`MAX_DEPTH`]
    /// directories are held at once.
    pub fn walk(path: &Path, walk: Walk) -> Result<File, ProvenDirError> {
        if !path.is_absolute() {
            return Err(ProvenDirError::NotAbsolute(path.to_path_buf()));
        }
        let invoker = Invoker::current();
        let mut held = vec![open_root(invoker)?];
        let mut pending: VecDeque<Step> = steps_of(path).into();
        let mut hops = 0usize;
        while let Some(step) = pending.pop_front() {
            let name = match step {
                Step::Parent => {
                    if held.len() > 1 {
                        held.pop();
                    }
                    continue;
                }
                Step::Name(name) => name,
            };
            let Some(parent) = held.last() else {
                return Err(ProvenDirError::Absent(path.to_path_buf()));
            };
            let shown = parent.path.join(&name);
            match find(parent, &name, &shown)? {
                Found::Link(owner) => match link_step(owner, invoker, pending.is_empty()) {
                    LinkStep::RefuseLeaf => return Err(ProvenDirError::SymlinkLeaf(shown)),
                    LinkStep::RefuseUntrusted => {
                        return Err(ProvenDirError::UntrustedLink(shown));
                    }
                    LinkStep::Follow => {
                        hops += 1;
                        if hops > MAX_LINK_HOPS {
                            return Err(ProvenDirError::TooManyLinks(shown));
                        }
                        let target = read_link(parent, &name, &shown)?;
                        if target.is_absolute() {
                            held.truncate(1);
                        }
                        for step in steps_of(&target).into_iter().rev() {
                            pending.push_front(step);
                        }
                        continue;
                    }
                },
                Found::Absent if walk == Walk::Create => make_dir(parent, &name, &shown)?,
                Found::Absent => return Err(ProvenDirError::Absent(shown)),
                Found::Other => {}
            }
            if held.len() >= MAX_DEPTH {
                return Err(ProvenDirError::TooDeep(shown));
            }
            let dir = open_dir(parent, &name, &shown)?;
            prove(&dir, &shown, invoker, container_breach)?;
            held.push(Held { dir, path: shown });
        }
        let Some(last) = held.pop() else {
            return Err(ProvenDirError::Absent(path.to_path_buf()));
        };
        prove(&last.dir, &last.path, invoker, breach)?;
        Ok(last.dir)
    }

    /// Create `name` under `dir` exclusively for writing, requesting `mode`.
    pub fn create_file(dir: &File, name: &EntryName, mode: NewFileMode) -> io::Result<File> {
        let owner = Mode::RUSR | Mode::WUSR;
        let mode = match mode {
            NewFileMode::OwnerOnly => owner,
            NewFileMode::WorldReadable => owner | Mode::RGRP | Mode::ROTH,
        };
        let flags = OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::NOCTTY
            | OFlags::CLOEXEC;
        rustix::fs::openat(dir.as_fd(), name.as_os_str(), flags, mode)
            .map(File::from)
            .map_err(Into::into)
    }

    /// Open the regular file `name` under `dir`, shown as `shown`, read-only.
    ///
    /// The entry is inspected by `fstatat` without following a link before
    /// it is opened, and the opened handle by `fstat` after.
    pub fn open_file(dir: &File, name: &EntryName, shown: &Path) -> Result<File, ProvenDirError> {
        let not_regular = || ProvenDirError::NotRegularFile(shown.to_path_buf());
        let stat = rustix::fs::statat(dir.as_fd(), name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|errno| io_at(shown, errno))?;
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => {}
            FileType::Symlink => return Err(io_at(shown, Errno::LOOP)),
            FileType::Directory
            | FileType::Fifo
            | FileType::Socket
            | FileType::CharacterDevice
            | FileType::BlockDevice
            | FileType::Unknown => return Err(not_regular()),
        }
        let flags =
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
        let file = rustix::fs::openat(dir.as_fd(), name.as_os_str(), flags, Mode::empty())
            .map(File::from)
            .map_err(|errno| io_at(shown, errno))?;
        let opened = rustix::fs::fstat(&file).map_err(|errno| io_at(shown, errno))?;
        if FileType::from_raw_mode(opened.st_mode) == FileType::RegularFile {
            Ok(file)
        } else {
            Err(not_regular())
        }
    }

    /// Rename `from` to `to` inside `dir`.
    pub fn rename(dir: &File, from: &EntryName, to: &EntryName) -> io::Result<()> {
        rustix::fs::renameat(dir.as_fd(), from.as_os_str(), dir.as_fd(), to.as_os_str())
            .map_err(Into::into)
    }

    /// Hard-link `from` to `to` inside `dir`, never following a link at `from`.
    pub fn hard_link(dir: &File, from: &EntryName, to: &EntryName) -> io::Result<()> {
        rustix::fs::linkat(
            dir.as_fd(),
            from.as_os_str(),
            dir.as_fd(),
            to.as_os_str(),
            AtFlags::empty(),
        )
        .map_err(Into::into)
    }

    /// Remove the non-directory `name` under `dir`.
    pub fn remove_file(dir: &File, name: &EntryName) -> io::Result<()> {
        rustix::fs::unlinkat(dir.as_fd(), name.as_os_str(), AtFlags::empty()).map_err(Into::into)
    }

    /// Whether nothing holds `name` under `dir`.
    pub fn is_vacant(dir: &File, name: &EntryName) -> io::Result<bool> {
        match rustix::fs::statat(dir.as_fd(), name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(false),
            Err(errno) if errno == Errno::NOENT => Ok(true),
            Err(errno) => Err(errno.into()),
        }
    }
}

/// A host without Unix ownership: no directory is ever proven, so no handle exists.
///
/// Windows ACLs grant access by security descriptor, not by an owner and
/// mode bits, and none of the Unix proof carries over; a secret-housing
/// directory is refused there rather than trusted unproven.
#[cfg(not(unix))]
mod sys {
    use std::convert::Infallible;
    use std::fs::File;
    use std::io;
    use std::path::Path;

    use super::{EntryName, NewFileMode, ProvenDirError, Walk};

    /// The handle no walk here ever produces.
    pub type Handle = Infallible;

    /// The error of a walk that followed too many links.
    pub fn link_loop_error() -> io::Error {
        io::ErrorKind::Unsupported.into()
    }

    /// The error of a walk nested too deep.
    pub fn too_deep_error() -> io::Error {
        io::ErrorKind::Unsupported.into()
    }

    /// Refuse: nothing proves a directory here.
    pub const fn walk(_path: &Path, _walk: Walk) -> Result<Handle, ProvenDirError> {
        Err(ProvenDirError::Unsupported)
    }

    /// Unreachable: no handle exists.
    pub const fn create_file(dir: &Handle, _: &EntryName, _: NewFileMode) -> io::Result<File> {
        match *dir {}
    }

    /// Unreachable: no handle exists.
    pub const fn open_file(dir: &Handle, _: &EntryName, _: &Path) -> Result<File, ProvenDirError> {
        match *dir {}
    }

    /// Unreachable: no handle exists.
    pub const fn rename(dir: &Handle, _: &EntryName, _: &EntryName) -> io::Result<()> {
        match *dir {}
    }

    /// Unreachable: no handle exists.
    pub const fn hard_link(dir: &Handle, _: &EntryName, _: &EntryName) -> io::Result<()> {
        match *dir {}
    }

    /// Unreachable: no handle exists.
    pub const fn remove_file(dir: &Handle, _: &EntryName) -> io::Result<()> {
        match *dir {}
    }

    /// Unreachable: no handle exists.
    pub const fn is_vacant(dir: &Handle, _: &EntryName) -> io::Result<bool> {
        match *dir {}
    }
}

#[cfg(test)]
mod tests;

//! Directory handles held open, so every act names one entry of a proven directory.
//!
//! A path-based check followed by a path-based act leaves a window in which a
//! level can be swapped for a symbolic link. Here every level is opened through
//! the held level above it without following a link, and every create, rename,
//! and unlink names a single entry of a held handle — a link planted at any
//! level is refused, never traversed, and a level swapped after it was opened
//! no longer matters because the held handle still names the real one. This
//! holds from the first held level (the anchor) down: the levels above it are
//! not ipe's and are opened following links ([`HeldDir::open_following`]), so a
//! caller proves what the anchor is on its canonical path.
//!
//! A subdirectory is removed only through [`Released`], a proof that its name
//! still named the held directory the instant its handles were let go, and only
//! by a primitive that removes nothing but an empty directory — a file, a link,
//! or a populated tree swapped in at the name is refused, never removed.
//!
//! A directory becomes ipe's only inside [`HeldDir::claim`]: a no-replace
//! create of [`CLAIM_FILE`] linearizes claimants and an exclusive lock on it
//! serializes them, so the emptiness check and the marker it licenses are one
//! locked step. A directory is ipe's only when [`HeldDir::owned_now`] reads a
//! genuine marker and no claim file through the one held handle.
//!
//! Opening, classifying, reading, and identifying a held level go through
//! [`ipe_fs_open`], the one home of handle-relative opens; the per-platform
//! write acts live in `unix` (descriptor-relative `*at` calls) and `windows`
//! (handle-relative creates and deletes; path acts run under a sentinel pin).

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use ipe_fs_open::{ByteCap, EntryName, FileId, FileKind, OpenRefusal, RegularFile};

use super::{
    CLAIM_FILE, CLAIM_POLL, MARKER_HEADER, MARKER_READ_CAP, MARKER_TEXT, MAX_CLAIM_POLLS,
    OWNERSHIP_MARKER, OutputRefusal, Tolerated, temp_suffix, tolerated_entry,
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
pub type DirId = ipe_fs_open::FileId;

/// The one byte a claim file holds once its claim has started publishing the marker.
const FINALIZING: u8 = b'1';

/// Who owns a held directory, as [`HeldDir::ownership`] reads it for a preflight.
///
/// Only [`HeldDir::owned_now`] decides ownership; this reading serves the
/// checks that run before a claim and the messages they give.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    /// It carries a genuine ownership marker.
    Marked,
    /// A claim file is present: a claim runs, or a crashed one awaits takeover.
    Claiming,
    /// It holds nothing but a regular file at the marker or the claim name.
    Empty,
    /// It holds something else and carries no marker: user territory.
    User,
}

/// Whether a held directory is ipe's now, the one ownership decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedNow {
    /// A genuine marker is linked and no claim file exists.
    Owned,
    /// A genuine marker is linked beside a claim file, whose claim decides.
    Claiming,
    /// No genuine marker is linked.
    Unowned,
}

/// Proof that a directory is ipe's, built only by [`HeldDir::claim`].
#[must_use]
#[derive(Debug)]
pub struct Claimed(());

/// Where a claim stands, read from the length of its locked claim file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimPhase {
    /// Nothing published yet: the claim file is empty.
    Pending,
    /// The claim file holds [`FINALIZING`]: a marker may have been published.
    Finalizing,
}

/// What the marker name of a held directory holds.
#[derive(Debug)]
enum MarkerState {
    /// No entry by that name.
    Absent,
    /// A singly linked regular file whose first line is [`MARKER_HEADER`], held open.
    Genuine(RegularFile),
    /// Anything else: another kind, another header, or a file linked elsewhere too.
    NotGenuine,
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
    dir: ipe_fs_open::HeldDir,
    path: PathBuf,
}

/// The [`Released`] proof, with fields no code outside this submodule can set.
///
/// A struct literal cannot name a private field from outside its module, so
/// the only way to produce a `Released` is `Released::new`, called solely
/// from [`HeldDir::release_proven`].
mod released {
    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};

    /// Proof that an entry named a held subdirectory the instant its last handle was released.
    ///
    /// Only [`HeldDir::release_proven`](super::HeldDir::release_proven) makes
    /// one, and [`HeldDir::rmdir_released`](super::HeldDir::rmdir_released) is
    /// the only removal of a subdirectory, so no subdirectory is ever removed
    /// by a name that was not re-proven first.
    #[derive(Debug)]
    pub(super) struct Released<'n> {
        name: &'n OsStr,
        path: PathBuf,
    }

    impl<'n> Released<'n> {
        /// Construct the proof that `name` still names the held subdirectory at `path`.
        ///
        /// Called only by [`HeldDir::release_proven`](super::HeldDir::release_proven).
        pub(super) const fn new(name: &'n OsStr, path: PathBuf) -> Self {
            Self { name, path }
        }

        /// The re-proven name.
        pub(super) const fn name(&self) -> &'n OsStr {
            self.name
        }

        /// The re-proven path.
        pub(super) fn path(&self) -> &Path {
            &self.path
        }

        /// Consume the proof, returning the path it names.
        pub(super) fn into_path(self) -> PathBuf {
            self.path
        }
    }
}
use released::Released;

/// What removing a re-proven, released subdirectory found at its name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rmdir {
    /// The empty directory was removed.
    Removed,
    /// Nothing is there any more.
    Vanished,
    /// A directory holding entries is there, at this path; it is kept.
    Refilled(PathBuf),
}

/// Whether a failed directory removal met something other than a directory at the name.
///
/// A file answers `NotADirectory` on both platforms, a Unix symbolic link
/// too; a Windows reparse point is refused before the removal.
fn is_replacement(error: &io::Error) -> bool {
    #[cfg(windows)]
    if sys::is_reparse_refusal(error) {
        return true;
    }
    error.kind() == io::ErrorKind::NotADirectory
}

/// The error for an act on `path` that failed with `error`.
///
/// An entry another program holds open (Windows) is refused with
/// [`OutputRefusal::InUse`], whose message names the fix; anything else is a
/// [`CliError::Io`].
fn act_err(path: &Path, error: io::Error) -> CliError {
    #[cfg(windows)]
    if sys::is_in_use(&error) {
        return OutputRefusal::InUse(path.to_path_buf()).into();
    }
    io_err(path, error)
}

/// The error for an open or read of `path` that `refusal` turned back.
///
/// An entry another program holds open is refused with
/// [`OutputRefusal::InUse`], as [`act_err`] refuses a write act on one.
fn refused(path: &Path, refusal: OpenRefusal) -> CliError {
    match refusal {
        OpenRefusal::InUse => OutputRefusal::InUse(path.to_path_buf()).into(),
        OpenRefusal::Absent
        | OpenRefusal::Link
        | OpenRefusal::NotRegular(_)
        | OpenRefusal::Denied
        | OpenRefusal::TooLarge(_)
        | OpenRefusal::TooManyEntries(_)
        | OpenRefusal::BadName
        | OpenRefusal::NotUtf8
        | OpenRefusal::Io(_) => act_err(path, refusal.into_io()),
    }
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
        match ipe_fs_open::HeldDir::open_root(path) {
            Ok(dir) => Ok(Some(Self {
                dir,
                path: path.to_path_buf(),
            })),
            Err(OpenRefusal::Absent) => Ok(None),
            Err(OpenRefusal::NotRegular(_) | OpenRefusal::Io(io::ErrorKind::NotADirectory)) => {
                Err(OutputRefusal::NotADirectory(path.to_path_buf()).into())
            }
            #[cfg(windows)]
            Err(OpenRefusal::Link) => Err(OutputRefusal::ReparsePoint(path.to_path_buf()).into()),
            Err(refusal) => Err(refused(path, refusal)),
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
        self.dir
            .id()
            .map_err(|refusal| refused(&self.path, refusal))
    }

    /// The entry `name` of this directory as one plain entry name.
    ///
    /// # Errors
    /// [`CliError::Io`] of [`io::ErrorKind::InvalidInput`] when it is not one.
    fn entry(&self, name: &OsStr) -> Result<EntryName, CliError> {
        EntryName::new(name).ok_or_else(|| {
            act_err(
                &self.path.join(name),
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} is not a plain entry name", name.to_string_lossy()),
                ),
            )
        })
    }

    /// Classify the entry `name` without following a link.
    ///
    /// # Errors
    /// [`CliError::Io`] on a failure other than absence.
    pub fn kind_of(&self, name: &OsStr) -> Result<EntryKind, CliError> {
        let entry = self.entry(name)?;
        match self.dir.kind_of(&entry) {
            Ok(None) => Ok(EntryKind::Absent),
            Ok(Some(FileKind::Dir)) => Ok(EntryKind::Directory),
            Ok(Some(FileKind::Symlink)) => Ok(EntryKind::Symlink),
            Ok(Some(
                FileKind::Regular
                | FileKind::Fifo
                | FileKind::Socket
                | FileKind::Device
                | FileKind::Other,
            )) => Ok(EntryKind::Other),
            Err(refusal) => Err(refused(&self.path.join(name), refusal)),
        }
    }

    /// Open the subdirectory `name`, refusing a link or a non-directory.
    ///
    /// `Ok(None)` when absent.
    ///
    /// # Errors
    /// [`OutputRefusal::Symlink`] or [`OutputRefusal::NotADirectory`]; [`CliError::Io`]
    /// on another failure.
    pub fn child(&self, name: &OsStr) -> Result<Option<Self>, CliError> {
        let entry = self.entry(name)?;
        let path = self.path.join(name);
        match self.dir.child_dir(&entry) {
            Ok(dir) => Ok(Some(Self { dir, path })),
            Err(OpenRefusal::Absent) => Ok(None),
            Err(OpenRefusal::Link) => Err(OutputRefusal::Symlink(path).into()),
            Err(OpenRefusal::NotRegular(_)) => Err(OutputRefusal::NotADirectory(path).into()),
            Err(refusal) => Err(refused(&path, refusal)),
        }
    }

    /// Open the subdirectory `name`, creating it when absent.
    ///
    /// The flag is `true` when this call created it.
    ///
    /// # Errors
    /// As [`HeldDir::child`].
    pub fn create_child(&self, name: &OsStr) -> Result<(Self, bool), CliError> {
        let entry = self.entry(name)?;
        let path = self.path.join(name);
        let created = match sys::mkdir(&self.dir, &entry) {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
            Err(e) => return Err(act_err(&path, e)),
        };
        self.child(name)?.map_or_else(
            || Err(act_err(&path, io::ErrorKind::NotFound.into())),
            |child| Ok((child, created)),
        )
    }

    /// What the marker name holds, read without following a link.
    ///
    /// A genuine marker is a regular file linked only here whose first line
    /// is [`MARKER_HEADER`]; a link, another kind, another header, or a
    /// hard link shared with another entry is no marker, and is never written
    /// through or removed.
    ///
    /// # Errors
    /// [`CliError::Io`] on an open or read failure other than absence.
    fn genuine_marker(&self) -> Result<MarkerState, CliError> {
        let name = self.entry(OsStr::new(OWNERSHIP_MARKER))?;
        let path = self.path.join(OWNERSHIP_MARKER);
        let marker = match self.dir.open_regular(&name) {
            Ok(marker) => marker,
            Err(OpenRefusal::Absent) => return Ok(MarkerState::Absent),
            Err(OpenRefusal::Link | OpenRefusal::NotRegular(_)) => {
                return Ok(MarkerState::NotGenuine);
            }
            Err(refusal) => return Err(refused(&path, refusal)),
        };
        if ipe_fs_open::link_count(marker.handle()).map_err(|refusal| refused(&path, refusal))? != 1
        {
            return Ok(MarkerState::NotGenuine);
        }
        let mut head = Vec::new();
        marker
            .handle()
            .take(MARKER_READ_CAP)
            .read_to_end(&mut head)
            .map_err(|e| act_err(&path, e))?;
        Ok(if head.starts_with(MARKER_HEADER.as_bytes()) {
            MarkerState::Genuine(marker)
        } else {
            MarkerState::NotGenuine
        })
    }

    /// Whether this directory is ipe's now, read through this one handle.
    ///
    /// Owned only when a genuine marker is linked, no claim file exists, and
    /// the marker name still names the marker file read first: the held
    /// marker pins its identity, and only a claim whose claim file exists
    /// ever unlinks a marker.
    ///
    /// # Errors
    /// [`CliError::Io`] on a filesystem failure.
    pub fn owned_now(&self) -> Result<OwnedNow, CliError> {
        let MarkerState::Genuine(marker) = self.genuine_marker()? else {
            return Ok(OwnedNow::Unowned);
        };
        claim_reached(ClaimPoint::MarkerRead, &self.path);
        if self.claim_present()? {
            return Ok(OwnedNow::Claiming);
        }
        let name = self.entry(OsStr::new(OWNERSHIP_MARKER))?;
        Ok(if self.still_named(&name, marker.handle())? {
            OwnedNow::Owned
        } else {
            OwnedNow::Unowned
        })
    }

    /// Whether anything is at the claim name.
    ///
    /// A name another claimant is deleting (Windows) counts as present.
    ///
    /// # Errors
    /// [`CliError::Io`] on a failure other than absence.
    fn claim_present(&self) -> Result<bool, CliError> {
        let name = self.entry(OsStr::new(CLAIM_FILE))?;
        match self.dir.kind_of(&name) {
            Ok(found) => Ok(found.is_some()),
            Err(OpenRefusal::Denied) => Ok(true),
            Err(refusal) => Err(refused(&self.path.join(CLAIM_FILE), refusal)),
        }
    }

    /// Whether the entry `name` still names the object `file` holds.
    ///
    /// A name another process is deleting (Windows) no longer names it.
    ///
    /// # Errors
    /// [`CliError::Io`] when either side cannot be stat'd.
    fn still_named(&self, name: &EntryName, file: &File) -> Result<bool, CliError> {
        let path = self.path.join(name.as_os_str());
        let held = FileId::of_file(file).map_err(|refusal| refused(&path, refusal))?;
        match self.dir.entry_id(name) {
            Ok(found) => Ok(found == Some(held)),
            Err(OpenRefusal::Denied) => Ok(false),
            Err(refusal) => Err(refused(&path, refusal)),
        }
    }

    /// Unlink the entry `name` only while it still names the object `file` holds.
    ///
    /// `false` when it names something else, which is left in place.
    ///
    /// # Errors
    /// [`CliError::Io`] on a filesystem failure.
    fn unlink_ours(&self, name: &EntryName, file: &File) -> Result<bool, CliError> {
        if !self.still_named(name, file)? {
            return Ok(false);
        }
        match sys::unlink(&self.dir, name) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(act_err(&self.path.join(name.as_os_str()), e)),
        }
    }

    /// Whether this directory holds an entry other than a regular file at the marker or the claim name.
    ///
    /// The listing stops at the first foreign entry, so it is bounded by the
    /// two tolerated names. An entry whose kind cannot be read is foreign.
    ///
    /// # Errors
    /// [`CliError::Io`] when the directory cannot be listed.
    fn has_foreign_entry(&self) -> Result<bool, CliError> {
        let names = sys::names(&self.dir).map_err(|e| act_err(&self.path, e))?;
        for name in names {
            let name = match name {
                Ok(name) => name,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(act_err(&self.path, e)),
            };
            let Some(entry) = EntryName::new(&name) else {
                return Ok(true);
            };
            let foreign = match self.dir.kind_of(&entry) {
                Ok(None) => false,
                Ok(Some(kind)) => tolerated_entry(&name, kind) == Tolerated::Foreign,
                Err(OpenRefusal::Denied) => true,
                Err(refusal) => return Err(refused(&self.path.join(&name), refusal)),
            };
            if foreign {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether this directory holds nothing but a regular file at the marker or the claim name.
    ///
    /// # Errors
    /// [`CliError::Io`] when the directory cannot be listed.
    pub fn is_empty(&self) -> Result<bool, CliError> {
        Ok(!self.has_foreign_entry()?)
    }

    /// Who owns this directory, read without writing, for a preflight only.
    ///
    /// A directory found non-empty is read again: a concurrent claim
    /// publishes its marker before it fills the directory, so only a
    /// directory still unmarked and unclaimed on the second read is user
    /// territory.
    ///
    /// # Errors
    /// [`CliError::Io`] on a filesystem failure.
    pub fn ownership(&self) -> Result<Ownership, CliError> {
        if self.claim_present()? {
            return Ok(Ownership::Claiming);
        }
        if matches!(self.genuine_marker()?, MarkerState::Genuine(_)) {
            return Ok(Ownership::Marked);
        }
        if self.is_empty()? {
            return Ok(Ownership::Empty);
        }
        if self.claim_present()? {
            return Ok(Ownership::Claiming);
        }
        Ok(
            if matches!(self.genuine_marker()?, MarkerState::Genuine(_)) {
                Ownership::Marked
            } else {
                Ownership::User
            },
        )
    }

    /// Make this directory ipe's, or refuse it as user territory.
    ///
    /// Already owned: nothing to do. Otherwise the claim file is created (or
    /// an existing one opened) and locked exclusively, and under that lock
    /// the directory is checked empty, the marker published by a no-replace
    /// create, and the directory checked again before the claim file is
    /// unlinked. A claimant waits at most `MAX_CLAIM_POLLS` polls for a held
    /// lock. User entries are never touched.
    ///
    /// # Errors
    /// [`OutputRefusal::NotIpeOwned`] for user territory or a planted
    /// marker or claim name; [`OutputRefusal::ClaimBusy`] past the wait
    /// bound; [`OutputRefusal::ClaimLockUnavailable`] when the filesystem
    /// refuses the lock; [`OutputRefusal::ClaimInterrupted`] when a crashed
    /// claim left foreign entries beside its marker; [`CliError::Io`] on a
    /// filesystem failure.
    pub fn claim(&self) -> Result<Claimed, CliError> {
        let name = self.entry(OsStr::new(CLAIM_FILE))?;
        for attempt in 0..MAX_CLAIM_POLLS {
            if attempt > 0 {
                std::thread::sleep(CLAIM_POLL);
            }
            if self.owned_now()? == OwnedNow::Owned {
                return Ok(Claimed(()));
            }
            let Some(claim) = self.lock_claim(&name)? else {
                claim_reached(ClaimPoint::Busy, &self.path);
                continue;
            };
            claim_reached(ClaimPoint::AfterLock, &self.path);
            if !self.still_named(&name, claim.handle())? {
                continue;
            }
            return self.claim_locked(&name, &claim);
        }
        Err(OutputRefusal::ClaimBusy {
            dir: self.path.clone(),
            waited: CLAIM_POLL.saturating_mul(MAX_CLAIM_POLLS),
        }
        .into())
    }

    /// Create or open the claim file `name` and take its exclusive lock.
    ///
    /// `None` when another claimant holds the lock or is deleting the name,
    /// so the claim tries again.
    ///
    /// # Errors
    /// [`OutputRefusal::NotIpeOwned`] for anything but a regular file at the
    /// name; [`OutputRefusal::ClaimLockUnavailable`] when the lock is refused
    /// for another reason; [`CliError::Io`] on a filesystem failure.
    fn lock_claim(&self, name: &EntryName) -> Result<Option<RegularFile>, CliError> {
        let path = self.path.join(CLAIM_FILE);
        let file = match sys::create_claim(&self.dir, name) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                match sys::open_claim(&self.dir, name) {
                    Ok(file) => file,
                    Err(e) => {
                        self.refuse_a_foreign_claim_name(name)?;
                        if e.kind() == io::ErrorKind::NotFound || sys::is_claim_pending(&e) {
                            return Ok(None);
                        }
                        return Err(act_err(&path, e));
                    }
                }
            }
            Err(e) => {
                self.refuse_a_foreign_claim_name(name)?;
                if sys::is_claim_pending(&e) {
                    return Ok(None);
                }
                return Err(act_err(&path, e));
            }
        };
        let claim = match RegularFile::prove(file) {
            Ok(claim) => claim,
            Err(OpenRefusal::Link | OpenRefusal::NotRegular(_)) => {
                return Err(OutputRefusal::NotIpeOwned(self.path.clone()).into());
            }
            Err(refusal) => return Err(refused(&path, refusal)),
        };
        match claim.handle().try_lock() {
            Ok(()) => Ok(Some(claim)),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => Err(OutputRefusal::ClaimLockUnavailable {
                dir: self.path.clone(),
                kind: e.kind(),
            }
            .into()),
        }
    }

    /// Refuse the directory when something other than a regular file sits at the claim name.
    ///
    /// # Errors
    /// [`OutputRefusal::NotIpeOwned`] for a link, a directory, or a special
    /// file there.
    fn refuse_a_foreign_claim_name(&self, name: &EntryName) -> Result<(), CliError> {
        match self.dir.kind_of(name) {
            Ok(Some(kind)) if kind != FileKind::Regular => {
                Err(OutputRefusal::NotIpeOwned(self.path.clone()).into())
            }
            Ok(_) | Err(_) => Ok(()),
        }
    }

    /// Decide the claim whose file `claim`, linked at `name`, this claimant holds locked.
    ///
    /// # Errors
    /// As [`HeldDir::claim`].
    fn claim_locked(&self, name: &EntryName, claim: &RegularFile) -> Result<Claimed, CliError> {
        let Some(phase) = self.claim_phase(claim)? else {
            return Err(OutputRefusal::NotIpeOwned(self.path.clone()).into());
        };
        match (phase, self.genuine_marker()?) {
            (ClaimPhase::Pending, MarkerState::NotGenuine) => {
                self.unlink_ours(name, claim.handle())?;
                Err(OutputRefusal::NotIpeOwned(self.path.clone()).into())
            }
            (ClaimPhase::Finalizing, MarkerState::NotGenuine) => {
                self.unlink_ours(name, claim.handle())?;
                Err(OutputRefusal::ClaimInterrupted(self.path.clone()).into())
            }
            (ClaimPhase::Pending, MarkerState::Genuine(_)) => self.commit(name, claim),
            (ClaimPhase::Finalizing, MarkerState::Genuine(_)) => {
                if self.has_foreign_entry()? {
                    Err(OutputRefusal::ClaimInterrupted(self.path.clone()).into())
                } else {
                    self.commit(name, claim)
                }
            }
            (ClaimPhase::Pending | ClaimPhase::Finalizing, MarkerState::Absent) => {
                self.publish(name, claim)
            }
        }
    }

    /// The phase the locked claim file records; `None` for a file no claim wrote.
    ///
    /// A claim file is believed only when it is linked only here and holds
    /// nothing or exactly [`FINALIZING`].
    ///
    /// # Errors
    /// [`CliError::Io`] when the file cannot be stat'd or read.
    fn claim_phase(&self, claim: &RegularFile) -> Result<Option<ClaimPhase>, CliError> {
        let path = self.path.join(CLAIM_FILE);
        let mut handle: &File = claim.handle();
        if ipe_fs_open::link_count(handle).map_err(|refusal| refused(&path, refusal))? != 1 {
            return Ok(None);
        }
        let len = handle.metadata().map_err(|e| act_err(&path, e))?.len();
        if len == 0 {
            return Ok(Some(ClaimPhase::Pending));
        }
        if len != 1 {
            return Ok(None);
        }
        let mut byte = [0_u8; 1];
        handle
            .seek(SeekFrom::Start(0))
            .and_then(|_| handle.read_exact(&mut byte))
            .map_err(|e| act_err(&path, e))?;
        Ok((byte == [FINALIZING]).then_some(ClaimPhase::Finalizing))
    }

    /// Check the directory empty, publish the marker, and check it again, all under the claim lock.
    ///
    /// # Errors
    /// As [`HeldDir::claim`].
    fn publish(&self, name: &EntryName, claim: &RegularFile) -> Result<Claimed, CliError> {
        if self.has_foreign_entry()? {
            self.unlink_ours(name, claim.handle())?;
            return Err(OutputRefusal::NotIpeOwned(self.path.clone()).into());
        }
        claim_reached(ClaimPoint::AfterPreCheck, &self.path);
        self.mark_finalizing(claim)?;
        let Some(marker) = self.publish_marker()? else {
            self.unlink_ours(name, claim.handle())?;
            return Err(OutputRefusal::NotIpeOwned(self.path.clone()).into());
        };
        claim_reached(ClaimPoint::AfterPublish, &self.path);
        if self.has_foreign_entry()? {
            let marker_name = self.entry(OsStr::new(OWNERSHIP_MARKER))?;
            self.unlink_ours(&marker_name, &marker)?;
            self.unlink_ours(name, claim.handle())?;
            return Err(OutputRefusal::NotIpeOwned(self.path.clone()).into());
        }
        claim_reached(ClaimPoint::BeforeCommit, &self.path);
        let committed = self.commit(name, claim);
        drop(marker);
        committed
    }

    /// Record in the locked claim file that this claim is publishing its marker.
    ///
    /// The byte is written at offset zero and synced, so a crash after the
    /// marker lands is read back as `Finalizing`.
    ///
    /// # Errors
    /// [`CliError::Io`] on a write failure.
    fn mark_finalizing(&self, claim: &RegularFile) -> Result<(), CliError> {
        let mut handle: &File = claim.handle();
        handle
            .seek(SeekFrom::Start(0))
            .and_then(|_| handle.write_all(&[FINALIZING]))
            .and_then(|()| handle.sync_data())
            .map_err(|e| act_err(&self.path.join(CLAIM_FILE), e))
    }

    /// Publish the marker by a no-replace create, returning its handle; `None` when the name is taken.
    ///
    /// Nothing at the marker name is ever replaced or written through.
    ///
    /// # Errors
    /// [`CliError::Io`] on a filesystem failure.
    fn publish_marker(&self) -> Result<Option<File>, CliError> {
        let name = self.entry(OsStr::new(OWNERSHIP_MARKER))?;
        let path = self.path.join(OWNERSHIP_MARKER);
        let mut marker = match sys::create_new(&self.dir, &name) {
            Ok(marker) => marker,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(None),
            Err(e) => return Err(act_err(&path, e)),
        };
        match marker
            .write_all(MARKER_TEXT.as_bytes())
            .and_then(|()| marker.sync_data())
        {
            Ok(()) => Ok(Some(marker)),
            Err(e) => {
                let _ = self.unlink_ours(&name, &marker);
                Err(act_err(&path, e))
            }
        }
    }

    /// Commit the claim: unlink the claim file this claimant holds locked at `name`.
    ///
    /// The lock is released when the caller drops `claim`.
    ///
    /// # Errors
    /// [`CliError::Io`] on a filesystem failure.
    fn commit(&self, name: &EntryName, claim: &RegularFile) -> Result<Claimed, CliError> {
        self.unlink_ours(name, claim.handle())?;
        Ok(Claimed(()))
    }

    /// Replace the file `name` with the result of `fill`, atomically.
    ///
    /// A link at `name` is refused. The content goes to an exclusively created
    /// temp file (`.<name>.ipe-tmp.<pid>.<n>`) that is renamed over `name`, so
    /// nothing is ever written through an existing entry.
    ///
    /// The marker and claim names are refused: no product write forges or
    /// clobbers either.
    ///
    /// # Errors
    /// [`OutputRefusal::UnsafeComponent`] for the marker or claim name;
    /// [`OutputRefusal::Symlink`]; [`CliError::Io`] on a filesystem failure.
    pub fn write_file(
        &self,
        name: &OsStr,
        permissions: Option<std::fs::Permissions>,
        fill: impl FnOnce(&mut std::fs::File) -> io::Result<()>,
    ) -> Result<(), CliError> {
        if name == OWNERSHIP_MARKER || name == CLAIM_FILE {
            return Err(OutputRefusal::UnsafeComponent(self.path.join(name)).into());
        }
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
        let (target, staging) = (self.entry(name)?, self.entry(tmp)?);
        let tmp_path = self.path.join(tmp);
        let mut staged = sys::create_new(&self.dir, &staging).map_err(|e| act_err(&tmp_path, e))?;
        let filled = fill(&mut staged).and_then(|()| {
            permissions.map_or(Ok(()), |permissions| staged.set_permissions(permissions))
        });
        drop(staged);
        let result = filled.map_err(|e| act_err(&tmp_path, e)).and_then(|()| {
            sys::rename(&self.dir, &staging, &target).map_err(|e| act_err(&self.path.join(name), e))
        });
        if result.is_err() {
            let _ = sys::unlink(&self.dir, &staging);
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
        let entry = self.entry(name)?;
        match sys::unlink(&self.dir, &entry) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(act_err(&self.path.join(name), e)),
        }
    }

    /// Empty the subdirectory `name` at nesting `depth`, then remove it.
    ///
    /// An absent subdirectory is already removed. The removal goes through
    /// [`HeldDir::remove_held`], so it re-proves the name first.
    fn remove_dir(&self, name: &OsStr, depth: usize) -> Result<(), CliError> {
        if depth >= MAX_REMOVE_DEPTH {
            return Err(OutputRefusal::TooDeep {
                path: self.path.join(name),
                limit: MAX_REMOVE_DEPTH,
            }
            .into());
        }
        self.child(name)?
            .map_or(Ok(()), |child| self.remove_held(name, child, depth))
    }

    /// Empty the held subdirectory `child` (at nesting `depth`), then remove the entry `name` it was opened as.
    ///
    /// The contents are removed through `child`'s own handle, so a swap of
    /// `name` after it was opened cannot redirect them; the final removal
    /// re-proves that `name` still names `child`. An entry that vanishes after
    /// the proof is already removed.
    fn remove_held(&self, name: &OsStr, child: Self, depth: usize) -> Result<(), CliError> {
        child.remove_contents(depth)?;
        let released = self.release_proven(name, child)?;
        match self.rmdir_released(released)? {
            Rmdir::Removed | Rmdir::Vanished => Ok(()),
            Rmdir::Refilled(path) => Err(act_err(&path, io::ErrorKind::DirectoryNotEmpty.into())),
        }
    }

    /// Remove every entry of this directory, which sits at nesting `depth`.
    fn remove_contents(&self, depth: usize) -> Result<(), CliError> {
        let names = sys::names(&self.dir).map_err(|e| act_err(&self.path, e))?;
        for name in names {
            let name = match name {
                Ok(name) => name,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(act_err(&self.path, e)),
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
            Err(refusal) => Err(refused(&path, refusal)),
        }
    }

    /// Whether looking `path` up now reaches this very directory.
    ///
    /// # Errors
    /// [`CliError::Io`] when `path` cannot be stat'd or the handle cannot be.
    pub fn is_at(&self, path: &Path) -> Result<bool, CliError> {
        let found = DirId::of_path(path).map_err(|refusal| refused(path, refusal))?;
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
    /// [`OutputRefusal::InUse`] for an entry another program holds open
    /// (Windows); [`CliError::Io`] on another filesystem failure.
    pub fn remove_proven(&self, name: &OsStr, child: Self) -> Result<(), CliError> {
        self.remove_held(name, child, 0)
    }

    /// Remove the held subdirectory `child`, opened as `name`, when it is empty.
    ///
    /// `false` when it is not: emptiness is proven through `child`'s own
    /// handle, so a non-empty directory is kept without a removal attempt. An
    /// empty one is removed once `name` is re-proven to name it; one refilled
    /// in between is kept.
    ///
    /// # Errors
    /// [`OutputRefusal::Replaced`] when `name` no longer names `child`, or
    /// names a non-directory by the time it is removed;
    /// [`OutputRefusal::Symlink`] for a link there; [`OutputRefusal::InUse`]
    /// for an entry another program holds open (Windows); [`CliError::Io`] on
    /// another filesystem failure.
    pub fn remove_empty_dir(&self, name: &OsStr, child: Self) -> Result<bool, CliError> {
        if !child.holds_no_entries()? {
            return Ok(false);
        }
        let released = self.release_proven(name, child)?;
        Ok(matches!(self.rmdir_released(released)?, Rmdir::Removed))
    }

    /// Re-prove that `name` still names the held subdirectory `child`, then release it.
    ///
    /// Every handle to `child` is closed on return, since a held directory
    /// cannot be removed on every platform. The returned proof is the only way
    /// to reach [`HeldDir::rmdir_released`].
    ///
    /// # Errors
    /// [`OutputRefusal::Replaced`] when `name` no longer names `child`;
    /// [`OutputRefusal::Symlink`] or [`OutputRefusal::NotADirectory`] for a
    /// link or a non-directory there; [`CliError::Io`] on a filesystem failure.
    fn release_proven<'n>(&self, name: &'n OsStr, child: Self) -> Result<Released<'n>, CliError> {
        let same = match self.child(name)? {
            Some(now) => now.id()? == child.id()?,
            None => false,
        };
        drop(child);
        let path = self.path.join(name);
        if same {
            Ok(Released::new(name, path))
        } else {
            Err(OutputRefusal::Replaced(path).into())
        }
    }

    /// Remove the subdirectory `released` proved, through the empty-directory-only primitive.
    ///
    /// Whatever was swapped in at the name after the proof is never removed
    /// unless it is itself an empty directory: a non-directory or a Unix
    /// symbolic link is refused as a replacement, and a directory holding
    /// entries is reported refilled and kept. On Windows a directory junction
    /// swapped in between the attribute check and the removal call is removed
    /// as the junction it is — the link only, its target untouched, no data
    /// loss — rather than refused.
    ///
    /// # Errors
    /// [`OutputRefusal::Replaced`] for a non-directory or a Unix symbolic link
    /// at the name; [`OutputRefusal::InUse`] for an entry another program
    /// holds open (Windows); [`CliError::Io`] on another filesystem failure.
    fn rmdir_released(&self, released: Released<'_>) -> Result<Rmdir, CliError> {
        let entry = self.entry(released.name())?;
        subdir_released(released.path());
        let path = released.into_path();
        match sys::rmdir(&self.dir, &entry) {
            Ok(()) => Ok(Rmdir::Removed),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Rmdir::Vanished),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::AlreadyExists
                ) =>
            {
                Ok(Rmdir::Refilled(path))
            }
            Err(e) if is_replacement(&e) => Err(OutputRefusal::Replaced(path).into()),
            Err(e) => Err(act_err(&path, e)),
        }
    }

    /// Whether this directory has no entries at all.
    ///
    /// # Errors
    /// [`CliError::Io`] when the directory cannot be listed.
    fn holds_no_entries(&self) -> Result<bool, CliError> {
        let mut names = sys::names(&self.dir).map_err(|e| act_err(&self.path, e))?;
        names.next().map_or(Ok(true), |name| {
            name.map(|_| false).map_err(|e| act_err(&self.path, e))
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
        let names = sys::names(&self.dir).map_err(|e| act_err(&self.path, e))?;
        for name in names {
            let name = match name {
                Ok(name) => name,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(act_err(&self.path, e)),
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
    /// holding them, so the caller rewrites. At most one byte past `contents`
    /// is read, so a longer file is never read without bound.
    #[must_use]
    pub fn holds_contents(&self, name: &OsStr, contents: &[u8]) -> bool {
        let Some(entry) = EntryName::new(name) else {
            return false;
        };
        let Ok(file) = self.dir.open_regular(&entry) else {
            return false;
        };
        let Ok(len) = u64::try_from(contents.len()) else {
            return false;
        };
        if file.len() != len {
            return false;
        }
        let cap = ByteCap::from_nonzero(NonZeroU64::new(len).unwrap_or(NonZeroU64::MIN));
        file.read_bytes(cap)
            .is_ok_and(|existing| existing == contents)
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

/// A point in [`HeldDir::claim`] or [`HeldDir::owned_now`] a test can act at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimPoint {
    /// The claim lock is held; the claim file's identity is not yet re-checked.
    AfterLock,
    /// The pre-check found the directory empty; the marker is not yet published.
    AfterPreCheck,
    /// The marker is published; the post-check has not run.
    AfterPublish,
    /// The post-check passed; the claim file is not yet unlinked.
    BeforeCommit,
    /// The claim lock was held elsewhere, or its name was being deleted.
    Busy,
    /// `owned_now` read a genuine marker; the marker name is not yet re-checked.
    MarkerRead,
}

/// Test-only hook run at each [`ClaimPoint`] of the directory at the path.
#[cfg(test)]
pub type ClaimHook = Box<dyn FnMut(ClaimPoint, &Path)>;

#[cfg(test)]
thread_local! {
    static CLAIM_HOOK: std::cell::RefCell<Option<ClaimHook>> = const { std::cell::RefCell::new(None) };
}

/// Install (or clear) the hook run at each point of a claim on this thread.
#[cfg(test)]
pub fn set_claim_hook(hook: Option<ClaimHook>) {
    CLAIM_HOOK.with(|slot| *slot.borrow_mut() = hook);
}

/// Run the claim hook, if any, at `point` for the directory at `path`.
#[cfg(test)]
fn claim_reached(point: ClaimPoint, path: &Path) {
    let taken = CLAIM_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(mut hook) = taken {
        hook(point, path);
        CLAIM_HOOK.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_none() {
                *slot = Some(hook);
            }
        });
    }
}

/// Outside tests there is no hook: a claim point has no side effect.
#[cfg(not(test))]
const fn claim_reached(_point: ClaimPoint, _path: &Path) {}

/// Test-only hook run after a subdirectory is re-proven and released, before its removal.
#[cfg(test)]
pub type ReleaseHook = Box<dyn FnMut(&Path)>;

#[cfg(test)]
thread_local! {
    static RELEASE_HOOK: std::cell::RefCell<Option<ReleaseHook>> = const { std::cell::RefCell::new(None) };
}

/// Install (or clear) the hook run between a subdirectory's re-proof and its removal.
///
/// It lets a test swap or refill the entry in the window the proof cannot close.
#[cfg(test)]
pub fn set_release_hook(hook: Option<ReleaseHook>) {
    RELEASE_HOOK.with(|slot| *slot.borrow_mut() = hook);
}

/// Run the release hook, if any, for the subdirectory at `path`.
#[cfg(test)]
fn subdir_released(path: &Path) {
    let taken = RELEASE_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(mut hook) = taken {
        hook(path);
        RELEASE_HOOK.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_none() {
                *slot = Some(hook);
            }
        });
    }
}

/// Outside tests there is no hook: releasing a subdirectory has no side effect.
#[cfg(not(test))]
const fn subdir_released(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;
    use std::rc::Rc;

    /// A fresh, empty scratch directory unique to this test process.
    fn scratch(tag: &str) -> PathBuf {
        let dir = ipe_test_temp::temp_root().join(format!("ipe_held_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("make scratch");
        std::fs::canonicalize(&dir).expect("canonicalize scratch")
    }

    /// Open `base` and its subdirectory `name` as held handles.
    fn hold(base: &Path, name: &OsStr) -> (HeldDir, HeldDir) {
        let parent = HeldDir::open(base)
            .expect("open base")
            .expect("base exists");
        let child = parent
            .child(name)
            .expect("open child")
            .expect("child exists");
        (parent, child)
    }

    /// Run `swap` once, after the subdirectory at `at` is released and before its removal.
    fn on_release(at: PathBuf, swap: impl FnOnce() + 'static) {
        let mut swap = Some(swap);
        set_release_hook(Some(Box::new(move |released: &Path| {
            if released == at
                && let Some(swap) = swap.take()
            {
                swap();
            }
        })));
    }

    /// An empty directory refilled after its release is kept, its new entry intact.
    #[test]
    fn remove_empty_dir_keeps_a_directory_refilled_after_its_release() {
        let base = scratch("refilled");
        let name = OsStr::new("doomed");
        let doomed = base.join(name);
        std::fs::create_dir(&doomed).expect("make doomed");
        let (parent, child) = hold(&base, name);
        let late = doomed.join("late.txt");
        let written = late.clone();
        on_release(doomed, move || {
            std::fs::write(&written, "late").expect("refill");
        });

        let removed = parent.remove_empty_dir(name, child);
        set_release_hook(None);
        assert!(
            matches!(removed, Ok(false)),
            "the refilled directory is kept, got {removed:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&late).ok().as_deref(),
            Some("late"),
            "the refilled entry survives"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A file swapped in for an empty directory after its release is refused, never removed.
    #[test]
    fn remove_empty_dir_refuses_a_file_swapped_in_after_its_release() {
        let base = scratch("empty_file_swap");
        let name = OsStr::new("doomed");
        let doomed = base.join(name);
        std::fs::create_dir(&doomed).expect("make doomed");
        let (parent, child) = hold(&base, name);
        let (from, aside) = (doomed.clone(), base.join("doomed.aside"));
        on_release(doomed.clone(), move || {
            std::fs::rename(&from, &aside).expect("move doomed aside");
            std::fs::write(&from, "keep").expect("plant file");
        });

        let removed = parent.remove_empty_dir(name, child);
        set_release_hook(None);
        assert!(
            matches!(
                removed,
                Err(CliError::OutputRefused(OutputRefusal::Replaced(_)))
            ),
            "the swapped-in file is refused, got {removed:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&doomed).ok().as_deref(),
            Some("keep"),
            "the swapped-in file survives"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A symlink swapped in for an empty directory after its release is refused, never removed.
    #[cfg(unix)]
    #[test]
    fn remove_empty_dir_refuses_a_symlink_swapped_in_after_its_release() {
        let base = scratch("empty_symlink_swap");
        let name = OsStr::new("doomed");
        let doomed = base.join(name);
        std::fs::create_dir(&doomed).expect("make doomed");
        let (parent, child) = hold(&base, name);
        let (from, aside) = (doomed.clone(), base.join("doomed.aside"));
        on_release(doomed.clone(), move || {
            std::fs::rename(&from, &aside).expect("move doomed aside");
            std::os::unix::fs::symlink(&aside, &from).expect("plant symlink");
        });

        let removed = parent.remove_empty_dir(name, child);
        set_release_hook(None);
        assert!(
            matches!(
                removed,
                Err(CliError::OutputRefused(OutputRefusal::Replaced(_)))
            ),
            "the swapped-in symlink is refused, got {removed:?}"
        );
        assert!(
            std::fs::symlink_metadata(&doomed).is_ok_and(|meta| meta.file_type().is_symlink()),
            "the swapped-in symlink survives"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A file swapped in for an emptied tree after its release is refused, never removed.
    #[test]
    fn remove_proven_refuses_a_file_swapped_in_after_its_release() {
        let base = scratch("proven_file_swap");
        let name = OsStr::new("doomed");
        let doomed = base.join(name);
        std::fs::create_dir_all(doomed.join("sub")).expect("make tree");
        std::fs::write(doomed.join("sub").join("f.txt"), "gone").expect("tree file");
        let (parent, child) = hold(&base, name);
        let (from, aside) = (doomed.clone(), base.join("doomed.aside"));
        on_release(doomed.clone(), move || {
            std::fs::rename(&from, &aside).expect("move doomed aside");
            std::fs::write(&from, "keep").expect("plant file");
        });

        let removed = parent.remove_proven(name, child);
        set_release_hook(None);
        assert!(
            matches!(
                removed,
                Err(CliError::OutputRefused(OutputRefusal::Replaced(_)))
            ),
            "the swapped-in file is refused, got {removed:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&doomed).ok().as_deref(),
            Some("keep"),
            "the swapped-in file survives"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// An inner directory of a removed tree is re-proven before its removal.
    ///
    /// On Unix a held directory can be renamed away, so the test swaps an
    /// empty impostor in while the tree below it is removed: the removal is
    /// refused and the impostor survives. On Windows a held directory cannot
    /// be renamed at all, so the swap itself is refused and the tree goes.
    #[test]
    fn an_inner_directory_swapped_mid_removal_is_never_removed_by_name() {
        let base = scratch("inner_swap");
        let inner = base.join("tree").join("inner");
        std::fs::create_dir_all(inner.join("leaf")).expect("make tree");
        std::fs::write(inner.join("leaf").join("f.txt"), "gone").expect("tree file");
        let parent = HeldDir::open(&base.join("tree"))
            .expect("open tree")
            .expect("tree exists");
        let swapped = Rc::new(Cell::new(None));
        let seen = Rc::clone(&swapped);
        let (from, aside) = (inner.clone(), base.join("inner.aside"));
        on_release(inner.join("leaf"), move || {
            let moved = std::fs::rename(&from, &aside).is_ok();
            if moved {
                std::fs::create_dir(&from).expect("plant impostor");
            }
            seen.set(Some(moved));
        });

        let removed = parent.remove_entry(OsStr::new("inner"));
        set_release_hook(None);
        #[cfg(unix)]
        {
            assert_eq!(swapped.get(), Some(true), "a held directory moves on Unix");
            assert!(
                matches!(
                    removed,
                    Err(CliError::OutputRefused(OutputRefusal::Replaced(_)))
                ),
                "the swapped inner directory is refused, got {removed:?}"
            );
            assert!(inner.is_dir(), "the impostor survives");
        }
        #[cfg(windows)]
        {
            assert_eq!(swapped.get(), Some(false), "a held directory cannot move");
            assert!(
                removed.is_ok(),
                "the unswapped tree is removed, got {removed:?}"
            );
            assert!(!inner.exists(), "the tree is gone");
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A held subdirectory another handle keeps open without delete sharing is refused, in use.
    #[cfg(windows)]
    #[test]
    fn remove_entry_of_a_held_subdirectory_in_use_elsewhere_is_refused() {
        use std::os::windows::fs::OpenOptionsExt as _;

        /// `FILE_FLAG_BACKUP_SEMANTICS`: allows opening a directory handle.
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        /// `FILE_SHARE_READ | FILE_SHARE_WRITE`, without `FILE_SHARE_DELETE`.
        const SHARE_NO_DELETE: u32 = 0x1 | 0x2;

        let base = scratch("win_in_use");
        let name = OsStr::new("busy");
        let busy = base.join(name);
        std::fs::create_dir(&busy).expect("make busy");
        let other = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(SHARE_NO_DELETE)
            .custom_flags(BACKUP_SEMANTICS)
            .open(&busy)
            .expect("hold busy open elsewhere");

        let parent = HeldDir::open(&base)
            .expect("open base")
            .expect("base exists");
        let removed = parent.remove_entry(name);
        assert!(
            matches!(
                removed,
                Err(CliError::OutputRefused(OutputRefusal::InUse(_)))
            ),
            "the in-use directory is refused, got {removed:?}"
        );
        assert!(busy.is_dir(), "the busy directory survives");

        drop(other);
        parent
            .remove_entry(name)
            .expect("removable once the other handle releases it");
        assert!(!busy.exists(), "the directory is gone once free");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// An empty subdirectory turned into a junction is refused as a link, never entered.
    #[cfg(windows)]
    #[test]
    fn a_junction_child_is_link() {
        use super::super::test_links::junction_in_place;

        let base = scratch("junction_child");
        let victim = base.join("victim");
        std::fs::create_dir(&victim).expect("make victim");
        std::fs::write(victim.join("keep.txt"), "keep").expect("victim file");
        let link = base.join("link");
        std::fs::create_dir(&link).expect("make link dir");
        junction_in_place(&link, &victim);

        let held = HeldDir::open(&base)
            .expect("open base")
            .expect("base exists");
        let name = EntryName::new(OsStr::new("link")).expect("plain name");
        let refused = held.dir.child_dir(&name);
        assert_eq!(refused.err(), Some(OpenRefusal::Link));
        let child = held.child(OsStr::new("link"));
        assert!(
            matches!(
                child,
                Err(CliError::OutputRefused(OutputRefusal::Symlink(_)))
            ),
            "the junction is refused as a link, got {child:?}"
        );
        assert!(victim.join("keep.txt").is_file(), "the target is untouched");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A held empty directory turned into a junction refuses its listing rather than listing the target.
    #[cfg(windows)]
    #[test]
    fn a_held_empty_dir_turned_junction_refuses_entries() {
        use super::super::test_links::junction_in_place;

        let base = scratch("junction_held");
        let victim = base.join("victim");
        std::fs::create_dir(&victim).expect("make victim");
        std::fs::write(victim.join("keep.txt"), "keep").expect("victim file");
        let level = base.join("level");
        std::fs::create_dir(&level).expect("make level");
        let held = HeldDir::open(&level)
            .expect("open level")
            .expect("level exists");
        junction_in_place(&level, &victim);

        let cap = ipe_fs_open::EntryCap::new(16).expect("non-zero cap");
        let listed = held.dir.entries(cap);
        assert_eq!(listed.err(), Some(OpenRefusal::Link));
        assert!(victim.join("keep.txt").is_file(), "the target is untouched");
        drop(held);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A directory at the marker name is refused, never read as an empty directory awaiting its marker.
    #[test]
    fn a_directory_at_the_marker_name_refuses_ownership() {
        let base = scratch("marker_dir");
        let marker = base.join(OWNERSHIP_MARKER);
        std::fs::create_dir(&marker).expect("make marker-named dir");
        std::fs::write(marker.join("keep.txt"), "keep").expect("user file");
        let held = HeldDir::open(&base)
            .expect("open base")
            .expect("base exists");
        let ownership = held.ownership();
        assert!(
            matches!(ownership, Ok(Ownership::User)),
            "a directory at the marker name is user territory, got {ownership:?}"
        );
        let claimed = held.claim();
        assert!(
            matches!(
                claimed,
                Err(CliError::OutputRefused(OutputRefusal::NotIpeOwned(_)))
            ),
            "no claim takes it, got {claimed:?}"
        );
        assert!(
            marker.join("keep.txt").is_file(),
            "the user file is untouched"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A symbolic link at the marker name is no marker, and never followed.
    #[cfg(unix)]
    #[test]
    fn a_link_at_the_marker_name_is_no_marker() {
        let base = scratch("marker_link");
        let elsewhere = base.join("elsewhere");
        std::fs::write(&elsewhere, MARKER_TEXT).expect("write lookalike marker");
        let level = base.join("level");
        std::fs::create_dir(&level).expect("make level");
        std::os::unix::fs::symlink(&elsewhere, level.join(OWNERSHIP_MARKER)).expect("link marker");
        let held = HeldDir::open(&level)
            .expect("open level")
            .expect("level exists");
        let owned = held.owned_now();
        assert!(
            matches!(owned, Ok(OwnedNow::Unowned)),
            "a linked marker is not followed, got {owned:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Open `path` as a held directory.
    fn held_at(path: &Path) -> HeldDir {
        HeldDir::open(path).expect("open dir").expect("dir exists")
    }

    /// Run `act` once, at the first time a claim reaches `at` on this thread.
    fn at_claim_point(at: ClaimPoint, act: impl FnOnce() + 'static) {
        let mut act = Some(act);
        set_claim_hook(Some(Box::new(move |point, _path: &Path| {
            if point == at
                && let Some(act) = act.take()
            {
                act();
            }
        })));
    }

    /// Whether `result` is the refusal `NotIpeOwned`.
    fn is_not_ipe_owned<T>(result: &Result<T, CliError>) -> bool {
        matches!(
            result,
            Err(CliError::OutputRefused(OutputRefusal::NotIpeOwned(_)))
        )
    }

    /// A user file landing after the pre-check is caught by the post-check: no marker, no claim, the file kept.
    #[test]
    fn a_file_planted_after_the_pre_check_is_refused_and_kept() {
        let dir = scratch("claim_planted_late");
        let user = dir.join("user.txt");
        let planted = user.clone();
        at_claim_point(ClaimPoint::AfterPublish, move || {
            std::fs::write(&planted, "mine").expect("plant user file");
        });
        let claimed = held_at(&dir).claim();
        set_claim_hook(None);
        assert!(is_not_ipe_owned(&claimed), "refused, got {claimed:?}");
        assert!(
            !dir.join(OWNERSHIP_MARKER).exists(),
            "the marker is withdrawn"
        );
        assert!(!dir.join(CLAIM_FILE).exists(), "the claim file is unlinked");
        assert_eq!(std::fs::read(&user).ok().as_deref(), Some(&b"mine"[..]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file planted at the marker name before the publish is never replaced.
    #[test]
    fn a_marker_name_planted_before_publish_is_never_replaced() {
        let dir = scratch("claim_marker_planted");
        let marker = dir.join(OWNERSHIP_MARKER);
        let planted = marker.clone();
        at_claim_point(ClaimPoint::AfterPreCheck, move || {
            std::fs::write(&planted, "user bytes").expect("plant marker name");
        });
        let claimed = held_at(&dir).claim();
        set_claim_hook(None);
        assert!(is_not_ipe_owned(&claimed), "refused, got {claimed:?}");
        assert_eq!(
            std::fs::read(&marker).ok().as_deref(),
            Some(&b"user bytes"[..]),
            "the planted file is untouched"
        );
        assert!(!dir.join(CLAIM_FILE).exists(), "the claim file is unlinked");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two claimants racing on one empty directory both succeed, and neither unmarks the other's output.
    #[test]
    fn two_claims_on_one_empty_dir_never_unmark_each_other() {
        let base = scratch("claim_race");
        for round in 0..200_u32 {
            let dir = base.join(format!("r{round}"));
            std::fs::create_dir(&dir).expect("make round dir");
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let claimants: Vec<_> = (0..2_u32)
                .map(|n| {
                    let (dir, barrier) = (dir.clone(), std::sync::Arc::clone(&barrier));
                    std::thread::spawn(move || {
                        let held = held_at(&dir);
                        barrier.wait();
                        let claimed = held.claim().map(|_| ()).map_err(|e| format!("{e:?}"));
                        std::fs::write(dir.join(format!("out{n}.txt")), "built")
                            .expect("write output");
                        claimed
                    })
                })
                .collect();
            for claimant in claimants {
                let claimed = claimant.join().expect("claimant thread");
                assert!(claimed.is_ok(), "round {round}: {claimed:?}");
            }
            let owned = held_at(&dir).owned_now();
            assert!(
                matches!(owned, Ok(OwnedNow::Owned)),
                "round {round}: still ipe's, got {owned:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A claimant still pending when another claim commits and fills the directory returns claimed, unmarking nothing.
    #[test]
    fn a_pending_claim_over_a_committed_marker_returns_claimed() {
        let dir = scratch("claim_pending_committed");
        let marker = dir.join(OWNERSHIP_MARKER);
        let committed = Rc::new(Cell::new(None));
        let seen = Rc::clone(&committed);
        let (written, filled) = (marker.clone(), dir.join("built.txt"));
        at_claim_point(ClaimPoint::AfterLock, move || {
            std::fs::write(&written, MARKER_TEXT).expect("committed marker");
            std::fs::write(&filled, "built").expect("committed output");
            seen.set(FileId::of_path(&written).ok());
        });
        let claimed = held_at(&dir).claim();
        set_claim_hook(None);
        assert!(claimed.is_ok(), "claimed, got {claimed:?}");
        assert!(committed.get().is_some(), "the other claim committed");
        assert_eq!(
            FileId::of_path(&marker).ok(),
            committed.get(),
            "the committed marker is the one kept"
        );
        assert!(dir.join("built.txt").is_file(), "the output is kept");
        assert!(!dir.join(CLAIM_FILE).exists(), "the claim file is unlinked");
        let owned = held_at(&dir).owned_now();
        assert!(matches!(owned, Ok(OwnedNow::Owned)), "got {owned:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A claim file a crashed claim left empty is taken over in place.
    #[test]
    fn a_stale_pending_claim_is_taken_over_in_place() {
        let dir = scratch("claim_stale_pending");
        let claim = dir.join(CLAIM_FILE);
        std::fs::write(&claim, b"").expect("stale claim file");
        let stale = FileId::of_path(&claim).expect("stale id");
        let locked = Rc::new(Cell::new(None));
        let (seen, at) = (Rc::clone(&locked), claim.clone());
        at_claim_point(ClaimPoint::AfterLock, move || {
            seen.set(FileId::of_path(&at).ok());
        });
        let claimed = held_at(&dir).claim();
        set_claim_hook(None);
        assert!(claimed.is_ok(), "claimed, got {claimed:?}");
        assert_eq!(locked.get(), Some(stale), "the stale claim file was locked");
        assert!(!claim.exists(), "the claim file is unlinked on commit");
        let owned = held_at(&dir).owned_now();
        assert!(matches!(owned, Ok(OwnedNow::Owned)), "got {owned:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A claim lock held elsewhere is waited on for exactly the poll bound, then refused busy.
    #[test]
    fn a_live_claim_refuses_busy_at_the_bound() {
        let dir = scratch("claim_busy");
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.join(CLAIM_FILE))
            .expect("live claim file");
        holder.try_lock().expect("hold the claim lock");
        let polls = Rc::new(Cell::new(0_u32));
        let counted = Rc::clone(&polls);
        set_claim_hook(Some(Box::new(move |point, _path: &Path| {
            if point == ClaimPoint::Busy {
                counted.set(counted.get().saturating_add(1));
            }
        })));
        let claimed = held_at(&dir).claim();
        set_claim_hook(None);
        assert!(
            matches!(
                claimed,
                Err(CliError::OutputRefused(OutputRefusal::ClaimBusy { .. }))
            ),
            "refused busy, got {claimed:?}"
        );
        assert_eq!(polls.get(), MAX_CLAIM_POLLS, "one try per poll");
        assert!(!dir.join(OWNERSHIP_MARKER).exists(), "nothing is published");
        drop(holder);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A claim whose locked claim file was unlinked and recreated re-evaluates, never publishing on the old file.
    #[cfg(unix)]
    #[test]
    fn a_claim_on_an_unlinked_inode_reevaluates() {
        let dir = scratch("claim_unlinked");
        let claim = dir.join(CLAIM_FILE);
        let old = Rc::new(Cell::new(None));
        let published_under = Rc::new(Cell::new(None));
        let (old_seen, published_seen) = (Rc::clone(&old), Rc::clone(&published_under));
        let mut swapped = false;
        let at = claim.clone();
        set_claim_hook(Some(Box::new(move |point, _path: &Path| match point {
            ClaimPoint::AfterLock if !swapped => {
                swapped = true;
                old_seen.set(FileId::of_path(&at).ok());
                std::fs::remove_file(&at).expect("unlink locked claim");
                std::fs::write(&at, b"").expect("recreate claim");
            }
            ClaimPoint::AfterPublish => published_seen.set(FileId::of_path(&at).ok()),
            ClaimPoint::AfterLock
            | ClaimPoint::AfterPreCheck
            | ClaimPoint::BeforeCommit
            | ClaimPoint::Busy
            | ClaimPoint::MarkerRead => {}
        })));
        let claimed = held_at(&dir).claim();
        set_claim_hook(None);
        assert!(claimed.is_ok(), "claimed, got {claimed:?}");
        assert!(old.get().is_some(), "the first lock was taken");
        assert!(published_under.get().is_some(), "a publish ran");
        assert_ne!(
            published_under.get(),
            old.get(),
            "the publish ran under the recreated claim file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A crashed finalizing claim is resumed when clean, and refused interrupted beside a user file.
    #[test]
    fn a_finalizing_crash_with_a_user_file_is_interrupted() {
        let base = scratch("claim_finalizing");
        let crashed = |name: &str, marker: bool, user: bool| {
            let dir = base.join(name);
            std::fs::create_dir(&dir).expect("make dir");
            std::fs::write(dir.join(CLAIM_FILE), [FINALIZING]).expect("finalizing claim");
            if marker {
                std::fs::write(dir.join(OWNERSHIP_MARKER), MARKER_TEXT).expect("marker");
            }
            if user {
                std::fs::write(dir.join("user.txt"), "mine").expect("user file");
            }
            dir
        };

        let dir = crashed("with_user", true, true);
        let claimed = held_at(&dir).claim();
        assert!(
            matches!(
                claimed,
                Err(CliError::OutputRefused(OutputRefusal::ClaimInterrupted(_)))
            ),
            "interrupted, got {claimed:?}"
        );
        for kept in [CLAIM_FILE, OWNERSHIP_MARKER, "user.txt"] {
            assert!(dir.join(kept).is_file(), "{kept} is kept");
        }

        let dir = crashed("marker_only", true, false);
        let claimed = held_at(&dir).claim();
        assert!(claimed.is_ok(), "resumed, got {claimed:?}");
        assert!(!dir.join(CLAIM_FILE).exists(), "the claim file is unlinked");

        let dir = crashed("no_marker", false, false);
        let claimed = held_at(&dir).claim();
        assert!(claimed.is_ok(), "published, got {claimed:?}");
        assert!(
            dir.join(OWNERSHIP_MARKER).is_file(),
            "the marker is published"
        );
        let owned = held_at(&dir).owned_now();
        assert!(matches!(owned, Ok(OwnedNow::Owned)), "got {owned:?}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The listing judges entries by kind: only a regular file at the marker or claim name is tolerated.
    #[test]
    fn listing_is_kind_aware() {
        let base = scratch("claim_kinds");
        let refused_with = |name: &str, plant: &dyn Fn(&Path)| {
            let dir = base.join(name);
            std::fs::create_dir(&dir).expect("make dir");
            plant(&dir);
            let claimed = held_at(&dir).claim();
            assert!(
                is_not_ipe_owned(&claimed),
                "{name}: refused, got {claimed:?}"
            );
            assert!(
                !std::fs::symlink_metadata(dir.join(OWNERSHIP_MARKER)).is_ok_and(|m| m.is_file()),
                "{name}: no marker is published"
            );
            dir
        };

        let dir = refused_with("temp_dir", &|dir: &Path| {
            let temp = dir.join(".ipe-output.1.2.tmp");
            std::fs::create_dir(&temp).expect("temp-named dir");
            std::fs::write(temp.join("keep.txt"), "keep").expect("user file");
        });
        assert!(dir.join(".ipe-output.1.2.tmp/keep.txt").is_file());

        let dir = refused_with("temp_file", &|dir: &Path| {
            std::fs::write(dir.join(".ipe-output.1.2.tmp"), "keep").expect("temp-named file");
        });
        assert!(dir.join(".ipe-output.1.2.tmp").is_file());

        let dir = refused_with("claim_dir", &|dir: &Path| {
            std::fs::create_dir(dir.join(CLAIM_FILE)).expect("dir at claim name");
        });
        assert!(dir.join(CLAIM_FILE).is_dir(), "the directory is kept");

        #[cfg(unix)]
        {
            let target = base.join("lookalike");
            std::fs::write(&target, MARKER_TEXT).expect("lookalike marker");
            let linked = target.clone();
            let dir = refused_with("marker_link", &move |dir: &Path| {
                std::os::unix::fs::symlink(&linked, dir.join(OWNERSHIP_MARKER))
                    .expect("link at marker name");
            });
            assert!(dir.join(OWNERSHIP_MARKER).is_symlink(), "the link is kept");
            assert_eq!(
                std::fs::read(&target).ok().as_deref(),
                Some(MARKER_TEXT.as_bytes())
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A file hard-linked at the claim or marker name is never believed, written, or removed.
    #[test]
    fn a_hard_link_at_a_reserved_name_is_refused_untouched() {
        let base = scratch("claim_hard_link");
        let victim = base.join("victim");
        std::fs::write(&victim, b"").expect("empty victim");
        let dir = base.join("claim_link");
        std::fs::create_dir(&dir).expect("make dir");
        std::fs::hard_link(&victim, dir.join(CLAIM_FILE)).expect("link at claim name");
        let claimed = held_at(&dir).claim();
        assert!(is_not_ipe_owned(&claimed), "refused, got {claimed:?}");
        assert_eq!(std::fs::read(&victim).ok().as_deref(), Some(&b""[..]));
        assert!(dir.join(CLAIM_FILE).is_file(), "the link is kept");
        assert!(!dir.join(OWNERSHIP_MARKER).exists(), "nothing is published");

        let marker_victim = base.join("marker_victim");
        std::fs::write(&marker_victim, MARKER_TEXT).expect("lookalike marker");
        let dir = base.join("marker_link");
        std::fs::create_dir(&dir).expect("make dir");
        std::fs::hard_link(&marker_victim, dir.join(OWNERSHIP_MARKER)).expect("link at marker");
        let owned = held_at(&dir).owned_now();
        assert!(matches!(owned, Ok(OwnedNow::Unowned)), "got {owned:?}");
        let claimed = held_at(&dir).claim();
        assert!(is_not_ipe_owned(&claimed), "refused, got {claimed:?}");
        assert_eq!(
            std::fs::read(&marker_victim).ok().as_deref(),
            Some(MARKER_TEXT.as_bytes())
        );
        assert!(dir.join(OWNERSHIP_MARKER).is_file(), "the link is kept");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A claim file left with bytes no claim writes is refused untouched.
    #[test]
    fn a_claim_file_with_foreign_bytes_is_refused_untouched() {
        let dir = scratch("claim_foreign_bytes");
        std::fs::write(dir.join(CLAIM_FILE), "user notes").expect("foreign claim bytes");
        let claimed = held_at(&dir).claim();
        assert!(is_not_ipe_owned(&claimed), "refused, got {claimed:?}");
        assert_eq!(
            std::fs::read(dir.join(CLAIM_FILE)).ok().as_deref(),
            Some(&b"user notes"[..])
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A marked directory is not owned while a claim file sits beside it, nor once its marker is swapped.
    #[test]
    fn owned_now_is_false_while_claiming_or_swapped() {
        let dir = scratch("owned_now");
        let claimed = held_at(&dir).claim();
        assert!(claimed.is_ok(), "claimed, got {claimed:?}");
        std::fs::write(dir.join(CLAIM_FILE), b"").expect("claim in flight");
        let owned = held_at(&dir).owned_now();
        assert!(matches!(owned, Ok(OwnedNow::Claiming)), "got {owned:?}");
        std::fs::remove_file(dir.join(CLAIM_FILE)).expect("claim done");

        let (marker, fresh) = (dir.join(OWNERSHIP_MARKER), dir.join("fresh"));
        at_claim_point(ClaimPoint::MarkerRead, move || {
            std::fs::write(&fresh, MARKER_TEXT).expect("lookalike marker");
            std::fs::rename(&fresh, &marker).expect("swap marker");
        });
        let owned = held_at(&dir).owned_now();
        set_claim_hook(None);
        assert!(matches!(owned, Ok(OwnedNow::Unowned)), "got {owned:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No product write may forge or clobber the marker or the claim file.
    #[test]
    fn write_file_refuses_the_marker_and_claim_names() {
        let dir = scratch("write_reserved");
        let held = held_at(&dir);
        for name in [OWNERSHIP_MARKER, CLAIM_FILE] {
            let written = held.write_file(OsStr::new(name), None, |file| {
                file.write_all(MARKER_TEXT.as_bytes())
            });
            assert!(
                matches!(
                    written,
                    Err(CliError::OutputRefused(OutputRefusal::UnsafeComponent(_)))
                ),
                "{name} is refused, got {written:?}"
            );
            assert!(!dir.join(name).exists(), "{name} is not written");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A subdirectory another program holds open without sharing is refused, in use, when entered.
    #[cfg(windows)]
    #[test]
    fn a_child_held_open_elsewhere_is_in_use() {
        use std::os::windows::fs::OpenOptionsExt as _;

        /// `FILE_FLAG_BACKUP_SEMANTICS`: allows opening a directory handle.
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;

        let base = scratch("win_child_in_use");
        let busy = base.join("busy");
        std::fs::create_dir(&busy).expect("make busy");
        let other = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(BACKUP_SEMANTICS)
            .open(&busy)
            .expect("hold busy open elsewhere");
        let parent = HeldDir::open(&base)
            .expect("open base")
            .expect("base exists");
        let child = parent.child(OsStr::new("busy"));
        assert!(
            matches!(child, Err(CliError::OutputRefused(OutputRefusal::InUse(_)))),
            "the in-use subdirectory is refused, got {child:?}"
        );
        drop(other);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// An in-use refusal stays in use on every platform; every other refusal is an I/O error of its kind.
    #[test]
    fn every_open_refusal_maps_to_its_cli_error() {
        let path = Path::new("held/entry");
        let in_use = refused(path, OpenRefusal::InUse);
        assert!(
            matches!(&in_use, CliError::OutputRefused(OutputRefusal::InUse(p)) if p == path),
            "an in-use entry is refused as in use, got {in_use:?}"
        );
        let cap = ByteCap::new(4).expect("non-zero cap");
        let entries = ipe_fs_open::EntryCap::new(4).expect("non-zero cap");
        for refusal in [
            OpenRefusal::Absent,
            OpenRefusal::Link,
            OpenRefusal::NotRegular(FileKind::Fifo),
            OpenRefusal::Denied,
            OpenRefusal::TooLarge(cap),
            OpenRefusal::TooManyEntries(entries),
            OpenRefusal::BadName,
            OpenRefusal::NotUtf8,
            OpenRefusal::Io(io::ErrorKind::Interrupted),
        ] {
            let error = refused(path, refusal);
            assert!(
                matches!(&error, CliError::Io { source, .. } if source.kind() == refusal.kind()),
                "{refusal:?} is an I/O error of its kind, got {error:?}"
            );
        }
    }
}

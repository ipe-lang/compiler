//! Owner trust: admitting only discovered files no other local user can write.
//!
//! An FFI cache compiles unsandboxed into the crate and a `package.ipe` steers
//! the whole build, so either one planted by another user is a code-injection
//! vector. Discovery admits them only when the invoking user owns them and no
//! other user can write them. The FFI cache is walked component by component
//! through held, no-follow directory handles, and every artifact is read
//! through the handle that passed the check, so no path swap between check and
//! use can redirect a read.

use std::fmt;
use std::path::{Path, PathBuf};

use ipe_ffi::diag::Diagnostic;

use crate::CliError;
use crate::text;

/// The most entries an FFI cache directory may list before it is refused.
pub const MAX_CACHE_ENTRIES: usize = 65_536;

/// The identity the running process acts as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invoker {
    /// The effective user id.
    pub uid: u32,
    /// The effective group id.
    pub gid: u32,
}

#[cfg(unix)]
impl Invoker {
    /// The effective uid and gid of this process.
    #[must_use]
    pub fn current() -> Self {
        Self {
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
        }
    }
}

/// The owner and permission bits of one filesystem entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    /// The owning user id.
    pub uid: u32,
    /// The owning group id.
    pub gid: u32,
    /// The mode bits, file type included.
    pub mode: u32,
}

#[cfg(unix)]
impl Stamp {
    /// The stamp `meta` carries.
    #[must_use]
    pub fn of(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
        }
    }
}

/// Why an entry lets a user other than the invoker write it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Breach {
    /// Another user owns it.
    ForeignOwner,
    /// Every user may write it.
    WorldWritable,
    /// A group other than the invoker's own may write it.
    ForeignGroupWritable,
}

/// The mode bit granting every user write access.
const WORLD_WRITE: u32 = 0o002;

/// The mode bit granting the owning group write access.
const GROUP_WRITE: u32 = 0o020;

/// The mode bit restricting renames and removals in a directory to each entry's owner.
const STICKY: u32 = 0o1000;

/// The uid of the superuser, who can write anything regardless of ownership.
const ROOT_UID: u32 = 0;

/// Why `stamp` names an entry some user other than `invoker` can write.
///
/// Group write access passes only when the owning group is the invoker's
/// effective group, which a default `0o002` umask grants to every file the
/// invoker creates. This admits the entry to every member of that group: it
/// is sound where the effective group is a per-user private group (the
/// user-private-group convention), and extends trust to the group's other
/// members where the effective group is shared.
#[must_use]
pub const fn breach(stamp: Stamp, invoker: Invoker) -> Option<Breach> {
    if stamp.uid != invoker.uid {
        Some(Breach::ForeignOwner)
    } else if stamp.mode & WORLD_WRITE != 0 {
        Some(Breach::WorldWritable)
    } else if stamp.mode & GROUP_WRITE != 0 && stamp.gid != invoker.gid {
        Some(Breach::ForeignGroupWritable)
    } else {
        None
    }
}

/// Why `stamp` names a directory where another user could replace an entry the invoker owns.
///
/// Root may own the directory, and a sticky directory may be shared-writable:
/// in one, only an entry's owner can rename or remove it. Group write access
/// passes under the invoker's effective group, on the same terms as [`breach`].
#[must_use]
pub const fn container_breach(stamp: Stamp, invoker: Invoker) -> Option<Breach> {
    if stamp.uid != invoker.uid && stamp.uid != ROOT_UID {
        Some(Breach::ForeignOwner)
    } else if stamp.mode & STICKY != 0 {
        None
    } else if stamp.mode & WORLD_WRITE != 0 {
        Some(Breach::WorldWritable)
    } else if stamp.mode & GROUP_WRITE != 0 && stamp.gid != invoker.gid {
        Some(Breach::ForeignGroupWritable)
    } else {
        None
    }
}

/// Whether a symbolic link owned by `owner_uid` may stand for a directory on a path the invoker trusts.
///
/// Only root or the invoker may own it: in a sticky shared directory any
/// user can plant a link, and following one would hand them the rest of the
/// path. The link's target is walked under the same checks as any path.
#[must_use]
pub const fn link_owner_admitted(owner_uid: u32, invoker: Invoker) -> bool {
    owner_uid == invoker.uid || owner_uid == ROOT_UID
}

/// What a failed trust check guarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustSubject {
    /// A discovered `package.ipe`.
    Manifest,
    /// The FFI artifact cache or the catalog loaded from it.
    Ffi,
}

/// A discovered manifest or FFI cache refused because it failed a trust check.
///
/// Each variant names the refused entry; [`TrustRefusal::message`] is its
/// user-facing text.
#[derive(Debug)]
pub enum TrustRefusal {
    /// The discovered manifest is a symbolic link.
    ManifestSymlink(PathBuf),
    /// Another user can write or replace the discovered manifest.
    ManifestUntrusted(PathBuf),
    /// This host has no owner check, so the discovered manifest is not obeyed.
    ManifestUnverifiable(PathBuf),
    /// This host has no owner check, so the FFI cache is not loaded.
    FfiCacheUnverifiable(PathBuf),
    /// An FFI cache component or artifact is a symbolic link.
    FfiCacheSymlink(PathBuf),
    /// Another user can write an FFI cache component or artifact.
    FfiCacheUntrusted(PathBuf),
    /// An FFI cache artifact is not a regular file.
    FfiCacheNotRegular(PathBuf),
    /// An FFI cache directory lists more entries than its cap.
    FfiCacheTooManyEntries {
        /// The refused cache directory.
        path: PathBuf,
        /// The entry cap that was exceeded.
        cap: usize,
    },
    /// The catalog loader refused an FFI cache artifact's content.
    FfiCatalog(Box<Diagnostic>),
    /// An installed crate claims the reserved asserted-call module.
    FfiReservedModule {
        /// The claiming crate.
        slug: String,
    },
    /// An installed crate declares a wrapper under the reserved asserted-call prefix.
    FfiReservedWrapperPrefix {
        /// The claiming crate.
        slug: String,
        /// The offending wrapper identifier.
        ident: String,
    },
}

impl TrustRefusal {
    /// Whether the refused entry is a manifest or part of the FFI cache.
    #[must_use]
    pub const fn subject(&self) -> TrustSubject {
        match self {
            Self::ManifestSymlink(_)
            | Self::ManifestUntrusted(_)
            | Self::ManifestUnverifiable(_) => TrustSubject::Manifest,
            Self::FfiCacheUnverifiable(_)
            | Self::FfiCacheSymlink(_)
            | Self::FfiCacheUntrusted(_)
            | Self::FfiCacheNotRegular(_)
            | Self::FfiCacheTooManyEntries { .. }
            | Self::FfiCatalog(_)
            | Self::FfiReservedModule { .. }
            | Self::FfiReservedWrapperPrefix { .. } => TrustSubject::Ffi,
        }
    }

    /// The refusal's user-facing text, naming the refused entry and the fix.
    #[must_use]
    pub fn message(&self) -> text::Message {
        match self {
            Self::ManifestSymlink(path) => text::msg::manifest_symlink(&path.display()),
            Self::ManifestUntrusted(path) => text::msg::manifest_untrusted(&path.display()),
            Self::ManifestUnverifiable(path) => text::msg::manifest_unverifiable(&path.display()),
            Self::FfiCacheUnverifiable(path) => text::msg::ffi_cache_unverifiable(&path.display()),
            Self::FfiCacheSymlink(path) => text::msg::ffi_cache_symlink(&path.display()),
            Self::FfiCacheUntrusted(path) => text::msg::ffi_cache_untrusted(&path.display()),
            Self::FfiCacheNotRegular(path) => text::msg::ffi_cache_not_regular(&path.display()),
            Self::FfiCacheTooManyEntries { path, cap } => {
                text::msg::ffi_cache_too_many_entries(&path.display(), cap)
            }
            Self::FfiCatalog(diag) => text::Message::relay(&**diag),
            Self::FfiReservedModule { slug } => {
                text::msg::ffi_reserved_module_claimed(slug, &ipe_canon::asserted::ASSERTED_MODULE)
            }
            Self::FfiReservedWrapperPrefix { slug, ident } => {
                text::msg::ffi_reserved_wrapper_prefix(
                    slug,
                    ident,
                    &ipe_canon::asserted::ASSERTED_WRAPPER_PREFIX,
                )
            }
        }
    }
}

impl fmt::Display for TrustRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

/// A failure while loading the catalog from a held FFI cache.
#[derive(Debug)]
pub enum CacheLoadError {
    /// The catalog loader refused an artifact's content.
    Catalog(Diagnostic),
    /// Listing or reading the cache failed, or an entry failed the owner rule.
    Cli(CliError),
}

impl From<Diagnostic> for CacheLoadError {
    fn from(diag: Diagnostic) -> Self {
        Self::Catalog(diag)
    }
}

impl From<CacheLoadError> for CliError {
    fn from(err: CacheLoadError) -> Self {
        match err {
            CacheLoadError::Catalog(diag) => {
                Self::TrustRefused(TrustRefusal::FfiCatalog(Box::new(diag)))
            }
            CacheLoadError::Cli(err) => err,
        }
    }
}

/// Refuse a discovered `package.ipe` another user could have written or replaced.
///
/// A manifest found by walking up from an entry file was not named by the
/// user, so it is obeyed only when the invoker owns it, it is a regular file
/// rather than a link, no other user can write it, and no other user can
/// replace it in its directory.
///
/// # Errors
///
/// [`CliError::TrustRefused`] naming the refused manifest; [`CliError::Io`]
/// when it cannot be inspected.
#[cfg(unix)]
pub fn admit_discovered_manifest(manifest: &Path) -> Result<(), CliError> {
    let invoker = Invoker::current();
    let io = |path: &Path, source| CliError::Io {
        path: path.to_path_buf(),
        source,
    };
    let untrusted =
        || CliError::TrustRefused(TrustRefusal::ManifestUntrusted(manifest.to_path_buf()));
    let meta = std::fs::symlink_metadata(manifest).map_err(|e| io(manifest, e))?;
    if meta.file_type().is_symlink() {
        return Err(CliError::TrustRefused(TrustRefusal::ManifestSymlink(
            manifest.to_path_buf(),
        )));
    }
    if !meta.is_file() || breach(Stamp::of(&meta), invoker).is_some() {
        return Err(untrusted());
    }
    let dir = manifest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dir_meta = std::fs::metadata(dir).map_err(|e| io(dir, e))?;
    if container_breach(Stamp::of(&dir_meta), invoker).is_some() {
        return Err(untrusted());
    }
    Ok(())
}

/// Off Unix no portable owner check exists, so every discovered manifest is refused.
///
/// # Errors
///
/// Always [`CliError::TrustRefused`] naming the manifest (see [`refuse_unverifiable_manifest`]).
#[cfg(not(unix))]
pub fn admit_discovered_manifest(manifest: &Path) -> Result<(), CliError> {
    refuse_unverifiable_manifest(manifest)
}

/// The refusal of a discovered `package.ipe` on a host with no owner check.
///
/// Every platform compiles this, so its refusal is exercised everywhere, not
/// only where it is the discovery rule.
///
/// # Errors
///
/// Always [`CliError::TrustRefused`] naming the manifest and the explicit-directory fix.
pub fn refuse_unverifiable_manifest(manifest: &Path) -> Result<(), CliError> {
    Err(CliError::TrustRefused(TrustRefusal::ManifestUnverifiable(
        manifest.to_path_buf(),
    )))
}

/// Refuse whatever exists at `anchor/rel` on a host with no owner check.
///
/// Every platform compiles this, so its refusal is exercised everywhere, not
/// only where it is the discovery rule. A missing entry, or a path through a
/// non-directory, is no cache.
///
/// # Errors
///
/// [`CliError::TrustRefused`] when anything exists at `anchor/rel`, link or not;
/// [`CliError::Io`] when its presence cannot be determined.
pub fn refuse_unverifiable_cache(anchor: &Path, rel: &str) -> Result<(), CliError> {
    let candidate = anchor.join(rel);
    match std::fs::symlink_metadata(&candidate) {
        Ok(_) => Err(CliError::TrustRefused(TrustRefusal::FfiCacheUnverifiable(
            candidate,
        ))),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(())
        }
        Err(source) => Err(CliError::Io {
            path: candidate,
            source,
        }),
    }
}

#[cfg(unix)]
pub use held::{TrustedCache, open_cache};

#[cfg(not(unix))]
pub use unverifiable::{TrustedCache, open_cache};

/// Held, no-follow descriptors over the FFI cache.
#[cfg(unix)]
mod held {
    use std::fs::File;
    use std::os::fd::{AsFd as _, BorrowedFd};
    use std::path::{Path, PathBuf};

    use ipe_ffi::driver::CacheSource;
    use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags};
    use rustix::io::Errno;

    use super::{CacheLoadError, Invoker, MAX_CACHE_ENTRIES, Stamp, TrustRefusal, breach};
    use crate::CliError;
    use crate::io_bounded::{FFI_CACHE_CAP, prove_regular, read_proven};

    /// The FFI cache directory, held open once every component passed the owner rule.
    #[derive(Debug)]
    pub struct TrustedCache {
        /// The handle every listing and read goes through.
        dir: File,
        /// The path the cache was discovered at, for diagnostics only.
        path: PathBuf,
        /// The identity each artifact's owner is checked against.
        invoker: Invoker,
    }

    impl TrustedCache {
        /// The path the cache was discovered at.
        #[must_use]
        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    /// Flags for opening one cache directory component, never through a link.
    fn dir_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    /// Flags for opening one artifact, never through a link and never blocking on a FIFO.
    fn file_flags() -> OFlags {
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
    }

    /// The type of the entry `name` under `parent`, without following a link.
    fn entry_type(parent: BorrowedFd<'_>, name: &Path) -> Result<Option<FileType>, Errno> {
        match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(FileType::from_raw_mode(stat.st_mode))),
            Err(e) if e == Errno::NOENT => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The component `name` under `parent`, or `None` when absent or not a directory.
    ///
    /// # Errors
    ///
    /// [`CliError::TrustRefused`] when the component is a symbolic link; [`CliError::Io`]
    /// when it cannot be opened for another reason.
    fn open_component(
        parent: BorrowedFd<'_>,
        name: &Path,
        shown: &Path,
    ) -> Result<Option<File>, CliError> {
        let open_err = match rustix::fs::openat(parent, name, dir_flags(), Mode::empty()) {
            Ok(fd) => return Ok(Some(File::from(fd))),
            Err(e) if e == Errno::NOENT => return Ok(None),
            Err(e) => e,
        };
        match entry_type(parent, name) {
            Ok(Some(FileType::Symlink)) => Err(CliError::TrustRefused(
                TrustRefusal::FfiCacheSymlink(shown.to_path_buf()),
            )),
            Ok(Some(FileType::Directory)) | Err(_) => Err(CliError::Io {
                path: shown.to_path_buf(),
                source: open_err.into(),
            }),
            Ok(
                None
                | Some(
                    FileType::RegularFile
                    | FileType::Fifo
                    | FileType::Socket
                    | FileType::CharacterDevice
                    | FileType::BlockDevice
                    | FileType::Unknown,
                ),
            ) => Ok(None),
        }
    }

    /// Open the cache at `anchor/rel`, owner-checking every component below `anchor`.
    ///
    /// `anchor` itself is reached by path, following links; each component of
    /// `rel` is opened relative to the handle on its parent without following
    /// a link, then checked on the opened handle. `None` when a component is
    /// absent or is not a directory.
    ///
    /// # Errors
    ///
    /// [`CliError::TrustRefused`] when a component is a symbolic link or some user
    /// other than the invoker can write it; [`CliError::Io`] when a component
    /// cannot be opened or inspected.
    pub fn open_cache(anchor: &Path, rel: &str) -> Result<Option<TrustedCache>, CliError> {
        let invoker = Invoker::current();
        let mut shown = anchor.to_path_buf();
        let mut held: Option<File> = None;
        let mut breached: Option<PathBuf> = None;
        for segment in rel.split('/') {
            shown.push(segment);
            let opened = match &held {
                None => open_component(CWD, &shown, &shown)?,
                Some(dir) => open_component(dir.as_fd(), Path::new(segment), &shown)?,
            };
            let Some(dir) = opened else {
                return Ok(None);
            };
            let meta = dir.metadata().map_err(|source| CliError::Io {
                path: shown.clone(),
                source,
            })?;
            if breached.is_none() && breach(Stamp::of(&meta), invoker).is_some() {
                breached = Some(shown.clone());
            }
            held = Some(dir);
        }
        if let Some(path) = breached {
            return Err(CliError::TrustRefused(TrustRefusal::FfiCacheUntrusted(
                path,
            )));
        }
        Ok(held.map(|dir| TrustedCache {
            dir,
            path: shown,
            invoker,
        }))
    }

    /// The UTF-8 entry names in `dir`, refusing a listing past `cap` entries.
    ///
    /// Every entry counts toward `cap`, including one whose name is not UTF-8
    /// and so is never an artifact.
    ///
    /// # Errors
    ///
    /// [`CliError::TrustRefused`] past `cap` entries; [`CliError::Io`] when the
    /// directory cannot be listed.
    pub fn list_capped(dir: &File, path: &Path, cap: usize) -> Result<Vec<String>, CliError> {
        let io = |e: Errno| CliError::Io {
            path: path.to_path_buf(),
            source: e.into(),
        };
        let mut names = Vec::new();
        let mut seen: usize = 0;
        for entry in rustix::fs::Dir::read_from(dir).map_err(io)? {
            let entry = entry.map_err(io)?;
            let raw = entry.file_name();
            if matches!(raw.to_bytes(), b"." | b"..") {
                continue;
            }
            seen = seen.saturating_add(1);
            if seen > cap {
                return Err(CliError::TrustRefused(
                    TrustRefusal::FfiCacheTooManyEntries {
                        path: path.to_path_buf(),
                        cap,
                    },
                ));
            }
            let Ok(name) = raw.to_str() else {
                continue;
            };
            names.push(name.to_owned());
        }
        Ok(names)
    }

    impl CacheSource for TrustedCache {
        type Error = CacheLoadError;

        fn root(&self) -> &Path {
            &self.path
        }

        fn entry_names(&self) -> Result<Vec<String>, CacheLoadError> {
            list_capped(&self.dir, &self.path, MAX_CACHE_ENTRIES).map_err(CacheLoadError::Cli)
        }

        fn read_artifact(&self, name: &str) -> Result<Option<String>, CacheLoadError> {
            let path = self.path.join(name);
            let refuse = |err| Err(CacheLoadError::Cli(err));
            let io = |source: std::io::Error| {
                CacheLoadError::Cli(CliError::Io {
                    path: path.clone(),
                    source,
                })
            };
            if name.is_empty() || name == "." || name == ".." || name.contains('/') {
                return Err(io(std::io::Error::from(std::io::ErrorKind::InvalidInput)));
            }
            let fd = match rustix::fs::openat(&self.dir, name, file_flags(), Mode::empty()) {
                Ok(fd) => fd,
                Err(e) if e == Errno::NOENT => return Ok(None),
                Err(e) => {
                    return match entry_type(self.dir.as_fd(), Path::new(name)) {
                        Ok(Some(FileType::Symlink)) => refuse(CliError::TrustRefused(
                            TrustRefusal::FfiCacheSymlink(path.clone()),
                        )),
                        Ok(_) | Err(_) => Err(io(e.into())),
                    };
                }
            };
            let file = File::from(fd);
            let meta = file.metadata().map_err(io)?;
            if !meta.file_type().is_file() {
                return refuse(CliError::TrustRefused(TrustRefusal::FfiCacheNotRegular(
                    path.clone(),
                )));
            }
            if breach(Stamp::of(&meta), self.invoker).is_some() {
                return refuse(CliError::TrustRefused(TrustRefusal::FfiCacheUntrusted(
                    path.clone(),
                )));
            }
            prove_regular(file, &path)
                .and_then(|file| read_proven(file, &path, FFI_CACHE_CAP))
                .map(Some)
                .map_err(CacheLoadError::Cli)
        }
    }
}

/// Off Unix no cache can be owner-checked, so none is ever held.
#[cfg(not(unix))]
mod unverifiable {
    use std::path::Path;

    use ipe_ffi::driver::CacheSource;

    use super::{CacheLoadError, refuse_unverifiable_cache};
    use crate::CliError;

    /// An owner-checked FFI cache, which this platform can never produce.
    #[derive(Debug)]
    pub enum TrustedCache {}

    impl TrustedCache {
        /// The path the cache was discovered at.
        #[must_use]
        pub const fn path(&self) -> &Path {
            match *self {}
        }
    }

    impl CacheSource for TrustedCache {
        type Error = CacheLoadError;

        fn root(&self) -> &Path {
            match *self {}
        }

        fn entry_names(&self) -> Result<Vec<String>, CacheLoadError> {
            match *self {}
        }

        fn read_artifact(&self, _name: &str) -> Result<Option<String>, CacheLoadError> {
            match *self {}
        }
    }

    /// Refuse any entry at `anchor/rel`, since its ownership cannot be verified here.
    ///
    /// # Errors
    ///
    /// As [`refuse_unverifiable_cache`].
    pub fn open_cache(anchor: &Path, rel: &str) -> Result<Option<TrustedCache>, CliError> {
        refuse_unverifiable_cache(anchor, rel).map(|()| None)
    }
}

#[cfg(test)]
mod tests;

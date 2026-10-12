//! Loose-file resolution — the one module set a `.ipe` file under no `package.ipe` compiles to.
//!
//! `ipe dev build`, `ipe dev watch`, `ipe lint`, the single-entry analysis commands
//! and `ipe lsp` all resolve a loose file here, so the editor and the batch
//! build can never disagree about which modules make up the program. The
//! set is the entry plus the transitive closure of the sibling modules its
//! imports name: each import walks exactly one path down from the entry's
//! directory, holding a directory handle at every level, refusing every
//! symlink, deciding every kind before anything is opened, and reading only
//! the regular file the walk opened; the entry itself is read beneath the
//! same directory handle. The closure is capped by [`LooseFileLimits`]. No
//! unrelated file is ever opened, so a loose file in `/tmp` or `$HOME` reads
//! nothing unrelated to it. A
//! directory is listed only when a probed name's case-swapped spelling also
//! resolves — always on a case-insensitive filesystem — and only to compare
//! its entry names against the probed name's exact spelling, so one file
//! never loads under two module keys (`import Helper` and `import HELPER`).
//! Each directory is listed at most once per load, and the names listed
//! across the load are capped by [`LooseFileLimits::listed_names`].

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use ipe_intern::{Interner, Symbol};

use crate::{CliError, io_bounded, project};

/// Upper bound on the user modules a loose-file load follows through imports.
pub const MAX_LOOSE_FILE_MODULES: usize = 256;

/// Upper bound on the source bytes a loose-file load reads across its whole closure.
pub const MAX_LOOSE_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Upper bound on the distinct module paths a loose-file load probes, the entry included.
pub const MAX_LOOSE_FILE_PROBES: usize = 4096;

/// Upper bound on the directory entry names a loose-file load lists for exact-spelling checks.
pub const MAX_LOOSE_FILE_LISTED_NAMES: usize = 65_536;

/// The ceilings one loose-file load is held to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LooseFileLimits {
    /// Most modules the closure may hold, the entry included.
    pub modules: usize,
    /// Most source bytes the closure may hold, the entry included.
    pub bytes: u64,
    /// Most distinct module paths the closure's imports may name, the entry included.
    pub probes: usize,
    /// Most directory entry names the exact-spelling checks may list, summed over every directory.
    pub listed_names: usize,
}

impl LooseFileLimits {
    /// The limits every CLI and editor surface loads a loose file under.
    pub const DEFAULT: Self = Self {
        modules: MAX_LOOSE_FILE_MODULES,
        bytes: MAX_LOOSE_FILE_BYTES,
        probes: MAX_LOOSE_FILE_PROBES,
        listed_names: MAX_LOOSE_FILE_LISTED_NAMES,
    };
}

/// Where a `.ipe` file's project is rooted.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProjectRoot {
    /// A package directory holding a `package.ipe` manifest.
    Package(PathBuf),
    /// A file under no manifest, compiled alone plus the siblings it imports.
    LooseFile(PathBuf),
}

impl ProjectRoot {
    /// Classify `file` by its nearest `package.ipe`.
    ///
    /// A workspace folder holding a manifest wins; otherwise the manifest
    /// walk-up from the file decides (it probes one `package.ipe` path per
    /// ancestor and lists no directory). A discovered manifest is obeyed only
    /// once it passes the owner rule, so an untrusted one refuses the file
    /// rather than demoting it to a loose file.
    ///
    /// # Errors
    ///
    /// The refusal of [`crate::find_manifest_for_ipe_file`] when the nearest
    /// manifest is a link, foreign-owned, or writable by another user.
    pub fn of(workspace_root: Option<&Path>, file: &Path) -> Result<Self, CliError> {
        if let Some(root) = workspace_root.filter(|root| project::manifest_in_dir(root).is_some()) {
            return Ok(Self::Package(root.to_path_buf()));
        }
        Ok(crate::find_manifest_for_ipe_file(file)?
            .and_then(|manifest| manifest.parent().map(Path::to_path_buf))
            .map_or_else(|| Self::LooseFile(file.to_path_buf()), Self::Package))
    }
}

/// The user modules a loose file resolves to, before stdlib and FFI injection.
#[derive(Debug)]
pub struct LooseFileSources {
    /// Every loaded module's path and source text, keyed by module path.
    pub sources: BTreeMap<Vec<String>, (PathBuf, String)>,
    /// The loaded modules as discovery records, in module-path order.
    pub discovered: Vec<project::DiscoveredModule>,
    /// The entry's declared module path.
    pub entry_module: Vec<String>,
    /// Every sibling file the closure's imports probe, relative to the entry's directory.
    ///
    /// A probed file that does not exist yet is listed too, so a watcher
    /// sees it appear.
    pub probed_files: Vec<PathBuf>,
    /// Every sibling file the closure loaded, relative to the entry's directory.
    ///
    /// With the entry, these are exactly the files the build reads.
    pub loaded_files: Vec<PathBuf>,
}

/// The outcome of reading one vetted sibling: its path and text.
type SiblingRead = Result<(PathBuf, String), CliError>;

/// Load a loose file plus the transitive closure of sibling modules it imports.
///
/// An import `A.B` resolves to `<dir>/A/B.ipe`, where `<dir>` is the entry's
/// directory; only that one path is probed. On unix `<dir>` is opened once,
/// before anything is read: the entry is read beneath it, and the probe
/// walks `A` then `B.ipe` from it, holding a handle at every
/// level: each name is looked up without following a link, checked for its
/// exact on-disk spelling, and opened beneath the very handle it was looked
/// up in, and the file is read from the handle the walk opened. The name
/// checked is the name opened, so a file swapped after the checks can
/// neither escape `<dir>` nor block the load. Other platforms walk by path
/// and have no such race guarantee. An import with no such file (the stdlib,
/// a typo), or one a case-insensitive lookup alone finds, is left for the
/// compiler to resolve or report, exactly as on a case-sensitive filesystem.
/// A sibling that fails to parse is still loaded — the compiler reports its
/// errors — but contributes no further imports.
/// `entry_text` shadows the entry's disk bytes (an unsaved editor buffer).
///
/// # Errors
/// [`CliError::Pipeline`] when the entry does not parse;
/// [`CliError::SourceRefused`] when the entry or a probed module is a FIFO,
/// device, socket or other non-regular file, a probed module or a directory
/// on its way is a symlink, or it lies where the process may not look (an
/// unreadable or exec-only directory); [`CliError::Io`] when the entry or a
/// probed module otherwise cannot be read; [`CliError::FileTooLarge`] when
/// one file passes [`io_bounded::SOURCE_READ_CAP`];
/// [`CliError::DiscoveryLimitReached`] when the import closure, or the
/// directory names its spelling checks list, exceed `limits`;
/// [`CliError::DeviceNamedModule`] when an import's module path names a
/// Windows reserved device.
pub fn resolve_loose_file(
    entry: &Path,
    entry_text: Option<&str>,
    limits: LooseFileLimits,
) -> Result<LooseFileSources, CliError> {
    let source_dir = SourceDir::open(entry_directory(entry));
    let entry_source = match entry_text {
        Some(text) if source_bytes(text) > limits.bytes => {
            return Err(bytes_past_budget(entry, limits));
        }
        Some(text) => text.to_owned(),
        None => charge_budget(
            source_dir.read_entry(entry, budget_cap(limits.bytes)),
            entry,
            limits.bytes,
            limits,
        )?,
    };
    let mut interner = Interner::new();
    let parsed = ipe_parse::parse_module(&entry_source, &mut interner).map_err(|diag| {
        CliError::Pipeline {
            file: entry.to_path_buf(),
            src: entry_source.clone(),
            diag: Box::new(diag),
        }
    })?;
    let entry_module = module_segments(&parsed.name.value, &interner);
    let mut pending = imported_modules(&parsed, &interner);
    let mut total_bytes = source_bytes(&entry_source);
    let mut probed: BTreeSet<Vec<String>> = BTreeSet::from([entry_module.clone()]);
    let mut probed_files = Vec::new();
    let mut loaded_files = Vec::new();
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    sources.insert(entry_module.clone(), (entry.to_path_buf(), entry_source));

    let mut spelling = Spelling::new(entry, limits.listed_names);
    while let Some(module) = pending.pop() {
        if probed.contains(&module) {
            continue;
        }
        if probed.len() >= limits.probes {
            return Err(closure_too_large(
                entry,
                &format!("more than {} distinct modules", limits.probes),
            ));
        }
        probed.insert(module.clone());
        if let project::ModulePathShape::DeviceNamed(segment) = project::module_path_shape(&module)
        {
            return Err(device_named_import(entry, &module, segment));
        }
        let Some(relative) = module_file(&module) else {
            continue;
        };
        probed_files.push(relative.clone());
        let Some(sibling) = source_dir.vet(&module, &mut spelling)? else {
            continue;
        };
        if sources.len() >= limits.modules {
            return Err(closure_too_large(
                entry,
                &format!("more than {} sibling modules", limits.modules),
            ));
        }
        let remaining = limits.bytes.saturating_sub(total_bytes);
        let read = sibling.read(budget_cap(remaining));
        let (path, source) = charge_budget(read, entry, remaining, limits)?;
        total_bytes = total_bytes.saturating_add(source_bytes(&source));
        if total_bytes > limits.bytes {
            return Err(bytes_past_budget(entry, limits));
        }
        if let Ok(parsed) = ipe_parse::parse_module(&source, &mut interner) {
            pending.extend(imported_modules(&parsed, &interner));
        }
        sources.insert(module, (path, source));
        loaded_files.push(relative);
    }

    let discovered = sources
        .iter()
        .map(|(module, (path, _))| project::DiscoveredModule::user(path.clone(), module.clone()))
        .collect();
    Ok(LooseFileSources {
        sources,
        discovered,
        entry_module,
        probed_files,
        loaded_files,
    })
}

/// The refusal for a closure past one of its [`LooseFileLimits`].
fn closure_too_large(entry: &Path, what: &str) -> CliError {
    CliError::DiscoveryLimitReached {
        detail: format!("`{}` imports {what}", entry.display()),
    }
}

/// The refusal for a closure past [`LooseFileLimits::bytes`].
fn bytes_past_budget(entry: &Path, limits: LooseFileLimits) -> CliError {
    closure_too_large(
        entry,
        &format!("more than {} bytes of source", limits.bytes),
    )
}

/// The most bytes one file may be read to with `remaining` bytes of budget left.
fn budget_cap(remaining: u64) -> u64 {
    remaining.min(io_bounded::SOURCE_READ_CAP)
}

/// Turn a read the byte budget cut short, not the per-file cap, into the closure refusal.
fn charge_budget<T>(
    read: Result<T, CliError>,
    entry: &Path,
    remaining: u64,
    limits: LooseFileLimits,
) -> Result<T, CliError> {
    match read {
        Err(CliError::FileTooLarge { .. }) if remaining < io_bounded::SOURCE_READ_CAP => {
            Err(bytes_past_budget(entry, limits))
        }
        other => other,
    }
}

/// The byte length of `source`, as counted against [`LooseFileLimits::bytes`].
fn source_bytes(source: &str) -> u64 {
    u64::try_from(source.len()).unwrap_or(u64::MAX)
}

/// The directory sibling imports resolve against: the entry's parent, or `.` for a bare file name.
fn entry_directory(entry: &Path) -> &Path {
    entry
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// The file module `A.B` lives in, `A/B.ipe`, relative to the entry's directory.
///
/// `None` unless [`project::module_path_shape`] finds a module path, so no
/// `..`, separator, empty component or device name can reach the path.
fn module_file(module: &[String]) -> Option<PathBuf> {
    (project::module_path_shape(module) == project::ModulePathShape::Module)
        .then(|| spelled_file(module))
        .flatten()
}

/// `A/B.ipe` for `A.B`, segments unchecked; `None` for the empty path.
fn spelled_file(module: &[String]) -> Option<PathBuf> {
    let (file_segment, dir_segments) = module.split_last()?;
    let mut path: PathBuf = dir_segments.iter().collect();
    path.push(format!("{file_segment}.ipe"));
    Some(path)
}

/// The refusal for an import whose well-formed module path names a Windows device.
///
/// The import is refused on every platform, as package discovery refuses
/// such a file, so one loose file maps to one module set everywhere.
fn device_named_import(entry: &Path, module: &[String], segment: &str) -> CliError {
    let dir = entry_directory(entry);
    CliError::DeviceNamedModule {
        path: spelled_file(module).map_or_else(|| dir.to_path_buf(), |file| dir.join(file)),
        segment: segment.to_owned(),
    }
}

/// The entry's directory, opened once before the entry or any sibling is read.
struct SourceDir<'e> {
    /// The directory as the entry path spells it, so diagnostics name files as the user wrote them.
    spelled: &'e Path,
    /// The handle the entry is read from and every sibling walk starts at.
    ///
    /// The user named this directory, so a link in its path is followed,
    /// once, by this open; nothing below it is. An open failure is kept
    /// rather than raised: it surfaces only when an import names something
    /// on disk, so an entry importing nothing on disk loads from a
    /// directory it may not list.
    #[cfg(unix)]
    root: Result<HeldDir, rustix::io::Errno>,
    /// The canonical directory every sibling walk starts from; `None` when it does not canonicalize.
    #[cfg(not(unix))]
    root: Option<PathDir>,
}

impl<'e> SourceDir<'e> {
    /// Open `spelled` as the directory the load reads from.
    fn open(spelled: &'e Path) -> Self {
        #[cfg(unix)]
        let root = {
            use rustix::fs::OFlags;
            rustix::fs::open(
                spelled,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map(HeldDir)
        };
        #[cfg(not(unix))]
        let root = fs::canonicalize(spelled).ok().map(PathDir);
        Self { spelled, root }
    }

    /// Read the entry file, at most `cap` bytes, beneath this directory's handle.
    ///
    /// The entry is the user-named file, so a final link is followed; its
    /// kind is checked before it is opened and again on the opened handle.
    /// When this directory's handle did not open (an exec-only directory),
    /// or off unix, the entry is read by its path under the same checks.
    ///
    /// # Errors
    /// [`CliError::SourceRefused`] when the entry is not a regular file or
    /// may not be opened; [`CliError::Io`] when it otherwise cannot be read;
    /// [`CliError::FileTooLarge`] past `cap`.
    fn read_entry(&self, entry: &Path, cap: u64) -> Result<String, CliError> {
        #[cfg(unix)]
        if let (Ok(root), Some(name)) = (&self.root, entry.file_name()) {
            return root.read_named(name, entry, cap);
        }
        read_entry_by_path(entry, cap)
    }

    /// The opened sibling file for `module`, walked down by [`walk`].
    ///
    /// `Ok(None)` — the import is left to the compiler — when the module
    /// path is malformed, [`walk`] finds nothing to open, or (off unix) the
    /// directory does not canonicalize.
    ///
    /// # Errors
    /// Any error of [`walk`]; [`CliError::SourceRefused`] when the import
    /// names something on disk but this directory's handle could not be
    /// opened (an exec-only directory).
    fn vet(
        &self,
        module: &[String],
        spelling: &mut Spelling<'_>,
    ) -> Result<Option<VettedSibling>, CliError> {
        let Some(relative) = module_file(module) else {
            return Ok(None);
        };
        let path = self.spelled.join(&relative);
        #[cfg(unix)]
        let root = match &self.root {
            Ok(root) => root,
            Err(errno) => return self.unopened(&relative, &path, *errno),
        };
        #[cfg(not(unix))]
        let Some(root) = &self.root else {
            return Ok(None);
        };
        Ok(walk(root, module, &path, spelling)?.map(|file| VettedSibling { file, path }))
    }

    /// The outcome of probing `relative` when this directory's handle failed to open with `errno`.
    ///
    /// An import whose first segment is absent is still left to the
    /// compiler; any other is refused, since it cannot be walked by handle.
    #[cfg(unix)]
    fn unopened(
        &self,
        relative: &Path,
        probed: &Path,
        errno: rustix::io::Errno,
    ) -> Result<Option<VettedSibling>, CliError> {
        let Some(first) = relative.components().next() else {
            return Ok(None);
        };
        match fs::symlink_metadata(self.spelled.join(first)) {
            Err(error) if is_absent(&error) => Ok(None),
            Err(error) => Err(io_bounded::access_error(probed, error)),
            Ok(_) => Err(io_bounded::open_error(probed, errno.into())),
        }
    }
}

/// Whether a lookup failed because the name does not exist.
fn is_absent(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// Read the user-named `entry` by its path, at most `cap` bytes, following a final link.
///
/// # Errors
/// As [`SourceDir::read_entry`].
fn read_entry_by_path(entry: &Path, cap: u64) -> Result<String, CliError> {
    let file = ipe_fs_open::RegularFile::open_user_named(entry)
        .map_err(|refusal| io_bounded::refusal_error(entry, refusal))?;
    io_bounded::read_proven_within(file, entry, cap)
}

/// What a no-follow lookup finds at one name in a walked directory, decided before anything is opened.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EntryKind {
    /// A real directory.
    Directory,
    /// A symbolic link, never followed.
    Symlink,
    /// A regular file, the one kind a module file may be opened as.
    Regular,
    /// A FIFO, socket, device or unknown kind, refused without being opened.
    NotRegular,
}

/// Why descending into a subdirectory opened nothing.
enum DescendFailure {
    /// The name is a symlink, refused by the no-follow open.
    Symlink,
    /// The name no longer exists.
    Absent,
    /// The name is not a directory; what it is must be looked up again.
    NotDirectory,
    /// Any other failure, as its typed error (boxed, so the failure stays narrow).
    Failed(Box<CliError>),
}

/// One directory of a loose file's import walk.
trait WalkDir: Sized {
    /// What opening a module file yields.
    type Opened;

    /// What `name` is in this directory, without following a link; `None` when it is absent.
    ///
    /// # Errors
    /// [`CliError::SourceRefused`] with [`io_bounded::SourceRefusal::AccessDenied`],
    /// naming `probed`, when the lookup is denied; [`CliError::Io`] when it
    /// otherwise fails.
    fn entry_kind(&self, name: &str, probed: &Path) -> Result<Option<EntryKind>, CliError>;

    /// This directory's entry names, at most `limit` of them; `None` when it holds more.
    ///
    /// # Errors
    /// The I/O error listing the directory.
    fn names(&self, limit: usize) -> io::Result<Option<Vec<OsString>>>;

    /// The subdirectory `name`, opened beneath this one without following a link.
    ///
    /// # Errors
    /// The [`DescendFailure`] saying why nothing was opened; a denied open
    /// is [`DescendFailure::Failed`] with [`CliError::SourceRefused`], naming
    /// `probed`.
    fn descend(&self, name: &str, probed: &Path) -> Result<Self, DescendFailure>;

    /// The regular file `name`, opened beneath this one without following a link.
    ///
    /// Called only once [`Self::entry_kind`] found `name` to be
    /// [`EntryKind::Regular`]; the opened handle's type is checked again.
    ///
    /// # Errors
    /// [`CliError::SourceRefused`], naming `probed`, when `name` is a
    /// symlink, is not a regular file, or may not be opened;
    /// [`CliError::Io`] when the open otherwise fails.
    fn open_file(&self, name: &str, probed: &Path) -> Result<Self::Opened, CliError>;
}

/// Walk `module` down from `root`, one directory per segment, and open its file.
///
/// Every segment is looked up without following a link, its kind decided
/// before anything is opened, checked for its exact on-disk spelling, and
/// then opened beneath the directory it was looked up in, so the name
/// checked is the name opened. Only a [`EntryKind::Regular`] file is ever
/// opened. `Ok(None)` — the import is left to the compiler — when a
/// segment or the file is absent, a segment is not a directory (also when
/// it stops being one between its lookup and its open), or a name is found
/// only because the filesystem ignores case (a case-sensitive one would not
/// find it either). A `Symlink` or `NotRegular` kind is refused as soon as
/// it is decided, before the spelling check runs — conservative on a
/// case-insensitive filesystem, where a wrongly-spelled symlink or FIFO is
/// still refused rather than passed through as absent.
///
/// # Errors
/// [`CliError::SourceRefused`], naming `probed`, with
/// [`io_bounded::SourceRefusal::Symlink`] when a segment or the file is a
/// symlink, with [`io_bounded::SourceRefusal::NotRegularFile`] when the file
/// is a directory, FIFO, device or socket (refused before any open), and
/// with [`io_bounded::SourceRefusal::AccessDenied`] when a lookup is denied;
/// any error of [`Spelling::is_exact`]; [`CliError::Io`] when a lookup or
/// open otherwise fails.
fn walk<D: WalkDir>(
    root: &D,
    module: &[String],
    probed: &Path,
    spelling: &mut Spelling<'_>,
) -> Result<Option<D::Opened>, CliError> {
    let Some((file_segment, dir_segments)) = module.split_last() else {
        return Ok(None);
    };
    let symlink = || io_bounded::source_refused(probed, io_bounded::SourceRefusal::Symlink);
    let mut descended: Option<D> = None;
    let mut key = PathBuf::new();
    for segment in dir_segments {
        let dir = descended.as_ref().unwrap_or(root);
        match dir.entry_kind(segment, probed)? {
            None | Some(EntryKind::Regular | EntryKind::NotRegular) => return Ok(None),
            Some(EntryKind::Symlink) => return Err(symlink()),
            Some(EntryKind::Directory) => {}
        }
        if !spelling.is_exact(dir, &key, segment, probed)? {
            return Ok(None);
        }
        let next = match dir.descend(segment, probed) {
            Ok(next) => next,
            Err(DescendFailure::Symlink) => return Err(symlink()),
            Err(DescendFailure::Absent) => return Ok(None),
            Err(DescendFailure::NotDirectory) => {
                return match dir.entry_kind(segment, probed)? {
                    Some(EntryKind::Symlink) => Err(symlink()),
                    None
                    | Some(EntryKind::Directory | EntryKind::Regular | EntryKind::NotRegular) => {
                        Ok(None)
                    }
                };
            }
            Err(DescendFailure::Failed(error)) => return Err(*error),
        };
        key.push(segment);
        descended = Some(next);
    }
    let dir = descended.as_ref().unwrap_or(root);
    let file_name = format!("{file_segment}.ipe");
    match dir.entry_kind(&file_name, probed)? {
        None => return Ok(None),
        Some(EntryKind::Symlink) => return Err(symlink()),
        Some(EntryKind::Directory | EntryKind::NotRegular) => {
            return Err(io_bounded::source_refused(
                probed,
                io_bounded::SourceRefusal::NotRegularFile,
            ));
        }
        Some(EntryKind::Regular) => {}
    }
    if !spelling.is_exact(dir, &key, &file_name, probed)? {
        return Ok(None);
    }
    dir.open_file(&file_name, probed).map(Some)
}

/// The flags every held directory is opened with: read-only, never through a final link.
#[cfg(unix)]
fn held_dir_flags() -> rustix::fs::OFlags {
    use rustix::fs::OFlags;
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// A directory held open by handle; every lookup and open is relative to it.
#[cfg(unix)]
struct HeldDir(OwnedFd);

#[cfg(unix)]
impl WalkDir for HeldDir {
    type Opened = fs::File;

    fn entry_kind(&self, name: &str, probed: &Path) -> Result<Option<EntryKind>, CliError> {
        use rustix::fs::{AtFlags, FileType};
        use rustix::io::Errno;
        match rustix::fs::statat(&self.0, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => EntryKind::Directory,
                FileType::Symlink => EntryKind::Symlink,
                FileType::RegularFile => EntryKind::Regular,
                FileType::Fifo
                | FileType::Socket
                | FileType::CharacterDevice
                | FileType::BlockDevice
                | FileType::Unknown => EntryKind::NotRegular,
            })),
            Err(errno) if errno == Errno::NOENT || errno == Errno::NOTDIR => Ok(None),
            Err(errno) => Err(io_bounded::access_error(probed, errno.into())),
        }
    }

    fn names(&self, limit: usize) -> io::Result<Option<Vec<OsString>>> {
        use std::os::unix::ffi::OsStrExt as _;
        let mut names = Vec::new();
        for entry in rustix::fs::Dir::read_from(&self.0)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            if names.len() >= limit {
                return Ok(None);
            }
            names.push(OsStr::from_bytes(name).to_os_string());
        }
        Ok(Some(names))
    }

    /// A symlink swapped in after the lookup is reported as a symlink.
    ///
    /// The open then fails with the platform's no-follow errno or, with
    /// `O_DIRECTORY`, `ENOTDIR`; the walk re-checks an `ENOTDIR`.
    fn descend(&self, name: &str, probed: &Path) -> Result<Self, DescendFailure> {
        use rustix::io::Errno;
        rustix::fs::openat(&self.0, name, held_dir_flags(), rustix::fs::Mode::empty())
            .map(Self)
            .map_err(|errno| {
                if names_a_nofollow_link(errno) {
                    DescendFailure::Symlink
                } else if errno == Errno::NOTDIR {
                    DescendFailure::NotDirectory
                } else if errno == Errno::NOENT {
                    DescendFailure::Absent
                } else {
                    DescendFailure::Failed(Box::new(held_open_error(probed, errno)))
                }
            })
    }

    /// Opened `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY`, so a FIFO never blocks the open and a terminal never becomes the controlling one.
    fn open_file(&self, name: &str, probed: &Path) -> Result<fs::File, CliError> {
        use rustix::fs::OFlags;
        let flags =
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
        let file = rustix::fs::openat(&self.0, name, flags, rustix::fs::Mode::empty())
            .map_err(|errno| held_open_error(probed, errno))?;
        io_bounded::regular_file(fs::File::from(file), probed)
    }
}

#[cfg(unix)]
impl HeldDir {
    /// The user-named entry `name` in this directory, read once its kind is proven regular.
    ///
    /// The final link is followed (the user named the entry), but its target
    /// is typed by `stat` before the open, so a FIFO or device is never
    /// opened, and the opened handle's type is checked again.
    ///
    /// # Errors
    /// [`CliError::SourceRefused`], naming `path`, when the entry is not a
    /// regular file or may not be opened; [`CliError::Io`] when the stat,
    /// open or read otherwise fails or the entry exceeds `cap`.
    fn read_named(&self, name: &OsStr, path: &Path, cap: u64) -> Result<String, CliError> {
        use rustix::fs::{AtFlags, FileType, OFlags};
        let stat = rustix::fs::statat(&self.0, name, AtFlags::empty())
            .map_err(|errno| io_bounded::open_error(path, errno.into()))?;
        if !matches!(FileType::from_raw_mode(stat.st_mode), FileType::RegularFile) {
            return Err(io_bounded::source_refused(
                path,
                io_bounded::SourceRefusal::NotRegularFile,
            ));
        }
        let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
        let fd = rustix::fs::openat(&self.0, name, flags, rustix::fs::Mode::empty())
            .map_err(|errno| io_bounded::open_error(path, errno.into()))?;
        let file = io_bounded::prove_regular(fs::File::from(fd), path)?;
        io_bounded::read_proven_within(file, path, cap)
    }
}

/// Whether `errno` from an `O_NOFOLLOW` open means the final component is a symlink.
///
/// Linux and macOS say `ELOOP`; FreeBSD says `EMLINK` and NetBSD `EFTYPE`.
#[cfg(unix)]
fn names_a_nofollow_link(errno: rustix::io::Errno) -> bool {
    #[cfg(target_os = "freebsd")]
    if errno == rustix::io::Errno::MLINK {
        return true;
    }
    #[cfg(target_os = "netbsd")]
    if errno == rustix::io::Errno::FTYPE {
        return true;
    }
    errno == rustix::io::Errno::LOOP
}

/// The typed error for a no-follow open beneath a held directory; a no-follow errno means a symlink.
#[cfg(unix)]
fn held_open_error(probed: &Path, errno: rustix::io::Errno) -> CliError {
    if names_a_nofollow_link(errno) {
        io_bounded::source_refused(probed, io_bounded::SourceRefusal::Symlink)
    } else {
        io_bounded::open_error(probed, errno.into())
    }
}

/// A directory walked by path; off unix nothing stops a swap between a lookup and its open.
#[cfg(not(unix))]
struct PathDir(PathBuf);

#[cfg(not(unix))]
impl WalkDir for PathDir {
    type Opened = fs::File;

    fn entry_kind(&self, name: &str, probed: &Path) -> Result<Option<EntryKind>, CliError> {
        match fs::symlink_metadata(self.0.join(name)) {
            Ok(meta) => {
                let kind = meta.file_type();
                Ok(Some(if kind.is_symlink() {
                    EntryKind::Symlink
                } else if kind.is_dir() {
                    EntryKind::Directory
                } else if kind.is_file() {
                    EntryKind::Regular
                } else {
                    EntryKind::NotRegular
                }))
            }
            Err(error) if is_absent(&error) => Ok(None),
            Err(error) => Err(io_bounded::access_error(probed, error)),
        }
    }

    fn names(&self, limit: usize) -> io::Result<Option<Vec<OsString>>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(&self.0)? {
            if names.len() >= limit {
                return Ok(None);
            }
            names.push(entry?.file_name());
        }
        Ok(Some(names))
    }

    /// The lookup is repeated, so a swap already done since the walk's lookup is caught.
    fn descend(&self, name: &str, probed: &Path) -> Result<Self, DescendFailure> {
        let path = self.0.join(name);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => Err(DescendFailure::Symlink),
            Ok(meta) if meta.is_dir() => Ok(Self(path)),
            Ok(_) => Err(DescendFailure::NotDirectory),
            Err(error) if is_absent(&error) => Err(DescendFailure::Absent),
            Err(error) => Err(DescendFailure::Failed(Box::new(io_bounded::access_error(
                probed, error,
            )))),
        }
    }

    fn open_file(&self, name: &str, _probed: &Path) -> Result<fs::File, CliError> {
        io_bounded::open_regular(&self.0.join(name), io_bounded::FinalLink::Refuse)
    }
}

/// A sibling module file the walk opened; reading consumes it.
struct VettedSibling {
    /// The file the walk opened, already checked to be a regular file.
    file: fs::File,
    /// The file's path as the user spelled the entry's directory, for diagnostics.
    path: PathBuf,
}

impl VettedSibling {
    /// Read the opened sibling, at most `cap` bytes.
    ///
    /// # Errors
    /// [`CliError::Io`] when the read fails; [`CliError::FileTooLarge`] past `cap`.
    fn read(self, cap: u64) -> SiblingRead {
        let Self { file, path } = self;
        let source = io_bounded::prove_regular(file, &path)
            .and_then(|file| io_bounded::read_proven_within(file, &path, cap))?;
        Ok((path, source))
    }
}

/// The exact-spelling checks of one load.
///
/// Each directory is listed at most once, and every listing is charged to
/// one budget of entry names.
struct Spelling<'e> {
    /// The load's entry file, named by the budget refusal.
    entry: &'e Path,
    /// Every directory listed so far, keyed by its path below the entry's directory.
    listed: BTreeMap<PathBuf, BTreeSet<OsString>>,
    /// The entry names the load may still list.
    remaining: usize,
    /// The whole budget, [`LooseFileLimits::listed_names`].
    limit: usize,
}

impl<'e> Spelling<'e> {
    /// The checks for the load of `entry`, listing at most `limit` entry names in all.
    const fn new(entry: &'e Path, limit: usize) -> Self {
        Self {
            entry,
            listed: BTreeMap::new(),
            remaining: limit,
            limit,
        }
    }

    /// Whether the existing entry `name` of `dir` is spelled on disk exactly as `name`.
    ///
    /// A case-insensitive filesystem resolves `HELPER.ipe` to `Helper.ipe`,
    /// which would load one file under two module keys. When the
    /// case-swapped spelling is absent, the lookup that found `name` was
    /// exact and nothing is listed; otherwise the entry names of `dir`
    /// (memoised under `key`, its path below the entry's directory) are
    /// compared against `name` byte for byte.
    ///
    /// # Errors
    /// [`CliError::DiscoveryLimitReached`] when the listing would pass the
    /// load's budget; [`CliError::SourceRefused`] with
    /// [`io_bounded::SourceRefusal::AccessDenied`], naming `probed`, when the
    /// listing is denied; [`CliError::Io`] when it otherwise fails. A listing
    /// that cannot be completed never reads as a misspelling.
    fn is_exact(
        &mut self,
        dir: &impl WalkDir,
        key: &Path,
        name: &str,
        probed: &Path,
    ) -> Result<bool, CliError> {
        let swapped = swap_ascii_case(name);
        if swapped == name || matches!(dir.entry_kind(&swapped, probed), Ok(None)) {
            return Ok(true);
        }
        if let Some(names) = self.listed.get(key) {
            return Ok(names.contains(OsStr::new(name)));
        }
        let names = match dir.names(self.remaining) {
            Ok(Some(names)) => names,
            Ok(None) => {
                return Err(closure_too_large(
                    self.entry,
                    &format!(
                        "modules whose directories list more than {} entries",
                        self.limit
                    ),
                ));
            }
            Err(error) => return Err(io_bounded::access_error(probed, error)),
        };
        self.remaining = self.remaining.saturating_sub(names.len());
        let names: BTreeSet<OsString> = names.into_iter().collect();
        let is_exact = names.contains(OsStr::new(name));
        self.listed.insert(key.to_path_buf(), names);
        Ok(is_exact)
    }
}

/// `name` with every ASCII letter's case inverted.
fn swap_ascii_case(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                c.to_ascii_lowercase()
            } else {
                c.to_ascii_uppercase()
            }
        })
        .collect()
}

/// Every module path `parsed` imports.
fn imported_modules(parsed: &ipe_syntax::Module, interner: &Interner) -> Vec<Vec<String>> {
    parsed
        .imports
        .iter()
        .map(|import| module_segments(&import.name.value, interner))
        .collect()
}

/// Render interned module-name segments as strings.
fn module_segments(symbols: &[Symbol], interner: &Interner) -> Vec<String> {
    symbols
        .iter()
        .map(|symbol| interner.resolve(*symbol).unwrap_or_default().to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsString;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};

    #[cfg(unix)]
    use super::HeldDir;
    use super::{
        CliError, DescendFailure, EntryKind, LooseFileLimits, LooseFileSources, ProjectRoot,
        SourceDir, Spelling, WalkDir, io_bounded, resolve_loose_file, swap_ascii_case, walk,
    };

    /// A fresh, canonical scratch directory unique to `name` and this process.
    #[allow(clippy::expect_used)] // test fixture: an unwritable temp dir IS the failure
    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            ipe_test_temp::temp_root().join(format!("ipe-loose-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create scratch dir");
        fs::canonicalize(&dir).expect("canonical scratch dir")
    }

    #[allow(clippy::expect_used)] // test fixture: an unwritable temp dir IS the failure
    fn write(path: &Path, text: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dir");
        }
        fs::write(path, text).expect("write fixture file");
    }

    fn user_modules(loaded: &LooseFileSources) -> Vec<Vec<String>> {
        loaded.sources.keys().cloned().collect()
    }

    fn module(segments: &[&str]) -> Vec<String> {
        segments.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The default limits with the module ceiling lowered to `modules`.
    const fn modules_only(modules: usize) -> LooseFileLimits {
        LooseFileLimits {
            modules,
            ..LooseFileLimits::DEFAULT
        }
    }

    /// What the resolver's walk finds for `module` under `dir`.
    fn vet(dir: &Path, module: &[String]) -> Result<Option<PathBuf>, CliError> {
        let source_dir = SourceDir::open(dir);
        let entry = dir.join("Main.ipe");
        let mut spelling = Spelling::new(&entry, LooseFileLimits::DEFAULT.listed_names);
        source_dir
            .vet(module, &mut spelling)
            .map(|sibling| sibling.map(|vetted| vetted.path))
    }

    /// The path the resolver's walk opens for `module` under `dir`, if any.
    fn vetted_path(dir: &Path, module: &[String]) -> Option<PathBuf> {
        vet(dir, module).ok().flatten()
    }

    #[test]
    #[allow(clippy::expect_used)] // a load failure IS the regression under test
    fn loose_file_beside_unreadable_directories_loads_alone() {
        let dir = scratch_dir("unreadable");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport Ipe.Io as Io\n\nmain = Io.println \"hi\"\n",
        );
        // Unrelated neighbours: a sibling module nobody imports and a
        // directory the process may not read (a systemd-private dir in `/tmp`).
        write(
            &dir.join("Other.ipe"),
            "module Other exposing (x)\n\nx = 1\n",
        );
        let locked = dir.join("locked");
        write(
            &locked.join("Hidden.ipe"),
            "module Hidden exposing (y)\n\ny = 2\n",
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o000))
                .expect("lock the unrelated directory");
        }

        let loaded = resolve_loose_file(&entry, None, LooseFileLimits::DEFAULT);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&locked, fs::Permissions::from_mode(0o755));
        }
        let _ = fs::remove_dir_all(&dir);
        let loaded = loaded.expect("a loose file loads without listing its directory");
        assert_eq!(user_modules(&loaded), vec![module(&["Main"])]);
        assert_eq!(loaded.entry_module, module(&["Main"]));
    }

    #[test]
    #[allow(clippy::expect_used)] // a load failure IS the regression under test
    fn loose_file_follows_the_sibling_modules_it_imports() {
        let dir = scratch_dir("imports");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport Helper\nimport Ipe.Io as Io\n\nmain = Io.println Helper.greeting\n",
        );
        write(
            &dir.join("Helper.ipe"),
            "module Helper exposing (greeting)\n\nimport Lib.Util\n\ngreeting = Lib.Util.word\n",
        );
        write(
            &dir.join("Lib").join("Util.ipe"),
            "module Lib.Util exposing (word)\n\nword = \"hi\"\n",
        );
        write(
            &dir.join("Unused.ipe"),
            "module Unused exposing (z)\n\nz = 3\n",
        );

        let loaded = resolve_loose_file(&entry, None, LooseFileLimits::DEFAULT);
        let _ = fs::remove_dir_all(&dir);
        let loaded = loaded.expect("imported siblings resolve");
        assert_eq!(
            user_modules(&loaded),
            vec![
                module(&["Helper"]),
                module(&["Lib", "Util"]),
                module(&["Main"])
            ]
        );
        assert_eq!(loaded.discovered.len(), 3);
        let mut loaded_files = loaded.loaded_files;
        loaded_files.sort();
        assert_eq!(
            loaded_files,
            vec![
                PathBuf::from("Helper.ipe"),
                Path::new("Lib").join("Util.ipe")
            ],
            "only the siblings read are loaded, the missing stdlib one excluded"
        );
        let mut probed_files = loaded.probed_files;
        probed_files.sort();
        assert_eq!(
            probed_files,
            vec![
                PathBuf::from("Helper.ipe"),
                Path::new("Ipe").join("Io.ipe"),
                Path::new("Lib").join("Util.ipe"),
            ],
            "every probed sibling path is listed, the missing stdlib one included"
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // a load failure IS the regression under test
    fn open_buffer_imports_drive_the_loose_file_closure() {
        let dir = scratch_dir("overlay");
        let entry = dir.join("Main.ipe");
        write(&entry, "module Main exposing (main)\n\nmain = 1\n");
        write(
            &dir.join("Helper.ipe"),
            "module Helper exposing (x)\n\nx = 1\n",
        );
        let buffer = "module Main exposing (main)\n\nimport Helper\n\nmain = Helper.x\n";

        let loaded = resolve_loose_file(&entry, Some(buffer), LooseFileLimits::DEFAULT);
        let _ = fs::remove_dir_all(&dir);
        let loaded = loaded.expect("overlay entry loads");
        assert_eq!(
            user_modules(&loaded),
            vec![module(&["Helper"]), module(&["Main"])]
        );
        assert_eq!(
            loaded
                .sources
                .get(&module(&["Main"]))
                .map(|(_, text)| text.as_str()),
            Some(buffer)
        );
    }

    #[test]
    fn loose_file_import_closure_past_the_module_limit_is_refused() {
        let dir = scratch_dir("limit");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport A\n\nmain = A.a\n",
        );
        write(
            &dir.join("A.ipe"),
            "module A exposing (a)\n\nimport B\n\na = B.b\n",
        );
        write(&dir.join("B.ipe"), "module B exposing (b)\n\nb = 1\n");

        let at_limit = resolve_loose_file(&entry, None, modules_only(3));
        let past_limit = resolve_loose_file(&entry, None, modules_only(2));
        let _ = fs::remove_dir_all(&dir);
        assert!(at_limit.is_ok(), "three modules fit a limit of three");
        assert!(
            matches!(past_limit, Err(CliError::DiscoveryLimitReached { .. })),
            "a closure one module past the limit is refused"
        );
    }

    #[test]
    fn loose_file_import_probes_past_the_probe_limit_are_refused() {
        let dir = scratch_dir("probes");
        let entry = dir.join("Main.ipe");
        // Neither import exists on disk: probing alone must be bounded.
        write(
            &entry,
            "module Main exposing (main)\n\nimport A\nimport B\n\nmain = 1\n",
        );
        let probes = |probes| LooseFileLimits {
            probes,
            ..LooseFileLimits::DEFAULT
        };

        let at_limit = resolve_loose_file(&entry, None, probes(3));
        let past_limit = resolve_loose_file(&entry, None, probes(2));
        let _ = fs::remove_dir_all(&dir);
        assert!(at_limit.is_ok(), "Main, A and B fit a probe limit of three");
        assert!(
            matches!(past_limit, Err(CliError::DiscoveryLimitReached { .. })),
            "a closure naming one module past the probe limit is refused"
        );
    }

    /// The device-named segment a load was refused for, if that is the refusal.
    fn device_segment<T>(result: &Result<T, CliError>) -> Option<&str> {
        match result {
            Err(CliError::DeviceNamedModule { segment, .. }) => Some(segment),
            _ => None,
        }
    }

    #[test]
    fn a_device_named_import_is_refused_even_without_a_file() {
        let dir = scratch_dir("device-import");
        let bare = dir.join("Bare.ipe");
        write(
            &bare,
            "module Bare exposing (main)\n\nimport Aux\n\nmain = Aux.a\n",
        );
        let nested = dir.join("Nested.ipe");
        write(
            &nested,
            "module Nested exposing (main)\n\nimport Lib.Com1\n\nmain = Com1.a\n",
        );
        let control = dir.join("Control.ipe");
        write(
            &control,
            "module Control exposing (main)\n\nimport Auxiliary\n\nmain = Auxiliary.a\n",
        );

        let bare_result = resolve_loose_file(&bare, None, LooseFileLimits::DEFAULT);
        let nested_result = resolve_loose_file(&nested, None, LooseFileLimits::DEFAULT);
        let control_result = resolve_loose_file(&control, None, LooseFileLimits::DEFAULT);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(device_segment(&bare_result), Some("Aux"));
        assert_eq!(device_segment(&nested_result), Some("Com1"));
        assert!(
            control_result.is_ok(),
            "a segment that only starts with a device name is an ordinary module"
        );
    }

    #[test]
    fn a_device_named_import_is_refused_even_when_the_file_exists() {
        let dir = scratch_dir("device-import-file");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport Nul\n\nmain = Nul.a\n",
        );
        write(&dir.join("Nul.ipe"), "module Nul exposing (a)\n\na = 1\n");

        let result = resolve_loose_file(&entry, None, LooseFileLimits::DEFAULT);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(device_segment(&result), Some("Nul"));
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // a load failure IS the regression under test
    fn loose_file_refuses_an_import_symlinked_out_of_its_directory() {
        let outside = scratch_dir("symlink-outside");
        write(
            &outside.join("Secret.ipe"),
            "module Secret exposing (s)\n\ns = 1\n",
        );
        let dir = scratch_dir("symlink");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport Secret\n\nmain = Secret.s\n",
        );
        std::os::unix::fs::symlink(outside.join("Secret.ipe"), dir.join("Secret.ipe"))
            .expect("plant symlink");

        let loaded = resolve_loose_file(&entry, None, LooseFileLimits::DEFAULT);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
        assert!(
            is_refused(&loaded, io_bounded::SourceRefusal::Symlink),
            "a symlinked module file is refused, never read or silently skipped"
        );
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // a load failure IS the regression under test
    fn loose_file_refuses_a_directory_symlinked_out_of_its_directory() {
        let outside = scratch_dir("dir-symlink-outside");
        write(
            &outside.join("Util.ipe"),
            "module Lib.Util exposing (u)\n\nu = 1\n",
        );
        let dir = scratch_dir("dir-symlink");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport Lib.Util\n\nmain = Lib.Util.u\n",
        );
        std::os::unix::fs::symlink(&outside, dir.join("Lib")).expect("plant symlink");

        let loaded = resolve_loose_file(&entry, None, LooseFileLimits::DEFAULT);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
        assert!(
            is_refused(&loaded, io_bounded::SourceRefusal::Symlink),
            "a symlinked intermediate directory is refused"
        );
    }

    /// A directory symlink that stays inside is refused all the same.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed symlink IS the failure
    fn loose_file_refuses_a_directory_symlinked_inside_its_directory() {
        let dir = scratch_dir("dir-symlink-inside");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport A.B\n\nmain = A.B.b\n",
        );
        write(
            &dir.join("Real").join("B.ipe"),
            "module A.B exposing (b)\n\nb = 1\n",
        );
        std::os::unix::fs::symlink(dir.join("Real"), dir.join("A")).expect("plant symlink");

        let probed = dir.join("A").join("B.ipe");
        let passes_regular_file_check =
            fs::symlink_metadata(&probed).is_ok_and(|meta| meta.file_type().is_file());
        let passes_containment =
            fs::canonicalize(&probed).is_ok_and(|canonical| canonical.starts_with(&dir));
        let loaded = resolve_loose_file(&entry, None, LooseFileLimits::DEFAULT);
        let _ = fs::remove_dir_all(&dir);
        assert!(
            passes_regular_file_check && passes_containment,
            "only the symlinked directory component sets this path apart"
        );
        assert!(
            is_refused(&loaded, io_bounded::SourceRefusal::Symlink),
            "the no-follow walk refuses the symlinked directory"
        );
    }

    #[test]
    fn file_inside_a_package_resolves_to_the_package_root() {
        let dir = scratch_dir("package-root");
        write(
            &dir.join("package.ipe"),
            "module Package exposing (package)\n",
        );
        let entry = dir.join("src").join("Main.ipe");
        write(&entry, "module Main exposing (main)\n\nmain = 1\n");

        let from_walk_up = ProjectRoot::of(None, &entry);
        let from_workspace = ProjectRoot::of(Some(&dir), &entry);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(from_walk_up.ok(), Some(ProjectRoot::Package(dir.clone())));
        assert_eq!(from_workspace.ok(), Some(ProjectRoot::Package(dir)));
    }

    #[test]
    fn file_under_no_manifest_is_a_loose_file() {
        let dir = scratch_dir("loose-root");
        let entry = dir.join("Main.ipe");
        write(&entry, "module Main exposing (main)\n\nmain = 1\n");

        let root = ProjectRoot::of(Some(&dir), &entry);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(root.ok(), Some(ProjectRoot::LooseFile(entry)));
    }

    #[test]
    fn loose_file_import_closure_past_the_byte_budget_is_refused() {
        let dir = scratch_dir("bytes");
        let entry = dir.join("Main.ipe");
        let entry_text = "module Main exposing (main)\n\nimport A\n\nmain = A.a\n";
        let sibling_text = "module A exposing (a)\n\na = 1\n";
        write(&entry, entry_text);
        write(&dir.join("A.ipe"), sibling_text);
        let closure_bytes = u64::try_from(entry_text.len() + sibling_text.len()).unwrap_or(0);
        let budget = |bytes| LooseFileLimits {
            bytes,
            ..LooseFileLimits::DEFAULT
        };

        let at_budget = resolve_loose_file(&entry, None, budget(closure_bytes));
        let past_budget = resolve_loose_file(&entry, None, budget(closure_bytes - 1));
        let _ = fs::remove_dir_all(&dir);
        assert!(
            at_budget.is_ok(),
            "a closure exactly at the byte budget loads"
        );
        assert!(
            matches!(past_budget, Err(CliError::DiscoveryLimitReached { .. })),
            "a sibling read one byte past the budget is refused as a closure limit"
        );
    }

    #[test]
    fn loose_file_entry_past_the_byte_budget_is_refused_before_parsing() {
        let dir = scratch_dir("entry-bytes");
        let entry = dir.join("Main.ipe");
        let entry_text = "module Main exposing (main)\n\nmain = 1\n";
        write(&entry, entry_text);
        let entry_bytes = u64::try_from(entry_text.len()).unwrap_or(0);
        let budget = LooseFileLimits {
            bytes: entry_bytes - 1,
            ..LooseFileLimits::DEFAULT
        };

        let from_disk = resolve_loose_file(&entry, None, budget);
        let from_buffer = resolve_loose_file(&entry, Some(entry_text), budget);
        let _ = fs::remove_dir_all(&dir);
        assert!(
            matches!(from_disk, Err(CliError::DiscoveryLimitReached { .. })),
            "an entry file one byte past the budget is refused"
        );
        assert!(
            matches!(from_buffer, Err(CliError::DiscoveryLimitReached { .. })),
            "an editor buffer one byte past the budget is refused"
        );
    }

    #[test]
    fn repeated_imports_load_each_sibling_once() {
        let dir = scratch_dir("diamond");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport Left\nimport Right\nimport Ipe.Io as Io\n\nmain = Left.l\n",
        );
        write(
            &dir.join("Left.ipe"),
            "module Left exposing (l)\n\nimport Shared\nimport Ipe.Io as Io\n\nl = Shared.s\n",
        );
        write(
            &dir.join("Right.ipe"),
            "module Right exposing (r)\n\nimport Shared\nimport Ipe.Io as Io\n\nr = Shared.s\n",
        );
        write(
            &dir.join("Shared.ipe"),
            "module Shared exposing (s)\n\ns = 1\n",
        );

        // A limit of four fits the diamond only if `Shared` counts once.
        let loaded = resolve_loose_file(&entry, None, modules_only(4));
        let _ = fs::remove_dir_all(&dir);
        assert!(
            loaded.is_ok_and(|loaded| loaded.sources.len() == 4),
            "the diamond loads Main, Left, Right and Shared once each"
        );
    }

    /// The walk refuses a module reached through a directory symlinked outside.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed symlink IS the failure
    fn sibling_path_through_a_parent_symlinked_outside_is_refused() {
        let outside = scratch_dir("parent-link-outside");
        write(&outside.join("B.ipe"), "module A.B exposing (b)\n\nb = 1\n");
        let dir = scratch_dir("parent-link");
        std::os::unix::fs::symlink(&outside, dir.join("A")).expect("plant symlink");

        let probed = dir.join("A").join("B.ipe");
        let passes_regular_file_check =
            fs::symlink_metadata(&probed).is_ok_and(|meta| meta.file_type().is_file());
        let walked = vet(&dir, &module(&["A", "B"]));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
        assert!(
            passes_regular_file_check,
            "the file behind the symlinked parent is a regular file"
        );
        assert!(
            is_refused(&walked, io_bounded::SourceRefusal::Symlink),
            "the no-follow walk refuses the symlinked directory"
        );
    }

    /// An in-directory file symlink is refused although its target stays inside.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed symlink IS the failure
    fn sibling_file_symlinked_inside_the_directory_is_refused_as_a_symlink() {
        let dir = scratch_dir("file-link");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport X\n\nmain = X.x\n",
        );
        write(&dir.join("Real.ipe"), "module X exposing (x)\n\nx = 1\n");
        std::os::unix::fs::symlink(dir.join("Real.ipe"), dir.join("X.ipe")).expect("plant symlink");

        let passes_containment =
            fs::canonicalize(dir.join("X.ipe")).is_ok_and(|canonical| canonical.starts_with(&dir));
        let loaded = resolve_loose_file(&entry, None, LooseFileLimits::DEFAULT);
        let _ = fs::remove_dir_all(&dir);
        assert!(
            passes_containment,
            "the symlink target stays in the directory"
        );
        assert!(
            is_refused(&loaded, io_bounded::SourceRefusal::Symlink),
            "the no-follow walk refuses the final symlink"
        );
    }

    /// A symlink swapped in after the lookup is refused by the no-follow open beneath the held handle.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed open or symlink IS the failure
    fn opens_beneath_a_held_directory_refuse_a_swapped_in_symlink() {
        let dir = scratch_dir("held-swap");
        write(
            &dir.join("Real").join("B.ipe"),
            "module A.B exposing (b)\n\nb = 1\n",
        );
        std::os::unix::fs::symlink(dir.join("Real").join("B.ipe"), dir.join("X.ipe"))
            .expect("plant file symlink");
        std::os::unix::fs::symlink(dir.join("Real"), dir.join("A")).expect("plant dir symlink");
        let held = rustix::fs::open(
            dir.as_path(),
            super::held_dir_flags(),
            rustix::fs::Mode::empty(),
        )
        .map(HeldDir)
        .expect("hold the directory");

        let probed = dir.join("probed");
        let file = held.open_file("X.ipe", &probed).map(drop);
        let descended = held.descend("A", &probed).map(drop);
        let rechecked = held.entry_kind("A", &probed);
        let real = held.descend("Real", &probed).map(drop);
        let _ = fs::remove_dir_all(&dir);
        let symlink = io_bounded::SourceRefusal::Symlink;
        assert!(is_refused(&file, symlink), "a file symlink is never opened");
        // `O_DIRECTORY | O_NOFOLLOW` on a directory symlink fails with the
        // no-follow errno or, on Linux, `ENOTDIR`; either way nothing is opened,
        // and the walk's re-lookup after `NotDirectory` names the symlink.
        assert!(
            matches!(
                descended,
                Err(DescendFailure::Symlink | DescendFailure::NotDirectory)
            ),
            "a directory symlink is never descended"
        );
        assert!(
            matches!(descended, Err(DescendFailure::Symlink))
                || matches!(rechecked, Ok(Some(EntryKind::Symlink))),
            "a refused descent into a directory symlink is classified as a symlink"
        );
        assert!(real.is_ok(), "a real directory is descended");
    }

    #[test]
    fn sibling_path_with_a_parent_or_empty_segment_is_refused() {
        let dir = scratch_dir("segments");
        let sub = dir.join("sub");
        write(&sub.join("X.ipe"), "module X exposing (x)\n\nx = 1\n");

        let plain = vetted_path(&sub, &module(&["X"]));
        let parent = vetted_path(&sub, &module(&["..", "sub", "X"]));
        let empty = vetted_path(&sub, &module(&["", "X"]));
        let none = vetted_path(&sub, &[]);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(plain, Some(sub.join("X.ipe")), "the control path resolves");
        assert_eq!(parent, None, "a `..` segment is refused");
        assert_eq!(empty, None, "an empty segment is refused");
        assert_eq!(none, None, "an empty module path is refused");
    }

    /// Make `path` a FIFO.
    #[cfg(unix)]
    #[allow(clippy::expect_used)] // test fixture: a failed `mkfifo` IS the failure
    fn make_fifo(path: &Path) {
        let made = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo creates the fixture");
    }

    /// Whether `result` is the typed refusal for `reason`.
    fn is_refused<T>(result: &Result<T, CliError>, reason: io_bounded::SourceRefusal) -> bool {
        matches!(result, Err(CliError::SourceRefused { reason: got, .. }) if *got == reason)
    }

    /// An imported FIFO is refused without blocking the load.
    ///
    /// Every open is non-blocking, so the test needs no writer and no timeout.
    #[cfg(unix)]
    #[test]
    fn sibling_fifo_is_refused_without_blocking() {
        let dir = scratch_dir("fifo");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport Pipe\n\nmain = Pipe.x\n",
        );
        make_fifo(&dir.join("Pipe.ipe"));

        let walked = vet(&dir, &module(&["Pipe"]));
        let loaded = resolve_loose_file(&entry, None, LooseFileLimits::DEFAULT);
        let _ = fs::remove_dir_all(&dir);
        let not_regular = io_bounded::SourceRefusal::NotRegularFile;
        assert!(
            is_refused(&walked, not_regular),
            "the walk refuses a FIFO without reading it"
        );
        assert!(
            is_refused(&loaded, not_regular),
            "the load refuses an imported FIFO"
        );
    }

    /// A FIFO as the entry itself is refused at once, never blocking on a writer.
    #[cfg(unix)]
    #[test]
    fn entry_fifo_is_refused_without_blocking() {
        let dir = scratch_dir("entry-fifo");
        let entry = dir.join("Main.ipe");
        make_fifo(&entry);
        let loaded = resolve_loose_file(&entry, None, LooseFileLimits::DEFAULT);
        let _ = fs::remove_dir_all(&dir);
        assert!(
            is_refused(&loaded, io_bounded::SourceRefusal::NotRegularFile),
            "a FIFO entry is refused as not a regular file"
        );
    }

    /// An import under a directory the process may not search is refused, not reported missing.
    ///
    /// Skipped when the permission bits are not enforced (running as root).
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: an unchangeable mode IS the failure
    fn sibling_under_an_unreadable_directory_is_refused_as_access_denied() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("locked-import");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport Locked.Hidden\n\nmain = Locked.Hidden.y\n",
        );
        let locked = dir.join("Locked");
        write(
            &locked.join("Hidden.ipe"),
            "module Locked.Hidden exposing (y)\n\ny = 2\n",
        );
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000))
            .expect("lock the directory");
        let privileged = fs::read_dir(&locked).is_ok();
        let loaded = resolve_loose_file(&entry, None, LooseFileLimits::DEFAULT);
        let _ = fs::set_permissions(&locked, fs::Permissions::from_mode(0o755));
        let _ = fs::remove_dir_all(&dir);
        if privileged {
            return;
        }
        assert!(
            is_refused(&loaded, io_bounded::SourceRefusal::AccessDenied),
            "an import the process may not look up is refused as access denied"
        );
    }

    /// Siblings in an exec-only directory are refused as access denied, not a raw I/O error.
    ///
    /// The entry opens by name, but the directory handle every sibling read
    /// walks from needs the read bit. Skipped when running as root.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: an unchangeable mode IS the failure
    fn sibling_in_an_exec_only_directory_is_refused_as_access_denied() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("exec-only");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport Helper\n\nmain = Helper.x\n",
        );
        write(
            &dir.join("Helper.ipe"),
            "module Helper exposing (x)\n\nx = 1\n",
        );
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o311)).expect("drop the read bit");
        let privileged = fs::read_dir(&dir).is_ok();
        let loaded = resolve_loose_file(&entry, None, LooseFileLimits::DEFAULT);
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o755));
        let _ = fs::remove_dir_all(&dir);
        if privileged {
            return;
        }
        assert!(
            is_refused(&loaded, io_bounded::SourceRefusal::AccessDenied),
            "a sibling read from an exec-only directory is refused as access denied"
        );
    }

    /// An entry in an exec-only directory whose only import names a stdlib
    /// module loads through the by-path fallback.
    ///
    /// No sibling file exists to probe, so the walk's `unopened` branch
    /// finds nothing at the import's first segment and leaves it to the
    /// compiler — the unopened directory handle is never a refusal. Skipped
    /// when running as root.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture setup, and a load failure, are both the regression under test
    fn entry_in_an_exec_only_directory_with_only_stdlib_imports_loads() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("exec-only-stdlib-entry");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport Ipe.Io as Io\n\nmain = Io.println \"hi\"\n",
        );
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o311)).expect("drop the read bit");
        let privileged = fs::read_dir(&dir).is_ok();
        let loaded = resolve_loose_file(&entry, None, LooseFileLimits::DEFAULT);
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o755));
        let _ = fs::remove_dir_all(&dir);
        if privileged {
            return;
        }
        let loaded = loaded.expect("the entry loads by path, its only import unresolved on disk");
        assert_eq!(user_modules(&loaded), vec![module(&["Main"])]);
    }

    /// A FIFO entry in an exec-only directory is refused before the by-path
    /// fallback ever opens it.
    ///
    /// The by-path fallback opens non-blocking and proves the handle regular,
    /// which needs only the exec bit on the directory to reach the entry by
    /// name. Skipped when running as root.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: an unchangeable mode IS the failure
    fn fifo_entry_in_an_exec_only_directory_is_refused_as_not_regular_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("exec-only-fifo-entry");
        let entry = dir.join("Main.ipe");
        make_fifo(&entry);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o311)).expect("drop the read bit");
        let privileged = fs::read_dir(&dir).is_ok();
        let loaded = resolve_loose_file(&entry, None, LooseFileLimits::DEFAULT);
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o755));
        let _ = fs::remove_dir_all(&dir);
        if privileged {
            return;
        }
        assert!(
            is_refused(&loaded, io_bounded::SourceRefusal::NotRegularFile),
            "a FIFO entry in an exec-only directory is refused as not a regular file"
        );
    }

    /// A user-named entry that is a link, in an exec-only directory, is read through the link.
    ///
    /// The by-path fallback is the user-named read, so it follows the final
    /// link the user named. Skipped when running as root.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: an unchangeable mode IS the failure
    fn a_user_named_entry_symlink_in_an_exec_only_directory_is_followed() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("exec-only-link-entry");
        let real = scratch_dir("exec-only-link-target");
        write(
            &real.join("Main.ipe"),
            "module Main exposing (main)\n\nmain = 1\n",
        );
        let entry = dir.join("Main.ipe");
        std::os::unix::fs::symlink(real.join("Main.ipe"), &entry).expect("plant the entry link");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o311)).expect("drop the read bit");
        let privileged = fs::read_dir(&dir).is_ok();
        let loaded = resolve_loose_file(&entry, None, LooseFileLimits::DEFAULT);
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o755));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&real);
        if privileged {
            return;
        }
        assert!(
            loaded.is_ok(),
            "a user-named entry link must be followed: {:?}",
            loaded.err()
        );
    }

    #[test]
    fn swapping_case_changes_every_module_file_name() {
        assert_eq!(swap_ascii_case("Helper.ipe"), "hELPER.IPE");
        assert_eq!(swap_ascii_case("A1.ipe"), "a1.IPE");
        assert_eq!(swap_ascii_case("Lib"), "lIB");
        assert_ne!(swap_ascii_case("x.ipe"), "x.ipe");
    }

    #[test]
    #[allow(clippy::expect_used)] // a load failure IS the regression under test
    fn a_case_mismatched_import_is_never_loaded_on_any_filesystem() {
        let dir = scratch_dir("case-parity");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport Helper\nimport Lib.Util\n\nmain = 1\n",
        );
        write(
            &dir.join("helper.ipe"),
            "module Helper exposing (x)\n\nx = 1\n",
        );
        write(
            &dir.join("lib").join("Util.ipe"),
            "module Lib.Util exposing (u)\n\nu = 1\n",
        );

        let loaded = resolve_loose_file(&entry, None, LooseFileLimits::DEFAULT);
        let _ = fs::remove_dir_all(&dir);
        let loaded = loaded.expect("the entry loads");
        assert_eq!(
            user_modules(&loaded),
            vec![module(&["Main"])],
            "a file or directory spelled differently on disk is left to the compiler, as on a case-sensitive filesystem"
        );
    }

    #[test]
    fn an_exactly_spelled_sibling_is_vetted() {
        let dir = scratch_dir("exact-spelling");
        write(
            &dir.join("Helper.ipe"),
            "module Helper exposing (x)\n\nx = 1\n",
        );
        write(
            &dir.join("Lib").join("Util.ipe"),
            "module Lib.Util exposing (u)\n\nu = 1\n",
        );

        let helper = vetted_path(&dir, &module(&["Helper"]));
        let util = vetted_path(&dir, &module(&["Lib", "Util"]));
        let shouted = vetted_path(&dir, &module(&["HELPER"]));
        let shouted_dir = vetted_path(&dir, &module(&["LIB", "Util"]));
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(helper, Some(dir.join("Helper.ipe")));
        assert_eq!(util, Some(dir.join("Lib").join("Util.ipe")));
        assert_eq!(shouted, None, "a case variant of the file is not vetted");
        assert_eq!(
            shouted_dir, None,
            "a case variant of a directory is not vetted"
        );
    }

    /// An in-memory directory tree whose lookups may ignore case, as on macOS or Windows.
    struct FakeFs {
        /// Every directory, keyed by its on-disk path, with its entry names.
        dirs: BTreeMap<PathBuf, Vec<OsString>>,
        /// Whether a lookup matches a name of any ASCII case.
        ignores_case: bool,
        /// The error every listing fails with, if any.
        failure: Option<io::ErrorKind>,
        /// How many times a directory was listed.
        listings: Cell<usize>,
        /// Every on-disk path that is a FIFO, device or socket rather than a regular file.
        not_regular: BTreeSet<PathBuf>,
        /// How many times a file was opened.
        opens: Cell<usize>,
        /// A directory swapped for another kind, or removed, the moment it is descended into.
        swap: Option<(PathBuf, Option<EntryKind>)>,
        /// Whether [`Self::swap`] has happened.
        swapped: Cell<bool>,
    }

    impl FakeFs {
        fn new(ignores_case: bool, dirs: &[(&str, &[&str])]) -> Self {
            Self {
                dirs: dirs
                    .iter()
                    .map(|(path, names)| {
                        (
                            PathBuf::from(path),
                            names.iter().map(OsString::from).collect(),
                        )
                    })
                    .collect(),
                ignores_case,
                failure: None,
                listings: Cell::new(0),
                not_regular: BTreeSet::new(),
                opens: Cell::new(0),
                swap: None,
                swapped: Cell::new(false),
            }
        }

        fn root(&self) -> FakeDir<'_> {
            FakeDir {
                fs: self,
                path: PathBuf::default(),
            }
        }
    }

    /// One directory of a [`FakeFs`].
    struct FakeDir<'f> {
        fs: &'f FakeFs,
        path: PathBuf,
    }

    impl FakeDir<'_> {
        /// The on-disk path a lookup of `name` resolves to.
        fn resolve(&self, name: &str) -> Option<PathBuf> {
            let names = self.fs.dirs.get(&self.path)?;
            names
                .iter()
                .find(|entry| {
                    entry.to_str().is_some_and(|entry| {
                        if self.fs.ignores_case {
                            entry.eq_ignore_ascii_case(name)
                        } else {
                            entry == name
                        }
                    })
                })
                .map(|entry| self.path.join(entry))
        }
    }

    impl WalkDir for FakeDir<'_> {
        type Opened = PathBuf;

        fn entry_kind(&self, name: &str, _probed: &Path) -> Result<Option<EntryKind>, CliError> {
            let path = self.resolve(name);
            if let (Some(path), Some((swapped, kind))) = (&path, &self.fs.swap)
                && self.fs.swapped.get()
                && path == swapped
            {
                return Ok(*kind);
            }
            Ok(path.map(|path| {
                if self.fs.dirs.contains_key(&path) {
                    EntryKind::Directory
                } else if self.fs.not_regular.contains(&path) {
                    EntryKind::NotRegular
                } else {
                    EntryKind::Regular
                }
            }))
        }

        fn names(&self, limit: usize) -> io::Result<Option<Vec<OsString>>> {
            self.fs.listings.set(self.fs.listings.get() + 1);
            if let Some(kind) = self.fs.failure {
                return Err(io::Error::from(kind));
            }
            let names = self.fs.dirs.get(&self.path).cloned().unwrap_or_default();
            Ok((names.len() <= limit).then_some(names))
        }

        fn descend(&self, name: &str, _probed: &Path) -> Result<Self, DescendFailure> {
            let path = self.resolve(name).unwrap_or_default();
            if self
                .fs
                .swap
                .as_ref()
                .is_some_and(|(swapped, _)| *swapped == path)
            {
                self.fs.swapped.set(true);
                return Err(DescendFailure::NotDirectory);
            }
            Ok(Self { fs: self.fs, path })
        }

        fn open_file(&self, name: &str, _probed: &Path) -> Result<PathBuf, CliError> {
            self.fs.opens.set(self.fs.opens.get() + 1);
            Ok(self.resolve(name).unwrap_or_default())
        }
    }

    /// Walk `segments` in `fs` with a fresh load's spelling checks under `limit`.
    fn fake_walk(
        fs: &FakeFs,
        segments: &[&str],
        limit: usize,
    ) -> Result<Option<PathBuf>, CliError> {
        let entry = PathBuf::from("Main.ipe");
        let mut spelling = Spelling::new(&entry, limit);
        walk(
            &fs.root(),
            &module(segments),
            Path::new("probed"),
            &mut spelling,
        )
    }

    /// A FIFO, device or socket module file is refused before anything is opened.
    #[test]
    fn a_not_regular_file_is_refused_without_an_open() {
        let mut fs = FakeFs::new(false, &[("", &["Pipe.ipe", "Plain.ipe"])]);
        fs.not_regular.insert(PathBuf::from("Pipe.ipe"));
        let limit = LooseFileLimits::DEFAULT.listed_names;
        let refused = fake_walk(&fs, &["Pipe"], limit);
        assert!(is_refused(
            &refused,
            io_bounded::SourceRefusal::NotRegularFile
        ));
        assert_eq!(fs.opens.get(), 0, "a non-regular file is never opened");
        let plain = fake_walk(&fs, &["Plain"], limit);
        assert_eq!(plain.ok().flatten(), Some(PathBuf::from("Plain.ipe")));
        assert_eq!(fs.opens.get(), 1, "a regular file is opened once");
    }

    /// A non-regular entry where a directory segment belongs is left to the compiler.
    #[test]
    fn a_not_regular_directory_segment_is_left_to_the_compiler() {
        let mut fs = FakeFs::new(false, &[("", &["Pipe"])]);
        fs.not_regular.insert(PathBuf::from("Pipe"));
        let walked = fake_walk(&fs, &["Pipe", "B"], LooseFileLimits::DEFAULT.listed_names);
        assert!(matches!(walked, Ok(None)));
        assert_eq!(fs.opens.get(), 0);
    }

    /// The walk of `A.B` when `A` becomes `kind` between its lookup and its open.
    ///
    /// Yields the walk, whether the open of `A` was reached, and the file opens.
    fn walk_swapped(kind: Option<EntryKind>) -> SwappedWalk {
        let mut fs = FakeFs::new(false, &[("", &["A"]), ("A", &["B.ipe"])]);
        fs.swap = Some((PathBuf::from("A"), kind));
        let walked = fake_walk(&fs, &["A", "B"], LooseFileLimits::DEFAULT.listed_names);
        (walked, fs.swapped.get(), fs.opens.get())
    }

    /// What [`walk_swapped`] yields.
    type SwappedWalk = (Result<Option<PathBuf>, CliError>, bool, usize);

    /// A directory segment that stops being one before it is opened reads as the static case.
    #[test]
    fn a_segment_swapped_before_its_open_agrees_with_the_static_case() {
        for kind in [
            None,
            Some(EntryKind::Regular),
            Some(EntryKind::NotRegular),
            Some(EntryKind::Directory),
        ] {
            let (walked, descended, opens) = walk_swapped(kind);
            assert!(descended, "the walk reached the open of `A`");
            assert!(
                matches!(walked, Ok(None)),
                "a segment swapped to {kind:?} is left to the compiler"
            );
            assert_eq!(opens, 0);
        }
        let (walked, descended, opens) = walk_swapped(Some(EntryKind::Symlink));
        assert!(descended, "the walk reached the open of `A`");
        assert!(
            is_refused(&walked, io_bounded::SourceRefusal::Symlink),
            "a segment swapped to a symlink is refused as one"
        );
        assert_eq!(opens, 0);
    }

    #[test]
    fn a_case_insensitive_match_is_left_to_the_compiler() {
        let fs = FakeFs::new(
            true,
            &[("", &["helper.ipe", "lib"]), ("lib", &["Util.ipe"])],
        );
        let limit = LooseFileLimits::DEFAULT.listed_names;
        assert!(matches!(fake_walk(&fs, &["Helper"], limit), Ok(None)));
        assert!(matches!(fake_walk(&fs, &["Lib", "Util"], limit), Ok(None)));
        assert!(matches!(fake_walk(&fs, &["lib", "UTIL"], limit), Ok(None)));
        assert_eq!(
            fake_walk(&fs, &["helper"], limit).ok().flatten(),
            Some(PathBuf::from("helper.ipe"))
        );
        assert_eq!(
            fake_walk(&fs, &["lib", "Util"], limit).ok().flatten(),
            Some(Path::new("lib").join("Util.ipe"))
        );
    }

    #[test]
    fn a_case_swapped_sibling_does_not_hide_the_exact_spelling() {
        let fs = FakeFs::new(false, &[("", &["Helper.ipe", "hELPER.IPE"])]);
        let found = fake_walk(&fs, &["Helper"], LooseFileLimits::DEFAULT.listed_names);
        assert_eq!(found.ok().flatten(), Some(PathBuf::from("Helper.ipe")));
        assert_eq!(
            fs.listings.get(),
            1,
            "the swapped spelling forces one listing"
        );
    }

    /// Whether `name` in the root of `fs` is the exact spelling, checked by `spelling`.
    fn exact(spelling: &mut Spelling<'_>, fs: &FakeFs, name: &str) -> Result<bool, CliError> {
        spelling.is_exact(&fs.root(), Path::new(""), name, Path::new("probed"))
    }

    #[test]
    fn a_case_variant_is_not_the_exact_spelling() {
        let fs = FakeFs::new(true, &[("", &["Helper.ipe"])]);
        let entry = PathBuf::from("Main.ipe");
        let mut spelling = Spelling::new(&entry, 16);
        assert!(matches!(exact(&mut spelling, &fs, "HELPER.ipe"), Ok(false)));
        assert!(matches!(exact(&mut spelling, &fs, "Helper.ipe"), Ok(true)));
    }

    #[test]
    fn the_exact_spelling_is_found_among_case_variants() {
        let fs = FakeFs::new(true, &[("", &["helper.ipe", "Helper.ipe"])]);
        let entry = PathBuf::from("Main.ipe");
        let mut spelling = Spelling::new(&entry, 16);
        assert!(matches!(exact(&mut spelling, &fs, "Helper.ipe"), Ok(true)));
        assert!(matches!(exact(&mut spelling, &fs, "helper.ipe"), Ok(true)));
        assert!(matches!(exact(&mut spelling, &fs, "HELPER.ipe"), Ok(false)));
    }

    #[test]
    fn a_directory_is_listed_once_per_load() {
        let fs = FakeFs::new(true, &[("", &["Helper.ipe", "Other.ipe"])]);
        let entry = PathBuf::from("Main.ipe");
        let mut spelling = Spelling::new(&entry, 16);
        assert!(matches!(exact(&mut spelling, &fs, "Helper.ipe"), Ok(true)));
        assert!(matches!(exact(&mut spelling, &fs, "Helper.ipe"), Ok(true)));
        assert!(matches!(exact(&mut spelling, &fs, "Other.ipe"), Ok(true)));
        assert_eq!(fs.listings.get(), 1);
    }

    #[test]
    fn an_absent_case_swap_is_exact_without_listing() {
        let fs = FakeFs::new(false, &[("", &["Helper.ipe"])]);
        let entry = PathBuf::from("Main.ipe");
        let mut spelling = Spelling::new(&entry, 0);
        assert!(matches!(exact(&mut spelling, &fs, "Helper.ipe"), Ok(true)));
        assert_eq!(
            fs.listings.get(),
            0,
            "a case-sensitive lookup lists nothing"
        );
    }

    #[test]
    fn the_listing_budget_is_exact_and_aggregate() {
        let fs = FakeFs::new(
            true,
            &[("", &["A.ipe", "lib"]), ("lib", &["B.ipe", "C.ipe"])],
        );
        let at_budget = fake_walk(&fs, &["lib", "B"], 4);
        let past_budget = fake_walk(&fs, &["lib", "B"], 3);
        assert_eq!(
            at_budget.ok().flatten(),
            Some(Path::new("lib").join("B.ipe")),
            "two directories of two names each fit a budget of four"
        );
        assert!(
            matches!(past_budget, Err(CliError::DiscoveryLimitReached { .. })),
            "the second listing passes a budget of three summed over both directories"
        );
    }

    #[test]
    fn a_denied_listing_is_refused_as_access_denied() {
        let mut fs = FakeFs::new(true, &[("", &["Helper.ipe"])]);
        fs.failure = Some(io::ErrorKind::PermissionDenied);
        let walked = fake_walk(&fs, &["Helper"], 16);
        assert!(is_refused(&walked, io_bounded::SourceRefusal::AccessDenied));
    }

    #[test]
    fn a_failed_listing_is_an_io_error() {
        let mut fs = FakeFs::new(true, &[("", &["Helper.ipe"])]);
        fs.failure = Some(io::ErrorKind::Other);
        let walked = fake_walk(&fs, &["Helper"], 16);
        assert!(
            matches!(walked, Err(CliError::Io { .. })),
            "a listing that cannot be completed never reads as a misspelling"
        );
    }
}

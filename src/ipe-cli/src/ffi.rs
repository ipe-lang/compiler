//! The `ipe rust add` / `ipe rust install` / `ipe rust remove` commands and the
//! build-time FFI seam: interface-module injection + backend emission-input
//! assembly.
//!
//! `ipe rust add <crate>` runs the `ipe-ffi-inspector` inside the `ipe_sandbox`
//! bubblewrap jail (fetch posture: network on, everything else confined),
//! decodes the inspection, and writes the six cache artifacts under
//! `<project>/.ipe/cache/ffi/rust/`. At build time the driver loads that
//! cache, injects one `Rust.<Crate>` interface module per installed crate
//! (origin [`ipe_canon::ModuleOrigin::FfiInterface`] — unforgeable), and
//! hands the backend its [`ipe_backend_rust::FfiEmit`] inputs.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use ipe_ffi::driver::{CargoDep, CrateName, CrateSpec, FfiCache, InstalledCrate, VersionPin};
use ipe_ffi::pkginfo::FeatureName;
use ipe_fs_open::{ByteCap, EntryCap, EntryName, FileKind, HeldDir, OpenRefusal};

use crate::CliError;
use crate::owner_trust::{self, TrustedCache};
use crate::text;

/// The project-relative FFI cache directory.
const CACHE_REL: &str = ipe_ffi::driver::FFI_CACHE_REL;

/// The project manifest that bounds the upward cache-discovery walk.
const PROJECT_MANIFEST: &str = "package.ipe";

/// The legacy TOML manifest name the `ipe rust install` text inspector reads
/// for `[rust.dependencies]` / `[rust.wrapper]`, pending the ergonomic Rust-FFI
/// work that lifts those bindings out of a `package.ipe`.
const PROJECT_MANIFEST_TOML: &str = "ipe.toml";

/// A [`ByteCap`] of `bytes`, never below one byte.
const fn byte_cap(bytes: u64) -> ByteCap {
    ByteCap::from_nonzero(NonZeroU64::MIN.saturating_add(bytes.saturating_sub(1)))
}

/// The ceiling on a project manifest or `.ipe` source read.
pub const MANIFEST_CAP: ByteCap = byte_cap(crate::io_bounded::MANIFEST_READ_CAP);

/// The ceiling on an FFI cache, wrapper source, or emitted sidecar read.
pub const FFI_CACHE_CAP: ByteCap = byte_cap(crate::io_bounded::FFI_CACHE_READ_CAP);

/// The ceiling on a `Cargo.toml` read.
pub const SMALL_FILE_CAP: ByteCap = byte_cap(crate::io_bounded::SMALL_FILE_READ_CAP);

/// The most entries one source-tree read lists, across every level, before it is refused.
const TREE_ENTRY_CAP: EntryCap = EntryCap::from_nonzero(NonZeroU32::MIN.saturating_add(65_535));

/// The error for a held open or read of `path` that `refusal` turned back.
///
/// Every refusal keeps its own kind: a link, a non-regular entry and a denied
/// open are [`CliError::SourceRefused`], a read past its cap is
/// [`CliError::FileTooLarge`], and the rest are [`CliError::Io`] of the
/// refusal's own kind.
#[must_use]
pub fn held_read_error(path: &Path, refusal: OpenRefusal) -> CliError {
    use crate::io_bounded::{SourceRefusal, source_refused};
    match refusal {
        OpenRefusal::Link => source_refused(path, SourceRefusal::Symlink),
        OpenRefusal::NotRegular(_) => source_refused(path, SourceRefusal::NotRegularFile),
        OpenRefusal::Denied => source_refused(path, SourceRefusal::AccessDenied),
        OpenRefusal::TooLarge(cap) => CliError::FileTooLarge {
            path: path.to_path_buf(),
            max: cap.get(),
        },
        OpenRefusal::Absent
        | OpenRefusal::InUse
        | OpenRefusal::TooManyEntries(_)
        | OpenRefusal::BadName
        | OpenRefusal::NotUtf8
        | OpenRefusal::Io(_) => CliError::Io {
            path: path.to_path_buf(),
            source: refusal.into_io(),
        },
    }
}

/// `result` with absence as `None`; every other refusal is the error for `path`.
fn absent_as_none<T>(result: Result<T, OpenRefusal>, path: &Path) -> Result<Option<T>, CliError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(OpenRefusal::Absent) => Ok(None),
        Err(refusal) => Err(held_read_error(path, refusal)),
    }
}

/// `dir` joined with each of `below`.
fn joined(dir: &Path, below: &[&str]) -> PathBuf {
    below
        .iter()
        .fold(dir.to_path_buf(), |path, name| path.join(name))
}

/// Hold the directory `below` spells under `dir`; `None` when a level is absent.
///
/// `dir` itself is opened as named (an empty `dir` is the working directory);
/// every level of `below` is opened without following a link.
///
/// # Errors
/// The [`held_read_error`] of a level that is a link, not a directory, or not
/// openable.
pub fn open_project_dir(dir: &Path, below: &[&str]) -> Result<Option<HeldDir>, CliError> {
    absent_as_none(open_levels(dir, below), &joined(dir, below))
}

/// `dir` opened as named, then each of `below` from its parent's handle without following a link.
fn open_levels(dir: &Path, below: &[&str]) -> Result<HeldDir, OpenRefusal> {
    let mut level = HeldDir::open_root(dir)?;
    for name in below {
        level = level.child_dir(&EntryName::parse(OsStr::new(name))?)?;
    }
    Ok(level)
}

/// Read the regular file `name` in the held `dir` (at `dir_path`) as UTF-8 within `cap`.
///
/// The open never follows a link and never blocks on a FIFO, and the type is
/// checked on the opened handle; `None` when the entry is absent.
///
/// # Errors
/// The [`held_read_error`] of a link, a non-regular entry, a denied open, a
/// read past `cap`, or a read failure.
pub fn read_held_file(
    dir: &HeldDir,
    dir_path: &Path,
    name: &str,
    cap: ByteCap,
) -> Result<Option<String>, CliError> {
    let read = EntryName::parse(OsStr::new(name))
        .and_then(|entry| dir.open_regular(&entry))
        .and_then(|file| file.read_utf8(cap));
    absent_as_none(read, &dir_path.join(name))
}

/// Read the regular file `name` in the directory `below` spells under `dir`.
///
/// `None` when any level, or the file, is absent.
///
/// # Errors
/// As [`open_project_dir`] and [`read_held_file`].
pub fn read_project_file(
    dir: &Path,
    below: &[&str],
    name: &str,
    cap: ByteCap,
) -> Result<Option<String>, CliError> {
    open_project_dir(dir, below)?.map_or(Ok(None), |held| {
        read_held_file(&held, &joined(dir, below), name, cap)
    })
}

/// What the entry `name` in the held `dir` (at `dir_path`) is, read without following a link.
///
/// `None` when the entry is absent.
///
/// # Errors
/// The [`held_read_error`] of a failure other than absence.
pub fn held_entry_kind(
    dir: &HeldDir,
    dir_path: &Path,
    name: &str,
) -> Result<Option<FileKind>, CliError> {
    EntryName::parse(OsStr::new(name))
        .and_then(|entry| dir.kind_of(&entry))
        .map_err(|refusal| held_read_error(&dir_path.join(name), refusal))
}

/// Which entries a [`read_source_tree`] takes.
#[derive(Debug, Clone, Copy)]
pub struct TreeSelect {
    /// Whether a regular file of this name is read.
    pub keep: fn(&OsStr) -> bool,
    /// Whether a directory of this name is walked.
    pub descend: fn(&OsStr) -> bool,
}

/// How a [`read_source_tree`] treats an entry it cannot read as source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreadable {
    /// Refuse the whole read: a selected link, special file, or unreadable
    /// file or directory is an error, so no source goes unscanned.
    Refuse,
    /// Leave the entry out: the read is advisory and the compiler reports the
    /// entry itself.
    Skip,
}

/// One directory a [`read_source_tree`] still has to list.
enum Level {
    /// The held top of the tree.
    Top(HeldDir),
    /// The subdirectory `name` of an already-listed directory.
    Below(Rc<HeldDir>, EntryName),
}

/// Read every regular file `select` keeps under the held `top` (at `top_path`), sorted by path.
///
/// Every level is opened from its parent's handle without following a link,
/// every file without following a link and without blocking, each read within
/// `cap`, and the listing of the whole tree within one entry budget. Only the
/// directories still being walked stay open. Under [`Unreadable::Refuse`] a
/// link where `select` would read or walk is refused, so a linked directory
/// can never hide source from the read.
///
/// # Errors
/// [`CliError::Io`] when the tree lists more entries than its budget; under
/// [`Unreadable::Refuse`], the [`held_read_error`] of the first selected entry
/// that is a link, not regular, or unreadable.
pub fn read_source_tree(
    top: HeldDir,
    top_path: &Path,
    select: TreeSelect,
    cap: ByteCap,
    unreadable: Unreadable,
) -> Result<Vec<(PathBuf, String)>, CliError> {
    let refused = |path: &Path, refusal: OpenRefusal| -> Result<(), CliError> {
        match unreadable {
            Unreadable::Refuse => Err(held_read_error(path, refusal)),
            Unreadable::Skip => Ok(()),
        }
    };
    let mut files: Vec<(PathBuf, String)> = Vec::new();
    let mut listed: u32 = 0;
    let mut pending: Vec<(Level, PathBuf)> = vec![(Level::Top(top), top_path.to_path_buf())];
    while let Some((level, dir_path)) = pending.pop() {
        let opened = match level {
            Level::Top(dir) => Ok(dir),
            Level::Below(parent, name) => parent.child_dir(&name),
        };
        let dir = match opened {
            Ok(dir) => Rc::new(dir),
            Err(refusal) => {
                refused(&dir_path, refusal)?;
                continue;
            }
        };
        let over_budget =
            || held_read_error(&dir_path, OpenRefusal::TooManyEntries(TREE_ENTRY_CAP));
        let listing_cap =
            EntryCap::new(TREE_ENTRY_CAP.get().saturating_sub(listed)).ok_or_else(over_budget)?;
        let entries = match dir.entries(listing_cap) {
            Ok(entries) => entries,
            Err(OpenRefusal::TooManyEntries(_)) => return Err(over_budget()),
            Err(refusal) => {
                refused(&dir_path, refusal)?;
                continue;
            }
        };
        listed = listed.saturating_add(u32::try_from(entries.len()).unwrap_or(u32::MAX));
        for (name, kind) in entries {
            let walked = (select.descend)(name.as_os_str());
            let kept = (select.keep)(name.as_os_str());
            let path = dir_path.join(name.as_os_str());
            match kind {
                FileKind::Dir if walked => {
                    pending.push((Level::Below(Rc::clone(&dir), name), path));
                }
                FileKind::Regular if kept => {
                    match dir.open_regular(&name).and_then(|file| file.read_utf8(cap)) {
                        Ok(text) => files.push((path, text)),
                        Err(refusal) => refused(&path, refusal)?,
                    }
                }
                FileKind::Symlink if walked || kept => refused(&path, OpenRefusal::Link)?,
                FileKind::Fifo | FileKind::Socket | FileKind::Device | FileKind::Other if kept => {
                    refused(&path, OpenRefusal::NotRegular(kind))?;
                }
                FileKind::Dir
                | FileKind::Regular
                | FileKind::Symlink
                | FileKind::Fifo
                | FileKind::Socket
                | FileKind::Device
                | FileKind::Other => {}
            }
        }
    }
    files.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
    Ok(files)
}

/// Whether `name` is a Rust source file name.
fn is_rust_source(name: &OsStr) -> bool {
    Path::new(name).extension() == Some(OsStr::new("rs"))
}

/// Whether `name` is not a Cargo build-output directory.
///
/// A built wrapper's `target/` holds its dependencies' source, not the
/// author's Rust, and would swamp the scan (the manifest already refuses
/// those dependencies). The author surface is `src/`, `build.rs`, and any
/// sibling module files.
fn is_not_build_output(name: &OsStr) -> bool {
    name != OsStr::new("target")
}

/// Whether `name` is an Ipê source file name.
fn is_ipe_source(name: &OsStr) -> bool {
    Path::new(name).extension() == Some(OsStr::new("ipe"))
}

/// Whether `name` is an FFI binding file name.
fn is_binding_source(name: &OsStr) -> bool {
    name.to_str().is_some_and(|n| n.ends_with("_bindings.rs"))
}

/// Every directory is walked.
const fn every_dir(_name: &OsStr) -> bool {
    true
}

/// The Rust a wrapper crate's author wrote: every `.rs`, `target/` not walked.
const WRAPPER_SOURCES: TreeSelect = TreeSelect {
    keep: is_rust_source,
    descend: is_not_build_output,
};

/// Every `.ipe` source under a project's `src`.
const IPE_SOURCES: TreeSelect = TreeSelect {
    keep: is_ipe_source,
    descend: every_dir,
};

/// Every `_bindings.rs` under an FFI cache.
pub const BINDING_SOURCES: TreeSelect = TreeSelect {
    keep: is_binding_source,
    descend: every_dir,
};

/// Walk up from `start` looking for an FFI artifact cache, bounded at the
/// nearest `package.ipe` project root.
///
/// Never walks above the nearest `package.ipe`, so a planted ancestor cache
/// outside the project cannot be discovered. A found cache is held open
/// through no-follow handles once every component below the directory it was
/// found in passed the owner rule (see [`owner_trust::open_cache`]); one
/// reached through a link, or writable by another user, is REFUSED, not
/// loaded, since its `_bindings.rs` compiles unsandboxed into the crate.
///
/// # Errors
///
/// [`CliError::TrustRefused`] when a discovered cache fails the ownership check;
/// [`CliError::Io`] when a component cannot be opened.
pub fn find_cache_root(start: &Path) -> Result<Option<TrustedCache>, CliError> {
    let mut dir = if start.is_dir() {
        Some(start)
    } else {
        start.parent()
    };
    while let Some(d) = dir {
        if let Some(cache) = owner_trust::open_cache(d, CACHE_REL)? {
            return Ok(Some(cache));
        }
        // Stop at the project root: do not walk above the nearest package.ipe.
        if d.join(PROJECT_MANIFEST).is_file() {
            return Ok(None);
        }
        dir = d.parent();
    }
    Ok(None)
}

/// Load the installed-crate catalog for a build rooted at (or blamed on)
/// `blame_path`. Absent cache ⇒ empty catalog.
///
/// # Errors
/// [`CliError::TrustRefused`] relaying the catalog loader's diagnostic (a
/// tampered or half-written cache is refused, never silently skipped), or
/// refusing a cache entry that fails the owner rule.
pub fn load_catalog_for(blame_path: &Path) -> Result<Vec<InstalledCrate>, CliError> {
    load_located_catalog(blame_path).map(|(catalog, _)| catalog)
}

/// Whether a build can link Rust FFI: an installed crate catalog makes its
/// `Rust.*` interfaces reachable from the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiPresence {
    /// No crate is installed; the program links no foreign code.
    Absent,
    /// At least one crate is installed for the build.
    Present,
}

/// The [`FfiPresence`] of the build rooted at (or blamed on) `blame_path`.
///
/// # Errors
/// As [`load_catalog_for`].
pub fn project_ffi_presence(blame_path: &Path) -> Result<FfiPresence, CliError> {
    Ok(if load_catalog_for(blame_path)?.is_empty() {
        FfiPresence::Absent
    } else {
        FfiPresence::Present
    })
}

/// The catalog for `blame_path` with the path of the cache it was read from
/// (empty when no cache exists), from one discovery walk.
///
/// # Errors
/// As [`load_catalog_for`].
fn load_located_catalog(blame_path: &Path) -> Result<(Vec<InstalledCrate>, PathBuf), CliError> {
    let Some(cache) = find_cache_root(blame_path)? else {
        return Ok((Vec::new(), PathBuf::new()));
    };
    let catalog = ipe_ffi::driver::load_catalog_from(&cache)?;
    Ok((catalog, cache.path().to_path_buf()))
}

/// Inject each installed crate's interface module into the build's source
/// map, returning the set of injected module paths (they earn
/// [`ipe_canon::ModuleOrigin::FfiInterface`] at input creation).
///
/// # Errors
/// [`FfiPrepError::ModuleClaimed`] when a project module already claims an
/// installed crate's `Rust.*` module path.
pub fn inject_interfaces(
    sources: &mut BTreeMap<Vec<String>, (PathBuf, String)>,
    catalog: &[InstalledCrate],
    cache_root_hint: &Path,
) -> Result<BTreeSet<Vec<String>>, FfiPrepError> {
    let mut injected = BTreeSet::new();
    for c in catalog {
        let mod_path: Vec<String> = c.module_name.split('.').map(str::to_owned).collect();
        if sources.contains_key(&mod_path) {
            return Err(FfiPrepError::ModuleClaimed {
                module: c.module_name.clone(),
                slug: c.slug.clone(),
            });
        }
        let pseudo_path = cache_root_hint.join(format!("{}.ipe", c.slug));
        sources.insert(mod_path.clone(), (pseudo_path, c.interface_source.clone()));
        injected.insert(mod_path);
    }
    Ok(injected)
}

/// The backend emission inputs with the one dependency table they were sealed against.
///
/// Later growth of the wrapper module (the asserted shims) re-seals against
/// this same table, so one catalog is merged exactly once.
pub struct AssembledEmit {
    /// The backend emission inputs.
    pub emit: ipe_backend_rust::FfiEmit,
    /// The merged `[dependencies]` table the emit renders and was sealed against.
    merged: MergedDeps,
}

/// Assemble the backend emission inputs from the catalog: the merged
/// module-qualified opaque-type map, the de-duplicated pinned dep lines, and
/// the combined `src/ffi.rs` (one `pub mod <slug>` per crate).
///
/// # Errors
/// [`FfiPrepError::DefineOpaqueCollision`] when a define type and an opaque
/// type of one crate share a name; [`FfiPrepError::DependencyMerge`] when two
/// installed crates pin the SAME dependency name to versions that cannot share
/// one line, or bind one dependency name to two different sources (a registry
/// pin and a wrapper path, or two wrapper paths);
/// [`FfiPrepError::CatalogSeal`] when emitted code names the path root of a
/// dependency left out of `[dependencies]` — an unbuildable crate refused here
/// rather than discovered by `cargo`; [`FfiPrepError::TransparentWithoutShape`]
/// when a binding names a transparent shape the catalog does not carry.
pub fn assemble_emit(catalog: &[InstalledCrate]) -> Result<Option<AssembledEmit>, FfiPrepError> {
    use std::fmt::Write as _;
    if catalog.is_empty() {
        return Ok(None);
    }
    let mut foreign_types: BTreeMap<String, String> = BTreeMap::new();
    let mut wrapper_glue: BTreeMap<String, ipe_backend_rust::FfiWrapperGlue> = BTreeMap::new();
    let mut bindings_source = String::from(
        "//! Foreign-crate FFI wrappers — one module per installed crate.\n\
         //! Generated from the project's `.ipe/cache/ffi/rust` artifacts.\n",
    );
    for c in catalog {
        for (name, path) in &c.opaque_types {
            foreign_types.insert(format!("{}.{name}", c.module_name), path.clone());
        }
        assemble_wrapper_glue(c, &mut wrapper_glue)?;
        // A `[rust.define.struct/enum]` type is DEFINED in the emitted
        // `_bindings.rs` (wrapped `pub mod <slug> { … } pub use <slug>::*;` in
        // `src/ffi.rs`), so it resolves at the crate-absolute path
        // `crate::ffi::<slug>::<Name>` — never an external `::crate::Path`, and
        // never the bare `<Name>` glob (the `pub use` re-exports inside
        // `src/ffi.rs`, but the backend renders the foreign-type path into the
        // app's MAIN module tree, where only a crate-absolute path resolves).
        for name in &c.define_types {
            let key = format!("{}.{name}", c.module_name);
            // A define type sharing a name with an inspected opaque of the same
            // crate would silently overwrite the other's path (a wrong Rust type
            // the SEAL would then compile against). Fail closed — the author must
            // rename one; the two nominals are genuinely different Rust types.
            if foreign_types.contains_key(&key) {
                return Err(FfiPrepError::DefineOpaqueCollision {
                    slug: c.slug.clone(),
                    name: name.clone(),
                });
            }
            foreign_types.insert(key, format!("crate::ffi::{}::{name}", c.slug));
        }
        // Writing into a String is infallible.
        let _ = write!(
            bindings_source,
            "\npub mod {slug} {{\n{body}}}\npub use {slug}::*;\n",
            slug = c.slug,
            body = c.bindings_source
        );
    }
    let merged = merge_catalog_deps(catalog).map_err(FfiPrepError::DependencyMerge)?;
    let dep_lines: Vec<String> = merged
        .declared
        .values()
        .map(|dep| dep.to_cargo_dep().render())
        .collect();
    let emit = ipe_backend_rust::FfiEmit {
        foreign_types,
        dep_lines,
        bindings_source,
        interface_modules: catalog.iter().map(|c| c.module_name.clone()).collect(),
        wrapper_glue,
    };
    seal_dependency_references(catalog, &merged, &emit).map_err(FfiPrepError::CatalogSeal)?;
    Ok(Some(AssembledEmit { emit, merged }))
}

/// Every refusal FFI prep returns, one variant per cause.
///
/// It reaches [`CliError`] only as [`CliError::FfiPrep`], so a consumer (the
/// LSP's load classifier) decides each cause's handling from its type, never
/// from message text.
#[derive(Debug, PartialEq, Eq)]
pub enum FfiPrepError {
    /// A project module already claims an installed crate's interface module path.
    ModuleClaimed { module: String, slug: String },
    /// A project module already occupies the reserved asserted module path.
    ReservedModuleExists,
    /// An asserted call or constant failed validation or deduplication.
    AssertedRefused(Box<ipe_ffi::diag::Diagnostic>),
    /// The shims appended for asserted calls name a crate the table leaves out.
    AssertedShimSeal(SealRefusal),
    /// A define type and an opaque type share one name in one crate.
    DefineOpaqueCollision { slug: String, name: String },
    /// The merged `[dependencies]` table cannot be built.
    DependencyMerge(MergeRefusal),
    /// Emitted catalog code names a dependency the table leaves out.
    CatalogSeal(SealRefusal),
    /// A binding references a transparent shape the catalog does not carry.
    TransparentWithoutShape {
        slug: String,
        name: String,
        binding: String,
    },
    /// Asserted calls validated, yet the assembled emit is empty (an internal invariant).
    AssertedWithoutCatalog,
}

/// Why the catalog's dependencies cannot merge into one `[dependencies]` table.
#[derive(Debug, PartialEq, Eq)]
pub enum MergeRefusal {
    /// Two members pin one package to versions no single line satisfies, and
    /// the package is not provably a transitive dependency Cargo may resolve.
    PinConflict {
        name: String,
        first: String,
        second: String,
    },
    /// Two members bind one package to different sources (a registry pin and a
    /// wrapper path, or two wrapper paths); one key admits exactly one source.
    SourceConflict {
        name: String,
        first: String,
        second: String,
    },
}

/// Why an emitted text cannot be sealed against the merged dependency table.
#[derive(Debug, PartialEq, Eq)]
pub enum SealRefusal {
    /// Emitted code names the path root of a package left out of
    /// `[dependencies]`, so `cargo` could not resolve it.
    DroppedTransitive {
        package: String,
        ident: String,
        site: String,
    },
    /// An emitted text does not lex as Rust, so the crates it names are unknown.
    Unlexable { site: String },
}

impl FfiPrepError {
    /// The catalog message this refusal renders as.
    fn message(&self) -> text::Message {
        match self {
            Self::ModuleClaimed { module, slug } => text::msg::ffi_module_clash(module, slug),
            Self::ReservedModuleExists => {
                text::msg::ffi_reserved_module_exists(&ipe_canon::asserted::ASSERTED_MODULE)
            }
            Self::AssertedRefused(diag) => text::Message::relay(&**diag),
            Self::AssertedShimSeal(refusal) | Self::CatalogSeal(refusal) => refusal.message(),
            Self::DefineOpaqueCollision { slug, name } => {
                text::msg::ffi_define_opaque_collision(slug, name)
            }
            Self::DependencyMerge(refusal) => refusal.message(),
            Self::TransparentWithoutShape {
                slug,
                name,
                binding,
            } => text::msg::ffi_transparent_without_shape(slug, name, binding),
            Self::AssertedWithoutCatalog => text::msg::ffi_asserted_empty_catalog(),
        }
    }
}

impl std::fmt::Display for FfiPrepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl MergeRefusal {
    /// The catalog message naming the conflicting dependency and its two sources.
    fn message(&self) -> text::Message {
        match self {
            Self::PinConflict {
                name,
                first,
                second,
            } => text::msg::ffi_dependency_pin_conflict(name, first, second),
            Self::SourceConflict {
                name,
                first,
                second,
            } => text::msg::ffi_dependency_source_conflict(name, first, second),
        }
    }
}

impl SealRefusal {
    /// The catalog message naming the offending site.
    fn message(&self) -> text::Message {
        match self {
            Self::DroppedTransitive {
                package,
                ident,
                site,
            } => text::msg::ffi_dropped_transitive(package, ident, site),
            Self::Unlexable { site } => text::msg::ffi_emit_unlexable(site),
        }
    }
}

impl From<FfiPrepError> for CliError {
    fn from(refusal: FfiPrepError) -> Self {
        Self::FfiPrep(Box::new(refusal))
    }
}

/// The dependencies a version disagreement may defer to Cargo instead of refusing.
///
/// Built from typed inspection facts only: a dependency qualifies when every
/// member's own package name is known, none of them is that dependency (a
/// direct crate is pinned exactly or refused), and the dependency's Rust lib
/// identifier is known (so a later drop can be checked against emitted paths).
/// A legacy cache lacks those facts, so any disagreement it takes part in is
/// refused.
struct DeferrableDeps<'a> {
    typed: bool,
    direct: BTreeSet<&'a str>,
    identified: BTreeSet<&'a str>,
}

impl<'a> DeferrableDeps<'a> {
    fn of(catalog: &'a [InstalledCrate]) -> Self {
        Self {
            typed: catalog.iter().all(|c| c.package_name.is_some()),
            direct: catalog
                .iter()
                .filter_map(|c| c.package_name.as_ref())
                .map(ipe_ffi::pkginfo::PackageName::as_str)
                .collect(),
            identified: catalog
                .iter()
                .flat_map(|c| c.dep_idents.keys())
                .map(String::as_str)
                .collect(),
        }
    }

    fn admits(&self, name: &str) -> bool {
        self.typed && !self.direct.contains(name) && self.identified.contains(name)
    }
}

/// Refuse an emit whose code names a dependency the `[dependencies]` table
/// leaves out.
///
/// The two tables that must agree are the path roots emitted code names and the
/// lib identifiers of the declared packages, both taken from the one merge rule
/// [`merge_catalog_deps`] that also renders `[dependencies]`. A package some
/// member lists but the merged table dropped (a transitive whose versions
/// disagree) has no line; any `::<ident>::` still rooted at it would be `ipe`-accepted and
/// then fail `cargo` with an unresolved crate. Every emitted text is scanned:
/// the wrapper module (including shims appended after assembly), the opaque
/// and define type paths, and the transparent conversion paths. An ident a
/// declared package also answers to stays resolvable and is not refused.
///
/// # Errors
///
/// [`SealRefusal::DroppedTransitive`] naming the first offending site, or
/// [`SealRefusal::Unlexable`] for a text whose references are unknown.
fn seal_dependency_references(
    catalog: &[InstalledCrate],
    merged: &MergedDeps,
    emit: &ipe_backend_rust::FfiEmit,
) -> Result<(), SealRefusal> {
    let all_idents = || catalog.iter().flat_map(|c| &c.dep_idents);
    let declared_idents: BTreeSet<&str> = all_idents()
        .filter(|(name, _)| merged.declared.contains_key(*name))
        .map(|(_, ident)| ident.as_str())
        .collect();
    // ident → package, for every listed package the table dropped.
    let dropped: BTreeMap<&str, &str> = all_idents()
        .filter(|(name, ident)| {
            merged.unpinned.contains(*name) && !declared_idents.contains(ident.as_str())
        })
        .map(|(name, ident)| (ident.as_str(), name.as_str()))
        .collect();
    if dropped.is_empty() {
        return Ok(());
    }
    let glue_sites = emit.wrapper_glue.iter().flat_map(|(wrapper, glue)| {
        glue.params
            .iter()
            .flatten()
            .chain(glue.result.iter().map(|r| &r.ty))
            .map(move |ty| (wrapper.as_str(), glue_rust_path(ty)))
    });
    let sites = std::iter::once(("src/ffi.rs", emit.bindings_source.as_str()))
        .chain(
            emit.foreign_types
                .iter()
                .map(|(key, path)| (key.as_str(), path.as_str())),
        )
        .chain(glue_sites);
    for (site, text) in sites {
        let refs =
            ipe_ffi::crate_refs::crate_references(text).map_err(|_| SealRefusal::Unlexable {
                site: site.to_owned(),
            })?;
        if let Some((ident, package)) = dropped.iter().find(|(ident, _)| refs.contains(**ident)) {
            return Err(SealRefusal::DroppedTransitive {
                package: (*package).to_owned(),
                ident: (*ident).to_owned(),
                site: site.to_owned(),
            });
        }
    }
    Ok(())
}

/// The foreign path one transparent conversion names.
fn glue_rust_path(ty: &ipe_backend_rust::FfiGlueType) -> &str {
    match ty {
        ipe_backend_rust::FfiGlueType::Record { rust_path, .. }
        | ipe_backend_rust::FfiGlueType::Union { rust_path, .. } => rust_path,
    }
}

/// Assemble one crate's per-wrapper transparent conversion glue from the
/// interface's structured positions + the crate's transparent shapes.
///
/// A referenced shape missing from the catalog is an internal invariant
/// violation (the interface derived both), refused rather than emitted as a
/// seam whose two sides disagree.
///
/// # Errors
/// [`FfiPrepError::TransparentWithoutShape`] naming the crate, binding, and
/// missing shape.
fn assemble_wrapper_glue(
    c: &InstalledCrate,
    wrapper_glue: &mut BTreeMap<String, ipe_backend_rust::FfiWrapperGlue>,
) -> Result<(), FfiPrepError> {
    for b in &c.bindings {
        if b.transparent_params.is_none() && b.transparent_result.is_none() {
            continue;
        }
        let glue_ty = |name: &str| -> Result<ipe_backend_rust::FfiGlueType, FfiPrepError> {
            let t = c.transparent_types.get(name).ok_or_else(|| {
                FfiPrepError::TransparentWithoutShape {
                    slug: c.slug.clone(),
                    name: name.to_owned(),
                    binding: b.ref_name.clone(),
                }
            })?;
            Ok(glue_type_of(&c.module_name, &c.slug, t))
        };
        let mut params = Vec::with_capacity(b.transparent_params.slots().len());
        for p in b.transparent_params.slots() {
            params.push(match p {
                None => None,
                Some(name) => Some(glue_ty(name)?),
            });
        }
        let result = match &b.transparent_result {
            None => None,
            Some(r) => Some(ipe_backend_rust::FfiResultGlue {
                in_result: r.in_result,
                ty: glue_ty(&r.type_name)?,
            }),
        };
        wrapper_glue.insert(
            b.wrapper_ident.clone(),
            ipe_backend_rust::FfiWrapperGlue { params, result },
        );
    }
    Ok(())
}

/// One transparent shape in the backend's glue vocabulary. An imported crate
/// type's path absolutizes with a leading `::` (the wrapper spelling); a
/// define-defined type carries the BARE nominal (the define convention — the
/// import classification refuses bare paths) and resolves crate-locally at
/// `crate::ffi::<slug>::<Name>`, where its `_bindings.rs` definition lives.
/// The union's app-side identity is the interface module + nominal, resolved
/// by the backend against the enum the lowerer emitted.
fn glue_type_of(
    module_name: &str,
    slug: &str,
    t: &ipe_ffi::transparency::TransparentType,
) -> ipe_backend_rust::FfiGlueType {
    use ipe_ffi::transparency::{ForeignVariantPayload, TransparentType};
    let absolutize = |p: &str| -> String {
        if p.contains("::") {
            format!("::{}", p.trim_start_matches(':'))
        } else {
            format!("crate::ffi::{slug}::{p}")
        }
    };
    match t {
        TransparentType::Struct {
            rust_path, fields, ..
        } => ipe_backend_rust::FfiGlueType::Record {
            rust_path: absolutize(rust_path.as_str()),
            fields: fields.iter().map(|f| f.name.as_str().to_owned()).collect(),
        },
        TransparentType::Enum {
            name,
            rust_path,
            variants,
        } => ipe_backend_rust::FfiGlueType::Union {
            module: module_name.split('.').map(str::to_owned).collect(),
            name: name.as_str().to_owned(),
            rust_path: absolutize(rust_path.as_str()),
            variants: variants
                .iter()
                .map(|v| ipe_backend_rust::FfiGlueVariant {
                    name: v.name.as_str().to_owned(),
                    payload: match &v.payload {
                        ForeignVariantPayload::Unit => ipe_backend_rust::FfiGluePayload::Unit,
                        ForeignVariantPayload::Tuple(cs) => {
                            ipe_backend_rust::FfiGluePayload::Tuple(cs.len())
                        }
                        ForeignVariantPayload::Struct(ms) => {
                            ipe_backend_rust::FfiGluePayload::Struct(
                                ms.iter().map(|m| m.name.as_str().to_owned()).collect(),
                            )
                        }
                    },
                })
                .collect(),
        },
    }
}

/// The source one merged `[dependencies]` entry binds.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MergedSource {
    /// A registry crate pinned to one exact version.
    Registry(ipe_ffi::pkginfo::CrateVersion),
    /// A wrapper crate bound by its jailed directory.
    Wrapper(ipe_ffi::pkginfo::JailedWrapperDir),
}

impl MergedSource {
    /// The source as it appears in a conflict message.
    fn describe(&self) -> String {
        match self {
            Self::Registry(version) => format!("version ={}", version.as_str()),
            Self::Wrapper(dir) => format!("path {}", dir.as_str()),
        }
    }
}

/// One merged `[dependencies]` entry: its key, source, and the union of every
/// member's requested features (Cargo unifies features additively).
struct MergedDep {
    name: ipe_ffi::pkginfo::PackageName,
    source: MergedSource,
    features: BTreeSet<FeatureName>,
}

impl MergedDep {
    /// Split a typed entry into its merge parts.
    fn of(dep: &CargoDep) -> Self {
        let (source, features) = match dep {
            CargoDep::Registry {
                version, features, ..
            } => (MergedSource::Registry(version.clone()), features),
            CargoDep::Wrapper { dir, features } => (MergedSource::Wrapper(dir.clone()), features),
        };
        Self {
            name: dep.name().clone(),
            source,
            features: features.iter().cloned().collect(),
        }
    }

    /// The typed entry, features in sorted order, for the single renderer.
    fn to_cargo_dep(&self) -> CargoDep {
        let features = self.features.iter().cloned().collect();
        match &self.source {
            MergedSource::Registry(version) => CargoDep::Registry {
                name: self.name.clone(),
                version: version.clone(),
                features,
            },
            MergedSource::Wrapper(dir) => CargoDep::Wrapper {
                dir: dir.clone(),
                features,
            },
        }
    }
}

/// The manifest-wide dependency table: the declared entries by key, and the
/// transitive packages dropped for Cargo to resolve.
struct MergedDeps {
    declared: BTreeMap<String, MergedDep>,
    unpinned: BTreeSet<String>,
}

/// Merge every member's typed dependencies into one manifest-wide table.
///
/// # Errors
/// The first [`MergeRefusal`] of [`merge_cargo_dep`].
fn merge_catalog_deps(catalog: &[InstalledCrate]) -> Result<MergedDeps, MergeRefusal> {
    let deferrable = DeferrableDeps::of(catalog);
    let mut merged = MergedDeps {
        declared: BTreeMap::new(),
        unpinned: BTreeSet::new(),
    };
    for dep in catalog.iter().flat_map(|c| &c.cargo_deps) {
        merge_cargo_dep(dep, &deferrable, &mut merged)?;
    }
    Ok(merged)
}

/// Merge one member's typed dependency into the manifest-wide set.
///
/// Same source: features union. Two registry versions of a package
/// [`DeferrableDeps`] admits: dropped and recorded as unpinned, left to Cargo's
/// own resolution — no single pin is provably acceptable to every
/// intermediate crate's unrecorded requirement, and the dropped package is
/// then undeclared, so [`seal_dependency_references`] refuses any emitted path
/// still rooted at it. Two registry versions of any other package (a direct
/// crate, or any package of a legacy cache): refused. Any disagreement
/// involving a wrapper path (a registry pin against a path, two different
/// paths, or a path named like a dropped transitive): refused, since exactly
/// one source can back a dependency key.
///
/// # Errors
/// [`MergeRefusal::PinConflict`] or [`MergeRefusal::SourceConflict`].
fn merge_cargo_dep(
    dep: &CargoDep,
    deferrable: &DeferrableDeps<'_>,
    merged: &mut MergedDeps,
) -> Result<(), MergeRefusal> {
    let incoming = MergedDep::of(dep);
    let key = incoming.name.as_str().to_owned();
    if merged.unpinned.contains(&key) {
        return match incoming.source {
            MergedSource::Registry(_) => Ok(()),
            MergedSource::Wrapper(_) => Err(MergeRefusal::SourceConflict {
                first: "an unpinned registry dependency".to_owned(),
                second: incoming.source.describe(),
                name: key,
            }),
        };
    }
    let Some(prev) = merged.declared.get_mut(&key) else {
        merged.declared.insert(key, incoming);
        return Ok(());
    };
    if prev.source == incoming.source {
        prev.features.extend(incoming.features);
        return Ok(());
    }
    match (&prev.source, &incoming.source) {
        (MergedSource::Registry(a), MergedSource::Registry(b)) => {
            if !deferrable.admits(&key) {
                return Err(MergeRefusal::PinConflict {
                    first: a.as_str().to_owned(),
                    second: b.as_str().to_owned(),
                    name: key,
                });
            }
            merged.declared.remove(&key);
            merged.unpinned.insert(key);
            Ok(())
        }
        (MergedSource::Wrapper(_), MergedSource::Wrapper(_) | MergedSource::Registry(_))
        | (MergedSource::Registry(_), MergedSource::Wrapper(_)) => {
            Err(MergeRefusal::SourceConflict {
                first: prev.source.describe(),
                second: incoming.source.describe(),
                name: key,
            })
        }
    }
}

/// All FFI seam outputs produced from a single project-scoped catalog load.
///
/// Returned by [`prepare_ffi`]; consumed by the build pipeline, `ipe dev watch`,
/// and `ipe lsp` so all three go through exactly the same injection steps.
pub struct FfiPrep {
    /// The parsed per-crate entries — used to assemble [`ipe_backend_rust::FfiEmit`].
    pub catalog: Vec<InstalledCrate>,
    /// Cross-crate foreign-type nominal unification decisions (one Ipê home
    /// per foreign type) applied to the catalog before injection.
    pub unify: ipe_ffi::unify::UnifyReport,
    /// The module paths injected into the source map (earn
    /// `ModuleOrigin::FfiInterface` at [`crate::create_source_root`]).
    pub injected: BTreeSet<Vec<String>>,
    /// The assembled backend emission inputs, or `None` when no crates are
    /// installed. Mirrors the `ffi_emit` local in `run_build_inner`.
    pub emit: Option<ipe_backend_rust::FfiEmit>,
}

/// Load, inject, and assemble the FFI catalog for a project in one step.
///
/// This is the shared seam used by `run_build`, `ipe dev watch`, and `ipe lsp` so
/// all three compilation paths go through the SAME catalog-load → interface-
/// inject → emit-assemble sequence. Each caller was previously duplicating
/// these steps independently, or (in `watch`/`lsp`) skipping them entirely —
/// both are bugs (CO-INCR-005).
///
/// `blame_path` is the project entry file or manifest: the catalog search
/// walks up from it looking for `.ipe/cache/ffi/rust`.
///
/// `sources` is mutated in-place: one `Rust.<Crate>` interface module is
/// inserted per installed crate.
///
/// # Errors
/// [`CliError`] when the catalog is tampered/unreadable, two installed
/// crates pin the same dependency to conflicting version lines, or emitted
/// code names a dependency the manifest leaves out.
pub fn prepare_ffi(
    sources: &mut BTreeMap<Vec<String>, (PathBuf, String)>,
    blame_path: &Path,
) -> Result<FfiPrep, CliError> {
    let (mut catalog, cache_hint) = load_located_catalog(blame_path)?;
    // The asserted-call classifications lean on two unforgeable names: the
    // `Rust.Ffi` module and the `ipe_asserted_` wrapper prefix. No installed
    // crate may claim either — refused at load, before anything is injected.
    for c in &catalog {
        if c.module_name == ipe_canon::asserted::ASSERTED_MODULE {
            return Err(CliError::TrustRefused(
                owner_trust::TrustRefusal::FfiReservedModule {
                    slug: c.slug.clone(),
                },
            ));
        }
        if let Some(ident) = c
            .wrapper_idents
            .iter()
            .find(|w| w.starts_with(ipe_canon::asserted::ASSERTED_WRAPPER_PREFIX))
        {
            return Err(CliError::TrustRefused(
                owner_trust::TrustRefusal::FfiReservedWrapperPrefix {
                    slug: c.slug.clone(),
                    ident: ident.clone(),
                },
            ));
        }
    }
    // One Ipê home per foreign type: collapse same-defining-path nominals
    // across the catalog BEFORE injection, so every injected signature and
    // the assembled `foreign_types` map agree on one nominal per type.
    let unify = ipe_ffi::unify::unify_foreign_nominals(&mut catalog);
    // Scan for asserted calls BEFORE interface injection, while `sources`
    // holds only project (and stdlib) modules.
    let ScannedFfi { asserted, consts } = scan_asserted(sources, &catalog)?;
    let mut injected = inject_interfaces(sources, &catalog, &cache_hint)?;
    let mut assembled = assemble_emit(&catalog)?;
    if !asserted.is_empty() || !consts.is_empty() {
        let mod_path: Vec<String> = ipe_canon::asserted::ASSERTED_MODULE
            .split('.')
            .map(str::to_owned)
            .collect();
        if sources.contains_key(&mod_path) {
            return Err(FfiPrepError::ReservedModuleExists.into());
        }
        let iface = ipe_ffi::asserted::render_asserted_interface(&asserted, &consts);
        sources.insert(mod_path.clone(), (cache_hint.join("Rust.Ffi.ipe"), iface));
        injected.insert(mod_path);
        // `validate` proved every target crate is installed, so the catalog —
        // and therefore the assembled emit — is non-empty here.
        let Some(a) = assembled.as_mut() else {
            return Err(FfiPrepError::AssertedWithoutCatalog.into());
        };
        a.emit
            .interface_modules
            .push(ipe_canon::asserted::ASSERTED_MODULE.to_owned());
        append_asserted_shims(&catalog, a, &asserted, &consts)?;
    }
    Ok(FfiPrep {
        catalog,
        unify,
        injected,
        emit: assembled.map(|a| a.emit),
    })
}

/// Append the asserted-call and asserted-const shims to the wrapper module.
///
/// The shims name crates too, so the grown module is re-checked against the
/// dependency table before it can reach the backend.
///
/// The re-check reads the table the emit was assembled and sealed against,
/// never a second merge of the catalog.
///
/// # Errors
///
/// [`FfiPrepError::AssertedShimSeal`] when a shim names a crate the table
/// leaves out.
fn append_asserted_shims(
    catalog: &[InstalledCrate],
    assembled: &mut AssembledEmit,
    asserted: &[ipe_ffi::asserted::AssertedSpec],
    consts: &[ipe_ffi::asserted::ConstSpec],
) -> Result<(), FfiPrepError> {
    let AssembledEmit { emit, merged } = assembled;
    if !asserted.is_empty() {
        emit.bindings_source.push('\n');
        emit.bindings_source
            .push_str(&ipe_ffi::asserted::emit_asserted_shims(asserted));
    }
    if !consts.is_empty() {
        emit.bindings_source.push('\n');
        emit.bindings_source
            .push_str(&ipe_ffi::asserted::emit_const_shims(consts));
    }
    seal_dependency_references(catalog, merged, emit).map_err(FfiPrepError::AssertedShimSeal)
}

/// The two native-binding surfaces one scan pass produces: forwarder calls
/// (`Rust.fn` / `Rust.Ffi.call`) and bare-scalar constant reads (`Rust.const`).
/// A single pass over the modules yields both — splitting the scan would
/// re-parse every module.
struct ScannedFfi {
    asserted: Vec<ipe_ffi::asserted::AssertedSpec>,
    consts: Vec<ipe_ffi::asserted::ConstSpec>,
}

/// Scan every project source module for asserted-call sites
/// (`Rust.Ffi.call "<path>"`) and validate each against the installed-crate
/// catalog, deduplicating identical assertions.
///
/// A module that fails to parse is skipped here: it cannot carry a working
/// asserted call, and the compile pipeline reports the parse error with full
/// context moments later.
///
/// # Errors
/// [`CliError::Pipeline`] (IPE-N0038, span-attributed) for a malformed site;
/// [`FfiPrepError::AssertedRefused`] (IPE-F4414) for a refused assertion.
fn scan_asserted(
    sources: &BTreeMap<Vec<String>, (PathBuf, String)>,
    catalog: &[InstalledCrate],
) -> Result<ScannedFfi, CliError> {
    let mut specs = Vec::new();
    let mut const_specs = Vec::new();
    for (file, text) in sources.values() {
        // Cheap pre-filter: skip a module that spells no native-binding surface
        // before the parse. `scan_module` is the authoritative classifier; this
        // only avoids parsing modules that cannot carry one.
        if !text.contains("Rust.Ffi.call")
            && !text.contains("Rust.fn")
            && !text.contains("Rust.const")
        {
            continue;
        }
        let mut interner = ipe_intern::Interner::new();
        let Ok(module) = ipe_parse::parse_module(text, &mut interner) else {
            continue;
        };
        let uses = ipe_canon::asserted::scan_module(&module, &interner).map_err(|diag| {
            CliError::Pipeline {
                file: file.clone(),
                src: text.clone(),
                diag: Box::new(diag),
            }
        })?;
        for u in uses {
            // A native constant reads a bare scalar; every other surface is a
            // forwarder. The classifier carried on the use routes the two.
            if matches!(u.callee, ipe_canon::asserted::AssertedCallee::RustConst) {
                let spec =
                    ipe_ffi::asserted::validate_const(u.path, &u.annotation, &interner, catalog)
                        .map_err(asserted_refused)?;
                const_specs.push(spec);
            } else {
                let spec = ipe_ffi::asserted::validate(u.path, &u.annotation, &interner, catalog)
                    .map_err(asserted_refused)?;
                specs.push(spec);
            }
        }
    }
    let asserted = ipe_ffi::asserted::dedupe(specs).map_err(asserted_refused)?;
    let consts = ipe_ffi::asserted::dedupe_consts(const_specs).map_err(asserted_refused)?;
    Ok(ScannedFfi { asserted, consts })
}

/// Lift a refused asserted call or constant into its typed FFI prep refusal.
fn asserted_refused(diag: ipe_ffi::diag::Diagnostic) -> CliError {
    FfiPrepError::AssertedRefused(Box::new(diag)).into()
}

/// Locate the `ipe-ffi-inspector` binary: beside the running `ipe`
/// executable first, then `$PATH`.
fn inspector_binary() -> Result<PathBuf, CliError> {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join("ipe-ffi-inspector");
        if sibling.is_file() {
            return Ok(sibling);
        }
    }
    if let Some(paths) = ipe_env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join("ipe-ffi-inspector");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(CliError::Usage(text::msg::ffi_inspector_not_found()))
}

/// A per-invocation scratch directory under the sanctioned write-boundary
/// root (`~/.cache/ipe/ffi-scratch/`), created with an unpredictable name via
/// 128-bit OS entropy and exclusive-create semantics so a pre-seeded symlink or
/// directory causes failure rather than reuse.  `/tmp` is never used: it is
/// world-writable and outside the write-boundary.  HOME must be an absolute
/// path; absent that the function fails closed rather than falling back to a
/// world-writable or working-directory-relative path.
fn make_scratch_dir(krate: &str) -> Result<PathBuf, CliError> {
    let home = crate::env_dir::home()
        .map_err(|_refusal| CliError::Usage(text::msg::ffi_add_home_not_absolute()))?;
    let base = home.join(".cache/ipe/ffi-scratch");
    crate::scratch::ScratchDir::new_under(&base, &format!("add-{krate}"))
        .map(crate::scratch::ScratchDir::into_path)
        .map_err(|e| CliError::Usage(text::msg::ffi_add_scratch_dir(&e)))
}

/// The toolchain side of one jail: what it runs, what it re-binds, and which
/// homes it masks.
///
/// Every path is canonical, resolved once: the inspector the payload execs,
/// the `PATH` entries, and the rustup home it is handed are the very paths the
/// jail binds.
#[derive(Debug)]
struct ToolchainBinds {
    /// The inspector binary the payload execs.
    inspector: ipe_sandbox::CanonicalPath,
    /// Directories re-bound read-only through the home masks.
    ro_binds: Vec<ipe_sandbox::CanonicalPath>,
    /// Directories prepended to the jailed `PATH`.
    path_prepend: Vec<ipe_sandbox::CanonicalPath>,
    /// The rustup home exported into the jail.
    rustup_home: Option<ipe_sandbox::CanonicalPath>,
    /// The user and cargo homes, masked wherever they live.
    homes: ipe_sandbox::HomeMasks,
}

/// A jail path that does not resolve, or a home the jail cannot mask, refuses
/// the jail.
fn jail_path_refused(e: &ipe_sandbox::JailPathError) -> CliError {
    CliError::Usage(text::msg::ffi_jail_path_refused(e))
}

/// Read-only jail binds for the toolchain, deliberately NARROW.
///
/// Never the cargo home itself (which carries `credentials.toml`, the
/// crates.io API token): only `$CARGO_HOME/bin` (the proxy binaries) and the
/// rustup home are exposed. Both homes resolve exactly as the tools resolve
/// them (`CARGO_HOME`/`RUSTUP_HOME`, else under the user's home).
///
/// # Errors
/// - [`CliError::EnvDirNotAbsolute`] when `CARGO_HOME` or `RUSTUP_HOME` is set
///   to a relative path.
/// - [`CliError::Usage`] when the cargo home is unknown, a bind would expose
///   it, a jail path does not resolve, or the user's home is unknown (see
///   [`toolchain_binds_from`]).
fn toolchain_binds(inspector: &Path) -> Result<ToolchainBinds, CliError> {
    let user_home = crate::env_dir::home();
    let cargo_home = crate::env_dir::tool_home("CARGO_HOME", user_home.as_ref().ok(), ".cargo")?;
    let rustup_home = crate::env_dir::tool_home("RUSTUP_HOME", user_home.as_ref().ok(), ".rustup")?;
    toolchain_binds_from(
        inspector,
        cargo_home.as_ref(),
        rustup_home,
        user_home.as_ref().map_err(|refusal| *refusal),
    )
}

/// The toolchain binds over already-resolved tool homes.
///
/// Each path is resolved to its canonical form once, here; the exposure check
/// runs over those canonical binds, so it judges exactly what the jail mounts.
///
/// # Errors
/// [`CliError::Usage`] when:
/// - the cargo home is unknown (neither `CARGO_HOME` nor an absolute `HOME`),
///   so no check could keep it out of the jail;
/// - the inspector, its directory, `$CARGO_HOME/bin`, or the rustup home does
///   not resolve;
/// - any read-only bind equals or contains the cargo home (a rustup home at or
///   above it, or an inspector directory above it): binding it would expose
///   `credentials.toml` inside the jail;
/// - the user's home is refused, so it cannot be masked.
fn toolchain_binds_from(
    inspector: &Path,
    cargo_home: Option<&crate::env_dir::ToolHome>,
    rustup_home: Option<crate::env_dir::ToolHome>,
    user_home: Result<&crate::env_dir::HomeDir, crate::env_dir::HomeRefusal>,
) -> Result<ToolchainBinds, CliError> {
    let cargo_home =
        cargo_home.ok_or_else(|| CliError::Usage(text::msg::ffi_cargo_home_unresolved()))?;
    let canonical =
        |path: &Path| ipe_sandbox::CanonicalPath::resolve(path).map_err(|e| jail_path_refused(&e));
    let inspector = canonical(inspector)?;
    let mut toolchain_ro_binds = Vec::new();
    // The inspector binary may live under a masked mount ($HOME target dirs) —
    // re-bind its directory read-only.
    if let Some(dir) = inspector.as_path().parent() {
        toolchain_ro_binds.push(canonical(dir)?);
    }
    let mut path_prepend = Vec::new();
    let cargo_bin = cargo_home.join("bin");
    if cargo_bin.is_dir() {
        let cargo_bin = canonical(&cargo_bin)?;
        path_prepend.push(cargo_bin.clone());
        // Bind ONLY the bin dir — NEVER the cargo home itself, so
        // credentials.toml stays outside the jail.
        toolchain_ro_binds.push(cargo_bin);
    }
    let rustup_home = match rustup_home.filter(|rustup| rustup.as_path().is_dir()) {
        Some(rustup) => Some(canonical(rustup.as_path())?),
        None => None,
    };
    if let Some(rustup) = &rustup_home {
        toolchain_ro_binds.push(rustup.clone());
    }
    if let Some(bind) = ipe_sandbox::bind_exposing(&toolchain_ro_binds, cargo_home.as_path()) {
        return Err(CliError::Usage(
            text::msg::ffi_toolchain_bind_exposes_cargo_home(
                &bind.as_path().display(),
                &cargo_home.as_path().display(),
            ),
        ));
    }
    let homes = ipe_sandbox::HomeMasks::resolve(user_home, Some(cargo_home))
        .map_err(|e| jail_path_refused(&e))?;
    Ok(ToolchainBinds {
        inspector,
        ro_binds: toolchain_ro_binds,
        path_prepend,
        rustup_home,
        homes,
    })
}

/// The jail resource caps: the fail-closed defaults, each raisable through an
/// explicit env override that prints a warning (an SDK-scale dependency
/// closure — hundreds of crates under one `cargo check`/rustdoc — legitimately
/// needs more CPU/wall/output than the small-crate defaults).
fn jail_limits() -> ipe_sandbox::ResourceLimits {
    let mut limits = ipe_sandbox::ResourceLimits::default();
    let with_override = |var: &str, slot: &mut u64, scale: u64| {
        if let Ok(raw) = ipe_env::var(var) {
            if let Ok(v) = raw.parse::<u64>().map(|v| v.saturating_mul(scale))
                && v > 0
            {
                crate::screen::chatter(
                    crate::screen::Stream::Stderr,
                    crate::screen::Tone::UserError,
                    &format!("WARNING: jail cap override {var}={raw}"),
                );
                *slot = v;
            } else {
                crate::screen::chatter(
                    crate::screen::Stream::Stderr,
                    crate::screen::Tone::UserError,
                    &format!("WARNING: ignoring non-numeric jail cap override {var}={raw}"),
                );
            }
        }
    };
    with_override("IPE_FFI_RSS_MB", &mut limits.rss_bytes, 1024 * 1024);
    with_override("IPE_FFI_CPU_SECS", &mut limits.cpu_secs, 1);
    with_override("IPE_FFI_WALL_SECS", &mut limits.wall_secs, 1);
    with_override("IPE_FFI_FD_CAP", &mut limits.fd_cap, 1);
    with_override("IPE_FFI_PROC_CAP", &mut limits.proc_cap, 1);
    with_override("IPE_FFI_OUT_CAP_MB", &mut limits.out_cap_bytes, 1024 * 1024);
    limits
}

/// Run one jailed inspector phase over the shared `scoped_tmp`, returning its
/// captured stdout.
fn run_phase(
    caps: &ipe_sandbox::Capabilities,
    network: ipe_sandbox::NetworkPolicy,
    scoped_tmp: &ipe_sandbox::CanonicalPath,
    binds: &ToolchainBinds,
    payload: &[OsString],
) -> Result<ipe_sandbox::JailedOutput, CliError> {
    let io_err = |detail: String| {
        CliError::Usage(text::msg::command_refusal(
            &"add",
            &crate::style::TerminalSafe::sanitize(&detail),
        ))
    };
    let spec = ipe_sandbox::JailSpec {
        network,
        scoped_tmp: scoped_tmp.clone(),
        registry_cache: None,
        toolchain: None,
        toolchain_ro_binds: binds.ro_binds.clone(),
        homes: binds.homes.clone(),
        path_prepend: binds.path_prepend.clone(),
        rustup_home: binds.rustup_home.clone(),
        limits: jail_limits(),
    };
    ipe_sandbox::run_in_bwrap_jail(caps, &spec, payload)
        .map_err(|d| io_err(format!("sandboxed inspection failed: {d}")))
}

/// Run the inspector for `krate` inside the sandbox jail and return its
/// stdout (the inspection JSON).
///
/// Two phases over a SHARED scoped scratch dir (same in-jail `CARGO_HOME`):
///   1. fetch (`FetchOnly`, network on) — the inspector runs `--fetch-only`,
///      populating the registry cache; NO proc-macro / build-script / rustdoc
///      expansion, so no foreign code runs while egress is available.
///   2. introspect (`Denied`, fresh empty net namespace, `CARGO_NET_OFFLINE`)
///      — rustdoc expands proc-macros / build scripts (the foreign code) with
///      NO network egress, so the crates.io token cannot be exfiltrated even
///      if it were reachable (it is not — see [`toolchain_binds`]).
fn run_inspector(
    krate: &CrateSpec,
    features: &[String],
    allow_build_scripts: bool,
) -> Result<String, CliError> {
    run_inspector_job(
        &InspectorJob::Single { krate, features },
        allow_build_scripts,
    )
}

/// One jailed inspector invocation: either a single crate or a MULTI-crate
/// manifest. The manifest form matters beyond convenience: the inspector's
/// cross-crate impl index is process-global, so a trait method defined in one
/// crate and implemented for a sibling's type (the async-SDK `send` shape)
/// resolves only when every project crate is inspected in ONE process.
enum InspectorJob<'a> {
    /// `ipe add <crate>`.
    Single {
        /// The crate (with optional version pin).
        krate: &'a CrateSpec,
        /// The requested feature list.
        features: &'a [String],
    },
    /// `ipe install` — every `[rust.dependencies]` entry in one run.
    Manifest {
        /// Per-crate (spec, features) pairs.
        entries: &'a [(CrateSpec, Vec<String>)],
    },
    /// A `[rust.wrapper]` local wrapper crate: inspected from an absolute path
    /// (bound RO by the whole-`/` jail bind), binding only the exposed symbols.
    WrapperPath {
        /// The wrapper crate's Cargo package name (the inspection slug).
        krate: &'a CrateName,
        /// The absolute, package-jailed wrapper-crate directory.
        abs_path: &'a str,
        /// The public symbols to bind (empty ⇒ every public symbol).
        expose: &'a [String],
    },
}

/// Serialize the inspector's `--manifest` JSON into the scoped scratch dir
/// (the only jail-writable mount, so the path is visible inside the jail).
fn write_inspector_manifest(
    scoped_tmp: &Path,
    entries: &[(CrateSpec, Vec<String>)],
) -> Result<PathBuf, CliError> {
    let arr: Vec<serde_json::Value> = entries
        .iter()
        .map(|(spec, feats)| serde_json::json!({ "name": spec.inspector_arg(), "features": feats }))
        .collect();
    let path = scoped_tmp.join("ipe-install-manifest.json");
    let body = serde_json::Value::Array(arr).to_string();
    std::fs::write(&path, body)
        .map_err(|e| CliError::Usage(text::msg::ffi_install_manifest_write_failed(&e)))?;
    Ok(path)
}

/// The full inspector argv (program + flags) for one phase of a job. The
/// manifest path, when present, was written into the jail-visible scratch.
fn inspector_payload(
    inspector: &Path,
    job: &InspectorJob,
    manifest_path: Option<&Path>,
    allow_build_scripts: bool,
    fetch_only: bool,
) -> Vec<OsString> {
    let mut payload: Vec<OsString> = vec![inspector.to_path_buf().into_os_string()];
    match job {
        InspectorJob::Single { krate, features } => {
            payload.extend(ipe_ffi::driver::inspector_argv(
                krate,
                features,
                None,
                allow_build_scripts,
                fetch_only,
            ));
        }
        InspectorJob::Manifest { .. } => {
            if fetch_only {
                payload.push("--fetch-only".into());
            }
            if allow_build_scripts {
                payload.push("--allow-build-scripts".into());
            }
            payload.push("--manifest".into());
            if let Some(p) = manifest_path {
                payload.push(p.to_path_buf().into_os_string());
            }
        }
        InspectorJob::WrapperPath {
            krate,
            abs_path,
            expose,
        } => {
            if fetch_only {
                payload.push("--fetch-only".into());
            }
            if allow_build_scripts {
                payload.push("--allow-build-scripts".into());
            }
            payload.push("--path".into());
            payload.push((*abs_path).into());
            if !expose.is_empty() {
                payload.push("--expose".into());
                payload.push(expose.join(",").into());
            }
            payload.push(krate.as_str().into());
        }
    }
    payload
}

/// How an inspector job should be run, once the host's sandbox capabilities and
/// the operator's unsandboxed override have been weighed. Every reachable
/// combination maps to exactly one variant, so no host configuration can fall
/// through to a branch its capabilities doom.
enum SandboxRoute {
    /// bubblewrap with the mandatory cap helpers present — the jailed path.
    Jailed,
    /// The operator accepted running foreign build code without a jail. Reached
    /// either when bwrap is absent or when its cap helpers are missing, and only
    /// when `IPE_FFI_ALLOW_UNSANDBOXED=1` is set.
    Unsandboxed,
    /// bwrap is absent and no override is set — refuse, advising bwrap.
    RefuseNoBwrap,
    /// bwrap is present but a mandatory cap helper is missing and no override is
    /// set — refuse, advising the missing helpers.
    RefuseMissingCaps { missing: Vec<&'static str> },
}

/// Decide how to run an inspector job from the host's sandbox capabilities and
/// the unsandboxed override. Pure so the refusal and override paths are pinned
/// by tests without spawning a subprocess.
fn choose_sandbox_route(
    mechanism: &ipe_sandbox::Mechanism,
    missing_caps: Vec<&'static str>,
    unsandboxed_ok: bool,
) -> SandboxRoute {
    match mechanism {
        ipe_sandbox::Mechanism::Bwrap(_) if missing_caps.is_empty() => SandboxRoute::Jailed,
        ipe_sandbox::Mechanism::Bwrap(_) | ipe_sandbox::Mechanism::Refused if unsandboxed_ok => {
            SandboxRoute::Unsandboxed
        }
        ipe_sandbox::Mechanism::Bwrap(_) => SandboxRoute::RefuseMissingCaps {
            missing: missing_caps,
        },
        ipe_sandbox::Mechanism::Refused => SandboxRoute::RefuseNoBwrap,
    }
}

fn run_inspector_job(job: &InspectorJob, allow_build_scripts: bool) -> Result<String, CliError> {
    let inspector = inspector_binary()?;
    let scratch_hint = match job {
        InspectorJob::Single { krate, .. } => krate.name().as_str(),
        InspectorJob::WrapperPath { krate, .. } => krate.as_str(),
        InspectorJob::Manifest { .. } => "manifest",
    };

    let caps = ipe_sandbox::probe();
    let mechanism = ipe_sandbox::select_mechanism(&caps);
    let unsandboxed_ok = ipe_sandbox::unsandboxed_override_set();
    let io_err = |detail: String| {
        CliError::Usage(text::msg::command_refusal(
            &"add",
            &crate::style::TerminalSafe::sanitize(&detail),
        ))
    };

    match choose_sandbox_route(&mechanism, ipe_sandbox::missing_caps(&caps), unsandboxed_ok) {
        SandboxRoute::RefuseNoBwrap => {
            return Err(CliError::Usage(text::msg::ffi_no_bubblewrap()));
        }
        SandboxRoute::RefuseMissingCaps { missing } => {
            return Err(io_err(format!(
                "missing mandatory sandbox cap helper(s): {} — install coreutils \
                 (timeout) and util-linux (prlimit), or set IPE_FFI_ALLOW_UNSANDBOXED=1 \
                 (dangerous)",
                missing.join(", ")
            )));
        }
        SandboxRoute::Unsandboxed => {
            return run_inspector_job_unsandboxed(
                &inspector,
                job,
                scratch_hint,
                allow_build_scripts,
            );
        }
        SandboxRoute::Jailed => {}
    }

    let binds = toolchain_binds(&inspector)?;
    let scratch = make_scratch_dir(scratch_hint)?;
    // The scratch the jail binds, the TMPDIR and cwd it hands the payload, and
    // every manifest path under it share this one canonical spelling.
    let scoped_tmp = match ipe_sandbox::CanonicalPath::resolve(&scratch) {
        Ok(dir) => dir,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&scratch);
            return Err(jail_path_refused(&e));
        }
    };
    let result = match job {
        // A single crate — or a single local wrapper crate — is one
        // populate-free bind over the historical two phases (fetch,
        // introspect) on one scoped scratch. A wrapper crate is local, so
        // its fetch phase only resolves the wrapper's own registry deps.
        InspectorJob::Single { .. } | InspectorJob::WrapperPath { .. } => run_single_bwrap(
            binds.inspector.as_path(),
            job,
            &caps,
            &scoped_tmp,
            &binds,
            allow_build_scripts,
        ),
        // A multi-crate manifest is CHUNKED: one fetch, then a per-crate
        // populate sequence that accumulates the cross-crate index through
        // a checkpoint, then a per-crate bind — so no single jailed run
        // exceeds the wall, which the whole-manifest run did (its populate
        // + bind of every crate ran under one wall budget).
        InspectorJob::Manifest { entries } => run_manifest_bwrap_chunked(
            binds.inspector.as_path(),
            entries,
            &caps,
            &scoped_tmp,
            &binds,
            allow_build_scripts,
        ),
    };
    let _ = std::fs::remove_dir_all(&scoped_tmp);
    result
}

/// The historical two-phase single-crate flow: fetch (network on, no foreign
/// code) then introspect (no egress, foreign code runs) over one scratch.
fn run_single_bwrap(
    inspector: &Path,
    job: &InspectorJob,
    caps: &ipe_sandbox::Capabilities,
    scoped_tmp: &ipe_sandbox::CanonicalPath,
    binds: &ToolchainBinds,
    allow_build_scripts: bool,
) -> Result<String, CliError> {
    let io_err = |detail: String| {
        CliError::Usage(text::msg::command_refusal(
            &"add",
            &crate::style::TerminalSafe::sanitize(&detail),
        ))
    };
    let with_payload =
        |fetch_only: bool| inspector_payload(inspector, job, None, allow_build_scripts, fetch_only);
    run_phase(
        caps,
        ipe_sandbox::NetworkPolicy::FetchOnly,
        scoped_tmp,
        binds,
        &with_payload(true),
    )?;
    let out = run_phase(
        caps,
        ipe_sandbox::NetworkPolicy::Denied,
        scoped_tmp,
        binds,
        &with_payload(false),
    )?;
    if out.status != Some(0) {
        return Err(io_err(format!(
            "inspector exited with {:?}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    String::from_utf8(out.stdout)
        .map_err(|_| io_err("inspector produced non-UTF-8 output".to_owned()))
}

/// The inspector argv for one chunk of the manifest flow: a single-crate
/// manifest file plus optional cross-crate checkpoint load/save flags. The
/// manifest form is kept (never `Single`) so a one-crate chunk still emits a
/// JSON array — the shape `run_install` decodes.
fn manifest_chunk_payload(
    inspector: &Path,
    manifest_path: &Path,
    allow_build_scripts: bool,
    fetch_only: bool,
    xc_load: Option<&Path>,
    xc_save: Option<&Path>,
) -> Vec<OsString> {
    let mut payload: Vec<OsString> = vec![inspector.to_path_buf().into_os_string()];
    if fetch_only {
        payload.push("--fetch-only".into());
    }
    if allow_build_scripts {
        payload.push("--allow-build-scripts".into());
    }
    if let Some(p) = xc_load {
        payload.push("--xc-load".into());
        payload.push(p.to_path_buf().into_os_string());
    }
    if let Some(p) = xc_save {
        payload.push("--xc-save".into());
        payload.push(p.to_path_buf().into_os_string());
    }
    payload.push("--manifest".into());
    payload.push(manifest_path.to_path_buf().into_os_string());
    payload
}

/// Run one jailed introspect chunk (network denied — foreign code runs here)
/// and return its stdout, mapping a non-zero exit to a typed error.
fn run_introspect_chunk(
    caps: &ipe_sandbox::Capabilities,
    scoped_tmp: &ipe_sandbox::CanonicalPath,
    binds: &ToolchainBinds,
    payload: &[OsString],
) -> Result<String, CliError> {
    let io_err = |detail: String| {
        CliError::Usage(text::msg::command_refusal(
            &"add",
            &crate::style::TerminalSafe::sanitize(&detail),
        ))
    };
    let out = run_phase(
        caps,
        ipe_sandbox::NetworkPolicy::Denied,
        scoped_tmp,
        binds,
        payload,
    )?;
    if out.status != Some(0) {
        return Err(io_err(format!(
            "inspector exited with {:?}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    String::from_utf8(out.stdout)
        .map_err(|_| io_err("inspector produced non-UTF-8 output".to_owned()))
}

/// Chunk a multi-crate manifest into per-crate jailed runs so no single run
/// exceeds the jail wall.
///
/// One shared scratch (one `CARGO_HOME`, one checkpoint) hosts three stages:
///  1. **Fetch** — one network-on run over the WHOLE manifest, populating the
///     scoped registry. No foreign code runs (the inspector stops at
///     `--fetch-only`).
///  2. **Populate** — one network-denied run PER crate, each loading the prior
///     crate's checkpoint and saving the accumulated one. A crate's build
///     scripts run here, but the checkpoint is read before any foreign code
///     and rewritten (full accumulated maps) after it, so no crate can corrupt
///     the index a sibling later loads — the trust model of the single-process
///     populate pass, split across processes.
///  3. **Bind** — one network-denied run PER crate, each loading the COMPLETE
///     checkpoint, so every sibling impl is indexed before the crate binds.
///
/// Returns the concatenated bind results as one JSON array string — the shape
/// the whole-manifest run produced, so `run_install`'s decode is unchanged.
fn run_manifest_bwrap_chunked(
    inspector: &Path,
    entries: &[(CrateSpec, Vec<String>)],
    caps: &ipe_sandbox::Capabilities,
    scoped_tmp: &ipe_sandbox::CanonicalPath,
    binds: &ToolchainBinds,
    allow_build_scripts: bool,
) -> Result<String, CliError> {
    let io_err = |detail: String| {
        CliError::Usage(text::msg::command_refusal(
            &"add",
            &crate::style::TerminalSafe::sanitize(&detail),
        ))
    };

    // Stage 1 — fetch every crate in one network-on run (no foreign code).
    let full_manifest = write_inspector_manifest(scoped_tmp.as_path(), entries)?;
    let fetch_payload = manifest_chunk_payload(
        inspector,
        &full_manifest,
        allow_build_scripts,
        true,
        None,
        None,
    );
    run_phase(
        caps,
        ipe_sandbox::NetworkPolicy::FetchOnly,
        scoped_tmp,
        binds,
        &fetch_payload,
    )?;

    // The checkpoint lives in the shared scratch: written by each populate
    // chunk, read by the next populate chunk and by every bind chunk. It is a
    // jail-writable path, but each process reads it before foreign code runs
    // and rewrites it after, so a build script cannot plant facts a sibling
    // then trusts.
    let checkpoint = scoped_tmp.as_path().join("xc-checkpoint.json");

    // Stage 2 — populate the cross-crate index one crate at a time.
    for (i, (spec, features)) in entries.iter().enumerate() {
        let chunk_manifest = write_inspector_manifest_chunk(
            scoped_tmp.as_path(),
            &format!("populate-{i}"),
            spec,
            features,
        )?;
        let xc_load = (i > 0).then_some(checkpoint.as_path());
        let payload = manifest_chunk_payload(
            inspector,
            &chunk_manifest,
            allow_build_scripts,
            false,
            xc_load,
            Some(checkpoint.as_path()),
        );
        // Populate emits no stdout of interest (bindings discarded); a non-zero
        // exit still surfaces as an error.
        let _ = run_introspect_chunk(caps, scoped_tmp, binds, &payload)?;
    }

    // Stage 3 — bind each crate against the complete cross-crate index.
    let mut bound: Vec<serde_json::Value> = Vec::with_capacity(entries.len());
    for (i, (spec, features)) in entries.iter().enumerate() {
        let chunk_manifest = write_inspector_manifest_chunk(
            scoped_tmp.as_path(),
            &format!("bind-{i}"),
            spec,
            features,
        )?;
        let payload = manifest_chunk_payload(
            inspector,
            &chunk_manifest,
            allow_build_scripts,
            false,
            Some(checkpoint.as_path()),
            None,
        );
        let json = run_introspect_chunk(caps, scoped_tmp, binds, &payload)?;
        // A manifest chunk always emits a JSON array (of one PkgInfo).
        match serde_json::from_str::<serde_json::Value>(&json) {
            Ok(serde_json::Value::Array(items)) => bound.extend(items),
            Ok(other) => bound.push(other),
            Err(e) => {
                return Err(io_err(format!(
                    "invalid inspector JSON for `{}`: {e}",
                    spec.inspector_arg()
                )));
            }
        }
    }
    serde_json::to_string(&serde_json::Value::Array(bound))
        .map_err(|e| io_err(format!("re-serializing chunked inspection failed: {e}")))
}

/// Serialize a SINGLE-crate inspector manifest into the scoped scratch under a
/// stage-unique name (`<stage>.json`), so a crate's populate and bind chunks —
/// and successive crates — never clobber each other's manifest file.
fn write_inspector_manifest_chunk(
    scoped_tmp: &Path,
    stage: &str,
    spec: &CrateSpec,
    features: &[String],
) -> Result<PathBuf, CliError> {
    let arr = serde_json::json!([{ "name": spec.inspector_arg(), "features": features }]);
    let path = scoped_tmp.join(format!("ipe-install-{stage}.json"));
    std::fs::write(&path, arr.to_string())
        .map_err(|e| CliError::Usage(text::msg::ffi_install_manifest_chunk_write_failed(&e)))?;
    Ok(path)
}

/// The explicit `IPE_FFI_ALLOW_UNSANDBOXED=1` escape hatch: one direct argv
/// spawn, loudly labelled.
fn run_inspector_job_unsandboxed(
    inspector: &Path,
    job: &InspectorJob,
    scratch_hint: &str,
    allow_build_scripts: bool,
) -> Result<String, CliError> {
    let io_err = |detail: String| {
        CliError::Usage(text::msg::command_refusal(
            &"add",
            &crate::style::TerminalSafe::sanitize(&detail),
        ))
    };
    crate::screen::chatter(
        crate::screen::Stream::Stderr,
        crate::screen::Tone::UserError,
        "WARNING: running the FFI inspector UNSANDBOXED (IPE_FFI_ALLOW_UNSANDBOXED=1)",
    );
    let scoped_tmp = make_scratch_dir(scratch_hint)?;
    let manifest_path = match job {
        InspectorJob::Manifest { entries } => Some(write_inspector_manifest(&scoped_tmp, entries)?),
        InspectorJob::Single { .. } | InspectorJob::WrapperPath { .. } => None,
    };
    let payload = inspector_payload(
        inspector,
        job,
        manifest_path.as_deref(),
        allow_build_scripts,
        false,
    );
    let (program, rest) = payload
        .split_first()
        .ok_or(CliError::Usage(text::msg::ffi_add_no_payload()))?;
    let out = std::process::Command::new(program)
        .args(rest)
        .output()
        .map_err(|e| io_err(e.to_string()));
    let _ = std::fs::remove_dir_all(&scoped_tmp);
    let out = out?;
    if !out.status.success() {
        return Err(io_err(format!(
            "inspector exited with {:?}\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    String::from_utf8(out.stdout)
        .map_err(|_| io_err("inspector produced non-UTF-8 output".to_owned()))
}

/// Inspect + install a `[rust.wrapper]` local wrapper crate.
///
/// The path is decode-jailed to the package tree by
/// [`ipe_ffi::wrapper::WrapperManifest`], then canonicalized under the project
/// root; the inspector binds only the exposed symbols and reports the crate's
/// absolute path as `wrapperPath`, so the emitted app crate depends on it by
/// `path`. The wrapper's build runs in the same RCE jail as a crate's build
/// script — the whole-`/` read-only bind makes the local source readable, and
/// the sandboxed build catches a non-compiling wrapper BEFORE exit 0.
fn install_wrapper(
    cache: &FfiCache,
    raw: &RawWrapperTable,
    assume_yes: bool,
    allow_build_scripts: bool,
) -> Result<(), CliError> {
    let manifest =
        ipe_ffi::wrapper::WrapperManifest::parse(&raw.path, &raw.expose, &raw.capabilities)
            .map_err(|diag| CliError::Usage(crate::text::Message::relay(&diag)))?;
    // Resolve the package-jailed relative path under the cache's project root
    // through the SAME jail the build-time load re-proves: canonicalization
    // resolves symlinks (so a checked-in symlink cannot lead out of the
    // project), confirms the wrapper directory and its `Cargo.toml` exist
    // before any jailed build, and reads the crate's `[package] name`.
    let rel = manifest.path().as_str();
    let relay =
        |diag: &ipe_ffi::diag::Diagnostic| CliError::Usage(crate::text::Message::relay(diag));
    let project_root = cache.project_root().map_err(|diag| relay(&diag))?;
    let jailed = ipe_ffi::pkginfo::WrapperCratePath::parse(rel)
        .and_then(|path| path.jail(project_root))
        .map_err(|defect| {
            relay(&ipe_ffi::diag::Diagnostic::WireMalformed {
                context: format!("wrapper crate `{rel}`"),
                defect,
            })
        })?;
    let abs_str = jailed.as_str().to_owned();
    let abs = PathBuf::from(&abs_str);
    // The inspection slug is the `[package] name` the jail read from the
    // wrapper's own `Cargo.toml`, so the installed package name, the
    // dependency key, and the crate cargo finds at the path are one name.
    let krate = CrateName::parse(jailed.package().as_str())
        .map_err(|diag| CliError::Usage(crate::text::Message::relay(&diag)))?;

    // The capability gate runs BEFORE the trust prompt and any jailed compile: a
    // wrapper whose effects Ipê cannot contain at run must be refused before we
    // ask to build it. It scans the wrapper's own `.rs`, reconciles the inferred
    // set against the declared one, and refuses any runtime-unenforceable or
    // opaque capability (there is no runtime sandbox around the emitted app in
    // this release, so such a capability would be uncontained — refuse rather
    // than admit unenforced).
    enforce_wrapper_capabilities(&abs, manifest.capabilities())?;

    if !assume_yes {
        use std::io::Write as _;
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            &format!(
                "About to COMPILE a local wrapper crate `{}` at {} (inside the isolation jail).",
                krate.as_str(),
                abs_str
            ),
        );
        crate::screen::prompt("Continue? [y/N] ");
        let _ = std::io::stdout().flush();
        if !crate::read_yes_no() {
            return Err(CliError::Usage(text::msg::install_aborted()));
        }
    }
    let expose = manifest.expose_names();
    let json = run_inspector_job(
        &InspectorJob::WrapperPath {
            krate: &krate,
            abs_path: &abs_str,
            expose: &expose,
        },
        allow_build_scripts,
    )
    .map_err(|e| match e {
        CliError::Usage(msg) => map_inspector_error(msg),
        other => other,
    })?;
    // A single-crate inspector run may emit a singleton array; unwrap it.
    let doc_text = match serde_json::from_str::<serde_json::Value>(&json) {
        Ok(serde_json::Value::Array(items)) if items.len() == 1 => items
            .first()
            .map(serde_json::Value::to_string)
            .unwrap_or(json),
        _ => json,
    };
    let (pkg, paths) = ipe_ffi::driver::install_from_inspection(cache, &doc_text)
        .map_err(|diag| CliError::Usage(crate::text::Message::relay(&diag)))?;
    let iface = ipe_ffi::interface::crate_interface(&pkg);
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(
            crate::screen::Tone::Text,
            &format!(
                "added wrapper `{}`: {} bindings ({} skipped) -> {}",
                pkg.name(),
                iface.bindings.len(),
                iface.skipped.len(),
                paths.interface.display()
            ),
        )
        .emit();
    Ok(())
}

/// The capability gate for a `[rust.wrapper]` crate: scan its source, reconcile
/// the inferred set against the author's declaration, and REFUSE any wrapper
/// whose effects Ipê cannot enforce at run.
///
/// The three-layer defence, load-bearing part last (spec §5):
///   1. **Static inference** proposes a coarse capability set by token-scanning
///      the wrapper's `.rs` (string/comment-safe, over-approximating).
///   2. **Declaration** is the author's typed [`Capability`] set (already parsed
///      fail-closed by [`ipe_ffi::wrapper::WrapperManifest`]).
///   3. **Enforcement**: there is no runtime sandbox around the emitted app in
///      this release, so a capability on a runtime-enforced axis is infeasible to
///      contain — [`ipe_ffi::capability_scan::reconcile`] REFUSES it rather than
///      admit it unenforced. Only wrappers confined to the containable axes
///      (clock/random, or none) install.
///
/// # Errors
/// [`CliError::Io`] on a read failure; [`CliError::Usage`] when the
/// reconcile refuses the wrapper (naming every reason and the proposed set).
/// The jail-holds verdict for THIS host — the admit path's per-target hand-off.
///
/// The refuse-until-jail → admit-and-isolate hand-off is per-target: a
/// runtime-enforced axis is admitted only where the jail actually holds. The
/// deploy target is unknown at install, so the honest proxy is this host's jail
/// capability — `ipe add` and `ipe dev run` typically run on the same machine. It is
/// built from [`ipe_sandbox::run_jail::platform_confined_axes`] — the SET of
/// runtime-enforced axes the compiled-in `exec_in_run_jail` arm actually confines
/// on this host, single-sourced to that arm by the `on_jailed_target!` macro. So
/// the admit path can never claim an axis the jail does not enforce: a full-set
/// host (Linux/macOS) admits-and-isolates every axis, an empty-set (stub) host
/// refuse-gaps every axis, and a future partial-coverage host admits only the
/// axes it confines.
fn jail_for_host() -> ipe_ffi::capability_scan::JailForTarget {
    let mut confined = ipe_ffi::capability_scan::CapabilitySet::EMPTY;
    for &axis in ipe_sandbox::run_jail::platform_confined_axes() {
        confined = confined.with(axis);
    }
    ipe_ffi::capability_scan::JailForTarget::Holds(confined)
}

/// The refusal for a wrapper crate whose capabilities cannot be enforced.
pub(crate) struct WrapperRefusal {
    /// Every reason the wrapper is refused.
    reasons: Vec<ipe_ffi::capability_scan::RefuseReason>,
    /// The capability set the scan inferred from the wrapper's source.
    proposed: BTreeSet<ipe_ffi::capability_scan::Capability>,
}

impl std::fmt::Display for WrapperRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "ipe install: the wrapper crate cannot be admitted — its capabilities cannot be \
             enforced in this release."
        )?;
        for reason in &self.reasons {
            writeln!(f, "  - {reason}")?;
        }
        if self.proposed.is_empty() {
            writeln!(
                f,
                "  inferred from its source: (none — but see the reasons above)"
            )?;
        } else {
            let names: Vec<&str> = self.proposed.iter().map(|c| c.as_str()).collect();
            writeln!(f, "  inferred from its source: {}", names.join(", "))?;
        }
        f.write_str(
            "  Ipê has no runtime sandbox around the emitted app yet, so a wrapper that \
             touches the network, filesystem, environment, a subprocess, native FFI, or a \
             non-std dependency would run uncontained. Narrow the wrapper to pure compute \
             (Tier 1 `[rust.define.*]` covers the safe shapes), or wait for the runtime jail.",
        )
    }
}

fn enforce_wrapper_capabilities(
    wrapper_dir: &Path,
    declared: &BTreeSet<ipe_ffi::capability_scan::Capability>,
) -> Result<(), CliError> {
    // Read every `.rs` under the wrapper crate (incl. `build.rs`, `bin/`,
    // nested modules). A single unscanned file is a hole, so the walk is
    // recursive and unfiltered. The crate is held once: its manifest and every
    // source are opened from that handle, no link followed, and a link where a
    // source or directory could be is refused, so nothing hides from the scan.
    let wrapper = open_project_dir(wrapper_dir, &[])?
        .ok_or_else(|| held_read_error(wrapper_dir, OpenRefusal::Absent))?;

    // A wrapper with any non-`std` Cargo dependency is opaque: a dependency's
    // capabilities live in source the scan never opens.
    let non_std_deps = wrapper_non_std_dependencies(&wrapper, wrapper_dir)?;

    let sources: Vec<(String, String)> = read_source_tree(
        wrapper,
        wrapper_dir,
        WRAPPER_SOURCES,
        FFI_CACHE_CAP,
        Unreadable::Refuse,
    )?
    .into_iter()
    .map(|(file, src)| (file.display().to_string(), src))
    .collect();
    let scan = ipe_ffi::capability_scan::scan_sources(
        sources.iter().map(|(f, s)| (f.as_str(), s.as_str())),
    );

    let jail = jail_for_host();

    // A best-effort honesty smell test on the declaration: surface an obvious
    // under-declaration (the scan proposes an axis the author did not declare)
    // that the jail nonetheless CONFINES on this host. An undeclared axis the
    // jail does NOT confine is refused by the reconcile below, so it is not a
    // "will still contain" note. This is DEFEATABLE and never the boundary — the
    // jail is — but it nudges an honest declaration.
    let confined = jail.confined();
    let undeclared: Vec<&str> = scan
        .proposed
        .difference(declared)
        .filter(|c| confined.confines(**c))
        .map(|c| c.as_str())
        .collect();
    if !undeclared.is_empty() {
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            &format!(
                "note: the wrapper's source appears to reach {} that it did not declare. \
                 The runtime jail will still contain any undeclared effect (it fails closed at \
                 the OS boundary), but an honest declaration is the consent surface a user sees — \
                 consider declaring it.",
                undeclared.join(", ")
            ),
        );
    }

    match ipe_ffi::capability_scan::reconcile_for(declared, &scan, &non_std_deps, jail) {
        ipe_ffi::capability_scan::Verdict::Admit { declared } => {
            let contains_native_ffi =
                declared.contains(&ipe_ffi::capability_scan::Capability::NativeFfi);
            let cap_line = if declared.is_empty() {
                "wrapper capability check: no capabilities — pure compute.".to_owned()
            } else {
                let names: Vec<&str> = declared.iter().map(|c| c.as_str()).collect();
                format!(
                    "wrapper capability check: admitted and isolated by the runtime jail — {}.",
                    names.join(", ")
                )
            };
            let consent_note = if contains_native_ffi {
                "\n  note: this wrapper crosses into native `Rust.` code (native-ffi). Ipê \
                 cannot infer its true effects — the runtime jail CONTAINS it (an undeclared \
                 syscall fails closed), but does not PROVE the declared set is complete. \
                 Installing is informed consent to the declared capabilities."
            } else {
                ""
            };
            crate::screen::Screen::new(crate::screen::Stream::Stdout)
                .line(
                    crate::screen::Tone::Text,
                    &format!("{cap_line}{consent_note}"),
                )
                .emit();
            Ok(())
        }
        ipe_ffi::capability_scan::Verdict::Refuse { reasons, proposed } => Err(CliError::Usage(
            crate::text::Message::relay(&WrapperRefusal { reasons, proposed }),
        )),
    }
}

/// The wrapper crate's non-`std` Cargo dependency names, read from its
/// `Cargo.toml`. A wrapper with any external dependency is opaque to the source
/// scan (a dependency's capabilities live in source the scan never opens), so
/// each name becomes a refuse trigger.
///
/// This is a deliberately conservative line-scan of EVERY Cargo dependency-table
/// form — `[dependencies]`, `[build-dependencies]`, `[target.*.dependencies]`,
/// `[workspace.dependencies]`, and the `[….dependencies.<name>]` sub-table — via
/// [`parse_cargo_dependency_names`]. It OVER-collects (the safe direction): an
/// over-refused wrapper costs an author a narrowing, whereas a missed dep would
/// admit an unconstrained capability. `dev-dependencies` are excluded (test/
/// build-only, never shipped).
///
/// # Errors
/// The [`held_read_error`] of a manifest that is a link, not a regular file,
/// past its cap, or unreadable (refused, not silently treated as
/// dependency-free).
fn wrapper_non_std_dependencies(
    wrapper: &HeldDir,
    wrapper_dir: &Path,
) -> Result<Vec<String>, CliError> {
    // No manifest means no crate to inspect; the inspector will fail loudly
    // later. Treat as no declared deps here (the source scan still runs).
    Ok(
        read_held_file(wrapper, wrapper_dir, "Cargo.toml", SMALL_FILE_CAP)?
            .as_deref()
            .map_or_else(Vec::new, parse_cargo_dependency_names),
    )
}

/// Extract every dependency name from a `Cargo.toml`'s text — the pure,
/// unit-testable core of [`wrapper_non_std_dependencies`].
///
/// Parse, don't validate: the manifest is parsed into a typed TOML document and
/// EVERY dependency table is read structurally, so a trailing comment on a
/// header, whitespace inside `[ dependencies ]`, an inline
/// `dependencies = { … }` table, and the `[target.*]` / `[workspace]` forms all
/// resolve identically — a hand-rolled line scan under-refuses on those and any
/// missed dependency would admit an unconstrained capability. A manifest that
/// does not parse yields the whole document's key set conservatively via the
/// fallback, so a malformed `Cargo.toml` never silently reports "no deps"
/// (the inspector's own build then fails it loudly).
fn parse_cargo_dependency_names(text: &str) -> Vec<String> {
    let Ok(doc) = text.parse::<toml::Value>() else {
        // A `Cargo.toml` that does not parse is refused conservatively: if the
        // word `dependencies` appears anywhere, treat it as having a dependency
        // (a sentinel name), so a malformed manifest cannot fail OPEN. The real
        // build later rejects the unparseable manifest loudly.
        return if text.contains("dependencies") {
            vec!["<unparseable-cargo-toml>".to_owned()]
        } else {
            Vec::new()
        };
    };
    let mut deps: BTreeSet<String> = BTreeSet::new();
    collect_dependency_tables(&doc, &mut deps);
    deps.into_iter().collect()
}

/// Walk a parsed `Cargo.toml` value, inserting the name of every dependency
/// declared in any `dependencies` or `build-dependencies` table — at the top
/// level, under `[target.*]`, or under `[workspace]`. `dev-dependencies` are
/// test/build-only and never shipped, so they are deliberately NOT collected.
fn collect_dependency_tables(value: &toml::Value, out: &mut BTreeSet<String>) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (key, sub) in table {
        match key.as_str() {
            // A shipped dependency table: every KEY is a dependency name.
            "dependencies" | "build-dependencies" => {
                if let Some(deps) = sub.as_table() {
                    for name in deps.keys() {
                        out.insert(name.clone());
                    }
                }
            }
            // Any other table may nest a dependency table one or more levels
            // down: `[target.<cfg>].dependencies`, `[workspace].dependencies`,
            // or a future/unknown Cargo form. Recurse into EVERY sub-table so no
            // nesting escapes the scan (bounded by the parser's own nesting
            // limit). Over-collection is the safe direction — a spurious name
            // only over-refuses a wrapper, whereas a missed one would admit an
            // unconstrained capability.
            _ => collect_dependency_tables(sub, out),
        }
    }
}

/// Map an FFI driver diagnostic to a [`CliError`] that does NOT trigger the
/// `CommandUsage` help page.
///
/// A build/inspection failure is not command-line misuse — showing the `ipe
/// rust add` usage synopsis after a pkg-config error is noise, not help.
/// `Resolve` passes through `with_help_on_misuse` unchanged and renders via
/// the normal `ipe: {msg}` path.
///
/// Render an inspector diagnostic as a `CliError`. The raw log escape hatch is
/// the caller's concern (it holds the inspection document): under `--verbose` a
/// caller emits the raw log via [`emit_raw_inspector_log`] before this summary.
fn ffi_build_error(diag: ipe_ffi::diag::Diagnostic) -> CliError {
    // Convert the FFI diagnostic into the shared typed currency and route it
    // through the single pipeline renderer. Both text and `--format json` now
    // use the same path as every P/N/T/L diagnostic.
    let shared: ipe_diagnostics::Diagnostic = diag.into();
    CliError::Pipeline {
        file: PathBuf::new(),
        src: String::new(),
        diag: Box::new(shared),
    }
}

/// Emit the raw inspector error log to stderr — the `--verbose` escape hatch
/// behind the summarised build diagnostic. Each line renders as inline
/// [`TerminalSafe`](crate::style::TerminalSafe), so raw build-script stderr
/// cannot forge terminal markup or an output line. A document with no error
/// channel prints nothing.
fn emit_raw_inspector_log(inspection_json: &str) {
    let log = ipe_ffi::driver::inspection_error_log(inspection_json);
    if log.is_empty() {
        return;
    }
    crate::screen::chatter(
        crate::screen::Stream::Stderr,
        crate::screen::Tone::Text,
        "raw inspector log (--verbose):",
    );
    for line in &log {
        let clean = crate::style::TerminalSafe::sanitize(line);
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Aux,
            &format!("  {clean}"),
        );
    }
}

/// Detect the inspector's `--allow-build-scripts` refusal text in a raw error
/// message and return it as a warning string suitable for a banner.
///
/// The inspector prints this when it finds build-script crates but the flag
/// was not passed. Returns `None` when the text is not present.
fn detect_build_scripts_hint(raw: &str) -> Option<&str> {
    // The inspector emits a line containing "--allow-build-scripts" in its
    // human-readable refusal message. Any line that mentions it is the hint.
    raw.lines().find(|l| l.contains("--allow-build-scripts"))
}

/// Map a raw inspector `Usage` error string to a `CliError::Resolve`
/// that never triggers the `CommandUsage` help page.
///
/// If the raw error contains the `--allow-build-scripts` refusal hint, the
/// hint is pulled out and rendered as a separate plain-text warning banner so
/// the user can see the actionable flag clearly.
fn map_inspector_error(msg: crate::text::Message) -> CliError {
    // Detect the hint before consuming `msg`, then branch.
    let hint_line =
        detect_build_scripts_hint(&msg).map(|l| crate::style::TerminalSafe::sanitize(l.trim()));
    hint_line.map_or(CliError::Resolve(msg), |hint| {
        // The build-scripts refusal: render the hint as a banner so the
        // `--allow-build-scripts` flag stands out as the actionable next step.
        CliError::Resolve(crate::text::Message::relay(&BuildScriptsBanner { hint }))
    })
}

/// The warning banner for an inspector refusal that `--allow-build-scripts`
/// would lift.
///
/// Plain text: a relayed [`crate::text::Message`] is sanitised whole, so the
/// banner carries no styling escapes of its own.
pub(crate) struct BuildScriptsBanner {
    /// The inspector's hint line.
    hint: crate::style::TerminalSafe,
}

impl std::fmt::Display for BuildScriptsBanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "warning: some crates in the dependency graph have build scripts.\n\
             Pass --allow-build-scripts to proceed (you will see a warning naming\n\
             those packages first, and they will run inside the isolation jail).\n\
             \n\
             hint: {hint}",
            hint = self.hint,
        )
    }
}

/// Shared tail of `add` / `install`: inspect one crate + write its artifacts.
///
/// Emits progress stage lines to stderr as each phase runs so the user can
/// follow the long resolve → inspect → build sequence.
fn add_one(
    cache: &FfiCache,
    krate: &CrateSpec,
    features: &[String],
    allow_build_scripts: bool,
    verbose: bool,
) -> Result<(), CliError> {
    use crate::progress::{Mode, Stage};
    let mode = Mode::for_stream(&std::io::stderr());
    let crate_label = krate.name().as_str();

    let stage = Stage::with_mode(std::io::stderr(), mode, format!("resolving {crate_label}…"));
    let json_result = run_inspector(krate, features, allow_build_scripts);
    let json = match json_result {
        Ok(j) => {
            stage.success(format!("resolved {crate_label}"));
            j
        }
        Err(e) => {
            stage.failure(format!("resolve failed for {crate_label}"));
            // A build failure from the inspector is not command-line misuse.
            return Err(match e {
                CliError::Usage(msg) => map_inspector_error(msg),
                other => other,
            });
        }
    };
    // A multi-crate inspector run emits a JSON array; `ipe add` runs one
    // crate, but tolerate the array wrapper by unwrapping a singleton.
    let doc_text = match serde_json::from_str::<serde_json::Value>(&json) {
        Ok(serde_json::Value::Array(items)) if items.len() == 1 => items
            .first()
            .map(serde_json::Value::to_string)
            .unwrap_or(json),
        _ => json,
    };
    // Lift `foreign` declarations from the project's source files and merge them
    // into the inspection document before the driver decodes it, so each
    // author-declared adapter/struct/enum flows through the same `PkgInfo` gate
    // and the unforgeable `FfiInterface` module as an inspected binding.
    let doc_text = match read_project_file(Path::new(""), &[], PROJECT_MANIFEST, MANIFEST_CAP)? {
        Some(text) => {
            reject_legacy_define_tables(&text)?;
            let src_root = Path::new("src");
            let (closures, structs, enums, opaques) = scan_foreign_defines(src_root)?;
            let sole_dep = rust_dependencies_from_manifest(&text).len() <= 1;
            merge_provides(
                &doc_text,
                krate.name().as_str(),
                &closures,
                &structs,
                &enums,
                &opaques,
                sole_dep,
            )?
        }
        // No manifest (a bare `ipe add` outside a project) ⇒ nothing to merge.
        None => doc_text,
    };
    let build_stage = Stage::with_mode(std::io::stderr(), mode, format!("building {crate_label}…"));
    let install_result = ipe_ffi::driver::install_from_inspection(cache, &doc_text);
    match install_result {
        Ok((pkg, paths)) => {
            build_stage.success(format!("built {crate_label}"));
            let iface = ipe_ffi::interface::crate_interface(&pkg);
            crate::screen::Screen::new(crate::screen::Stream::Stdout)
                .line(
                    crate::screen::Tone::Text,
                    &format!(
                        "added `{}` v{}: {} bindings ({} skipped) -> {}",
                        pkg.name(),
                        pkg.version(),
                        iface.bindings.len(),
                        iface.skipped.len(),
                        paths.interface.display()
                    ),
                )
                .emit();
            Ok(())
        }
        Err(diag) => {
            build_stage.failure(format!("build failed for {crate_label}"));
            if verbose {
                emit_raw_inspector_log(&doc_text);
            }
            Err(ffi_build_error(diag))
        }
    }
}

/// The file the FFI text inspector reads the `[rust.dependencies]` vocabulary
/// from.
///
/// `package.ipe` cannot yet express `[rust.dependencies]` (the outstanding
/// ergonomic Rust-FFI work), so a native `package.ipe` keeps that vocabulary in
/// a sibling `ipe.toml` sidecar, which is read here. A path that is already an
/// `ipe.toml` (or any non-`package.ipe`) is read as-is, and a `package.ipe`
/// with no sidecar falls back to itself so a pure-Ipê manifest stays a no-op.
/// Both are read from one held handle on the manifest's directory, never
/// following a link and never blocking on a FIFO.
///
/// # Errors
/// [`CliError::Io`] when the manifest is absent or its name is not one plain
/// UTF-8 entry name; the [`held_read_error`] of a sidecar or manifest that is a
/// link, not a regular file, past [`MANIFEST_CAP`], or unreadable.
fn read_ffi_vocabulary(manifest_path: &Path) -> Result<String, CliError> {
    let (Some(dir), Some(name)) = (
        manifest_path.parent(),
        manifest_path.file_name().and_then(OsStr::to_str),
    ) else {
        return Err(held_read_error(manifest_path, OpenRefusal::BadName));
    };
    let absent = || held_read_error(manifest_path, OpenRefusal::Absent);
    let held = open_project_dir(dir, &[])?.ok_or_else(absent)?;
    if name == PROJECT_MANIFEST
        && let Some(sidecar) = read_held_file(&held, dir, PROJECT_MANIFEST_TOML, MANIFEST_CAP)?
    {
        return Ok(sidecar);
    }
    read_held_file(&held, dir, name, MANIFEST_CAP)?.ok_or_else(absent)
}

/// Returns an error if `text` contains a legacy `[[rust.define.*]]` TOML table.
///
/// `[[rust.define.*]]` is no longer supported; declare FFI types via `foreign`
/// in `src/Ffi/<Crate>.ipe` instead.
fn reject_legacy_define_tables(text: &str) -> Result<(), CliError> {
    if text.contains("[[rust.define.") {
        return Err(CliError::Usage(
            crate::text::msg::ffi_legacy_define_removed(),
        ));
    }
    Ok(())
}

/// Install the registry FFI dependencies declared in `manifest_path`'s
/// `[rust.dependencies]` into the project root's `.ipe/cache/ffi/rust`.
///
/// Used by the package audit gate to regenerate bindings from the pinned crates
/// rather than trusting any committed cache. The generated artifacts are written
/// into the project's own `.ipe/cache/ffi/rust` directory, so the audit gate's
/// ownership check ([`owner_trust::open_cache`]) passes — the directory is
/// created by the invoking process under the invoking uid, and no other user
/// can write it.
///
/// `allow_build_scripts` controls whether the bwrap-jailed inspector runs each
/// crate's build scripts. The audit gate always passes `true` because build
/// scripts run inside the bwrap jail with network access denied; skipping them
/// would silently omit bindings for crates that require them to generate their
/// API surface. The jail, not pre-verification, is the confinement boundary.
///
/// Pure-Ipê manifests without `[rust.dependencies]` or `[rust.wrapper]` are a
/// no-op: the function returns `Ok(())` immediately.
///
/// # Errors
/// [`CliError::Io`] when the manifest cannot be read; [`CliError::Usage`]
/// when the jailed inspector fails or produces an undecodable result.
pub fn install_registry_deps_for_project(
    manifest_path: &Path,
    allow_build_scripts: bool,
) -> Result<(), CliError> {
    let project_root = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    // The `[rust.dependencies]` FFI vocabulary lives in the `ipe.toml` sidecar
    // for a native `package.ipe`, so read the source that actually carries it
    // before scanning for dependencies.
    let text = read_ffi_vocabulary(manifest_path)?;
    let deps = rust_dependencies_from_manifest(&text);
    if deps.is_empty() {
        return Ok(());
    }
    let cache = FfiCache::at_project_root(project_root);
    let mut entries: Vec<(CrateSpec, Vec<String>)> = Vec::with_capacity(deps.len());
    for dep in &deps {
        let name = CrateName::parse(&dep.name)
            .map_err(|diag| CliError::Usage(crate::text::Message::relay(&diag)))?;
        let version = match dep.version.trim() {
            "" | "*" => None,
            pin => Some(
                VersionPin::parse(pin)
                    .map_err(|diag| CliError::Usage(crate::text::Message::relay(&diag)))?,
            ),
        };
        let mut features = Vec::with_capacity(dep.features.len());
        for feat in &dep.features {
            features.push(
                FeatureName::parse(feat)
                    .map_err(|defect| CliError::Usage(crate::text::Message::relay(&defect)))?,
            );
        }
        let features: Vec<String> = features.iter().map(|f| f.as_str().to_owned()).collect();
        entries.push((CrateSpec::new(name, version), features));
    }
    let json = run_inspector_job(
        &InspectorJob::Manifest { entries: &entries },
        allow_build_scripts,
    )
    .map_err(|e| match e {
        CliError::Usage(msg) => map_inspector_error(msg),
        other => other,
    })?;
    let val: serde_json::Value = serde_json::from_str(&json)
        .map_err(|e| CliError::Usage(text::msg::ffi_regen_invalid_json(&e)))?;
    let items: Vec<serde_json::Value> = match val {
        serde_json::Value::Array(items) => items,
        one @ serde_json::Value::Object(_) => vec![one],
        other => {
            return Err(CliError::Usage(text::msg::ffi_regen_unexpected_shape(
                &other,
            )));
        }
    };
    reject_legacy_define_tables(&text)?;
    // Lift `foreign` declarations from the project's source files.
    let src_root = project_root.join("src");
    let (closures, structs, enums, opaques) = scan_foreign_defines(&src_root)?;
    let sole_dep = deps.len() <= 1;
    for item in &items {
        let item_crate = item
            .get("name")
            .or_else(|| item.get("pkg"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CliError::Usage(text::msg::ffi_regen_item_unnamed(&item)))?
            .to_owned();
        let merged = merge_provides(
            &item.to_string(),
            &item_crate,
            &closures,
            &structs,
            &enums,
            &opaques,
            sole_dep,
        )?;
        ipe_ffi::driver::install_from_inspection(&cache, &merged).map_err(ffi_build_error)?;
    }
    Ok(())
}

/// `ipe rust <add|remove|install> …` — the Rust foreign-function group.
///
/// Bare `ipe rust` prints the group's own `--help` page (the single source of
/// truth in `help::command`). Every subcommand dispatches to the existing FFI
/// command body unchanged.
///
/// # Errors
/// [`CliError`] on an unknown subcommand or any subcommand failure.
pub fn run_rust(rest: &[String]) -> Result<(), CliError> {
    match rest.split_first() {
        // A bare `ipe rust` is misuse, not a help request: fail closed with the
        // usage hint so the dispatcher shows the `--help` page and exits
        // non-zero — matching bare `ipe package`. An explicit `ipe rust --help`
        // is still honoured as a help request upstream.
        None => Err(CliError::Usage(text::msg::rust_usage())),
        Some((sub, args)) if sub == "add" => run_add(args),
        Some((sub, args)) if sub == "remove" => run_remove(args),
        Some((sub, args)) if sub == "install" => run_install(args),
        Some((sub, _)) => Err(crate::cli_args::usage_unknown_subcommand(
            "rust",
            sub,
            "add, remove, or install",
        )),
    }
}

/// `ipe rust add <crate>[@<version>] [--features a,b] [--yes] [--verbose]`.
///
/// # Errors
/// [`CliError`] on misuse, a refused inspection, or a cache-write failure.
pub fn run_add(rest: &[String]) -> Result<(), CliError> {
    let mut krate: Option<String> = None;
    let mut features: Vec<String> = Vec::new();
    let mut assume_yes = false;
    let mut allow_build_scripts = false;
    let mut verbose = false;
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--features" => {
                let raw = it.next().ok_or_else(|| {
                    CliError::Usage(text::msg::flag_needs_value(&"rust add", &"--features"))
                })?;
                // Parse, don't validate: gate each feature name at the boundary
                // before it can reach the emitted manifest's `features` array.
                for feat in raw.split(',') {
                    let gated = FeatureName::parse(feat)
                        .map_err(|defect| CliError::Usage(crate::text::Message::relay(&defect)))?;
                    features.push(gated.as_str().to_owned());
                }
            }
            "--yes" => assume_yes = true,
            "--allow-build-scripts" => allow_build_scripts = true,
            "--verbose" => verbose = true,
            other if krate.is_none() => krate = Some(other.to_owned()),
            _ => {
                return Err(CliError::Usage(text::msg::rust_add_usage()));
            }
        }
    }
    let raw = krate.ok_or(CliError::Usage(text::msg::rust_add_usage()))?;
    let spec = CrateSpec::parse(&raw)
        .map_err(|diag| CliError::Usage(crate::text::Message::relay(&diag)))?;

    if !assume_yes {
        use std::io::Write as _;
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            &ipe_ffi::driver::trust_summary(spec.name(), "", None, 0),
        );
        crate::screen::prompt("[y/N] ");
        let _ = std::io::stdout().flush();
        if !crate::read_yes_no() {
            return Err(CliError::Usage(text::msg::rust_add_aborted()));
        }
    }

    let cache = FfiCache::at_project_root(Path::new("."));
    add_one(&cache, &spec, &features, allow_build_scripts, verbose)
}

/// `ipe rust remove <crate>`.
///
/// # Errors
/// [`CliError`] on misuse or a cache-delete failure.
pub fn run_remove(rest: &[String]) -> Result<(), CliError> {
    let [raw] = rest else {
        return Err(CliError::Usage(text::msg::rust_remove_usage()));
    };
    let cache = FfiCache::at_project_root(Path::new("."));
    let slug = ipe_ffi::driver::slugify(raw);
    cache
        .remove_package(&slug)
        .map_err(|diag| CliError::Usage(crate::text::Message::relay(&diag)))?;
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &format!("removed `{raw}`"))
        .emit();
    Ok(())
}

/// `ipe rust install [--yes] [--allow-build-scripts] [--verbose]` — (re)inspect every
/// rust-dependency crate the project's manifest binds, honouring each entry's
/// version pin and feature list.
///
/// The manifest's rust-dependency + wrapper vocabulary is read from a legacy
/// `ipe.toml`'s `[rust.dependencies]` / `[rust.wrapper]` TOML sections, the only
/// format the text inspector understands. Reading those bindings out of a
/// `package.ipe` is part of the outstanding ergonomic Rust-FFI work, so a
/// `package.ipe`-only project is refused with that pointer rather than silently
/// installing nothing.
///
/// # Errors
/// [`CliError`] on misuse, a missing manifest, or any per-crate failure.
#[allow(clippy::too_many_lines)] // one linear command body: parse manifest, prompt, inspect, per-crate merge+install
pub fn run_install(rest: &[String]) -> Result<(), CliError> {
    let mut assume_yes = false;
    let mut allow_build_scripts = false;
    let mut verbose = false;
    for flag in rest {
        match flag.as_str() {
            "--yes" => assume_yes = true,
            "--allow-build-scripts" => allow_build_scripts = true,
            "--verbose" => verbose = true,
            _ => {
                return Err(CliError::Usage(text::msg::rust_install_usage()));
            }
        }
    }
    if crate::project::manifest_in_dir(Path::new(".")).is_some() {
        return Err(CliError::Usage(
            text::msg::rust_install_package_ipe_unsupported(),
        ));
    }
    let text = match read_project_file(Path::new(""), &[], PROJECT_MANIFEST_TOML, MANIFEST_CAP) {
        Ok(Some(text)) => text,
        Ok(None) => return Err(CliError::Usage(text::msg::rust_install_no_manifest())),
        Err(e) => return Err(CliError::Usage(text::msg::command_refusal(&"install", &e))),
    };
    let deps = rust_dependencies_from_manifest(&text);
    let wrapper = rust_wrapper_from_manifest(&text);
    if deps.is_empty() && wrapper.is_none() {
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(
                crate::screen::Tone::Text,
                "ipe install: no [rust.dependencies] or [rust.wrapper] entries",
            )
            .emit();
        return Ok(());
    }
    let cache = FfiCache::at_project_root(Path::new("."));
    // A `[rust.wrapper]` local crate is inspected + bound like any dependency,
    // from its package-jailed path. Processed before the registry deps so a
    // wrapper-only manifest still installs.
    if let Some(w) = &wrapper {
        install_wrapper(&cache, w, assume_yes, allow_build_scripts)?;
    }
    if deps.is_empty() {
        return Ok(());
    }
    // Bare `ipe install` COMPILES every listed untrusted crate — the same
    // build-script/proc-macro RCE surface `ipe add` gates. Prompt once for the
    // whole list; reserve the silent path for an explicit `--yes`.
    if !assume_yes {
        use std::io::Write as _;
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            &format!(
                "About to fetch and COMPILE untrusted code for {} crate(s): {}\n\
                 Compiling runs each crate's build scripts and proc-macros (inside the isolation jail).",
                names.len(),
                names.join(", ")
            ),
        );
        crate::screen::prompt("Continue? [y/N] ");
        let _ = std::io::stdout().flush();
        if !crate::read_yes_no() {
            return Err(CliError::Usage(text::msg::install_aborted()));
        }
    }
    let mut entries: Vec<(CrateSpec, Vec<String>)> = Vec::with_capacity(deps.len());
    for dep in &deps {
        let name = CrateName::parse(&dep.name)
            .map_err(|diag| CliError::Usage(crate::text::Message::relay(&diag)))?;
        // `*` / empty keep the historical latest-stable resolution; anything
        // else pins the inspector's probe (a prerelease NEEDS an exact `=`).
        let version = match dep.version.trim() {
            "" | "*" => None,
            pin => Some(
                VersionPin::parse(pin)
                    .map_err(|diag| CliError::Usage(crate::text::Message::relay(&diag)))?,
            ),
        };
        // Parse, don't validate: every feature name is gated at the boundary
        // (it is later spliced into the emitted manifest's `features` array).
        let mut features = Vec::with_capacity(dep.features.len());
        for feat in &dep.features {
            features.push(
                FeatureName::parse(feat)
                    .map_err(|defect| CliError::Usage(crate::text::Message::relay(&defect)))?,
            );
        }
        let features: Vec<String> = features.iter().map(|f| f.as_str().to_owned()).collect();
        entries.push((CrateSpec::new(name, version), features));
    }
    // ONE inspector invocation for the whole list: the cross-crate impl
    // index is process-global, so a trait method defined in one dependency
    // and implemented for a sibling's type (the async-SDK `send` shape)
    // binds only when every crate is inspected together.
    let json = run_inspector_job(
        &InspectorJob::Manifest { entries: &entries },
        allow_build_scripts,
    )
    .map_err(|e| match e {
        CliError::Usage(msg) => map_inspector_error(msg),
        other => other,
    })?;
    let val: serde_json::Value = serde_json::from_str(&json)
        .map_err(|e| CliError::Usage(text::msg::ffi_install_invalid_json(&e)))?;
    let items: Vec<serde_json::Value> = match val {
        serde_json::Value::Array(items) => items,
        one @ serde_json::Value::Object(_) => vec![one],
        other => {
            return Err(CliError::Usage(text::msg::ffi_install_unexpected_shape(
                &other,
            )));
        }
    };
    reject_legacy_define_tables(&text)?;
    // Lift `foreign` declarations from the project's source files; merge them
    // per-crate below. `sole_dep` decides whether an unqualified entry attaches.
    let (closures, structs, enums, opaques) = scan_foreign_defines(Path::new("src"))?;
    let sole_dep = deps.len() <= 1;
    for item in items {
        // The crate's own name, from its inspection document, is the key an
        // unqualified `[[rust.define.closure]]` attaches to under `sole_dep`
        // and a qualified one matches against.
        // The manifest's `[rust.dependencies]` key is the crates.io name (the
        // inspection `name`), so match on it; `pkg` (the lib ident) is the
        // fallback for a legacy document that omits `name`.
        let item_crate = item
            .get("name")
            .or_else(|| item.get("pkg"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned();
        let merged = merge_provides(
            &item.to_string(),
            &item_crate,
            &closures,
            &structs,
            &enums,
            &opaques,
            sole_dep,
        )?;
        let (pkg, paths) =
            ipe_ffi::driver::install_from_inspection(&cache, &merged).map_err(|diag| {
                if verbose {
                    emit_raw_inspector_log(&merged);
                }
                ffi_build_error(diag)
            })?;
        let iface = ipe_ffi::interface::crate_interface(&pkg);
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            &format!(
                "added `{}` v{}: {} bindings ({} skipped) -> {}",
                pkg.name(),
                pkg.version(),
                iface.bindings.len(),
                iface.skipped.len(),
                paths.interface.display()
            ),
        );
    }
    Ok(())
}

/// One `[rust.dependencies]` manifest entry.
#[derive(Debug, PartialEq, Eq)]
struct ManifestDep {
    /// The dependency key (the crates.io package name).
    name: String,
    /// The version requirement (empty when unspecified).
    version: String,
    /// The requested feature list (empty when unspecified).
    features: Vec<String>,
}

/// One `[[rust.define.closure]]` manifest entry — the author-declared surface
/// that turns an Ipê function value into a Rust `dyn Fn` of an exact signature.
///
/// This is Rust-side native code shown to the user under informed consent, like
/// any `[rust.*]` surface; it never routes untrusted text into emitted Rust —
/// the `signature` is re-parsed through the closed [`ipe_ffi`] carrier/bound
/// gate (`ClosureSig`) in the driver's `PkgInfo` decode, so a malformed entry
/// over-drops rather than emit-and-cargo-fail, and the wrapper the driver mints
/// lives in the unforgeable `FfiInterface` module exactly like every other
/// binding (user `.ipe` source still cannot mint a `ForeignCall`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ManifestDefineClosure {
    /// The dependency this closure adapter augments (the `[rust.dependencies]`
    /// key). Empty ⇒ attach to the sole dependency (an ambiguity when there is
    /// more than one, refused at merge).
    pub(crate) krate: String,
    /// The wrapper name (the Ipê-facing binding / tri-artifact key).
    pub(crate) name: String,
    /// The exact author-declared target signature, verbatim from the manifest.
    /// It reaches emitted Rust only after re-parsing through `ClosureSig`.
    pub(crate) signature: String,
}

/// One `[[rust.define.struct]]` manifest entry — the author-declared surface
/// that DEFINES a nominal Rust type (a record of owned carrier fields, with an
/// allowlisted `#[derive]` set) plus a constructor wrapper.
///
/// Like the closure surface, this is Rust-side native code shown under informed
/// consent; it never routes untrusted text into emitted Rust — the type name,
/// every field name/type, and every derive re-parse through the driver's closed
/// `StructDef` gate in `PkgInfo` decode, so a malformed entry over-drops rather
/// than emit-and-cargo-fail, and the wrapper lives in the unforgeable
/// `FfiInterface` module exactly like every other binding.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ManifestDefineStruct {
    /// The dependency this struct augments (empty ⇒ the sole dependency).
    pub(crate) krate: String,
    /// The constructor wrapper name (the Ipê-facing binding / tri-artifact key).
    pub(crate) ctor: String,
    /// The Rust type name to define.
    pub(crate) struct_name: String,
    /// The struct fields as `(name, carrier-spelling)` pairs, in order.
    pub(crate) fields: Vec<(String, String)>,
    /// The requested derive tokens (validated against the closed allowlist in
    /// the driver, never rendered raw).
    pub(crate) derives: Vec<String>,
}

/// One `[[rust.define.enum]]` manifest entry — the author-declared surface that
/// DEFINES a nominal Rust `enum` (a sum of unit / tuple-payload variants over
/// owned carriers, with an allowlisted `#[derive]` set) plus one constructor
/// wrapper per variant. This is the P4 `define` form — the shape an Iced/TEA
/// `Message` needs.
///
/// Like the struct surface, this is Rust-side native code shown under informed
/// consent; it never routes untrusted text into emitted Rust — the enum name,
/// every variant name/payload type, and every derive re-parse through the
/// driver's closed `EnumDef` gate in `PkgInfo` decode, so a malformed entry
/// over-drops rather than emit-and-cargo-fail, and the wrappers live in the
/// unforgeable `FfiInterface` module exactly like every other binding.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ManifestDefineEnum {
    /// The dependency this enum augments (empty ⇒ the sole dependency).
    pub(crate) krate: String,
    /// The constructor-wrapper prefix (the Ipê-facing binding / tri-artifact
    /// key). Each variant's constructor is named `<ctor>_<snake(variant)>`.
    pub(crate) ctor: String,
    /// The Rust enum name to define.
    pub(crate) enum_name: String,
    /// The variants as `(name, payload-carrier-spellings)` pairs, in order.
    /// An empty payload list is a unit variant.
    pub(crate) variants: Vec<(String, Vec<String>)>,
    /// The requested derive tokens (validated against the closed allowlist in
    /// the driver, never rendered raw).
    pub(crate) derives: Vec<String>,
}

/// Extract the manifest's `[rust.dependencies]` / `["rust.dependencies"]`
/// entries. Values may be a bare version string (`uuid = "1"`) or an inline
/// table (`stripe = { version = "=1.0.0-rc.6", features = ["a", "b"] }`).
/// A raw `[rust.wrapper]` manifest table: the local wrapper-crate path, the
/// public symbols to bind, and the (accepted-but-not-enforced) capability set.
/// Every field is carried verbatim; `ipe_ffi::wrapper::WrapperManifest::parse`
/// is the gate that validates the path (package-jailed) and each symbol.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RawWrapperTable {
    pub(crate) path: String,
    pub(crate) expose: Vec<String>,
    pub(crate) capabilities: Vec<String>,
}

/// Read the single `[rust.wrapper]` table from a manifest, or `None` when the
/// package declares no wrapper crate. Line-based, matching the other
/// `[rust.*]` readers here (no TOML dependency in this crate).
pub(crate) fn rust_wrapper_from_manifest(text: &str) -> Option<RawWrapperTable> {
    let mut in_table = false;
    let mut table = RawWrapperTable::default();
    let mut found = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_table = crate::project::is_rust_wrapper_header(line);
            if in_table {
                found = true;
            }
            continue;
        }
        if !in_table || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().trim_matches('"');
        let value = v.trim();
        match key {
            "path" => value.trim_matches('"').clone_into(&mut table.path),
            "expose" => table.expose = parse_string_array(value),
            "capabilities" => table.capabilities = parse_string_array(value),
            _ => {}
        }
    }
    found.then_some(table)
}

/// Parse a `["a", "b"]` inline array into its string elements.
fn parse_string_array(value: &str) -> Vec<String> {
    let inner = value
        .trim()
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(value);
    inner
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

fn rust_dependencies_from_manifest(text: &str) -> Vec<ManifestDep> {
    let mut in_table = false;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_table = line == "[rust.dependencies]" || line == "[\"rust.dependencies\"]";
            continue;
        }
        if !in_table || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let name = k.trim().trim_matches('"').to_owned();
            let value = v.trim();
            if let Some(body) = value
                .strip_prefix('{')
                .and_then(|rest| rest.strip_suffix('}'))
            {
                out.push(ManifestDep {
                    name,
                    version: inline_table_string(body, "version").unwrap_or_default(),
                    features: inline_table_string_array(body, "features"),
                });
            } else {
                out.push(ManifestDep {
                    name,
                    version: value.trim_matches('"').to_owned(),
                    features: Vec::new(),
                });
            }
        }
    }
    out
}

/// Read `key = "value"` out of an inline-table body.
fn inline_table_string(body: &str, key: &str) -> Option<String> {
    let at = find_inline_key(body, key)?;
    let rest = body.get(at..)?;
    let (_, after_eq) = rest.split_once('=')?;
    let after_quote = after_eq.trim_start().strip_prefix('"')?;
    after_quote.split_once('"').map(|(v, _)| v.to_owned())
}

/// Read `key = ["a", "b"]` out of an inline-table body.
fn inline_table_string_array(body: &str, key: &str) -> Vec<String> {
    let Some(at) = find_inline_key(body, key) else {
        return Vec::new();
    };
    let Some(rest) = body.get(at..) else {
        return Vec::new();
    };
    let Some((_, after_eq)) = rest.split_once('=') else {
        return Vec::new();
    };
    let Some(after_bracket) = after_eq.trim_start().strip_prefix('[') else {
        return Vec::new();
    };
    let Some((inner, _)) = after_bracket.split_once(']') else {
        return Vec::new();
    };
    inner
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The byte offset of `key` as a whole word in an inline-table body (so
/// `version` never matches inside `some_version_like_name`).
fn find_inline_key(body: &str, key: &str) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut from = 0;
    while let Some(rel) = body.get(from..)?.find(key) {
        let at = from + rel;
        let before_ok = at == 0
            || bytes
                .get(at.wrapping_sub(1))
                .is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'_');
        let after = at + key.len();
        let after_ok = bytes
            .get(after)
            .is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'_');
        if before_ok && after_ok {
            return Some(at);
        }
        from = at + key.len();
    }
    None
}

/// The `snake_case` of a Rust type name (`CounterState` → `counter_state`), for
/// the default constructor-wrapper name.
pub(crate) fn to_snake_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Whether a `[[rust.define.*]]` entry keyed by `entry_crate` attaches to
/// `crate_name`: a qualified entry matches by name; an unqualified one attaches
/// only when the crate is the SOLE dependency (`sole_dep`).
fn define_attaches(entry_crate: &str, crate_name: &str, sole_dep: bool) -> bool {
    if entry_crate.is_empty() {
        sole_dep
    } else {
        entry_crate == crate_name
    }
}

/// Refuse an unqualified `[[rust.define.*]]` entry under a multi-crate manifest
/// (it cannot be attributed to one crate — parse, don't validate at the manifest
/// boundary). `kind` names the surface for the diagnostic; `name` the entry.
fn reject_ambiguous_define<'a>(
    kind: &str,
    sole_dep: bool,
    mut unqualified: impl Iterator<Item = &'a str>,
) -> Result<(), CliError> {
    if !sole_dep && let Some(name) = unqualified.next() {
        return Err(CliError::Usage(text::msg::ffi_define_crate_ambiguous(
            &kind, &name,
        )));
    }
    Ok(())
}

/// Merge every `[[rust.define.closure]]` / `[[rust.define.struct]]` entry that
/// targets `crate_name` into the crate's inspection JSON, as synthetic
/// `functions` carrying the wire flags the driver's `PkgInfo` decode reads.
///
/// The driver's `install_from_inspection` already accepts the merged document
/// and decodes each synthetic entry through the same gate as an inspected
/// function (an ill-formed `signature`/struct over-drops at decode, never
/// emit-and-cargo-fail). The trust gate is intact: the entry is author-declared
/// native code the driver mints into the `FfiInterface` module — user `.ipe`
/// source never sees it.
///
/// An entry whose `crate` is empty attaches to `crate_name` only when it is the
/// SOLE dependency (`sole_dep`); an unqualified entry under a multi-crate
/// manifest is ambiguous and refused, never silently attached to every crate.
/// Refuse any unqualified `foreign`/`[[rust.define.*]]` entry under a
/// multi-crate manifest, across all four surfaces (closure/struct/enum/opaque).
fn reject_ambiguous_defines(
    closures: &[ManifestDefineClosure],
    structs: &[ManifestDefineStruct],
    enums: &[ManifestDefineEnum],
    opaques: &[ManifestDefineOpaque],
    sole_dep: bool,
) -> Result<(), CliError> {
    reject_ambiguous_define(
        "closure",
        sole_dep,
        closures
            .iter()
            .filter(|c| c.krate.is_empty())
            .map(|c| c.name.as_str()),
    )?;
    reject_ambiguous_define(
        "struct",
        sole_dep,
        structs
            .iter()
            .filter(|s| s.krate.is_empty())
            .map(|s| s.ctor.as_str()),
    )?;
    reject_ambiguous_define(
        "enum",
        sole_dep,
        enums
            .iter()
            .filter(|e| e.krate.is_empty())
            .map(|e| e.ctor.as_str()),
    )?;
    reject_ambiguous_define(
        "opaque",
        sole_dep,
        opaques
            .iter()
            .filter(|o| o.krate.is_empty())
            .map(|o| o.ipe_name.as_str()),
    )
}

/// Build the synthetic `functions` entries the driver decodes for every
/// closure/struct/enum define that attaches to `crate_name` — the DEFINE
/// surfaces that mint a Rust type or adapter. Opaque declarations are NOT
/// functions; they merge into `declaredOpaques` separately.
fn build_synthetic_functions(
    crate_name: &str,
    closures: &[ManifestDefineClosure],
    structs: &[ManifestDefineStruct],
    enums: &[ManifestDefineEnum],
    sole_dep: bool,
) -> Vec<serde_json::Value> {
    closures
        .iter()
        .filter(|c| define_attaches(&c.krate, crate_name, sole_dep))
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "effect": "pure",
                "isClosureAdapter": true,
                "closureSig": c.signature,
            })
        })
        .chain(
            structs
                .iter()
                .filter(|s| define_attaches(&s.krate, crate_name, sole_dep))
                .map(|s| {
                    let fields: Vec<serde_json::Value> = s
                        .fields
                        .iter()
                        .map(|(n, t)| serde_json::json!({ "name": n, "type": t }))
                        .collect();
                    serde_json::json!({
                        "name": s.ctor,
                        "effect": "pure",
                        "isStructCtor": true,
                        "structName": s.struct_name,
                        "structFields": fields,
                        "structDerives": s.derives,
                    })
                }),
        )
        .chain(
            enums
                .iter()
                .filter(|e| define_attaches(&e.krate, crate_name, sole_dep))
                .map(|e| {
                    let variants: Vec<serde_json::Value> = e
                        .variants
                        .iter()
                        .map(|(n, payload)| serde_json::json!({ "name": n, "payload": payload }))
                        .collect();
                    serde_json::json!({
                        "name": e.ctor,
                        "effect": "pure",
                        "isEnumDef": true,
                        "enumName": e.enum_name,
                        "enumVariants": variants,
                        "enumDerives": e.derives,
                    })
                }),
        )
        .collect()
}

fn merge_provides(
    inspection_json: &str,
    crate_name: &str,
    closures: &[ManifestDefineClosure],
    structs: &[ManifestDefineStruct],
    enums: &[ManifestDefineEnum],
    opaques: &[ManifestDefineOpaque],
    sole_dep: bool,
) -> Result<String, CliError> {
    reject_ambiguous_defines(closures, structs, enums, opaques, sole_dep)?;
    let synthetic = build_synthetic_functions(crate_name, closures, structs, enums, sole_dep);
    let attached_opaques: Vec<&ManifestDefineOpaque> = opaques
        .iter()
        .filter(|o| define_attaches(&o.krate, crate_name, sole_dep))
        .collect();
    if synthetic.is_empty() && attached_opaques.is_empty() {
        return Ok(inspection_json.to_owned());
    }
    let mut doc: serde_json::Value = serde_json::from_str(inspection_json)
        .map_err(|e| CliError::Usage(text::msg::ffi_inspection_not_object_detail(&e)))?;
    if !synthetic.is_empty() {
        let obj = doc
            .as_object_mut()
            .ok_or_else(|| CliError::Usage(text::msg::ffi_inspection_not_object()))?;
        let serde_json::Value::Array(functions) = obj
            .entry("functions")
            .or_insert_with(|| serde_json::Value::Array(Vec::new()))
        else {
            return Err(CliError::Usage(
                text::msg::ffi_inspection_functions_not_array(),
            ));
        };
        functions.extend(synthetic);
    }
    merge_declared_opaques(&mut doc, crate_name, &attached_opaques)?;
    Ok(doc.to_string())
}

/// Resolve each attached `foreign … kind = Opaque "<Type>"` against the crate's
/// own inspection and merge the survivors into the doc's `declaredOpaques` map
/// (Ipê handle nominal → absolute Rust path).
///
/// Fail-closed at every step, so a handle is minted only over a type the
/// inspector actually reported AND left opaque:
///   - the named type must appear in the inspection's reported `types`;
///   - it must NOT have surfaced transparently (a transparent record/union is a
///     value type, not a handle) — a transparent target is refused;
///   - the resolved Rust path is rendered absolute (`::crate::Type`) so it
///     matches the opaque-path spelling the emitter and the asserted-call
///     validator resolve against.
fn merge_declared_opaques(
    doc: &mut serde_json::Value,
    crate_name: &str,
    opaques: &[&ManifestDefineOpaque],
) -> Result<(), CliError> {
    if opaques.is_empty() {
        return Ok(());
    }
    // The inspection's reported foreign types: `{ name, rustPath, kind }`. A
    // classification error leaves a type opaque, so this reads the RAW reports
    // and treats a transparent classification (via `ForeignTypeCatalog`) as the
    // only disqualifier — everything else the inspector reported stays a handle.
    let types = doc
        .get("types")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let transparent = transparent_type_names(&types);

    let mut declared: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    for o in opaques {
        let reported = types.iter().find(|t| {
            t.get("name").and_then(serde_json::Value::as_str) == Some(o.rust_type.as_str())
        });
        let Some(reported) = reported else {
            return Err(CliError::Usage(text::msg::ffi_opaque_unknown_type(
                &o.ipe_name,
                &o.rust_type,
                &crate_name,
            )));
        };
        if transparent.contains(o.rust_type.as_str()) {
            return Err(CliError::Usage(text::msg::ffi_opaque_is_transparent(
                &o.ipe_name,
                &o.rust_type,
            )));
        }
        let rust_path = reported
            .get("rustPath")
            .and_then(serde_json::Value::as_str)
            .filter(|p| !p.is_empty())
            .ok_or_else(|| {
                CliError::Usage(text::msg::ffi_opaque_without_path(
                    &o.ipe_name,
                    &o.rust_type,
                ))
            })?;
        let absolute = if rust_path.starts_with("::") {
            rust_path.to_owned()
        } else {
            format!("::{rust_path}")
        };
        if let Some(prev) = declared.get(o.ipe_name.as_str())
            && prev.as_str() != Some(absolute.as_str())
        {
            return Err(CliError::Usage(text::msg::ffi_opaque_declared_twice(
                &o.ipe_name,
            )));
        }
        declared.insert(o.ipe_name.clone(), serde_json::Value::String(absolute));
    }
    if let Some(obj) = doc.as_object_mut() {
        obj.insert(
            "declaredOpaques".to_owned(),
            serde_json::Value::Object(declared),
        );
    }
    Ok(())
}

/// The reported-type names the representation classifier surfaces TRANSPARENTLY
/// (a value record or closed union) — the set a `foreign … Opaque` target may
/// not name, since a transparent type is a value, not a handle.
fn transparent_type_names(types: &[serde_json::Value]) -> BTreeSet<String> {
    let doc = serde_json::json!({
        "pkg": "opaque_probe",
        "name": "opaque_probe",
        "version": "0.0.0",
        "errors": [],
        "types": types,
    });
    // A probe decode failure never widens the opaque surface: if the axis cannot
    // be classified, treat nothing as transparent (the inspected-type membership
    // check is the primary gate).
    ipe_ffi::pkginfo::PkgInfo::decode_json(&doc.to_string()).map_or_else(
        |_| BTreeSet::new(),
        |pkg| pkg.foreign_types().transparent().keys().cloned().collect(),
    )
}

/// One `foreign X = { crate = "…", kind = Opaque "<Type>" }` declaration — an
/// OPAQUE Ipê handle minted over a crate type the inspector reports but does not
/// destructure (a `Connection`, `Hasher`, …). No fields, no constructor: the
/// handle is a runtime-owned resource whose value never crosses transparently.
///
/// The declaration DECLARES the nominal so a `.fn` method that takes or returns
/// the handle (`connect : () -> Connection`) resolves against the crate's opaque
/// map without the program importing `Rust.<Crate>`. It is fail-closed: the named
/// type must be an inspected opaque type of the crate (a reported `types` entry
/// that did NOT surface transparently) — an un-inspectable or transparent target
/// is refused at merge, never minted blind.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ManifestDefineOpaque {
    /// The dependency this handle names (empty ⇒ the sole dependency).
    pub(crate) krate: String,
    /// The Ipê-facing handle nominal (the `foreign <Name>` head).
    pub(crate) ipe_name: String,
    /// The inspected crate type's reported name — resolved to its absolute Rust
    /// path against the crate's inspection at merge, then validated opaque.
    pub(crate) rust_type: String,
}

/// A single `foreign` declaration extracted from a `.ipe` source file, ready for
/// lifting into a `ManifestDefine*` value.
///
/// Four shapes, each selected by the record's `kind` field:
///
/// - `Struct` — `{ crate = "…", kind = Struct { field = Carrier }, derives = [ … ] }`
/// - `Enum`   — `{ crate = "…", kind = Enum [ Variant "Name" [ Carrier ] ], derives = [ … ] }`
/// - `Closure`— `{ crate = "…", kind = Closure { args = [ Carrier ], returns = Carrier } }`
/// - `Opaque` — `{ crate = "…", kind = Opaque "<Type>" }`
///
/// The `Struct`/`Enum`/`Closure` shapes DEFINE a nominal in the emitted
/// `_bindings.rs`, byte-identical to what the TOML `[[rust.define.*]]` readers
/// produced; `Opaque` DECLARES a handle over an existing inspected crate type.
#[derive(Debug, PartialEq, Eq)]
enum ForeignDefine {
    Struct(ManifestDefineStruct),
    Enum(ManifestDefineEnum),
    Closure(ManifestDefineClosure),
    Opaque(ManifestDefineOpaque),
}

/// The tuple returned by `scan_foreign_defines`:
/// `(closures, structs, enums, opaques)`.
type ForeignDefines = (
    Vec<ManifestDefineClosure>,
    Vec<ManifestDefineStruct>,
    Vec<ManifestDefineEnum>,
    Vec<ManifestDefineOpaque>,
);

/// Walk every `.ipe` source file reachable from `src_root`, parse each module,
/// and extract its `foreign` declarations, lifting each inert `Foreign` record
/// into a `ManifestDefine*` value through the same record-reading discipline the
/// package-manifest pipeline uses.
///
/// A parse error in any source module is silently skipped here — the compile
/// pipeline will surface it with full context moments later. A malformed
/// `foreign` declaration (invalid carrier, unknown kind, …) is a typed refusal
/// returned as an `Err` with a `CliError::Usage` carrying the source path
/// and reason; the caller decides whether to propagate it immediately or defer.
///
/// The returned vectors are the exact same `ManifestDefine*` shapes the TOML
/// readers produce, so they feed unchanged into `merge_provides`.
pub(crate) fn scan_foreign_defines(src_root: &Path) -> Result<ForeignDefines, CliError> {
    let mut closures = Vec::new();
    let mut structs = Vec::new();
    let mut enums = Vec::new();
    let mut opaques = Vec::new();

    // A missing or unreadable source dir, and any file in it that cannot be
    // read as source, is left to the compiler to report.
    let Ok(Some(src)) = open_project_dir(src_root, &[]) else {
        return Ok((closures, structs, enums, opaques));
    };
    let ipe_files = read_source_tree(src, src_root, IPE_SOURCES, MANIFEST_CAP, Unreadable::Skip)?;

    for (file, text) in &ipe_files {
        // Fast reject: skip files with no `foreign` keyword.
        if !text.contains("foreign") {
            continue;
        }
        let mut interner = ipe_intern::Interner::new();
        let Ok(module) = ipe_parse::parse_module(text, &mut interner) else {
            continue; // compile pipeline surfaces parse errors
        };
        if module.foreigns.is_empty() {
            continue;
        }
        let reader = ForeignReader {
            interner: &interner,
            src: text,
            file,
        };
        for foreign in &module.foreigns {
            match reader.lift_foreign(foreign)? {
                ForeignDefine::Struct(s) => structs.push(s),
                ForeignDefine::Enum(e) => enums.push(e),
                ForeignDefine::Closure(c) => closures.push(c),
                ForeignDefine::Opaque(o) => opaques.push(o),
            }
        }
    }
    Ok((closures, structs, enums, opaques))
}

/// Borrowed context for lifting one `ForeignDecl` into a `ForeignDefine`.
struct ForeignReader<'a> {
    interner: &'a ipe_intern::Interner,
    src: &'a str,
    file: &'a Path,
}

impl ForeignReader<'_> {
    /// Resolve a `Symbol` to its interned text, or `""` on failure.
    fn text(&self, sym: ipe_intern::Symbol) -> &str {
        self.interner.resolve(sym).unwrap_or("")
    }

    /// Emit a typed refusal with a source location prefix.
    fn reject(&self, span: ipe_diagnostics::Span, reason: &str) -> CliError {
        let (line, col) = line_col_from_span(self.src, span.lo);
        CliError::Usage(text::msg::located_refusal(
            &self.file.display(),
            &line,
            &col,
            &reason,
        ))
    }

    /// Lift one `ForeignDecl` into a `ForeignDefine`, refusing with a span if the
    /// declaration body is not a valid inert `Foreign` record.
    ///
    /// The body is a record literal `{ crate = "…", kind = <Kind>, derives = [ … ] }`.
    /// `crate` and `kind` are required; `derives` and `ctor` are optional. The
    /// `kind` field selects the shape — `Struct { … }`, `Enum [ … ]`,
    /// `Closure { … }`, or `Opaque` — and each maps to the same `ManifestDefine*`
    /// value the TOML `[[rust.define.*]]` reader produces, so emitted Rust is
    /// unchanged. No field holds a function or effect: reading the record runs no
    /// author code.
    fn lift_foreign(
        &self,
        foreign: &ipe_diagnostics::Located<ipe_syntax::ForeignDecl>,
    ) -> Result<ForeignDefine, CliError> {
        let decl = &foreign.value;
        let name_text = self.text(decl.name.value).to_owned();

        let fields = self.expect_record(&decl.body)?;

        let mut krate: Option<String> = None;
        let mut kind_expr: Option<&ipe_syntax::Expr> = None;
        let mut derives: Vec<String> = Vec::new();
        let mut ctor: Option<String> = None;
        for (fname_loc, value) in fields {
            match self.text(fname_loc.value) {
                "crate" => krate = Some(self.expect_string(value)?),
                "kind" => kind_expr = Some(value),
                "derives" => derives = self.read_derives(value)?,
                "ctor" => ctor = Some(self.expect_string(value)?),
                other => {
                    return Err(self.reject(
                        fname_loc.span,
                        &format!(
                            "`{other}` is not a `Foreign` field — use `crate`, `kind`, \
                             `derives`, or `ctor`"
                        ),
                    ));
                }
            }
        }

        let krate = krate.ok_or_else(|| {
            self.reject(
                foreign.span,
                "a `foreign` declaration needs a `crate = \"<crate-name>\"` field",
            )
        })?;
        let kind_expr = kind_expr.ok_or_else(|| {
            self.reject(
                foreign.span,
                "a `foreign` declaration needs a `kind = <Struct|Enum|Closure|Opaque>` field",
            )
        })?;

        self.lift_kind(foreign, kind_expr, krate, name_text, derives, ctor)
    }

    /// Decode the `kind` field of a `Foreign` record into a `ForeignDefine`,
    /// carrying the already-read `crate`/`derives`/`ctor` fields.
    fn lift_kind(
        &self,
        foreign: &ipe_diagnostics::Located<ipe_syntax::ForeignDecl>,
        kind_expr: &ipe_syntax::Expr,
        krate: String,
        name: String,
        derives: Vec<String>,
        ctor: Option<String>,
    ) -> Result<ForeignDefine, CliError> {
        let (ctor_name, args) = self.expect_ctor_app(kind_expr, "a `kind`")?;
        match ctor_name {
            "Struct" => self.lift_struct(foreign, args, krate, name, derives, ctor),
            "Enum" => self.lift_enum(foreign, args, krate, name, derives, ctor),
            "Closure" => self.lift_closure(foreign, args, krate, name),
            "Opaque" => self.lift_opaque(foreign, args, krate, name),
            other => Err(self.reject(
                kind_expr.span,
                &format!(
                    "`{other}` is not a `kind` — use `Struct {{ … }}`, `Enum [ … ]`, \
                     `Closure {{ … }}`, or `Opaque \"<Type>\"`."
                ),
            )),
        }
    }

    /// Lift a `kind = Opaque "<Type>"` payload into a `ManifestDefineOpaque`. The
    /// argument is a single string LITERAL naming the inspected crate type; the
    /// fail-closed "must be an inspected opaque type" check happens later at
    /// `merge_provides`, where the crate's inspection is in hand.
    fn lift_opaque(
        &self,
        foreign: &ipe_diagnostics::Located<ipe_syntax::ForeignDecl>,
        args: &[ipe_syntax::Expr],
        krate: String,
        ipe_name: String,
    ) -> Result<ForeignDefine, CliError> {
        let type_arg = args.first().ok_or_else(|| {
            self.reject(
                foreign.span,
                "`Opaque` requires a string type argument `Opaque \"<Type>\"`",
            )
        })?;
        if args.len() > 1 {
            return Err(self.reject(
                type_arg.span,
                "`Opaque` takes exactly one string type argument `Opaque \"<Type>\"`",
            ));
        }
        let rust_type = self.expect_string(type_arg)?;
        if rust_type.is_empty() {
            return Err(self.reject(
                type_arg.span,
                "`Opaque` type name must not be empty — name the crate's reported type",
            ));
        }
        Ok(ForeignDefine::Opaque(ManifestDefineOpaque {
            krate,
            ipe_name,
            rust_type,
        }))
    }

    /// Lift a `kind = Struct { field = Carrier, … }` payload into a
    /// `ManifestDefineStruct`, byte-identical to the TOML path.
    fn lift_struct(
        &self,
        foreign: &ipe_diagnostics::Located<ipe_syntax::ForeignDecl>,
        args: &[ipe_syntax::Expr],
        krate: String,
        struct_name: String,
        derives: Vec<String>,
        ctor: Option<String>,
    ) -> Result<ForeignDefine, CliError> {
        let record_arg = args.first().ok_or_else(|| {
            self.reject(
                foreign.span,
                "`Struct` requires a record argument `{ field = Carrier }`",
            )
        })?;
        let fields = self.read_struct_fields(record_arg)?;
        if fields.is_empty() {
            return Err(self.reject(
                foreign.span,
                "a `foreign` struct declaration must have at least one field",
            ));
        }

        let ctor = ctor.unwrap_or_else(|| format!("{}_new", to_snake_case(&struct_name)));
        Ok(ForeignDefine::Struct(ManifestDefineStruct {
            krate,
            ctor,
            struct_name,
            fields,
            derives,
        }))
    }

    /// Lift a `kind = Enum [ Variant "Name" [ Carrier, … ], … ]` payload into a
    /// `ManifestDefineEnum`, byte-identical to the TOML path.
    fn lift_enum(
        &self,
        foreign: &ipe_diagnostics::Located<ipe_syntax::ForeignDecl>,
        args: &[ipe_syntax::Expr],
        krate: String,
        enum_name: String,
        derives: Vec<String>,
        ctor: Option<String>,
    ) -> Result<ForeignDefine, CliError> {
        let list_arg = args.first().ok_or_else(|| {
            self.reject(
                foreign.span,
                "`Enum` requires a variant list `[ Variant \"Name\" [ … ], … ]`",
            )
        })?;
        let variants = self.read_enum_variants(list_arg)?;
        if variants.is_empty() {
            return Err(self.reject(
                foreign.span,
                "a `foreign` enum declaration must have at least one variant",
            ));
        }

        let ctor = ctor.unwrap_or_else(|| format!("{}_new", to_snake_case(&enum_name)));
        Ok(ForeignDefine::Enum(ManifestDefineEnum {
            krate,
            ctor,
            enum_name,
            variants,
            derives,
        }))
    }

    /// Lift a `kind = Closure { args = [ Carrier, … ], returns = Carrier }`
    /// payload into a `ManifestDefineClosure`, byte-identical to the TOML path.
    ///
    /// The record builds the canonical `Fn(P0, P1, …) -> R + Send + Sync +
    /// 'static` signature string the driver's `ClosureSig::parse` consumes; the
    /// bound set `{Send, Sync, 'static}` is implicit (the only set the sync adapter
    /// supports).
    fn lift_closure(
        &self,
        foreign: &ipe_diagnostics::Located<ipe_syntax::ForeignDecl>,
        args: &[ipe_syntax::Expr],
        krate: String,
        name: String,
    ) -> Result<ForeignDefine, CliError> {
        let record_arg = args.first().ok_or_else(|| {
            self.reject(
                foreign.span,
                "`Closure` requires a record argument `{ args = [ … ], returns = Carrier }`",
            )
        })?;
        let signature = self.read_closure_signature(record_arg)?;
        Ok(ForeignDefine::Closure(ManifestDefineClosure {
            krate,
            name,
            signature,
        }))
    }

    /// Read a `{ args = [ Carrier, … ], returns = Carrier }` record into the
    /// `Fn(P0, …) -> R + Send + Sync + 'static` signature string the driver
    /// decodes via `ClosureSig::parse`.
    ///
    /// Carriers are bare upper-case names: `Int`, `Float`, `Bool`, `Char`,
    /// `String`, `Bytes`, or an opaque handle name. An unknown carrier is
    /// rejected with a span.
    fn read_closure_signature(&self, expr: &ipe_syntax::Expr) -> Result<String, CliError> {
        let fields = self.expect_record(expr)?;
        let mut args_expr: Option<&ipe_syntax::Expr> = None;
        let mut returns_expr: Option<&ipe_syntax::Expr> = None;
        for (fname_loc, value) in fields {
            match self.text(fname_loc.value) {
                "args" => args_expr = Some(value),
                "returns" => returns_expr = Some(value),
                other => {
                    return Err(self.reject(
                        fname_loc.span,
                        &format!("`{other}` is not a `Closure` field — use `args` or `returns`"),
                    ));
                }
            }
        }
        let args_expr = args_expr
            .ok_or_else(|| self.reject(expr.span, "`Closure` requires an `args = [ … ]` field"))?;
        let returns_expr = returns_expr.ok_or_else(|| {
            self.reject(expr.span, "`Closure` requires a `returns = Carrier` field")
        })?;

        let params = self.read_carrier_list(args_expr)?;
        let ret = self.read_carrier_type_from_expr(returns_expr)?;

        let sig = format!(
            "Fn({}) -> {} + Send + Sync + 'static",
            params.join(", "),
            ret
        );
        Ok(sig)
    }

    /// Read a list-literal of carrier names into their canonical spellings.
    fn read_carrier_list(&self, expr: &ipe_syntax::Expr) -> Result<Vec<String>, CliError> {
        use ipe_syntax::Expr_;
        let Expr_::List(items) = &expr.value else {
            return Err(self.reject(expr.span, "expected a list of carriers `[ Int, … ]`"));
        };
        items
            .iter()
            .map(|item| self.read_carrier_type_from_expr(item))
            .collect()
    }

    /// Read a `Struct { field = Carrier, … }` record payload into
    /// `(field-name, carrier-spelling)` pairs, in source order.
    ///
    /// In Ipê expression context, record literals use `=` for field assignment:
    /// `{ value = Int }`. The right-hand side is an upper-case name (a blessed
    /// carrier: `Int`, `String`, `Bool`, `Char`, `Float`, `Bytes`) or an opaque
    /// handle name (any bare upper-case identifier).
    fn read_struct_fields(
        &self,
        expr: &ipe_syntax::Expr,
    ) -> Result<Vec<(String, String)>, CliError> {
        let fields = self.expect_record(expr)?;
        let mut out = Vec::new();
        for (name_loc, val_expr) in fields {
            let field_name = self.text(name_loc.value).to_owned();
            let carrier = self.read_carrier_type_from_expr(val_expr)?;
            out.push((field_name, carrier));
        }
        Ok(out)
    }

    /// Read a carrier spelling from an expression that represents a field value
    /// in a record literal `{ field = Int }`. The parser produces `Int` as
    /// `Expr_::VarLocal("Int")`.
    fn read_carrier_type_from_expr(&self, expr: &ipe_syntax::Expr) -> Result<String, CliError> {
        use ipe_syntax::Expr_;
        match &expr.value {
            // Bare upper-case names: `Int`, `Float`, `Bool`, `Char`, `String`, `Bytes`,
            // or any opaque handle whose name starts with an ASCII upper-case letter.
            Expr_::VarLocal(sym) => {
                let n = self.text(*sym);
                match n {
                    "Int" => Ok("Int".to_owned()),
                    "Float" => Ok("Float".to_owned()),
                    "Bool" => Ok("Bool".to_owned()),
                    "Char" => Ok("Char".to_owned()),
                    "String" => Ok("String".to_owned()),
                    "Bytes" => Ok("Bytes".to_owned()),
                    other if other.chars().next().is_some_and(|c| c.is_ascii_uppercase()) => {
                        // Upper-case bare name → opaque handle.
                        Ok(other.to_owned())
                    }
                    other => Err(self.reject(
                        expr.span,
                        &format!(
                            "`{other}` is not a valid field carrier — use `Int`, `Float`, `Bool`, \
                             `Char`, `String`, `Bytes`, or an upper-case opaque handle name"
                        ),
                    )),
                }
            }
            _ => Err(self.reject(
                expr.span,
                "expected a field carrier (`Int`, `String`, …) as a bare upper-case name",
            )),
        }
    }

    /// Read a `derives = [ Default, Clone, Debug, … ]` list into derive token
    /// strings. Each element is a bare upper-case constructor naming a Rust
    /// derive; the closed allowlist (`ffi_derive_name`) is the single source of
    /// truth, so a misspelt derive is a refusal, never emitted Rust.
    fn read_derives(&self, expr: &ipe_syntax::Expr) -> Result<Vec<String>, CliError> {
        let items = self.expect_list(expr)?;
        let mut out = Vec::new();
        for item in items {
            let name = self.expect_ctor(item, "a derive")?;
            let derive = ffi_derive_name(name).ok_or_else(|| {
                self.reject(
                    item.span,
                    &format!(
                        "`{name}` is not a recognised derive — accepted: \
                         `Default`, `Clone`, `Debug`, `Copy`, `PartialEq`, `Eq`, \
                         `PartialOrd`, `Ord`, `Hash`"
                    ),
                )
            })?;
            out.push(derive.to_owned());
        }
        Ok(out)
    }

    /// Read a `[ Variant "Name" [ Carrier, … ], … ]` list into
    /// `(variant-name, payload-carrier-spellings)` pairs.
    fn read_enum_variants(
        &self,
        expr: &ipe_syntax::Expr,
    ) -> Result<Vec<(String, Vec<String>)>, CliError> {
        let items = self.expect_list(expr)?;
        let mut out = Vec::new();
        for item in items {
            let (ctor, args) = self.expect_ctor_app(item, "a variant")?;
            if ctor != "Variant" {
                return Err(self.reject(
                    item.span,
                    &format!("`{ctor}` is not a variant — use `Variant \"Name\" [ Carrier, … ]`"),
                ));
            }
            let name_arg = args.first().ok_or_else(|| {
                self.reject(item.span, "`Variant` requires a string name argument")
            })?;
            let variant_name = self.expect_string(name_arg)?;
            if variant_name.is_empty()
                || !variant_name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_uppercase())
            {
                return Err(self.reject(
                    item.span,
                    "a variant name must be a non-empty upper-case identifier",
                ));
            }
            let payload = if let Some(payload_arg) = args.get(1) {
                self.read_carrier_list(payload_arg)?
            } else {
                Vec::new()
            };
            out.push((variant_name, payload));
        }
        Ok(out)
    }

    /// Require `expr` to be a record literal `{ … }`, returning its
    /// `(field-name, value)` pairs. Any other shape is rejected — a `foreign`
    /// declaration is inert data, never a computed value.
    fn expect_record<'e>(
        &self,
        expr: &'e ipe_syntax::Expr,
    ) -> Result<
        &'e [(
            ipe_diagnostics::Located<ipe_intern::Symbol>,
            ipe_syntax::Expr,
        )],
        CliError,
    > {
        use ipe_syntax::Expr_;
        match &expr.value {
            Expr_::Record(fields) => Ok(fields.as_slice()),
            _ => Err(self.reject(
                expr.span,
                "expected a record literal `{ … }` — a `foreign` declaration is written as a \
                 record of literals, never computed",
            )),
        }
    }

    /// Require `expr` to be a bare nullary constructor, returning its name.
    /// `what` names the expected kind in the error.
    fn expect_ctor<'e>(&'e self, expr: &ipe_syntax::Expr, what: &str) -> Result<&'e str, CliError> {
        use ipe_syntax::Expr_;
        match &expr.value {
            Expr_::VarLocal(n) | Expr_::VarQual(_, n) => Ok(self.text(*n)),
            _ => Err(self.reject(
                expr.span,
                &format!("expected {what} as a constructor, never a computed value or binding"),
            )),
        }
    }

    /// Require `expr` to be a constructor APPLIED to arguments (`Struct { … }`,
    /// `Variant "…" [ … ]`), returning `(ctor-name, args)`. A bare nullary
    /// constructor yields an empty argument slice.
    fn expect_ctor_app<'e>(
        &'e self,
        expr: &'e ipe_syntax::Expr,
        what: &str,
    ) -> Result<(&'e str, &'e [ipe_syntax::Expr]), CliError> {
        use ipe_syntax::Expr_;
        match &expr.value {
            Expr_::Call(callee, args) => {
                let name = match &callee.value {
                    Expr_::VarLocal(n) | Expr_::VarQual(_, n) => self.text(*n),
                    _ => {
                        return Err(self.reject(
                            callee.span,
                            &format!(
                                "expected {what} as a constructor applied to its argument, never \
                                 a computed function"
                            ),
                        ));
                    }
                };
                Ok((name, args.as_slice()))
            }
            Expr_::VarLocal(n) | Expr_::VarQual(_, n) => Ok((self.text(*n), &[])),
            _ => Err(self.reject(expr.span, &format!("expected {what} as a constructor"))),
        }
    }

    /// Read a list-literal expression, returning its element expressions.
    fn expect_list<'e>(
        &self,
        expr: &'e ipe_syntax::Expr,
    ) -> Result<&'e [ipe_syntax::Expr], CliError> {
        use ipe_syntax::Expr_;
        match &expr.value {
            Expr_::List(items) => Ok(items.as_slice()),
            _ => Err(self.reject(expr.span, "expected a list literal `[ … ]`")),
        }
    }

    /// Read a string-literal expression; reject anything that is not a literal.
    fn expect_string(&self, expr: &ipe_syntax::Expr) -> Result<String, CliError> {
        use ipe_syntax::Expr_;
        match &expr.value {
            Expr_::Str(s) => Ok(s.clone()),
            _ => Err(self.reject(
                expr.span,
                "expected a string literal — a `foreign` declaration field may only be a literal",
            )),
        }
    }
}

/// Map a derive constructor name to the Rust derive token the driver decodes.
/// The constructor spelling and the emitted token coincide; this closed match is
/// the allowlist, so an unrecognised derive is rejected rather than emitted.
fn ffi_derive_name(ctor: &str) -> Option<&'static str> {
    match ctor {
        "Clone" => Some("Clone"),
        "Debug" => Some("Debug"),
        "Default" => Some("Default"),
        "PartialEq" => Some("PartialEq"),
        "Eq" => Some("Eq"),
        "PartialOrd" => Some("PartialOrd"),
        "Ord" => Some("Ord"),
        "Hash" => Some("Hash"),
        "Copy" => Some("Copy"),
        _ => None,
    }
}

/// Compute the 1-based `(line, col)` of a byte offset in `src`. Degrades
/// gracefully to `(1, 1)` on an out-of-range offset — the lift pass stays total.
fn line_col_from_span(src: &str, off: u32) -> (usize, usize) {
    let off = off as usize;
    let mut line = 1usize;
    let mut col = 1usize;
    for (i, ch) in src.char_indices() {
        if i >= off {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

#[cfg(test)]
/// Test-only re-export so `project.rs` tests can verify that the ffi.rs
/// wrapper-header reader uses the same predicate as `is_rust_wrapper_header`.
pub(crate) fn rust_wrapper_header_accepted_by_ffi_reader(line: &str) -> bool {
    crate::project::is_rust_wrapper_header(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seal `emit` against the table `catalog` merges to.
    #[allow(clippy::expect_used)] // every catalog sealed here merges; a refusal is a red test
    fn seal(
        catalog: &[InstalledCrate],
        emit: &ipe_backend_rust::FfiEmit,
    ) -> Result<(), SealRefusal> {
        let merged = merge_catalog_deps(catalog).expect("the sealed catalog merges");
        seal_dependency_references(catalog, &merged, emit)
    }

    /// The backend emission inputs [`assemble_emit`] produces, without the table.
    fn emit_of(
        catalog: &[InstalledCrate],
    ) -> Result<Option<ipe_backend_rust::FfiEmit>, FfiPrepError> {
        assemble_emit(catalog).map(|a| a.map(|a| a.emit))
    }

    #[test]
    fn jail_for_host_tracks_the_compiled_in_run_jail() {
        // The admit hand-off must equal the run-jail's own compiled-in confined
        // set, whatever that set is: this is the single source that stops the
        // admit path claiming a jail the target does not compile in —
        // `jail_for_host` folds EXACTLY `platform_confined_axes()`, so the two
        // cannot drift on any target (full, partial, or empty).
        let mut from_axes = ipe_ffi::capability_scan::CapabilitySet::EMPTY;
        for &axis in ipe_sandbox::run_jail::platform_confined_axes() {
            from_axes = from_axes.with(axis);
        }
        assert_eq!(
            jail_for_host(),
            ipe_ffi::capability_scan::JailForTarget::Holds(from_axes)
        );
        assert_eq!(jail_for_host().confined(), from_axes);

        // A non-empty compiled-in axis list must mean the platform is a jailed
        // target (and vice-versa): a stub host confines nothing. This keeps the
        // predicate and the axis list in lock without assuming the set is FULL —
        // a jailed target may be PARTIAL (Windows).
        if ipe_sandbox::run_jail::platform_supports_jail() {
            assert!(
                !from_axes.is_empty(),
                "a jailed host must confine at least one axis"
            );
        } else {
            assert!(
                from_axes.is_empty(),
                "a stub host must confine no axis (refuse-gap)"
            );
        }
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn jail_for_host_holds_on_linux_x86_64() {
        // Linux/x86_64 confines every runtime-enforced axis → the full set.
        assert_eq!(
            jail_for_host(),
            ipe_ffi::capability_scan::JailForTarget::FULLY_CONFINED
        );
        assert!(jail_for_host().confined().is_full());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn jail_for_host_holds_on_macos() {
        // macOS confines every runtime-enforced axis → the full set.
        assert_eq!(
            jail_for_host(),
            ipe_ffi::capability_scan::JailForTarget::FULLY_CONFINED
        );
        assert!(jail_for_host().confined().is_full());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn jail_for_host_confines_the_partial_windows_set() {
        // Windows is a jailed target with a PARTIAL confined set: the admit path
        // must fold EXACTLY the run-jail's single-sourced axis list — never
        // assume FULL. subprocess + env + filesystem + network + native-ffi are
        // confined by the Job Object + AppContainer + launcher scrub (with
        // filesystem/network fail-closed at runtime off an ACL volume), and
        // database is derived from net + fs.
        let confined = jail_for_host().confined();
        use ipe_ffi::capability_scan::Capability;
        for cap in [
            Capability::Subprocess,
            Capability::Env,
            Capability::Filesystem,
            Capability::Network,
            Capability::NativeFfi,
            Capability::Database,
        ] {
            assert!(confined.confines(cap), "Windows must confine {cap:?}");
        }
        // The fold must equal the run-jail's own list — no drift, no over-claim.
        let mut from_axes = ipe_ffi::capability_scan::CapabilitySet::EMPTY;
        for &axis in ipe_sandbox::run_jail::platform_confined_axes() {
            from_axes = from_axes.with(axis);
        }
        assert_eq!(confined, from_axes);
    }

    #[test]
    fn manifest_rust_dependencies_table_parses_both_spellings() {
        let text = "[project]\nname = \"x\"\n\n[\"rust.dependencies\"]\nsemver = \"1\"\n\n[live]\nport = 1\n";
        assert_eq!(
            rust_dependencies_from_manifest(text),
            vec![ManifestDep {
                name: "semver".to_owned(),
                version: "1".to_owned(),
                features: Vec::new(),
            }]
        );
        let text2 = "[rust.dependencies]\nuuid = \"1.10\"\n";
        assert_eq!(
            rust_dependencies_from_manifest(text2),
            vec![ManifestDep {
                name: "uuid".to_owned(),
                version: "1.10".to_owned(),
                features: Vec::new(),
            }]
        );
    }

    #[test]
    fn manifest_rust_wrapper_table_reads_path_expose_and_capabilities() {
        let text = "[project]\nname = \"app\"\n\n\
                    [rust.wrapper]\n\
                    path = \"wrappers/engine\"\n\
                    expose = [\"make\", \"describe\", \"Engine\"]\n\
                    capabilities = [\"network\"]\n";
        let w = rust_wrapper_from_manifest(text).expect("wrapper table present");
        assert_eq!(w.path, "wrappers/engine");
        assert_eq!(w.expose, ["make", "describe", "Engine"]);
        assert_eq!(w.capabilities, ["network"]);
        // The typed gate accepts it (path is package-jailed, symbols validate)
        // and parses the declared capability into the closed vocabulary.
        let parsed = ipe_ffi::wrapper::WrapperManifest::parse(&w.path, &w.expose, &w.capabilities)
            .expect("typed decode accepts a jailed relative path + valid symbols");
        assert_eq!(parsed.path().as_str(), "wrappers/engine");
        assert!(
            parsed
                .capabilities()
                .contains(&ipe_ffi::capability_scan::Capability::Network)
        );
    }

    #[test]
    fn manifest_without_a_wrapper_table_reports_none() {
        let text = "[rust.dependencies]\nsemver = \"1\"\n";
        assert!(rust_wrapper_from_manifest(text).is_none());
    }

    #[test]
    fn wrapper_cargo_dep_scan_catches_every_dependency_table_form() {
        // The guardian's fail-open case: a target-cfg / triple / workspace dep
        // table must be scanned, or a network dep (`reqwest`) hides there and a
        // Network-capable wrapper installs unconstrained.
        let text = "\
[package]
name = \"w\"

[dependencies]
serde = \"1\"

[build-dependencies]
cc = \"1\"

[target.'cfg(unix)'.dependencies]
reqwest = \"0.12\"

[target.x86_64-unknown-linux-gnu.dependencies]
libc_dep = \"0.2\"

[workspace.dependencies]
tokio = \"1\"

[dependencies.hyper]
version = \"1\"
";
        let deps = parse_cargo_dependency_names(text);
        for expected in ["serde", "cc", "reqwest", "libc_dep", "tokio", "hyper"] {
            assert!(
                deps.iter().any(|d| d == expected),
                "dep `{expected}` must be caught: {deps:?}"
            );
        }
    }

    #[test]
    fn wrapper_cargo_dep_scan_survives_unusual_but_valid_toml() {
        // The forms a hand-rolled line scan under-refuses on — each a real Cargo
        // dependency the structural parse resolves identically. A miss here would
        // admit a Network-capable wrapper unconstrained.
        // Trailing comment on the header.
        let commented = "[dependencies] # a comment\nreqwest = \"0.12\"\n";
        assert!(
            parse_cargo_dependency_names(commented)
                .iter()
                .any(|d| d == "reqwest"),
            "a header with a trailing comment must still be scanned"
        );
        // An inline dependency table under a target-cfg parent.
        let inline = "[target.'cfg(unix)']\ndependencies = { reqwest = \"0.12\" }\n";
        assert!(
            parse_cargo_dependency_names(inline)
                .iter()
                .any(|d| d == "reqwest"),
            "an inline dependencies table must be scanned"
        );
        // A workspace inline dependencies table.
        let ws = "[workspace]\ndependencies = { tokio = \"1\" }\n";
        assert!(
            parse_cargo_dependency_names(ws)
                .iter()
                .any(|d| d == "tokio"),
            "a workspace inline dependencies table must be scanned"
        );
    }

    #[test]
    fn wrapper_cargo_dep_scan_excludes_dev_dependencies() {
        // `dev-dependencies` are test/build-only and never ship, so they are not
        // a runtime capability surface and must NOT force a refuse.
        let text = "[package]\nname = \"w\"\n\n[dev-dependencies]\nproptest = \"1\"\n";
        let deps = parse_cargo_dependency_names(text);
        assert!(
            !deps.iter().any(|d| d == "proptest"),
            "dev-dependencies must not be flagged: {deps:?}"
        );
        // Target-scoped dev-dependencies are likewise excluded.
        let scoped = "[target.'cfg(unix)'.dev-dependencies]\nproptest = \"1\"\n";
        assert!(
            parse_cargo_dependency_names(scoped).is_empty(),
            "target dev-dependencies must not be flagged"
        );
    }

    #[test]
    fn a_pure_wrapper_cargo_toml_has_no_deps() {
        let text = "[package]\nname = \"w\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";
        assert!(parse_cargo_dependency_names(text).is_empty());
    }

    #[test]
    fn a_malformed_cargo_toml_mentioning_dependencies_fails_closed() {
        // An unparseable manifest that names `dependencies` must NOT report an
        // empty set (fail-open); it yields a sentinel so the wrapper is refused.
        let text = "[dependencies\nreqwest = \"0.12\"  # missing closing bracket";
        let deps = parse_cargo_dependency_names(text);
        assert!(
            !deps.is_empty(),
            "a malformed manifest mentioning dependencies must fail closed: {deps:?}"
        );
    }

    #[test]
    fn a_wrapper_path_escape_is_refused_by_the_typed_gate() {
        let text = "[rust.wrapper]\npath = \"../evil\"\nexpose = [\"f\"]\n";
        let w = rust_wrapper_from_manifest(text).expect("table present");
        assert!(
            ipe_ffi::wrapper::WrapperManifest::parse(&w.path, &w.expose, &w.capabilities).is_err(),
            "a `..` escape must be refused at decode"
        );
    }

    #[test]
    fn manifest_rust_dependencies_inline_table_carries_pin_and_features() {
        let text = "[rust.dependencies]\n\
                    async-stripe-checkout = { version = \"=1.0.0-rc.6\", features = [\"checkout_session\"] }\n\
                    firestore = { version = \"0.49\" }\n\
                    plain = \"2\"\n";
        assert_eq!(
            rust_dependencies_from_manifest(text),
            vec![
                ManifestDep {
                    name: "async-stripe-checkout".to_owned(),
                    version: "=1.0.0-rc.6".to_owned(),
                    features: vec!["checkout_session".to_owned()],
                },
                ManifestDep {
                    name: "firestore".to_owned(),
                    version: "0.49".to_owned(),
                    features: Vec::new(),
                },
                ManifestDep {
                    name: "plain".to_owned(),
                    version: "2".to_owned(),
                    features: Vec::new(),
                },
            ]
        );
    }

    #[test]
    fn manifest_chunk_is_a_single_crate_array_with_pin_and_features() {
        let scratch =
            ipe_test_temp::temp_root().join(format!("ipe-chunk-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("mk scratch");
        let spec = CrateSpec::parse("async-stripe-checkout@=1.0.0-rc.6").expect("spec parses");
        let path = write_inspector_manifest_chunk(
            &scratch,
            "populate-0",
            &spec,
            &["checkout_session".to_owned()],
        )
        .expect("chunk write");
        assert_eq!(
            path.file_name().and_then(|f| f.to_str()),
            Some("ipe-install-populate-0.json"),
            "the stage names the file so chunks never clobber each other"
        );
        let body = std::fs::read_to_string(&path).expect("read chunk");
        let val: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let arr = val.as_array().expect("a single-crate array");
        assert_eq!(arr.len(), 1, "one crate per chunk");
        let entry = arr.first().expect("the single crate entry");
        assert_eq!(
            entry.get("name"),
            Some(&serde_json::json!("async-stripe-checkout@=1.0.0-rc.6"))
        );
        assert_eq!(
            entry.get("features"),
            Some(&serde_json::json!(["checkout_session"]))
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn chunk_payload_wires_xc_flags_and_manifest_shell_free() {
        let inspector = Path::new("/opt/ipe/bin/ipe-ffi-inspector");
        let manifest = Path::new("/scratch/ipe-install-populate-1.json");
        let load = Path::new("/scratch/xc-checkpoint.json");
        let save = Path::new("/scratch/xc-checkpoint.json");
        let payload =
            manifest_chunk_payload(inspector, manifest, true, false, Some(load), Some(save));
        let rendered: Vec<String> = payload
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        // The accumulating populate chunk: load prior, save merged, over a
        // single-crate manifest, with build scripts allowed and no fetch flag.
        // The value following each flag is asserted by finding the flag and
        // reading the next token via `.get`, never a raw index.
        let arg_after = |flag: &str| -> Option<&String> {
            rendered
                .iter()
                .position(|s| s == flag)
                .and_then(|at| rendered.get(at + 1))
        };
        assert_eq!(
            rendered.first().map(String::as_str),
            Some("/opt/ipe/bin/ipe-ffi-inspector")
        );
        assert!(rendered.contains(&"--allow-build-scripts".to_owned()));
        assert!(!rendered.contains(&"--fetch-only".to_owned()));
        assert_eq!(
            arg_after("--xc-load").map(String::as_str),
            Some("/scratch/xc-checkpoint.json")
        );
        assert_eq!(
            arg_after("--xc-save").map(String::as_str),
            Some("/scratch/xc-checkpoint.json")
        );
        assert_eq!(
            arg_after("--manifest").map(String::as_str),
            Some("/scratch/ipe-install-populate-1.json")
        );
        // No shell metacharacter smuggled into any token (direct-argv contract).
        assert!(
            rendered
                .iter()
                .all(|t| !t.contains(';') && !t.contains('|'))
        );
    }

    /// `prepare_ffi` with a blame path that has no `.ipe/cache/ffi/rust`
    /// directory up-tree returns an empty `FfiPrep` (no crates installed).
    /// This is the common case for every project that has never run `ipe add`.
    #[test]
    fn prepare_ffi_no_cache_returns_empty_prep() {
        let tmp = ipe_test_temp::temp_root();
        let mut sources: BTreeMap<Vec<String>, (std::path::PathBuf, String)> = BTreeMap::new();
        let prep = super::prepare_ffi(&mut sources, &tmp.join("Main.ipe"))
            .expect("prepare_ffi on a no-cache path must not error");
        assert!(prep.catalog.is_empty(), "no crates should be loaded");
        assert!(prep.injected.is_empty(), "no modules should be injected");
        assert!(prep.emit.is_none(), "emit should be None with no crates");
    }

    #[test]
    fn cache_root_walk_stops_at_the_ipe_toml_project_root() {
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-t1-cacheroot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        // Ancestor cache (a planted vector) ABOVE the project root.
        let ancestor_cache = tmp.join(CACHE_REL);
        std::fs::create_dir_all(&ancestor_cache).expect("mk ancestor cache");
        // The project root, with its own package.ipe, one level down; no cache.
        let project = tmp.join("proj");
        std::fs::create_dir_all(&project).expect("mk project");
        std::fs::write(
            project.join("package.ipe"),
            "module Package exposing (package)\n",
        )
        .expect("write manifest");
        let src = project.join("src");
        std::fs::create_dir_all(&src).expect("mk src");
        // Discovery from inside the project must NOT climb past package.ipe to the
        // planted ancestor cache — it returns None.
        let found = find_cache_root(&src).expect("no error");
        assert!(found.is_none(), "must not discover the ancestor cache");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[cfg(unix)]
    #[test]
    fn owned_project_cache_is_discovered() {
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-t1-owncache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let cache = tmp.join(CACHE_REL);
        std::fs::create_dir_all(&cache).expect("mk cache");
        std::fs::write(
            tmp.join("package.ipe"),
            "module Package exposing (package)\n",
        )
        .expect("manifest");
        // The invoker owns a freshly-created dir, so it is trusted + found.
        let found = find_cache_root(&tmp).expect("no error");
        assert_eq!(
            found.as_ref().map(TrustedCache::path),
            Some(cache.as_path())
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// On a host with no portable owner check, even a freshly-created, invoker-owned cache is
    /// refused — the fail-closed twin of `owned_project_cache_is_discovered`.
    #[cfg(not(unix))]
    #[test]
    fn owned_project_cache_is_refused_when_unverifiable() {
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-t1-owncache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let cache = tmp.join(CACHE_REL);
        std::fs::create_dir_all(&cache).expect("mk cache");
        std::fs::write(
            tmp.join("package.ipe"),
            "module Package exposing (package)\n",
        )
        .expect("manifest");
        let result = find_cache_root(&tmp);
        assert!(
            matches!(
                &result,
                Err(CliError::TrustRefused(owner_trust::TrustRefusal::FfiCacheUnverifiable(p)))
                    if *p == cache
            ),
            "{result:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_cache_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = ipe_test_temp::temp_root().join(format!("ipe-t1-wwcache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let cache = tmp.join(CACHE_REL);
        std::fs::create_dir_all(&cache).expect("mk cache");
        std::fs::write(
            tmp.join("package.ipe"),
            "module Package exposing (package)\n",
        )
        .expect("manifest");
        // Make the cache world-writable — the delivery vector for a planted
        // _bindings.rs — and confirm discovery refuses it.
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let r = find_cache_root(&tmp);
        assert!(
            matches!(
                &r,
                Err(CliError::TrustRefused(owner_trust::TrustRefusal::FfiCacheUntrusted(p)))
                    if *p == cache
            ),
            "{r:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn scratch_dir_is_under_the_cache_root_and_fails_on_a_pre_existing_path() {
        // HOME must be set for the sanctioned path; the test crate always has
        // one. The scratch dir lives under ~/.cache/ipe/ffi-scratch/, never
        // /tmp.
        let Ok(home) = crate::env_dir::home() else {
            return;
        };
        let scratch = make_scratch_dir("semver").expect("first create succeeds");
        assert!(
            scratch.starts_with(home.join(".cache/ipe/ffi-scratch")),
            "scratch under the write-boundary root: {}",
            scratch.display()
        );
        assert!(scratch.is_dir());
        // A second `create_dir` on the SAME path fails (planted-dir race
        // rejection). `make_scratch_dir` uses a fresh name each call, so we
        // assert the primitive directly on the returned path.
        assert!(
            std::fs::create_dir(&scratch).is_err(),
            "re-creating an existing scratch path must fail"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// A fresh scratch root per test, so parallel tests never share homes.
    fn toolbinds_root(tag: &str) -> PathBuf {
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-toolbinds-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("mk scratch root");
        tmp
    }

    /// A cargo home at `cargo_home` holding `bin/` and `credentials.toml`.
    fn plant_cargo_home(cargo_home: &Path) {
        std::fs::create_dir_all(cargo_home.join("bin")).expect("mk cargo bin");
        std::fs::write(cargo_home.join("credentials.toml"), "").expect("credentials");
    }

    /// An inspector binary planted in `dir`.
    fn plant_inspector(dir: &Path) -> PathBuf {
        std::fs::create_dir_all(dir).expect("mk inspector dir");
        let inspector = dir.join("ipe-ffi-inspector");
        std::fs::write(&inspector, "").expect("inspector");
        inspector
    }

    /// A user home planted under `tmp`.
    fn plant_user_home(tmp: &Path) -> crate::env_dir::HomeDir {
        let user_home = tmp.join("user");
        std::fs::create_dir_all(&user_home).expect("mk user home");
        crate::env_dir::HomeDir::try_parse(Some(user_home.into_os_string()))
            .expect("an absolute test home")
    }

    /// A tool home over the absolute test path `path`, spelled as given.
    fn tool(path: &Path) -> crate::env_dir::ToolHome {
        ipe_sandbox::home::tool_home_from("CARGO_HOME", Some(path.into()), None, ".cargo")
            .expect("an absolute test tool home")
            .expect("a set tool home")
    }

    fn canonical(path: &Path) -> ipe_sandbox::CanonicalPath {
        ipe_sandbox::CanonicalPath::resolve(path).expect("resolves")
    }

    #[test]
    fn toolchain_binds_over_disjoint_homes_expose_only_cargo_bin() {
        let tmp = toolbinds_root("disjoint");
        let cargo_home = tmp.join(".cargo");
        let rustup_home = tmp.join(".rustup");
        plant_cargo_home(&cargo_home);
        std::fs::create_dir_all(&rustup_home).expect("mk rustup home");
        let inspector = plant_inspector(&tmp.join("tools"));
        let user_home = plant_user_home(&tmp);
        let got = toolchain_binds_from(
            &inspector,
            Some(&tool(&cargo_home)),
            Some(tool(&rustup_home)),
            Ok(&user_home),
        );
        let want_homes = ipe_sandbox::HomeMasks::resolve(Ok(&user_home), Some(&tool(&cargo_home)))
            .expect("homes resolve");
        let want_inspector = canonical(&inspector);
        let cargo_bin = canonical(&cargo_home.join("bin"));
        let rustup_home = canonical(&rustup_home);
        let cargo_home = canonical(&cargo_home);
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(got.is_ok(), "disjoint homes must be accepted: {got:?}");
        let Ok(ToolchainBinds {
            inspector,
            ro_binds: binds,
            path_prepend: path,
            rustup_home: rustup,
            homes,
        }) = got
        else {
            return;
        };
        assert_eq!(homes, want_homes);
        assert_eq!(inspector, want_inspector);
        assert!(binds.contains(&cargo_bin), "{binds:?}");
        assert!(!binds.contains(&cargo_home), "{binds:?}");
        assert!(
            binds
                .iter()
                .all(|b| !ipe_sandbox::path_covers(b.as_path(), cargo_home.as_path())),
            "no bind may contain the cargo home: {binds:?}"
        );
        assert_eq!(path, vec![cargo_bin]);
        assert_eq!(rustup, Some(rustup_home));
    }

    /// `toolchain_binds_from` over `(cargo_home, rustup_home)` must refuse.
    fn assert_toolchain_refused(cargo_home: &Path, rustup_home: &Path, inspector: &Path) {
        let got = toolchain_binds_from(
            inspector,
            Some(&tool(cargo_home)),
            Some(tool(rustup_home)),
            Err(crate::env_dir::HomeRefusal::Unset),
        );
        assert!(
            matches!(&got, Err(CliError::Usage(m)) if m.contains("credentials.toml")),
            "a bind exposing the cargo home must be refused: {got:?}"
        );
    }

    #[test]
    fn toolchain_binds_refuse_a_rustup_home_equal_to_the_cargo_home() {
        let tmp = toolbinds_root("equal");
        let home = tmp.join("toolchain");
        plant_cargo_home(&home);
        let inspector = plant_inspector(&tmp.join("tools"));
        assert_toolchain_refused(&home, &home, &inspector);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn toolchain_binds_refuse_a_cargo_home_nested_under_the_rustup_home() {
        let tmp = toolbinds_root("nested");
        let rustup_home = tmp.join("rustup");
        let cargo_home = rustup_home.join("cargo");
        plant_cargo_home(&cargo_home);
        let inspector = plant_inspector(&tmp.join("tools"));
        assert_toolchain_refused(&cargo_home, &rustup_home, &inspector);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn toolchain_binds_refuse_a_dot_dot_or_trailing_slash_spelled_ancestor() {
        let tmp = toolbinds_root("dotdot");
        let cargo_home = tmp.join(".cargo");
        let rustup_dir = tmp.join(".rustup");
        plant_cargo_home(&cargo_home);
        std::fs::create_dir_all(&rustup_dir).expect("mk rustup home");
        let inspector = plant_inspector(&tmp.join("tools"));
        // `<tmp>/.rustup/..` names `<tmp>`, the cargo home's parent.
        assert_toolchain_refused(&cargo_home, &rustup_dir.join(".."), &inspector);
        // `<tmp>/.cargo/bin/../` names the cargo home itself.
        let mut spelled = cargo_home.join("bin").join("..").into_os_string();
        spelled.push("/");
        assert_toolchain_refused(&cargo_home, &PathBuf::from(spelled), &inspector);
        // The cargo home spelled with `..` against a plain rustup home above it.
        assert_toolchain_refused(&rustup_dir.join("..").join(".cargo"), &tmp, &inspector);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[cfg(unix)]
    #[test]
    fn toolchain_binds_refuse_a_rustup_home_symlinked_to_the_cargo_home() {
        let tmp = toolbinds_root("symlink");
        let cargo_home = tmp.join(".cargo");
        plant_cargo_home(&cargo_home);
        let link = tmp.join("rustup-link");
        std::os::unix::fs::symlink(&cargo_home, &link).expect("symlink");
        let inspector = plant_inspector(&tmp.join("tools"));
        assert_toolchain_refused(&cargo_home, &link, &inspector);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn toolchain_binds_refuse_an_inspector_dir_above_the_cargo_home() {
        let tmp = toolbinds_root("inspector");
        let cargo_home = tmp.join(".cargo");
        let rustup_home = tmp.join("elsewhere").join(".rustup");
        plant_cargo_home(&cargo_home);
        std::fs::create_dir_all(&rustup_home).expect("mk rustup home");
        let inspector = plant_inspector(&tmp);
        assert_toolchain_refused(&cargo_home, &rustup_home, &inspector);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_cargo_home_holding_the_rustup_home_is_accepted() {
        let tmp = toolbinds_root("rustup-inside");
        let cargo_home = tmp.join(".cargo");
        let rustup_home = cargo_home.join("rustup");
        plant_cargo_home(&cargo_home);
        std::fs::create_dir_all(&rustup_home).expect("mk rustup home");
        let inspector = plant_inspector(&tmp.join("tools"));
        let user_home = plant_user_home(&tmp);
        let got = toolchain_binds_from(
            &inspector,
            Some(&tool(&cargo_home)),
            Some(tool(&rustup_home)),
            Ok(&user_home),
        );
        let cargo_home = canonical(&cargo_home);
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(
            matches!(&got, Ok(binds) if !binds.ro_binds.contains(&cargo_home)),
            "a rustup home below the cargo home does not expose it: {got:?}"
        );
    }

    #[test]
    fn toolchain_binds_refuse_an_unknown_cargo_home() {
        let got = toolchain_binds_from(
            Path::new("/opt/ipe/bin/ipe-ffi-inspector"),
            None,
            None,
            Err(crate::env_dir::HomeRefusal::Unset),
        );
        assert!(
            matches!(&got, Err(CliError::Usage(m)) if m.contains("cannot locate the cargo home")),
            "no cargo home means no exposure check, so the jail must be refused: {got:?}"
        );
    }

    #[test]
    fn toolchain_binds_mask_the_user_and_cargo_homes() {
        let tmp = toolbinds_root("homes");
        let user_home = plant_user_home(&tmp);
        let cargo_home = tmp.join("elsewhere").join(".cargo");
        plant_cargo_home(&cargo_home);
        let inspector = plant_inspector(&tmp.join("tools"));
        let got = toolchain_binds_from(&inspector, Some(&tool(&cargo_home)), None, Ok(&user_home));
        let want = ipe_sandbox::HomeMasks::resolve(Ok(&user_home), Some(&tool(&cargo_home)))
            .expect("homes resolve");
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(
            matches!(&got, Ok(binds) if binds.homes == want),
            "both homes must be masked: {got:?}"
        );
    }

    #[test]
    fn toolchain_binds_refuse_an_unset_user_home() {
        use crate::env_dir::HomeRefusal;
        let tmp = toolbinds_root("no-user-home");
        let cargo_home = tmp.join(".cargo");
        plant_cargo_home(&cargo_home);
        let inspector = plant_inspector(&tmp.join("tools"));
        let refusals = [
            HomeRefusal::Unset,
            HomeRefusal::NotUtf8,
            HomeRefusal::ContainsNul,
            HomeRefusal::NotAbsolute,
            HomeRefusal::ParentComponent,
            HomeRefusal::WindowsDeviceOrVerbatim,
            HomeRefusal::WindowsUnc,
        ];
        let walks: Vec<_> = refusals
            .iter()
            .map(|refusal| {
                let got =
                    toolchain_binds_from(&inspector, Some(&tool(&cargo_home)), None, Err(*refusal));
                (*refusal, got)
            })
            .collect();
        let _ = std::fs::remove_dir_all(&tmp);
        for (refusal, got) in walks {
            assert!(
                matches!(&got, Err(CliError::Usage(m))
                    if m.contains("cannot be masked") && m.contains(&refusal.to_string())),
                "a refused user home cannot be masked, so the jail must be refused: {got:?}"
            );
        }
    }

    #[test]
    fn toolchain_binds_refuse_an_inspector_that_does_not_resolve() {
        let tmp = toolbinds_root("no-inspector");
        let cargo_home = tmp.join(".cargo");
        plant_cargo_home(&cargo_home);
        let user_home = plant_user_home(&tmp);
        let got = toolchain_binds_from(
            &tmp.join("missing").join("ipe-ffi-inspector"),
            Some(&tool(&cargo_home)),
            None,
            Ok(&user_home),
        );
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(
            matches!(&got, Err(CliError::Usage(m)) if m.contains("does not resolve")),
            "an inspector path that does not resolve cannot be bound: {got:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_inspector_is_run_and_bound_at_its_canonical_path() {
        let tmp = toolbinds_root("inspector-link");
        let cargo_home = tmp.join(".cargo");
        plant_cargo_home(&cargo_home);
        let user_home = plant_user_home(&tmp);
        let real = plant_inspector(&tmp.join("real"));
        let link_dir = tmp.join("link");
        std::os::unix::fs::symlink(tmp.join("real"), &link_dir).expect("symlink");
        let got = toolchain_binds_from(
            &link_dir.join("ipe-ffi-inspector"),
            Some(&tool(&cargo_home)),
            None,
            Ok(&user_home),
        );
        let real_dir = canonical(&tmp.join("real"));
        let real = canonical(&real);
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(
            matches!(&got, Ok(binds)
                if binds.inspector == real
                    && binds.ro_binds.contains(&real_dir)
                    && binds.ro_binds.iter().all(|b| !b.as_path().starts_with(&link_dir))),
            "the payload's inspector and its bound dir must be the canonical target: {got:?}"
        );
    }

    #[test]
    fn conflicting_dep_pins_are_refused() {
        let mk = |slug: &str, line: &str| InstalledCrate {
            slug: slug.to_owned(),
            module_name: format!("Rust.{slug}"),
            kernel_name: format!("Rust_{slug}"),
            interface_source: String::new(),
            bindings_source: String::new(),
            opaque_types: BTreeMap::new(),
            opaque_type_ids: BTreeMap::new(),
            define_types: BTreeSet::new(),
            transparent_types: BTreeMap::new(),
            bindings: Vec::new(),
            dep_versions: BTreeMap::new(),
            inspected_free_fns: BTreeMap::new(),
            inspected_consts: BTreeMap::new(),
            cargo_deps: vec![CargoDep::parse_registry_line(line).expect("registry line")],
            wrapper_idents: BTreeSet::new(),
            package_name: None,
            dep_idents: BTreeMap::new(),
        };
        // Two crates agreeing on a shared dep line dedupe to one.
        let ok = emit_of(&[mk("a", "serde = \"=1.0.1\""), mk("b", "serde = \"=1.0.1\"")]);
        assert!(ok.is_ok_and(|e| e.is_some_and(|e| e.dep_lines == vec!["serde = \"=1.0.1\""])));
        // A VERSION disagreement between legacy members (no typed package name, so
        // no proof the dep is transitive) is refused fail-closed. (A typed
        // transitive-dep conflict instead defers to Cargo — see
        // `transitive_version_conflict_defers_to_cargo`.)
        let clash = emit_of(&[
            mk("serde", "serde = \"=1.0.1\""),
            mk("other", "serde = \"=1.0.2\""),
        ]);
        assert!(
            refused_as(
                &clash,
                &FfiPrepError::DependencyMerge(MergeRefusal::PinConflict {
                    name: "serde".to_owned(),
                    first: "1.0.1".to_owned(),
                    second: "1.0.2".to_owned(),
                })
            ),
            "{clash:?}"
        );
    }

    #[test]
    fn same_version_different_features_unify() {
        // The stripe-manifest shape: `async-stripe-shared` pinned bare by one crate
        // (as a transitive dep) and with features by another (its own self-line).
        // Same version → Cargo-style feature union, NOT a conflict.
        let mk = |slug: &str, line: &str| InstalledCrate {
            slug: slug.to_owned(),
            module_name: format!("Rust.{slug}"),
            kernel_name: format!("Rust_{slug}"),
            interface_source: String::new(),
            bindings_source: String::new(),
            opaque_types: BTreeMap::new(),
            opaque_type_ids: BTreeMap::new(),
            define_types: BTreeSet::new(),
            transparent_types: BTreeMap::new(),
            bindings: Vec::new(),
            dep_versions: BTreeMap::new(),
            inspected_free_fns: BTreeMap::new(),
            inspected_consts: BTreeMap::new(),
            cargo_deps: vec![CargoDep::parse_registry_line(line).expect("registry line")],
            wrapper_idents: BTreeSet::new(),
            package_name: None,
            dep_idents: BTreeMap::new(),
        };
        let e = emit_of(&[
            mk("a", "async-stripe-shared = \"=1.0.0-rc.6\""),
            mk(
                "b",
                "async-stripe-shared = { version = \"=1.0.0-rc.6\", features = [\"serialize\", \"deserialize\"] }",
            ),
        ])
        .expect("union must not error")
        .expect("emit present");
        assert_eq!(
            e.dep_lines,
            vec![
                "async-stripe-shared = { version = \"=1.0.0-rc.6\", features = [\"deserialize\", \"serialize\"] }"
                    .to_owned()
            ],
            "features union into one line at the shared version"
        );
    }

    #[test]
    fn transitive_version_conflict_defers_to_cargo() {
        // A TRANSITIVE dep (`syn`, not a catalog crate) pinned to two majors by two
        // members — each inspected in its own jail — must NOT refuse the build and must
        // NOT be exact-pinned to one arbitrary version. It is dropped so Cargo resolves
        // the transitive graph of the direct pins itself.
        let mk = |slug: &str, lines: Vec<&str>| typed_crate(slug, slug, &lines);
        let e = emit_of(&[
            mk("a", vec!["a = \"=1.0.0\"", "syn = \"=2.0.119\""]),
            mk("b", vec!["b = \"=1.0.0\"", "syn = \"=3.0.0\""]),
        ])
        .expect("transitive conflict must not error")
        .expect("emit present");
        assert!(
            e.dep_lines.iter().all(|l| !l.starts_with("syn =")),
            "the conflicting transitive `syn` is dropped, not pinned: {:?}",
            e.dep_lines
        );
        assert!(
            e.dep_lines.contains(&"a = \"=1.0.0\"".to_owned())
                && e.dep_lines.contains(&"b = \"=1.0.0\"".to_owned()),
            "the direct crates stay pinned: {:?}",
            e.dep_lines
        );
        // A DIRECT crate version conflict is still a hard error.
        let clash = emit_of(&[
            mk("stripe", vec!["stripe = \"=1.0.0\""]),
            mk("other", vec!["stripe = \"=2.0.0\""]),
        ]);
        assert!(
            refused_as(
                &clash,
                &FfiPrepError::DependencyMerge(MergeRefusal::PinConflict {
                    name: "stripe".to_owned(),
                    first: "1.0.0".to_owned(),
                    second: "2.0.0".to_owned(),
                })
            ),
            "a direct-crate version conflict still refuses: {clash:?}"
        );
    }

    /// Whether `result` is exactly the refusal `want`.
    fn refused_as(
        result: &Result<Option<ipe_backend_rust::FfiEmit>, FfiPrepError>,
        want: &FfiPrepError,
    ) -> bool {
        result.as_ref().err() == Some(want)
    }

    /// The `syn` 2.x / 3.x pin conflict between the two [`syn_split`] members.
    fn syn_pin_conflict() -> FfiPrepError {
        FfiPrepError::DependencyMerge(MergeRefusal::PinConflict {
            name: "syn".to_owned(),
            first: "2.0.119".to_owned(),
            second: "3.0.0".to_owned(),
        })
    }

    /// The seal refusal for a `syn` reference at `site` once `syn` is dropped.
    fn syn_dropped_at(site: &str) -> SealRefusal {
        SealRefusal::DroppedTransitive {
            package: "syn".to_owned(),
            ident: "syn".to_owned(),
            site: site.to_owned(),
        }
    }

    /// The catalog seal refusal for a `syn` reference at `site`.
    fn catalog_dropped_at(site: &str) -> FfiPrepError {
        FfiPrepError::CatalogSeal(syn_dropped_at(site))
    }

    /// A typed (inspection-built) member: package `package`, lib slug `slug`,
    /// and one `dep_idents` entry per dependency line (`-` → `_`).
    fn typed_crate(slug: &str, package: &str, lines: &[&str]) -> InstalledCrate {
        let mut c = crate_with_types(slug, &[], &[]);
        c.cargo_deps = lines
            .iter()
            .map(|l| CargoDep::parse_registry_line(l).expect("registry line"))
            .collect();
        c.package_name = ipe_ffi::pkginfo::PackageName::parse(package).ok();
        c.dep_idents = c
            .cargo_deps
            .iter()
            .filter_map(|dep| {
                let name = dep.name().as_str();
                ipe_ffi::naming::RustIdent::parse(&name.replace('-', "_"))
                    .ok()
                    .map(|ident| (name.to_owned(), ident))
            })
            .collect();
        c
    }

    /// Two typed members whose `syn` pins span majors, so `syn` is dropped.
    fn syn_split() -> [InstalledCrate; 2] {
        [
            typed_crate("a", "a", &["a = \"=1.0.0\"", "syn = \"=2.0.119\""]),
            typed_crate("b", "b", &["b = \"=1.0.0\"", "syn = \"=3.0.0\""]),
        ]
    }

    #[test]
    fn a_dropped_transitive_named_by_the_bindings_is_refused() {
        let [a, mut b] = syn_split();
        b.bindings_source = "pub fn span() -> ::syn::Ident { ::syn::parse_str(\"x\") }".to_owned();
        let refused = emit_of(&[a, b]);
        assert!(
            refused_as(&refused, &catalog_dropped_at("src/ffi.rs")),
            "a `::syn::` path with `syn` undeclared must refuse: {refused:?}"
        );
    }

    #[test]
    fn a_dropped_transitive_named_by_an_opaque_path_is_refused() {
        let [mut a, b] = syn_split();
        a.opaque_types
            .insert("Ident".to_owned(), "::syn::Ident".to_owned());
        let refused = emit_of(&[a, b]);
        assert!(
            refused_as(&refused, &catalog_dropped_at("Rust.a.Ident")),
            "an opaque path rooted at undeclared `syn` must refuse: {refused:?}"
        );
    }

    #[test]
    fn the_seal_refuses_a_dropped_root_and_spares_a_declared_one() {
        let [a, b] = syn_split();
        let catalog = [a, b];
        let mut emit =
            emit_of(&catalog)
                .ok()
                .flatten()
                .unwrap_or_else(|| ipe_backend_rust::FfiEmit {
                    foreign_types: BTreeMap::new(),
                    dep_lines: Vec::new(),
                    bindings_source: String::new(),
                    interface_modules: Vec::new(),
                    wrapper_glue: BTreeMap::new(),
                });
        assert!(seal(&catalog, &emit).is_ok());
        // A shim appended after assembly naming a declared root stays sound.
        emit.bindings_source
            .push_str("\npub fn f() -> ::a::T { ::b::g() }");
        assert!(seal(&catalog, &emit).is_ok());
        // One naming the dropped root is refused with the typed reason.
        emit.bindings_source
            .push_str("\npub fn h() -> syn::Ident { todo() }");
        assert_eq!(
            seal(&catalog, &emit),
            Err(SealRefusal::DroppedTransitive {
                package: "syn".to_owned(),
                ident: "syn".to_owned(),
                site: "src/ffi.rs".to_owned(),
            })
        );
    }

    #[test]
    fn a_renamed_lib_direct_crate_conflict_is_refused() {
        // Package `async-stripe` exposes lib `stripe`: the direct set is built from
        // the typed package name, so the `async-stripe` clash is caught as direct.
        let refused = emit_of(&[
            typed_crate("stripe", "async-stripe", &["async-stripe = \"=1.0.0\""]),
            typed_crate(
                "other",
                "other",
                &["other = \"=1.0.0\"", "async-stripe = \"=2.0.0\""],
            ),
        ]);
        assert!(
            refused_as(
                &refused,
                &FfiPrepError::DependencyMerge(MergeRefusal::PinConflict {
                    name: "async-stripe".to_owned(),
                    first: "1.0.0".to_owned(),
                    second: "2.0.0".to_owned(),
                })
            ),
            "a direct-crate conflict must refuse even when its lib ident differs: {refused:?}"
        );
    }

    #[test]
    fn an_underscore_named_direct_crate_conflict_is_refused() {
        // The direct set and the dependency keys compare one typed package-name
        // spelling, so `foo_bar` is direct on both sides and never deferred.
        let refused = emit_of(&[
            typed_crate("foo_bar", "foo_bar", &["foo_bar = \"=1.0.0\""]),
            typed_crate(
                "other",
                "other",
                &["other = \"=1.0.0\"", "foo_bar = \"=2.0.0\""],
            ),
        ]);
        assert!(
            refused_as(
                &refused,
                &FfiPrepError::DependencyMerge(MergeRefusal::PinConflict {
                    name: "foo_bar".to_owned(),
                    first: "1.0.0".to_owned(),
                    second: "2.0.0".to_owned(),
                })
            ),
            "a direct crate named with `_` must refuse its conflict: {refused:?}"
        );
    }

    #[test]
    fn a_legacy_member_transitive_conflict_is_refused() {
        // Without a typed package name no member can prove `syn` is transitive.
        let [a, mut b] = syn_split();
        b.package_name = None;
        b.dep_idents = BTreeMap::new();
        let refused = emit_of(&[a, b]);
        assert!(
            refused_as(&refused, &syn_pin_conflict()),
            "a conflict involving a legacy member must fail closed: {refused:?}"
        );
    }

    #[test]
    fn a_transitive_conflict_without_a_known_ident_is_refused() {
        // A dropped dep whose lib ident is unknown cannot be checked against
        // emitted paths, so it is refused rather than dropped.
        let [mut a, mut b] = syn_split();
        a.dep_idents.remove("syn");
        b.dep_idents.remove("syn");
        let refused = emit_of(&[a, b]);
        assert!(
            refused_as(&refused, &syn_pin_conflict()),
            "an unidentifiable dropped dep must fail closed: {refused:?}"
        );
    }

    #[test]
    fn a_same_major_transitive_conflict_is_dropped_not_pinned() {
        // No single pin is provably acceptable to every intermediate crate's
        // requirement, so even a same-major disagreement leaves the choice to
        // Cargo and the seal guards every emitted reference.
        let e = emit_of(&[
            typed_crate("a", "a", &["a = \"=1.0.0\"", "syn = \"=2.0.1\""]),
            typed_crate(
                "b",
                "b",
                &[
                    "b = \"=1.0.0\"",
                    "syn = { version = \"=2.0.119\", features = [\"full\"] }",
                ],
            ),
        ]);
        assert!(
            e.as_ref().is_ok_and(|e| e
                .as_ref()
                .is_some_and(|e| e.dep_lines.iter().all(|l| !l.starts_with("syn")))),
            "a same-major transitive disagreement is dropped: {e:?}"
        );
        let [mut a, b] = [
            typed_crate("a", "a", &["a = \"=1.0.0\"", "syn = \"=2.0.1\""]),
            typed_crate("b", "b", &["b = \"=1.0.0\"", "syn = \"=2.0.119\""]),
        ];
        a.bindings_source = "pub fn f() -> ::syn::Ident { g() }".to_owned();
        let refused = emit_of(&[a, b]);
        assert!(
            refused_as(&refused, &catalog_dropped_at("src/ffi.rs")),
            "a reference to the dropped same-major dep is refused: {refused:?}"
        );
    }

    #[test]
    fn a_dropped_transitive_named_by_a_glue_path_is_refused() {
        let [a, b] = syn_split();
        let catalog = [a, b];
        let mut emit = emit_of(&catalog)
            .expect("no emitted text names `syn` yet")
            .expect("emit present");
        emit.wrapper_glue.insert(
            "ipe_a_span".to_owned(),
            ipe_backend_rust::FfiWrapperGlue {
                params: vec![Some(ipe_backend_rust::FfiGlueType::Record {
                    rust_path: "::syn::Ident".to_owned(),
                    fields: Vec::new(),
                })],
                result: None,
            },
        );
        assert_eq!(seal(&catalog, &emit), Err(syn_dropped_at("ipe_a_span")));
    }

    #[test]
    fn an_asserted_shim_naming_a_dropped_transitive_is_refused() {
        let [a, b] = syn_split();
        let catalog = [a, b];
        let assembled = || {
            assemble_emit(&catalog)
                .ok()
                .flatten()
                .ok_or("no emitted text names `syn` yet")
        };
        let spec = |path: &str| ipe_ffi::asserted::ConstSpec {
            path: ipe_canon::asserted::AssertedPath::parse(path).expect("valid path"),
            scalar: ipe_ffi::carrier::ScalarCarrier::Int,
            def_name: "limit".to_owned(),
            wrapper_ident: "ipe_asserted_const_limit".to_owned(),
        };
        // A shim rooted at a declared crate passes the second seal.
        let sound = assembled().and_then(|mut a| {
            append_asserted_shims(&catalog, &mut a, &[], &[spec("a::LIMIT")])
                .map_err(|_| "a declared root refused")
        });
        assert_eq!(sound, Ok(()));
        let dropped = assembled()
            .map(|mut a| append_asserted_shims(&catalog, &mut a, &[], &[spec("syn::LIMIT")]));
        assert_eq!(
            dropped,
            Ok(Err(FfiPrepError::AssertedShimSeal(syn_dropped_at(
                "src/ffi.rs"
            ))))
        );
    }

    #[test]
    fn a_dropped_ident_a_declared_package_answers_to_is_spared() {
        // `syn-compat` is declared and its lib is `syn`, so `::syn::` still
        // resolves after the conflicting `syn` package is dropped.
        let [a, mut b] = syn_split();
        let mut c = typed_crate("c", "c", &["c = \"=1.0.0\"", "syn-compat = \"=1.0.0\""]);
        c.dep_idents.insert(
            "syn-compat".to_owned(),
            ipe_ffi::naming::RustIdent::parse("syn").expect("valid ident"),
        );
        b.bindings_source = "pub fn span() -> ::syn::Ident { g() }".to_owned();
        let e = emit_of(&[a, b, c]);
        assert!(
            e.as_ref().is_ok_and(|e| e
                .as_ref()
                .is_some_and(|e| e.dep_lines.contains(&"syn-compat = \"=1.0.0\"".to_owned()))),
            "an ident a declared package answers to is not refused: {e:?}"
        );
    }

    #[test]
    fn scanner_misses_are_refused_at_the_seal() {
        for body in [
            "pub fn f() -> S { S { ..syn::X::default() } }",
            "use::syn::X;",
            "pub fn f(x: &mut::syn::X) {}",
            "pub fn f(x: u8) -> T { x as::syn::T }",
            "pub fn f() { for v in::syn::iter() {} }",
            "pub fn f(a: u8) -> bool { a>::syn::C }",
            "use syn;",
            "extern crate syn;",
            "pub fn f() -> syn /* note */ :: Ident { g() }",
            "pub fn f() -> r#syn::Ident { g() }",
            "m!(syn);",
        ] {
            let [a, mut b] = syn_split();
            b.bindings_source = body.to_owned();
            let refused = emit_of(&[a, b]);
            assert!(
                refused_as(&refused, &catalog_dropped_at("src/ffi.rs")),
                "{body}: {refused:?}"
            );
        }
    }

    #[test]
    fn unlexable_emitted_text_is_refused() {
        let [a, mut b] = syn_split();
        b.bindings_source = "pub fn f() { \"unterminated }".to_owned();
        let refused = emit_of(&[a, b]);
        assert!(
            refused_as(
                &refused,
                &FfiPrepError::CatalogSeal(SealRefusal::Unlexable {
                    site: "src/ffi.rs".to_owned()
                })
            ),
            "{refused:?}"
        );
    }

    #[test]
    fn inspected_members_splitting_a_named_transitive_are_refused() {
        // Two inspection documents: each member links its own `syn` major and
        // `a` declares the opaque handle `foreign Ident = { kind = Opaque
        // "syn::Ident" }`. A declared opaque surfaces unconditionally (no
        // binding has to resolve it), so the dropped root reaches the emit
        // through exactly one site: the `Rust.A.Ident` foreign-type path.
        let member = |name: &str, syn: &str, declared: serde_json::Value| {
            let doc = serde_json::json!({
                "pkg": name, "name": name, "version": "1.0.0",
                "functions": [],
                "constants": [],
                "errors": [],
                "transitiveDeps": [
                    {"ident": name, "name": name, "version": "1.0.0"},
                    {"ident": "syn", "name": "syn", "version": syn}
                ],
                "declaredOpaques": declared
            })
            .to_string();
            let pkg = ipe_ffi::pkginfo::PkgInfo::decode_json(&doc).expect("decodes");
            ipe_ffi::driver::installed_crate_from_pkg(
                name.to_owned(),
                &pkg,
                &FfiCache::at_project_root(Path::new(".")),
            )
            .expect("installs")
        };
        let a = member("a", "2.0.119", serde_json::json!({"Ident": "::syn::Ident"}));
        let b = member("b", "3.0.0", serde_json::json!({}));
        assert_eq!(
            a.opaque_types.get("Ident").map(String::as_str),
            Some("::syn::Ident"),
            "the declared opaque surfaces"
        );
        let refused = emit_of(&[a, b]);
        assert!(
            refused_as(&refused, &catalog_dropped_at("Rust.A.Ident")),
            "{refused:?}"
        );
    }

    /// A bare typed member, package `slug`, carrying only the given typed
    /// dependencies and one `dep_idents` entry per dependency (`-` → `_`).
    fn crate_with_deps(slug: &str, cargo_deps: Vec<CargoDep>) -> InstalledCrate {
        let dep_idents = cargo_deps
            .iter()
            .filter_map(|dep| {
                let name = dep.name().as_str();
                ipe_ffi::naming::RustIdent::parse(&name.replace('-', "_"))
                    .ok()
                    .map(|ident| (name.to_owned(), ident))
            })
            .collect();
        InstalledCrate {
            slug: slug.to_owned(),
            module_name: format!("Rust.{slug}"),
            kernel_name: format!("Rust_{slug}"),
            interface_source: String::new(),
            bindings_source: String::new(),
            opaque_types: BTreeMap::new(),
            opaque_type_ids: BTreeMap::new(),
            define_types: BTreeSet::new(),
            transparent_types: BTreeMap::new(),
            bindings: Vec::new(),
            dep_versions: BTreeMap::new(),
            inspected_free_fns: BTreeMap::new(),
            inspected_consts: BTreeMap::new(),
            cargo_deps,
            wrapper_idents: BTreeSet::new(),
            package_name: ipe_ffi::pkginfo::PackageName::parse(slug).ok(),
            dep_idents,
        }
    }

    /// A scratch project with `wrappers/<name>` crates all named `engine_wrap`,
    /// jailed into typed wrapper entries; returns the project root and the entries.
    fn jailed_wrappers(tag: &str, dirs: &[&str]) -> (PathBuf, Vec<CargoDep>) {
        let project =
            ipe_test_temp::temp_root().join(format!("ipe-cli-wrap-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&project);
        let deps = dirs
            .iter()
            .map(|dir| {
                let rel = format!("wrappers/{dir}");
                std::fs::create_dir_all(project.join(&rel)).expect("scratch wrapper dir");
                std::fs::write(
                    project.join(&rel).join("Cargo.toml"),
                    "[package]\nname = \"engine_wrap\"\nversion = \"0.1.0\"\n",
                )
                .expect("scratch wrapper manifest");
                let jailed = ipe_ffi::pkginfo::WrapperCratePath::parse(&rel)
                    .and_then(|path| path.jail(&project))
                    .expect("jails inside the scratch root");
                CargoDep::Wrapper {
                    dir: jailed,
                    features: Vec::new(),
                }
            })
            .collect();
        (project, deps)
    }

    /// The source description a wrapper entry carries in a conflict message.
    fn wrapper_source(deps: &[CargoDep], at: usize) -> String {
        let Some(CargoDep::Wrapper { dir, .. }) = deps.get(at) else {
            return String::new();
        };
        format!("path {}", dir.as_str())
    }

    /// The exact source-conflict refusal for the `engine_wrap` key.
    fn source_conflict(first: &str, second: &str) -> String {
        text::msg::ffi_dependency_source_conflict(&"engine_wrap", &first, &second).to_string()
    }

    /// The conflict message renders both sources on their own lines.
    #[test]
    fn the_source_conflict_message_names_both_sources() {
        assert_eq!(
            source_conflict("version =1.0.0", "path /p/engine"),
            "installed FFI crates bind dependency `engine_wrap` to two different sources:\n  \
             version =1.0.0\n  path /p/engine"
        );
    }

    /// A wrapper crate flows through `assemble_emit` as its typed entry and
    /// renders the one canonical `path` line; two members naming the same
    /// wrapper directory dedupe to it.
    #[test]
    fn a_wrapper_crate_renders_its_path_line_through_emit_of() {
        let (project, deps) = jailed_wrappers("ok", &["engine"]);
        let canonical = std::fs::canonicalize(project.join("wrappers/engine"))
            .expect("wrapper dir canonicalizes");
        let r = emit_of(&[
            crate_with_deps("engine_wrap", deps.clone()),
            crate_with_deps("other", deps),
        ]);
        let _ = std::fs::remove_dir_all(&project);
        let emit = r.expect("a wrapper crate assembles").expect("emit present");
        assert_eq!(
            emit.dep_lines,
            vec![format!(
                "engine_wrap = {{ path = \"{}\" }}",
                canonical.display()
            )]
        );
    }

    /// One dependency key bound to a registry pin by one member and a wrapper
    /// path by another is refused, in either order.
    #[test]
    fn a_registry_pin_against_a_wrapper_path_is_refused() {
        let (project, wrapper) = jailed_wrappers("mixed", &["engine"]);
        let path = wrapper_source(&wrapper, 0);
        let registry =
            vec![CargoDep::parse_registry_line("engine_wrap = \"=1.0.0\"").expect("registry line")];
        let forward = emit_of(&[
            crate_with_deps("a", registry.clone()),
            crate_with_deps("b", wrapper.clone()),
        ]);
        let backward = emit_of(&[
            crate_with_deps("a", wrapper),
            crate_with_deps("b", registry),
        ]);
        let _ = std::fs::remove_dir_all(&project);
        for (r, expected) in [
            (forward, source_conflict("version =1.0.0", &path)),
            (backward, source_conflict(&path, "version =1.0.0")),
        ] {
            assert!(
                matches!(&r, Err(e @ FfiPrepError::DependencyMerge(MergeRefusal::SourceConflict { .. }))
                    if e.to_string() == expected),
                "{r:?}"
            );
        }
    }

    /// One dependency key bound to two different wrapper directories is refused.
    #[test]
    fn two_wrapper_paths_for_one_dependency_are_refused() {
        let (project, deps) = jailed_wrappers("two", &["engine", "engine2"]);
        let r = emit_of(&[
            crate_with_deps("a", deps.iter().take(1).cloned().collect()),
            crate_with_deps("b", deps.iter().skip(1).cloned().collect()),
        ]);
        let _ = std::fs::remove_dir_all(&project);
        let expected = source_conflict(&wrapper_source(&deps, 0), &wrapper_source(&deps, 1));
        assert!(
            matches!(&r, Err(e @ FfiPrepError::DependencyMerge(MergeRefusal::SourceConflict { .. }))
                    if e.to_string() == expected),
            "{r:?}"
        );
    }

    /// A wrapper path under a key a transitive version conflict already left
    /// to Cargo is refused, never silently dropped.
    #[test]
    fn a_wrapper_path_under_an_unpinned_transitive_is_refused() {
        let (project, wrapper) = jailed_wrappers("unpinned", &["engine"]);
        let pin = |v: &str| {
            CargoDep::parse_registry_line(&format!("engine_wrap = \"={v}\""))
                .expect("registry line")
        };
        let r = emit_of(&[
            crate_with_deps("a", vec![pin("1.0.0")]),
            crate_with_deps("b", vec![pin("2.0.0")]),
            crate_with_deps("c", wrapper.clone()),
        ]);
        let _ = std::fs::remove_dir_all(&project);
        let expected = source_conflict(
            "an unpinned registry dependency",
            &wrapper_source(&wrapper, 0),
        );
        assert!(
            matches!(&r, Err(e @ FfiPrepError::DependencyMerge(MergeRefusal::SourceConflict { .. }))
                    if e.to_string() == expected),
            "{r:?}"
        );
    }

    #[test]
    fn merge_injects_a_matching_closure_as_a_synthetic_function() {
        let doc = "{\"pkg\":\"demo\",\"name\":\"demo\",\"functions\":[]}";
        let closures = vec![ManifestDefineClosure {
            krate: "demo".to_owned(),
            name: "update_fn".to_owned(),
            signature: "Fn(Int) -> Int + Send + Sync + 'static".to_owned(),
        }];
        let merged = merge_provides(doc, "demo", &closures, &[], &[], &[], true).expect("merges");
        let val: serde_json::Value = serde_json::from_str(&merged).expect("valid json");
        let fns = val
            .get("functions")
            .and_then(serde_json::Value::as_array)
            .expect("functions array");
        assert_eq!(fns.len(), 1);
        let f0 = fns.first().expect("one function");
        assert_eq!(
            f0.get("name").and_then(serde_json::Value::as_str),
            Some("update_fn")
        );
        assert_eq!(
            f0.get("isClosureAdapter")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            f0.get("closureSig").and_then(serde_json::Value::as_str),
            Some("Fn(Int) -> Int + Send + Sync + 'static")
        );
    }

    #[test]
    fn merge_leaves_a_non_matching_crate_untouched() {
        let doc = "{\"pkg\":\"other\",\"name\":\"other\",\"functions\":[]}";
        let closures = vec![ManifestDefineClosure {
            krate: "demo".to_owned(),
            name: "update_fn".to_owned(),
            signature: "Fn(Int) -> Int".to_owned(),
        }];
        // A qualified entry for `demo` does not attach to `other`.
        let merged = merge_provides(doc, "other", &closures, &[], &[], &[], false).expect("merges");
        let val: serde_json::Value = serde_json::from_str(&merged).expect("valid json");
        assert!(
            val.get("functions")
                .and_then(serde_json::Value::as_array)
                .expect("array")
                .is_empty()
        );
    }

    #[test]
    fn an_unqualified_closure_under_a_multi_crate_manifest_is_refused() {
        let doc = "{\"pkg\":\"demo\",\"name\":\"demo\",\"functions\":[]}";
        let closures = vec![ManifestDefineClosure {
            krate: String::new(),
            name: "update_fn".to_owned(),
            signature: "Fn(Int) -> Int".to_owned(),
        }];
        // sole_dep = false ⇒ an unattributed entry cannot be placed: refuse.
        assert!(merge_provides(doc, "demo", &closures, &[], &[], &[], false).is_err());
        // sole_dep = true ⇒ it attaches to the one crate.
        assert!(merge_provides(doc, "demo", &closures, &[], &[], &[], true).is_ok());
    }

    #[test]
    fn an_unqualified_struct_under_a_multi_crate_manifest_is_refused() {
        let doc = "{\"pkg\":\"demo\",\"name\":\"demo\",\"functions\":[]}";
        let structs = vec![ManifestDefineStruct {
            krate: String::new(),
            ctor: "counter_new".to_owned(),
            struct_name: "Counter".to_owned(),
            fields: vec![("value".to_owned(), "i64".to_owned())],
            derives: Vec::new(),
        }];
        assert!(merge_provides(doc, "demo", &[], &structs, &[], &[], false).is_err());
        assert!(merge_provides(doc, "demo", &[], &structs, &[], &[], true).is_ok());
    }

    /// An inspection document that reports one opaque type `Client` (a struct
    /// with hidden members, so the classifier leaves it opaque).
    fn doc_reporting_opaque_client() -> String {
        serde_json::json!({
            "pkg": "postgres",
            "name": "postgres",
            "version": "0.1.0",
            "functions": [],
            "errors": [],
            "types": [
                { "name": "Client", "rustPath": "postgres::Client",
                  "kind": "struct", "hiddenMembers": true }
            ]
        })
        .to_string()
    }

    #[test]
    fn a_declared_opaque_over_a_reported_type_is_merged() {
        let opaques = vec![ManifestDefineOpaque {
            krate: "postgres".to_owned(),
            ipe_name: "Connection".to_owned(),
            rust_type: "Client".to_owned(),
        }];
        let merged = merge_provides(
            &doc_reporting_opaque_client(),
            "postgres",
            &[],
            &[],
            &[],
            &opaques,
            true,
        )
        .expect("merges");
        let val: serde_json::Value = serde_json::from_str(&merged).expect("valid json");
        assert_eq!(
            val.get("declaredOpaques")
                .and_then(|d| d.get("Connection"))
                .and_then(serde_json::Value::as_str),
            Some("::postgres::Client"),
            "{merged}"
        );
    }

    #[test]
    fn a_declared_opaque_over_an_unreported_type_is_refused() {
        let opaques = vec![ManifestDefineOpaque {
            krate: "postgres".to_owned(),
            ipe_name: "Connection".to_owned(),
            rust_type: "Nonexistent".to_owned(),
        }];
        let err = merge_provides(
            &doc_reporting_opaque_client(),
            "postgres",
            &[],
            &[],
            &[],
            &opaques,
            true,
        )
        .expect_err("must_refuse: an un-inspected type cannot mint a handle");
        assert!(
            matches!(&err, CliError::Usage(m) if m.contains("not an inspected type")),
            "{err:?}"
        );
    }

    #[test]
    fn a_declared_opaque_over_a_transparent_type_is_refused() {
        // A struct with two identity-carrier fields surfaces TRANSPARENTLY, so
        // it is a value type — an `Opaque` handle over it is refused.
        let doc = serde_json::json!({
            "pkg": "geo", "name": "geo", "version": "0.1.0",
            "functions": [], "errors": [],
            "types": [
                { "name": "Point", "rustPath": "geo::Point", "kind": "struct",
                  "fields": [
                    { "name": "x", "type": "Int", "rustType": "i64" },
                    { "name": "y", "type": "Int", "rustType": "i64" }
                  ]}
            ]
        })
        .to_string();
        let opaques = vec![ManifestDefineOpaque {
            krate: "geo".to_owned(),
            ipe_name: "Pt".to_owned(),
            rust_type: "Point".to_owned(),
        }];
        let err = merge_provides(&doc, "geo", &[], &[], &[], &opaques, true)
            .expect_err("must_refuse: a transparent value type is not a handle");
        assert!(
            matches!(&err, CliError::Usage(m) if m.contains("TRANSPARENTLY")),
            "{err:?}"
        );
    }

    #[test]
    fn an_unqualified_opaque_under_a_multi_crate_manifest_is_refused() {
        let opaques = vec![ManifestDefineOpaque {
            krate: String::new(),
            ipe_name: "Connection".to_owned(),
            rust_type: "Client".to_owned(),
        }];
        // sole_dep = false ⇒ an unattributed declaration cannot be placed.
        assert!(
            merge_provides(
                &doc_reporting_opaque_client(),
                "postgres",
                &[],
                &[],
                &[],
                &opaques,
                false
            )
            .is_err()
        );
        // sole_dep = true ⇒ it attaches to the one crate.
        assert!(
            merge_provides(
                &doc_reporting_opaque_client(),
                "postgres",
                &[],
                &[],
                &[],
                &opaques,
                true
            )
            .is_ok()
        );
    }

    #[test]
    fn lift_opaque_reads_the_kind_and_rejects_a_non_literal() {
        let interner_and_module = |src: &str| {
            let mut interner = ipe_intern::Interner::new();
            let module = ipe_parse::parse_module(src, &mut interner).expect("parses");
            (interner, module)
        };
        // A well-formed opaque declaration lifts to `ManifestDefineOpaque`.
        let (interner, module) = interner_and_module(
            "module M exposing (..)\n\nforeign Connection =\n    { crate = \"postgres\"\n    , kind = Opaque \"Client\"\n    }\n",
        );
        let reader = ForeignReader {
            interner: &interner,
            src: "",
            file: Path::new("M.ipe"),
        };
        let foreign = module.foreigns.first().expect("one foreign");
        let lifted = reader.lift_foreign(foreign).expect("lifts");
        assert_eq!(
            lifted,
            ForeignDefine::Opaque(ManifestDefineOpaque {
                krate: "postgres".to_owned(),
                ipe_name: "Connection".to_owned(),
                rust_type: "Client".to_owned(),
            })
        );
        // A non-literal type argument is refused (literal-only, invariant 5).
        let (interner2, module2) = interner_and_module(
            "module M exposing (..)\n\nname = \"Client\"\n\nforeign Connection =\n    { crate = \"postgres\"\n    , kind = Opaque name\n    }\n",
        );
        let reader2 = ForeignReader {
            interner: &interner2,
            src: "",
            file: Path::new("M.ipe"),
        };
        let foreign2 = module2.foreigns.first().expect("one foreign");
        assert!(
            reader2.lift_foreign(foreign2).is_err(),
            "must_refuse a computed type name"
        );
    }

    /// A one-crate `InstalledCrate` with the given opaque + define type maps.
    fn crate_with_types(slug: &str, opaque: &[(&str, &str)], define: &[&str]) -> InstalledCrate {
        InstalledCrate {
            slug: slug.to_owned(),
            module_name: format!("Rust.{slug}"),
            kernel_name: format!("Rust_{slug}"),
            interface_source: String::new(),
            bindings_source: String::new(),
            opaque_types: opaque
                .iter()
                .map(|(n, p)| ((*n).to_owned(), (*p).to_owned()))
                .collect(),
            opaque_type_ids: BTreeMap::new(),
            define_types: define.iter().map(|n| (*n).to_owned()).collect(),
            transparent_types: BTreeMap::new(),
            bindings: Vec::new(),
            dep_versions: BTreeMap::new(),
            inspected_free_fns: BTreeMap::new(),
            inspected_consts: BTreeMap::new(),
            cargo_deps: Vec::new(),
            wrapper_idents: BTreeSet::new(),
            package_name: None,
            dep_idents: BTreeMap::new(),
        }
    }

    #[test]
    fn a_define_type_renders_a_crate_absolute_ffi_path() {
        // A define-defined type lives in `crate::ffi::<slug>::<Name>` (the app
        // crate's own module tree), NOT at an external `::crate::Path`.
        let emit = emit_of(&[crate_with_types("iced", &[], &["Counter", "Message"])])
            .expect("emit ok")
            .expect("emit present");
        assert_eq!(
            emit.foreign_types
                .get("Rust.iced.Counter")
                .map(String::as_str),
            Some("crate::ffi::iced::Counter")
        );
        assert_eq!(
            emit.foreign_types
                .get("Rust.iced.Message")
                .map(String::as_str),
            Some("crate::ffi::iced::Message")
        );
    }

    #[test]
    fn a_transparent_define_glues_at_its_crate_local_path() {
        // A transparent define shape carries the BARE nominal (the define
        // convention); the assembled conversion glue must resolve it to the
        // crate-local `crate::ffi::<slug>::<Name>` where its `_bindings.rs`
        // definition lives — never an external `::Name`.
        let mut c = crate_with_types("demo", &[], &[]);
        let t = ipe_ffi::transparency::TransparentType::from_projection_json(&serde_json::json!({
            "name": "Counter", "kind": "struct", "rustPath": "Counter",
            "fields": [{"name": "value", "carrier": "Int"}]
        }))
        .expect("decodes");
        c.transparent_types.insert("Counter".to_owned(), t);
        c.bindings.push(ipe_ffi::interface::InterfaceBinding {
            ref_name: "counter_new".to_owned(),
            wrapper_ident: "Rust_demo_counter_new".to_owned(),
            arity: 1,
            sig: "Int -> Counter".to_owned(),
            transparent_params: ipe_ffi::interface::TransparentParams::None,
            transparent_result: Some(ipe_ffi::interface::TransparentResult {
                type_name: "Counter".to_owned(),
                in_result: false,
            }),
        });
        let emit = emit_of(&[c]).expect("emit ok").expect("emit present");
        let glue = emit
            .wrapper_glue
            .get("Rust_demo_counter_new")
            .expect("constructor glue assembled");
        let result = glue.result.as_ref().expect("result conversion");
        assert_eq!(
            result.ty,
            ipe_backend_rust::FfiGlueType::Record {
                rust_path: "crate::ffi::demo::Counter".to_owned(),
                fields: vec!["value".to_owned()],
            }
        );
        // A transparent define is a native app type — never a foreign-path
        // mapping.
        assert!(!emit.foreign_types.contains_key("Rust.demo.Counter"));
    }

    #[test]
    fn a_define_type_colliding_with_an_inspected_opaque_is_refused() {
        // A define type sharing a name with an inspected opaque of the SAME
        // crate would silently overwrite one path — the two are different Rust
        // types. Fail closed rather than emit a wrong-type binding.
        let clash = emit_of(&[crate_with_types(
            "iced",
            &[("Element", "::iced::Element")],
            &["Element"],
        )]);
        assert!(
            refused_as(
                &clash,
                &FfiPrepError::DefineOpaqueCollision {
                    slug: "iced".to_owned(),
                    name: "Element".to_owned(),
                }
            ),
            "a define-vs-opaque name clash must refuse: {clash:?}"
        );
    }

    #[test]
    fn inject_interfaces_two_crates_one_module_is_module_claimed() {
        let mut sources = BTreeMap::new();
        let claimed = (
            PathBuf::from("src/Rust/b.ipe"),
            "module Rust.b exposing (..)\n".to_owned(),
        );
        sources.insert(vec!["Rust".to_owned(), "b".to_owned()], claimed);
        let catalog = [
            crate_with_types("a", &[], &[]),
            crate_with_types("b", &[], &[]),
        ];
        let got = inject_interfaces(&mut sources, &catalog, Path::new("/cache"));
        assert_eq!(
            got,
            Err(FfiPrepError::ModuleClaimed {
                module: "Rust.b".to_owned(),
                slug: "b".to_owned(),
            })
        );
    }

    #[test]
    fn assemble_wrapper_glue_missing_shape_is_transparent_without_shape() {
        let mut c = crate_with_types("demo", &[], &[]);
        c.bindings.push(ipe_ffi::interface::InterfaceBinding {
            ref_name: "counter_new".to_owned(),
            wrapper_ident: "Rust_demo_counter_new".to_owned(),
            arity: 1,
            sig: "Int -> Counter".to_owned(),
            transparent_params: ipe_ffi::interface::TransparentParams::None,
            transparent_result: Some(ipe_ffi::interface::TransparentResult {
                type_name: "Counter".to_owned(),
                in_result: false,
            }),
        });
        let mut glue = BTreeMap::new();
        assert_eq!(
            assemble_wrapper_glue(&c, &mut glue),
            Err(FfiPrepError::TransparentWithoutShape {
                slug: "demo".to_owned(),
                name: "Counter".to_owned(),
                binding: "counter_new".to_owned(),
            })
        );
        assert!(
            glue.is_empty(),
            "no glue is assembled for a refused binding"
        );
    }

    /// One source module whose body is `body`, keyed as `Main`.
    fn main_module(body: &str) -> BTreeMap<Vec<String>, (PathBuf, String)> {
        let text = format!("module Main exposing (main)\nimport Rust.Ffi\n\n{body}");
        BTreeMap::from([(
            vec!["Main".to_owned()],
            (PathBuf::from("src/Main.ipe"), text),
        )])
    }

    #[test]
    fn scan_asserted_refused_assertion_is_asserted_refused() {
        let sources = main_module(
            "shifted : Int -> Result Error Int\nshifted =\n    Rust.Ffi.call \"tm::shift\"\n",
        );
        let got = scan_asserted(&sources, &[]);
        assert!(
            matches!(&got, Err(CliError::FfiPrep(refusal))
                if matches!(refusal.as_ref(), FfiPrepError::AssertedRefused(diag)
                    if matches!(diag.as_ref(), ipe_ffi::diag::Diagnostic::AssertedRefused { path, .. }
                        if path == "tm::shift"))),
            "an asserted call into an uninstalled crate is a typed refusal"
        );
    }

    #[test]
    fn scan_asserted_malformed_site_stays_pipeline() {
        let sources = main_module(
            "main =\n    case (Rust.Ffi.call \"tm::shift\") 1 of\n        Ok _ -> 1\n        Err _ -> 0\n",
        );
        let got = scan_asserted(&sources, &[]);
        assert!(
            matches!(&got, Err(CliError::Pipeline { .. })),
            "a misplaced asserted call stays a span-attributed pipeline error"
        );
    }

    #[test]
    fn display_is_byte_identical_per_variant() {
        let dropped = || SealRefusal::DroppedTransitive {
            package: "syn".to_owned(),
            ident: "syn".to_owned(),
            site: "src/ffi.rs".to_owned(),
        };
        let diag = ipe_ffi::diag::Diagnostic::ArtifactIo {
            path: "/p/x.consumer.json".to_owned(),
            detail: "refused".to_owned(),
        };
        let cases: [(FfiPrepError, text::Message); 10] = [
            (
                FfiPrepError::ModuleClaimed {
                    module: "Rust.a".to_owned(),
                    slug: "a".to_owned(),
                },
                text::msg::ffi_module_clash(&"Rust.a", &"a"),
            ),
            (
                FfiPrepError::ReservedModuleExists,
                text::msg::ffi_reserved_module_exists(&ipe_canon::asserted::ASSERTED_MODULE),
            ),
            (
                FfiPrepError::AssertedRefused(Box::new(diag.clone())),
                text::Message::relay(&diag),
            ),
            (
                FfiPrepError::AssertedShimSeal(dropped()),
                text::msg::ffi_dropped_transitive(&"syn", &"syn", &"src/ffi.rs"),
            ),
            (
                FfiPrepError::DefineOpaqueCollision {
                    slug: "a".to_owned(),
                    name: "T".to_owned(),
                },
                text::msg::ffi_define_opaque_collision(&"a", &"T"),
            ),
            (
                FfiPrepError::DependencyMerge(MergeRefusal::PinConflict {
                    name: "serde".to_owned(),
                    first: "1.0.1".to_owned(),
                    second: "1.0.2".to_owned(),
                }),
                text::msg::ffi_dependency_pin_conflict(&"serde", &"1.0.1", &"1.0.2"),
            ),
            (
                FfiPrepError::DependencyMerge(MergeRefusal::SourceConflict {
                    name: "engine_wrap".to_owned(),
                    first: "version =1.0.0".to_owned(),
                    second: "path /p/engine".to_owned(),
                }),
                text::msg::ffi_dependency_source_conflict(
                    &"engine_wrap",
                    &"version =1.0.0",
                    &"path /p/engine",
                ),
            ),
            (
                FfiPrepError::CatalogSeal(SealRefusal::Unlexable {
                    site: "src/ffi.rs".to_owned(),
                }),
                text::msg::ffi_emit_unlexable(&"src/ffi.rs"),
            ),
            (
                FfiPrepError::TransparentWithoutShape {
                    slug: "a".to_owned(),
                    name: "Shape".to_owned(),
                    binding: "make".to_owned(),
                },
                text::msg::ffi_transparent_without_shape(&"a", &"Shape", &"make"),
            ),
            (
                FfiPrepError::AssertedWithoutCatalog,
                text::msg::ffi_asserted_empty_catalog(),
            ),
        ];
        for (refusal, message) in cases {
            let want = message.to_string();
            assert_eq!(refusal.to_string(), want);
            assert_eq!(CliError::from(refusal).to_string(), want);
        }
    }

    /// The FFI prep entry point every prep refusal leaves through.
    const FFI_PREP_ENTRY: &str = "prepare_ffi";

    /// Prep functions the reach walk must find from [`FFI_PREP_ENTRY`]: a walk
    /// that loses one (a rename, a parse that stopped early) goes red instead
    /// of passing over less code.
    const FFI_PREP_REACHED: [&str; 11] = [
        "prepare_ffi",
        "load_located_catalog",
        "scan_asserted",
        "asserted_refused",
        "inject_interfaces",
        "assemble_emit",
        "assemble_wrapper_glue",
        "append_asserted_shims",
        "seal_dependency_references",
        "merge_catalog_deps",
        "merge_cargo_dep",
    ];

    /// Whether `attrs` carry `#[cfg(test)]`.
    fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|attr| {
            matches!(&attr.meta, syn::Meta::List(list)
                if list.path.is_ident("cfg") && list.tokens.to_string() == "test")
        })
    }

    /// Every production function body under `items`, keyed by its name.
    ///
    /// A `#[cfg(test)]` item and everything inside it is left out. Methods and
    /// trait defaults are keyed by their bare name, so same-named functions
    /// are all walked.
    fn production_fn_bodies<'f>(
        items: &'f [syn::Item],
        bodies: &mut BTreeMap<String, Vec<&'f syn::Block>>,
    ) {
        for item in items {
            match item {
                syn::Item::Fn(f) if !is_cfg_test(&f.attrs) => {
                    bodies
                        .entry(f.sig.ident.to_string())
                        .or_default()
                        .push(&f.block);
                }
                syn::Item::Impl(imp) if !is_cfg_test(&imp.attrs) => {
                    for member in &imp.items {
                        if let syn::ImplItem::Fn(f) = member
                            && !is_cfg_test(&f.attrs)
                        {
                            bodies
                                .entry(f.sig.ident.to_string())
                                .or_default()
                                .push(&f.block);
                        }
                    }
                }
                syn::Item::Trait(tr) if !is_cfg_test(&tr.attrs) => {
                    for member in &tr.items {
                        if let syn::TraitItem::Fn(f) = member
                            && let Some(block) = &f.default
                            && !is_cfg_test(&f.attrs)
                        {
                            bodies
                                .entry(f.sig.ident.to_string())
                                .or_default()
                                .push(block);
                        }
                    }
                }
                syn::Item::Mod(m) if !is_cfg_test(&m.attrs) => {
                    if let Some((_, inner)) = &m.content {
                        production_fn_bodies(inner, bodies);
                    }
                }
                _ => {}
            }
        }
    }

    /// The names one function body mentions, and how many of them are `Usage`.
    #[derive(Default)]
    struct Mentions {
        names: BTreeSet<String>,
        usage: usize,
    }

    impl Mentions {
        fn word(&mut self, word: String) {
            if word == "Usage" {
                self.usage += 1;
            }
            self.names.insert(word);
        }

        /// Every identifier of a macro's unparsed tokens; a literal never matches.
        fn tokens(&mut self, stream: proc_macro2::TokenStream) {
            for tree in stream {
                match tree {
                    proc_macro2::TokenTree::Ident(ident) => self.word(ident.to_string()),
                    proc_macro2::TokenTree::Group(group) => self.tokens(group.stream()),
                    proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
                }
            }
        }
    }

    impl<'ast> syn::visit::Visit<'ast> for Mentions {
        fn visit_path_segment(&mut self, segment: &'ast syn::PathSegment) {
            self.word(segment.ident.to_string());
            syn::visit::visit_path_segment(self, segment);
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.word(call.method.to_string());
            syn::visit::visit_expr_method_call(self, call);
        }

        fn visit_use_path(&mut self, path: &'ast syn::UsePath) {
            self.word(path.ident.to_string());
            syn::visit::visit_use_path(self, path);
        }

        fn visit_use_name(&mut self, name: &'ast syn::UseName) {
            self.word(name.ident.to_string());
        }

        fn visit_use_rename(&mut self, rename: &'ast syn::UseRename) {
            self.word(rename.ident.to_string());
            self.word(rename.rename.to_string());
        }

        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            self.tokens(mac.tokens.clone());
            syn::visit::visit_macro(self, mac);
        }
    }

    /// The production functions `src` reaches from [`FFI_PREP_ENTRY`], with
    /// the count of `Usage` mentions in their bodies; `None` when `src` does
    /// not parse.
    ///
    /// Reach over-approximates: every name a body mentions (a call, a method,
    /// a function value, a macro token) that names a production function is
    /// walked, so a refusal built one helper deep is still seen.
    fn ffi_prep_reach(src: &str) -> Option<(BTreeSet<String>, usize)> {
        use syn::visit::Visit as _;
        let file = syn::parse_file(src).ok()?;
        let mut bodies = BTreeMap::new();
        production_fn_bodies(&file.items, &mut bodies);
        let mut reached = BTreeSet::new();
        let mut usage = 0;
        let mut pending = vec![FFI_PREP_ENTRY.to_owned()];
        while let Some(name) = pending.pop() {
            let Some(blocks) = bodies.get(&name) else {
                continue;
            };
            if !reached.insert(name) {
                continue;
            }
            for block in blocks {
                let mut mentions = Mentions::default();
                mentions.visit_block(block);
                usage += mentions.usage;
                pending.extend(
                    mentions
                        .names
                        .into_iter()
                        .filter(|n| bodies.contains_key(n) && !reached.contains(n)),
                );
            }
        }
        Some((reached, usage))
    }

    #[test]
    fn ffi_prep_reach_sees_a_usage_build_one_helper_deep() {
        let src = "fn prepare_ffi() { helper(); x.map_err(lift); }\n\
                   fn helper() -> Result<(), CliError> { Err(CliError::Usage(m())) }\n\
                   fn lift(m: M) -> CliError { wrap!(Usage, \"Usage\") }\n\
                   fn unrelated() -> CliError { CliError::Usage(x()) }\n\
                   #[cfg(test)]\n\
                   fn prepare_ffi() -> CliError { CliError::Usage(t()) }\n";
        let want = BTreeSet::from(["helper", "lift", "prepare_ffi"].map(str::to_owned));
        assert_eq!(ffi_prep_reach(src), Some((want, 2)));
    }

    /// No function FFI prep reaches builds `CliError::Usage`: each prep
    /// refusal is a typed [`FfiPrepError`] the LSP classifies by variant.
    #[test]
    fn ffi_prep_builds_no_usage() {
        let reach = ffi_prep_reach(include_str!("ffi.rs"));
        assert!(reach.is_some(), "ffi.rs parses");
        let (reached, usage) = reach.unwrap_or_default();
        let lost: Vec<&str> = FFI_PREP_REACHED
            .into_iter()
            .filter(|f| !reached.contains(*f))
            .collect();
        assert!(lost.is_empty(), "the prep walk lost {lost:?}");
        assert_eq!(
            usage, 0,
            "an FFI prep function builds `CliError::Usage`; type the refusal as an \
             `FfiPrepError` variant (walked: {reached:?})"
        );
    }

    #[test]
    fn build_failure_does_not_trigger_usage_help() {
        // A build/inspection failure must not be wrapped into CliError::Usage*
        // (which `with_help_on_misuse` converts to CommandUsage + help page).
        // The `Pipeline` variant (typed diagnostic) never triggers usage help.
        let diag = ipe_ffi::diag::Diagnostic::WireMalformed {
            context: "crate `bevy`".to_owned(),
            defect: ipe_ffi::diag::WireDefect::Json {
                detail: "the inspector failed: error[E0412]: cannot find type".to_owned(),
            },
        };
        let err = ffi_build_error(diag);
        assert!(
            matches!(err, CliError::Pipeline { .. }),
            "build failure must produce CliError::Pipeline (typed diagnostic), got {err:?}"
        );
    }

    #[test]
    fn build_scripts_hint_is_detected_in_raw_error() {
        let raw = "inspector exited with Some(1)\n\
            error: some crates require build scripts\n\
            pass --allow-build-scripts to proceed anyway";
        assert!(
            detect_build_scripts_hint(raw).is_some(),
            "the --allow-build-scripts text must be detected"
        );
        assert!(
            detect_build_scripts_hint("unrelated cargo error: E0001").is_none(),
            "a plain build error must not be detected as a build-scripts hint"
        );
    }

    #[test]
    #[allow(clippy::panic)]
    fn build_scripts_error_renders_as_warning_not_usage_help() {
        let raw = "inspector exited with Some(1)\n\
            crates with build scripts found\n\
            pass --allow-build-scripts to proceed";
        let err = map_inspector_error(crate::text::msg::command_refusal(&"add", &raw));
        match err {
            CliError::Resolve(msg) => {
                assert!(
                    msg.starts_with(
                        "warning: some crates in the dependency graph have build scripts.\n\
                         Pass --allow-build-scripts to proceed"
                    ),
                    "the banner leads with the plain warning and flag: {msg:?}"
                );
                assert!(
                    msg.ends_with("hint: pass --allow-build-scripts to proceed"),
                    "the inspector hint closes the banner: {msg:?}"
                );
                assert!(!msg.contains('\u{1b}'), "the banner is plain text: {msg:?}");
            }
            other => panic!("expected Resolve, got {other:?}"),
        }
    }

    // ── foreign-declaration lift tests ──────────────────────────────────────

    /// Parse a `foreign` source snippet and expect lifting to fail, returning
    /// the error message for further assertions.
    fn lift_one_err(src: &str) -> String {
        lift_first_foreign(src).expect_err("lift_foreign should fail for an invalid declaration")
    }

    /// An invalid carrier in a `foreign` struct field is rejected with a span
    /// pointing at the bad carrier. Lower-case field types are not carriers.
    #[test]
    fn foreign_struct_invalid_carrier_is_refused() {
        // `int` (lower-case) is not a valid carrier name.
        let bad = "module Main exposing (..)\n\nforeign Foo =\n          { crate = \"x\"\n          , kind = Struct { value = int }\n          }\n";
        let err = lift_one_err(bad);
        assert!(
            err.contains("not a valid field carrier") || err.contains("carrier"),
            "error must mention carrier: {err}"
        );
    }

    /// A derive that is not in the blessed allowlist is refused.
    #[test]
    fn foreign_struct_unknown_derive_is_refused() {
        let src = "module Main exposing (..)\n\nforeign Foo =\n          { crate = \"x\"\n          , kind = Struct { value = Int }\n          , derives = [ Display ]\n          }\n";
        let err = lift_one_err(src);
        assert!(
            err.contains("not a recognised derive") || err.contains("derive"),
            "error must mention derive: {err}"
        );
    }

    /// An unknown record field is refused, blocking injection of arbitrary Rust
    /// code through an unblessed vocabulary.
    #[test]
    fn foreign_struct_unknown_builder_is_refused() {
        let src = "module Main exposing (..)\n\nforeign Foo =\n          { crate = \"x\"\n          , kind = Struct { value = Int }\n          , inject = \"unsafe\"\n          }\n";
        let err = lift_one_err(src);
        assert!(
            err.contains("not a `Foreign` field") || err.contains("field"),
            "error must mention field: {err}"
        );
    }

    /// An unknown `kind` constructor (not `Struct`/`Enum`/`Closure`) is refused.
    #[test]
    fn foreign_unknown_shape_is_refused() {
        let src = "module Main exposing (..)\n\nforeign Foo =\n          { crate = \"x\"\n          , kind = Phantom\n          }\n";
        let err = lift_one_err(src);
        assert!(
            err.contains("not a `kind`") || err.contains("kind"),
            "error must mention kind: {err}"
        );
    }

    /// `scan_foreign_defines` on a non-existent directory returns three empty
    /// vectors — it must not propagate an I/O error for a missing src dir.
    #[test]
    fn scan_foreign_defines_on_missing_src_returns_empty() {
        // Use a path that is extremely unlikely to exist.
        let non_existent = std::path::Path::new("/tmp/__ipe_lane1_no_such_dir_ae3338f3");
        let (c, s, e, o) =
            scan_foreign_defines(non_existent).expect("missing dir must not be an error");
        assert!(c.is_empty() && s.is_empty() && e.is_empty() && o.is_empty());
    }

    /// `scan_foreign_defines` on a directory whose `.ipe` files have no
    /// `foreign` keyword returns four empty vectors without error.
    #[test]
    fn scan_foreign_defines_skips_files_without_foreign_keyword() {
        use std::io::Write as _;
        // Write a plain .ipe file (no `foreign` keyword) to a temp directory.
        let dir = ipe_test_temp::temp_root().join("ipe_lane1_no_foreign_test_ae3338f3");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let mut f = std::fs::File::create(dir.join("Main.ipe")).expect("create file");
        f.write_all(b"module Main exposing (..)\n\nmain = Io.println \"hello\"\n")
            .expect("write");
        drop(f);
        let (closures, structs, enums, opaques) =
            scan_foreign_defines(&dir).expect("no foreign keyword must not produce an error");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            closures.is_empty() && structs.is_empty() && enums.is_empty() && opaques.is_empty()
        );
    }

    /// A `_bindings.rs` that is a symlink is refused, never followed: the
    /// read of the FFI cache is the scan's whole input, so a link that could
    /// point it elsewhere fails the read with the link refusal itself.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write or symlink IS the failure
    fn a_symlinked_ffi_cache_binding_is_refused() {
        let root = ipe_test_temp::temp_root()
            .join(format!("ipe-held-binding-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let cache = root.join(ipe_ffi::driver::FFI_CACHE_REL);
        std::fs::create_dir_all(&cache).expect("cache dir");
        let outside = root.join("outside.rs");
        std::fs::write(&outside, "pub fn elsewhere() {}\n").expect("write link target");
        std::fs::write(cache.join("real_bindings.rs"), "pub fn f() {}\n").expect("write binding");
        let cache_rel: Vec<&str> = ipe_ffi::driver::FFI_CACHE_REL.split('/').collect();
        let held = || {
            open_project_dir(&root, &cache_rel)
                .expect("open cache")
                .expect("cache present")
        };
        let read = read_source_tree(
            held(),
            &cache,
            BINDING_SOURCES,
            FFI_CACHE_CAP,
            Unreadable::Refuse,
        )
        .expect("a cache of regular bindings reads");
        assert_eq!(read.len(), 1, "the one regular binding is read: {read:?}");

        std::os::unix::fs::symlink(&outside, cache.join("linked_bindings.rs"))
            .expect("plant symlink");
        let refused = read_source_tree(
            held(),
            &cache,
            BINDING_SOURCES,
            FFI_CACHE_CAP,
            Unreadable::Refuse,
        );
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            matches!(
                refused,
                Err(CliError::SourceRefused {
                    ref path,
                    reason: crate::io_bounded::SourceRefusal::Symlink,
                }) if path.ends_with("linked_bindings.rs")
            ),
            "a symlinked binding is refused as a symlink, got: {refused:?}"
        );
    }

    #[test]
    fn legacy_define_tables_are_rejected() {
        let toml_with_define = r#"
[package]
name = "my-pkg"

[[rust.define.struct]]
name = "Counter"
fields = { value = "i64" }
"#;
        let err = reject_legacy_define_tables(toml_with_define)
            .expect_err("must reject legacy [[rust.define.*]]");
        let msg = err.to_string();
        assert!(
            msg.contains("[[rust.define.*]] is no longer supported"),
            "diagnostic must say what is rejected: {msg}"
        );
        assert!(
            msg.contains("foreign"),
            "diagnostic must point to the replacement surface: {msg}"
        );
    }

    #[test]
    fn clean_manifest_passes_the_define_table_guard() {
        let toml_clean = r#"
[package]
name = "my-pkg"

[rust.dependencies]
iced = "=0.12.1"
"#;
        reject_legacy_define_tables(toml_clean)
            .expect("manifest without [[rust.define.*]] must pass");
    }

    /// Parse `src` and lift its first `foreign` declaration through the record
    /// reader, returning either the lifted `ForeignDefine` or the refusal
    /// message. The read is purely syntactic — no author code runs.
    fn lift_first_foreign(src: &str) -> Result<ForeignDefine, String> {
        let mut interner = ipe_intern::Interner::new();
        let module = ipe_parse::parse_module(src, &mut interner).expect("parse");
        let foreign = module.foreigns.first().expect("one foreign decl");
        let reader = ForeignReader {
            interner: &interner,
            src,
            file: std::path::Path::new("Ffi.ipe"),
        };
        reader.lift_foreign(foreign).map_err(|e| e.to_string())
    }

    #[test]
    fn record_struct_lifts_to_the_same_define_as_the_toml_path() {
        let src = "module Ffi exposing (Counter)\n\
                   foreign Counter =\n\
                   \x20   { crate = \"iced\"\n\
                   \x20   , kind = Struct { value = Int }\n\
                   \x20   , derives = [ Default, Clone ]\n\
                   \x20   }\n";
        let got = lift_first_foreign(src).expect("valid struct record");
        assert_eq!(
            got,
            ForeignDefine::Struct(ManifestDefineStruct {
                krate: "iced".to_owned(),
                ctor: "counter_new".to_owned(),
                struct_name: "Counter".to_owned(),
                fields: vec![("value".to_owned(), "Int".to_owned())],
                derives: vec!["Default".to_owned(), "Clone".to_owned()],
            })
        );
    }

    #[test]
    fn record_enum_lifts_variants_and_payloads() {
        let src = "module Ffi exposing (Message)\n\
                   foreign Message =\n\
                   \x20   { crate = \"iced\"\n\
                   \x20   , kind = Enum [ Variant \"Increment\" [], Variant \"Set\" [ Int ] ]\n\
                   \x20   , derives = [ Clone, Debug ]\n\
                   \x20   }\n";
        let got = lift_first_foreign(src).expect("valid enum record");
        assert_eq!(
            got,
            ForeignDefine::Enum(ManifestDefineEnum {
                krate: "iced".to_owned(),
                ctor: "message_new".to_owned(),
                enum_name: "Message".to_owned(),
                variants: vec![
                    ("Increment".to_owned(), vec![]),
                    ("Set".to_owned(), vec!["Int".to_owned()]),
                ],
                derives: vec!["Clone".to_owned(), "Debug".to_owned()],
            })
        );
    }

    #[test]
    fn record_closure_builds_the_canonical_signature() {
        let src = "module Ffi exposing (update)\n\
                   foreign update =\n\
                   \x20   { crate = \"iced\"\n\
                   \x20   , kind = Closure { args = [ Int, String ], returns = Int }\n\
                   \x20   }\n";
        let got = lift_first_foreign(src).expect("valid closure record");
        assert_eq!(
            got,
            ForeignDefine::Closure(ManifestDefineClosure {
                krate: "iced".to_owned(),
                name: "update".to_owned(),
                signature: "Fn(Int, String) -> Int + Send + Sync + 'static".to_owned(),
            })
        );
    }

    #[test]
    fn a_misspelt_derive_is_a_refusal() {
        let src = "module Ffi exposing (Counter)\n\
                   foreign Counter =\n\
                   \x20   { crate = \"iced\"\n\
                   \x20   , kind = Struct { value = Int }\n\
                   \x20   , derives = [ Cloen ]\n\
                   \x20   }\n";
        let err = lift_first_foreign(src).expect_err("misspelt derive must refuse");
        assert!(err.contains("Cloen"), "{err}");
        assert!(err.contains("not a recognised derive"), "{err}");
    }

    #[test]
    fn a_misspelt_kind_is_a_refusal() {
        let src = "module Ffi exposing (Counter)\n\
                   foreign Counter =\n\
                   \x20   { crate = \"iced\"\n\
                   \x20   , kind = Strcut { value = Int }\n\
                   \x20   }\n";
        let err = lift_first_foreign(src).expect_err("misspelt kind must refuse");
        assert!(err.contains("Strcut"), "{err}");
        assert!(err.contains("not a `kind`"), "{err}");
    }

    #[test]
    fn a_non_record_body_is_a_refusal() {
        let src = "module Ffi exposing (Counter)\n\
                   foreign Counter = \"iced\"\n";
        let err = lift_first_foreign(src).expect_err("a string body must refuse");
        assert!(err.contains("record literal"), "{err}");
    }

    #[test]
    fn a_missing_crate_field_is_a_refusal() {
        let src = "module Ffi exposing (Counter)\n\
                   foreign Counter =\n\
                   \x20   { kind = Struct { value = Int } }\n";
        let err = lift_first_foreign(src).expect_err("a missing crate must refuse");
        assert!(err.contains("crate"), "{err}");
    }

    #[test]
    fn an_unknown_field_is_a_refusal() {
        let src = "module Ffi exposing (Counter)\n\
                   foreign Counter =\n\
                   \x20   { crate = \"iced\"\n\
                   \x20   , kind = Struct { value = Int }\n\
                   \x20   , flavour = \"spicy\"\n\
                   \x20   }\n";
        let err = lift_first_foreign(src).expect_err("an unknown field must refuse");
        assert!(err.contains("flavour"), "{err}");
    }

    fn bwrap() -> ipe_sandbox::Mechanism {
        ipe_sandbox::Mechanism::Bwrap(PathBuf::from("/usr/bin/bwrap"))
    }

    #[test]
    fn bwrap_with_all_caps_runs_jailed() {
        assert!(matches!(
            choose_sandbox_route(&bwrap(), vec![], false),
            SandboxRoute::Jailed
        ));
        // The override is irrelevant when the jail is fully viable.
        assert!(matches!(
            choose_sandbox_route(&bwrap(), vec![], true),
            SandboxRoute::Jailed
        ));
    }

    #[test]
    fn bwrap_missing_caps_without_override_refuses() {
        assert!(matches!(
            choose_sandbox_route(&bwrap(), vec!["timeout", "prlimit"], false),
            SandboxRoute::RefuseMissingCaps { missing } if missing == vec!["timeout", "prlimit"]
        ));
    }

    #[test]
    fn bwrap_missing_caps_with_override_runs_unsandboxed() {
        // The escape hatch the missing-caps message advertises must be live on
        // exactly this configuration: bwrap present, cap helpers absent.
        assert!(matches!(
            choose_sandbox_route(&bwrap(), vec!["prlimit"], true),
            SandboxRoute::Unsandboxed
        ));
    }

    #[test]
    fn no_bwrap_without_override_refuses() {
        assert!(matches!(
            choose_sandbox_route(&ipe_sandbox::Mechanism::Refused, vec![], false),
            SandboxRoute::RefuseNoBwrap
        ));
    }

    #[test]
    fn no_bwrap_with_override_runs_unsandboxed() {
        assert!(matches!(
            choose_sandbox_route(&ipe_sandbox::Mechanism::Refused, vec![], true),
            SandboxRoute::Unsandboxed
        ));
    }

    /// An escape sequence in a dependency name cannot swallow the reasons after
    /// it nor the closing no-sandbox warning: the name is terminal-safe from the
    /// moment the refusal is built, and the relay's own pass stops any
    /// sequence at the line break.
    #[test]
    fn an_escape_in_a_dependency_name_keeps_the_refusal_tail() {
        use ipe_ffi::capability_scan::{Capability, RefuseReason};
        let refusal = WrapperRefusal {
            reasons: vec![
                RefuseReason::NonStdDependency {
                    name: crate::style::TerminalSafe::sanitize("dep\u{1b}]8;;https://evil"),
                },
                RefuseReason::DeclaredUnenforceable {
                    cap: Capability::Network,
                },
            ],
            proposed: BTreeSet::new(),
        };
        let relayed = crate::text::Message::relay(&refusal).to_string();
        assert!(
            relayed.contains("depends on `dep` — a dependency"),
            "{relayed:?}"
        );
        assert!(relayed.contains("  - declares `"), "{relayed:?}");
        assert!(
            relayed.contains("inferred from its source: (none"),
            "{relayed:?}"
        );
        assert!(
            relayed.contains("Ipê has no runtime sandbox around the emitted app yet"),
            "{relayed:?}"
        );
        assert!(!relayed.contains("evil"), "{relayed:?}");
    }
}

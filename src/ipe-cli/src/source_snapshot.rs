//! One held read of a project's source tree: the only reader of program text.
//!
//! [`SourceSnapshot::read`] walks the held `src/` (and `tests/`) of a
//! [`ProjectRoot`] through directory handles, never through a path: names are
//! listed through the held handle, each subdirectory is opened without
//! following a link beneath its parent, and each module file is opened
//! without following a link and read under a byte cap. A link anywhere in the
//! tree (on Windows, any reparse point) refuses the whole read, so no link has
//! a representation in the snapshot. A module path is the exact listed
//! spelling of its file, so a name that differs from an import only in case
//! never satisfies it. The FFI catalog is read once, its artifacts through
//! the cache directory the root holds open, never by a path; every consumer
//! then sees these bytes and that catalog and no others. A wrapper crate's
//! directory is the exception: it is jailed and bound by path, as `cargo`
//! later builds it.
//!
//! The build sees `src/` and what it injects, never `tests/`: the stdlib
//! closure and the FFI preparation run over `src/` alone, so no byte under
//! `tests/` can add, mask or refuse a module of the build. Every `tests/`
//! module is read, bounded and link-checked with the rest, and held apart.
//! A test program compiles in its own universe ([`SourceSnapshot::test_view`]):
//! a separate value built from the same text and the same catalog, never
//! merged into the build's modules.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ipe_fs_open::{ByteCap, EntryCap, EntryName, FileKind};

use crate::CliError;
use crate::api_surface::ModulePath;
use crate::ffi::{Catalog, FfiPrep, load_catalog, prepare};
use crate::io_bounded::{self, SourceRefusal};
use crate::output_dir::OutputRefusal;
use crate::output_dir::held::HeldDir;
use crate::project::{
    MAX_DISCOVERED_MODULES, MAX_DISCOVERY_DEPTH, MAX_DISCOVERY_ENTRIES, ModulePathShape,
    ModuleSources, extract_imports_from_source, inject_compiled_std_closure, module_path_shape,
};
use crate::project_root::{EntrySet, ProjectRoot, SourceDir};

/// The extension of an Ipê module file, matched exactly.
const MODULE_EXT: &str = ".ipe";

/// Where a snapshot module's text came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceOrigin {
    /// A file of the project, under this directory.
    Own(SourceDir),
    /// Compiled-source stdlib text injected for an import.
    Stdlib,
    /// An installed crate's FFI interface module.
    FfiInterface,
}

/// One module's text and where it came from.
#[derive(Debug, Clone)]
pub struct SnapshotModule {
    origin: SourceOrigin,
    path: PathBuf,
    text: Arc<str>,
}

impl SnapshotModule {
    fn new(origin: SourceOrigin, path: PathBuf, text: String) -> Self {
        Self {
            origin,
            path,
            text: Arc::from(text),
        }
    }

    /// Where the text came from.
    #[must_use]
    pub const fn origin(&self) -> SourceOrigin {
        self.origin
    }

    /// The path the text is reported under; it is never read again.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The module's text, as read.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// Ceiling on the bytes summed over every module file one snapshot reads.
///
/// 256 MiB is far above any real project while refusing a tree of many
/// cap-sized files that would otherwise be held in memory at once.
pub const SOURCE_TREE_READ_CAP: u64 = 256 * 1024 * 1024;

/// The ceilings one snapshot read is held to.
///
/// A directory is at depth 0 when it is `src/` or `tests/`; a directory past
/// `depth`, a module past `modules`, a listed entry past `entries`, a file
/// past `file_cap` bytes or module text past `total_bytes` summed over `src/`
/// and `tests/` refuses the read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    depth: usize,
    modules: usize,
    entries: usize,
    file_cap: ByteCap,
    total_bytes: u64,
}

impl Limits {
    /// The discovery ceilings and the source read cap every build is held to.
    pub const DEFAULT: Self = Self {
        depth: MAX_DISCOVERY_DEPTH,
        modules: MAX_DISCOVERED_MODULES,
        entries: MAX_DISCOVERY_ENTRIES,
        file_cap: io_bounded::SOURCE_CAP,
        total_bytes: SOURCE_TREE_READ_CAP,
    };

    /// These limits with the directory depth ceiling `depth`.
    #[cfg(test)]
    #[must_use]
    pub const fn depth(self, depth: usize) -> Self {
        Self { depth, ..self }
    }

    /// These limits with the module count ceiling `modules`.
    #[cfg(test)]
    #[must_use]
    pub const fn modules(self, modules: usize) -> Self {
        Self { modules, ..self }
    }

    /// These limits with the listed-entry ceiling `entries`.
    #[cfg(test)]
    #[must_use]
    pub const fn entries(self, entries: usize) -> Self {
        Self { entries, ..self }
    }

    /// These limits with the per-file byte cap `file_cap`.
    #[cfg(test)]
    #[must_use]
    pub const fn file_cap(self, file_cap: ByteCap) -> Self {
        Self { file_cap, ..self }
    }

    /// These limits with the summed module byte ceiling `total_bytes`.
    #[cfg(test)]
    #[must_use]
    pub const fn total_bytes(self, total_bytes: u64) -> Self {
        Self {
            total_bytes,
            ..self
        }
    }
}

/// Every module text of one build, read once from held handles.
///
/// Fields are private: [`SourceSnapshot::read`] is the only mint.
pub struct SourceSnapshot {
    modules: BTreeMap<ModulePath, SnapshotModule>,
    tests: BTreeMap<ModulePath, SnapshotModule>,
    ffi: FfiPrep,
    catalog: Catalog,
}

impl SourceSnapshot {
    /// Read every module of `root` under `limits`, inject the stdlib closure and prepare FFI once.
    ///
    /// `src/` is walked first, then `tests/` when present. The build's
    /// modules are those of `src/` with the stdlib closure and the FFI
    /// interfaces they reach; `tests/` modules are held apart
    /// ([`SourceSnapshot::tests`]), so a `tests/` module never masks, adds
    /// or refuses one of the build. The FFI catalog is read once through
    /// the root's held cache directory ([`ProjectRoot::cache_dir`]) and
    /// kept, so a test view prepares over the same catalog.
    ///
    /// # Errors
    /// [`CliError::SymlinkInSource`] for a link (on Windows, any reparse
    /// point) anywhere in the tree, including one swapped in between the
    /// listing and the read; [`CliError::DiscoveryLimitReached`] past the
    /// depth, module, entry or summed byte ceiling; [`CliError::FileTooLarge`]
    /// past the file cap; [`CliError::DeviceNamedModule`] for a module path
    /// naming a Windows device; [`CliError::SourceRefused`] for a module file
    /// that is not a regular file or may not be read; [`CliError::Io`] for
    /// text that is not UTF-8 or another failure; every refusal of
    /// [`ProjectRoot::cache_dir`], [`load_catalog`] and [`prepare`].
    pub fn read(root: &ProjectRoot, limits: Limits) -> Result<Self, CliError> {
        let mut walk = Walk::new(limits);
        walk.tree(root.src(), SourceDir::Src)?;
        if let Some(tests) = root.tests() {
            walk.tree(tests, SourceDir::Tests)?;
        }
        let Walk {
            src: sources,
            tests,
            ..
        } = walk;
        let own = sources
            .keys()
            .map(|module| (module.clone(), SourceDir::Src))
            .collect();
        let catalog = load_catalog(root.cache_dir()?.as_ref())?;
        let (modules, ffi) = universe(sources, &own, &catalog)?;
        let tests = tests
            .into_iter()
            .map(|(module, (path, text))| {
                let held = SnapshotModule::new(SourceOrigin::Own(SourceDir::Tests), path, text);
                (module, held)
            })
            .collect();
        Ok(Self {
            modules,
            tests,
            ffi,
            catalog,
        })
    }

    /// The `tests/` module `module` as the entry of a test program, when the snapshot holds it.
    #[must_use]
    pub fn test_entry(&self, module: &[String]) -> Option<TestEntry<'_>> {
        self.tests
            .get_key_value(module)
            .map(|(module, held)| TestEntry {
                snapshot: self,
                module,
                held,
            })
    }

    /// The universe the test program `entry` compiles in, separate from the build's modules.
    ///
    /// Its project modules are, first admitted wins: the entry, then every
    /// `src/` module, then every other `tests/` module. So the entry masks
    /// a `src/` module of its path, and a `src/` module masks any other
    /// `tests/` module of its path. The stdlib closure and the FFI
    /// preparation run again over that universe, with the catalog this
    /// snapshot read: nothing is read from disk.
    ///
    /// # Errors
    /// Every refusal of [`prepare`] over the test universe, such as an
    /// asserted call into a crate the catalog does not install.
    pub fn test_view(entry: TestEntry<'_>) -> Result<TestView, CliError> {
        let TestEntry {
            snapshot,
            module: entry,
            held: entry_held,
        } = entry;
        let mut own = BTreeMap::new();
        let mut sources = ModuleSources::new();
        admit(&mut own, &mut sources, entry, entry_held, SourceDir::Tests);
        for (module, held) in &snapshot.modules {
            if held.origin == SourceOrigin::Own(SourceDir::Src) {
                admit(&mut own, &mut sources, module, held, SourceDir::Src);
            }
        }
        for (module, held) in &snapshot.tests {
            admit(&mut own, &mut sources, module, held, SourceDir::Tests);
        }
        let (modules, ffi) = universe(sources, &own, &snapshot.catalog)?;
        Ok(TestView {
            entry: entry.clone(),
            modules,
            ffi,
        })
    }

    /// The modules the `dir` module `module` is analysed over, when the snapshot holds a `tests/` one.
    ///
    /// A `src/` module is analysed over the build's modules
    /// ([`SourceSnapshot::modules`]); a `tests/` module over its own
    /// [`SourceSnapshot::test_view`], never merged into the build's. `None`
    /// when `dir` is `tests/` and the snapshot holds no `tests/` module
    /// `module`; whether a `src/` module is held is the caller's to check
    /// against each module's [`SourceOrigin`].
    ///
    /// # Errors
    /// Every refusal of [`SourceSnapshot::test_view`].
    pub fn view<'s>(
        &'s self,
        dir: SourceDir,
        module: &'s [String],
    ) -> Result<Option<ModuleView<'s>>, CliError> {
        match dir {
            SourceDir::Src => Ok(Some(ModuleView::Build {
                modules: &self.modules,
                entry: module,
            })),
            SourceDir::Tests => self
                .test_entry(module)
                .map(Self::test_view)
                .transpose()
                .map(|view| view.map(|view| ModuleView::Test(Box::new(view)))),
        }
    }

    /// Every module the build sees, keyed by module path.
    #[must_use]
    pub const fn modules(&self) -> &BTreeMap<ModulePath, SnapshotModule> {
        &self.modules
    }

    /// Every `tests/` module, keyed by module path, including one whose path a `src/` module has.
    #[must_use]
    pub const fn tests(&self) -> &BTreeMap<ModulePath, SnapshotModule> {
        &self.tests
    }

    /// The module `module`, when the snapshot holds it.
    #[must_use]
    pub fn module(&self, module: &[String]) -> Option<&SnapshotModule> {
        self.modules.get(module)
    }

    /// The FFI preparation made over this snapshot's text.
    #[must_use]
    pub const fn ffi(&self) -> &FfiPrep {
        &self.ffi
    }

    /// The FFI catalog read once through the root's held cache directory.
    #[must_use]
    pub const fn catalog(&self) -> &Catalog {
        &self.catalog
    }
}

/// A `tests/` module of one snapshot, named as a test program's entry.
///
/// Fields are private: [`SourceSnapshot::test_entry`] is the only mint, so
/// an entry is always a `tests/` module of the snapshot it is viewed in.
#[derive(Debug, Clone, Copy)]
pub struct TestEntry<'s> {
    snapshot: &'s SourceSnapshot,
    module: &'s ModulePath,
    held: &'s SnapshotModule,
}

impl TestEntry<'_> {
    /// The entry's module path.
    #[must_use]
    pub const fn module(&self) -> &ModulePath {
        self.module
    }
}

/// Every module one test program sees: its own universe, never the build's.
///
/// Fields are private: [`SourceSnapshot::test_view`] is the only mint.
pub struct TestView {
    entry: ModulePath,
    modules: BTreeMap<ModulePath, SnapshotModule>,
    ffi: FfiPrep,
}

impl TestView {
    /// The test program's entry module.
    #[must_use]
    pub const fn entry(&self) -> &ModulePath {
        &self.entry
    }

    /// Every module the test program sees, keyed by module path.
    #[must_use]
    pub const fn modules(&self) -> &BTreeMap<ModulePath, SnapshotModule> {
        &self.modules
    }

    /// The module `module`, when the test universe holds it.
    #[must_use]
    pub fn module(&self, module: &[String]) -> Option<&SnapshotModule> {
        self.modules.get(module)
    }

    /// The FFI preparation made over the test universe.
    #[must_use]
    pub const fn ffi(&self) -> &FfiPrep {
        &self.ffi
    }
}

/// The modules one project module is analysed over, and the entry it names in them.
///
/// Minted by [`SourceSnapshot::view`].
pub enum ModuleView<'s> {
    /// A `src/` module over the build's modules.
    Build {
        /// Every module the build sees.
        modules: &'s BTreeMap<ModulePath, SnapshotModule>,
        /// The module analysed.
        entry: &'s [String],
    },
    /// A `tests/` module over its own test universe.
    Test(Box<TestView>),
}

impl ModuleView<'_> {
    /// Every module the analysed module sees, keyed by module path.
    #[must_use]
    pub fn modules(&self) -> &BTreeMap<ModulePath, SnapshotModule> {
        match self {
            Self::Build { modules, .. } => modules,
            Self::Test(view) => view.modules(),
        }
    }

    /// The analysed module.
    #[must_use]
    pub fn entry(&self) -> &[String] {
        match self {
            Self::Build { entry, .. } => entry,
            Self::Test(view) => view.entry(),
        }
    }
}

impl std::fmt::Debug for TestView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestView")
            .field("entry", &self.entry)
            .field("modules", &self.modules)
            .field("ffi_injected", &self.ffi.injected)
            .finish_non_exhaustive()
    }
}

/// Add `held` to a universe's project modules under `dir`, unless a module of its path is already in.
fn admit(
    own: &mut BTreeMap<ModulePath, SourceDir>,
    sources: &mut ModuleSources,
    module: &ModulePath,
    held: &SnapshotModule,
    dir: SourceDir,
) {
    if let std::collections::btree_map::Entry::Vacant(slot) = own.entry(module.clone()) {
        slot.insert(dir);
        sources.insert(
            module.clone(),
            (held.path().to_path_buf(), held.text().to_owned()),
        );
    }
}

/// Inject the stdlib closure into `sources` and prepare FFI over `catalog`, giving each module its origin.
///
/// `own` names the directory of every project module of `sources`.
/// Injection and preparation each insert only keys absent from `sources`
/// and record what they inserted; a module's origin is the record that
/// holds it, the project's first.
fn universe(
    mut sources: ModuleSources,
    own: &BTreeMap<ModulePath, SourceDir>,
    catalog: &Catalog,
) -> Result<(BTreeMap<ModulePath, SnapshotModule>, FfiPrep), CliError> {
    let stdlib = inject_compiled_std_closure(&mut sources, &mut Vec::new());
    let ffi = prepare(&mut sources, catalog)?;
    let modules = sources
        .into_iter()
        .filter_map(|(module, (path, text))| {
            let origin = if let Some(dir) = own.get(&module) {
                SourceOrigin::Own(*dir)
            } else if stdlib.contains(&module) {
                SourceOrigin::Stdlib
            } else if ffi.injected.contains(&module) {
                SourceOrigin::FfiInterface
            } else {
                // Text no step recorded inserting earns no origin and is
                // never compiled: an import of it resolves to nothing.
                return None;
            };
            Some((module, SnapshotModule::new(origin, path, text)))
        })
        .collect();
    Ok((modules, ffi))
}

/// A hook run between listing a module file and reading it, so a test can swap the entry.
#[cfg(test)]
type BeforeRead = Box<dyn FnMut(&Path)>;

#[cfg(test)]
thread_local! {
    static BEFORE_READ: std::cell::RefCell<Option<BeforeRead>> = std::cell::RefCell::new(None);
}

/// Run the test hook, if one is set, on `path` before it is read.
#[cfg(test)]
fn before_read(path: &Path) {
    BEFORE_READ.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook(path);
        }
    });
}

/// The state of one held walk.
struct Walk {
    limits: Limits,
    examined: usize,
    read: usize,
    bytes: u64,
    src: ModuleSources,
    tests: ModuleSources,
}

impl Walk {
    const fn new(limits: Limits) -> Self {
        Self {
            limits,
            examined: 0,
            read: 0,
            bytes: 0,
            src: ModuleSources::new(),
            tests: ModuleSources::new(),
        }
    }

    /// Walk the held tree `top`, reading each module file under it.
    fn tree(&mut self, top: &HeldDir, dir: SourceDir) -> Result<(), CliError> {
        self.directory(top, 0, Some(&[]), dir)
    }

    /// List `held`, walk each subdirectory and read each module file.
    ///
    /// Depth first, so the handles held open at once are one per level, at
    /// most the depth ceiling plus one; the recursion is bounded by the same
    /// ceiling. `segments` name `held` as a module path prefix, `None` when
    /// some name on the way is not UTF-8: nothing below it is a module.
    fn directory(
        &mut self,
        held: &HeldDir,
        depth: usize,
        segments: Option<&[String]>,
        dir: SourceDir,
    ) -> Result<(), CliError> {
        if depth > self.limits.depth {
            return Err(CliError::DiscoveryLimitReached {
                detail: format!(
                    "directory tree exceeded the {}-level depth ceiling at `{}`",
                    self.limits.depth,
                    held.path().display()
                ),
            });
        }
        let names = held.list_names(self.listing_cap())?;
        self.examined = self.examined.saturating_add(names.len());
        if self.examined > self.limits.entries {
            return Err(CliError::DiscoveryLimitReached {
                detail: format!(
                    "source tree holds more than {} entries at `{}`",
                    self.limits.entries,
                    held.path().display()
                ),
            });
        }
        for (name, kind) in names {
            let path = held.path().join(name.as_os_str());
            match kind {
                FileKind::Symlink => return Err(CliError::SymlinkInSource { path }),
                FileKind::Dir => {
                    let child = held
                        .child(name.as_os_str())
                        .map_err(|error| link_refusal(error, &path))?;
                    if let Some(child) = child {
                        let below = segments.and_then(|segments| {
                            name.as_os_str().to_str().map(|segment| {
                                let mut below = segments.to_vec();
                                below.push(segment.to_owned());
                                below
                            })
                        });
                        self.directory(&child, depth.saturating_add(1), below.as_deref(), dir)?;
                    }
                }
                FileKind::Regular
                | FileKind::Fifo
                | FileKind::Socket
                | FileKind::Device
                | FileKind::Other => {
                    let Some(module) = module_of(segments, &name, &path)? else {
                        continue;
                    };
                    if kind != FileKind::Regular {
                        return Err(io_bounded::source_refused(
                            &path,
                            SourceRefusal::NotRegularFile,
                        ));
                    }
                    self.module(held, &name, path, module, dir)?;
                }
            }
        }
        Ok(())
    }

    /// The cap one listing is held to: the entries the walk may still examine.
    ///
    /// Never zero, so an empty directory lists at an exhausted budget; a
    /// listing past what remains is refused after it returns.
    fn listing_cap(&self) -> EntryCap {
        let remaining = self.limits.entries.saturating_sub(self.examined);
        let remaining = NonZeroU32::new(u32::try_from(remaining).unwrap_or(u32::MAX));
        EntryCap::from_nonzero(remaining.unwrap_or(NonZeroU32::MIN))
    }

    /// Read the module file `name` of `held` as `module`.
    fn module(
        &mut self,
        held: &HeldDir,
        name: &EntryName,
        path: PathBuf,
        module: ModulePath,
        dir: SourceDir,
    ) -> Result<(), CliError> {
        if self.read >= self.limits.modules {
            return Err(CliError::DiscoveryLimitReached {
                detail: format!(
                    "source tree holds more than {} modules at `{}`",
                    self.limits.modules,
                    held.path().display()
                ),
            });
        }
        #[cfg(test)]
        before_read(&path);
        // A read never buffers past what the summed ceiling leaves; a file
        // the remainder cannot hold is the summed refusal, not the file cap's.
        let remaining = self.limits.total_bytes.saturating_sub(self.bytes);
        let left = ByteCap::from_nonzero(NonZeroU64::new(remaining).unwrap_or(NonZeroU64::MIN));
        let cap = self.limits.file_cap.min(left);
        let text = held
            .read_file_capped(name, cap)
            .map_err(|error| match error {
                CliError::FileTooLarge { .. } if cap < self.limits.file_cap => {
                    self.total_refusal(&path)
                }
                other => link_refusal(other, &path),
            })?;
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(text.len()).unwrap_or(u64::MAX));
        if self.bytes > self.limits.total_bytes {
            return Err(self.total_refusal(&path));
        }
        self.read = self.read.saturating_add(1);
        let tree = match dir {
            SourceDir::Src => &mut self.src,
            SourceDir::Tests => &mut self.tests,
        };
        tree.insert(module, (path, text));
        Ok(())
    }

    /// The refusal of a read that would sum module text past the byte ceiling.
    fn total_refusal(&self, path: &Path) -> CliError {
        CliError::DiscoveryLimitReached {
            detail: format!(
                "source tree holds more than {} bytes of module text at `{}`",
                self.limits.total_bytes,
                path.display()
            ),
        }
    }
}

/// The module path of the file `name` in a directory named by `segments`.
///
/// `Ok(None)` when it is no module: not exactly `.ipe`-suffixed, not UTF-8,
/// or not a module path ([`module_path_shape`]).
///
/// # Errors
/// [`CliError::DeviceNamedModule`] when a segment is a Windows device name.
fn module_of(
    segments: Option<&[String]>,
    name: &EntryName,
    path: &Path,
) -> Result<Option<ModulePath>, CliError> {
    let Some(stem) = name
        .as_os_str()
        .to_str()
        .and_then(|name| name.strip_suffix(MODULE_EXT))
    else {
        return Ok(None);
    };
    let Some(segments) = segments else {
        return Ok(None);
    };
    let mut module = segments.to_vec();
    module.push(stem.to_owned());
    let device = match module_path_shape(&module) {
        ModulePathShape::NotModule => return Ok(None),
        ModulePathShape::DeviceNamed(segment) => Some(segment.to_owned()),
        ModulePathShape::Module => None,
    };
    device.map_or(Ok(Some(module)), |segment| {
        Err(CliError::DeviceNamedModule {
            path: path.to_path_buf(),
            segment,
        })
    })
}

/// `error` with every link refusal on `path` reported as [`CliError::SymlinkInSource`].
fn link_refusal(error: CliError, path: &Path) -> CliError {
    match error {
        CliError::OutputRefused(OutputRefusal::Symlink(_))
        | CliError::SourceRefused {
            reason: SourceRefusal::Symlink,
            ..
        } => CliError::SymlinkInSource {
            path: path.to_path_buf(),
        },
        other => other,
    }
}

impl std::fmt::Debug for SourceSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceSnapshot")
            .field("modules", &self.modules)
            .field("ffi_injected", &self.ffi.injected)
            .finish_non_exhaustive()
    }
}

/// The modules one build compiles: a closed set over a snapshot.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the build reads its module set through this snapshot once it is wired in"
    )
)]
#[derive(Debug, Clone)]
pub struct ModuleSet<'s> {
    snapshot: &'s SourceSnapshot,
    members: BTreeSet<&'s ModulePath>,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the build reads its module set through this snapshot once it is wired in"
    )
)]
impl<'s> ModuleSet<'s> {
    /// The modules `entries` builds from `snapshot`, closed under import.
    ///
    /// Programs build every module under `src/`; a library builds the reach
    /// of its exposed modules. A `tests/` module is never a member: the
    /// snapshot holds `tests/` apart from the build's modules.
    ///
    /// # Errors
    /// [`CliError::EntryMissing`] or [`CliError::ExposedModuleMissing`] when an
    /// entry is not a `src/` module of the snapshot.
    pub fn of(entries: &EntrySet, snapshot: &'s SourceSnapshot) -> Result<Self, CliError> {
        let is_src = |module: &[String]| {
            snapshot
                .module(module)
                .is_some_and(|m| m.origin == SourceOrigin::Own(SourceDir::Src))
        };
        let roots: Vec<&'s ModulePath> = match entries {
            EntrySet::Programs(programs) => {
                if let Some(missing) = programs.iter().find(|entry| !is_src(entry.module())) {
                    return Err(CliError::EntryMissing {
                        entry: format!("{}{MODULE_EXT}", missing.module().join("/")),
                    });
                }
                snapshot
                    .modules
                    .iter()
                    .filter(|(_, m)| m.origin == SourceOrigin::Own(SourceDir::Src))
                    .map(|(module, _)| module)
                    .collect()
            }
            EntrySet::Library(exposed) => {
                let mut roots = Vec::new();
                for module in exposed.iter() {
                    let Some((key, _)) = snapshot
                        .modules
                        .get_key_value(module)
                        .filter(|_| is_src(module))
                    else {
                        return Err(CliError::ExposedModuleMissing {
                            module: module.join("."),
                        });
                    };
                    roots.push(key);
                }
                roots
            }
        };
        let mut set = Self {
            snapshot,
            members: BTreeSet::new(),
        };
        set.close(roots);
        Ok(set)
    }

    /// Add `roots` and every snapshot module they import, transitively.
    fn close(&mut self, roots: Vec<&'s ModulePath>) {
        let mut queue: VecDeque<&'s ModulePath> = roots.into();
        while let Some(module) = queue.pop_front() {
            if !self.members.insert(module) {
                continue;
            }
            let Some(entry) = self.snapshot.modules.get(module) else {
                continue;
            };
            for import in extract_imports_from_source(entry.text()) {
                if let Some((key, _)) = self.snapshot.modules.get_key_value(&import)
                    && !self.members.contains(key)
                {
                    queue.push_back(key);
                }
            }
        }
    }

    /// Whether `module` is a member.
    #[must_use]
    pub fn contains(&self, module: &[String]) -> bool {
        self.members.contains(&module.to_vec())
    }

    /// Every member and its snapshot module, in module-path order.
    pub fn members(&self) -> impl Iterator<Item = (&'s ModulePath, &'s SnapshotModule)> + '_ {
        self.members
            .iter()
            .filter_map(|module| self.snapshot.modules.get_key_value(*module))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_root::{ScratchRoot, SourceTree};

    const MAIN: &str = "module Main exposing (main)\n\nmain =\n    1\n";

    const PALETTE_MAIN: &str =
        "module Main exposing (main)\n\nimport Ipe.Palette\n\nmain =\n    1\n";

    fn module_source(name: &str, imports: &[&str]) -> String {
        let imports: String = imports
            .iter()
            .map(|import| ["import ", import, "\n"].concat())
            .collect();
        format!("module {name} exposing (x)\n\n{imports}\nx =\n    1\n")
    }

    fn path(module: &str) -> ModulePath {
        module.split('.').map(str::to_owned).collect()
    }

    fn resolve(tree: &SourceTree) -> ScratchRoot {
        tree.resolve().expect("resolve the tree")
    }

    fn read(scratch: &ScratchRoot, limits: Limits) -> Result<SourceSnapshot, CliError> {
        SourceSnapshot::read(scratch.root(), limits)
    }

    fn src(scratch: &ScratchRoot) -> PathBuf {
        scratch.root().path().join("src")
    }

    fn is_symlink_refusal(result: &Result<SourceSnapshot, CliError>) -> bool {
        matches!(result, Err(CliError::SymlinkInSource { .. }))
    }

    fn is_limit_refusal(result: &Result<SourceSnapshot, CliError>) -> bool {
        matches!(result, Err(CliError::DiscoveryLimitReached { .. }))
    }

    /// A module `name` whose one definition is an asserted call into the crate `tm`.
    fn asserted_module(name: &str) -> String {
        format!(
            "module {name} exposing (shifted)\nimport Rust.Ffi\n\n\
             shifted : Int -> Result Error Int\nshifted =\n    Rust.Ffi.call \"tm::shift\"\n"
        )
    }

    /// The test view of the `tests/` module `entry`.
    fn test_view(snapshot: &SourceSnapshot, entry: &str) -> Result<TestView, CliError> {
        let entry = snapshot.test_entry(&path(entry)).expect("a tests/ module");
        SourceSnapshot::test_view(entry)
    }

    /// The text and origin of `module` in `view`.
    fn seen<'v>(view: &'v TestView, module: &str) -> Option<(&'v str, SourceOrigin)> {
        view.module(&path(module))
            .map(|held| (held.text(), held.origin()))
    }

    /// Install the crate `slug` in the FFI cache of the project at `project`.
    #[cfg(unix)]
    fn install_crate(project: &Path, slug: &str) {
        let cache = ipe_ffi::driver::FfiCache::at_project_root(project);
        let inspection = format!(
            r#"{{"pkg":"{slug}","name":"{slug}","version":"0.1.0","functions":[{{"name":"shift","params":[{{"name":"n","type":"i64"}}],"results":[{{"name":"","type":"i64"}}],"effect":"pure"}}],"constants":[],"errors":[],"transitiveDeps":[{{"ident":"{slug}","name":"{slug}","version":"0.1.0"}}]}}"#
        );
        let installed = ipe_ffi::driver::install_from_inspection(&cache, &inspection);
        assert!(installed.is_ok(), "install {slug}: {installed:?}");
    }

    /// The slugs of the crates `prep` was prepared over.
    #[cfg(unix)]
    fn slugs(prep: &FfiPrep) -> Vec<&str> {
        prep.catalog.iter().map(|c| c.slug.as_str()).collect()
    }

    /// Every own module is read once, with its exact text and directory.
    #[test]
    fn reads_every_own_module_with_its_origin() {
        let util = module_source("Util", &[]);
        let spec = module_source("UtilSpec", &["Util"]);
        let scratch = resolve(
            &SourceTree::main(MAIN)
                .module("Util", &util)
                .test_module("UtilSpec", &spec),
        );
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        let main = snapshot.module(&path("Main")).expect("Main read");
        assert_eq!(main.text(), MAIN);
        assert_eq!(main.origin(), SourceOrigin::Own(SourceDir::Src));
        assert_eq!(main.path(), src(&scratch).join("Main.ipe"));
        let util_module = snapshot.module(&path("Util")).expect("Util read");
        assert_eq!(util_module.text(), util);
        assert!(snapshot.module(&path("UtilSpec")).is_none());
        let spec_module = snapshot
            .tests()
            .get(&path("UtilSpec"))
            .expect("UtilSpec read");
        assert_eq!(spec_module.origin(), SourceOrigin::Own(SourceDir::Tests));
        assert_eq!(spec_module.text(), spec);
        assert!(snapshot.ffi().injected.is_empty());
        assert!(snapshot.ffi().emit.is_none());
        assert!(format!("{snapshot:?}").contains("Main"));
    }

    /// A stdlib import is injected and marked as stdlib, never as the project's.
    #[test]
    fn injected_stdlib_modules_are_marked_stdlib() {
        let scratch = resolve(&SourceTree::main(PALETTE_MAIN));
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        let palette = snapshot
            .module(&path("Ipe.Palette"))
            .expect("the imported stdlib module is injected");
        assert_eq!(palette.origin(), SourceOrigin::Stdlib);
        let set = ModuleSet::of(scratch.root().entries(), &snapshot).expect("module set");
        assert!(set.contains(&path("Ipe.Palette")));
    }

    /// A project file on a stdlib module path stays the project's, never stdlib.
    #[test]
    fn project_file_on_a_stdlib_path_stays_own() {
        let squat = module_source("Ipe.Palette", &[]);
        let scratch = resolve(&SourceTree::main(PALETTE_MAIN).module("Ipe.Palette", &squat));
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        let palette = snapshot.module(&path("Ipe.Palette")).expect("read");
        assert_eq!(palette.origin(), SourceOrigin::Own(SourceDir::Src));
        assert_eq!(palette.text(), squat);
    }

    /// A symbolic link to a file under `src/` refuses the read; a plain file in its place reads.
    #[cfg(unix)]
    #[test]
    fn symlinked_file_under_src_is_refused() {
        use crate::output_dir::test_links::plant_link;
        let scratch = resolve(&SourceTree::main(MAIN));
        assert!(read(&scratch, Limits::DEFAULT).is_ok());
        let outside = scratch.root().path().join("Outside.ipe");
        std::fs::write(&outside, module_source("Linked", &[])).expect("write target");
        plant_link(&outside, &src(&scratch).join("Linked.ipe"));
        let result = read(&scratch, Limits::DEFAULT);
        assert!(
            matches!(&result, Err(CliError::SymlinkInSource { path }) if path.ends_with("Linked.ipe"))
        );
    }

    /// A link that is no module file at all still refuses the read.
    #[cfg(unix)]
    #[test]
    fn symlink_that_names_no_module_is_refused() {
        use crate::output_dir::test_links::plant_link;
        let scratch = resolve(&SourceTree::main(MAIN));
        plant_link(
            &scratch.root().path().join("package.ipe"),
            &src(&scratch).join("notes.txt"),
        );
        assert!(is_symlink_refusal(&read(&scratch, Limits::DEFAULT)));
    }

    /// A symbolic link to a directory under `src/` refuses the read, its contents unread.
    #[cfg(unix)]
    #[test]
    fn symlinked_dir_under_src_is_refused() {
        use crate::output_dir::test_links::plant_link;
        let scratch = resolve(&SourceTree::main(MAIN));
        let outside = scratch.root().path().join("elsewhere");
        std::fs::create_dir(&outside).expect("create target dir");
        std::fs::write(outside.join("B.ipe"), module_source("A.B", &[])).expect("write");
        plant_link(&outside, &src(&scratch).join("A"));
        let result = read(&scratch, Limits::DEFAULT);
        assert!(matches!(&result, Err(CliError::SymlinkInSource { path }) if path.ends_with("A")));
    }

    /// A symbolic link under `tests/` refuses the read as one under `src/` does.
    #[cfg(unix)]
    #[test]
    fn symlinked_file_under_tests_is_refused() {
        use crate::output_dir::test_links::plant_link;
        let scratch = resolve(
            &SourceTree::main(MAIN).test_module("MainSpec", &module_source("MainSpec", &[])),
        );
        assert!(read(&scratch, Limits::DEFAULT).is_ok());
        plant_link(
            &src(&scratch).join("Main.ipe"),
            &scratch.root().path().join("tests").join("Other.ipe"),
        );
        assert!(is_symlink_refusal(&read(&scratch, Limits::DEFAULT)));
    }

    /// A junction under `src/` refuses the read.
    #[cfg(windows)]
    #[test]
    fn junction_under_src_is_refused() {
        use crate::output_dir::test_links::junction_in_place;
        let scratch = resolve(&SourceTree::main(MAIN));
        let outside = scratch.root().path().join("elsewhere");
        std::fs::create_dir(&outside).expect("create target dir");
        std::fs::write(outside.join("B.ipe"), module_source("A.B", &[])).expect("write");
        let at = src(&scratch).join("A");
        std::fs::create_dir(&at).expect("create junction dir");
        assert!(read(&scratch, Limits::DEFAULT).is_ok());
        junction_in_place(&at, &outside);
        assert!(is_symlink_refusal(&read(&scratch, Limits::DEFAULT)));
    }

    /// A file swapped for a link between listing and reading is refused, the link not followed.
    #[cfg(unix)]
    #[test]
    fn file_swapped_for_symlink_after_listing_is_refused() {
        use crate::output_dir::test_links::plant_link;
        const SECRET: &str = "module Util exposing (x)\n\nx =\n    \"secret\"\n";
        let scratch = resolve(&SourceTree::main(MAIN).module("Util", &module_source("Util", &[])));
        let target = scratch.root().path().join("secret.ipe");
        std::fs::write(&target, SECRET).expect("write target");
        let control = read(&scratch, Limits::DEFAULT).expect("read before the swap");
        assert!(control.module(&path("Util")).is_some());
        let swapped = std::rc::Rc::new(std::cell::Cell::new(false));
        let seen = std::rc::Rc::clone(&swapped);
        let link_target = target.clone();
        BEFORE_READ.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |at: &Path| {
                if at.ends_with("Util.ipe") {
                    std::fs::remove_file(at).expect("remove listed file");
                    plant_link(&link_target, at);
                    seen.set(true);
                }
            }));
        });
        let result = read(&scratch, Limits::DEFAULT);
        BEFORE_READ.with(|hook| *hook.borrow_mut() = None);
        assert!(swapped.get(), "the hook ran between listing and reading");
        assert!(
            matches!(&result, Err(CliError::SymlinkInSource { path }) if path.ends_with("Util.ipe"))
        );
        assert_eq!(
            std::fs::read_to_string(&target).expect("target intact"),
            SECRET
        );
    }

    /// A module file whose name differs from an import only in case is not that module.
    #[test]
    fn case_mismatched_names_are_not_the_imported_module() {
        let scratch = resolve(&SourceTree::main(
            "module Main exposing (main)\n\nimport Util\n\nmain =\n    1\n",
        ));
        std::fs::write(src(&scratch).join("util.ipe"), module_source("Util", &[])).expect("write");
        std::fs::write(src(&scratch).join("Shout.IPE"), module_source("Shout", &[]))
            .expect("write");
        std::fs::create_dir(src(&scratch).join("geo")).expect("mkdir");
        std::fs::write(
            src(&scratch).join("geo").join("Point.ipe"),
            module_source("Geo.Point", &[]),
        )
        .expect("write");
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        assert!(snapshot.module(&path("Util")).is_none());
        assert!(snapshot.module(&path("util")).is_none());
        assert!(snapshot.module(&path("Shout")).is_none());
        assert!(snapshot.module(&path("Geo.Point")).is_none());
        assert!(snapshot.module(&path("Main")).is_some());
        let set = ModuleSet::of(scratch.root().entries(), &snapshot).expect("module set");
        assert!(!set.contains(&path("Util")));
    }

    /// The control: the exactly spelled file is the imported module.
    #[test]
    fn exactly_spelled_names_are_the_imported_module() {
        let scratch = resolve(
            &SourceTree::main("module Main exposing (main)\n\nimport Util\n\nmain =\n    1\n")
                .module("Geo.Point", &module_source("Geo.Point", &[])),
        );
        std::fs::write(src(&scratch).join("Util.ipe"), module_source("Util", &[])).expect("write");
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        assert!(snapshot.module(&path("Util")).is_some());
        assert!(snapshot.module(&path("Geo.Point")).is_some());
    }

    /// A module file that is not a regular file is refused.
    #[cfg(unix)]
    #[test]
    fn non_regular_module_file_is_refused() {
        let scratch = resolve(&SourceTree::main(MAIN));
        let fifo = src(&scratch).join("Pipe.ipe");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(made.success());
        let result = read(&scratch, Limits::DEFAULT);
        assert!(matches!(
            &result,
            Err(CliError::SourceRefused {
                reason: SourceRefusal::NotRegularFile,
                ..
            })
        ));
    }

    /// A module path naming a Windows device is refused on every platform.
    #[test]
    fn device_named_module_is_refused() {
        let scratch = resolve(&SourceTree::main(MAIN));
        std::fs::write(src(&scratch).join("Aux.ipe"), module_source("Aux", &[])).expect("write");
        let result = read(&scratch, Limits::DEFAULT);
        assert!(
            matches!(&result, Err(CliError::DeviceNamedModule { segment, .. }) if segment == "Aux")
        );
    }

    /// The depth ceiling: a directory at the ceiling is walked, one deeper is refused.
    #[test]
    fn depth_limit_accepts_the_limit_and_refuses_one_past() {
        let at = resolve(&SourceTree::main(MAIN).module("A.B", &module_source("A.B", &[])));
        let snapshot = read(&at, Limits::DEFAULT.depth(1)).expect("depth 1 is accepted");
        assert!(snapshot.module(&path("A.B")).is_some());
        let past = resolve(&SourceTree::main(MAIN).module("A.B.C", &module_source("A.B.C", &[])));
        assert!(read(&past, Limits::DEFAULT.depth(2)).is_ok());
        assert!(is_limit_refusal(&read(&past, Limits::DEFAULT.depth(1))));
    }

    /// The module ceiling: as many modules as the ceiling are read, one more is refused.
    #[test]
    fn module_limit_accepts_the_limit_and_refuses_one_past() {
        let scratch = resolve(
            &SourceTree::main(MAIN)
                .module("A", &module_source("A", &[]))
                .module("B", &module_source("B", &[])),
        );
        let snapshot = read(&scratch, Limits::DEFAULT.modules(3)).expect("3 modules accepted");
        assert_eq!(
            snapshot
                .modules()
                .values()
                .filter(|m| matches!(m.origin(), SourceOrigin::Own(_)))
                .count(),
            3
        );
        assert!(is_limit_refusal(&read(
            &scratch,
            Limits::DEFAULT.modules(2)
        )));
    }

    /// The module ceiling counts `tests/` modules with `src/` ones.
    #[test]
    fn module_limit_spans_src_and_tests() {
        let scratch = resolve(
            &SourceTree::main(MAIN).test_module("MainSpec", &module_source("MainSpec", &[])),
        );
        assert!(read(&scratch, Limits::DEFAULT.modules(2)).is_ok());
        assert!(is_limit_refusal(&read(
            &scratch,
            Limits::DEFAULT.modules(1)
        )));
    }

    /// The entry ceiling: as many listed entries as the ceiling are examined, one more is refused.
    #[test]
    fn entry_limit_accepts_the_limit_and_refuses_one_past() {
        let scratch = resolve(&SourceTree::main(MAIN).module("A.B", &module_source("A.B", &[])));
        // `src/` lists `Main.ipe` and `A`; `src/A` lists `B.ipe`.
        assert!(read(&scratch, Limits::DEFAULT.entries(3)).is_ok());
        assert!(is_limit_refusal(&read(
            &scratch,
            Limits::DEFAULT.entries(2)
        )));
        assert!(is_limit_refusal(&read(
            &scratch,
            Limits::DEFAULT.entries(1)
        )));
    }

    /// The file cap: a file of exactly the cap is read, one byte over is refused.
    #[test]
    fn file_cap_accepts_the_limit_and_refuses_one_past() {
        let scratch = resolve(&SourceTree::main(MAIN));
        let size = u64::try_from(MAIN.len()).expect("small");
        let at = ByteCap::new(size).expect("non-zero");
        let snapshot = read(&scratch, Limits::DEFAULT.file_cap(at)).expect("cap-sized file read");
        assert_eq!(
            snapshot.module(&path("Main")).map(SnapshotModule::text),
            Some(MAIN)
        );
        let under = ByteCap::new(size - 1).expect("non-zero");
        let result = read(&scratch, Limits::DEFAULT.file_cap(under));
        assert!(matches!(&result, Err(CliError::FileTooLarge { max, .. }) if *max == size - 1));
    }

    /// The default limits are the discovery ceilings and the source read cap.
    #[test]
    fn default_limits_are_the_discovery_ceilings() {
        assert_eq!(
            Limits::DEFAULT,
            Limits::DEFAULT
                .depth(MAX_DISCOVERY_DEPTH)
                .modules(MAX_DISCOVERED_MODULES)
                .entries(MAX_DISCOVERY_ENTRIES)
                .file_cap(io_bounded::SOURCE_CAP)
                .total_bytes(SOURCE_TREE_READ_CAP)
        );
        assert_eq!(Limits::DEFAULT.file_cap.get(), io_bounded::SOURCE_READ_CAP);
    }

    /// A `tests/` module with a `src/` module's path is read and held apart; the build sees `src/`'s.
    #[test]
    fn tests_module_of_a_src_path_is_held_apart() {
        let scratch = resolve(
            &SourceTree::main(MAIN)
                .module("Util", &module_source("Util", &[]))
                .test_module("Util", "not ipe at all"),
        );
        let snapshot = read(&scratch, Limits::DEFAULT.modules(3)).expect("read");
        let util = snapshot.module(&path("Util")).expect("Util");
        assert_eq!(util.origin(), SourceOrigin::Own(SourceDir::Src));
        assert_eq!(util.text(), module_source("Util", &[]));
        let held = snapshot.tests().get(&path("Util")).expect("tests Util");
        assert_eq!(held.origin(), SourceOrigin::Own(SourceDir::Tests));
        assert_eq!(held.text(), "not ipe at all");
        assert!(is_limit_refusal(&read(
            &scratch,
            Limits::DEFAULT.modules(2)
        )));
    }

    /// `tests/Main.ipe` is read beside `src/Main.ipe`, never masked by it.
    #[test]
    fn tests_main_is_read_beside_src_main() {
        let spec = "module Main exposing (main)\n\nmain =\n    2\n";
        let scratch = resolve(&SourceTree::main(MAIN).test_module("Main", spec));
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        assert_eq!(
            snapshot.module(&path("Main")).map(SnapshotModule::text),
            Some(MAIN)
        );
        assert_eq!(
            snapshot
                .tests()
                .get(&path("Main"))
                .map(SnapshotModule::text),
            Some(spec)
        );
    }

    /// A `tests/` module on a stdlib path never masks the stdlib module the build imports.
    #[test]
    fn tests_module_never_masks_a_stdlib_module_of_the_build() {
        let scratch = resolve(
            &SourceTree::main(PALETTE_MAIN)
                .test_module("Ipe.Palette", &module_source("Ipe.Palette", &[])),
        );
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        let palette = snapshot.module(&path("Ipe.Palette")).expect("injected");
        assert_eq!(palette.origin(), SourceOrigin::Stdlib);
        let set = ModuleSet::of(scratch.root().entries(), &snapshot).expect("module set");
        assert!(set.contains(&path("Ipe.Palette")));
    }

    /// A stdlib import only `tests/` spells injects nothing into the build.
    #[test]
    fn tests_import_injects_no_stdlib_module_into_the_build() {
        let spec = module_source("MainSpec", &["Ipe.Palette"]);
        let scratch = resolve(&SourceTree::main(MAIN).test_module("MainSpec", &spec));
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        assert!(snapshot.module(&path("Ipe.Palette")).is_none());
        let control = resolve(&SourceTree::main(PALETTE_MAIN));
        let snapshot = read(&control, Limits::DEFAULT).expect("read");
        assert!(snapshot.module(&path("Ipe.Palette")).is_some());
    }

    /// An asserted native call under `tests/` never reaches the build's FFI preparation.
    #[test]
    fn tests_asserted_call_never_reaches_the_build_ffi() {
        let in_tests =
            resolve(&SourceTree::main(MAIN).test_module("Shift", &asserted_module("Shift")));
        let snapshot = read(&in_tests, Limits::DEFAULT).expect("tests/ never reaches FFI");
        assert!(snapshot.ffi().injected.is_empty());
        assert!(snapshot.ffi().emit.is_none());
        assert!(snapshot.tests().contains_key(&path("Shift")));
        // The control: the same module under `src/` is scanned, and its call
        // into a crate no catalog installs is refused.
        let in_src = resolve(&SourceTree::main(MAIN).module("Shift", &asserted_module("Shift")));
        assert!(matches!(
            read(&in_src, Limits::DEFAULT),
            Err(CliError::FfiPrep(_))
        ));
    }

    /// The summed byte ceiling: module text summing to it is read, one byte less refuses.
    #[test]
    fn total_bytes_accepts_the_limit_and_refuses_one_past() {
        let spec = module_source("MainSpec", &[]);
        let scratch = resolve(&SourceTree::main(MAIN).test_module("MainSpec", &spec));
        let total = u64::try_from(MAIN.len() + spec.len()).expect("small");
        assert!(read(&scratch, Limits::DEFAULT.total_bytes(total)).is_ok());
        assert!(is_limit_refusal(&read(
            &scratch,
            Limits::DEFAULT.total_bytes(total - 1)
        )));
        // A ceiling the first file alone passes is the summed refusal, never the file cap's.
        let main = u64::try_from(MAIN.len()).expect("small");
        assert!(is_limit_refusal(&read(
            &scratch,
            Limits::DEFAULT.total_bytes(main - 1)
        )));
        assert!(is_limit_refusal(&read(
            &scratch,
            Limits::DEFAULT.total_bytes(0)
        )));
    }

    /// Programs build every `src/` module and its reach; no `tests/` module is a member.
    #[test]
    fn programs_build_every_src_module() {
        let scratch = resolve(
            &SourceTree::main(MAIN)
                .module("Orphan", &module_source("Orphan", &[]))
                .test_module("Helper", &module_source("Helper", &[]))
                .test_module(
                    "MainSpec",
                    &module_source("MainSpec", &["Helper", "Orphan"]),
                ),
        );
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        let set = ModuleSet::of(scratch.root().entries(), &snapshot).expect("module set");
        assert!(set.contains(&path("Main")));
        assert!(set.contains(&path("Orphan")));
        assert!(!set.contains(&path("MainSpec")));
        assert!(!set.contains(&path("Helper")));
        assert_eq!(set.members().count(), 2);
    }

    /// A library builds the reach of its exposed modules, nothing else.
    #[test]
    fn library_builds_the_reach_of_its_exposed_modules() {
        let scratch = resolve(
            &SourceTree::new()
                .module("Geo", &module_source("Geo", &["Geo.Point"]))
                .module("Geo.Point", &module_source("Geo.Point", &[]))
                .module("Unused", &module_source("Unused", &[]))
                .field("exposedModules = [ \"Geo\" ]"),
        );
        assert!(matches!(scratch.root().entries(), EntrySet::Library(_)));
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        let set = ModuleSet::of(scratch.root().entries(), &snapshot).expect("module set");
        assert!(set.contains(&path("Geo")));
        assert!(set.contains(&path("Geo.Point")));
        assert!(!set.contains(&path("Unused")));
    }

    /// A library whose exposed module left `src/` after resolution is refused.
    #[test]
    fn library_with_an_exposed_module_gone_is_refused() {
        let scratch = resolve(
            &SourceTree::new()
                .module("Geo", &module_source("Geo", &[]))
                .field("exposedModules = [ \"Geo\" ]"),
        );
        assert!(read(&scratch, Limits::DEFAULT).is_ok());
        std::fs::remove_file(src(&scratch).join("Geo.ipe")).expect("remove");
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        let result = ModuleSet::of(scratch.root().entries(), &snapshot);
        assert!(
            matches!(&result, Err(CliError::ExposedModuleMissing { module }) if module == "Geo")
        );
    }

    /// A program whose entry left `src/` after resolution is refused.
    #[test]
    fn program_with_its_entry_gone_is_refused() {
        let scratch = resolve(&SourceTree::main(MAIN).module("A", &module_source("A", &[])));
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        assert!(ModuleSet::of(scratch.root().entries(), &snapshot).is_ok());
        std::fs::remove_file(src(&scratch).join("Main.ipe")).expect("remove");
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        let result = ModuleSet::of(scratch.root().entries(), &snapshot);
        assert!(matches!(&result, Err(CliError::EntryMissing { entry }) if entry == "Main.ipe"));
    }

    /// A `tests/Main.ipe` with a planted error is the test entry, never the `src/Main.ipe` of its path.
    #[test]
    fn test_view_entry_is_the_tests_module_with_its_planted_error() {
        let planted = "module Main exposing (main)\n\nmain =\n    notDefinedAnywhere\n";
        let scratch = resolve(&SourceTree::main(MAIN).test_module("Main", planted));
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        let view = test_view(&snapshot, "Main").expect("the test view");
        assert_eq!(view.entry(), &path("Main"));
        let entry = view.module(&path("Main")).expect("the entry");
        assert_eq!(entry.text(), planted);
        assert_eq!(entry.origin(), SourceOrigin::Own(SourceDir::Tests));
        assert_eq!(
            entry.path(),
            scratch.root().path().join("tests").join("Main.ipe")
        );
        // The build view is a separate value: its `Main` stays the `src/` text.
        assert_eq!(
            snapshot.module(&path("Main")).map(SnapshotModule::text),
            Some(MAIN)
        );
        assert!(format!("{view:?}").contains("Main"));
    }

    /// Only a `tests/` module names a test entry.
    #[test]
    fn test_entry_is_only_a_tests_module() {
        let util = module_source("Util", &[]);
        let scratch = resolve(
            &SourceTree::main(MAIN)
                .module("Util", &util)
                .test_module("UtilSpec", &module_source("UtilSpec", &["Util"])),
        );
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        assert!(snapshot.test_entry(&path("Util")).is_none());
        assert!(snapshot.test_entry(&path("Main")).is_none());
        let entry = snapshot
            .test_entry(&path("UtilSpec"))
            .expect("a tests/ module");
        assert_eq!(entry.module(), &path("UtilSpec"));
    }

    /// An asserted call into an uninstalled crate under `tests/` refuses its test view, never the build.
    #[test]
    fn tests_asserted_call_refuses_the_test_view_not_the_build() {
        let scratch =
            resolve(&SourceTree::main(MAIN).test_module("Shift", &asserted_module("Shift")));
        let snapshot = read(&scratch, Limits::DEFAULT).expect("the build reads");
        assert!(snapshot.modules().contains_key(&path("Main")));
        assert!(snapshot.ffi().injected.is_empty());
        assert!(matches!(
            test_view(&snapshot, "Shift"),
            Err(CliError::FfiPrep(_))
        ));
        // The control: a test entry with no asserted call prepares cleanly.
        let clean =
            resolve(&SourceTree::main(MAIN).test_module("Plain", &module_source("Plain", &[])));
        let snapshot = read(&clean, Limits::DEFAULT).expect("read");
        assert!(test_view(&snapshot, "Plain").is_ok());
    }

    /// The test entry masks a `src/` module of its path; a `src/` module masks any other `tests/` module.
    #[test]
    fn test_view_entry_wins_and_src_masks_other_tests_modules() {
        let util = module_source("Util", &[]);
        let spec = "module Main exposing (main)\n\nimport Util\nimport Helper\n\nmain =\n    2\n";
        let helper = module_source("Helper", &[]);
        let scratch = resolve(
            &SourceTree::main(MAIN)
                .module("Util", &util)
                .test_module("Main", spec)
                .test_module("Util", "not ipe at all")
                .test_module("Helper", &helper),
        );
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        let view = test_view(&snapshot, "Main").expect("the test view");
        assert_eq!(
            seen(&view, "Main"),
            Some((spec, SourceOrigin::Own(SourceDir::Tests)))
        );
        assert_eq!(
            seen(&view, "Util"),
            Some((util.as_str(), SourceOrigin::Own(SourceDir::Src)))
        );
        assert_eq!(
            seen(&view, "Helper"),
            Some((helper.as_str(), SourceOrigin::Own(SourceDir::Tests)))
        );
        let own: Vec<&ModulePath> = view
            .modules()
            .iter()
            .filter(|(_, held)| matches!(held.origin(), SourceOrigin::Own(_)))
            .map(|(module, _)| module)
            .collect();
        assert_eq!(own, [&path("Helper"), &path("Main"), &path("Util")]);
        // The build view is unchanged by the test view.
        assert_eq!(
            snapshot.module(&path("Main")).map(SnapshotModule::text),
            Some(MAIN)
        );
        assert!(snapshot.module(&path("Helper")).is_none());
    }

    /// The stdlib closure is injected again over the test universe, never into the build.
    #[test]
    fn test_view_injects_the_stdlib_its_modules_import() {
        let spec = module_source("MainSpec", &["Ipe.Palette"]);
        let scratch = resolve(&SourceTree::main(MAIN).test_module("MainSpec", &spec));
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read");
        let view = test_view(&snapshot, "MainSpec").expect("the test view");
        assert_eq!(
            view.module(&path("Ipe.Palette"))
                .map(SnapshotModule::origin),
            Some(SourceOrigin::Stdlib)
        );
        assert!(snapshot.module(&path("Ipe.Palette")).is_none());
    }

    /// A cache planted at the project's old path after resolution is never the snapshot's catalog.
    ///
    /// The project directory is renamed away after resolution and a
    /// project with a foreign crate installed takes its path. The snapshot
    /// and its test view read the crate of the cache the root holds; the
    /// control reads the planted crate by path, so the swap is live.
    #[cfg(unix)]
    #[test]
    fn cache_planted_at_the_old_path_is_never_read() {
        let base = crate::scratch::ScratchDir::new("ipe-snapshot-cache").expect("scratch base");
        let scratch = SourceTree::main(MAIN)
            .test_module("Spec", &module_source("Spec", &[]))
            .resolve_under(base.path())
            .expect("resolve the tree");
        let project = scratch.root().path().to_path_buf();
        install_crate(&project, "tm");
        let moved = base.path().join("moved");
        std::fs::rename(&project, &moved).expect("rename the project away");
        std::fs::create_dir(&project).expect("plant a project at the old path");
        install_crate(&project, "planted");
        let snapshot = read(&scratch, Limits::DEFAULT).expect("read through the held root");
        assert_eq!(slugs(snapshot.ffi()), ["tm"]);
        assert_eq!(
            snapshot
                .catalog
                .crates()
                .iter()
                .map(|c| c.slug.as_str())
                .collect::<Vec<_>>(),
            ["tm"]
        );
        let view = test_view(&snapshot, "Spec").expect("the test view");
        assert_eq!(slugs(view.ffi()), ["tm"]);
        // The control: the by-path search finds the planted crate.
        let by_path =
            crate::ffi::prepare_ffi(&mut ModuleSources::new(), &project).expect("by path");
        assert_eq!(slugs(&by_path), ["planted"]);
    }

    /// A refused cache refuses the snapshot: a linked cache directory, and a tampered artifact.
    #[cfg(unix)]
    #[test]
    fn refused_cache_refuses_the_snapshot() {
        let linked = resolve(&SourceTree::main(MAIN));
        let ffi = linked.root().path().join(".ipe").join("cache").join("ffi");
        std::fs::create_dir_all(&ffi).expect("cache parent");
        let elsewhere = linked.root().path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("link target");
        std::os::unix::fs::symlink(elsewhere, ffi.join("rust")).expect("link the cache");
        let refused = read(&linked, Limits::DEFAULT);
        assert!(
            matches!(
                refused,
                Err(CliError::TrustRefused(
                    crate::owner_trust::TrustRefusal::FfiCacheEscapes(_)
                ))
            ),
            "{refused:?}"
        );
        let tampered = resolve(&SourceTree::main(MAIN));
        install_crate(tampered.root().path(), "tm");
        let cache = ipe_ffi::driver::FfiCache::at_project_root(tampered.root().path());
        for artifact in std::fs::read_dir(cache.root()).expect("list the cache") {
            let artifact = artifact.expect("a cache entry").path();
            std::fs::write(artifact, "{").expect("tamper with the artifact");
        }
        let refused = read(&tampered, Limits::DEFAULT);
        assert!(
            matches!(refused, Err(CliError::TrustRefused(_))),
            "{refused:?}"
        );
    }
}

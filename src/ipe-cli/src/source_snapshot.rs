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
//! never satisfies it. The stdlib closure is injected and the FFI catalog
//! prepared exactly once, over the text read here; every consumer then sees
//! these bytes and no others.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the build reads its sources through this snapshot once it is wired in"
    )
)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ipe_fs_open::{ByteCap, EntryCap, EntryName, FileKind};

use crate::CliError;
use crate::api_surface::ModulePath;
use crate::ffi::{FfiPrep, prepare_ffi};
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

/// The ceilings one snapshot read is held to.
///
/// A directory is at depth 0 when it is `src/` or `tests/`; a directory past
/// `depth`, a module past `modules`, a listed entry past `entries` or a file
/// past `file_cap` bytes refuses the read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    depth: usize,
    modules: usize,
    entries: usize,
    file_cap: ByteCap,
}

impl Limits {
    /// The discovery ceilings and the source read cap every build is held to.
    pub const DEFAULT: Self = Self {
        depth: MAX_DISCOVERY_DEPTH,
        modules: MAX_DISCOVERED_MODULES,
        entries: MAX_DISCOVERY_ENTRIES,
        file_cap: io_bounded::SOURCE_CAP,
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
}

/// Every module text of one build, read once from held handles.
///
/// Fields are private: [`SourceSnapshot::read`] is the only mint.
pub struct SourceSnapshot {
    modules: BTreeMap<ModulePath, SnapshotModule>,
    ffi: FfiPrep,
}

impl SourceSnapshot {
    /// Read every module of `root` under `limits`, inject the stdlib closure and prepare FFI once.
    ///
    /// `src/` is walked first, then `tests/` when present; a `tests/` module
    /// whose path a `src/` module already has is not read. The FFI catalog is
    /// found from the project directory.
    ///
    /// # Errors
    /// [`CliError::SymlinkInSource`] for a link (on Windows, any reparse
    /// point) anywhere in the tree, including one swapped in between the
    /// listing and the read; [`CliError::DiscoveryLimitReached`] past the
    /// depth, module or entry ceiling; [`CliError::FileTooLarge`] past the
    /// file cap; [`CliError::DeviceNamedModule`] for a module path naming a
    /// Windows device; [`CliError::SourceRefused`] for a module file that is
    /// not a regular file or may not be read; [`CliError::Io`] for text that
    /// is not UTF-8 or another failure; every refusal of [`prepare_ffi`].
    pub fn read(root: &ProjectRoot, limits: Limits) -> Result<Self, CliError> {
        let mut walk = Walk::new(limits);
        walk.tree(root.src(), SourceDir::Src)?;
        if let Some(tests) = root.tests() {
            walk.tree(tests, SourceDir::Tests)?;
        }
        let Walk {
            mut sources, own, ..
        } = walk;
        // Each step after the walk only inserts keys absent from `sources`, so a
        // module's origin is the step that inserted it: the walk, the stdlib
        // injection, or the FFI preparation.
        inject_compiled_std_closure(&mut sources, &mut Vec::new());
        let stdlib: BTreeSet<ModulePath> = sources
            .keys()
            .filter(|module| !own.contains_key(*module))
            .cloned()
            .collect();
        let ffi = prepare_ffi(&mut sources, root.path())?;
        let modules = sources
            .into_iter()
            .map(|(module, (path, text))| {
                let origin = match own.get(&module) {
                    Some(dir) => SourceOrigin::Own(*dir),
                    None if stdlib.contains(&module) => SourceOrigin::Stdlib,
                    None => SourceOrigin::FfiInterface,
                };
                (
                    module,
                    SnapshotModule {
                        origin,
                        path,
                        text: Arc::from(text),
                    },
                )
            })
            .collect();
        Ok(Self { modules, ffi })
    }

    /// Every module, keyed by module path.
    #[must_use]
    pub const fn modules(&self) -> &BTreeMap<ModulePath, SnapshotModule> {
        &self.modules
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
    sources: ModuleSources,
    own: BTreeMap<ModulePath, SourceDir>,
}

impl Walk {
    const fn new(limits: Limits) -> Self {
        Self {
            limits,
            examined: 0,
            read: 0,
            sources: ModuleSources::new(),
            own: BTreeMap::new(),
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
                            &SourceRefusal::NotRegularFile,
                        ));
                    }
                    if self.sources.contains_key(&module) {
                        continue;
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
        let text = held
            .read_file_capped(name, self.limits.file_cap)
            .map_err(|error| link_refusal(error, &path))?;
        self.read = self.read.saturating_add(1);
        self.own.insert(module.clone(), dir);
        self.sources.insert(module, (path, text));
        Ok(())
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
#[derive(Debug, Clone)]
pub struct ModuleSet<'s> {
    snapshot: &'s SourceSnapshot,
    members: BTreeSet<&'s ModulePath>,
}

impl<'s> ModuleSet<'s> {
    /// The modules `entries` builds from `snapshot`, closed under import.
    ///
    /// Programs build every module under `src/`; a library builds the reach
    /// of its exposed modules. A `tests/` module is never a member.
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
        set.close(roots, false);
        Ok(set)
    }

    /// This set with every `tests/` module and its reach added.
    #[must_use]
    pub fn with_tests(mut self) -> Self {
        let roots = self
            .snapshot
            .modules
            .iter()
            .filter(|(_, m)| m.origin == SourceOrigin::Own(SourceDir::Tests))
            .map(|(module, _)| module)
            .collect();
        self.close(roots, true);
        self
    }

    /// Add `roots` and every snapshot module they import, transitively.
    fn close(&mut self, roots: Vec<&'s ModulePath>, tests: bool) {
        let mut queue: VecDeque<&'s ModulePath> = roots.into();
        while let Some(module) = queue.pop_front() {
            if !self.members.insert(module) {
                continue;
            }
            let Some(entry) = self.snapshot.modules.get(module) else {
                continue;
            };
            for import in extract_imports_from_source(entry.text()) {
                let Some((key, imported)) = self.snapshot.modules.get_key_value(&import) else {
                    continue;
                };
                if !self.members.contains(key)
                    && (tests || imported.origin != SourceOrigin::Own(SourceDir::Tests))
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
            .map(|import| format!("import {import}\n"))
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
        let spec_module = snapshot.module(&path("UtilSpec")).expect("UtilSpec read");
        assert_eq!(spec_module.origin(), SourceOrigin::Own(SourceDir::Tests));
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
        );
        assert_eq!(Limits::DEFAULT.file_cap.get(), io_bounded::SOURCE_READ_CAP);
    }

    /// A `tests/` module with a `src/` module's path is masked by it, never read.
    #[test]
    fn src_module_masks_a_tests_module_of_the_same_path() {
        let scratch = resolve(
            &SourceTree::main(MAIN)
                .module("Util", &module_source("Util", &[]))
                .test_module("Util", "not ipe at all"),
        );
        let snapshot = read(&scratch, Limits::DEFAULT.modules(2)).expect("read");
        let util = snapshot.module(&path("Util")).expect("Util");
        assert_eq!(util.origin(), SourceOrigin::Own(SourceDir::Src));
        assert_eq!(util.text(), module_source("Util", &[]));
    }

    /// Programs build every `src/` module and its reach; `tests/` only joins with `with_tests`.
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
        let with_tests = set.with_tests();
        assert!(with_tests.contains(&path("MainSpec")));
        assert!(with_tests.contains(&path("Helper")));
        assert!(with_tests.contains(&path("Orphan")));
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
}

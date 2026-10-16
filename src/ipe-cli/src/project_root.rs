//! The project root: one parsed, held, typed value resolved once at the boundary.
//!
//! A project is the directory ipe is pointed at, never one found by searching
//! upward. [`ProjectRoot::resolve`] is the only constructor: it reads that
//! directory's `package.ipe` through a held handle that refuses a link, holds
//! `src/` (and `tests/` when present) without following a link, and resolves
//! every program entry or exposed module to a file under `src/`. Each module
//! file is derived from its module path and reached component by component
//! through the held `src/` handle, so a file and its module cannot disagree and
//! no lexical path can step outside the project.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use ipe_fs_open::{EntryName, FileKind, OpenRefusal};

use crate::CliError;
use crate::api_surface::ModulePath;
use crate::contained_path::ResolvedPath;
use crate::io_bounded::{self, MANIFEST_CAP};
use crate::output_dir::OutputRefusal;
use crate::output_dir::held::{EntryKind, HeldDir};
use crate::package_manifest::{PACKAGE_IPE, parse_package_manifest_source};
use crate::project::{IPE_TOML, ProjectManifest, parse_entry};
use crate::text;

#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixture;
mod tree;

pub use tree::{DEFAULT_NAME, ScratchRoot, SourceTree, TreeRefusal};

/// The directory holding a project's modules.
const SRC_DIR: &str = "src";
/// The directory holding a project's test modules.
const TESTS_DIR: &str = "tests";
/// The extension of every module file.
const MODULE_EXT: &str = ".ipe";
/// The module a project with no declared program builds.
const DEFAULT_ENTRY: &str = "Main";

/// A vector with at least one element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonEmpty<T> {
    first: T,
    rest: Vec<T>,
}

impl<T> NonEmpty<T> {
    /// The elements of `items`, or `None` when it is empty.
    #[must_use]
    pub fn from_vec(items: Vec<T>) -> Option<Self> {
        let mut items = items.into_iter();
        let first = items.next()?;
        Some(Self {
            first,
            rest: items.collect(),
        })
    }

    /// The first element.
    #[must_use]
    pub const fn first(&self) -> &T {
        &self.first
    }

    /// Every element, first to last.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        std::iter::once(&self.first).chain(self.rest.iter())
    }
}

/// The name of one program a project builds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramName(String);

impl ProgramName {
    /// The name as text.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// One program of a project: its name and the entry module it starts from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEntry {
    name: ProgramName,
    module: ModulePath,
}

impl ResolvedEntry {
    /// The program's name.
    #[must_use]
    pub const fn name(&self) -> &ProgramName {
        &self.name
    }

    /// The entry module, whose file lies under `src/`.
    #[must_use]
    pub const fn module(&self) -> &[String] {
        self.module.as_slice()
    }
}

/// What a project builds, each member present under `src/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntrySet {
    /// Programs: `src/Main.ipe`, or each declared `programs` entry.
    Programs(NonEmpty<ResolvedEntry>),
    /// A library: each `exposedModules` name.
    Library(NonEmpty<ModulePath>),
}

/// The directory a module argument lies in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceDir {
    /// `src/`.
    Src,
    /// `tests/`, analysed over `tests/` and `src/`.
    Tests,
}

/// What one analysis command looks at.
#[derive(Debug)]
pub enum AnalysisTarget<'r> {
    /// The whole project: every member of its [`EntrySet`].
    Project(&'r ProjectRoot),
    /// One module of the project.
    Module {
        /// The project the module belongs to.
        root: &'r ProjectRoot,
        /// The directory its file lies in.
        dir: SourceDir,
        /// The module, its file derived from this path under `dir`.
        module: ModulePath,
    },
}

/// The directory a command was pointed at: the project root to resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootArg {
    dir: PathBuf,
}

/// A file argument, to be judged against a resolved [`ProjectRoot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileArg {
    path: PathBuf,
}

impl FileArg {
    /// The argument, joined onto the current directory when relative.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl RootArg {
    /// Split a command's optional path argument into the root and a file argument.
    ///
    /// No argument makes `cwd` the root; a directory is the root itself; any
    /// other path is a file argument over the root `cwd`, judged by
    /// [`ProjectRoot::target`]. No directory above is ever consulted.
    #[must_use]
    pub fn of(cwd: &Path, arg: Option<&Path>) -> (Self, Option<FileArg>) {
        let Some(arg) = arg else {
            return (Self::at(cwd), None);
        };
        let joined = cwd.join(arg);
        if joined.is_dir() {
            (Self { dir: joined }, None)
        } else {
            (Self::at(cwd), Some(FileArg { path: joined }))
        }
    }

    /// The directory `dir` as the root.
    #[must_use]
    pub fn at(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    /// The directory to resolve.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// Where a module path leads under a held directory.
enum Located {
    /// A file that is neither a directory nor a link.
    Found,
    /// No such file.
    Missing,
    /// A link on the way, or the file itself a link.
    Link(PathBuf),
}

/// A project directory, its manifest, and its held source directories.
#[derive(Debug)]
pub struct ProjectRoot {
    dir: HeldDir,
    manifest: ProjectManifest,
    src: HeldDir,
    tests: Option<HeldDir>,
    entries: EntrySet,
}

impl ProjectRoot {
    /// Resolve the project at `arg`: the only way to build a [`ProjectRoot`].
    ///
    /// # Errors
    /// [`CliError::NoManifest`] (or the legacy `ipe.toml` hint) when the
    /// directory holds no `package.ipe`; [`CliError::SymlinkInSource`] when
    /// `package.ipe`, `tests` or a module file is a link;
    /// [`CliError::NoSrcDir`] when `src` is absent or a link;
    /// [`CliError::EntryMissing`], [`CliError::EntryEscapes`],
    /// [`CliError::ExposedModuleMissing`] or [`CliError::NoDefaultEntry`] when
    /// what the project builds is not all present under `src/`;
    /// [`CliError::Usage`] when `package.ipe` names a `sourceRoot` other than
    /// `src`, or for the manifest's own refusals; [`CliError::Io`] on another
    /// failure.
    pub fn resolve(arg: RootArg) -> Result<Self, CliError> {
        let RootArg { dir: path } = arg;
        let fs_root = ipe_fs_open::HeldDir::open_root(&path)
            .map_err(|r| io_bounded::refusal_error(&path, r))?;
        let source = read_manifest(&fs_root, &path)?;
        let dir = HeldDir::open_following(&path)?
            .ok_or_else(|| CliError::NoManifest { dir: path.clone() })?;
        let fs_id = fs_root
            .id()
            .map_err(|r| io_bounded::refusal_error(&path, r))?;
        if dir.id()? != fs_id {
            return Err(OutputRefusal::Replaced(path).into());
        }
        let src = match dir.child(OsStr::new(SRC_DIR)) {
            Ok(Some(src)) => src,
            Ok(None)
            | Err(CliError::OutputRefused(
                OutputRefusal::Symlink(_) | OutputRefusal::NotADirectory(_),
            )) => return Err(CliError::NoSrcDir { root: path }),
            Err(other) => return Err(other),
        };
        let tests = match dir.child(OsStr::new(TESTS_DIR)) {
            Ok(tests) => tests,
            Err(CliError::OutputRefused(OutputRefusal::Symlink(link))) => {
                return Err(CliError::SymlinkInSource { path: link });
            }
            Err(CliError::OutputRefused(OutputRefusal::NotADirectory(_))) => None,
            Err(other) => return Err(other),
        };
        let (manifest, spelled) = parse_package_manifest_source(&source, &path.join(PACKAGE_IPE))?;
        if spelled != SRC_DIR {
            return Err(CliError::Usage(
                text::msg::package_manifest_source_root_removed(),
            ));
        }
        let entries = entry_set(&src, &manifest, &path)?;
        Ok(Self {
            dir,
            manifest,
            src,
            tests,
            entries,
        })
    }

    /// The project directory, as it was reached.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The parsed `package.ipe`.
    #[must_use]
    pub const fn manifest(&self) -> &ProjectManifest {
        &self.manifest
    }

    /// What the project builds.
    #[must_use]
    pub const fn entries(&self) -> &EntrySet {
        &self.entries
    }

    /// Judge a file argument against this project.
    ///
    /// The project's `package.ipe` names the whole project; a module file
    /// under `tests/` or `src/` names that module, `tests/` checked first.
    /// The argument is compared on its path below the root as spelled, and
    /// failing that on its canonical path; the module is then reached through
    /// the held directory without following a link.
    ///
    /// # Errors
    /// [`CliError::FileOutsideRoot`] for a file outside `src/` and `tests/`
    /// or one naming no module; [`CliError::SymlinkInSource`] for a link on
    /// the way to it; [`CliError::Io`] when it is absent or unreadable.
    pub fn target(&self, arg: &FileArg) -> Result<AnalysisTarget<'_>, CliError> {
        let outside = || CliError::FileOutsideRoot {
            arg: arg.path.clone(),
            root: suggested_root(&arg.path),
        };
        let Some(rel) = self.below_root(&arg.path)? else {
            return Err(outside());
        };
        let mut parts = rel.components();
        let Some(Component::Normal(first)) = parts.next() else {
            return Err(outside());
        };
        let rest = parts.as_path();
        if first == OsStr::new(PACKAGE_IPE) && rest.as_os_str().is_empty() {
            return Ok(AnalysisTarget::Project(self));
        }
        let (dir, held) = if first == OsStr::new(TESTS_DIR) {
            match self.tests.as_ref() {
                Some(tests) => (SourceDir::Tests, tests),
                None => return Err(outside()),
            }
        } else if first == OsStr::new(SRC_DIR) {
            (SourceDir::Src, &self.src)
        } else {
            return Err(outside());
        };
        let Some(module) = module_of(rest) else {
            return Err(outside());
        };
        match locate(held, &module)? {
            Located::Found => Ok(AnalysisTarget::Module {
                root: self,
                dir,
                module,
            }),
            Located::Link(path) => Err(CliError::SymlinkInSource { path }),
            Located::Missing => Err(CliError::Io {
                path: arg.path.clone(),
                source: std::io::ErrorKind::NotFound.into(),
            }),
        }
    }

    /// The path of `arg` below the project directory, or `None` when it lies outside.
    fn below_root(&self, arg: &Path) -> Result<Option<PathBuf>, CliError> {
        let root = self.dir.path();
        let spelled = !arg.components().any(|c| c == Component::ParentDir);
        if spelled && let Ok(rel) = arg.strip_prefix(root) {
            return Ok(Some(rel.to_path_buf()));
        }
        let canonical_root = ResolvedPath::of(root).map_err(|source| CliError::Io {
            path: root.to_path_buf(),
            source,
        })?;
        if spelled && let Ok(rel) = arg.strip_prefix(canonical_root.as_path()) {
            return Ok(Some(rel.to_path_buf()));
        }
        let (Some(parent), Some(name)) = (arg.parent(), arg.file_name()) else {
            return Ok(None);
        };
        let canonical_parent = ResolvedPath::of(parent).map_err(|source| CliError::Io {
            path: arg.to_path_buf(),
            source,
        })?;
        let canonical = canonical_parent.as_path().join(name);
        Ok(canonical
            .strip_prefix(canonical_root.as_path())
            .ok()
            .map(Path::to_path_buf))
    }
}

/// Read `package.ipe` through `root`, refusing a link and capping its size.
fn read_manifest(root: &ipe_fs_open::HeldDir, dir: &Path) -> Result<String, CliError> {
    let manifest_path = dir.join(PACKAGE_IPE);
    let no_manifest = || CliError::NoManifest {
        dir: dir.to_path_buf(),
    };
    let name = EntryName::new(OsStr::new(PACKAGE_IPE)).ok_or_else(no_manifest)?;
    match root.open_regular(&name) {
        Ok(file) => file
            .read_utf8(MANIFEST_CAP)
            .map_err(|r| io_bounded::refusal_error(&manifest_path, r)),
        Err(OpenRefusal::Absent) => {
            let legacy = EntryName::new(OsStr::new(IPE_TOML))
                .map(|toml| root.kind_of(&toml))
                .transpose()
                .map_err(|r| io_bounded::refusal_error(&dir.join(IPE_TOML), r))?
                .flatten();
            match legacy {
                Some(FileKind::Regular | FileKind::Symlink) => {
                    Err(CliError::Usage(text::msg::legacy_toml_hint()))
                }
                Some(
                    FileKind::Dir
                    | FileKind::Fifo
                    | FileKind::Socket
                    | FileKind::Device
                    | FileKind::Other,
                )
                | None => Err(no_manifest()),
            }
        }
        Err(OpenRefusal::Link) => Err(CliError::SymlinkInSource {
            path: manifest_path,
        }),
        Err(refusal) => Err(io_bounded::refusal_error(&manifest_path, refusal)),
    }
}

/// What the project builds: its declared programs, else `src/Main.ipe`, else its exposed modules.
fn entry_set(src: &HeldDir, manifest: &ProjectManifest, root: &Path) -> Result<EntrySet, CliError> {
    let mut library = Vec::with_capacity(manifest.exposed_modules.len());
    for name in &manifest.exposed_modules {
        library.push(exposed_module(src, name)?);
    }
    let mut programs = Vec::with_capacity(manifest.programs.len());
    for program in &manifest.programs {
        let module = parse_entry(&program.entry)
            .map_err(|refusal| CliError::manifest_entry_refused(&program.entry, &refusal))?;
        match locate(src, &module)? {
            Located::Found => programs.push(ResolvedEntry {
                name: ProgramName(program.name.clone()),
                module,
            }),
            Located::Missing => {
                return Err(CliError::EntryMissing {
                    entry: program.entry.clone(),
                });
            }
            Located::Link(path) => {
                return Err(CliError::EntryEscapes {
                    entry: program.entry.clone(),
                    path,
                });
            }
        }
    }
    if let Some(programs) = NonEmpty::from_vec(programs) {
        return Ok(EntrySet::Programs(programs));
    }
    let main = vec![DEFAULT_ENTRY.to_owned()];
    match locate(src, &main)? {
        Located::Found => {
            return Ok(EntrySet::Programs(NonEmpty {
                first: ResolvedEntry {
                    name: ProgramName(manifest.name.clone()),
                    module: main,
                },
                rest: Vec::new(),
            }));
        }
        Located::Link(path) => return Err(CliError::SymlinkInSource { path }),
        Located::Missing => {}
    }
    NonEmpty::from_vec(library)
        .map(EntrySet::Library)
        .ok_or_else(|| CliError::NoDefaultEntry {
            root: root.to_path_buf(),
        })
}

/// The module path of the exposed module `name`, its file present under `src/`.
fn exposed_module(src: &HeldDir, name: &str) -> Result<ModulePath, CliError> {
    let missing = || CliError::ExposedModuleMissing {
        module: name.to_owned(),
    };
    let file = format!("{}{MODULE_EXT}", name.replace('.', "/"));
    let module = parse_entry(&file).map_err(|_| missing())?;
    match locate(src, &module)? {
        Located::Found => Ok(module),
        Located::Missing => Err(missing()),
        Located::Link(path) => Err(CliError::SymlinkInSource { path }),
    }
}

/// The module a file path below `src/` or `tests/` names, or `None` when it names none.
fn module_of(rel: &Path) -> Option<ModulePath> {
    let mut segments = Vec::new();
    for component in rel.components() {
        let Component::Normal(segment) = component else {
            return None;
        };
        segments.push(segment.to_str()?);
    }
    parse_entry(&segments.join("/")).ok()
}

/// Walk `module`'s file under `dir`, never following a link.
fn locate(dir: &HeldDir, module: &[String]) -> Result<Located, CliError> {
    let Some((leaf, parents)) = module.split_last() else {
        return Ok(Located::Missing);
    };
    let mut walked: Option<HeldDir> = None;
    for segment in parents {
        let here = walked.as_ref().unwrap_or(dir);
        let next = match here.child(OsStr::new(segment)) {
            Ok(Some(next)) => next,
            Ok(None) | Err(CliError::OutputRefused(OutputRefusal::NotADirectory(_))) => {
                return Ok(Located::Missing);
            }
            Err(CliError::OutputRefused(OutputRefusal::Symlink(link))) => {
                return Ok(Located::Link(link));
            }
            Err(other) => return Err(other),
        };
        walked = Some(next);
    }
    let here = walked.as_ref().unwrap_or(dir);
    let file = format!("{leaf}{MODULE_EXT}");
    let name = here.entry(OsStr::new(&file))?;
    Ok(match here.kind_of(&name)? {
        EntryKind::Other => Located::Found,
        EntryKind::Absent | EntryKind::Directory => Located::Missing,
        EntryKind::Symlink => Located::Link(here.path().join(file)),
    })
}

/// The directory to run ipe from for `arg`: the parent of its last `src` or `tests` component.
///
/// Lexical only; failing such a component, the file's own directory.
fn suggested_root(arg: &Path) -> PathBuf {
    let mut root = None;
    let mut prefix = PathBuf::new();
    for component in arg.components() {
        if let Component::Normal(name) = component
            && (name == OsStr::new(SRC_DIR) || name == OsStr::new(TESTS_DIR))
        {
            root = Some(prefix.clone());
        }
        prefix.push(component);
    }
    root.or_else(|| arg.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    const MANIFEST: &str = "module Package exposing (package)\n\npackage =\n    { name = \"x\" }\n";
    const MODULE: &str = "module Main exposing (main)\n\nmain =\n    1\n";

    /// A scratch project directory, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let base = ipe_test_temp::temp_root()
                .canonicalize()
                .expect("canonical temp root");
            let dir = base.join(format!("ipe-project-root-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, rel: &str, text: &str) {
            let path = self.0.join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create parent dir");
            }
            fs::write(path, text).expect("write fixture file");
        }

        fn mkdir(&self, rel: &str) {
            fs::create_dir_all(self.0.join(rel)).expect("create fixture dir");
        }

        #[cfg(unix)]
        fn link(&self, target: &str, rel: &str) {
            let path = self.0.join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create parent dir");
            }
            std::os::unix::fs::symlink(self.0.join(target), path).expect("create symlink");
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn manifest_with(fields: &str) -> String {
        format!("module Package exposing (package)\n\npackage =\n    {{ name = \"x\"{fields} }}\n")
    }

    fn resolve(dir: &Path) -> Result<ProjectRoot, CliError> {
        ProjectRoot::resolve(RootArg::at(dir))
    }

    fn resolve_err(dir: &Path) -> CliError {
        resolve(dir).expect_err("the project must be refused")
    }

    /// A project with `package.ipe` and `src/Main.ipe`.
    fn app(tag: &str) -> Scratch {
        let s = Scratch::new(tag);
        s.write(PACKAGE_IPE, MANIFEST);
        s.write("src/Main.ipe", MODULE);
        s
    }

    fn file_arg(path: PathBuf) -> FileArg {
        FileArg { path }
    }

    // ── Refusals ──────────────────────────────────────────────────────────────

    #[test]
    fn a_directory_without_package_ipe_is_no_manifest_with_the_exact_text() {
        let s = Scratch::new("no-manifest");
        s.write("src/Main.ipe", MODULE);
        let err = resolve_err(s.path());
        assert!(matches!(&err, CliError::NoManifest { dir } if dir == s.path()));
        assert_eq!(
            err.to_string(),
            format!(
                "error[IPE-E0004]: no package.ipe at {}; run `ipe init` there",
                s.path().display()
            )
        );
    }

    #[test]
    fn a_package_ipe_only_in_a_parent_directory_is_never_used() {
        let s = app("parent-manifest");
        s.write("inner/src/Main.ipe", MODULE);
        let inner = s.path().join("inner");
        let err = resolve_err(&inner);
        assert!(matches!(&err, CliError::NoManifest { dir } if *dir == inner));
        assert!(err.to_string().contains("IPE-E0004"));
    }

    #[test]
    fn a_legacy_ipe_toml_keeps_its_hint_and_is_still_refused() {
        let s = Scratch::new("legacy-toml");
        s.write(IPE_TOML, "[package]\nname = \"x\"\n");
        s.write("src/Main.ipe", MODULE);
        let err = resolve_err(s.path());
        assert_eq!(
            err.to_string(),
            CliError::Usage(text::msg::legacy_toml_hint()).to_string()
        );
    }

    #[test]
    fn a_project_without_src_is_no_src_dir() {
        let s = Scratch::new("no-src");
        s.write(PACKAGE_IPE, MANIFEST);
        let err = resolve_err(s.path());
        assert!(matches!(&err, CliError::NoSrcDir { root } if root == s.path()));
        assert!(err.to_string().contains("IPE-E0005"));
    }

    #[test]
    fn a_src_that_is_a_file_is_no_src_dir() {
        let s = Scratch::new("src-file");
        s.write(PACKAGE_IPE, MANIFEST);
        s.write(SRC_DIR, "not a directory");
        assert!(matches!(resolve_err(s.path()), CliError::NoSrcDir { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn a_src_that_is_a_symlink_is_no_src_dir() {
        let s = Scratch::new("src-link");
        s.write(PACKAGE_IPE, MANIFEST);
        s.write("real/Main.ipe", MODULE);
        s.link("real", SRC_DIR);
        let err = resolve_err(s.path());
        assert!(matches!(&err, CliError::NoSrcDir { .. }));
        assert!(err.to_string().contains("IPE-E0005"));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_package_ipe_is_refused() {
        let s = Scratch::new("manifest-link");
        s.write("elsewhere/package.ipe", MANIFEST);
        s.write("src/Main.ipe", MODULE);
        s.link("elsewhere/package.ipe", PACKAGE_IPE);
        let err = resolve_err(s.path());
        assert!(
            matches!(&err, CliError::SymlinkInSource { path } if *path == s.path().join(PACKAGE_IPE))
        );
        assert!(err.to_string().contains("IPE-E0010"));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_tests_directory_is_refused() {
        let s = app("tests-link");
        s.mkdir("elsewhere");
        s.link("elsewhere", TESTS_DIR);
        assert!(matches!(
            resolve_err(s.path()),
            CliError::SymlinkInSource { path } if path == s.path().join(TESTS_DIR)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_default_main_is_refused() {
        let s = Scratch::new("main-link");
        s.write(PACKAGE_IPE, MANIFEST);
        s.write("elsewhere/Main.ipe", MODULE);
        s.link("elsewhere/Main.ipe", "src/Main.ipe");
        assert!(matches!(
            resolve_err(s.path()),
            CliError::SymlinkInSource { path } if path == s.path().join("src/Main.ipe")
        ));
    }

    #[test]
    fn a_declared_entry_that_is_missing_is_named() {
        let s = Scratch::new("entry-missing");
        s.write(
            PACKAGE_IPE,
            &manifest_with(", programs = [ { name = \"cli\", entry = \"Cli/Main.ipe\" } ]"),
        );
        s.write("src/Main.ipe", MODULE);
        let err = resolve_err(s.path());
        assert!(matches!(&err, CliError::EntryMissing { entry } if entry == "Cli/Main.ipe"));
        let shown = err.to_string();
        assert!(shown.contains("IPE-E0006"));
        assert!(shown.contains("\"Cli/Main.ipe\""));
    }

    #[cfg(unix)]
    #[test]
    fn a_declared_entry_through_a_symlink_escapes() {
        let s = Scratch::new("entry-link");
        s.write(
            PACKAGE_IPE,
            &manifest_with(", programs = [ { name = \"cli\", entry = \"Cli/Main.ipe\" } ]"),
        );
        s.mkdir(SRC_DIR);
        s.write("outside/Main.ipe", MODULE);
        s.link("outside", "src/Cli");
        let err = resolve_err(s.path());
        assert!(matches!(
            &err,
            CliError::EntryEscapes { entry, path }
                if entry == "Cli/Main.ipe" && *path == s.path().join("src/Cli")
        ));
        assert!(err.to_string().contains("IPE-E0008"));
    }

    #[test]
    fn a_project_naming_no_entry_names_both_fixes() {
        let s = Scratch::new("no-default-entry");
        s.write(PACKAGE_IPE, MANIFEST);
        s.mkdir(TESTS_DIR);
        s.write("src/Other.ipe", MODULE);
        let err = resolve_err(s.path());
        assert!(matches!(&err, CliError::NoDefaultEntry { root } if root == s.path()));
        let shown = err.to_string();
        assert!(shown.contains("IPE-E0007"));
        assert!(shown.contains("src/Main.ipe"));
        assert!(shown.contains("programs = ["));
    }

    #[test]
    fn an_exposed_module_that_is_missing_is_named() {
        let s = Scratch::new("exposed-missing");
        s.write(
            PACKAGE_IPE,
            &manifest_with(", exposedModules = [ \"Shapes\", \"Geo.Point\" ]"),
        );
        s.write("src/Shapes.ipe", MODULE);
        let err = resolve_err(s.path());
        assert!(matches!(&err, CliError::ExposedModuleMissing { module } if module == "Geo.Point"));
        assert!(err.to_string().contains("IPE-E0009"));
    }

    #[test]
    fn a_source_root_other_than_src_is_refused_with_the_teaching_hint() {
        let s = app("source-root");
        s.write(PACKAGE_IPE, &manifest_with(", sourceRoot = \"app\""));
        s.write("app/Main.ipe", MODULE);
        let err = resolve_err(s.path());
        assert_eq!(
            err.to_string(),
            CliError::Usage(text::msg::package_manifest_source_root_removed()).to_string()
        );
        assert!(err.to_string().contains("must live in `src/`"));
    }

    #[test]
    fn each_project_refusal_renders_the_code_the_diagnostics_table_defines() {
        let p = PathBuf::from("/p");
        let cases = [
            (
                CliError::NoManifest { dir: p.clone() },
                ipe_diagnostics::IPE_E0004,
            ),
            (
                CliError::NoSrcDir { root: p.clone() },
                ipe_diagnostics::IPE_E0005,
            ),
            (
                CliError::EntryMissing {
                    entry: "Cli/Main.ipe".to_owned(),
                },
                ipe_diagnostics::IPE_E0006,
            ),
            (
                CliError::NoDefaultEntry { root: p.clone() },
                ipe_diagnostics::IPE_E0007,
            ),
            (
                CliError::EntryEscapes {
                    entry: "Cli/Main.ipe".to_owned(),
                    path: p.join("src/Cli"),
                },
                ipe_diagnostics::IPE_E0008,
            ),
            (
                CliError::ExposedModuleMissing {
                    module: "Shapes".to_owned(),
                },
                ipe_diagnostics::IPE_E0009,
            ),
            (
                CliError::SymlinkInSource {
                    path: p.join("src/Main.ipe"),
                },
                ipe_diagnostics::IPE_E0010,
            ),
            (
                CliError::FileOutsideRoot {
                    arg: p.join("other/Main.ipe"),
                    root: p.clone(),
                },
                ipe_diagnostics::IPE_E0011,
            ),
        ];
        for (err, code) in cases {
            let shown = err.to_string();
            assert!(
                shown.starts_with(&format!("error[{}]: ", code.as_str())),
                "{shown}"
            );
        }
    }

    #[test]
    fn a_file_outside_src_and_tests_is_refused_naming_the_root() {
        let s = app("outside-root");
        s.write("other/Thing.ipe", MODULE);
        let root = resolve(s.path()).expect("project resolves");
        let arg = s.path().join("other/Thing.ipe");
        let err = root.target(&file_arg(arg.clone())).expect_err("refused");
        assert!(matches!(&err, CliError::FileOutsideRoot { arg: a, .. } if *a == arg));
        assert!(err.to_string().contains("IPE-E0011"));
    }

    #[test]
    fn a_file_under_src_naming_no_module_is_refused() {
        let s = app("no-module");
        s.write("src/notes.txt", "notes");
        let root = resolve(s.path()).expect("project resolves");
        let err = root
            .target(&file_arg(s.path().join("src/notes.txt")))
            .expect_err("refused");
        assert!(matches!(err, CliError::FileOutsideRoot { .. }));
    }

    #[test]
    fn a_file_of_a_nested_project_suggests_that_project() {
        let s = app("nested");
        s.write("vendor/pkg/package.ipe", MANIFEST);
        s.write("vendor/pkg/src/Lib.ipe", MODULE);
        let root = resolve(s.path()).expect("project resolves");
        let err = root
            .target(&file_arg(s.path().join("vendor/pkg/src/Lib.ipe")))
            .expect_err("refused");
        assert!(matches!(
            &err,
            CliError::FileOutsideRoot { root, .. } if *root == s.path().join("vendor/pkg")
        ));
        assert!(
            err.to_string()
                .contains(&s.path().join("vendor/pkg").display().to_string())
        );
    }

    #[test]
    fn a_file_in_another_directory_is_refused() {
        let s = app("elsewhere-root");
        let other = Scratch::new("elsewhere-other");
        other.write("src/Main.ipe", MODULE);
        let root = resolve(s.path()).expect("project resolves");
        let err = root
            .target(&file_arg(other.path().join("src/Main.ipe")))
            .expect_err("refused");
        assert!(matches!(
            err,
            CliError::FileOutsideRoot { root, .. } if root == other.path()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_file_argument_through_a_symlinked_directory_is_refused() {
        let s = app("arg-link");
        s.write("real/Util.ipe", MODULE);
        s.link("real", "src/Lib");
        let root = resolve(s.path()).expect("project resolves");
        let err = root
            .target(&file_arg(s.path().join("src/Lib/Util.ipe")))
            .expect_err("refused");
        assert!(matches!(
            err,
            CliError::SymlinkInSource { path } if path == s.path().join("src/Lib")
        ));
    }

    #[test]
    fn a_missing_file_under_src_is_not_found() {
        let s = app("arg-missing");
        let root = resolve(s.path()).expect("project resolves");
        let err = root
            .target(&file_arg(s.path().join("src/Gone.ipe")))
            .expect_err("refused");
        assert!(
            matches!(err, CliError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound)
        );
    }

    // ── Accepted neighbours ───────────────────────────────────────────────────

    #[test]
    fn a_project_with_src_main_builds_main_under_its_name() {
        let s = app("default-main");
        let root = resolve(s.path()).expect("project resolves");
        let programs = programs_of(&root);
        let main = programs.first();
        assert_eq!(main.name().as_str(), "x");
        assert_eq!(main.module(), ["Main".to_owned()]);
        assert_eq!(programs.iter().count(), 1);
        assert_eq!(root.path(), s.path());
        assert_eq!(root.manifest().name, "x");
    }

    #[test]
    fn declared_programs_resolve_in_order() {
        let s = Scratch::new("programs");
        s.write(
            PACKAGE_IPE,
            &manifest_with(
                ", programs = [ { name = \"web\", entry = \"Main.ipe\" }, { name = \"cli\", entry = \"Cli/Main.ipe\" } ]",
            ),
        );
        s.write("src/Main.ipe", MODULE);
        s.write("src/Cli/Main.ipe", MODULE);
        let root = resolve(s.path()).expect("project resolves");
        let programs = programs_of(&root);
        let seen: Vec<(&str, &[String])> = programs
            .iter()
            .map(|p| (p.name().as_str(), p.module()))
            .collect();
        assert_eq!(
            seen,
            [
                ("web", &["Main".to_owned()][..]),
                ("cli", &["Cli".to_owned(), "Main".to_owned()][..]),
            ]
        );
    }

    #[test]
    fn a_library_resolves_its_exposed_modules() {
        let s = Scratch::new("library");
        s.write(
            PACKAGE_IPE,
            &manifest_with(", exposedModules = [ \"Shapes\", \"Geo.Point\" ]"),
        );
        s.write("src/Shapes.ipe", MODULE);
        s.write("src/Geo/Point.ipe", MODULE);
        let root = resolve(s.path()).expect("project resolves");
        let modules = library_of(&root);
        let seen: Vec<&ModulePath> = modules.iter().collect();
        assert_eq!(
            seen,
            [
                &vec!["Shapes".to_owned()],
                &vec!["Geo".to_owned(), "Point".to_owned()]
            ]
        );
    }

    #[test]
    fn a_src_file_argument_names_its_own_module() {
        let s = app("src-arg");
        s.write("src/Other.ipe", MODULE);
        let root = resolve(s.path()).expect("project resolves");
        let target = root
            .target(&file_arg(s.path().join("src/Other.ipe")))
            .expect("accepted");
        assert!(matches!(
            target,
            AnalysisTarget::Module { dir: SourceDir::Src, module, .. } if module == ["Other"]
        ));
    }

    #[test]
    fn a_tests_file_argument_is_analysed_from_tests() {
        let s = app("tests-arg");
        s.write("tests/Suite/MainTest.ipe", MODULE);
        let root = resolve(s.path()).expect("project resolves");
        let target = root
            .target(&file_arg(s.path().join("tests/Suite/MainTest.ipe")))
            .expect("accepted");
        assert!(matches!(
            target,
            AnalysisTarget::Module { dir: SourceDir::Tests, module, .. }
                if module == ["Suite", "MainTest"]
        ));
    }

    #[test]
    fn the_package_ipe_argument_names_the_whole_project() {
        let s = app("manifest-arg");
        let root = resolve(s.path()).expect("project resolves");
        let target = root
            .target(&file_arg(s.path().join(PACKAGE_IPE)))
            .expect("accepted");
        assert!(matches!(target, AnalysisTarget::Project(_)));
    }

    #[test]
    fn a_relative_file_argument_is_judged_against_the_current_directory() {
        let s = app("relative-arg");
        s.write("src/Other.ipe", MODULE);
        let (root_arg, file) = RootArg::of(s.path(), Some(Path::new("src/Other.ipe")));
        assert_eq!(root_arg.dir(), s.path());
        let file = file.expect("a file argument");
        assert_eq!(file.path(), s.path().join("src/Other.ipe"));
        let root = ProjectRoot::resolve(root_arg).expect("project resolves");
        assert!(matches!(
            root.target(&file).expect("accepted"),
            AnalysisTarget::Module {
                dir: SourceDir::Src,
                ..
            }
        ));
    }

    #[test]
    fn a_directory_argument_is_the_root_itself() {
        let s = Scratch::new("dir-arg");
        s.write("app/package.ipe", MANIFEST);
        s.write("app/src/Main.ipe", MODULE);
        let (root_arg, file) = RootArg::of(s.path(), Some(Path::new("app")));
        assert!(file.is_none());
        assert_eq!(root_arg.dir(), s.path().join("app"));
        assert!(ProjectRoot::resolve(root_arg).is_ok());
        let (cwd_arg, none) = RootArg::of(s.path(), None);
        assert!(none.is_none());
        assert_eq!(cwd_arg.dir(), s.path());
    }

    #[test]
    fn non_empty_refuses_an_empty_vector() {
        assert!(NonEmpty::<u8>::from_vec(Vec::new()).is_none());
        let one = NonEmpty::from_vec(vec![1_u8, 2]).expect("non-empty");
        assert_eq!(one.iter().copied().collect::<Vec<_>>(), [1, 2]);
    }

    fn programs_of(root: &ProjectRoot) -> &NonEmpty<ResolvedEntry> {
        match root.entries() {
            EntrySet::Programs(programs) => Some(programs),
            EntrySet::Library(_) => None,
        }
        .expect("the project builds programs")
    }

    fn library_of(root: &ProjectRoot) -> &NonEmpty<ModulePath> {
        match root.entries() {
            EntrySet::Library(modules) => Some(modules),
            EntrySet::Programs(_) => None,
        }
        .expect("the project is a library")
    }
}

//! A source tree written to a private scratch directory and resolved as a project root.
//!
//! The writer emits a real `package.ipe` with a `src/` (and `tests/`) tree, then
//! hands the directory to [`ProjectRoot::resolve`], the one constructor. A tree
//! written here is therefore accepted or refused on the same terms as any
//! project on disk: nothing builds a [`ProjectRoot`] around the resolver.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use super::{DEFAULT_ENTRY, MODULE_EXT, ProjectRoot, RootArg, SRC_DIR, SourceDir, TESTS_DIR};
use crate::CliError;
use crate::package_manifest::PACKAGE_IPE;
use crate::package_name::PackageName;
use crate::project::is_module_segment;
use crate::scratch::ScratchDir;

/// The package name of a tree that is not named.
pub const DEFAULT_NAME: &str = "ipe-app";

/// The tag of the private directory holding a written tree.
const SCRATCH_LABEL: &str = "ipe-root";

/// One module file of a tree.
#[derive(Debug, Clone)]
struct TreeModule {
    dir: SourceDir,
    module: String,
    source: String,
}

/// The description of a project: its name, manifest fields, module sources
/// and the files its manifest names (an icon).
///
/// Nothing is written until [`SourceTree::resolve`] or
/// [`SourceTree::resolve_under`].
#[derive(Debug, Clone)]
pub struct SourceTree {
    name: String,
    fields: Vec<String>,
    modules: Vec<TreeModule>,
    files: Vec<(String, Vec<u8>)>,
}

impl Default for SourceTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceTree {
    /// A tree named [`DEFAULT_NAME`] with no modules.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: DEFAULT_NAME.to_owned(),
            fields: Vec::new(),
            modules: Vec::new(),
            files: Vec::new(),
        }
    }

    /// A tree whose one module is `Main`, holding `source`.
    #[must_use]
    pub fn main(source: &str) -> Self {
        Self::new().module(DEFAULT_ENTRY, source)
    }

    /// Name the package `name`.
    #[must_use]
    pub fn named(mut self, name: &str) -> Self {
        name.clone_into(&mut self.name);
        self
    }

    /// Add one record field to `package.ipe`, spelled as in the manifest (`exposedModules = [ "A" ]`).
    ///
    /// Raw manifest text, so only test targets reach it.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn field(mut self, field: &str) -> Self {
        self.fields.push(field.to_owned());
        self
    }

    /// Add the file at `path` (relative, `/`-separated) holding `bytes`, written
    /// before the tree is resolved so a manifest field naming it reads it.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn file(mut self, path: &str, bytes: &[u8]) -> Self {
        self.files.push((path.to_owned(), bytes.to_vec()));
        self
    }

    /// Add the module `module` (dotted, as imported) under `src/`, holding `source`.
    #[must_use]
    pub fn module(self, module: &str, source: &str) -> Self {
        self.with_module(SourceDir::Src, module, source)
    }

    /// Add the module `module` (dotted, as imported) under `tests/`, holding `source`.
    #[must_use]
    pub fn test_module(self, module: &str, source: &str) -> Self {
        self.with_module(SourceDir::Tests, module, source)
    }

    fn with_module(mut self, dir: SourceDir, module: &str, source: &str) -> Self {
        self.modules.push(TreeModule {
            dir,
            module: module.to_owned(),
            source: source.to_owned(),
        });
        self
    }

    /// Write the tree to a private directory under the scratch base and resolve it.
    ///
    /// # Errors
    /// [`CliError::ScratchUnavailable`] when the directory cannot be created;
    /// otherwise as [`SourceTree::resolve_under`].
    pub fn resolve(&self) -> Result<ScratchRoot, CliError> {
        let dir = ScratchDir::new(SCRATCH_LABEL)
            .map_err(|source| CliError::ScratchUnavailable { source })?;
        self.resolve_in(dir)
    }

    /// Write the tree to a private directory directly under `base` and resolve it.
    ///
    /// # Errors
    /// [`CliError::ScratchUnavailable`] when the directory cannot be created;
    /// [`CliError::Resolve`] for a name that is not a package name;
    /// [`CliError::SourceTree`] for a module name that is not a dotted module
    /// name or for two module paths one case-insensitive file system would merge;
    /// [`CliError::Io`] for a file that cannot be written; otherwise every
    /// refusal of [`ProjectRoot::resolve`].
    pub fn resolve_under(&self, base: &Path) -> Result<ScratchRoot, CliError> {
        let dir = ScratchDir::new_under(base, SCRATCH_LABEL)
            .map_err(|source| CliError::ScratchUnavailable { source })?;
        self.resolve_in(dir)
    }

    fn resolve_in(&self, dir: ScratchDir) -> Result<ScratchRoot, CliError> {
        let files = self.files()?;
        let manifest = self.manifest()?;
        let root = dir.path();
        write_file(&root.join(PACKAGE_IPE), manifest.as_bytes())?;
        let src = root.join(SRC_DIR);
        fs::create_dir(&src).map_err(|source| io_error(&src, source))?;
        for (rel, source) in &files {
            write_file(&root.join(rel), source)?;
        }
        let root = ProjectRoot::resolve(RootArg::at(root))?;
        Ok(ScratchRoot { root, _dir: dir })
    }

    /// The `package.ipe` text.
    fn manifest(&self) -> Result<String, CliError> {
        let name = PackageName::parse(&self.name)?;
        let mut fields = String::new();
        for field in &self.fields {
            fields.push_str(", ");
            fields.push_str(field);
        }
        Ok(format!(
            "module Package exposing (package)\n\npackage =\n    {{ name = \"{}\"{fields} }}\n",
            name.as_str()
        ))
    }

    /// Every module and named file as its path below the root and its bytes,
    /// all paths proven first.
    fn files(&self) -> Result<Vec<(PathBuf, &[u8])>, CliError> {
        self.plan().map_err(CliError::SourceTree)
    }

    /// Every module and named file below the root, refusing a name that is not
    /// a dotted module name, a file path that is not relative, and two paths one
    /// case-insensitive file system would merge.
    fn plan(&self) -> Result<Vec<(PathBuf, &[u8])>, TreeRefusal> {
        let mut claimed = FoldedPaths::default();
        let modules = self
            .modules
            .iter()
            .map(|m| Ok((module_file(m.dir, &m.module)?, m.source.as_bytes())));
        let files = self
            .files
            .iter()
            .map(|(path, bytes)| Ok((relative_file(path)?, bytes.as_slice())));
        modules
            .chain(files)
            .map(|planned| {
                let (path, bytes) = planned?;
                claimed.claim(&path)?;
                Ok((path, bytes))
            })
            .collect()
    }
}

/// Why the modules of a tree have no files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeRefusal {
    /// A `.`-separated segment of `module` is not a module segment
    /// (`[A-Z][A-Za-z0-9_]*`, no Windows device name).
    NotModuleSegment {
        /// The module name as given.
        module: String,
        /// The refused segment.
        segment: String,
    },
    /// A named file path that is empty or has a root, `.` or `..` component.
    NotRelativeFile {
        /// The path as given.
        path: String,
    },
    /// Two module files, or two of their directories, that differ at most in ASCII case.
    Collision {
        /// The path claimed first.
        first: PathBuf,
        /// The path that coincides with it.
        second: PathBuf,
    },
}

impl fmt::Display for TreeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotModuleSegment { module, segment } => write!(
                f,
                "`{module}` is not a module name: `{segment}` is not a module segment"
            ),
            Self::NotRelativeFile { path } => {
                write!(f, "`{path}` is not a file path below the project root")
            }
            Self::Collision { first, second } => write!(
                f,
                "`{}` and `{}` are one path on a case-insensitive file system",
                first.display(),
                second.display()
            ),
        }
    }
}

impl std::error::Error for TreeRefusal {}

/// The directories and files of a tree, keyed by their ASCII case fold.
///
/// Module segments are ASCII, so the ASCII fold covers every fold a file
/// system applies to them.
#[derive(Default)]
struct FoldedPaths {
    dirs: BTreeMap<String, PathBuf>,
    files: BTreeMap<String, PathBuf>,
}

impl FoldedPaths {
    /// Claim `file` and each of its directories, refusing a repeat or a case-only clash.
    fn claim(&mut self, file: &Path) -> Result<(), TreeRefusal> {
        let mut dir = PathBuf::new();
        for component in file.parent().into_iter().flat_map(Path::components) {
            dir.push(component);
            let first = self.dirs.entry(fold(&dir)).or_insert_with(|| dir.clone());
            if *first != dir {
                return Err(TreeRefusal::Collision {
                    first: first.clone(),
                    second: dir,
                });
            }
        }
        match self.files.entry(fold(file)) {
            Entry::Occupied(first) => Err(TreeRefusal::Collision {
                first: first.get().clone(),
                second: file.to_path_buf(),
            }),
            Entry::Vacant(slot) => {
                slot.insert(file.to_path_buf());
                Ok(())
            }
        }
    }
}

/// The ASCII case fold of `path`, `/`-joined.
fn fold(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("/")
}

/// The file of the dotted `module` below the root, built from its checked segments so it cannot leave `dir`.
fn module_file(dir: SourceDir, module: &str) -> Result<PathBuf, TreeRefusal> {
    let mut path = PathBuf::from(match dir {
        SourceDir::Src => SRC_DIR,
        SourceDir::Tests => TESTS_DIR,
    });
    let mut segments = module.split('.').peekable();
    while let Some(segment) = segments.next() {
        if !is_module_segment(segment) {
            return Err(TreeRefusal::NotModuleSegment {
                module: module.to_owned(),
                segment: segment.to_owned(),
            });
        }
        if segments.peek().is_some() {
            path.push(segment);
        } else {
            path.push(format!("{segment}{MODULE_EXT}"));
        }
    }
    Ok(path)
}

/// `path` as a path below the root: non-empty, every component a plain name.
fn relative_file(path: &str) -> Result<PathBuf, TreeRefusal> {
    let rel = PathBuf::from(path);
    let plain = rel
        .components()
        .all(|c| matches!(c, std::path::Component::Normal(_)));
    if plain && rel.components().next().is_some() {
        Ok(rel)
    } else {
        Err(TreeRefusal::NotRelativeFile {
            path: path.to_owned(),
        })
    }
}

/// Write `bytes` to a new file at `path`, creating its parent directories.
///
/// A file already at `path` is refused, never overwritten.
fn write_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    }
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|source| io_error(path, source))
}

fn io_error(path: &Path, source: io::Error) -> CliError {
    CliError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// A resolved [`ProjectRoot`] and the private directory holding it, removed on drop.
#[derive(Debug)]
pub struct ScratchRoot {
    root: ProjectRoot,
    _dir: ScratchDir,
}

impl ScratchRoot {
    /// The resolved project.
    #[must_use]
    pub const fn root(&self) -> &ProjectRoot {
        &self.root
    }
}

impl ProjectRoot {
    /// Resolve `snippet` as the `Main` module of a throwaway project under the scratch base.
    ///
    /// # Errors
    /// As [`SourceTree::resolve`].
    pub fn scratch(snippet: &str) -> Result<ScratchRoot, CliError> {
        SourceTree::main(snippet).resolve()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_root::EntrySet;

    const MODULE: &str = "module Main exposing (main)\n\nmain =\n    1\n";

    fn base() -> PathBuf {
        ipe_test_temp::temp_root()
            .canonicalize()
            .expect("canonical temp root")
    }

    fn tree() -> SourceTree {
        SourceTree::main(MODULE)
    }

    fn refused(tree: &SourceTree) -> CliError {
        tree.resolve_under(&base())
            .expect_err("the tree must be refused")
    }

    #[test]
    fn a_tree_is_named_ipe_app_unless_it_is_named() {
        let default = tree().resolve_under(&base()).expect("resolves");
        assert_eq!(default.root().manifest().name, DEFAULT_NAME);
        assert_eq!(DEFAULT_NAME, "ipe-app");
        let named = tree()
            .named("other")
            .resolve_under(&base())
            .expect("resolves");
        assert_eq!(named.root().manifest().name, "other");
    }

    #[test]
    fn a_tree_with_a_main_module_resolves_to_a_program() {
        let written = tree().resolve_under(&base()).expect("resolves");
        assert!(matches!(written.root().entries(), EntrySet::Programs(_)));
        assert!(written.root().path().join(PACKAGE_IPE).is_file());
        assert!(written.root().path().join("src/Main.ipe").is_file());
    }

    #[test]
    fn a_nested_module_lands_below_its_own_directory() {
        let written = tree()
            .module("Data.List", MODULE)
            .resolve_under(&base())
            .expect("resolves");
        assert!(written.root().path().join("src/Data/List.ipe").is_file());
    }

    #[test]
    fn a_test_module_lands_under_tests_and_holds_the_tests_directory() {
        let written = tree()
            .test_module("MainTest", MODULE)
            .resolve_under(&base())
            .expect("resolves");
        assert!(written.root().path().join("tests/MainTest.ipe").is_file());
        assert!(written.root.tests.is_some());
        let plain = tree().resolve_under(&base()).expect("resolves");
        assert!(plain.root.tests.is_none());
    }

    #[test]
    fn a_tree_the_resolver_refuses_is_refused_with_the_resolver_error() {
        let none = refused(&SourceTree::new());
        assert!(matches!(none, CliError::NoDefaultEntry { .. }), "{none}");
        let missing =
            refused(&tree().field("programs = [ { name = \"cli\", entry = \"Cli.ipe\" } ]"));
        assert!(
            matches!(&missing, CliError::EntryMissing { entry } if entry == "Cli.ipe"),
            "{missing}"
        );
        let library = refused(&tree().field("exposedModules = [ \"Absent\" ]"));
        assert!(
            matches!(&library, CliError::ExposedModuleMissing { module } if module == "Absent"),
            "{library}"
        );
        let moved = refused(&tree().field("sourceRoot = \"app\""));
        assert!(matches!(moved, CliError::Usage(_)));
    }

    #[test]
    fn the_refused_shapes_resolve_once_the_missing_piece_is_supplied() {
        tree()
            .module("Cli", MODULE)
            .field("programs = [ { name = \"cli\", entry = \"Cli.ipe\" } ]")
            .resolve_under(&base())
            .expect("a declared entry that exists resolves");
        tree()
            .module("Absent", MODULE)
            .field("exposedModules = [ \"Absent\" ]")
            .resolve_under(&base())
            .expect("an exposed module that exists resolves");
    }

    #[test]
    fn a_module_that_is_not_a_module_path_writes_nothing() {
        for module in [
            "../Evil",
            "a/b",
            "main",
            "Data..List",
            "",
            ".Main",
            "Main.",
            "C:Main",
            "Data\\List",
            "Data/List",
            "/Main",
            "Con",
            "Data.Nul",
            "Main\0",
        ] {
            let err = refused(&tree().module(module, MODULE));
            assert!(
                matches!(
                    &err,
                    CliError::SourceTree(TreeRefusal::NotModuleSegment { .. })
                ),
                "{module:?}: {err}"
            );
        }
        let err = refused(&tree().test_module("../Evil", MODULE));
        assert!(matches!(
            err,
            CliError::SourceTree(TreeRefusal::NotModuleSegment { .. })
        ));
    }

    #[test]
    fn a_module_name_is_refused_at_its_first_bad_segment() {
        let plan = |module: &str| tree().module(module, MODULE).plan().map(drop);
        let not_segment = |module: &str, segment: &str| {
            Err(TreeRefusal::NotModuleSegment {
                module: module.to_owned(),
                segment: segment.to_owned(),
            })
        };
        assert_eq!(plan("Data/List"), not_segment("Data/List", "Data/List"));
        assert_eq!(plan("Data.List/X"), not_segment("Data.List/X", "List/X"));
        assert_eq!(plan("Data..List"), not_segment("Data..List", ""));
        assert_eq!(plan("Aux.Main"), not_segment("Aux.Main", "Aux"));
        assert_eq!(plan("Data.List"), Ok(()));
    }

    #[test]
    fn two_modules_one_case_insensitive_file_system_would_merge_are_refused() {
        let collision = |first: &str, second: &str| {
            Err(TreeRefusal::Collision {
                first: PathBuf::from(first),
                second: PathBuf::from(second),
            })
        };
        let plan = |tree: SourceTree| tree.plan().map(drop);
        assert_eq!(
            plan(tree().module("Lib", MODULE).module("Lib", MODULE)),
            collision("src/Lib.ipe", "src/Lib.ipe")
        );
        assert_eq!(
            plan(tree().module("Lib", MODULE).module("LIB", MODULE)),
            collision("src/Lib.ipe", "src/LIB.ipe")
        );
        assert_eq!(
            plan(
                tree()
                    .module("Data.List", MODULE)
                    .module("DATA.Dict", MODULE)
            ),
            collision("src/Data", "src/DATA")
        );
        assert_eq!(
            plan(tree().test_module("Main", MODULE)),
            Ok(()),
            "a test module and a source module of one name are two files"
        );
        assert_eq!(
            plan(tree().module("Data", MODULE).module("Data.List", MODULE)),
            Ok(())
        );
        let err = refused(&tree().module("Main", MODULE));
        assert!(
            matches!(&err, CliError::SourceTree(TreeRefusal::Collision { .. })),
            "{err}"
        );
    }

    #[test]
    fn a_named_file_outside_the_root_or_on_a_module_is_refused() {
        let plan = |path: &str| tree().file(path, b"x").plan().map(drop);
        let not_relative = |path: &str| {
            Err(TreeRefusal::NotRelativeFile {
                path: path.to_owned(),
            })
        };
        for path in [
            "",
            "/etc/icon.png",
            "../icon.png",
            "assets/../icon.png",
            "./icon.png",
        ] {
            assert_eq!(plan(path), not_relative(path), "{path:?}");
        }
        assert_eq!(plan("assets/icon.png"), Ok(()));
        assert_eq!(
            tree()
                .module("Lib", MODULE)
                .file("src/LIB.ipe", b"x")
                .plan()
                .map(drop),
            Err(TreeRefusal::Collision {
                first: PathBuf::from("src/Lib.ipe"),
                second: PathBuf::from("src/LIB.ipe"),
            })
        );
    }

    #[test]
    fn a_name_that_is_not_a_package_name_is_refused() {
        for name in ["", "Not A Name", "a\"b", "../x", "UPPER"] {
            let err = refused(&tree().named(name));
            assert!(matches!(err, CliError::Resolve(..)), "{name:?}: {err}");
        }
    }

    #[test]
    fn a_scratch_root_lives_under_the_test_temp_root_and_is_removed_on_drop() {
        let written = ProjectRoot::scratch(MODULE).expect("scratch resolves");
        let path = written.root().path().to_path_buf();
        assert!(path.starts_with(base()), "{}", path.display());
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(!path.starts_with(manifest_dir));
        assert!(path.join(PACKAGE_IPE).is_file());
        assert!(matches!(written.root().entries(), EntrySet::Programs(_)));
        drop(written);
        assert!(!path.exists());
    }

    #[test]
    fn two_scratch_roots_never_share_a_directory() {
        let first = ProjectRoot::scratch(MODULE).expect("scratch resolves");
        let second = ProjectRoot::scratch(MODULE).expect("scratch resolves");
        assert_ne!(first.root().path(), second.root().path());
    }

    #[test]
    fn a_scratch_snippet_the_resolver_cannot_use_has_no_root() {
        let err = SourceTree::new().resolve().expect_err("no entry");
        assert!(matches!(err, CliError::NoDefaultEntry { .. }));
    }
}

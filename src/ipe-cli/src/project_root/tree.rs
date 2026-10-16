//! A source tree written to a private scratch directory and resolved as a project root.
//!
//! The writer emits a real `package.ipe` with a `src/` (and `tests/`) tree, then
//! hands the directory to [`ProjectRoot::resolve`], the one constructor. A tree
//! written here is therefore accepted or refused on the same terms as any
//! project on disk: nothing builds a [`ProjectRoot`] around the resolver.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::{DEFAULT_ENTRY, MODULE_EXT, ProjectRoot, RootArg, SRC_DIR, SourceDir, TESTS_DIR};
use crate::CliError;
use crate::package_manifest::PACKAGE_IPE;
use crate::package_name::PackageName;
use crate::project::parse_entry;
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

/// The description of a project: its name, manifest fields and module sources.
///
/// Nothing is written until [`SourceTree::resolve`] or
/// [`SourceTree::resolve_under`].
#[derive(Debug, Clone)]
pub struct SourceTree {
    name: String,
    fields: Vec<String>,
    modules: Vec<TreeModule>,
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
    #[must_use]
    pub fn field(mut self, field: &str) -> Self {
        self.fields.push(field.to_owned());
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
    /// [`CliError::Io`] for a module that is not a module path or a file that
    /// cannot be written; otherwise every refusal of [`ProjectRoot::resolve`].
    pub fn resolve_under(&self, base: &Path) -> Result<ScratchRoot, CliError> {
        let dir = ScratchDir::new_under(base, SCRATCH_LABEL)
            .map_err(|source| CliError::ScratchUnavailable { source })?;
        self.resolve_in(dir)
    }

    fn resolve_in(&self, dir: ScratchDir) -> Result<ScratchRoot, CliError> {
        let files = self.files()?;
        let manifest = self.manifest()?;
        let root = dir.path();
        write_file(&root.join(PACKAGE_IPE), &manifest)?;
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

    /// Every module file as its path below the root and its text, all paths proven first.
    fn files(&self) -> Result<Vec<(PathBuf, &str)>, CliError> {
        self.modules
            .iter()
            .map(|m| Ok((module_file(m.dir, &m.module)?, m.source.as_str())))
            .collect()
    }
}

/// The file of `module` below the root, derived from its parsed path so it cannot leave `dir`.
fn module_file(dir: SourceDir, module: &str) -> Result<PathBuf, CliError> {
    let refused = || {
        io_error(
            Path::new(module),
            io::Error::new(io::ErrorKind::InvalidInput, "not a module path"),
        )
    };
    let segments =
        parse_entry(&format!("{}{MODULE_EXT}", module.replace('.', "/"))).map_err(|_| refused())?;
    let (leaf, parents) = segments.split_last().ok_or_else(refused)?;
    let mut path = PathBuf::from(match dir {
        SourceDir::Src => SRC_DIR,
        SourceDir::Tests => TESTS_DIR,
    });
    path.extend(parents);
    path.push(format!("{leaf}{MODULE_EXT}"));
    Ok(path)
}

/// Write `text` to `path`, creating its parent directories.
fn write_file(path: &Path, text: &str) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    }
    fs::write(path, text).map_err(|source| io_error(path, source))
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
        ] {
            let err = refused(&tree().module(module, MODULE));
            assert!(
                matches!(&err, CliError::Io { source, .. } if source.kind() == io::ErrorKind::InvalidInput),
                "{module:?}: {err}"
            );
        }
        let err = refused(&tree().test_module("../Evil", MODULE));
        assert!(matches!(err, CliError::Io { .. }));
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

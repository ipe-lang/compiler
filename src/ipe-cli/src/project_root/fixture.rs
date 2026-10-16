//! Test fixtures: a project reached the one way production reaches it.
//!
//! A [`RootFixture`] is a real project tree on disk, resolved by
//! [`ProjectRoot::resolve`](super::ProjectRoot::resolve). A test builds
//! through [`build_fixture`], so a tree the production resolver would refuse
//! has no fixture, and no test reaches a project through a loose file or a
//! walk up from a file.

use std::path::{Path, PathBuf};

use super::{ProjectRoot, ScratchRoot, SourceTree};
use crate::package_manifest::PACKAGE_IPE;
use crate::{BuildOptions, CliError, build_project_with_options};

/// A project tree written to a private directory and resolved, removed on drop.
#[derive(Debug)]
pub struct RootFixture {
    written: ScratchRoot,
}

impl RootFixture {
    /// A project named `ipe-app` whose only module is `Main`, holding `source`.
    ///
    /// # Errors
    /// As [`RootFixture::from_tree`].
    pub fn main(source: &str) -> Result<Self, CliError> {
        Self::from_tree(&SourceTree::main(source))
    }

    /// Write `tree` and resolve it.
    ///
    /// # Errors
    /// Every refusal of [`SourceTree::resolve`]: a tree the production resolver
    /// would refuse has no fixture.
    pub fn from_tree(tree: &SourceTree) -> Result<Self, CliError> {
        tree.resolve().map(|written| Self { written })
    }

    /// The resolved project.
    #[must_use]
    pub const fn root(&self) -> &ProjectRoot {
        self.written.root()
    }

    /// The project directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.root().path()
    }

    /// The project's `package.ipe`.
    #[must_use]
    pub fn manifest_path(&self) -> PathBuf {
        self.path().join(PACKAGE_IPE)
    }
}

/// Build `fixture` into `out_dir`, vendoring the runtime from `runtime_dir`.
///
/// # Errors
/// As [`crate::build_project`].
pub fn build_fixture(
    fixture: &RootFixture,
    out_dir: &Path,
    runtime_dir: &Path,
) -> Result<(), CliError> {
    build_fixture_with_options(fixture, out_dir, runtime_dir, &BuildOptions::from_env())
}

/// [`build_fixture`] with explicit [`BuildOptions`].
///
/// # Errors
/// As [`crate::build_project_with_options`].
pub fn build_fixture_with_options(
    fixture: &RootFixture,
    out_dir: &Path,
    runtime_dir: &Path,
    options: &BuildOptions,
) -> Result<(), CliError> {
    build_project_with_options(&fixture.manifest_path(), out_dir, runtime_dir, options)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULE: &str = "module Main exposing (main)\n\nmain =\n    1\n";

    #[test]
    fn a_fixture_is_the_project_the_resolver_returns() {
        let fixture = RootFixture::main(MODULE).expect("fixture");
        assert!(fixture.manifest_path().is_file());
        assert_eq!(fixture.root().manifest().name, "ipe-app");
        assert_eq!(fixture.path(), fixture.root().path());
    }

    #[test]
    fn a_tree_the_resolver_refuses_has_no_fixture() {
        let err = RootFixture::from_tree(&SourceTree::new()).expect_err("no entry");
        assert!(matches!(err, CliError::NoDefaultEntry { .. }), "{err}");
        let err = RootFixture::from_tree(&SourceTree::main(MODULE).field("sourceRoot = \"app\""))
            .expect_err("moved source root");
        assert!(matches!(err, CliError::Usage(_)), "{err}");
    }

    #[test]
    fn a_fixture_is_removed_on_drop() {
        let fixture = RootFixture::main(MODULE).expect("fixture");
        let path = fixture.path().to_path_buf();
        assert!(path.is_dir());
        drop(fixture);
        assert!(!path.exists());
    }
}

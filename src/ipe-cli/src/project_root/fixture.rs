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

/// An emitted crate built from a [`RootFixture`].
///
/// Its crate and binary names are read from the emitted manifest by the
/// production reader, so no test names the crate by a literal.
#[derive(Debug)]
pub struct BuiltFixture {
    out: PathBuf,
}

impl BuiltFixture {
    /// The directory holding the emitted crate.
    #[must_use]
    pub fn out(&self) -> &Path {
        &self.out
    }

    /// The emitted crate's `[package] name`.
    ///
    /// # Errors
    /// An unreadable or nameless emitted manifest is refused, never defaulted.
    pub fn crate_name(&self) -> Result<String, CliError> {
        crate::driver::emitted_bin_name(&self.out)
    }

    /// The executable cargo leaves in `profile_dir` for this crate.
    ///
    /// # Errors
    /// As [`BuiltFixture::crate_name`].
    pub fn binary_in(&self, profile_dir: &Path) -> Result<PathBuf, CliError> {
        Ok(profile_dir.join(crate::driver::emitted_bin_filename(&self.out)?))
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
) -> Result<BuiltFixture, CliError> {
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
) -> Result<BuiltFixture, CliError> {
    build_project_with_options(&fixture.manifest_path(), out_dir, runtime_dir, options)?;
    Ok(BuiltFixture {
        out: out_dir.to_path_buf(),
    })
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

    /// A scratch directory holding `manifest` as an emitted `Cargo.toml`.
    fn emitted(manifest: Option<&str>) -> (RootFixture, BuiltFixture) {
        let scratch = RootFixture::main(MODULE).expect("fixture");
        if let Some(text) = manifest {
            std::fs::write(scratch.path().join("Cargo.toml"), text).expect("manifest");
        }
        let built = BuiltFixture {
            out: scratch.path().to_path_buf(),
        };
        (scratch, built)
    }

    #[test]
    fn a_binary_path_is_joined_from_the_emitted_manifest() {
        let (_scratch, built) = emitted(Some("[package]\nname = \"demo_1a2b3c4d\"\n"));
        let profile = Path::new("target/debug");
        assert_eq!(built.crate_name().expect("name"), "demo_1a2b3c4d");
        assert_eq!(
            built.binary_in(profile).expect("binary"),
            profile.join(format!("demo_1a2b3c4d{}", std::env::consts::EXE_SUFFIX))
        );
    }

    #[test]
    fn a_manifest_without_a_plain_name_is_refused_never_defaulted() {
        let (_scratch, built) = emitted(Some("[package]\nname = \"../evil\"\n"));
        assert!(built.crate_name().is_err());
        assert!(built.binary_in(Path::new("target/debug")).is_err());
    }

    #[test]
    fn a_missing_manifest_is_refused_never_defaulted() {
        let (_scratch, built) = emitted(None);
        assert!(built.crate_name().is_err());
        assert!(built.binary_in(Path::new("target/debug")).is_err());
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

//! Inline test source and manifest-less `src/` goldens built through the fixed project root.

use std::path::Path;

use ipe::project_root::SourceTree;
use ipe::{CliError, RootFixture};

/// A project fixture whose only module is `Main`, holding `source`.
///
/// A fixture that cannot be written fails the test, never skips it.
#[track_caller]
#[allow(clippy::expect_used)] // a refusal or acceptance test must fail loudly on a setup failure
pub fn main(source: &str) -> RootFixture {
    RootFixture::main(source).expect("the project fixture must be written and resolved")
}

/// Build `fixture` into `out`, vendoring the runtime from `runtime`.
///
/// # Errors
/// As [`ipe::build_fixture`].
pub fn build(fixture: &RootFixture, out: &Path, runtime: &Path) -> Result<(), CliError> {
    ipe::build_fixture(fixture, out, runtime).map(drop)
}

/// Build the golden `golden`, whose `modules` sit under `src/` with no manifest, as a project.
///
/// Each module is read from `<golden>/src/<module>.ipe`; a module the golden
/// lacks is an error, never skipped.
///
/// # Errors
/// [`CliError::Io`] when a module cannot be read; otherwise as [`build`].
pub fn build_src_golden(
    golden: &Path,
    modules: &[&str],
    out: &Path,
    runtime: &Path,
) -> Result<(), CliError> {
    let src = golden.join("src");
    let mut tree = SourceTree::new();
    for module in modules {
        let path = src.join(format!("{module}.ipe"));
        let source = std::fs::read_to_string(&path).map_err(|source| CliError::Io { path, source })?;
        tree = tree.module(module, &source);
    }
    let fixture = RootFixture::from_tree(&tree)?;
    build(&fixture, out, runtime)
}

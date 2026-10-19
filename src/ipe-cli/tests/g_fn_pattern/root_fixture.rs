//! Inline test source built through the fixed project root.

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

/// A project fixture holding each `(module, source)` pair under `src/`.
///
/// A fixture that cannot be written fails the test, never skips it.
#[track_caller]
#[allow(clippy::expect_used)] // a refusal or acceptance test must fail loudly on a setup failure
pub fn project(modules: &[(&str, &str)]) -> RootFixture {
    let tree = modules
        .iter()
        .fold(SourceTree::new(), |tree, (module, source)| {
            tree.module(module, source)
        });
    RootFixture::from_tree(&tree).expect("the project fixture must be written and resolved")
}

/// Build `fixture` into `out`, vendoring the runtime from `runtime`.
///
/// # Errors
/// As [`ipe::build_fixture`].
pub fn build(fixture: &RootFixture, out: &Path, runtime: &Path) -> Result<(), CliError> {
    ipe::build_fixture(fixture, out, runtime).map(drop)
}

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

/// The project fixture holding every `src/<Name>.ipe` module of the golden at `dir`.
///
/// Such a golden has no `package.ipe`, so `support::build_golden` has no
/// project to build; the fixture holds the golden's own module files under a
/// written `package.ipe`.
#[track_caller]
#[allow(clippy::expect_used)] // an unreadable checked-in golden is a broken fixture: fail loudly
pub fn src_golden(dir: &Path) -> RootFixture {
    let src = dir.join("src");
    let mut files: Vec<_> = std::fs::read_dir(&src)
        .expect("the golden's src/ directory is readable")
        .map(|entry| entry.expect("a src/ entry is readable").path())
        .collect();
    files.sort();
    let mut tree = SourceTree::new();
    for file in &files {
        assert!(
            file.is_file() && file.extension().is_some_and(|ext| ext == "ipe"),
            "a src/ golden holds only flat module files, found {}",
            file.display()
        );
        let module = file
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("a module file stem is UTF-8");
        let source = std::fs::read_to_string(file).expect("a golden module is readable");
        tree = tree.module(module, &source);
    }
    RootFixture::from_tree(&tree).expect("the golden's modules resolve as a project")
}

/// Build `fixture` into `out`, vendoring the runtime from `runtime`.
///
/// # Errors
/// As [`ipe::build_fixture`].
pub fn build(fixture: &RootFixture, out: &Path, runtime: &Path) -> Result<(), CliError> {
    ipe::build_fixture(fixture, out, runtime).map(drop)
}

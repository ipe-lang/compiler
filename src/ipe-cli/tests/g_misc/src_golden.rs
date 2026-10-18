//! A checked-in golden that keeps its modules under `src/` with no manifest, as a project fixture.
//!
//! Such a golden has no `package.ipe`, so `support::build_golden` has no
//! project to build. The fixture holds the golden's own module files, one
//! module per `src/<Name>.ipe`, under a written `package.ipe`.

use std::path::Path;

use ipe::RootFixture;
use ipe::project_root::SourceTree;

/// The project fixture holding every `src/<Name>.ipe` module of the golden at `dir`.
#[allow(clippy::expect_used)] // an unreadable checked-in golden is a broken fixture: fail loudly
pub fn fixture_of(dir: &Path) -> RootFixture {
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

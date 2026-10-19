//! AUD-14 regression — two `import ... as <same alias>` statements naming
//! DIFFERENT dep modules must be rejected with `NameError::DuplicateQualifier`
//! (IPE-N0027), never silently resolve to whichever import came last in
//! source order. See `docs/architecture/principles-audit-2026-07-09.md`
//! (AUD-14) for the finding; the batch-a fix-spec's "A2" root-cause writeup
//! is preserved in git history.
//!
//! ```text
//! cargo test -p ipe --test golden_aud14_duplicate_qualifier
//! ```

use std::fs;
use std::path::PathBuf;

use ipe::RootFixture;
use ipe::project_root::SourceTree;

/// A project fixture holding one `src/` module per `(file, source)` pair.
#[allow(clippy::expect_used)] // a fixture-setup failure must fail the test loudly
fn write_project(files: &[(&str, &str)]) -> RootFixture {
    let tree = files
        .iter()
        .fold(SourceTree::new(), |tree, (file, source)| {
            let module = file
                .strip_suffix(".ipe")
                .expect("a fixture file is a `.ipe` module");
            tree.module(module, source)
        });
    RootFixture::from_tree(&tree).expect("the fixture project resolves")
}

/// Two distinct modules, `A` and `B`, both imported under the explicit alias
/// `Utils`. Without the collision check this silently resolves `Utils.format`
/// to whichever import is LAST in source order (`B`'s), with no diagnostic — a
/// well-typed program producing a wrong-module resolution.
#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn distinct_modules_sharing_an_explicit_alias_is_rejected() {
    let runtime = e2e_support::require_runtime().into_path_buf();

    let fixture = write_project(&[
        ("A.ipe", "module A exposing (format)\nformat = \"from A\"\n"),
        ("B.ipe", "module B exposing (format)\nformat = \"from B\"\n"),
        (
            "Main.ipe",
            "module Main exposing (main)\n\
                 import A as Utils\n\
                 import B as Utils\n\n\
import Ipe.Io
                 main = Io.println Utils.format\n",
        ),
    ]);

    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("aud14_duplicate_qualifier_out");
    let _ = fs::remove_dir_all(&out);

    let built = ipe::build_fixture(&fixture, &out, &runtime);
    let Err(err) = built else {
        panic!(
            "expected DuplicateQualifier rejection for two modules sharing alias `Utils`, \
             but ipe dev build SUCCEEDED — the last import silently won"
        )
    };
    let ipe::CliError::Pipeline { diag, .. } = &err else {
        panic!("expected a Pipeline diagnostic, got: {err}")
    };
    let ipe_diagnostics::Diagnostic::Name {
        msg: ipe_diagnostics::NameError::DuplicateQualifier { qualifier, .. },
        ..
    } = &**diag
    else {
        panic!("expected NameError::DuplicateQualifier, got: {err}")
    };
    assert_eq!(&**qualifier, "Utils");
}

/// Positive control: re-importing the SAME dep module under the same
/// qualifier twice (a diamond-dependency shape) must stay accepted — the
/// check only rejects a clash between two DIFFERENT dep modules.
#[test]
fn same_module_reimported_under_same_alias_is_accepted() {
    let runtime = e2e_support::require_runtime().into_path_buf();

    let fixture = write_project(&[
        ("A.ipe", "module A exposing (format)\nformat = \"from A\"\n"),
        (
            "Main.ipe",
            "module Main exposing (main)\n\
                 import A as Utils\n\
                 import A as Utils\n\n\
import Ipe.Io
                 main = Io.println Utils.format\n",
        ),
    ]);

    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("aud14_duplicate_qualifier_diamond_out");
    let _ = fs::remove_dir_all(&out);

    let built = ipe::build_fixture(&fixture, &out, &runtime);
    assert!(
        built.is_ok(),
        "re-importing the SAME module under the same alias twice must stay accepted: {:?}",
        built.err()
    );
}

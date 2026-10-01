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

fn write_project(dir: &std::path::Path, files: &[(&str, &str)]) -> bool {
    let src = dir.join("src");
    let _ = fs::remove_dir_all(dir);
    if fs::create_dir_all(&src).is_err() {
        return false;
    }
    files
        .iter()
        .all(|(name, contents)| fs::write(src.join(name), contents).is_ok())
}

/// Two distinct modules, `A` and `B`, both imported under the explicit alias
/// `Utils`. Without the collision check this silently resolves `Utils.format`
/// to whichever import is LAST in source order (`B`'s), with no diagnostic — a
/// well-typed program producing a wrong-module resolution.
#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn distinct_modules_sharing_an_explicit_alias_is_rejected() {
    let runtime = e2e_support::require_runtime().into_path_buf();

    let tmp = crate::support::scratch_root().join("ipec_aud14_duplicate_qualifier");
    let wrote = write_project(
        &tmp,
        &[
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
        ],
    );
    assert!(wrote, "must write the fixture project to a temp dir");

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("aud14_duplicate_qualifier_out");
    let _ = fs::remove_dir_all(&out);

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    let Err(err) = built else {
        panic!(
            "expected DuplicateQualifier rejection for two modules sharing alias `Utils`, \
             but ipe build SUCCEEDED — the last import silently won"
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

    let tmp = crate::support::scratch_root().join("ipec_aud14_duplicate_qualifier_diamond");
    let wrote = write_project(
        &tmp,
        &[
            ("A.ipe", "module A exposing (format)\nformat = \"from A\"\n"),
            (
                "Main.ipe",
                "module Main exposing (main)\n\
                 import A as Utils\n\
                 import A as Utils\n\n\
import Ipe.Io
                 main = Io.println Utils.format\n",
            ),
        ],
    );
    assert!(wrote, "must write the fixture project to a temp dir");

    let entry = tmp.join("src").join("Main.ipe");
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("aud14_duplicate_qualifier_diamond_out");
    let _ = fs::remove_dir_all(&out);

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "re-importing the SAME module under the same alias twice must stay accepted: {:?}",
        built.err()
    );
}

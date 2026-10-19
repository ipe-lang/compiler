//! `Store.selectToList` / `Store.selectToMaybe` read the projected rows in every call form.
//!
//! `x |> f a` is `f a x`, so the piped (`j |> Store.select f |> Store.selectToList
//! db`), back-piped (`<|`), composed (`>>`) and nested-pipe forms of a
//! projection read must return what the direct call returns. The intercept
//! collapses the call spine before it reads the `Store.select` expression, and
//! the lowering refuses any IR edge to the placeholder `selectTo*` bodies, so a
//! form the intercept missed is a build error rather than a runtime `Err`.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "db_store_select_pipe";

fn golden_dir(root: &Path) -> PathBuf {
    root.join("tests").join("golden").join(GOLDEN)
}

/// Every pipe, back-pipe, composition and nested-pipe `selectTo*` form is accepted and emitted.
///
/// A form whose `selectTo*` reference escaped the intercept would reach the
/// placeholder body, which the lowering refuses as an IPE-L0149 build error;
/// a successful build therefore proves every form in the fixture was
/// intercepted, without running it.
#[test]
fn db_store_select_pipe_builds() {
    let root = repo_root();
    let golden_project = golden_dir(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_select_pipe_build");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&golden_project, &out, &runtime);
    assert!(
        built.is_ok(),
        "every call form of `Store.selectToList` / `Store.selectToMaybe` with a \
         visible `Store.select` expression must be accepted, got: {built:?}"
    );
}

/// Under `IPE_E2E=1`, each call form reads its projected rows on `sqlite::memory:`.
///
/// The emitted crate is built and run; its stdout must match `expected.txt`
/// line for line, so no form returns the placeholder `Err`.
#[test]
fn db_store_select_pipe_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let dir = golden_dir(&root);
    let out = crate::support::scratch_root().join("ipec_db_store_select_pipe_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&dir, &out, &runtime);
    assert!(
        built.is_ok(),
        "build failed for {GOLDEN}: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
    crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "{GOLDEN} must exit 0");
}

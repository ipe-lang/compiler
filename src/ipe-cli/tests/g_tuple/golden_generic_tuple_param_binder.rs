//! Generic tuple-pattern parameter gate: `fst (a, b) = a` and
//! `pick (a, b) flag` under polymorphic signatures, each instantiated at two
//! types, so every tuple component binder resolves against its own
//! definition's type variables. `ipe` must emit `main.rs` byte-identical to the checked-in
//! golden, and (behind `IPE_E2E=1`) the emitted project must build and print
//! `40 ok r 1`.
//!
//! ```text
//! fst : ( a, b ) -> a
//! fst (a, b) = a
//! pick : ( a, a ) -> Bool -> a
//! pick (a, b) flag = if flag then a else b
//! main = Io.println (String.fromInt (fst (40, "x")) ++ " " ++ fst ("ok", 2)
//!     ++ " " ++ pick ("l", "r") False ++ " " ++ String.fromInt (pick (1, 2) True))
//! ```
use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "generic_tuple_param_binder";

fn golden_dir(root: &Path) -> PathBuf {
    root.join("tests").join("golden").join(GOLDEN)
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let dir = golden_dir(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("generic_tuple_param_binder_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve: {:?}", runtime.err());
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&dir.join("Main.ipe"), &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    crate::support::assert_emitted_project_matches_golden_dir(&out, &dir);
}

/// Full spine: the emitted project builds and prints `40 ok r 1`.
///
/// Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_both_instantiations() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = golden_dir(&root);
    let out = crate::support::scratch_root().join("ipec_generic_tuple_param_binder_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&dir.join("Main.ipe"), &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
    crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

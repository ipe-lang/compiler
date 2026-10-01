//! IPE-L0105 lambda / function parameter patterns — positive surface,
//! end to end. The fixture exercises every irrefutable binding-position shape in
//! ONE program (each contributing to a hand-computed total of `112`):
//!
//! * `\_ -> …` — the dominant wildcard-lambda idiom, in argument position.
//! * `\(a, b) -> …` / `\{ x } -> …` — tuple / record field-pun lambda params.
//! * `\_ x (a, b) -> …` — a MULTI-parameter lambda mixing all three shapes.
//! * `f _ = …` / `f (a, b) = …` / `f { y } = …` — the same shapes as def heads.
//! * `((a, b) as whole)` — an alias over a destructure.
//! * a TAIL-RECURSIVE `f (n, acc) = … f (n - 1, acc + n)` proving the tuple
//!   destructure re-runs each iteration (the prologue folds INSIDE the `TailLoop`).
//!
//! Two locks:
//!
//! 1. `ipe` emits `main.rs` byte-identical to the checked-in golden — which
//!    records the exact desugaring: each non-var param takes a GLOBALLY-unique
//!    synthetic binder (`arg_0` … `arg_9`, never a shadowed reuse), a record
//!    param recovers its COMPLETE field set from the solved type
//!    (`RecXY { x: _, y, .. }`), and `\_ ->` emits NO destructure (it rides the
//!    preamble `#![allow(unused, non_snake_case)]`).
//! 2. Behind `IPE_E2E=1` the emitted project builds and prints `112`, exit 0 —
//!    the soundness floor: an irrefutable param never fails a match at runtime.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn fixture_dir(root: &Path) -> PathBuf {
    root.join("tests").join("golden").join("param_patterns")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = fixture_dir(&root).join("Main.ipe");
    let golden = fixture_dir(&root).join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("l0105_param_patterns_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    // Directory-diff the emitted project against the golden dir (byte-compares
    // the emitted `src/main.rs` against the golden `main.rs`). Replaces the
    // former hand-rolled `read_to_string` + `assert_eq!` pair with the shared
    // harness helper.
    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// Structural invariants that must survive any future codegen churn, asserted
/// independently of the byte-identical lock so a regression names the exact
/// property it broke.
#[test]
fn emission_preserves_the_load_bearing_shapes() {
    let root = repo_root();
    let entry = fixture_dir(&root).join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("l0105_param_patterns_shapes");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());
    let src = crate::support::read_all_emitted_src(&out);

    // `\_ ->` / `f _ =` stay warning-clean under the preamble.
    assert!(
        src.contains("#![allow(unused"),
        "preamble must keep #![allow(unused …)] so `\\_ ->` is warning-clean"
    );
    // A wildcard param emits NO destructure — just an unused synthetic binder.
    // Visibility is `pub(crate)` when in a split module file, `pub` in
    // single-file emit; match the function signature without the visibility
    // keyword so the assertion holds under both layouts.
    assert!(
        src.contains("fn main_ignore_arg(arg_0: i64) -> i64 {"),
        "wildcard def param → fresh unused binder, no destructure:\n{src}"
    );
    // A record param recovers its COMPLETE field set from the solved type.
    assert!(
        src.contains("let RecXY { x: _, y, .. } = arg_2;"),
        "record param → complete field set (x wildcarded, y bound):\n{src}"
    );
    // The tail-recursive tuple destructure re-runs INSIDE the loop, and the
    // synthetic binder is reassigned each iteration.
    assert!(
        src.contains("let mut arg_4 = arg_4;") && src.contains("let (n, acc) = arg_4;"),
        "tail-recursive tuple destructure must re-run per iteration:\n{src}"
    );
    // Globally-unique binders: the lambda inside the body uses a DISTINCT name
    // (`arg_5`), never a shadowed reuse of a def param binder.
    assert!(
        src.contains("move |arg_5: i64| -> i64 { 42i64 }"),
        "`\\_ ->` lambda → distinct fresh binder, no destructure:\n{src}"
    );
}

/// Full spine: build the emitted Cargo project, run it, assert it prints `112`
/// (the hand-computed total) and exits 0. Gated on `IPE_E2E=1`. This is the
/// soundness-floor regression: every irrefutable param binds every value of its
/// type, so no run-time match failure is possible.
#[test]
fn end_to_end_builds_and_prints_one_hundred_twelve() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let entry = fixture_dir(&root).join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_l0105_param_patterns_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("param_patterns", &out);
    assert_eq!(outcome.stdout.trim_end(), "112", "hand-computed total");
    assert_eq!(outcome.exit_code, Some(0), "clean exit — no match failure");
}

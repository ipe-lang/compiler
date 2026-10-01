//! Regression for adversarial-review Finding B: a `case`-dispatched `ipe_main`
//! where every arm produces a `Result`-typed expression (the validate-then-
//! return idiom, `Err e -> Err e; Ok cfg -> Ok cfg`).
//!
//! `emit_func`'s `ipe_main_wrap` fallback covers `func.ret == Result(_, A)`:
//! the body evaluates synchronously to a uniform `Result e a` and wraps in
//! `task_from_result({ <original body> })` — an ALREADY-RESOLVED `IpeTask<A>`
//! carrying the body's actual computed `Ok`/`Err`, not a discarded one
//! (contrast the sibling `Unit`-return wrap, which always returns
//! `task_succeed(())`).
//!
//! Same DEFAULT-gate structure as `golden_tui_entry_case_seal.rs`: the first
//! two tests inspect the emitted `src/main.rs` text (no cargo build) so they
//! pin the regression even when `IPE_E2E` is unset; the third is the
//! `IPE_E2E`-gated cargo-build-and-run proof.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("mixed_arm_task_run_elision")
        .join("Main.ipe")
}

/// Build the fixture and return the emitted `src/main.rs` text. `None` when the
/// build fails (the caller's `assert!` reports the diag).
fn built_main_rs(root: &Path, out: &Path) -> (Result<(), ipe::CliError>, Option<String>) {
    let entry = fixture_entry(root);
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, out, &runtime);
    let main_rs = if built.is_ok() {
        std::fs::read_to_string(out.join("src").join("main.rs")).ok()
    } else {
        None
    };
    (built, main_rs)
}

/// `ipe_main` must return `IpeTask<…>` (the wrapped shape the
/// `block_on(ipe_main())` epilogue requires), never `IpeResult<…>` — even
/// though the body's arms are a genuine MIX of `Task.run` calls and plain
/// `Result` expressions, so `elide_task_run_tail` cannot elide.
#[test]
fn mixed_arm_entry_point_wraps_to_ipetask() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_mixed_arm_task_run_elision_signature");
    let (built, main_rs) = built_main_rs(&root, &out);
    assert!(
        built.is_ok(),
        "mixed_arm_task_run_elision: must be accepted, got: {built:?}"
    );
    let main_rs = main_rs.expect("an accepted build yields the emitted source");

    assert!(
        main_rs.contains("fn ipe_main() -> IpeTask<"),
        "ipe_main must return IpeTask<…> when its case arms all return \
         Result expressions — the block_on(ipe_main()) epilogue requires \
         a Task, not a Result. Got signature region:\n{}",
        main_rs
            .lines()
            .filter(|l| l.contains("ipe_main") || l.contains("IpeTask") || l.contains("IpeResult"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        !main_rs.contains("fn ipe_main() -> IpeResult<"),
        "ipe_main must not return IpeResult<…> — that is the un-wrapped \
         shape that mismatches block_on's IpeTask<…> parameter.\n{}",
        main_rs
            .lines()
            .filter(|l| l.contains("ipe_main"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The wrap must carry the body's ACTUAL computed value through
/// `task_from_result`, not discard it the way the sibling `Unit`-return wrap
/// discards its body via `task_succeed(())` — the Ok/Err arms must remain the
/// exact `IpeResult` the un-wrapped body would have produced.
#[test]
fn mixed_arm_entry_point_wraps_via_task_from_result() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_mixed_arm_task_run_elision_wrap_shape");
    let (built, main_rs) = built_main_rs(&root, &out);
    assert!(
        built.is_ok(),
        "mixed_arm_task_run_elision: must be accepted, got: {built:?}"
    );
    let main_rs = main_rs.expect("an accepted build yields the emitted source");

    assert!(
        main_rs.contains("task_from_result({"),
        "expected ipe_main's body to wrap in task_from_result({{ .. }}) so \
         the body's actual Ok/Err value is preserved (not discarded like \
         the Unit-return task_succeed(()) wrap); got:\n{main_rs}",
    );
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, actually `cargo build` the
/// emitted crate and run it, confirming the `task_from_result` wrap round-trips
/// the body's `Ok`/`Err` through `block_on` back to `fn main`'s epilogue. The
/// body performs no effect, so the `Ok(_)` epilogue exits 0 with empty stdout.
#[test]
fn mixed_arm_task_run_elision_builds_and_runs() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_mixed_arm_task_run_elision_e2e");
    let runtime = e2e_support::require_runtime().into_path_buf();
    let entry = fixture_entry(&root);
    let _ = std::fs::remove_dir_all(&out);
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "mixed_arm_task_run_elision: must be accepted, got: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("mixed_arm_task_run_elision", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "mixed_arm_task_run_elision: emitted crate must build and exit 0; stdout:\n{}",
            outcome.stdout
        );
        assert!(
            outcome.stdout.trim().is_empty(),
            "the effect-free Result body must produce no output; got: {:?}",
            outcome.stdout
        );
    }
}

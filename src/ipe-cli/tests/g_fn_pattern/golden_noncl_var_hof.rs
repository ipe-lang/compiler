//! Seal — `NonClone` Var forwarded as a HOF callback must not emit IPE-L0126.
//!
//! Root cause (b): the slot type for `Task.andThen writeAll` IS resolved by
//! `ir_type_from_ty`, but it resolves to `IrType::Fun` whose `clone_class` is
//! `NonClone`.  Before this fix, any `Expr::Var` in a `NonClone` slot triggered
//! `return Err(IPE-L0126)` — even when the Var is merely forwarded as a `FnOnce`
//! callback that consumes it exactly once.
//!
//! In `eta_expand_partial`, the `Some(CloneClass::NonClone)` arm for a
//! bare `Expr::Var` falls through (`{}`) — the Var is bare-moved into the
//! fresh eta-lambda.  The `None` arm (genuinely unknown slot type) keeps the
//! conservative L0126 fail-close.
//!
//! Fixture shape: `Task.succeed "hello" |> Task.andThen go` where `go` is a
//! let-bound local of type `String -> Task Error String`.
//!
//! ```text
//! # compile-only check (fast, no IPE_E2E needed):
//! cargo test -p ipe --test golden_i149_noncl_var_hof
//!
//! # full E2E (run emitted binary):
//! IPE_E2E=1 cargo test -p ipe --test golden_i149_noncl_var_hof
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Assert that `ipe::build(fixture)` SUCCEEDS (exit-0 from the lowerer).
/// Runs without `IPE_E2E` so the compile check is always fast.
fn assert_ipec_ok(fixture: &str, out_suffix: &str) {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out_suffix);
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for fixture {fixture}: {:?}",
        built.err()
    );
}

// ── A1 — NonClone Var (let-bound fn) forwarded to Task.andThen ───────────────

/// `go = step` where `step : String -> Task Error String`, then
/// `Task.succeed "hello" |> Task.andThen go`.  This must not emit
/// IPE-L0126 ("non-Clone capture in a closure is not yet supported");
/// it compiles and, when run, prints "hello!".
#[test]
fn a1_noncl_var_task_and_then_compiles() {
    assert_ipec_ok("noncl_var_hof", "i149_noncl_var_hof_emit");

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let root = repo_root();
        let entry = root
            .join("tests")
            .join("golden")
            .join("noncl_var_hof")
            .join("Main.ipe");
        let out = crate::support::scratch_root().join("ipec_i149_noncl_var_hof_e2e");
        let _ = std::fs::remove_dir_all(&out);

        let runtime = e2e_support::require_runtime().into_path_buf();

        let built = ipe::build(&entry, &out, &runtime);
        assert!(
            built.is_ok(),
            "ipe dev build must succeed for noncl_var_hof: {:?}",
            built.err()
        );

        let outcome = crate::support::build_and_run_emitted("noncl_var_hof", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "A1: must exit 0 (was IPE-L0126 before #149)"
        );
        assert!(
            outcome.stdout.contains("hello!"),
            "A1: NonClone Var forwarded to Task.andThen must produce 'hello!'; got:\n{}",
            outcome.stdout
        );
    }
}

//! IPE-L0102 regression seal — wildcard lambda parameter `\_ -> expr`.
//!
//! A `PAnything` (wildcard `_`) lambda parameter whose type is a free
//! `Ty::Var(_)` — a type variable HM inference leaves unconstrained because the
//! parameter is discarded — would make the lowerer raise
//! `Feature::Polymorphism`.  Instead, `ir_type_from_ty_json` maps `Ty::Var(_)`
//! to `IrType::Json` and emits a fresh `_ipe_wildcard_N` binder in
//! `lower_lambda` / `eta_expand_partial`.
//!
//! Root cause: three call sites missed — `lower_lambda` (direct `\_ -> body`),
//! `eta_expand_partial` (eta-expanded closure for partially-applied kernels),
//! and the `TaskRun`/`TaskPerform` constraint left the error type as a free
//! variable `result(var(1), var(0))` instead of `result(error_ty(), var(0))`.
//!
//! Shapes tested:
//!   * `\_ -> Task.succeed v` — lambda with wildcard ignoring prior result
//!   * `Task.fail e |> Task.andThen (\_ -> Task.succeed "unreachable")`
//!   * `ignore : a -> Task Error String` with `_` as named binder
//!
//! Asserts ipe-0 ∧ cargo-0 ∧ run produces expected output. `Error.toString`
//! renders the `ErrorKind` ADT as `"<Kind>: <message>"`, so the `Task.fail`
//! chain prints `err: Unexpected: intentional`.
//!
//! Gated on `IPE_E2E=1`. Run:
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_l0102_wildcard_lambda_pany
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn wildcard_lambda_pany_ipec_cargo_and_run_zero() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = root
        .join("tests")
        .join("golden")
        .join("wildcard_lambda_pany");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_l0102_wildcard_lambda_pany_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    // ipe-0: compiler must succeed.  Without the wildcard mapping this fails
    // with IPE-L0102 ("unsupported feature: Polymorphism") on the `\_ ->`
    // lambda parameter.
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for wildcard_lambda_pany (was: IPE-L0102 Polymorphism): {:?}",
        built.err()
    );

    // cargo-0 ∧ run: the emitted binary must build, run, and produce the
    // expected output showing all three shapes executed correctly.
    let outcome = crate::support::build_and_run_emitted("wildcard_lambda_pany", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "binary must exit 0; stdout:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("ok: done"),
        "Task.succeed chain must print 'ok: done'; got:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("err: Unexpected: intentional"),
        "Task.fail chain must print 'err: Unexpected: intentional'; got:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("ignore: ignored"),
        "ignore helper must print 'ignore: ignored'; got:\n{}",
        outcome.stdout
    );
}

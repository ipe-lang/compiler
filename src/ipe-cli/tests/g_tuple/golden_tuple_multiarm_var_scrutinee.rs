//! Multi-arm / refutable tuple `case` on a NON-literal scrutinee.
//!
//! `Ipe.Test.summarise` matches `case pair of ( _, Passed ) -> … ; ( name,
//! Failed _ ) -> …`. The scrutinee `pair` is a VARIABLE, not a literal tuple, so
//! the pre-tuple-match path (which needs the element expressions to apply
//! per-column slice / `&str` coercions) did not apply and the arm fell
//! fail-closed as IPE-L0115. It now lowers to a by-value whole `match pair { (_,
//! Passed) => …, (name, Failed(_)) => … }` — no coercion, the tuple matches by
//! value. A column that WOULD need coercion (a string literal, or a cons / list
//! sub-pattern) still requires the literal-tuple scrutinee, so it stays
//! fail-closed on the non-literal path (the coercion machinery only exists for a
//! literal-tuple scrutinee).
//!
//! Gate check (fast, always): `ipe build` succeeds — no IPE-L0115.
//! Green check (`IPE_E2E=1`): the emitted Rust cargo-builds AND runs, proving the
//! Seal (ipe-0 ⟹ cargo-0) for the by-value whole tuple-match codegen.
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_tuple_multiarm_var_scrutinee
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry() -> PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join("i_tuple_multiarm_var_scrutinee")
        .join("Main.ipe")
}

/// Fast gate: a multi-arm refutable tuple `case` on a VARIABLE scrutinee builds
/// cleanly — the IPE-L0115 product gap is closed for the `Ipe.Test.summarise`
/// shape.
#[test]
fn var_scrutinee_tuple_case_builds() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("tuple_var_scrut_gate");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&fixture_entry(), &out, &runtime);
    assert!(
        built.is_ok(),
        "variable-scrutinee multi-arm tuple `case` must build (IPE-L0115 close); got {:?}",
        built.err()
    );
}

/// Seal: the emitted Rust cargo-builds and runs. The sum in `main` is
/// `7 + 0 + 10 + 20 + 30 + 105 + 200 == 372`.
#[test]
fn var_scrutinee_tuple_case_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let out = crate::support::scratch_root().join("ipec_tuple_var_scrut_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&fixture_entry(), &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for i_tuple_multiarm_var_scrutinee: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("i_tuple_multiarm_var_scrutinee", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "emitted by-value tuple-match program must exit 0"
    );
    assert!(
        outcome.stdout.contains("372"),
        "expected '372' (7+0+10+20+30+105+200); got:\n{}",
        outcome.stdout
    );
}

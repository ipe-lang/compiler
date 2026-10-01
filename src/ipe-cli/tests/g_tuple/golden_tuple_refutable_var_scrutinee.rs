//! Tuple `case` on a NON-literal scrutinee with refutable list / cons columns.
//!
//! The exact shape from issue #1532: `List.partition` returns a tuple and the
//! arms match on list patterns in one column. Before this fix, the lowerer
//! rejected such a `case` with IPE-L0115 because the coerced-column path
//! (which can apply `.as_slice()` to individual element expressions) requires
//! a literal-tuple scrutinee — a non-literal like a function call or variable
//! has no individual element expressions to coerce.
//!
//! The fix synthesises a literal-tuple scrutinee: the non-literal scrutinee is
//! destructured into fresh element temps and an `Expr::Tuple` of those vars is
//! used as the match scrutinee, enabling the coerced-column backend path.
//!
//! Three shapes are tested:
//!
//! * Shape 1 — the issue example: `case List.partition … of ( [ row ], rest )
//!   -> … ; ( _, rest ) -> …`
//! * Shape 2 — cons column: `case pair of ( a :: as, b :: bs ) -> … ;
//!   ( _, _ ) -> …`
//! * Shape 3 — singleton gate: `case pair of ( [ x ], _ ) -> x ; ( _, _ ) -> 0`
//!
//! Still fail-closed (PROBE G: nested-tuple column with a list sub-pattern):
//! a `PTuple` column carries its OWN nested product that would need per-column
//! coercion — the synthesis does not recurse into nested tuples and stays
//! IPE-L0115.
//!
//! Gate check (fast, always): `ipe build` succeeds — no IPE-L0115.
//! Green check (`IPE_E2E=1`): the emitted Rust cargo-builds AND runs.
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test g_tuple
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
        .join("i_tuple_refutable_var_scrutinee")
        .join("Main.ipe")
}

/// Fast gate: a non-literal tuple scrutinee with list / cons columns builds
/// cleanly — the IPE-L0115 gap is closed for the issue #1532 shape.
#[test]
fn refutable_var_scrutinee_builds() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("tuple_refutable_var_scrut_gate");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&fixture_entry(), &out, &runtime);
    assert!(
        built.is_ok(),
        "non-literal-scrutinee tuple `case` with list column must build (IPE-L0115 close); \
         got {:?}",
        built.err()
    );
}

/// Seal (`IPE_E2E=1`): the emitted Rust cargo-builds and produces the correct
/// output. The `main` function computes `updatedLen + zipped + s1 + s2`
/// = 2 + 3 + 42 + 0 = 47.
#[test]
fn refutable_var_scrutinee_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let out = crate::support::scratch_root().join("ipec_tuple_refutable_var_scrut_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&fixture_entry(), &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for i_tuple_refutable_var_scrutinee: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("i_tuple_refutable_var_scrutinee", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "emitted refutable-var-scrutinee tuple-match program must exit 0"
    );
    assert!(
        outcome.stdout.contains("47"),
        "expected '47' (2+3+42+0); got:\n{}",
        outcome.stdout
    );
}

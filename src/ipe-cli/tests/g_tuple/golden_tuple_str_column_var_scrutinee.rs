//! A VARIABLE (non-literal) tuple `case` with a STRING-LITERAL column.
//!
//! `Ipe.Ui.Transform.propsToCss` matches `case pair of ( "transform", v ) -> …`
//! (a variable scrutinee, a string-literal column) — used by
//! `Ipe.Ui.Transform` / `Ipe.Ui.Animation` / `26-ui-showcase`. Admitting a
//! variable tuple scrutinee while fail-closing any string-literal column to
//! IPE-L0115 (no per-column `.as_str()` coercion on the by-value path) would
//! reject this shape.
//!
//! It lowers via the reference's guard mechanism: each `PStr` column
//! becomes a fresh binder plus an `if __sgN.as_str() == "lit"` match guard, so it
//! emits `match pair { (__sg0, v) if __sg0.as_str() == "transform" => …, … }` — a
//! by-value binder + guard, sound for a variable scrutinee. A list / cons column
//! still requires the literal-tuple coerced-column path and stays fail-closed.
//!
//! Gate check (fast, always): `ipe dev build` succeeds — no IPE-L0115.
//! Green check (`IPE_E2E=1`): the emitted Rust cargo-builds AND runs, the right
//! arm firing for every input — proving the seal (ipe-0 ⟹ cargo-0) AND runtime
//! correctness (a mis-coerced guard firing the wrong arm is the worst outcome).
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_tuple_str_column_var_scrutinee
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
        .join("tuple_str_column_var_scrutinee")
        .join("Main.ipe")
}

/// Fast gate: a multi-arm tuple `case` on a VARIABLE scrutinee with a
/// string-literal column builds cleanly — the IPE-L0115 gap is closed for the
/// `Ipe.Ui.Transform.propsToCss` shape.
#[test]
fn str_column_var_scrutinee_builds() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("tuple_str_col_var_scrut_gate");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&fixture_entry(), &out, &runtime);
    assert!(
        built.is_ok(),
        "variable-scrutinee string-column tuple `case` must build (#182); got {:?}",
        built.err()
    );
}

/// Seal + runtime correctness: the emitted Rust cargo-builds and runs, the right
/// arm firing for every input. The program prints
/// `scale(0.9)|other|F|T|1121` (see the fixture's arithmetic).
#[test]
fn str_column_var_scrutinee_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let out = crate::support::scratch_root().join("ipec_tuple_str_col_var_scrut_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&fixture_entry(), &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for tuple_str_column_var_scrutinee: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("tuple_str_column_var_scrutinee", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "emitted string-column tuple-match program must exit 0"
    );
    // The exact string proves the RIGHT arm fired for every probe — a mis-coerced
    // guard would return a different arm's value.
    assert!(
        outcome.stdout.contains("scale(0.9)|other|F|T|1121"),
        "expected 'scale(0.9)|other|F|T|1121'; got:\n{}",
        outcome.stdout
    );
}

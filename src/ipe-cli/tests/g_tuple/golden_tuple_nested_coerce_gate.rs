//! A coercing leaf nested inside a nested-TUPLE column on a
//! VARIABLE (non-literal) tuple scrutinee.
//!
//! Two shapes, two outcomes (both SEAL-clean — never ipe-0-then-cargo-fail):
//!
//! * PROBE E — a string LITERAL (`PStr`) nested in a nested-tuple column:
//!   `case v of ( ( "x", n ), A ) -> …` on `v : ((String,Int), Tag)`.
//!   **This is SUPPORTED.** The backend renders each nested `PStr` leaf as
//!   a fresh binder plus an `if __sgN.as_str() == "lit"` match guard, so it lowers
//!   to `match v { ((__sg0, n), Tag::A) if __sg0.as_str() == "x" => … }` — a
//!   by-value binder + `as_str()` guard, sound for a variable scrutinee (mirrors
//!   the reference's `renderPatGuarded`). ipe-0 ⟹ cargo-0 ⟹ the right arm fires.
//!
//! * PROBE G — a CONS sub-pattern (`PCons`) nested in a nested-tuple column:
//!   `case v of ( ( x :: _, n ), A ) -> …` on `v : ((List Int,Int), Tag)`.
//!   **Still fail-closed to IPE-L0115.** A slice pattern needs `&[T]` from an
//!   owned `Vec`, which only the literal-tuple coerced-column path can produce
//!   (there are no element expressions to `.as_slice()`-wrap a variable tuple
//!   column). So a `PList` / `PCons` column at any depth stays an honest
//!   ipe-fail, never an exit-0-then-cargo-fail.

use std::path::PathBuf;

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(fixture: &str) -> PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe")
}

/// Build the named golden fixture and assert it surfaces exactly IPE-L0115 as a
/// pipeline diagnostic. A build that SUCCEEDS (an exit-0 hole), or fails with any
/// other error, makes `got` differ from `Some(IPE_L0115)` and fails with a
/// descriptive message — never a panic. A skip occurs only when the runtime
/// cannot be resolved.
fn assert_l0115_gate(fixture: &str, out_suffix: &str) {
    let entry = fixture_entry(fixture);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out_suffix);
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_L0115),
        "fixture {fixture}: a list / cons sub-pattern nested in a nested-tuple column \
         must fail closed to IPE-L0115 (never ipe-0-then-cargo-fail); got build \
         result {built:?}"
    );
}

/// PROBE E: a string literal (`PStr`) nested inside a nested-tuple column now
/// LOWERS (fast gate — `ipe build` succeeds).
#[test]
fn nested_tuple_str_column_builds() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("tuple_nested_coerce_str_gate");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&fixture_entry("i_tuple_nested_coerce_str"), &out, &runtime);
    assert!(
        built.is_ok(),
        "a string-literal column nested in a nested-tuple column on a variable \
         scrutinee must build (#182 binder + `as_str()` guard); got {:?}",
        built.err()
    );
}

/// PROBE E seal (`IPE_E2E=1`): the emitted Rust cargo-builds and runs, the right
/// arm firing. `classify (("x", 5), A)` matches the first arm → prints `5`.
#[test]
fn nested_tuple_str_column_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let out = crate::support::scratch_root().join("ipec_tuple_nested_coerce_str_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&fixture_entry("i_tuple_nested_coerce_str"), &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for i_tuple_nested_coerce_str: {:?}",
        built.err()
    );
    let outcome = crate::support::build_and_run_emitted("i_tuple_nested_coerce_str", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "emitted string-column tuple-match program must exit 0"
    );
    assert!(
        outcome.stdout.contains('5'),
        "expected '5' (first arm, `(\"x\", 5)`); got:\n{}",
        outcome.stdout
    );
}

/// PROBE G: a cons sub-pattern (`PCons`) nested inside a nested-tuple column stays
/// fail-closed to IPE-L0115 — only the literal-tuple coerced-column path can
/// lower a slice column soundly.
#[test]
fn nested_tuple_cons_column_is_ipe_l0115() {
    assert_l0115_gate(
        "i_tuple_nested_coerce_cons",
        "tuple_nested_coerce_cons_emit",
    );
}

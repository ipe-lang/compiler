//! AUD-12 regression: numeric-var defaulting must gate on the class's full
//! accumulated bounds, not only the `Number` bit.
//!
//! Root cause: `f x = (x ++ x) + 1` gave `x` both `Append` and `Number`
//! super-type obligations. The defaulting arm fired on `has_number()` and
//! pinned `x` to `Int` WITHOUT checking whether `Int` satisfied `Append`
//! (it does not). ipe accepted (exit 0) and emitted Rust that `cargo`
//! rejected — a seal violation.
//!
//! Fix: before pinning to `Int`, call `concrete_super_ok(interner, bounds,
//! &int_ty)`. If it returns false, emit `super_unsatisfied` (IPE-T0014)
//! instead of the structural pin.

use std::path::PathBuf;

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden(name: &str) -> PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

fn out(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name)
}

/// Negative: `f x = (x ++ x) + 1` must be rejected with IPE-T0014,
/// never accepted at exit 0 (a seal violation).
#[test]
fn append_and_number_on_same_var_is_ipe_t0014() {
    let rt = e2e_support::require_runtime().into_path_buf();
    let o = out("append_number");
    let _ = std::fs::remove_dir_all(&o);
    let built = ipe::build(&golden("append_number"), &o, &rt);
    let code = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        code,
        Some(ipe_diagnostics::IPE_T0014),
        "expected IPE-T0014 (Append+Number unsatisfied by Int), got: {built:?}"
    );
}

/// Positive control: `f x = x + 1` (Number-only, no Append) must still
/// compile — the fix must not over-tighten the defaulting rule.
#[test]
fn number_only_var_still_defaults_to_int() {
    let rt = e2e_support::require_runtime().into_path_buf();
    let o = out("number_only");
    let _ = std::fs::remove_dir_all(&o);
    let built = ipe::build(&golden("number_only"), &o, &rt);
    assert!(
        built.is_ok(),
        "Number-only super var must still default to Int and compile: {built:?}"
    );
}

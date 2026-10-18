//! The interpolable obligation of `{{expr}}` interpolation (the internal
//! `Interpolate : a -> String` renderer) and `Log.*With` attributes.
//!
//! The argument must be one of the closed scalar set `String` / `Int` /
//! `Float` / `Bool` / `Char`, lowered to the runtime's sealed `IpeInterpolate`.
//! A record, custom type or function is refused AT TYPE-CHECK (IPE-T0014,
//! fail-closed), never emitting an `interpolate_to_string::<T>` that `cargo`
//! would reject.
//!
//! Positive case is `IPE_E2E`-gated (build + run). The negative cases are pure
//! ipe compiles (no cargo), so they always run.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

fn compile_golden(name: &str) -> PathBuf {
    let root = repo_root();
    let entry = golden_dir(&root, name).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());
    out
}

/// Interpolating scalars compiles + runs (`Bool` renders lowercase, the
/// `String.fromBool` form).
#[test]
fn tostring_scalars_run() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_golden("m_tostring");
    let out = crate::support::build_and_run_emitted("m_tostring", &dir);
    assert_eq!(out.exit_code, Some(0), "got {:?}", out.exit_code);
    assert_eq!(out.stdout.trim(), "42 true 3");
}

/// Interpolating a RECORD and a custom type is refused at ipe type-check with
/// IPE-T0014 — never an ipe-accept followed by a `cargo` E0277, and never a
/// `Debug` rendering of the composite. A pure compile — no `IPE_E2E` needed.
#[test]
fn tostring_record_and_adt_are_refused() {
    let root = repo_root();
    let entry = golden_dir(&root, "m_tostring_composite").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m_tostring_composite_refused");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let code = match ipe::build(&entry, &out, &runtime) {
        Err(ipe::CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        code,
        Some(ipe_diagnostics::IPE_T0014),
        "interpolating a record / custom type must be refused as not interpolable"
    );
}

/// `Log.infoWith : String -> List a -> Task Error ()` with scalar attrs
/// compiles (the interpolable obligation on the list element) — a pure ipe
/// compile.
#[test]
fn log_info_with_scalar_attrs_compiles() {
    let root = repo_root();
    let entry = golden_dir(&root, "m_log_with").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m_log_with_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "Log.infoWith with String attrs must compile: {:?}",
        built.err()
    );
}

/// SEAL-PRESERVING negative gate: interpolating a FUNCTION is rejected at ipe
/// type-check (a function is outside the interpolable scalar set), NOT deferred to
/// a cargo failure. A pure compile — no `IPE_E2E` needed.
#[test]
fn tostring_on_function_is_rejected_at_typecheck() {
    let root = repo_root();
    let entry = golden_dir(&root, "m_tostring_fn_rejected").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m_tostring_fn_rejected_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_err(),
        "interpolating a function MUST fail at ipec type-check (interpolable obligation), \
         not exit 0 and defer to cargo",
    );
}

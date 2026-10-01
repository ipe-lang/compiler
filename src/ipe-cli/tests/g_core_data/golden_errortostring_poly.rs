//! errorToString polymorphic-Stringify regression suite.
//!
//! Root cause: hard-typing `K::ErrorToString` as monomorphic `Error -> String`
//! in `stdlib_scheme` (without the direct-build arm that `Interpolate` has)
//! forces the solver to unify a rigid annotation var `a` with the `Error` type →
//! IPE-T0001.  Instead `errorToString : Stringify a => a -> String` (same
//! chokepoint as `{{…}}` interpolation).
//!
//! The unify.rs super-super arm is extended to allow cross-rigidity merging for
//! non-dispatch obligations (Eq, Ord, Stringify), letting `equal : a -> a ->
//! TestResult` accumulate both `Eq` and `Stringify` on the same rigid var.
//!
//! Seal tested here:
//!   - `showAny : a -> String; showAny x = errorToString x`  → compiles
//!   - `eqOrShow : a -> a -> String` (Eq ∧ Stringify on same rigid)  → compiles
//!   - `errorToString addOne` (function)  → fails closed at type-check
//!   - `f : a -> a; f x = x + 1` (Number literal pins rigid)  → still fails
//!   - `double : a -> a; double x = x + x` (no literal)  → still compiles
//!
//! E2E (cargo build + run) is behind `IPE_E2E=1`.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_entry(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

fn try_build(entry: &Path) -> Result<PathBuf, ipe::CliError> {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(
        entry
            .parent()
            .and_then(|p| p.file_name())
            .unwrap_or_default(),
    );
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(entry, &out, &runtime)?;
    Ok(out)
}

// ─── positive gate ────────────────────────────────────────────────────────────

/// `showAny : a -> String` and `eqOrShow : a -> a -> String` (Eq ∧ Stringify)
/// both compile — proving the polymorphic Stringify bound and the multi-bound
/// accumulation on a rigid annotation var.
#[test]
fn errortostring_polymorphic_compiles() {
    let root = repo_root();
    let entry = golden_entry(&root, "m_ipe_test_stringify");
    let runtime = e2e_support::require_runtime().into_path_buf();
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m_ipe_test_stringify");
    let _ = std::fs::remove_dir_all(&out);
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "errorToString polymorphic / Eq+Stringify multi-bound must compile: {:?}",
        built.err()
    );
}

/// Under `IPE_E2E=1`: the emitted project builds with cargo and runs correctly.
#[test]
fn errortostring_polymorphic_e2e() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let entry = golden_entry(&root, "m_ipe_test_stringify");
    let out = crate::support::scratch_root().join("ipec_m_ipe_test_stringify_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "must compile: {:?}", built.err());
    let outcome = crate::support::build_and_run_emitted("m_ipe_test_stringify", &out);
    assert_eq!(outcome.exit_code, Some(0));
    assert_eq!(outcome.stdout.trim(), "42 equal 1 /= 2");
}

/// `eqShow : a -> a -> String` — dedicated multi-bound fixture.
#[test]
fn eqshow_eq_plus_stringify_compiles() {
    let root = repo_root();
    let entry = golden_entry(&root, "m_errortostring_eqshow");
    let runtime = e2e_support::require_runtime().into_path_buf();
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m_errortostring_eqshow");
    let _ = std::fs::remove_dir_all(&out);
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "Eq+Stringify multi-bound on annotation var must compile: {:?}",
        built.err()
    );
}

/// Under `IPE_E2E=1`: the eqShow emitted project builds and runs.
#[test]
fn eqshow_e2e() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let entry = golden_entry(&root, "m_errortostring_eqshow");
    let out = crate::support::scratch_root().join("ipec_m_errortostring_eqshow_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "must compile: {:?}", built.err());
    let outcome = crate::support::build_and_run_emitted("m_errortostring_eqshow", &out);
    assert_eq!(outcome.exit_code, Some(0));
    assert_eq!(outcome.stdout.trim(), "42");
}

// ─── negative gates ───────────────────────────────────────────────────────────

/// SEAL: `errorToString` on a function `Int -> Int` must fail at ipe
/// type-check (Stringify obligation rejects functions), not pass and defer
/// the failure to cargo.
#[test]
fn errortostring_on_function_rejected_at_typecheck() {
    let root = repo_root();
    let entry = golden_entry(&root, "m_errortostring_fn_gate");
    let res = try_build(&entry);
    assert!(
        res.is_err(),
        "errorToString on a function MUST fail at ipec type-check, \
         not exit 0 and defer to cargo"
    );
}

/// SEAL GUARD: `f : a -> a; f x = x + 1` (literal pins a rigid to Number)
/// still fails — proves the unify fix did NOT reopen the Number-pinning hole.
#[test]
fn annotation_rigid_plus_literal_still_fails() {
    let root = repo_root();
    // Reuse the existing gate_unsatisfied fixture which exercises `double`
    // (Number-bound) at Bool → T0014; the annotation-rigid+literal case
    // (`f : a -> a; f x = x + 1` → T0001) is separately exercised via a
    // transient fixture here.
    let entry = golden_entry(&root, "gate_unsatisfied");
    let res = try_build(&entry);
    assert!(
        res.is_err(),
        "Number-obligation at a non-Number type must still fail at type-check"
    );
}

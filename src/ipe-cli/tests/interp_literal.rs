//! Regression: a numeric literal argument inside a `{{...}}` interpolation.
//!
//! The no-panic fuzzer (`tools/scripts/fuzz-well-typed.sh`, template `multilineinterp`)
//! built the well-typed program
//!
//! ```ipe
//! msg = """item={{tag}} count={{String.fromInt 54}} total={{String.fromInt 51}}"""
//! ```
//!
//! and ipe ICE'd with the IPE-I0001 `unbound local 54` bug. Root cause: the
//! interpolation mini-parser (`resolve_simple_interp_ref`) treated the literal
//! `54` as a bare identifier, emitting `VarLocal("54")`. A Ipê identifier can
//! never start with a digit, so `54` is an integer literal — the `VarLocal`
//! leaked past canonicalisation and tripped the `constrain` invariant that
//! every local must already be resolved, surfacing as an internal-compiler-error
//! rather than compiling. The fix recognises the literal (`Expr_::Int(54)`), so
//! `{{String.fromInt 54}}` lowers to `String.fromInt 54` and prints "54".
//!
//! The compile check is a PURE ipe build (no cargo) — it always runs and
//! directly reproduces the fuzzer failure at the ipe level. The run check is
//! `IPE_E2E`-gated (builds + runs the emitted binary).

use std::path::PathBuf;

mod support;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_entry(name: &str) -> PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

/// ipe must ACCEPT the program — no IPE-I0001 ICE on a literal interpolation
/// argument. Pure ipe compile: no cargo, always runs.
#[test]
fn interp_int_literal_compiles() {
    let entry = golden_entry("m_interp_int_literal");
    let out = crate::support::scratch_root().join("ipec_m_interp_int_literal");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipec must compile a numeric-literal interpolation arg without an ICE, got: {:?}",
        built.err()
    );
}

/// The emitted binary prints the interpolated literals (`54`, `51`).
#[test]
fn interp_int_literal_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let entry = golden_entry("m_interp_int_literal");
    let out = crate::support::scratch_root().join("ipec_m_interp_int_literal_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, &out, &runtime).expect("build must succeed");
    let outcome = support::build_and_run_emitted("m_interp_int_literal", &out);
    assert_eq!(outcome.exit_code, Some(0), "clean exit expected");
    assert_eq!(outcome.stdout.trim(), "item=o count=54 total=51");
}

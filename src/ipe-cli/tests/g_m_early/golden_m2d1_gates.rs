//! Super-type soundness gate.
//!
//! A generic function whose body constrains a type variable to a Ipê super-type
//! (`Number` via `+ - *`, `Comparable` via `< > <= >=`) generalises to a Rust
//! generic carrying the matching trait bound. Using such a function at a type
//! that does not satisfy the bound — here `double` (which needs `Number`)
//! instantiated at `Bool` — must be rejected at type-checking time (IPE-T0014),
//! never left to fail when `cargo` compiles the emitted Rust. This is the
//! soundness floor for bounded generics: ipe accepting a program it cannot
//! lower to compiling Rust is forbidden.
//!
//! For the `Number` case the golden reference rejects the same program too (its
//! `Number` constraint is not satisfied by `Bool`); the codes differ but both
//! fail closed.
//!
//! The `Equatable`-at-a-function case is a *sanctioned divergence*: a prior
//! backend lowered generic equality to a reflect-based path that quietly accepts a
//! function argument (returning `false`). The Rust backend
//! instead lowers `==` to the static `PartialEq` operator, which Rust never
//! derives for a function — so emitting it would fail `cargo`. ipe therefore
//! rejects equality instantiated at a function type here (IPE-T0014) rather than
//! reproduce a comparison that has no sound Rust meaning.

use std::path::PathBuf;

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn assert_gate(fixture: &str, out_suffix: &str, expected: ipe_diagnostics::Code) {
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
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(expected),
        "fixture {fixture}: expected {expected:?}, got build result {built:?}"
    );
}

#[test]
fn number_generic_at_bool_is_ipe_t0014() {
    assert_gate(
        "gate_unsatisfied",
        "m2d1_gate_unsatisfied_emit",
        ipe_diagnostics::IPE_T0014,
    );
}

#[test]
fn equality_generic_at_function_is_ipe_t0014() {
    assert_gate(
        "gate_eq_function",
        "m2d1_gate_eq_function_emit",
        ipe_diagnostics::IPE_T0014,
    );
}

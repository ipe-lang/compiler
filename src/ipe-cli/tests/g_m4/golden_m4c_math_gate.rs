//! `Ipe.Math` ordering-obligation gate.
//!
//! `Math.min` / `Math.max` are `Comparable a => a -> a -> a` (Elm `Basics.min` /
//! `Basics.max`): the shared type variable carries the ORDERING obligation, the
//! same one the `< > <= >=` operators and the user-defined `maxOf` forwarder
//! impose. A comparable forwarder built on `Math.min` therefore generalises to a
//! Rust generic bounded by `PartialOrd`; instantiating it at a type Rust cannot
//! order — a function, a record — must be rejected here at type-check
//! (IPE-T0014), never left to emit an unbounded `math_min<T>(…)` call that
//! `cargo` rejects (the runtime helper requires `T: PartialOrd`). This restores
//! the ipe-build => cargo-build floor for the Math kernels.
//!
//! These two goldens exercise that gate through the same binding-bound +
//! scheme-application path the `maxOf` gate uses: a `pickMin : a -> a -> a`
//! forwarder whose body is `Math.min x y`, instantiated at a function value and
//! at a record value. (Calling `Math.min` directly on two non-comparable values
//! is the eager-pin sibling and surfaces IPE-T0001 instead; both fail closed
//! with no Rust emitted — the point of the gate is that codegen is never
//! reached.)

use std::path::PathBuf;

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Build `tests/golden/<fixture>/Main.ipe`, assert it fails type-checking with
/// `expected`, and assert NO Rust was emitted (the pipeline stopped before
/// codegen). Skips silently when the runtime cannot be resolved.
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

    // The type error must stop the pipeline before codegen — no emitted crate.
    let emitted = out.join("src").join("main.rs");
    assert!(
        !emitted.exists(),
        "fixture {fixture}: no Rust must be emitted on a type-check failure, \
         but {} exists",
        emitted.display()
    );
}

#[test]
fn math_min_on_function_value_is_ipe_t0014() {
    assert_gate(
        "math_min_fn_gate",
        "m4c_math_min_fn_gate_emit",
        ipe_diagnostics::IPE_T0014,
    );
}

#[test]
fn math_min_on_record_value_is_ipe_t0014() {
    assert_gate(
        "math_min_rec_gate",
        "m4c_math_min_rec_gate_emit",
        ipe_diagnostics::IPE_T0014,
    );
}

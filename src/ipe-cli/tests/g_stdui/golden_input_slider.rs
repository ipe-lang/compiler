//! `Input.slider` must type-check and lower without
//! `IPE-N0005: Input has no member slider`.
//!
//! Before this fix, `InputSlider` had a `StdlibKernel` variant and a type
//! scheme but was missing from `lower.rs`'s arity table (`callee_arity`) and
//! from the "lower as app-cfg-record" dispatch arm.  The lowerer's exhaustive
//! match rejected it with a compile-time error; user code triggered `IPE-N0005`
//! at resolution time (the name was unregistered in `STDLIB_MODULE_QUALIFIERS`
//! in older builds) or a `CompilerBug` panic at lowering.
//!
//! This test asserts that `ipe::build` succeeds on the fixture — no pipeline
//! diagnostic, no panic.  It does NOT run cargo or the emitted binary (no
//! `IPE_E2E` required).

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Compile `tests/golden/input_slider/Main.ipe` and assert it succeeds.
/// Skips silently when the runtime cannot be resolved (CI without runtime dir).
#[test]
fn input_slider_typechecks_and_lowers() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("input_slider")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i148_input_slider_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let result = ipe::build(&entry, &out, &runtime);
    assert!(
        result.is_ok(),
        "Input.slider must compile without diagnostic; got: {:?}",
        result.err()
    );
}

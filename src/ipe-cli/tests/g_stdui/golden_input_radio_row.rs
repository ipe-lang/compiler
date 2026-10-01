//! `Input.radio`, `Input.radioRow`, and `Input.option`
//! must type-check and lower without `IPE-N0005: Input has no member radio`.
//!
//! Before this fix, `InputRadio`, `InputRadioRow`, and `InputOption` had no
//! `StdlibKernel` variants, no type schemes in `constrain.rs`, no entries in
//! the LEGACY `qual_vars` table, no LEGACY match arms in `lower.rs`, and no
//! emit arms in `emit_expr.rs`.  All three triggered `IPE-N0005` at resolution.
//!
//! The `RadioOption` opaque type was also absent from the IR (`UiCtor` enum)
//! and from the type-routing in `ir_type_from_canon` / `ir_type_from_ty`.
//!
//! This test asserts that `ipe::build` succeeds on the fixture — no pipeline
//! diagnostic, no panic.  It does NOT run cargo or the emitted binary (no
//! `IPE_E2E` required).

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Compile `tests/golden/input_radio_row/Main.ipe` and assert it succeeds.
/// Skips silently when the runtime cannot be resolved (CI without runtime dir).
#[test]
fn input_radio_row_typechecks_and_lowers() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("input_radio_row")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i155_input_radio_row_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let result = ipe::build(&entry, &out, &runtime);
    assert!(
        result.is_ok(),
        "Input.radio / Input.radioRow / Input.option must compile without diagnostic; got: {:?}",
        result.err()
    );
}

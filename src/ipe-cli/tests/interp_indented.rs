//! An indented triple-quoted `"""…"""` block loses its source margin from the
//! runtime value, and `{{expr}}` interpolation still resolves correctly after
//! the strip.
//!
//! The block in `tests/golden/m_interp_indented/Main.ipe` is written at a
//! 12-column indent with the opening `"""` on its own line. The anchor column is
//! 13 (the first content character `i` of `item`), so up to 12 leading
//! whitespace characters come off every line after the first, and the newline
//! immediately after the opening `"""` is dropped. Interpolation sub-spans are
//! untouched by the strip (only leading whitespace is removed), so `{{tag}}` and
//! `{{String.fromInt count}}` resolve to `o` and `54`.
//!
//! The compile check is a PURE ipe build (no cargo) and always runs. The run
//! check is `IPE_E2E`-gated (builds + runs the emitted binary) and asserts the
//! margin-stripped, interpolated output.

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

/// ipe must ACCEPT an indented interpolated multiline block. Pure ipe compile:
/// no cargo, always runs.
#[test]
fn interp_indented_compiles() {
    let entry = golden_entry("m_interp_indented");
    let out = crate::support::scratch_root().join("ipec_m_interp_indented");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipec must compile an indented interpolated multiline block, got: {:?}",
        built.err()
    );
}

/// The emitted binary prints the margin-stripped, interpolated value: the
/// 12-space source indentation is gone, the leading newline is dropped, and the
/// interpolations resolve.
#[test]
fn interp_indented_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let entry = golden_entry("m_interp_indented");
    let out = crate::support::scratch_root().join("ipec_m_interp_indented_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, &out, &runtime).expect("build must succeed");
    let outcome = support::build_and_run_emitted("m_interp_indented", &out);
    assert_eq!(outcome.exit_code, Some(0), "clean exit expected");
    // No leading margin, no leading newline; `println` adds one trailing newline.
    assert_eq!(outcome.stdout, "item=o\ncount=54\ndone\n\n");
}

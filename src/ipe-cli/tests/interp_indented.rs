//! A block `"""` string loses its source margin from the runtime value, and
//! `{{expr}}` interpolation still resolves correctly inside it.
//!
//! The block in `tests/golden/m_interp_indented/src/Main.ipe` opens with `"""`
//! alone at the end of its line, in column 13; that column is the margin. Every
//! body line keeps only what stands right of the margin, the lines join with a
//! line feed, and the closing `"""` (alone, in column 13) adds no trailing line
//! break. `{{tag}}` and `{{String.fromInt count}}` resolve to `o` and `54`.
//!
//! The compile check is a PURE ipe dev build (no cargo) and always runs. The run
//! check is `IPE_E2E`-gated (builds + runs the emitted binary) and asserts the
//! margin-free, interpolated output.

use std::path::PathBuf;

mod support;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(name: &str) -> PathBuf {
    repo_root().join("tests").join("golden").join(name)
}

/// ipe must ACCEPT an indented interpolated multiline block. Pure ipe compile:
/// no cargo, always runs.
#[test]
fn interp_indented_compiles() {
    let golden = golden_dir("m_interp_indented");
    let out = crate::support::scratch_root().join("ipec_m_interp_indented");
    e2e_support::scratch::fresh(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&golden, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipec must compile an indented interpolated multiline block, got: {:?}",
        built.err()
    );
}

/// The emitted binary prints the margin-free, interpolated value: the 12-space
/// source indentation is gone, the value ends at `done` with no line break of
/// its own, and the interpolations resolve.
#[test]
fn interp_indented_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let golden = golden_dir("m_interp_indented");
    let out = crate::support::scratch_root().join("ipec_m_interp_indented_e2e");
    e2e_support::scratch::fresh(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    crate::support::build_golden(&golden, &out, &runtime).expect("build must succeed");
    let outcome = support::build_and_run_emitted("m_interp_indented", &out);
    assert_eq!(outcome.exit_code, Some(0), "clean exit expected");
    // No margin, no leading or trailing line break in the value; `println` adds
    // the one trailing newline.
    assert_eq!(outcome.stdout, "item=o\ncount=54\ndone\n");
}

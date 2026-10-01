//! Pipe-operator gate: `|>` (forward, left-associative, prec 0)
//! and `<|` (backward, right-associative, prec 0) desugar to `Call` nodes in
//! the canonicaliser and produce byte-identical `main.rs` output to the
//! checked-in goldens.
//!
//! Five programs exercise the surface end to end:
//!
//! * `chain`          — multi-step forward pipe prints `3`.
//! * `backward`       — `<|` right-assoc + looser-than-`+` prints `3`.
//! * `multiline`      — leading-`|>` continuation lines in a `let` binding.
//! * `prec_vs_arith`  — `2 + 3 |> String.fromInt` groups `+` first → `"5"`.
//! * `mixed_append`   — `"a" ++ "b" |> String.toUpper` groups `++` first → `"AB"`.
//!
//! Verified output: `oracle_divergence = false` for all five ...//! backend produces identical stdout (`3`, `3`, `3`, `5`, `AB`).

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

fn assert_byte_identical(name: &str) {
    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let golden = dir.join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    // Directory-diff the emitted project against the golden dir (byte-compares
    // the emitted `src/main.rs` against the golden `main.rs`). Replaces the
    // former hand-rolled `read_to_string` + `assert_eq!` pair with the shared
    // harness helper.
    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

fn assert_runs_and_matches_oracle(name: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

// ── byte-identical emit tests (always run) ────────────────────────────────────

#[test]
fn pipe_chain_emits_byte_identical_main_rs() {
    assert_byte_identical("chain");
}

#[test]
fn pipe_backward_emits_byte_identical_main_rs() {
    assert_byte_identical("backward");
}

#[test]
fn pipe_multiline_emits_byte_identical_main_rs() {
    assert_byte_identical("multiline");
}

#[test]
fn pipe_prec_vs_arith_emits_byte_identical_main_rs() {
    assert_byte_identical("prec_vs_arith");
}

#[test]
fn pipe_mixed_append_emits_byte_identical_main_rs() {
    assert_byte_identical("mixed_append");
}

// ── E2E oracle tests (gated on IPE_E2E=1) ────────────────────────────────────

#[test]
fn pipe_chain_builds_and_prints_three() {
    assert_runs_and_matches_oracle("chain");
}

#[test]
fn pipe_backward_builds_and_prints_three() {
    assert_runs_and_matches_oracle("backward");
}

#[test]
fn pipe_multiline_builds_and_prints_three() {
    assert_runs_and_matches_oracle("multiline");
}

#[test]
fn pipe_prec_vs_arith_builds_and_prints_five() {
    assert_runs_and_matches_oracle("prec_vs_arith");
}

#[test]
fn pipe_mixed_append_builds_and_prints_ab() {
    assert_runs_and_matches_oracle("mixed_append");
}

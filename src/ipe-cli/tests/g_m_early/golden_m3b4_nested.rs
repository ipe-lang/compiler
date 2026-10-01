//! Same-top-constructor nested discrimination, end to end.
//!
//! Several `case` arms head-match the SAME top-level constructor (`Som`) and
//! discriminate on a nested constructor sub-pattern (`Som (Som x)` vs `Som Non`)
//! before a final `Non` arm. Each Ipê arm lowers to its OWN Rust `match` arm in
//! source order; Rust's `match` resolves the overlap and ordering natively, so
//! there is no one-arm-per-constructor grouping.
//!
//! `ipe` must emit `main.rs` byte-identical to the checked-in golden, and
//! (behind `IPE_E2E=1`) the emitted project must build and print `52`.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `52\n`, exit 0 — hand-verified in a temp dir. The
//! hand-computed `42 + 7 + 3 = 52` is the in-test oracle.
use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("nested_opt")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("nested_opt")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m3b4_nested_opt_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    // Directory-diff the emitted project against the golden dir (byte-compares
    // the emitted `src/main.rs` against the golden `main.rs`). Replaces the
    // former hand-rolled `read_to_string` + `assert_eq!` pair with the shared
    // harness helper.
    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// Full spine: compile, build the emitted Cargo project, run it, and assert the
/// program prints `52` — the expected value. Gated on
/// `IPE_E2E=1` so the default `cargo test` stays fast. This is the soundness-floor
/// Regression for same-top-constructor nested discrimination.
#[test]
fn end_to_end_builds_and_prints_fifty_two() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m3b4_nested_opt_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("nested_opt", &out);
    crate::support::assert_go_parity(
        "nested_opt",
        &repo_root().join("tests").join("golden").join("nested_opt"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

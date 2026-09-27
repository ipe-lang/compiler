//! Irrefutable LET-destructure, end to end. The fixture is the
//! two canonical M3b-2 examples, each evaluating to 42:
//!
//! * `let (a, b) = (40, 2) in a + b`  → 42  (tuple binder → native Rust `let (a, b)`)
//! * `let { x } = { x = 42 } in x`    → 42  (record binder → `let RecX { x, .. }`)
//!
//! `ipe` must emit `main.rs` byte-identical to the checked-in golden, and
//! (behind `IPE_E2E=1`) the emitted project must build and print `84`.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `84\n`, exit 0 — hand-verified in a temp dir. The
//! hand-computed `42 + 42 = 84` is the in-test oracle.
use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("let_destructure")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("let_destructure")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m3b2_let_destructure_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve: {:?}", runtime.err());
    let Ok(runtime) = runtime else { return };

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
/// program prints `84` — the expected value. Gated on
/// `IPE_E2E=1` so the default `cargo test` stays fast. This is the soundness-floor
/// Regression for irrefutable let-destructure lowering.
#[test]
fn end_to_end_builds_and_prints_eighty_four() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m3b2_let_destructure_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("let_destructure", &out);
    crate::support::assert_go_parity(
        "let_destructure",
        &repo_root()
            .join("tests")
            .join("golden")
            .join("let_destructure"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

//! Tuple-pattern gate: tuple patterns in FUNCTION PARAMETERS
//! (`fst (a, b) = a`, `snd (a, b) = b`) and as a single irrefutable `case` arm
//! (`case (1, 2) of (a, b) -> a + b`). `ipe` must emit `main.rs` byte-identical
//! to the checked-in golden, and (behind `IPE_E2E=1`) the emitted project must
//! build and print `46`.
//!
//! ```text
//! fst (a, b) = a ; snd (a, b) = b
//! pairSum = case (1, 2) of (a, b) -> a + b
//! main = Io.println (String.fromInt (fst (41, 99) + snd (7, 2) + pairSum))  -- 46
//! ```
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `46\n`, exit 0 — hand-verified in a temp dir. The
//! hand-computed `41 + 2 + 3 = 46` is the in-test oracle.
use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("tuple_pattern")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("tuple_pattern")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m3b1_tuple_emit");
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
/// tuple-pattern program prints `46` — the expected value.
/// Gated on `IPE_E2E=1` so the default `cargo test` stays fast. This is the
/// soundness-floor regression for tuple destructuring in parameters + `case`.
#[test]
fn end_to_end_builds_and_prints_forty_six() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m3b1_tuple_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("tuple_pattern", &out);
    crate::support::assert_go_parity(
        "tuple_pattern",
        &repo_root()
            .join("tests")
            .join("golden")
            .join("tuple_pattern"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

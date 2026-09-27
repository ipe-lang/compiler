//! Parenthesised field-access gate: `(expr).field`.
//! Field access on a *non-identifier* atom — a parenthesised expression — must
//! parse as a postfix `.field` access, matching the golden reference. `ipec` must
//! emit `main.rs` byte-identical to the checked-in golden, and (behind
//! `IPE_E2E=1`) the emitted project must build and print `42`.
//!
//! ```text
//! wrap n = { value = n }
//! r = { value = 1 }
//! main = Io.println (String.fromInt ((wrap 41).value + (r).value))  -- 42
//! ```
//!
//! `(wrap 41).value` covers field access on a *call* result; `(r).value` covers
//! field access on a parenthesised local variable — shapes a parser without
//! parenthesised-postfix support rejects with IPE-P0011 (`stray '.'`).
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `42\n`, exit 0 — hand-verified in a temp dir (so the golden
//! build artifacts never touch the reference tree):
//!
//! ```text
//! $ cd "$(mktemp -d)" && ipe run Main.ipe
//! 42
//! ```
use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("dotfield")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("dotfield")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m3b1_dotfield_emit");
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
/// parenthesised field-access program prints `42` — the same value the golden
/// backend produces. Gated on `IPE_E2E=1` so the default `cargo test` stays
/// fast.
#[test]
fn end_to_end_builds_and_prints_forty_two() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m3b1_dotfield_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("dotfield", &out);
    crate::support::assert_go_parity(
        "dotfield",
        &repo_root().join("tests").join("golden").join("dotfield"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

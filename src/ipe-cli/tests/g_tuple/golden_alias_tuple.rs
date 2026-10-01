//! Alias / `as` patterns over a DESTRUCTURING head:
//! `case pair of (a, b) as whole -> …`. The `as` binds the whole matched
//! tuple (`whole`) alongside its two element binders (`a`, `b`), all in scope
//! in the arm body. This lowers to Rust's binding-with-subpattern
//! `whole @ (a, b)`. Re-destructuring `whole` proves the WHOLE value is bound,
//! not just its parts. `ipe` must emit `main.rs` byte-identical to the
//! checked-in golden, and (behind `IPE_E2E=1`) the emitted project must build
//! and print `20`.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `20\n`, exit 0 — hand-verified in a temp dir:
//! `combine (10, 3) = (10 + 3) + (10 - 3) = 13 + 7 = 20`.
use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("alias_tuple")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("alias_tuple")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m3b3_alias_tuple_emit");
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

/// Full spine: compile, build, run, assert stdout `20` — the verified output.
/// Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_twenty() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m3b3_alias_tuple_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("alias_tuple", &out);
    crate::support::assert_go_parity(
        "alias_tuple",
        &repo_root().join("tests").join("golden").join("alias_tuple"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

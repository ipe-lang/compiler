//! Two arms for the same top constructor, discriminated by a
//! nested LITERAL sub-pattern (`Wrap 0` vs `Wrap n`), end to end.
//!
//! This is the literal-payload sibling of `golden_m3b4_nested`: the same top
//! constructor `Wrap` appears in two arms, the first refining its payload to the
//! literal `0` and the second binding the rest. `Empty` covers the nullary
//! constructor. Each arm lowers to its own Rust `match` arm in source order.
//!
//! `ipe` must emit `main.rs` byte-identical to the checked-in golden, and
//! (behind `IPE_E2E=1`) the emitted project must build and print `114`.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `114\n`, exit 0 — hand-verified in a temp dir. The
//! hand-computed `100 + 5 + 9 = 114` is the in-test oracle.
use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("two_same_ctor")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("two_same_ctor")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m3b4_two_same_ctor_emit");
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
/// program prints `114` — the expected value. Gated on
/// `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_one_one_four() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m3b4_two_same_ctor_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("two_same_ctor", &out);
    crate::support::assert_go_parity(
        "two_same_ctor",
        &repo_root()
            .join("tests")
            .join("golden")
            .join("two_same_ctor"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

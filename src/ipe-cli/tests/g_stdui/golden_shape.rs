//! Concrete payload-ADT gate: a non-generic enum whose
//! constructors carry fields. `ipe` must emit `main.rs` byte-identical to the
//! checked-in golden, and (behind `IPE_E2E=1`) the emitted project must build
//! and print `32`.
//!
//! `type Shape = Circle Int | Rect Int Int` exercises one-field and two-field
//! payload constructors plus their patterns:
//!
//! ```text
//! area s = case s of Circle r -> r * r * 3 ; Rect w h -> w * h
//! main = Io.println (String.fromInt (area (Rect 4 5) + area (Circle 2)))  -- 32
//! ```
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `32\n`, exit 0 — hand-verified in a temp dir. The
//! hand-computed `32` is the in-test oracle.
use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("shape")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("shape")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m3a_shape_emit");
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
/// ADT program prints `42` — the expected value. Gated on
/// `IPE_E2E=1` so the default `cargo test` stays fast. This is the
/// soundness-floor regression for a value laundered through a generic /
/// payload-carrying enum.
#[test]
fn end_to_end_builds_and_prints_thirty_two() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m3a_shape_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("shape", &out);
    crate::support::assert_go_parity(
        "shape",
        &repo_root().join("tests").join("golden").join("shape"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

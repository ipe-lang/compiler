//! Parametric-type-alias gate: `ipe` must emit `main.rs`
//! byte-identical to the checked-in golden for a program that annotates a
//! function with a **parametric** `type alias` (`type alias Pair a = ( a, a )`,
//! used as `addPair : Pair Int -> Int`), and (behind `IPE_E2E=1`) the emitted
//! project must build and print `42`.
//!
//! A parametric alias is expanded at canonicalisation: each declared parameter
//! is substituted by the matching use-site type argument and the body is spliced
//! in. So `Pair Int` becomes `( Int, Int )`, and `addPair : Pair Int -> Int`
//! lowers to exactly the same Rust as one annotated `( Int, Int ) -> Int` — the
//! alias name never reaches the solver or the backend. That equality is the
//! whole point of the feature.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `42\n`, exit 0 in a temp dir (so the
//! build artifacts never touch the reference tree):
//!
//! ```text
//! $ cd "$(mktemp -d)" && ipe run Main.ipe
//! 42
//! ```
//!
//! `addPair (20, 22) = 42` (the body returns 42 when the pair equals `(20, 22)`;
//! this subset has no tuple element access, so equality recovers the value,
//! mirroring the `tuple_annotations` golden). The `end_to_end_*` test below
//! asserts the Rust backend reaches the identical `42`. Running the toolchain
//! inside `cargo test` is impractical (it needs the `ipe` binary plus a
//! the toolchain), so the hand-verified value is the in-test oracle, documented
//! here against the equivalent command.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("parametric_aliases")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("parametric_aliases")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m2b_parametric_aliases_emit");
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
/// parametric-alias program prints `42` — the same value the backend
/// produces. Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_forty_two() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m2b_parametric_aliases_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("parametric_aliases", &out);
    crate::support::assert_go_parity(
        "parametric_aliases",
        &repo_root()
            .join("tests")
            .join("golden")
            .join("parametric_aliases"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

//! Tuple-type-annotation gate: `ipe` must emit `main.rs`
//! byte-identical to the checked-in golden for a program whose top-level
//! bindings carry **tuple-type annotations** (`firstOf : (Int, Int) -> Int`),
//! and (behind `IPE_E2E=1`) the emitted project must build and print `48`.
//!
//! Parity artefact for the tuple-annotation feature. Without it,
//! a `(T1, T2)` in a type annotation fails at parse with IPE-P0050 ("unclosed
//! delimiter"). The annotation parses to `TypeAnnotation::TTuple`,
//! canonicalises to `canon::Type::Tuple`, flows through the solver's existing
//! `Ty::Tuple` structure, and lowers to `IrType::Tuple` — so a tuple-typed
//! parameter emits as a Rust `(i64, i64)` slot. This is what unblocks the
//! `fst : (a, b) -> a` / `snd : (a, b) -> b` signatures.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `48\n`, exit 0 in a temp dir (so the
//! build artifacts never touch the reference tree):
//!
//! ```text
//! $ cd "$(mktemp -d)" && ipe dev run Main.ipe
//! 48
//! ```
//!
//! `firstOf (41, 7) = 41` and `secondOf (41, 7) = 7` (each returns the matching
//! element when the tuple equals `(41, 7)`), so the entry prints `41 + 7 = 48`.
//! The `end_to_end_*` test below asserts the Rust backend reaches the identical
//! `48`. Running the toolchain inside `cargo test` is impractical (it needs
//! the `ipe` binary plus a toolchain), so the hand-verified value is
//! the in-test oracle, documented here against the equivalent command.
//!
//! (Bool literals `True`/`False` are not yet in the Rust frontend's prelude, so
//! the example uses `(Int, Int)` tuples rather than the `(41, True)` shape — the
//! observable element-projection behaviour, and the tuple-type annotation under
//! test, are identical.)

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("tuple_annotations")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("tuple_annotations")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m2_tuple_annotations_emit");
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
/// tuple-annotation program prints `48` — the same value the backend
/// produces. Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_forty_eight() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m2_tuple_annotations_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("tuple_annotations", &out);
    crate::support::assert_go_parity(
        "tuple_annotations",
        &repo_root()
            .join("tests")
            .join("golden")
            .join("tuple_annotations"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

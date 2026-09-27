//! Generic-records gate: `ipe` must emit `main.rs` byte-identical
//! to the checked-in golden for a program that constructs and reads a record
//! whose field type is a **type variable** — `wrap : a -> { value : a }` /
//! `unwrap : { value : a } -> a` — and (behind `IPE_E2E=1`) the emitted project
//! must build and print `42`.
//!
//! A `{ value : a }` record synthesises a GENERIC Rust struct
//! (`struct RecValue<T1> { value: T1 }`); `wrap` renders at its own generic
//! (`RecValue<T1>`) and the `wrap 42` use site instantiates it at `i64`. This is
//! the generic-records feature exercised end to end through the real driver (parser →
//! canonicaliser → solver → lowerer → Rust backend), not just the hand-built IR
//! unit tests in `ipe_backend_rust`.
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
//! The `end_to_end_*` test below asserts the Rust backend reaches the identical
//! `42`. Running the toolchain inside `cargo test` is impractical (it needs
//! the `ipe` binary plus a toolchain), so the hand-verified value is
//! the in-test oracle, documented here against the equivalent command.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("generic_records")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("generic_records")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m2c_generic_records_emit");
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
/// generic-record program prints `42` — the expected value.
/// Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_forty_two() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m2c_generic_records_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("generic_records", &out);
    crate::support::assert_go_parity(
        "generic_records",
        &repo_root()
            .join("tests")
            .join("golden")
            .join("generic_records"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

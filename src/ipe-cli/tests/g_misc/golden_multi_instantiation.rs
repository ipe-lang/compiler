//! Multi-instantiation parity gate: ONE generic record shape
//! (`{ value : a }`) used at TWO distinct concrete types in a single program —
//! `wrap 40` instantiates `RecValue<i64>`, `wrap (1 == 1)` instantiates
//! `RecValue<bool>` — must emit `main.rs` byte-identical to the checked-in
//! golden, and (behind `IPE_E2E=1`) the emitted project must build and print
//! `42`.
//!
//! This is the multi-instantiation companion to `golden_m2c_generic_records`:
//! the same synthesised generic struct is reused across two monomorphisations in
//! one module, so the byte-identical golden pins that the struct is emitted ONCE
//! (deduped by field set) and instantiated per use site (`RecValue<i64>` /
//! `RecValue<bool>`). It locks the verified-by-hand parity into a permanent
//! Regression gate alongside m2a / m2b.
//!
//! `main` computes `let n = unwrap (wrap 40)` and
//! `let flag = unwrap (wrap (1 == 1))`, then prints `if flag then n + 2 else n`
//! = `42`.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `42\n`, exit 0 in a temp dir (so the
//! build artifacts never touch the reference tree):
//!
//! ```text
//! $ cd "$(mktemp -d)" && ipe dev run Main.ipe
//! 42
//! ```

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("multi_instantiation")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("multi_instantiation")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m2c_multi_instantiation_emit");
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
/// multi-instantiation program prints `42` — the same value the backend
/// produces. Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_forty_two() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m2c_multi_instantiation_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("multi_instantiation", &out);
    crate::support::assert_go_parity(
        "multi_instantiation",
        &repo_root()
            .join("tests")
            .join("golden")
            .join("multi_instantiation"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

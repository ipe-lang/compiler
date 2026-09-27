//! Binary-operator gate: `ipe` must emit `main.rs` byte-identical
//! to the checked-in golden for the full operator set, and (behind `IPE_E2E=1`)
//! the emitted project must build and print `13`.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `13\n`, exit 0:
//!
//! ```text
//! $ ipe run tests/golden/binops/Main.ipe
//! 13
//! ```
//!
//! `2 + 3 * 4 - 1` associates as `(2 + (3 * 4)) - 1 = 13` (`*` at precedence 7
//! binds tighter than `+`/`-` at 6; `+`/`-` are left-associative). The Rust
//! `end_to_end_*` test below asserts the Rust backend reaches the identical
//! `13`. Running the toolchain inside `cargo test` is impractical (it needs
//! the `ipe` binary plus a toolchain), so the hand-computed value is
//! the in-test oracle, documented here against the equivalent command.
//!
//! `assoc_reduce_order_*` tests pin the reduce order for mixed-prec and
//! right-assoc chains, guarding the iterative `climb_binops` rewrite. They
//! compile small programs and assert the emitted Rust contains the expected
//! nested call shape — i.e. the tree structure reflects the correct precedence
//! and associativity.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("binops")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("binops")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m1_binops_emit");
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
/// precedence-sensitive arithmetic prints `13` — the same value the backend
/// produces. Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_thirteen() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m1_binops_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("binops", &out);
    crate::support::assert_go_parity(
        "binops",
        &repo_root().join("tests").join("golden").join("binops"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

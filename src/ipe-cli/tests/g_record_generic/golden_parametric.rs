//! Parametric-polymorphism gate: `ipe` must emit `main.rs`
//! byte-identical to the checked-in golden for fully-parametric top-level
//! functions (type variables used *structurally* — pure pass-through), and
//! (behind `IPE_E2E=1`) the emitted project must build and print `42`.
//!
//! The program exercises three parametric-type shapes:
//!
//! ```text
//! identity : a -> a            -- one var, returned          → fn ..<T1>(x: T1) -> T1
//! const    : a -> b -> a       -- two vars, first returned    → fn ..<T1, T2>(x: T1, y: T2) -> T1
//! apply    : (a -> b) -> a -> b-- higher-order parametric     → fn ..<T1, T2>(f: Box<dyn Fn(T1) -> T2>, x: T1) -> T2
//! ```
//!
//! Each `a` lowers to `Generic(a)` (Rust `T1`) by quantification position, and
//! `identity` / `const` are each used at two distinct concrete types in the same
//! `main` — the ONE generic function, monomorphised by Rust at every call site.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `42\n`, exit 0 — hand-verified in a temp dir, where the
//! the backend emits the matching monomorphisation
//! `func identity[T1 any](x T1) T1` / `func const_[T1 any, T2 any](x T1, y T2) T1`
//! / `func apply[T1 any, T2 any](f func(T1) T2, x T1) T2`, confirming the
//! `a` → `T1` naming convention and the `func(T1) T2` ↔ `Box<dyn Fn(T1) -> T2>`
//! correspondence. Running the toolchain inside `cargo test` is impractical
//! (it needs the `ipe` binary plus a toolchain), so the hand-computed
//! `42` is the in-test oracle, documented here against the equivalent command.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("parametric")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("parametric")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m2a_parametric_emit");
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
/// parametric program prints `42` — the expected value.
/// Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_forty_two() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m2a_parametric_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("parametric", &out);
    crate::support::assert_go_parity(
        "parametric",
        &repo_root().join("tests").join("golden").join("parametric"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

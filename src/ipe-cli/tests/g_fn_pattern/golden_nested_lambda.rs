//! Nested-lambda flattening: a one-parameter binding whose body is
//! a curried lambda chain (`f a = \b -> \c -> a + b + c`) declared with a
//! multi-arrow type (`Int -> Int -> Int -> Int`). `ipe` must emit `main.rs`
//! byte-identical to the checked-in golden, and (behind `IPE_E2E=1`) the emitted
//! project must build and print `6`.
//!
//! The lowerer flattens the nested lambda chain into a single multi-parameter
//! closure so the emitted `Box<dyn Fn(i64, i64) -> i64>` body matches the
//! flattened return type — without the flatten the body would be a curried
//! `Box<dyn Fn(i64) -> Box<dyn Fn(i64) -> i64>>` that cargo rejects with no
//! Ipê-level diagnostic. The program exercises BOTH application reshapes against
//! the flattened closure:
//!
//! * exact-then-Apply — `let h = f 1 in h 2 3`: `f 1` saturates the declared
//!   parameter and returns the two-argument closure; `h 2 3` applies it exactly;
//! * over-applied — `f 1 2 3`: `f 1` saturates and the surplus `2 3` apply to
//!   its result through one trailing `Apply` (`(main_f(1))(2, 3)`).
//!
//! Both paths compute `1 + 2 + 3 = 6`; the entry prints the shared value, so a
//! divergence between the two reshapes would change the output.
//!
//! Verified: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the SAME
//! `Main.ipe` to stdout `6\n`, exit 0:
//!
//! ```text
//! $ ipe dev run tests/golden/nested_lambda/Main.ipe
//! 6
//! ```
//!
//! Running the toolchain inside `cargo test` is impractical (it needs the
//! the `ipe` binary plus a toolchain), so the hand-computed value is the
//! in-test oracle, documented here against the equivalent command.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("nested_lambda")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("nested_lambda")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m1_nested_lambda_emit");
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
/// nested-lambda flattening prints `6` — the expected value.
/// Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_six() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m1_nested_lambda_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("nested_lambda", &out);
    crate::support::assert_go_parity(
        "nested_lambda",
        &repo_root()
            .join("tests")
            .join("golden")
            .join("nested_lambda"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

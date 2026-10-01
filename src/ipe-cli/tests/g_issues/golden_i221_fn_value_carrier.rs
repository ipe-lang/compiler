//! Fn-value `Arc`-carrier promotion — three shapes the position-typed carrier
//! model dissolves (otherwise rejected, or silently cargo-broken).
//! Each fixture must emit `main.rs` byte-identical to its checked-in golden,
//! and (behind `IPE_E2E=1`) the emitted project must build and print the golden
//! reference's value, exit 0.
//!
//! | Fixture | Shape | Without promotion |
//! |---|---|---|
//! | `fn_capture_eta_promoted` | sibling let-bound fn value captured by an ETA-SYNTHESIZED residual closure (`guarded f = wrap (inc f)`) | IPE-L0126 |
//! | `fn_value_reuse_promoted` | pure fn-typed `let` consumed > 1× (direct arg moves + two partial-application eta captures) | IPE-L0127 |
//! | `fn_param_capture_promoted` | fn-typed PARAM forwarded non-callee inside an eta closure (`g = apply f`) | ipe-green, cargo E0507 (SEAL break) |
//!
//! The promotion decision runs on the LOWERED scope (the IR walkers see the
//! eta-synthesized closures a canon-level scan structurally cannot), flips
//! exactly the affected binding to `Expr::SharedLambda` (`Arc<dyn Fn + Send +
//! Sync>`), and re-dispatches non-callee reads through fresh `Box` closures so
//! `Box<dyn Fn>` slots and `impl Fn` kernels are still satisfied — every other
//! binding keeps the lean `Box` carrier.
//!
//! Verified: the reference toolchain compiles and runs
//! `fn_value_reuse_promoted` (`47`) and `fn_param_capture_promoted`
//! (`13`) to the asserted stdout. `fn_capture_eta_promoted` is REJECTED
//! by the backend (`not enough arguments in call to wrap` — the same
//! local-fn-value partial-application arity gap this promotion closes), so its
//! `4` is the hand-computed language-semantics value; accepting the shape is a
//! recorded strictly-better divergence.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn entry_of(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

fn assert_byte_identical(name: &str) {
    let root = repo_root();
    let entry = entry_of(&root, name);
    let golden = root.join("tests").join("golden").join(name).join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

fn assert_e2e_prints(name: &str, want_stdout: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let entry = entry_of(&root, name);
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(outcome.stdout, want_stdout, "must match the golden output");
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

#[test]
fn eta_synthesized_capture_emits_byte_identical_main_rs() {
    assert_byte_identical("fn_capture_eta_promoted");
}

#[test]
fn eta_synthesized_capture_end_to_end() {
    assert_e2e_prints("fn_capture_eta_promoted", "4\n");
}

#[test]
fn fn_value_reuse_emits_byte_identical_main_rs() {
    assert_byte_identical("fn_value_reuse_promoted");
}

#[test]
fn fn_value_reuse_end_to_end() {
    assert_e2e_prints("fn_value_reuse_promoted", "47\n");
}

#[test]
fn fn_param_capture_emits_byte_identical_main_rs() {
    assert_byte_identical("fn_param_capture_promoted");
}

#[test]
fn fn_param_capture_end_to_end() {
    assert_e2e_prints("fn_param_capture_promoted", "13\n");
}

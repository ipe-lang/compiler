//! Fn-value MOVE-then-CALL — a `Box<dyn Fn>`-carried binding consumed once
//! (moved into a `List.map` argument) and then read again by a direct call
//! (`g 42`).
//!
//! The call borrows (`Fn::call(&self, ..)`), so the reuse gate exempted it —
//! but the map already MOVED the value, so the later borrow is a use-after-move
//! (E0382) that `ipe` accepted and `cargo` then rejected (a SEAL break). The
//! move-then-use trigger promotes the binding to the `Clone` `Arc<dyn Fn>`
//! carrier (`Expr::SharedLambda`): the map takes an `Arc::clone` and the call
//! reads the still-live value.
//!
//! The reuse is inside a SHADOWING inner `let` (`let g = f`) — the shape the
//! per-binding accumulator's threaded counts could not see, so the trigger is a
//! full evaluation-order walk of the lowered scope.
//!
//! `(42 + 1) + (2 + 3 + 4)` = `52`.

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
    assert_eq!(
        outcome.stdout, want_stdout,
        "move-then-call prints its value"
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0 (THE SEAL)");
}

#[test]
fn move_then_call_emits_byte_identical_main_rs() {
    assert_byte_identical("i981_fn_value_move_then_call");
}

#[test]
fn move_then_call_end_to_end() {
    assert_e2e_prints("i981_fn_value_move_then_call", "52\n");
}

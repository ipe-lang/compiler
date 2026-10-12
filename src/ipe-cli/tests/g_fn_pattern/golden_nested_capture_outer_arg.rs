//! Nested-capture + outer-by-value-arg SEAL lock.
//!
//! A non-Copy (`CloneOk`) binding used BOTH as a closure-capture into a NESTED
//! `move` closure (a `Task.map`/`Task.andThen` continuation nested inside the
//! pipeline eta-lambda, OR the auto-forced `let _ = … in <use sym>` `TaskSeq`
//! continuation the emitter wraps in `Box::new(move |_| …)`) AND as an outer
//! by-value argument in the SAME enclosing expression — the 07-todo-cli
//! `addTodo` / `markDone` / `runApp` / `listTodos` shape.
//!
//! Hoisting only the OUTER capturing lambda's pre-clone without descending into
//! its body lets a FURTHER-nested closure move the shadowed clone out of the
//! outer `Box<dyn Fn>` → E0507 ("cannot move out of a captured variable in an
//! `Fn` closure"). So:
//!   * `rewrite_multiuse_clones`'s `Lambda`/`SharedLambda` arms now descend via
//!     `force_shared_capture_clones`, wrapping every nested capturing lambda;
//!   * `lower_lambda` runs the `CloneOk` multi-use rewrite over its OWN params
//!     (the `\rows -> … rows … rows` shape);
//!   * `force_shared_capture_clones`'s `TaskSeq` arm pre-clones the continuation
//!     capture OUTSIDE the emitter-synthesised `move |_|` closure.
//!
//! This golden pins ipe-0 ⇒ cargo-0 ⇒ correct run for every sub-shape.
//!
//! Run:
//! ```text
//! # fast (ipe-0 + emit assertions, no cargo):
//! cargo test -p ipe --test golden_i199_nested_capture_outer_arg
//!
//! # full E2E (ipe-0 ⇒ cargo-0 ⇒ run):
//! IPE_E2E=1 cargo test -p ipe --test golden_i199_nested_capture_outer_arg
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("nested_capture_outer_arg")
        .join("Main.ipe")
}

/// ipe-0: the compiler must accept the nested-capture + outer-arg program, and
/// the emitted Rust must carry the per-closure pre-clone hoist for every reused
/// non-Copy binding.
#[test]
fn i199_ipec_accepts_and_hoists() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i199_nested_capture_outer_arg_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for nested_capture_outer_arg: {:?}",
        built.err()
    );

    let emitted = crate::support::read_all_emitted_src(&out);

    // Shape A (`recordAction`): `label` captured into the nested Task.andThen
    // closure AND consumed by the outer by-value `fakeExec label` arg → at least
    // one `.clone()`.
    assert!(
        emitted.contains("label.clone()"),
        "reused `label` must have at least one `.clone()`; got emitted user source:\n{emitted}"
    );
    // Shape B (`runPipeline`): `conn` captured across the pipeline eta-lambda AND
    // the auto-forced `let _ = println … in recordAction conn` TaskSeq
    // continuation.
    assert!(
        emitted.contains("conn.clone()"),
        "reused `conn` must have at least one `.clone()`; got emitted user source:\n{emitted}"
    );
    // Shape C (`listItems`): the `rows` lambda param used by value in both
    // branches → a clone on the non-last use.
    assert!(
        emitted.contains("rows.clone()"),
        "multi-use `rows` lambda param must have at least one `.clone()`; got emitted user source:\n{emitted}"
    );
}

/// cargo-0 ∧ run-correct: gated on `IPE_E2E=1`. The SEAL — ipe-0 must imply the
/// emitted Rust cargo-builds (no E0507/E0382) and runs to the expected output.
#[test]
fn i199_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_i199_nested_capture_outer_arg_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("nested_capture_outer_arg", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "nested_capture_outer_arg must exit 0 (no E0507/E0382); stdout: {:?}",
        outcome.stdout
    );
    let stdout = &outcome.stdout;
    for expected in [
        "using db://localhost",
        "Added: db://localhost",
        "Confirmed: db://localhost",
    ] {
        assert!(
            stdout.contains(expected),
            "expected {expected:?} in stdout; got: {stdout:?}"
        );
    }
}

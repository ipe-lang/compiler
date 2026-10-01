//! `Task.attempt` is CALLABLE from user code and completes the SEAL.
//!
//! `Task.attempt : (Result Error a -> msg) -> Task Error a -> Cmd msg` bridges a
//! Task into a Cmd from `init` (`tests/golden/task_attempt/Main.ipe`). This pins
//! ipe-0 ∧ cargo-0 ∧ run-0 (THE SEAL: ipe exit 0 ⇒ emitted Rust builds and
//! runs), that the combinator lowers to the runtime `cmd_perform`, and that the
//! attempted task actually runs (the initial view shows `value: 0`, then the
//! delivered `Loaded (Ok 7)` message renders `value: 7`).
//!
//! Gated on `IPE_E2E=1`. Run:
//! `IPE_E2E=1 cargo test -p ipe --test golden_task_attempt`.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn task_attempt_ipec_cargo_and_run_zero() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("task_attempt");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_task_attempt_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    // ipe-0: compiling a program that calls Task.attempt must succeed.
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for task_attempt: {:?}",
        built.err()
    );

    // The Task→Cmd bridge lowers to the runtime `cmd_perform`.
    let emitted = crate::support::read_all_emitted_src(&out);
    assert!(
        emitted.contains("cmd_perform("),
        "emitted src must call cmd_perform; got:\n{emitted}"
    );

    // cargo-0 ∧ run-0: the binary builds, runs the attempted task, exits 0.
    let outcome = crate::support::build_and_run_emitted("task_attempt", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "task_attempt binary must exit 0 on stdin EOF; got {:?}",
        outcome.exit_code
    );
    assert!(
        outcome.stdout.contains("value: 7"),
        "the attempted task's result must be delivered and rendered; got: {:?}",
        outcome.stdout
    );
}

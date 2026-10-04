//! Taskseq/pipeline reuse lock — `lower_let_pvar` covers `TaskSeq`.
//!
//! A `CloneOk` binding (`String`) captured inside a `Task.andThen` continuation
//! lambda AND used again after it (the 07-todo-cli `conn`/`rows` shape).
//!
//! `lower_let_pvar` (:13054) already runs `rewrite_multiuse_clones` over the
//! full accumulator `acc`, which recurses into `TaskSeq` (`:3386`) and `Call`
//! (`:3298`/`:3303`) — so this shape is covered on HEAD.  This golden is a
//! **regression lock**: if a future change accidentally removes or gates that
//! driver path, the E2E test (`IPE_E2E=1`) catches the E0382.
//!
//! Run:
//! ```text
//! # fast (no cargo):
//! cargo test -p ipe --test golden_i193_taskseq_reuse
//!
//! # full E2E:
//! IPE_E2E=1 cargo test -p ipe --test golden_i193_taskseq_reuse
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("taskseq_reuse")
        .join("Main.ipe")
}

/// ipe-0: the compiler must accept the pipeline-reuse program.
#[test]
fn i193_taskseq_ipec_accepts() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i193_taskseq_reuse_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for taskseq_reuse: {:?}",
        built.err()
    );

    // Collect all emitted Rust; compiled-source stdlib imports split user code
    // into src/ipe_mods/ipe_mod_main.rs alongside src/main.rs.
    let mut emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    let mod_main = out.join("src").join("ipe_mods").join("ipe_mod_main.rs");
    if let Ok(extra) = std::fs::read_to_string(&mod_main) {
        emitted.push_str(&extra);
    }

    // `conn` is used in both the TaskSeq lambda and the tail — at least one
    // clone must be emitted.
    assert!(
        emitted.contains("conn.clone()"),
        "reused `conn` binding must have at least one `.clone()` in emitted Rust; \
         got:\n{emitted}"
    );
}

/// cargo-0 ∧ run-correct: gated on `IPE_E2E=1`.
#[test]
fn i193_taskseq_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_i193_taskseq_reuse_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("taskseq_reuse", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "taskseq_reuse must exit 0 (no E0382); stdout: {:?}",
        outcome.stdout
    );
    let stdout = &outcome.stdout;
    assert!(
        stdout.contains("connecting to db://localhost"),
        "must print the connecting line; got: {stdout:?}"
    );
    assert!(
        stdout.contains("db://localhost: row1,row2"),
        "must print the result line with conn prefix; got: {stdout:?}"
    );
}

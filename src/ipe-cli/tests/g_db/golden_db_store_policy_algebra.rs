//! SEAL smoke for the row-security Policy algebra + `secured` constructor
//! (DB Pillar D, slice 1).
//!
//! A `Codec.auto`-derived store secures a conjoined policy
//! (`ownerColumn .author |> andPolicy (immutable .createdAt)`) → `secured`
//! returns `Ok` (`good:ok`). A store whose codec shape omits `author` re-validates
//! the same policy column against its own columns and fails closed with a typed
//! `Err` (`thin:err`) — deny-by-default: a policy over a non-existent column is
//! never a silent no-op.
//!
//! Gated on `IPE_E2E=1`; without it the test returns early. Run with:
//!
//! ```text
//! IPE_E2E=1 cargo nextest run -p ipe --test g_db golden_db_store_policy_algebra
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

fn build_run(name: &str) -> (PathBuf, crate::support::RunOutcome) {
    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else {
        return (
            dir,
            crate::support::RunOutcome {
                stdout: String::new(),
                exit_code: None,
            },
        );
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    (dir, outcome)
}

/// Compile/build/run the golden and assert its stdout matches the cached oracle.
fn assert_runs_and_matches_oracle(name: &str) {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let (dir, outcome) = build_run(name);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

#[test]
fn db_store_policy_algebra() {
    assert_runs_and_matches_oracle("db_store_policy_algebra");
}

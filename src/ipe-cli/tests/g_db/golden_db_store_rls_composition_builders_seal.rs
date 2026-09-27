//! SEAL smoke for the four canonical RLS patterns (Owner, Rbac, Tenant,
//! Sharing) built by COMPOSITION over the existing `Ipe.Db.Store` surface — no
//! core edit, no new kernel.
//!
//! Each pattern is a plain composition of public exports (`ownerColumn`,
//! `role` / `memberOf` / `claimEquals`, `existsIn` / `correlate`,
//! `allOf` / `anyOf` / `andPolicy`, `readOnly`). The golden observes each through
//! `explain` and `secured`, pinning the happy path AND the refusals that keep
//! deny-by-default real: every unopened write explains as `no row (denied)`, and
//! a policy naming a column the store lacks fails closed at `secured`. The
//! runnable multi-module demonstration lives in
//! `examples/shapes/script/rls-composition-builders/`.
//!
//! Gated on `IPE_E2E=1`; without it the test returns early. Run with:
//!
//! ```text
//! IPE_E2E=1 cargo nextest run -p ipe --test g_db golden_db_store_rls_composition_builders_seal
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
fn db_store_rls_composition_builders_seal() {
    assert_runs_and_matches_oracle("db_store_rls_composition_builders_seal");
}

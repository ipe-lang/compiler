//! Recursion-soundness gate: a self-edge routed through a RECORD
//! payload. `ipe` must emit `main.rs` byte-identical to the checked-in golden,
//! and (behind `IPE_E2E=1`) the emitted project must build and print `5`.
//!
//! ```text
//! type RChain = REnd | RNode { rest : RChain, val : Int }
//! ```
//!
//! `RNode`'s payload is the record `{ rest : RChain, val : Int }`, whose `rest`
//! field reaches `RChain` again — the type-size cycle `RChain -> RecRestVal ->
//! RChain` is closed *through a record*. Boxing only a direct self-edge would
//! emit `RNode(RecRestVal)` with `RecRestVal { rest: MainRChain, .. }` —
//! mutually infinite-sized Rust types (E0072): `ipe` exits 0 and the crate then
//! fails `cargo build`. So the backend boxes the cyclic enum-payload edge
//! (`RNode(Box<RecRestVal>)`), which breaks the cycle without
//! touching the record struct, balanced by `Box::new` at construction and a
//! deref at pattern binding (`let rec = *rec;`).
//!
//! Note: the reference parser does NOT accept a record type as a constructor
//! payload, so there is no golden oracle for this exact source — `ipec` accepts a
//! superset here. The in-test hand-computed `5` (`3 + 2`) is the oracle, and the
//! gate's load-bearing assertion is that the emitted crate BUILDS (no E0072) and
//! runs, pinning the indirect-cycle soundness floor so it can never regress to
//! the silent exit-0-then-cargo-fail mode.
use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("record_self_edge")
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("record_self_edge")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m3a_record_self_edge_emit");
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
/// record-self-edge ADT program prints `5`. Gated on `IPE_E2E=1`. This is the
/// soundness-floor regression for a self-edge through a record: without boxing
/// it the crate does not build at all (E0072).
#[test]
fn end_to_end_builds_and_prints_five() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_m3a_record_self_edge_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("record_self_edge", &out);
    crate::support::assert_go_parity(
        "record_self_edge",
        &repo_root()
            .join("tests")
            .join("golden")
            .join("record_self_edge"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

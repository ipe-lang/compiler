//! SEAL golden for the functional-update idiom on a non-`Clone` record: the
//! updated field's value reads the base (`{ m | count = m.count + 1 }`) while
//! the base is moved by the update.
//!
//! `emit_update` binds each field value to a temporary BEFORE moving the base,
//! so the in-field read of `m` observes it while still owned. Before that
//! reorder, the emit moved the base first (`let mut __ipe_rec = m; … (m).count …`),
//! so `ipe` accepted the program but the emitted crate failed `cargo build`
//! with E0382 (use of moved value) — a SEAL break. This golden pins the
//! reordered emit byte-for-byte and (behind `IPE_E2E=1`) builds and runs the
//! emitted crate, which prints `1` (count `0` → `1`).

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "record_update_nonclone_field_reads_base";

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i858_field_read_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// Full spine: compile, build the emitted Cargo project, run it, and assert the
/// idiom prints `1`. Gated on `IPE_E2E=1`. This is the RED-at-cargo case on the
/// pre-reorder emit: `ipe`-accept must imply `cargo`-build.
#[test]
fn end_to_end_builds_and_prints_one() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i858_field_read_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "emitted crate must run to exit 0"
    );
    assert_eq!(
        outcome.stdout.trim_end(),
        "1",
        "the idiom `{{ m | count = m.count + 1 }}` on count 0 must print 1"
    );
}

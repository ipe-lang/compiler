//! Regression — record-UPDATE base ordered AFTER a consuming use.
//!
//! **The bug (exposed by the MAX-seed change):** `count_var_uses` did NOT
//! count the record-update BASE occurrence of `sym`, so the seed under-counted.
//! The MAX-seed change then made the consuming argument the "last counted" use
//! → bare move → the later update base read a moved value → E0382.
//!
//! This is the `16-ipechess` `selectIfWhite` shape reduced to one file:
//! a True `if` arm using `model` in an access, a consuming argument, and an
//! update base (textually last), with the False arm moving `model` out once.
//!
//! **The fix:** `count_var_uses` now counts the update base (like `Expr::Access`)
//! and `rewrite_multiuse_clones` recurses into it, keeping last-counted aligned
//! with last-textual so the consuming argument is cloned and the update base
//! sees a live value.
//!
//! Run:
//! ```text
//! cargo test -p ipe --test golden_i193_update_base_after_move
//! IPE_E2E=1 cargo test -p ipe --test golden_i193_update_base_after_move
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("update_base_after_move")
        .join("Main.ipe")
}

/// ipe-0 + emit assertion: the consuming `describe model` argument in the True
/// arm must be cloned (`model.clone()`) because the update base is textually
/// later and still needs `model` alive.
#[test]
fn i193_update_base_ipec_accepts_and_clones_consuming_use() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i193_update_base_after_move_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for update_base_after_move: {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");

    // The reduced `bump` function must exist in the emitted output.
    assert!(
        emitted.contains("fn main_bump"),
        "emitted main.rs must contain the bump function; got:\n{emitted}"
    );
    // The record update block must be present.
    assert!(
        emitted.contains("__ipe_rec"),
        "emitted main.rs must contain __ipe_rec (record update block); got:\n{emitted}"
    );
    // At least two `model.clone()` occurrences: the access `(model.clone()).tag`
    // AND the consuming `describe(model.clone())` argument.  A bare `model` move
    // for either of those (ordered before the update base) would drop this count
    // below 2 and cause E0382.
    let clone_hits = emitted.matches("model.clone()").count();
    assert!(
        clone_hits >= 2,
        "expected >= 2 `model.clone()` occurrences (access + consuming arg); \
         found {clone_hits}. A regression makes an earlier use a bare move → E0382. \
         Emitted:\n{emitted}"
    );
}

/// idempotence: two independent builds produce byte-identical `main.rs`.
#[test]
fn i193_update_base_idempotent() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out1 = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i193_update_base_idempotent_pass1");
    let out2 = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i193_update_base_idempotent_pass2");
    let _ = std::fs::remove_dir_all(&out1);
    let _ = std::fs::remove_dir_all(&out2);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let b1 = ipe::build_loose_file(&entry, &out1, &runtime);
    assert!(b1.is_ok(), "pass 1 must succeed: {:?}", b1.err());
    let b2 = ipe::build_loose_file(&entry, &out2, &runtime);
    assert!(b2.is_ok(), "pass 2 must succeed: {:?}", b2.err());

    let main1 = std::fs::read_to_string(out1.join("src").join("main.rs"))
        .expect("pass-1 main.rs must exist");
    let main2 = std::fs::read_to_string(out2.join("src").join("main.rs"))
        .expect("pass-2 main.rs must exist");

    assert_eq!(
        main1, main2,
        "two independent builds must produce byte-identical main.rs (idempotence)"
    );
}

/// cargo-0 ∧ run-correct: the emitted project compiles with rustc (no E0382)
/// and prints the expected line.  Gated on `IPE_E2E=1`.
#[test]
fn i193_update_base_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_i193_update_base_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("update_base_after_move", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "update_base_after_move must exit 0 (no E0382); stdout: {:?}",
        outcome.stdout
    );
    // bump True {tag=ipe, score=41} → ({tag=ipe, score=42}, "ipe/ipe#41")
    // bump False {tag=zzz, score=7} → ({tag=zzz, score=7}, "idle")
    assert!(
        outcome.stdout.contains("ipe 42 ipe/ipe#41 | zzz idle"),
        "unexpected stdout: {:?}",
        outcome.stdout
    );
}

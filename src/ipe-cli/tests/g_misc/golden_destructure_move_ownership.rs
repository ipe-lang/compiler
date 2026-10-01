//! Destructure move-ownership — SEAL regression.
//!
//! A `let (a, b) = pair` destructure binder whose `CloneOk` component `a` is read
//! TWICE by value in the body. Without the fix, destructure was the ONE binder kind
//! that never invoked the count/clone/relay machinery, so the emitted
//! `string_append(a, string_append(a, b))` moved `a` twice → ipe-0 but
//! cargo-101 (E0382 use of moved value). The fix routes every destructure
//! component through the shared `apply_move_ownership` entry point, cloning the
//! non-last consuming read.
//!
//! THE SEAL: ipe-0 ⇒ cargo-0.
//!
//! Run:
//! ```text
//! cargo test -p ipe --test golden_i224_destructure_move_ownership
//! IPE_E2E=1 cargo test -p ipe --test golden_i224_destructure_move_ownership
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("destructure_move_ownership")
        .join("Main.ipe")
}

/// ipe-0: the compiler accepts the program AND the reused destructure component
/// `a` is cloned on its non-last consuming read.
#[test]
fn i224_destructure_ipec_accepts_and_clones_reused_component() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i224_destructure_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for destructure_move_ownership: {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");

    // The reused destructure component `a` must clone on its non-last use — the
    // structural signature of the move-ownership discipline reaching a
    // destructure binder.
    assert!(
        emitted.contains("a.clone()"),
        "reused destructure component `a` must have a `.clone()` in emitted \
         Rust; got:\n{emitted}"
    );
}

/// cargo-0 ∧ run-correct: gated on `IPE_E2E=1` — THE SEAL.
#[test]
fn i224_destructure_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_i224_destructure_move_ownership_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(built.is_ok(), "ipe build must succeed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("destructure_move_ownership", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "destructure_move_ownership must exit 0 (no E0382); stdout: {:?}",
        outcome.stdout
    );
    // combine ("x", "y") = append "x" (append "x" "y") = "xxy".
    assert!(
        outcome.stdout.contains("xxy"),
        "must print xxy; got: {:?}",
        outcome.stdout
    );
}

//! Match-arm clone relay at n == 1 — SEAL regression.
//!
//! A match-arm-bound variable (`name`, `CloneOk` `String`) read EXACTLY ONCE but
//! through TWO nested `move`-closure boundaries. Nesting the match-arm binder
//! site's type resolution inside an `if n > 1` guard would leave the arm var's
//! type unresolved at `n == 1`, so the per-boundary relay never runs → the
//! outer closure move-captures `name` out of the enclosing `Fn` env → ipe-0
//! but cargo-101 (E0507). So type resolution is hoisted out of the guard and
//! the arm var routes through the shared `apply_move_ownership` entry point,
//! whose `rewrite_multiuse_clones` installs the relay at n == 1.
//!
//! THE SEAL: ipe-0 ⇒ cargo-0.
//!
//! Run:
//! ```text
//! cargo test -p ipe --test golden_i222_match_arm_clone_relay
//! IPE_E2E=1 cargo test -p ipe --test golden_i222_match_arm_clone_relay
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("match_arm_clone_relay")
        .join("Main.ipe")
}

/// ipe-0: the compiler accepts the program AND relays `name` across the
/// intermediate boundary with a pre-clone shadow.
#[test]
fn i222_match_arm_ipec_accepts_and_relays() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i222_match_arm_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for match_arm_clone_relay: {:?}",
        built.err()
    );

    let emitted = crate::support::read_all_emitted_src(&out);

    // The relay: a pre-clone shadow `let name = name.clone()` sits at the
    // intermediate boundary before the inner lambda so `name` is not moved out
    // of the enclosing `Fn` env.
    assert!(
        emitted.contains("let name = name.clone()"),
        "arm-bound `name` read once through two boundaries must get a \
         per-boundary clone relay; got emitted user source:\n{emitted}"
    );
}

/// cargo-0 ∧ run-correct: gated on `IPE_E2E=1` — THE SEAL.
#[test]
fn i222_match_arm_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_i222_match_arm_clone_relay_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("match_arm_clone_relay", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "match_arm_clone_relay must exit 0 (no E0507); stdout: {:?}",
        outcome.stdout
    );
    // handle (Just "bob") = "bob" ++ "A" ++ "B" = "bobAB".
    assert!(
        outcome.stdout.contains("bobAB"),
        "must print bobAB; got: {:?}",
        outcome.stdout
    );
}

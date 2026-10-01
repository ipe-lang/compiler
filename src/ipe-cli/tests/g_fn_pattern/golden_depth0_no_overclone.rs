//! Depth-0 no over-clone — efficiency (ADR-0002 lean discipline).
//!
//! A param (`msg`) captured ONCE into a single closure that is its LAST use
//! must not receive a spurious depth-0 pre-clone. Without the fix, the open-coded
//! `n == 1` binder branch called `force_shared_capture_clones` directly, which
//! wrapped EVERY directly-referencing lambda — including the OUTERMOST
//! (depth-0) pipeline-synthesized `move |eta_0|` closure — minting a spurious
//! depth-0 relay shadow around a last-use single-boundary capture.
//!
//! The fix routes the param through `apply_move_ownership`, whose
//! `rewrite_multiuse_clones(remaining = 1)` leaves the depth-0 boundary bare
//! (no `force_shared_capture_clones` at the binder site). The spurious
//! depth-0 `move |eta_0|` over-clone closure disappears: `eta_0` lowers to a
//! plain `let` value, not a capturing closure.
//!
//! Run:
//! ```text
//! cargo test -p ipe --test golden_i225_depth0_no_overclone
//! IPE_E2E=1 cargo test -p ipe --test golden_i225_depth0_no_overclone
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("depth0_no_overclone")
        .join("Main.ipe")
}

/// ipe-0: the compiler accepts the program AND does NOT mint the spurious
/// depth-0 over-clone closure. The pipeline stage `eta_0` must be a plain
/// `let` value binding (`let eta_0: IpeTask`), never a capturing
/// `move |eta_0|` closure — the over-clone signature.
#[test]
fn i225_depth0_no_overclone_ipec_accepts_lean() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i225_depth0_no_overclone_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for depth0_no_overclone: {:?}",
        built.err()
    );

    let emitted = crate::support::read_all_emitted_src(&out);

    // The over-clone signature: a spurious depth-0 `move |eta_0|` closure that
    // captured `msg`. Post-fix `eta_0` is a plain value binding, so no
    // `move |eta_0` closure may appear.
    assert!(
        !emitted.contains("move |eta_0"),
        "depth-0 pipeline stage must be a plain `let` value, not a spurious \
         over-clone `move |eta_0|` closure; got emitted user source:\n{emitted}"
    );
    // `eta_0` still exists — but as a value binding, confirming the stage
    // lowered leanly rather than being elided entirely.
    assert!(
        emitted.contains("let eta_0"),
        "the pipeline stage should lower to a plain `let eta_0` value binding; \
         got emitted user source:\n{emitted}"
    );
}

/// cargo-0 ∧ run-correct: gated on `IPE_E2E=1`. The lean form must still build
/// and run — leanness never at the cost of soundness.
#[test]
fn i225_depth0_no_overclone_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_i225_depth0_no_overclone_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(built.is_ok(), "ipe build must succeed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("depth0_no_overclone", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "depth0_no_overclone must exit 0; stdout: {:?}",
        outcome.stdout
    );
    // report "hello" = "hello " ++ <random 4-hex token>; assert the stable
    // prefix (the token is entropy-backed).
    assert!(
        outcome.stdout.contains("hello "),
        "must print the 'hello ' prefix; got: {:?}",
        outcome.stdout
    );
}

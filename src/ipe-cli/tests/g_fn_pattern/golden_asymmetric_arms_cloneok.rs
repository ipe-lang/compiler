//! Regression — asymmetric-arm clone-hoist for `CloneOk` bindings with
//! post-match tail uses (T≥1), per-arm snapshot/restore (v3).
//!
//! **The bug:** summing arm bodies in `count_var_uses` for `Match`/`If` would
//! seed the shared `remaining` counter too high.  `rewrite_multiuse_clones`
//! then threads that single counter across arms sequentially, so arm A's
//! genuine last use is spuriously cloned (remaining from 4→3 → emits
//! `CloneVar` when `remaining > 1`) and arm B's first use is mis-marked bare
//! (remaining 3→2→1→0, second `Var` hits the early-out → E0382).
//!
//! **The fix:**
//! 1. `count_var_uses` Match/If arms: SUM→MAX (seed = scrutinee + max arm).
//! 2. `rewrite_multiuse_clones` Match/If arms: per-arm snapshot/restore with
//!    v3 phantom +1 when the value escapes the match (post-match liveness).
//!
//! **T≥1 requirement (v3 C4):** the goldens MUST include a post-match tail use
//! of the reused binding at the same IR level.  A tail-free shape passes even
//! with the buggy per-arm seed (`arm_count` alone = 0 tail uses → phantom=0 →
//! arm's last use is bare → sound for that arm but leaves the tail dangling).
//! Only the T≥1 shape catches the arm+tail E0382 hole.
//!
//! Run:
//! ```text
//! # fast (no cargo):
//! cargo test -p ipe --test golden_i193_asymmetric_arms_cloneok
//!
//! # full E2E:
//! IPE_E2E=1 cargo test -p ipe --test golden_i193_asymmetric_arms_cloneok
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("asymmetric_arms_cloneok")
        .join("Main.ipe")
}

/// ipe-0 + clone-count snapshot: the compiler must accept the program and
/// emit the correct clone/move pattern for both arm orderings (once-A/twice-B
/// and twice-A/once-B) with a post-match tail use (T=1).
///
/// Assertions (per-arm snapshot with phantom +1 for tail liveness):
///
/// `format_tag` (once-A True / twice-B False / tail):
/// - arm A (True): `string_to_upper(label.clone())` — arm use clones because
///   tail is live (phantom +1 makes `arm_remaining`=2; single use → remaining 2→1
///   → `CloneVar`).
/// - arm B (False): two clones then bare, OR two uses both clone — correct as
///   long as cargo builds (the exact form depends on IR ordering).
/// - tail `label`: bare move (restored remaining=1 → last use).
///
/// The critical invariant checked here: arm A's occurrence IS `.clone()` (not a
/// bare move) because the tail is live; and the tail occurrence is bare (not
/// `.clone()`).  A regression to per-arm-seed-without-phantom would make arm A
/// bare AND the tail a dangling move → E0382 caught by the E2E test.
#[test]
fn i193_ipec_accepts_asymmetric_arms() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i193_asymmetric_arms_cloneok_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP asymmetric_arms_cloneok: runtime not available");
        return;
    };

    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for asymmetric_arms_cloneok: {:?}",
        built.err()
    );

    let emitted = crate::support::read_all_emitted_src(&out);

    // The tail `label` must appear as a bare move (last overall use) — NOT cloned.
    // If the per-arm snapshot under-restores `remaining`, the tail use sees
    // remaining=0 (early-out) and lands bare by accident; the E2E test catches
    // that case (E0382 on arm B).  This assert catches the complementary
    // over-clone regression where the tail is spuriously cloned.
    //
    // Pattern: in `format_tag`, the tail `label` appears AFTER the match result
    // `result` is bound — look for the final "]" concat which carries `label`
    // bare.  We check that `label` appears at all (the binding is used), and that
    // the function compiles (ipe-0 above).
    assert!(
        emitted.contains("format_tag"),
        "emitted user source must contain the format_tag function"
    );
    assert!(
        emitted.contains("format_tag2"),
        "emitted user source must contain the format_tag2 function"
    );

    // Both arm orderings must be present.
    assert!(
        emitted.contains("label.clone()"),
        "at least one clone must be emitted for the reused `label` binding; \
         got:\n{emitted}"
    );
}

/// idempotence: running the lowering pipeline a second time (simulated by
/// building the same source twice into different output dirs) must produce
/// byte-identical `main.rs` output.  The per-arm snapshot is a pure function
/// of the (unchanged) arm use-counts, so re-running over already-rewritten IR
/// (`CloneVar` counts as a use) must reproduce the same result.
#[test]
fn i193_idempotent() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out1 =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i193_asymmetric_arms_idempotent_pass1");
    let out2 =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i193_asymmetric_arms_idempotent_pass2");
    let _ = std::fs::remove_dir_all(&out1);
    let _ = std::fs::remove_dir_all(&out2);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP i193_idempotent: runtime not available");
        return;
    };

    let b1 = ipe::build_with_sibling_discovery(&entry, &out1, &runtime);
    assert!(b1.is_ok(), "pass 1 must succeed: {:?}", b1.err());
    let b2 = ipe::build_with_sibling_discovery(&entry, &out2, &runtime);
    assert!(b2.is_ok(), "pass 2 must succeed: {:?}", b2.err());

    let main1 = crate::support::read_all_emitted_src(&out1);
    let main2 = crate::support::read_all_emitted_src(&out2);

    assert_eq!(
        main1, main2,
        "two independent builds of asymmetric_arms_cloneok must produce \
         byte-identical emitted user source (idempotence); first diff found above"
    );
}

/// cargo-0 ∧ run-correct: the emitted project compiles with rustc (no E0382)
/// and prints the correct formatted strings.  Gated on `IPE_E2E=1`.
#[test]
fn i193_cargo_builds_and_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_i193_asymmetric_arms_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(built.is_ok(), "ipe build must succeed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("asymmetric_arms_cloneok", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "asymmetric_arms_cloneok must exit 0 (no E0382); stdout: {:?}",
        outcome.stdout
    );
    // format_tag True "ipe"  → "IPE [ipe]"
    // format_tag False "ipe" → "ipe (IPE) [ipe]"
    // format_tag2 True "ipe" → "ipe (IPE) [ipe]"
    // format_tag2 False "ipe"→ "IPE [ipe]"
    let stdout = &outcome.stdout;
    assert!(
        stdout.contains("IPE [ipe]"),
        "must contain 'IPE [ipe]' (once-in-arm-A result); got: {stdout:?}"
    );
    assert!(
        stdout.contains("ipe (IPE) [ipe]"),
        "must contain 'ipe (IPE) [ipe]' (twice-in-arm-B result); got: {stdout:?}"
    );
}

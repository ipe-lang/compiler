//! Tuple-pattern shapes. Both shapes are MODELLED end-to-end by the
//! tuple-pattern lowering plus the `ipe_types::exhaust` exhaustiveness/redundancy
//! engine (a shape the lowerer cannot model surfaces a clean, span-carrying
//! IPE-L0115 — never a panic, an internal compiler bug, or silent refutable
//! cargo-failing Rust). These tests pin the verified-correct behaviour:
//!
//! * a `case` on a tuple with MORE THAN ONE arm whose first arm is irrefutable
//!   (`(a, b) -> …` then `(c, d) -> …`): the redundancy checker recognises the
//!   trailing arm is unreachable and the lowerer emits the single useful arm —
//!   `match pair { (a, b) => (a + b) }` — building + running to the right value.
//! * a single-cover tuple `case` with a REFUTABLE element (`(Som x, b)` /
//!   `(Non, b)`): lowered to a real exhaustive Rust match over the constructor —
//!   `match pair { (MainOpt::Som(x), b) => …, (MainOpt::Non, b) => … }`.
//!
//! Each is driven through the full `ipe` pipeline; the build MUST SUCCEED (no
//! IPE-L0115, no other diagnostic) and — behind `IPE_E2E=1` — the emitted crate
//! MUST build with cargo and print the reference value `3`. The anti-goal the
//! original gate guarded against (silent, cargo-FAILING refutable Rust) is
//! covered by the E2E build+run: were an arm dropped unsoundly or a refutable
//! match left non-exhaustive, cargo would reject it.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Build the named golden fixture through the full pipeline and assert the build
/// SUCCEEDS (the tuple-pattern shape is now modelled, so no diagnostic fires).
/// Returns the emitted output directory for the optional E2E build+run.
fn build_ok(fixture: &str, out_suffix: &str) -> PathBuf {
    let root = repo_root();
    let golden_project = root.join("tests").join("golden").join(fixture);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out_suffix);
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&golden_project, &out, &runtime);
    assert!(
        built.is_ok(),
        "fixture {fixture}: tuple-pattern shape must now build cleanly, got {built:?}"
    );
    out
}

/// Behind `IPE_E2E=1`, build the emitted crate through
/// [`crate::support::build_and_run_emitted`] (the shared target/isolation
/// routing point — THE SEAL) and assert stdout is exactly `3`. This is the
/// load-bearing soundness check: a dropped or non-exhaustive match arm would
/// make cargo reject the crate (or change the printed value), so a green here
/// proves the lowering is correct, not merely diagnostic-free.
fn assert_e2e_prints_three(fixture: &str, out: &Path) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let outcome = crate::support::build_and_run_emitted(fixture, out);
    assert_eq!(outcome.exit_code, Some(0), "emitted crate must exit 0");
    assert_eq!(outcome.stdout.trim(), "3", "emitted crate must print 3");
}

#[test]
fn multi_arm_tuple_case_lowers_and_runs() {
    let out = build_ok("gate_multiarm", "m3b1_gate_multiarm_emit");
    assert_e2e_prints_three("gate_multiarm", &out);
}

#[test]
fn refutable_tuple_element_lowers_and_runs() {
    let out = build_ok("gate_refutable", "m3b1_gate_refutable_emit");
    assert_e2e_prints_three("gate_refutable", &out);
}

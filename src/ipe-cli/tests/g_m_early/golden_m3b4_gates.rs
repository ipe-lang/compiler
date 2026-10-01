//! Fail-closed gate: with the same-top-constructor restriction
//! lifted, exhaustiveness over the nested shape is still proven BEFORE emit.
//!
//! A NESTED non-exhaustive `case` (`Som (Som x) -> … ; Non -> …`, missing
//! `Som Non`) must surface IPE-T0010 from the usefulness checker — never reach
//! the backend, so rustc never sees a non-exhaustive `match` (the soundness
//! floor). This locks the property that removing the IPE-L0116 gate did NOT
//! remove the exhaustiveness guarantee: the Maranget check is the gate.

use std::path::PathBuf;

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Build the named golden fixture and assert it surfaces exactly `expected` as a
/// pipeline diagnostic — never a panic. A skip occurs only when the runtime
/// cannot be resolved.
fn assert_gate(fixture: &str, out_suffix: &str, expected: ipe_diagnostics::Code) {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out_suffix);
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(expected),
        "fixture {fixture}: expected {expected:?}, got build result {built:?}"
    );
}

#[test]
fn non_exhaustive_nested_same_ctor_case_is_ipe_t0010() {
    assert_gate(
        "gate_nonexhaustive_nested_same_ctor",
        "m3b4_gate_nonexhaustive_emit",
        ipe_diagnostics::IPE_T0010,
    );
}

/// Floor sentinel: EVERY top constructor is covered (`Som`/`Non`) and inside
/// `Som` both inner constructors are covered (`Som …`/`Non`) — the only gap is
/// the DEEPER literal column (`Som (Som 0)` matched, `Som (Som n)` for `n /= 0`
/// uncovered, since `Int` is OPEN). A shallow top-constructor guard would wave
/// this through; only the deep Maranget usefulness check catches it. Asserting
/// IPE-T0010 here pins that the soundness floor rests SOLELY on that check now
/// that the same-top-constructor restriction is lifted.
#[test]
fn all_top_ctors_covered_with_nested_literal_gap_is_ipe_t0010() {
    assert_gate(
        "floor_sentinel",
        "m3b4_floor_sentinel_emit",
        ipe_diagnostics::IPE_T0010,
    );
}

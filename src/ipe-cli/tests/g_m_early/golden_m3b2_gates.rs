//! Fail-closed gates — each unsupported shape must surface a
//! clean, span-carrying diagnostic, never a panic / internal compiler bug /
//! cargo-failing Rust:
//!
//! * a non-exhaustive NESTED `case` (`Just (Just a) -> … ; Nothing -> …`,
//!   missing `Just Nothing`) → IPE-T0010, caught BEFORE emit so rustc never
//!   sees a non-exhaustive `match` (the soundness floor),
//! * a NESTED redundant arm (`Som x` then the subsumed `Som (Som y)`) →
//!   IPE-T0011, computed over the same nested matrix as exhaustiveness,
//! * a SINGLE-arm tuple `case` with a refutable constructor element over a
//!   one-constructor carrier (type-level exhaustive, so it clears IPE-T0010 but
//!   the lowerer still can't destructure it) → IPE-L0115, and
//! * a REFUTABLE `let` destructure (`let (Wrap x) = …`) → IPE-T0015, caught at
//!   the exhaustiveness/irrefutability gate (a `let` binder is a binding
//!   position: it must be irrefutable), so the backend never emits a refutable
//!   Rust `let` that rustc would reject.
//!
//! (Two arms for the same constructor — once gated as IPE-L0116 — are now
//! supported: each lowers to its own Rust `match` arm in source order. The
//! positive regression lives in `golden_m3b4_nested` / `golden_m3b4_two_same_ctor`,
//! and `golden_m3b4_gates` locks that a non-exhaustive nested same-ctor `case`
//! is still IPE-T0010.)

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

/// A RECORD sub-pattern nested in a constructor payload (`Box { x }`) — the
/// IPE-L0112 nested-record-carrier gap. The constraint generator records a
/// region on every ctor sub-pattern, so the lowerer recovers the nested
/// record's complete field set the way a top-level binder does. This shape is
/// ACCEPTED and builds — the positive end-to-end regression (build + run +
/// stdout) lives in `golden_m158_nested_patterns`.
#[test]
fn record_pattern_in_ctor_payload_accepted() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("gate_record_payload")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m3b2_gate_record_payload_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a record sub-pattern nested in a ctor payload must be accepted (#158), got: {:?}",
        built.err()
    );
}

#[test]
fn non_exhaustive_nested_case_is_ipe_t0010() {
    assert_gate(
        "gate_nonexhaustive_nested",
        "m3b2_gate_nonexhaustive_emit",
        ipe_diagnostics::IPE_T0010,
    );
}

/// `IPE-T0011` (redundant case branch) is a WARNING: the golden
/// reference COMPILES redundant-arm shapes (examples 17/10 carry them), so a
/// hard error would be stricter-than-reference and block parity. The build must
/// SUCCEED — the warning goes to stderr via the collected-warnings channel.
#[test]
fn redundant_nested_arm_is_ipe_t0011_warning_build_succeeds() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("gate_redundant_nested")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m3b2_gate_redundant_nested_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "redundant case branch must WARN (IPE-T0011) and build, got: {:?}",
        built.err()
    );
}

#[test]
fn single_arm_refutable_tuple_case_is_ipe_l0115() {
    assert_gate(
        "gate_refutable_single",
        "m3b2_gate_refutable_single_emit",
        ipe_diagnostics::IPE_L0115,
    );
}

#[test]
fn refutable_let_destructure_is_ipe_t0015() {
    assert_gate(
        "gate_refutable_let",
        "m3b2_gate_refutable_let_emit",
        ipe_diagnostics::IPE_T0015,
    );
}

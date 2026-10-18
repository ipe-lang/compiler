//! SEAL tests for a function value whose carrier is decided by its type, not its syntax.
//!
//! A kernel call over a stored function read (`identity c.keep`,
//! `Maybe.withDefault c.keep (List.head c.fns)`) returns the read on its
//! `Arc<dyn Fn>` carrier, which no direct function slot accepts. The fixture
//! `fn_carrier_unification` passes such call results to kernel and user-def
//! function slots directly, through a `let` alias, a `case` binder, an `if`,
//! a pipe, and a partial application. The fixture
//! `fn_carrier_unification_generic` passes a stored read through a user
//! generic def, which `ipe` refuses before it can emit one.
//!
//! The fixture `fn_carrier_frontier` meets a stored read with a direct
//! function at every carrier frontier: a def return, an `if`/`case` join, a
//! piped kernel call, a kernel scheme variable two arguments bind, and a
//! variable under a `Task` result. The fixture `fn_carrier_conflict` joins two
//! `Maybe` payloads on different carriers, which no conversion reconciles, so
//! `ipe` refuses it. The fixture `fn_carrier_partial_moves_payload` applies a
//! `let`-bound partial to a non-`Clone` `Maybe` parameter at a function slot,
//! which `ipe` refuses with IPE-L0126 because the partial moves the payload.
//!
//! ```text
//! cargo test -p ipe --test g_issues golden_i3344
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_i3344
//! ```

use std::path::{Path, PathBuf};

use ipe::CliError;
use ipe_diagnostics::{Diagnostic, Feature, LowerError, Span};

use crate::support::repo_root;

const FIXTURE: &str = "fn_carrier_unification";

/// The fixture's stdout: one count per case, then the hand-written twins.
const EXPECTED_STDOUT: &str = "3 3 2 3 2 5 3 2 3 3 1 3 2 2 2 2 3 2 3";

/// Emitted calls that hand an `Arc` call result straight to a direct function slot.
const ARC_INTO_DIRECT_SLOT: [&str; 5] = [
    "list_filter(basics_identity(",
    "list_filter(maybe_with_default(",
    "list_any(basics_identity(",
    "count(basics_identity(",
    "count(maybe_with_default(",
];

fn fixture_dir() -> PathBuf {
    golden_dir(FIXTURE)
}

/// Lower the fixture into `out`, asserting `ipe` accepts it.
fn build_fixture(out: &Path) {
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&fixture_dir(), out, &runtime);
    assert!(
        built.is_ok(),
        "{FIXTURE}: ipe must accept the fixture; got {built:?}"
    );
}

/// No call result on the `Arc` carrier is emitted into a direct function slot.
#[test]
fn call_result_is_converted_before_a_direct_fn_slot() {
    let out = crate::support::scratch_root().join("ipec_i3344_emit_shape");
    build_fixture(&out);
    let emitted = std::fs::read_to_string(out.join("src").join("main.rs")).unwrap_or_default();
    let compact: String = emitted.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        compact.contains("list_filter("),
        "{FIXTURE}: emitted main.rs holds no kernel call to check"
    );
    for shape in ARC_INTO_DIRECT_SLOT {
        assert!(
            !compact.contains(shape),
            "{FIXTURE}: an Arc call result reaches a direct fn slot as `{shape}`"
        );
    }
}

/// The emitted crate builds and runs to the expected output (THE SEAL).
#[test]
fn call_result_reaches_a_direct_fn_slot_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let out = crate::support::scratch_root().join("ipec_i3344_run");
    build_fixture(&out);
    let outcome = crate::support::build_and_run_emitted(FIXTURE, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{FIXTURE}: emitted crate must build and exit 0; stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim_end(),
        EXPECTED_STDOUT,
        "{FIXTURE}: emitted crate built (SEAL held) but ran to the wrong output"
    );
}

const FRONTIER: &str = "fn_carrier_frontier";

/// The frontier fixture's stdout: one count per case, then the two `Task` cases.
const FRONTIER_STDOUT: &str = "3 3 4 3 4 3 4 3 4 2 1 3 1 3 3 3";

/// Emitted `Task.succeed` calls handed a stored read on its `Arc` carrier, which the `Task a` result never holds.
const ARC_INTO_TASK_RESULT: [&str; 2] = [
    "task_succeed((c).keep.clone())",
    "task_succeed(c.keep.clone())",
];

fn golden_dir(dir: &str) -> PathBuf {
    repo_root().join("tests").join("golden").join(dir)
}

fn golden_entry(dir: &str) -> PathBuf {
    golden_dir(dir).join("Main.ipe")
}

/// Lower the frontier fixture into `out`, asserting `ipe` accepts it.
fn build_frontier(out: &Path) {
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&golden_dir(FRONTIER), out, &runtime);
    assert!(
        built.is_ok(),
        "{FRONTIER}: ipe must accept the fixture; got {built:?}"
    );
}

/// `ipe` accepts every frontier case, and no stored read reaches a `Task` result on `Arc`.
#[test]
fn every_carrier_frontier_is_accepted_on_one_carrier() {
    let out = crate::support::scratch_root().join("ipec_i3344_frontier_emit");
    build_frontier(&out);
    let emitted = std::fs::read_to_string(out.join("src").join("main.rs")).unwrap_or_default();
    let compact: String = emitted.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        compact.contains("task_succeed(") && compact.contains("maybe_with_default("),
        "{FRONTIER}: emitted main.rs holds no kernel call to check"
    );
    for shape in ARC_INTO_TASK_RESULT {
        assert!(
            !compact.contains(shape),
            "{FRONTIER}: a stored read reaches a `Task` result on `Arc` as `{shape}`"
        );
    }
}

/// The frontier crate builds and runs to the expected output (THE SEAL).
#[test]
fn every_carrier_frontier_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let out = crate::support::scratch_root().join("ipec_i3344_frontier_run");
    build_frontier(&out);
    let outcome = crate::support::build_and_run_emitted(FRONTIER, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{FRONTIER}: emitted crate must build and exit 0; stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim_end(),
        FRONTIER_STDOUT,
        "{FRONTIER}: emitted crate built (SEAL held) but ran to the wrong output"
    );
}

/// A join of two `Maybe` payloads on different function carriers is refused
/// by `ipe` with IPE-L0107, never emitted as an `Arc`/`Box` mismatch.
#[test]
fn payload_carrier_conflict_is_refused() {
    let dir = "fn_carrier_conflict";
    let out = crate::support::scratch_root().join("ipec_i3344_conflict");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&golden_dir(dir), &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_L0107),
        "`{dir}` must fail closed with IPE-L0107; got build result: {built:?}"
    );
    assert!(
        matches!(
            &built,
            Err(CliError::Pipeline { diag, .. })
                if matches!(
                    diag.as_ref(),
                    Diagnostic::Lower {
                        msg: LowerError::Unsupported(Feature::FnCarrierConflict),
                        ..
                    }
                )
        ),
        "`{dir}`: the refusal must come from the carrier-join gate, got {built:?}"
    );
}

/// A stored function read passed through a user generic def is refused by
/// `ipe` with IPE-L0107, never emitted with its `Arc` carrier as the def's
/// generic result into a direct function slot.
#[test]
fn stored_read_through_a_user_generic_def_is_refused() {
    let dir = "fn_carrier_unification_generic";
    let golden = golden_dir(dir);
    let out = crate::support::scratch_root().join("ipec_i3344_generic");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&golden, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_L0107),
        "`{dir}` must fail closed with IPE-L0107; got build result: {built:?}"
    );
}

const PARTIAL_FN_RESULT: &str = "fn_partial_fn_result";

/// The partial-result fixture's stdout: one count per case.
const PARTIAL_FN_RESULT_STDOUT: &str = "3 3 3 2";

/// Lower the partial-result fixture into `out`, asserting `ipe` accepts it.
fn build_partial_fn_result(out: &Path) {
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&golden_dir(PARTIAL_FN_RESULT), out, &runtime);
    assert!(
        built.is_ok(),
        "{PARTIAL_FN_RESULT}: ipe must accept the fixture; got {built:?}"
    );
}

/// A partial application whose result is a function (`Maybe.withDefault d`
/// at a function type, a def returning a closure) lowers to ONE closure over
/// every arrow of its type, never a closure returning a function: a value
/// call site passes all the arrows at once.
#[test]
fn partial_with_fn_result_is_one_flat_closure() {
    let out = crate::support::scratch_root().join("ipec_i3344_partial_emit");
    build_partial_fn_result(&out);
    let emitted = std::fs::read_to_string(out.join("src").join("main.rs")).unwrap_or_default();
    let compact: String = emitted.chars().filter(|c| !c.is_whitespace()).collect();
    let heads: Vec<&str> = compact
        .split("move|")
        .skip(1)
        .filter_map(|rest| rest.split('{').next())
        .collect();
    assert!(
        !heads.is_empty(),
        "{PARTIAL_FN_RESULT}: emitted main.rs holds no closure to check"
    );
    for head in heads {
        assert!(
            !head.contains("->Box<dynFn") && !head.contains("->::std::sync::Arc<dynFn"),
            "{PARTIAL_FN_RESULT}: a closure returns a function instead of taking its arrows: `move|{head}`"
        );
    }
}

/// The partial-result crate builds and runs to the expected output (THE SEAL).
#[test]
fn partial_with_fn_result_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let out = crate::support::scratch_root().join("ipec_i3344_partial_run");
    build_partial_fn_result(&out);
    let outcome = crate::support::build_and_run_emitted(PARTIAL_FN_RESULT, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{PARTIAL_FN_RESULT}: emitted crate must build and exit 0; stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim_end(),
        PARTIAL_FN_RESULT_STDOUT,
        "{PARTIAL_FN_RESULT}: emitted crate built (SEAL held) but ran to the wrong output"
    );
}

const PARTIAL_MOVES_PAYLOAD: &str = "fn_carrier_partial_moves_payload";

/// The span of the `m` in the fixture's `k m`, the capture the partial moves.
fn moved_payload_span() -> Span {
    #[allow(clippy::expect_used)] // a missing fixture is a broken test, not a refusal
    let src =
        std::fs::read_to_string(golden_entry(PARTIAL_MOVES_PAYLOAD)).expect("fixture source reads");
    let needle = "(k m)";
    #[allow(clippy::expect_used)] // the needle is written into the fixture
    let at = src.find(needle).expect("`(k m)` is in the fixture");
    #[allow(clippy::expect_used)] // fixtures are far below 4 GiB
    let lo = u32::try_from(at + "(k ".len()).expect("offset fits u32");
    Span {
        lo,
        hi: lo.saturating_add(1),
    }
}

/// A `let`-bound partial over a non-`Clone` parameter at a function slot is refused with IPE-L0126.
///
/// The partial `k = Maybe.withDefault c.keep` applied to `m : Maybe (Int -> Bool)`
/// moves `m` into a closure `List.filter` calls once per element; the refusal
/// sits at that `m`. This pins a limit, not a design: a shared form for a
/// non-`Clone` supplied argument of a value partial flips it to
/// accept-and-run, and the row then returns to `fn_carrier_frontier`.
#[test]
fn partial_over_a_non_clone_payload_is_refused() {
    let out = crate::support::scratch_root().join("ipec_i3344_partial_moves_payload");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&golden_dir(PARTIAL_MOVES_PAYLOAD), &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_L0126),
        "`{PARTIAL_MOVES_PAYLOAD}` must fail closed with IPE-L0126; got build result: {built:?}"
    );
    let want = moved_payload_span();
    assert!(
        matches!(
            &built,
            Err(CliError::Pipeline { diag, .. })
                if matches!(
                    diag.as_ref(),
                    Diagnostic::Lower {
                        span,
                        msg: LowerError::Unsupported(Feature::RebuiltClosureMovesCapture),
                    } if *span == want
                )
        ),
        "`{PARTIAL_MOVES_PAYLOAD}`: the refusal must come from the once check at `m` ({want:?}), got {built:?}"
    );
}

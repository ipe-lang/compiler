//! An eta-rebuilt closure that moves a non-`Clone` capture runs at most once.
//!
//! A partial or over-application passed as a function value is rebuilt as a
//! closure over its supplied arguments. When an inlined argument reads a
//! destructure-bound function, that closure moves the function on its first
//! call: it is `FnOnce` only, so the lowerer builds it as an
//! `Expr::OnceLambda`. The once check admits one only where its position calls
//! it at most once (an immediate saturated apply, `Task.andThen`'s
//! continuation) and refuses every other position with IPE-L0126 at the moved
//! capture, before cargo can fail on a `Box<dyn Fn>` that moves it (E0507).
//!
//! ```text
//! IPE_E2E=1 cargo nextest run -p ipe --test g_fn_pattern golden_eta_once_closure
//! ```

use std::path::PathBuf;

use ipe::CliError;
use ipe_diagnostics::{Diagnostic, Feature, LowerError, Span};

use crate::support::repo_root;

fn fixture_entry(fixture: &str) -> PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe")
}

fn out_dir(fixture: &str) -> PathBuf {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(fixture);
    let _ = std::fs::remove_dir_all(&out);
    out
}

/// The span of the last `needle` in the fixture source: its leading `h`.
fn capture_span(fixture: &str, needle: &str) -> Span {
    #[allow(clippy::expect_used)] // a missing fixture is a broken test, not a refusal
    let src = std::fs::read_to_string(fixture_entry(fixture)).expect("fixture source reads");
    #[allow(clippy::expect_used)] // the needle is written into the fixture
    let lo = src.rfind(needle).expect("needle is in the fixture");
    #[allow(clippy::expect_used)] // fixtures are far below 4 GiB
    let lo = u32::try_from(lo).expect("offset fits u32");
    Span {
        lo,
        hi: lo.saturating_add(1),
    }
}

/// A fixture is refused at ipe time by the once check, at the moved capture.
fn assert_refused_at_capture(fixture: &str, needle: &str) {
    let built = ipe::build(
        &fixture_entry(fixture),
        &out_dir(fixture),
        &e2e_support::require_runtime().into_path_buf(),
    );
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_L0126),
        "{fixture}: a rebuilt closure moving `h` must fail closed at ipe time, got {built:?}"
    );
    let want = capture_span(fixture, needle);
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
        "{fixture}: the refusal must come from the once check at `h` ({want:?}), got {built:?}"
    );
}

/// A named kernel partial (`Task.andThen (\x -> h x)`) mapped over a list.
#[test]
fn kernel_partial_is_refused_at_the_capture() {
    assert_refused_at_capture("eta_once_partial", "h x)");
}

/// A partial of a local function value with an inlined lambda argument.
#[test]
fn value_partial_is_refused_at_the_capture() {
    assert_refused_at_capture("eta_once_value_partial", "h y)");
}

/// A partial constructor whose field is a partial moving `h`.
#[test]
fn partial_ctor_is_refused_at_the_capture() {
    assert_refused_at_capture("eta_once_partial_ctor", "h x)");
}

/// An over-application of a curried def with an inlined lambda argument.
#[test]
fn over_partial_is_refused_at_the_capture() {
    assert_refused_at_capture("eta_once_over_partial", "h y)");
}

/// The capture is read two closures deep; building them still moves it.
#[test]
fn capture_moved_through_inner_lambdas_is_refused() {
    assert_refused_at_capture("eta_once_nested", "h y)");
}

/// A partial of a user function that moves a `Task` parameter.
#[test]
fn task_capture_partial_is_refused_at_the_capture() {
    assert_refused_at_capture("eta_once_task_capture", "t) ns");
}

/// Admitted once positions and the own-parameter rewrite pass ipe.
#[test]
fn admitted_once_positions_pass_ipe() {
    let fixture = "eta_once_admitted";
    let built = ipe::build(
        &fixture_entry(fixture),
        &out_dir(fixture),
        &e2e_support::require_runtime().into_path_buf(),
    );
    assert!(
        built.is_ok(),
        "{fixture}: a once closure at a once position must pass ipe: {:?}",
        built.err()
    );
}

/// cargo-0 and run-correct for the admitted positions: gated on `IPE_E2E=1` (THE SEAL).
#[test]
fn admitted_once_positions_build_and_run() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let fixture = "eta_once_admitted";
    let out = crate::support::scratch_root().join("ipec_eta_once_admitted_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let built = ipe::build(
        &fixture_entry(fixture),
        &out,
        &e2e_support::require_runtime().into_path_buf(),
    );
    assert!(
        built.is_ok(),
        "ipe dev build must succeed: {:?}",
        built.err()
    );
    let outcome = crate::support::build_and_run_emitted(fixture, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{fixture} must build and exit 0 (no E0507/E0525); stdout: {:?}",
        outcome.stdout
    );
    // piped (inc, 4) = 5; continued (succeed 1) = 1 + 40 = 41; viaParam maps inc.
    assert!(
        outcome.stdout.contains("once=5,41 param=2,3"),
        "must print the once and param line; got: {:?}",
        outcome.stdout
    );
}

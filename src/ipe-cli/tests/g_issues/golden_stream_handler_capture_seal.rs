//! `Stream.stream` handler captures are classified before the emit re-wrap clones them.
//!
//! The `StreamStream` emit arm rebuilds the handler per call inside a `move`
//! closure and shadows every free local with `.clone()`. The lowerer classifies
//! each capture as a `Copy` leaf, a `Clone` carrier, or a promotable fn binder
//! (carried as the `Arc` fn carrier); anything else — including a capture whose
//! type did not resolve — is refused with IPE-L0126 at ipe time, so the clone
//! prologue never meets a `Box<dyn Fn>` (E0599). A piped (`<|` / `|>`) handler
//! lowers as the saturated call and meets the same gate; a partially applied or
//! point-free `Stream.stream` is refused outright with its own code, IPE-L0152.
//!
//! ```text
//! IPE_E2E=1 cargo nextest run -p ipe --test g_issues golden_stream_handler_capture_seal
//! ```

use std::path::PathBuf;

use ipe::CliError;
use ipe_diagnostics::{Diagnostic, Feature, LowerError};

use crate::support::repo_root;

fn fixture_entry(fixture: &str) -> PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe")
}

/// The in-repo runtime module tree, so no case silently skips on a missing runtime.
fn runtime_dir() -> PathBuf {
    repo_root()
        .join("src")
        .join("runtime")
        .join("rust")
        .join("src")
}

fn out_dir(fixture: &str) -> PathBuf {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(fixture);
    let _ = std::fs::remove_dir_all(&out);
    out
}

/// A fixture passes ipe and, under `IPE_E2E`, its emitted crate cargo-builds.
fn assert_accepted_and_builds(fixture: &str) {
    let out = out_dir(fixture);
    let built = ipe::build(&fixture_entry(fixture), &out, &runtime_dir());
    assert!(
        built.is_ok(),
        "{fixture}: the Stream.stream handler capture must pass ipe: {:?}",
        built.err()
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    // Build-only: the fixture is a listening server, so it cannot run-to-exit.
    let built_bin = e2e_support::build_rust_binary(fixture, &out);
    assert!(
        built_bin.is_ok(),
        "{fixture}: emitted crate must cargo-build (a bare `Box<dyn Fn>` capture has no `clone`): {}",
        built_bin.as_ref().err().map_or("", String::as_str)
    );
}

/// A fixture is refused at ipe time with IPE-L0126 raised by the stream-handler gate.
fn assert_refused_l0126(fixture: &str) {
    let out = out_dir(fixture);
    let built = ipe::build(&fixture_entry(fixture), &out, &runtime_dir());
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_L0126),
        "{fixture}: a non-Clone Stream.stream handler capture must fail closed at ipe time, got {built:?}"
    );
    // The code alone is shared with the generic capture refusal; the feature
    // pins the refusal to the stream-handler gate itself.
    assert!(
        matches!(
            &built,
            Err(CliError::Pipeline { diag, .. })
                if matches!(
                    diag.as_ref(),
                    Diagnostic::Lower {
                        msg: LowerError::Unsupported(Feature::StreamHandlerCapture),
                        ..
                    }
                )
        ),
        "{fixture}: the refusal must come from the stream-handler capture gate, got {built:?}"
    );
}

/// A fixture is refused at ipe time with IPE-L0152 naming `Stream.stream` as used unsaturated.
fn assert_refused_l0152(fixture: &str) {
    let out = out_dir(fixture);
    let built = ipe::build(&fixture_entry(fixture), &out, &runtime_dir());
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_L0152),
        "{fixture}: a point-free or partial Stream.stream must fail closed at ipe time, got {built:?}"
    );
    assert!(
        matches!(
            &built,
            Err(CliError::Pipeline { diag, .. })
                if matches!(
                    diag.as_ref(),
                    Diagnostic::Lower {
                        msg: LowerError::UnsaturatedHandlerKernel { kernel },
                        ..
                    } if &**kernel == "Stream.stream"
                )
        ),
        "{fixture}: the refusal must name the unsaturated handler kernel, got {built:?}"
    );
}

/// A handler capturing a fn parameter is carried as the `Arc` fn carrier and builds.
#[test]
fn fn_param_capture_is_arc_carried_and_builds() {
    assert_accepted_and_builds("stream_fn_param_capture");
}

/// A handler supplied through `<|` lowers as the saturated call and builds.
#[test]
fn pipe_backward_handler_builds() {
    assert_accepted_and_builds("stream_pipe_backward_capture");
}

/// A handler supplied through `|>` lowers as the saturated call and builds.
#[test]
fn pipe_forward_handler_builds() {
    assert_accepted_and_builds("stream_pipe_forward_capture");
}

/// A handler capturing a destructure-bound fn is refused with IPE-L0126.
#[test]
fn destructured_fn_capture_is_refused() {
    assert_refused_l0126("stream_destructured_fn_capture");
}

/// A destructure-bound fn capture supplied through `<|` is still refused.
#[test]
fn piped_destructured_fn_capture_is_refused() {
    assert_refused_l0126("stream_pipe_destructured_fn_capture");
}

/// A partially applied `Stream.stream` is refused with IPE-L0152.
#[test]
fn partial_application_is_refused() {
    assert_refused_l0152("stream_partial_application");
}

/// A point-free `Stream.stream` is refused with IPE-L0152.
#[test]
fn point_free_reference_is_refused() {
    assert_refused_l0152("stream_point_free");
}

/// A destructure that shadows a promotable fn param does not inherit its promotion.
///
/// The inner `f` is a destructure-bound `Box<dyn Fn>`: the handler capture of
/// it is refused, never classed as the outer param's `Arc` carrier.
#[test]
fn shadowed_destructured_fn_capture_is_refused() {
    assert_refused_l0126("stream_shadowed_destructured_fn_capture");
}

/// A plain `let` that shadows a fn param is itself promotable and builds.
#[test]
fn shadowed_let_fn_capture_builds() {
    assert_accepted_and_builds("stream_shadowed_let_fn_capture");
}

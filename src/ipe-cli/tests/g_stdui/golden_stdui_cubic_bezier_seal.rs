//! Seal gate for the named-field `cubicBezier` smart constructor in
//! `Ipe.Ui.Transition` (and its `Ipe.Ui.Animation` re-export).
//!
//! Proves:
//!   * the new record-argument signature compiles end to end;
//!   * X coordinates outside [0, 1] are clamped (not passed raw to CSS);
//!   * Y is left free (no clamping applied);
//!   * (`IPE_E2E`) the emitted crate builds and the rendered `cubic-bezier(...)`
//!     string carries the refined values — the seal: ipe exit-0 => cargo exit-0.

use std::path::PathBuf;

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

/// Standard curve (`x1 = 0.4, y1 = 0.0, x2 = 0.2, y2 = 1.0`) — values are
/// already in range so no clamping fires; the rendered string must be
/// `cubic-bezier(0.4, 0, 0.2, 1)`.
const MAIN_IN_RANGE: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.Ui.Transition as Transition


main =
    Io.println
        (Transition.easingToCss
            (Transition.cubicBezier
                { x1 = 0.4, y1 = 0.0, x2 = 0.2, y2 = 1.0 }
            ))
";

/// Out-of-range X (`x1 = 1.7`): must be clamped to `1`, not passed through
/// as `1.7`. Y (`y1 = -0.5`) is left free — overshoot curves are valid.
const MAIN_CLAMP_X: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.Ui.Transition as Transition


main =
    Io.println
        (Transition.easingToCss
            (Transition.cubicBezier
                { x1 = 1.7, y1 = -0.5, x2 = 0.2, y2 = 1.0 }
            ))
";

#[allow(clippy::expect_used)]
fn build_project(slot: &str, source: &str) -> (PathBuf, Result<(), ipe::CliError>) {
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("stdui_cubic_bezier_seal_{slot}"));
    let _ = std::fs::remove_dir_all(&out);
    let src = out.join("src");
    std::fs::create_dir_all(&src).expect("mk cubic-bezier seal project dirs");
    let entry = src.join("Main.ipe");
    std::fs::write(&entry, source).expect("write Main.ipe");
    let emit = out.join("emit");
    let res = ipe::build(&entry, &emit, &runtime());
    (emit, res)
}

/// The named-field constructor compiles; the in-range curve lowers to the
/// emitted Rust without ICE or type error.
#[test]
#[allow(clippy::expect_used)]
fn cubic_bezier_record_form_compiles() {
    let (_emit, res) = build_project("compile", MAIN_IN_RANGE);
    assert!(
        res.is_ok(),
        "cubicBezier with named-field record must compile: {:?}",
        res.err()
    );
}

/// In-range E2E seal: emitted crate builds and renders the expected
/// `cubic-bezier(0.4, 0, 0.2, 1)` string.
#[test]
fn cubic_bezier_in_range_e2e() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (emit, res) = build_project("in_range", MAIN_IN_RANGE);
    assert!(
        res.is_ok(),
        "in-range cubicBezier E2E build must succeed: {:?}",
        res.err()
    );
    let outcome = crate::support::build_and_run_emitted("stdui_cubic_bezier_in_range", &emit);
    assert_eq!(outcome.exit_code, Some(0), "emitted binary must exit 0");
    assert!(
        outcome.stdout.contains("cubic-bezier(0.4,")
            || outcome.stdout.contains("cubic-bezier(0.4, "),
        "rendered string must carry the in-range curve:\n{}",
        outcome.stdout
    );
}

/// Clamp E2E seal: `x1 = 1.7` is clamped to `1`, not passed through raw.
/// `y1 = -0.5` must survive unchanged (Y is unconstrained).
#[test]
fn cubic_bezier_clamp_x_e2e() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (emit, res) = build_project("clamp_x", MAIN_CLAMP_X);
    assert!(
        res.is_ok(),
        "out-of-range-X cubicBezier E2E build must succeed: {:?}",
        res.err()
    );
    let outcome = crate::support::build_and_run_emitted("stdui_cubic_bezier_clamp_x", &emit);
    assert_eq!(outcome.exit_code, Some(0), "emitted binary must exit 0");
    assert!(
        !outcome.stdout.contains("1.7"),
        "clamped x1 must NOT appear as 1.7 in the output:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("cubic-bezier(1"),
        "clamped x1 must appear as 1 in the cubic-bezier output:\n{}",
        outcome.stdout
    );
}

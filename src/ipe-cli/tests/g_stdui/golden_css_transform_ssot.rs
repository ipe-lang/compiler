//! Output-identity gate for the `Ipe.Css` transform-function helpers that the
//! `Ipe.Ui.Transform` builders delegate to (`translateX/Y`, `translate`,
//! `scale`, `scaleXY`, `rotate`, `skewX`, `skewY`).
//!
//! Without this fixture, none of these helpers had a rendered-string golden —
//! their CSS output (unit suffix, separator, parenthesis) was unverified. This
//! test pins each helper's exact string so a wrong `px`/`deg`, a dropped comma,
//! or a botched delegation is caught.
//!
//! Run (emit-only):
//! ```text
//! cargo nextest run -p ipe -E 'binary(g_stdui)' css_transform_ssot
//! ```
//! Run with full E2E (asserts the rendered strings):
//! ```text
//! IPE_E2E=1 cargo nextest run -p ipe -E 'binary(g_stdui)' css_transform_ssot
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_dir() -> PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join("css_transform_ssot")
}

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

/// Emit-only: `ipe dev build` of the transform fixture must succeed.
#[test]
fn css_transform_ssot_emits() {
    let dir = fixture_dir();
    let entry = dir.join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("css_transform_ssot_emit");
    let _ = std::fs::remove_dir_all(&out);

    let rt = runtime();
    let built = ipe::build(&entry, &out, &rt);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for css_transform_ssot: {:?}",
        built.err()
    );
}

/// Full E2E (`IPE_E2E=1`): build and run the fixture; assert every transform
/// helper renders its exact CSS string. These are the SAME strings the old
/// hand-rolled `Ui.Transform` builders produced (byte-identity of the #1213
/// delegation), proving the helpers and the delegation are output-correct.
#[test]
fn css_transform_ssot_e2e_output_matches_expected() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let dir = fixture_dir();
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_css_transform_ssot_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let rt = runtime();
    let built = ipe::build(&entry, &out, &rt);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for css_transform_ssot E2E: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("css_transform_ssot", &out);
    assert_eq!(outcome.exit_code, Some(0), "emitted binary must exit 0");

    let stdout = &outcome.stdout;

    for (helper, expected) in [
        ("translateX (px 12)", "translateX(12px)"),
        ("translateY (px -8)", "translateY(-8px)"),
        ("translate (px 3) (px 4)", "translate(3px, 4px)"),
        ("scale 0.9", "scale(0.9)"),
        ("scaleXY 1.5 2.0", "scale(1.5, 2)"),
        ("rotate (deg 45.0)", "rotate(45deg)"),
        ("skewX (deg 10.0)", "skewX(10deg)"),
        ("skewY (deg -5.0)", "skewY(-5deg)"),
    ] {
        assert!(
            stdout.contains(expected),
            "Ipe.Css {helper} must render {expected:?}; got:\n{stdout}"
        );
    }
}

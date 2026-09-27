//! Output-identity gate for the `Ipe.Css` `Opacity` newtype and `opacityOf`
//! smart constructor.
//!
//! Pins three behaviours:
//! - Normal path: `opacityOf 0.5` round-trips through `rgba` and `opacity`.
//! - Clamp: `opacityOf 1.7` renders as `"1"` (clamped to 1.0).
//! - NaN-guard: `opacityOf Math.nan` renders as `"0"` (maps to 0.0).
//!
//! Run (emit-only):
//! ```text
//! cargo nextest run -p ipe -E 'binary(g_stdui)' css_opacity_refinement
//! ```
//! Run with full E2E:
//! ```text
//! IPE_E2E=1 cargo nextest run -p ipe -E 'binary(g_stdui)' css_opacity_refinement
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_dir() -> PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join("css_opacity_refinement")
}

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    ipe::resolve_runtime().expect("runtime must resolve for css_opacity_refinement golden")
}

/// Emit-only: `ipe build` of the opacity fixture must succeed.
#[test]
fn css_opacity_refinement_emits() {
    let dir = fixture_dir();
    let entry = dir.join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("css_opacity_refinement_emit");
    let _ = std::fs::remove_dir_all(&out);

    let rt = runtime();
    let built = ipe::build(&entry, &out, &rt);
    assert!(
        built.is_ok(),
        "ipe build must succeed for css_opacity_refinement: {:?}",
        built.err()
    );
}

/// Full E2E (`IPE_E2E=1`): build and run the fixture; assert the four output
/// lines match the expected values, proving clamping and NaN-guard behaviour.
#[test]
fn css_opacity_refinement_e2e_output_matches_expected() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let dir = fixture_dir();
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_css_opacity_refinement_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let rt = runtime();
    let built = ipe::build(&entry, &out, &rt);
    assert!(
        built.is_ok(),
        "ipe build must succeed for css_opacity_refinement E2E: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("css_opacity_refinement", &out);
    assert_eq!(outcome.exit_code, Some(0), "emitted binary must exit 0");

    let stdout = &outcome.stdout;

    assert!(
        stdout.contains("rgba(255,0,0,0.5)"),
        "Css.rgba 255 0 0 (opacityOf 0.5) must render rgba(255,0,0,0.5); got:\n{stdout}"
    );
    assert!(
        stdout.contains("opacity:0.5"),
        "Css.opacity (opacityOf 0.5) must render opacity:0.5; got:\n{stdout}"
    );
    assert!(
        stdout.contains("\n1\n") || stdout.ends_with("\n1"),
        "opacityOf 1.7 must clamp to render '1'; got:\n{stdout}"
    );
    assert!(
        stdout.contains("\n0") || stdout.starts_with('0'),
        "opacityOf NaN must render '0'; got:\n{stdout}"
    );
}

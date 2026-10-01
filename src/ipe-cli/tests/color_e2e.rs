//! End-to-end SEAL for the `Ipe.Color` compiled-source veneer.
//!
//! A NON-UI console program imports `Ipe.Color`, builds a colour with the
//! constructor + manipulation kernels, parses one through the typed
//! `Result ColorError Color` boundary (`fromHex`), and derives a readable text
//! colour (the a11y surface), then prints their hex + CSS spellings. This locks
//! two properties together:
//!   * the `Ipe.Color` veneer is REACHABLE — every `Kernel.kernel "Color_*"`
//!     alias resolves to a registered kernel (no IPE-N0005 dead feature);
//!   * (`IPE_E2E`) the emitted Cargo project builds and RUNS — the SEAL — with
//!     the always-vendored `ipe_runtime::color::Color` carrier and NO `Ipe.Ui`
//!     import, proving a colour value is one type everywhere, UI or not, and
//!     that a bound a11y/parse kernel emits code that cargo-builds and runs.

use std::path::PathBuf;

mod support;

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn color_manifest() -> PathBuf {
    repo_root()
        .join("tests")
        .join("fixtures")
        .join("color-e2e")
        .join("package.ipe")
}

/// The emitted Rust carries thin `Ipe.Color` kernel calls resolved at the
/// runtime crate root (the `pub use color::*` glob), so the project builds even
/// with no `Ipe.Ui` surface in scope.
#[test]
fn color_project_builds_with_no_ui_import() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("color_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build_project(&color_manifest(), &out, &runtime());
    assert!(
        res.is_ok(),
        "color-e2e build_project must succeed (Ipe.Color veneer → emit): {:?}",
        res.err()
    );

    let emitted = support::read_all_emitted_src(&out);
    assert!(
        emitted.contains("color_rgb") && emitted.contains("color_with_alpha"),
        "emitted Rust must carry the thin `Ipe.Color` kernel shims:\n{emitted}"
    );
}

/// The GREEN GATE end-to-end: under `IPE_E2E=1` the emitted non-UI Cargo project
/// compiles and RUNS, printing the hex + CSS spelling of the built colour — the
/// whole seam from `Ipe.Color` source to a running binary.
#[test]
fn color_e2e_runs_and_prints_hex_and_css() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("color_e2e_run");
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build_project(&color_manifest(), &out, &runtime());
    assert!(res.is_ok(), "color-e2e build must succeed: {:?}", res.err());

    let outcome = support::build_and_run_emitted("color_e2e", &out);
    assert_eq!(
        outcome.stdout, "#2878c8 rgba(40,120,200,0.5) #2878c8 #000000\n",
        "the emitted binary must print `toHex (rgb 40 120 200)`, \
         `toCssRgba (withAlpha 0.5 …)`, the `fromHex \"#2878c8\"` round-trip, \
         then `toHex (readableTextOn base)` (black on the mid-blue base)"
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

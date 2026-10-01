//! Seal gate for the native `Ui.gridTracks` primitive and the compiled
//! `Ipe.Ui.Grid` module (26-ui-showcase: `__gridTracks` sentinel silently
//! dropped by the web renderer's `SafeCssPropertyName` gate).
//!
//! `Ipe.Ui.Grid.columns`/`rows`/`tracks` are pure-Ipê wrappers over the native
//! `Ui.gridTracks : String -> String -> Attribute msg` kernel
//! (`KernelFn::UiGridTracksRaw`), which constructs `AttrGridTracks(cols, rows)`.
//! This test proves the whole seam:
//!   * `import Ipe.Ui.Grid` resolves (no IPE-N0004 regression);
//!   * `gridTracks` type-checks as `String -> String -> Attribute msg`;
//!   * the emit lowers both `Grid.columns` and `Grid.tracks` to
//!     `ui_grid_tracks_raw_(…)` — NO `__gridTracks` sentinel in emitted Rust;
//!   * (`IPE_E2E`) the emitted Cargo project builds AND rendered web HTML carries
//!     `grid-template-columns:`, `grid-template-rows:`, and `display:grid` —
//!     the mandated web-HTML grid-template assertion (the seal).

use std::path::PathBuf;

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

/// A minimal Ipe.Ui program exercising BOTH grid entry points:
/// `Grid.columns` (cols only, rows = "") and `Grid.tracks` (both axes).
const MAIN_IPE: &str = r#"module Main exposing (main)

import Ipe.Html as Html
import Ipe.Ui as Ui
import Ipe.Ui.Grid as Grid
import Ipe.Io


main =
    Io.println
        (Html.htmlRender
            (Ui.layout []
                (Ui.column []
                    [ Ui.grid
                        [ Grid.columns [ Grid.fr 1, Grid.px 200, Grid.fr 1 ] ]
                        [ Ui.text "cols-only" ]
                    , Ui.grid
                        [ Grid.tracks
                            [ Grid.fr 1, Grid.fr 2 ]
                            [ Grid.auto, Grid.px 100 ]
                        ]
                        [ Ui.text "both-axes" ]
                    ])))
"#;

#[allow(clippy::expect_used)]
// `slot` gives each `#[test]` its OWN project dir under CARGO_TARGET_TMPDIR:
// the two tests here run in parallel by default; a shared path would let one
// test's `remove_dir_all` race the other's `create_dir_all`. A per-test slot
// removes the shared-path contention entirely.
fn build_grid_project(slot: &str) -> (PathBuf, Result<(), ipe::CliError>) {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("stdui_grid_seal_{slot}"));
    let _ = std::fs::remove_dir_all(&out);
    let src = out.join("src");
    std::fs::create_dir_all(&src).expect("mk grid test project dirs");
    let entry = src.join("Main.ipe");
    std::fs::write(&entry, MAIN_IPE).expect("write Main.ipe");
    let emit = out.join("emit");
    let res = ipe::build(&entry, &emit, &runtime());
    (emit, res)
}

/// `Ipe.Ui.Grid` resolves (no IPE-N0004), type-checks, and the emit lowers
/// both `Grid.columns` and `Grid.tracks` to `ui_grid_tracks_raw_` — with NO
/// `__gridTracks` sentinel leaking into the emitted Rust.
#[test]
#[allow(clippy::expect_used)]
fn grid_module_resolves_and_emits_kernel() {
    let (emit, res) = build_grid_project("emit");
    assert!(
        res.is_ok(),
        "ipe build with `import Ipe.Ui.Grid` must succeed \
         (native gridTracks + compiled module): {:?}",
        res.err()
    );

    // The compiled `Ipe.Ui.Grid` module lowers to its OWN Rust file under
    // `src/ipe_mods/` once the per-Ipê-module split
    // fires — this program has two distinct homes (`Main` + `Ipe.Ui.Grid`).
    // Scan the WHOLE emitted Ipê-side tree (main.rs + ipe_mods/*.rs) so the
    // assertion holds wherever the split correctly placed the helper calls.
    let emitted = crate::support::read_all_emitted_src(&emit);

    // Both entry points lower through the native kernel helper.
    let calls = emitted.matches("ui_grid_tracks_raw_(").count();
    assert!(
        calls >= 2,
        "emitted Rust must carry BOTH gridTracks helper calls (got {calls}):\n{emitted}"
    );

    // The old __gridTracks sentinel must be gone — it was silently dropped by
    // SafeCssPropertyName. The typed AttrGridTracks carrier replaces it.
    assert!(
        !emitted.contains("__gridTracks"),
        "emitted Rust must NOT contain the __gridTracks sentinel:\n{emitted}"
    );
}

/// The GREEN GATE: under `IPE_E2E=1` the emitted Cargo project builds and runs,
/// rendering `grid-template-columns:`, `grid-template-rows:`, and `display:grid`
/// in the HTML output — the seal, end to end.
#[test]
fn grid_e2e_builds_and_renders_grid_css() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (emit, res) = build_grid_project("e2e");
    assert!(res.is_ok(), "grid E2E build must succeed: {:?}", res.err());

    let outcome = crate::support::build_and_run_emitted("stdui_grid_seal", &emit);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "emitted grid binary must exit 0 (the seal)"
    );
    assert!(
        outcome.stdout.contains("display:grid"),
        "rendered HTML must carry display:grid:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("grid-template-columns:"),
        "rendered HTML must carry grid-template-columns:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("grid-template-rows:"),
        "rendered HTML must carry grid-template-rows (from Grid.tracks call):\n{}",
        outcome.stdout
    );
}

//! Seal gate for the native `Ipe.Ui.transition` primitive + the compiled
//! `Ipe.Ui.Transition` module (26-ui-showcase blocker: IPE-N0004 unknown
//! module `Transition`).
//!
//! `Ipe.Ui.Transition.attribute` / `attributeUnsafe` are pure-Ipê wrappers over
//! the native `Ui.transition : String -> Bool -> Attribute msg` kernel
//! (`KernelFn::UiTransitionRaw`), which constructs `AttrTransition shorthand
//! respect`.  This test proves the whole seam:
//!   * `import Ipe.Ui.Transition` resolves (no IPE-N0004 regression);
//!   * `transition` type-checks as `String -> Bool -> Attribute msg`;
//!   * the emit lowers both entry points to `ui_transition_raw_(<shorthand>,
//!     <respect>)` with the CORRECT respect flag (`true` for `attribute`,
//!     `false` for `attributeUnsafe`);
//!   * (`IPE_E2E`) the emitted Cargo project builds — the seal: ipe exit-0 ⟹
//!     cargo exit-0 — and renders the CSS `transition:` shorthand.

use std::path::PathBuf;

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

/// A minimal Ipe.Ui program exercising BOTH transition entry points: the
/// a11y-gated `attribute` (respect = True) and the opt-out `attributeUnsafe`
/// (respect = False).
const MAIN_IPE: &str = r#"module Main exposing (main)

import Ipe.Html as Html
import Ipe.Ui as Ui
import Ipe.Ui.Transition as Transition
import Ipe.Io


main =
    Io.println
        (Html.htmlRender
            (Ui.layout []
                (Ui.column []
                    [ Ui.el
                        [ Transition.attribute
                            [ Transition.property "background-color"
                            , Transition.duration 200
                            , Transition.easing Transition.easeOut
                            ]
                        ]
                        (Ui.text "safe")
                    , Ui.el
                        [ Transition.attributeUnsafe
                            [ Transition.property "opacity"
                            , Transition.duration 100
                            ]
                        ]
                        (Ui.text "unsafe")
                    ])))
"#;

// `slot` gives each `#[test]` its OWN project dir under CARGO_TARGET_TMPDIR:
// the two tests here run in parallel by default, and a shared
// `stdui_transition_seal` path would let one test's `remove_dir_all` race the
// other's `create_dir_all` (a NotFound flake). A per-test slot removes the
// shared-path contention entirely.
#[allow(clippy::expect_used)]
fn build_transition_project(slot: &str) -> (PathBuf, Result<(), ipe::CliError>) {
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("stdui_transition_seal_{slot}"));
    let _ = std::fs::remove_dir_all(&out);
    let src = out.join("src");
    std::fs::create_dir_all(&src).expect("mk transition test project dirs");
    let entry = src.join("Main.ipe");
    std::fs::write(&entry, MAIN_IPE).expect("write Main.ipe");
    let emit = out.join("emit");
    let res = ipe::build(&entry, &emit, &runtime());
    (emit, res)
}

/// `Ipe.Ui.Transition` resolves (no IPE-N0004), type-checks, and the emit
/// lowers both wrappers to `ui_transition_raw_` with the correct respect flags.
#[test]
#[allow(clippy::expect_used)]
fn transition_module_resolves_and_emits_kernel() {
    let (emit, res) = build_transition_project("emit");
    assert!(
        res.is_ok(),
        "ipe build with `import Ipe.Ui.Transition` must succeed \
         (native transition + compiled module): {:?}",
        res.err()
    );

    // The compiled `Ipe.Ui.Transition` module lowers to its OWN Rust file
    // under `src/ipe_mods/` once the per-Ipê-module split
    // fires — this program has two distinct homes (`Main` + `Ipe.Ui.Transition`).
    // Scan the WHOLE emitted Ipê-side tree (main.rs + ipe_mods/*.rs) so the
    // assertion holds wherever the split correctly placed the helper calls.
    let emitted = crate::support::read_all_emitted_src(&emit);

    // Both entry points lower through the native kernel helper — once each.
    let calls = emitted.matches("ui_transition_raw_(").count();
    assert!(
        calls >= 2,
        "emitted Rust must carry BOTH transition helper calls (got {calls}):\n{emitted}"
    );
    // `attribute` gates on reduced-motion (respect = true); `attributeUnsafe`
    // opts out (respect = false). Both flags must reach the emit as the
    // second argument of the helper — proving the flag is threaded, not
    // dropped. rustfmt wraps each call's args on their own line (adding a
    // trailing comma the compact `, true)` span never has) once the line
    // exceeds its width limit, so match on rustfmt-normalized text
    // (`crate::support::normalize_rustfmt_whitespace`) rather than the raw source —
    // same stale-substring class as #269/#191/#195.
    let normalized = crate::support::normalize_rustfmt_whitespace(&emitted);
    assert!(
        emitted.contains("ui_transition_raw_(")
            && normalized.contains(&crate::support::normalize_rustfmt_whitespace(", true)")),
        "the a11y-gated `attribute` must emit `ui_transition_raw_(…, true)`:\n{emitted}"
    );
    assert!(
        normalized.contains(&crate::support::normalize_rustfmt_whitespace(", false)")),
        "`attributeUnsafe` must emit `ui_transition_raw_(…, false)`:\n{emitted}"
    );
}

/// The GREEN GATE: under `IPE_E2E=1` the emitted Cargo project builds and runs,
/// rendering the CSS `transition:` shorthand — the seal, end to end.
#[test]
fn transition_e2e_builds_and_renders_shorthand() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (emit, res) = build_transition_project("e2e");
    assert!(
        res.is_ok(),
        "transition E2E build must succeed: {:?}",
        res.err()
    );

    let outcome = crate::support::build_and_run_emitted("stdui_transition_seal", &emit);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "emitted transition binary must exit 0 (the seal)"
    );
    assert!(
        outcome
            .stdout
            .contains("transition:background-color 200ms ease-out"),
        "rendered HTML must carry the built CSS transition shorthand:\n{}",
        outcome.stdout
    );
}

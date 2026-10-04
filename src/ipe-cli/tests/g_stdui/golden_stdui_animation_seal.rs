//! Seal gate for the native `Ipe.Ui.animate` primitive + the compiled
//! `Ipe.Ui.Animation` module (26-ui-showcase blocker #175: IPE-N0004 unknown
//! module `Animation`).
//!
//! `Ipe.Ui.Animation.attribute` is a pure-Ipê wrapper over the native
//! `Ui.animate : String -> String -> String -> Bool -> Attribute msg` kernel
//! (`KernelFn::UiAnimateRaw`), which constructs `AttrAnimation name shorthand
//! keyframes respect`.  This test proves the whole seam:
//!   * `import Ipe.Ui.Animation` resolves (no IPE-N0004 regression) — the module
//!     also transitively pulls in its `Ipe.Ui.Transition` (`Easing`) and
//!     `Ipe.Ui.Transform` (`Prop`/`propsToCss`) sibling ports;
//!   * `Animation.attribute` type-checks against the `Spec` record;
//!   * the emit lowers to `ui_animate_raw_(<name>, <shorthand>, <keyframes>,
//!     <respect>)` — the four-arg native helper;
//!   * (`IPE_E2E`) the emitted Cargo project builds — the seal: ipe exit-0 ⟹
//!     cargo exit-0 — and renders the CSS `animation:` shorthand.

use std::path::PathBuf;

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

/// A minimal Ipe.Ui program exercising `Animation.attribute`. NOTE: the
/// `keyframes` list is left EMPTY deliberately. A populated keyframe list routes
/// through `Ipe.Ui.Transform.propsToCss`, whose refutable tuple patterns
/// (`( "transform", v ) -> …`) hit the still-unimplemented `IPE-L0115
/// TuplePatternMatch` lowering — an INDEPENDENT blocker from this
/// module's resolution + kernel wiring. Empty keyframes still fully
/// exercise `Ui.animate` (name + shorthand tail + empty body + respect flag),
/// so the seal this test guards — `Ipe.Ui.Animation` resolves and its
/// `attribute` lowers to the native kernel — is proven without depending on it.
const MAIN_IPE: &str = r#"module Main exposing (main)

import Ipe.Html as Html
import Ipe.Ui as Ui
import Ipe.Ui.Animation as Animation
import Ipe.Io


main =
    Io.println
        (Html.htmlRender
            (Ui.layout []
                (Ui.el
                    [ Animation.attribute
                        { name = "fadeInUp"
                        , duration = 600
                        , easing = Animation.easeOut
                        , delay = 0
                        , iterations = Animation.once
                        , fillMode = Animation.forwards
                        , respectReducedMotion = True
                        , keyframes = []
                        }
                    ]
                    (Ui.text "fade"))))
"#;

/// `slot` gives each `#[test]` its OWN project dir under `CARGO_TARGET_TMPDIR` so
/// the two tests here (which run in parallel) never race on a shared path.
#[allow(clippy::expect_used)]
fn build_animation_project(slot: &str) -> (PathBuf, Result<(), ipe::CliError>) {
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("stdui_animation_seal_{slot}"));
    let _ = std::fs::remove_dir_all(&out);
    let src = out.join("src");
    std::fs::create_dir_all(&src).expect("mk animation test project dirs");
    let entry = src.join("Main.ipe");
    std::fs::write(&entry, MAIN_IPE).expect("write Main.ipe");
    let emit = out.join("emit");
    let res = ipe::build(&entry, &emit, &runtime());
    (emit, res)
}

/// `Ipe.Ui.Animation` resolves (no IPE-N0004), type-checks, and the emit lowers
/// `Animation.attribute` to the four-arg `ui_animate_raw_` native helper.
///
/// Now supported: `Ipe.Ui.Transform`'s refutable tuple `case`s
/// (`( "transform", v ) -> …` — a VARIABLE tuple scrutinee with a string-literal
/// column) now lower to a native `match pair { (__sg0, v) if __sg0.as_str() ==
/// "transform" => … }` (a by-value binder + `as_str()` guard), so the whole
/// `import Ipe.Ui.Animation` → `Ipe.Ui.Transform` seam builds end to end.
#[test]
#[allow(clippy::expect_used)]
fn animation_module_resolves_and_emits_kernel() {
    let (emit, res) = build_animation_project("emit");
    assert!(
        res.is_ok(),
        "ipe dev build with `import Ipe.Ui.Animation` must succeed \
         (native animate + compiled module): {:?}",
        res.err()
    );

    // The compiled `Ipe.Ui.Animation` module lowers to its OWN Rust file under
    // `src/ipe_mods/` (per-Ipê-module split), so scan the WHOLE emitted Ipê-side
    // tree (main.rs + ipe_mods/*.rs) for the helper call.
    let emitted = crate::support::read_all_emitted_src(&emit);

    let calls = emitted.matches("ui_animate_raw_(").count();
    assert!(
        calls >= 1,
        "emitted Rust must carry the animate helper call (got {calls}):\n{emitted}"
    );
    // `Ipe.Ui.Animation.attribute` (`src/stdlib/Ipe/Ui/Animation.ipe`) is a
    // stdlib function of `spec : Spec`, compiled ONCE — it calls
    // `Ui.animate spec.name (buildShorthandTail spec) (buildKeyframesBody
    // spec.keyframes) spec.respectReducedMotion`, so `respectReducedMotion`
    // threads through as a genuine field READ on the runtime `spec` value,
    // never as a literal baked in from THIS fixture's `respectReducedMotion =
    // True` call site (this function is not specialised/inlined per caller).
    // The fourth argument must be the `spec` record's field access, proving
    // the flag is threaded rather than dropped or defaulted.
    assert!(
        emitted.contains("ui_animate_raw_(") && emitted.contains("(spec).respectReducedMotion"),
        "the a11y-gated `attribute` must thread `spec.respectReducedMotion` into \
         `ui_animate_raw_`'s fourth argument:\n{emitted}"
    );
}

/// The GREEN GATE: under `IPE_E2E=1` the emitted Cargo project builds and runs,
/// rendering the CSS `animation:` shorthand — the seal, end to end.
///
/// Now supported (see `animation_module_resolves_and_emits_kernel`).
#[test]
fn animation_e2e_builds_and_renders_shorthand() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (emit, res) = build_animation_project("e2e");
    assert!(
        res.is_ok(),
        "animation E2E build must succeed: {:?}",
        res.err()
    );

    let outcome = crate::support::build_and_run_emitted("stdui_animation_seal", &emit);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "emitted animation binary must exit 0 (the seal)"
    );
    assert!(
        outcome.stdout.contains("animation:fadeInUp"),
        "rendered HTML must carry the built CSS animation shorthand:\n{}",
        outcome.stdout
    );
}

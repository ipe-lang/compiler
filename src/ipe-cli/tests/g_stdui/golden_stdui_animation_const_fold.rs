//! Phase-2 partial evaluation for `Ipe.Ui.Animation`: a pure literal builder
//! pipeline feeding `Animation.attribute` folds to a constant at compile time,
//! so the appearance-literal registry hot-swaps the animation exactly as a
//! hand-written literal.
//!
//! `Animation.attribute (defaultSpec "spin" |> withDuration 300 |> withEasing
//! easeInOut |> …)` is a call to a whitelisted builder over an all-constant
//! argument, so the const-fold pass ([`ipe_backend_rust::const_fold`]) inlines
//! `attribute`'s body with the constant `Spec` substituted and folds the inner
//! `Ui.animate` (`KernelFn::UiAnimateRaw`) call's scalar arguments to direct
//! string literals. This test proves:
//!   * the emitted `ui_animate_raw_(…)` carries DIRECT string literals for the
//!     `name` / shorthand-tail / keyframes-body arguments, not the runtime
//!     `(spec).name` / `buildShorthandTail(spec)` computed reads;
//!   * under `IPE_WATCH_HOT_APPEARANCE` the emitted view routes the folded
//!     animation strings through the per-view `LiteralTable` (`__ipe_lit`) — the
//!     existing `UiAnimateRaw` hoist arm fires on the now-direct literal, with NO
//!     registry change.

use std::path::PathBuf;
use std::sync::Mutex;

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

/// A `Ipe.Tea.Web` app whose view attaches an animation built from a fully
/// literal `Ipe.Ui.Animation` pipeline — every knob a compile-time constant, so
/// the whole `Spec` and its rendered strings fold. Empty `keyframes` keep the
/// fixture focused on the shorthand-tail fold (a populated list folds the same
/// way; the tail alone exercises the `String.fromInt` / `++` / `easingToCss`
/// pipeline the fold must reduce).
const MAIN_IPE: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
import Ipe.Ui.Animation as Animation


type alias Model =
    { count : Int }


type Msg
    = NoOp


init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )


update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )


view : Model -> Element Msg
view _model =
    Ui.el
        [ Animation.attribute
            { name = "spin"
            , duration = 300
            , easing = Animation.easeInOut
            , delay = 0
            , iterations = Animation.once
            , fillMode = Animation.forwards
            , respectReducedMotion = True
            , keyframes = []
            }
        ]
        (Ui.text "spinner")


subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none


main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = NoOp
        }
"#;

/// Serialise the two hot-appearance-env-sensitive builds — the env var is
/// process-global, so a parallel sibling toggling it would race this test.
static HOT_ENV_LOCK: Mutex<()> = Mutex::new(());

#[allow(clippy::expect_used)]
fn build_project(slot: &str, hot: bool) -> (PathBuf, Result<(), ipe::CliError>) {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("stdui_animation_const_fold_{slot}"));
    let _ = std::fs::remove_dir_all(&out);
    let src = out.join("src");
    std::fs::create_dir_all(&src).expect("mk const-fold test project dirs");
    let entry = src.join("Main.ipe");
    std::fs::write(&entry, MAIN_IPE).expect("write Main.ipe");
    let emit = out.join("emit");
    // `ipe::build` is the prod entry and keeps `hot_appearance` off regardless of
    // environment; drive the hot-swap hoist explicitly through the option instead.
    let options = ipe::BuildOptions {
        hot_appearance: hot,
        ..ipe::BuildOptions::from_env()
    };
    let res = ipe::build_with_options(&entry, &emit, &runtime(), options);
    (emit, res)
}

/// The fold surfaces DIRECT string-literal arguments to `ui_animate_raw_`, not
/// the runtime `(spec)`-field computed reads.
#[test]
#[allow(clippy::expect_used)]
fn literal_animation_pipeline_folds_to_direct_string_args() {
    let _guard = HOT_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // The ordinary (non-hot) build must still fold; hot-swap hoist stays off.
    let (emit, res) = build_project("emit", false);
    assert!(
        res.is_ok(),
        "const-fold build must succeed: {:?}",
        res.err()
    );

    let emitted = crate::support::read_all_emitted_src(&emit);
    assert!(
        emitted.contains("ui_animate_raw_("),
        "emitted Rust must carry the animate helper call:\n{emitted}"
    );
    // The folded `name` argument is the direct literal `"spin"`, and the folded
    // shorthand tail is the direct literal `"300ms ..."` — proving the pipeline
    // reduced at compile time rather than threading `(spec).name` /
    // `buildShorthandTail(spec)` at run time.
    assert!(
        emitted.contains("\"spin\""),
        "the folded animation name must appear as a direct string literal:\n{emitted}"
    );
    assert!(
        emitted.contains("\"300ms"),
        "the folded shorthand tail must appear as a direct string literal \
         starting with the duration:\n{emitted}"
    );
    // The folded call must NOT thread the runtime `spec` field reads — those are
    // the tell-tale of an UN-folded computed argument.
    assert!(
        !emitted.contains("buildShorthandTail"),
        "a folded pipeline must not emit the runtime shorthand builder call:\n{emitted}"
    );
}

/// Under `IPE_WATCH_HOT_APPEARANCE`, the now-direct-literal animation arguments
/// route through the per-view `LiteralTable` (`__ipe_lit`) — the existing
/// `UiAnimateRaw` hoist arm, with no registry change.
#[test]
#[allow(clippy::expect_used)]
fn folded_animation_hoists_under_hot_appearance() {
    let _guard = HOT_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (emit, res) = build_project("hot", true);
    assert!(
        res.is_ok(),
        "hot-appearance const-fold build must succeed: {:?}",
        res.err()
    );

    let emitted = crate::support::read_all_emitted_src(&emit);
    assert!(
        emitted.contains("ui_animate_raw_("),
        "emitted Rust must carry the animate helper call under hot-appearance:\n{emitted}"
    );
    assert!(
        emitted.contains("__ipe_lit"),
        "under IPE_WATCH_HOT_APPEARANCE the folded animation must hoist into the \
         per-view LiteralTable (__ipe_lit):\n{emitted}"
    );
}

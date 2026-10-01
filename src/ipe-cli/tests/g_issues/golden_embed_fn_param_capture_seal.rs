//! THE SEAL for a `Web.embed` cfg that captures a function-typed parameter.
//!
//! `mk f = Web.embed { …, update = f, … }` passes a caller's update function
//! through an enclosing parameter. A function value lowers to a boxed closure,
//! which is not `Clone`, so the mountable handle must evaluate the cfg once and
//! share it between its standalone `serve` task and its mount router builder —
//! never emit the callbacks twice nor clone their captures. Both the
//! single-page and the routed (`Model` has a `page` field) embed must be
//! accepted, and under `IPE_E2E` the emitted crate must `cargo build`. The
//! entry is a mounted server app, so the emitted binary listens forever; the
//! test proves the build, not a run.
//!
//! ```text
//! # emit check only (fast):
//! cargo test -p ipe --test g_issues golden_embed_fn_param_capture
//! # full (cargo build of the emitted program):
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_embed_fn_param_capture
//! ```

use std::path::PathBuf;

use ipe::CliError;

/// A runtime `false` the optimiser cannot fold, so `assert!(false_marker(), …)`
/// reads as a deliberate unconditional failure rather than a suspicious constant
/// condition.
const fn false_marker() -> bool {
    std::hint::black_box(false)
}

/// A single-page `Web.embed` whose `update` is the function parameter `f`.
const EMBED_FN_PARAM_UPDATE: &str = r#"module Main exposing (main)

import Ipe.Server.Http as Server
import Ipe.String as String
import Ipe.Task as Task exposing (Task)
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui


type alias Model =
    { count : Int }


type Msg
    = Increment
    | NoOp


step : Msg -> Model -> ( Model, Cmd.Cmd Msg )
step msg model =
    case msg of
        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )

        NoOp ->
            ( model, Cmd.none )


mk : (Msg -> Model -> ( Model, Cmd.Cmd Msg )) -> Web.WebApp
mk f =
    Web.embed
        { init = \_ -> ( { count = 0 }, Cmd.none )
        , update = f
        , view = \model -> Ui.text (String.fromInt model.count)
        , subscriptions = \_ -> Sub.none
        , routes = []
        , notFound = NoOp
        }


main : Task Error ()
main =
    Server.listen 8000 [ Server.mountApp "/" (mk step) ]
"#;

/// A routed `Web.embed` whose `update` is the function parameter `f`.
const EMBED_ROUTED_FN_PARAM_UPDATE: &str = r#"module Main exposing (main)

import Ipe.Server.Http as Server
import Ipe.String as String
import Ipe.Task as Task exposing (Task)
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui


type Page
    = HomePage
    | AboutPage


type alias Model =
    { page : Page
    , count : Int
    }


type Msg
    = Increment
    | NoOp


step : Msg -> Model -> ( Model, Cmd.Cmd Msg )
step msg model =
    case msg of
        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )

        NoOp ->
            ( model, Cmd.none )


mk : (Msg -> Model -> ( Model, Cmd.Cmd Msg )) -> Web.WebApp
mk f =
    Web.embed
        { init = \_ -> ( { page = HomePage, count = 0 }, Cmd.none )
        , update = f
        , view =
            \model ->
                case model.page of
                    HomePage ->
                        Ui.text (String.fromInt model.count)

                    AboutPage ->
                        Ui.text "about"
        , subscriptions = \_ -> Sub.none
        , routes =
            [ Web.route "/" HomePage
            , Web.route "/about" AboutPage
            ]
        , notFound = HomePage
        }


main : Task Error ()
main =
    Server.listen 8000 [ Server.mountApp "/" (mk step) ]
"#;

#[test]
fn embed_fn_param_update_builds() {
    assert_accepted_and_builds("embed_fn_param_update", EMBED_FN_PARAM_UPDATE);
}

#[test]
fn embed_routed_fn_param_update_builds() {
    assert_accepted_and_builds("embed_routed_fn_param_update", EMBED_ROUTED_FN_PARAM_UPDATE);
}

/// `source` must be accepted by `ipe`, and under `IPE_E2E` its crate must `cargo build`.
fn assert_accepted_and_builds(name: &str, source: &str) {
    let Some((built, out)) = build_fixture(name, source) else {
        return;
    };
    match built {
        Ok(()) => crate::support::assert_seal_builds(name, &out),
        Err(err) => assert!(
            false_marker(),
            "{name}: a concrete embed capturing a function parameter must be accepted, got: {err:?}"
        ),
    }
}

/// Build `source` as `name`, returning the build result and its output dir
/// (`None`, after a failed assertion, when scratch or runtime setup fails).
fn build_fixture(name: &str, source: &str) -> Option<(Result<(), CliError>, PathBuf)> {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("embed-fn-param-capture");
    let src = root.join(name).join("src");
    let _ = std::fs::remove_dir_all(root.join(name));
    let entry = src.join("Main.ipe");
    if std::fs::create_dir_all(&src)
        .and_then(|()| std::fs::write(&entry, source))
        .is_err()
    {
        assert!(
            false_marker(),
            "{name}: could not write the fixture into the scratch dir"
        );
        return None;
    }
    let out = root.join(format!("{name}-out"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    Some((ipe::build(&entry, &out, &runtime), out))
}

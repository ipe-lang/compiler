//! The `Ipe.Web` / `Ipe.Tui` / `Ipe.WebView` app-entry Msg-admissibility gate.
//!
//! `web_app` bounds its Msg `Clone + Send + Sync + Debug + 'static`;
//! `tui_app` / `webview_app` bound it `Clone + Send + 'static`. Without the
//! gate, a Msg storing a non-admissible value (`Cmd` / `Sub` / `Task` /
//! `Decoder` / `Db` / a function) makes `ipe` exit 0 and then `cargo build`
//! fail on the missing trait bound. The gate converts that into a fail-closed
//! `IPE-L0125` diagnostic.
//!
//! KEY ASYMMETRY: `Html`-carrying Msg MUST be ACCEPTED. The predicate is
//! `ir_type_is_derivable` (NOT serde) — `Html` derives Clone+Debug+PartialEq
//! and is therefore admissible in a Msg, unlike in a `Ipe.Web` Model (where
//! serde is required). This fixture is the critical acceptance case.
//!
//! These tests are COMPILE-ONLY (they run the `ipe` pipeline + write the
//! project, but never invoke `cargo`), so they are fast and NOT gated on
//! `IPE_E2E`.

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Compile `source` through `ipe::build`, returning the pipeline result.
fn compile(test_name: &str, source: &str) -> Result<Result<(), ipe::CliError>, BoxError> {
    let ipe_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("msg_adm_{test_name}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(&ipe_dir)?;
    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, source)?;

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("msg_adm_{test_name}_out"));
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();
    Ok(ipe::build(&entry, &out_dir, &runtime))
}

/// Assert compilation failed with the given diagnostic code.
fn assert_rejected_with(
    test_name: &str,
    source: &str,
    expected_code: &str,
) -> Result<(), BoxError> {
    match compile(test_name, source)? {
        Ok(()) => Err(format!("{test_name}: expected {expected_code}, but ipec succeeded").into()),
        Err(ipe::CliError::Pipeline { diag, .. }) => {
            assert_eq!(
                diag.code().as_str(),
                expected_code,
                "{test_name}: wrong diagnostic code"
            );
            Ok(())
        }
        Err(other) => Err(format!("{test_name}: expected {expected_code}, got {other:?}").into()),
    }
}

/// Assert compilation succeeded (ipe-0).
fn assert_accepted(test_name: &str, source: &str) -> Result<(), BoxError> {
    match compile(test_name, source)? {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("{test_name}: expected ipec success, got {e:?}").into()),
    }
}

// ── Rejection fixtures ────────────────────────────────────────────────────────

/// `Ipe.Web` app: Msg variant carries a `Cmd`. Must be rejected with IPE-L0125.
const LIVE_CMD_MSG: &str = r"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.String
import Ipe.Tea.Web.Sub

type Msg
    = Tick
    | WithEffect (Cmd Msg)

type alias Model = { count : Int }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Tick ->
            ( { model | count = model.count + 1 }, Cmd.none )
        WithEffect _ ->
            ( model, Cmd.none )

view : Model -> Element Msg
view model =
    Ui.text (String.fromInt model.count)

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Tick
        }
";

/// `Ipe.Web` app: Msg variant carries a function. A declared function-typed
/// payload is sound on its own (derive-demotion keeps the emitted enum's
/// derives correct), so it is NOT rejected at the declaration site
/// (`IPE-L0114`); it falls through to the MORE PRECISE Msg-admissibility
/// gate: `Msg` fails the runtime's `Clone + Send + Sync + Debug + 'static`
/// bound because of the embedded function, `IPE-L0125`.
const LIVE_FN_MSG: &str = r"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.String
import Ipe.Tea.Web.Sub

type Msg
    = Noop
    | SetHandler (Int -> String)

type alias Model = { count : Int }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Noop ->
            ( model, Cmd.none )
        SetHandler _ ->
            ( model, Cmd.none )

view : Model -> Element Msg
view model =
    Ui.text (String.fromInt model.count)

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Noop
        }
";

/// `Ipe.Web` app: `update` is an inline lambda; Msg carries a `Cmd`.
/// Exercises the `fn_param_ty` Lambda recovery path for Msg.
const LIVE_LAMBDA_UPDATE_CMD_MSG: &str = r"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.String
import Ipe.Tea.Web.Sub

type Msg
    = Tick
    | WithEffect (Cmd Msg)

type alias Model = { count : Int }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

view : Model -> Element Msg
view model =
    Ui.text (String.fromInt model.count)

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init
        , update = \msg model ->
            case msg of
                Tick -> ( { model | count = model.count + 1 }, Cmd.none )
                WithEffect _ -> ( model, Cmd.none )
        , view = view
        , subscriptions = subscriptions
        , routes = [], notFound = Tick
        }
";

/// `Ipe.Tui` app: Msg variant carries a `Cmd`. Must be rejected with IPE-L0125.
const TUI_CMD_MSG: &str = r"module Main exposing (main)

import Ipe.Tea.Tui as Tui
import Ipe.Ui.Cells as Cells
import Ipe.Ui.Cells exposing (Screen)
import Ipe.Tea.Terminal.Cmd
import Ipe.String
import Ipe.Tea.Tui.Sub

type Msg
    = Increment
    | NoOp
    | WithEffect (Cmd Msg)

type alias Model = { count : Int }

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )
        NoOp ->
            ( model, Cmd.none )
        WithEffect _ ->
            ( model, Cmd.none )

view : Model -> Screen Msg
view model =
    Cells.column [] [ Cells.el [] (Cells.text (String.fromInt model.count)) ]

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.onKey onKey

type alias KeyEvent = { kind : String, value : String }

onKey : KeyEvent -> Msg
onKey _event =
    NoOp

main =
    Tui.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        }
";

/// `Ipe.Tui` app: Msg variant carries a function. Same shape as
/// `LIVE_FN_MSG` — falls through to the Msg gate, `IPE-L0125`.
const TUI_FN_MSG: &str = r"module Main exposing (main)

import Ipe.Tea.Tui as Tui
import Ipe.Ui.Cells as Cells
import Ipe.Ui.Cells exposing (Screen)
import Ipe.Tea.Terminal.Cmd
import Ipe.String
import Ipe.Tea.Tui.Sub

type Msg
    = NoOp
    | SetHandler (Int -> String)

type alias Model = { count : Int }

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        NoOp ->
            ( model, Cmd.none )
        SetHandler _ ->
            ( model, Cmd.none )

view : Model -> Screen Msg
view model =
    Cells.column [] [ Cells.el [] (Cells.text (String.fromInt model.count)) ]

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.onKey onKey

type alias KeyEvent = { kind : String, value : String }

onKey : KeyEvent -> Msg
onKey _event =
    NoOp

main =
    Tui.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        }
";

// ── Acceptance fixtures ───────────────────────────────────────────────────────

/// CRITICAL asymmetry fixture: `Ipe.Web` Msg carries `Html Msg`.
/// `Html` derives Clone+Debug+PartialEq (derivable) but is NOT serde.
/// The Msg gate uses derivable (not serde), so this MUST be ACCEPTED (ipe-0).
/// If the gate incorrectly used serde, this would be rejected — breaking the
/// invariant that Msg and Model use different admissibility predicates.
const LIVE_HTML_MSG: &str = r"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.String
import Ipe.Tea.Web.Sub

type Msg
    = Noop
    | CachedView (Html Msg)

type alias Model = { count : Int }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Noop ->
            ( model, Cmd.none )
        CachedView _ ->
            ( model, Cmd.none )

view : Model -> Element Msg
view model =
    Ui.text (String.fromInt model.count)

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Noop
        }
";

/// Plain-data Msg + `Ipe.Web` app — the normal happy path. Must be accepted.
const LIVE_PLAIN_MSG: &str = r"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.String
import Ipe.Tea.Web.Sub

type Msg
    = Increment
    | Reset
    | SetLabel String

type alias Model = { count : Int }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )
        Reset ->
            ( { model | count = 0 }, Cmd.none )
        SetLabel _ ->
            ( model, Cmd.none )

view : Model -> Element Msg
view model =
    Ui.text (String.fromInt model.count)

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Reset
        }
";

// ── Test functions ────────────────────────────────────────────────────────────

#[test]
fn live_msg_with_cmd_is_rejected() -> Result<(), BoxError> {
    assert_rejected_with("live_cmd_msg", LIVE_CMD_MSG, "IPE-L0125")
}

#[test]
fn live_msg_with_fn_is_rejected() -> Result<(), BoxError> {
    // The declaration-site gate (L0114) does not fire on a declared
    // function-typed payload; the Msg gate (L0125) catches the non-admissible
    // function-embedding Msg.
    assert_rejected_with("live_fn_msg", LIVE_FN_MSG, "IPE-L0125")
}

#[test]
fn live_lambda_update_with_cmd_msg_is_rejected() -> Result<(), BoxError> {
    assert_rejected_with(
        "live_lambda_update_cmd_msg",
        LIVE_LAMBDA_UPDATE_CMD_MSG,
        "IPE-L0125",
    )
}

#[test]
fn tui_msg_with_cmd_is_rejected() -> Result<(), BoxError> {
    assert_rejected_with("tui_cmd_msg", TUI_CMD_MSG, "IPE-L0125")
}

#[test]
fn tui_msg_with_fn_is_rejected() -> Result<(), BoxError> {
    // The declaration-site gate (L0114) does not fire on a declared
    // function-typed payload; the Msg gate (L0125) catches the non-admissible
    // function-embedding Msg.
    assert_rejected_with("tui_fn_msg", TUI_FN_MSG, "IPE-L0125")
}

/// THE CRITICAL ASYMMETRY TEST: Html in Msg must be ACCEPTED (derivable, not serde).
#[test]
fn live_html_msg_is_accepted() -> Result<(), BoxError> {
    assert_accepted("live_html_msg", LIVE_HTML_MSG)
}

#[test]
fn live_plain_msg_is_accepted() -> Result<(), BoxError> {
    assert_accepted("live_plain_msg", LIVE_PLAIN_MSG)
}

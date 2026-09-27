//! Compile-time surface tests for `Ipe.Tea.Tui` and `Ipe.Tea.Cli`.
//!
//! `Ipe.Tea.Tui` exposes the full-screen terminal TEA entry via `Tui.tea`;
//! `Ipe.Tea.Cli` exposes the line-oriented entry via `Cli.tea`. Both `app`
//! entries are registered in the `env.rs` qualifier catalog and carry
//! `KernelClass::Terminal` (the one terminal rendering family).
//!
//! These tests are COMPILE-ONLY (the `ipe` pipeline writes the emitted project
//! but `cargo` is never invoked), so they run in CI without `IPE_E2E`.

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

fn compile(test_name: &str, source: &str) -> Result<Result<(), ipe::CliError>, BoxError> {
    let ipe_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("tea_surface_{test_name}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(&ipe_dir)?;
    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, source)?;

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("tea_surface_{test_name}_out"));
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = ipe::resolve_runtime().map_err(|e| -> BoxError { format!("{e:?}").into() })?;
    Ok(ipe::build(&entry, &out_dir, &runtime))
}

fn assert_accepted(test_name: &str, source: &str) -> Result<(), BoxError> {
    match compile(test_name, source)? {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("{test_name}: expected ipe success, got {e:?}").into()),
    }
}

/// Assert `source` is REJECTED by the pipeline with exactly `expected` wire
/// code (never exit-0 — a wrong code or an accept both fail). Pins the SPECIFIC
/// rejection reason so a right-outcome-wrong-reason regression is caught.
fn assert_rejected_code(test_name: &str, source: &str, expected: &str) -> Result<(), BoxError> {
    match compile(test_name, source)? {
        Ok(()) => {
            Err(format!("{test_name}: expected rejection {expected}, but ipe accepted").into())
        }
        Err(ipe::CliError::Pipeline { diag, .. }) => {
            let got = diag.code().as_str();
            if got == expected {
                Ok(())
            } else {
                Err(format!(
                    "{test_name}: expected {expected}, got {got} — rejected for the WRONG reason"
                )
                .into())
            }
        }
        Err(other) => {
            Err(format!("{test_name}: expected pipeline rejection, got {other:?}").into())
        }
    }
}

/// Minimal `Tui.tea` program — `import Ipe.Tea.Tui as Tui` then `Tui.tea { ... }`.
const TUI_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Tui as Tui
import Ipe.Ui.Cells as Cells
import Ipe.Ui.Cells exposing (Screen)
import Ipe.Tea.Tui.Cmd
import Ipe.Tea.Tui.Sub

type Msg = NoOp

type alias Model = { count : Int }

type alias KeyEvent = { kind : String, value : String }

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )

view : Model -> Screen Msg
view _model =
    Cells.text "hello"

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

onKey : KeyEvent -> Msg
onKey _event =
    NoOp

main =
    Tui.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions, onKey = onKey
        }
"#;

/// Minimal `Cli.tea` program — `import Ipe.Tea.Cli as Cli` then `Cli.tea { ... }`.
const CLI_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Cli as Cli
import Ipe.Tea.Cli.Cmd
import Ipe.Tea.Cli.Sub
import Ipe.Ui.Cli as Ui
import Ipe.Ui.Cli exposing (Lines)

type Msg = Line String | NoOp

type alias Model = { lines : List String }

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { lines = [] }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Line s ->
            ( { model | lines = model.lines ++ [ s ] }, Cmd.none )
        NoOp ->
            ( model, Cmd.none )

view : Model -> Lines Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

onLine : String -> Msg
onLine s =
    Line s

main =
    Cli.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions, onLine = onLine
        }
"#;

/// A DOM view (`View Web msg`) whose container holds a terminal-cells node
/// (`View Tui msg`). The two engines are distinct nullary tags on the one
/// `View engine msg` carrier, so mixing them in one view tree fails
/// unification — a cross-engine view is unrepresentable, not a silent render.
const CROSS_ENGINE_VIEW: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
import Ipe.Ui.Cells as Cells

type Msg = NoOp

type alias Model = { count : Int }

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update _msg model =
    ( model, Cmd.none )

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Sub.none

-- A DOM column (`View Web Msg`) whose child is a terminal-cells node
-- (`View Tui Msg`): the engines differ, so this cannot unify.
view : Model -> Element Msg
view _model =
    Ui.column [] [ Cells.text "nope" ]

main =
    Web.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        , routes = [], notFound = NoOp
        }
"#;

/// A `View` over a tag outside the closed `{Web, Tui, Cli}` engine set. The
/// tag names no view engine, so it is rejected fail-closed at canon — never a
/// flexible variable that defers the failure downstream.
const NON_ENGINE_VIEW: &str = r"module Main exposing (v)

v : View Foo Msg
v = v
";

/// `Tui.tea` is the full-screen terminal entry kernel registered in
/// the `env.rs` qualifier catalog. A program using
/// `import Ipe.Tea.Tui as Tui` and `Tui.tea { ... }` must compile (ipe-0).
#[test]
fn tui_app_surface_compiles() -> Result<(), BoxError> {
    assert_accepted("tui_app", TUI_APP)
}

/// A cross-engine view (a `View Tui Msg` node inside a `View Web Msg` tree)
/// fails unification: the engine tags are distinct, so
/// make-invalid-states-unrepresentable turns the mix into an IPE-T0001 type
/// mismatch rather than a silent wrong-engine render.
#[test]
fn cross_engine_view_fails_unification() -> Result<(), BoxError> {
    assert_rejected_code("cross_engine_view", CROSS_ENGINE_VIEW, "IPE-T0001")
}

/// A `View` over a non-engine tag (`View Foo Msg`) is rejected fail-closed as
/// an unknown type name (IPE-N0002) — the engine set is CLOSED, so an
/// unrecognised tag has no view denotation and never becomes a flexible var.
#[test]
fn non_engine_view_tag_is_rejected() -> Result<(), BoxError> {
    assert_rejected_code("non_engine_view", NON_ENGINE_VIEW, "IPE-N0002")
}

/// `Cli.tea` is the line-oriented terminal entry kernel registered in
/// the `env.rs` qualifier catalog. A program using
/// `import Ipe.Tea.Cli as Cli` and `Cli.tea { ... }` must compile (ipe-0).
#[test]
fn cli_app_surface_compiles() -> Result<(), BoxError> {
    assert_accepted("cli_app", CLI_APP)
}

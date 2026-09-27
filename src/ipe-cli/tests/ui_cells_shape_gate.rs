//! The `Ui.cells` shape-admissibility gate (IPE-L0132).
//!
//! `Ui.cells : List (List Char) -> Element msg` paints a raw terminal cell grid
//! and has no browser denotation. Its runtime helper degrades to plain text on a
//! non-terminal backend, so a `Web` / `WebView` program using it would `ipe`-
//! succeed and then silently render the wrong thing. The backend gate converts
//! that into a fail-closed `IPE-L0132` diagnostic the moment `Ui.cells` is
//! emitted under a web-family shape (SECURITY — fail closed, never a `cargo`
//! failure and never a panic).
//!
//! These tests are COMPILE-ONLY (they run the `ipe` pipeline + write the
//! project, but never invoke `cargo`), so they are fast and NOT gated on
//! `IPE_E2E`.

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Compile `source` through `ipe::build`, returning the pipeline result. The
/// emitted project is written to a per-test temp dir; `cargo` is never invoked.
fn compile(test_name: &str, source: &str) -> Result<Result<(), ipe::CliError>, BoxError> {
    let ipe_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ui_cells_gate_{test_name}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(&ipe_dir)?;
    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, source)?;

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ui_cells_gate_{test_name}_out"));
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = ipe::resolve_runtime().map_err(|e| -> BoxError { format!("{e:?}").into() })?;
    Ok(ipe::build(&entry, &out_dir, &runtime))
}

/// Assert compilation failed with the given diagnostic code (fail-closed, an
/// `ipe`-time diagnostic — never a `cargo` failure or a panic).
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

/// `Ui.cells` inside a `Web.tea` view — must be rejected with IPE-L0132.
const WEB_UI_CELLS: &str = r"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub

type Msg = Tick

type alias Model = { count : Int }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Tick ->
            ( { model | count = model.count + 1 }, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.cells [ [ 'h', 'i' ] ]

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Tick
        }
";

/// `Cells.cells` inside a `Tui.tea` view — must be ACCEPTED (the raw
/// cell grid is a terminal primitive; this is the shape it belongs to). A Tui
/// view is `Screen Msg`, so the grid island is built with `Cells.cells`.
const TERMINAL_UI_CELLS: &str = r#"module Main exposing (main)

import Ipe.Tea.Tui as Tui
import Ipe.Ui.Cells as Cells
import Ipe.Ui.Cells exposing (Screen)
import Ipe.Tea.Terminal.Cmd
import Ipe.Tea.Terminal.Sub

type Msg = NoOp

type alias Model = { count : Int }

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        NoOp ->
            ( model, Cmd.none )

view : Model -> Screen Msg
view _model =
    Cells.column []
        [ Cells.text "grid:"
        , Cells.cells [ [ '4', '8' ], [ '6', '9' ] ]
        ]

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

type alias KeyEvent = { kind : String, value : String }

onKey : KeyEvent -> Msg
onKey _event =
    NoOp

main =
    Tui.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions, onKey = onKey
        }
"#;

/// A `Web.tea` view painting `Ui.cells` is a terminal-only node in a web-family
/// build: rejected fail-closed with IPE-L0132, not a cargo failure or a panic.
#[test]
fn web_view_with_ui_cells_is_rejected() -> Result<(), BoxError> {
    assert_rejected_with("web_ui_cells", WEB_UI_CELLS, "IPE-L0132")
}

/// Non-regression control: `Cells.cells` under `Tui.tea` is the
/// shape it belongs to and must compile cleanly (ipe-0).
#[test]
fn terminal_view_with_ui_cells_is_accepted() -> Result<(), BoxError> {
    assert_accepted("terminal_ui_cells", TERMINAL_UI_CELLS)
}

/// `Ui.cells` in a `Cli.tea` (Cli shape) view.
///
/// `Cli.tea` requires `view : Model -> Lines msg`. `Ui.cells` returns
/// `Element msg` (a 2D cell grid), which is incompatible with `Lines msg`. The
/// type checker rejects the program with IPE-T0001 (type mismatch) before the
/// backend shape gate (IPE-L0153) is reached. The shape gate is defense-in-depth:
/// unreachable helper functions containing `Ui.cells` are eliminated by dead
/// code analysis before emission, so the gate fires only if the type system
/// is bypassed (e.g., programmatic IR construction). This test confirms
/// the type-level rejection.
const CLI_UI_CELLS: &str = r"module Main exposing (main)

import Ipe.Tea.Cli as Cli
import Ipe.Ui.Cli exposing (Lines)
import Ipe.Ui as Ui

type Msg = NoOp

type alias Model = { count : Int }

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        NoOp ->
            ( model, Cmd.none )

view : Model -> Lines Msg
view _model =
    Ui.cells [ [ 'h', 'i' ] ]

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

onLine : String -> Msg
onLine _line =
    NoOp

main =
    Cli.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions, onLine = onLine
        }
";

/// `Ui.cells` in a `Cli.tea` view is rejected because the type checker
/// rejects `Element msg` where `Lines msg` is required (IPE-T0001). The backend
/// shape gate (IPE-L0153) is defense-in-depth for paths that bypass type
/// inference.
#[test]
fn cli_view_with_ui_cells_is_rejected() -> Result<(), BoxError> {
    match compile("cli_ui_cells", CLI_UI_CELLS)? {
        Ok(()) => Err("cli_ui_cells: expected a type or shape error, but ipec succeeded".into()),
        Err(ipe::CliError::Pipeline { .. }) => Ok(()),
        Err(other) => Err(format!("cli_ui_cells: unexpected error: {other:?}").into()),
    }
}

/// A DOM attribute (`Ui.onClick`) placed in a `Screen` view. `Ipe.Ui.Tui`'s
/// builders take a cell-native `Attribute msg` (`TuiAttr`), a type DISTINCT from
/// the DOM `Ipe.Ui.Attribute msg`. So naming a DOM attribute here is a type
/// error (IPE-T0001) — the terminal author's intent is rejected at type-check,
/// never silently discarded at render time. This is the make-invalid-states-
/// unrepresentable half of the surface: the builder half was already guarded;
/// this pins the attribute half.
const SCREEN_WITH_DIM_REVERSE: &str = r#"module Main exposing (main)

import Ipe.Tea.Tui as Tui
import Ipe.Ui.Tui as Ui
import Ipe.Ui.Tui exposing (Screen)
import Ipe.Tea.Tui.Cmd
import Ipe.Tea.Tui.Sub

type Msg = NoOp

type alias Model = { count : Int }

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )

view : Model -> Screen Msg
view _model =
    Ui.column []
        [ Ui.el [ Ui.dim ] (Ui.text "faint")
        , Ui.el [ Ui.reverse ] (Ui.text "reversed")
        ]

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

type alias KeyEvent = { kind : String, value : String }

onKey : KeyEvent -> Msg
onKey _event =
    NoOp

main =
    Tui.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions, onKey = onKey
        }
"#;

/// The line-scoped `dim` / `reverse` text styles are admissible cell-native
/// attributes in a `Screen` view (ipe-0).
#[test]
fn screen_view_with_dim_and_reverse_is_accepted() -> Result<(), BoxError> {
    assert_accepted("screen_dim_reverse", SCREEN_WITH_DIM_REVERSE)
}

const SCREEN_WITH_DOM_ATTRIBUTE: &str = r#"module Main exposing (main)

import Ipe.Tea.Tui as Tui
import Ipe.Ui.Tui as Ui
import Ipe.Ui.Tui exposing (Screen)
import Ipe.Ui as Dom
import Ipe.Tea.Tui.Cmd
import Ipe.Tea.Tui.Sub

type Msg = Clicked | NoOp

type alias Model = { count : Int }

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )

view : Model -> Screen Msg
view _model =
    Ui.el [ Dom.onClick Clicked ] (Ui.text "hello")

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

type alias KeyEvent = { kind : String, value : String }

onKey : KeyEvent -> Msg
onKey _event =
    NoOp

main =
    Tui.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions, onKey = onKey
        }
"#;

/// A DOM attribute in a `Screen` view is IPE-T0001 (rejected at type-check),
/// NOT a silent render-time drop. The distinct cell-native `Attribute` type
/// makes the DOM constructor unnameable in the terminal surface.
#[test]
fn screen_view_with_dom_attribute_is_rejected() -> Result<(), BoxError> {
    assert_rejected_with("screen_dom_attr", SCREEN_WITH_DOM_ATTRIBUTE, "IPE-T0001")
}

// ── Ipe.Ui.Cli structured `Lines` view surface ───────────────────────────

const CLI_WITH_LINES_HELPER: &str = r#"module Main exposing (main)

import Ipe.String as String
import Ipe.Tea.Cli as Cli
import Ipe.Tea.Cli.Cmd as Cmd
import Ipe.Tea.Cli.Sub as Sub
import Ipe.Ui.Cli as Ui
import Ipe.Ui.Cli exposing (Lines)
import Ipe.Color.Ansi as Color

type Msg = NoOp

type alias Model = { count : Int }

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )

banner : Model -> Lines Msg
banner model =
    Ui.lines
        [ Ui.line [ Ui.bold, Ui.color Color.brightGreen ] "ready"
        , Ui.line [ Ui.dim ] ("count = " ++ String.fromInt model.count)
        , Ui.line [ Ui.reverse, Ui.bg Color.blue ] "status"
        , Ui.text "(type a line)"
        ]

view : Model -> Lines Msg
view model =
    banner model

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

onLine : String -> Msg
onLine _line =
    NoOp

main =
    Cli.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions, onLine = onLine
        }
"#;

/// The structured `Lines` view surface, its line-native `Attribute` builders,
/// and the `Ipe.Color` terminal palette (`AnsiColor`) type-check + lower + emit
/// under the Cli shape (ipe-0). The `Cli.tea` `view` returns a `Lines msg` value
/// built from those builders.
#[test]
fn cli_lines_surface_with_palette_is_accepted() -> Result<(), BoxError> {
    assert_accepted("cli_lines_palette", CLI_WITH_LINES_HELPER)
}

const LINES_WITH_DOM_ATTRIBUTE: &str = r#"module Main exposing (main)

import Ipe.Tea.Cli as Cli
import Ipe.Tea.Cli.Cmd as Cmd
import Ipe.Tea.Cli.Sub as Sub
import Ipe.Ui.Cli as Ui
import Ipe.Ui.Cli exposing (Lines)
import Ipe.Ui as Dom

type Msg = Clicked | NoOp

type alias Model = { count : Int }

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )

banner : Model -> Lines Msg
banner _model =
    Ui.line [ Dom.onClick Clicked ] "hello"

view : Model -> Lines Msg
view model =
    banner model

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

onLine : String -> Msg
onLine _line =
    NoOp

main =
    Cli.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions, onLine = onLine
        }
"#;

/// A DOM attribute in a `Lines` view is IPE-T0001 (rejected at type-check), NOT
/// a silent render-time drop: the line-native `Attribute` type makes the DOM
/// constructor unnameable in the line surface. The diagnostic names the
/// user-facing `Cli.Ui.Attribute`, not the internal `CliAttr` spelling.
#[test]
fn lines_view_with_dom_attribute_is_rejected() -> Result<(), BoxError> {
    match compile("lines_dom_attr", LINES_WITH_DOM_ATTRIBUTE)? {
        Ok(()) => Err("lines_dom_attr: expected IPE-T0001, but ipec succeeded".into()),
        Err(ipe::CliError::Pipeline { diag, src, .. }) => {
            assert_eq!(diag.code().as_str(), "IPE-T0001", "wrong diagnostic code");
            let rendered = ipe_diagnostics::plain_message(&diag, &src);
            assert!(
                rendered.contains("Cli.Ui.Attribute"),
                "diagnostic must name the user-facing `Cli.Ui.Attribute`, got:\n{rendered}"
            );
            assert!(
                !rendered.contains("CliAttr"),
                "diagnostic must not leak the internal `CliAttr` spelling, got:\n{rendered}"
            );
            Ok(())
        }
        Err(other) => Err(format!("lines_dom_attr: expected IPE-T0001, got {other:?}").into()),
    }
}

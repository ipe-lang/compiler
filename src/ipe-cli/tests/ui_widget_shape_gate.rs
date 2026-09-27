//! The `CustomElement.node` shape-admissibility gate (IPE-L0147).
//!
//! `CustomElement.node : CustomElement down up -> down -> (up -> msg) -> Element msg`
//! mounts a server-driven browser custom element. Its up-event payload rides the
//! seal codec, which is compiled in only when a browser shape forces the runtime
//! `json` feature (the `Web` shape, served or webview-hosted). Under a
//! `Terminal` / `Program`
//! shape the widget has NO transport for its handler, so the node would be inert
//! and the emitted crate's non-`json` runtime fallback would leave the up-event
//! type parameter unconstrained (rustc E0282). The backend gate converts that
//! into a fail-closed `IPE-L0147` the moment `CustomElement.node` is emitted outside a
//! browser shape (SECURITY — fail closed, never a `cargo` failure and never a
//! panic).
//!
//! These tests are COMPILE-ONLY (they run the `ipe` pipeline + write the
//! project, but never invoke `cargo`), so they are fast and NOT gated on
//! `IPE_E2E`. The `customElement` constructor requires its JS source file to be
//! present at build time, so each fixture is written as a two-file project (the
//! `.ipe` entry plus its `js/*.js`) through [`compile_with_files`].

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Compile a `CustomElement.node` fixture as a two-file project (`Main.ipe` + a JS file
/// the `customElement` constructor references), returning the pipeline result.
/// The emitted project is written to a per-test temp dir; `cargo` is never
/// invoked.
fn compile_with_files(
    test_name: &str,
    source: &str,
    extra: &[(&str, &str)],
) -> Result<Result<(), ipe::CliError>, BoxError> {
    let ipe_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ui_widget_gate_{test_name}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(&ipe_dir)?;
    for (rel, contents) in extra {
        let path = ipe_dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, contents)?;
    }
    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, source)?;

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ui_widget_gate_{test_name}_out"));
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = ipe::resolve_runtime().map_err(|e| -> BoxError { format!("{e:?}").into() })?;
    Ok(ipe::build(&entry, &out_dir, &runtime))
}

/// Assert compilation succeeded (ipe-0).
fn assert_accepted(test_name: &str, source: &str, extra: &[(&str, &str)]) -> Result<(), BoxError> {
    match compile_with_files(test_name, source, extra)? {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("{test_name}: expected ipec success, got {e:?}").into()),
    }
}

/// The JS custom-element source the fixtures' `customElement` constructor points
/// at — its mere presence satisfies the build-time file-existence gate.
const WIDGET_JS: &str = "export function mount(host, emit) { return {}; }\n";

/// `CustomElement.node` inside a `Tui.tea` view — must be rejected. A Tui
/// view is `Screen Msg`; `CustomElement.node` returns `Element msg`, so the type checker
/// rejects the program (a browser custom element has no seam in a terminal
/// build, and no `Cells` denotation either).
const TERMINAL_UI_WIDGET: &str = r#"module Main exposing (main)

import Ipe.Tea.Tui as Tui
import Ipe.Ffi.Js.CustomElement as CustomElement
import Ipe.Ui.Cells exposing (Screen)
import Ipe.Tea.Terminal.Cmd
import Ipe.Tea.Terminal.Sub

type alias EditorState = { text : String, line : Int }

type EditorEvent = Changed String | Saved

type Msg = Edited EditorEvent

type alias Model = { state : EditorState }

codeEditor : CustomElement EditorState EditorEvent
codeEditor = CustomElement.fromFile "js/x.js"

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { state = { text = "", line = 0 } }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )

view : Model -> Screen Msg
view model =
    CustomElement.node codeEditor model.state Edited

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

type alias KeyEvent = { kind : String, value : String }

onKey : KeyEvent -> Msg
onKey _event =
    Edited Saved

main =
    Tui.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions, onKey = onKey
        }
"#;

/// `CustomElement.node` inside a `Web.tea` view — must be ACCEPTED (the browser shape has
/// the custom-element runtime and the seal codec).
const WEB_UI_WIDGET: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ffi.Js.CustomElement as CustomElement
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub

type alias EditorState = { text : String, line : Int }

type EditorEvent = Changed String | Saved

type Msg = Edited EditorEvent

type alias Model = { state : EditorState }

codeEditor : CustomElement EditorState EditorEvent
codeEditor = CustomElement.fromFile "js/x.js"

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { state = { text = "", line = 0 } }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )

view : Model -> Element Msg
view model =
    CustomElement.node codeEditor model.state Edited

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Edited Saved
        }
"#;

/// A `Tui.tea` view mounting `CustomElement.node` is a browser-only node in a
/// terminal build: rejected fail-closed at ipe time (not a cargo failure or a
/// panic). A Tui view is `Screen Msg` and `CustomElement.node` returns `Element msg`, so
/// the type checker rejects it (IPE-T0001); the `RejectInNonWebShape` shape gate
/// (IPE-L0147) is defense-in-depth for any path that bypasses type inference.
#[test]
fn terminal_view_with_ui_widget_is_rejected() -> Result<(), BoxError> {
    match compile_with_files(
        "terminal_ui_widget",
        TERMINAL_UI_WIDGET,
        &[("js/x.js", WIDGET_JS)],
    )? {
        Ok(()) => Err("terminal_ui_widget: expected a type error, but ipec succeeded".into()),
        Err(ipe::CliError::Pipeline { .. }) => Ok(()),
        Err(other) => {
            Err(format!("terminal_ui_widget: expected a type error, got {other:?}").into())
        }
    }
}

/// Non-regression control: `CustomElement.node` under `Web.tea` is the shape it belongs
/// to and must compile cleanly (ipe-0).
#[test]
fn web_view_with_ui_widget_is_accepted() -> Result<(), BoxError> {
    assert_accepted("web_ui_widget", WEB_UI_WIDGET, &[("js/x.js", WIDGET_JS)])
}

/// `Ui.widget` under a `Web.tea` view. The custom-element node's sole
/// user-facing surface is `CustomElement.node`; `Ipe.Ui` exposes no `widget`
/// member, so a program spelling `Ui.widget` fails to resolve (IPE-N0005)
/// rather than dispatching to the kernel behind a name the module never
/// exposes.
const WEB_OLD_UI_WIDGET_SURFACE: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui exposing (Element)
import Ipe.Ffi.Js.CustomElement as CustomElement

type alias EditorState = { text : String, line : Int }

type EditorEvent = Changed String | Saved

type Msg = Edited EditorEvent

type alias Model = { state : EditorState }

codeEditor : CustomElement EditorState EditorEvent
codeEditor = CustomElement.fromFile "js/x.js"

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { state = { text = "", line = 0 } }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )

view : Model -> Element Msg
view model =
    Ui.widget codeEditor model.state Edited

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        , routes = [], notFound = Edited Saved
        }
"#;

/// `Ui.widget` does not resolve: `Ipe.Ui` exposes no `widget` member, so the
/// program is rejected at name resolution (IPE-N0005). The same node reached
/// through `CustomElement.node` compiles cleanly
/// (`web_view_with_ui_widget_is_accepted`), pinning that the custom-element
/// node has exactly one user-facing surface.
#[test]
fn web_view_with_old_ui_widget_surface_is_rejected() -> Result<(), BoxError> {
    match compile_with_files(
        "web_old_ui_widget_surface",
        WEB_OLD_UI_WIDGET_SURFACE,
        &[("js/x.js", WIDGET_JS)],
    )? {
        Ok(()) => Err(
            "web_old_ui_widget_surface: expected IPE-N0005 (Ui has no member widget), but ipec succeeded"
                .into(),
        ),
        Err(ipe::CliError::Pipeline { .. }) => Ok(()),
        Err(other) => Err(format!(
            "web_old_ui_widget_surface: expected a resolution error, got {other:?}"
        )
        .into()),
    }
}

/// `CustomElement.node` inside a `Cli.tea` (Cli shape) view.
///
/// A Cli view has type `Model -> Lines msg`. `CustomElement.node` returns `Element msg`,
/// so the type checker rejects the program before the `RejectInNonWebShape`
/// shape gate is reached — the type mismatch is the primary rejection. The shape
/// gate is defense-in-depth for any hypothetical path that bypasses type
/// inference (e.g., programmatic IR construction in tests).
const CLI_UI_WIDGET: &str = r#"module Main exposing (main)

import Ipe.Tea.Cli as Cli
import Ipe.Ui.Cli exposing (Lines)
import Ipe.Ffi.Js.CustomElement as CustomElement

type alias EditorState = { text : String, line : Int }

type EditorEvent = Changed String | Saved

type Msg = Edited EditorEvent

type alias Model = { state : EditorState }

codeEditor : CustomElement EditorState EditorEvent
codeEditor = CustomElement.fromFile "js/x.js"

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { state = { text = "", line = 0 } }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )

view : Model -> Lines Msg
view model =
    CustomElement.node codeEditor model.state Edited

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

onLine : String -> Msg
onLine _line =
    Edited Saved

main =
    Cli.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions, onLine = onLine
        }
"#;

/// `CustomElement.node` in a `Cli.tea` view is rejected because `CustomElement.node`
/// returns `Element msg` but the Cli view expects `Lines msg`. The type checker
/// rejects it (IPE-T0001) before the `RejectInNonWebShape` shape gate fires.
/// The gate is defense-in-depth for any IR path that bypasses type inference.
#[test]
fn cli_view_with_ui_widget_is_rejected() -> Result<(), BoxError> {
    match compile_with_files("cli_ui_widget", CLI_UI_WIDGET, &[("js/x.js", WIDGET_JS)])? {
        Ok(()) => Err("cli_ui_widget: expected a type error, but ipec succeeded".into()),
        Err(ipe::CliError::Pipeline { .. }) => Ok(()),
        Err(other) => Err(format!("cli_ui_widget: expected a type error, got {other:?}").into()),
    }
}

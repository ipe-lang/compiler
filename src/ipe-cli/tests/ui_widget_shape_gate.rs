//! The custom-element placement gate (IPE-L0147).
//!
//! A `CustomElement.fromFile` handle names browser JS the build ships whether or
//! not a view mounts it, and only a Web build links the `web` runtime module that
//! serves it. The front gate inside `lower_program` therefore refuses every
//! constructor a non-Web program links (script, terminal app, worker), at the
//! constructor's span, before emit splices a registration the runtime cannot
//! link. Every consumer of the lowered program (`type-check`, `dev build`, the
//! LSP) reaches the refusal through that one query.
//!
//! These tests are COMPILE-ONLY (they run the `ipe` pipeline and write the
//! project, but never invoke `cargo`), so they are fast and NOT gated on
//! `IPE_E2E`. The constructor requires its JS source file to be present at build
//! time, so each fixture is written as a multi-file project (the `.ipe` modules
//! plus their `js/*.js`) through [`compile_with_files`].

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
    let fixture = ipe::RootFixture::main(source)
        .map_err(|e| -> BoxError { format!("{test_name}: fixture: {e}").into() })?;
    let src_dir = fixture.path().join("src");
    for (rel, contents) in extra {
        let path = src_dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, contents)?;
    }

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ui_widget_gate_{test_name}_out"));
    e2e_support::scratch::fresh(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();
    Ok(ipe::build_fixture(&fixture, &out_dir, &runtime).map(drop))
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
import Ipe.Tea.Tui.Sub

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
    Sub.onKey onKey

type alias KeyEvent = { kind : String, value : String }

onKey : KeyEvent -> Msg
onKey _event =
    Edited Saved

main =
    Tui.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
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
import Ipe.Tea.Cli.Sub as Sub
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
    Sub.onLine onLine

onLine : String -> Msg
onLine _line =
    Edited Saved

main =
    Cli.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
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

/// Assert the build refuses with IPE-L0147, framed against the file ending in
/// `file_suffix`, with the primary span starting at that file's
/// `CustomElement.fromFile` constructor.
fn assert_placement_refused(
    test_name: &str,
    source: &str,
    extra: &[(&str, &str)],
    file_suffix: &str,
) -> Result<(), BoxError> {
    match compile_with_files(test_name, source, extra)? {
        Ok(()) => Err(format!("{test_name}: expected IPE-L0147, but ipe accepted").into()),
        Err(ipe::CliError::Pipeline { file, src, diag }) => {
            let code = diag.code();
            if code.as_str() != "IPE-L0147" {
                return Err(
                    format!("{test_name}: expected IPE-L0147, got {code:?}: {diag:?}").into(),
                );
            }
            if !file.to_string_lossy().ends_with(file_suffix) {
                return Err(format!(
                    "{test_name}: expected the refusal framed against `{file_suffix}`, got {}",
                    file.display()
                )
                .into());
            }
            let lo = usize::try_from(diag.primary_span().lo)?;
            match src.get(lo..) {
                Some(rest) if rest.starts_with("CustomElement.fromFile") => Ok(()),
                rest => Err(format!(
                    "{test_name}: expected the span at the constructor, got {:?}",
                    rest.map(|r| r.chars().take(40).collect::<String>())
                )
                .into()),
            }
        }
        Err(other) => Err(format!("{test_name}: expected IPE-L0147, got {other:?}").into()),
    }
}

/// A script (`main : Task Error ()`) that constructs a handle and mounts it
/// nowhere. The constructor alone ships the JS, so it is refused even though no
/// view exists.
const SCRIPT_UNMOUNTED_WIDGET: &str = r#"module Main exposing (main)

import Ipe.Ffi.Js.CustomElement as CustomElement
import Ipe.Io as Io

editor : CustomElement String String
editor =
    CustomElement.fromFile "js/x.js"

main : Task Error ()
main =
    Io.println "hi"
"#;

/// A script with an unmounted constructor is refused at `dev build` with
/// IPE-L0147 at the constructor. The JS file is present, so the file-existence
/// gate passes and the placement gate is what refuses.
#[test]
fn script_with_unmounted_widget_is_refused_at_build() -> Result<(), BoxError> {
    assert_placement_refused(
        "script_unmounted_widget",
        SCRIPT_UNMOUNTED_WIDGET,
        &[("js/x.js", WIDGET_JS)],
        "Main.ipe",
    )
}

/// `ipe type-check` reaches the same refusal through `lower_program`: it exits
/// non-zero and its JSON diagnostic names IPE-L0147 at the constructor's line.
#[test]
fn script_with_unmounted_widget_is_refused_at_type_check() -> Result<(), BoxError> {
    let fixture = ipe::RootFixture::main(SCRIPT_UNMOUNTED_WIDGET)
        .map_err(|e| -> BoxError { format!("fixture: {e}").into() })?;
    let js = fixture.path().join("src/js/x.js");
    if let Some(parent) = js.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&js, WIDGET_JS)?;
    let out = std::process::Command::new(e2e_support::cargo_bin!("ipe"))
        .args(["type-check", "--json", "src/Main.ipe"])
        .current_dir(fixture.path())
        .env("NO_COLOR", "1")
        .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if out.status.success() {
        return Err(
            format!("type-check accepted a script that constructs a widget: {stderr}").into(),
        );
    }
    let line = SCRIPT_UNMOUNTED_WIDGET
        .lines()
        .position(|l| l.contains("CustomElement.fromFile"))
        .map(|i| i + 1)
        .ok_or("fixture has no constructor line")?;
    if stderr.contains("IPE-L0147") && stderr.contains(&format!("\"line\":{line}")) {
        Ok(())
    } else {
        Err(format!("expected IPE-L0147 at line {line}, got:\n{stderr}").into())
    }
}

/// A helper module with no `main` that only constructs a handle.
const WIDGETS_MODULE: &str = r#"module Widgets exposing (editor)

import Ipe.Ffi.Js.CustomElement as CustomElement

editor : CustomElement String String
editor =
    CustomElement.fromFile "js/x.js"
"#;

/// A `Tui.tea` entry that imports [`WIDGETS_MODULE`] and renders native cells.
const TUI_WITH_WIDGET_HELPER: &str = r#"module Main exposing (main)

import Ipe.Tea.Tui as Tui
import Ipe.Ui.Cells as Cells
import Ipe.Ui.Cells exposing (Screen)
import Ipe.Tea.Tui.Cmd
import Ipe.Tea.Tui.Sub
import Widgets

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
    Cells.text "hello"

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Tui.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        }
"#;

/// A `Cli.tea` entry that imports [`WIDGETS_MODULE`] and renders native lines.
const CLI_WITH_WIDGET_HELPER: &str = r#"module Main exposing (main)

import Ipe.Tea.Cli as Cli
import Ipe.Tea.Cli.Cmd
import Ipe.Tea.Cli.Sub
import Ipe.Ui.Cli as Ui
import Ipe.Ui.Cli exposing (Lines)
import Widgets

type Msg = NoOp

type alias Model = { count : Int }

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )

view : Model -> Lines Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Cli.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        }
"#;

/// A view-less `Worker.tea` entry that imports [`WIDGETS_MODULE`].
const WORKER_WITH_WIDGET_HELPER: &str = r"module Main exposing (main)

import Ipe.Tea.Worker as Worker
import Ipe.Tea.Worker.Cmd
import Ipe.Tea.Worker.Sub
import Widgets

type Msg = NoOp

type alias Model = { ticks : Int }

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { ticks = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Worker.tea { init = init, update = update, subscriptions = subscriptions }
";

/// A terminal app, a line app and a worker each refuse a constructor that lives
/// in an imported helper module and is never used: the gate judges the whole
/// linked set the build ships, and frames the refusal against the helper.
#[test]
fn non_web_entries_refuse_a_widget_in_a_helper_module() -> Result<(), BoxError> {
    for (name, entry) in [
        ("tui_widget_helper", TUI_WITH_WIDGET_HELPER),
        ("cli_widget_helper", CLI_WITH_WIDGET_HELPER),
        ("worker_widget_helper", WORKER_WITH_WIDGET_HELPER),
    ] {
        assert_placement_refused(
            name,
            entry,
            &[("Widgets.ipe", WIDGETS_MODULE), ("js/x.js", WIDGET_JS)],
            "Widgets.ipe",
        )?;
    }
    Ok(())
}

/// A script whose `main` is a server that mounts a `Web.embed` app, and whose
/// embedded view mounts a custom element. The mounted app is a browser page the
/// `web` runtime serves, widget assets included, so the script shape alone is
/// no reason to refuse it.
const SCRIPT_EMBEDDED_APP_WIDGET: &str = r#"module Main exposing (main)

import Ipe.Ffi.Js.CustomElement as CustomElement
import Ipe.Server.Http as Server
import Ipe.Task as Task exposing (Task)
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui exposing (Element)

type Msg = Edited String | NoOp

type alias Model = { text : String }

editor : CustomElement String String
editor = CustomElement.fromFile "js/x.js"

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _req =
    ( { text = "" }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        Edited text ->
            ( { model | text = text }, Cmd.none )

        NoOp ->
            ( model, Cmd.none )

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Sub.none

view : Model -> Element Msg
view model =
    CustomElement.node editor model.text Edited

editorApp : Web.WebApp
editorApp =
    Web.embed
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = NoOp
        }

main : Task Error ()
main =
    Server.listen 8000 [ Server.mountApp "/" editorApp ]
"#;

/// A script that mounts a `Web.embed` app serves a browser page through the
/// linked `web` runtime, so a custom element in its view is accepted: the gate
/// judges whether the program links the `web` runtime, not the entry's shape.
#[test]
fn script_mounting_an_embedded_web_app_accepts_its_widget() -> Result<(), BoxError> {
    assert_accepted(
        "script_embedded_app_widget",
        SCRIPT_EMBEDDED_APP_WIDGET,
        &[("js/x.js", WIDGET_JS)],
    )
}

/// A server script that mounts no web app: it serves HTTP but no browser page.
const SCRIPT_SERVER_WIDGET_NO_APP: &str = r#"module Main exposing (main)

import Ipe.Ffi.Js.CustomElement as CustomElement
import Ipe.Server.Http as Server
import Ipe.Task as Task exposing (Task)

editor : CustomElement String String
editor = CustomElement.fromFile "js/x.js"

health : Server.Request -> Task Error Server.Response
health _req =
    Task.succeed (Server.json "{}")

main : Task Error ()
main =
    Server.listen 8000 [ Server.get "/health" health ]
"#;

/// A server script that mounts no web app links no `web` runtime, so its
/// constructor is refused like any other script's: serving HTTP is not serving
/// a browser page.
#[test]
fn script_server_without_a_web_app_refuses_its_widget() -> Result<(), BoxError> {
    assert_placement_refused(
        "script_server_widget_no_app",
        SCRIPT_SERVER_WIDGET_NO_APP,
        &[("js/x.js", WIDGET_JS)],
        "Main.ipe",
    )
}

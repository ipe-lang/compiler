#![forbid(unsafe_code)]
//! The split (multi-home) emit applies every emit setting.
//!
//! A program with two or more homes is assembled by `emit_manifest` from the
//! spine and the per-module file queries. Each of those producers must render
//! with the same settings the single-file emit uses, so a setting that reaches
//! only one of them would make a split build diverge from a single-file one.

use ipe_backend_rust::{
    BuildIntent, CrateName, DbDriver, EmitHost, EmitSettings, MountBase, RuntimeDep, WebViewWindow,
};
use ipe_db::{BuildConfig, IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};

const LIB: &str = "module Lib exposing (label)\n\nlabel : String\nlabel = \"ok\"\n";

const CLI_MAIN: &str = r"module Main exposing (main)

import Lib exposing (label)
import Ipe.Tea.Cli as Cli
import Ipe.Tea.Cli.Cmd
import Ipe.Tea.Cli.Sub
import Ipe.Ui.Cli as Ui
import Ipe.Ui.Cli exposing (Lines)

type Msg = Line String

type alias Model = { lines : List String }

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { lines = [] }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )

view : Model -> Lines Msg
view _model =
    Ui.text label

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.onLine Line

main =
    Cli.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        }
";

const WEB_MAIN: &str = r"module Main exposing (main)

import Lib exposing (label)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub

type Msg
    = Increment

type alias Model =
    { count : Int }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( { model | count = model.count + 1 }, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.el [ Ui.onClick Increment ] (Ui.text label)

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = Increment
        }
";

/// The runtime path every session codec is rendered under.
const SESSION_CODEC: &str = "ipe_runtime::debugger::session_log::";

/// The opening of the console app entry call.
const CONSOLE_APP: &str = "ipe_runtime::console_app(";

fn file(db: &IpeDatabase, path: &[&str], text: &str) -> SourceFile {
    SourceFile::new(
        db,
        path.iter().map(|s| (*s).to_owned()).collect(),
        text.to_owned(),
        ModuleOrigin::User,
    )
}

/// A source root of `Lib`, `Main`, and the compiled-source stdlib closure
/// `Main` imports, each stdlib file under the driver-vouched origin.
fn split_root(db: &IpeDatabase, lib: SourceFile, main: SourceFile) -> SourceRoot {
    use std::collections::{BTreeMap, VecDeque};

    let mut files: BTreeMap<Vec<String>, SourceFile> = BTreeMap::new();
    files.insert(vec!["Lib".to_owned()], lib);
    files.insert(vec!["Main".to_owned()], main);
    let mut work: VecDeque<Vec<String>> = ipe_db::extract_imports_from_source(main.text(db))
        .into_iter()
        .filter(|imp| ipe_stdlib::is_compiled_source_segments(imp))
        .collect();
    while let Some(path) = work.pop_front() {
        if files.contains_key(&path) {
            continue;
        }
        let Some(source) = ipe_stdlib::compiled_std_source_segments(&path) else {
            continue;
        };
        let sf = SourceFile::new(
            db,
            path.clone(),
            source.to_owned(),
            ModuleOrigin::EmbeddedStdlib,
        );
        files.insert(path, sf);
        for imp in ipe_db::extract_imports_from_source(source) {
            if ipe_stdlib::is_compiled_source_segments(&imp) && !files.contains_key(&imp) {
                work.push_back(imp);
            }
        }
    }
    SourceRoot::new(db, files)
}

/// Dependency-model settings: the debugger module lives only in the linked
/// runtime crate, so both the plain and the debugger build link one.
fn settings(debugger: bool, host: EmitHost) -> EmitSettings {
    EmitSettings {
        db_driver: DbDriver::Sqlite,
        ffi: None,
        target: ipe_ir::Target::Native,
        wasm_public_env: Vec::new(),
        mount_base: MountBase::root(),
        server_origins: ipe_backend_rust::ServerOrigins::none(),
        wasm_hydrate_mode: false,
        runtime_dep: Some(RuntimeDep {
            root: std::path::PathBuf::from("/ipe-runtime"),
        }),
        debugger,
        crate_name: CrateName::SingleFile,
        hot_appearance: false,
        host,
        intent: BuildIntent::Development,
    }
}

/// Every emitted file of the split program `Main` + `Lib` under `settings`,
/// after asserting the program really has more than one home.
#[allow(clippy::expect_used)] // a test helper: a failed emit is the failure under test
fn split_files(main_src: &str, settings: EmitSettings) -> Vec<String> {
    let db = IpeDatabase::new();
    let lib = file(&db, &["Lib"], LIB);
    let main = file(&db, &["Main"], main_src);
    let root = split_root(&db, lib, main);
    let homes = ipe_db::program_rust_file_ids(&db, root, main)
        .clone()
        .expect("the program lowers");
    assert!(
        homes.len() > 1,
        "the program has {} home, not a split",
        homes.len()
    );
    let config = BuildConfig::new(&db, settings);
    let project = ipe_db::emit_manifest(&db, root, main, config)
        .clone()
        .expect("the split program emits");
    project.files.values().cloned().collect()
}

/// The console app entry call in `files`, through its closing parentheses.
fn console_call(files: &[String]) -> Option<String> {
    files.iter().find_map(|text| {
        let start = text.find(CONSOLE_APP)?;
        let rest = text.get(start..)?;
        let end = rest.find("))")?;
        rest.get(..end).map(str::to_owned)
    })
}

/// A `debugger` build of a split console program passes the session codec to
/// `console_app`, exactly as the single-file emit does, so the call matches the
/// runtime's `debugger` arity.
#[test]
#[allow(clippy::expect_used)]
fn split_debugger_module_passes_codec() {
    let plain = console_call(&split_files(CLI_MAIN, settings(false, EmitHost::Served)))
        .expect("the plain build calls console_app");
    let debug = console_call(&split_files(CLI_MAIN, settings(true, EmitHost::Served)))
        .expect("the debugger build calls console_app");
    assert!(
        !plain.contains(SESSION_CODEC),
        "a plain build passed a codec: {plain}"
    );
    let codec = debug
        .strip_prefix(plain.as_str())
        .and_then(|tail| tail.strip_prefix(", "))
        .expect("the debugger call is the plain call plus one trailing argument");
    assert!(
        codec.starts_with(SESSION_CODEC),
        "the trailing argument is not a session codec: {codec}"
    );
}

/// A split web program under the webview host builds `ipe_main` as the
/// `WebViewApp`, sized and titled by the window the settings carry.
#[test]
fn split_webview_uses_window() {
    let host = EmitHost::WebView(WebViewWindow {
        title: "Split".to_owned(),
        width: 320,
        height: 240,
    });
    let files = split_files(WEB_MAIN, settings(false, host));
    assert!(
        files
            .iter()
            .any(|text| text.contains("fn ipe_main() -> ipe_runtime::tea::WebViewApp")),
        "ipe_main is not the webview app"
    );
    assert!(
        files.iter().any(|text| text.contains(
            "ipe_runtime::webview::WebViewWindowCfg { title: \"Split\".to_string(), size: (320, 240) }"
        )),
        "the webview app does not carry the settings' window"
    );
    assert!(
        files
            .iter()
            .all(|text| !text.contains("ipe_runtime::tea::WebApp(")),
        "the served web app was emitted beside the webview app"
    );
}

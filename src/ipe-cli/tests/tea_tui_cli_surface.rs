//! Compile-time surface tests for `Ipe.Tea.Tui` and `Ipe.Tea.Cli`.
//!
//! `Ipe.Tea.Tui` exposes the full-screen terminal TEA entry via `Tui.tea`;
//! `Ipe.Tea.Cli` exposes the line-oriented entry via `Cli.tea`. Both `app`
//! entries are registered in the `env.rs` qualifier catalog and carry
//! `KernelClass::Terminal` (the one terminal rendering family).
//!
//! Terminal input is a subscription (`Tui.Sub.onKey` / `Cli.Sub.onLine`); the
//! refusals below pin that a stale `onKey` / `onLine` config field and a
//! wrong-surface input subscription are both rejected at `ipe` time.
//!
//! The `ipe` half of every test runs in CI without `IPE_E2E`. The `seal_*`
//! tests additionally `cargo build` the emitted project under `IPE_E2E=1`, so
//! every accepted input-subscription shape (point-free, let-bound, lambda,
//! constructor, helper module) is proven to build, not just to be accepted.

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

fn compile(test_name: &str, source: &str) -> Result<Result<(), ipe::CliError>, BoxError> {
    compile_files(test_name, &[("Main.ipe", source)])
}

/// Compile a multi-module program whose entry is `Main.ipe`.
///
/// Every `(file name, source)` is written beside the entry.
fn compile_files(
    test_name: &str,
    files: &[(&str, &str)],
) -> Result<Result<(), ipe::CliError>, BoxError> {
    let ipe_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("tea_surface_{test_name}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(&ipe_dir)?;
    for (name, source) in files {
        std::fs::write(ipe_dir.join(name), source)?;
    }
    let entry = ipe_dir.join("Main.ipe");

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("tea_surface_{test_name}_out"));
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();
    Ok(ipe::build_loose_file(&entry, &out_dir, &runtime))
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
    Sub.onKey onKey

onKey : KeyEvent -> Msg
onKey _event =
    NoOp

main =
    Tui.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
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
    Sub.onLine onLine

onLine : String -> Msg
onLine s =
    Line s

main =
    Cli.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
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

// ── Terminal input is a subscription ────────────────────────────────────────

/// The four-field config closing lines shared by `TUI_APP` and `CLI_APP`.
///
/// The two `…_WITH_…` variants still carry an input config field.
const CFG_TAIL: &str = "        , subscriptions = subscriptions\n        }";
const CFG_TAIL_WITH_ON_KEY: &str =
    "        , subscriptions = subscriptions, onKey = onKey\n        }";
const CFG_TAIL_WITH_ON_LINE: &str =
    "        , subscriptions = subscriptions, onLine = onLine\n        }";

/// `source` with `from` replaced by `to`, failing if `from` is absent.
///
/// A fixture drift then cannot silently turn a refusal test into an acceptance
/// one.
fn variant(source: &str, from: &str, to: &str) -> Result<String, BoxError> {
    if source.contains(from) {
        Ok(source.replace(from, to))
    } else {
        Err(format!("fixture does not contain {from:?}").into())
    }
}

/// Assert `source` is REJECTED by the pipeline for any reason (never exit-0).
fn assert_rejected(test_name: &str, source: &str) -> Result<(), BoxError> {
    match compile(test_name, source)? {
        Ok(()) => Err(format!("{test_name}: expected rejection, but ipe accepted").into()),
        Err(_) => Ok(()),
    }
}

/// A `Tui.tea` config still passing `onKey` is refused with IPE-N0052.
///
/// Never silently accepted with key input dropped.
#[test]
fn tui_on_key_config_field_is_rejected() -> Result<(), BoxError> {
    let src = variant(TUI_APP, CFG_TAIL, CFG_TAIL_WITH_ON_KEY)?;
    assert_rejected_code("tui_on_key_field", &src, "IPE-N0052")
}

/// A `Cli.tea` config still passing `onLine` is refused with IPE-N0052.
#[test]
fn cli_on_line_config_field_is_rejected() -> Result<(), BoxError> {
    let src = variant(CLI_APP, CFG_TAIL, CFG_TAIL_WITH_ON_LINE)?;
    assert_rejected_code("cli_on_line_field", &src, "IPE-N0052")
}

/// A config bound to a top-level name is checked too.
#[test]
fn cli_on_line_in_top_level_config_is_rejected() -> Result<(), BoxError> {
    let src = variant(
        CLI_APP,
        "main =\n    Cli.tea\n        { init = init, update = update, view = view\n        , subscriptions = subscriptions\n        }",
        "cfg =\n    { init = init, update = update, view = view\n    , subscriptions = subscriptions, onLine = onLine\n    }\n\nmain =\n    Cli.tea cfg",
    )?;
    assert_rejected_code("cli_on_line_top_level_cfg", &src, "IPE-N0052")
}

/// The config rows are closed, so an extra field is refused.
///
/// Never absorbed and ignored.
#[test]
fn unknown_terminal_config_field_is_rejected() -> Result<(), BoxError> {
    let tui = variant(
        TUI_APP,
        CFG_TAIL,
        "        , subscriptions = subscriptions, extra = 1\n        }",
    )?;
    assert_rejected("tui_extra_field", &tui)?;
    // The other surface's input field is just as foreign to this entry.
    let cli = variant(
        CLI_APP,
        CFG_TAIL,
        "        , subscriptions = subscriptions, onKey = onLine\n        }",
    )?;
    assert_rejected("cli_on_key_field", &cli)
}

/// `Tui.Sub.onKey` in a `Cli` app is refused with IPE-N0035.
///
/// A line app has no key stream.
#[test]
fn tui_sub_in_cli_app_is_rejected() -> Result<(), BoxError> {
    let src = variant(CLI_APP, "import Ipe.Tea.Cli.Sub", "import Ipe.Tea.Tui.Sub")?;
    let src = variant(&src, "Sub.onLine onLine", "Sub.onKey (\\_ -> NoOp)")?;
    assert_rejected_code("tui_sub_in_cli", &src, "IPE-N0035")
}

/// `Cli.Sub.onLine` in a `Tui` app is refused with IPE-N0035.
///
/// A full-screen app has no line stream.
#[test]
fn cli_sub_in_tui_app_is_rejected() -> Result<(), BoxError> {
    let src = variant(TUI_APP, "import Ipe.Tea.Tui.Sub", "import Ipe.Tea.Cli.Sub")?;
    let src = variant(&src, "Sub.onKey onKey", "Sub.onLine (\\_ -> NoOp)")?;
    assert_rejected_code("cli_sub_in_tui", &src, "IPE-N0035")
}

/// The shared `Ipe.Tea.Terminal.Sub` carries no input subscription.
///
/// Naming `onKey` through it under its own alias is an unknown member. Under
/// the bare `Sub` spelling it merges into the shape's own `Sub`, which does
/// carry `onKey`.
#[test]
fn terminal_sub_has_no_input_subscription() -> Result<(), BoxError> {
    let src = variant(
        TUI_APP,
        "import Ipe.Tea.Tui.Sub",
        "import Ipe.Tea.Tui.Sub\nimport Ipe.Tea.Terminal.Sub as TermSub",
    )?;
    let src = variant(&src, "Sub.onKey onKey", "TermSub.onKey onKey")?;
    assert_rejected_code("terminal_sub_on_key", &src, "IPE-N0005")
}

/// Any handler expression is accepted.
///
/// Covers a lambda, and a key subscription combined with a timer through
/// `Sub.batch`.
#[test]
fn tui_on_key_accepts_any_handler_form() -> Result<(), BoxError> {
    let lambda = variant(TUI_APP, "Sub.onKey onKey", "Sub.onKey (\\_ -> NoOp)")?;
    assert_accepted("tui_on_key_lambda", &lambda)?;
    let batched = variant(
        TUI_APP,
        "Sub.onKey onKey",
        "Sub.batch [ Sub.onKey onKey, Sub.every 1000 NoOp ]",
    )?;
    assert_accepted("tui_on_key_batched", &batched)
}

/// `Cli.Sub.onLine` accepts a constructor directly as its handler.
#[test]
fn cli_on_line_accepts_a_constructor_handler() -> Result<(), BoxError> {
    let src = variant(CLI_APP, "Sub.onLine onLine", "Sub.onLine Line")?;
    assert_accepted("cli_on_line_ctor", &src)
}

/// A helper module's `Tui.Sub.onKey` in a `Cli` app is refused with IPE-N0035.
///
/// The helper is not the entry, so the entry-module import gate never sees it;
/// the lowerer's surface gate refuses the reference itself, so it never
/// compiles into a key subscription the line loop would silently never read.
#[test]
fn tui_sub_from_a_helper_module_in_a_cli_app_is_rejected() -> Result<(), BoxError> {
    let main = variant(
        CLI_APP,
        "import Ipe.Tea.Cli as Cli\n",
        "import Ipe.Tea.Cli as Cli\nimport Keys\n",
    )?;
    let main = variant(&main, "Sub.onLine onLine", "Keys.keys NoOp")?;
    let keys = "module Keys exposing (keys)\n\n\
                import Ipe.Tea.Tui.Sub as Sub\n\n\n\
                keys msg =\n    Sub.onKey (\\_ -> msg)\n";
    let outcome = compile_files(
        "tui_sub_helper_in_cli",
        &[("Main.ipe", main.as_str()), ("Keys.ipe", keys)],
    )?;
    match outcome {
        Ok(()) => Err("tui_sub_helper_in_cli: expected rejection, but ipe accepted".into()),
        Err(ipe::CliError::Pipeline { diag, .. }) if diag.code().as_str() == "IPE-N0035" => Ok(()),
        Err(other) => {
            Err(format!("tui_sub_helper_in_cli: expected IPE-N0035, got {other:?}").into())
        }
    }
}

/// The emitted Ipê-side Rust of a compiled test program (`main.rs` + `ipe_mods`).
fn emitted_rust(test_name: &str) -> String {
    let src = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("tea_surface_{test_name}_out"))
        .join("src");
    let mut combined = std::fs::read_to_string(src.join("main.rs")).unwrap_or_default();
    if let Ok(entries) = std::fs::read_dir(src.join("ipe_mods")) {
        let mut files: Vec<std::path::PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "rs"))
            .collect();
        files.sort();
        for path in files {
            if let Ok(text) = std::fs::read_to_string(&path) {
                combined.push('\n');
                combined.push_str(&text);
            }
        }
    }
    combined
}

/// A point-free `Sub.onKey` still emits through the `KeyEvent` bridge.
///
/// `List.map Sub.onKey handlers` reifies the kernel as a first-class value;
/// the lowerer eta-expands it so the saturated emit arm (and its bridge) fires,
/// instead of boxing the bare runtime function (a `cargo` E0277).
#[test]
fn point_free_tui_on_key_emits_the_bridge() -> Result<(), BoxError> {
    let src = variant(
        TUI_APP,
        "import Ipe.Tea.Tui as Tui\n",
        "import Ipe.Tea.Tui as Tui\nimport Ipe.List as List\n",
    )?;
    let src = variant(
        &src,
        "Sub.onKey onKey",
        "Sub.batch (List.map Sub.onKey [ onKey, onKey ])",
    )?;
    assert_accepted("point_free_on_key", &src)?;
    let emitted: String = emitted_rust("point_free_on_key")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if emitted.is_empty() {
        return Err("point_free_on_key: the accepted build emitted no Rust".into());
    }
    if !emitted.contains("tui_sub_on_key(") || !emitted.contains("|kind: String, value: String|") {
        return Err(
            format!("point-free Sub.onKey must emit the KeyEvent bridge; got:\n{emitted}").into(),
        );
    }
    if emitted.contains("Box::new(tui_sub_on_key)") {
        return Err("point-free Sub.onKey must never be boxed as a bare function value".into());
    }
    Ok(())
}

/// A let-bound `Sub.onKey` is eta-expanded the same way and accepted.
#[test]
fn let_bound_tui_on_key_is_accepted() -> Result<(), BoxError> {
    let src = variant(
        TUI_APP,
        "Sub.onKey onKey",
        "let\n        on =\n            Sub.onKey\n    in\n    on onKey",
    )?;
    assert_accepted("let_bound_on_key", &src)
}

/// A point-free `Cli.Sub.onLine` in a helper module of a `Tui` app is refused with IPE-N0035.
///
/// The surface gate checks the reference itself, so the point-free form cannot
/// route around it into a line subscription the key loop never reads.
#[test]
fn point_free_cli_sub_from_a_helper_module_in_a_tui_app_is_rejected() -> Result<(), BoxError> {
    let main = variant(
        TUI_APP,
        "import Ipe.Tea.Tui as Tui\n",
        "import Ipe.Tea.Tui as Tui\nimport Lines\n",
    )?;
    let main = variant(&main, "Sub.onKey onKey", "Lines.lines (\\_ -> NoOp)")?;
    let lines = "module Lines exposing (lines)\n\n\
                 import Ipe.Tea.Cli.Sub as Sub\n\n\n\
                 lines =\n    Sub.onLine\n";
    assert_rejected_files_code(
        "cli_sub_point_free_helper_in_tui",
        &[("Main.ipe", main.as_str()), ("Lines.ipe", lines)],
        "IPE-N0035",
    )
}

/// A stray `Tui.tea` in a helper module does not widen a `Cli` app to key input.
///
/// The surface is read from the entry's own `main`, never from an app entry
/// that merely appears in another module.
#[test]
fn a_stray_tui_entry_in_a_helper_does_not_widen_a_cli_app() -> Result<(), BoxError> {
    let main = variant(
        CLI_APP,
        "import Ipe.Tea.Cli as Cli\n",
        "import Ipe.Tea.Cli as Cli\nimport Keys\n",
    )?;
    let main = variant(&main, "Sub.onLine onLine", "Keys.keys NoOp")?;
    let keys = "module Keys exposing (keys, stray)\n\n\
                import Ipe.Tea.Tui as Tui\n\
                import Ipe.Tea.Tui.Cmd as Cmd\n\
                import Ipe.Tea.Tui.Sub as Sub\n\
                import Ipe.Ui.Cells as Cells\n\n\n\
                keys msg =\n    Sub.onKey (\\_ -> msg)\n\n\n\
                stray =\n    Tui.tea\n        { init = \\_ -> ( 0, Cmd.none )\n        \
                , update = \\_ m -> ( m, Cmd.none )\n        \
                , view = \\_ -> Cells.text \"x\"\n        \
                , subscriptions = \\_ -> Sub.none\n        }\n";
    assert_rejected_files_code(
        "stray_tui_helper_in_cli",
        &[("Main.ipe", main.as_str()), ("Keys.ipe", keys)],
        "IPE-N0035",
    )
}

/// Assert a multi-module program is REJECTED with exactly `expected`.
fn assert_rejected_files_code(
    test_name: &str,
    files: &[(&str, &str)],
    expected: &str,
) -> Result<(), BoxError> {
    match compile_files(test_name, files)? {
        Ok(()) => Err(format!("{test_name}: expected {expected}, but ipe accepted").into()),
        Err(ipe::CliError::Pipeline { diag, .. }) if diag.code().as_str() == expected => Ok(()),
        Err(other) => Err(format!("{test_name}: expected {expected}, got {other:?}").into()),
    }
}

// ── SEAL: every accepted input-subscription shape cargo-builds ──────────────

/// Compile `files` with `ipe`, then under `IPE_E2E` `cargo build` the emitted project.
///
/// The build is the SEAL: an input-subscription shape `ipe` accepts must also
/// build, so a point-free, let-bound, or helper-module reference can never
/// exit 0 and then fail `cargo` on the bridge closure's `Send + 'static` bound.
/// Without `IPE_E2E` only the `ipe` half runs.
fn assert_builds_files(test_name: &str, files: &[(&str, &str)]) -> Result<(), BoxError> {
    if let Err(e) = compile_files(test_name, files)? {
        return Err(format!("{test_name}: expected ipe success, got {e:?}").into());
    }
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("tea_surface_{test_name}_out"));
    e2e_support::build_rust_binary(test_name, &out_dir)
        .map(|_| ())
        .map_err(|e| -> BoxError {
            format!("{test_name}: ipe accepted but cargo build failed: {e}").into()
        })
}

/// [`assert_builds_files`] for a single-module program.
fn assert_builds(test_name: &str, source: &str) -> Result<(), BoxError> {
    assert_builds_files(test_name, &[("Main.ipe", source)])
}

/// `TUI_APP` with `Ipe.List` imported and its subscription body replaced by `subs`.
fn tui_subscribing(subs: &str) -> Result<String, BoxError> {
    let src = variant(
        TUI_APP,
        "import Ipe.Tea.Tui as Tui\n",
        "import Ipe.Tea.Tui as Tui\nimport Ipe.List as List\n",
    )?;
    variant(&src, "Sub.onKey onKey", subs)
}

/// `CLI_APP` with `Ipe.List` imported and its subscription body replaced by `subs`.
fn cli_subscribing(subs: &str) -> Result<String, BoxError> {
    let src = variant(
        CLI_APP,
        "import Ipe.Tea.Cli as Cli\n",
        "import Ipe.Tea.Cli as Cli\nimport Ipe.List as List\n",
    )?;
    variant(&src, "Sub.onLine onLine", subs)
}

/// `Sub.onKey` mapped point-free over a handler list builds.
#[test]
fn seal_tui_on_key_point_free_in_list_map_builds() -> Result<(), BoxError> {
    let src = tui_subscribing("Sub.batch (List.map Sub.onKey [ onKey, onKey ])")?;
    assert_builds("seal_tui_list_map", &src)
}

/// A let-bound `Sub.onKey` applied later builds.
#[test]
fn seal_tui_on_key_let_bound_builds() -> Result<(), BoxError> {
    let src = tui_subscribing("let\n        on =\n            Sub.onKey\n    in\n    on onKey")?;
    assert_builds("seal_tui_let_bound", &src)
}

/// `Sub.onKey` with a lambda handler builds.
#[test]
fn seal_tui_on_key_lambda_handler_builds() -> Result<(), BoxError> {
    let src = tui_subscribing("Sub.onKey (\\_ -> NoOp)")?;
    assert_builds("seal_tui_lambda", &src)
}

/// `Cli.Sub.onLine` mapped point-free over a handler list builds.
#[test]
fn seal_cli_on_line_point_free_in_list_map_builds() -> Result<(), BoxError> {
    let src = cli_subscribing("Sub.batch (List.map Sub.onLine [ onLine, Line ])")?;
    assert_builds("seal_cli_list_map", &src)
}

/// `Cli.Sub.onLine` mapped through an explicit lambda over a handler list builds:
/// the lambda's element binder rides the list's `Arc<dyn Fn>` carrier, and its
/// value read into `onLine` is re-dispatched rather than passed raw.
#[test]
fn seal_cli_on_line_lambda_in_list_map_builds() -> Result<(), BoxError> {
    let src = cli_subscribing("Sub.batch (List.map (\\h -> Sub.onLine h) [ onLine, Line ])")?;
    assert_builds("seal_cli_lambda_list_map", &src)
}

/// `Tui.Sub.onKey` mapped through an explicit lambda over a handler list builds.
#[test]
fn seal_tui_on_key_lambda_in_list_map_builds() -> Result<(), BoxError> {
    let src = tui_subscribing("Sub.batch (List.map (\\h -> Sub.onKey h) [ onKey, onKey ])")?;
    assert_builds("seal_tui_lambda_list_map", &src)
}

/// A stored predicate read out of a `List` of functions and passed to the
/// `impl Fn` parameter of `List.filter` builds — the same `Arc<dyn Fn>`-into-
/// `Fn`-bound class as `onLine`, on a non-subscription kernel.
#[test]
fn seal_stored_fn_element_into_impl_fn_kernel_builds() -> Result<(), BoxError> {
    let src = variant(
        CLI_APP,
        "( { model | lines = model.lines ++ [ s ] }, Cmd.none )",
        "( { model | lines = model.lines ++ List.concat (List.map (\\keep -> List.filter keep [ s ]) [ \\t -> t /= \"\", \\t -> t /= \"x\" ]) }, Cmd.none )",
    )?;
    let src = variant(
        &src,
        "import Ipe.Tea.Cli as Cli\n",
        "import Ipe.Tea.Cli as Cli\nimport Ipe.List as List\n",
    )?;
    assert_builds("seal_stored_fn_impl_fn_kernel", &src)
}

/// The emitted adaptation for a point-free `onLine` over a stored handler list
/// is pinned without `IPE_E2E`: the handler reaches `cli_sub_on_line` through
/// the line-handler bridge, and the bridge never binds the mapper's raw
/// `Arc<dyn Fn>` element parameter (`eta_N`) — the lowerer re-dispatches that
/// value read through a fresh closure first.
#[test]
fn cli_on_line_point_free_in_list_map_emits_adapted_handler() -> Result<(), BoxError> {
    const BRIDGE: &str = "cli_sub_on_line({ let __ipe_on_line = ";
    let name = "emit_cli_list_map";
    let src = cli_subscribing("Sub.batch (List.map Sub.onLine [ onLine, Line ])")?;
    if let Err(e) = compile(name, &src)? {
        return Err(format!("{name}: expected ipe success, got {e:?}").into());
    }
    let rust = emitted_rust(name);
    if !rust.contains(BRIDGE) {
        return Err(format!("{name}: `onLine` handler not bridged:\n{rust}").into());
    }
    for (at, _) in rust.match_indices(BRIDGE) {
        let bound = rust.get(at + BRIDGE.len()..).unwrap_or_default();
        let raw_eta = bound.strip_prefix("eta_").is_some_and(|rest| {
            let digits = rest.chars().take_while(char::is_ascii_digit).count();
            digits > 0 && rest.get(digits..).is_some_and(|tail| tail.starts_with(';'))
        });
        if raw_eta {
            return Err(format!(
                "{name}: the raw `Arc<dyn Fn>` element param reaches `cli_sub_on_line`:\n{rust}"
            )
            .into());
        }
    }
    Ok(())
}

// ── Mapper parameters bound to stored function elements ─────────────────────
//
// Each program feeds a collection of functions (stored on the `Arc` carrier) to
// a higher-order kernel whose mapper closure reads the element parameter as a
// VALUE (a non-callee read), so the parameter must ride the `Arc` carrier and
// the read must be re-dispatched into the `Fn`-bound position it reaches.

/// The stored predicates the fixtures below map over.
const STORED_PREDICATES: &str = r#"[ \t -> t /= "", \t -> t /= "x" ]"#;

/// `CLI_APP` with `imports` added and its `Line s` branch appending `appended`
/// (a `List String`) instead of `[ s ]`.
fn cli_appending(imports: &str, appended: &str) -> Result<String, BoxError> {
    let src = variant(
        CLI_APP,
        "( { model | lines = model.lines ++ [ s ] }, Cmd.none )",
        &format!("( {{ model | lines = model.lines ++ {appended} }}, Cmd.none )"),
    )?;
    variant(
        &src,
        "import Ipe.Tea.Cli as Cli\n",
        &format!("import Ipe.Tea.Cli as Cli\n{imports}"),
    )
}

/// `List.map2` over a stored handler list: each list binds its own mapper
/// parameter, and the handler list's parameter is read as a value.
fn map2_handlers() -> Result<String, BoxError> {
    cli_subscribing("Sub.batch (List.map2 (\\f _n -> Sub.onLine f) [ onLine, Line ] [ 1, 2 ])")
}

/// `List.map2` PARTIALLY applied to its mapper, the stored handler list
/// supplied later through the residual closure: the eta-expanded partial must
/// re-carrier the mapper exactly as the saturated call does.
fn partial_map2_handlers() -> Result<String, BoxError> {
    cli_subscribing(
        "let\n        pair =\n            List.map2 (\\f _n -> Sub.onLine f)\n    in\n    Sub.batch (pair [ onLine, Line ] [ 1, 2 ])",
    )
}

/// `List.sortBy` over stored predicates, its key reading the predicate as a
/// value into the `impl Fn` parameter of `List.filter`.
fn sort_by_predicates() -> Result<String, BoxError> {
    cli_appending(
        "import Ipe.List as List\n",
        &format!(
            "List.concat (List.map (\\keep -> List.filter keep [ s ]) (List.sortBy (\\p -> List.length (List.filter p [ s ])) {STORED_PREDICATES}))"
        ),
    )
}

/// `Dict.map` over a `Dict` of stored predicates, its value parameter read as
/// a value into the `impl Fn` parameter of `List.filter`.
fn dict_map_predicates() -> Result<String, BoxError> {
    cli_appending(
        "import Ipe.Dict as Dict\nimport Ipe.List as List\n",
        "List.concat (Dict.values (Dict.map (\\_k p -> List.filter p [ s ]) (Dict.fromList [ ( \"a\", \\t -> t /= \"\" ), ( \"b\", \\t -> t /= \"x\" ) ])))",
    )
}

/// Stored `Int -> Int` steps, each applied to the line length.
const STORED_STEPS: &str = r"[ \n -> n + 1, \n -> n * 2 ]";

/// `CLI_APP` whose `Line s` branch appends `appended` (a `List String`), with
/// `Ipe.Dict`/`Ipe.List`/`Ipe.String` imported and top-level `defs` added.
fn cli_appending_with(defs: &str, appended: &str) -> Result<String, BoxError> {
    let src = cli_appending(
        "import Ipe.Dict as Dict\nimport Ipe.List as List\nimport Ipe.String as String\n",
        appended,
    )?;
    variant(
        &src,
        "subscriptions : Model -> Sub Msg\n",
        &format!("{defs}\nsubscriptions : Model -> Sub Msg\n"),
    )
}

/// `Dict.foldl` OVER-applied (its function result applied to one more
/// argument), its lambda step binding the stored `Dict` value and returning a
/// function.
fn over_applied_dict_foldl() -> Result<String, BoxError> {
    cli_appending_with(
        "",
        r#"[ String.fromInt (Dict.foldl (\_k f acc -> \n -> f (acc n)) (\n -> n) (Dict.fromList [ ( "inc", \n -> n + 1 ), ( "dbl", \n -> n * 2 ) ]) (String.length s)) ]"#,
    )
}

/// `List.map2` whose mapper is a NAMED top-level function binding the stored
/// element.
fn named_mapper_map2() -> Result<String, BoxError> {
    cli_appending_with(
        "applyTo : (Int -> Int) -> Int -> Int\napplyTo f n =\n    f n\n",
        &format!(
            "List.map String.fromInt (List.map2 applyTo {STORED_STEPS} [ String.length s, 3 ])"
        ),
    )
}

/// `List.map2` whose mapper is a LET-BOUND lambda binding the stored element.
fn let_bound_mapper_map2() -> Result<String, BoxError> {
    cli_appending_with(
        "",
        &format!(
            "(let\n                app =\n                    \\f n -> f (n + 1) + 1\n            in\n            List.map String.fromInt (List.map2 app {STORED_STEPS} [ String.length s, 3 ]))"
        ),
    )
}

/// A POINT-FREE `List.map2` reference, applied later to a mapper binding the
/// stored element.
fn point_free_map2() -> Result<String, BoxError> {
    cli_appending_with(
        "",
        &format!(
            "(let\n                m =\n                    List.map2\n            in\n            List.map String.fromInt (m (\\f n -> f n) {STORED_STEPS} [ String.length s, 3 ]))"
        ),
    )
}

/// Whether some emitted closure binds a parameter on the `Arc` function carrier.
fn closure_binds_shared_fn(rust: &str) -> bool {
    rust.match_indices("move |").any(|(at, opener)| {
        rust.get(at + opener.len()..)
            .and_then(|rest| rest.split_once('|'))
            .is_some_and(|(params, _)| params.contains("::std::sync::Arc<dyn Fn("))
    })
}

/// Compile `source` and require its mapper closure to bind the `Arc` carrier.
fn assert_emits_shared_fn_param(name: &str, source: &str) -> Result<(), BoxError> {
    if let Err(e) = compile(name, source)? {
        return Err(format!("{name}: expected ipe success, got {e:?}").into());
    }
    let rust = emitted_rust(name);
    if closure_binds_shared_fn(&rust) {
        Ok(())
    } else {
        Err(format!("{name}: no mapper closure binds the `Arc` element carrier:\n{rust}").into())
    }
}

/// The control: a program with no stored function binds no closure parameter
/// on the `Arc` carrier, so the pins below cannot pass vacuously.
#[test]
fn no_stored_fn_binds_no_shared_fn_param() -> Result<(), BoxError> {
    let name = "emit_no_stored_fn";
    if let Err(e) = compile(name, CLI_APP)? {
        return Err(format!("{name}: expected ipe success, got {e:?}").into());
    }
    if closure_binds_shared_fn(&emitted_rust(name)) {
        return Err(format!("{name}: a closure binds the `Arc` carrier with no stored fn").into());
    }
    Ok(())
}

/// `List.map2`'s handler parameter binds the stored element's `Arc` carrier.
#[test]
fn map2_stored_fn_param_emits_shared_carrier() -> Result<(), BoxError> {
    assert_emits_shared_fn_param("emit_map2_stored_fn", &map2_handlers()?)
}

/// A partially-applied `List.map2`'s handler parameter binds the stored
/// element's `Arc` carrier too.
#[test]
fn partial_map2_stored_fn_param_emits_shared_carrier() -> Result<(), BoxError> {
    assert_emits_shared_fn_param("emit_partial_map2_stored_fn", &partial_map2_handlers()?)
}

/// `List.sortBy`'s key parameter binds the stored element's `Arc` carrier.
#[test]
fn sort_by_stored_fn_param_emits_shared_carrier() -> Result<(), BoxError> {
    assert_emits_shared_fn_param("emit_sort_by_stored_fn", &sort_by_predicates()?)
}

/// `Dict.map`'s value parameter binds the stored value's `Arc` carrier.
#[test]
fn dict_map_stored_fn_param_emits_shared_carrier() -> Result<(), BoxError> {
    assert_emits_shared_fn_param("emit_dict_map_stored_fn", &dict_map_predicates()?)
}

/// `List.map2` over a stored handler list, feeding each handler to
/// `Cli.Sub.onLine`, builds.
#[test]
fn seal_map2_stored_fn_into_on_line_builds() -> Result<(), BoxError> {
    assert_builds("seal_map2_stored_fn", &map2_handlers()?)
}

/// A partially-applied `List.map2` over a stored handler list, feeding each
/// handler to `Cli.Sub.onLine`, builds.
#[test]
fn seal_partial_map2_stored_fn_into_on_line_builds() -> Result<(), BoxError> {
    assert_builds("seal_partial_map2_stored_fn", &partial_map2_handlers()?)
}

/// `List.sortBy` keyed on a stored predicate fed to `List.filter` builds.
#[test]
fn seal_sort_by_stored_fn_into_impl_fn_kernel_builds() -> Result<(), BoxError> {
    assert_builds("seal_sort_by_stored_fn", &sort_by_predicates()?)
}

/// `Dict.map` over stored predicates fed to `List.filter` builds.
#[test]
fn seal_dict_map_stored_fn_into_impl_fn_kernel_builds() -> Result<(), BoxError> {
    assert_builds("seal_dict_map_stored_fn", &dict_map_predicates()?)
}

/// A named mapper is eta-wrapped onto the stored element's `Arc` carrier.
#[test]
fn named_mapper_map2_emits_shared_carrier() -> Result<(), BoxError> {
    assert_emits_shared_fn_param("emit_named_mapper_map2", &named_mapper_map2()?)
}

/// A let-bound lambda mapper is eta-wrapped onto the `Arc` carrier.
#[test]
fn let_bound_mapper_map2_emits_shared_carrier() -> Result<(), BoxError> {
    assert_emits_shared_fn_param("emit_let_bound_mapper_map2", &let_bound_mapper_map2()?)
}

/// A point-free `List.map2`'s eta mapper parameter is wrapped onto the `Arc`
/// carrier.
#[test]
fn point_free_map2_emits_shared_carrier() -> Result<(), BoxError> {
    assert_emits_shared_fn_param("emit_point_free_map2", &point_free_map2()?)
}

/// An over-applied `Dict.foldl` needs a function-valued accumulator, so its
/// step callback returns a function: the callback-result obligation refuses it
/// at type time, where the function initial accumulator meets the obligated
/// result variable.
#[test]
fn over_applied_dict_foldl_function_accumulator_refused() -> Result<(), BoxError> {
    assert_rejected_code(
        "over_applied_dict_foldl_fn_acc",
        &over_applied_dict_foldl()?,
        "IPE-T0001",
    )
}

/// `List.map2` with a named mapper over stored functions builds.
#[test]
fn seal_named_mapper_map2_stored_fn_builds() -> Result<(), BoxError> {
    assert_builds("seal_named_mapper_map2", &named_mapper_map2()?)
}

/// `List.map2` with a let-bound lambda mapper over stored functions builds.
#[test]
fn seal_let_bound_mapper_map2_stored_fn_builds() -> Result<(), BoxError> {
    assert_builds("seal_let_bound_mapper_map2", &let_bound_mapper_map2()?)
}

/// A point-free `List.map2` applied to stored functions builds.
#[test]
fn seal_point_free_map2_stored_fn_builds() -> Result<(), BoxError> {
    assert_builds("seal_point_free_map2", &point_free_map2()?)
}

/// A let-bound `Cli.Sub.onLine` applied later builds.
#[test]
fn seal_cli_on_line_let_bound_builds() -> Result<(), BoxError> {
    let src = cli_subscribing("let\n        on =\n            Sub.onLine\n    in\n    on onLine")?;
    assert_builds("seal_cli_let_bound", &src)
}

/// `Cli.Sub.onLine` with a lambda handler builds.
#[test]
fn seal_cli_on_line_lambda_handler_builds() -> Result<(), BoxError> {
    let src = cli_subscribing("Sub.onLine (\\s -> Line s)")?;
    assert_builds("seal_cli_lambda", &src)
}

/// `Cli.Sub.onLine` with a constructor handler builds.
#[test]
fn seal_cli_on_line_constructor_handler_builds() -> Result<(), BoxError> {
    let src = cli_subscribing("Sub.onLine Line")?;
    assert_builds("seal_cli_ctor", &src)
}

// ── Helper modules exposing an input subscription ───────────────────────────

/// A `Keys` helper exposing point-free `keys` over a polymorphic message.
const KEYS_POLYMORPHIC: &str = r"module Keys exposing (keys)

import Ipe.Tea.Tui.Sub

type alias KeyEvent = { kind : String, value : String }

keys : (KeyEvent -> msg) -> Sub msg
keys =
    Sub.onKey
";

/// A `Keys` helper exposing point-free `keys` over its own concrete `Msg`.
const KEYS_CONCRETE: &str = r"module Keys exposing (Msg(..), keys)

import Ipe.Tea.Tui.Sub

type Msg = NoOp

type alias KeyEvent = { kind : String, value : String }

keys : (KeyEvent -> Msg) -> Sub Msg
keys =
    Sub.onKey
";

/// A `Keys` helper exposing an unannotated point-free `keys`.
const KEYS_UNANNOTATED: &str = r"module Keys exposing (keys)

import Ipe.Tea.Tui.Sub

keys =
    Sub.onKey
";

/// A `Keys` helper whose polymorphic `msg` is captured bare into the handler.
const KEYS_CAPTURED_MSG: &str = r"module Keys exposing (keys)

import Ipe.Tea.Tui.Sub

keys msg =
    Sub.onKey (\_ -> msg)
";

/// A `Lines` helper exposing point-free `lines` over a polymorphic message.
const LINES_POLYMORPHIC: &str = r"module Lines exposing (lines)

import Ipe.Tea.Cli.Sub

lines : (String -> msg) -> Sub msg
lines =
    Sub.onLine
";

/// A `Lines` helper exposing point-free `lines` over its own concrete `Msg`.
const LINES_CONCRETE: &str = r"module Lines exposing (Msg(..), lines)

import Ipe.Tea.Cli.Sub

type Msg = Line String | NoOp

lines : (String -> Msg) -> Sub Msg
lines =
    Sub.onLine
";

/// A `Lines` helper exposing an unannotated point-free `lines`.
const LINES_UNANNOTATED: &str = r"module Lines exposing (lines)

import Ipe.Tea.Cli.Sub

lines =
    Sub.onLine
";

/// A `Lines` helper whose polymorphic `msg` is captured bare into the handler.
const LINES_CAPTURED_MSG: &str = r"module Lines exposing (lines)

import Ipe.Tea.Cli.Sub

lines msg =
    Sub.onLine (\_ -> msg)
";

/// An entry fixture a helper-module test rewrites to subscribe through the helper.
struct HelperMain<'a> {
    /// The entry program.
    source: &'a str,
    /// The entry's app import, which the helper import follows.
    entry_import: &'a str,
    /// The entry's own `Msg` declaration, dropped when the helper owns `Msg`.
    own_msg: &'a str,
    /// The entry's subscription body, replaced by the helper call.
    own_subs: &'a str,
}

const TUI_MAIN: HelperMain<'static> = HelperMain {
    source: TUI_APP,
    entry_import: "import Ipe.Tea.Tui as Tui\n",
    own_msg: "type Msg = NoOp\n",
    own_subs: "Sub.onKey onKey",
};

const CLI_MAIN: HelperMain<'static> = HelperMain {
    source: CLI_APP,
    entry_import: "import Ipe.Tea.Cli as Cli\n",
    own_msg: "type Msg = Line String | NoOp\n",
    own_subs: "Sub.onLine onLine",
};

impl HelperMain<'_> {
    /// The entry importing `helper` and subscribing through `subs`.
    ///
    /// With `exposing`, the helper owns `Msg`, so the entry's own is dropped.
    fn with(&self, helper: &str, exposing: Option<&str>, subs: &str) -> Result<String, BoxError> {
        let import = exposing.map_or_else(
            || format!("import {helper}\n"),
            |names| format!("import {helper} exposing ({names})\n"),
        );
        let src = variant(
            self.source,
            self.entry_import,
            &format!("{}{import}", self.entry_import),
        )?;
        let src = if exposing.is_some() {
            variant(&src, self.own_msg, "")?
        } else {
            src
        };
        variant(&src, self.own_subs, subs)
    }
}

/// A polymorphic point-free helper `keys : (KeyEvent -> msg) -> Sub msg` builds.
///
/// The helper's generic `msg` flows into the bridge closure, so it must carry
/// `Send + 'static` — the shape that exits 0 and then fails `cargo` without it.
#[test]
fn seal_tui_polymorphic_point_free_helper_builds() -> Result<(), BoxError> {
    let main = TUI_MAIN.with("Keys", None, "Keys.keys onKey")?;
    assert_builds_files(
        "seal_tui_helper_poly",
        &[("Main.ipe", main.as_str()), ("Keys.ipe", KEYS_POLYMORPHIC)],
    )
}

/// A concrete-`Msg` point-free helper `keys : (KeyEvent -> Msg) -> Sub Msg` builds.
#[test]
fn seal_tui_concrete_point_free_helper_builds() -> Result<(), BoxError> {
    let main = TUI_MAIN.with("Keys", Some("Msg(..)"), "Keys.keys onKey")?;
    assert_builds_files(
        "seal_tui_helper_concrete",
        &[("Main.ipe", main.as_str()), ("Keys.ipe", KEYS_CONCRETE)],
    )
}

/// An unannotated point-free helper `keys = Sub.onKey` builds.
#[test]
fn seal_tui_unannotated_point_free_helper_builds() -> Result<(), BoxError> {
    let main = TUI_MAIN.with("Keys", None, "Keys.keys onKey")?;
    assert_builds_files(
        "seal_tui_helper_unannotated",
        &[("Main.ipe", main.as_str()), ("Keys.ipe", KEYS_UNANNOTATED)],
    )
}

/// A helper capturing its polymorphic `msg` bare into the key handler builds.
#[test]
fn seal_tui_helper_capturing_msg_builds() -> Result<(), BoxError> {
    let main = TUI_MAIN.with("Keys", None, "Keys.keys NoOp")?;
    assert_builds_files(
        "seal_tui_helper_captured",
        &[("Main.ipe", main.as_str()), ("Keys.ipe", KEYS_CAPTURED_MSG)],
    )
}

/// A polymorphic point-free helper `lines : (String -> msg) -> Sub msg` builds.
#[test]
fn seal_cli_polymorphic_point_free_helper_builds() -> Result<(), BoxError> {
    let main = CLI_MAIN.with("Lines", None, "Lines.lines Line")?;
    assert_builds_files(
        "seal_cli_helper_poly",
        &[
            ("Main.ipe", main.as_str()),
            ("Lines.ipe", LINES_POLYMORPHIC),
        ],
    )
}

/// A concrete-`Msg` point-free helper `lines : (String -> Msg) -> Sub Msg` builds.
#[test]
fn seal_cli_concrete_point_free_helper_builds() -> Result<(), BoxError> {
    let main = CLI_MAIN.with("Lines", Some("Msg(..)"), "Lines.lines onLine")?;
    assert_builds_files(
        "seal_cli_helper_concrete",
        &[("Main.ipe", main.as_str()), ("Lines.ipe", LINES_CONCRETE)],
    )
}

/// An unannotated point-free helper `lines = Sub.onLine` builds.
#[test]
fn seal_cli_unannotated_point_free_helper_builds() -> Result<(), BoxError> {
    let main = CLI_MAIN.with("Lines", None, "Lines.lines onLine")?;
    assert_builds_files(
        "seal_cli_helper_unannotated",
        &[
            ("Main.ipe", main.as_str()),
            ("Lines.ipe", LINES_UNANNOTATED),
        ],
    )
}

/// A helper capturing its polymorphic `msg` bare into the line handler builds.
#[test]
fn seal_cli_helper_capturing_msg_builds() -> Result<(), BoxError> {
    let main = CLI_MAIN.with("Lines", None, "Lines.lines NoOp")?;
    assert_builds_files(
        "seal_cli_helper_captured",
        &[
            ("Main.ipe", main.as_str()),
            ("Lines.ipe", LINES_CAPTURED_MSG),
        ],
    )
}

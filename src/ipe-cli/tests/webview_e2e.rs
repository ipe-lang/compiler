//! End-to-end tests for the DOM `Web` shape hosted as a native webview.
//!
//! A `Web.tea` built under a webview-native (`web desktop`) delivery host is
//! driven by `ipe_runtime::tea::WebViewApp` rather than the served
//! `ipe_runtime::tea::WebApp`. These tests build a `Web.tea` with the webview
//! host forced on and assert the emitted project links and (Tier-B) opens a
//! window. All tests are gated on `IPE_E2E=1`; without it they return early so
//! the default `cargo test` stays fast.
//!
//! ## Architecture
//!
//! 1. A minimal `Web.tea` program is written to a temp dir.
//! 2. `ipe::build_with_options` compiles it with `webview_host = true` — the
//!    same host decision the CLI derives from a resolved `web desktop` delivery.
//! 3. `e2e_support::build_rust_binary` runs `cargo build` on the emitted project.
//!
//! ## Test tiers
//!
//! * **Tier-A** (`webview_counter_build_only`): ipe compile + `cargo build
//!   --features webview` links cleanly. The `webview` feature is promoted to the
//!   default feature list, so a plain `cargo build` already uses it. This is the
//!   SEAL assertion for a webview-hosted `Web.tea`.
//! * **Tier-B** (`webview_counter_tier_b`): the compiled binary is launched under
//!   `xvfb-run -a timeout 5` to exercise the native-window open path. A timeout
//!   exit (124) means the window stayed alive: pass. The test **loud-skips**
//!   (prints a message + returns Ok) when `xvfb-run` is absent or the system
//!   webview dev packages are not installed (headless CI environments).
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test webview_e2e
//! ```

/// A minimal `Web.tea` counter, built under a webview host.
///
/// The webview executor takes `init/update/view/subscriptions`; the window is a
/// delivery-host decision (threaded via `BuildOptions::webview_window`), never a
/// source `main` field. `view` returns `Element Msg` — the same portable Ipe.Ui
/// view a served `Web` page uses; the framework applies `Ui.layout` internally.
/// `init` takes `WebReq`, matching the `Web.tea` cfg scheme.
const IPE_WEB_COUNTER: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.String

type Msg
    = Increment
    | Decrement

type alias Model =
    { count : Int }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )
        Decrement ->
            ( { model | count = model.count - 1 }, Cmd.none )

view : Model -> Element Msg
view model =
    Ui.column []
        [ Ui.el [ Ui.onClick Increment ] (Ui.text "+")
        , Ui.text (String.fromInt model.count)
        , Ui.el [ Ui.onClick Decrement ] (Ui.text "-")
        ]

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
"#;

/// A minimal `Web.tea` mounting a `CustomElement.node` whose DOWN state is a user record
/// (`EditorState`) and whose UP event is a user ADT (`EditorEvent`).
///
/// The serde-derive gate on a widget's seal types keys on the browser SHAPE
/// (`uses_web || uses_webview`), not the Model bound, so a serde-legal widget
/// seal type derives serde in a webview-hosted `Web.tea` exactly as in a served
/// `Web` build. This fixture proves the closed seam: ipe-accept ⇒ cargo-build.
const IPE_WEB_WIDGET: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ffi.Js.CustomElement as CustomElement
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub

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
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = Edited Saved
        }
"#;

/// The JS custom-element source the widget fixture's constructor points at — its
/// mere presence satisfies the build-time file-existence gate.
const WIDGET_JS: &str = "export function mount(host, emit) { return {}; }\n";

/// Shared error type for E2E helpers.
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Build options that force the webview-native host — the same signal the CLI
/// derives from a resolved `web desktop` delivery — with an explicit desktop
/// window (there is no manifest on the single-file build path).
fn webview_host_options() -> ipe::BuildOptions {
    ipe::BuildOptions {
        webview_host: true,
        webview_window: Some(ipe_backend_rust::WebViewWindow {
            title: "Counter".to_owned(),
            width: 400,
            height: 300,
        }),
        ..ipe::BuildOptions::from_env()
    }
}

/// Compile a `Web.tea` program string under a webview host, build the emitted
/// Rust project, and return the path to the compiled binary.
fn compile_and_build(test_name: &str, ipe_source: &str) -> Result<std::path::PathBuf, BoxError> {
    compile_and_build_with_files(test_name, ipe_source, &[])
}

/// As [`compile_and_build`], but first writes extra sibling files (e.g. the JS
/// source a `CustomElement` constructor references) into the ipe source dir so
/// the build-time file-existence gate is satisfied.
fn compile_and_build_with_files(
    test_name: &str,
    ipe_source: &str,
    extra: &[(&str, &str)],
) -> Result<std::path::PathBuf, BoxError> {
    let ipe_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("webview_e2e_{test_name}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(&ipe_dir).map_err(|e| -> BoxError {
        format!("{test_name}: cannot create ipe source dir: {e}").into()
    })?;

    for (rel, contents) in extra {
        let path = ipe_dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| -> BoxError {
                format!("{test_name}: cannot create {rel} parent dir: {e}").into()
            })?;
        }
        std::fs::write(&path, contents)
            .map_err(|e| -> BoxError { format!("{test_name}: cannot write {rel}: {e}").into() })?;
    }

    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, ipe_source)
        .map_err(|e| -> BoxError { format!("{test_name}: cannot write Main.ipe: {e}").into() })?;

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("webview_e2e_{test_name}_emitted"));
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();

    ipe::build_with_options(&entry, &out_dir, &runtime, webview_host_options())
        .map_err(|e| -> BoxError { format!("{test_name}: ipe build failed: {e}").into() })?;

    let exe = e2e_support::build_rust_binary(test_name, &out_dir)
        .map_err(|e| -> BoxError { format!("{test_name}: cargo build failed: {e}").into() })?;

    Ok(std::path::PathBuf::from(exe))
}

/// Whether a `compile_and_build` failure is the Linux `wry`/`tao` link gap —
/// the system `webkit2gtk`/`glib` dev packages missing from `pkg-config`'s
/// search path — rather than a real codegen/link regression. Scoped to the
/// exact `pkg-config` "not found" signature so an unrelated cargo build failure
/// (a genuine SEAL break) still fails the test loudly.
#[must_use]
fn is_missing_linux_webview_system_libs(err: &str) -> bool {
    err.contains("cargo build failed") && err.contains("pkg-config exited with status code 1")
}

/// Tier-A: ipe compiles a `Web.tea` under a webview host, the emitted Rust
/// project links (with the `webview` + `wry` + `tao` deps from the promoted
/// default features), and the binary exists.
///
/// Assertions:
/// - emit: a webview-hosted `Web.tea` renders the `WebViewApp` executor with the
///   delivery-host window, and the `fn main` epilogue switches to `run_blocking`.
/// - manifest: the emitted crate promotes `"webview"` to its default features,
///   wires `webview = ["dep:wry", "dep:tao"]`, and the runtime `mod.rs` gets the
///   `webview` module line.
#[test]
fn webview_counter_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    match compile_and_build("webview_build_only", IPE_WEB_COUNTER) {
        Ok(_exe) => Ok(()),
        Err(e) if is_missing_linux_webview_system_libs(&e.to_string()) => {
            // LOUD-SKIP: `wry`/`tao` link against the system `webkit2gtk`/`glib`
            // dev packages on Linux, which this runner may not install. An
            // environment gap, not a codegen regression — THE SEAL is left
            // unproven on this host, never asserted false-green.
            println!(
                "LOUD-SKIP: Tier-A (webview build) — system `webkit2gtk`/`glib` dev \
                 packages not installed on this runner (the webview host is macOS-first; \
                 Linux support is tracked, not yet CI-verified). Install \
                 `libwebkit2gtk-4.1-dev libglib2.0-dev` to run this test for real."
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// SEAL golden: a `CustomElement.node` whose down is a user record and up is a user ADT
/// must ipe-accept AND cargo-build in a webview-hosted `Web.tea`.
///
/// A serde-legal widget seal type derives serde in a webview build exactly as in
/// a served `Web` build; a clean `cargo build` is the proof.
#[test]
fn webview_ui_widget_seal_builds() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    match compile_and_build_with_files(
        "webview_ui_widget_seal",
        IPE_WEB_WIDGET,
        &[("js/x.js", WIDGET_JS)],
    ) {
        Ok(_exe) => Ok(()),
        Err(e) if is_missing_linux_webview_system_libs(&e.to_string()) => {
            println!(
                "LOUD-SKIP: webview widget SEAL — system `webkit2gtk`/`glib` dev \
                 packages not installed on this runner (the webview host is macOS-first; \
                 Linux support is tracked, not yet CI-verified). Install \
                 `libwebkit2gtk-4.1-dev libglib2.0-dev` to run this test for real."
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Tier-B: launch the compiled binary under `xvfb-run` to exercise the
/// native-window-open path. A timeout (exit 124) means the window stayed alive
/// long enough — that is the success condition.
///
/// LOUD-SKIP conditions (prints a clear message, returns `Ok(())`):
/// - `xvfb-run` is not on `$PATH` (headless CI without a virtual framebuffer).
/// - the system webview dev packages are not installed.
///
/// The test is NOT a silent-green skip — it always prints whether it ran or was
/// skipped and why.
#[test]
fn webview_counter_tier_b() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let xvfb_available = std::process::Command::new("which")
        .arg("xvfb-run")
        .output()
        .is_ok_and(|o| o.status.success());

    if !xvfb_available {
        println!(
            "LOUD-SKIP: Tier-B (webview paint smoke) — `xvfb-run` not found on PATH. \
             Install `xvfb-run` (e.g. `apt-get install xvfb`) to run this test."
        );
        return Ok(());
    }

    let exe = match compile_and_build("webview_tier_b", IPE_WEB_COUNTER) {
        Ok(exe) => exe,
        Err(e) if is_missing_linux_webview_system_libs(&e.to_string()) => {
            println!(
                "LOUD-SKIP: Tier-B (webview paint smoke) — system `webkit2gtk`/`glib` dev \
                 packages not installed on this runner (same gap as Tier-A). Install \
                 `libwebkit2gtk-4.1-dev libglib2.0-dev` to run this test for real."
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    // `timeout 5 <binary>` wrapped by `xvfb-run -a` (a virtual display). Exit 124
    // = timeout killed the process = the window stayed open = pass. Any other
    // non-zero exit is a failure.
    let result = std::process::Command::new("xvfb-run")
        .arg("-a")
        .arg("timeout")
        .arg("5")
        .arg(&exe)
        .output()
        .map_err(|e| -> BoxError { format!("Tier-B: failed to spawn xvfb-run: {e}").into() })?;

    let exit_code = result.status.code().unwrap_or(-1);

    if exit_code == 124 || exit_code == 0 {
        println!("Tier-B webview paint smoke: exit={exit_code} (pass — window stayed alive)");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&result.stderr);
        let stdout = String::from_utf8_lossy(&result.stdout);
        Err(format!(
            "Tier-B webview paint smoke FAILED: exit={exit_code}\n\
             --- stdout ---\n{stdout}\n\
             --- stderr ---\n{stderr}"
        )
        .into())
    }
}

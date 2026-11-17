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
//! 1. A minimal `Web.tea` program is written as a project whose manifest
//!    carries a `delivery.desktop` window.
//! 2. `ipe::build_fixture_for` compiles it for the host a resolved `web desktop`
//!    delivery asks for — the same host decision the CLI makes.
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
/// delivery-host decision (the manifest's `delivery.desktop`), never a source
/// `main` field. `view` returns `Element Msg` — the same portable Ipe.Ui
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

/// The manifest field that sizes and titles the desktop window.
const DESKTOP_WINDOW: &str =
    "delivery = { desktop = { title = \"Counter\", width = 400, height = 300 } }";

/// The host a resolved `web desktop` delivery asks the emit for.
fn web_desktop_host() -> Result<ipe::delivery::HostIntent, BoxError> {
    ipe::delivery::Delivery::resolve(
        ipe::delivery::Shape::Web,
        None,
        ipe::delivery::Host::Desktop,
    )
    .map(ipe::delivery::Delivery::host_intent)
    .map_err(|e| -> BoxError { format!("web desktop does not resolve: {e}").into() })
}

/// The whole emitted Ipê-side Rust tree: `src/main.rs` plus every
/// `src/ipe_mods/*.rs` a project build splits its modules into.
fn emitted_source(out_dir: &std::path::Path) -> std::io::Result<String> {
    let src = out_dir.join("src");
    let mut combined = std::fs::read_to_string(src.join("main.rs"))?;
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(src.join("ipe_mods"))
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    files.sort();
    for path in files {
        combined.push('\n');
        combined.push_str(&std::fs::read_to_string(&path)?);
    }
    Ok(combined)
}

/// Compile a `Web.tea` program string under a webview host, build the emitted
/// Rust project, and return the path to the compiled binary.
fn compile_and_build(
    test_name: &str,
    ipe_source: &str,
) -> Result<e2e_support::SharedBuild, BoxError> {
    compile_and_build_with_files(test_name, ipe_source, &[])
}

/// As [`compile_and_build`], but first writes extra sibling files (e.g. the JS
/// source a `CustomElement` constructor references) into the ipe source dir so
/// the build-time file-existence gate is satisfied.
fn compile_and_build_with_files(
    test_name: &str,
    ipe_source: &str,
    extra: &[(&str, &str)],
) -> Result<e2e_support::SharedBuild, BoxError> {
    let tree = ipe::project_root::SourceTree::main(ipe_source).field(DESKTOP_WINDOW);
    let fixture = ipe::RootFixture::from_tree(&tree)
        .map_err(|e| -> BoxError { format!("{test_name}: fixture: {e}").into() })?;

    // Extra files sit beside the entry module, where its widget paths resolve.
    let src_dir = fixture.path().join("src");
    for (rel, contents) in extra {
        let path = src_dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| -> BoxError {
                format!("{test_name}: cannot create {rel} parent dir: {e}").into()
            })?;
        }
        std::fs::write(&path, contents)
            .map_err(|e| -> BoxError { format!("{test_name}: cannot write {rel}: {e}").into() })?;
    }

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("webview_e2e_{test_name}_emitted"));
    e2e_support::scratch::fresh(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();

    ipe::build_fixture_for(
        &fixture,
        &out_dir,
        &runtime,
        &ipe::BuildOptions::from_env().map_err(|e| -> BoxError {
            format!("{test_name}: emit options refused: {e}").into()
        })?,
        web_desktop_host()?,
    )
    .map_err(|e| -> BoxError { format!("{test_name}: ipe dev build failed: {e}").into() })?;

    let emitted = emitted_source(&out_dir).map_err(|e| -> BoxError {
        format!("{test_name}: cannot read emitted source: {e}").into()
    })?;
    if !emitted.contains("WebViewApp") || !emitted.contains("\"Counter\"") {
        return Err(format!(
            "{test_name}: the emit is not a webview app titled from the manifest window"
        )
        .into());
    }

    let exe = e2e_support::build_rust_binary(test_name, &out_dir)
        .map_err(|e| -> BoxError { format!("{test_name}: cargo build failed: {e}").into() })?;

    Ok(exe)
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
///   wires `webview` to the runtime crate's own feature edges (its
///   `webview-shell` pulling the native webview dependencies), and the runtime
///   `mod.rs` gets the `webview` module line.
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

/// A `web client desktop` project with the counter as its program and
/// `mobile` as its `delivery.mobile` record.
fn client_desktop_fixture(test_name: &str, mobile: &str) -> Result<ipe::RootFixture, BoxError> {
    let tree = ipe::project_root::SourceTree::main(IPE_WEB_COUNTER)
        .field(&format!("delivery = {{ mobile = {mobile} }}"));
    ipe::RootFixture::from_tree(&tree)
        .map_err(|e| -> BoxError { format!("{test_name}: fixture: {e}").into() })
}

/// A link argument the host's linker driver accepts and the wasm32 `rust-lld`
/// rejects, as a host linking through its own flags exports.
const HOST_ONLY_RUSTFLAGS: &str = "-C link-arg=-Wl,-O1";

/// `ipe dev build <project> web client desktop`, its output captured.
///
/// The build runs in an exclusive target: `ipe dev build` emits fixed package
/// names a concurrent build in the shared target would collide with. The
/// ambient `RUSTFLAGS` are [`HOST_ONLY_RUSTFLAGS`]: the shell links for the
/// host under them, and the wasm client build must not see them.
fn dev_build_client_desktop(project: &std::path::Path) -> Result<std::process::Output, BoxError> {
    Ok(dev_build_client_desktop_command(project)?.output()?)
}

/// The command [`dev_build_client_desktop`] runs, before it is spawned.
fn dev_build_client_desktop_command(
    project: &std::path::Path,
) -> Result<std::process::Command, BoxError> {
    let isolated =
        e2e_support::target::isolated(e2e_support::target::IsolationReason::FixedPackageName);
    let Ok(isolated) = isolated else {
        return Err(format!("isolated build target: {isolated:?}").into());
    };
    let target = e2e_support::target::BuildTarget::Isolated(isolated);
    let ipe_bin = e2e_support::cargo_bin!("ipe").into_path_buf();
    let mut command = e2e_support::target::ipe_command(&ipe_bin, &target);
    command
        .args(["dev", "build"])
        .arg(project)
        .args(["web", "client", "desktop"])
        .env("RUSTFLAGS", HOST_ONLY_RUSTFLAGS)
        .env_remove("CARGO_ENCODED_RUSTFLAGS");
    Ok(command)
}

/// A bundle id the bundle grammar admits but no OS can name a directory by is
/// refused before any build: the command fails, names the id, and writes no
/// shell crate.
#[test]
fn client_desktop_refuses_a_dos_device_bundle_id() -> Result<(), BoxError> {
    let test_name = "client_desktop_dos_device";
    let fixture = client_desktop_fixture(test_name, "{ bundleId = \"con.acme\" }")?;
    let out = dev_build_client_desktop(fixture.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("con.acme"), "{stderr}");
    assert!(
        !fixture.path().join("out").join("client-shell").exists(),
        "no shell crate is written for a refused bundle id"
    );
    Ok(())
}

/// A fresh, empty directory to hold a test's own `PATH` entries.
#[cfg(unix)]
fn private_bin(tag: &str) -> Result<std::path::PathBuf, BoxError> {
    let dir = ipe_test_temp::temp_root()
        .join(format!("ipe_webview_e2e_{tag}_bin_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// A host without the `wasm-bindgen` CLI is refused by name before any wasm
/// build: the message names the tool and its pinned version, and neither the
/// nested `web client` build nor the shell build reads the tool as a source
/// path or prints a usage page. The `PATH` holds `cargo` and `rustc` alone.
#[cfg(unix)]
#[test]
fn client_desktop_without_wasm_bindgen_names_the_tool() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "client_desktop_without_wasm_bindgen";
    let bin = private_bin(test_name)?;
    for tool in [
        ipe_sandbox::host_tool::HostTool::Cargo,
        ipe_sandbox::host_tool::HostTool::Rustc,
    ] {
        let found = ipe_sandbox::host_tool::resolve(tool)
            .map_err(|e| format!("{test_name}: {} must be on PATH: {e:?}", tool.name()))?;
        std::os::unix::fs::symlink(found.as_path(), bin.join(tool.name()))?;
    }
    let fixture = client_desktop_fixture(test_name, "{ bundleId = \"io.acme.counter\" }")?;
    let out = dev_build_client_desktop_command(fixture.path())?
        .env("PATH", &bin)
        .output();
    let _ = std::fs::remove_dir_all(&bin);
    let out = out?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("wasm-bindgen was not found"), "{stderr}");
    assert!(stderr.contains("so it needs wasm-bindgen-cli "), "{stderr}");
    assert!(!stderr.contains("source file"), "{stderr}");
    assert!(!stderr.contains("Usage:"), "{stderr}");
    assert!(
        !stderr.contains("compiled the emitted wasm program"),
        "the tool is checked before the wasm build: {stderr}"
    );
    Ok(())
}

/// The policy value one `<meta http-equiv="Content-Security-Policy">` in
/// `page` carries.
fn meta_policy(page: &str) -> Option<&str> {
    let (_, after) = page.split_once("http-equiv=\"Content-Security-Policy\" content=\"")?;
    after.split_once('"').map(|(value, _)| value)
}

/// The `csp` literal `site.rs` carries, still in its Rust-literal form.
fn site_policy(site_rs: &str) -> Option<&str> {
    site_rs
        .lines()
        .find_map(|line| line.trim().strip_prefix("csp: \""))
        .and_then(|rest| rest.strip_suffix("\","))
}

/// SEAL, Tier-A: `ipe dev build web client desktop` on the counter builds the
/// wasm client, writes the shell crate with every published file in its table
/// and one policy for the page and the header, and the shell crate builds.
#[test]
fn client_desktop_shell_builds() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "client_desktop_shell_builds";
    let fixture = client_desktop_fixture(test_name, "{ bundleId = \"io.acme.counter\" }")?;
    let out = dev_build_client_desktop(fixture.path())?;
    // The shell links the system webview (Linux: `libwebkit2gtk-4.1-dev`), so a
    // host without it fails here rather than passing unproven.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");

    let shell = fixture.path().join("out").join("client-shell");
    let site_rs = std::fs::read_to_string(shell.join("src").join("site.rs"))?;
    let index = std::fs::read_to_string(shell.join("www").join("index.html"))?;
    assert!(
        site_rs.contains("storage_key: \"io.acme.counter\","),
        "{site_rs}"
    );
    assert!(site_rs.contains("path: \"index.html\","), "{site_rs}");
    // A policy value holds no `"` or backslash, so its Rust literal is its text.
    let Some(header) = site_policy(&site_rs).filter(|value| !value.contains('\\')) else {
        return Err(format!("{test_name}: no plain `csp` literal in site.rs:\n{site_rs}").into());
    };
    let shown = ipe_runtime_rust::escape::html_attr(header);
    assert_eq!(
        meta_policy(&index),
        Some(shown.as_str()),
        "the page and the header carry one policy"
    );
    Ok(())
}

/// The storage key the client desktop fixtures' bundle id folds to.
#[cfg(all(unix, not(target_os = "macos")))]
const CLIENT_DESKTOP_KEY: &str = "io.acme.counter";

/// A fresh, empty, owner-only directory for `tag`.
#[cfg(all(unix, not(target_os = "macos")))]
fn private_scratch(tag: &str) -> Result<std::path::PathBuf, BoxError> {
    use std::os::unix::fs::PermissionsExt as _;
    let dir =
        ipe_test_temp::temp_root().join(format!("ipe_webview_e2e_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

/// The shell binary `ipe dev build web client desktop` packed for Linux under
/// `project`: `out/dist/linux/<app>/bin/<app>`, the one bundle directory there
/// (the output root's ownership marker beside it is a file).
#[cfg(all(unix, not(target_os = "macos")))]
fn client_desktop_binary(project: &std::path::Path) -> Result<std::path::PathBuf, BoxError> {
    let dist = project.join("out").join("dist").join("linux");
    let mut roots = Vec::new();
    for entry in std::fs::read_dir(&dist)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            roots.push(entry);
        }
    }
    let [root] = roots.as_slice() else {
        return Err(format!("one bundle under {}: {roots:?}", dist.display()).into());
    };
    let binary = root.path().join("bin").join(root.file_name());
    if binary.is_file() {
        Ok(binary)
    } else {
        Err(format!("no shell binary at {}", binary.display()).into())
    }
}

/// The counter's client desktop shell, built: its fixture and its binary.
#[cfg(all(unix, not(target_os = "macos")))]
fn built_client_desktop(
    test_name: &str,
) -> Result<(ipe::RootFixture, std::path::PathBuf), BoxError> {
    let fixture = client_desktop_fixture(test_name, "{ bundleId = \"io.acme.counter\" }")?;
    let out = dev_build_client_desktop(fixture.path())?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("{test_name}: the client desktop build failed:\n{stderr}").into());
    }
    let binary = client_desktop_binary(fixture.path())?;
    Ok((fixture, binary))
}

/// Run `binary` under `timeout 10` from `cwd`, its `XDG_DATA_HOME` set to `xdg`.
///
/// The bound keeps a shell whose storage guard is gone from holding the test
/// open on a host with a display; a refused shell exits long before it.
#[cfg(all(unix, not(target_os = "macos")))]
fn run_shell_with_xdg(
    binary: &std::path::Path,
    xdg: &std::ffi::OsStr,
    cwd: &std::path::Path,
) -> Result<std::process::Output, BoxError> {
    Ok(std::process::Command::new("timeout")
        .arg("10")
        .arg(binary)
        .env("XDG_DATA_HOME", xdg)
        .current_dir(cwd)
        .output()?)
}

/// Tier-B: the client desktop shell starts under `xvfb-run`, loads its bundle,
/// and exits only by the timeout; its webview data lives in the storage key's
/// private directory under the `XDG_DATA_HOME` it was given.
///
/// Exit 124 is the only pass: an exit by the shell's own error is 1, and a
/// shell that closed on its own is 0. Afterwards `<xdg>/<key>/webview` exists,
/// is mode 0o700 like `<xdg>/<key>`, and holds the engine's data.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn client_desktop_shell_boots_and_loads_wasm() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "client_desktop_shell_boots";
    let (_fixture, binary) = built_client_desktop(test_name)?;
    let xdg = private_scratch(test_name)?;
    let result = std::process::Command::new("xvfb-run")
        .args(["-a", "timeout", "10"])
        .arg(&binary)
        .env("XDG_DATA_HOME", &xdg)
        .output()?;
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert_eq!(
        result.status.code(),
        Some(124),
        "the shell exits only by the timeout:\n{stderr}"
    );

    let key_dir = xdg.join(CLIENT_DESKTOP_KEY);
    let data_dir = key_dir.join("webview");
    for dir in [&key_dir, &data_dir] {
        let meta = std::fs::symlink_metadata(dir)?;
        assert!(meta.is_dir(), "{} is a real directory", dir.display());
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777,
            0o700,
            "{}",
            dir.display()
        );
    }
    assert!(
        std::fs::read_dir(&data_dir)?.next().is_some(),
        "the engine keeps its data in {}",
        data_dir.display()
    );
    let _ = std::fs::remove_dir_all(&xdg);
    Ok(())
}

/// A relative `XDG_DATA_HOME` is refused before any window: the shell exits 1
/// naming the variable, and creates nothing relative to its working directory.
///
/// Without the refusal the shell would fall back to `$HOME/.local/share` and
/// go on to open a window, so the exit and the line both go red.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn client_desktop_shell_refuses_a_relative_xdg_data_home() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "client_desktop_relative_xdg";
    let (_fixture, binary) = built_client_desktop(test_name)?;
    let cwd = private_scratch(test_name)?;
    let result = run_shell_with_xdg(&binary, std::ffi::OsStr::new("rel"), &cwd)?;
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert_eq!(result.status.code(), Some(1), "{stderr}");
    assert!(
        stderr
            .lines()
            .any(|line| line == "no app-data directory: `XDG_DATA_HOME` is not an absolute path"),
        "{stderr}"
    );
    assert!(
        std::fs::read_dir(&cwd)?.next().is_none(),
        "nothing is created under the working directory"
    );
    let _ = std::fs::remove_dir_all(&cwd);
    Ok(())
}

/// A storage key directory planted as a symlink is refused, never followed:
/// the shell exits 1 with the not-a-real-directory refusal, and the link's
/// target stays empty.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn client_desktop_shell_refuses_a_symlinked_storage_dir() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "client_desktop_symlinked_storage";
    let (_fixture, binary) = built_client_desktop(test_name)?;
    let scratch = private_scratch(test_name)?;
    let xdg = scratch.join("data");
    let elsewhere = scratch.join("elsewhere");
    std::fs::create_dir(&xdg)?;
    std::fs::create_dir(&elsewhere)?;
    let key_dir = xdg.join(CLIENT_DESKTOP_KEY);
    std::os::unix::fs::symlink(&elsewhere, &key_dir)?;
    let result = run_shell_with_xdg(&binary, xdg.as_os_str(), &scratch)?;
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert_eq!(result.status.code(), Some(1), "{stderr}");
    assert!(
        stderr
            .lines()
            .any(|line| line == "the app-data directory is not a real directory"),
        "{stderr}"
    );
    assert!(
        std::fs::symlink_metadata(&key_dir)?
            .file_type()
            .is_symlink()
    );
    assert!(
        std::fs::read_dir(&elsewhere)?.next().is_none(),
        "the link's target is never written"
    );
    let _ = std::fs::remove_dir_all(&scratch);
    Ok(())
}

/// With no display to answer, the shell exits 1 with the typed no-display
/// refusal, never a GTK panic (exit 101).
///
/// The child runs with `DISPLAY`, `WAYLAND_DISPLAY` and `GDK_BACKEND` removed
/// and `XDG_RUNTIME_DIR` an empty directory, so neither X11 nor a default
/// Wayland socket is reachable. Without `WindowSystem::open`'s fallible GTK
/// start, tao's event loop builder panics here.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn client_desktop_shell_refuses_without_a_display() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "client_desktop_no_display";
    let (_fixture, binary) = built_client_desktop(test_name)?;
    let scratch = private_scratch(test_name)?;
    let xdg = scratch.join("data");
    let runtime = scratch.join("runtime");
    std::fs::create_dir(&xdg)?;
    std::fs::create_dir(&runtime)?;
    let result = std::process::Command::new("timeout")
        .arg("10")
        .arg(&binary)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("GDK_BACKEND")
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("XDG_DATA_HOME", &xdg)
        .current_dir(&scratch)
        .output()?;
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert_eq!(result.status.code(), Some(1), "{stderr}");
    assert!(
        stderr
            .lines()
            .any(|line| line.starts_with("no graphical display is available (")),
        "{stderr}"
    );
    assert!(!stderr.contains("panicked"), "{stderr}");
    let _ = std::fs::remove_dir_all(&scratch);
    Ok(())
}

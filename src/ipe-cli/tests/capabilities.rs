//! `ipe capabilities` — the read-only capability report and the
//! declared-set verification primitive.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::PathBuf;
use std::process::Command;

use ipe::verify_capabilities;
use ipe_ir::{Capability, WebCapability};

mod support;

type TestResult = Result<(), Box<dyn Error>>;

/// A minimal Web-shape TEA app whose view mounts one `CustomElement.node` over a
/// `customElement` handle — the smallest program that ships browser JS, so its
/// inferred capability set must contain `custom-element`.
const WIDGET_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Ffi.Js.CustomElement as CustomElement
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.String as String

type alias WidgetState = { count : Int }

type WidgetUp = Bumped Int

type Msg = FromWidget WidgetUp

type alias Model = { count : Int }

counter : CustomElement WidgetState WidgetUp
counter = CustomElement.fromFile "js/counter.js"

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        FromWidget (Bumped n) ->
            ( { count = model.count + n }, Cmd.none )

view : Model -> Element Msg
view model =
    Ui.column []
        [ CustomElement.node counter { count = model.count } FromWidget
        , Ui.text (String.fromInt model.count)
        ]

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = FromWidget (Bumped 0)
        }
"#;

/// The author widget-hook JS. Its exact bytes are what the served page SRI pins;
/// present so the build path's widget-file gate is satisfied when a test builds.
const COUNTER_JS: &str =
    "export function mount(host, emit) {\n  return { onState(state) {} };\n}\n";

/// Materialise a widget project (`package.ipe` + `src/Main.ipe` + `src/js/…`)
/// under a unique temp dir, returning the dir. The caller removes it.
fn widget_project(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = crate::support::scratch_root().join(format!(
        "ipe-ce-cap-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src/js"))?;
    std::fs::write(
        dir.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"widgetpkg\", version = \"0.1.0\" }\n",
    )?;
    std::fs::write(dir.join("src/Main.ipe"), WIDGET_APP)?;
    std::fs::write(dir.join("src/js/counter.js"), COUNTER_JS)?;
    Ok(dir)
}

/// Absolute path to a fixture under this crate's `tests/fixtures/capabilities`.
fn fixture(name: &str) -> PathBuf {
    support::manifest_dir()
        .join("tests/fixtures/capabilities")
        .join(name)
}

/// Run the built `ipe` binary and return its captured `(status_success, stdout)`.
fn run_ipe(args: &[&str]) -> Result<(bool, String), Box<dyn Error>> {
    let out = Command::new(support::ipe_bin()).args(args).output()?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    ))
}

#[test]
fn reports_network_for_an_http_program() -> TestResult {
    let (ok, stdout) = run_ipe(&[
        "capabilities",
        "--plain",
        &fixture("uses_http.ipe").to_string_lossy(),
    ])?;
    assert!(ok, "capabilities must exit 0");
    assert_eq!(stdout.trim(), "network");
    Ok(())
}

#[test]
fn reports_none_for_a_pure_program() -> TestResult {
    let (ok, stdout) = run_ipe(&[
        "capabilities",
        "--plain",
        &fixture("pure_string.ipe").to_string_lossy(),
    ])?;
    assert!(ok, "capabilities must exit 0");
    // Under `--plain`, a pure program emits zero records (empty) — the "no
    // capabilities" wording lives only in the human default and `--json`'s `[]`.
    assert!(
        stdout.trim().is_empty(),
        "a pure program has no --plain capability lines, got:\n{stdout}"
    );
    Ok(())
}

#[test]
fn reports_unsafe_for_an_html_unsafe_script_program() -> TestResult {
    // Importing `Ipe.Html.Unsafe` (the inline-`<script>` / raw-HTML escape-hatch
    // home) discloses the `unsafe` capability — the import itself is the signal,
    // so a raw HTML/script sink cannot hide from `ipe capabilities`.
    let (ok, stdout) = run_ipe(&[
        "capabilities",
        "--plain",
        &fixture("uses_html_unsafe_script.ipe").to_string_lossy(),
    ])?;
    assert!(ok, "capabilities must exit 0");
    assert_eq!(stdout.trim(), "unsafe");
    Ok(())
}

#[test]
fn capabilities_help_page_lists_the_command() -> TestResult {
    let (ok, stdout) = run_ipe(&["capabilities", "--help"])?;
    assert!(ok, "--help exits 0");
    assert!(
        stdout.contains("capabilities"),
        "help page names the command, got:\n{stdout}"
    );
    Ok(())
}

#[test]
fn verify_accepts_the_exact_declared_set() {
    let declared = BTreeSet::from([Capability::Network]);
    let r = verify_capabilities(&fixture("uses_http.ipe"), &declared);
    assert!(r.is_ok(), "an exact declaration verifies: {r:?}");
}

#[test]
fn verify_rejects_underdeclared() {
    // The program uses `network` but declares nothing.
    let declared = BTreeSet::new();
    let r = verify_capabilities(&fixture("uses_http.ipe"), &declared);
    assert!(r.is_err(), "an empty declaration must be rejected");
}

#[test]
fn verify_rejects_overdeclared() {
    // The pure program uses nothing but declares `filesystem`.
    let declared = BTreeSet::from([Capability::Filesystem]);
    let r = verify_capabilities(&fixture("pure_string.ipe"), &declared);
    assert!(r.is_err(), "an over-declaration must be rejected");
}

/// A program importing the compiled-source `Ipe.File` veneer discloses
/// `filesystem`.
///
/// The kernel reached through the veneer's alias carries the tag, so the full
/// pipeline (compiled-stdlib injection included) must infer exactly
/// `{filesystem}` and refuse an empty declaration.
#[test]
fn importing_ipe_file_discloses_filesystem() -> TestResult {
    let dir = write_single("file-cap", FILE_WRITE_APP)?;
    let entry = dir.join("Main.ipe");
    let exact = verify_capabilities(&entry, &BTreeSet::from([Capability::Filesystem]));
    let under = verify_capabilities(&entry, &BTreeSet::new());
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        exact.is_ok(),
        "importing Ipe.File must infer exactly {{filesystem}}: {exact:?}"
    );
    assert!(
        under.is_err(),
        "a filesystem program declaring nothing must be rejected"
    );
    Ok(())
}

const FILE_WRITE_APP: &str = r#"module Main exposing (main)

import Ipe.File as File
import Ipe.Path as Path
import Ipe.Task as Task


main =
    Task.fromResult (Path.fromString "/tmp/ipe-cap-probe")
        |> Task.andThen (\p -> File.writeFile p "probe")
"#;

/// Acceptance test: a program using both `Http.get` (network) and `Time.now`
/// (clock) must report exactly `{network, clock}`. Any drift is a mis-classified
/// tag, caught against a real program rather than a minimal fixture.
#[test]
fn acceptance_http_and_clock_example_infers_network_and_clock() -> TestResult {
    let example = fixture("uses_http_and_clock.ipe");
    let (ok, stdout) = run_ipe(&["capabilities", "--plain", &example.to_string_lossy()])?;
    assert!(ok, "capabilities must exit 0 on the example");
    let reported: BTreeSet<&str> = stdout.split_whitespace().collect();
    assert_eq!(
        reported,
        BTreeSet::from(["network", "clock"]),
        "unexpected capability set for uses_http_and_clock, got:\n{stdout}"
    );

    // The library verifier agrees with the reported set exactly.
    let declared = BTreeSet::from([Capability::Network, Capability::Clock]);
    let r = verify_capabilities(&example, &declared);
    assert!(r.is_ok(), "the exact inferred set must verify: {r:?}");
    Ok(())
}

// ── Web-app-mounted-into-a-server invariant ─────────────────────────────────

/// A Direct program whose `main` is a `Server.listen` Task that mounts a
/// `Web.embed`'d web app on a route via `Server.mountApp`. This is the
/// maintainer-mandated invariant: a Web app must stay mountable into a server —
/// `Web.embed -> WebApp -> Server.mountApp "/app" webApp` type-checks, and the
/// whole program's `main` is a composable `Task` (Direct), not a shape carrier.
const SERVER_MOUNTS_WEB_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.String as String
import Ipe.Http.Server as Server
import Ipe.Task as Task

type Msg = Increment

type alias Model = { count : Int }

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )

view : Model -> Element Msg
view model =
    Ui.text (String.fromInt model.count)

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Sub.none

main : Task Error ()
main =
    Server.listen 8000
        [ Server.mountApp "/app"
            (Web.embed
                { init = init
                , update = update
                , view = view
                , subscriptions = subscriptions
                , routes = []
                , notFound = Increment
                }
            )
        , Server.get "/api" (\_req -> Task.succeed (Server.json "{\"ok\":true}"))
        ]
"#;

/// Materialise a server-mounts-web project under a unique temp dir.
fn server_mount_project(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = crate::support::scratch_root().join(format!(
        "ipe-mount-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src"))?;
    std::fs::write(
        dir.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"mountpkg\", version = \"0.1.0\" }\n",
    )?;
    std::fs::write(dir.join("src/Main.ipe"), SERVER_MOUNTS_WEB_APP)?;
    Ok(dir)
}

/// A Web app mounted into a server must type-check: `Server.listen 8000
/// [ Server.mountApp "/app" (Web.embed cfg) ]` is the maintainer-mandated
/// invariant. Dropping the generic `TeaApp` / `Script.program` entries must NOT
/// disturb the `Web.embed` -> `WebApp` -> `Server.mountApp` mount surface.
#[test]
fn a_web_app_mounts_into_a_server() -> TestResult {
    let dir = server_mount_project("typecheck")?;
    let entry = dir.join("src/Main.ipe");
    let (ok, stdout) = run_ipe(&["type-check", &entry.to_string_lossy()])?;
    assert!(
        ok,
        "a Web app mounted via Server.mountApp (Web.embed …) inside Server.listen \
         must type-check, got stdout:\n{stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ── the `custom-element` disclosure axis ────────────────────────────────────

/// A program that mounts a `CustomElement.node` ships browser JS, so its inferred
/// capability set must contain `custom-element`. Proven through the same
/// `verify_capabilities` inference `ipe capabilities` reports, over a real
/// Web-shape widget app.
#[test]
fn a_widget_program_discloses_custom_element() -> TestResult {
    let dir = widget_project("infer")?;
    let entry = dir.join("src/Main.ipe");
    // Declaring exactly `{custom-element}` must verify: it is the whole inferred
    // set of a widget app that reaches no other effect.
    let declared = BTreeSet::from([Capability::CustomElement]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "a widget program's inferred set is exactly {{custom-element}}: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Fail-closed: a program that ships a widget but declares NOTHING on the
/// `custom-element` axis is rejected — a widget-bearing module can never hide the
/// disclosure. This is the load-bearing invariant.
#[test]
fn a_widget_program_that_hides_custom_element_is_rejected() -> TestResult {
    let dir = widget_project("hide")?;
    let entry = dir.join("src/Main.ipe");
    // Declare the empty set even though the program ships a widget.
    let declared = BTreeSet::new();
    let r = verify_capabilities(&entry, &declared);
    assert!(
        matches!(
            &r,
            Err(ipe::CliError::CapabilityMismatch { missing, .. })
                if missing.contains(&"custom-element")
        ),
        "a widget program that omits `custom-element` must be rejected as under-declared, got: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// A Web-shape app that CONSTRUCTS a `customElement` handle at top level but never
/// mounts it in `view`. The emitter still serves the author JS (the handle is a
/// served asset the moment it is constructed), so disclosure must follow serving:
/// the inferred set contains `custom-element` even though no `CustomElement.node` is
/// reachable and the handle DCEs out of the lowered program. The prior kernel-only
/// inference reported nothing here while the emitter served the JS — a
/// served-but-undisclosed browser-JS hole. The `js/counter.js` marker in the
/// served bytes is the same file the mounted-case project ships.
const UNMOUNTED_WIDGET_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Ffi.Js.CustomElement as CustomElement
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.String as String

type alias WidgetState = { count : Int }

type WidgetUp = Bumped Int

type Msg = Noop

type alias Model = { count : Int }

counter : CustomElement WidgetState WidgetUp
counter = CustomElement.fromFile "js/counter.js"

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        Noop ->
            ( model, Cmd.none )

view : Model -> Element Msg
view model =
    Ui.column []
        [ Ui.text (String.fromInt model.count)
        ]

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Noop
        }
"#;

/// Materialise an unmounted-handle widget project (a `customElement` handle
/// constructed but never mounted), returning its dir. The caller removes it.
fn unmounted_widget_project(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = crate::support::scratch_root().join(format!(
        "ipe-ce-unmounted-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src/js"))?;
    std::fs::write(
        dir.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"unmountedpkg\", version = \"0.1.0\" }\n",
    )?;
    std::fs::write(dir.join("src/Main.ipe"), UNMOUNTED_WIDGET_APP)?;
    std::fs::write(dir.join("src/js/counter.js"), COUNTER_JS)?;
    Ok(dir)
}

/// An unmounted `customElement` handle still ships browser JS, so its inferred
/// capability set contains `custom-element`: declaring exactly `{custom-element}`
/// verifies. Disclosure derives from the served-asset walk, not from a reachable
/// `CustomElement.node` kernel.
#[test]
fn an_unmounted_handle_still_discloses_custom_element() -> TestResult {
    let dir = unmounted_widget_project("infer")?;
    let entry = dir.join("src/Main.ipe");
    let declared = BTreeSet::from([Capability::CustomElement]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "an unmounted-handle app's inferred set is exactly {{custom-element}}: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Fail-closed on the unmounted-handle case: constructing a `customElement` handle
/// ships its JS, so declaring NOTHING is rejected with a `custom-element`-naming
/// mismatch — the exact hole a mounted-only test never exercised.
#[test]
fn an_unmounted_handle_that_hides_custom_element_is_rejected() -> TestResult {
    let dir = unmounted_widget_project("hide")?;
    let entry = dir.join("src/Main.ipe");
    let declared = BTreeSet::new();
    let r = verify_capabilities(&entry, &declared);
    assert!(
        matches!(
            &r,
            Err(ipe::CliError::CapabilityMismatch { missing, .. })
                if missing.contains(&"custom-element")
        ),
        "an unmounted-handle app that omits `custom-element` must be rejected as under-declared, got: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Transitivity: a `customElement` handle constructed in an IMPORTED module and
/// never mounted anywhere still ships its JS, so the entry's inferred set
/// discloses `custom-element`. The served-asset walk covers the whole linked
/// program, so a handle a dependency constructs is disclosed by the consumer.
#[test]
fn a_handle_constructed_in_an_imported_module_discloses_custom_element() -> TestResult {
    let dir = crate::support::scratch_root().join(format!(
        "ipe-ce-transitive-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src/js"))?;
    std::fs::write(
        dir.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"transpkg\", version = \"0.1.0\" }\n",
    )?;
    // Module B constructs the handle; nothing mounts it.
    std::fs::write(
        dir.join("src/Widgets.ipe"),
        "module Widgets exposing (counter)\n\nimport Ipe.Ffi.Js.CustomElement as CustomElement\n\ntype alias WidgetState = { count : Int }\n\ntype WidgetUp = Bumped Int\n\ncounter : CustomElement WidgetState WidgetUp\ncounter = CustomElement.fromFile \"js/counter.js\"\n",
    )?;
    // Main imports Widgets but never mounts `counter`.
    std::fs::write(
        dir.join("src/Main.ipe"),
        "module Main exposing (main)\n\nimport Ipe.Tea.Web as Web\nimport Ipe.Ui as Ui\nimport Ipe.Tea.Web.Cmd as Cmd\nimport Ipe.Tea.Web.Sub as Sub\nimport Ipe.String as String\nimport Widgets\n\ntype Msg = Noop\n\ntype alias Model = { count : Int }\n\ninit : WebReq -> ( Model, Cmd.Cmd Msg )\ninit _req =\n    ( { count = 0 }, Cmd.none )\n\nupdate : Msg -> Model -> ( Model, Cmd.Cmd Msg )\nupdate msg model =\n    case msg of\n        Noop ->\n            ( model, Cmd.none )\n\nview : Model -> Element Msg\nview model =\n    Ui.column [] [ Ui.text (String.fromInt model.count) ]\n\nsubscriptions : Model -> Sub.Sub Msg\nsubscriptions _model =\n    Sub.none\n\nmain =\n    Web.tea\n        { init = init, update = update, view = view, subscriptions = subscriptions\n        , routes = [], notFound = Noop\n        }\n",
    )?;
    std::fs::write(dir.join("src/js/counter.js"), COUNTER_JS)?;

    let entry = dir.join("src/Main.ipe");
    let declared = BTreeSet::from([Capability::CustomElement]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "a handle constructed in an imported module must disclose `custom-element` transitively: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// The manifest-less single-file audit path (the `entry` alone, no `package.ipe`
/// up-tree) must disclose `custom-element` for a constructed-but-unmounted
/// `customElement` handle. This is the seam the run-jail resolver consumes via
/// [`ipe::run_sandbox::resolve_for_run`]; routing it through the
/// served-widget-aware inference keeps it consistent with `ipe capabilities` /
/// `package audit`. The `customElement "js/counter.js"` literal
/// resolves against the lone entry's own directory, so the JS sits beside it.
#[test]
fn a_manifest_less_single_file_handle_discloses_custom_element() -> TestResult {
    let dir = crate::support::scratch_root().join(format!(
        "ipe-ce-singlefile-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("js"))?;
    std::fs::write(dir.join("Main.ipe"), UNMOUNTED_WIDGET_APP)?;
    std::fs::write(dir.join("js/counter.js"), COUNTER_JS)?;

    let entry = dir.join("Main.ipe");
    let resolved = ipe::run_sandbox::resolve_for_run(None, None, &entry)?;
    assert!(
        resolved.inferred.contains(&Capability::CustomElement),
        "a manifest-less single file that constructs a served widget handle must \
         disclose `custom-element` from the single-file audit path, got: {:?}",
        resolved.inferred
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ── the `js-port` disclosure axis ───────────────────────────────────────────

/// A Web-shape app that reaches a `Js.send` / `Js.subscribe` port exchanges raw
/// typed values with page JavaScript, so its inferred capability set must contain
/// `js-port`. A port program discloses the same way a widget program discloses
/// `custom-element`: through the `verify_capabilities` inference `ipe
/// capabilities` reports.
const JS_PORT_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
import Ipe.Ffi.Js as Js
import Ipe.Json.Decode as Decode

type alias Model = { n : Int }

type Msg = Tick | Got Int

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _r =
    ( { n = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        Tick ->
            ( model, Js.send model.n )

        Got k ->
            ( { n = k }, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Js.subscribe Decode.int Got

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Tick
        }
"#;

/// Write [`JS_PORT_APP`] as a manifest-less single file and return its dir.
fn js_port_project(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = crate::support::scratch_root().join(format!(
        "ipe-jsport-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("Main.ipe"), JS_PORT_APP)?;
    Ok(dir)
}

/// A hand-rolled port program's inferred set is exactly `{js-port:raw}`: the raw
/// `Js.send`/`Js.subscribe` kernels disclose the uncharacterised `:raw` floor
/// (no `Ipe.Browser.<Api>` import characterises the axis). Declaring that set
/// must verify.
#[test]
fn a_port_program_discloses_js_port() -> TestResult {
    let dir = js_port_project("infer")?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([Capability::JsPort(WebCapability::Raw)]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "a hand-rolled port program's inferred set is exactly {{js-port:raw}}: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ── the per-capability `js-port:<axis>` web disclosure ──────────────────────

/// A Web-shape app importing the reserved `Ipe.Browser.Clipboard` module — the
/// import-derived signal that discloses the SPECIFIC `js-port:clipboard` axis, on
/// top of the raw `:raw` floor `Js.send` tags.
const CLIPBOARD_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
import Ipe.Browser.Clipboard as Clipboard

type alias Model = { n : Int }

type Msg = Copy

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _r =
    ( { n = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update _msg model =
    ( model, Clipboard.write "hello" )

view : Model -> Element Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Copy
        }
"#;

/// Importing `Ipe.Browser.Clipboard` discloses the specific `js-port:clipboard`
/// web axis. This is the whole import-derived mechanism end-to-end through the
/// real pipeline: the reserved module → the `for_browser_module` table → the
/// whole-program scan. A transitive-through-injection disclosure (the Clipboard
/// module is injected as a dep of the entry, so its axis reaches the entry's
/// linked set) pins MUST-FIX #1's link-fold at the CLI level.
#[test]
fn importing_browser_clipboard_discloses_js_port_clipboard() -> TestResult {
    let dir = crate::support::scratch_root().join(format!(
        "ipe-clip-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("Main.ipe"), CLIPBOARD_APP)?;
    let entry = dir.join("Main.ipe");
    // The `:clipboard` characterised axis AND the `:raw` kernel floor (the
    // `Clipboard.write` body reaches `Js.send`) are both disclosed.
    let declared = BTreeSet::from([
        Capability::JsPort(WebCapability::Clipboard),
        Capability::JsPort(WebCapability::Raw),
    ]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "importing Ipe.Browser.Clipboard must disclose js-port:clipboard (+ the :raw floor): {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// MUST-FIX #1, airtight: a dep-of-dep browser import reaches the linked entry's
/// set. `Main` imports a local `Widget` that itself imports
/// `Ipe.Browser.Clipboard`; `Main` never names the browser module. The link-fold
/// must still carry `Widget`'s disclosure into the whole-program inferred set.
#[test]
fn a_transitive_browser_import_reaches_the_linked_set() -> TestResult {
    let dir = crate::support::scratch_root().join(format!(
        "ipe-cliptrans-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    // `Widget` is the intermediate dep: it imports the browser module and re-exposes
    // a plain helper. `Main` imports only `Widget`, never the browser module.
    std::fs::write(
        dir.join("Widget.ipe"),
        "module Widget exposing (copy)\n\
         import Ipe.Browser.Clipboard as Clipboard\n\
         copy : String -> Cmd msg\n\
         copy s =\n    Clipboard.write s\n",
    )?;
    std::fs::write(
        dir.join("Main.ipe"),
        "module Main exposing (main)\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\
         import Ipe.Ui as Ui\n\
         import Widget\n\
         type alias Model = { n : Int }\n\
         type Msg = Copy\n\
         init : WebReq -> ( Model, Cmd.Cmd Msg )\n\
         init _r =\n    ( { n = 0 }, Cmd.none )\n\
         update : Msg -> Model -> ( Model, Cmd.Cmd Msg )\n\
         update _msg model =\n    ( model, Widget.copy \"x\" )\n\
         view : Model -> Element Msg\n\
         view _model =\n    Ui.text \"ok\"\n\
         subscriptions : Model -> Sub.Sub Msg\n\
         subscriptions _model =\n    Sub.none\n\
         main =\n    Web.tea\n        { init = init, update = update, view = view, subscriptions = subscriptions\n        , routes = [], notFound = Copy\n        }\n",
    )?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([
        Capability::JsPort(WebCapability::Clipboard),
        Capability::JsPort(WebCapability::Raw),
    ]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "a dep-of-dep Ipe.Browser.Clipboard import must reach the linked entry's set (MUST-FIX #1): {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// The consent gate refuses an ungranted disclosed axis naming the module, and
/// admits it once granted — the app-boundary consent mechanism, exercised through
/// `web_consent::gate` over the real inferred set.
#[test]
fn web_consent_refuses_ungranted_clipboard_then_admits_it() {
    use ipe::web_consent;
    let inferred = BTreeSet::from([Capability::JsPort(WebCapability::Clipboard)]);
    let provenance = web_consent::WebAxisProvenance::from_sources([(
        "Main",
        "import Ipe.Browser.Clipboard as Clipboard\n",
    )]);
    // Ungranted → fail closed, naming the disclosing module.
    let ungranted = web_consent::gate(&inferred, &BTreeSet::new(), &provenance)
        .expect_err("an ungranted web axis is refused");
    let msg = ungranted.to_string();
    assert!(msg.contains("js-port:clipboard"), "names the axis: {msg}");
    assert!(msg.contains("Main"), "names the disclosing module: {msg}");
    // Granted → proceeds.
    let granted = BTreeSet::from([Capability::JsPort(WebCapability::Clipboard)]);
    web_consent::gate(&inferred, &granted, &provenance).expect("a granted web axis builds");
}

/// Fail-closed: a program that reaches a port but declares NOTHING on the
/// `js-port` axis is rejected as under-declared — a port-bearing module can never
/// hide the disclosure.
#[test]
fn a_port_program_that_hides_js_port_is_rejected() -> TestResult {
    let dir = js_port_project("hide")?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::new();
    let r = verify_capabilities(&entry, &declared);
    assert!(
        matches!(
            &r,
            Err(ipe::CliError::CapabilityMismatch { missing, .. })
                if missing.contains(&"js-port:raw")
        ),
        "a port program that omits `js-port:raw` must be rejected as under-declared, got: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ── Ipe.Browser.Geolocation — the second first-party web-API module ─────────

/// A Web-shape app importing `Ipe.Browser.Geolocation` — the import-derived signal
/// that discloses the SPECIFIC `js-port:geolocation` axis on top of the `:raw`
/// floor the underlying `Js.send`/`Js.subscribe` tag.
const GEOLOCATION_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
import Ipe.Error as Error exposing (Error)
import Ipe.Browser.Geolocation as Geo
import Ipe.Task as Task

type alias Model = { where_ : String }

type Msg = Locate | Got (Result Error Geo.Coords)

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _r =
    ( { where_ = "?" }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        Locate ->
            ( model, Task.attempt Got Geo.current )

        Got _r ->
            ( model, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Geo.positions Got

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Locate
        }
"#;

fn write_single(tag: &str, src: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = crate::support::scratch_root().join(format!(
        "ipe-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("Main.ipe"), src)?;
    Ok(dir)
}

/// Importing `Ipe.Browser.Geolocation` discloses the specific `js-port:geolocation`
/// axis — the whole import-derived mechanism through the real pipeline, mirroring
/// the shipped Clipboard proof for the second web-API module.
#[test]
fn importing_browser_geolocation_discloses_js_port_geolocation() -> TestResult {
    let dir = write_single("geo", GEOLOCATION_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([
        Capability::JsPort(WebCapability::Geolocation),
        Capability::JsPort(WebCapability::Raw),
    ]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "importing Ipe.Browser.Geolocation must disclose js-port:geolocation (+ the :raw floor): {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// The prefix disclosure key closes the low-level submodule hole: importing the
/// `Ipe.Browser.Geolocation.Internals` submodule discloses the SAME
/// `js-port:geolocation` axis as the top-level module, so the full option surface
/// cannot be reached undisclosed.
const GEOLOCATION_INTERNALS_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
import Ipe.Browser.Geolocation.Internals as Geo

type alias Model = { n : Int }

type Msg = Poke

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _r =
    ( { n = 0 }, Geo.request (Geo.Current Geo.defaults) )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update _msg model =
    ( model, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Poke
        }
"#;

#[test]
fn importing_geolocation_internals_discloses_the_same_axis() -> TestResult {
    let dir = write_single("geointernals", GEOLOCATION_INTERNALS_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([
        Capability::JsPort(WebCapability::Geolocation),
        Capability::JsPort(WebCapability::Raw),
    ]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "importing the Internals submodule must disclose js-port:geolocation (prefix key): {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Fail-closed: a geolocation app that omits the grant is rejected as
/// under-declared, the axis named — the negative half of the consent gate.
#[test]
fn a_geolocation_app_without_the_grant_is_rejected() -> TestResult {
    let dir = write_single("geonogrant", GEOLOCATION_APP)?;
    let entry = dir.join("Main.ipe");
    // Grant only the raw floor, not the geolocation axis.
    let declared = BTreeSet::from([Capability::JsPort(WebCapability::Raw)]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        matches!(
            &r,
            Err(ipe::CliError::CapabilityMismatch { missing, .. })
                if missing.contains(&"js-port:geolocation")
        ),
        "an ungranted geolocation app must be rejected naming js-port:geolocation, got: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// The `web_consent::gate` refuses an ungranted geolocation axis naming the module
/// and admits it once granted — the app-boundary consent mechanism over the second
/// web-API module.
#[test]
fn web_consent_refuses_ungranted_geolocation_then_admits_it() {
    use ipe::web_consent;
    let inferred = BTreeSet::from([Capability::JsPort(WebCapability::Geolocation)]);
    let provenance = web_consent::WebAxisProvenance::from_sources([(
        "Main",
        "import Ipe.Browser.Geolocation as Geo\n",
    )]);
    let ungranted = web_consent::gate(&inferred, &BTreeSet::new(), &provenance)
        .expect_err("an ungranted web axis is refused");
    let msg = ungranted.to_string();
    assert!(msg.contains("js-port:geolocation"), "names the axis: {msg}");
    assert!(msg.contains("Main"), "names the disclosing module: {msg}");
    let granted = BTreeSet::from([Capability::JsPort(WebCapability::Geolocation)]);
    web_consent::gate(&inferred, &granted, &provenance).expect("a granted web axis builds");
}

// ── Ipe.Browser.Notification — a first-party web-API module ──────────────────

/// A Web-shape app importing `Ipe.Browser.Notification` — the import-derived signal
/// that discloses the SPECIFIC `js-port:notification` axis on top of the `:raw`
/// floor the underlying `Js.send` / `Js.subscribe` tag.
const NOTIFICATION_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
import Ipe.Error as Error exposing (Error)
import Ipe.Browser.Notification as Note
import Ipe.Task as Task

type alias Model = { n : Int }

type Msg = Ask | Asked (Result Error ()) | Fired (Result Error ())

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _r =
    ( { n = 0 }, Task.attempt Asked Note.requestPermission )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        Ask ->
            ( model, Note.notify "hi" )

        Asked _r ->
            ( model, Cmd.none )

        Fired _r ->
            ( model, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Note.outcomes Fired

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Ask
        }
"#;

/// Importing `Ipe.Browser.Notification` discloses the specific `js-port:notification`
/// axis — the whole import-derived mechanism through the real pipeline.
#[test]
fn importing_browser_notification_discloses_js_port_notification() -> TestResult {
    let dir = write_single("note", NOTIFICATION_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([
        Capability::JsPort(WebCapability::Notification),
        Capability::JsPort(WebCapability::Raw),
    ]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "importing Ipe.Browser.Notification must disclose js-port:notification (+ the :raw floor): {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Fail-closed: a notification app that omits the grant is rejected as
/// under-declared, the axis named — the negative half of the consent gate.
#[test]
fn a_notification_app_without_the_grant_is_rejected() -> TestResult {
    let dir = write_single("notenogrant", NOTIFICATION_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([Capability::JsPort(WebCapability::Raw)]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        matches!(
            &r,
            Err(ipe::CliError::CapabilityMismatch { missing, .. })
                if missing.contains(&"js-port:notification")
        ),
        "an ungranted notification app must be rejected naming js-port:notification, got: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ── Ipe.Browser.Storage — a first-party web-API module ──────────────────────

/// A Web-shape app importing `Ipe.Browser.Storage` — the import-derived signal
/// that discloses the SPECIFIC `js-port:storage` axis on top of the `:raw` floor.
const STORAGE_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
import Ipe.Error as Error exposing (Error)
import Ipe.Browser.Storage as Storage
import Ipe.Task as Task

type alias Model = { v : Maybe String }

type Msg = Save | Load | Loaded (Result Error (Maybe String)) | Changed (Result Error (Maybe String))

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _r =
    ( { v = Nothing }, Storage.set "k" "v" )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        Save ->
            ( model, Storage.set "k" "v" )

        Load ->
            ( model, Task.attempt Loaded (Storage.get "k") )

        Loaded _r ->
            ( model, Cmd.none )

        Changed _r ->
            ( model, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Storage.changes Changed

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Load
        }
"#;

/// Importing `Ipe.Browser.Storage` discloses the specific `js-port:storage` axis.
#[test]
fn importing_browser_storage_discloses_js_port_storage() -> TestResult {
    let dir = write_single("storage", STORAGE_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([
        Capability::JsPort(WebCapability::Storage),
        Capability::JsPort(WebCapability::Raw),
    ]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "importing Ipe.Browser.Storage must disclose js-port:storage (+ the :raw floor): {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Fail-closed: a storage app that omits the grant is rejected as under-declared.
#[test]
fn a_storage_app_without_the_grant_is_rejected() -> TestResult {
    let dir = write_single("storagenogrant", STORAGE_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([Capability::JsPort(WebCapability::Raw)]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        matches!(
            &r,
            Err(ipe::CliError::CapabilityMismatch { missing, .. })
                if missing.contains(&"js-port:storage")
        ),
        "an ungranted storage app must be rejected naming js-port:storage, got: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ── Ipe.Browser.Vibration — a first-party web-API module ────────────────────

/// A Web-shape app importing `Ipe.Browser.Vibration` — the import-derived signal
/// that discloses the SPECIFIC `js-port:vibration` axis on top of the `:raw` floor.
const VIBRATION_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
import Ipe.Error as Error exposing (Error)
import Ipe.Browser.Vibration as Vib

type alias Model = { n : Int }

type Msg = Buzz | Acked (Result Error ())

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _r =
    ( { n = 0 }, Vib.vibrate 200 )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        Buzz ->
            ( model, Vib.pattern [ 100, 50, 100 ] )

        Acked _r ->
            ( model, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Vib.acknowledgements Acked

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Buzz
        }
"#;

/// Importing `Ipe.Browser.Vibration` discloses the specific `js-port:vibration` axis.
#[test]
fn importing_browser_vibration_discloses_js_port_vibration() -> TestResult {
    let dir = write_single("vib", VIBRATION_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([
        Capability::JsPort(WebCapability::Vibration),
        Capability::JsPort(WebCapability::Raw),
    ]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "importing Ipe.Browser.Vibration must disclose js-port:vibration (+ the :raw floor): {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Fail-closed: a vibration app that omits the grant is rejected as under-declared.
#[test]
fn a_vibration_app_without_the_grant_is_rejected() -> TestResult {
    let dir = write_single("vibnogrant", VIBRATION_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([Capability::JsPort(WebCapability::Raw)]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        matches!(
            &r,
            Err(ipe::CliError::CapabilityMismatch { missing, .. })
                if missing.contains(&"js-port:vibration")
        ),
        "an ungranted vibration app must be rejected naming js-port:vibration, got: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ── Ipe.Browser.Share — a first-party web-API module ────────────────────────

/// A Web-shape app importing `Ipe.Browser.Share` — the import-derived signal that
/// discloses the SPECIFIC `js-port:share` axis on top of the `:raw` floor.
const SHARE_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
import Ipe.Error as Error exposing (Error)
import Ipe.Browser.Share as Share
import Ipe.Maybe exposing (Maybe(..))
import Ipe.Result as Result exposing (Result(..))
import Ipe.Task as Task
import Ipe.Url as Url

type alias Model = { n : Int }

type Msg = Send | Sent (Result Error ()) | Outcome (Result Error ())

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _r =
    ( { n = 0 }, Cmd.none )

shareCmd : Cmd.Cmd Msg
shareCmd =
    case Result.andThen Share.shareUrl (Url.fromString "https://e.com") of
        Ok u ->
            Task.attempt Sent (Share.share { title = "t", text = "x", url = Just u })

        Err _ ->
            Cmd.none

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        Send ->
            ( model, shareCmd )

        Sent _r ->
            ( model, Cmd.none )

        Outcome _r ->
            ( model, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Share.outcomes Outcome

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Send
        }
"#;

/// Importing `Ipe.Browser.Share` discloses the specific `js-port:share` axis.
#[test]
fn importing_browser_share_discloses_js_port_share() -> TestResult {
    let dir = write_single("share", SHARE_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([
        Capability::JsPort(WebCapability::Share),
        Capability::JsPort(WebCapability::Raw),
    ]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "importing Ipe.Browser.Share must disclose js-port:share (+ the :raw floor): {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Fail-closed: a share app that omits the grant is rejected as under-declared.
#[test]
fn a_share_app_without_the_grant_is_rejected() -> TestResult {
    let dir = write_single("sharenogrant", SHARE_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([Capability::JsPort(WebCapability::Raw)]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        matches!(
            &r,
            Err(ipe::CliError::CapabilityMismatch { missing, .. })
                if missing.contains(&"js-port:share")
        ),
        "an ungranted share app must be rejected naming js-port:share, got: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ── Ipe.Browser.Battery — a first-party web-API module ──────────────────────

/// A Web-shape app importing `Ipe.Browser.Battery` — the import-derived signal that
/// discloses the SPECIFIC `js-port:battery` axis on top of the `:raw` floor.
const BATTERY_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
import Ipe.Error as Error exposing (Error)
import Ipe.Browser.Battery as Battery
import Ipe.Task as Task

type alias Model = { charging : Bool }

type Msg = Check | Got (Result Error Battery.Status) | Reading (Result Error Battery.Status)

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _r =
    ( { charging = False }, Task.attempt Got Battery.status )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        Check ->
            ( model, Battery.watch )

        Got _r ->
            ( model, Cmd.none )

        Reading _r ->
            ( model, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Battery.readings Reading

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Check
        }
"#;

/// Importing `Ipe.Browser.Battery` discloses the specific `js-port:battery` axis.
#[test]
fn importing_browser_battery_discloses_js_port_battery() -> TestResult {
    let dir = write_single("battery", BATTERY_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([
        Capability::JsPort(WebCapability::Battery),
        Capability::JsPort(WebCapability::Raw),
    ]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "importing Ipe.Browser.Battery must disclose js-port:battery (+ the :raw floor): {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Fail-closed: a battery app that omits the grant is rejected as under-declared.
#[test]
fn a_battery_app_without_the_grant_is_rejected() -> TestResult {
    let dir = write_single("batterynogrant", BATTERY_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([Capability::JsPort(WebCapability::Raw)]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        matches!(
            &r,
            Err(ipe::CliError::CapabilityMismatch { missing, .. })
                if missing.contains(&"js-port:battery")
        ),
        "an ungranted battery app must be rejected naming js-port:battery, got: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ── Ipe.Browser.NetworkInfo — a first-party web-API module ──────────────────

/// A Web-shape app importing `Ipe.Browser.NetworkInfo` — the import-derived signal
/// that discloses the SPECIFIC `js-port:network-info` axis on top of the `:raw` floor.
const NETWORK_INFO_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
import Ipe.Error as Error exposing (Error)
import Ipe.Browser.NetworkInfo as Net
import Ipe.Task as Task

type alias Model = { kind : String }

type Msg = Check | Got (Result Error Net.Info) | Changed (Result Error Net.Info)

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _r =
    ( { kind = "?" }, Task.attempt Got Net.info )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        Check ->
            ( model, Net.watch )

        Got _r ->
            ( model, Cmd.none )

        Changed _r ->
            ( model, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Net.changes Changed

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Check
        }
"#;

/// Importing `Ipe.Browser.NetworkInfo` discloses the specific `js-port:network-info`
/// axis.
#[test]
fn importing_browser_network_info_discloses_js_port_network_info() -> TestResult {
    let dir = write_single("netinfo", NETWORK_INFO_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([
        Capability::JsPort(WebCapability::NetworkInfo),
        Capability::JsPort(WebCapability::Raw),
    ]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "importing Ipe.Browser.NetworkInfo must disclose js-port:network-info (+ the :raw floor): {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Fail-closed: a network-info app that omits the grant is rejected as under-declared.
#[test]
fn a_network_info_app_without_the_grant_is_rejected() -> TestResult {
    let dir = write_single("netinfonogrant", NETWORK_INFO_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([Capability::JsPort(WebCapability::Raw)]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        matches!(
            &r,
            Err(ipe::CliError::CapabilityMismatch { missing, .. })
                if missing.contains(&"js-port:network-info")
        ),
        "an ungranted network-info app must be rejected naming js-port:network-info, got: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ── Ipe.Browser.FilePicker — a first-party web-API module ────────────────────

/// A Web-shape app importing `Ipe.Browser.FilePicker` — the import-derived signal
/// that discloses the SPECIFIC `js-port:file` axis on top of the `:raw` floor.
const FILE_PICKER_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
import Ipe.Error as Error exposing (Error)
import Ipe.Browser.FilePicker as FilePicker
import Ipe.Task as Task

type alias Model = { result : String }

type Msg = Pick | GotFile (Result Error FilePicker.PickedFile)

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _r =
    ( { result = "" }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        Pick ->
            ( model, Task.attempt GotFile FilePicker.pickFile )

        GotFile _r ->
            ( model, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    FilePicker.picks GotFile

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Pick
        }
"#;

/// Importing `Ipe.Browser.FilePicker` discloses the specific `js-port:file` axis.
#[test]
fn importing_browser_file_picker_discloses_js_port_file() -> TestResult {
    let dir = write_single("filepicker", FILE_PICKER_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([
        Capability::JsPort(WebCapability::File),
        Capability::JsPort(WebCapability::Raw),
    ]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "importing Ipe.Browser.FilePicker must disclose js-port:file (+ the :raw floor): {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Fail-closed: a file-picker app that omits the grant is rejected as under-declared.
#[test]
fn a_file_picker_app_without_the_grant_is_rejected() -> TestResult {
    let dir = write_single("filepickernogrant", FILE_PICKER_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([Capability::JsPort(WebCapability::Raw)]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        matches!(
            &r,
            Err(ipe::CliError::CapabilityMismatch { missing, .. })
                if missing.contains(&"js-port:file")
        ),
        "an ungranted file-picker app must be rejected naming js-port:file, got: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ── Ipe.Browser.Camera — a first-party web-API module ────────────────────────

/// A Web-shape app importing `Ipe.Browser.Camera` — the import-derived signal
/// that discloses the SPECIFIC `js-port:camera` axis on top of the `:raw` floor.
const CAMERA_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
import Ipe.Error as Error exposing (Error)
import Ipe.Browser.Camera as Camera
import Ipe.Task as Task

type alias Model = { result : String }

type Msg = Capture | GotPhoto (Result Error Camera.PickedFile)

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _r =
    ( { result = "" }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        Capture ->
            ( model, Task.attempt GotPhoto Camera.capturePhoto )

        GotPhoto _r ->
            ( model, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Camera.captures GotPhoto

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Capture
        }
"#;

/// Importing `Ipe.Browser.Camera` discloses the specific `js-port:camera` axis.
#[test]
fn importing_browser_camera_discloses_js_port_camera() -> TestResult {
    let dir = write_single("camera", CAMERA_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([
        Capability::JsPort(WebCapability::Camera),
        Capability::JsPort(WebCapability::Raw),
    ]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "importing Ipe.Browser.Camera must disclose js-port:camera (+ the :raw floor): {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Fail-closed: a camera app that omits the grant is rejected as under-declared.
#[test]
fn a_camera_app_without_the_grant_is_rejected() -> TestResult {
    let dir = write_single("cameranogrant", CAMERA_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([Capability::JsPort(WebCapability::Raw)]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        matches!(
            &r,
            Err(ipe::CliError::CapabilityMismatch { missing, .. })
                if missing.contains(&"js-port:camera")
        ),
        "an ungranted camera app must be rejected naming js-port:camera, got: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ── Ipe.Browser.Microphone — a first-party web-API module ────────────────────

/// A Web-shape app importing `Ipe.Browser.Microphone` — the import-derived
/// signal that discloses the SPECIFIC `js-port:microphone` axis on top of the
/// `:raw` floor. The pinned refusal test (IPE-S0002) and the accepted-grant
/// path are both exercised.
const MICROPHONE_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
import Ipe.Error as Error exposing (Error)
import Ipe.Browser.Microphone as Microphone
import Ipe.Task as Task

type alias Model = { result : String }

type Msg = Record | GotClip (Result Error Microphone.AudioClip)

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _r =
    ( { result = "" }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        Record ->
            ( model
            , Task.attempt GotClip
                (Microphone.captureAudio { maxDurationMs = 3000, mimeType = "audio/webm" })
            )

        GotClip _r ->
            ( model, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Microphone.recordings GotClip

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Record
        }
"#;

/// Importing `Ipe.Browser.Microphone` discloses the specific `js-port:microphone`
/// axis (the import-derived mechanism, alias-immune).
#[test]
fn importing_browser_microphone_discloses_js_port_microphone() -> TestResult {
    let dir = write_single("microphone", MICROPHONE_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([
        Capability::JsPort(WebCapability::Microphone),
        Capability::JsPort(WebCapability::Raw),
    ]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "importing Ipe.Browser.Microphone must disclose js-port:microphone (+ the :raw floor): {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Fail-closed (IPE-S0002): a microphone app that omits the grant is rejected
/// as under-declared, naming `js-port:microphone` in the refusal.
#[test]
fn a_microphone_app_without_the_grant_is_rejected_ipe_s0002() -> TestResult {
    let dir = write_single("micnogrant", MICROPHONE_APP)?;
    let entry = dir.join("Main.ipe");
    // Granting only `:raw` (the kernel floor) is not enough — the specific
    // `js-port:microphone` axis must be accepted explicitly.
    let declared = BTreeSet::from([Capability::JsPort(WebCapability::Raw)]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        matches!(
            &r,
            Err(ipe::CliError::CapabilityMismatch { missing, .. })
                if missing.contains(&"js-port:microphone")
        ),
        "an ungranted microphone app must be rejected naming js-port:microphone (IPE-S0002), got: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ── Ipe.Browser.Gamepad — a first-party web-API module ────────────────────────

/// A Web-shape app importing `Ipe.Browser.Gamepad` — the import-derived signal
/// that discloses the SPECIFIC `js-port:gamepad` axis on top of the `:raw` floor.
/// Both the accepted-grant path and the IPE-S0002 refusal path are exercised.
const GAMEPAD_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
import Ipe.Browser.Gamepad as Gamepad

type alias Model = { info : String }

type Msg = StartWatch | GotEvent Gamepad.GamepadEvent

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _r =
    ( { info = "" }, Gamepad.watch )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        StartWatch ->
            ( model, Gamepad.watch )

        GotEvent _ev ->
            ( model, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Gamepad.events GotEvent

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = StartWatch
        }
"#;

/// Importing `Ipe.Browser.Gamepad` discloses the specific `js-port:gamepad` axis
/// (the import-derived mechanism, alias-immune).
#[test]
fn importing_browser_gamepad_discloses_js_port_gamepad() -> TestResult {
    let dir = write_single("gamepad", GAMEPAD_APP)?;
    let entry = dir.join("Main.ipe");
    let declared = BTreeSet::from([
        Capability::JsPort(WebCapability::Gamepad),
        Capability::JsPort(WebCapability::Raw),
    ]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        r.is_ok(),
        "importing Ipe.Browser.Gamepad must disclose js-port:gamepad (+ the :raw floor): {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Fail-closed (IPE-S0002): a gamepad app that omits the grant is rejected as
/// under-declared, naming `js-port:gamepad` in the refusal.
#[test]
fn a_gamepad_app_without_the_grant_is_rejected_ipe_s0002() -> TestResult {
    let dir = write_single("gamepadnogrant", GAMEPAD_APP)?;
    let entry = dir.join("Main.ipe");
    // Granting only `:raw` (the kernel floor) is not enough — the specific
    // `js-port:gamepad` axis must be accepted explicitly.
    let declared = BTreeSet::from([Capability::JsPort(WebCapability::Raw)]);
    let r = verify_capabilities(&entry, &declared);
    assert!(
        matches!(
            &r,
            Err(ipe::CliError::CapabilityMismatch { missing, .. })
                if missing.contains(&"js-port:gamepad")
        ),
        "an ungranted gamepad app must be rejected naming js-port:gamepad (IPE-S0002), got: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

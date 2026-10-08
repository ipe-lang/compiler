//! Honest end-to-end tests for `Ipe.Web` / `Ipe.Web` — `Web.tea`, `Ui.layout`,
//! `Ui.column`, `Ui.el`, `Ui.onClick`, `Ui.text`, and `String.fromInt`.
//!
//! All tests are gated on `IPE_E2E=1`.  Without it they return early so the
//! default `cargo test` stays fast.
//!
//! ## Architecture
//!
//! 1. A minimal Ipe.Web counter program is written to a temp dir.
//! 2. `ipe::build_with_options` compiles it with the dev-loop intent
//!    (parse → canon → types → lower → emit Rust).
//! 3. `e2e_support::build_rust_binary` runs `cargo build` on the emitted project —
//!    the shared Cargo target (`~/.cargo/config.toml`) lets axum/tokio/serde
//!    compile once and be reused.
//! 4. An ephemeral TCP port is reserved via `TcpListener::bind("0")` → drop.
//! 5. The binary is spawned with `IPE_WEB_PORT=<port>` and `IPE_CSRF=off`.
//!    `IPE_CSRF=off` disables the double-submit cookie check so test GETs
//!    exercise the full page render without cookie plumbing.
//! 6. Readiness: reads the child's stderr until `[ipe.web] listening on`.
//! 7. `GET /` is sent via raw `TcpStream`; the response body must contain
//!    the initial counter value rendered as `>0<`, proving the full Live
//!    pipeline ran:
//!    `web_app → init → view → render_page → HTML served`.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test live_e2e
//! ```
//!
//! ## SEAL tiering (three-way split)
//!
//! Each live-server guarantee is proved by three tiers, so no single test has to
//! pay for all of them:
//!   1. compile-proof — the `*_build_only` tests here run the real `ipe` + `cargo
//!      build` and are the accept ⇒ build half of THE SEAL;
//!   2. in-process behavior — `ipe_runtime::web`'s `emitted_router_behavior_tests`
//!      drive the SAME fully-layered production router
//!      (`build_web_router`) via `tower::ServiceExt::oneshot` and carry the
//!      behavioral asserts (`>0<`, click→`>1<`, SSE `data-ipe-hid`, typed-record
//!      submit→decoded record) with no socket, subprocess, or cold build;
//!   3. socket smoke — `live_get_root_contains_initial_count` keeps ONE real
//!      bind+serve+request per transport, proving the listener path oneshot skips.
//!
//! The remaining socket-driven behavior tests below stay for now (belt-and-braces
//! coverage) pending the guardian-reviewed narrowing tracked in #2134.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Shared error type for E2E helpers.
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

// ── Ipê program ───────────────────────────────────────────────────────────────

/// A minimal Ipe.Web counter app.
///
/// Kernels exercised:
/// - `Web.tea`     — constrain scheme + serde derives
/// - `Ui.layout`    — converts Element tree to HTML
/// - `Ui.column`    — vertical layout
/// - `Ui.el`        — generic element container with onClick attribute
/// - `Ui.onClick`   — binds a click event to a Msg
/// - `Ui.text`      — text leaf node
/// - `String.fromInt` — displays the counter value
/// - `Cmd.none` / `Sub.none` — baseline TEA primitives
///
/// The rendered initial page will contain the text `>0<` (the counter starts at
/// zero, rendered inside a text element).  No `Ui.button` is used because that
/// function is not a raw kernel — it is defined in ipe-stdlib as a Ipê function.
const IPE_LIVE_COUNTER: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
import Ipe.String

type Msg = Increment | Decrement

type alias Model = { count : Int }

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

htmlView : Model -> Html Msg
htmlView model =
    Ui.layout []
        (Ui.column []
            [ Ui.el [ Ui.onClick Increment ] (Ui.text "+")
            , Ui.text (String.fromInt model.count)
            , Ui.el [ Ui.onClick Decrement ] (Ui.text "-")
            ])

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

view : Model -> Element Msg
view model =
    Ui.html (htmlView model)

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

/// Serde-derive gating seal: a `Ipe.Web` program with a NON-Model view-helper
/// record that holds an `Html` field (`Section = { title : String, body : Html
/// Msg }`) and a plain-data Model.
///
/// `Section` is `CDPeq`-supporting (`Html<Msg>` derives Clone/Debug/PartialEq) but
/// NOT serde-supporting. The emitter gates the serde derive on the per-record
/// serde flag, not the `CDPeq` flag — gating it on `CDPeq` would force
/// `#[derive(..., serde::Serialize, serde::Deserialize)]` onto `Section` under
/// `uses_web` → `ipe` exit 0 then `cargo build` E0277 (`Html<MainMsg>:
/// Serialize` unsatisfied). So `Section` keeps its `CDPeq` derive WITHOUT serde
/// and the project is cargo-buildable. The Model (`{ count : Int }`)
/// is plain data and still gets serde. The Model-admissibility gate is NOT
/// tripped because the non-serde record is a view helper, not the Model.
const IPE_LIVE_HTML_HELPER: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
import Ipe.String

type Msg = Increment | Decrement

type alias Model = { count : Int }

type alias Section = { title : String, body : Html Msg }

renderSection : Section -> Element Msg
renderSection section =
    Ui.column [] [ Ui.text section.title, Ui.html section.body ]

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

htmlView : Model -> Html Msg
htmlView model =
    Ui.layout []
        (renderSection { title = "Count", body = Ui.layout [] (Ui.text (String.fromInt model.count)) })

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

view : Model -> Element Msg
view model =
    Ui.html (htmlView model)

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

/// Inline-lambda subscriptions seal — BUILD-ONLY: a routed `Ipe.Web` app whose
/// `subscriptions` cfg field is an INLINE LAMBDA (`\_ -> Sub.none`) rather than
/// a top-level `fn` reference must compile end-to-end.
///
/// `web_app_routed`'s four function slots (`FInit`/`FUpdate`/`FView`/`FSubs`)
/// are GENERIC type params bounded `Fn(..) -> R + Send + Sync + 'static`. A
/// top-level `subscriptions` reference emits as a bare `fn` item (implicitly
/// `Send + Sync`). An inline lambda emitted through the general `emit_expr_at`
/// path as `Box<dyn Fn(..) -> R + Send + 'static>` — a trait object that
/// carries `Send` but NOT `Sync` — would fail the slot's `Sync` bound: `ipe`
/// exit 0 then `cargo build` E0277 (`dyn Fn(..) -> IpeSub<Msg> + Send cannot be
/// shared between threads safely`).
///
/// So an inline-lambda live-cfg callback is emitted UNBOXED (`move |_| -> R
/// { .. }`), so rustc monomorphizes the generic slot to the concrete closure
/// type whose auto-derived `Send + Sync` satisfies the bound — the same shape
/// the sibling `set_page` and `Route::new` builder closures use.
///
/// A successful `ipe` + `cargo build` IS the assertion.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
const IPE_LIVE_LAMBDA_SUBS: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
import Ipe.String

type Msg = Increment | Decrement

type Page = HomePage

type alias Model = { count : Int, page : Page }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0, page = HomePage }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )
        Decrement ->
            ( { model | count = model.count - 1 }, Cmd.none )

htmlView : Model -> Html Msg
htmlView model =
    Ui.layout []
        (Ui.column []
            [ Ui.el [ Ui.onClick Increment ] (Ui.text "+")
            , Ui.text (String.fromInt model.count)
            ])

view : Model -> Element Msg
view model =
    Ui.html (htmlView model)

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = \_ -> Sub.none
        , routes = [ Web.route "/" HomePage ]
        , notFound = HomePage
        }
"#;

/// A routed Ipe.Web app: two pages, nullary page ctors, `routes`/`notFound`
/// supplied. The Model carries a `page` field → `emit_web_app_inner` takes
/// the T5 routed branch and emits `web_app_routed` instead of `web_app`.
///
/// Exercises the full T5 emit path through the compiler:
/// - open-record unification of the 6-field `Web.tea` cfg (T2/T3)
/// - `routed_page_field` detection in `emit_web_app_inner` (T5)
/// - `set_page` closure generation (T5)
/// - `web_app_routed` runtime entry (already ported in `runtime/`)
///
/// This is the same structure as `examples/09-live-counter/src/Main.ipe`.
const IPE_LIVE_ROUTED: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
import Ipe.String

type Page
    = CounterPage
    | AboutPage

type Msg = Increment | GoAbout | GoCounter

type alias Model =
    { page : Page
    , count : Int
    }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { page = CounterPage, count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )
        GoAbout ->
            ( { model | page = AboutPage }, Cmd.none )
        GoCounter ->
            ( { model | page = CounterPage }, Cmd.none )

htmlView : Model -> Html Msg
htmlView model =
    Ui.layout []
        (Ui.column []
            [ Ui.text (String.fromInt model.count)
            , Ui.el [ Ui.onClick Increment ] (Ui.text "+")
            ])

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

view : Model -> Element Msg
view model =
    Ui.html (htmlView model)

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = [ Web.route "/" CounterPage, Web.route "/about" AboutPage ]
        , notFound = CounterPage
        }
"#;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// The `ipe dev build` dev-loop intent: these fixtures exercise the dev posture
/// (plain cookie names, loopback upstreams), which a release binary refuses.
fn dev_loop_options() -> ipe::BuildOptions {
    ipe::BuildOptions {
        intent: ipe_backend_rust::BuildIntent::Development,
        ..ipe::BuildOptions::from_env()
    }
}

/// Compile a Ipê program string, build the emitted Rust project, and return
/// the path to the compiled binary.
///
/// # Errors
///
/// Returns an error on any pipeline or Cargo build failure.
fn compile_and_build(test_name: &str, ipe_source: &str) -> Result<PathBuf, BoxError> {
    let ipe_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("live_e2e_{test_name}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(&ipe_dir).map_err(|e| -> BoxError {
        format!("{test_name}: cannot create ipe source dir: {e}").into()
    })?;

    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, ipe_source)
        .map_err(|e| -> BoxError { format!("{test_name}: cannot write Main.ipe: {e}").into() })?;

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("live_e2e_{test_name}_emitted"));
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();

    ipe::build_with_options(&entry, &out_dir, &runtime, dev_loop_options())
        .map_err(|e| -> BoxError { format!("{test_name}: ipe dev build failed: {e}").into() })?;

    let exe = e2e_support::build_rust_binary(test_name, &out_dir)
        .map_err(|e| -> BoxError { format!("{test_name}: cargo build failed: {e}").into() })?;

    Ok(PathBuf::from(exe))
}

/// Reserve an ephemeral loopback port by binding then immediately dropping a
/// `TcpListener`.  The OS assigns port 0 → an unused port.
///
/// There is a small TOCTOU window between the drop and the Ipê server binding
/// the same port; in practice the window is negligible on a loopback test.
///
/// # Errors
///
/// Returns an error if the OS refuses to bind.
fn pick_ephemeral_port() -> Result<u16, BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| -> BoxError { format!("cannot bind ephemeral port: {e}").into() })?;
    let port = listener
        .local_addr()
        .map_err(|e| -> BoxError { format!("cannot read ephemeral port: {e}").into() })?
        .port();
    // Drop `listener` here — releases the port for the Ipê Web server.
    Ok(port)
}

/// RAII guard: kills the wrapped child process on `Drop`.
struct ProcessGuard(Child);

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// How a spawned app binary learns its port and announces readiness.
struct Launch<'a> {
    /// The env var the binary reads its port from.
    port_var: &'a str,
    /// The stderr text the binary prints once its listener is bound.
    ready_marker: &'a str,
    /// Env vars set on the child after the defaults.
    extra_env: &'a [(&'a str, &'a str)],
}

/// A standalone `Web.tea` app: `IPE_WEB_PORT` and the `[ipe.web]` banner.
const WEB_LAUNCH: Launch<'static> = Launch {
    port_var: "IPE_WEB_PORT",
    ready_marker: "[ipe.web] listening on",
    extra_env: &[],
};

/// Env vars that set a revocation or session-store posture.
///
/// The spawner clears them so a test's posture comes only from its own
/// `extra_env`, never from the environment the test runner inherited.
const POSTURE_ENV: [&str; 5] = [
    "IPE_AUTH_REVOCATION",
    "IPE_AUTH_MAX_LIFETIME",
    "IPE_AUTH_SLIDE_WINDOW",
    "IPE_WEB_STORE",
    "IPE_WEB_STORE_PATH",
];

/// Spawn the Ipê Live binary and wait until it signals readiness via
/// `[ipe.web] listening on` on stderr.
///
/// # Errors
///
/// Returns an error if the binary cannot be spawned or the ready signal does
/// not appear within 10 s.
fn spawn_and_wait_ready(
    test_name: &str,
    exe: &std::path::Path,
    port: u16,
) -> Result<ProcessGuard, BoxError> {
    spawn_ready_with(test_name, exe, port, &WEB_LAUNCH)
}

/// Spawn an app binary under `launch` and wait for its ready banner.
///
/// # Errors
///
/// Returns an error if the binary cannot be spawned or the ready signal does
/// not appear within 10 s.
fn spawn_ready_with(
    test_name: &str,
    exe: &std::path::Path,
    port: u16,
    launch: &Launch<'_>,
) -> Result<ProcessGuard, BoxError> {
    let mut command = Command::new(exe);
    for var in POSTURE_ENV {
        command.env_remove(var);
    }
    command
        .env(launch.port_var, port.to_string())
        // Disable the double-submit CSRF check so raw TcpStream GETs work.
        .env("IPE_CSRF", "off")
        // Disable the dev console proxy. The console child binary is pre-built
        // and cached on this machine; without this gate it is spawned on its
        // own ephemeral port and emits its own `[ipe.web] listening on`
        // to the inherited stderr pipe before the parent app has bound its
        // port. The test sees that line, declares the server ready, and then
        // immediately tries to connect to the parent's port — which is not
        // bound yet — getting ECONNREFUSED. Setting IPE_CONSOLE_EMBED=off
        // makes gate_allows() return false so no child is spawned and the
        // only `[ipe.web] listening on` line in the stderr pipe is the
        // parent's own (emitted AFTER the TCP listener is bound).
        .env("IPE_CONSOLE_EMBED", "off");
    for (key, value) in launch.extra_env {
        command.env(key, value);
    }
    let mut child = command
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| -> BoxError { format!("{test_name}: cannot spawn Web binary: {e}").into() })?;

    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| -> BoxError { format!("{test_name}: child stderr pipe was None").into() })?;

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut reader = BufReader::new(stderr);
    let mut line = String::new();

    loop {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(
                format!("{test_name}: Ipe Web did not signal readiness within 10 s").into(),
            );
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                let _ = child.wait();
                return Err(
                    format!("{test_name}: Ipe Web process exited before signalling ready").into(),
                );
            }
            Ok(_) => {
                // e.g. `[ipe.web] listening on http://127.0.0.1:<port>`
                if line.contains(launch.ready_marker) {
                    return Ok(ProcessGuard(child));
                }
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{test_name}: error reading child stderr: {e}").into());
            }
        }
    }
}

/// Send a raw HTTP/1.1 request and return the split `(raw_headers, body)`.
///
/// `extra_headers` is a slice of `(name, value)` pairs added after the
/// standard `Host` and `Connection` headers.  For POST requests `body` is
/// the bytes to send; pass `None` for GET.  The helper automatically adds a
/// `Content-Length` header when `body` is `Some`.
///
/// Reads up to 64 KiB (sufficient for a full HTML page from the counter app).
///
/// # Errors
///
/// Returns an error if the stream write or read fails.
fn http_send(
    test_name: &str,
    addr: &str,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<(String, String), BoxError> {
    let mut stream = TcpStream::connect(addr).map_err(|e| -> BoxError {
        format!("{test_name}: cannot connect to Ipe Web server: {e}").into()
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| -> BoxError { format!("{test_name}: set_read_timeout failed: {e}").into() })?;

    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    for (k, v) in extra_headers {
        request.push_str(k);
        request.push_str(": ");
        request.push_str(v);
        request.push_str("\r\n");
    }
    if let Some(b) = body {
        request.push_str("Content-Length: ");
        request.push_str(&b.len().to_string());
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    stream
        .write_all(request.as_bytes())
        .map_err(|e| -> BoxError { format!("{test_name}: write headers failed: {e}").into() })?;
    if let Some(b) = body {
        stream
            .write_all(b)
            .map_err(|e| -> BoxError { format!("{test_name}: write body failed: {e}").into() })?;
    }

    let mut buf = Vec::with_capacity(65536);
    stream
        .read_to_end(&mut buf)
        .map_err(|e| -> BoxError { format!("{test_name}: read failed: {e}").into() })?;

    let response = String::from_utf8_lossy(&buf).into_owned();
    match response.find("\r\n\r\n") {
        Some(idx) => Ok((response[..idx].to_owned(), response[idx + 4..].to_owned())),
        None => Ok((response, String::new())),
    }
}

/// Convenience wrapper: `GET <path>` with no extra headers; returns the body.
fn http_get(test_name: &str, addr: &str, path: &str) -> Result<String, BoxError> {
    let (_, body) = http_send(test_name, addr, "GET", path, &[], None)?;
    Ok(body)
}

/// Extract the value of a named cookie from raw HTTP response headers.
///
/// Searches each `Set-Cookie:` line for `<name>=<value>` (header name
/// matched case-insensitively).
///
/// Returns `None` when no matching `Set-Cookie` line is present.
fn extract_cookie(raw_headers: &str, name: &str) -> Option<String> {
    for line in raw_headers.lines() {
        if !line.to_ascii_lowercase().starts_with("set-cookie:") {
            continue;
        }
        let value_part = line["set-cookie:".len()..].trim();
        // Cookie string: `NAME=VALUE; attr=…`
        let prefix = format!("{name}=");
        if value_part
            .to_ascii_lowercase()
            .starts_with(&prefix.to_ascii_lowercase())
        {
            let after = &value_part[prefix.len()..];
            let end = after.find(';').unwrap_or(after.len());
            return Some(after[..end].trim().to_string());
        }
    }
    None
}

/// Extract the `data-ipe-hid` attribute value from the nearest element that
/// directly contains the given text node.
///
/// Searches backwards from `>TEXT<` for `data-ipe-hid="…"` within the
/// element's opening tag — the runtime emits this attribute on every element
/// that carries at least one event handler, keyed to the handler-index lookup.
///
/// Returns `None` when no match is found (e.g. the element does not carry a
/// click handler, or the text does not appear in the page).
fn extract_hid_near_text(html: &str, text: &str) -> Option<String> {
    let marker = format!(">{text}<");
    let text_pos = html.find(&marker)?;
    // Everything before the `>` that closes the element's start tag.
    let before = &html[..text_pos];
    let attr_prefix = "data-ipe-hid=\"";
    // `rfind`: take the NEAREST (last) occurrence — the direct parent's id,
    // not an ancestor's.
    let hid_pos = before.rfind(attr_prefix)?;
    let after = &before[hid_pos + attr_prefix.len()..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

/// Extract the `data-ipe-hid` attribute value from the FIRST `<tag …>` open
/// tag in `html` (e.g. `"form"`) — used for elements (like `<form>`) that
/// don't necessarily wrap a distinguishing text node directly.
///
/// Returns `None` when the tag or the attribute is not present.
fn extract_hid_for_open_tag(html: &str, tag: &str) -> Option<String> {
    let open_marker = format!("<{tag} ");
    let tag_pos = html.find(&open_marker)?;
    let after_tag = &html[tag_pos..];
    let tag_end = after_tag.find('>')?;
    let tag_slice = &after_tag[..tag_end];
    let attr_prefix = "data-ipe-hid=\"";
    let hid_pos = tag_slice.find(attr_prefix)?;
    let after = &tag_slice[hid_pos + attr_prefix.len()..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

/// A well-formed tab id, as a browser tab mints once per page load.
const TAB: &str = "00112233445566778899aabbccddeeff";

/// The render epoch the page's boot data block carries.
///
/// An event carries it so the server resolves the handler id against the
/// render that produced it.
fn extract_epoch(test_name: &str, html: &str) -> Result<String, BoxError> {
    e2e_support::live_page::boot_string(html, "epoch").ok_or_else(|| -> BoxError {
        format!("{test_name}: no boot-block epoch in the page").into()
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// `GET /` on a Ipe.Web counter app returns an HTML page containing the
/// initial counter value rendered as the text node `>0<`.
///
/// This test proves the FULL Ipe.Web pipeline end-to-end:
///
/// ```text
/// Ipê source
///   → ipe (parse → canon → types → lower → emit Rust with "live" feature)
///   → cargo build
///   → ipe_runtime::web::web_app(init, update, view, subs, …)
///   → init(WebReq) → (Model{count:0}, Cmd::None)
///   → view(model)   → Html tree with text node "0"
///   → render_page   → full HTML document
///   → axum HTTP response
///   → test asserts ">0<" appears in the body
/// ```
///
/// The assertion uses `>0<` rather than the bare character `'0'` to avoid
/// false positives from CSS values, ipe-ids, or other numeric occurrences in
/// the generated page markup.
///
/// The `live` Cargo feature is injected by `emit_program` when `uses_web` is
/// set.  Without the constraint scheme the build would fail with `exit 0 then
/// cargo fail` (constraint scheme missing) or `cargo build error` (serde
/// derives absent).
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or HTTP error as a test error.
#[test]
fn live_get_root_contains_initial_count() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let test_name = "live_get_root";
    let exe = compile_and_build(test_name, IPE_LIVE_COUNTER)?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready(test_name, &exe, port)?;

    let addr = format!("127.0.0.1:{port}");
    let body = http_get(test_name, &addr, "/")?;

    // The rendered page wraps every text node in an element with a ipe-id.
    // The counter is `Ui.text (String.fromInt 0)` → renders text "0" inside
    // an element.  We assert the `>0<` sequence to distinguish the counter
    // text node from other numeric occurrences in page markup (ipe-ids, CSS
    // values, etc.).
    assert!(
        body.contains(">0<"),
        "live_get_root: initial counter (>0<) not found in GET / body\n\
         --- first 2000 bytes ---\n{}",
        &body[..body.len().min(2000)]
    );
    // Sanity: must be an HTML document, not an error message.
    assert!(
        body.contains("<!DOCTYPE html>") || body.contains("<html"),
        "live_get_root: response does not look like HTML\n\
         --- first 500 bytes ---\n{}",
        &body[..body.len().min(500)]
    );
    Ok(())
}

/// Compile-only: the Ipe.Web counter emits a Cargo project with the `"live"`
/// feature in the default feature list.
///
/// This is a BUILD-ONLY test — it does not spawn the binary.  A successful
/// `cargo build` is the assertion.  If `serde::Serialize / Deserialize` derives
/// are absent on the `Msg` enum and `Model` struct, `cargo build` will fail
/// with a trait-bound error from `ipe_runtime::web::web_app`.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn live_counter_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    // compile_and_build already does ipe + cargo build; success is the proof.
    let _exe = compile_and_build("live_build_only", IPE_LIVE_COUNTER)?;
    Ok(())
}

/// Serde-derive gating seal — BUILD-ONLY: a Ipe.Web program with a NON-Model
/// view-helper record holding an `Html` field must compile end-to-end.
///
/// A successful `ipe` + `cargo build` IS the assertion. Gating serde on the
/// record's `CDPeq` flag would make this `ipe` exit 0 then `cargo build` E0277
/// (`Html<MainMsg>: Serialize` unsatisfied on the `Section` struct's forced
/// serde derive). See `IPE_LIVE_HTML_HELPER` for the full rationale.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn live_html_helper_record_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build("live_html_helper", IPE_LIVE_HTML_HELPER)?;
    Ok(())
}

/// Inline-lambda subscriptions seal — BUILD-ONLY: an inline-lambda
/// `subscriptions` cfg field on a routed `Web.tea` must compile end-to-end.
/// See `IPE_LIVE_LAMBDA_SUBS` for the full rationale — a lambda pinned to
/// `Box<dyn Fn + Send>` (no `Sync`) instead of emitted unboxed into the generic
/// `FSubs` slot makes this `ipe` exit 0 then `cargo build` E0277
/// (`dyn Fn(..) -> IpeSub<Msg> + Send cannot be shared between threads safely`).
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn live_lambda_subscriptions_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build("live_lambda_subs", IPE_LIVE_LAMBDA_SUBS)?;
    Ok(())
}

/// A click on the `+` element increments the counter: `GET /` → extract
/// session cookie + ipe-id of the `+` element → `POST /_ipe/event` (click) →
/// wait for the async model update → `GET /` with session cookie → body
/// contains `>1<`.
///
/// ## Wire protocol exercised
///
/// 1. `GET /` → axum sets `ipe_sid=<sid>` in `Set-Cookie`.  The initial model
///    (`count = 0`) is rendered with `>0<`.
/// 2. The rendered HTML carries `data-ipe-hid="<ipe-id>"` on every element
///    that has event handlers.  The `Ui.el [ Ui.onClick Increment ]` element
///    (containing `+`) is found by searching backwards from `>+<` for the
///    nearest `data-ipe-hid`.
/// 3. `POST /_ipe/event` with body
///    `{"id":"<ipe-id>","msg":"click","args":[],"sessionId":""}` and
///    `Cookie: ipe_sid=<sid>`.  The runtime authenticates via the COOKIE only;
///    the body's `sessionId` is ignored per the security policy.
/// 4. The event is enqueued via `try_send` and processed asynchronously by
///    `drive_session`.  A 200 ms sleep after the POST gives the driver time to
///    commit the model update.
/// 5. A second `GET /` with `Cookie: ipe_sid=<sid>` re-renders the live
///    session (store hit → re-view with current model) → the body must contain
///    `>1<`.
///
/// This test is the definitive proof that the full TEA loop works:
/// `init → view → event → update → re-view` over the HTTP/1.1 wire.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, HTTP, or assertion error.
#[test]
fn live_onclick_increments_counter() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let test_name = "live_onclick";
    let exe = compile_and_build(test_name, IPE_LIVE_COUNTER)?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready(test_name, &exe, port)?;
    let addr = format!("127.0.0.1:{port}");

    // ── Step 1: GET / — initial page, extract session cookie + ipe-id ─────────
    let (raw_headers, body) = http_send(test_name, &addr, "GET", "/", &[], None)?;

    let sid = extract_cookie(&raw_headers, "ipe_sid").ok_or_else(|| -> BoxError {
        format!(
            "{test_name}: no ipe_sid cookie in GET / response\n\
             --- raw headers ---\n{raw_headers}"
        )
        .into()
    })?;

    let hid = extract_hid_near_text(&body, "+").ok_or_else(|| -> BoxError {
        format!(
            "{test_name}: could not find data-ipe-hid near '>+<' in GET / body\n\
             --- first 2000 bytes ---\n{}",
            &body[..body.len().min(2000)]
        )
        .into()
    })?;

    // ── Step 2: POST /_ipe/event — Increment click ───────────────────────────
    //
    // `msg` carries the event name (the runtime prefers `event`, then `msg`,
    // then defaults to "click").  `sessionId` is retained in the body for
    // wire-compat but ignored by the server; auth is via the Cookie header.
    let epoch = extract_epoch(test_name, &body)?;
    let event_body = format!(
        r#"{{"id":"{hid}","msg":"click","args":[],"sessionId":"","epoch":"{epoch}","tab":"{TAB}","seq":1}}"#
    );
    let cookie_header = format!("ipe_sid={sid}");
    let (_, post_body) = http_send(
        test_name,
        &addr,
        "POST",
        "/_ipe/event",
        &[
            ("Content-Type", "application/json"),
            ("Cookie", &cookie_header),
        ],
        Some(event_body.as_bytes()),
    )?;

    assert!(
        post_body.contains("patches"),
        "{test_name}: POST /_ipe/event did not return a patches ACK\nbody: {post_body}"
    );

    // ── Step 3: wait for async model update ─────────────────────────────────
    //
    // `event_handler` uses `try_send` (non-blocking) — the actual model update
    // happens in the `drive_session` task.  200 ms is sufficient for the
    // in-process channel round-trip on any reasonable test host.
    std::thread::sleep(Duration::from_millis(200));

    // ── Step 4: GET / with session cookie — should show count = 1 ───────────
    let (_, body2) = http_send(
        test_name,
        &addr,
        "GET",
        "/",
        &[("Cookie", &cookie_header)],
        None,
    )?;

    assert!(
        body2.contains(">1<"),
        "{test_name}: counter not incremented to 1 after Increment click\n\
         --- first 2000 bytes of second GET / ---\n{}",
        &body2[..body2.len().min(2000)]
    );

    // ── Step 5: an event from another render history is refused ─────────────
    //
    // The same handler id under an epoch this server never minted must not
    // resolve against the current render: 409 with the current render, and
    // the counter stays at 1.
    let foreign = format!("{:032x}.1", 0xdead_u128);
    let stale_body = format!(
        r#"{{"id":"{hid}","msg":"click","args":[],"sessionId":"","epoch":"{foreign}","tab":"{TAB}","seq":2}}"#
    );
    let (stale_headers, stale_reply) = http_send(
        test_name,
        &addr,
        "POST",
        "/_ipe/event",
        &[
            ("Content-Type", "application/json"),
            ("Cookie", &cookie_header),
        ],
        Some(stale_body.as_bytes()),
    )?;
    assert!(
        stale_headers.starts_with("HTTP/1.1 409") && stale_reply.contains("stale-render"),
        "{test_name}: a foreign-epoch event must be refused with 409 stale-render\n\
         --- headers ---\n{stale_headers}\n--- body ---\n{stale_reply}"
    );
    std::thread::sleep(Duration::from_millis(200));
    let (_, body3) = http_send(
        test_name,
        &addr,
        "GET",
        "/",
        &[("Cookie", &cookie_header)],
        None,
    )?;
    assert!(
        body3.contains(">1<") && !body3.contains(">2<"),
        "{test_name}: a refused event must not dispatch\n\
         --- first 2000 bytes of third GET / ---\n{}",
        &body3[..body3.len().min(2000)]
    );

    Ok(())
}

/// Read the SSE stream until the `event: patch` resync frame arrives (or a byte
/// cap / read timeout is hit), returning the accumulated stream text. The SSE
/// endpoint never sends `Connection: close`, so a plain `read_to_end` would
/// block until the socket's read timeout; instead we read in chunks and stop as
/// soon as the resync frame's body is in hand.
fn http_read_sse_until_patch(
    test_name: &str,
    addr: &str,
    cookie_header: &str,
) -> Result<String, BoxError> {
    use std::io::Read;
    let mut stream = TcpStream::connect(addr)
        .map_err(|e| -> BoxError { format!("{test_name}: SSE connect failed: {e}").into() })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| -> BoxError { format!("{test_name}: SSE set_read_timeout: {e}").into() })?;
    let request = format!(
        "GET /_ipe/sse?path=%2F HTTP/1.1\r\nHost: 127.0.0.1\r\n\
         Accept: text/event-stream\r\nCookie: {cookie_header}\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| -> BoxError { format!("{test_name}: SSE write failed: {e}").into() })?;

    let mut acc = String::new();
    let mut chunk = [0u8; 8192];
    // Cap total read so a misbehaving server can't spin us forever; the resync
    // frame is the FIRST `event: patch` after `event: hello`, well within 256 KB.
    while acc.len() < 256 * 1024 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                // `n <= chunk.len()` by the Read contract; `get(..n)` keeps the
                // slice total (falls back to the whole buffer if ever violated).
                let read = chunk.get(..n).unwrap_or(&chunk);
                acc.push_str(&String::from_utf8_lossy(read));
                if acc.contains("event: patch") && acc.contains("data-ipe-hid") {
                    break;
                }
            }
            // A timed-out read with data already in hand is the normal stop
            // path: the heartbeat keepalive means the socket won't EOF, so we
            // rely on the timeout once the resync frame is captured.
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => return Err(format!("{test_name}: SSE read failed: {e}").into()),
        }
    }
    Ok(acc)
}

/// The SSE resync frame the browser applies on connect must carry
/// `data-ipe-hid` on event elements. When the reconnect reconciliation rebuilt
/// the view without stamping ipe-ids, the resync body replaced the client DOM
/// with id-less elements — every click then posted an empty handlerId the
/// server dropped, so interactions silently did nothing until a full reload.
///
/// A page GET alone never exposes this: its body IS stamped. Only the SSE
/// resync path (exercised here) surfaces the divergence.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, HTTP, or assertion error.
#[test]
fn live_sse_resync_body_carries_event_hids() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let test_name = "live_sse_resync_hids";
    let exe = compile_and_build(test_name, IPE_LIVE_COUNTER)?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready(test_name, &exe, port)?;
    let addr = format!("127.0.0.1:{port}");

    // GET / to mint the session (the SSE endpoint authenticates by cookie).
    let (raw_headers, _body) = http_send(test_name, &addr, "GET", "/", &[], None)?;
    let sid = extract_cookie(&raw_headers, "ipe_sid").ok_or_else(|| -> BoxError {
        format!("{test_name}: no ipe_sid cookie in GET / response").into()
    })?;
    let cookie_header = format!("ipe_sid={sid}");

    // The resync frame the client applies on SSE connect must stamp ids, or
    // the whole DOM the browser ends up with is un-clickable.
    let sse = http_read_sse_until_patch(test_name, &addr, &cookie_header)?;
    assert!(
        sse.contains("event: patch"),
        "{test_name}: no resync patch frame on SSE connect\n\
         --- first 1000 bytes ---\n{}",
        &sse[..sse.len().min(1000)]
    );
    assert!(
        sse.contains("data-ipe-hid"),
        "{test_name}: SSE resync body has no data-ipe-hid — event elements are \
         un-clickable\n--- first 2000 bytes ---\n{}",
        &sse[..sse.len().min(2000)]
    );

    Ok(())
}

/// T5 seal — BUILD-ONLY: a routed `Web.tea` with a `page` field in the Model
/// must compile and produce a Cargo project that links against
/// `web_app_routed` rather than `web_app`.
///
/// This regression-tests the full T3→T5 emit path:
/// - T3: 6-field open-record constraint passes type-checking.
/// - T5: `routed_page_field` detects the `page` field in the Model and the
///   emitter branches to `web_app_routed` with a generated `set_page` closure.
///
/// A successful `ipe` + `cargo build` is the assertion.  If T5 emits
/// `web_app` instead of `web_app_routed`, or emits a malformed `set_page`
/// closure, `cargo build` surfaces the type mismatch.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn live_routed_app_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build("live_routed_build_only", IPE_LIVE_ROUTED)?;
    Ok(())
}

/// Pub/sub seal — BUILD-ONLY: a Ipe.Web app that uses `Cmd.publish` and
/// `Sub.subscribeTopic` must compile end-to-end without a `CompilerBug`
/// diagnostic.
///
/// Kernels exercised:
/// - `Cmd.publish : Topic a -> a -> Cmd msg`
/// - `Sub.subscribeTopic : Topic a -> (a -> msg) -> Sub msg`
///   (exercised here as the natural pair to `Cmd.publish`)
///
/// Both publisher and subscriber share `chatTopic : Topic (Dict String String)`,
/// enforcing payload-type agreement at compile time.
///
/// A successful `ipe` + `cargo build` is the assertion.  Without pub/sub
/// wiring the compiler would emit a `CompilerBug` diagnostic on `Cmd.publish`
/// or `Cmd.publishNoEcho` — exit-0 structurally impossible.
///
/// The app structure mirrors `examples/27-multi-session-chat` at its simplest:
/// one pub/sub topic `"chat"`, a `BroadcastMsg` that carries the payload dict,
/// and an `update` arm that publishes then clears the pending message.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
const IPE_PUBSUB_LIVE: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
import Ipe.String
import Ipe.List
import Ipe.Dict
import Ipe.Maybe
import Ipe.PubSub as PubSub exposing (Topic)

type Msg
    = BroadcastMsg (Dict String String)
    | TypeMsg String

type alias Model =
    { pending : String
    , received : List String
    }

chatTopic : Topic (Dict String String)
chatTopic =
    PubSub.topic "chat"

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { pending = "", received = [] }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        TypeMsg s ->
            ( { model | pending = s }, Cmd.none )

        BroadcastMsg payload ->
            let
                text =
                    Maybe.withDefault "" (Dict.get "text" payload)
            in
            ( { model | received = model.received ++ [ text ] }
            , Cmd.none
            )

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.subscribeTopic chatTopic BroadcastMsg

sendMessage : Model -> Cmd Msg
sendMessage model =
    let
        payload =
            Dict.fromList [ ( "text", model.pending ) ]
    in
    Cmd.publish chatTopic payload

htmlView : Model -> Html Msg
htmlView model =
    Ui.layout []
        (Ui.column []
            [ Ui.text (String.fromInt (List.length model.received))
            ])

view : Model -> Element Msg
view model =
    Ui.html (htmlView model)

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = TypeMsg ""
        }
"#;

#[test]
fn live_pubsub_cmd_publish_and_sub_subscribe_topic_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build("live_pubsub_build_only", IPE_PUBSUB_LIVE)?;
    Ok(())
}

/// Regression: `Cmd.publish` / `Cmd.publishNoEcho` must accept a record payload
/// (or any Ipê value), not only `Dict String String`.
///
/// The constrain scheme is `Topic a -> a -> Cmd msg` (var(1) for payload),
/// matching the reference runtime which is generic in T. A narrower scheme
/// would reject publishing `{ count : Int, name : String }` with IPE-T0001
/// (type mismatch).  The `Topic a` handle binds the publisher and subscriber
/// to the same payload type `a` at compile time.
///
/// This test also asserts `cargo build` succeeds — verifying the re-export
/// (`cmd_publish`, `cmd_publish_no_echo` in `RUNTIME_MOD_RS_LIVE_APPEND`) is
/// present; without it the emitted project would fail with E0425 (seal violation).
const IPE_PUBSUB_RECORD_PAYLOAD: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
import Ipe.String
import Ipe.List
import Ipe.PubSub as PubSub exposing (Topic)

type alias CartItem =
    { count : Int
    , name : String
    }

type Msg
    = AddItem CartItem
    | SendCart CartItem

type alias Model =
    { items : List CartItem
    }

cartTopic : Topic CartItem
cartTopic =
    PubSub.topic "cart"

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { items = [] }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        AddItem item ->
            ( { model | items = model.items ++ [ item ] }
            , Cmd.batch
                [ Cmd.publish cartTopic item
                , Cmd.publishNoEcho cartTopic item
                ]
            )

        SendCart item ->
            ( model, Cmd.publish cartTopic item )

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.subscribeTopic cartTopic AddItem

htmlView : Model -> Html Msg
htmlView model =
    Ui.layout []
        (Ui.column []
            [ Ui.text (String.fromInt (List.length model.items))
            ])

view : Model -> Element Msg
view model =
    Ui.html (htmlView model)

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = SendCart { count = 0, name = "" }
        }
"#;

#[test]
fn live_pubsub_publish_polymorphic_record_payload_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build(
        "live_pubsub_record_payload_build_only",
        IPE_PUBSUB_RECORD_PAYLOAD,
    )?;
    Ok(())
}

/// Typed-record onSubmit — the CANONICAL AGENTS.md "forms with passwords" idiom:
/// `Ui.form [Ui.onSubmit DoSignIn] [...]` where `DoSignIn : Creds -> Msg` is a
/// TYPED-RECORD payload constructor (not a bare Msg). This is the exact shape
/// `examples/19-ipeforum`'s `View/Login.ipe` and `examples/27-multi-session-chat`
/// use in production.
///
/// Forwarding the codegen's boxed closure value (`Box<dyn Fn(T) -> M + Send +
/// 'static>` — the generic `IrType::Fun` rendering, which never claims `+Sync`)
/// straight through as `ui_on_submit_`'s generic `F: Fn(T) -> M + Send + Sync +
/// 'static` would be unsatisfiable: a trait object's auto-trait set is exactly
/// its bound list, so that box can never satisfy `+ Sync` regardless of what it
/// captures — a ipe-accept/cargo-reject SEAL violation. The emit re-wraps the
/// boxed value in a freshly-declared closure at the `KernelFn::UiOnSubmit` /
/// `HtmlEventShape::Raw` emit sites (`ipe_backend_rust::emit_expr`) instead of
/// forwarding the box itself — see that arm's comment for the full mechanism.
const IPE_ONSUBMIT_TYPED_RECORD: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub

type alias Creds =
    { username : String
    , password : String
    }

type Msg
    = DoSignIn Creds

type alias Model =
    { lastUsername : String
    }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { lastUsername = "" }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        DoSignIn creds ->
            ( { model | lastUsername = creds.username }, Cmd.none )

htmlView : Model -> Html Msg
htmlView model =
    Ui.layout []
        (Ui.column []
            [ Ui.form
                [ Ui.onSubmit DoSignIn ]
                [ Ui.input [ Ui.name "username" ]
                , Ui.input [ Ui.name "password" ]
                , Ui.input [ Ui.htmlAttribute "type" "submit" ]
                ]
            , Ui.text model.lastUsername
            ])

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

view : Model -> Element Msg
view model =
    Ui.html (htmlView model)

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = DoSignIn { username = "", password = "" }
        }
"#;

/// Typed-record onSubmit seal — BUILD-ONLY: the typed-record `Ui.onSubmit` form
/// must compile end-to-end. A successful `ipe` + `cargo build` IS the assertion
/// — forwarding the bare box makes this `ipe` exit 0 then `cargo build` E0277
/// (`dyn Fn(Creds) -> MainMsg + Send` cannot be shared between threads safely).
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn live_onsubmit_typed_record_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build(
        "live_onsubmit_typed_record_build_only",
        IPE_ONSUBMIT_TYPED_RECORD,
    )?;
    Ok(())
}

/// Typed-record onSubmit seal — FULL E2E: submitting the typed-record form over
/// the wire must dispatch `DoSignIn` with the DECODED `Creds` record, proving
/// the compile-time wrapping does not leave the handler undispatchable at
/// runtime (the failure mode of an `OnRaw`-style variant).
///
/// ## Wire protocol exercised
///
/// 1. `GET /` → session cookie + the `<form>`'s `data-ipe-hid`.
/// 2. `POST /_ipe/event` with
///    `{"id":"<hid>","event":"submit","args":[{"username":"alice","password":"s3cr3t"}],"sessionId":""}`
///    — mirrors what the browser's delegated form-submit binder sends
///    (`live/mod.rs`'s `event == "submit"` branch treats `args[0]` as the
///    form-data object).
/// 3. A second `GET /` with the session cookie must show `>alice<` — proving
///    `resolve_form` → `decode_form_or_warn::<Creds>` → `DoSignIn` → `update`
///    ran end-to-end with the CONCRETE decoded record, not a type-erased or
///    dropped payload.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, HTTP, or assertion error.
#[test]
fn live_onsubmit_typed_record_dispatches_decoded_payload() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let test_name = "live_onsubmit_typed_record";
    let exe = compile_and_build(test_name, IPE_ONSUBMIT_TYPED_RECORD)?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready(test_name, &exe, port)?;
    let addr = format!("127.0.0.1:{port}");

    // ── Step 1: GET / — initial page, extract session cookie + form hid ─────
    let (raw_headers, body) = http_send(test_name, &addr, "GET", "/", &[], None)?;

    let sid = extract_cookie(&raw_headers, "ipe_sid").ok_or_else(|| -> BoxError {
        format!(
            "{test_name}: no ipe_sid cookie in GET / response\n\
             --- raw headers ---\n{raw_headers}"
        )
        .into()
    })?;

    let hid = extract_hid_for_open_tag(&body, "form").ok_or_else(|| -> BoxError {
        format!(
            "{test_name}: could not find data-ipe-hid on <form> in GET / body\n\
             --- first 2000 bytes ---\n{}",
            &body[..body.len().min(2000)]
        )
        .into()
    })?;

    // ── Step 2: POST /_ipe/event — submit with the typed-record form data ──
    let epoch = extract_epoch(test_name, &body)?;
    let event_body = format!(
        r#"{{"id":"{hid}","event":"submit","args":[{{"username":"alice","password":"s3cr3t"}}],"sessionId":"","epoch":"{epoch}","tab":"{TAB}","seq":1}}"#
    );
    let cookie_header = format!("ipe_sid={sid}");
    let (_, post_body) = http_send(
        test_name,
        &addr,
        "POST",
        "/_ipe/event",
        &[
            ("Content-Type", "application/json"),
            ("Cookie", &cookie_header),
        ],
        Some(event_body.as_bytes()),
    )?;

    assert!(
        post_body.contains("patches"),
        "{test_name}: POST /_ipe/event (submit) did not return a patches ACK\nbody: {post_body}"
    );

    // ── Step 3: wait for async model update ─────────────────────────────────
    std::thread::sleep(Duration::from_millis(200));

    // ── Step 4: GET / with session cookie — should show the decoded username
    let (_, body2) = http_send(
        test_name,
        &addr,
        "GET",
        "/",
        &[("Cookie", &cookie_header)],
        None,
    )?;

    assert!(
        body2.contains(">alice<"),
        "{test_name}: DoSignIn was not dispatched with the decoded Creds \
         record (expected the re-rendered page to contain the username \
         \"alice\")\n--- first 2000 bytes of second GET / ---\n{}",
        &body2[..body2.len().min(2000)]
    );

    Ok(())
}

/// Bare-Msg onSubmit — the "ignore form data, always dispatch this fixed
/// action" idiom: `Ipe.Html.Events.onSubmit Confirm` where `Confirm : Msg`
/// carries NO payload (a nullary constructor, not a decoder function). This
/// is the exact shape `examples/12-ipevote`'s `Page/AuthPage.ipe` /
/// `Page/Submit.ipe` / `Page/Detail.ipe` use throughout (`onSubmit
/// DoSignUp` / `DoSignIn` / `SubmitIdea` / `SubmitComment`) — form fields
/// are already synced into `Model` via `onInput`/`onChange`; `onSubmit`
/// just triggers the action, ignoring the posted `FormData` entirely.
///
/// `ipe dev build` exits 0 here (`HtmlOnSubmit`'s Ipê-level scheme
/// deliberately leaves the argument type unconstrained — decoupled from
/// `msg`, see `constrain.rs`'s `HtmlEventShape::Raw` arm — so a Msg-typed
/// value type-checks fine there). Emitting the argument unconditionally as a
/// callable decoder (`(payload_s)(_x)`) would fail `cargo build` with E0618
/// ("expected function, found `MainMsg`"), because a bare nullary constructor
/// reference lowers to a plain `Expr::Ctor` VALUE (`lower_expr`'s `VarCtor`
/// arm), never a function. So a provably-non-callable argument shape routes to
/// the `html_on_raw_fixed_` runtime helper (dispatches the fixed value
/// directly, no decode attempt) instead of `html_on_raw_`
/// (`ipe_backend_rust::emit_expr`'s `is_definitely_not_callable` gate).
const IPE_ONSUBMIT_BARE_MSG: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Html exposing (..)
import Ipe.Html.Attributes exposing (..)
import Ipe.Html.Events exposing (onSubmit, onInput)
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub

type Msg
    = UpdateName String
    | Confirm

type alias Model =
    { name : String
    , confirmed : Bool
    }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { name = "", confirmed = False }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        UpdateName n ->
            ( { model | name = n }, Cmd.none )

        Confirm ->
            ( { model | confirmed = True }, Cmd.none )

htmlView : Model -> Html Msg
htmlView model =
    div []
        [ form
            [ onSubmit Confirm ]
            [ input [ type_ "text", name "name", value model.name, onInput UpdateName ]
            , button [ type_ "submit" ] [ text "Go" ]
            ]
        , text
            (if model.confirmed then
                "confirmed:" ++ model.name

             else
                "not-confirmed"
            )
        ]

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

view : Model -> Element Msg
view model =
    Ui.html (htmlView model)

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = Confirm
        }
"#;

/// Bare-Msg onSubmit seal — BUILD-ONLY: the bare-Msg `onSubmit` form must
/// compile end-to-end. A successful `ipe` + `cargo build` IS the assertion —
/// treating the bare Msg as callable makes this `ipe` exit 0 then `cargo
/// build` E0618.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn live_onsubmit_bare_msg_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build("live_onsubmit_bare_msg_build_only", IPE_ONSUBMIT_BARE_MSG)?;
    Ok(())
}

/// Bare-Msg onSubmit seal — FULL E2E: submitting the bare-Msg form over the wire
/// must dispatch `Confirm` regardless of the posted `FormData` — proving the
/// dispatch is not left undispatchable (or, worse, silently swallowed by a
/// decode failure — see
/// `html_on_raw_fixed_`'s doc for why it deliberately does NOT route
/// through `decode_form_or_warn`). The posted form body deliberately
/// carries a REAL field value (`name=alice`, matching the `<input
/// name="name">` in the view) to prove the fixed dispatch survives
/// non-empty form data, not just the trivial empty-body case.
///
/// ## Wire protocol exercised
///
/// 1. `GET /` → session cookie + the `<form>`'s `data-ipe-hid`.
/// 2. `POST /_ipe/event` with
///    `{"id":"<hid>","event":"submit","args":[{"name":"alice"}],"sessionId":""}`
///    — mirrors what the browser's delegated form-submit binder sends.
/// 3. A second `GET /` with the session cookie must show the "confirmed:"
///    marker — proving `resolve_form` → `html_on_raw_fixed_`'s closure →
///    `Confirm` → `update` ran end-to-end, dispatching the FIXED value
///    (not the posted `name` field, which `update`'s `Confirm` arm never
///    reads — `model.name` stays empty since no separate `onInput` event
///    was sent, so `"confirmed:alice"` would be a FALSE pass here; the
///    assertion below checks the "confirmed:" prefix only).
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, HTTP, or assertion error.
#[test]
fn live_onsubmit_bare_msg_dispatches_fixed_msg() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let test_name = "live_onsubmit_bare_msg";
    let exe = compile_and_build(test_name, IPE_ONSUBMIT_BARE_MSG)?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready(test_name, &exe, port)?;
    let addr = format!("127.0.0.1:{port}");

    // ── Step 1: GET / — initial page, extract session cookie + form hid ─────
    let (raw_headers, body) = http_send(test_name, &addr, "GET", "/", &[], None)?;

    let sid = extract_cookie(&raw_headers, "ipe_sid").ok_or_else(|| -> BoxError {
        format!(
            "{test_name}: no ipe_sid cookie in GET / response\n\
             --- raw headers ---\n{raw_headers}"
        )
        .into()
    })?;

    let hid = extract_hid_for_open_tag(&body, "form").ok_or_else(|| -> BoxError {
        format!(
            "{test_name}: could not find data-ipe-hid on <form> in GET / body\n\
             --- first 2000 bytes ---\n{}",
            &body[..body.len().min(2000)]
        )
        .into()
    })?;

    // ── Step 2: POST /_ipe/event — submit with REAL (but ignored) form data ─
    let epoch = extract_epoch(test_name, &body)?;
    let event_body = format!(
        r#"{{"id":"{hid}","event":"submit","args":[{{"name":"alice"}}],"sessionId":"","epoch":"{epoch}","tab":"{TAB}","seq":1}}"#
    );
    let cookie_header = format!("ipe_sid={sid}");
    let (_, post_body) = http_send(
        test_name,
        &addr,
        "POST",
        "/_ipe/event",
        &[
            ("Content-Type", "application/json"),
            ("Cookie", &cookie_header),
        ],
        Some(event_body.as_bytes()),
    )?;

    assert!(
        post_body.contains("patches"),
        "{test_name}: POST /_ipe/event (submit) did not return a patches ACK\nbody: {post_body}"
    );

    // ── Step 3: wait for async model update ─────────────────────────────────
    std::thread::sleep(Duration::from_millis(200));

    // ── Step 4: GET / with session cookie — should show the fixed dispatch ──
    let (_, body2) = http_send(
        test_name,
        &addr,
        "GET",
        "/",
        &[("Cookie", &cookie_header)],
        None,
    )?;

    assert!(
        body2.contains("confirmed:"),
        "{test_name}: Confirm was not dispatched on bare-Msg onSubmit \
         (expected the re-rendered page to contain \"confirmed:\")\n\
         --- first 2000 bytes of second GET / ---\n{}",
        &body2[..body2.len().min(2000)]
    );

    Ok(())
}

// ── onSubmit COMPOUND-literal payloads (record / tuple / list) ─────────
//
// The bare nullary-`Ctor` onSubmit payload (`onSubmit Confirm`,
// `Confirm : Msg`). The same emit gate (`is_definitely_not_callable`) left
// three sibling literal shapes on the wrap-and-call path even though they are
// EQUALLY provably-non-callable structural values: a record literal
// (`{ … }`), a tuple literal (`(…, …)`), and a list literal (`[…]`).
//
// `HtmlOnSubmit`'s payload type is `var(1)` in `constrain.rs`'s
// `HtmlEventShape::Raw` arm — decoupled from `msg`, hence UNCONSTRAINED — so
// these shapes type-check in ipe; the well-typed, SEAL-relevant program is one
// whose `Msg` type IS that record / tuple / list (`type alias Msg = { … }`
// etc), where the literal is a genuine `Msg` value. Wrapping the value in
// `(payload_s)(_x)` would make each such program `ipe` exit 0 then `cargo
// build` E0618 ("expected function, found …"). `is_definitely_not_callable`
// covers the three compound literal variants (`Expr::Record` / `Expr::Tuple` /
// `Expr::List`), routing them to `html_on_raw_fixed_` (fixed dispatch, no
// decode) — sealing the class. A successful `ipe` + `cargo build` IS the
// assertion.

/// `onSubmit` payload is a RECORD literal, `Msg` is a record alias.
const IPE_ONSUBMIT_RECORD_LITERAL: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Html exposing (..)
import Ipe.Html.Attributes exposing (..)
import Ipe.Html.Events exposing (onSubmit)
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub

type alias Msg =
    { action : String }

type alias Model =
    { last : String }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { last = "" }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    ( { model | last = msg.action }, Cmd.none )

htmlView : Model -> Html Msg
htmlView model =
    div []
        [ form
            [ onSubmit { action = "confirmed" } ]
            [ button [ type_ "submit" ] [ text "Go" ] ]
        , text model.last
        ]

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

view : Model -> Element Msg
view model =
    Ui.html (htmlView model)

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = { action = "" }
        }
"#;

/// `onSubmit` payload is a TUPLE literal, `Msg` is a tuple alias.
const IPE_ONSUBMIT_TUPLE_LITERAL: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Html exposing (..)
import Ipe.Html.Attributes exposing (..)
import Ipe.Html.Events exposing (onSubmit)
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub

type alias Msg =
    ( String, Int )

type alias Model =
    { last : String }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { last = "" }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    let
        ( label, _n ) =
            msg
    in
    ( { model | last = label }, Cmd.none )

htmlView : Model -> Html Msg
htmlView model =
    div []
        [ form
            [ onSubmit ( "confirmed", 1 ) ]
            [ button [ type_ "submit" ] [ text "Go" ] ]
        , text model.last
        ]

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

view : Model -> Element Msg
view model =
    Ui.html (htmlView model)

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = ( "", 0 )
        }
"#;

/// `onSubmit` payload is a LIST literal, `Msg` is a list alias.
const IPE_ONSUBMIT_LIST_LITERAL: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Html exposing (..)
import Ipe.Html.Attributes exposing (..)
import Ipe.Html.Events exposing (onSubmit)
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
import Ipe.String
import Ipe.List

type alias Msg =
    List String

type alias Model =
    { count : Int }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    ( { model | count = List.length msg }, Cmd.none )

htmlView : Model -> Html Msg
htmlView model =
    div []
        [ form
            [ onSubmit [ "a", "b", "c" ] ]
            [ button [ type_ "submit" ] [ text "Go" ] ]
        , text (String.fromInt model.count)
        ]

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

view : Model -> Element Msg
view model =
    Ui.html (htmlView model)

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = [ "" ]
        }
"#;

/// Compound-literal onSubmit seal — BUILD-ONLY: a RECORD-literal `onSubmit`
/// payload must compile end-to-end. A successful `ipe` + `cargo build` IS the
/// assertion — the wrap-and-call path makes this `ipe` exit 0 then `cargo
/// build` E0618.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn live_onsubmit_record_literal_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build(
        "live_onsubmit_record_literal_build_only",
        IPE_ONSUBMIT_RECORD_LITERAL,
    )?;
    Ok(())
}

/// Compound-literal onSubmit seal — BUILD-ONLY: a TUPLE-literal `onSubmit`
/// payload must compile end-to-end (see [`IPE_ONSUBMIT_TUPLE_LITERAL`]).
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn live_onsubmit_tuple_literal_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build(
        "live_onsubmit_tuple_literal_build_only",
        IPE_ONSUBMIT_TUPLE_LITERAL,
    )?;
    Ok(())
}

/// Compound-literal onSubmit seal — BUILD-ONLY: a LIST-literal `onSubmit`
/// payload must compile end-to-end (see [`IPE_ONSUBMIT_LIST_LITERAL`]).
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn live_onsubmit_list_literal_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build(
        "live_onsubmit_list_literal_build_only",
        IPE_ONSUBMIT_LIST_LITERAL,
    )?;
    Ok(())
}

// ── onSubmit VAR-bound bare-Msg payload ────────
//
// A SYNTACTIC `is_definitely_not_callable` classifier that inspects the payload
// `Expr` variant covers the bare-`Ctor` / record / tuple / list LITERAL
// onSubmit payloads, but a `let`-bound bare `Msg` VALUE dispatched by
// `onSubmit` (`let m = DoSignUp in onSubmit m`) lowers the payload to a plain
// `Expr::Var`, which is NOT in such a classifier's fixed set, so it would be
// wrapped as a decoder: `html_on_raw_("submit", move |_x| (m)(_x))`.
// `m` is `MainMsg::DoSignUp`, a non-callable enum value → `(m)(_x)` is cargo
// `E0618` ("expected function") AFTER `ipe` exit 0 — a SEAL violation.
//
// Classification is TYPE-DIRECTED instead (mirroring `../ipe`'s
// `formTargetRustType`): the lowerer reads the handler's SOLVED type and
// records `OnFormKind::{Decoder,FixedValue}` on the `Call`. A non-arrow value
// (this shape) routes to `html_on_raw_fixed_` regardless of its syntax; an
// arrow handler keeps the decode path. Acceptance does not depend on the
// payload's `Expr` shape, so a `Var`/`Apply`/`Access`-bound bare `Msg` seals
// identically to a bare-`Ctor` one. A successful `ipe` + `cargo build` IS the
// assertion; the E2E companion proves the fixed value is actually dispatched.

/// `onSubmit m` where `m : Msg` is a `let`-bound bare (non-function)
/// value. The payload lowers to `Expr::Var`, the shape a purely syntactic
/// classifier would misroute to the decoder path.
const IPE_ONSUBMIT_VAR_BOUND_MSG: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Html exposing (..)
import Ipe.Html.Attributes exposing (..)
import Ipe.Html.Events exposing (onSubmit, onInput)
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub

type Msg
    = UpdateName String
    | DoSignUp

type alias Model =
    { name : String
    , confirmed : Bool
    }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { name = "", confirmed = False }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        UpdateName n ->
            ( { model | name = n }, Cmd.none )

        DoSignUp ->
            ( { model | confirmed = True }, Cmd.none )

htmlView : Model -> Html Msg
htmlView model =
    let
        m =
            DoSignUp
    in
    div []
        [ form
            [ onSubmit m ]
            [ input [ type_ "text", name "name", value model.name, onInput UpdateName ]
            , button [ type_ "submit" ] [ text "Go" ]
            ]
        , text
            (if model.confirmed then
                "confirmed:" ++ model.name

             else
                "not-confirmed"
            )
        ]

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

view : Model -> Element Msg
view model =
    Ui.html (htmlView model)

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = DoSignUp
        }
"#;

/// Var-bound bare-Msg onSubmit seal — BUILD-ONLY: the `Var`-bound bare-Msg
/// `onSubmit` form must compile end-to-end. A syntactic classifier would make
/// this `ipe` exit 0 then `cargo build` E0618 (`(m)(_x)` on a non-callable
/// value). A successful `ipe` + `cargo build` IS the assertion.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn live_onsubmit_var_bound_msg_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build(
        "live_onsubmit_var_bound_msg_build_only",
        IPE_ONSUBMIT_VAR_BOUND_MSG,
    )?;
    Ok(())
}

/// Var-bound bare-Msg onSubmit seal — FULL E2E: submitting the `Var`-bound
/// bare-Msg form over the wire must dispatch `DoSignUp` regardless of the posted
/// `FormData`, proving the type-directed classification routes to the
/// fixed-dispatch runtime helper (fires
/// unconditionally) rather than a decoder that could silently swallow the
/// submit. The posted args carry a real field (`name=alice`) the fixed path
/// ignores. Structurally mirrors [`live_onsubmit_bare_msg_dispatches_fixed_msg`].
///
/// # Errors
///
/// Propagates any pipeline, Cargo build, server-spawn, or HTTP error.
#[test]
fn live_onsubmit_var_bound_msg_dispatches_fixed_msg() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let test_name = "live_onsubmit_var_bound_msg";
    let exe = compile_and_build(test_name, IPE_ONSUBMIT_VAR_BOUND_MSG)?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready(test_name, &exe, port)?;
    let addr = format!("127.0.0.1:{port}");

    // ── Step 1: GET / — initial page, extract session cookie + form hid ─────
    let (raw_headers, body) = http_send(test_name, &addr, "GET", "/", &[], None)?;

    let sid = extract_cookie(&raw_headers, "ipe_sid").ok_or_else(|| -> BoxError {
        format!(
            "{test_name}: no ipe_sid cookie in GET / response\n\
             --- raw headers ---\n{raw_headers}"
        )
        .into()
    })?;

    let hid = extract_hid_for_open_tag(&body, "form").ok_or_else(|| -> BoxError {
        format!(
            "{test_name}: could not find data-ipe-hid on <form> in GET / body\n\
             --- first 2000 bytes ---\n{}",
            &body[..body.len().min(2000)]
        )
        .into()
    })?;

    // ── Step 2: POST /_ipe/event — submit with REAL (but ignored) form data ─
    let epoch = extract_epoch(test_name, &body)?;
    let event_body = format!(
        r#"{{"id":"{hid}","event":"submit","args":[{{"name":"alice"}}],"sessionId":"","epoch":"{epoch}","tab":"{TAB}","seq":1}}"#
    );
    let cookie_header = format!("ipe_sid={sid}");
    let (_, post_body) = http_send(
        test_name,
        &addr,
        "POST",
        "/_ipe/event",
        &[
            ("Content-Type", "application/json"),
            ("Cookie", &cookie_header),
        ],
        Some(event_body.as_bytes()),
    )?;

    assert!(
        post_body.contains("patches"),
        "{test_name}: POST /_ipe/event (submit) did not return a patches ACK\nbody: {post_body}"
    );

    // ── Step 3: wait for async model update ─────────────────────────────────
    std::thread::sleep(Duration::from_millis(200));

    // ── Step 4: GET / with session cookie — should show the fixed dispatch ──
    let (_, body2) = http_send(
        test_name,
        &addr,
        "GET",
        "/",
        &[("Cookie", &cookie_header)],
        None,
    )?;

    assert!(
        body2.contains("confirmed:"),
        "{test_name}: DoSignUp was not dispatched on Var-bound bare-Msg \
         onSubmit (expected the re-rendered page to contain \"confirmed:\")\n\
         --- first 2000 bytes of second GET / ---\n{}",
        &body2[..body2.len().min(2000)]
    );

    Ok(())
}

/// Let-bound closure onSubmit — a `let`-bound LOCAL closure dispatched via
/// `Ui.onSubmit`.
///
/// `let handler = \c -> DoSignIn c in ... Ui.onSubmit handler ...`. A `handler`
/// declared `Box<dyn Fn(Creds) -> MainMsg + Send + 'static>` (never `+ Sync`)
/// captured by move into the `ui_on_submit_(move |_x| (handler)(_x))` wrapper
/// would make this `ipe` exit 0 then `cargo build` E0277 (`dyn Fn(..) ->
/// MainMsg + Send` cannot be shared between threads safely). So
/// `ipe_lower::lower_let_pvar` + `flows_into_sync_kernel_call` promote the
/// let-bound closure to `Arc<dyn Fn + Send + Sync>` at its declaration.
const IPE_ONSUBMIT_LET_BOUND_HANDLER: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub

type alias Creds =
    { username : String
    , password : String
    }

type Msg
    = DoSignIn Creds

type alias Model =
    { lastUsername : String
    }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { lastUsername = "" }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        DoSignIn creds ->
            ( { model | lastUsername = creds.username }, Cmd.none )

htmlView : Model -> Html Msg
htmlView model =
    let
        handler = \c -> DoSignIn c
    in
    Ui.layout []
        (Ui.column []
            [ Ui.form
                [ Ui.onSubmit handler ]
                [ Ui.input [ Ui.name "username" ]
                , Ui.input [ Ui.name "password" ]
                , Ui.input [ Ui.htmlAttribute "type" "submit" ]
                ]
            , Ui.text model.lastUsername
            ])

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

view : Model -> Element Msg
view model =
    Ui.html (htmlView model)

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = DoSignIn { username = "", password = "" }
        }
"#;

/// Let-alias chain onSubmit — a MULTI-HOP `let`-alias chain from the root
/// closure to the `Ui.onSubmit` call (`handler` → `inner` → `outer`).
///
/// The `onSubmit` argument (`outer`) is two aliases removed from the closure
/// literal (`handler`). Only promoting the ROOT `handler` binding to
/// `Arc<dyn Fn + Send + Sync>` is both necessary (the alias bindings carry no
/// closure literal to promote) and sufficient (Rust type inference propagates
/// the `Arc` type through each single-owner move), so
/// `flows_into_sync_kernel_call` must be alias-transparent to reach the root.
const IPE_ONSUBMIT_LET_ALIAS_CHAIN: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub

type alias Creds =
    { username : String
    , password : String
    }

type Msg
    = DoSignIn Creds

type alias Model =
    { lastUsername : String
    }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { lastUsername = "" }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        DoSignIn creds ->
            ( { model | lastUsername = creds.username }, Cmd.none )

htmlView : Model -> Html Msg
htmlView model =
    let
        handler = \c -> DoSignIn c
        inner = handler
        outer = inner
    in
    Ui.layout []
        (Ui.column []
            [ Ui.form
                [ Ui.onSubmit outer ]
                [ Ui.input [ Ui.name "username" ]
                , Ui.input [ Ui.htmlAttribute "type" "submit" ]
                ]
            , Ui.text model.lastUsername
            ])

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

view : Model -> Element Msg
view model =
    Ui.html (htmlView model)

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = DoSignIn { username = "", password = "" }
        }
"#;

/// Let-bound closure onSubmit seal — BUILD-ONLY: a single-hop `let`-bound
/// `Ui.onSubmit` handler must compile end-to-end. A successful `ipe` + `cargo
/// build` IS the assertion — a non-`Sync` boxed handler makes this `ipe` exit 0
/// then `cargo build` E0277.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn live_onsubmit_let_bound_handler_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build(
        "live_onsubmit_let_bound_handler_build_only",
        IPE_ONSUBMIT_LET_BOUND_HANDLER,
    )?;
    Ok(())
}

/// Let-alias chain onSubmit seal — BUILD-ONLY: a MULTI-HOP `let`-alias chain
/// into `Ui.onSubmit` must compile end-to-end (see
/// [`IPE_ONSUBMIT_LET_ALIAS_CHAIN`]). Guards the
/// alias-transparent branch of `flows_into_sync_kernel_call`.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn live_onsubmit_let_alias_chain_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build(
        "live_onsubmit_let_alias_chain_build_only",
        IPE_ONSUBMIT_LET_ALIAS_CHAIN,
    )?;
    Ok(())
}

/// Fixture for the unrouted-GET session-wipe regression: a ROUTED app whose
/// `/` page carries a typed-record `onSubmit` form and whose `notFound` page
/// does NOT. The two pages must render DIFFERENT trees so a spurious
/// re-route visibly destroys the form's handler index (same shape as
/// `examples/12-ipevote`: form at `/auth/signup`, `notFound` = board).
const IPE_ONSUBMIT_ROUTED_FORM: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub

type Page
    = FormPage
    | AboutPage

type alias Creds =
    { username : String
    , password : String
    }

type Msg
    = DoSignIn Creds

type alias Model =
    { page : Page
    , lastUsername : String
    }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { page = FormPage, lastUsername = "" }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        DoSignIn creds ->
            ( { model | lastUsername = creds.username }, Cmd.none )

htmlView : Model -> Html Msg
htmlView model =
    case model.page of
        AboutPage ->
            Ui.layout [] (Ui.text "about")

        FormPage ->
            Ui.layout []
                (Ui.column []
                    [ Ui.form
                        [ Ui.onSubmit DoSignIn ]
                        [ Ui.input [ Ui.name "username" ]
                        , Ui.input [ Ui.name "password" ]
                        , Ui.input [ Ui.htmlAttribute "type" "submit" ]
                        ]
                    , Ui.text model.lastUsername
                    ])

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

view : Model -> Element Msg
view model =
    Ui.html (htmlView model)

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = [ Web.route "/" FormPage, Web.route "/about" AboutPage ]
        , notFound = AboutPage
        }
"#;

/// FULL E2E for the "form submission does nothing" case. A real browser
/// interleaves an automatic unrouted GET (`/favicon.ico` — headless Chromium
/// fetches it without surfacing a request event, so browserless wire tests
/// never see it) between the page load and the user's submit. If the page
/// handler's Live-hit branch re-routed the session model for that GET
/// (`/favicon.ico` matches no route → `notFound` page), re-rendered THAT view,
/// and replaced the session's handler index + `last_view`, every subsequent
/// event from the page the browser is actually showing (the form submit
/// included) would resolve against the wrong index and be silently dropped.
///
/// golden parity (live.go `handleInitial`): unrouted browser-noise paths 404
/// before touching session state; an unrouted GET against an existing
/// session 404s without re-routing it.
///
/// Wire sequence (mirrors the real browser):
///  1. `GET /`             → session + typed-record form page.
///  2. `GET /favicon.ico`  (same cookie) → MUST 404 and leave the session
///     untouched (the step that must not wipe the handler index).
///  3. `POST /_ipe/event`  submit with form data → Msg must dispatch.
///  4. `GET /`             → re-rendered page must show the decoded value.
///
/// # Errors
///
/// Propagates any pipeline, spawn, or HTTP failure as a test error.
#[test]
fn live_unrouted_get_does_not_wipe_form_handlers() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let test_name = "live_unrouted_get_wipe";
    let exe = compile_and_build(test_name, IPE_ONSUBMIT_ROUTED_FORM)?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready(test_name, &exe, port)?;
    let addr = format!("127.0.0.1:{port}");

    // ── Step 1: GET / — session cookie + the form page's handler id ────────
    let (raw_headers, body) = http_send(test_name, &addr, "GET", "/", &[], None)?;
    let sid = extract_cookie(&raw_headers, "ipe_sid").ok_or_else(|| -> BoxError {
        format!("{test_name}: no ipe_sid cookie in GET / response").into()
    })?;
    let hid = extract_hid_for_open_tag(&body, "form").ok_or_else(|| -> BoxError {
        format!(
            "{test_name}: could not find data-ipe-hid on <form> in GET / body\n\
             --- first 2000 bytes ---\n{}",
            &body[..body.len().min(2000)]
        )
        .into()
    })?;
    let cookie_header = format!("ipe_sid={sid}");

    // ── Step 2: GET /favicon.ico with the session cookie ───────────────────
    // The browser-noise probe. Must 404 (golden parity) and must NOT re-route
    // the session (asserted indirectly by steps 3–4 dispatching).
    let (noise_headers, _) = http_send(
        test_name,
        &addr,
        "GET",
        "/favicon.ico",
        &[("Cookie", &cookie_header)],
        None,
    )?;
    assert!(
        noise_headers.starts_with("HTTP/1.1 404"),
        "{test_name}: GET /favicon.ico must 404 (browser-noise gate), got:\n{noise_headers}"
    );

    // ── Step 3: POST /_ipe/event — submit the typed-record form ────────────
    let epoch = extract_epoch(test_name, &body)?;
    let event_body = format!(
        r#"{{"id":"{hid}","event":"submit","args":[{{"username":"alice","password":"s3cr3t"}}],"sessionId":"","epoch":"{epoch}","tab":"{TAB}","seq":1}}"#
    );
    let (_, post_body) = http_send(
        test_name,
        &addr,
        "POST",
        "/_ipe/event",
        &[
            ("Content-Type", "application/json"),
            ("Cookie", &cookie_header),
        ],
        Some(event_body.as_bytes()),
    )?;
    assert!(
        post_body.contains("patches"),
        "{test_name}: POST /_ipe/event (submit) did not return a patches ACK\nbody: {post_body}"
    );

    // ── Step 4: the Msg must have dispatched (model re-rendered) ───────────
    std::thread::sleep(Duration::from_millis(200));
    let (_, body2) = http_send(
        test_name,
        &addr,
        "GET",
        "/",
        &[("Cookie", &cookie_header)],
        None,
    )?;
    assert!(
        body2.contains(">alice<"),
        "{test_name}: the submit after GET /favicon.ico did not dispatch — \
         the unrouted GET wiped the session's handler index (the exact \
         examples/12-ipevote break)\n--- first 2000 bytes of second GET / ---\n{}",
        &body2[..body2.len().min(2000)]
    );

    Ok(())
}

/// A generic `.ipe` helper that RETURNS a `Decoder a` built from a
/// caller-supplied value — the `custom`/`enum`-style decoder-factory shape.
///
/// The runtime `Decoder<E, T>` (`ipe_runtime::json::Decoder`) boxes a
/// `Box<dyn Fn(..) -> IpeResult<E, T> + Send>`, so `decode_succeed` bounds its
/// payload `A: 'static + Send`. `custom`'s tvar `a` flows into its return
/// `Decoder a`, so the emitted `fn main_custom<T1>` needs `T1: Send + 'static`;
/// without it `ipe` accepts but `cargo build` fails with E0277 (`T1 cannot be
/// sent between threads safely`) — an exit-0-then-cargo-fail SEAL break. The
/// decoder is then RUN through `Config.decodeJson`, keeping the helper reachable
/// so the generic signature is actually emitted (never DCE'd).
const IPE_GENERIC_DECODER_HELPER: &str = r#"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String
import Ipe.Config as Config exposing (Decoder)
import Ipe.Error exposing (Error)
import Ipe.Result as Result exposing (Result(..))


custom : a -> Decoder a
custom fallback =
    Config.succeed fallback


main : Task Error ()
main =
    case Config.decodeJson "{}" (custom 8080) of
        Ok n ->
            Io.println (String.fromInt n)

        Err _ ->
            Io.println "err"
"#;

/// SEAL — a generic `Decoder`-returning helper must build end-to-end. Without
/// the `Send`-bound obligation on a tvar carried inside a `Decoder<E, tv>`, `ipe`
/// accepts this and the emitted crate fails `cargo build` (`decode_succeed`'s
/// `A: Send` unmet on the helper's unbounded `T1`). A successful `ipe` +
/// `cargo build` IS the assertion.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn live_generic_decoder_helper_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build(
        "live_generic_decoder_helper_build_only",
        IPE_GENERIC_DECODER_HELPER,
    )?;
    Ok(())
}

// ── Ipe.Browser.Geolocation + Ipe.Browser.Clipboard ──────────────────────────
//
// The geo-clipboard example is the first-party proof of the Ipe.Browser.*
// capability surface: two port-direction pairs (outbound Cmd + inbound Sub)
// over the fail-closed JS port mechanism, with the app-boundary consent gate
// satisfied by `package.ipe`'s `accepts` list.
//
// BUILD-ONLY seal: `ipe::build_project` compiles the real on-disk example
// (which carries its `package.ipe` capabilities grant).  A successful
// `cargo build` proves the full emit path for Geolocation + Clipboard —
// their port-glue kernels, SRI-addressed JS, and inbound subscription
// decoders — without requiring a headless browser.
//
// BEHAVIOUR seal: the served initial page must render the four expected
// interaction buttons and the two labelled state lines ("location:" and
// "clipboard:").  This proves the full Ipe.Web pipeline ran to a real HTML
// page — not a blank or error page — and that the Ipe.Browser.* port
// registration did not panic at runtime init.
//
// Real browser behaviour (grant/deny geolocation, clipboard round-trip) is
// covered by the Playwright spec at
// tools/scripts/browser-e2e/geo-clipboard.spec.mjs, which is wired into the
// `browser-e2e` CI job and can also be run locally:
//
//   IPE_E2E=1 cargo test geo_clipboard_browser_build_only   # build
//   bash tools/scripts/browser-e2e/run.sh                  # full browser spec

/// Absolute path to the geo-clipboard `package.ipe` manifest, resolved
/// relative to `CARGO_MANIFEST_DIR` (the `ipe-cli` crate root).
fn geo_clipboard_manifest() -> PathBuf {
    // CARGO_MANIFEST_DIR points at the crate that owns this test binary
    // (src/ipe-cli/), two levels above the workspace root where
    // examples/shapes/web/geo-clipboard/ lives.
    let manifest_dir =
        PathBuf::from(ipe_env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));
    manifest_dir
        .join("../..")
        .join("examples/shapes/web/geo-clipboard/package.ipe")
}

/// Compile and cargo-build the geo-clipboard example from its on-disk
/// `package.ipe` manifest, returning the path to the compiled binary.
///
/// Uses `ipe::build_project_with_options` (not `ipe::build_with_options`) so
/// the capabilities consent gate is applied: without the `accepts = [JsPort Geolocation, JsPort
/// Clipboard, JsPort Raw]` grant the build must fail closed (IPE-S0002).
fn compile_and_build_geo_clipboard() -> Result<PathBuf, BoxError> {
    let manifest = geo_clipboard_manifest();
    let manifest = manifest.canonicalize().map_err(|e| -> BoxError {
        format!(
            "geo-clipboard: cannot canonicalize manifest {}: {}",
            manifest.display(),
            e
        )
        .into()
    })?;

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("live_e2e_geo_clipboard_emitted");
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();

    ipe::build_project_with_options(&manifest, &out_dir, &runtime, &dev_loop_options()).map_err(
        |e| -> BoxError { format!("geo-clipboard: ipe build_project failed: {e}").into() },
    )?;

    let exe = e2e_support::build_rust_binary("geo_clipboard", &out_dir)
        .map_err(|e| -> BoxError { format!("geo-clipboard: cargo build failed: {e}").into() })?;

    Ok(PathBuf::from(exe))
}

/// BUILD-ONLY: the geo-clipboard example compiles end-to-end through
/// `ipe::build_project` (capabilities consent gate active) and its emitted
/// Rust project links cleanly.
///
/// Kernels exercised:
/// - `Ipe.Browser.Geolocation` (`current`, `watch`, `positions` subscription)
/// - `Ipe.Browser.Clipboard` (`write`, `read`, `contents` subscription)
/// - The per-capability JS-port disclosure + fail-closed app-boundary
///   consent gate (`accepts = [JsPort Geolocation, JsPort Clipboard, JsPort Raw]`)
/// - Port-glue SRI-addressed asset serving (`/_ipe/port.<hex16>.js`)
///
/// A successful `ipe::build_project` + `cargo build` IS the assertion.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn geo_clipboard_browser_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build_geo_clipboard()?;
    Ok(())
}

/// BEHAVIOUR: the geo-clipboard app's initial `GET /` must return an HTML page
/// containing all four interaction buttons and the two labelled state lines.
///
/// Assertions (each proves a distinct part of the pipeline):
///
/// - `>Locate<`          — `Ui.button` for `Locate` rendered; TEA `view` ran.
/// - `>Copy location<`   — `Ui.button` for `CopyLocation` rendered.
/// - `>Paste<`           — `Ui.button` for `Paste` rendered.
/// - `location: unknown` — initial `Model.location` rendered correctly.
/// - `clipboard:`        — initial `Model.clipboard` line present (empty string).
///
/// This test does NOT exercise the geolocation or clipboard browser APIs —
/// those require a real browser with permission grants and are covered by the
/// Playwright spec in `tools/scripts/browser-e2e/geo-clipboard.spec.mjs`.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or HTTP error as a test error.
#[test]
fn geo_clipboard_browser_initial_page() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let test_name = "geo_clipboard_browser_initial_page";
    let exe = compile_and_build_geo_clipboard()?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready(test_name, &exe, port)?;

    let addr = format!("127.0.0.1:{port}");
    let body = http_get(test_name, &addr, "/")?;

    // All four buttons must be present in the initial render.
    for expected in &["Locate", "Copy location", "Paste"] {
        assert!(
            body.contains(&format!(">{expected}<")),
            "{test_name}: button text >{expected}< not found in GET / body\n\
             --- first 2000 bytes ---\n{}",
            &body[..body.len().min(2000)]
        );
    }

    // Initial model state lines.
    assert!(
        body.contains("location: unknown"),
        "{test_name}: initial 'location: unknown' not found in GET / body\n\
         --- first 2000 bytes ---\n{}",
        &body[..body.len().min(2000)]
    );
    assert!(
        body.contains("clipboard:"),
        "{test_name}: 'clipboard:' label not found in GET / body\n\
         --- first 2000 bytes ---\n{}",
        &body[..body.len().min(2000)]
    );

    // Must be a proper HTML document, not an error page.
    assert!(
        body.contains("<!DOCTYPE html>") || body.contains("<html"),
        "{test_name}: GET / response does not look like HTML\n\
         --- first 500 bytes ---\n{}",
        &body[..body.len().min(500)]
    );

    Ok(())
}

// ── Ipe.Browser.Gamepad — build-only E2E gate ────────────────────────────────
//
// Proves that the gamepad-watch example compiles end-to-end through
// `ipe::build_project` (capabilities consent gate active) and that its emitted
// Rust project links cleanly. Real browser behaviour (connect/disconnect events,
// polled state frames) requires a physical or emulated gamepad and is not
// exercised by this test.
//
//   IPE_E2E=1 cargo test gamepad_watch_browser_build_only

/// Absolute path to the gamepad-watch `package.ipe` manifest, resolved
/// relative to `CARGO_MANIFEST_DIR` (the `ipe-cli` crate root).
fn gamepad_watch_manifest() -> PathBuf {
    let manifest_dir =
        PathBuf::from(ipe_env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));
    manifest_dir
        .join("../..")
        .join("examples/shapes/web/gamepad-watch/package.ipe")
}

/// Compile and cargo-build the gamepad-watch example from its on-disk
/// `package.ipe` manifest, returning the path to the compiled binary.
///
/// Uses `ipe::build_project` so the capabilities consent gate is applied:
/// without the `accepts = [JsPort Gamepad, JsPort Raw]` grant the build must
/// fail closed (IPE-S0002).
fn compile_and_build_gamepad_watch() -> Result<PathBuf, BoxError> {
    let manifest = gamepad_watch_manifest();
    let manifest = manifest.canonicalize().map_err(|e| -> BoxError {
        format!(
            "gamepad-watch: cannot canonicalize manifest {}: {}",
            manifest.display(),
            e
        )
        .into()
    })?;

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("live_e2e_gamepad_watch_emitted");
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();

    ipe::build_project_with_options(&manifest, &out_dir, &runtime, &dev_loop_options()).map_err(
        |e| -> BoxError { format!("gamepad-watch: ipe build_project failed: {e}").into() },
    )?;

    let exe = e2e_support::build_rust_binary("gamepad_watch", &out_dir)
        .map_err(|e| -> BoxError { format!("gamepad-watch: cargo build failed: {e}").into() })?;

    Ok(PathBuf::from(exe))
}

/// BUILD-ONLY: the gamepad-watch example compiles end-to-end through
/// `ipe::build_project` (capabilities consent gate active) and its emitted
/// Rust project links cleanly.
///
/// Kernels exercised:
/// - `Ipe.Browser.Gamepad` (`watch`, `stopWatch`, `events` subscription)
/// - The per-capability JS-port disclosure + fail-closed app-boundary
///   consent gate (`accepts = [JsPort Gamepad, JsPort Raw]`)
/// - Port-glue SRI-addressed asset serving (`/_ipe/port.<hex16>.js`)
///
/// A successful `ipe::build_project` + `cargo build` IS the assertion.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn gamepad_watch_browser_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build_gamepad_watch()?;
    Ok(())
}

// ── Ipe.Browser.Recorder — build-only E2E gate ───────────────────────────────
//
// Proves that the recorder-stream example compiles end-to-end through
// `ipe::build_project` (capabilities consent gate active) and that its emitted
// Rust project links cleanly. Real browser behaviour (getUserMedia prompt,
// MediaRecorder chunk stream, stop) requires a physical camera/microphone and a
// real page, and is not exercised by this build-only test.
//
//   IPE_E2E=1 cargo test recorder_stream_browser_build_only

/// Absolute path to the recorder-stream `package.ipe` manifest, resolved
/// relative to `CARGO_MANIFEST_DIR` (the `ipe-cli` crate root).
fn recorder_stream_manifest() -> PathBuf {
    let manifest_dir =
        PathBuf::from(ipe_env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));
    manifest_dir
        .join("../..")
        .join("examples/shapes/web/recorder-stream/package.ipe")
}

/// Compile and cargo-build the recorder-stream example from its on-disk
/// `package.ipe` manifest, returning the path to the compiled binary.
///
/// Uses `ipe::build_project` so the capabilities consent gate is applied:
/// without the `accepts = [JsPort Recorder, JsPort Raw]` grant the build must
/// fail closed (IPE-S0002).
fn compile_and_build_recorder_stream() -> Result<PathBuf, BoxError> {
    let manifest = recorder_stream_manifest();
    let manifest = manifest.canonicalize().map_err(|e| -> BoxError {
        format!(
            "recorder-stream: cannot canonicalize manifest {}: {}",
            manifest.display(),
            e
        )
        .into()
    })?;

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("live_e2e_recorder_stream_emitted");
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();

    ipe::build_project_with_options(&manifest, &out_dir, &runtime, &dev_loop_options()).map_err(
        |e| -> BoxError { format!("recorder-stream: ipe build_project failed: {e}").into() },
    )?;

    let exe = e2e_support::build_rust_binary("recorder_stream", &out_dir)
        .map_err(|e| -> BoxError { format!("recorder-stream: cargo build failed: {e}").into() })?;

    Ok(PathBuf::from(exe))
}

/// BUILD-ONLY: the recorder-stream example compiles end-to-end through
/// `ipe::build_project` (capabilities consent gate active) and its emitted
/// Rust project links cleanly.
///
/// Kernels exercised:
/// - `Ipe.Browser.Recorder` (`startAudio`, `startVideo`, `stop`, `chunks`
///   subscription, the opaque `Recording` handle)
/// - The per-capability JS-port disclosure + fail-closed app-boundary
///   consent gate (`accepts = [JsPort Recorder, JsPort Raw]`)
/// - Port-glue SRI-addressed asset serving (`/_ipe/port.<hex16>.js`)
///
/// A successful `ipe::build_project` + `cargo build` IS the assertion.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn recorder_stream_browser_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build_recorder_stream()?;
    Ok(())
}

// ── Ipe.Browser.WebAuthn — build-only E2E gate ───────────────────────────────
//
// Proves that the web-authn example compiles end-to-end through
// `ipe::build_project` (capabilities consent gate active) and that its emitted
// Rust project links cleanly. Real ceremony behaviour (the authenticator prompt,
// the attestation / assertion returned by navigator.credentials) requires a real
// browser, a secure context, and a physical authenticator, and is not exercised
// by this build-only test.
//
//   IPE_E2E=1 cargo test web_authn_browser_build_only

/// Absolute path to the web-authn `package.ipe` manifest, resolved relative to
/// `CARGO_MANIFEST_DIR` (the `ipe-cli` crate root).
fn web_authn_manifest() -> PathBuf {
    let manifest_dir =
        PathBuf::from(ipe_env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));
    manifest_dir
        .join("../..")
        .join("examples/shapes/web/web-authn/package.ipe")
}

/// Compile and cargo-build the web-authn example from its on-disk `package.ipe`
/// manifest, returning the path to the compiled binary.
///
/// Uses `ipe::build_project` so the capabilities consent gate is applied:
/// without the `accepts = [JsPort WebAuthn, JsPort Raw]` grant the build must
/// fail closed (IPE-S0002).
fn compile_and_build_web_authn() -> Result<PathBuf, BoxError> {
    let manifest = web_authn_manifest();
    let manifest = manifest.canonicalize().map_err(|e| -> BoxError {
        format!(
            "web-authn: cannot canonicalize manifest {}: {}",
            manifest.display(),
            e
        )
        .into()
    })?;

    let out_dir =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("live_e2e_web_authn_emitted");
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();

    ipe::build_project_with_options(&manifest, &out_dir, &runtime, &dev_loop_options())
        .map_err(|e| -> BoxError { format!("web-authn: ipe build_project failed: {e}").into() })?;

    let exe = e2e_support::build_rust_binary("web_authn", &out_dir)
        .map_err(|e| -> BoxError { format!("web-authn: cargo build failed: {e}").into() })?;

    Ok(PathBuf::from(exe))
}

/// BUILD-ONLY: the web-authn example compiles end-to-end through
/// `ipe::build_project` (capabilities consent gate active) and its emitted Rust
/// project links cleanly.
///
/// Kernels exercised:
/// - `Ipe.Browser.WebAuthn` (`register`, `authenticate` over the port→Task
///   bridge, the opaque `PublicKeyCredential` handle)
/// - The per-capability JS-port disclosure + fail-closed app-boundary consent
///   gate (`accepts = [JsPort WebAuthn, JsPort Raw]`)
/// - Port-glue SRI-addressed asset serving (`/_ipe/port.<hex16>.js`)
///
/// A successful `ipe::build_project` + `cargo build` IS the assertion.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn web_authn_browser_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let _exe = compile_and_build_web_authn()?;
    Ok(())
}

// ── Credential revocation and the credential cap ─────────────────────────────

/// The first `max` characters of `text`, for a failure message.
fn head(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// The status code on the status line of raw response headers.
fn status_code(raw_headers: &str) -> Option<u16> {
    raw_headers
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Whether raw response headers carry `name: value`, both case-insensitive.
fn has_header(raw_headers: &str, name: &str, value: &str) -> bool {
    raw_headers.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case(name) && v.trim().eq_ignore_ascii_case(value)
        })
    })
}

/// The `(name, value)` of the session cookie a response sets.
///
/// A mounted app suffixes the `ipe_sid` name with its base path, so the name
/// is matched by prefix.
fn extract_session_cookie(raw_headers: &str) -> Option<(String, String)> {
    for line in raw_headers.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        let pair = value.trim().split(';').next().unwrap_or_default();
        let Some((name, sid)) = pair.split_once('=') else {
            continue;
        };
        if name.trim().starts_with("ipe_sid") {
            return Some((name.trim().to_owned(), sid.trim().to_owned()));
        }
    }
    None
}

/// Whether a response is the Web runtime's session-lost answer.
///
/// That is a `404` with the `x-ipe-web: 1` marker and the `session not found`
/// body, which the client turns into a fresh page load.
fn is_session_lost(raw_headers: &str, body: &str) -> bool {
    status_code(raw_headers) == Some(404)
        && has_header(raw_headers, "x-ipe-web", "1")
        && body.contains("session not found")
}

/// One rendered page: the session it joined and the `+` handler it shows.
struct Page {
    /// The `Cookie` header value naming the page's session.
    cookie: String,
    /// The session id the page set.
    sid: String,
    /// The handler id of the `+` element.
    hid: String,
    /// The render epoch the page's handlers resolve against.
    epoch: String,
    /// The page body.
    body: String,
}

/// `GET path` with `cookie`, read as a page that sets a session cookie.
///
/// # Errors
///
/// Returns an error when the request fails, or the response sets no session
/// cookie, shows no `+` handler or carries no render epoch.
fn get_page(
    test_name: &str,
    addr: &str,
    path: &str,
    cookie: Option<&str>,
) -> Result<Page, BoxError> {
    let headers: Vec<(&str, &str)> = cookie.map(|c| ("Cookie", c)).into_iter().collect();
    let (raw_headers, body) = http_send(test_name, addr, "GET", path, &headers, None)?;
    let (name, sid) = extract_session_cookie(&raw_headers).ok_or_else(|| -> BoxError {
        format!(
            "{test_name}: GET {path} set no session cookie\n--- raw headers ---\n{raw_headers}\n--- body ---\n{}",
            head(&body, 2000)
        )
        .into()
    })?;
    let hid = extract_hid_near_text(&body, "+").ok_or_else(|| -> BoxError {
        format!(
            "{test_name}: GET {path} shows no '+' handler\n--- body ---\n{}",
            head(&body, 2000)
        )
        .into()
    })?;
    let epoch = extract_epoch(test_name, &body)?;
    Ok(Page {
        cookie: format!("{name}={sid}"),
        sid,
        hid,
        epoch,
        body,
    })
}

/// POST one `+` click against `page` and return `(raw_headers, body)`.
///
/// # Errors
///
/// Returns an error when the request fails.
fn post_click(
    test_name: &str,
    addr: &str,
    event_path: &str,
    page: &Page,
    seq: u64,
) -> Result<(String, String), BoxError> {
    let event_body = format!(
        r#"{{"id":"{}","msg":"click","args":[],"sessionId":"","epoch":"{}","tab":"{TAB}","seq":{seq}}}"#,
        page.hid, page.epoch
    );
    http_send(
        test_name,
        addr,
        "POST",
        event_path,
        &[
            ("Content-Type", "application/json"),
            ("Cookie", &page.cookie),
        ],
        Some(event_body.as_bytes()),
    )
}

/// A `Server` that issues a token for `alice`, revokes its bearer's subject,
/// and mounts a single-page `Web.embed` app whose `init` verifies the `auth`
/// cookie and shows who it admitted.
///
/// The program never calls `Server.withRevocation`: the revocation gate is
/// armed only by the operator env floor, so one binary runs armed and unarmed.
const IPE_SERVER_REVOCATION_MOUNT: &str = r#"module Main exposing (main)

import Ipe.Auth as Auth
import Ipe.Auth.Revocation as Revocation
import Ipe.Dict as Dict
import Ipe.Error as Error exposing (Error)
import Ipe.Http.Server as Server
import Ipe.Http.Server exposing (Request, Response)
import Ipe.Maybe as Maybe exposing (Maybe(..))
import Ipe.Result as Result exposing (Result(..))
import Ipe.Secret as Secret
import Ipe.String as String
import Ipe.System as System
import Ipe.Task as Task exposing (Task)
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
import Ipe.Ui as Ui


signingKey : Secret.Secret
signingKey =
    Secret.fromString (System.getenvOr "LIVE_E2E_SIGNING_KEY" "live-e2e-revocation-signing-key-of-32-bytes-or-more")


type Msg
    = Increment


type alias Model =
    { user : String
    , count : Int
    }


userOf : String -> String
userOf token =
    case Auth.verifyToken signingKey token of
        Ok claims ->
            Maybe.withDefault "anon" (Dict.get "sub" claims)

        Err _ ->
            "anon"


init : WebReq -> ( Model, Cmd Msg )
init req =
    ( { user = userOf (Maybe.withDefault "" (Dict.get "auth" req.cookies)), count = 0 }, Cmd.none )


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )


htmlView : Model -> Html Msg
htmlView model =
    Ui.layout []
        (Ui.column []
            [ Ui.text (String.concat [ "user:", model.user ])
            , Ui.el [ Ui.onClick Increment ] (Ui.text "+")
            , Ui.text (String.fromInt model.count)
            ])


view : Model -> Element Msg
view model =
    Ui.html (htmlView model)


subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none


issueToken : Request -> Task Error Response
issueToken _req =
    case Auth.signToken signingKey (Dict.fromList [ ( "sub", "alice" ) ]) 3600 of
        Ok token ->
            Task.succeed (Server.text token)

        Err e ->
            Task.succeed (Server.text (String.concat [ "token-error:", Error.message e ]))


revoke : Request -> Auth.Principal -> Task Error Response
revoke _req principal =
    Task.onError
        (\_ -> Task.succeed (Server.text "revoke-error"))
        (Task.andThen
            (\_ -> Task.succeed (Server.text "revoked"))
            (Revocation.revokeUser principal (Auth.subject principal))
        )


main : Task Error ()
main =
    let port = Maybe.withDefault 8080 (String.toInt (System.getenvOr "IPE_SERVER_PORT" "8080"))
    in
    Server.listen port
        [ Server.get "/token" issueToken
        , Server.postAuthed "/revoke" (Server.authConfig signingKey Server.bearerToken) revoke
        , Server.mountApp "/app"
            (Web.embed
                { init = init
                , update = update
                , view = view
                , subscriptions = subscriptions
                , routes = []
                , notFound = Increment
                }
            )
        ]
"#;

/// A `Server` program: `IPE_SERVER_PORT` and the `[ipe.http.server]` banner.
const fn server_launch<'a>(extra_env: &'a [(&'a str, &'a str)]) -> Launch<'a> {
    Launch {
        port_var: "IPE_SERVER_PORT",
        ready_marker: "[ipe.http.server] listening on",
        extra_env,
    }
}

/// The mounted app's page path: `/app/`, else `/app`, whichever serves it.
///
/// # Errors
///
/// Returns an error when neither path serves the page.
fn first_mounted_page(
    test_name: &str,
    addr: &str,
    cookie: &str,
) -> Result<(String, Page), BoxError> {
    let mut misses = Vec::new();
    for path in ["/app/", "/app"] {
        match get_page(test_name, addr, path, Some(cookie)) {
            Ok(page) => return Ok((path.to_owned(), page)),
            Err(e) => misses.push(e.to_string()),
        }
    }
    Err(format!(
        "{test_name}: the mounted app served no page\n{}",
        misses.join("\n")
    )
    .into())
}

/// Revoke alice through the mounted server's `/revoke` route and require the
/// `revoked` answer.
///
/// # Errors
///
/// Returns an error when the request fails or the route does not answer
/// `revoked`.
fn revoke_alice(test_name: &str, addr: &str, token: &str) -> Result<(), BoxError> {
    let bearer = format!("Bearer {token}");
    let (raw_headers, body) = http_send(
        test_name,
        addr,
        "POST",
        "/revoke",
        &[("Authorization", &bearer)],
        Some(b"".as_slice()),
    )?;
    if body.trim() == "revoked" {
        Ok(())
    } else {
        Err(format!(
            "{test_name}: POST /revoke did not answer `revoked`\n--- raw headers ---\n{raw_headers}\n--- body ---\n{}",
            head(&body, 2000)
        )
        .into())
    }
}

/// What one run of the mounted program observed after revoking alice.
struct RevokedRun {
    /// The page path the mounted app answered on.
    path: String,
    /// The page alice's session rendered.
    page: Page,
    /// The auth cookie carrying alice's token.
    auth_cookie: String,
    /// The raw headers of the event sent after the revocation.
    after_headers: String,
    /// The body of the event sent after the revocation.
    after_body: String,
}

/// Issue a token, open alice's mounted session, click once, revoke alice and
/// click again.
///
/// # Errors
///
/// Returns an error on any request failure, a page that did not admit alice,
/// a first click that was not acknowledged, or a refused revocation.
fn revoke_during_session(test_name: &str, addr: &str) -> Result<RevokedRun, BoxError> {
    let token = http_get(test_name, addr, "/token")?.trim().to_owned();
    if token.is_empty() || token.starts_with("token-error") {
        return Err(format!("{test_name}: GET /token issued no token: {token}").into());
    }
    let auth_cookie = format!("auth={token}");

    let (path, page) = first_mounted_page(test_name, addr, &auth_cookie)?;
    if !page.body.contains(">user:alice<") {
        return Err(format!(
            "{test_name}: the mounted page did not admit alice's verified token\n--- body ---\n{}",
            head(&page.body, 2000)
        )
        .into());
    }

    let event_path = "/app/_ipe/event";
    let (first_headers, first_body) = post_click(test_name, addr, event_path, &page, 1)?;
    if !first_body.contains("patches") {
        return Err(format!(
            "{test_name}: the click before the revocation was not acknowledged\n--- raw headers ---\n{first_headers}\n--- body ---\n{first_body}"
        )
        .into());
    }
    std::thread::sleep(Duration::from_millis(200));

    revoke_alice(test_name, addr, &token)?;

    let (after_headers, after_body) = post_click(test_name, addr, event_path, &page, 2)?;
    Ok(RevokedRun {
        path,
        page,
        auth_cookie,
        after_headers,
        after_body,
    })
}

/// A user revoked through a mounted server loses its live Web session.
///
/// The gate is armed by `IPE_AUTH_REVOCATION=store` alone. After the server's
/// `/revoke` route revokes alice, the session's next event answers
/// session-lost and a page reload re-runs `init`, which no longer admits the
/// revoked token. The same binary run unarmed keeps the session, so the
/// session-lost answer is the gate's, not the route's.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, HTTP, or assertion error.
#[test]
fn web_session_revoked_through_mounted_server_is_session_lost() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "web_session_revoked_through_mounted_server";
    let exe = compile_and_build(test_name, IPE_SERVER_REVOCATION_MOUNT)?;

    // ── Armed: the env floor alone arms the gate ─────────────────────────────
    {
        let port = pick_ephemeral_port()?;
        let armed_env = [
            ("IPE_HTTP_BIND", "127.0.0.1"),
            ("IPE_AUTH_REVOCATION", "store"),
        ];
        let _guard = spawn_ready_with(test_name, &exe, port, &server_launch(&armed_env))?;
        let addr = format!("127.0.0.1:{port}");

        let run = revoke_during_session(test_name, &addr)?;
        assert!(
            is_session_lost(&run.after_headers, &run.after_body),
            "{test_name}: an event after the revocation must answer session-lost\n--- raw headers ---\n{}\n--- body ---\n{}",
            run.after_headers,
            run.after_body
        );

        // The reload carries the closed sid and the revoked token: the closed
        // session is gone, so `init` runs under a fresh sid and refuses the
        // revoked token.
        let reload_cookie = format!("{}; {}", run.page.cookie, run.auth_cookie);
        let reload = get_page(test_name, &addr, &run.path, Some(&reload_cookie))?;
        assert_ne!(
            reload.sid, run.page.sid,
            "{test_name}: the reload must not rejoin the revoked session"
        );
        assert!(
            reload.body.contains(">user:anon<") && !reload.body.contains(">user:alice<"),
            "{test_name}: the reload must not admit the revoked token\n--- body ---\n{}",
            head(&reload.body, 2000)
        );
    }

    // ── Unarmed control: the same binary keeps the session ───────────────────
    {
        let port = pick_ephemeral_port()?;
        let off_env = [("IPE_HTTP_BIND", "127.0.0.1")];
        let _guard = spawn_ready_with(test_name, &exe, port, &server_launch(&off_env))?;
        let addr = format!("127.0.0.1:{port}");

        let run = revoke_during_session(test_name, &addr)?;
        assert!(
            run.after_body.contains("patches"),
            "{test_name}: unarmed, the event after the revocation must still be acknowledged\n--- raw headers ---\n{}\n--- body ---\n{}",
            run.after_headers,
            run.after_body
        );
    }

    Ok(())
}

/// A standalone `Web.appWith` app armed by `Web.withRevocation` whose `init`
/// signs and verifies its own token, so every session carries a credential
/// whose cap the operator sets.
const IPE_WEB_CAPPED_SESSION: &str = r#"module Main exposing (main)

import Ipe.Auth as Auth
import Ipe.Dict as Dict
import Ipe.Maybe as Maybe exposing (Maybe(..))
import Ipe.Result as Result exposing (Result(..))
import Ipe.Secret as Secret
import Ipe.String as String
import Ipe.System as System
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
import Ipe.Ui as Ui


signingKey : Secret.Secret
signingKey =
    Secret.fromString (System.getenvOr "LIVE_E2E_SIGNING_KEY" "live-e2e-capped-session-signing-key-of-32-bytes-or-more")


type Msg
    = Increment


type alias Model =
    { user : String
    , count : Int
    }


userOf : String -> String
userOf token =
    case Auth.verifyToken signingKey token of
        Ok claims ->
            Maybe.withDefault "anon" (Dict.get "sub" claims)

        Err _ ->
            "anon"


init : WebReq -> ( Model, Cmd Msg )
init _req =
    case Auth.signToken signingKey (Dict.fromList [ ( "sub", "alice" ) ]) 3600 of
        Ok token ->
            ( { user = userOf token, count = 0 }, Cmd.none )

        Err _ ->
            ( { user = "unsigned", count = 0 }, Cmd.none )


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )


htmlView : Model -> Html Msg
htmlView model =
    Ui.layout []
        (Ui.column []
            [ Ui.text (String.concat [ "user:", model.user ])
            , Ui.el [ Ui.onClick Increment ] (Ui.text "+")
            , Ui.text (String.fromInt model.count)
            ])


view : Model -> Element Msg
view model =
    Ui.html (htmlView model)


subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none


main =
    Web.appWith
        [ Web.withRevocation Web.revocationStore
        ]
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = Increment
        }
"#;

/// The credential cap, in seconds, the capped-session test runs under.
///
/// Long enough that a restart lands well inside it, short enough that the
/// session ends within the poll ceiling.
const CAP_SECONDS: &str = "10";

/// How long the capped-session test waits for the session to end.
const CAP_POLL_CEILING: Duration = Duration::from_secs(30);

/// A standalone Web session ends at its credential cap, across a restart.
///
/// The session is persisted to a file store with its verified credential,
/// the server is killed and restarted, and the restored session rejoins with
/// its model. Its credential is re-proved on restore, so once the cap passes
/// its next event answers session-lost.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, HTTP, or assertion error.
#[test]
fn standalone_web_tea_session_ends_at_cap() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "standalone_web_tea_session_ends_at_cap";
    let exe = compile_and_build(test_name, IPE_WEB_CAPPED_SESSION)?;

    let store_path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("live_e2e_{test_name}_sessions.json"));
    let _ = std::fs::remove_file(&store_path);
    let store_path = store_path.to_str().ok_or_else(|| -> BoxError {
        format!("{test_name}: the session-store path is not UTF-8").into()
    })?;
    let env = [
        ("IPE_AUTH_MAX_LIFETIME", CAP_SECONDS),
        ("IPE_AUTH_SLIDE_WINDOW", "1"),
        ("IPE_WEB_STORE", "file"),
        ("IPE_WEB_STORE_PATH", store_path),
    ];
    let launch = Launch {
        extra_env: &env,
        ..WEB_LAUNCH
    };

    // ── First run: open the session and commit one click ─────────────────────
    let sid = {
        let port = pick_ephemeral_port()?;
        let _guard = spawn_ready_with(test_name, &exe, port, &launch)?;
        let addr = format!("127.0.0.1:{port}");

        let page = get_page(test_name, &addr, "/", None)?;
        assert!(
            page.body.contains(">user:alice<") && page.body.contains(">0<"),
            "{test_name}: `init` did not admit its own token\n--- body ---\n{}",
            head(&page.body, 2000)
        );
        let (raw_headers, body) = post_click(test_name, &addr, "/_ipe/event", &page, 1)?;
        assert!(
            body.contains("patches"),
            "{test_name}: the first click was not acknowledged\n--- raw headers ---\n{raw_headers}\n--- body ---\n{body}"
        );
        // The driver commits and checkpoints after `update`.
        std::thread::sleep(Duration::from_millis(300));
        page.sid
    };

    // ── Second run: the persisted session restores, then ends at its cap ─────
    let port = pick_ephemeral_port()?;
    let _guard = spawn_ready_with(test_name, &exe, port, &launch)?;
    let addr = format!("127.0.0.1:{port}");

    let cookie = format!("ipe_sid={sid}");
    let restored = get_page(test_name, &addr, "/", Some(&cookie))?;
    assert_eq!(
        restored.sid, sid,
        "{test_name}: the restart must rejoin the persisted session, not mint a new one"
    );
    assert!(
        restored.body.contains(">1<") && restored.body.contains(">user:alice<"),
        "{test_name}: the persisted session did not restore with its model\n--- body ---\n{}",
        head(&restored.body, 2000)
    );
    let (raw_headers, body) = post_click(test_name, &addr, "/_ipe/event", &restored, 2)?;
    assert!(
        body.contains("patches"),
        "{test_name}: the restored session's first click was not acknowledged\n--- raw headers ---\n{raw_headers}\n--- body ---\n{body}"
    );

    let deadline = Instant::now() + CAP_POLL_CEILING;
    let mut seq = 3;
    loop {
        std::thread::sleep(Duration::from_millis(250));
        let (raw_headers, body) = post_click(test_name, &addr, "/_ipe/event", &restored, seq)?;
        if is_session_lost(&raw_headers, &body) {
            break;
        }
        // Before the cap an event is acknowledged, or refused as stale once
        // its render leaves the retained history; anything else is a fault.
        let status = status_code(&raw_headers);
        if status != Some(200) && status != Some(409) {
            return Err(format!(
                "{test_name}: an event before the session ended answered {status:?}\n--- raw headers ---\n{raw_headers}\n--- body ---\n{body}"
            )
            .into());
        }
        if Instant::now() > deadline {
            return Err(format!(
                "{test_name}: the restored session outlived its {CAP_SECONDS} s credential cap by the {} s poll ceiling",
                CAP_POLL_CEILING.as_secs()
            )
            .into());
        }
        seq += 1;
    }
    Ok(())
}

//! End-to-end proof that an emitted `CustomElement.node` is LIVE in the browser (WP5).
//!
//! WP4 renders a `<ipe-ce-… state="…">` node; WP5 serves the author widget JS
//! content-addressed + SRI, generates the registration glue, and wires up-events
//! back through `/_ipe/event`. This test proves the whole loop at the HTTP layer
//! against a REAL build (no loud-skip): it compiles a `Web.tea` with a
//! `CustomElement.node`, spawns the emitted binary, and drives it over raw sockets.
//!
//! What it proves:
//!
//! 1. **Page references the SRI'd glue + preloads the author asset.** `GET /`
//!    carries an external `<script type="module" … integrity="sha256-…"
//!    crossorigin="anonymous">` for the glue and a `<link rel="modulepreload" …
//!    integrity="sha256-…">` for the author asset — no inline script.
//! 2. **SRI content-pinning: page == bytes.** The author asset served at its
//!    content-addressed URL is byte-identical to the author file, AND
//!    `sha256(served bytes)` equals the `integrity` the page pinned. A tampered
//!    byte would change the hash → the browser would refuse; this asserts the
//!    invariant the browser relies on.
//! 3. **Glue defines only the compiler tag + imports the asset.** The served
//!    glue `customElements.define`s the `ipe-ce-*` tag and `import`s the author
//!    asset URL — never evals, never defines an author-controlled name.
//! 4. **Down-state reaches the node as an escaped attribute** (not spliced into a
//!    script), carrying the initial model state.
//! 5. **Up-event round-trips through `/_ipe/event`.** A valid up-body posted
//!    under the `ipe-widget` event updates the model (the down-state attribute
//!    re-renders); a MALFORMED up-body is DROPPED fail-closed (no update), the
//!    WP4 seal decoder's contract, observable at the model level.
//!
//! Gated on `IPE_E2E=1`; without it every test returns early so the default
//! `cargo test` stays fast.
//!
//! ```text
//! IPE_E2E=1 cargo test --test widget_e2e
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use sha2::{Digest, Sha256};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

// ── The Ipê program + author widget JS ──────────────────────────────────────

/// A `Web.tea` whose view mounts one `CustomElement.node`. The down-state is the current
/// count (so a model change re-renders the `state` attribute); the up-event
/// `Bumped n` folds `n` into the count, so a valid up-event is observable as a
/// count change and a malformed one leaves the count untouched (the fail-closed
/// drop). A plain `>N<` counter text sits beside the widget so the HTTP-layer
/// assertions can read the model without parsing the widget attribute.
const WIDGET_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Ffi.Js.CustomElement as CustomElement
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
import Ipe.String

type alias WidgetState = { count : Int }

type WidgetUp = Bumped Int

type Msg = FromWidget WidgetUp

type alias Model = { count : Int }

counter : CustomElement WidgetState WidgetUp
counter = CustomElement.fromFile "js/counter.js"

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        FromWidget (Bumped n) ->
            ( { model | count = model.count + n }, Cmd.none )

view : Model -> Element Msg
view model =
    Ui.column []
        [ CustomElement.node counter { count = model.count } FromWidget
        , Ui.text (String.fromInt model.count)
        ]

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = FromWidget (Bumped 0)
        }
"#;

/// The author hook module. Renders the down-state and, on a host `click`, emits a
/// typed up-event. Its exact bytes are what the page SRI pins and the asset route
/// serves; the HTTP-layer test verifies that content-pinning, not the DOM
/// behaviour (which needs a browser — asserted structurally in the glue instead).
const COUNTER_JS: &str = "export function mount(host, emit) {\n\
  return {\n\
    onState(state) { host.textContent = \"count=\" + (state && state.count); },\n\
  };\n\
}\n";

// ── Build + spawn harness (mirrors live_e2e) ────────────────────────────────

/// The `ipe dev build` dev-loop intent: these fixtures exercise the dev posture
/// (plain cookie names, loopback upstreams), which a release binary refuses.
fn dev_loop_options() -> ipe::BuildOptions {
    ipe::BuildOptions {
        intent: ipe_backend_rust::BuildIntent::Development,
        ..ipe::BuildOptions::from_env()
    }
}

/// Compile the program (with the author JS file present so the `customElement`
/// existence gate clears), build the emitted Rust project, and return the binary
/// path.
fn compile_and_build(test_name: &str, ipe_source: &str) -> Result<PathBuf, BoxError> {
    let ipe_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("widget_e2e_{test_name}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(ipe_dir.join("js")).map_err(|e| -> BoxError {
        format!("{test_name}: cannot create ipe source dir: {e}").into()
    })?;
    std::fs::write(ipe_dir.join("js").join("counter.js"), COUNTER_JS)
        .map_err(|e| -> BoxError { format!("{test_name}: cannot write counter.js: {e}").into() })?;

    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, ipe_source)
        .map_err(|e| -> BoxError { format!("{test_name}: cannot write Main.ipe: {e}").into() })?;

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("widget_e2e_{test_name}_emitted"));
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();

    ipe::build_with_options(&entry, &out_dir, &runtime, dev_loop_options())
        .map_err(|e| -> BoxError { format!("{test_name}: ipe dev build failed: {e}").into() })?;

    let exe = e2e_support::build_rust_binary(test_name, &out_dir)
        .map_err(|e| -> BoxError { format!("{test_name}: cargo build failed: {e}").into() })?;

    Ok(PathBuf::from(exe))
}

/// Reserve an ephemeral loopback port (bind port 0, drop the listener).
fn pick_ephemeral_port() -> Result<u16, BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| -> BoxError { format!("cannot bind ephemeral port: {e}").into() })?;
    let port = listener
        .local_addr()
        .map_err(|e| -> BoxError { format!("cannot read ephemeral port: {e}").into() })?
        .port();
    Ok(port)
}

/// RAII guard: kills the child on drop.
struct ProcessGuard(Child);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn the Web binary and wait for its `[ipe.web] listening on` readiness line.
fn spawn_and_wait_ready(
    test_name: &str,
    exe: &std::path::Path,
    port: u16,
) -> Result<ProcessGuard, BoxError> {
    let mut child = Command::new(exe)
        .env("IPE_WEB_PORT", port.to_string())
        // Disable the double-submit CSRF check so raw-socket POSTs work (the
        // client-side CSRF wiring is exercised structurally in the glue; here we
        // drive the wire directly). The up-event path is otherwise identical.
        .env("IPE_CSRF", "off")
        .env("IPE_CONSOLE_EMBED", "off")
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
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{test_name}: child stderr closed before readiness").into());
            }
            Ok(_) => {
                if line.contains("[ipe.web] listening on") {
                    // KEEP DRAINING the child's stderr on a background thread after
                    // readiness. If the read end is dropped here, the child's next
                    // `eprintln!` (session-store line, per-request logs) hits a
                    // broken pipe; Rust ignores SIGPIPE, so the write errors and
                    // `eprintln!` PANICS inside the accept/log path, killing the
                    // listener after it has already bound — the connect then races
                    // an about-to-die server. Draining keeps the pipe open and
                    // empty, so the child never blocks or faults on a log write.
                    let drain = std::thread::Builder::new().spawn(move || {
                        let mut sink = reader;
                        let mut buf = String::new();
                        while sink.read_line(&mut buf).is_ok_and(|n| n > 0) {
                            buf.clear();
                        }
                    });
                    // The guard owns the child before the drain verdict, so a
                    // refused drain thread still kills and reaps the server.
                    let guard = ProcessGuard(child);
                    drain.map_err(|e| -> BoxError {
                        format!("{test_name}: cannot start the stderr drain: {e}").into()
                    })?;
                    return Ok(guard);
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

/// Poll the loopback address until a TCP connect succeeds or the deadline
/// passes. The readiness line is printed as the listener binds, but there is a
/// small window (and, with an ephemeral port just released by
/// `pick_ephemeral_port`, a TOCTOU) before the socket accepts — so the first
/// request can race an unbound port. This closes that race without masking a real
/// failure: a genuinely-dead server still fails after the deadline.
fn wait_until_connectable(test_name: &str, addr: &str) -> Result<(), BoxError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(addr) {
            Ok(_) => return Ok(()),
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                return Err(format!("{test_name}: server never accepted a connection: {e}").into());
            }
        }
    }
}

/// Send a raw HTTP/1.1 request; return `(raw_headers, body)`.
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

/// Extract a named cookie value from raw response headers.
fn extract_cookie(raw_headers: &str, name: &str) -> Option<String> {
    for line in raw_headers.lines() {
        if !line.to_ascii_lowercase().starts_with("set-cookie:") {
            continue;
        }
        let value_part = line["set-cookie:".len()..].trim();
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

/// The `data-ipe-hid` on the element carrying the `ipe-widget` up-event marker.
/// The widget node renders `… ipe-widget="ipe-widget" data-ipe-hid="…"`; find the
/// nearest `data-ipe-hid` attribute inside that opening tag.
fn extract_widget_hid(html: &str) -> Option<String> {
    let marker = html.find("ipe-widget=")?;
    // The opening tag containing the marker starts at the preceding `<`.
    let tag_start = html[..marker].rfind('<')?;
    let tag = &html[tag_start..marker + 60.min(html.len() - marker)];
    let key = "data-ipe-hid=\"";
    let at = tag.find(key)?;
    let rest = &tag[at + key.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// The `href`/`src` + `integrity` of the first tag matching `needle` (e.g.
/// `rel="modulepreload"` or `type="module"`). Returns `(url, integrity)`.
fn extract_url_and_integrity(html: &str, needle: &str) -> Option<(String, String)> {
    let at = html.find(needle)?;
    // Scan the enclosing tag: from the preceding `<` to the next `>`.
    let tag_start = html[..at].rfind('<')?;
    let tag_end = html[at..].find('>')? + at;
    let tag = &html[tag_start..tag_end];
    let url = attr_value(tag, "href").or_else(|| attr_value(tag, "src"))?;
    let integrity = attr_value(tag, "integrity")?;
    Some((url, integrity))
}

/// The value of a `name="…"` attribute in a single opening tag, or `None`.
fn attr_value(tag: &str, name: &str) -> Option<String> {
    let key = format!("{name}=\"");
    let at = tag.find(&key)?;
    let rest = &tag[at + key.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// `sha256-<base64>` over `bytes` — the SRI value a browser computes over a
/// fetched asset and compares against the page's `integrity`.
fn sri_of(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256-{}", B64.encode(digest))
}

// ── The E2E ─────────────────────────────────────────────────────────────────

/// The full server-driven widget loop. See the module docs for the five proven
/// properties. Kept as one sequential flow: the five steps share the running
/// server + session and read top-to-bottom as the browser's own lifecycle would;
/// splitting them across helpers would obscure the round-trip, not clarify it.
#[test]
#[allow(clippy::too_many_lines)]
fn ui_widget_serves_sri_glue_and_round_trips_up_event() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let test_name = "widget_live";
    let exe = compile_and_build(test_name, WIDGET_APP)?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready(test_name, &exe, port)?;
    let addr = format!("127.0.0.1:{port}");
    wait_until_connectable(test_name, &addr)?;

    // ── Step 1: GET / — the page, glue script, asset preload, widget node ─────
    let (raw_headers, body) = http_send(test_name, &addr, "GET", "/", &[], None)?;
    let sid = extract_cookie(&raw_headers, "ipe_sid").ok_or_else(|| -> BoxError {
        format!("{test_name}: no ipe_sid cookie in GET /\n{raw_headers}").into()
    })?;

    // Property 1: the page references the glue as an EXTERNAL SRI'd module script.
    let (glue_url, glue_integrity) =
        extract_url_and_integrity(&body, "widget-glue.").ok_or_else(|| -> BoxError {
            format!(
                "{test_name}: no SRI'd widget-glue <script> in page\n--- first 3000 ---\n{}",
                &body[..body.len().min(3000)]
            )
            .into()
        })?;
    assert!(
        glue_integrity.starts_with("sha256-"),
        "{test_name}: glue integrity is not a sha256 SRI: {glue_integrity}"
    );
    assert!(
        body.contains("type=\"module\""),
        "{test_name}: the glue script must be a module script"
    );
    assert!(
        body.contains("crossorigin=\"anonymous\""),
        "{test_name}: SRI'd scripts must carry crossorigin=anonymous"
    );
    // No inline widget script: the only inline <script> is the per-session vars
    // block the client already emits; the glue + asset are external. Assert the
    // glue body is not inlined (the module import lives in the served asset).
    assert!(
        !body.contains("customElements.define"),
        "{test_name}: registration must be in the EXTERNAL glue, never inline in the page"
    );

    // Property 1 (asset preload): a modulepreload with SRI for the author asset.
    let (asset_url, asset_integrity) = extract_url_and_integrity(&body, "modulepreload")
        .ok_or_else(|| -> BoxError {
            format!("{test_name}: no SRI'd modulepreload for the author asset in page").into()
        })?;
    assert!(
        asset_url.contains("/_ipe/widget."),
        "{test_name}: asset preload URL is not a content-addressed widget URL: {asset_url}"
    );

    // Property 4: the down-state crosses as an escaped `state` attribute on the
    // widget node (never spliced into a script), carrying the initial count.
    assert!(
        body.contains("ipe-ce-"),
        "{test_name}: no custom-element node in the page body"
    );
    // The attribute escaper renders `"` as its numeric HTML entity; asserting the
    // ESCAPED `count` key (never a raw `"` breaking the attribute) proves the
    // down-state crossed through the standard entity-escaper, not HRaw.
    let escaped_quote = format!("&#{};", 34); // the numeric entity for `"`
    let escaped_state = format!("state=\"{{{escaped_quote}count{escaped_quote}:0}}\"");
    assert!(
        body.contains(&escaped_state),
        "{test_name}: the down-state must ride an ENTITY-ESCAPED `state` attribute carrying `count`\n\
         --- first 3000 ---\n{}",
        &body[..body.len().min(3000)]
    );
    let widget_hid = extract_widget_hid(&body).ok_or_else(|| -> BoxError {
        format!("{test_name}: no data-ipe-hid on the widget (up-event) node").into()
    })?;

    // ── Step 2: GET the author asset — SRI content-pinning (page == bytes) ────
    let (_, asset_body) = http_send(test_name, &addr, "GET", &asset_url, &[], None)?;
    // Property 2a: served bytes are byte-identical to the author file.
    assert_eq!(
        asset_body, COUNTER_JS,
        "{test_name}: served author asset must be byte-identical to the author file"
    );
    // Property 2b: sha256(served bytes) == the integrity the page pinned. This is
    // the SEAL invariant: ipe-accepts ⇒ the page's SRI matches the served bytes,
    // so a tampered byte makes the browser refuse the module.
    assert_eq!(
        sri_of(asset_body.as_bytes()),
        asset_integrity,
        "{test_name}: page SRI must equal sha256 of the served asset bytes (page == bytes)"
    );

    // ── Step 3: GET the glue — defines only the compiler tag, imports the asset ─
    let (_, glue_body) = http_send(test_name, &addr, "GET", &glue_url, &[], None)?;
    assert_eq!(
        sri_of(glue_body.as_bytes()),
        glue_integrity,
        "{test_name}: page SRI for the glue must equal sha256 of the served glue bytes"
    );
    // Property 3: registration targets ONLY the compiler-generated ipe-ce-* tag,
    // imports the author asset URL, and never evals.
    assert!(
        glue_body.contains("customElements.define(\"ipe-ce-"),
        "{test_name}: glue must define an ipe-ce-* tag\n--- glue ---\n{glue_body}"
    );
    assert!(
        glue_body.contains(&asset_url),
        "{test_name}: glue must import the content-addressed author asset URL {asset_url}"
    );
    assert!(
        !glue_body.contains("eval("),
        "{test_name}: glue must never eval"
    );
    assert!(
        glue_body.contains("JSON.parse"),
        "{test_name}: down-state must be JSON.parse'd (data), never eval'd"
    );
    assert!(
        glue_body.contains("__ipeSend(\"ipe-widget\""),
        "{test_name}: up-events must route through the existing __ipeSend wire"
    );

    // ── Step 4: valid up-event round-trips through /_ipe/event ────────────────
    // The wire posts the encoded `up` as args[0] under the `ipe-widget` event; the
    // server resolves the handler by (ipe-id, event) and runs the fail-closed seal
    // up-decoder. `Bumped 3` folds +3 into the count.
    let cookie_header = format!("ipe_sid={sid}");
    let up_valid = r#"{"Bumped":3}"#;
    let event_body = format!(
        r#"{{"handlerId":"{widget_hid}","msg":"ipe-widget","args":[{up}],"sessionId":""}}"#,
        up = serde_json::to_string(up_valid).expect("string always serializes")
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
        post_body.contains("patches") || post_body.contains("seq"),
        "{test_name}: valid up-event POST did not return an ACK\nbody: {post_body}"
    );
    std::thread::sleep(Duration::from_millis(200));

    let body_after_valid = {
        let (_, b) = http_send(
            test_name,
            &addr,
            "GET",
            "/",
            &[("Cookie", &cookie_header)],
            None,
        )?;
        b
    };
    assert!(
        body_after_valid.contains(">3<"),
        "{test_name}: a valid `Bumped 3` up-event must fold +3 into the model\n\
         --- first 2500 ---\n{}",
        &body_after_valid[..body_after_valid.len().min(2500)]
    );

    // ── Step 5: malformed up-event is DROPPED fail-closed (no update) ─────────
    // A payload that does not decode to the declared `up` type must be dropped
    // whole by the WP4 seal decoder — the model must NOT move off 3.
    let up_bogus = r#"{"Nonexistent":true}"#;
    let bogus_body = format!(
        r#"{{"handlerId":"{widget_hid}","msg":"ipe-widget","args":[{up}],"sessionId":""}}"#,
        up = serde_json::to_string(up_bogus).expect("string always serializes")
    );
    let _ = http_send(
        test_name,
        &addr,
        "POST",
        "/_ipe/event",
        &[
            ("Content-Type", "application/json"),
            ("Cookie", &cookie_header),
        ],
        Some(bogus_body.as_bytes()),
    )?;
    std::thread::sleep(Duration::from_millis(200));
    let body_after_bogus = {
        let (_, b) = http_send(
            test_name,
            &addr,
            "GET",
            "/",
            &[("Cookie", &cookie_header)],
            None,
        )?;
        b
    };
    assert!(
        body_after_bogus.contains(">3<") && !body_after_bogus.contains(">4<"),
        "{test_name}: a malformed up-event must be DROPPED (model stays at 3)\n\
         --- first 2500 ---\n{}",
        &body_after_bogus[..body_after_bogus.len().min(2500)]
    );

    Ok(())
}

/// A `Web.tea` that reaches a `Js.send` outbound port (an `Int` payload, through
/// `update`) and a `Js.subscribe` inbound port (an `Int` decoder feeding `Got`,
/// through `subscriptions`) — the minimal seal-legal port program.
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

/// Read and concatenate the whole emitted Ipê-side Rust tree (`main.rs` +
/// `src/ipe_mods/*.rs`) so a test can assert the SHAPE of the lowering, not
/// only that `cargo build` succeeded. A build can succeed on a program whose
/// port calls were never emitted (dead-code elimination, a stubbed arm); the
/// only way to prove the ports actually lowered to the transport is to read
/// the emitted source.
fn emitted_source(out_dir: &std::path::Path) -> String {
    let src = out_dir.join("src");
    let mut combined = std::fs::read_to_string(src.join("main.rs")).unwrap_or_default();
    if let Ok(entries) = std::fs::read_dir(src.join("ipe_mods")) {
        let mut files: Vec<PathBuf> = entries
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

/// THE SEAL for `Ipe.Ffi.Js` ports: a seal-legal port program `ipe`-accepts (exit 0)
/// AND the emitted Rust `cargo build`s. A `Js.send model.n` lowers to
/// `js_send(...)` and `Js.subscribe Decode.int Got` to
/// `js_subscribe(json_decode_int(), ...)`; the payload type's serde derive is
/// already present (the seal-legality gate guarantees it), so the generic
/// transport call resolves with no per-port adapter. If either the lowering arm
/// or the runtime signature drifted, this build would fail — the whole point.
///
/// Two guarantees, two proofs:
///
/// 1. **Compile seal** — `compile_and_build` reaching the built binary means
///    `ipe dev build` accepted + emitted AND `cargo build` linked the runtime
///    transport signatures (THE SEAL).
/// 2. **Lowering shape** — the emitted Rust actually CONTAINS the transport
///    calls (`js_send(` outbound, `js_subscribe(` inbound). A green
///    `cargo build` alone does not prove the port calls survived into the
///    emitted program; asserting the lowered calls are present does. The
///    behaviour of those calls — a payload seal-encoded outbound and a clean
///    inbound frame decoded fail-closed and emitted as a `Msg`, per session,
///    with cross-session isolation — is proven in-process by the runtime's
///    `js_port` transport suite (`ipe_runtime::js_port` `#[tokio::test]`s:
///    `inbound_clean_payload_is_emitted`,
///    `outbound_send_encodes_and_delivers_to_origin_sink`,
///    `sessions_are_isolated_inbound_and_outbound`, …), which drives the same
///    `js_send`/`js_subscribe` this program lowers to.
#[test]
fn js_port_seal_legal_lowers_and_builds() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    // `compile_and_build` returns the built binary path; reaching it means both
    // `ipe dev build` (accept + emit) and `cargo build` (THE SEAL) succeeded.
    let _exe = compile_and_build("js_port_seal", JS_PORT_APP)?;

    // The compile seal alone would pass even if the port calls were elided; the
    // emitted source must actually carry both transport arms. `cargo build` has
    // already succeeded, so the emitted tree exists and must contain them.
    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("widget_e2e_js_port_seal_emitted");
    let emitted = emitted_source(&out_dir);
    if !emitted.contains("js_send(") {
        return Err(format!(
            "emitted Rust must lower `Js.send` to a `js_send(` transport call; \
             emitted source did not contain it:\n{emitted}"
        )
        .into());
    }
    if !emitted.contains("js_subscribe(") {
        return Err(format!(
            "emitted Rust must lower `Js.subscribe` to a `js_subscribe(` transport call; \
             emitted source did not contain it:\n{emitted}"
        )
        .into());
    }
    Ok(())
}

//! Honest end-to-end tests for `Ipe.Http.Server` — `Server.listen`,
//! `Server.get`, `Server.text`, and `Server.param`.
//!
//! All tests are gated on `IPE_E2E=1`.  Without it they return early so the
//! default `cargo test` stays fast.
//!
//! ## Architecture
//!
//! Each test:
//!
//! 1. Writes a Ipê program to a fresh temp dir.
//! 2. Compiles it through `ipe::build` (full pipeline: parse → canon → types →
//!    lower → emit Rust).
//! 3. Builds the emitted Cargo project with `e2e_support::build_rust_binary` — the
//!    global `~/.cargo/config.toml` shared target is used so dependencies
//!    (axum, tokio, tower-http, …) compile once and are reused.
//! 4. Acquires an ephemeral port by binding `TcpListener::bind("127.0.0.1:0")`,
//!    reading the assigned port, then dropping the listener so the Ipê server
//!    can bind the same port moments later.
//! 5. Spawns the compiled binary as a child process, passing
//!    `IPE_SERVER_PORT=<port>` and `IPE_HTTP_BIND=127.0.0.1` so the server
//!    binds loopback-only.
//! 6. Polls for server readiness: retries `TcpStream::connect` every 50 ms for
//!    up to 10 s.  The ready signal is the appearance of
//!    `[ipe.http.server] listening on` in the child's stderr.
//! 7. Sends raw HTTP/1.1 requests via `TcpStream` (no extra dependencies) and
//!    asserts the response body.
//! 8. A `ProcessGuard` wrapper kills the child process on `Drop`, so the port
//!    is always released even when a test fails.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test server_e2e
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Shared error type for E2E helpers.
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

// ── Ipê programs ──────────────────────────────────────────────────────────────

/// A minimal Ipê HTTP server. Reads its port from `IPE_SERVER_PORT`.
///
/// Routes:
/// * `GET /`             → body `hello server`
/// * `GET /greet/:name`  → body `hi <name>` (exercises `Server.param`)
const IPE_SERVER_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Http.Server as Server
import Ipe.Maybe
import Ipe.String
import Ipe.System
import Ipe.Task

main =
    let port = Maybe.withDefault 8080 (String.toInt (System.getenvOr "IPE_SERVER_PORT" "8080"))
    in
    Server.listen port
        [ Server.get "/" (\req -> Task.succeed (Server.text "hello server"))
        , Server.get "/greet/:name" (\req ->
            let name = Maybe.withDefault "world" (Server.param "name" req)
            in
            Task.succeed (Server.text ("hi " ++ name)))
        ]
"#;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Compile a Ipê program string as `ipe dev build` does (Development intent), build
/// the emitted Rust project, and return the path to the compiled binary.
///
/// # Errors
///
/// Returns an error on any pipeline or Cargo build failure.
fn compile_and_build(test_name: &str, ipe_source: &str) -> Result<PathBuf, BoxError> {
    compile_and_build_as(
        test_name,
        ipe_source,
        ipe_backend_rust::BuildIntent::Development,
    )
}

/// [`compile_and_build`] under an explicit build intent.
///
/// # Errors
///
/// Returns an error on any pipeline or Cargo build failure.
fn compile_and_build_as(
    test_name: &str,
    ipe_source: &str,
    intent: ipe_backend_rust::BuildIntent,
) -> Result<PathBuf, BoxError> {
    let ipe_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("server_e2e_{test_name}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(&ipe_dir).map_err(|e| -> BoxError {
        format!("{test_name}: cannot create ipe source dir: {e}").into()
    })?;

    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, ipe_source)
        .map_err(|e| -> BoxError { format!("{test_name}: cannot write Main.ipe: {e}").into() })?;

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("server_e2e_{test_name}_emitted"));
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let options = ipe::BuildOptions {
        intent,
        ..ipe::BuildOptions::from_env()
    };
    ipe::build_with_options(&entry, &out_dir, &runtime, options)
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
    // Drop `listener` here — releases the port for the Ipê server.
    Ok(port)
}

/// RAII guard: kills the wrapped child process on `Drop`.
///
/// This ensures the port is always released and the OS-level child is always
/// reaped, even when a test assertion fails or panics.
struct ProcessGuard(Child);

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        // Best-effort: ignore errors — if the process already exited the kill
        // will return an error we discard, and `wait` cleans up the zombie.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn the Ipê server binary and wait until it signals readiness.
///
/// Readiness is detected by watching the child's stderr for the line
/// `[ipe.http.server] listening on`.  The `server_listen` runtime emits this
/// line immediately after `tokio::net::TcpListener::bind` succeeds, so
/// receiving it means the socket is open and accepts connections.
///
/// Times out after 10 s; returns an error if the line never appears.
///
/// # Errors
///
/// Returns an error if the binary cannot be spawned or the ready signal does
/// not appear within the timeout.
fn spawn_and_wait_ready(
    test_name: &str,
    exe: &std::path::Path,
    port: u16,
) -> Result<ProcessGuard, BoxError> {
    spawn_and_wait_ready_with_env(test_name, exe, port, &[])
}

/// Same as `spawn_and_wait_ready`, plus caller-supplied extra environment
/// variables on the child (e.g. `IPE_TRUSTED_PROXY` / `ENV` for the
/// CSRF-cookie `Secure`-gating E2E tests, which need a real subprocess
/// because the runtime's `IPE_TRUSTED_PROXY` trust decision is cached in a
/// process-wide `OnceLock` — an in-process unit test cannot toggle it
/// per-test the way `csrf_set_cookie_value`'s pure-function unit tests can).
///
/// # Errors
///
/// Returns an error if the binary cannot be spawned or the ready signal does
/// not appear within the timeout.
fn spawn_and_wait_ready_with_env(
    test_name: &str,
    exe: &std::path::Path,
    port: u16,
    extra_env: &[(&str, &str)],
) -> Result<ProcessGuard, BoxError> {
    let mut cmd = Command::new(exe);
    cmd.env("IPE_SERVER_PORT", port.to_string())
        .env("IPE_HTTP_BIND", "127.0.0.1")
        .stderr(Stdio::piped())
        .stdout(Stdio::null());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().map_err(|e| -> BoxError {
        format!("{test_name}: cannot spawn server binary: {e}").into()
    })?;

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
            return Err(format!("{test_name}: server did not signal readiness within 10 s").into());
        }
        line.clear();
        // `read_line` blocks until a newline or EOF.  A short-lived server that
        // exits before printing the ready line will produce EOF, which
        // `read_line` signals as 0 bytes.
        match reader.read_line(&mut line) {
            Ok(0) => {
                // Child exited without printing the ready line.
                let _ = child.wait();
                return Err(
                    format!("{test_name}: server process exited before signalling ready").into(),
                );
            }
            Ok(_) => {
                if line.contains("[ipe.http.server] listening on") {
                    // Server is ready.  Detach the reader (it stays alive on
                    // the guard's `stderr` pipe until the guard is dropped).
                    return Ok(ProcessGuard(child));
                }
                // Any other line: keep reading.
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{test_name}: error reading child stderr: {e}").into());
            }
        }
    }
}

/// Ipê server that echoes the POST body verbatim.
///
/// Route: `POST /echo` → body `Server.body req`
const IPE_POST_ECHO_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Http.Server as Server
import Ipe.Maybe
import Ipe.String
import Ipe.System
import Ipe.Task

main =
    let port = Maybe.withDefault 8080 (String.toInt (System.getenvOr "IPE_SERVER_PORT" "8080"))
    in
    Server.listen port
        [ Server.post "/echo" (\req -> Task.succeed (Server.text (Server.body req)))
        ]
"#;

/// Ipê server that exercises all four request-introspection kernels in one
/// handler: method, path, header, queryParam, and param.
///
/// Route: `POST /introspect/:tag?q=<val>` with header `X-Probe: <val>`
/// → body `<method>|<path>|<probe>|<q>|<tag>`
const IPE_INTROSPECT_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Http.Server as Server
import Ipe.Maybe
import Ipe.String
import Ipe.System
import Ipe.Task

main =
    let port = Maybe.withDefault 8080 (String.toInt (System.getenvOr "IPE_SERVER_PORT" "8080"))
    in
    Server.listen port
        [ Server.post "/introspect/:tag" (\req ->
            Task.succeed (Server.text
                (Server.method req ++ "|" ++ Server.path req
                 ++ "|" ++ Maybe.withDefault "?" (Server.header "x-probe" req)
                 ++ "|" ++ Maybe.withDefault "?" (Server.queryParam "q" req)
                 ++ "|" ++ Maybe.withDefault "?" (Server.param "tag" req))))
        ]
"#;

/// Ipê server that uses BOTH `Server.listen` and a `Db.open` call — the
/// minimal program that sets both `uses_server` and `uses_db` in the lowerer,
/// exercising the server+db manifest composition (GAP 1 fix).
///
/// `Db.open : String -> String -> Task Error Db` (driver, url).
/// `Db.connect : () -> Task Error Db` takes unit, not a URL string, so we use
/// `Db.open` here for clarity.
const IPE_SERVER_AND_DB_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Http.Server as Server
import Ipe.Db as Db
import Ipe.Maybe
import Ipe.String
import Ipe.System
import Ipe.Task

main =
    Task.andThen
        (\conn ->
            let port = Maybe.withDefault 8080 (String.toInt (System.getenvOr "IPE_SERVER_PORT" "8080"))
            in
            Server.listen port
                [ Server.get "/" (\req -> Task.succeed (Server.text "ok"))
                ])
        (Db.open "sqlite" (System.getenvOr "DATABASE_URL" "sqlite::memory:"))
"#;

/// Ipê server exercising `Middleware.withCsrf` end-to-end.  Mirrors
/// `tests/golden/middleware_csrf/Main.ipe` but adds a `GET /action` route
/// (also wrapped in `Middleware.withCsrf`) so a real HTTP client can mint the
/// double-submit cookie via a safe-method request before probing the
/// CSRF-protected `POST /action`.
const IPE_CSRF_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Http.Server as Server
import Ipe.Http.Middleware as Middleware
import Ipe.Maybe
import Ipe.String
import Ipe.System
import Ipe.Task

handle : Server.Request -> Task Error Server.Response
handle _req =
    Task.succeed (Server.text "ok")

main =
    let port = Maybe.withDefault 8080 (String.toInt (System.getenvOr "IPE_SERVER_PORT" "8080"))
    in
    Server.listen port
        [ Server.get "/action" (Middleware.withCsrf handle)
        , Server.post "/action" (Middleware.withCsrf handle)
        ]
"#;

/// A parsed raw HTTP/1.1 response: status code, headers (lower-cased names,
/// duplicates preserved in arrival order — `Set-Cookie` legitimately repeats
/// per RFC 6265 §4.1, which forbids comma-folding it into one line), and
/// body.
struct RawResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

/// Send a raw, fully-formed HTTP/1.1 `request` (including the terminating
/// `\r\n\r\n` and any body) to `addr` and parse the full response: status
/// line, headers, and body.
///
/// Used by the CSRF tests, which need to read the `Set-Cookie` response
/// header (to capture the minted double-submit token) and the response
/// status code (200 vs 403) — the body-only `http_get`/`http_post` helpers
/// above are insufficient for that.
///
/// # Errors
///
/// Returns an error if the connection, write, or read fails, or if the
/// response cannot be parsed as a well-formed HTTP/1.1 message.
fn send_raw_request(test_name: &str, addr: &str, request: &str) -> Result<RawResponse, BoxError> {
    let mut stream = TcpStream::connect(addr).map_err(|e| -> BoxError {
        format!("{test_name}: cannot connect to server: {e}").into()
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| -> BoxError { format!("{test_name}: set_read_timeout failed: {e}").into() })?;

    stream
        .write_all(request.as_bytes())
        .map_err(|e| -> BoxError { format!("{test_name}: write failed: {e}").into() })?;

    let mut buf = Vec::with_capacity(4096);
    stream
        .read_to_end(&mut buf)
        .map_err(|e| -> BoxError { format!("{test_name}: read failed: {e}").into() })?;

    let response = String::from_utf8_lossy(&buf).into_owned();
    let sep = response.find("\r\n\r\n").ok_or_else(|| -> BoxError {
        format!("{test_name}: no header/body separator in response\n--- raw ---\n{response}").into()
    })?;
    let head = response
        .get(..sep)
        .ok_or_else(|| -> BoxError { format!("{test_name}: cannot slice response head").into() })?;
    let body = response.get(sep + 4..).unwrap_or("").to_owned();

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| -> BoxError {
            format!("{test_name}: cannot parse status code from status line: {status_line:?}")
                .into()
        })?;

    let headers = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        })
        .collect();

    Ok(RawResponse {
        status,
        headers,
        body,
    })
}

/// Extract the bare `value` out of a `Set-Cookie` header value of shape
/// `"<name>=<value>; Path=/; ..."`, matching on `name`.  Returns `None` if
/// the header does not start with `<name>=`.
fn cookie_token_value(set_cookie: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    let rest = set_cookie.strip_prefix(prefix.as_str())?;
    let value = rest.split(';').next().unwrap_or(rest);
    Some(value.to_string())
}

/// Send a raw HTTP/1.1 GET request on `stream` and return the full response
/// body (everything after the blank-header separator `\r\n\r\n`).
///
/// Reads up to 8 KiB; sufficient for the small test responses.
///
/// # Errors
///
/// Returns an error if the stream write or read fails.
fn http_get(test_name: &str, addr: &str, path: &str) -> Result<String, BoxError> {
    let mut stream = TcpStream::connect(addr).map_err(|e| -> BoxError {
        format!("{test_name}: cannot connect to server: {e}").into()
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| -> BoxError { format!("{test_name}: set_read_timeout failed: {e}").into() })?;

    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|e| -> BoxError { format!("{test_name}: write failed: {e}").into() })?;

    let mut buf = Vec::with_capacity(4096);
    stream
        .read_to_end(&mut buf)
        .map_err(|e| -> BoxError { format!("{test_name}: read failed: {e}").into() })?;

    let response = String::from_utf8_lossy(&buf).into_owned();
    // Split headers from body on the blank-line separator.
    let body = if let Some(idx) = response.find("\r\n\r\n") {
        response[idx + 4..].to_owned()
    } else {
        // No separator → return the whole response so the assertion fails with
        // a useful diff.
        response
    };
    Ok(body)
}

/// Send a raw HTTP/1.1 POST request with `body` and optional extra `headers`
/// (each `"Name: Value"`) to `addr/path`.  Returns the response body.
///
/// # Errors
///
/// Returns an error if the stream write or read fails.
fn http_post(
    test_name: &str,
    addr: &str,
    path: &str,
    body: &str,
    extra_headers: &[&str],
) -> Result<String, BoxError> {
    let mut stream = TcpStream::connect(addr).map_err(|e| -> BoxError {
        format!("{test_name}: cannot connect to server: {e}").into()
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| -> BoxError { format!("{test_name}: set_read_timeout failed: {e}").into() })?;

    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n",
        body.len()
    );
    for h in extra_headers {
        request.push_str(h);
        request.push_str("\r\n");
    }
    request.push_str("Connection: close\r\n\r\n");
    request.push_str(body);

    stream
        .write_all(request.as_bytes())
        .map_err(|e| -> BoxError { format!("{test_name}: write failed: {e}").into() })?;

    let mut buf = Vec::with_capacity(4096);
    stream
        .read_to_end(&mut buf)
        .map_err(|e| -> BoxError { format!("{test_name}: read failed: {e}").into() })?;

    let response = String::from_utf8_lossy(&buf).into_owned();
    let resp_body = if let Some(idx) = response.find("\r\n\r\n") {
        response[idx + 4..].to_owned()
    } else {
        response
    };
    Ok(resp_body)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// `Server.get "/"` returns the expected body with a 200 status.
///
/// Proves the full M6-server pipeline end-to-end:
/// Ipê source → ipe → emitted Rust (with `server` feature injected) →
/// `ipe_runtime::server::server_listen` + `server_get` + `server_text` →
/// axum HTTP server → response received by the test.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or HTTP error as a test error.
#[test]
fn server_get_root() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let exe = compile_and_build("server_get_root", IPE_SERVER_PROGRAM)?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready("server_get_root", &exe, port)?;

    let addr = format!("127.0.0.1:{port}");
    let body = http_get("server_get_root", &addr, "/")?;

    assert_eq!(
        body, "hello server",
        "server_get_root: unexpected response body\n--- actual ---\n{body}"
    );
    Ok(())
}

/// `Server.get "/greet/:name"` with `Server.param` returns the expected body.
///
/// Exercises `server_param` — the `name` path capture is extracted via
/// `Server.param "name" req` and interpolated into the response.  Proves the
/// `Request.params` field is populated by `server_listen`'s axum route
/// extraction and readable via the typed kernel.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or HTTP error as a test error.
#[test]
fn server_get_param() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let exe = compile_and_build("server_get_param", IPE_SERVER_PROGRAM)?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready("server_get_param", &exe, port)?;

    let addr = format!("127.0.0.1:{port}");
    let body = http_get("server_get_param", &addr, "/greet/alice")?;

    assert_eq!(
        body, "hi alice",
        "server_get_param: unexpected response body\n--- actual ---\n{body}"
    );
    Ok(())
}

/// `Server.body` reads the POST request body and echoes it verbatim.
///
/// A POST handler CAN read the request body via `Server.body req`.  Without a
/// `Server.body` kernel POST bodies would be unreadable — a completeness loss.
///
/// Full pipeline: Ipê source → ipe (new `ServerBody` kernel) →
/// emitted `server_body(req)` Rust call → axum populates `req.body` from the
/// request → handler echoes it.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or HTTP error as a test error.
#[test]
fn post_body_echo() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let exe = compile_and_build("post_body_echo", IPE_POST_ECHO_PROGRAM)?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready("post_body_echo", &exe, port)?;

    let addr = format!("127.0.0.1:{port}");
    let body = http_post("post_body_echo", &addr, "/echo", "hello-post-42", &[])?;

    assert_eq!(
        body, "hello-post-42",
        "post_body_echo: response body must echo the POST body exactly\n--- actual ---\n{body}"
    );
    Ok(())
}

/// A single handler reads all five request-introspection dimensions:
/// `Server.method`, `Server.path`, `Server.header`, `Server.queryParam`,
/// and `Server.param` (path capture).
///
/// Proves the `body|path|method` kernel triples wired correctly alongside
/// the existing `header|queryParam|param` accessors.
///
/// Expected response: `POST|/introspect/abc|pv|val|abc`
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or HTTP error as a test error.
#[test]
fn request_introspection() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let exe = compile_and_build("request_introspection", IPE_INTROSPECT_PROGRAM)?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready("request_introspection", &exe, port)?;

    let addr = format!("127.0.0.1:{port}");
    let body = http_post(
        "request_introspection",
        &addr,
        "/introspect/abc?q=val",
        "",
        &["X-Probe: pv"],
    )?;

    assert_eq!(
        body, "POST|/introspect/abc|pv|val|abc",
        "request_introspection: unexpected response body\n--- actual ---\n{body}"
    );
    Ok(())
}

/// A program that uses BOTH `Server.listen` and `Db.connect` compiles,
/// cargo-builds, and emits a manifest with BOTH `"server"` AND `"db"` in the
/// default feature list.
///
/// The feature-list anchor finds the closing `]` regardless of what precedes
/// it: anchoring on `"json"]` would break when `db_cargo_toml` has already run
/// (the list becomes `"json", "db"]`), causing a `CompilerBug` ICE.
///
/// Test is BUILD-ONLY — the compiled binary is not spawned (it would start a
/// server and block).  A successful `cargo build` is the assertion.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn server_and_db_compose() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    // compile_and_build already does ipe + cargo build; success is the proof.
    let _exe = compile_and_build("server_and_db_compose", IPE_SERVER_AND_DB_PROGRAM)?;
    Ok(())
}

/// Real HTTP-level proof that `Middleware.withCsrf` rejects a forged
/// cross-site-style POST that carries neither the double-submit cookie nor
/// the `X-Csrf-Token` header.
///
/// Covers the gap other tests leave: `golden_m6_middleware_csrf.rs`
/// only proves `ipe`/`cargo build` succeed (compile-level), and
/// `server.rs`'s in-process unit tests call `middleware_with_csrf` directly
/// as a bare Rust function — bypassing the full kernel-registry dispatch
/// chain (canon → constrain → lower → naming → pretty → emit). This test proves
/// the chain end to end: Ipê source → `ipe` → emitted Rust → the actual served
/// binary's real behavior over a real TCP connection.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or HTTP error as a test error.
#[test]
fn csrf_forged_post_without_token_rejected() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "csrf_forged_post_without_token_rejected";

    let exe = compile_and_build(test_name, IPE_CSRF_PROGRAM)?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready(test_name, &exe, port)?;
    let addr = format!("127.0.0.1:{port}");

    let request = "POST /action HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let resp = send_raw_request(test_name, &addr, request)?;

    assert_eq!(
        resp.status, 403,
        "{test_name}: forged POST with no cookie and no X-Csrf-Token header must be rejected\n--- body ---\n{}",
        resp.body
    );
    Ok(())
}

/// Real HTTP-level proof that `Middleware.withCsrf` rejects a POST
/// that carries the double-submit cookie (minted by a prior GET) but an
/// `X-Csrf-Token` header that is either missing or does not match the
/// cookie's value.
///
/// Simulates an attacker page that can trigger a simple cross-origin POST
/// (the cookie rides along automatically) but cannot read the victim-origin
/// cookie to forge a matching custom header without a CORS preflight allow.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or HTTP error as a test error.
#[test]
fn csrf_post_with_cookie_but_mismatched_header_rejected() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "csrf_post_with_cookie_but_mismatched_header_rejected";

    let exe = compile_and_build(test_name, IPE_CSRF_PROGRAM)?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready(test_name, &exe, port)?;
    let addr = format!("127.0.0.1:{port}");

    // GET is a "safe" method: `Middleware.withCsrf` skips the check and
    // mints a fresh double-submit cookie via a `Set-Cookie` response header.
    let get_req = "GET /action HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let get_resp = send_raw_request(test_name, &addr, get_req)?;
    assert_eq!(
        get_resp.status, 200,
        "{test_name}: GET must mint the cookie and succeed\n--- body ---\n{}",
        get_resp.body
    );
    let set_cookie = get_resp
        .headers
        .iter()
        .find(|(k, _)| k == "set-cookie")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| -> BoxError {
            format!("{test_name}: GET response missing a Set-Cookie header").into()
        })?;
    let token = cookie_token_value(&set_cookie, "ipe_csrf").ok_or_else(|| -> BoxError {
        format!("{test_name}: cannot parse ipe_csrf cookie value from {set_cookie:?}").into()
    })?;

    // Cookie present, header value present but WRONG (well-formed 64-hex, so
    // this exercises the mismatch branch specifically, not the
    // malformed-token branch).
    let wrong_token = "0".repeat(64);
    let post_mismatched = format!(
        "POST /action HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: ipe_csrf={token}\r\nX-Csrf-Token: {wrong_token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let resp_mismatched = send_raw_request(test_name, &addr, &post_mismatched)?;
    assert_eq!(
        resp_mismatched.status, 403,
        "{test_name}: POST with cookie but a mismatched X-Csrf-Token header must be rejected\n--- body ---\n{}",
        resp_mismatched.body
    );

    // Cookie present, header entirely MISSING.
    let post_missing_header = format!(
        "POST /action HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: ipe_csrf={token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let resp_missing_header = send_raw_request(test_name, &addr, &post_missing_header)?;
    assert_eq!(
        resp_missing_header.status, 403,
        "{test_name}: POST with cookie but no X-Csrf-Token header must be rejected\n--- body ---\n{}",
        resp_missing_header.body
    );

    Ok(())
}

/// Real HTTP-level proof of the legitimate flow: a GET mints the
/// double-submit cookie, and a same-origin-style POST that echoes the
/// cookie's value in the `X-Csrf-Token` header is allowed through to the
/// wrapped handler.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or HTTP error as a test error.
#[test]
fn csrf_legit_post_with_matching_token_allowed() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "csrf_legit_post_with_matching_token_allowed";

    let exe = compile_and_build(test_name, IPE_CSRF_PROGRAM)?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready(test_name, &exe, port)?;
    let addr = format!("127.0.0.1:{port}");

    let get_req = "GET /action HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let get_resp = send_raw_request(test_name, &addr, get_req)?;
    assert_eq!(
        get_resp.status, 200,
        "{test_name}: GET must mint the cookie and succeed\n--- body ---\n{}",
        get_resp.body
    );
    let set_cookie = get_resp
        .headers
        .iter()
        .find(|(k, _)| k == "set-cookie")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| -> BoxError {
            format!("{test_name}: GET response missing a Set-Cookie header").into()
        })?;
    let token = cookie_token_value(&set_cookie, "ipe_csrf").ok_or_else(|| -> BoxError {
        format!("{test_name}: cannot parse ipe_csrf cookie value from {set_cookie:?}").into()
    })?;

    let post_req = format!(
        "POST /action HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: ipe_csrf={token}\r\nX-Csrf-Token: {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let post_resp = send_raw_request(test_name, &addr, &post_req)?;
    assert_eq!(
        post_resp.status, 200,
        "{test_name}: legit POST echoing the cookie value in X-Csrf-Token must be allowed\n--- body ---\n{}",
        post_resp.body
    );
    assert_eq!(
        post_resp.body, "ok",
        "{test_name}: response body must be the wrapped handler's own response"
    );

    Ok(())
}

/// Real HTTP-level proof that `Middleware.withCsrf`'s minted cookie
/// `Secure` attribute is gated on the REQUEST-scoped TLS signal
/// (`X-Forwarded-Proto: https`, only honoured when the operator opts in via
/// `IPE_TRUSTED_PROXY`), not just a process-wide `ENV` snapshot — closing
/// the same ENV-vs-TLS gap already fixed for the Ipe.Web session cookie
/// (`src/runtime/rust/src/live/mod.rs::page_response`,
/// `request_is_https`). The `server.rs` side needed a real design
/// adaptation (not a copy-paste of the session-cookie fix): the signal has
/// to be captured from `ServerRequest.headers` BEFORE `middleware_with_csrf`
/// moves the request into the wrapped handler, then threaded through as a
/// plain `bool` capture into the async block that stamps the cookie after
/// the handler's `Task` resolves.
///
/// Scenario (a): `IPE_TRUSTED_PROXY=1`, `ENV` unset (dev mode), GET carries
/// `X-Forwarded-Proto: https` -> the minted `ipe_csrf` cookie gets `Secure`
/// even though `ENV` never claims production. Proves the request-scoped
/// signal alone (independent of `ENV`) can flip the gate on.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or HTTP error as a test error.
#[test]
fn csrf_cookie_secure_behind_trusted_tls_proxy() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "csrf_cookie_secure_behind_trusted_tls_proxy";

    let exe = compile_and_build(test_name, IPE_CSRF_PROGRAM)?;
    let port = pick_ephemeral_port()?;
    let _guard =
        spawn_and_wait_ready_with_env(test_name, &exe, port, &[("IPE_TRUSTED_PROXY", "1")])?;
    let addr = format!("127.0.0.1:{port}");

    let get_req = "GET /action HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n";
    let get_resp = send_raw_request(test_name, &addr, get_req)?;
    assert_eq!(
        get_resp.status, 200,
        "{test_name}: GET must succeed\n--- body ---\n{}",
        get_resp.body
    );
    let set_cookie = get_resp
        .headers
        .iter()
        .find(|(k, _)| k == "set-cookie")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| -> BoxError {
            format!("{test_name}: GET response missing a Set-Cookie header").into()
        })?;

    assert!(
        set_cookie.contains("; Secure"),
        "{test_name}: TLS-detected request (trusted proxy + X-Forwarded-Proto: https) must set Secure, even with ENV unset\n--- Set-Cookie ---\n{set_cookie}"
    );

    Ok(())
}

/// Scenario (b): same trusted-proxy opt-in as scenario (a), but THIS
/// specific request does NOT carry `X-Forwarded-Proto: https` (the ordinary
/// plain-HTTP loopback case) — the cookie must NOT get `Secure`.
/// Dev-mode-correct: a plain-HTTP connection must never be told by the
/// browser to require HTTPS on future requests, or local dev breaks.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or HTTP error as a test error.
#[test]
fn csrf_cookie_not_secure_when_request_not_tls_detected() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "csrf_cookie_not_secure_when_request_not_tls_detected";

    let exe = compile_and_build(test_name, IPE_CSRF_PROGRAM)?;
    let port = pick_ephemeral_port()?;
    // IPE_TRUSTED_PROXY is set (the opt-in is active), but the GET below
    // never sends X-Forwarded-Proto — this specific request is not
    // TLS-detected.
    let _guard =
        spawn_and_wait_ready_with_env(test_name, &exe, port, &[("IPE_TRUSTED_PROXY", "1")])?;
    let addr = format!("127.0.0.1:{port}");

    let get_req = "GET /action HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let get_resp = send_raw_request(test_name, &addr, get_req)?;
    assert_eq!(
        get_resp.status, 200,
        "{test_name}: GET must succeed\n--- body ---\n{}",
        get_resp.body
    );
    let set_cookie = get_resp
        .headers
        .iter()
        .find(|(k, _)| k == "set-cookie")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| -> BoxError {
            format!("{test_name}: GET response missing a Set-Cookie header").into()
        })?;

    assert!(
        !set_cookie.contains("; Secure"),
        "{test_name}: a plain-HTTP request (no X-Forwarded-Proto) must NOT get Secure\n--- Set-Cookie ---\n{set_cookie}"
    );

    Ok(())
}

/// Scenario (c) — the combined-gate semantics of the session cookie:
/// `ENV=production` is an UNCONDITIONAL floor.  Even
/// when THIS specific request is not TLS-detected (no `IPE_TRUSTED_PROXY`
/// opt-in here at all), a production deploy must still get `Secure` —
/// production assumes TLS termination happens somewhere in front of it.
/// This matches `server_with_cookie`'s pre-existing production gate and
/// `live/mod.rs::page_response`'s `csrf::cookies_secure() ||
/// request_is_https(headers)` OR-gate: production forces `Secure`
/// regardless of the request-scoped signal; the request-scoped signal only
/// ADDS `Secure` in the non-production case (scenario (a) above). A
/// same-request AND of "production" with "not TLS-detected" must NOT
/// produce a non-Secure cookie — that would be a downgrade from the
/// ENV-only rule that is always Secure in production.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or HTTP error as a test error.
#[test]
fn csrf_cookie_secure_when_env_production_regardless_of_tls_signal() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "csrf_cookie_secure_when_env_production_regardless_of_tls_signal";

    let exe = compile_and_build(test_name, IPE_CSRF_PROGRAM)?;
    let port = pick_ephemeral_port()?;
    // ENV=production, no IPE_TRUSTED_PROXY at all -> request_is_https() is
    // always false in this process, yet Secure must still fire off the
    // unconditional production floor.
    let _guard = spawn_and_wait_ready_with_env(test_name, &exe, port, &[("ENV", "production")])?;
    let addr = format!("127.0.0.1:{port}");

    let get_req = "GET /action HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let get_resp = send_raw_request(test_name, &addr, get_req)?;
    assert_eq!(
        get_resp.status, 200,
        "{test_name}: GET must succeed\n--- body ---\n{}",
        get_resp.body
    );
    let set_cookie = get_resp
        .headers
        .iter()
        .find(|(k, _)| k == "set-cookie")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| -> BoxError {
            format!("{test_name}: GET response missing a Set-Cookie header").into()
        })?;

    assert!(
        set_cookie.contains("; Secure"),
        "{test_name}: ENV=production must force Secure even when this request isn't TLS-detected\n--- Set-Cookie ---\n{set_cookie}"
    );

    Ok(())
}

/// Shape-model §10 flagship: a declarative `Server` that mounts a `Web.embed`'d
/// single-page Web app under `/app` AND serves a plain `GET /api` route — BOTH
/// on one listener (one port). The embedded app is a value produced by
/// `Web.embed` and mounted by `Server.mountApp`; the whole program's `main` is a
/// `Server.listen` Task (a Program, not a Web shape).
const IPE_SERVER_MOUNTS_WEB_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
import Ipe.String
import Ipe.Http.Server as Server
import Ipe.Maybe
import Ipe.System
import Ipe.Task


type Msg
    = Increment


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


view : Model -> Element Msg
view model =
    Ui.text (String.fromInt model.count)


subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none


main : Task Error ()
main =
    let port = Maybe.withDefault 8080 (String.toInt (System.getenvOr "IPE_SERVER_PORT" "8080"))
    in
    Server.listen port
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

/// THE SEAL for shape-model §9/§10: a `Server` mounts a `Web.embed`'d web app
/// and serves a sibling `GET /api` route, both on ONE port. Proves end to end
/// that the `ipe`-accepted program's emitted Rust `cargo build`s, the binary
/// binds one listener, and BOTH surfaces answer on it: `/api` returns the JSON
/// handler's body, and the mounted `/app/` returns the embedded web app's HTML
/// page (a live-session bootstrap, not a 404) — the two are served by the
/// SAME axum router the mount nests under `/app`.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or HTTP error as a test error.
#[test]
fn server_mounts_web_app_and_api_on_one_port() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "server_mounts_web_app_and_api_on_one_port";

    let exe = compile_and_build(test_name, IPE_SERVER_MOUNTS_WEB_PROGRAM)?;
    let port = pick_ephemeral_port()?;
    let _guard = spawn_and_wait_ready(test_name, &exe, port)?;

    let addr = format!("127.0.0.1:{port}");

    // The sibling plain route answers with the JSON handler's body.
    let api_body = http_get(test_name, &addr, "/api")?;
    assert_eq!(
        api_body, "{\"ok\":true}",
        "{test_name}: /api handler body wrong\n--- actual ---\n{api_body}"
    );

    // The mounted web app answers under its prefix on the SAME port. A live web
    // page bootstrap is HTML (it embeds the client asset + a session cookie), so
    // the response is non-empty HTML — NOT a 404 (which the JSON `/api` handler
    // or an unmounted path would give). We assert it looks like an HTML document
    // rather than pinning the full page bytes (which carry a per-build asset
    // hash + a fresh session id).
    let app_slash = http_get(test_name, &addr, "/app/")?;
    let app_noslash = http_get(test_name, &addr, "/app")?;
    let is_html =
        |b: &str| b.contains("<!DOCTYPE html>") || b.contains("<html") || b.contains("<body");
    assert!(
        is_html(&app_slash) || is_html(&app_noslash),
        "{test_name}: mounted /app did not return an HTML page (embedded web app not served on the shared port?)\n--- /app/ (first 300) ---\n{}\n--- /app (first 300) ---\n{}",
        app_slash.chars().take(300).collect::<String>(),
        app_noslash.chars().take(300).collect::<String>()
    );

    Ok(())
}

/// A release build keeps the operator console closed with no
/// `IPE_CONSOLE_AUTH` configured, even on a loopback bind: the dev default
/// exists only in a Development emit, so neither the mounted app's console
/// path nor the root one answers 200.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or HTTP error as a test error.
#[test]
fn release_web_app_keeps_console_closed_without_auth() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "release_web_app_keeps_console_closed_without_auth";

    let exe = compile_and_build_as(
        test_name,
        IPE_SERVER_MOUNTS_WEB_PROGRAM,
        ipe_backend_rust::BuildIntent::Release,
    )?;
    let port = pick_ephemeral_port()?;
    // Empty values read as absent, so an inherited posture or credential mode
    // cannot open the console behind the test's back.
    let _guard = spawn_and_wait_ready_with_env(
        test_name,
        &exe,
        port,
        &[("ENV", ""), ("IPE_ENV", ""), ("IPE_CONSOLE_AUTH", "")],
    )?;
    let addr = format!("127.0.0.1:{port}");

    for path in ["/app/_ipe/console", "/_ipe/console"] {
        let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        let resp = send_raw_request(test_name, &addr, &req)?;
        assert!(
            matches!(resp.status, 401 | 404),
            "{test_name}: {path} must stay closed in a release build, got {}\n--- body ---\n{}",
            resp.status,
            resp.body
        );
    }

    Ok(())
}

/// A server whose source hardcodes a LITERAL port and never reads the
/// environment. The runtime, not the program, must honour the operator
/// `IPE_SERVER_PORT`. This is the T1 regression fixture: `8000` is a
/// bare literal, so if `server_listen` ignored `IPE_SERVER_PORT` the app would
/// bind `8000`, never the ephemeral port the test connects to.
const IPE_SERVER_HARDCODED_PORT_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Http.Server as Server
import Ipe.Task

main =
    Server.listen 8000
        [ Server.get "/" (\req -> Task.succeed (Server.text "hardcoded ok"))
        ]
"#;

/// A server whose source port comes from `E2E_SOURCE_PORT`, a name outside the
/// runtime's port precedence, so a test sets the source, operator and
/// relocation layers independently on one binary.
const IPE_SERVER_SOURCE_PORT_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Http.Server as Server
import Ipe.Maybe
import Ipe.String
import Ipe.System
import Ipe.Task

main =
    let port = Maybe.withDefault 8000 (String.toInt (System.getenvOr "E2E_SOURCE_PORT" "8000"))
    in
    Server.listen port
        [ Server.get "/" (\req -> Task.succeed (Server.text "source ok"))
        ]
"#;

/// Two distinct free loopback ports.
fn pick_two_ports() -> Result<(u16, u16), BoxError> {
    let first = pick_ephemeral_port()?;
    for _ in 0..16 {
        let second = pick_ephemeral_port()?;
        if second != first {
            return Ok((first, second));
        }
    }
    Err("cannot pick two distinct ephemeral ports".into())
}

/// Whether a loopback connect to `port` is refused (nothing listens on it).
fn connect_refused(port: u16) -> bool {
    TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(500),
    )
    .is_err()
}

/// E2 (prove the refusal): the operator `IPE_SERVER_PORT` loses to the
/// supervisor's relocation var, and a malformed operator value falls back to
/// the source port, never to `0` or a refusal to bind.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or HTTP error as a test error.
#[test]
fn server_port_precedence_is_relocation_then_operator_then_source() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "server_port_precedence_is_relocation_then_operator_then_source";
    let relocation = ipe_runtime_rust::LISTEN_PORT_RELOCATION_ENV;
    let exe = compile_and_build(test_name, IPE_SERVER_SOURCE_PORT_PROGRAM)?;

    // Garbage operator value over a free source port: the source port binds.
    let source = pick_ephemeral_port()?;
    let source_text = source.to_string();
    {
        let _guard = spawn_and_wait_ready_with_env(
            test_name,
            &exe,
            source,
            &[
                ("IPE_SERVER_PORT", "80a0"),
                ("E2E_SOURCE_PORT", source_text.as_str()),
            ],
        )?;
        let body = http_get(test_name, &format!("127.0.0.1:{source}"), "/")?;
        assert_eq!(
            body, "source ok",
            "{test_name}: garbage IPE_SERVER_PORT must fall back to the source port"
        );
    }

    // A valid operator value and a relocation: the relocation binds and the
    // operator port stays closed.
    let (relocated, operator) = pick_two_ports()?;
    let relocated_text = relocated.to_string();
    let operator_text = operator.to_string();
    let _guard = spawn_and_wait_ready_with_env(
        test_name,
        &exe,
        operator,
        &[
            (relocation, relocated_text.as_str()),
            ("E2E_SOURCE_PORT", operator_text.as_str()),
        ],
    )?;
    let body = http_get(test_name, &format!("127.0.0.1:{relocated}"), "/")?;
    assert_eq!(
        body, "source ok",
        "{test_name}: the relocation port must serve"
    );
    assert!(
        connect_refused(operator),
        "{test_name}: the operator port must stay closed under relocation"
    );
    Ok(())
}

/// T1 (prove the refusal): `IPE_SERVER_PORT` overrides a HARDCODED literal port
/// in `server_listen`. The program passes `8000` literally; the runtime must
/// bind the ephemeral `IPE_SERVER_PORT` value instead, so the ephemeral port —
/// not `8000` — answers.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or HTTP error as a test error.
#[test]
fn server_honours_ipe_server_port_over_a_hardcoded_literal() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "server_honours_ipe_server_port_over_a_hardcoded_literal";

    let exe = compile_and_build(test_name, IPE_SERVER_HARDCODED_PORT_PROGRAM)?;
    let port = pick_ephemeral_port()?;
    // `spawn_and_wait_ready` sets `IPE_SERVER_PORT=<port>`; the ready line only
    // appears once the socket binds. It binding at all — on a port the source
    // never mentions — is the proof the env override took effect.
    let _guard = spawn_and_wait_ready(test_name, &exe, port)?;

    let addr = format!("127.0.0.1:{port}");
    let body = http_get(test_name, &addr, "/")?;
    assert_eq!(
        body, "hardcoded ok",
        "{test_name}: the ephemeral IPE_SERVER_PORT must answer even though the source hardcodes 8000\n--- actual ---\n{body}"
    );
    Ok(())
}

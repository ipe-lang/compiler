//! Hermetic network tests for Ipe.Http — `Http.get`, `Http.post`, and the
//! SSRF deny-private guard.
//!
//! All tests are gated on `IPE_E2E=1`.  Without it they return early so the
//! default `cargo test` stays fast.
//!
//! ## Architecture
//!
//! Each test:
//!
//! 1. Writes a Ipê program to a fresh temp dir.
//! 2. Compiles it through `ipe::build_with_options` with the dev-loop intent
//!    (full pipeline: parse → canon → types → lower → emit Rust).
//! 3. Builds the emitted Cargo project with the shared target via
//!    `e2e_support::build_rust_binary` — build-only, returns the binary path so the
//!    test controls execution.
//! 4. Launches a raw `TcpListener` fixture server (bound to `127.0.0.1:0` for an
//!    ephemeral port) in a background thread that handles exactly one HTTP
//!    request.  The fixture writes a canned HTTP/1.1 response and terminates.
//!    Using a raw TCP listener keeps the test free of extra dependencies (no
//!    `warp`, no `hyper-test`).
//! 5. Runs the compiled binary with the fixture URL in `IPE_HTTP_TEST_URL` and
//!    asserts exact stdout.
//!
//! ## SSRF negative test
//!
//! `http_ssrf_deny_loopback` does NOT start a fixture server.  It sets
//! `IPE_HTTP_DENY_PRIVATE=1`, points `Http.get` at the loopback address, and
//! asserts the runtime blocks the request (`DENIED` on stdout).  Proves the guard
//! works end-to-end (Ipê source → emitted Rust → `ipe_runtime` SSRF check).
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test http_e2e
//! ```

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

/// Default fail-fast ceiling for the fixture server's single `accept`.
///
/// If the compiled client never connects (a wedged runtime, a build that
/// produced a broken binary) the fixture thread would otherwise block in
/// `accept` until the outer nextest per-test cap. Bounding the accept lets the
/// thread exit promptly; the client-run assertion then fails on stdout with a
/// clear message rather than the whole shard stalling. The Ipê client connects
/// within milliseconds, so this window is never approached in the normal case.
const DEFAULT_FIXTURE_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Shared error type for E2E helpers: propagated via `?` so helpers and test
/// functions never call `panic!` or `expect`.
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// The `ipe build` dev-loop intent: these fixtures exercise the dev posture
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
/// Creates a unique temp dir per test name, writes `Main.ipe`, runs the full
/// ipe pipeline, then delegates the Cargo build to `e2e_support::build_rust_binary`.
///
/// # Errors
///
/// Returns an error on any pipeline or Cargo build failure.
fn compile_and_build(test_name: &str, ipe_source: &str) -> Result<PathBuf, BoxError> {
    let ipe_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("http_e2e_{test_name}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(&ipe_dir).map_err(|e| -> BoxError {
        format!("{test_name}: cannot create ipe source dir: {e}").into()
    })?;

    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, ipe_source)
        .map_err(|e| -> BoxError { format!("{test_name}: cannot write Main.ipe: {e}").into() })?;

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("http_e2e_{test_name}_emitted"));
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();

    ipe::build_with_options(&entry, &out_dir, &runtime, dev_loop_options())
        .map_err(|e| -> BoxError { format!("{test_name}: ipe build failed: {e}").into() })?;

    let exe = e2e_support::build_rust_binary(test_name, &out_dir)
        .map_err(|e| -> BoxError { format!("{test_name}: cargo build failed: {e}").into() })?;

    Ok(PathBuf::from(exe))
}

/// Spawn a minimal HTTP/1.1 fixture server that handles exactly one request and
/// returns `(url, join_handle)`.
///
/// Binds `127.0.0.1:0` for an ephemeral port.  The background thread reads
/// enough bytes to see the request line (the fixture ignores the request body
/// and headers) then writes back `raw_response`.  The listener closes after one
/// exchange.
///
/// `raw_response` must be a complete, valid HTTP/1.1 response including the
/// final `\r\n\r\n` header terminator and body — the fixture sends it verbatim.
///
/// The accept deadline runs from this call, so start the fixture only once the
/// client binary is built: a build slower than the deadline would otherwise
/// leave the client nothing to connect to.
///
/// # Errors
///
/// Returns an error if the listener cannot bind or if the local address cannot
/// be retrieved.
fn start_fixture(
    test_name: &str,
    raw_response: &'static str,
) -> Result<(String, thread::JoinHandle<()>), BoxError> {
    start_fixture_with_accept_timeout(test_name, raw_response, DEFAULT_FIXTURE_ACCEPT_TIMEOUT)
}

/// [`start_fixture`] with an explicit accept deadline, so the fail-fast
/// behaviour can be proven with a short window instead of the default wait.
///
/// # Errors
///
/// Returns an error if the listener cannot bind or if the local address cannot
/// be retrieved.
fn start_fixture_with_accept_timeout(
    test_name: &str,
    raw_response: &'static str,
    accept_timeout: Duration,
) -> Result<(String, thread::JoinHandle<()>), BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| -> BoxError {
        format!("{test_name}: cannot bind fixture server: {e}").into()
    })?;
    let port = listener
        .local_addr()
        .map_err(|e| -> BoxError { format!("{test_name}: cannot get fixture port: {e}").into() })?
        .port();
    let url = format!("http://127.0.0.1:{port}/");

    // Non-blocking accept so the thread is not wedged forever if the client
    // never connects: a bounded poll gives the fixture a fail-fast deadline
    // instead of blocking to the outer per-test cap.
    listener.set_nonblocking(true).map_err(|e| -> BoxError {
        format!("{test_name}: cannot set fixture listener non-blocking: {e}").into()
    })?;

    let handle = thread::Builder::new().spawn(move || {
        // Accept exactly one connection within the deadline. If none arrives
        // (a wedged or broken client) the fixture thread exits when the
        // deadline elapses; the running binary then produces no/short stdout
        // and the test assertion fails fast with a clear message rather than
        // hanging to the outer cap.
        let deadline = Instant::now() + accept_timeout;
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // The accepted stream inherits the listener's non-blocking
                    // flag; restore blocking so the drain + write below block
                    // normally. Bound them with explicit read/write timeouts so
                    // a peer that connects but never speaks cannot re-introduce
                    // a hang.
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                    // Drain enough bytes so the client finishes sending its
                    // request before we write the response. We never parse it.
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(raw_response.as_bytes());
                    let _ = stream.flush();
                    // `stream` drops here, closing the connection.
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                // A real accept error is terminal: exit so the client sees a
                // connection failure and the test assertion reports it.
                Err(_) => break,
            }
        }
    })?;

    Ok((url, handle))
}

// Ipê source shared between GET and POST tests.  The program reads the fixture
// URL from the `IPE_HTTP_TEST_URL` env var, performs the request, and prints
// `<status>\n<body>` so the test can assert both independently.

const IPE_HTTP_GET_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Http as Http
import Ipe.Io
import Ipe.String
import Ipe.System
import Ipe.Task
import Ipe.Url

main =
    case Url.fromString (System.getenvOr "IPE_HTTP_TEST_URL" "http://127.0.0.1:1") of
        Ok url ->
            Task.andThen
                (\resp -> Io.println (String.fromInt resp.status ++ "\n" ++ resp.body))
                (Http.get url)

        Err e ->
            Task.fail e
"#;

const IPE_HTTP_POST_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Http as Http
import Ipe.Io
import Ipe.String
import Ipe.System
import Ipe.Task
import Ipe.Url

main =
    case Url.fromString (System.getenvOr "IPE_HTTP_TEST_URL" "http://127.0.0.1:1") of
        Ok url ->
            Task.andThen
                (\resp -> Io.println (String.fromInt resp.status ++ "\n" ++ resp.body))
                (Http.post url "ping")

        Err e ->
            Task.fail e
"#;

// The SSRF program reads the fixture URL from `IPE_HTTP_TEST_URL` (a LIVE
// loopback server — see `http_ssrf_deny_loopback`).  With IPE_HTTP_DENY_PRIVATE=1
// the `ipe_runtime` guard rejects the request at address-resolution time, before
// it reaches the network. Task.onError wraps Task.andThen so that a failure in
// Http.get propagates past the andThen (which short-circuits on failure) and into
// the onError handler, which prints "DENIED"; the andThen success branch prints
// the status, so a guard that FAILED to fire would print "200", not "DENIED".
// Using nested calls (no |> operator) avoids Ipê layout-rule parse ambiguity
// when the pipe sits at a continuation line.
const IPE_HTTP_SSRF_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Http as Http
import Ipe.Io
import Ipe.String
import Ipe.System
import Ipe.Task
import Ipe.Url

main =
    case Url.fromString (System.getenvOr "IPE_HTTP_TEST_URL" "http://127.0.0.1:1") of
        Ok url ->
            Task.onError
                (\e -> Io.println "DENIED")
                (Task.andThen
                    (\resp -> Io.println (String.fromInt resp.status))
                    (Http.get url))

        Err e ->
            Task.fail e
"#;

// ── Tests ─────────────────────────────────────────────────────────────────────

/// `Http.get` against a raw TCP fixture returns the expected status and body.
///
/// The fixture server responds with HTTP 200 and body `hello get`.  The Ipê
/// program prints `200\nhello get`.  Proves the full pipeline end-to-end:
/// Ipê source → ipe → emitted Rust → `ipe_runtime` `Http.get` → parsed response.
///
/// # Errors
///
/// Propagates any pipeline, build, or process-launch failure as a test error.
#[test]
fn http_get_fixture() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let exe = compile_and_build("http_get_fixture", IPE_HTTP_GET_PROGRAM)?;

    let (url, _server) = start_fixture(
        "http_get_fixture",
        "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nhello get",
    )?;

    let out = Command::new(&exe)
        .env("IPE_HTTP_TEST_URL", &url)
        .output()
        .map_err(|e| -> BoxError { format!("http_get_fixture: cannot run binary: {e}").into() })?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.as_ref(),
        "200\nhello get\n",
        "http_get_fixture: unexpected stdout\n--- actual ---\n{stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "http_get_fixture: binary must exit 0"
    );
    Ok(())
}

/// `Http.post` against a raw TCP fixture returns the expected status and body.
///
/// The fixture server responds with HTTP 201 and body `hello post`.  The Ipê
/// program prints `201\nhello post`.  Proves `Http.post` posts the body and
/// reads the response correctly.
///
/// # Errors
///
/// Propagates any pipeline, build, or process-launch failure as a test error.
#[test]
fn http_post_fixture() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let exe = compile_and_build("http_post_fixture", IPE_HTTP_POST_PROGRAM)?;

    let (url, _server) = start_fixture(
        "http_post_fixture",
        "HTTP/1.1 201 Created\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhello post",
    )?;

    let out = Command::new(&exe)
        .env("IPE_HTTP_TEST_URL", &url)
        .output()
        .map_err(|e| -> BoxError { format!("http_post_fixture: cannot run binary: {e}").into() })?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.as_ref(),
        "201\nhello post\n",
        "http_post_fixture: unexpected stdout\n--- actual ---\n{stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "http_post_fixture: binary must exit 0"
    );
    Ok(())
}

/// `Http.get` to a LIVE `127.0.0.1` fixture with `IPE_HTTP_DENY_PRIVATE=1` is
/// BLOCKED.
///
/// A live loopback fixture IS started and its URL is handed to the program. This
/// is what makes the negative test honest: the port is open and reachable, so a
/// plain connection-refused cannot masquerade as a guard block. If the SSRF guard
/// did NOT fire, `Http.get` would connect to the fixture and the program would
/// print `200` (the andThen success branch) instead of `DENIED`. With
/// `IPE_HTTP_DENY_PRIVATE=1` the guard rejects the loopback address at
/// resolution time — before any connection — so the fixture is never contacted
/// and the program prints `DENIED`.
///
/// This is a negative test: it proves the `ipe_runtime` SSRF guard fires
/// correctly for loopback addresses via the full emitted-binary path (not just
/// at the unit-test level in `ipe_runtime`).
///
/// # Errors
///
/// Propagates any pipeline, build, or process-launch failure as a test error.
#[test]
fn http_ssrf_deny_loopback() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let exe = compile_and_build("http_ssrf_deny_loopback", IPE_HTTP_SSRF_PROGRAM)?;

    // Web loopback fixture: an open, reachable port. Excludes connection-refused
    // as an alternative explanation for the DENIED result — only the SSRF guard
    // can produce it. The fixture would answer `200 hi` if the guard let the
    // request through.
    let (url, _server) = start_fixture(
        "http_ssrf_deny_loopback",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
    )?;

    let out = Command::new(&exe)
        .env("IPE_HTTP_DENY_PRIVATE", "1")
        .env("IPE_HTTP_TEST_URL", &url)
        .output()
        .map_err(|e| -> BoxError {
            format!("http_ssrf_deny_loopback: cannot run binary: {e}").into()
        })?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.as_ref(),
        "DENIED\n",
        "http_ssrf_deny_loopback: SSRF guard must print DENIED\n--- actual ---\n{stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "http_ssrf_deny_loopback: binary must exit 0 (Task.onError recovered)"
    );
    Ok(())
}

/// The fixture accept deadline fires: with no client ever connecting, the
/// fixture thread must exit promptly once the deadline elapses rather than
/// blocking forever (which would spin to the outer per-test cap).
///
/// A short explicit deadline makes the proof fast. This test needs no compiled
/// binary, so it runs without `IPE_E2E`.
///
/// # Errors
///
/// Propagates a fixture-bind failure.
#[test]
fn fixture_accept_deadline_fires_when_no_client_connects() -> Result<(), BoxError> {
    let started = Instant::now();
    let (_url, handle) = start_fixture_with_accept_timeout(
        "fixture_accept_deadline",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        Duration::from_millis(200),
    )?;
    // Never connect. The thread must exit near the 200ms deadline, well under
    // any outer cap; join it and assert it returned promptly.
    handle
        .join()
        .map_err(|_| -> BoxError { "fixture thread panicked".into() })?;
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "the accept deadline must fire fast (no-connect), took {elapsed:?}"
    );
    Ok(())
}

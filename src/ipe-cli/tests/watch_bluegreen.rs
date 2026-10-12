#![forbid(unsafe_code)]
//! End-to-end proof for the DEV-ONLY blue-green front proxy in `ipe dev watch`
//! (`crate::watch` with `WatchOptions::bluegreen`).
//!
//! The load-bearing property: a rebuild behind the proxy does NOT drop the
//! browser's connection. The test holds ONE keep-alive TCP socket open to the
//! user-facing proxy port across a rebuild and asserts the SAME socket still
//! serves — now the NEW binary — after the cutover. Without the proxy, a
//! rebuild kills the old binary to free the port, so that socket would be
//! dropped (connection reset) and the assertion would fail.
//!
//! Gated on `IPE_E2E=1` exactly like `watch_integration.rs`: it drives a REAL
//! `cargo build` of the emitted web project and spawns the resulting binary.
//!
//! ```text
//! IPE_E2E=1 cargo nextest run -p ipe --test watch_bluegreen
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ipe::watch::{WatchHandle, WatchOptions};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A minimal `Ipe.Web` (TEA) app whose rendered page carries `marker` in its
/// heading, so a `GET /` can observe which binary is live. Uses `Web.tea`, so
/// the emitted entry contains `ipe_runtime::web::web_app` — the marker
/// `watch::emitted_is_web` keys the `/_ipe/readyz` readiness probe on.
fn web_fixture(marker: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\n\
         type Msg = Noop\n\n\
         type alias Model = {{ count : Int }}\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req = ( {{ count = 0 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model = ( model, Cmd.none )\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model = Sub.none\n\n\
         view : Model -> Element Msg\n\
         view _model =\n    \
             Ui.column [ Ui.spacing 8 ] [ Ui.el [] (Ui.text \"{marker}\") ]\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init\n        \
                 , update = update\n        \
                 , view = view\n        \
                 , subscriptions = subscriptions\n        \
                 , routes = []\n        \
                 , notFound = Noop\n        \
                 }}\n"
    )
}

/// A `Ipe.Web` app whose `Model` is `{ count : Int }`, incremented once per
/// `Sub.every` tick, with the live count rendered as the literal text
/// `count=<N>` so a `GET /` can read the running Model's state. `marker` is
/// rendered too so a probe can tell which binary is live. Used by the Model-
/// handoff E2E: after a few ticks the count is > 0 and write-through-
/// checkpointed to the shared session store, so a rebuild that rehydrates the
/// Model (rather than resetting to `init`'s `count = 0`) is observable.
fn ticker_fixture(marker: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.String as String\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\n\
         type Msg = Tick\n\n\
         type alias Model = {{ count : Int }}\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req = ( {{ count = 0 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model = ( {{ model | count = model.count + 1 }}, Cmd.none )\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model = Sub.every 100 Tick\n\n\
         view : Model -> Element Msg\n\
         view model =\n    \
             Ui.column [ Ui.spacing 8 ]\n        \
                 [ Ui.el [] (Ui.text \"{marker}\")\n        \
                 , Ui.el [] (Ui.text (String.concat [ \"count=\", String.fromInt model.count ]))\n        \
                 ]\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init\n        \
                 , update = update\n        \
                 , view = view\n        \
                 , subscriptions = subscriptions\n        \
                 , routes = []\n        \
                 , notFound = Tick\n        \
                 }}\n"
    )
}

/// A Model with a RENAMED field (`score : Int` instead of `count : Int`) so a
/// session checkpointed under the old schema is REJECTED by the additive-splice
/// gate: the old `count` key is absent from the new schema (removal) and the new
/// `score` key is absent from the old checkpoint (would be insertion) — neither
/// side is a superset of the other, so the splice is refused and the new binary
/// starts at a clean `init`. `notFound = Tick` keeps the single-Msg shape.
fn changed_model_fixture(marker: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.String as String\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\n\
         type Msg = Tick\n\n\
         type alias Model = {{ score : Int }}\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req = ( {{ score = 0 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model = ( {{ model | score = model.score + 1 }}, Cmd.none )\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model = Sub.every 100 Tick\n\n\
         view : Model -> Element Msg\n\
         view model =\n    \
             Ui.column [ Ui.spacing 8 ]\n        \
                 [ Ui.el [] (Ui.text \"{marker}\")\n        \
                 , Ui.el [] (Ui.text (String.concat [ \"score=\", String.fromInt model.score ]))\n        \
                 ]\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init\n        \
                 , update = update\n        \
                 , view = view\n        \
                 , subscriptions = subscriptions\n        \
                 , routes = []\n        \
                 , notFound = Tick\n        \
                 }}\n"
    )
}

/// Read timeout on the test's keep-alive socket.
///
/// This guards against a hanging `get_body_keepalive` call, not a slow server:
/// `wait_for_marker` has already confirmed (on fresh connections) that the proxy
/// is serving the expected binary before this socket sends its second request.
/// 30 s is generous enough to survive CI CPU starvation (the proxy and the
/// upstream are both local loopback; the round-trip is sub-millisecond when
/// uncontended) while bounding the worst-case hang to an acceptable window.
const E2E_KEEPALIVE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

fn fresh_dirs(tag: &str) -> Result<(PathBuf, PathBuf), BoxError> {
    let base = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "watch_bg_{tag}_{}_{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    let ipe_dir = base.join("ipe");
    let out_dir = base.join("out");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&ipe_dir)
        .map_err(|e| -> BoxError { format!("mkdir {}: {e}", ipe_dir.display()).into() })?;
    Ok((ipe_dir, out_dir))
}

fn write_main(ipe_dir: &Path, source: &str) -> Result<(), BoxError> {
    std::fs::write(ipe_dir.join("Main.ipe"), source)
        .map_err(|e| -> BoxError { format!("write Main.ipe: {e}").into() })
}

#[allow(clippy::expect_used)] // a refused session thread is a harness setup failure
fn start_watch(
    entry: &Path,
    out_dir: &Path,
    port: u16,
    bluegreen: bool,
) -> (
    std::thread::JoinHandle<Result<(), ipe::CliError>>,
    WatchHandle,
) {
    let runtime_dir = e2e_support::require_runtime().into_path_buf();
    let mut opts = WatchOptions::new(entry.to_path_buf(), out_dir.to_path_buf(), runtime_dir);
    opts.port = port;
    opts.bluegreen = bluegreen;
    // Forward CI's warm shared target (exported ONLY as IPE_ORACLE_SHARED_TARGET)
    // into the watch rebuild so it links against a pre-compiled dep tree; absent,
    // the watch stays isolated exactly as before.
    opts.target_dir = e2e_support::child_shared_target_from_env().map(PathBuf::from);
    opts.debounce = ipe_watch::DebounceConfig {
        quiescence: Duration::from_millis(120),
        hard_cap: Duration::from_millis(600),
    };
    ipe::watch::spawn(opts).expect("spawn the watch session")
}

/// One `GET / HTTP/1.1` on an ALREADY-OPEN keep-alive socket, returning the
/// response body. Reads the status line + headers, then the body per its
/// `Content-Length` (or, absent one, until the read times out). Crucially it
/// does NOT open a new connection — the whole point is to prove the SAME
/// socket survives a rebuild.
///
/// Returns `None` ONLY on a genuine EOF (the peer closed or reset the TCP
/// connection). A read timeout returns `Err`, which callers distinguish from
/// the "socket closed" failure this function exists to detect.
fn get_body_keepalive(stream: &mut TcpStream) -> Result<Option<String>, std::io::Error> {
    stream.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n")?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut content_length: Option<usize> = None;
    let mut status_ok = false;
    let mut first = true;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            // Genuine EOF: the peer closed the connection.
            return Ok(None);
        }
        if first {
            status_ok = line.starts_with("HTTP/1.1 2") || line.starts_with("HTTP/1.0 2");
            first = false;
        } else if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().ok();
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    if !status_ok {
        return Ok(Some(String::new()));
    }
    if let Some(len) = content_length {
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body)?;
        Ok(Some(String::from_utf8_lossy(&body).into_owned()))
    } else {
        // No Content-Length: read what's buffered within a short window.
        let mut body = Vec::new();
        let _ = reader
            .get_ref()
            .set_read_timeout(Some(Duration::from_millis(500)));
        let _ = reader.read_to_end(&mut body);
        Ok(Some(String::from_utf8_lossy(&body).into_owned()))
    }
}

/// A `GET /` on a fresh connection that returns BOTH the body and every
/// `Set-Cookie` value the server sent — the session-continuity E2E needs the
/// `ipe_sid` cookie so a later request can present it and be recognised as the
/// SAME session (rehydrating the checkpointed Model rather than minting a new
/// one). Optionally sends a `Cookie:` header (the previously-captured session
/// cookie) so the request is attributed to an existing session.
fn get_with_cookies(port: u16, send_cookie: Option<&str>) -> Option<(String, Vec<String>)> {
    let addr = format!("127.0.0.1:{port}").parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let req = send_cookie.map_or_else(
        || "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".to_string(),
        |cookie| {
            format!(
                "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nCookie: {cookie}\r\n\r\n"
            )
        },
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut reader = BufReader::new(stream);
    let mut cookies = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut first = true;
    let mut status_ok = false;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).ok()?;
        if n == 0 {
            return None;
        }
        if first {
            status_ok = line.starts_with("HTTP/1.1 2") || line.starts_with("HTTP/1.0 2");
            first = false;
        } else {
            let lower = line.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("set-cookie:") {
                // Keep only the `name=value` pair (before the first `;`).
                let raw = line.get("set-cookie:".len()..).unwrap_or("").trim();
                let pair = raw.split(';').next().unwrap_or("").trim().to_string();
                if !pair.is_empty() {
                    cookies.push(pair);
                }
                let _ = v;
            } else if let Some(v) = lower.strip_prefix("content-length:") {
                content_length = v.trim().parse().ok();
            } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
                chunked = true;
            }
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    if !status_ok {
        return Some((String::new(), cookies));
    }
    let body = if let Some(len) = content_length {
        let mut b = vec![0u8; len];
        reader.read_exact(&mut b).ok()?;
        String::from_utf8_lossy(&b).into_owned()
    } else if chunked {
        // Read chunks until the terminating 0-chunk; sufficient for the small
        // fixture page this test serves.
        let mut out = String::new();
        loop {
            let mut size_line = String::new();
            if reader.read_line(&mut size_line).ok()? == 0 {
                break;
            }
            let hex = size_line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(hex, 16).unwrap_or(0);
            if size == 0 {
                break;
            }
            let mut chunk = vec![0u8; size];
            reader.read_exact(&mut chunk).ok()?;
            out.push_str(&String::from_utf8_lossy(&chunk));
            let mut crlf = String::new();
            let _ = reader.read_line(&mut crlf);
        }
        out
    } else {
        let mut b = Vec::new();
        let _ = reader
            .get_mut()
            .set_read_timeout(Some(Duration::from_millis(500)));
        let _ = reader.read_to_end(&mut b);
        String::from_utf8_lossy(&b).into_owned()
    };
    Some((body, cookies))
}

/// Extract the `ipe_sid=<value>` session cookie (dev / plain-HTTP name) from a
/// captured `Set-Cookie` list. Returns the full `name=value` pair ready to send
/// back in a `Cookie:` header.
fn session_cookie(cookies: &[String]) -> Option<String> {
    cookies.iter().find(|c| c.starts_with("ipe_sid=")).cloned()
}

/// Parse the `count=<N>` the fixtures render into the page body.
fn rendered_count(body: &str) -> Option<i64> {
    let idx = body.find("count=")? + "count=".len();
    let rest = body.get(idx..)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Poll a FRESH connection to `port` until `GET /` serves a body containing
/// `want`, or `timeout` elapses. Used to wait for a cold build / a cutover to
/// land before exercising the kept-alive socket.
fn wait_for_marker(port: u16, want: &str, timeout: Duration) -> bool {
    let Ok(addr) = format!("127.0.0.1:{port}").parse() else {
        return false;
    };
    e2e_support::wait_for(timeout, || {
        let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) else {
            return false;
        };
        // A short per-sample read timeout: this is a polling probe; a
        // timeout just means the server is not ready yet, so continue.
        let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
        get_body_keepalive(&mut s)
            .ok()
            .flatten()
            .is_some_and(|b| b.contains(want))
    })
}

fn stop_and_join(
    handle: &WatchHandle,
    join: std::thread::JoinHandle<Result<(), ipe::CliError>>,
) -> Result<(), BoxError> {
    handle.stop();
    join.join().map_or_else(
        |_| Err("watch thread panicked".into()),
        |result| result.map_err(|e| -> BoxError { e.to_string().into() }),
    )
}

/// One rebuild's client-visible outage tail: sampling `GET /` on `port` every
/// 5ms, the wall-clock from the last successful serve of the OLD marker to the
/// first successful serve of the NEW marker, together with how many of those
/// samples FAILED to connect/serve (the socket-drop + reconnect cost the proxy
/// removes). Returns `(tail, failed_samples)`.
///
/// A FRESH connection per sample deliberately measures the browser-reconnect
/// experience: the direct path drops the socket on restart, so a browser must
/// reconnect — and during the respawn window every reconnect attempt is
/// refused. The proxy holds the port throughout, so reconnects never fail and
/// the tail collapses to just the cutover.
fn measure_rebuild_tail(
    port: u16,
    old_marker: &str,
    new_marker: &str,
    budget: Duration,
) -> (Duration, usize) {
    let start = Instant::now();
    let mut last_old_seen = start;
    let mut failed = 0usize;
    let Ok(addr) = format!("127.0.0.1:{port}").parse::<std::net::SocketAddr>() else {
        return (Duration::ZERO, 0);
    };
    loop {
        if start.elapsed() > budget {
            return (start.elapsed(), failed);
        }
        let served = TcpStream::connect_timeout(&addr, Duration::from_millis(150))
            .ok()
            .and_then(|mut s| {
                let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
                // `.ok().flatten()`: a timeout (Err) and a genuine socket close
                // (Ok(None)) both map to None, which the match below counts as
                // a failed sample — the same observable outcome for this harness.
                get_body_keepalive(&mut s).ok().flatten()
            });
        match served {
            Some(body) if body.contains(new_marker) => {
                // First serve of the new binary — the tail is measured from the
                // last successful old serve to here.
                return (last_old_seen.elapsed(), failed);
            }
            Some(body) if body.contains(old_marker) => {
                last_old_seen = Instant::now();
            }
            // A failed connect/serve OR an empty/unknown body during the window
            // is a reconnect the client would have had to make.
            _ => failed += 1,
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The MEASUREMENT harness (not a pass/fail gate — it prints a table). For a
/// given mode it does 3 rebuilds and reports the per-rebuild client-visible
/// outage tail and the number of failed reconnect samples. Run explicitly:
///
/// ```text
/// IPE_E2E=1 cargo test -p ipe --test watch_bluegreen -- --ignored --nocapture measure
/// ```
fn run_measurement(bluegreen: bool, port: u16, tag: &str) -> Result<(), BoxError> {
    let (ipe_dir, out_dir) = fresh_dirs(tag)?;
    write_main(&ipe_dir, &web_fixture("M-0"))?;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, bluegreen);
    assert!(
        wait_for_marker(port, "M-0", Duration::from_mins(5)),
        "cold build must serve M-0"
    );

    let mode = if bluegreen {
        "proxy cutover"
    } else {
        "direct (drop+reconnect)"
    };
    let mut tails = Vec::new();
    for i in 1..=3u32 {
        let old = format!("M-{}", i - 1);
        let new = format!("M-{i}");
        // Kick a background prober that measures the tail across the edit.
        let old_c = old.clone();
        let new_c = new.clone();
        let prober = std::thread::Builder::new()
            .spawn(move || measure_rebuild_tail(port, &old_c, &new_c, Duration::from_mins(2)))?;
        // Give the prober a beat to establish the baseline, then edit.
        std::thread::sleep(Duration::from_millis(50));
        write_main(&ipe_dir, &web_fixture(&new))?;
        let (tail, failed) = prober
            .join()
            .map_err(|_| -> BoxError { "prober panicked".into() })?;
        eprintln!(
            "[measure] {mode:<26} rebuild {i}: tail = {:>7.1} ms, failed reconnect samples = {failed}",
            tail.as_secs_f64() * 1000.0
        );
        tails.push(tail);
    }
    let count = u32::try_from(tails.len()).unwrap_or(1).max(1);
    let avg = tails.iter().sum::<Duration>() / count;
    eprintln!(
        "[measure] {mode:<26} AVERAGE tail over 3 rebuilds = {:.1} ms",
        avg.as_secs_f64() * 1000.0
    );

    stop_and_join(&handle, join)
}

#[test]
#[ignore = "measurement harness (prints a table); run explicitly with --ignored --nocapture"]
fn measure_direct_path_tail() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    run_measurement(false, 19181, "measure_direct")
}

#[test]
#[ignore = "measurement harness (prints a table); run explicitly with --ignored --nocapture"]
fn measure_bluegreen_path_tail() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    run_measurement(true, 19182, "measure_bluegreen")
}

/// The core proof: a rebuild behind the blue-green proxy does not drop the
/// browser's connection, and the same socket afterwards serves the NEW binary.
#[test]
fn bluegreen_rebuild_keeps_the_client_connection_alive() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    let (ipe_dir, out_dir) = fresh_dirs("keepalive")?;
    write_main(&ipe_dir, &web_fixture("MARKER-V1"))?;

    let port = 19191;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, true);

    assert!(
        wait_for_marker(port, "MARKER-V1", Duration::from_mins(5)),
        "cold build must serve v1 through the blue-green proxy"
    );

    // Open ONE keep-alive socket to the proxy port and confirm it serves v1.
    let mut client = TcpStream::connect(format!("127.0.0.1:{port}"))
        .map_err(|e| -> BoxError { format!("connect to proxy: {e}").into() })?;
    // The read timeout guards against a hung call, not a slow-but-correct
    // response: `wait_for_marker` (below) confirms on fresh connections that the
    // binary is serving before the socket sends its second request.
    client.set_read_timeout(Some(E2E_KEEPALIVE_RESPONSE_TIMEOUT))?;
    let first = get_body_keepalive(&mut client)
        .map_err(|e| -> BoxError { format!("v1 response read failed: {e}").into() })?;
    assert!(
        first.as_deref().is_some_and(|b| b.contains("MARKER-V1")),
        "the kept-alive socket must serve v1 first: {first:?}"
    );

    // Trigger a rebuild to a new binary and wait (on FRESH probes) for the
    // cutover to land.
    write_main(&ipe_dir, &web_fixture("MARKER-V2"))?;
    assert!(
        wait_for_marker(port, "MARKER-V2", Duration::from_mins(3)),
        "the rebuild must cut over to v2 behind the proxy"
    );

    // THE ASSERTION: the SAME socket, never reconnected, still works and now
    // serves the new binary. A dropped connection (the pre-proxy behaviour)
    // would make `get_body_keepalive` return `Ok(None)`. A read timeout
    // (proxy alive but slow — never a correct "socket dropped" signal) returns
    // `Err`; we propagate it so the failure message names the actual cause.
    let second = get_body_keepalive(&mut client).map_err(|e| -> BoxError {
        format!("v2 response read failed (timeout or I/O error — NOT a dropped connection): {e}")
            .into()
    })?;
    assert!(
        second.is_some(),
        "the client socket must SURVIVE the rebuild (not be dropped): got None (closed)"
    );
    assert!(
        second.as_deref().is_some_and(|b| b.contains("MARKER-V2")),
        "the surviving socket must serve the NEW binary after cutover: {second:?}"
    );

    stop_and_join(&handle, join)
}

/// Wait (on fresh cookie-bearing probes) until the SAME session's rendered
/// `count` reaches at least `min`, or `timeout` elapses. Returns the last
/// observed count. Used both to let a session tick up before a rebuild and to
/// confirm the rehydrated session after one.
fn wait_for_count_at_least(port: u16, cookie: &str, min: i64, timeout: Duration) -> Option<i64> {
    let deadline = Instant::now() + timeout;
    let mut last = None;
    while Instant::now() < deadline {
        if let Some((body, _)) = get_with_cookies(port, Some(cookie))
            && let Some(c) = rendered_count(&body)
        {
            last = Some(c);
            if c >= min {
                return Some(c);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    last
}

/// The Model-handoff proof: an edit + blue-green rebuild preserves the running
/// Model rather than resetting it to `init`.
///
/// A `Sub.every` ticker fixture increments `count` and write-through-
/// checkpoints it to the shared dev session store on every commit. The test
/// mints a session (capturing its `ipe_sid` cookie), lets the count tick well
/// past `init`'s `0`, then edits + rebuilds behind the proxy (Model TYPE
/// unchanged → same schema tag). Presenting the SAME cookie to the NEW binary
/// must rehydrate the checkpointed Model (`count` preserved, > 0), while a
/// FRESH cookieless request still gets a brand-new `init` session (`count`
/// starting at 0) — proving handoff restores the returning session without
/// breaking new-session init.
#[test]
fn bluegreen_rebuild_preserves_the_model_across_the_swap() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    let (ipe_dir, out_dir) = fresh_dirs("handoff")?;
    write_main(&ipe_dir, &ticker_fixture("HANDOFF-V1"))?;

    let port = 19193;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, true);
    assert!(
        wait_for_marker(port, "HANDOFF-V1", Duration::from_mins(5)),
        "cold build must serve v1 through the blue-green proxy"
    );

    // Mint a session and capture its sid cookie.
    let (_body, cookies) = get_with_cookies(port, None)
        .ok_or_else(|| -> BoxError { "initial GET must succeed".into() })?;
    let cookie = session_cookie(&cookies)
        .ok_or_else(|| -> BoxError { "server must set an ipe_sid cookie".into() })?;

    // Let this session tick up (count > 0) so the checkpoint is non-init.
    let before = wait_for_count_at_least(port, &cookie, 3, Duration::from_secs(20))
        .ok_or_else(|| -> BoxError { "session count must advance past init".into() })?;
    assert!(
        before >= 3,
        "pre-rebuild count must be > init's 0: {before}"
    );

    // Edit + rebuild behind the proxy — Model TYPE unchanged (same schema tag).
    write_main(&ipe_dir, &ticker_fixture("HANDOFF-V2"))?;
    assert!(
        wait_for_marker(port, "HANDOFF-V2", Duration::from_mins(3)),
        "the rebuild must cut over to v2 behind the proxy"
    );

    // THE ASSERTION: the SAME session, presented to the NEW binary, comes up
    // with its PRESERVED Model (count carried across, never reset to 0). The
    // ticker keeps running, so assert strictly > 0 (preserved), not an exact
    // value.
    let after = wait_for_count_at_least(port, &cookie, 1, Duration::from_secs(20))
        .ok_or_else(|| -> BoxError { "rehydrated session must render a count".into() })?;
    assert!(
        after >= 1,
        "the new binary must rehydrate the preserved Model (count > 0), not reset to init's 0: \
         got {after}"
    );

    // Control: a FRESH cookieless session still inits at 0 (handoff didn't
    // break new-session init — the very first read of a new session, before any
    // tick, is init's 0).
    let (fresh_body, fresh_cookies) = get_with_cookies(port, None)
        .ok_or_else(|| -> BoxError { "fresh GET must succeed".into() })?;
    assert!(
        session_cookie(&fresh_cookies).is_some_and(|c| c != cookie),
        "a cookieless GET must mint a DISTINCT new session"
    );
    assert_eq!(
        rendered_count(&fresh_body),
        Some(0),
        "a brand-new session must start at init's count=0: {fresh_body:?}"
    );

    stop_and_join(&handle, join)
}

/// The clean-reset half of the handoff: when the Model changes in a
/// NON-additive way between the old and new binary, the additive-splice gate
/// REJECTS the old checkpoint and the returning session falls back to a fresh
/// `init` — never a crash, never a torn/mismatched Model.
///
/// The old binary uses `{ count : Int }`; the rebuild renames that field to
/// `{ score : Int }` — a removal + addition, not a superset → the splice is
/// refused (the persisted `count` key is absent from the new schema).
/// Presenting the old session's cookie to the new binary must yield a clean
/// `init` (`score=0`), with the server healthy throughout.
#[test]
fn bluegreen_rebuild_resets_cleanly_on_model_type_change() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    let (ipe_dir, out_dir) = fresh_dirs("reset")?;
    write_main(&ipe_dir, &ticker_fixture("RESET-V1"))?;

    let port = 19194;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, true);
    assert!(
        wait_for_marker(port, "RESET-V1", Duration::from_mins(5)),
        "cold build must serve v1 through the blue-green proxy"
    );

    let (_body, cookies) = get_with_cookies(port, None)
        .ok_or_else(|| -> BoxError { "initial GET must succeed".into() })?;
    let cookie = session_cookie(&cookies)
        .ok_or_else(|| -> BoxError { "server must set an ipe_sid cookie".into() })?;

    // Tick the old session up so its checkpoint is decidedly non-init — the
    // whole point is that this state is DISCARDED, not carried into the wrong
    // shape.
    let before = wait_for_count_at_least(port, &cookie, 3, Duration::from_secs(20))
        .ok_or_else(|| -> BoxError { "session count must advance past init".into() })?;
    assert!(before >= 3, "pre-rebuild count must be > 0: {before}");

    // Edit + rebuild with a STRUCTURALLY DIFFERENT Model (extra `label` field
    // → different schema tag).
    write_main(&ipe_dir, &changed_model_fixture("RESET-V2"))?;
    assert!(
        wait_for_marker(port, "RESET-V2", Duration::from_mins(3)),
        "the rebuild must cut over to the changed-Model v2 behind the proxy"
    );

    // THE ASSERTION: the SAME cookie against the NEW binary is served cleanly
    // (no crash — the socket answers) and starts FRESH at init's score=0
    // (the non-additive rename was rejected, not spliced into the wrong shape).
    // The first read of the reset session is before any tick, so score=0.
    let (body, _) = get_with_cookies(port, Some(&cookie)).ok_or_else(|| -> BoxError {
        "server must answer after a non-additive Model change".into()
    })?;
    assert!(
        body.contains("RESET-V2"),
        "the new (renamed-field Model) binary must serve a healthy page: {body:?}"
    );
    // score=0 proves the session was reset to init (old `count` checkpoint was
    // refused), not spliced (which would have carried across no matching field).
    assert!(
        body.contains("score=0"),
        "a non-additive Model change must reset to init's score=0, never splice the \
         mismatched checkpoint: {body:?}"
    );

    stop_and_join(&handle, join)
}

/// A `Ipe.Web` app that ADDS a new `label : String` field to the existing
/// `{ count : Int }` Model — a purely additive change. `ticker_fixture` is
/// the "before" binary; this is the "after". The additive-splice algorithm
/// must PRESERVE the running `count` from the old checkpoint and fill the new
/// `label` field from `init`'s value. Both `count=N` and the new field's
/// init value (`label=init`) are rendered so a `GET /` can verify both.
fn additive_ticker_fixture(marker: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.String as String\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\n\
         type Msg = Tick\n\n\
         type alias Model = {{ count : Int, label : String }}\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req = ( {{ count = 0, label = \"init\" }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model = ( {{ model | count = model.count + 1 }}, Cmd.none )\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model = Sub.every 100 Tick\n\n\
         view : Model -> Element Msg\n\
         view model =\n    \
             Ui.column [ Ui.spacing 8 ]\n        \
                 [ Ui.el [] (Ui.text \"{marker}\")\n        \
                 , Ui.el [] (Ui.text (String.concat [ \"count=\", String.fromInt model.count ]))\n        \
                 , Ui.el [] (Ui.text (String.concat [ \"label=\", model.label ]))\n        \
                 ]\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init\n        \
                 , update = update\n        \
                 , view = view\n        \
                 , subscriptions = subscriptions\n        \
                 , routes = []\n        \
                 , notFound = Tick\n        \
                 }}\n"
    )
}

/// The additive-preserve proof: when the Model gains a NEW field (and nothing
/// is removed or retyped), the additive-splice gate KEEPS the returning
/// session's existing state and fills each new field from `init`.
///
/// The old binary uses `{ count : Int }`; the rebuild adds `label : String` —
/// a proven additive superset. The returning session must see its `count`
/// carried across (preserved, > 0) AND `label` filled from `init`'s `"init"`
/// value, without losing either old state or the new field's default.
#[test]
fn bluegreen_rebuild_preserves_state_on_additive_model_change() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    let (ipe_dir, out_dir) = fresh_dirs("additive")?;
    write_main(&ipe_dir, &ticker_fixture("ADDITIVE-V1"))?;

    let port = 19195;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, true);
    assert!(
        wait_for_marker(port, "ADDITIVE-V1", Duration::from_mins(5)),
        "cold build must serve v1 through the blue-green proxy"
    );

    // Mint a session and let the count tick well past init.
    let (_body, cookies) = get_with_cookies(port, None)
        .ok_or_else(|| -> BoxError { "initial GET must succeed".into() })?;
    let cookie = session_cookie(&cookies)
        .ok_or_else(|| -> BoxError { "server must set an ipe_sid cookie".into() })?;

    let before = wait_for_count_at_least(port, &cookie, 3, Duration::from_secs(20))
        .ok_or_else(|| -> BoxError { "session count must advance past init".into() })?;
    assert!(before >= 3, "pre-rebuild count must be > 0: {before}");

    // Rebuild with an ADDITIVE Model change (new `label` field).
    write_main(&ipe_dir, &additive_ticker_fixture("ADDITIVE-V2"))?;
    assert!(
        wait_for_marker(port, "ADDITIVE-V2", Duration::from_mins(3)),
        "the rebuild must cut over to the additive-Model v2 behind the proxy"
    );

    // THE ASSERTION: the returning session must have its `count` preserved
    // (> 0, carried across via the additive splice) AND `label` filled from
    // `init`'s `"init"` value (the new field's default).
    let (body, _) = get_with_cookies(port, Some(&cookie)).ok_or_else(|| -> BoxError {
        "server must answer after an additive Model change".into()
    })?;
    assert!(
        body.contains("ADDITIVE-V2"),
        "the additive-Model binary must serve a healthy page: {body:?}"
    );
    let after = rendered_count(&body);
    assert!(
        after.is_some_and(|c| c >= 1),
        "an additive Model change must PRESERVE the old count (> 0), not reset to 0: \
         {body:?}"
    );
    assert!(
        body.contains("label=init"),
        "the new `label` field must be filled from init's value: {body:?}"
    );

    stop_and_join(&handle, join)
}

/// The flag-OFF control: with `bluegreen` disabled, `ipe dev watch` keeps its
/// direct-bind behaviour — a rebuild still swaps the served binary (proving
/// the default path is unchanged). It does NOT assert socket survival (the
/// direct path drops connections on restart by design).
#[test]
fn flag_off_direct_path_still_swaps_the_binary() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    let (ipe_dir, out_dir) = fresh_dirs("flagoff")?;
    write_main(&ipe_dir, &web_fixture("OFF-V1"))?;

    let port = 19192;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, false);

    assert!(
        wait_for_marker(port, "OFF-V1", Duration::from_mins(5)),
        "cold build must serve v1 on the direct path"
    );

    write_main(&ipe_dir, &web_fixture("OFF-V2"))?;
    assert!(
        wait_for_marker(port, "OFF-V2", Duration::from_mins(3)),
        "the direct (flag-off) path must still swap the running binary to v2"
    );

    stop_and_join(&handle, join)
}

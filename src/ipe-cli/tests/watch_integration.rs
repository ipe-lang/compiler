#![forbid(unsafe_code)]
//! End-to-end proofs for `ipe dev watch` (`crate::watch`). The cancellation proof
//! lives separately in
//! `watch_cancellation.rs`, deterministically, since racing a real
//! file-save against warm salsa recompute — which is DELIBERATELY fast —
//! is not a reliable timing window for an E2E test).
//!
//! Gated on `IPE_E2E=1` exactly like `server_e2e.rs`: every scenario here
//! drives a REAL `cargo build` of the emitted project and spawns the
//! resulting binary, so these are slow (first build pays the full
//! dependency-compile cost) but honest — no mocked compiler, no mocked
//! process supervisor.
//!
//! ```text
//! IPE_E2E=1 cargo nextest run -p ipe --test watch_integration
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ipe::watch::{WatchEvent, WatchHandle, WatchOptions};

use e2e_support::wait_for;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The supervisor's listener relocation var `ipe dev watch` places its child with.
const RELOCATION_ENV: &str = ipe_runtime_rust::LISTEN_PORT_RELOCATION_ENV;

/// A minimal `Ipe.Http.Server` fixture, parameterised on the response body
/// so a test can edit it in place and observe the swap. Passes the operator
/// `IPE_SERVER_PORT` (the `server_e2e.rs` convention) as its source port; under
/// watch the supervisor's relocation var outranks both, so the child binds the
/// port `watch::child_env` derives from `WatchOptions::port`.
fn server_fixture(body: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Http.Server as Server\n\
         import Ipe.Maybe\n\
         import Ipe.String\n\
         import Ipe.System\n\
         import Ipe.Task\n\n\
         main =\n    \
             let port = Maybe.withDefault 8080 (String.toInt (System.getenvOr \"IPE_SERVER_PORT\" \"8080\"))\n    \
             in\n    \
             Server.listen port\n        \
                 [ Server.get \"/\" (\\req -> Task.succeed (Server.text \"{body}\")) ]\n"
    )
}

/// A server whose port is a HARDCODED literal (`8000`) — it never reads the
/// environment. Under blue-green the app must relocate to an internal port
/// dictated only by the listener relocation var (T1), and the proxy must front it on
/// `opts.port` (T2). If the runtime ignored the env, the app would bind `8000`
/// and collide with the proxy → the permanent `502 no upstream ready` this
/// guards against.
fn server_fixture_hardcoded_port(body: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Http.Server as Server\n\
         import Ipe.Task\n\n\
         main =\n    \
             Server.listen 8000\n        \
                 [ Server.get \"/\" (\\req -> Task.succeed (Server.text \"{body}\")) ]\n"
    )
}

/// A DELIBERATELY unparseable `.ipe` file — a dangling `let` with no `in`,
/// which fails at parse time (never reaches type-check, let alone emit).
const BROKEN_SOURCE: &str = "module Main exposing (main)\n\nmain =\n    let x = 1\n";

fn fresh_dirs(tag: &str) -> Result<(PathBuf, PathBuf), BoxError> {
    let base = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "watch_e2e_{tag}_{}_{}",
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

/// Poll `GET / HTTP/1.1` on `127.0.0.1:port` for up to `timeout`, returning
/// `true` the moment the body matches `want`, or `false` on timeout.
/// Mirrors `server_e2e.rs`'s own raw-socket polling — no extra HTTP
/// dependency.
///
/// Every caller's cold-build budget is generous on purpose: `start_watch`'s
/// `cargo build` is a genuinely isolated build (no shared cargo target — a
/// real `ipe dev watch` session must not silently reuse a stale one), competing
/// for CPU with every other test nextest runs in parallel. A tight deadline
/// here fails on scheduler contention, not on a real regression.
fn wait_for_body(port: u16, want: &str, timeout: Duration) -> bool {
    wait_for(timeout, || {
        http_get_body(port).is_some_and(|body| body.contains(want))
    })
}

fn http_get_body(port: u16) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().ok()?,
        Duration::from_millis(200),
    )
    .ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    text.split("\r\n\r\n").nth(1).map(str::to_owned)
}

/// A thread-safe sink for [`WatchEvent`]s, used to count `RebuildStarted`s
/// for the coalescing proof without capturing stderr or racing timing.
#[derive(Clone, Default)]
struct EventSink(Arc<Mutex<Vec<WatchEvent>>>);

impl EventSink {
    fn push(&self, event: WatchEvent) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event);
    }

    fn count_rebuild_started(&self) -> usize {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|e| matches!(e, WatchEvent::RebuildStarted { .. }))
            .count()
    }

    fn count_restarted(&self) -> usize {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|e| matches!(e, WatchEvent::Restarted { .. }))
            .count()
    }

    fn as_callback(&self) -> Arc<dyn Fn(WatchEvent) + Send + Sync> {
        let this = self.clone();
        Arc::new(move |e| this.push(e))
    }
}

#[allow(clippy::expect_used)] // a refused session thread is a harness setup failure
fn start_watch(
    entry: &Path,
    out_dir: &Path,
    port: u16,
    sink: &EventSink,
) -> (
    std::thread::JoinHandle<Result<(), ipe::CliError>>,
    WatchHandle,
) {
    let runtime_dir = e2e_support::require_runtime().into_path_buf();
    let mut opts = WatchOptions::new(entry.to_path_buf(), out_dir.to_path_buf(), runtime_dir);
    opts.port = port;
    // Forward CI's warm shared target (exported ONLY as IPE_ORACLE_SHARED_TARGET)
    // into the watch rebuild's cargo build, so it links against a pre-compiled
    // axum/tokio tree instead of cold-building it. Absent (a bare local run), the
    // watch stays isolated exactly as before.
    opts.target_dir = e2e_support::child_shared_target_from_env().map(PathBuf::from);
    // Tight debounce so the tests don't pay the default's full latency
    // budget while still comfortably coalescing a same-window double-save.
    opts.debounce = ipe_watch::DebounceConfig {
        quiescence: Duration::from_millis(120),
        hard_cap: Duration::from_millis(600),
    };
    opts.on_event = Some(sink.as_callback());
    ipe::watch::spawn(opts).expect("spawn the watch session")
}

/// Same as [`start_watch`] but with the blue-green proxy turned ON, so proxy
/// ENGAGEMENT (T2) is exercised: the proxy binds `port` IFF the emitted crate
/// binds a first-party HTTP listener; a non-HTTP shape takes the direct path.
#[allow(clippy::expect_used)] // a refused session thread is a harness setup failure
fn start_watch_bluegreen(
    entry: &Path,
    out_dir: &Path,
    port: u16,
    sink: &EventSink,
) -> (
    std::thread::JoinHandle<Result<(), ipe::CliError>>,
    WatchHandle,
) {
    let runtime_dir = e2e_support::require_runtime().into_path_buf();
    let mut opts = WatchOptions::new(entry.to_path_buf(), out_dir.to_path_buf(), runtime_dir);
    opts.port = port;
    opts.bluegreen = true;
    opts.target_dir = e2e_support::child_shared_target_from_env().map(PathBuf::from);
    opts.debounce = ipe_watch::DebounceConfig {
        quiescence: Duration::from_millis(120),
        hard_cap: Duration::from_millis(600),
    };
    opts.on_event = Some(sink.as_callback());
    ipe::watch::spawn(opts).expect("spawn the watch session")
}

/// A view-less worker that ticks forever — a LONG-LIVED non-HTTP shape. It emits
/// neither `web_app` nor `server_listen`, so under blue-green the proxy must NOT
/// engage (no bind on `opts.port`) and watch takes the direct-restart path. The
/// `marker` in the printed line lets a test observe that it is running.
fn worker_fixture(marker: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Io as Io\n\
         import Ipe.Task as Task\n\
         import Ipe.Tea.Worker\n\
         import Ipe.Tea.Worker.Cmd as Cmd\n\
         import Ipe.Tea.Worker.Sub as Sub\n\n\
         type Msg = Tick\n\n\
         type alias Model = {{ ticks : Int }}\n\n\
         init : () -> ( Model, Cmd Msg )\n\
         init _unit = ( {{ ticks = 0 }}, Task.attempt (\\_r -> Tick) (Io.println \"{marker}\") )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n    \
             ( {{ ticks = model.ticks + 1 }}\n    \
             , Task.attempt (\\_r -> Tick) (Io.println \"{marker}\")\n    \
             )\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model = Sub.every 100 Tick\n\n\
         main =\n    \
             Worker.tea {{ init = init, update = update, subscriptions = subscriptions }}\n"
    )
}

/// Try to bind `port` on loopback: `true` means the port is FREE (nothing — no
/// proxy — is holding it). Used to prove the proxy did NOT engage for a
/// non-HTTP shape under blue-green.
fn port_is_free(port: u16) -> bool {
    std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}

fn write_main(ipe_dir: &Path, source: &str) -> Result<(), BoxError> {
    std::fs::write(ipe_dir.join("Main.ipe"), source)
        .map_err(|e| -> BoxError { format!("write Main.ipe: {e}").into() })
}

/// Stop the watch session and propagate a thread panic (never swallowed) or
/// a setup-level `CliError` as a plain test failure.
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

/// Find a live process whose `/proc/<pid>/environ` contains the exact
/// `key=value` pair `ipe dev watch` injects into its supervised child's
/// environment (`watch::child_env` sets the listener relocation var
/// `ipe_runtime_rust::LISTEN_PORT_RELOCATION_ENV` to the child's port — see
/// `watch.rs`). Matching on the environment
/// rather than `cmdline`/the executable PATH is deliberate: the emitted
/// binary's actual on-disk location depends on where `cargo build` puts it
/// (honouring `CARGO_TARGET_DIR` if the test-runner's own environment sets
/// one — exactly the isolation convention this workspace's agent lanes
/// use), so asserting anything about that path here would make the test
/// depend on incidental build-cache configuration rather than the one thing
/// this test actually needs: an unambiguous handle on the correct PID.
/// `/proc/<pid>/environ` entries are NUL-separated, and NUL (0x00) is valid
/// single-byte UTF-8, so `String::from_utf8_lossy` preserves it verbatim —
/// matching `"KEY=VALUE\0"` (trailing NUL included) rules out a value that
/// merely starts with the same digits as another test's port. Linux-only:
/// the whole bug-3 regression below needs `/proc` for a black-box
/// PID-liveness check without adding any new production API surface just
/// for a test.
#[cfg(target_os = "linux")]
fn find_pid_by_environ_kv(key: &str, value: &str) -> Option<u32> {
    let needle = format!("{key}={value}\0");
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(environ) = std::fs::read(entry.path().join("environ")) else {
            continue;
        };
        if String::from_utf8_lossy(&environ).contains(&needle) {
            return Some(pid);
        }
    }
    None
}

/// Whether `pid` still names a live process. `/proc/<pid>` disappears the
/// moment the process is BOTH dead AND reaped (a zombie still has an entry
/// until its parent `wait()`s it) — which is exactly the property the
/// bug-3 regression needs: `SupervisorState::shutdown`'s `stop_gracefully`
/// calls `child.wait()` after killing it, so a lingering `/proc/<pid>` here
/// would mean the child was signalled but never actually reaped, not merely
/// "not yet observed dead".
#[cfg(target_os = "linux")]
fn pid_is_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

#[test]
fn watch_rebuild_on_save_swaps_the_running_binary() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    let (ipe_dir, out_dir) = fresh_dirs("rebuild_swap")?;
    write_main(&ipe_dir, &server_fixture("v1"))?;

    let sink = EventSink::default();
    let port = 19151;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink);

    assert!(
        wait_for_body(port, "v1", Duration::from_mins(4)),
        "initial cold build+spawn must serve v1 within budget"
    );

    write_main(&ipe_dir, &server_fixture("v2"))?;
    assert!(
        wait_for_body(port, "v2", Duration::from_mins(2)),
        "warm rebuild must swap the running binary to serve v2"
    );

    stop_and_join(&handle, join)
}

#[test]
fn watch_keeps_last_good_binary_alive_on_a_syntax_error() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    let (ipe_dir, out_dir) = fresh_dirs("last_good")?;
    write_main(&ipe_dir, &server_fixture("v1"))?;

    let sink = EventSink::default();
    let port = 19152;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink);

    assert!(
        wait_for_body(port, "v1", Duration::from_mins(4)),
        "initial cold build+spawn must serve v1"
    );

    // INV-3: a red build (here, a parse failure) must never touch the
    // running process. Introduce the deliberate syntax error, then assert
    // the server is STILL serving v1 after a window comfortably longer
    // than a real rebuild would take.
    write_main(&ipe_dir, BROKEN_SOURCE)?;
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("v1")),
        "last-good binary must still be serving v1 after a red build"
    );

    // Recovery: fixing the source must produce a fresh green build and
    // restart onto it. The recovery rebuild is a full isolated `cargo build`
    // (no shared target, exactly like the initial cold build), so it gets the
    // same generous cold-build budget — a tighter deadline here fails on a
    // loaded runner's slow rebuild, not on a real regression.
    write_main(&ipe_dir, &server_fixture("v2"))?;
    assert!(
        wait_for_body(port, "v2", Duration::from_mins(4)),
        "watch must recover once the syntax error is fixed"
    );

    stop_and_join(&handle, join)
}

#[test]
fn watch_coalesces_a_rapid_double_save_into_one_rebuild() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    let (ipe_dir, out_dir) = fresh_dirs("coalesce")?;
    write_main(&ipe_dir, &server_fixture("v1"))?;

    let sink = EventSink::default();
    let port = 19153;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink);

    assert!(
        wait_for_body(port, "v1", Duration::from_mins(4)),
        "initial cold build+spawn must serve v1"
    );

    let rebuilds_before = sink.count_rebuild_started();

    // Back-to-back writes, deliberately with NO intervening sleep: a
    // `thread::sleep` only guarantees a MINIMUM wait — under CPU contention
    // the scheduler can wake a parked thread arbitrarily late, so a fixed
    // sleep meant to land "well inside" the 120ms quiescence window
    // configured in `start_watch` can instead overshoot it, splitting this
    // burst into two rebuild cycles instead of one. Never voluntarily
    // yielding between the two writes keeps the real gap between them down
    // to the two syscalls' own cost, which stays inside the window
    // regardless of scheduler load. Both writes must still coalesce into
    // exactly ONE rebuild cycle, and the LAST write (v3) must be what ships.
    write_main(&ipe_dir, &server_fixture("v2"))?;
    write_main(&ipe_dir, &server_fixture("v3"))?;

    assert!(
        wait_for_body(port, "v3", Duration::from_mins(2)),
        "the LAST write in the coalesced burst must be what ships"
    );

    let rebuilds_after = sink.count_rebuild_started();
    assert_eq!(
        rebuilds_after - rebuilds_before,
        1,
        "a rapid double-save inside the quiescence window must coalesce into exactly one rebuild"
    );

    stop_and_join(&handle, join)
}

/// Bug-3 regression: an embedder that lets a [`WatchHandle`] fall out of
/// scope WITHOUT ever calling `stop()` — the exact shape of a caller bug, or
/// a panic unwinding through a scope that holds one — must not leak the
/// supervised child process as an orphan. `Drop for WatchHandle` is the
/// safety net; this proves it actually reaps the child, not merely that it
/// compiles.
///
/// Linux-only (`/proc`-based PID liveness — see `find_pid_by_environ_kv`/
/// `pid_is_alive`): no new production API surface was added just to make
/// this observable from a black-box test.
#[cfg(target_os = "linux")]
#[test]
fn dropping_a_watch_handle_without_stop_still_reaps_the_supervised_child() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    let (ipe_dir, out_dir) = fresh_dirs("drop_reaps_child")?;
    write_main(&ipe_dir, &server_fixture("v1"))?;

    let sink = EventSink::default();
    let port = 19155;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink);

    assert!(
        wait_for_body(port, "v1", Duration::from_mins(4)),
        "initial cold build+spawn must serve v1"
    );

    // `watch::child_env` sets the relocation var to `<port>` in the supervised
    // child's own environment, unique to this test's port — a stronger
    // handle on the right PID than the executable's on-disk path (which
    // moves if the test-runner's own environment sets `CARGO_TARGET_DIR`).
    let child_pid = find_pid_by_environ_kv(RELOCATION_ENV, &port.to_string())
        .expect("the supervised child process must be discoverable via /proc once v1 is serving");
    assert!(
        pid_is_alive(child_pid),
        "sanity: the child must be alive right after v1 is confirmed serving"
    );

    // Simulate the abnormal-exit shape the bug report describes: drop the
    // `WatchHandle` directly, never calling `stop()`. `Drop::drop` is the
    // ONLY thing standing between this and an orphaned `ipe-app` server
    // holding a real port open forever.
    drop(handle);

    // `Drop`'s synchronous wait-for-shutdown (bounded by
    // `SHUTDOWN_WAIT_BUDGET` inside `watch.rs`) means the child is
    // GUARANTEED fully reaped by the time `drop(handle)` above returns — no
    // polling loop needed here, unlike a fire-and-forget shutdown request
    // would require.
    assert!(
        !pid_is_alive(child_pid),
        "WatchHandle::drop must reap the supervised child even when stop() was never called \
         (it must have been both killed AND wait()ed — a lingering zombie also fails this)"
    );

    // The orchestrator thread has also fully exited by now (`Drop` waited
    // for its own done-signal, which only fires after `run_inner` returns)
    // — this join is a formality, not a wait.
    join.join().map_or_else(
        |_| Err("watch thread panicked".into()),
        |result| result.map_err(|e| -> BoxError { e.to_string().into() }),
    )
}

/// T2 (prove the refusal): a non-HTTP shape (a worker) under blue-green must NOT
/// bind a proxy on `opts.port`. Proxy engagement keys on the emitted crate
/// binding a first-party HTTP listener; a worker emits neither `web_app` nor
/// `server_listen`, so watch takes the direct-restart path and leaves the port
/// FREE. A rebuild still restarts the worker (direct path). Guards against the
/// spurious `:port` bind a shape-blind proxy would create.
#[cfg(target_os = "linux")]
#[test]
fn watch_does_not_bind_a_proxy_for_a_non_http_shape() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    let (ipe_dir, out_dir) = fresh_dirs("no_proxy_non_http")?;
    write_main(&ipe_dir, &worker_fixture("WORKER-V1"))?;

    let sink = EventSink::default();
    let port = 19156;
    let (join, handle) = start_watch_bluegreen(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink);

    // Wait for the cold build to spawn the worker (its child carries the
    // injected relocation var — discoverable via /proc).
    let deadline = Instant::now() + Duration::from_mins(4);
    let child_pid = loop {
        if let Some(pid) = find_pid_by_environ_kv(RELOCATION_ENV, &port.to_string()) {
            break pid;
        }
        if Instant::now() > deadline {
            let _ = stop_and_join(&handle, join);
            return Err("worker child must spawn within the cold-build budget".into());
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    assert!(pid_is_alive(child_pid), "the worker child must be alive");

    // THE REFUSAL: no proxy engaged, so nothing holds `opts.port`. A shape-blind
    // proxy would have bound it up front. (The worker does not bind it either.)
    assert!(
        port_is_free(port),
        "no proxy may bind opts.port for a non-HTTP shape — the port must be free"
    );

    // A rebuild still drives the direct-restart path.
    let restarts_before = sink.count_restarted();
    write_main(&ipe_dir, &worker_fixture("WORKER-V2"))?;
    assert!(
        wait_for(Duration::from_mins(3), || {
            sink.count_restarted() > restarts_before
        }),
        "a rebuild of a non-HTTP shape must restart it via the direct path"
    );

    stop_and_join(&handle, join)
}

/// T2 (proxy engages for a first-party HTTP server) + T1 (the app relocates off
/// its hardcoded port): a `Server.listen 8000` with a HARDCODED literal port,
/// under blue-green, must (a) have the proxy answer on `opts.port`, and (b) run
/// the app on a DIFFERENT internal port — never colliding on 8000. Proves the
/// permanent-502 regression is fixed and detection is by emitted `server_listen`,
/// not by shape (a `Server.listen` main is `Shape::Script`).
#[test]
fn watch_proxies_a_hardcoded_port_server_on_an_internal_port() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    let (ipe_dir, out_dir) = fresh_dirs("proxy_hardcoded_server")?;
    write_main(&ipe_dir, &server_fixture_hardcoded_port("v1"))?;

    let sink = EventSink::default();
    // Deliberately NOT 8000: the app source hardcodes 8000, so the proxy holding
    // opts.port must be a different port — proving the app relocated (T1) and the
    // proxy fronts it (T2).
    let port = 19157;
    let (join, handle) = start_watch_bluegreen(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink);

    // The proxy answers on opts.port with the app's body — the app came up on an
    // internal port BEHIND the proxy despite hardcoding 8000. (Were the 502
    // regression present, the app would collide on 8000 and never be ready.)
    assert!(
        wait_for_body(port, "v1", Duration::from_mins(4)),
        "the blue-green proxy must front the hardcoded-port server on opts.port (no 502)"
    );

    // A rebuild cuts over to the new binary behind the same proxy port.
    write_main(&ipe_dir, &server_fixture_hardcoded_port("v2"))?;
    assert!(
        wait_for_body(port, "v2", Duration::from_mins(3)),
        "a rebuild must cut over to v2 behind the proxy"
    );

    stop_and_join(&handle, join)
}

/// E1 (prove the refusal): operator port vars in `ipe dev watch`'s own environment
/// can neither relocate nor collide with the supervised child. A real
/// `ipe dev watch` subprocess (blue-green, the CLI default) runs with
/// `IPE_SERVER_PORT` and `IPE_WEB_PORT` set to `operator`; the fixture even
/// passes that value as its source port. The proxy on `port` must serve the
/// body, and nothing may listen on `operator`: the child binds the internal
/// port the supervisor chose through the relocation var, which outranks both.
#[cfg(target_os = "linux")]
#[test]
fn operator_port_vars_never_relocate_a_watched_child() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    let (ipe_dir, out_dir) = fresh_dirs("operator_port_vars")?;
    write_main(&ipe_dir, &server_fixture("OPERATOR-V1"))?;
    let port: u16 = 19165;
    let operator: u16 = 19166;
    let runtime_dir = e2e_support::require_runtime().into_path_buf();
    let mut cmd = std::process::Command::new(e2e_support::cargo_bin!("ipe").into_path_buf());
    cmd.arg("dev")
        .arg("watch")
        .arg(ipe_dir.join("Main.ipe"))
        .arg("--out")
        .arg(&out_dir)
        .arg("--runtime")
        .arg(&runtime_dir)
        .arg("--port")
        .arg(port.to_string())
        .env("IPE_SERVER_PORT", operator.to_string())
        .env("IPE_WEB_PORT", operator.to_string())
        .env_remove(RELOCATION_ENV)
        .env_remove("IPE_WATCH_NO_BLUEGREEN")
        .env_remove("IPE_WATCH_BLUEGREEN")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some(target) = e2e_support::child_shared_target_from_env() {
        cmd.env("CARGO_TARGET_DIR", target);
    }
    let mut watch = cmd
        .spawn()
        .map_err(|e| -> BoxError { format!("ipe dev watch must spawn: {e}").into() })?;

    let served = wait_for_body(port, "OPERATOR-V1", Duration::from_mins(4));
    let operator_refused = TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], operator)),
        Duration::from_millis(500),
    )
    .is_err();
    let operator_free = port_is_free(operator);

    // Orderly teardown (SIGTERM reaps the supervised child), bounded; a watch
    // that outlives the grace is killed so the test never hangs.
    let _ = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(watch.id().to_string())
        .status();
    let exited = wait_for(Duration::from_secs(30), || {
        matches!(watch.try_wait(), Ok(Some(_)))
    });
    if !exited {
        let _ = watch.kill();
        let _ = watch.wait();
    }

    assert!(served, "the proxy on --port must serve the body");
    assert!(
        operator_refused && operator_free,
        "nothing may listen on the operator port under watch \
         (refused {operator_refused}, free {operator_free})"
    );
    Ok(())
}

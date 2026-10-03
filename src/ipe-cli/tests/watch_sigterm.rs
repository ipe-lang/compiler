#![forbid(unsafe_code)]
//! SIGTERM-handling proofs for `ipe watch` (`crate::watch`).
//!
//! Three scenarios around the `run()`-only SIGTERM shutdown subscriber:
//!
//! 1. `IPE_E2E=1`: a PID-only `kill -TERM <ipe>` (the systemd-style shape —
//!    NOT the whole foreground process group Ctrl-C signals) runs the full
//!    orderly teardown, so the supervised child is reaped, never orphaned.
//! 2. Always-on negative control: `spawn()` (the embedder path) must NEVER
//!    install a process-wide SIGTERM handler — the embedding host's own
//!    disposition stays untouched.
//! 3. `IPE_E2E=1`: a SECOND SIGTERM during the teardown ends the process —
//!    by the signal, unless the teardown already finished cleanly — and the
//!    supervised child is gone either way.

#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::net::TcpStream;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::time::{Duration, Instant};

mod support;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Budget for `ipe watch` to build and serve after the dep graph has been
/// pre-warmed by [`warm_server_fixture_deps`]. All deps are already compiled;
/// the watch only pays a link step plus server startup — well under a minute on
/// any loaded box. The functional guard is the SIGTERM assertion that follows,
/// not this wait.
#[cfg(target_os = "linux")]
const WATCH_SERVE_BUDGET: Duration = Duration::from_mins(2);

/// Budget for the one-shot dep warm-up in [`warm_server_fixture_deps`]: a full
/// cold cargo build of the axum/tokio server fixture on a sccache-off box.
#[cfg(target_os = "linux")]
const DEP_WARM_BUDGET: Duration = Duration::from_mins(10);

/// The same minimal `Ipe.Http.Server` fixture `watch_integration.rs` uses:
/// long-running (never exits on its own); passes `IPE_SERVER_PORT` as its
/// source port, which the relocation var `watch::child_env` sets outranks.
#[cfg(target_os = "linux")]
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

/// A source that PARSES cleanly but fails name resolution — every rebuild
/// cycle goes `CompileOutcome::Red` (logged, loop stays alive) and never
/// reaches a `cargo build`, so the in-process `spawn()` control below runs in
/// milliseconds without ever paying a dependency compile.
const RED_BUILD_SOURCE: &str = "module Main exposing (main)\n\nmain = definitelyNotBound\n";

fn fresh_dirs(tag: &str) -> Result<(PathBuf, PathBuf), BoxError> {
    let base = crate::support::scratch_root().join(format!(
        "watch_sigterm_{tag}_{}_{}",
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

/// Pre-compile the server fixture's cargo dependencies into the shared target
/// so subsequent `ipe watch` cold builds pay only the link step.
///
/// `ipe watch` spawns its own `cargo build` subprocess in an emitted project
/// directory. On a sccache-off box with a cold cargo target that full dep compile
/// (axum, tokio, tower-http, …) can take many minutes, making the timed
/// `wait_for_body` guard unreliable regardless of the budget. This function
/// emits the same server fixture once and runs `cargo build` on it, warming
/// every dependency in the shared target the global `~/.cargo/config.toml`
/// points to. After this returns, `ipe watch`'s own build only needs to link —
/// seconds, not minutes.
///
/// `RUSTC_WRAPPER` is cleared so sccache does not interfere with the warm-up
/// build; the shared target's object cache is all that matters here.
#[cfg(target_os = "linux")]
fn warm_server_fixture_deps() -> Result<(), BoxError> {
    let warm_dir = crate::support::scratch_root().join(format!(
        "watch_sigterm_warm_{}_{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    let ipe_dir = warm_dir.join("ipe");
    let out_dir = warm_dir.join("out");
    let _ = std::fs::remove_dir_all(&warm_dir);
    std::fs::create_dir_all(&ipe_dir)
        .map_err(|e| -> BoxError { format!("warm: mkdir {}: {e}", ipe_dir.display()).into() })?;

    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, server_fixture("warm"))
        .map_err(|e| -> BoxError { format!("warm: write Main.ipe: {e}").into() })?;

    let runtime_dir = e2e_support::require_runtime().into_path_buf();

    ipe::build(&entry, &out_dir, &runtime_dir)
        .map_err(|e| -> BoxError { format!("warm: ipe build failed: {e}").into() })?;

    // Non-zero cargo exit is intentionally ignored: warming is best-effort.
    // A fluke build failure here means `ipe watch` pays the full cold build
    // time itself — the SIGTERM assertion is unaffected.
    //
    // Run with the same environment the watch's own cargo build inherits (no
    // RUSTC_WRAPPER override): cargo fingerprints include the wrapper, so a
    // warm built without sccache produces artifacts with a different fingerprint
    // than the watch's sccache-enabled build, forcing a full recompile and
    // defeating the warm-up entirely. Pin the SAME shared target the watch's
    // build is forwarded (IPE_ORACLE_SHARED_TARGET in CI), so the deps land where
    // the watch links them instead of in a throwaway per-dir target.
    let mut cargo = Command::new("cargo");
    cargo.arg("build").current_dir(&out_dir);
    if let Some(target) = e2e_support::child_shared_target_from_env() {
        cargo.env("CARGO_TARGET_DIR", target);
    }
    let _cargo_status = cargo
        .status()
        .map_err(|e| -> BoxError { format!("warm: cargo build spawn: {e}").into() })?;

    let _ = std::fs::remove_dir_all(&warm_dir);
    Ok(())
}

/// Convenience wrapper: run [`warm_server_fixture_deps`] with a hard timeout.
/// Returns `Ok(())` whether warming succeeded or not — a warm-up failure is
/// not fatal; the E2E test just pays the full cold build time itself.
#[cfg(target_os = "linux")]
fn try_warm(timeout: Duration) -> Result<(), BoxError> {
    // Run the warm-up on a background thread so we can enforce the timeout
    // without blocking the test process indefinitely.
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), BoxError>>();
    std::thread::Builder::new().spawn(move || {
        let _ = tx.send(warm_server_fixture_deps());
    })?;
    rx.recv_timeout(timeout).unwrap_or_else(|_| Ok(()))
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn wait_for_body(port: u16, want: &str, timeout: Duration) -> bool {
    e2e_support::wait_for(timeout, || {
        http_get_body(port).is_some_and(|body| body.contains(want))
    })
}

/// PID-only SIGTERM via `kill(1)` — never a process-group signal.
#[cfg(target_os = "linux")]
fn sigterm(pid: u32) -> Result<(), BoxError> {
    let status = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .map_err(|e| -> BoxError { format!("kill(1) must spawn: {e}").into() })?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("kill -TERM {pid} failed: {status}").into())
    }
}

#[cfg(target_os = "linux")]
fn pid_is_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// The supervised app binary is a direct child of the `ipe watch` process. In
/// blue-green mode the child binds an INTERNAL loopback port (the proxy holds
/// the user-facing one), so it cannot be found by the configured `--port`;
/// discover it by parent PID instead. Returns the first `/proc` entry whose
/// `PPid` is `ipe_pid`.
#[cfg(target_os = "linux")]
fn find_child_of(ipe_pid: u32) -> Option<u32> {
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        let parent = status
            .lines()
            .find_map(|l| l.strip_prefix("PPid:"))
            .and_then(|v| v.trim().parse::<u32>().ok());
        if parent == Some(ipe_pid) {
            return Some(pid);
        }
    }
    None
}

/// Poll for the supervised child of `ipe_pid` up to `timeout` — the child is
/// spawned a beat after the server first answers, so a single scan can race it.
#[cfg(target_os = "linux")]
fn wait_for_child_of(ipe_pid: u32, timeout: Duration) -> Option<u32> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(pid) = find_child_of(ipe_pid) {
            return Some(pid);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Spawn a REAL `ipe watch` subprocess (the `run()` path, `external_stop =
/// None` — the only caller the SIGTERM shutdown subscriber is registered for). When
/// `capture_stderr` is set the child's stderr is piped so the caller can
/// synchronize on the [`ipe::watch::SIGTERM_TEARDOWN_MARKER`] ack; otherwise it
/// is discarded.
#[cfg(target_os = "linux")]
fn spawn_ipe_watch(
    entry: &Path,
    out_dir: &Path,
    port: u16,
    capture_stderr: bool,
) -> Result<std::process::Child, BoxError> {
    let runtime_dir = e2e_support::require_runtime().into_path_buf();
    let mut cmd = std::process::Command::new(support::ipe_bin());
    cmd.arg("watch")
        .arg(entry)
        .arg("--out")
        .arg(out_dir)
        .arg("--runtime")
        .arg(&runtime_dir)
        .arg("--port")
        .arg(port.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(if capture_stderr {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        });
    // Forward CI's warm shared target (exported ONLY as IPE_ORACLE_SHARED_TARGET)
    // as the child `ipe watch`'s CARGO_TARGET_DIR, so its rebuild links against a
    // pre-compiled dep tree — the SAME target `warm_server_fixture_deps` warms.
    // Absent (a bare local run) the child stays isolated exactly as before.
    if let Some(target) = e2e_support::child_shared_target_from_env() {
        cmd.env("CARGO_TARGET_DIR", target);
    }
    cmd.spawn()
        .map_err(|e| -> BoxError { format!("ipe watch must spawn: {e}").into() })
}

/// Take the child's piped stderr and, on a reader thread, scan it line-by-line
/// for `marker` (matched as a substring — the emitted line wraps the marker in
/// gutter/colour escapes). The returned receiver yields `true` the instant a
/// line containing the marker is seen, `false` if stderr closes first (the
/// child exited before printing it). The thread keeps draining stderr after the
/// match so the child never blocks on a full pipe during teardown.
///
/// Synchronizing on this ack — rather than a fixed sleep — is what makes the
/// double-SIGTERM sequence deterministic: the second signal is sent only once
/// the subscriber has provably answered the first.
#[cfg(target_os = "linux")]
fn watch_marker_seen(
    child: &mut std::process::Child,
    marker: &'static str,
) -> Result<std::sync::mpsc::Receiver<bool>, BoxError> {
    use std::io::BufRead;
    let stderr = child
        .stderr
        .take()
        .ok_or("child stderr must be piped to observe the teardown ack")?;
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    std::thread::Builder::new().spawn(move || {
        let mut reader = std::io::BufReader::new(stderr);
        let mut announced = false;
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                // A non-empty read: check it for the marker.
                Ok(n) if n > 0 => {
                    if !announced && line.contains(marker) {
                        announced = true;
                        let _ = tx.send(true);
                    }
                }
                // Zero bytes (stderr closed) or a read error: stop draining.
                Ok(_) | Err(_) => break,
            }
        }
        if !announced {
            let _ = tx.send(false);
        }
    })?;
    Ok(rx)
}

/// Poll `child.try_wait()` until it exits or `timeout` elapses.
#[cfg(target_os = "linux")]
fn wait_for_exit(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// A supervisor's `kill -TERM <ipe-pid>` (PID only — explicitly NOT the
/// process group, reproducing the systemd-style gap) must run the full
/// orderly teardown: the `ipe` process exits cleanly AND the supervised
/// child is gone (killed and reaped), never an orphan holding the port.
#[cfg(target_os = "linux")]
#[test]
fn watch_shuts_down_the_supervised_child_on_sigterm_to_only_the_ipe_process() -> Result<(), BoxError>
{
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }

    // Pre-warm the shared cargo target so the watch's own build pays only a
    // link step. Best-effort: if warm-up fails or times out the test still
    // runs; it just takes longer.
    let _ = try_warm(DEP_WARM_BUDGET);

    let (ipe_dir, out_dir) = fresh_dirs("term_reaps_child")?;
    std::fs::write(ipe_dir.join("Main.ipe"), server_fixture("v1"))
        .map_err(|e| -> BoxError { format!("write Main.ipe: {e}").into() })?;

    let port = 19159;
    let mut ipe_proc = spawn_ipe_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, false)?;

    if !wait_for_body(port, "v1", WATCH_SERVE_BUDGET) {
        let _ = ipe_proc.kill();
        let _ = ipe_proc.wait();
        return Err("initial cold build+spawn must serve v1 within budget".into());
    }
    let child_pid = wait_for_child_of(ipe_proc.id(), Duration::from_secs(10))
        .ok_or("the supervised child must be discoverable via /proc once v1 is serving")?;

    sigterm(ipe_proc.id())?;

    let status = wait_for_exit(&mut ipe_proc, Duration::from_secs(30));
    let Some(status) = status else {
        let _ = ipe_proc.kill();
        let _ = ipe_proc.wait();
        return Err(
            "ipe must exit within a bounded wait after a PID-only SIGTERM \
                    (pre-fix: it died instantly via the default disposition, but the \
                    orphaned child kept the port)"
                .into(),
        );
    };
    assert!(
        status.success(),
        "the SIGTERM teardown path returns Ok(()) → exit 0, got {status}"
    );
    assert!(
        !pid_is_alive(child_pid),
        "the supervised child (pid {child_pid}) must be killed AND reaped by the \
         orderly teardown — a live/zombie child here is the orphan bug this fix closes"
    );
    Ok(())
}

/// Regression control: `spawn()` (the embedder path) must NEVER install a
/// process-wide SIGTERM handler. The test process plays the embedding host:
/// it installs its OWN handler (without one, the default disposition would
/// terminate the whole test on the self-SIGTERM below), delivers SIGTERM to
/// its own PID, and asserts (a) the host handler saw it, (b) the in-process
/// watch loop is UNAFFECTED — still running — and (c) only an explicit
/// `WatchHandle::stop()` shuts it down. Against an unconditional-install
/// build, the watch loop tears itself down on the signal and assertion (b)
/// fails.
#[cfg(unix)]
#[test]
fn spawn_never_installs_a_sigterm_forwarder() -> Result<(), BoxError> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let host_sigterm = Arc::new(AtomicBool::new(false));

    // The host's own SIGTERM handling — what `spawn()` must leave untouched.
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&host_sigterm))
        .map_err(|e| -> BoxError { format!("host handler registration: {e}").into() })?;

    let (ipe_dir, out_dir) = fresh_dirs("spawn_no_forwarder")?;
    // Red-build source: parses (so setup succeeds) but never compiles green,
    // so no cargo build ever starts — the loop just stays alive.
    std::fs::write(ipe_dir.join("Main.ipe"), RED_BUILD_SOURCE)
        .map_err(|e| -> BoxError { format!("write Main.ipe: {e}").into() })?;
    let runtime_dir = e2e_support::require_runtime().into_path_buf();
    let opts = ipe::watch::WatchOptions::new(ipe_dir.join("Main.ipe"), out_dir, runtime_dir);
    let (join, handle) = ipe::watch::spawn(opts)
        .map_err(|e| -> BoxError { format!("spawn the watch session: {e}").into() })?;

    // Let the orchestrator finish setup and enter its event loop.
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !join.is_finished(),
        "sanity: the watch loop must be running"
    );

    let status = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(std::process::id().to_string())
        .status()
        .map_err(|e| -> BoxError { format!("kill(1) must spawn: {e}").into() })?;
    assert!(status.success(), "kill -TERM must deliver");

    // The host's handler must observe the signal…
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && !host_sigterm.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        host_sigterm.load(Ordering::Relaxed),
        "the HOST's own SIGTERM handler must fire — spawn() must not have \
         swallowed or replaced the host's signal handling"
    );

    // …and the watch loop must be completely unaffected by it.
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        !join.is_finished(),
        "spawn() must NOT install a SIGTERM forwarder: the watch loop shut \
         itself down on a signal that belongs to the embedding host"
    );

    // Only the explicit stop channel shuts it down.
    handle.stop();
    join.join().map_or_else(
        |_| Err("watch thread panicked".into()),
        |result| result.map_err(|e| -> BoxError { e.to_string().into() }),
    )
}

/// A SECOND SIGTERM sent once the first was answered (the teardown marker
/// printed) ends the process: either the signal ends it, or the teardown it
/// raced had already exited cleanly. Neither path waits on a hung teardown,
/// and the supervised child is gone in both. The deterministic proof that a
/// second request ends the process while the teardown hangs is the
/// termination owner's own unit test.
#[cfg(target_os = "linux")]
#[test]
fn double_sigterm_during_teardown_ends_the_process_and_every_transfer_group() -> Result<(), BoxError>
{
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }

    // Pre-warm the shared cargo target so the watch's own build pays only a
    // link step. Best-effort: if warm-up fails or times out the test still
    // runs; it just takes longer.
    let _ = try_warm(DEP_WARM_BUDGET);

    let (ipe_dir, out_dir) = fresh_dirs("double_term")?;
    std::fs::write(ipe_dir.join("Main.ipe"), server_fixture("v1"))
        .map_err(|e| -> BoxError { format!("write Main.ipe: {e}").into() })?;

    let port = 19158;
    let mut ipe_proc = spawn_ipe_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, true)?;

    if !wait_for_body(port, "v1", WATCH_SERVE_BUDGET) {
        let _ = ipe_proc.kill();
        let _ = ipe_proc.wait();
        return Err("initial cold build+spawn must serve v1 within budget".into());
    }
    let child_pid = wait_for_child_of(ipe_proc.id(), Duration::from_secs(10))
        .ok_or("the supervised child must be discoverable via /proc once v1 is serving")?;

    // Watch the child's stderr for the subscriber's teardown ack BEFORE sending
    // any signal, so the reader thread is already draining when the marker is
    // printed.
    let marker_rx = watch_marker_seen(&mut ipe_proc, ipe::watch::SIGTERM_TEARDOWN_MARKER)?;

    // First SIGTERM: starts the orderly teardown.
    sigterm(ipe_proc.id())?;

    // Barrier — NOT a sleep: block until the first SIGTERM was provably
    // answered (the subscriber printed the teardown marker just before sending
    // the `Shutdown` event), so the next SIGTERM is a second request.
    let acked = marker_rx
        .recv_timeout(Duration::from_secs(30))
        .map_err(|_| -> BoxError {
            "the subscriber must announce it answered the first SIGTERM (teardown marker)".into()
        })?;
    if !acked {
        let _ = ipe_proc.kill();
        let _ = ipe_proc.wait();
        return Err(
            "child stderr closed before the SIGTERM teardown marker — the subscriber never \
             reported answering the first signal"
                .into(),
        );
    }

    // The second request. A send to an already-exited pid fails: that is the
    // clean-teardown ordering, so the send's result is not the outcome.
    let _ = sigterm(ipe_proc.id());

    let status = wait_for_exit(&mut ipe_proc, Duration::from_secs(30));
    let Some(status) = status else {
        let _ = ipe_proc.kill();
        let _ = ipe_proc.wait();
        return Err("a second SIGTERM must end ipe, never leave it waiting on its teardown".into());
    };
    assert!(
        std::os::unix::process::ExitStatusExt::signal(&status)
            == Some(signal_hook::consts::SIGTERM)
            || status.success(),
        "a second SIGTERM must end the process by the signal (or find it already \
         exited cleanly), got {status}"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while pid_is_alive(child_pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !pid_is_alive(child_pid),
        "the supervised child (pid {child_pid}) must not outlive ipe"
    );
    Ok(())
}

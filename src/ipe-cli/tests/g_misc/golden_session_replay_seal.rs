//! Seal — `ipe dev run --record` / `--replay` for a `Cli.tea` app, end to end.
//!
//! Builds the `console_app_seal` fixture with the debugger compiled in (its
//! `Msg` and `Model` both encode, so it gets the `Full` session codec and the
//! serde derives the typed log needs), then drives the binary the way
//! `ipe dev run` does, through the runtime's own env wire names:
//!
//! * a recording run writes the plain trace AND the typed log beside it;
//! * a replay run prints `start` + one line per step + `final`, control bytes
//!   stripped, byte-identically on every run;
//! * a log from a changed program (a different `Msg` schema tag) and a
//!   truncated log are each refused, exit non-zero, with nothing printed.
//!
//! Gated on `IPE_E2E=1`:
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test g_misc golden_session_replay_seal
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Run `exe` with one session env var set and `stdin` piped, returning
/// `(exit code, stdout)`.
fn run_with(exe: &str, var: &str, value: &Path, stdin: &[u8]) -> Option<(Option<i32>, String)> {
    use std::io::Write as _;
    let mut child = Command::new(exe)
        .env(var, value)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let Some(mut pipe) = child.stdin.take() {
        // A replay never reads stdin, so the child may exit before the write.
        match pipe.write_all(stdin) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(_) => return None,
        }
    }
    let output = child.wait_with_output().ok()?;
    Some((
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    ))
}

#[test]
fn record_then_replay_is_deterministic_and_refuses_bad_logs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("console_app_seal")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_session_replay_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let options = ipe::BuildOptions {
        debugger: true,
        ..ipe::BuildOptions::from_env()
    };
    let built = ipe::build_with_options(&entry, &out, &runtime, options);
    assert!(
        built.is_ok(),
        "ipe dev build --debugger must succeed: {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs")).unwrap_or_default();
    assert!(
        emitted.contains("ipe_runtime::debugger::session_log::Full::new("),
        "a debugger build of an encodable Cli app must pass the Full codec; got:\n{emitted}"
    );

    // THE SEAL: the codec argument and the serde derives cargo-build.
    let exe = e2e_support::build_rust_binary("session_replay_seal", &out);
    assert!(
        exe.is_ok(),
        "{}",
        exe.as_ref().err().map_or("", String::as_str)
    );
    let exe = exe.expect("`exe` must succeed");

    let logs =
        crate::support::scratch_root().join(format!("ipe_session_replay_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&logs);
    assert!(std::fs::create_dir_all(&logs).is_ok(), "make log dir");
    let trace = logs.join("session.ipelog");
    let typed = logs.join("session.ipemsgs");

    let recorded = run_with(
        &exe,
        ipe_runtime_rust::RECORD_ENV,
        &trace,
        b"one\ntwo\n\x1b[2Jthree\n",
    );
    assert!(
        matches!(recorded, Some((Some(0), _))),
        "the recording run must exit 0: {recorded:?}"
    );
    assert!(trace.is_file(), "the plain trace must be written");
    assert!(typed.is_file(), "the typed log must be written beside it");

    let first = run_with(&exe, ipe_runtime_rust::REPLAY_ENV, &typed, b"ignored\n");
    let second = run_with(&exe, ipe_runtime_rust::REPLAY_ENV, &typed, b"");
    assert!(
        matches!(first, Some((Some(0), _))),
        "a replay must exit 0: {first:?}"
    );
    assert_eq!(first, second, "replaying twice must be byte-identical");
    let (_, stdout) = first.expect("`first` must be present");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 5, "start + 3 steps + final: {stdout:?}");
    assert!(
        lines
            .first()
            .is_some_and(|l| l.starts_with("start (init): ")),
        "{stdout:?}"
    );
    assert!(
        lines
            .last()
            .is_some_and(|l| l.starts_with("final: ") && l.contains('3')),
        "{stdout:?}"
    );
    assert!(
        !stdout.chars().any(|c| c.is_control() && c != '\n'),
        "replay output must carry no control byte: {stdout:?}"
    );

    assert_bad_logs_are_refused(&exe, &logs, &typed);

    let _ = std::fs::remove_dir_all(&logs);
}

/// A log from a changed program or a truncated log is refused, printing nothing.
fn assert_bad_logs_are_refused(exe: &str, logs: &Path, typed: &Path) {
    // A changed program: the log's Msg tag no longer matches.
    let text = std::fs::read_to_string(typed).unwrap_or_default();
    assert!(
        !text.chars().any(char::is_control),
        "the typed log on disk must carry no raw control character: {text:?}"
    );
    let tampered = text.replacen("\"msg_tag\":\"", "\"msg_tag\":\"ff", 1);
    let changed = logs.join("changed.ipemsgs");
    assert!(
        std::fs::write(&changed, tampered).is_ok(),
        "write changed log"
    );
    let refused = run_with(exe, ipe_runtime_rust::REPLAY_ENV, &changed, b"");
    assert!(
        matches!(&refused, Some((Some(code), out)) if *code != 0 && out.is_empty()),
        "a log from a changed program must be refused with nothing printed: {refused:?}"
    );

    // A truncated log.
    let cut = logs.join("cut.ipemsgs");
    let half = text.get(..text.len() / 2).unwrap_or_default();
    assert!(std::fs::write(&cut, half).is_ok(), "write truncated log");
    let refused = run_with(exe, ipe_runtime_rust::REPLAY_ENV, &cut, b"");
    assert!(
        matches!(&refused, Some((Some(code), out)) if *code != 0 && out.is_empty()),
        "a truncated log must be refused with nothing printed: {refused:?}"
    );
}

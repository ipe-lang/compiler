//! Seal — a recorded `Cli.tea` session is dumped however the process ends.
//!
//! Builds the `console_app_exit_record` fixture with the debugger compiled in,
//! then ends a recording run two ways, each from inside `update`:
//!
//! * `quit` calls `System.exit 0`: the run exits 0, the trace holds the
//!   `hello` step, the typed log replays byte-identically twice, and stdout
//!   carries the piped frames with nothing after them;
//! * `boom` calls `Debug.todo`: the run exits non-zero and the same trace is
//!   still written.
//!
//! Gated on `IPE_E2E=1`:
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test g_misc golden_session_record_on_exit
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The piped frames of a run that echoes `hello` and then exits.
const EXPECTED_STDOUT: &str = "echoed 0 [] > \nechoed 1 [hello] > \n";

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Run `exe` with one session env var set and `stdin` piped, returning
/// `(exit code, stdout bytes)`.
fn run_with(exe: &Path, var: &str, value: &Path, stdin: &[u8]) -> Option<(Option<i32>, Vec<u8>)> {
    use std::io::Write as _;
    let mut child = Command::new(exe)
        .env(var, value)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let Some(mut pipe) = child.stdin.take() {
        pipe.write_all(stdin).ok()?;
    }
    let output = child.wait_with_output().ok()?;
    Some((output.status.code(), output.stdout))
}

/// The trace's lines, or none when no trace was written.
fn trace_lines(trace: &Path) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(trace).ok()?;
    Some(text.lines().map(str::to_owned).collect())
}

#[test]
fn a_session_is_recorded_through_system_exit_and_debug_todo() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = root
        .join("tests")
        .join("golden")
        .join("console_app_exit_record");
    let out = crate::support::scratch_root().join("ipec_session_record_on_exit_e2e");
    e2e_support::scratch::fresh(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let options = ipe::BuildOptions {
        debugger: true,
        intent: ipe_backend_rust::BuildIntent::Development,
        ..ipe::BuildOptions::from_env().expect("BuildOptions from env")
    };
    let built = ipe::build_golden_dir(&dir, &out, &runtime, &options);
    assert!(
        built.is_ok(),
        "ipe dev build --debugger must succeed: {:?}",
        built.err()
    );
    let exe = e2e_support::build_rust_binary("session_record_on_exit", &out);
    assert!(
        exe.is_ok(),
        "{}",
        exe.as_ref().err().map_or("", String::as_str)
    );
    let exe = exe.expect("`exe` must succeed");

    let logs = crate::support::scratch_root()
        .join(format!("ipe_session_record_on_exit_{}", std::process::id()));
    e2e_support::scratch::fresh(&logs);
    assert!(std::fs::create_dir_all(&logs).is_ok(), "make log dir");

    let trace = logs.join("quit.ipelog");
    let typed = logs.join("quit.ipemsgs");
    let quit = run_with(&exe, ipe_runtime_rust::RECORD_ENV, &trace, b"hello\nquit\n");
    assert!(quit.is_some(), "the recording run did not start");
    let (code, stdout) = quit.expect("the recording run must start");
    assert_eq!(code, Some(0), "a `System.exit 0` run exits 0");
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        EXPECTED_STDOUT,
        "the exit adds no stdout byte after the last frame"
    );
    let quit_trace = trace_lines(&trace);
    assert!(
        quit_trace.as_ref().is_some_and(
            |lines| lines.len() == 1 && lines.first().is_some_and(|l| l.contains("hello"))
        ),
        "the trace of a `System.exit` run holds the `hello` step: {quit_trace:?}"
    );
    assert!(typed.is_file(), "the typed log is written beside the trace");
    let first = run_with(&exe, ipe_runtime_rust::REPLAY_ENV, &typed, b"");
    let second = run_with(&exe, ipe_runtime_rust::REPLAY_ENV, &typed, b"ignored\n");
    assert!(
        matches!(first, Some((Some(0), _))),
        "a replay of the exit-recorded log exits 0: {first:?}"
    );
    assert_eq!(first, second, "replaying twice must be byte-identical");

    let boom_trace_path = logs.join("boom.ipelog");
    let boom = run_with(
        &exe,
        ipe_runtime_rust::RECORD_ENV,
        &boom_trace_path,
        b"hello\nboom\n",
    );
    assert!(
        boom.as_ref()
            .is_some_and(|(code, _)| code.is_some_and(|c| c != 0)),
        "a `Debug.todo` run exits non-zero: {boom:?}"
    );
    assert_eq!(
        trace_lines(&boom_trace_path),
        quit_trace,
        "a `Debug.todo` run dumps the same trace"
    );

    let _ = std::fs::remove_dir_all(&logs);
}

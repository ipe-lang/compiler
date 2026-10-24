//! `Io.readLine` over a real stdin pipe.
//!
//! Each test re-runs this binary as a child with its stdin piped, so the read
//! goes through the process-wide `StdinLock` the kernel shares between calls:
//! a reader private to one call would drop the bytes it buffered past the
//! first newline, and a second line written in the same pipe write would be
//! lost.
#![cfg(not(target_arch = "wasm32"))]

use std::io::Write;
use std::process::{Command, Stdio};

use ipe_runtime_rust::{IpeError, IpeErrorKind, IpeResult};

/// Names the scenario a child run executes instead of spawning.
const CHILD_SCENARIO: &str = "IPE_STDIN_LINE_READER_CHILD";

/// Starts each report line, so the harness's own output is never read as a report.
const REPORT: &str = "stdin-line-reader-report:";

/// The `Io.readLine` line cap, mirrored from `io.rs`.
const LINE_CAP_BYTES: usize = 1024 * 1024;

/// Reads one line through the public kernel and renders its outcome as one report line.
fn read_one() -> String {
    match ipe_runtime_rust::task::block_on::<IpeError, String>(ipe_runtime_rust::io::io_read_line(
        (),
    )) {
        IpeResult::Ok(line) => format!("line:{line}"),
        IpeResult::Err(IpeError::Error(kind, _)) => format!("refused:{kind:?}"),
    }
}

/// The scenario this process runs as a child, if it is one.
fn child_scenario() -> Option<String> {
    #[expect(
        clippy::disallowed_methods,
        reason = "an integration test has no crate-private env accessor"
    )]
    let scenario = std::env::var(CHILD_SCENARIO).ok();
    scenario
}

/// In a child, reads `reads` lines and prints one report line per read.
#[allow(
    clippy::expect_used,
    reason = "a child that cannot report must fail the test"
)]
fn run_child(reads: usize) {
    let mut out = std::io::stdout().lock();
    for _ in 0..reads {
        // The leading newline ends any harness text left open on the line.
        writeln!(out, "\n{REPORT}{}", read_one()).expect("write the report line");
    }
    out.flush().expect("flush the report");
}

/// Runs `test_name` as a child fed `input` on stdin and returns its report lines.
#[allow(
    clippy::expect_used,
    reason = "a child that cannot be driven must fail the test"
)]
fn spawn_child(test_name: &str, input: &[u8]) -> Vec<String> {
    let exe = std::env::current_exe().expect("the test binary must locate itself");
    let mut child = Command::new(exe)
        .env(CHILD_SCENARIO, test_name)
        .args(["--exact", test_name, "--nocapture"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the test binary must re-spawn itself");
    let mut stdin = child.stdin.take().expect("piped child stdin");
    stdin.write_all(input).expect("feed the child's stdin");
    drop(stdin);
    let output = child.wait_with_output().expect("wait for the child");
    assert!(output.status.success(), "the child run failed: {output:?}");
    String::from_utf8(output.stdout)
        .expect("the child's report is UTF-8")
        .lines()
        .filter_map(|line| line.strip_prefix(REPORT))
        .map(str::to_owned)
        .collect()
}

/// Two lines delivered in one pipe write are both read, then end of input.
#[test]
fn two_piped_lines_are_both_read() {
    const NAME: &str = "two_piped_lines_are_both_read";
    if child_scenario().as_deref() == Some(NAME) {
        run_child(3);
        return;
    }
    assert_eq!(
        spawn_child(NAME, b"a\nb\n"),
        ["line:a", "line:b", "line:"],
        "a second line written with the first must not be dropped"
    );
}

/// A piped line one byte past the cap is refused whole, and the next line is the next answer.
#[test]
fn piped_overlong_line_is_refused_and_the_next_answer_is_intact() {
    const NAME: &str = "piped_overlong_line_is_refused_and_the_next_answer_is_intact";
    if child_scenario().as_deref() == Some(NAME) {
        run_child(2);
        return;
    }
    let mut input = vec![b'y'; LINE_CAP_BYTES + 1];
    input.extend_from_slice(b"\nn\n");
    let refused = format!("refused:{:?}", IpeErrorKind::LimitExceeded);
    assert_eq!(
        spawn_child(NAME, &input),
        [refused.as_str(), "line:n"],
        "the over-long line's tail must never be read as the next answer"
    );
}

#![forbid(unsafe_code)]
//! A command-line argument that is not valid UTF-8 is refused by position.
//!
//! The `ipe` binary decodes its arguments through `ipe_docs::argv::host_args`:
//! the run exits non-zero with a usage refusal naming the argument's position,
//! never a panic, and the argument's bytes never reach the terminal.

#![cfg(unix)]

mod support;

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::process::{Command, Stdio};
use std::time::Duration;

/// An argument with an invalid UTF-8 byte and an escape sequence.
fn hostile_argument() -> OsString {
    OsString::from_vec(vec![
        b'M', 0xff, 0x1b, b'[', b'3', b'1', b'm', b'.', b'i', b'p', b'e',
    ])
}

/// Run `ipe` with `args`, bounded, returning its exit code and stderr.
fn run_ipe(args: &[OsString]) -> std::io::Result<(Option<i32>, Vec<u8>)> {
    let mut child = Command::new(support::ipe_bin())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let exited = e2e_support::wait_for(Duration::from_secs(120), || {
        matches!(child.try_wait(), Ok(Some(_)) | Err(_))
    });
    if !exited {
        child.kill()?;
    }
    let out = child.wait_with_output()?;
    assert!(exited, "ipe did not exit on a non-UTF-8 argument");
    Ok((out.status.code(), out.stderr))
}

/// Assert the run refused the argument at `position` without a panic or echo.
fn assert_refused_at(args: &[OsString], position: usize) -> std::io::Result<()> {
    let (code, stderr) = run_ipe(args)?;
    let text = String::from_utf8_lossy(&stderr);
    assert_eq!(code, Some(1), "a non-UTF-8 argument must exit 1: {text}");
    assert!(
        !text.contains("panicked"),
        "a non-UTF-8 argument panicked: {text}"
    );
    assert!(
        text.contains(&format!("argument {position} is not valid UTF-8")),
        "the refusal must name argument {position}: {text}"
    );
    assert!(
        !stderr.contains(&0xff) && !text.contains("31m.ipe") && !text.contains('\u{fffd}'),
        "the refusal echoed the argument's bytes: {text}"
    );
    Ok(())
}

#[test]
fn a_non_utf8_command_is_refused_by_position() -> std::io::Result<()> {
    assert_refused_at(&[hostile_argument()], 1)
}

#[test]
fn a_non_utf8_file_argument_is_refused_by_position() -> std::io::Result<()> {
    assert_refused_at(&[OsString::from("check"), hostile_argument()], 2)
}

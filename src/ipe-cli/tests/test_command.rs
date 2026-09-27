//! `ipe test` — build and run the project's `tests/Main.ipe`.
//!
//! `ipe test` shares its runner with `ipe verify`'s test stage, so these tests
//! assert the command's own contract: human-friendly output (a settled progress
//! line plus the runner's `N passed, M failed` summary) and a machine-readable
//! exit code (0 when every case passes or there is nothing to run, non-zero when
//! a case fails). The building cases invoke `cargo` and need the Ipê runtime, so
//! they are gated on `IPE_E2E=1` to keep the default `cargo nextest` fast and
//! offline; the offline cases (usage, no-test-entry) always run.

use std::error::Error;
use std::path::PathBuf;
use std::process::Command;

mod support;

type TestResult = Result<(), Box<dyn Error>>;

/// Absolute path to a fixture under this crate's `tests/fixtures/verify` (shared
/// with the `verify` tests — the same test suites drive both commands).
fn fixture(name: &str) -> PathBuf {
    support::manifest_dir()
        .join("tests/fixtures/verify")
        .join(name)
}

/// Run the built `ipe` binary and capture `(success, stdout, stderr)`.
fn run_ipe(args: &[&str]) -> Result<(bool, String, String), Box<dyn Error>> {
    let out = Command::new(support::ipe_bin()).args(args).output()?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// An unexpected flag is a misuse: `ipe test` names the bad option and shows its
/// own help page, exiting non-zero — never running a build. This is offline.
#[test]
fn unexpected_flag_is_misuse_and_shows_help() -> TestResult {
    let (ok, _stdout, stderr) = run_ipe(&["test", "--bogus"])?;
    assert!(!ok, "an unexpected flag must exit non-zero");
    assert!(
        stderr.contains("--bogus") && stderr.contains("ipe test [<path>]"),
        "the misuse must name the flag and show the test help page, got stderr:\n{stderr}"
    );
    Ok(())
}

/// A project with no `tests/Main.ipe` is not an error: `ipe test` reports there
/// is nothing to run and exits 0, without invoking `cargo`. This is offline —
/// the runner short-circuits before any build.
#[test]
fn a_project_with_no_test_entry_reports_nothing_to_run_and_exits_zero() -> TestResult {
    let dir = crate::support::scratch_root().join(format!("ipe_test_none_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::copy(fixture("clean.ipe"), dir.join("Main.ipe"))?;

    let (ok, stdout, stderr) = run_ipe(&["test", &dir.join("Main.ipe").to_string_lossy()])?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        ok,
        "a project with no test entry must exit 0, got stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("no tests to run"),
        "the command must report there is nothing to run, got stdout:\n{stdout}"
    );
    Ok(())
}

/// A project whose every test passes: `ipe test` prints the runner's summary
/// (`1 passed, 0 failed`) and exits 0. Gated on `IPE_E2E=1` — it builds and runs
/// the emitted test binary, needing `cargo` and the runtime.
#[test]
fn a_project_with_passing_tests_exits_zero_with_a_summary() -> TestResult {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping: set IPE_E2E=1 to run the passing-test E2E");
        return Ok(());
    }
    let dir = crate::support::scratch_root().join(format!("ipe_test_pass_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tests"))?;
    std::fs::copy(fixture("clean.ipe"), dir.join("Main.ipe"))?;
    std::fs::copy(
        fixture("tests_pass.ipe"),
        dir.join("tests").join("Main.ipe"),
    )?;

    let (ok, stdout, stderr) = run_ipe(&["test", &dir.join("Main.ipe").to_string_lossy()])?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        ok,
        "a project with all-passing tests must exit 0, got stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("passed") && stdout.contains("all tests passed"),
        "the summary and the settled outcome must appear, got stdout:\n{stdout}"
    );
    Ok(())
}

/// A project with a failing test: `ipe test` names the failing case and its
/// reason, prints a summary counting the failure, and exits non-zero. Gated on
/// `IPE_E2E=1` — it builds and runs the emitted test binary.
#[test]
fn a_project_with_a_failing_test_names_it_and_exits_non_zero() -> TestResult {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping: set IPE_E2E=1 to run the failing-test E2E");
        return Ok(());
    }
    let dir = crate::support::scratch_root().join(format!("ipe_test_fail_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tests"))?;
    std::fs::copy(fixture("clean.ipe"), dir.join("Main.ipe"))?;
    std::fs::copy(
        fixture("tests_fail.ipe"),
        dir.join("tests").join("Main.ipe"),
    )?;

    let (ok, stdout, stderr) = run_ipe(&["test", &dir.join("Main.ipe").to_string_lossy()])?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !ok,
        "a project with a failing test must exit non-zero, got stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("failed"),
        "the failure must be counted in the summary, got stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("one or more tests failed"),
        "the non-zero verdict must be reported, got stderr:\n{stderr}"
    );
    Ok(())
}

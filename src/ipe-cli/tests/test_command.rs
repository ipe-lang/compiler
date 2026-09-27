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

/// A test entry that links the database stdlib and holds a `case` over `Result`.
///
/// `Ipe.Db.Store` pulls in `Ipe.Db.Codec`; `catch_all_arm` is the pattern of the
/// arm that follows `Err _`.
fn db_test_entry(catch_all_arm: &str) -> String {
    format!(
        "module Main exposing (main)

import Ipe.Db.Dsn as Dsn exposing (Connection, ReadOnly)
import Ipe.Db.Store as Store exposing (Store)
import Ipe.Error exposing (Error)
import Ipe.Result as Result exposing (Result(..))
import Ipe.Test as Test exposing (Test)


readAll : Connection ReadOnly -> Store Store.Row -> Task Error (List Store.Row)
readAll conn store =
    Store.allOn conn store


isOk : Result String Int -> Bool
isOk result =
    case result of
        Err _ ->
            False

        {catch_all_arm} ->
            True


tests : List Test
tests =
    [ Test.test \"isOk\" (\\_ -> Test.equal True (isOk (Ok 1))) ]


main =
    Test.runMain tests
"
    )
}

/// Lay out a project whose `tests/Main.ipe` is `test_entry`, returning its root.
fn write_db_test_project(name: &str, test_entry: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = crate::support::scratch_root().join(format!("{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tests"))?;
    std::fs::copy(fixture("clean.ipe"), dir.join("Main.ipe"))?;
    std::fs::write(dir.join("tests").join("Main.ipe"), test_entry)?;
    Ok(dir)
}

/// A closed-union catch-all in the test entry is refused with IPE-T0018 at its own arm.
///
/// The refusal is framed against the test file at the `_` arm itself — never
/// against an embedded stdlib module whose byte offsets overlap it. Offline: the
/// refusal happens at type-check, before any `cargo` build.
#[test]
fn a_catch_all_in_the_test_entry_is_refused_at_its_own_arm() -> TestResult {
    let entry = db_test_entry("_");
    let Some(arm_line) = entry
        .lines()
        .position(|l| l.trim_start().starts_with("_ ->"))
        .map(|i| i + 1)
    else {
        return Err("the test entry must contain a `_ ->` arm".into());
    };
    let dir = write_db_test_project("ipe_test_catch_all", &entry)?;

    let (ok, stdout, stderr) = run_ipe(&["test", &dir.join("Main.ipe").to_string_lossy()])?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !ok,
        "a closed-union catch-all in the test entry must be refused, got stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("IPE-T0018"),
        "the refusal must be IPE-T0018, got stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("<embedded-stdlib>"),
        "the refusal must not be framed against the embedded stdlib, got stderr:\n{stderr}"
    );
    let location = format!("Main.ipe:{arm_line}:9");
    assert!(
        stderr.contains(&location),
        "the refusal must point at the `_` arm ({location}), got stderr:\n{stderr}"
    );
    Ok(())
}

/// The same entry with an explicit `Ok _` arm passes `ipe test`.
///
/// Linking the database stdlib raises no lint of its own. Gated on `IPE_E2E=1`
/// — it builds and runs the emitted test binary.
#[test]
fn a_test_entry_importing_the_database_stdlib_passes() -> TestResult {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping: set IPE_E2E=1 to run the database-stdlib test E2E");
        return Ok(());
    }
    let dir = write_db_test_project("ipe_test_db_clean", &db_test_entry("Ok _"))?;

    let (ok, stdout, stderr) = run_ipe(&["test", &dir.join("Main.ipe").to_string_lossy()])?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        ok,
        "a test entry importing the database stdlib must pass, got stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("all tests passed"),
        "the settled outcome must appear, got stdout:\n{stdout}"
    );
    Ok(())
}

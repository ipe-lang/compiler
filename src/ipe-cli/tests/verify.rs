//! `ipe verify` — the one-command project gate.
//!
//! Runs the project's checks in order — format, type-check, build, test —
//! stopping at the first failure. Each stage composes the same code path its
//! standalone command uses, so these tests assert the *composition and
//! reporting*: an unformatted project stops at the format stage, a
//! type-erroring but well-formatted project passes format then stops at the
//! type-check stage, and a clean project clears every stage (the full pass,
//! which builds and runs tests, is gated on `IPE_E2E=1` so the default
//! `cargo nextest` stays fast and offline).

use std::error::Error;
use std::path::PathBuf;
use std::process::Command;

mod support;

type TestResult = Result<(), Box<dyn Error>>;

/// Absolute path to a fixture under this crate's `tests/fixtures/verify`.
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

/// An unformatted project stops at the very first stage: `verify` reports the
/// format failure and exits non-zero, and never reaches the type-check stage.
#[test]
fn unformatted_project_stops_at_the_format_stage() -> TestResult {
    let (ok, stdout, stderr) = run_ipe(&["verify", &fixture("unformatted.ipe").to_string_lossy()])?;
    assert!(!ok, "an unformatted project must exit non-zero");
    assert!(
        stdout.contains("format failed"),
        "the format stage must be reported as failed, got stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("the format stage failed") && stderr.contains("not formatted"),
        "the format stage's own report must be shown, got stderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("type-check"),
        "verify must stop before the type-check stage, got stdout:\n{stdout}"
    );
    Ok(())
}

/// A well-formatted but type-erroring project passes the format stage, then
/// stops at the type-check stage, exiting non-zero with the type diagnostic —
/// and never reaches the build stage.
#[test]
fn type_error_project_stops_at_the_type_check_stage() -> TestResult {
    let (ok, stdout, stderr) = run_ipe(&["verify", &fixture("type_error.ipe").to_string_lossy()])?;
    assert!(!ok, "a type-erroring project must exit non-zero");
    assert!(
        stdout.contains("format passed") && stdout.contains("type-check failed"),
        "format must pass and type-check must fail, got stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("the type-check stage failed")
            && stderr.contains("IPE-T0001")
            && stderr.contains("TYPE MISMATCH"),
        "the type diagnostic must be shown, got stderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("stage 3/4"),
        "verify must stop before the build stage, got stdout:\n{stdout}"
    );
    Ok(())
}

/// A stage failure is a gate result, not a misuse of `verify`: the failing
/// stage's report is shown alone, never the `verify --help` page a raw usage
/// error would trigger.
#[test]
fn stage_failure_does_not_print_the_verify_help_page() -> TestResult {
    let (_, _, stderr) = run_ipe(&["verify", &fixture("unformatted.ipe").to_string_lossy()])?;
    assert!(
        !stderr.contains("ipe verify [<path>]"),
        "a stage failure must not print the verify help synopsis, got stderr:\n{stderr}"
    );
    Ok(())
}

/// An unknown flag IS a misuse of `verify`: it exits non-zero and shows the
/// `verify` help page (the uniform "misuse shows help" behaviour).
#[test]
fn unknown_flag_is_misuse_and_shows_help() {
    let args: Vec<String> = vec!["verify".to_owned(), "--bogus".to_owned()];
    let result = ipe::run_cli(&args);
    assert!(
        matches!(
            &result,
            Err(ipe::CliError::CommandUsage { command, reason })
                if *command == "verify" && reason.as_str().contains("--bogus")
        ),
        "expected a `verify` command-usage error naming the offending flag, got: {result:?}"
    );
}

/// A clean project with no `tests/Main.ipe` clears every stage and exits 0.
/// Gated on `IPE_E2E=1` because the build stage invokes `cargo` and needs the
/// Ipê runtime — kept out of the default fast, offline test run.
#[test]
fn clean_project_passes_every_stage() -> TestResult {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping: set IPE_E2E=1 to run the building verify E2E");
        return Ok(());
    }
    // Copy the clean entry into a fresh directory named `Main.ipe` so the build
    // stage's default entry conventions apply cleanly.
    let dir =
        crate::support::scratch_root().join(format!("ipe_verify_clean_{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let src = dir.join("Main.ipe");
    std::fs::copy(fixture("clean.ipe"), &src)?;

    let (ok, stdout, stderr) = run_ipe(&["verify", &src.to_string_lossy()])?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        ok,
        "a clean project must pass every stage, got stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("format passed")
            && stdout.contains("type-check passed")
            && stdout.contains("build passed")
            && stdout.contains("test passed")
            && stdout.contains("all 4 stages passed"),
        "every stage must be reported as passed, got stdout:\n{stdout}"
    );
    Ok(())
}

/// A project with a passing `tests/Main.ipe` test suite clears the test stage.
/// Gated on `IPE_E2E=1` — the test stage invokes `cargo` and needs the runtime.
#[test]
fn project_with_passing_tests_clears_the_test_stage() -> TestResult {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping: set IPE_E2E=1 to run the test-stage E2E");
        return Ok(());
    }
    // Set up a project dir with Main.ipe + tests/Main.ipe (all tests pass).
    let dir = crate::support::scratch_root()
        .join(format!("ipe_verify_tests_pass_{}", std::process::id()));
    std::fs::create_dir_all(dir.join("tests"))?;
    std::fs::copy(fixture("clean.ipe"), dir.join("Main.ipe"))?;
    std::fs::copy(
        fixture("tests_pass.ipe"),
        dir.join("tests").join("Main.ipe"),
    )?;

    let (ok, stdout, stderr) = run_ipe(&["verify", &dir.join("Main.ipe").to_string_lossy()])?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        ok,
        "a project with all-passing tests must exit 0, got stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("test passed"),
        "the test stage must be reported as passed, got stdout:\n{stdout}"
    );
    Ok(())
}

/// A `tests/Main.ipe` that imports a module living under `src/Lib/` resolves
/// the code under test: the test stage roots discovery at the project's `src/`
/// tree, not the `tests/` directory, so the standard `src/` + `tests/` layout
/// compiles and runs its tests without an IPE-N0020 module-resolution error.
/// Gated on `IPE_E2E=1` — the test stage invokes `cargo` and needs the runtime.
#[test]
fn test_stage_resolves_src_modules_from_a_sibling_tests_dir() -> TestResult {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping: set IPE_E2E=1 to run the cross-directory test-stage E2E");
        return Ok(());
    }
    let dir =
        crate::support::scratch_root().join(format!("ipe_verify_src_tests_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src").join("Lib"))?;
    std::fs::create_dir_all(dir.join("tests"))?;

    // Code under test: src/Lib/Foo.ipe.
    std::fs::write(
        dir.join("src").join("Lib").join("Foo.ipe"),
        "module Lib.Foo exposing (answer)\n\n\nanswer =\n    42\n",
    )?;
    // The project entry uses the library too, so the build stage is realistic.
    std::fs::write(
        dir.join("src").join("Main.ipe"),
        "module Main exposing (main)\n\nimport Ipe.Io as Io\nimport Ipe.String as String\nimport Lib.Foo as Foo\n\n\nmain =\n    Io.println (String.fromInt Foo.answer)\n",
    )?;
    // The test entry, in the sibling tests/ directory, imports the src/ module.
    std::fs::write(
        dir.join("tests").join("Main.ipe"),
        "module Main exposing (main)\n\nimport Ipe.Test as Test exposing (Test)\nimport Lib.Foo as Foo\n\n\ntests : List Test\ntests =\n    [ Test.test \"library answer\" (\\_ -> Test.equal 42 Foo.answer)\n    ]\n\n\nmain =\n    Test.runMain tests\n",
    )?;

    let (ok, stdout, stderr) = run_ipe(&[
        "verify",
        &dir.join("src").join("Main.ipe").to_string_lossy(),
    ])?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !stderr.contains("IPE-N0020"),
        "the test stage must resolve src/Lib/Foo.ipe (no IPE-N0020), got stderr:\n{stderr}"
    );
    assert!(
        ok,
        "a src/+tests/ project whose test imports the code under test must exit 0, got stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("build passed") && stdout.contains("test passed"),
        "build and test stages must pass, got stdout:\n{stdout}"
    );
    Ok(())
}

/// A project with a failing `tests/Main.ipe` test suite fails the test stage
/// and exits non-zero, after the build stage has already passed.
/// Gated on `IPE_E2E=1` — the test stage invokes `cargo` and needs the runtime.
#[test]
fn project_with_failing_tests_fails_the_test_stage() -> TestResult {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping: set IPE_E2E=1 to run the test-stage E2E");
        return Ok(());
    }
    let dir = crate::support::scratch_root()
        .join(format!("ipe_verify_tests_fail_{}", std::process::id()));
    std::fs::create_dir_all(dir.join("tests"))?;
    std::fs::copy(fixture("clean.ipe"), dir.join("Main.ipe"))?;
    std::fs::copy(
        fixture("tests_fail.ipe"),
        dir.join("tests").join("Main.ipe"),
    )?;

    let (ok, stdout, stderr) = run_ipe(&["verify", &dir.join("Main.ipe").to_string_lossy()])?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !ok,
        "a project with failing tests must exit non-zero, got stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("build passed") && stdout.contains("test failed"),
        "build must pass and test must fail, got stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("the test stage failed"),
        "the test stage's failure must be reported, got stderr:\n{stderr}"
    );
    Ok(())
}

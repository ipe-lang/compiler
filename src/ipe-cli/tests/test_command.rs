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
use std::path::{Path, PathBuf};
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

/// The manifest of every project these tests lay out.
const PACKAGE_IPE: &str = "module Package exposing (package)\n\nimport Ipe.Package exposing (..)\n\n\n\
                           package : Package\npackage =\n    { name = \"testproj\" }\n";

/// Lay out the project `dir`: its `package.ipe` and the clean `src/Main.ipe`.
fn write_project(dir: &Path) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(dir.join("src"))?;
    std::fs::write(dir.join("package.ipe"), PACKAGE_IPE)?;
    std::fs::copy(fixture("clean.ipe"), dir.join("src").join("Main.ipe"))?;
    Ok(())
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
    write_project(&dir)?;

    let (ok, stdout, stderr) = run_ipe(&["test", &dir.to_string_lossy()])?;
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

/// A directory with no `package.ipe` is no project to test: `ipe test` refuses
/// it naming the directory, even with a `tests/Main.ipe` beside a loose entry,
/// and never searches a parent directory. This is offline — the refusal comes
/// before any build.
#[test]
fn a_directory_without_a_manifest_is_refused() -> TestResult {
    let dir =
        crate::support::scratch_root().join(format!("ipe_test_no_manifest_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    write_project(&dir)?;
    std::fs::create_dir_all(dir.join("loose").join("tests"))?;
    std::fs::copy(fixture("clean.ipe"), dir.join("loose").join("Main.ipe"))?;
    std::fs::copy(
        fixture("tests_pass.ipe"),
        dir.join("loose").join("tests").join("Main.ipe"),
    )?;

    let (ok, _stdout, stderr) = run_ipe(&["test", &dir.join("loose").to_string_lossy()])?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!ok, "a directory without a manifest must be refused");
    assert!(
        stderr.contains("IPE-E0004") && stderr.contains("loose"),
        "the refusal must be NoManifest naming the directory, got stderr:\n{stderr}"
    );
    Ok(())
}

/// A project whose every test passes: `ipe test` prints the runner's summary
/// (`1 passed, 0 failed`) and exits 0. Gated on `IPE_E2E=1` — it builds and runs
/// the emitted test binary, needing `cargo` and the runtime.
#[test]
fn a_project_with_passing_tests_exits_zero_with_a_summary() -> TestResult {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping: set IPE_E2E=1 to run the passing-test E2E");
        return Ok(());
    }
    let dir = crate::support::scratch_root().join(format!("ipe_test_pass_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    write_project(&dir)?;
    std::fs::create_dir_all(dir.join("tests"))?;
    std::fs::copy(
        fixture("tests_pass.ipe"),
        dir.join("tests").join("Main.ipe"),
    )?;

    let (ok, stdout, stderr) = run_ipe(&["test", &dir.to_string_lossy()])?;
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
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping: set IPE_E2E=1 to run the failing-test E2E");
        return Ok(());
    }
    let dir = crate::support::scratch_root().join(format!("ipe_test_fail_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    write_project(&dir)?;
    std::fs::create_dir_all(dir.join("tests"))?;
    std::fs::copy(
        fixture("tests_fail.ipe"),
        dir.join("tests").join("Main.ipe"),
    )?;

    let (ok, stdout, stderr) = run_ipe(&["test", &dir.to_string_lossy()])?;
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
    write_project(&dir)?;
    std::fs::create_dir_all(dir.join("tests"))?;
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

    let (ok, stdout, stderr) = run_ipe(&["test", &dir.to_string_lossy()])?;
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
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping: set IPE_E2E=1 to run the database-stdlib test E2E");
        return Ok(());
    }
    let dir = write_db_test_project("ipe_test_db_clean", &db_test_entry("Ok _"))?;

    let (ok, stdout, stderr) = run_ipe(&["test", &dir.to_string_lossy()])?;
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

/// A fresh per-user cache base for one test, under this binary's scratch root.
fn fresh_cache(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let cache = crate::support::scratch_root().join(format!("{name}_cache_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cache);
    std::fs::create_dir_all(&cache)?;
    Ok(cache)
}

/// Lay out a project whose `tests/Main.ipe` is the fixture `tests_fixture`, returning its root.
fn fixture_project(name: &str, tests_fixture: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = crate::support::scratch_root().join(format!("{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    write_project(&dir)?;
    std::fs::create_dir_all(dir.join("tests"))?;
    std::fs::copy(fixture(tests_fixture), dir.join("tests").join("Main.ipe"))?;
    Ok(dir)
}

/// An `ipe test` of `project` with no build-directory pin and `cache` as the per-user cache base.
fn ipe_test_command(project: &Path, cache: &Path) -> Command {
    let mut cmd = Command::new(support::ipe_bin());
    cmd.arg("test")
        .arg(project)
        .env_remove("CARGO_TARGET_DIR")
        .env("XDG_CACHE_HOME", cache);
    cmd
}

/// Run `cmd` to its exit and capture `(success, stdout, stderr)`.
fn run_captured(mut cmd: Command) -> Result<(bool, String, String), Box<dyn Error>> {
    let out = cmd.output()?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// Every shared scratch build directory under `cache`.
fn scratch_targets(cache: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let root = cache.join("ipe").join("t");
    let mut found = Vec::new();
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with("scratch-") {
            found.push(entry.path());
        }
    }
    Ok(found)
}

/// The one shared scratch build directory under `cache`.
fn the_scratch_target(cache: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let mut targets = scratch_targets(cache)?;
    assert_eq!(
        targets.len(),
        1,
        "exactly one shared scratch build directory must exist, got {targets:?}"
    );
    targets
        .pop()
        .ok_or_else(|| "no shared scratch build directory".into())
}

/// The `[lib] name` of the bundled runtime manifest.
fn runtime_lib_name() -> Result<String, Box<dyn Error>> {
    let manifest =
        std::fs::read_to_string(e2e_support::require_runtime_crate().join("Cargo.toml"))?;
    let mut in_lib = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_lib = line == "[lib]";
        } else if in_lib && let Some(value) = line.strip_prefix("name") {
            let name = value
                .trim_start()
                .trim_start_matches('=')
                .trim()
                .trim_matches('"');
            return Ok(name.to_owned());
        }
    }
    Err("the bundled runtime manifest names no `[lib]`".into())
}

/// Every compiled rlib of the library `lib` in `target`'s dev profile.
fn rlibs_of(target: &Path, lib: &str) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let prefix = format!("lib{lib}-");
    let mut found = Vec::new();
    for entry in std::fs::read_dir(target.join("debug").join("deps"))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&prefix) && entry.path().extension().is_some_and(|ext| ext == "rlib") {
            found.push(entry.path());
        }
    }
    found.sort();
    Ok(found)
}

/// Move the modification time of every file under `dir` a day ahead.
///
/// Every build record then reads as newer than any source written later,
/// which is what a coarse-grained file system makes of two builds within one tick.
fn age_build_records_forward(dir: &Path) -> Result<(), Box<dyn Error>> {
    let ahead = std::time::SystemTime::now() + std::time::Duration::from_hours(24);
    let mut pending = vec![dir.to_path_buf()];
    let mut visited = 0_usize;
    while let Some(next) = pending.pop() {
        visited += 1;
        assert!(visited < 1_000_000, "the build directory is unbounded");
        for entry in std::fs::read_dir(&next)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                std::fs::File::options()
                    .write(true)
                    .open(entry.path())?
                    .set_modified(ahead)?;
            }
        }
    }
    Ok(())
}

/// Two runs of one project share one runtime unit, built once.
///
/// Run 2 builds in the same shared scratch directory as run 1, and the
/// runtime rlib run 1 built is the only one there, untouched by run 2.
#[test]
fn a_second_test_run_reuses_the_runtime_unit_of_the_first() -> TestResult {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping: set IPE_E2E=1 to run the runtime reuse E2E");
        return Ok(());
    }
    let cache = fresh_cache("ipe_test_reuse")?;
    let project = fixture_project("ipe_test_reuse", "tests_pass.ipe")?;
    let lib = runtime_lib_name()?;

    let (ok, _, stderr) = run_captured(ipe_test_command(&project, &cache))?;
    assert!(ok, "run 1 must pass, got stderr:\n{stderr}");
    let target = the_scratch_target(&cache)?;
    let first = rlibs_of(&target, &lib)?;
    assert_eq!(
        first.len(),
        1,
        "run 1 must build one runtime rlib, got {first:?}"
    );
    let Some(unit) = first.first() else {
        return Err("run 1 built no runtime rlib".into());
    };
    let built = std::fs::metadata(unit)?.modified()?;

    let (ok, _, stderr) = run_captured(ipe_test_command(&project, &cache))?;
    assert!(ok, "run 2 must pass, got stderr:\n{stderr}");
    let second = rlibs_of(&the_scratch_target(&cache)?, &lib)?;
    assert_eq!(second, first, "run 2 must reuse run 1's runtime rlib");
    assert_eq!(
        std::fs::metadata(unit)?.modified()?,
        built,
        "run 2 must not rebuild the runtime rlib"
    );
    let _ = std::fs::remove_dir_all(&project);
    let _ = std::fs::remove_dir_all(&cache);
    Ok(())
}

/// Cargo keeps two path dependencies apart when only their build metadata differs.
///
/// Two root crates share one build directory, each depending on a crate `dep`
/// of the same source whose versions differ only in `+a` / `+b`. Each gets
/// its own `dep` rlib, so a version stamp keys a runtime unit by content.
#[test]
fn build_metadata_alone_keeps_two_path_dependency_units_apart() -> TestResult {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping: set IPE_E2E=1 to run the build-metadata identity E2E");
        return Ok(());
    }
    let base =
        crate::support::scratch_root().join(format!("ipe_test_identity_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let target = base.join("target");
    let cargo = ipe_env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    for tag in ["a", "b"] {
        let root = base.join(format!("root_{tag}"));
        let dep = root.join("dep");
        std::fs::create_dir_all(dep.join("src"))?;
        std::fs::create_dir_all(root.join("src"))?;
        std::fs::write(
            dep.join("Cargo.toml"),
            format!("[package]\nname = \"dep\"\nversion = \"0.1.0+{tag}\"\nedition = \"2024\"\n"),
        )?;
        std::fs::write(dep.join("src").join("lib.rs"), "pub fn one() -> u8 { 1 }\n")?;
        std::fs::write(
            root.join("Cargo.toml"),
            format!(
                "[package]\nname = \"root_{tag}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
                 [workspace]\n\n[dependencies]\ndep = {{ path = \"dep\" }}\n"
            ),
        )?;
        std::fs::write(
            root.join("src").join("main.rs"),
            "fn main() { std::process::exit(i32::from(dep::one()) - 1); }\n",
        )?;
        let out = Command::new(&cargo)
            .arg("build")
            .arg("--offline")
            .current_dir(&root)
            .env("CARGO_TARGET_DIR", &target)
            .output()?;
        assert!(
            out.status.success(),
            "root_{tag} must build, got stderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let rlibs = rlibs_of(&target, "dep")?;
    let _ = std::fs::remove_dir_all(&base);
    assert_eq!(
        rlibs.len(),
        2,
        "versions differing only in build metadata must build two units, got {rlibs:?}"
    );
    Ok(())
}

/// A failing project run after a passing one on the same directory fails.
///
/// The passing run's build records are moved a day ahead first, so every
/// source the failing run writes reads as older than them; the previous test
/// runner's units are cleaned under the lock, so its verdict is never reused.
#[test]
fn a_failing_run_after_a_passing_one_is_judged_by_its_own_build() -> TestResult {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping: set IPE_E2E=1 to run the stale-verdict E2E");
        return Ok(());
    }
    let cache = fresh_cache("ipe_test_stale")?;
    let pass = fixture_project("ipe_test_stale_pass", "tests_pass.ipe")?;
    let fail = fixture_project("ipe_test_stale_fail", "tests_fail.ipe")?;

    let (ok, _, stderr) = run_captured(ipe_test_command(&pass, &cache))?;
    assert!(ok, "the passing project must pass, got stderr:\n{stderr}");
    age_build_records_forward(&the_scratch_target(&cache)?)?;

    let (ok, stdout, _) = run_captured(ipe_test_command(&fail, &cache))?;
    let _ = std::fs::remove_dir_all(&pass);
    let _ = std::fs::remove_dir_all(&fail);
    let _ = std::fs::remove_dir_all(&cache);
    assert!(
        !ok,
        "the failing project must exit non-zero, got stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("failed"),
        "the failing case must be counted, got stdout:\n{stdout}"
    );
    Ok(())
}

/// Two projects tested at once on one directory each get their own verdict.
#[test]
fn two_concurrent_test_runs_each_judge_their_own_project() -> TestResult {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping: set IPE_E2E=1 to run the concurrent-run E2E");
        return Ok(());
    }
    let cache = fresh_cache("ipe_test_concurrent")?;
    let pass = fixture_project("ipe_test_concurrent_pass", "tests_pass.ipe")?;
    let fail = fixture_project("ipe_test_concurrent_fail", "tests_fail.ipe")?;

    let mut passing = ipe_test_command(&pass, &cache);
    let mut failing = ipe_test_command(&fail, &cache);
    let passing = passing
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let failing = failing
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let passed = passing.wait_with_output()?;
    let failed = failing.wait_with_output()?;
    let _ = std::fs::remove_dir_all(&pass);
    let _ = std::fs::remove_dir_all(&fail);
    let _ = std::fs::remove_dir_all(&cache);
    assert!(
        passed.status.success(),
        "the passing project must pass, got stderr:\n{}",
        String::from_utf8_lossy(&passed.stderr)
    );
    assert!(
        !failed.status.success(),
        "the failing project must fail, got stdout:\n{}",
        String::from_utf8_lossy(&failed.stdout)
    );
    Ok(())
}

/// Run 2 replays run 1's lock offline, resolving nothing.
///
/// Run 1 stores its `Cargo.lock` in the directory's lock slot; run 2 runs
/// with the network off, passes, and stores a lock byte-equal to the slot it
/// was seeded from.
#[test]
fn a_second_test_run_replays_the_stored_lock_offline() -> TestResult {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping: set IPE_E2E=1 to run the lock-carry E2E");
        return Ok(());
    }
    let cache = fresh_cache("ipe_test_lock")?;
    let project = fixture_project("ipe_test_lock", "tests_pass.ipe")?;

    let (ok, _, stderr) = run_captured(ipe_test_command(&project, &cache))?;
    assert!(ok, "run 1 must pass, got stderr:\n{stderr}");
    let slot = the_scratch_target(&cache)?.join("ipe-test.Cargo.lock");
    let seeded = std::fs::read(&slot)?;

    let mut offline = ipe_test_command(&project, &cache);
    offline.env("CARGO_NET_OFFLINE", "true");
    let (ok, _, stderr) = run_captured(offline)?;
    let stored = std::fs::read(&slot)?;
    let _ = std::fs::remove_dir_all(&project);
    let _ = std::fs::remove_dir_all(&cache);
    assert!(ok, "run 2 must pass offline, got stderr:\n{stderr}");
    assert!(
        stored == seeded,
        "run 2 must build with the lock it was seeded from"
    );
    Ok(())
}

/// A hand-edited `out/` built in the shared directory never stands in for the test runtime.
///
/// After a test run, an `out/` project whose bundled runtime source is edited
/// is built by hand with the shared directory as `CARGO_TARGET_DIR`. Its
/// runtime unit carries the out role, so a second test run keeps its own
/// runtime unit, untouched, beside it and passes.
#[test]
fn a_hand_edited_out_build_never_replaces_the_test_runtime_unit() -> TestResult {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping: set IPE_E2E=1 to run the hand-edited out/ E2E");
        return Ok(());
    }
    let cache = fresh_cache("ipe_test_out")?;
    let project = fixture_project("ipe_test_out", "tests_pass.ipe")?;
    let lib = runtime_lib_name()?;

    let (ok, _, stderr) = run_captured(ipe_test_command(&project, &cache))?;
    assert!(ok, "the first test run must pass, got stderr:\n{stderr}");
    let target = the_scratch_target(&cache)?;
    let scratch_units = rlibs_of(&target, &lib)?;
    assert_eq!(
        scratch_units.len(),
        1,
        "one test runtime rlib, got {scratch_units:?}"
    );
    let Some(unit) = scratch_units.first().cloned() else {
        return Err("the first test run built no runtime rlib".into());
    };
    let built = std::fs::metadata(&unit)?.modified()?;

    let out = project.join("out");
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&project.join("src").join("Main.ipe"), &out, &runtime)
        .map_err(|e| format!("{e:?}"))?;
    let mod_rs = out.join("ipe_runtime_dep").join("src").join("mod.rs");
    let mut source = std::fs::read_to_string(&mod_rs)?;
    source.push_str("\n// edited by hand\n");
    std::fs::write(&mod_rs, source)?;
    std::fs::copy(target.join("ipe-test.Cargo.lock"), out.join("Cargo.lock"))?;
    let cargo = ipe_env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let hand = Command::new(&cargo)
        .arg("build")
        .current_dir(&out)
        .env("CARGO_TARGET_DIR", &target)
        .output()?;
    assert!(
        hand.status.success(),
        "the hand-edited out/ must build, got stderr:\n{}",
        String::from_utf8_lossy(&hand.stderr)
    );

    let (ok, _, stderr) = run_captured(ipe_test_command(&project, &cache))?;
    let units = rlibs_of(&target, &lib)?;
    let reused = std::fs::metadata(&unit)?.modified()?;
    let _ = std::fs::remove_dir_all(&project);
    let _ = std::fs::remove_dir_all(&cache);
    assert!(ok, "the second test run must pass, got stderr:\n{stderr}");
    assert_eq!(
        units.len(),
        2,
        "the out/ runtime unit must stand beside the test one, got {units:?}"
    );
    assert!(
        units.contains(&unit),
        "the test runtime rlib must survive the out/ build, got {units:?}"
    );
    assert_eq!(
        reused, built,
        "the second test run must reuse its own runtime rlib"
    );
    Ok(())
}

/// A test entry that opens an in-memory sqlite database and prints on success.
const MEMORY_OPEN_TEST: &str = "module Main exposing (main)

import Ipe.Db
import Ipe.Db.Location as Location
import Ipe.Error
import Ipe.Io as Io
import Ipe.Task


main : Task Error ()
main =
    Task.andThen (\\_ -> Io.println \"opened\") (Db.open Location.memory)
";

/// A Postgres project's test that opens a sqlite location is refused.
///
/// The test build links the manifest's database driver, so the engine check
/// refuses the in-memory location exactly as the shipped binary does; no
/// server is dialled. Gated on `IPE_E2E=1` — it builds and runs the emitted
/// test binary. Runs in the `e2e` CI job.
#[test]
fn a_postgres_project_test_cannot_open_an_sqlite_location() -> TestResult {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping: set IPE_E2E=1 to run the manifest-driver test E2E");
        return Ok(());
    }
    let dir = crate::support::scratch_root()
        .join(format!("ipe_test_postgres_driver_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src"))?;
    std::fs::create_dir_all(dir.join("tests"))?;
    std::fs::write(
        dir.join("package.ipe"),
        "module Package exposing (package)\n\nimport Ipe.Package exposing (..)\n\n\n\
         package : Package\npackage =\n    { name = \"pgtest\", build = { database = Postgres } }\n",
    )?;
    std::fs::copy(fixture("clean.ipe"), dir.join("src").join("Main.ipe"))?;
    std::fs::write(dir.join("tests").join("Main.ipe"), MEMORY_OPEN_TEST)?;

    let (ok, stdout, stderr) = run_ipe(&["test", &dir.join("package.ipe").to_string_lossy()])?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !ok,
        "a sqlite location must be refused under the manifest's postgres driver, got stdout:\n{stdout}"
    );
    assert!(
        format!("{stdout}{stderr}").contains("this build's driver is"),
        "the refusal must be the runtime's engine check, got stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("opened"),
        "the open must not succeed, got stdout:\n{stdout}"
    );
    Ok(())
}

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
    cmd.arg("test").arg(project).env("XDG_CACHE_HOME", cache);
    e2e_support::target::clear_target_dir_env(&mut cmd);
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
        let mut cmd = Command::new(e2e_support::target::cargo_program());
        cmd.arg("build").arg("--offline").current_dir(&root);
        e2e_support::target::set_target_dir_env(&mut cmd, &target);
        let out = cmd.output()?;
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
    let out_project = ipe::RootFixture::main(&std::fs::read_to_string(fixture("clean.ipe"))?)
        .map_err(|e| format!("{e:?}"))?;
    ipe::build_fixture(&out_project, &out, &runtime).map_err(|e| format!("{e:?}"))?;
    let mod_rs = out.join("ipe_runtime_dep").join("src").join("mod.rs");
    let mut source = std::fs::read_to_string(&mod_rs)?;
    source.push_str("\n// edited by hand\n");
    std::fs::write(&mod_rs, source)?;
    std::fs::copy(target.join("ipe-test.Cargo.lock"), out.join("Cargo.lock"))?;
    let mut hand_cmd = Command::new(e2e_support::target::cargo_program());
    hand_cmd.arg("build").current_dir(&out);
    e2e_support::target::set_target_dir_env(&mut hand_cmd, &target);
    let hand = hand_cmd.output()?;
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

    let (ok, stdout, stderr) = run_ipe(&["test", &dir.to_string_lossy()])?;
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

/// The push test entry: its `@REFUSALS@` line takes one case per bridge refusal.
const PUSH_TEST_ENTRY: &str = r#"module Main exposing (main)

import Ipe.Browser.Push as Push
import Ipe.Browser.Push.Internals as Internals
import Ipe.Error as Error exposing (Error)
import Ipe.Json.Decode as Decode
import Ipe.Json.Encode as Encode
import Ipe.Result as Result exposing (Result(..))
import Ipe.String as String
import Ipe.Test as Test exposing (Test)


outcome : Result Error a -> String
outcome result =
    case result of
        Ok _ ->
            "ok"

        Err err ->
            Error.toString err


replyOutcome : Decode.Decoder (Result Error a) -> String -> String
replyOutcome decoder frame =
    case Decode.decodeString decoder frame of
        Ok result ->
            outcome result

        Err _ ->
            "malformed"


roundTrip : String -> Result String String
roundTrip text =
    Result.mapError Error.toString (Result.map Internals.encodeSubscription (Internals.decodeSubscription text))


badKey : String
badKey =
    Error.toString (Error.invalidInput "a push application key must be a 65-byte uncompressed P-256 point in base64url")


malformed : String
malformed =
    Error.toString (Error.invalidInput "a push subscription text is malformed")


pastCeiling : String
pastCeiling =
    Error.toString (Error.limitExceeded "a push subscription text is past its ceiling")


validKey : String
validKey =
    "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"


receiver : String
receiver =
    "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"


auth : String
auth =
    "BTBZMqHH6r4Tts7J_aSIgg"


webOpen : String
webOpen =
    "{\"v\":1,\"kind\":\"web\",\"endpoint\":\"https://push.example.net/send/abc\",\"p256dh\":\"" ++ receiver ++ "\",\"auth\":\"" ++ auth ++ "\""


webText : String
webText =
    webOpen ++ "}"


webAmpersand : String
webAmpersand =
    String.replace "/send/abc" "/send/a\\u0026b" webText


apnsText : String
apnsText =
    "{\"v\":1,\"kind\":\"apns\",\"token\":\"" ++ String.repeat 8 "0a1b2c3d" ++ "\",\"env\":\"production\",\"p256dh\":\"" ++ receiver ++ "\",\"auth\":\"" ++ auth ++ "\"}"


fcmText : String
fcmText =
    "{\"v\":1,\"kind\":\"fcm\",\"token\":\"fcmToken:APA91b_x-Y0\",\"p256dh\":\"" ++ receiver ++ "\",\"auth\":\"" ++ auth ++ "\"}"


subscribedFrame : String -> String
subscribedFrame event =
    Encode.encode 0 (Encode.object [ ( "tag", Encode.string "push" ), ( "ok", Encode.bool True ), ( "event", Encode.string event ), ( "subscription", Encode.string webText ) ])


tests : List Test
tests =
    [ Test.suite "applicationKey"
        [ Test.test "a 65-byte point is a key" (\_ -> Test.equal "ok" (outcome (Push.applicationKey validKey)))
        , Test.test "a 64-byte value is refused" (\_ -> Test.equal badKey (outcome (Push.applicationKey "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A")))
        , Test.test "another point tag is refused" (\_ -> Test.equal badKey (outcome (Push.applicationKey "Bf4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8")))
        , Test.test "the standard alphabet is refused" (\_ -> Test.equal badKey (outcome (Push.applicationKey (String.replace "_" "/" validKey))))
        , Test.test "padding is refused" (\_ -> Test.equal badKey (outcome (Push.applicationKey (validKey ++ "="))))
        , Test.test "a second spelling is refused" (\_ -> Test.equal badKey (outcome (Push.applicationKey "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A9")))
        ]
    , Test.suite "subscriptionText"
        [ Test.test "a web subscription round-trips" (\_ -> Test.equal (Ok webText) (roundTrip webText))
        , Test.test "an apns subscription round-trips" (\_ -> Test.equal (Ok apnsText) (roundTrip apnsText))
        , Test.test "an fcm subscription round-trips" (\_ -> Test.equal (Ok fcmText) (roundTrip fcmText))
        , Test.test "another version is refused" (\_ -> Test.equal (Err malformed) (roundTrip (String.replace "\"v\":1" "\"v\":2" webText)))
        , Test.test "an unknown kind is refused" (\_ -> Test.equal (Err malformed) (roundTrip (String.replace "\"kind\":\"web\"" "\"kind\":\"mail\"" webText)))
        , Test.test "an endpoint with an escaped ampersand round-trips" (\_ -> Test.equal (Ok webAmpersand) (roundTrip webAmpersand))
        , Test.test "an endpoint with a bare ampersand is refused" (\_ -> Test.equal (Err malformed) (roundTrip (String.replace "\\u0026" "&" webAmpersand)))
        , Test.test "a plain http endpoint is refused" (\_ -> Test.equal (Err malformed) (roundTrip (String.replace "https://" "http://" webText)))
        , Test.test "a 15-byte secret is refused" (\_ -> Test.equal (Err malformed) (roundTrip (String.replace auth "BTBZMqHH6r4Tts7J_aSI" webText)))
        , Test.test "reordered keys are refused" (\_ -> Test.equal (Err malformed) (roundTrip ("{\"v\":1,\"kind\":\"web\",\"endpoint\":\"https://push.example.net/send/abc\",\"auth\":\"" ++ auth ++ "\",\"p256dh\":\"" ++ receiver ++ "\"}")))
        , Test.test "an extra key is refused" (\_ -> Test.equal (Err malformed) (roundTrip (webOpen ++ ",\"x\":1}")))
        , Test.test "a text under the ceiling is read" (\_ -> Test.equal (Err malformed) (roundTrip (webText ++ " ")))
        , Test.test "a text past the ceiling is refused unread" (\_ -> Test.equal (Err pastCeiling) (roundTrip (webText ++ String.repeat 4096 " ")))
        ]
    , Test.suite "replies"
        [ Test.test "a subscribed reply carries the subscription" (\_ -> Test.equal "ok" (replyOutcome Internals.subscribeReply (subscribedFrame "subscribed")))
        , Test.test "another event is refused" (\_ -> Test.equal "malformed" (replyOutcome Internals.subscribeReply (subscribedFrame "current")))
        , Test.test "an unsubscribed reply succeeds" (\_ -> Test.equal "ok" (replyOutcome Internals.unsubscribeReply "{\"tag\":\"push\",\"ok\":true,\"event\":\"unsubscribed\"}"))
        , Test.test "an untagged reply is refused" (\_ -> Test.equal "malformed" (replyOutcome Internals.unsubscribeReply "{\"ok\":true,\"event\":\"unsubscribed\"}"))
        , Test.test "another capability's reply is refused" (\_ -> Test.equal "malformed" (replyOutcome Internals.unsubscribeReply "{\"tag\":\"notification\",\"ok\":true,\"event\":\"unsubscribed\"}"))
        , Test.test "an unknown refusal code is refused" (\_ -> Test.equal "malformed" (replyOutcome Internals.unsubscribeReply "{\"tag\":\"push\",\"ok\":false,\"error\":\"nope\"}"))
@REFUSALS@        ]
    ]


main =
    Test.runMain tests
"#;

/// The low-level push module's source, as the stdlib compiles it.
const PUSH_INTERNALS_SOURCE: &str = include_str!("../../stdlib/Ipe/Browser/Push/Internals.ipe");

/// Every port event a push reply decoder waits for is an event the glue answers
/// with, and the push modules subscribe to no inbound frame the glue never sends:
/// a reply decoder waiting for an unsent event refuses every answer, and a `Sub`
/// over an unsent frame never fires.
#[test]
fn every_push_event_a_decoder_waits_for_is_one_the_glue_sends() {
    let glue = ipe_runtime_rust::js_port_glue::port_glue_js();
    let mut events = Vec::new();
    for piece in PUSH_INTERNALS_SOURCE.split("reply \"").skip(1) {
        let event = piece.split('"').next().unwrap_or_default();
        assert!(
            glue.contains(&format!("event: \"{event}\"")),
            "the glue never answers the push event {event:?}"
        );
        events.push(event);
    }
    assert_eq!(events, ["subscribed", "current", "unsubscribed"]);
    for source in [
        include_str!("../../stdlib/Ipe/Browser/Push.ipe"),
        PUSH_INTERNALS_SOURCE,
    ] {
        assert!(
            !source.contains("Js.subscribe") && !source.contains("Sub.Sub"),
            "a push inbound subscription has no frame producer in the glue"
        );
    }
}

/// The push sizes and version the stdlib parses by are the ones the runtime
/// glue checks: each is defined once in the Ipê source, with the runtime's value,
/// and each base64url length is the unpadded spelling of its byte length.
#[test]
fn push_stdlib_sizes_are_the_runtime_constants() {
    use ipe_runtime_rust::js_port_glue::{
        PUSH_APPLICATION_KEY_BYTES, PUSH_AUTH_SECRET_BYTES, PUSH_SUBSCRIPTION_VERSION,
    };
    let version = usize::try_from(PUSH_SUBSCRIPTION_VERSION).unwrap_or(usize::MAX);
    for (name, value) in [
        ("subscriptionVersion", version),
        ("pointBytes", PUSH_APPLICATION_KEY_BYTES),
        ("pointChars", (PUSH_APPLICATION_KEY_BYTES * 4).div_ceil(3)),
        ("authSecretBytes", PUSH_AUTH_SECRET_BYTES),
        ("authSecretChars", (PUSH_AUTH_SECRET_BYTES * 4).div_ceil(3)),
    ] {
        let head = format!("\n{name} =\n");
        assert_eq!(
            PUSH_INTERNALS_SOURCE.matches(head.as_str()).count(),
            1,
            "{name}"
        );
        let definition = format!("\n{name} : Int\n{name} =\n    {value}\n");
        assert_eq!(
            PUSH_INTERNALS_SOURCE.matches(definition.as_str()).count(),
            1,
            "{name} must be defined as {value}"
        );
    }
}

/// One test case per bridge refusal, naming the error the runtime defines for it.
fn push_refusal_cases() -> String {
    use ipe_runtime_rust::js_port_glue::native_bridge::{BridgeErrorKind, Reject};
    Reject::ALL
        .iter()
        .map(|reject| {
        let code = reject.as_str();
        let message = reject.message();
        let expected = match reject.error_kind() {
            BridgeErrorKind::PermissionDenied => "Error.permissionDenied".to_owned(),
            BridgeErrorKind::Unavailable => format!("(Error.unavailable \"{message}\")"),
            BridgeErrorKind::InvalidInput => format!("(Error.invalidInput \"{message}\")"),
            BridgeErrorKind::LimitExceeded => format!("(Error.limitExceeded \"{message}\")"),
        };
        format!(
            "        , Test.test \"the {code} refusal\" (\\_ -> Test.equal (Error.toString {expected}) \
             (replyOutcome Internals.unsubscribeReply \"{{\\\"tag\\\":\\\"push\\\",\\\"ok\\\":false,\\\"error\\\":\\\"{code}\\\"}}\"))\n"
        )
        })
        .collect::<Vec<_>>()
        .concat()
}

/// `Ipe.Browser.Push` parses keys and subscription texts in one spelling.
///
/// A malformed key, a second spelling of a subscription and an unknown reply
/// are refused beside a valid neighbour, and every bridge refusal decodes to
/// the error the runtime defines for its code. Gated on `IPE_E2E=1` — it builds
/// and runs the emitted test binary.
#[test]
fn push_parses_one_spelling_and_decodes_every_bridge_refusal() -> TestResult {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping: set IPE_E2E=1 to run the push test E2E");
        return Ok(());
    }
    let entry = PUSH_TEST_ENTRY.replace("@REFUSALS@", &push_refusal_cases());
    let dir = write_db_test_project("ipe_test_push", &entry)?;

    let (ok, stdout, stderr) = run_ipe(&["test", &dir.to_string_lossy()])?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        ok,
        "the push test entry must pass, got stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("all tests passed"),
        "the settled outcome must appear, got stdout:\n{stdout}"
    );
    Ok(())
}

/// Each `Ipe.Browser.*.Internals` module: its import alias, its frame tag, the
/// body of one frame its decoders accept, and the decoders it exposes.
const PORT_MODULES: &[(&str, &str, &str, &[&str])] = &[
    (
        "Battery",
        "battery",
        r#""ok":false,"error":"unavailable""#,
        &["inbound"],
    ),
    (
        "Camera",
        "camera",
        r#""ok":false,"error":"cancelled""#,
        &["inbound"],
    ),
    (
        "Channel",
        "channel",
        r#""event":"message","payload":"hello""#,
        &["inbound"],
    ),
    (
        "Clipboard",
        "clipboard",
        r#""ok":false,"error":"denied""#,
        &["inbound"],
    ),
    (
        "Connectivity",
        "connectivity",
        r#""ok":false,"error":"unavailable""#,
        &["inbound"],
    ),
    (
        "FilePicker",
        "file",
        r#""ok":false,"error":"cancelled""#,
        &["inbound"],
    ),
    ("Fullscreen", "fullscreen", r#""event":"ok""#, &["inbound"]),
    (
        "Gamepad",
        "gamepad",
        r#""event":"connected","index":0,"id":"pad""#,
        &["inbound"],
    ),
    (
        "Geolocation",
        "geolocation",
        r#""ok":false,"error":"denied""#,
        &["inbound"],
    ),
    (
        "MediaQuery",
        "media-query",
        r#""ok":false,"error":"unavailable""#,
        &["inbound"],
    ),
    (
        "Microphone",
        "microphone",
        r#""ok":false,"error":"denied""#,
        &["inbound"],
    ),
    (
        "Motion",
        "motion",
        r#""event":"reading","accelX":null,"accelY":null,"accelZ":null,"rotAlpha":null,"rotBeta":null,"rotGamma":null"#,
        &["inbound"],
    ),
    (
        "NetworkInfo",
        "network-info",
        r#""ok":false,"error":"unavailable""#,
        &["inbound"],
    ),
    (
        "Notification",
        "notification",
        r#""ok":false,"error":"denied""#,
        &["inbound", "permissionInbound"],
    ),
    (
        "Orientation",
        "orientation",
        r#""event":"reading","alpha":null,"beta":null,"gamma":null"#,
        &["inbound"],
    ),
    (
        "Permission",
        "permission",
        r#""ok":false,"error":"unavailable","name":"camera""#,
        &["inbound", "(inboundFor PermissionPort.Camera)"],
    ),
    (
        "Push",
        "push",
        r#""ok":false,"error":"denied""#,
        &["subscribeReply", "currentReply", "unsubscribeReply"],
    ),
    (
        "Recorder",
        "recorder",
        r#""event":"started","mime":"audio/webm""#,
        &["inbound"],
    ),
    (
        "ScreenOrientation",
        "screen-orientation",
        r#""event":"ok""#,
        &["inbound"],
    ),
    (
        "Share",
        "share",
        r#""ok":false,"error":"cancelled""#,
        &["inbound"],
    ),
    (
        "Speech",
        "speech",
        r#""ok":false,"error":"unavailable""#,
        &["inbound"],
    ),
    (
        "Storage",
        "storage",
        r#""ok":false,"error":"unavailable""#,
        &["inbound"],
    ),
    (
        "Vibration",
        "vibration",
        r#""ok":false,"error":"unavailable""#,
        &["inbound"],
    ),
    (
        "Visibility",
        "visibility",
        r#""ok":false,"error":"unavailable""#,
        &["inbound"],
    ),
    (
        "WakeLock",
        "wake-lock",
        r#""event":"acquired""#,
        &["inbound"],
    ),
    (
        "WebAuthn",
        "web-authn",
        r#""ok":false,"error":"denied""#,
        &["inbound"],
    ),
];

/// Forged frames no port decoder may accept: untagged denials, a tag of the
/// wrong type, and a tag hidden under `payload`.
const FORGED_FRAMES: &[(&str, &str)] = &[
    ("untagged-denied", r#"{"ok":false,"error":"denied"}"#),
    (
        "untagged-unavailable",
        r#"{"ok":false,"error":"unavailable"}"#,
    ),
    ("numeric-tag", r#"{"tag":1,"ok":false,"error":"denied"}"#),
    (
        "unknown-tag",
        r#"{"tag":"raw","ok":false,"error":"denied"}"#,
    ),
    (
        "payload-tag",
        r#"{"payload":{"tag":"geolocation","ok":true,"lat":1,"lng":1,"accuracy":1}}"#,
    ),
];

/// `text` as an Ipê string literal.
fn ipe_string(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// One `{ label = …, frame = … }` record line of an Ipê frame list.
fn frame_record(first: bool, label: &str, frame: &str) -> String {
    let lead = if first { "[" } else { "," };
    format!(
        "    {lead} {{ label = {}, frame = {} }}\n",
        ipe_string(label),
        ipe_string(frame)
    )
}

/// The test entry that feeds every port decoder every module's frame.
///
/// Each decoder must accept exactly its own module's tagged frame: never the
/// same frame untagged, never another capability's, never a forgery; and
/// `inboundFor` must accept exactly the frame naming its own permission.
fn port_tag_matrix_entry() -> String {
    use ipe_runtime_rust::js_port_glue::PERMISSION_NAMES;
    let mut source = vec![String::from("module Main exposing (main)\n\n")];
    for (alias, ..) in PORT_MODULES {
        source.push(format!(
            "import Ipe.Browser.{alias}.Internals as {alias}Port\n"
        ));
    }
    source.push(String::from(
        "import Ipe.Json.Decode as Decode\n\
         import Ipe.List as List\n\
         import Ipe.Result as Result exposing (Result(..))\n\
         import Ipe.Test as Test exposing (Test)\n\n\n\
         type alias Frame =\n    { label : String, frame : String }\n\n\n\
         accepts : Decode.Decoder a -> String -> Bool\n\
         accepts decoder frame =\n    \
         case Decode.decodeString decoder frame of\n        \
         Ok _ ->\n            True\n\n        \
         Err _ ->\n            False\n\n\n\
         accepted : List Frame -> (String -> Bool) -> List String\n\
         accepted pool accept =\n    \
         List.map (\\f -> f.label) (List.filter (\\f -> accept f.frame) pool)\n\n\n\
         frames : List Frame\nframes =\n",
    ));
    let mut first = true;
    for (_, tag, body, _) in PORT_MODULES {
        source.push(frame_record(
            first,
            tag,
            &format!("{{\"tag\":\"{tag}\",{body}}}"),
        ));
        first = false;
        source.push(frame_record(
            false,
            &format!("{tag}-untagged"),
            &format!("{{{body}}}"),
        ));
    }
    for (label, frame) in FORGED_FRAMES {
        source.push(frame_record(false, label, frame));
    }
    source.push("    ]\n\n\nnames : List Frame\nnames =\n".to_owned());
    let mut first = true;
    for (_, token) in PERMISSION_NAMES {
        let body = format!("\"ok\":false,\"error\":\"unavailable\",\"name\":\"{token}\"");
        source.push(frame_record(
            first,
            token,
            &format!("{{\"tag\":\"permission\",{body}}}"),
        ));
        first = false;
        source.push(frame_record(
            false,
            &format!("{token}-untagged"),
            &format!("{{{body}}}"),
        ));
        source.push(frame_record(
            false,
            &format!("{token}-as-geolocation"),
            &format!("{{\"tag\":\"geolocation\",{body}}}"),
        ));
    }
    source
        .push("    ]\n\n\ntests : List Test\ntests =\n    [ Test.suite \"tag gate\"\n".to_owned());
    let mut first = true;
    for (alias, tag, _, decoders) in PORT_MODULES {
        for decoder in *decoders {
            let lead = if first { "[" } else { "," };
            first = false;
            let expr = decoder.strip_prefix('(').map_or_else(
                || format!("{alias}Port.{decoder}"),
                |applied| format!("({alias}Port.{applied}"),
            );
            source.push(format!(
                "        {lead} Test.test {} (\\_ -> Test.equal [ {} ] (accepted frames (accepts {expr})))\n",
                ipe_string(&format!("{alias}.{decoder}")),
                ipe_string(tag),
            ));
        }
    }
    source.push("        ]\n    , Test.suite \"name gate\"\n".to_owned());
    let mut first = true;
    for (ctor, token) in PERMISSION_NAMES {
        let lead = if first { "[" } else { "," };
        first = false;
        source.push(format!(
            "        {lead} Test.test {} (\\_ -> Test.equal [ {} ] (accepted names (accepts (PermissionPort.inboundFor PermissionPort.{ctor}))))\n\
             \x20       , Test.test {} (\\_ -> Test.equal {} (PermissionPort.nameToken PermissionPort.{ctor}))\n",
            ipe_string(&format!("inboundFor {ctor}")),
            ipe_string(token),
            ipe_string(&format!("nameToken {ctor}")),
            ipe_string(token),
        ));
    }
    source.push("        ]\n    ]\n\n\nmain =\n    Test.runMain tests\n".to_owned());
    source.concat()
}

/// Every port decoder accepts only its own capability's tagged frames.
///
/// Each `Ipe.Browser.*.Internals` decoder is fed every module's accepted frame,
/// tagged and untagged, plus forgeries; it must accept exactly its own module's
/// tagged frame, and `inboundFor` exactly its own permission's. Gated on
/// `IPE_E2E=1` — it builds and runs the emitted test binary.
#[test]
fn every_port_decoder_accepts_only_its_own_tagged_frames() -> TestResult {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping: set IPE_E2E=1 to run the port tag matrix E2E");
        return Ok(());
    }
    let dir = write_db_test_project("ipe_test_port_tags", &port_tag_matrix_entry())?;

    let (ok, stdout, stderr) = run_ipe(&["test", &dir.to_string_lossy()])?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        ok,
        "the port tag matrix must pass, got stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("all tests passed"),
        "the settled outcome must appear, got stdout:\n{stdout}"
    );
    Ok(())
}

/// The matrix covers every `Ipe.Browser.*.Internals` module and every
/// permission constructor, each frame tag once.
#[test]
fn the_port_tag_matrix_covers_every_module_and_permission() {
    let modules: std::collections::BTreeSet<&str> = ipe_stdlib::COMPILED_STD_MODULES
        .iter()
        .filter_map(|m| {
            m.dotted
                .strip_prefix("Ipe.Browser.")
                .and_then(|rest| rest.strip_suffix(".Internals"))
        })
        .filter(|api| !api.contains('.'))
        .collect();
    let matrix: std::collections::BTreeSet<&str> =
        PORT_MODULES.iter().map(|(alias, ..)| *alias).collect();
    assert_eq!(matrix, modules);
    let tags: std::collections::BTreeSet<&str> =
        PORT_MODULES.iter().map(|(_, tag, ..)| *tag).collect();
    assert_eq!(tags.len(), PORT_MODULES.len());
    for (alias, tag, ..) in PORT_MODULES {
        let capability = ipe_kernels::WebCapability::for_browser_module(&["Ipe", "Browser", alias]);
        assert_eq!(
            capability.map(ipe_kernels::WebCapability::as_str),
            Some(*tag),
            "{alias}"
        );
    }
    let entry = port_tag_matrix_entry();
    for (ctor, _) in ipe_runtime_rust::js_port_glue::PERMISSION_NAMES {
        let case = format!(
            "(accepted names (accepts (PermissionPort.inboundFor PermissionPort.{ctor}))))"
        );
        assert_eq!(entry.matches(case.as_str()).count(), 1, "{ctor}");
    }
}

//! `ipe lint` (+ `--fix`) — a golden per rule (fixture → findings) plus the
//! `--fix` rewrite and idempotence for the one fixable rule.
//!
//! Each fixture exercises exactly one rule, linted as the `src/Main.ipe` of a
//! fresh project run from its root. The findings assertion pins the rule name
//! and the offending source location; the `--fix` assertion pins the exact
//! rewritten source and that a second `--fix` pass changes nothing.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

mod support;

type TestResult = Result<(), Box<dyn Error>>;

/// A per-test counter so each scratch directory is unique within this process.
static NEXT: AtomicU32 = AtomicU32::new(0);

/// A fresh, empty scratch directory unique to this process and call.
fn scratch(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir =
        crate::support::scratch_root().join(format!("ipe_lint_{tag}_{}_{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Absolute path to a fixture under `tests/fixtures/lint`.
fn fixture(name: &str) -> PathBuf {
    support::manifest_dir()
        .join("tests/fixtures/lint")
        .join(name)
}

/// Run `ipe` and capture `(success, stdout, stderr)`.
fn run_ipe(args: &[&str]) -> Result<(bool, String, String), Box<dyn Error>> {
    let out = Command::new(support::ipe_bin()).args(args).output()?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// Run `ipe` in `dir` with `NO_COLOR=1` and capture `(success, stdout, stderr)`.
fn run_ipe_in(dir: &Path, args: &[&str]) -> Result<(bool, String, String), Box<dyn Error>> {
    let out = Command::new(support::ipe_bin())
        .args(args)
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .output()?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// A fresh project holding each `(path under src/, source)` of `modules`, by its canonical path.
fn project(tag: &str, modules: &[(&str, &str)]) -> Result<PathBuf, Box<dyn Error>> {
    let dir = std::fs::canonicalize(scratch(tag)?)?;
    std::fs::write(dir.join("package.ipe"), support::package_ipe(tag))?;
    for (rel, source) in modules {
        let path = dir.join("src").join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, source)?;
    }
    Ok(dir)
}

/// A fresh project whose `src/Main.ipe` is the lint fixture `name`.
fn fixture_project(tag: &str, name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let source = std::fs::read_to_string(fixture(name))?;
    project(tag, &[("Main.ipe", &source)])
}

/// Lint one fixture as its own project's `src/Main.ipe` and return the stdout.
fn lint(fixture_name: &str) -> Result<String, Box<dyn Error>> {
    let dir = fixture_project("rule", fixture_name)?;
    let (_ok, stdout, _stderr) = run_ipe_in(&dir, &["lint"])?;
    Ok(stdout)
}

#[test]
fn prim_param_flags_a_bare_port_int() -> TestResult {
    let out = lint("prim_param.ipe")?;
    assert!(
        out.contains("lint/prim-param"),
        "prim-param must fire:\n{out}"
    );
    assert!(
        out.contains("Ipe.Net.Port"),
        "prim-param must name the fitting newtype:\n{out}"
    );
    assert!(
        out.contains(":4:"),
        "the finding points at the signature line:\n{out}"
    );
    Ok(())
}

#[test]
fn adjacent_bools_flags_two_bools() -> TestResult {
    let out = lint("adjacent_bools.ipe")?;
    assert!(
        out.contains("lint/adjacent-bools"),
        "adjacent-bools must fire:\n{out}"
    );
    assert!(
        out.contains("2 adjacent `Bool`"),
        "the message states the run length:\n{out}"
    );
    Ok(())
}

#[test]
fn wrapper_consistency_flags_the_bare_sibling() -> TestResult {
    let out = lint("wrapper_consistency.ipe")?;
    assert!(
        out.contains("lint/wrapper-consistency"),
        "wrapper-consistency must fire:\n{out}"
    );
    assert!(
        out.contains("sibling APIs wrap it as `Port`"),
        "the message names the established wrapper:\n{out}"
    );
    // Only the bare `probe` (line 14) is flagged, not the two consistent siblings.
    assert!(
        out.contains(":14:"),
        "only the bare sibling is flagged:\n{out}"
    );
    Ok(())
}

#[test]
fn unsafe_convention_flags_the_unsafe_call() -> TestResult {
    let out = lint("unsafe_convention.ipe")?;
    assert!(
        out.contains("lint/unsafe-convention"),
        "unsafe-convention must fire:\n{out}"
    );
    assert!(
        out.contains("unsafeFromInt"),
        "the finding names the escape hatch:\n{out}"
    );
    Ok(())
}

#[test]
fn prefer_pipeline_reports_and_fixes() -> TestResult {
    // Report: the rule fires with the pipeline suggestion.
    let out = lint("prefer_pipeline.ipe")?;
    assert!(
        out.contains("lint/prefer-pipeline"),
        "prefer-pipeline must fire:\n{out}"
    );
    assert!(
        out.contains("records |> List.filter live |> List.map fmt"),
        "the suggested pipeline is exact:\n{out}"
    );

    // Fix: the nested call is rewritten to the pipeline, verbatim.
    let dir = fixture_project("fix", "prefer_pipeline.ipe")?;
    let path = dir.join("src/Main.ipe");
    let (ok, stdout, _e) = run_ipe_in(&dir, &["lint", "--fix", "src/Main.ipe"])?;
    assert!(ok, "a warn-only --fix exits 0:\n{stdout}");
    let fixed = std::fs::read_to_string(&path)?;
    assert!(
        fixed.contains("records |> List.filter live |> List.map fmt"),
        "the fix rewrote the nested call:\n{fixed}"
    );
    assert!(
        !fixed.contains("(List.map fmt (List.filter"),
        "the nested form is gone:\n{fixed}"
    );

    // Idempotence: a second --fix pass changes nothing.
    let (_ok2, stdout2, _e2) = run_ipe_in(&dir, &["lint", "--fix", "src/Main.ipe"])?;
    assert!(
        stdout2.contains("no machine-applicable fixes"),
        "re-running --fix finds nothing:\n{stdout2}"
    );
    Ok(())
}

#[test]
fn inline_suppression_silences_a_site() -> TestResult {
    let dir = project(
        "suppress",
        &[(
            "Main.ipe",
            "module Main exposing (render)\n\n-- ipe-lint: allow adjacent-bools\nrender : Bool -> Bool -> String\nrender a b =\n    \"x\"\n",
        )],
    )?;
    let (_ok, stdout, _e) = run_ipe_in(&dir, &["lint", "src/Main.ipe"])?;
    assert!(
        stdout.contains("no findings"),
        "inline suppression silences the only finding:\n{stdout}"
    );
    Ok(())
}

#[test]
fn deny_gate_exits_nonzero() -> TestResult {
    let dir = scratch("gate")?;
    std::fs::create_dir_all(dir.join("src"))?;
    std::fs::write(
        dir.join("src/Main.ipe"),
        "module Main exposing (render)\n\nrender : Bool -> Bool -> String\nrender a b =\n    \"x\"\n",
    )?;
    std::fs::write(
        dir.join("package.ipe"),
        "module Package exposing (package)\n\npackage = { name = \"gated\" }\n",
    )?;
    std::fs::write(
        dir.join("lint.ipe"),
        "module Lint exposing (lint)\n\nlint = Lint.config |> Lint.deny \"adjacent-bools\"\n",
    )?;
    let (ok, _stdout, _e) = run_ipe(&["lint", &dir.to_string_lossy()])?;
    assert!(
        !ok,
        "a surviving denied finding fails the gate (non-zero exit)"
    );
    Ok(())
}

#[test]
fn unknown_rule_in_config_fails_closed() -> TestResult {
    let dir = scratch("badcfg")?;
    std::fs::create_dir_all(dir.join("src"))?;
    std::fs::write(
        dir.join("src/Main.ipe"),
        "module Main exposing (main)\n\nmain = 0\n",
    )?;
    std::fs::write(
        dir.join("package.ipe"),
        "module Package exposing (package)\n\npackage = { name = \"badcfg\" }\n",
    )?;
    std::fs::write(
        dir.join("lint.ipe"),
        "module Lint exposing (lint)\n\nlint = Lint.config |> Lint.deny \"no-such-rule\"\n",
    )?;
    let (ok, _stdout, stderr) = run_ipe(&["lint", &dir.to_string_lossy()])?;
    assert!(!ok, "an unknown rule name must fail closed");
    assert!(
        stderr.contains("not a known lint rule"),
        "the rejection names the problem:\n{stderr}"
    );
    Ok(())
}

/// A scratch project with a lint-clean `Main` and a manifest, but no `lint.ipe`.
fn project_without_lint_config(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = scratch(tag)?;
    std::fs::create_dir_all(dir.join("src"))?;
    std::fs::write(
        dir.join("src/Main.ipe"),
        "module Main exposing (main)\n\nmain = 0\n",
    )?;
    std::fs::write(
        dir.join("package.ipe"),
        "module Package exposing (package)\n\npackage = { name = \"refused\" }\n",
    )?;
    Ok(dir)
}

/// Run `ipe lint <dir>` and require the typed not-a-regular-file refusal for its `lint.ipe`.
#[cfg(unix)]
fn assert_lint_config_refused(dir: &std::path::Path) -> Result<String, Box<dyn Error>> {
    let (ok, _stdout, stderr) = run_ipe(&["lint", &dir.to_string_lossy()])?;
    assert!(!ok, "a non-regular lint.ipe must fail closed:\n{stderr}");
    assert!(
        stderr.contains("lint.ipe") && stderr.contains("not a regular file"),
        "the refusal names lint.ipe as not a regular file:\n{stderr}"
    );
    Ok(stderr)
}

#[test]
fn a_directory_lint_config_is_refused() -> TestResult {
    let dir = project_without_lint_config("cfgdir")?;
    std::fs::create_dir_all(dir.join("lint.ipe"))?;
    #[cfg(unix)]
    assert_lint_config_refused(&dir)?;
    #[cfg(not(unix))]
    {
        let (ok, _stdout, stderr) = run_ipe(&["lint", &dir.to_string_lossy()])?;
        assert!(!ok, "a directory lint.ipe must fail closed:\n{stderr}");
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_symlinked_lint_config_is_refused_not_followed() -> TestResult {
    let dir = project_without_lint_config("cfglink")?;
    let outside = scratch("cfglink_target")?.join("lint.ipe");
    std::fs::write(
        &outside,
        "module Lint exposing (lint)\n\nlint = Lint.config |> Lint.deny \"out-of-root-marker\"\n",
    )?;
    std::os::unix::fs::symlink(&outside, dir.join("lint.ipe"))?;
    let stderr = assert_lint_config_refused(&dir)?;
    assert!(
        !stderr.contains("out-of-root-marker"),
        "the link target is never read:\n{stderr}"
    );
    Ok(())
}

/// Human `ipe lint <file>` output is the one screen frame.
///
/// The product header, then every line in the two-space gutter; `NO_COLOR` output carries no colour.
#[test]
fn human_output_is_framed_and_guttered() -> TestResult {
    let dir = fixture_project("framed", "prim_param.ipe")?;
    let (_ok, stdout, _e) = run_ipe_in(&dir, &["lint"])?;
    let header = format!(
        "\n  Ipê language - v{} - {}\n",
        env!("CARGO_PKG_VERSION"),
        ipe::style::REPO_URL
    );
    assert!(
        stdout.starts_with(&header),
        "the frame header leads:\n{stdout}"
    );
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        assert!(line.starts_with("  "), "line outside the gutter: {line:?}");
    }
    assert!(
        !stdout.contains('\x1b'),
        "NO_COLOR output is plain:\n{stdout}"
    );
    Ok(())
}

/// `--json` and `--plain` are machine output: never framed, never coloured.
#[test]
fn machine_output_is_never_framed() -> TestResult {
    let dir = fixture_project("machine", "prim_param.ipe")?;
    let (_ok, json, _e) = run_ipe_in(&dir, &["lint", "--json"])?;
    assert!(json.starts_with('{'), "JSON is flush and unframed:\n{json}");
    assert!(!json.contains("Ipê language"), "no header in JSON:\n{json}");
    let (_ok, plain, _e) = run_ipe_in(&dir, &["lint", "--plain"])?;
    assert!(
        !plain.contains("Ipê language"),
        "no header in plain:\n{plain}"
    );
    assert!(
        plain.lines().all(|l| !l.starts_with(' ')),
        "plain lines are flush-left:\n{plain}"
    );
    Ok(())
}

/// A module holding the one fixable `prefer-pipeline` finding.
fn nested_call_module(module: &str) -> String {
    format!(
        "module {module} exposing (report)\n\n\nreport records =\n    String.concat (List.map fmt (List.filter live records))\n"
    )
}

/// A root with `src/Main.ipe` and `src/Helper.ipe`, each holding one fixable finding.
fn two_module_project(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    project(
        tag,
        &[
            ("Main.ipe", &nested_call_module("Main")),
            ("Helper.ipe", &nested_call_module("Helper")),
        ],
    )
}

/// The exact `NoManifest` refusal text for `dir`.
fn no_manifest_text(dir: &Path) -> String {
    format!(
        "error[IPE-E0004]: no package.ipe at {}; run `ipe init` there",
        dir.display()
    )
}

/// A file argument names one module of the current directory's project: every
/// module is read for context, but only the named one's findings are reported,
/// and `--fix` rewrites only its file. A file outside the root is refused with
/// the exact `FileOutsideRoot` text, never linted loose.
#[test]
fn lint_of_a_named_module_reports_and_fixes_only_that_module() -> TestResult {
    let dir = two_module_project("focus")?;
    let main = dir.join("src/Main.ipe");
    let main_before = std::fs::read(&main)?;

    let (_ok, stdout, stderr) = run_ipe_in(&dir, &["lint", "src/Helper.ipe"])?;
    assert!(
        stdout.contains("lint/prefer-pipeline") && stdout.contains("Helper.ipe"),
        "the named module's finding is reported:\n{stdout}{stderr}"
    );
    assert!(
        !stdout.contains("Main.ipe"),
        "no other module's finding is reported:\n{stdout}"
    );

    let (ok, stdout, stderr) = run_ipe_in(&dir, &["lint", "--fix", "src/Helper.ipe"])?;
    assert!(ok, "a warn-only --fix exits 0:\n{stdout}{stderr}");
    let helper = std::fs::read_to_string(dir.join("src/Helper.ipe"))?;
    assert!(
        helper.contains("records |> List.filter live |> List.map fmt"),
        "the named module is fixed:\n{helper}"
    );
    assert_eq!(
        std::fs::read(&main)?,
        main_before,
        "--fix on one module leaves every other module byte-identical"
    );

    let elsewhere = dir
        .parent()
        .ok_or("the scratch project has a parent")?
        .join("elsewhere");
    std::fs::create_dir_all(&elsewhere)?;
    std::fs::write(elsewhere.join("X.ipe"), nested_call_module("X"))?;
    let (ok, stdout, stderr) = run_ipe_in(&dir, &["lint", "../elsewhere/X.ipe"])?;
    let want = format!(
        "error[IPE-E0011]: {} names no module of this project: a file argument must lie under \
         `src/` or `tests/` of the current directory, or be its package.ipe; cd into {} and run \
         ipe there",
        dir.join("../elsewhere/X.ipe").display(),
        dir.join("../elsewhere").display()
    );
    assert!(
        !ok && stderr.contains(&want),
        "a file outside the root is refused with the exact text:\nwant: {want}\n{stdout}{stderr}"
    );
    Ok(())
}

/// With no argument, lint reports every module of the root.
#[test]
fn lint_with_no_argument_reports_every_module() -> TestResult {
    let dir = two_module_project("whole")?;
    let (_ok, stdout, stderr) = run_ipe_in(&dir, &["lint"])?;
    assert!(
        stdout.contains("Main.ipe") && stdout.contains("Helper.ipe"),
        "every module's finding is reported:\n{stdout}{stderr}"
    );
    Ok(())
}

/// `ipe lint` in a subdirectory of a project is refused with the exact
/// `NoManifest` text: the manifest above it is never consulted.
#[test]
fn lint_in_a_subdirectory_of_a_project_is_refused() -> TestResult {
    let dir = two_module_project("subdir")?;
    let src = dir.join("src");
    let (ok, stdout, stderr) = run_ipe_in(&src, &["lint"])?;
    let want = no_manifest_text(&src);
    assert!(
        !ok && stderr.contains(&want),
        "a subdirectory is no root:\nwant: {want}\n{stdout}{stderr}"
    );
    Ok(())
}

/// `ipe lint` in a directory with no `package.ipe` is refused with the exact
/// `NoManifest` text, never linting the loose files there.
#[test]
fn lint_without_a_manifest_is_refused_naming_the_directory() -> TestResult {
    let dir = std::fs::canonicalize(scratch("nomanifest")?)?;
    std::fs::write(dir.join("Main.ipe"), nested_call_module("Main"))?;
    let (ok, stdout, stderr) = run_ipe_in(&dir, &["lint"])?;
    let want = no_manifest_text(&dir);
    assert!(
        !ok && stderr.contains(&want),
        "no package.ipe is no root:\nwant: {want}\n{stdout}{stderr}"
    );
    Ok(())
}

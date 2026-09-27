//! `ipe lint` (+ `--fix`) — a golden per rule (fixture → findings) plus the
//! `--fix` rewrite and idempotence for the one fixable rule.
//!
//! Each fixture exercises exactly one rule. The findings assertion pins the rule
//! name and the offending source location; the `--fix` assertion pins the exact
//! rewritten source and that a second `--fix` pass changes nothing.

use std::error::Error;
use std::path::PathBuf;
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

/// Lint one fixture file and return its stdout.
fn lint(fixture_name: &str) -> Result<String, Box<dyn Error>> {
    let (_ok, stdout, _stderr) = run_ipe(&["lint", &fixture(fixture_name).to_string_lossy()])?;
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
    let dir = scratch("fix")?;
    let path = dir.join("Main.ipe");
    std::fs::copy(fixture("prefer_pipeline.ipe"), &path)?;
    let (ok, stdout, _e) = run_ipe(&["lint", "--fix", &path.to_string_lossy()])?;
    assert!(ok, "a warn-only --fix exits 0:\n{stdout}");
    let fixed = std::fs::read_to_string(&path)?;
    assert!(
        fixed.contains("records |> List.filter live |> List.map fmt"),
        "the fix rewrote the nested call:\n{fixed}"
    );
    assert!(
        !fixed.contains("List.map fmt (List.filter"),
        "the nested form is gone:\n{fixed}"
    );

    // Idempotence: a second --fix pass changes nothing.
    let (_ok2, stdout2, _e2) = run_ipe(&["lint", "--fix", &path.to_string_lossy()])?;
    assert!(
        stdout2.contains("no machine-applicable fixes"),
        "re-running --fix finds nothing:\n{stdout2}"
    );
    Ok(())
}

#[test]
fn inline_suppression_silences_a_site() -> TestResult {
    let dir = scratch("suppress")?;
    let path = dir.join("Main.ipe");
    std::fs::write(
        &path,
        "module Main exposing (render)\n\n-- ipe-lint: allow adjacent-bools\nrender : Bool -> Bool -> String\nrender a b =\n    \"x\"\n",
    )?;
    let (_ok, stdout, _e) = run_ipe(&["lint", &path.to_string_lossy()])?;
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

/// Human `ipe lint <file>` output is the one screen frame.
///
/// The product header, then every line in the two-space gutter; `NO_COLOR` output carries no colour.
#[test]
fn human_output_is_framed_and_guttered() -> TestResult {
    let out = Command::new(support::ipe_bin())
        .args(["lint", &fixture("prim_param.ipe").to_string_lossy()])
        .env("NO_COLOR", "1")
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let header = format!(
        "\n  Ipê language - v{} - https://github.com/arthurmaciel/ipe-lang\n",
        env!("CARGO_PKG_VERSION")
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
    let file = fixture("prim_param.ipe").to_string_lossy().into_owned();
    let (_ok, json, _e) = run_ipe(&["lint", "--json", &file])?;
    assert!(json.starts_with('{'), "JSON is flush and unframed:\n{json}");
    assert!(!json.contains("Ipê language"), "no header in JSON:\n{json}");
    let (_ok, plain, _e) = run_ipe(&["lint", "--plain", &file])?;
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

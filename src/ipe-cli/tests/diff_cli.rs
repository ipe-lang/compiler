#![forbid(unsafe_code)]
//! End-to-end `ipe diff`: the gate primitive over two real package trees, and
//! the CLI's exit behaviour in report and `check` modes (including the
//! deprecated `--check` alias).

// Test fixture setup: a failed `expect`/`panic` IS the failure signal — the
// harness reports it as the test failure, which is the intended behaviour here.
#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ipe::diff::{Magnitude, RequiredBump, check_semver_bump};
use semver::Version;

mod support;

/// A fresh temp package directory, unique per test.
fn temp_pkg(tag: &str) -> PathBuf {
    let dir = crate::support::scratch_root().join(format!(
        "ipe-diffcli-{}-{}-{}",
        std::process::id(),
        tag,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(dir.join("src")).expect("create temp src dir");
    dir
}

fn write_lib(pkg: &Path, source: &str) {
    std::fs::write(pkg.join("src").join("Lib.ipe"), source).expect("write Lib");
}

const V1: &str = r"module Lib exposing (double)



double : Int -> Int
double n =
    n + n
";

// A breaking change: `double`'s type changed.
const V2_BREAKING: &str = r"module Lib exposing (double)

import Ipe.String


double : Int -> String
double n =
    String.fromInt (n + n)
";

// A compatible change: a new exposed value added.
const V2_COMPATIBLE: &str = r"module Lib exposing (double, triple)



double : Int -> Int
double n =
    n + n


triple : Int -> Int
triple n =
    n + n + n
";

#[test]
fn check_semver_bump_classifies_a_breaking_change() {
    let old = temp_pkg("brk-old");
    let new = temp_pkg("brk-new");
    write_lib(&old, V1);
    write_lib(&new, V2_BREAKING);

    let rep = check_semver_bump(&old, &new, &Version::new(0, 1, 0), &Version::new(0, 1, 1))
        .expect("diff succeeds");
    assert_eq!(rep.magnitude, Magnitude::Breaking);
    assert_eq!(rep.required, RequiredBump::Minor);
    assert_eq!(rep.floor, Version::new(0, 2, 0));
    assert!(!rep.satisfied, "a patch bump under-bumps a breaking change");
}

#[test]
fn check_semver_bump_classifies_a_compatible_change() {
    let old = temp_pkg("cmp-old");
    let new = temp_pkg("cmp-new");
    write_lib(&old, V1);
    write_lib(&new, V2_COMPATIBLE);

    let rep = check_semver_bump(&old, &new, &Version::new(0, 1, 0), &Version::new(0, 1, 1))
        .expect("diff succeeds");
    assert_eq!(rep.magnitude, Magnitude::Additive);
    assert_eq!(rep.required, RequiredBump::Patch);
    assert!(rep.satisfied, "a patch bump clears a compatible change");
}

#[test]
fn cli_diff_reports_and_exits_zero() {
    let old = temp_pkg("cli-old");
    let new = temp_pkg("cli-new");
    write_lib(&old, V1);
    write_lib(&new, V2_COMPATIBLE);

    let out = Command::new(support::ipe_bin())
        .arg("diff")
        .arg(&old)
        .arg(&new)
        .output()
        .expect("run ipe diff");
    assert!(out.status.success(), "report mode exits 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("added Lib.triple"),
        "report names the added value; got:\n{stdout}"
    );
    assert!(
        stdout.contains("compatible"),
        "report names the compatibility; got:\n{stdout}"
    );
}

#[test]
fn cli_diff_check_rejects_an_underbump() {
    let old = temp_pkg("chk-old");
    let new = temp_pkg("chk-new");
    write_lib(&old, V1);
    write_lib(&new, V2_BREAKING);

    let out = Command::new(support::ipe_bin())
        .arg("diff")
        .arg("check")
        .arg(&old)
        .arg(&new)
        .arg("0.1.0")
        .arg("0.1.1")
        .output()
        .expect("run ipe diff check");
    assert!(
        !out.status.success(),
        "an under-bump of a breaking change is rejected"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("0.2.0"),
        "the error names the required floor; got:\n{stderr}"
    );
}

/// Run `ipe diff check` over two trees with the given version arguments.
fn diff_check(tag: &str, old_v: &str, new_v: &str) -> std::process::Output {
    let old = temp_pkg(&format!("{tag}-old"));
    let new = temp_pkg(&format!("{tag}-new"));
    write_lib(&old, V1);
    write_lib(&new, V2_BREAKING);
    Command::new(support::ipe_bin())
        .arg("diff")
        .arg("check")
        .arg(&old)
        .arg(&new)
        .arg(old_v)
        .arg(new_v)
        .output()
        .expect("run ipe diff check")
}

#[test]
fn cli_diff_check_refuses_a_build_metadata_version() {
    // `1.0.0+b` clears the floor by precedence yet the index refuses it, so no
    // bump verdict is issued for it.
    for (old_v, new_v) in [("0.1.0", "1.0.0+b"), ("0.1.0+b", "1.0.0")] {
        let out = diff_check("chk-build", old_v, new_v);
        assert!(!out.status.success(), "{old_v} -> {new_v} must be refused");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("build metadata"),
            "the refusal names build metadata; got:\n{stderr}"
        );
    }
}

#[test]
fn cli_diff_check_refuses_a_malformed_version() {
    let out = diff_check("chk-malformed", "0.1.0", "1.0");
    assert!(!out.status.success(), "a malformed version is refused");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("is not a valid semantic version"),
        "the refusal names the malformed value; got:\n{stderr}"
    );
}

#[test]
fn cli_diff_check_accepts_a_sufficient_bump() {
    let old = temp_pkg("acc-old");
    let new = temp_pkg("acc-new");
    write_lib(&old, V1);
    write_lib(&new, V2_BREAKING);

    let out = Command::new(support::ipe_bin())
        .arg("diff")
        .arg("check")
        .arg(&old)
        .arg(&new)
        .arg("0.1.0")
        .arg("0.2.0")
        .output()
        .expect("run ipe diff check");
    assert!(
        out.status.success(),
        "a minor bump clears a breaking change; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_diff_deprecated_check_flag_still_verifies_and_warns() {
    // The `--check` alias must keep gating (never-break-users) while printing a
    // notice that points at the bare `check` mode.
    let old = temp_pkg("dep-old");
    let new = temp_pkg("dep-new");
    write_lib(&old, V1);
    write_lib(&new, V2_BREAKING);

    let out = Command::new(support::ipe_bin())
        .arg("diff")
        .arg(&old)
        .arg(&new)
        .arg("--check")
        .arg("0.1.0")
        .arg("0.1.1")
        .output()
        .expect("run ipe diff --check");
    assert!(
        !out.status.success(),
        "the deprecated alias still rejects an under-bump"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("0.2.0"),
        "the alias still names the required floor; got:\n{stderr}"
    );
    assert!(
        stderr.contains("deprecated") && stderr.contains("diff check"),
        "the deprecation notice steers to the bare word; got:\n{stderr}"
    );
}

/// Declare `version` for the package at `pkg` in a minimal `package.ipe`.
fn write_manifest(pkg: &Path, version: &str) {
    std::fs::write(
        pkg.join("package.ipe"),
        format!(
            "module Package exposing (package)\n\n\npackage =\n    \
             {{ name = \"lib\", version = \"{version}\" }}\n"
        ),
    )
    .expect("write package.ipe");
}

/// Run report mode `ipe diff --plain <old> <new>`; return (stdout, stderr).
fn report_plain(old: &Path, new: &Path) -> (String, String) {
    let out = Command::new(support::ipe_bin())
        .arg("diff")
        .arg("--plain")
        .arg(old)
        .arg(new)
        .output()
        .expect("run ipe diff");
    assert!(
        out.status.success(),
        "report mode exits 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn cli_diff_report_measures_a_stable_breaking_change_as_major() {
    let old = temp_pkg("rpt-stable-old");
    let new = temp_pkg("rpt-stable-new");
    write_lib(&old, V1);
    write_lib(&new, V2_BREAKING);
    write_manifest(&old, "1.2.0");

    let (stdout, stderr) = report_plain(&old, &new);
    assert!(
        stdout.lines().any(|l| l == "bump\tbreaking\tmajor\t2.0.0"),
        "a breaking change over 1.2.0 requires a major bump; got:\n{stdout}"
    );
    assert!(
        !stderr.contains("declares no `version`"),
        "a declared version needs no fallback note; got:\n{stderr}"
    );

    let human = Command::new(support::ipe_bin())
        .arg("diff")
        .arg(&old)
        .arg(&new)
        .output()
        .expect("run ipe diff");
    let human = String::from_utf8_lossy(&human.stdout);
    assert!(
        human.contains("requires at least a major bump (>= 2.0.0)"),
        "the sentence names the major bump; got:\n{human}"
    );
}

#[test]
fn cli_diff_report_measures_an_initial_breaking_change_as_minor() {
    let old = temp_pkg("rpt-initial-old");
    let new = temp_pkg("rpt-initial-new");
    write_lib(&old, V1);
    write_lib(&new, V2_BREAKING);
    write_manifest(&old, "0.3.1");

    let (stdout, _) = report_plain(&old, &new);
    assert!(
        stdout.lines().any(|l| l == "bump\tbreaking\tminor\t0.4.0"),
        "a breaking change over 0.3.1 requires a minor bump; got:\n{stdout}"
    );
}

#[test]
fn cli_diff_report_measures_a_stable_additive_change_as_minor() {
    let old = temp_pkg("rpt-add-old");
    let new = temp_pkg("rpt-add-new");
    write_lib(&old, V1);
    write_lib(&new, V2_COMPATIBLE);
    write_manifest(&old, "1.2.0");

    let (stdout, _) = report_plain(&old, &new);
    assert!(
        stdout
            .lines()
            .any(|l| l == "bump\tcompatible\tminor\t1.3.0"),
        "an addition over 1.2.0 requires a minor bump; got:\n{stdout}"
    );
}

#[test]
fn cli_diff_report_notes_an_unversioned_predecessor() {
    let old = temp_pkg("rpt-unver-old");
    let new = temp_pkg("rpt-unver-new");
    write_lib(&old, V1);
    write_lib(&new, V2_BREAKING);

    let (stdout, stderr) = report_plain(&old, &new);
    assert!(
        stdout.lines().any(|l| l == "bump\tbreaking\tminor\t0.1.0"),
        "an unversioned tree is measured on the initial line; got:\n{stdout}"
    );
    assert!(
        stderr.contains("declares no `version`"),
        "the fallback is announced, never silent; got:\n{stderr}"
    );
}

#[test]
fn cli_diff_report_refuses_a_malformed_predecessor_manifest() {
    let old = temp_pkg("rpt-bad-old");
    let new = temp_pkg("rpt-bad-new");
    write_lib(&old, V1);
    write_lib(&new, V2_BREAKING);
    write_manifest(&old, "not-a-version");

    let out = Command::new(support::ipe_bin())
        .arg("diff")
        .arg(&old)
        .arg(&new)
        .output()
        .expect("run ipe diff");
    assert!(
        !out.status.success(),
        "a malformed version is refused, not measured from a guessed line"
    );
}

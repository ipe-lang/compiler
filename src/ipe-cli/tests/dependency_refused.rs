//! A package that declares a dependency is refused by every compiling command,
//! and a project-state refusal never prints a command's help page.
//!
//! No dependency kind is compiled yet, so `type-check`, `dev build`, `test`
//! and `lint` each refuse a manifest that declares one, naming the dependency
//! and its kind, rather than fail later on a module the dependency would have
//! supplied. `fmt` reads no manifest dependency and keeps working.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

mod support;

/// One `ipe` run: whether it exited 0, and its stderr.
struct Run {
    ok: bool,
    stderr: String,
}

/// Run `ipe <args>` with `NO_COLOR=1`.
fn run(args: &[&str]) -> Run {
    match Command::new(support::ipe_bin())
        .args(args)
        .env("NO_COLOR", "1")
        .output()
    {
        Ok(output) => Run {
            ok: output.status.success(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Err(e) => Run {
            ok: false,
            stderr: format!("failed to spawn ipe {args:?}: {e}"),
        },
    }
}

/// Run `ipe <args>` with `NO_COLOR=1` from the directory `cwd`.
fn run_in(cwd: &Path, args: &[&str]) -> Run {
    match Command::new(support::ipe_bin())
        .args(args)
        .current_dir(cwd)
        .env("NO_COLOR", "1")
        .output()
    {
        Ok(output) => Run {
            ok: output.status.success(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Err(e) => Run {
            ok: false,
            stderr: format!("failed to spawn ipe {args:?} in {}: {e}", cwd.display()),
        },
    }
}

/// A fresh directory unique to this process and call.
fn fresh_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = support::scratch_root().join(format!(
        "ipe_dependency_refused_{tag}_{}_{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The entry every fixture holds: it imports the module a dependency would supply.
const IMPORTING_MAIN: &str =
    "module Main exposing (main)\n\nimport SLib\n\n\nmain =\n    SLib.value\n";

/// A clean entry that imports nothing.
const PLAIN_MAIN: &str = "module Main exposing (main)\n\nimport Ipe.Io as Io\n\n\nmain : Task Error ()\nmain =\n    Io.println \"ok\"\n";

/// A project under `base` named `project`, whose `package.ipe` record carries
/// `fields` after its name and whose `src/Main.ipe` and `tests/Main.ipe` are `main`.
#[allow(clippy::expect_used)] // a failed fixture write is the test failure
fn project(base: &Path, fields: &str, main: &str) -> PathBuf {
    let dir = base.join("project");
    std::fs::create_dir_all(dir.join("src")).expect("create src/");
    std::fs::create_dir_all(dir.join("tests")).expect("create tests/");
    std::fs::write(
        dir.join("package.ipe"),
        format!(
            "module Package exposing (package)\n\n\npackage =\n    {{ name = \"app\"{fields} }}\n"
        ),
    )
    .expect("write package.ipe");
    std::fs::write(dir.join("src").join("Main.ipe"), main).expect("write src/Main.ipe");
    std::fs::write(dir.join("tests").join("Main.ipe"), main).expect("write tests/Main.ipe");
    dir
}

/// Each dependency builder as a `package.ipe` field, with the kind word its refusal names.
const DECLARED: [(&str, &str); 3] = [
    (
        ", dependencies = [ depPath \"s-lib\" \"../s-lib\" ]",
        "path",
    ),
    (", dependencies = [ dep \"s-lib\" \"^1.0\" ]", "index"),
    (
        ", dependencies = [ depGit \"s-lib\" \"https://example.invalid/s-lib\" ]",
        "git",
    ),
];

/// Every compiling command, as the arguments before the project directory.
const COMPILING: [&[&str]; 6] = [
    &["type-check"],
    &["dev", "build"],
    &["dev", "run"],
    &["release", "build"],
    &["test"],
    &["lint"],
];

/// Whether `stderr` holds a command's help page (its `Arguments:` section).
fn shows_help(stderr: &str) -> bool {
    stderr.contains("Arguments:")
}

/// Every compiling command refuses every dependency kind, naming the
/// dependency and its kind, before any module is resolved.
#[test]
fn every_compiling_command_refuses_every_dependency_kind() {
    for (field, kind) in DECLARED {
        let base = fresh_dir(kind);
        let dir = project(&base, field, IMPORTING_MAIN);
        let dir_arg = dir.to_string_lossy().into_owned();
        for command in COMPILING {
            let mut args = command.to_vec();
            args.push(&dir_arg);
            let r = run(&args);
            assert!(!r.ok, "{args:?} with a {kind} dependency must fail");
            assert!(
                r.stderr.contains("`s-lib`")
                    && r.stderr.contains(&format!("the {kind} dependency")),
                "{args:?} must name the {kind} dependency `s-lib`:\n{}",
                r.stderr
            );
            assert!(
                !r.stderr.contains("IPE-N0020"),
                "{args:?} must refuse before resolving the dependency's module:\n{}",
                r.stderr
            );
            assert!(
                !shows_help(&r.stderr),
                "{args:?} printed help:\n{}",
                r.stderr
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// A `depPath` is refused whether or not its directory exists: a present
/// library is not compiled either.
#[test]
#[allow(clippy::expect_used)] // a failed fixture write is the test failure
fn a_path_dependency_with_a_present_target_is_still_refused() {
    let base = fresh_dir("present");
    let lib = base.join("s-lib");
    std::fs::create_dir_all(lib.join("src")).expect("create the library");
    std::fs::write(
        lib.join("src").join("SLib.ipe"),
        "module SLib exposing (value)\n\n\nvalue =\n    1\n",
    )
    .expect("write the library module");
    let [(field, _), ..] = DECLARED;
    let dir = project(&base, field, IMPORTING_MAIN);
    let r = run(&["type-check", &dir.to_string_lossy()]);
    let _ = std::fs::remove_dir_all(&base);
    assert!(!r.ok, "a present path dependency must still be refused");
    assert!(r.stderr.contains("`s-lib`"), "{}", r.stderr);
}

/// `fmt` formats a package that declares a dependency: it compiles nothing.
#[test]
fn fmt_still_formats_a_package_with_a_dependency() {
    let base = fresh_dir("fmt");
    let [(field, _), ..] = DECLARED;
    let dir = project(&base, field, PLAIN_MAIN);
    let r = run(&["fmt", &dir.join("src").to_string_lossy()]);
    let _ = std::fs::remove_dir_all(&base);
    assert!(r.ok, "fmt must keep working:\n{}", r.stderr);
}

/// A package with no dependency is not refused by the dependency gate.
#[test]
fn a_package_without_dependencies_type_checks() {
    let base = fresh_dir("none");
    let dir = project(&base, "", PLAIN_MAIN);
    let r = run(&["type-check", &dir.to_string_lossy()]);
    let _ = std::fs::remove_dir_all(&base);
    assert!(
        r.ok,
        "a dependency-free package must type-check:\n{}",
        r.stderr
    );
}

/// A located manifest refusal and a moved source root are project-state
/// refusals: they name the problem and never print the command's help page.
#[test]
#[allow(clippy::expect_used)] // a failed fixture write is the test failure
fn a_project_state_refusal_prints_no_help() {
    for (tag, field, needle) in [
        (
            "located",
            ", delivery = { browser = { themeColor = \"#000\" } }",
            "`themeColor` is not a browser field",
        ),
        (
            "source-root",
            ", sourceRoot = \"app\"",
            "`sourceRoot` is not a package field",
        ),
        (
            "source-root-absent",
            ", sourceRoot = \"app\"",
            "`sourceRoot` is not a package field",
        ),
    ] {
        let base = fresh_dir(tag);
        let dir = project(&base, field, PLAIN_MAIN);
        // The removed field is refused whether or not the moved root exists.
        if tag == "source-root" {
            std::fs::create_dir_all(dir.join("app")).expect("create the moved root");
        }
        let r = run(&["type-check", &dir.to_string_lossy()]);
        let _ = std::fs::remove_dir_all(&base);
        assert!(!r.ok, "{tag}: the manifest must be refused");
        assert!(r.stderr.contains(needle), "{tag}: {}", r.stderr);
        assert!(!shows_help(&r.stderr), "{tag}: printed help:\n{}", r.stderr);
    }
}

/// Building a library package, which has no entry, is a project-state refusal:
/// it names the library and never prints the command's help page.
#[test]
#[allow(clippy::expect_used)] // a failed fixture write is the test failure
fn a_library_build_refusal_prints_no_help() {
    let base = fresh_dir("library");
    let dir = project(&base, ", exposedModules = [ \"SLib\" ]", PLAIN_MAIN);
    std::fs::remove_file(dir.join("src").join("Main.ipe")).expect("drop the entry");
    std::fs::write(
        dir.join("src").join("SLib.ipe"),
        "module SLib exposing (value)\n\n\nvalue =\n    1\n",
    )
    .expect("write the library module");
    let r = run(&["dev", "build", &dir.to_string_lossy()]);
    let _ = std::fs::remove_dir_all(&base);
    assert!(!r.ok, "a library has no entry to build");
    assert!(
        r.stderr.contains("this is a library package"),
        "{}",
        r.stderr
    );
    assert!(!shows_help(&r.stderr), "printed help:\n{}", r.stderr);
}

/// A directory with no `package.ipe` is a project-state refusal for the
/// commands that need one: each names the missing manifest and never prints
/// the command's help page.
#[test]
#[allow(clippy::expect_used)] // a failed fixture write is the test failure
fn a_missing_manifest_prints_no_help() {
    let base = fresh_dir("no-manifest");
    std::fs::create_dir_all(&base).expect("create the empty directory");
    let path = base.to_string_lossy().into_owned();
    let runs = [
        ("add", run_in(&base, &["add", "somepkg"])),
        ("remove", run_in(&base, &["remove", "somepkg"])),
        ("package audit", run(&["package", "audit", &path])),
    ];
    let _ = std::fs::remove_dir_all(&base);
    for (command, r) in runs {
        assert!(
            !r.ok,
            "{command}: a directory with no manifest must be refused"
        );
        assert!(r.stderr.contains("package.ipe"), "{command}: {}", r.stderr);
        assert!(
            !shows_help(&r.stderr),
            "{command}: printed help:\n{}",
            r.stderr
        );
    }
}

/// Real argument misuse still prints the command's help page, so the
/// no-help assertions above are not vacuous.
/// A path argument naming neither a directory nor a `package.ipe` is argument
/// misuse: `package audit` and `package publish` refuse it with the help page.
#[test]
fn a_path_argument_that_is_not_a_package_prints_help() {
    let base = fresh_dir("not_a_package");
    let missing = base.join("absent");
    let missing_arg = missing.to_string_lossy().into_owned();
    for sub in ["audit", "publish"] {
        let r = run(&["package", sub, &missing_arg]);
        assert!(!r.ok, "`package {sub}` must refuse a missing path");
        assert!(
            shows_help(&r.stderr),
            "`package {sub}` on a path that is no package must print help:\n{}",
            r.stderr
        );
    }
}

#[test]
fn argument_misuse_still_prints_help() {
    let r = run(&["type-check", "--no-such-flag"]);
    assert!(!r.ok, "an unknown flag must be refused");
    assert!(
        shows_help(&r.stderr),
        "misuse must print help:\n{}",
        r.stderr
    );
}

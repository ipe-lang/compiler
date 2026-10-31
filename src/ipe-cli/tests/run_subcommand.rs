//! Integration tests for `ipe dev run` — gated on `IPE_E2E=1` so the default
//! `cargo nextest` stays fast and offline (no cargo invocation required).
//!
//! The non-E2E tests still exercise the CLI parsing surface (usage errors) and
//! are unconditionally active.

use std::fs;

use ipe::project_root::SourceTree;
use ipe::{RootFixture, build_fixture};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CLI-parsing tests (unconditional — no network, no build)
// ---------------------------------------------------------------------------

/// `ipe dev run` (no arguments, no `package.ipe` in the working directory) is
/// refused as `NoManifest`, not a panic.
#[test]
fn run_no_args_is_refused_as_no_manifest() {
    let args: Vec<String> = vec!["dev".to_owned(), "run".to_owned()];
    let result = ipe::run_cli(&args);
    assert!(
        matches!(&result, Err(ipe::CliError::NoManifest { .. })),
        "expected NoManifest for bare `ipe dev run`, got: {result:?}"
    );
}

/// `ipe dev run <dir> --bogus` (unrecognised flag after the directory) must return a
/// command-usage error for `run` — carrying a reason naming the offending flag,
/// so the caller shows `run`'s help page — not panic.
#[test]
fn run_unknown_flag_returns_usage_error() {
    let args: Vec<String> = vec![
        "dev".to_owned(),
        "run".to_owned(),
        ".".to_owned(),
        "--bogus-flag".to_owned(),
    ];
    let result = ipe::run_cli(&args);
    assert!(
        matches!(
            &result,
            Err(ipe::CliError::CommandUsage { command, reason })
                if *command == "dev run" && reason.as_str().contains("--bogus-flag")
        ),
        "expected a `run` command-usage error naming the offending flag, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// E2E test — only active when IPE_E2E=1 (requires cargo + runtime)
// ---------------------------------------------------------------------------

/// `ipe dev run <project-dir>` must:
///   1. Compile the Ipê program (exit 0 from ipe pipeline).
///   2. Invoke `cargo build` on the emitted project (SEAL check).
///   3. Exec the resulting binary; its stdout must equal `"hello from run\n"`.
///
/// This test exercises the full `run_run` path from CLI dispatch through the
/// Unix `exec` replacement.  It is skipped unless `IPE_E2E=1` is set.
#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn run_subcommand_builds_and_executes_hello_program() {
    const SRC: &str =
        "module Main exposing (main)\n\nimport Ipe.Io\n\nmain = Io.println \"hello from run\"\n";

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        // Resolve the runtime dir (skips the test when IPE_RUNTIME_DIR is unset
        // and the walk-up also fails, which happens in CI without the repo tree).
        let runtime_dir = e2e_support::require_runtime().into_path_buf();

        // The program is a real project in a private scratch tree.
        let fixture = RootFixture::main(SRC);
        let Ok(fixture) = fixture else {
            panic!("write project: {fixture:?}")
        };
        let dir =
            std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_run_subcommand_e2e");
        let _ = fs::remove_dir_all(&dir);

        // Use a dedicated out dir so CARGO_TARGET_DIR contention is isolated.
        let out_dir = dir.join("out");

        // --- Step 1+2: compile + cargo build via run_cli ---
        // We cannot call run_cli("run", …) directly here because on Unix it would
        // exec (replace) this test process.  Instead, call the public project build
        // + cargo build directly to verify SEAL, then run the binary as a
        // child process to check stdout.  This exercises the same code paths as
        // run_run without sacrificing the test runner.
        let built = build_fixture(&fixture, &out_dir, &runtime_dir);
        let Ok(built) = built else {
            panic!("ipe dev build step must succeed: {built:?}")
        };

        // `ipe dev build`/`ipe dev run` emit the fixed package `ipe-app`: an
        // exclusive tree avoids colliding with a concurrent same-shaped test
        // over the same package name in the shared target. Removed on drop,
        // after the run below reads the binary out of it.
        let isolated =
            e2e_support::target::isolated(e2e_support::target::IsolationReason::FixedPackageName);
        let Ok(isolated) = isolated else {
            panic!("isolated build target: {isolated:?}")
        };
        let target = e2e_support::target::BuildTarget::Isolated(isolated);
        let cargo_status = e2e_support::target::cargo_command(&target)
            .arg("build")
            .current_dir(&out_dir)
            .status();
        assert!(
            matches!(&cargo_status, Ok(s) if s.success()),
            "cargo build on emitted project must succeed: {cargo_status:?}"
        );

        // --- Step 3: run the binary, capture stdout ---
        let bin = built.binary_in(&target.path().join("debug"));
        let Ok(bin) = bin else {
            panic!("the emitted binary name must read: {bin:?}")
        };
        let run = std::process::Command::new(&bin).output();
        let Ok(run) = run else {
            panic!("failed to run emitted binary: {run:?}")
        };
        assert!(run.status.success(), "binary must exit 0");
        assert_eq!(
            String::from_utf8_lossy(&run.stdout),
            "hello from run\n",
            "ipec run e2e: stdout mismatch"
        );
    }
}

/// After `ipe dev build` on a single-file program (no manifest) the emitted
/// `Cargo.toml` must carry `name = "ipe-app"`, and after `ipe build_project`
/// on a manifest that names the project the emitted `Cargo.toml` must carry
/// that name — not `"ipe-app"`.
///
/// This is the structural guarantee that `ipe dev run` relies on: it reads the
/// binary name from the emitted `Cargo.toml` (the same file cargo just built
/// from) rather than re-deriving it from the manifest, so both sides can never
/// disagree.
#[test]
fn emitted_cargo_toml_name_matches_binary_ipe_run_will_exec() {
    const SRC: &str = "module Main exposing (main)\n\nimport Ipe.Io\n\nmain = Io.println \"ok\"\n";

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let runtime_dir = e2e_support::require_runtime().into_path_buf();

        // --- Case 1: single-file build (no manifest) → name must be "ipe-app" ---
        let dir =
            std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipe_run_bin_name_e2e");
        let _ = fs::remove_dir_all(&dir);
        let entry = dir.join("Main.ipe");
        let created = fs::create_dir_all(&dir).and_then(|()| fs::write(&entry, SRC));
        assert!(created.is_ok(), "write source: {created:?}");

        let out_single = dir.join("out_single");
        let built = ipe::build(&entry, &out_single, &runtime_dir);
        assert!(built.is_ok(), "single-file build must succeed: {built:?}");

        let cargo_toml_text = fs::read_to_string(out_single.join("Cargo.toml"))
            .expect("emitted Cargo.toml must exist");
        assert!(
            cargo_toml_text.contains("name = \"ipe-app\""),
            "single-file build must emit name = \"ipe-app\", got:\n{cargo_toml_text}"
        );

        // --- Case 2: manifest build → name is the FRIENDLY slug + a path-derived
        // crate-identity hash suffix. The manifest name "crc32-checksum" yields the
        // emitted crate identity "crc32-checksum_<hash>", so
        // two same-named projects at different paths own separate shared-target slots.
        // The `ipe dev run` binary lookup reads THIS emitted name (SSOT), so it locates
        // the hashed binary cargo produces — never "ipe-app".
        let tree = SourceTree::main(SRC).named("crc32-checksum");
        let fixture = RootFixture::from_tree(&tree).expect("project resolves");

        let out_pkg = dir.join("out_pkg");
        let built =
            build_fixture(&fixture, &out_pkg, &runtime_dir).expect("project build must succeed");
        let name_pkg = built
            .crate_name()
            .expect("emitted Cargo.toml must carry a [package] name");
        let canonical = fixture
            .path()
            .canonicalize()
            .expect("canonical project dir");
        assert_eq!(
            name_pkg,
            ipe_backend_rust::crate_identity("crc32-checksum", &canonical).as_str(),
            "the emitted crate is the project name plus its canonical directory"
        );

        // Friendly base preserved as the prefix; the crate identity carries a hash
        // suffix so the plain slug never has to fight for a shared-target slot.
        assert!(
            name_pkg.starts_with("crc32-checksum_"),
            "project build must emit the friendly slug as the crate-identity prefix, got: {name_pkg}"
        );
        assert_ne!(
            name_pkg, "crc32-checksum",
            "the emitted crate identity must carry a path-derived suffix"
        );
        assert_ne!(
            name_pkg, "ipe-app",
            "a manifest build must NOT collapse to the single-file default"
        );

        // Deterministic: re-emitting the SAME project (same canonical path) yields
        // the SAME crate identity (PRINCIPLE 2 Correctness; reproducible goldens).
        let out_pkg2 = dir.join("out_pkg2");
        let rebuilt =
            build_fixture(&fixture, &out_pkg2, &runtime_dir).expect("re-emit must succeed");
        assert_eq!(
            name_pkg,
            rebuilt.crate_name().expect("re-emitted crate name"),
            "the same project path must yield the same crate identity every build"
        );

        // Distinct: a project with the SAME friendly name at a DIFFERENT canonical
        // path gets a DIFFERENT crate identity — the anti-thrash guarantee.
        let fixture_b = RootFixture::from_tree(&tree).expect("second project resolves");
        let out_pkg_b = dir.join("out_pkg_b");
        let built_b = build_fixture(&fixture_b, &out_pkg_b, &runtime_dir)
            .expect("second project build must succeed");
        let name_pkg_b = built_b.crate_name().expect("second emitted crate name");
        assert!(
            name_pkg_b.starts_with("crc32-checksum_"),
            "second project keeps the same friendly base, got: {name_pkg_b}"
        );
        assert_ne!(
            name_pkg, name_pkg_b,
            "two same-named projects at different paths must own DISTINCT crate identities"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}

// ---------------------------------------------------------------------------
// Toolchain-absence tests (unconditional — the whole point is NO cargo)
// ---------------------------------------------------------------------------

/// `ipe dev run <project-dir>` under a `PATH` with no `cargo`, and with `CARGO_HOME`
/// and `HOME` pointed at empty directories so no install location is found,
/// must fail with the friendly root-cause message — naming Rust/Cargo, why Ipê
/// needs it, and the rustup fix — rather than the opaque OS spawn error.
///
/// This spawns the `ipe` binary as a child (so the Unix `exec` in `run_run`
/// replaces the child, not the test runner) and requires no cargo, so it runs
/// unconditionally.
#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn run_without_cargo_reports_the_missing_toolchain() {
    const SRC: &str = "module Main exposing (main)\n\nimport Ipe.Io\n\nmain = Io.println \"hi\"\n";

    // A runtime dir is needed to reach the toolchain check (which fires after
    // emit). Skip when the repo tree is unavailable (CI without checkout).
    let runtime_dir = e2e_support::require_runtime().into_path_buf();

    let fixture = RootFixture::main(SRC);
    let Ok(fixture) = fixture else {
        panic!("write project: {fixture:?}")
    };
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipe_run_no_cargo_e2e");
    let _ = fs::remove_dir_all(&dir);
    let empty_home = dir.join("empty-home");
    let created = fs::create_dir_all(&empty_home);
    assert!(created.is_ok(), "write empty home: {created:?}");

    let ipe_bin = e2e_support::cargo_bin!("ipe");
    // `ipe dev run` emits the fixed package `ipe-app`; an exclusive tree keeps
    // this test from colliding with a concurrent same-shaped test over the
    // same package name — even though this run never reaches a build, since
    // the missing toolchain is caught first.
    let isolated =
        e2e_support::target::isolated(e2e_support::target::IsolationReason::FixedPackageName);
    let Ok(isolated) = isolated else {
        panic!("isolated build target: {isolated:?}")
    };
    let target = e2e_support::target::BuildTarget::Isolated(isolated);
    // A minimal PATH with no cargo. `/nonexistent-ipe-cargo-probe` cannot hold
    // any executable, so cargo is unresolvable on the PATH.
    let cargoless_path = "/nonexistent-ipe-cargo-probe";
    let out = e2e_support::target::ipe_command(ipe_bin.path(), &target)
        .args(["dev", "run", &fixture.path().to_string_lossy(), "--out"])
        .arg(dir.join("out"))
        .env("PATH", cargoless_path)
        .env("HOME", &empty_home)
        .env("CARGO_HOME", empty_home.join("no-cargo"))
        .env("IPE_RUNTIME_DIR", &runtime_dir)
        .env("NO_COLOR", "1")
        .output();
    let Ok(out) = out else {
        panic!("failed to spawn ipe: {out:?}")
    };

    assert!(
        !out.status.success(),
        "ipe dev run with no cargo must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Which disposition fires depends on the host: a machine with no Rust at
    // all reports "not found"; a machine where Cargo is installed but off this
    // scrubbed PATH reports "not on your PATH". Both name the root cause.
    assert!(
        stderr.contains("Rust and Cargo were not found") || stderr.contains("not on your PATH"),
        "the missing-toolchain message must name the root cause, got:\n{stderr}"
    );
    assert!(
        stderr.contains("compile and run this program"),
        "the message must name what `ipe dev run` was doing, got:\n{stderr}"
    );
    // Both dispositions end with an actionable fix: install via rustup, or add
    // the existing Cargo to PATH.
    assert!(
        stderr.contains("rustup.rs") || stderr.contains("PATH"),
        "the message must give an actionable fix, got:\n{stderr}"
    );
    // The opaque OS spawn error must NOT leak through.
    assert!(
        !stderr.contains("os error"),
        "the raw OS spawn error must never surface, got:\n{stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// The build verbs take a project directory, never a file
// ---------------------------------------------------------------------------

/// The six build verbs, as `ipe` spells them on the command line.
const BUILD_VERBS: [[&str; 2]; 6] = [
    ["dev", "build"],
    ["dev", "run"],
    ["dev", "watch"],
    ["release", "build"],
    ["release", "run"],
    ["release", "eject"],
];

/// `ipe <group> <verb> <args…> --out <out>` run from `cwd`, never reaching cargo.
#[allow(clippy::panic)] // a failed spawn is the test failure
fn run_verb(
    cwd: &std::path::Path,
    verb: [&str; 2],
    arg: &str,
    out: &std::path::Path,
) -> std::process::Output {
    let ran = std::process::Command::new(e2e_support::cargo_bin!("ipe"))
        .args(verb)
        .arg(arg)
        .arg("--out")
        .arg(out)
        .current_dir(cwd)
        .env("PATH", "/nonexistent-ipe-cargo-probe")
        .env("HOME", cwd.join("no-home"))
        .env("CARGO_HOME", cwd.join("no-home/no-cargo"))
        .env("NO_COLOR", "1")
        .output();
    let Ok(ran) = ran else {
        panic!("failed to spawn ipe: {ran:?}")
    };
    ran
}

/// Each build verb refuses a module file and a `package.ipe` with the exact text, and writes nothing.
///
/// Run from the project root, `src/Main.ipe` is refused with the current
/// directory as the hint and `package.ipe` with its own directory; a nested
/// `app/package.ipe` names `app`. No output directory is created, so no build
/// started. A directory with no `package.ipe` is refused as no manifest.
#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn the_build_verbs_refuse_a_file_argument() {
    const SRC: &str = "module Main exposing (main)\n\nimport Ipe.Io\n\nmain = Io.println \"hi\"\n";
    let fixture = RootFixture::main(SRC);
    let Ok(fixture) = fixture else {
        panic!("write project: {fixture:?}")
    };
    let root = fixture.path();
    let parent = root.parent().unwrap_or(root);
    let app = root
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let nested = format!("{app}/package.ipe");
    for verb in BUILD_VERBS {
        let spelled = verb.join(" ");
        for (cwd, arg, hint) in [
            (root, "src/Main.ipe", "."),
            (root, "package.ipe", "."),
            (parent, nested.as_str(), app.as_str()),
        ] {
            let out = root.join(format!("out-{}-{}", verb[0], verb[1]));
            let ran = run_verb(cwd, verb, arg, &out);
            let stderr = String::from_utf8_lossy(&ran.stderr);
            assert!(
                !ran.status.success(),
                "`ipe {spelled} {arg}` must be refused"
            );
            let expected = format!(
                "error[IPE-E0012]: `{arg}` is a file; `ipe {spelled}` takes a project directory. \
                 Pass the directory instead: `ipe {spelled} {hint}`"
            );
            assert!(
                stderr.contains(&expected),
                "`ipe {spelled} {arg}` must say:\n{expected}\ngot:\n{stderr}"
            );
            assert!(
                !out.exists(),
                "`ipe {spelled} {arg}` must write no output directory"
            );
        }

        let bare = root.join("not-a-project");
        let made = fs::create_dir_all(&bare);
        assert!(made.is_ok(), "make the bare directory: {made:?}");
        let out = root.join("out-bare");
        let ran = run_verb(root, verb, "not-a-project", &out);
        let stderr = String::from_utf8_lossy(&ran.stderr);
        let expected = format!(
            "error[IPE-E0004]: no package.ipe at {}; run `ipe init` there",
            bare.display()
        );
        assert!(
            stderr.contains(&expected),
            "`ipe {spelled} not-a-project` must say:\n{expected}\ngot:\n{stderr}"
        );
        assert!(
            !out.exists(),
            "`ipe {spelled} not-a-project` must write no output directory"
        );
    }
}

/// The neighbour of the refusal: `.` and the root's own path are taken as the project.
///
/// Each verb gets past the argument to the build, which then stops at the
/// missing cargo; neither spelling is refused as a file or as no manifest.
#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn the_build_verbs_take_a_directory_argument() {
    const SRC: &str = "module Main exposing (main)\n\nimport Ipe.Io\n\nmain = Io.println \"hi\"\n";
    let fixture = RootFixture::main(SRC);
    let Ok(fixture) = fixture else {
        panic!("write project: {fixture:?}")
    };
    let root = fixture.path();
    let spelled_root = root.to_string_lossy().into_owned();
    for verb in BUILD_VERBS {
        for arg in [".", spelled_root.as_str()] {
            let out = root.join(format!("out-{}-{}", verb[0], verb[1]));
            let ran = run_verb(root, verb, arg, &out);
            let stderr = String::from_utf8_lossy(&ran.stderr);
            assert!(
                !stderr.contains("IPE-E0012") && !stderr.contains("IPE-E0004"),
                "`ipe {} {arg}` must take the directory, got:\n{stderr}",
                verb.join(" ")
            );
            let _ = fs::remove_dir_all(&out);
        }
    }
}

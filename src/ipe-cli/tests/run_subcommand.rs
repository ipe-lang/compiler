//! Integration tests for `ipe dev run` — gated on `IPE_E2E=1` so the default
//! `cargo nextest` stays fast and offline (no cargo invocation required).
//!
//! The non-E2E tests still exercise the CLI parsing surface (usage errors) and
//! are unconditionally active.

use std::fs;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CLI-parsing tests (unconditional — no network, no build)
// ---------------------------------------------------------------------------

/// `ipe dev run` (no arguments, nothing to build here) must return a command-usage
/// error naming `run` — so the caller shows `run`'s help page — not panic.
#[test]
fn run_no_args_returns_usage_error() {
    let args: Vec<String> = vec!["dev".to_owned(), "run".to_owned()];
    let result = ipe::run_cli(&args);
    assert!(
        matches!(
            &result,
            Err(ipe::CliError::CommandUsage { command, .. }) if *command == "dev run"
        ),
        "expected a `run` command-usage error for bare `ipe dev run`, got: {result:?}"
    );
}

/// `ipe dev run <entry> --bogus` (unrecognised flag after the entry) must return a
/// command-usage error for `run` — carrying a reason naming the offending flag,
/// so the caller shows `run`'s help page — not panic.
#[test]
fn run_unknown_flag_returns_usage_error() {
    let args: Vec<String> = vec![
        "dev".to_owned(),
        "run".to_owned(),
        "Main.ipe".to_owned(),
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

/// `ipe dev run <entry.ipe>` must:
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

        // Write the source file into a temp directory.
        let dir =
            std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_run_subcommand_e2e");
        let _ = fs::remove_dir_all(&dir);
        let entry = dir.join("Main.ipe");
        let created = fs::create_dir_all(&dir).and_then(|()| fs::write(&entry, SRC));
        assert!(created.is_ok(), "write source: {created:?}");

        // Use a dedicated out dir so CARGO_TARGET_DIR contention is isolated.
        let out_dir = dir.join("out");

        // --- Step 1+2: compile + cargo build via run_cli ---
        // We cannot call run_cli("run", …) directly here because on Unix it would
        // exec (replace) this test process.  Instead, call the public `build`
        // function + cargo build directly to verify SEAL, then run the binary as a
        // child process to check stdout.  This exercises the same code paths as
        // run_run without sacrificing the test runner.
        let built = ipe::build(&entry, &out_dir, &runtime_dir);
        assert!(built.is_ok(), "ipe dev build step must succeed: {built:?}");

        // Forward the warm shared target (IPE_ORACLE_SHARED_TARGET in CI, else an
        // ambient CARGO_TARGET_DIR a local lane set); fall back to an isolated
        // dir inside out_dir so a bare local run stays hermetic.
        let target_dir = e2e_support::child_shared_target_from_env()
            .map_or_else(|| out_dir.join("target"), PathBuf::from);
        let cargo_status = std::process::Command::new("cargo")
            .arg("build")
            .current_dir(&out_dir)
            .env("CARGO_TARGET_DIR", &target_dir)
            .status();
        assert!(
            matches!(&cargo_status, Ok(s) if s.success()),
            "cargo build on emitted project must succeed: {cargo_status:?}"
        );

        // --- Step 3: run the binary, capture stdout ---
        let bin: PathBuf = target_dir.join("debug").join("ipe-app");
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

        // Prune only an isolated per-test target; a shared warm target is owned by
        // the harness and must not be removed here.
        if e2e_support::child_shared_target_from_env().is_none() {
            let _ = fs::remove_dir_all(&target_dir);
        }
    }
}

/// After `ipe dev build` on a single-file program (no manifest) the emitted
/// `Cargo.toml` must carry `name = "ipe-app"`, and after `ipe build_project`
/// on a manifest whose `name` field sanitizes to a different slug the emitted
/// `Cargo.toml` must carry that slug — not `"ipe-app"`.
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
        // crate-identity hash suffix. The manifest name "Crc32 Checksum" sanitizes to
        // "crc32-checksum"; the emitted crate identity is "crc32-checksum_<hash>" so
        // two same-named projects at different paths own separate shared-target slots.
        // The `ipe dev run` binary lookup reads THIS emitted name (SSOT), so it locates
        // the hashed binary cargo produces — never "ipe-app".
        let pkg_dir = dir.join("pkg");
        let src_dir = pkg_dir.join("src");
        let _ = fs::create_dir_all(&src_dir);
        fs::write(
        pkg_dir.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"Crc32 Checksum\", version = \"0.1.0\" }\n",
    )
    .expect("write package.ipe");
        fs::write(src_dir.join("Main.ipe"), SRC).expect("write Main.ipe");

        let emitted_pkg_name = |out: &std::path::Path| -> String {
            let text =
                fs::read_to_string(out.join("Cargo.toml")).expect("emitted Cargo.toml must exist");
            text.lines()
                .find_map(|l| {
                    let t = l.trim();
                    t.strip_prefix("name")
                        .and_then(|r| r.trim_start().strip_prefix('='))
                        .map(|r| r.trim().trim_matches('"').to_owned())
                })
                .filter(|n| !n.is_empty())
                .expect("emitted Cargo.toml must carry a [package] name")
        };

        let out_pkg = dir.join("out_pkg");
        let built = ipe::build_project(&pkg_dir.join("package.ipe"), &out_pkg, &runtime_dir);
        assert!(built.is_ok(), "project build must succeed: {built:?}");
        let name_pkg = emitted_pkg_name(&out_pkg);

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
        ipe::build_project(&pkg_dir.join("package.ipe"), &out_pkg2, &runtime_dir)
            .expect("re-emit must succeed");
        assert_eq!(
            name_pkg,
            emitted_pkg_name(&out_pkg2),
            "the same project path must yield the same crate identity every build"
        );

        // Distinct: a project with the SAME friendly name at a DIFFERENT canonical
        // path gets a DIFFERENT crate identity — the anti-thrash guarantee.
        let pkg_dir_b = dir.join("pkg_b");
        let src_dir_b = pkg_dir_b.join("src");
        let _ = fs::create_dir_all(&src_dir_b);
        fs::write(
        pkg_dir_b.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"Crc32 Checksum\", version = \"0.1.0\" }\n",
    )
    .expect("write package.ipe (b)");
        fs::write(src_dir_b.join("Main.ipe"), SRC).expect("write Main.ipe (b)");
        let out_pkg_b = dir.join("out_pkg_b");
        ipe::build_project(&pkg_dir_b.join("package.ipe"), &out_pkg_b, &runtime_dir)
            .expect("second project build must succeed");
        let name_pkg_b = emitted_pkg_name(&out_pkg_b);
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

/// `ipe dev run <entry.ipe>` under a `PATH` with no `cargo`, and with `CARGO_HOME`
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

    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipe_run_no_cargo_e2e");
    let _ = fs::remove_dir_all(&dir);
    let entry = dir.join("Main.ipe");
    let empty_home = dir.join("empty-home");
    let created = fs::create_dir_all(&empty_home).and_then(|()| fs::write(&entry, SRC));
    assert!(created.is_ok(), "write source + empty home: {created:?}");

    let ipe_bin = e2e_support::cargo_bin!("ipe");
    // A minimal PATH with no cargo. `/nonexistent-ipe-cargo-probe` cannot hold
    // any executable, so cargo is unresolvable on the PATH.
    let cargoless_path = "/nonexistent-ipe-cargo-probe";
    let out = std::process::Command::new(ipe_bin)
        .args(["dev", "run", &entry.to_string_lossy(), "--out"])
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

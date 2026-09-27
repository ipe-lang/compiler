//! Tests for `ipe build` / `ipe run` / `ipe watch` with no positional entry.
//!
//! The CLI-parsing tests run unconditionally (no cargo, no network).
//! The E2E test that exercises the full compile → cargo-build pipeline is
//! gated on `IPE_E2E=1`, matching the pattern in `init_subcommand.rs`.

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

/// A fresh temp directory unique to this process and call (removed first if
/// present). The process id plus a per-call counter keep two concurrent test
/// processes that share `/tmp` from ever colliding on the same fixture path.
fn fresh_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ipe_noarg_test_{tag}_{}_{n}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// Serializes the tests that mutate the process-global current directory so a
/// threaded `cargo test` run cannot interleave two `set_current_dir` calls.
/// (`cargo nextest` isolates each test in its own process; this keeps the suite
/// correct under `cargo test` too.) Poison-tolerant so a failing test does not
/// wedge the rest.
static CWD_GUARD: Mutex<()> = Mutex::new(());

/// Run `$body` with the process current directory set to `$dir`, restoring the
/// previous directory afterward, serialized against other CWD-mutating tests
/// via [`CWD_GUARD`]. A macro rather than a fn so the fallible calls expand
/// inside the `#[test]` body, where `unwrap` is permitted (a plain helper fn
/// would trip the workspace `unwrap_used`/`expect_used`/`panic` denies).
macro_rules! in_dir {
    ($dir:expr, $body:expr) => {{
        let _cwd_guard = CWD_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir($dir).unwrap();
        let out = $body;
        std::env::set_current_dir(&prev).unwrap();
        out
    }};
}

// ---------------------------------------------------------------------------
// CLI-parsing: no-project directory → usage error (no package.ipe, no src/Main.ipe)
// ---------------------------------------------------------------------------

/// `ipe build` with no argument in an empty temp directory returns a usage
/// error, not a panic.
#[test]
fn build_no_arg_empty_dir_returns_usage_error() {
    let dir = fresh_dir("build_empty");
    fs::create_dir_all(&dir).unwrap();

    let result = in_dir!(&dir, ipe::run_cli(&["build".to_owned()]));

    let _ = fs::remove_dir_all(&dir);

    assert!(
        matches!(
            result,
            Err(ipe::CliError::CommandUsage {
                command: "build",
                ..
            })
        ),
        "bare `ipe build` in an empty dir must yield a build command-usage error, got: {result:?}"
    );
}

/// `ipe run` with no argument in an empty temp directory returns a usage
/// error, not a panic.
#[test]
fn run_no_arg_empty_dir_returns_usage_error() {
    let dir = fresh_dir("run_empty");
    fs::create_dir_all(&dir).unwrap();

    let result = in_dir!(&dir, ipe::run_cli(&["run".to_owned()]));

    let _ = fs::remove_dir_all(&dir);

    assert!(
        matches!(
            result,
            Err(ipe::CliError::CommandUsage { command: "run", .. })
        ),
        "bare `ipe run` in an empty dir must yield a run command-usage error, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// E2E: `ipe init <dir>` then `ipe build` with no positional entry
// ---------------------------------------------------------------------------

/// `ipe build` (no positional) inside a scaffolded project directory must
/// compile and emit a Rust project that `cargo build` accepts (THE SEAL).
///
/// Gated on `IPE_E2E=1` — requires a working cargo and `IPE_RUNTIME_DIR`.
#[test]
fn build_no_arg_in_project_dir_succeeds() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let Ok(runtime_dir) = ipe::resolve_runtime() else {
        return; // runtime not available in this environment
    };

    let dir = fresh_dir("build_project");
    let project = dir.join("counter");

    // Scaffold via `ipe init`.
    let init = ipe::run_cli(&["init".to_owned(), project.to_string_lossy().into_owned()]);
    assert!(init.is_ok(), "ipe init must succeed: {init:?}");

    // Switch into the project directory and call `ipe build` with no entry.
    let out_dir = project.join("out").join("rust");
    let build_result = in_dir!(&project, ipe::run_cli(&["build".to_owned()]));

    assert!(
        build_result.is_ok(),
        "`ipe build` (no positional) in project dir must succeed: {build_result:?}"
    );

    // THE SEAL: emitted Rust must compile with cargo.
    let cargo_status = std::process::Command::new("cargo")
        .arg("build")
        .current_dir(&out_dir)
        .env("CARGO_TARGET_DIR", out_dir.join("target"))
        .env("IPE_RUNTIME_DIR", &runtime_dir)
        .status();
    assert!(
        matches!(&cargo_status, Ok(s) if s.success()),
        "cargo build on the emitted project must succeed: {cargo_status:?}"
    );

    let _ = fs::remove_dir_all(out_dir.join("target"));
    let _ = fs::remove_dir_all(&dir);
}

/// `ipe build --out /tmp/o` (flag-first, no positional entry) in a scaffolded
/// project directory must still resolve the default entry and succeed.
///
/// Gated on `IPE_E2E=1`.
#[test]
fn build_flag_first_no_entry_resolves_default() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let Ok(runtime_dir) = ipe::resolve_runtime() else {
        return;
    };

    let dir = fresh_dir("build_flagfirst");
    let project = dir.join("counter");
    let out_dir = dir.join("out");

    let init = ipe::run_cli(&["init".to_owned(), project.to_string_lossy().into_owned()]);
    assert!(init.is_ok(), "ipe init must succeed: {init:?}");

    let build_result = in_dir!(
        &project,
        ipe::run_cli(&[
            "build".to_owned(),
            "--out".to_owned(),
            out_dir.to_string_lossy().into_owned(),
        ])
    );

    assert!(
        build_result.is_ok(),
        "`ipe build --out <dir>` (no positional) must succeed: {build_result:?}"
    );

    // THE SEAL. `--out` names the output root; the emitted crate is its
    // `rust/` area.
    let crate_dir = out_dir.join("rust");
    let cargo_status = std::process::Command::new("cargo")
        .arg("build")
        .current_dir(&crate_dir)
        .env("CARGO_TARGET_DIR", crate_dir.join("target"))
        .env("IPE_RUNTIME_DIR", &runtime_dir)
        .status();
    assert!(
        matches!(&cargo_status, Ok(s) if s.success()),
        "cargo build on the emitted project must succeed: {cargo_status:?}"
    );

    let _ = fs::remove_dir_all(crate_dir.join("target"));
    let _ = fs::remove_dir_all(&dir);
}

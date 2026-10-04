//! The embedded WASI run honours the resource floor of its profile.
//!
//! Two ceilings bound a guest, each proven by a refusal and a control:
//!
//! * **Wall clock** — a guest that never returns is turned back with
//!   [`CliError::WasiRunFailed`] once `wall_secs` elapses; a guest that returns
//!   at once runs to `Ok`.
//! * **Linear memory** — a guest whose `memory.grow` would pass `as_bytes` is
//!   turned back with [`CliError::WasiRunFailed`] for a trap while it runs; a
//!   guest that grows within the ceiling runs to `Ok`, and the very module
//!   refused under the ceiling runs to `Ok` under the default ceiling, so the
//!   refusal is the ceiling's and not a module that fails to load.
//!
//! The modules are hand-assembled bytes (no wasm toolchain, no new dependency).
//! Every refusal test goes red when its ceiling is not honoured: without the
//! wall deadline the busy loop never returns (nextest terminates the test), and
//! without the memory limiter the grow succeeds and the run returns `Ok`.

#![cfg(feature = "wasi_run")]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ipe::CliError;
use ipe::wasi_run::run_wasi_module;
use ipe_sandbox::run_jail::{RunResourceLimits, SandboxProfile};

/// `(module (func (export "_start") (loop (br 0))))`: `_start` never returns.
const SPIN: [u8; 41] = [
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02,
    0x01, 0x00, 0x07, 0x0a, 0x01, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00, 0x0a, 0x09,
    0x01, 0x07, 0x00, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b,
];

/// `(module (func (export "_start")))`: `_start` returns at once.
const RETURN_AT_ONCE: [u8; 36] = [
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02,
    0x01, 0x00, 0x07, 0x0a, 0x01, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00, 0x0a, 0x04,
    0x01, 0x02, 0x00, 0x0b,
];

/// One 64 KiB page of memory; `_start` grows it by ONE page and executes
/// `unreachable` if the grow reports failure.
const GROW_ONE_PAGE: [u8; 52] = [
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02,
    0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x0a, 0x01, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72,
    0x74, 0x00, 0x00, 0x0a, 0x0f, 0x01, 0x0d, 0x00, 0x41, 0x01, 0x40, 0x00, 0x41, 0x7f, 0x46, 0x04,
    0x40, 0x00, 0x0b, 0x0b,
];

/// The same module, growing by TWO HUNDRED pages (12.5 MiB).
const GROW_TWO_HUNDRED_PAGES: [u8; 53] = [
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02,
    0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x0a, 0x01, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72,
    0x74, 0x00, 0x00, 0x0a, 0x10, 0x01, 0x0e, 0x00, 0x41, 0xc8, 0x01, 0x40, 0x00, 0x41, 0x7f, 0x46,
    0x04, 0x40, 0x00, 0x0b, 0x0b,
];

/// The memory ceiling the grow tests run under: 64 pages (4 MiB). The one
/// initial page and a one-page grow fit; a 200-page grow does not.
const MEMORY_CEILING_BYTES: u64 = 64 * 65_536;

/// Write `bytes` as a module file in a fresh, pid-isolated scratch dir under
/// the test tempdir; returns the file and the dir (used as the working tree).
#[allow(clippy::expect_used)] // test helper: a failed scratch setup IS the failure
fn module_file(name: &str, bytes: &[u8]) -> (PathBuf, PathBuf) {
    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir scratch");
    let file = dir.join("module.wasm");
    std::fs::write(&file, bytes).expect("write module");
    (file, dir)
}

fn profile(limits: RunResourceLimits) -> SandboxProfile {
    SandboxProfile {
        limits,
        ..SandboxProfile::maximally_isolated()
    }
}

fn run(file: &Path, tree: &Path, profile: &SandboxProfile) -> Result<(), CliError> {
    run_wasi_module(file, profile, tree, &[])
}

#[test]
fn a_guest_that_never_returns_is_turned_back_at_the_wall_ceiling() {
    let (file, tree) = module_file("wasi_ceiling_spin", &SPIN);
    let profile = profile(RunResourceLimits {
        wall_secs: Some(1),
        ..RunResourceLimits::default()
    });
    let started = Instant::now();
    let outcome = run(&file, &tree, &profile);
    let took = started.elapsed();
    assert!(
        matches!(outcome, Err(CliError::WasiRunFailed { .. })),
        "a busy loop past the wall ceiling must be refused, got {outcome:?}"
    );
    assert!(
        took >= Duration::from_secs(1),
        "the guest was stopped before its wall ceiling: {took:?}"
    );
    assert!(
        took < Duration::from_secs(30),
        "the wall ceiling did not stop the guest promptly: {took:?}"
    );
}

#[test]
fn a_guest_that_returns_at_once_runs_to_ok_under_the_wall_ceiling() {
    let (file, tree) = module_file("wasi_ceiling_return", &RETURN_AT_ONCE);
    let profile = profile(RunResourceLimits {
        wall_secs: Some(60),
        ..RunResourceLimits::default()
    });
    let started = Instant::now();
    let outcome = run(&file, &tree, &profile);
    let took = started.elapsed();
    assert!(
        matches!(outcome, Ok(())),
        "a guest inside its ceiling must run to completion, got {outcome:?}"
    );
    assert!(
        took < Duration::from_secs(30),
        "a guest that returns at once took {took:?}"
    );
}

#[test]
fn a_guest_that_grows_memory_past_the_ceiling_is_turned_back() {
    let (file, tree) = module_file("wasi_ceiling_grow_past", &GROW_TWO_HUNDRED_PAGES);
    let profile = profile(RunResourceLimits {
        as_bytes: MEMORY_CEILING_BYTES,
        ..RunResourceLimits::default()
    });
    let outcome = run(&file, &tree, &profile);
    assert!(
        matches!(
            &outcome,
            Err(CliError::WasiRunFailed { detail })
                if detail.as_str().starts_with("the module trapped during execution")
        ),
        "a grow past the memory ceiling must trap while the guest runs, got {outcome:?}"
    );
}

#[test]
fn the_over_ceiling_grow_runs_to_ok_once_the_ceiling_is_lifted() {
    let (file, tree) = module_file("wasi_ceiling_grow_lifted", &GROW_TWO_HUNDRED_PAGES);
    let defaults = RunResourceLimits::default();
    assert!(
        defaults.as_bytes > 201 * 65_536,
        "the default ceiling must fit the 200-page grow for this control to mean anything"
    );
    let outcome = run(&file, &tree, &profile(defaults));
    assert!(
        matches!(outcome, Ok(())),
        "the module refused under the memory ceiling must load and run under the default one, got {outcome:?}"
    );
}

#[test]
fn a_guest_that_grows_memory_within_the_ceiling_runs_to_ok() {
    let (file, tree) = module_file("wasi_ceiling_grow_within", &GROW_ONE_PAGE);
    let profile = profile(RunResourceLimits {
        as_bytes: MEMORY_CEILING_BYTES,
        ..RunResourceLimits::default()
    });
    let outcome = run(&file, &tree, &profile);
    assert!(
        matches!(outcome, Ok(())),
        "a grow inside the memory ceiling must succeed, got {outcome:?}"
    );
}

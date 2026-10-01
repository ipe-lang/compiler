//! End-to-end proof of the returning build jail + the per-axis differential
//! confinement contract — the Tier-2 observation primitive at the kernel
//! boundary.
//!
//! These are REAL jailed runs (they spawn `bwrap`) of the admission probe
//! fixture (`tests/fixtures/admission/untrusted-build.sh`, `PROBE_MODE=tier2`),
//! so they are gated behind `IPE_E2E=1` and skip cleanly when the jail cannot be
//! established here — either because bubblewrap / the cap helpers are absent, or
//! because the environment forbids establishing the jail (a locked-down runner
//! where `bwrap` is present but the kernel denies the namespace setup). A
//! one-time canary (`/bin/true` under the most-isolated profile) settles this;
//! the tests early-return exactly as they do when the tools are missing, never a
//! false pass.
//!
//! What they prove directly at the OS boundary, not by the payload's own choice:
//!
//! - **Denied names the axis.** Under a jail scoped to a DECLARED set that
//!   withholds `network`, the probe's socket attempt is denied → the fixture's
//!   wrapper-owned exit code decodes to [`JailOutcome::Denied`] naming
//!   `network`. Likewise an out-of-scratch write under a filesystem-withholding
//!   jail decodes to `Denied { filesystem }`.
//! - **Clean requires positive proof.** A benign in-scratch write under the
//!   declared-scoped jail exits 0 → [`JailOutcome::Clean`]. The one admit-eligible
//!   outcome only ever comes from the probe's clean exit.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
// Integration harness: `expect`/`unwrap` on setup make a mis-set-up test fail
// loudly (correct for a test); indexing mirrors the sibling `run_jail_e2e`.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::redundant_closure_for_method_calls
)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use ipe_sandbox::build_jail::{CapabilityAxis, JailOutcome, build_in_jail};
use ipe_sandbox::run_jail::{FilesystemScope, RunJailTools, SandboxProfile};
use ipe_sandbox::{CanonicalPath, JailMounts};

/// The `build_in_jail` seccomp path creates a `memfd` and clears its
/// close-on-exec flag — a process-global fd-table mutation. Serialize the jailed
/// runs so parallel `--test-threads` cannot race on fd numbers.
static JAIL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The absolute path to the admission probe fixture, from the workspace root
/// this crate is built within.
fn fixture_path() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `.../src/compiler/sandbox`; the fixture lives at
    // the repo root under `tests/fixtures/admission/`.
    e2e_support::manifest_dir!().join("../../../tests/fixtures/admission/untrusted-build.sh")
}

/// Skip unless `IPE_E2E=1`, the jail tools are present, AND a jail can actually
/// be established here. Mirrors the sibling `run_jail_e2e` gate: tool presence
/// alone is insufficient (a runner may have `bwrap` but deny the namespace
/// setup), so a `/bin/true` canary under the isolated profile decides once.
fn e2e_tools() -> Option<RunJailTools> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return None;
    }
    let caps = ipe_sandbox::probe();
    let tools = RunJailTools {
        bwrap: caps.bwrap?,
        prlimit: caps.prlimit?,
        timeout: caps.timeout,
    };
    if !jail_can_establish(&tools) {
        return None;
    }
    Some(tools)
}

/// One-time canary: `/bin/true` under the most-isolated profile must exit
/// `Clean`. Any other outcome means the jail could not be established here → the
/// tests skip rather than fail on a broken environment.
fn jail_can_establish(tools: &RunJailTools) -> bool {
    static CANARY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CANARY.get_or_init(|| {
        let scoped = fresh_scratch("canary");
        let bound = canonical(&scoped);
        let _guard = JAIL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let outcome = build_in_jail(
            tools,
            &SandboxProfile::maximally_isolated(),
            &mounts(&bound),
            &[OsString::from("/bin/true")],
        );
        let _ = std::fs::remove_dir_all(&scoped);
        let established = outcome.is_clean();
        if !established {
            eprintln!("build_jail_e2e: skipping — jail cannot be established here ({outcome:?})");
        }
        established
    })
}

/// A fresh per-test scratch dir under the system temp root (the one writable
/// mount inside the jail).
fn fresh_scratch(tag: &str) -> PathBuf {
    let dir = ipe_test_temp::temp_root().join(format!(
        "ipe-build-jail-e2e-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("scoped tmp");
    dir
}

/// `path` resolved to the canonical form the jail binds.
fn canonical(path: &Path) -> CanonicalPath {
    CanonicalPath::resolve(path).expect("canonical jail path")
}

/// The jail mounts over `bound` (scratch and working tree) plus [`ro_binds`],
/// checked against the invoker's cargo home.
fn mounts(bound: &CanonicalPath) -> JailMounts {
    JailMounts::of_invoker(bound.clone(), bound.clone(), ro_binds()).expect("checked jail mounts")
}

/// The interpreters/tools the fixture needs, re-exposed read-only past the
/// home/tmp tmpfs masks.
fn ro_binds() -> Vec<CanonicalPath> {
    ["/usr", "/bin", "/lib"]
        .into_iter()
        .map(Path::new)
        .filter(|p| p.exists())
        .map(canonical)
        .collect()
}

/// Run the admission fixture in `tier2` mode inside a jail scoped to `profile`,
/// exercising exactly `axis`, and return the decoded outcome. `escape_path` is
/// the fs-escape probe target (inside the scratch for a Clean run, outside it
/// for a denial).
fn run_fixture(
    tools: &RunJailTools,
    profile: &SandboxProfile,
    scoped: &Path,
    axis: &str,
    escape_path: &str,
) -> JailOutcome {
    // The env the fixture reads (`PROBE_MODE`/`TIER2_AXIS`/`SCRATCH_DIR`/
    // `ESCAPE_PATH`). These are PER-TEST data, not host state, so they must NOT
    // travel through the process-global environment: `std::env::set_var` mutates
    // a table shared by every parallel `--test-threads` worker, and the four
    // tests would race — thread A's argv could be built from thread B's
    // `SCRATCH_DIR`/`TIER2_AXIS`, so a probe writes into a sibling's (deleted)
    // scratch, `set -eu` aborts, and the run decodes to a spurious exit-2
    // BuildFailed. Instead, thread the config through the PAYLOAD via `env
    // NAME=VALUE … /bin/sh script`: `env` runs inside the jail (after
    // `--clearenv`) and sets exactly the child's environment. Each
    // `build_in_jail` call carries its own config with zero shared state, and the
    // primitive's host-env re-export contract is left untouched.
    //
    // The fixture lives in the repo tree, which the jail masks (only the scratch
    // mount and the ro tool binds are visible inside). Copy it into the scratch —
    // the one writable mount — so the jailed shell can read it. Every path the
    // payload names is the canonical path the jail binds.
    let bound = canonical(scoped);
    let scoped = bound.as_path();
    let jailed_fixture = scoped.join("untrusted-build.sh");
    std::fs::copy(fixture_path(), &jailed_fixture).expect("copy fixture into scratch");
    let payload: Vec<OsString> = vec![
        OsString::from("/usr/bin/env"),
        OsString::from("PROBE_MODE=tier2"),
        env_assignment("TIER2_AXIS", axis.as_ref()),
        env_assignment("SCRATCH_DIR", scoped.as_os_str()),
        env_assignment("ESCAPE_PATH", escape_path.as_ref()),
        OsString::from("/bin/sh"),
        jailed_fixture.into_os_string(),
    ];
    let _guard = JAIL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    build_in_jail(tools, profile, &mounts(&bound), &payload)
}

/// Build a single `NAME=VALUE` argument for `env(1)`. The value is an `OsStr` so
/// a path with non-UTF-8 bytes survives; the test paths are the process-id/
/// thread-id scratch dirs, which are ASCII, but keeping it `OsString`-typed
/// avoids a lossy `to_string_lossy` round-trip.
fn env_assignment(name: &str, value: &std::ffi::OsStr) -> OsString {
    let mut assignment = OsString::from(name);
    assignment.push("=");
    assignment.push(value);
    assignment
}

/// The declared-scoped profile a real Tier-2 probe runs under: `subprocess`
/// granted so the probe can fork its helper (python3/nc/rm), with the axis under
/// test withheld. The withheld axis — not the ability to spawn a helper — is what
/// the probe must observe a denial on.
fn probe_profile(network: bool, filesystem: FilesystemScope) -> SandboxProfile {
    SandboxProfile {
        network,
        filesystem,
        subprocess: true,
        ..SandboxProfile::maximally_isolated()
    }
}

#[test]
fn a_socket_under_a_network_withholding_jail_is_denied_naming_network() {
    let Some(tools) = e2e_tools() else { return };
    // Declared set grants `subprocess` (the probe forks python3 to open a socket)
    // but WITHHOLDS `network` → the socket is denied by the empty net namespace →
    // Denied { network }.
    let scoped = fresh_scratch("net-denied");
    let outcome = run_fixture(
        &tools,
        &probe_profile(false, FilesystemScope::Isolated),
        &scoped,
        "network",
        &format!("{}/escape", scoped.display()),
    );
    let _ = std::fs::remove_dir_all(&scoped);
    assert_eq!(
        outcome,
        JailOutcome::Denied {
            axis: CapabilityAxis::Network
        },
        "a withheld-network jail must deny the socket and name the network axis"
    );
}

#[test]
fn an_out_of_scratch_write_under_a_filesystem_withholding_jail_is_denied_naming_filesystem() {
    let Some(tools) = e2e_tools() else { return };
    // Declared set grants nothing but the scratch mount (isolated filesystem) →
    // an out-of-scratch write (to a read-only host path) is denied → Denied
    // { filesystem }. `/usr/...` is read-only under `--ro-bind / /`.
    let scoped = fresh_scratch("fs-denied");
    let outcome = run_fixture(
        &tools,
        &SandboxProfile::maximally_isolated(),
        &scoped,
        "filesystem",
        "/usr/ipe-tier2-escape-probe",
    );
    let _ = std::fs::remove_dir_all(&scoped);
    assert_eq!(
        outcome,
        JailOutcome::Denied {
            axis: CapabilityAxis::Filesystem
        },
        "a withheld-filesystem jail must deny the out-of-scratch write and name the filesystem axis"
    );
}

#[test]
fn a_benign_in_scratch_write_is_clean() {
    let Some(tools) = e2e_tools() else { return };
    // The fs-escape target is INSIDE the scratch (the one writable mount), so the
    // write succeeds and no axis is demanded-but-withheld → Clean. This is the
    // only admit-eligible outcome and requires the probe's positive clean exit.
    let scoped = fresh_scratch("clean");
    let escape = format!("{}/in-scratch-write", scoped.display());
    let outcome = run_fixture(
        &tools,
        &probe_profile(false, FilesystemScope::Isolated),
        &scoped,
        "filesystem",
        &escape,
    );
    let _ = std::fs::remove_dir_all(&scoped);
    assert_eq!(
        outcome,
        JailOutcome::Clean,
        "a benign in-scratch build must be Clean (the only admit-eligible outcome)"
    );
    assert!(outcome.is_clean());
}

#[test]
fn a_missing_fixture_is_a_non_clean_outcome_fail_closed() {
    let Some(tools) = e2e_tools() else { return };
    // Running a payload that cannot exec (a path that does not exist) must never
    // be Clean — the jail establishes but the payload fails, so the outcome is a
    // non-clean BuildFailed (or the spawn refuses). Fail-closed either way.
    let scoped = fresh_scratch("missing");
    let bound = canonical(&scoped);
    let outcome = {
        let _guard = JAIL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        build_in_jail(
            &tools,
            &SandboxProfile::maximally_isolated(),
            &mounts(&bound),
            &[
                OsString::from("/bin/sh"),
                OsString::from("/nonexistent/probe.sh"),
            ],
        )
    };
    let _ = std::fs::remove_dir_all(&scoped);
    assert!(
        !outcome.is_clean(),
        "a payload that cannot run must never be Clean, got {outcome:?}"
    );
}

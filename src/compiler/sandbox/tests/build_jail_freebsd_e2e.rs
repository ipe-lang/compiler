// End-to-end proof of the FreeBSD returning build jail's differential
// confinement — the Tier-2 observation primitive on FreeBSD, mirroring the
// Linux `build_jail_e2e`.
//
// These are REAL jailed runs (they establish a `jail(8)` and run the admission
// probe fixture under it, then decode the child's exit into a `JailOutcome`), so
// they are gated behind IPE_E2E=1 and only compile on FreeBSD. They drive the
// SAME `build_in_jail` the production Tier-2 reconciler calls.
//
// The red-canary the ADR demands: the probe opens a socket while the
// declared-scoped jail WITHHOLDS `network` → the fixture's wrapper-owned exit
// code 10 decodes to `Denied { axis: Network }` (a differentially-probed axis).
// The jail (established as root inside the vmactions VM) gives the withheld case a
// fresh EMPTY `vnet` (no route → the socket is denied at the kernel) and chroots to
// a read-only nullfs view of the host with only the scratch writable (so an
// out-of-scratch write hits the read-only mount and is denied structurally).

#![cfg(target_os = "freebsd")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use ipe_sandbox::build_jail::{CapabilityAxis, JailOutcome, build_in_jail};
use ipe_sandbox::run_jail::{FilesystemScope, RunJailTools, SandboxProfile};
use ipe_sandbox::{CanonicalPath, JailMounts};

fn fixture_path() -> PathBuf {
    e2e_support::manifest_dir!().join("../../../tests/fixtures/admission/untrusted-build.sh")
}

/// A per-test scratch dir under the system temp root.
fn scratch_dir(tag: &str) -> PathBuf {
    let dir =
        ipe_test_temp::temp_root().join(format!("ipe-build-fb-e2e-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

fn inert_tools() -> RunJailTools {
    RunJailTools {
        bwrap: PathBuf::from("freebsd-native"),
        prlimit: PathBuf::from("freebsd-native"),
        timeout: Some(PathBuf::from("freebsd-native")),
    }
}

/// The declared-scoped probe profile: `subprocess` granted (the probe forks
/// python3 to open a socket / `rm`), the axis under test WITHHELD.
fn probe_profile(network: bool, filesystem: FilesystemScope) -> SandboxProfile {
    SandboxProfile {
        network,
        filesystem,
        subprocess: true,
        ..SandboxProfile::maximally_isolated()
    }
}

fn env_assignment(name: &str, value: &OsStr) -> OsString {
    let mut a = OsString::from(name);
    a.push("=");
    a.push(value);
    a
}

/// Run the admission fixture in `tier2` mode inside a jail scoped to `profile`,
/// exercising exactly `axis`, and return the decoded outcome.
fn run_fixture(
    profile: &SandboxProfile,
    scoped: &Path,
    axis: &str,
    escape_path: &str,
) -> JailOutcome {
    // The fixture must be readable+executable by the unprivileged jail user; copy
    // it into the scratch, which `build_in_jail` chowns to that user. Every path
    // the payload names is the canonical path the jail binds.
    let canonical = CanonicalPath::resolve(scoped).expect("canonical scratch");
    let scoped = canonical.as_path();
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
    let mounts = JailMounts::of_invoker(canonical.clone(), canonical, Vec::new())
        .expect("checked jail mounts");
    build_in_jail(&inert_tools(), profile, &mounts, &payload)
}

#[test]
fn a_socket_under_a_network_withholding_jail_is_denied_naming_network() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scoped = scratch_dir("net-denied");
    let outcome = run_fixture(
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
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scoped = scratch_dir("fs-denied");
    // A path outside the scratch: inside the chroot it lands on the read-only nullfs
    // view of the host, so the write is denied by the mount flag (structural, not a
    // mere permission denial).
    let outcome = run_fixture(
        &probe_profile(false, FilesystemScope::Isolated),
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
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scoped = scratch_dir("clean");
    let escape = format!("{}/in-scratch-write", scoped.display());
    let outcome = run_fixture(
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

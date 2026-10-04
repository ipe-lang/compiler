// End-to-end proof of the Windows returning build jail's differential
// confinement — the Tier-2 observation primitive on Windows, mirroring the
// Linux `build_jail_e2e` and the Windows RUN-jail `run_jail_windows_e2e`.
//
// These are REAL jailed runs (they build a Job Object + AppContainer token and
// CreateProcess a probe under it, then decode the child's exit into a
// `JailOutcome`), so they are gated behind IPE_E2E=1 and only compile on
// Windows. They drive the SAME `build_in_jail` the production Tier-2 reconciler
// calls, so what these assert is exactly what confines a Tier-2 build.
//
// The red-canary the ADR demands: a payload that opens a socket while the
// declared-scoped jail WITHHOLDS `network` must decode to
// `Denied { axis: Network }` — a differentially-probed axis, not a
// subprocess/env one (those decode to BuildFailed, never a named denial). The
// probe emits the wrapper-owned per-axis exit code (10 network / 11 filesystem /
// 0 clean) directly, so the decode reads a wrapper-owned signal, never scraped
// stdout.

#![cfg(target_os = "windows")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use ipe_sandbox::build_jail::{CapabilityAxis, JailOutcome, build_in_jail};
use ipe_sandbox::run_jail::{FilesystemScope, RunJailTools, SandboxProfile};
use ipe_sandbox::{CanonicalPath, JailMounts};

/// A per-test scratch under the process temp dir (NTFS on the hosted image, so
/// the container-SID ACL — and thus the filesystem boundary — is meaningful).
fn scratch_dir(tag: &str) -> PathBuf {
    let dir = ipe_test_temp::temp_root().join(format!(
        "ipe-build-win-e2e-{}-{}",
        tag,
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

fn powershell() -> PathBuf {
    if let Some(path) = ipe_env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("powershell.exe");
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    let root = ipe_env::var_os("SystemRoot").unwrap_or_else(|| OsString::from("C:\\Windows"));
    PathBuf::from(root).join("System32\\WindowsPowerShell\\v1.0\\powershell.exe")
}

/// The declared-scoped probe profile: `subprocess` granted (PowerShell needs to
/// run), the axis under test WITHHELD. The Windows arm reads no `RunJailTools`, so
/// an inert token satisfies the shared signature.
fn probe_profile(network: bool, filesystem: FilesystemScope) -> SandboxProfile {
    SandboxProfile {
        network,
        filesystem,
        subprocess: true,
        ..SandboxProfile::maximally_isolated()
    }
}

fn inert_tools() -> RunJailTools {
    RunJailTools {
        bwrap: PathBuf::from("windows-native"),
        prlimit: PathBuf::from("windows-native"),
        timeout: Some(PathBuf::from("windows-native")),
    }
}

/// Build a payload: `powershell -Command <script>`. The script emits the
/// wrapper-owned per-axis exit code (10 network-denied / 11 fs-denied / 0 clean),
/// so the decode reads a wrapper-owned signal.
fn ps_payload(script: &str) -> Vec<OsString> {
    vec![
        powershell().into_os_string(),
        OsString::from("-NoProfile"),
        OsString::from("-NonInteractive"),
        OsString::from("-Command"),
        OsString::from(script),
    ]
}

fn run(profile: &SandboxProfile, scratch: &Path, script: &str) -> JailOutcome {
    let scratch = CanonicalPath::resolve(scratch).expect("canonical scratch");
    let mounts =
        JailMounts::of_invoker(scratch.clone(), scratch, Vec::new()).expect("checked jail mounts");
    build_in_jail(&inert_tools(), profile, &mounts, &ps_payload(script))
}

// ── the red canary: a withheld-network socket decodes to Denied { network } ───

#[test]
fn a_socket_under_a_network_withholding_jail_decodes_to_denied_network() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scratch = scratch_dir("net-denied");
    // The probe: try an outbound connect. On success (network reachable) it would
    // exit 0; under the network-withholding AppContainer the connect throws, so it
    // emits the wrapper-owned network-denial code 10 → Denied { network }.
    let probe = "try { $c = New-Object System.Net.Sockets.TcpClient; $c.Connect('1.1.1.1', 53); $c.Close(); exit 0 } catch { exit 10 }";
    let outcome = run(
        &probe_profile(false, FilesystemScope::Isolated),
        &scratch,
        probe,
    );
    let _ = std::fs::remove_dir_all(&scratch);
    assert_eq!(
        outcome,
        JailOutcome::Denied {
            axis: CapabilityAxis::Network
        },
        "a network-withholding jail must deny the socket and decode to Denied {{ network }}"
    );
}

// ── an out-of-scratch write under a filesystem-withholding jail ───────────────

#[test]
fn an_out_of_scratch_write_under_a_filesystem_withholding_jail_decodes_to_denied_filesystem() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scratch = scratch_dir("fs-denied");
    // A target OUTSIDE the ACLed scratch: the process temp dir root.
    let outside =
        ipe_test_temp::temp_root().join(format!("ipe-build-fs-outside-{}.txt", std::process::id()));
    let outside_str = outside.to_string_lossy().replace('\'', "''");
    // On a denied write emit the wrapper-owned filesystem-denial code 11.
    let probe = format!(
        "try {{ Set-Content -Path '{outside_str}' -Value 'x' -ErrorAction Stop; exit 0 }} catch {{ exit 11 }}"
    );
    let outcome = run(
        &probe_profile(false, FilesystemScope::Isolated),
        &scratch,
        &probe,
    );
    let _ = std::fs::remove_file(&outside);
    let _ = std::fs::remove_dir_all(&scratch);
    assert_eq!(
        outcome,
        JailOutcome::Denied {
            axis: CapabilityAxis::Filesystem
        },
        "a filesystem-withholding jail must deny the out-of-scratch write and decode to \
         Denied {{ filesystem }}"
    );
}

// ── a benign in-scratch build is Clean (the only admit-eligible outcome) ──────

#[test]
fn a_benign_in_scratch_write_is_clean() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scratch = scratch_dir("clean");
    let inside = scratch.join("ok.txt");
    let inside_str = inside.to_string_lossy().replace('\'', "''");
    // Write inside the ACLed scratch (allowed) and exit 0 → Clean.
    let probe = format!(
        "try {{ Set-Content -Path '{inside_str}' -Value 'ok' -ErrorAction Stop; exit 0 }} catch {{ exit 11 }}"
    );
    let outcome = run(
        &probe_profile(false, FilesystemScope::WorkingTreeReadWrite),
        &scratch,
        &probe,
    );
    let _ = std::fs::remove_dir_all(&scratch);
    assert_eq!(
        outcome,
        JailOutcome::Clean,
        "a benign in-scratch build must be Clean (the only admit-eligible outcome)"
    );
    assert!(outcome.is_clean());
}

// ── a grant covers the whole scratch subtree, not just its root ───────────────

#[test]
fn a_nested_write_then_reopen_in_the_granted_scratch_is_clean() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scratch = scratch_dir("nested");
    let nested = scratch.join("nested");
    let file = nested.join("f.txt");
    let nested_str = nested.to_string_lossy().replace('\'', "''");
    let file_str = file.to_string_lossy().replace('\'', "''");
    // Every entry the child creates must carry the container grant: a directory
    // it makes must accept a file, and a file it wrote must reopen for append and
    // read. A grant on the scratch root alone denies each step (exit 11).
    let probe = format!(
        "try {{ New-Item -ItemType Directory -Path '{nested_str}' -ErrorAction Stop | Out-Null; \
         [IO.File]::WriteAllText('{file_str}', 'one'); \
         [IO.File]::AppendAllText('{file_str}', 'two'); \
         if ([IO.File]::ReadAllText('{file_str}') -ne 'onetwo') {{ exit 11 }}; exit 0 }} \
         catch {{ exit 11 }}"
    );
    let outcome = run(
        &probe_profile(false, FilesystemScope::Isolated),
        &scratch,
        &probe,
    );
    let _ = std::fs::remove_dir_all(&scratch);
    assert_eq!(
        outcome,
        JailOutcome::Clean,
        "a nested create, reopen and read inside the scratch must be Clean"
    );
}

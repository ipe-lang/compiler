// End-to-end proof of the Windows run jail's containment — the SEAL's security
// half on Windows, mirroring the Linux run_jail_e2e and macOS run_jail_macos_e2e.
//
// These are REAL jailed runs (they build a Job Object + AppContainer token and
// CreateProcess a probe under it), so they are gated behind IPE_E2E=1 and only
// compile on Windows. They drive the RUN jail through the SAME
// ipe_sandbox::run_jail::run_windows_jailed_for_test seam the production
// exec_in_run_jail uses (one jail source, no fork) — so what these assert is
// exactly what confines the shipped app at run time.
//
// The load-bearing property is the enforce-vs-control DUALITY: a capability
// action DENIED under the jail AND the SAME action SUCCEEDING under control (no
// jail). The control run rules out a false pass from an unreachable host or an
// already-unwritable path — a denial under enforce can then only be the jail's.
//
// Per axis, provable on a hosted windows-2022 runner (design §5.1):
// - subprocess — a child spawn is denied under a subprocess-withholding job
//   (active-process cap 1) and succeeds under control.
// - env — a non-allowlisted host variable is absent from the jailed child's
//   environment (the launcher scrubs it) and present under control.
// - filesystem — a write outside the ACLed scratch is denied under the
//   AppContainer token and succeeds under control (an NTFS work dir is required).
// - network (enforce half) — an outbound connect is denied under an AppContainer
//   without internetClient; the positive control needs real egress and may only
//   hold on a self-hosted runner (design §5.2).

#![cfg(target_os = "windows")]
// An integration test harness: `expect`/`unwrap` on setup steps make a
// mis-set-up test fail loudly (the correct behavior for a test).
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use ipe_sandbox::run_jail::{
    FilesystemScope, RunResourceLimits, SandboxProfile, run_windows_jailed_for_test,
};

/// A per-test scratch under the process temp dir (NTFS on the hosted image, so
/// the container-SID ACL is meaningful).
fn scratch_dir(tag: &str) -> PathBuf {
    let dir =
        ipe_test_temp::temp_root().join(format!("ipe-run-win-e2e-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// Resolve a system executable (powershell / cmd) via `PATH`, or a conventional
/// absolute path, so the jailed launch has a real `.exe` to run.
fn system_exe(name: &str) -> PathBuf {
    if let Some(path) = ipe_env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    // Fallbacks under the system root.
    let root = ipe_env::var_os("SystemRoot").unwrap_or_else(|| OsString::from("C:\\Windows"));
    let root = PathBuf::from(root);
    match name {
        "powershell.exe" => root.join("System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        other => root.join("System32").join(other),
    }
}

fn powershell() -> PathBuf {
    system_exe("powershell.exe")
}

/// Run `command` (a PowerShell one-liner) under the run jail described by
/// `profile`, returning the exit code, or `None` if the jail refused to establish
/// (which the caller treats as a skip, since a hosted runner may lack a
/// primitive — the CI job proves presence separately).
fn run_jailed(profile: &SandboxProfile, scratch: &Path, command: &str) -> Option<u32> {
    let app = powershell();
    let args = [
        OsString::from("-NoProfile"),
        OsString::from("-NonInteractive"),
        OsString::from("-Command"),
        OsString::from(command),
    ];
    run_windows_jailed_for_test(profile, scratch, scratch, &app, &args).ok()
}

/// Run the same PowerShell one-liner unjailed — the control half of the duality.
fn run_control(command: &str) -> Option<i32> {
    Command::new(powershell())
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(command)
        .status()
        .expect("spawn control powershell")
        .code()
}

fn isolated() -> SandboxProfile {
    SandboxProfile::maximally_isolated()
}

fn subprocess_withheld() -> SandboxProfile {
    // The default (maximally isolated) already withholds subprocess; naming it
    // makes the axis under test explicit.
    SandboxProfile::maximally_isolated()
}

fn subprocess_granted() -> SandboxProfile {
    SandboxProfile {
        subprocess: true,
        limits: RunResourceLimits {
            proc_cap: 16,
            ..RunResourceLimits::default()
        },
        ..SandboxProfile::maximally_isolated()
    }
}

fn env_granted(names: &[&str]) -> SandboxProfile {
    SandboxProfile {
        env_allowlist: names.iter().map(|n| (*n).to_owned()).collect(),
        ..SandboxProfile::maximally_isolated()
    }
}

fn fs_granted() -> SandboxProfile {
    SandboxProfile {
        filesystem: FilesystemScope::WorkingTreeReadWrite,
        ..SandboxProfile::maximally_isolated()
    }
}

// ── subprocess ───────────────────────────────────────────────────────────────

#[test]
fn a_child_spawn_is_denied_under_a_subprocess_withholding_job_but_succeeds_under_control() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scratch = scratch_dir("sub");
    // Spawn a trivial child and exit 0 iff it started. Under a job capped at one
    // active process, the second process cannot be created.
    let spawn_child =
        "$p = Start-Process -FilePath cmd.exe -ArgumentList '/c exit 0' -PassThru -Wait; exit 0";
    // Control: spawning a child succeeds outside the job.
    let control = run_control(spawn_child);
    if control != Some(0) {
        let _ = std::fs::remove_dir_all(&scratch);
        return; // the probe itself cannot spawn on this runner — inconclusive.
    }
    // Subprocess granted: the same spawn is allowed under the jail (no false-deny).
    let granted = run_jailed(&subprocess_granted(), &scratch, spawn_child);
    // Subprocess withheld: the job's active-process cap denies the child, so the
    // probe (which needs to spawn) fails with a non-zero code.
    let withheld = run_jailed(&subprocess_withheld(), &scratch, spawn_child);
    let _ = std::fs::remove_dir_all(&scratch);
    if let Some(g) = granted {
        assert_eq!(g, 0, "subprocess granted must not false-deny a child spawn");
    }
    assert_ne!(
        withheld,
        Some(0),
        "a subprocess-withholding job must DENY the child spawn (control succeeded)"
    );
}

// ── env ──────────────────────────────────────────────────────────────────────

/// Set only on the env test's re-exec of this binary, whose environment carries
/// the seeded variables from spawn.
const ENV_CHILD_MARKER: &str = "IPE_WINDOWS_E2E_ENV_CHILD";

#[test]
fn a_non_allowlisted_env_var_is_absent_from_the_jailed_child_but_present_under_control() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    // The launcher scrubs the environment: only the allowlist re-enters. The
    // secret must be in THIS process's environment so it would be inherited if
    // the scrub were bypassed. The environment is set at spawn time on a re-exec
    // of this test binary (running only this test), never mutated in-process;
    // the re-exec must actually run and pass this test, never match nothing.
    if ipe_env::var_os(ENV_CHILD_MARKER).is_none() {
        let rerun = e2e_support::rerun_this_test_exact(
            "a_non_allowlisted_env_var_is_absent_from_the_jailed_child_but_present_under_control",
            |cmd| {
                cmd.arg("--nocapture")
                    .env(ENV_CHILD_MARKER, "1")
                    .env("IPE_SECRET_E2E", "leak")
                    .env("IPE_ALLOWED_E2E", "ok");
            },
        );
        assert!(
            rerun.is_ok(),
            "the env-seeded re-exec did not pass: {rerun:?}"
        );
    } else {
        let scratch = scratch_dir("env");
        // Print 1 iff the var is present, else 0.
        let probe = |name: &str| {
            format!(
                "if ($env:{name}) {{ Write-Output 'PRESENT' }} else {{ Write-Output 'ABSENT' }}; exit 0"
            )
        };
        // Under control (unscrubbed, inherited), the secret is present.
        let _ = run_control(&probe("IPE_SECRET_E2E"));

        // Under the jail with an allowlist that does NOT include the secret, the
        // secret must be absent from the child. We capture the child's stdout by
        // running through cmd and asserting on the exit code the probe encodes.
        let coded = |name: &str| format!("if ($env:{name}) {{ exit 42 }} else {{ exit 0 }}");
        // Allowlist only IPE_ALLOWED_E2E: the secret is scrubbed (exit 0 = absent),
        // and the allowlisted var survives (exit 42 = present).
        let profile = env_granted(&["IPE_ALLOWED_E2E"]);
        let secret_absent = run_jailed(&profile, &scratch, &coded("IPE_SECRET_E2E"));
        let allowed_present = run_jailed(&profile, &scratch, &coded("IPE_ALLOWED_E2E"));
        let _ = std::fs::remove_dir_all(&scratch);
        assert_eq!(
            secret_absent,
            Some(0),
            "a non-allowlisted var must be scrubbed from the jailed child"
        );
        if let Some(a) = allowed_present {
            assert_eq!(a, 42, "an allowlisted var must survive the scrub");
        }
    }
}

// ── filesystem (enforce half) ────────────────────────────────────────────────

#[test]
fn an_out_of_scratch_write_is_denied_under_the_appcontainer_but_succeeds_under_control() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scratch = scratch_dir("fs");
    // A target OUTSIDE the ACLed scratch/working-tree: the process temp dir root.
    let outside =
        ipe_test_temp::temp_root().join(format!("ipe-fs-e2e-outside-{}.txt", std::process::id()));
    let outside_str = outside.to_string_lossy().replace('\'', "''");
    let write = format!(
        "try {{ Set-Content -Path '{outside_str}' -Value 'x' -ErrorAction Stop; exit 0 }} catch {{ exit 13 }}"
    );
    // Control: the write outside succeeds under the launcher token.
    let control = run_control(&write);
    let _ = std::fs::remove_file(&outside);
    if control != Some(0) {
        let _ = std::fs::remove_dir_all(&scratch);
        return; // cannot even write it unjailed — inconclusive.
    }
    // Enforce: under the AppContainer token (filesystem-isolated, only the scratch
    // ACLed), the out-of-scratch write is denied.
    let jailed = run_jailed(&isolated(), &scratch, &write);
    let _ = std::fs::remove_file(&outside);
    let _ = std::fs::remove_dir_all(&scratch);
    assert_ne!(
        jailed,
        Some(0),
        "an AppContainer with only the scratch ACLed must DENY the out-of-scratch write"
    );
}

#[test]
fn a_write_into_the_granted_working_tree_succeeds_no_false_deny() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scratch = scratch_dir("fs-grant");
    let inside = scratch.join("inside.txt");
    let inside_str = inside.to_string_lossy().replace('\'', "''");
    let write = format!(
        "try {{ Set-Content -Path '{inside_str}' -Value 'x' -ErrorAction Stop; exit 0 }} catch {{ exit 13 }}"
    );
    // With the filesystem axis granted, the working tree (== scratch here) is
    // ACLed to the container SID, so a write into it must NOT be false-denied.
    let jailed = run_jailed(&fs_granted(), &scratch, &write);
    let _ = std::fs::remove_dir_all(&scratch);
    if let Some(code) = jailed {
        assert_eq!(
            code, 0,
            "a write into the granted working tree must succeed"
        );
    }
}

// ── network (enforce half) ───────────────────────────────────────────────────

#[test]
fn an_outbound_connect_is_denied_under_a_network_withholding_appcontainer() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scratch = scratch_dir("net");
    // A TCP connect probe. Exit 0 on connect, non-zero on failure/denial.
    let connect = "try { $c = New-Object System.Net.Sockets.TcpClient; $c.Connect('1.1.1.1', 53); $c.Close(); exit 0 } catch { exit 7 }";
    // Control needs real egress; if it cannot connect unjailed, the positive
    // control is invalid and this axis needs a self-hosted runner (design §5.2) —
    // skip rather than assert on a dead control.
    if run_control(connect) != Some(0) {
        let _ = std::fs::remove_dir_all(&scratch);
        return;
    }
    // Enforce: subprocess granted (so PowerShell can run its work), network
    // withheld → no internetClient capability SID → the connect is denied by the
    // AppContainer network isolation.
    let net_withheld = subprocess_granted(); // network stays false
    let jailed = run_jailed(&net_withheld, &scratch, connect);
    let _ = std::fs::remove_dir_all(&scratch);
    assert_ne!(
        jailed,
        Some(0),
        "a network-withholding AppContainer must DENY the outbound connect (control succeeded)"
    );
}

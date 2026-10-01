//! End-to-end proof of the macOS run jail's Seatbelt containment — the SEAL's
//! security half on macOS, mirroring the Linux `run_jail_e2e`.
//!
//! These are REAL jailed runs (they spawn `sandbox-exec`), so they are gated
//! behind `IPE_E2E=1` and only compile on macOS. They drive the RUN jail through
//! the SAME [`ipe_sandbox::build_jail::sbpl_from_profile`] the production
//! `exec_in_run_jail` macOS arm uses — there is ONE SBPL source, so what these
//! assert is exactly what confines the shipped app at run time.
//!
//! The load-bearing property is the enforce-vs-control DUALITY: a
//! capability action DENIED under the jail AND the SAME action SUCCEEDING under
//! control (no jail). The control run rules out a false pass from an unreachable
//! host or an already-unwritable path — a denial under enforce can then only be
//! the jail's.
//!
//! - **Fail-closed on the undeclared.** A network connect and an out-of-scratch
//!   write from a maximally-isolated (network- and filesystem-absent) jail are
//!   both denied by the SBPL; a subprocess spawn is denied by the SBPL's
//!   process-creation deny; a non-allowlisted env var is absent from the child
//!   because the launcher scrubs the environment (Seatbelt cannot).
//! - **No false-deny.** The same network connect from a network-GRANTED jail is
//!   not denied; a write into the always-writable scratch succeeds under any
//!   profile.
//!
//! The env axis is enforced by the LAUNCHER, not the SBPL (Seatbelt cannot scrub
//! env), so the jailed runner here applies the SAME
//! [`ipe_sandbox::build_jail::macos_scrubbed_env`] the production
//! `exec_in_run_jail` launcher applies — env is proven the same single-sourced
//! way the SBPL axes are.

#![cfg(target_os = "macos")]
// This is an integration test harness: `expect`/`unwrap` on setup steps make a
// mis-set-up test fail loudly (the correct behavior for a test).
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::Path;
use std::process::Command;

use ipe_sandbox::build_jail::{macos_scrubbed_env, sbpl_from_profile};
use ipe_sandbox::run_jail::SandboxProfile;

fn which_sandbox_exec() -> Option<std::path::PathBuf> {
    let path = ipe_env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("sandbox-exec"))
        .find(|candidate| candidate.is_file())
}

/// Run `sandbox-exec -p <sbpl> sh -c <script>` under the profile's SBPL,
/// returning the exit code (`None` if signalled).
///
/// The environment is scrubbed with the SAME `macos_scrubbed_env` the production
/// `exec_in_run_jail` launcher applies (Seatbelt cannot scrub env, so it is a
/// launcher contract) — so what this jailed runner confines on the env axis is
/// exactly what the shipped app runs under. `host` provides the inherited host
/// environment the scrub filters (the `env` axis's input).
fn run_jailed_with_host(
    profile: &SandboxProfile,
    scratch: &Path,
    script: &str,
    host: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<i32> {
    let sbpl = sbpl_from_profile(profile, scratch, scratch);
    let sandbox_exec = which_sandbox_exec().expect("sandbox-exec present");
    let mut cmd = Command::new(sandbox_exec);
    cmd.arg("-p").arg(&sbpl).arg("sh").arg("-c").arg(script);
    cmd.env_clear();
    for (name, value) in macos_scrubbed_env(profile, scratch, host) {
        cmd.env(name, value);
    }
    cmd.status().expect("spawn sandbox-exec").code()
}

/// The common case: scrub against the real process environment (what a user's
/// `ipe run` inherits). The oracle reads through `ipe_env`, which matches the
/// launcher's crate-private passthrough for every name but a home variable; no
/// profile in this file grants one, so the scrub is the launcher's.
fn run_jailed(profile: &SandboxProfile, scratch: &Path, script: &str) -> Option<i32> {
    let host = |k: &str| ipe_env::var_os(k);
    run_jailed_with_host(profile, scratch, script, &host)
}

/// Run the same script unjailed — the control half of the duality.
fn run_control(script: &str) -> Option<i32> {
    Command::new("sh")
        .arg("-c")
        .arg(script)
        .status()
        .expect("spawn control")
        .code()
}

fn scratch_dir() -> std::path::PathBuf {
    let dir = ipe_test_temp::temp_root().join(format!("ipe-run-macos-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

fn isolated() -> SandboxProfile {
    SandboxProfile::maximally_isolated()
}

// Subprocess is granted alongside network because the network probe runs the
// external `nc` binary, which must `exec`; network is the axis this profile
// proves, so subprocess is held constant (granted) across enforce and control.
fn net_granted() -> SandboxProfile {
    SandboxProfile {
        network: true,
        subprocess: true,
        ..SandboxProfile::maximally_isolated()
    }
}

fn subprocess_granted() -> SandboxProfile {
    SandboxProfile {
        subprocess: true,
        ..SandboxProfile::maximally_isolated()
    }
}

fn env_granted(names: &[&str]) -> SandboxProfile {
    SandboxProfile {
        env_allowlist: names.iter().map(|n| (*n).to_owned()).collect(),
        ..SandboxProfile::maximally_isolated()
    }
}

#[test]
fn undeclared_network_is_denied_under_the_run_jail_but_succeeds_under_control() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scratch = scratch_dir();
    // A TCP connect to a public resolver. `nc -z` returns non-zero when the
    // socket is denied. The control must succeed (proving the host has a route)
    // or the test is inconclusive and skips.
    let connect = "nc -z -G 5 1.1.1.1 53";
    if run_control(connect) != Some(0) {
        let _ = std::fs::remove_dir_all(&scratch);
        return; // no outbound route on this runner — nothing to prove.
    }
    // Subprocess is granted so the external `nc` probe can fork+exec; network is
    // the only withheld axis, so a denied connect is attributable to the network
    // rule (not to the subprocess fork denial).
    let net_withheld = SandboxProfile {
        subprocess: true,
        ..SandboxProfile::maximally_isolated()
    };
    let jailed = run_jailed(&net_withheld, &scratch, connect);
    let _ = std::fs::remove_dir_all(&scratch);
    assert_ne!(
        jailed,
        Some(0),
        "a network-withholding run jail must DENY the connect (control succeeded)"
    );
}

#[test]
fn declared_network_reaches_the_network_under_the_run_jail() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scratch = scratch_dir();
    let connect = "nc -z -G 5 1.1.1.1 53";
    if run_control(connect) != Some(0) {
        let _ = std::fs::remove_dir_all(&scratch);
        return;
    }
    let jailed = run_jailed(&net_granted(), &scratch, connect);
    let _ = std::fs::remove_dir_all(&scratch);
    assert_eq!(
        jailed,
        Some(0),
        "a network-granted run jail must reach the network (no false-deny)"
    );
}

#[test]
fn an_out_of_scratch_write_is_denied_under_the_run_jail_but_succeeds_under_control() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scratch = scratch_dir();
    // The escape target is a sibling of the scratch, NOT under it — the SBPL's
    // blanket file-write* denial withholds it under a filesystem-absent profile.
    let escape = scratch.with_extension("escape-probe");
    let escape_disp = escape.display();
    let write_escape = format!("echo x > '{escape_disp}'");
    // Control: the same write must succeed unjailed (proving the path is writable
    // and the denial under enforce is the jail's, not a pre-unwritable path).
    let control = run_control(&write_escape);
    let _ = std::fs::remove_file(&escape);
    if control != Some(0) {
        let _ = std::fs::remove_dir_all(&scratch);
        return;
    }
    let jailed = run_jailed(&isolated(), &scratch, &write_escape);
    let _ = std::fs::remove_file(&escape);
    let _ = std::fs::remove_dir_all(&scratch);
    assert_ne!(
        jailed,
        Some(0),
        "a filesystem-withholding run jail must DENY an out-of-scratch write (control succeeded)"
    );
}

#[test]
fn an_in_scratch_write_succeeds_under_the_run_jail() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scratch = scratch_dir();
    let inside = scratch.join("ok.txt");
    let inside_disp = inside.display();
    let jailed = run_jailed(&isolated(), &scratch, &format!("echo x > '{inside_disp}'"));
    let _ = std::fs::remove_dir_all(&scratch);
    assert_eq!(
        jailed,
        Some(0),
        "a write into the always-writable scratch must succeed (no false-deny)"
    );
}

// ── the subprocess axis (SBPL process-creation denial) ────────────────────────

/// Spawn a child process (an external `/usr/bin/true`, NOT a shell builtin, so it
/// forks+execs and exercises the `process-fork` deny). `command -v` resolves it
/// via the scrubbed `/usr/bin:/bin` PATH; the payload runs it and reports its
/// exit through the shell's own exit code.
const SPAWN_CHILD: &str = "exec_target=$(command -v true); \"$exec_target\"";

#[test]
fn undeclared_subprocess_spawn_is_denied_under_the_run_jail_but_succeeds_under_control() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scratch = scratch_dir();
    // Control: spawning the external child must succeed unjailed (proving the
    // binary is present and executable, so a denial under enforce is the jail's).
    if run_control(SPAWN_CHILD) != Some(0) {
        let _ = std::fs::remove_dir_all(&scratch);
        return; // no external `true` on this runner — nothing to prove.
    }
    // Under a subprocess-WITHHOLDING jail the exec/fork is denied, so the spawn
    // fails: the shell's exit code is non-zero. A silently-permissive profile
    // (one that emitted no process denial) would let the child run and this
    // assertion would FAIL — exactly the regression guard the blocker requires.
    let jailed = run_jailed(&isolated(), &scratch, SPAWN_CHILD);
    let _ = std::fs::remove_dir_all(&scratch);
    assert_ne!(
        jailed,
        Some(0),
        "a subprocess-withholding run jail must DENY the child spawn (control succeeded)"
    );
}

#[test]
fn declared_subprocess_spawn_succeeds_under_the_run_jail() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scratch = scratch_dir();
    if run_control(SPAWN_CHILD) != Some(0) {
        let _ = std::fs::remove_dir_all(&scratch);
        return;
    }
    // A subprocess-GRANTED jail emits no process denial, so the child spawns
    // (no false-deny of a granted axis).
    let jailed = run_jailed(&subprocess_granted(), &scratch, SPAWN_CHILD);
    let _ = std::fs::remove_dir_all(&scratch);
    assert_eq!(
        jailed,
        Some(0),
        "a subprocess-granted run jail must allow the child spawn (no false-deny)"
    );
}

// ── the env axis (launcher scrub — Seatbelt cannot) ───────────────────────────

/// Exit 0 iff `$IPE_E2E_SECRET` is set and non-empty. The child observes only the
/// scrubbed environment the launcher hands `sandbox-exec`.
const SECRET_PRESENT: &str = "test -n \"${IPE_E2E_SECRET-}\"";

#[test]
fn a_non_allowlisted_env_var_is_absent_under_the_run_jail_but_present_under_control() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scratch = scratch_dir();
    // The host sets IPE_E2E_SECRET, but the maximally-isolated profile grants no
    // env axis, so the launcher scrub drops it: the child must NOT see it.
    let host = |k: &str| match k {
        "IPE_E2E_SECRET" => Some(std::ffi::OsString::from("leak")),
        _ => ipe_env::var_os(k),
    };
    let jailed = run_jailed_with_host(&isolated(), &scratch, SECRET_PRESENT, &host);
    // Control: with the same var in the environment, the child DOES see it —
    // proving the absence under enforce is the scrub's, not a missing var.
    let control = Command::new("sh")
        .arg("-c")
        .arg(SECRET_PRESENT)
        .env("IPE_E2E_SECRET", "leak")
        .status()
        .expect("spawn control")
        .code();
    let _ = std::fs::remove_dir_all(&scratch);
    assert_eq!(
        control,
        Some(0),
        "control must see the host var (else the test is inconclusive)"
    );
    assert_ne!(
        jailed,
        Some(0),
        "a non-allowlisted env var must be absent under the run jail (control saw it)"
    );
}

#[test]
fn an_allowlisted_env_var_is_present_under_the_run_jail() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scratch = scratch_dir();
    // The profile grants the env axis for IPE_E2E_SECRET, so the launcher
    // re-exports it: the child DOES see it (no false-deny of a granted name).
    let host = |k: &str| match k {
        "IPE_E2E_SECRET" => Some(std::ffi::OsString::from("allowed")),
        _ => ipe_env::var_os(k),
    };
    let jailed = run_jailed_with_host(
        &env_granted(&["IPE_E2E_SECRET"]),
        &scratch,
        SECRET_PRESENT,
        &host,
    );
    let _ = std::fs::remove_dir_all(&scratch);
    assert_eq!(
        jailed,
        Some(0),
        "an allowlisted env var must be present under the run jail (no false-deny)"
    );
}

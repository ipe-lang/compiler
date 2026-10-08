//! End-to-end proof of the run jail's OS-boundary containment — the SEAL's
//! security half.
//!
//! These are REAL jailed runs (they spawn `bwrap`), so they are gated behind
//! `IPE_E2E=1` and skip cleanly when the jail cannot run here — either because
//! bubblewrap or the cap helpers are absent, or because the environment forbids
//! establishing the jail at all (a container/CI runner where `bwrap` is present
//! but the kernel denies the network namespace or loopback bring-up). A ONE-time
//! canary establishment run (a trivial `/bin/true` under the most-isolated
//! profile) decides this: if the jail cannot even boot a no-op payload, no
//! assertion below could hold, so every test early-returns exactly as it does
//! when the tools are missing.
//! They prove the two load-bearing properties directly at the kernel boundary,
//! not by the app's own choice:
//!
//! - **Fail-closed on the undeclared.** A network connect from an isolated
//!   (network-absent) jail fails — the fresh empty net namespace has no route
//!   off-host. A `fork`/subprocess from a subprocess-absent jail is EPERM'd by
//!   the seccomp filter.
//! - **No false-deny.** A thread-spawning program boots under the isolated jail
//!   (the seccomp filter allows the thread-create path), and a network connect
//!   from a network-GRANTED jail is not blocked by the namespace.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
// This is an integration test harness: `expect`/`unwrap` on setup steps make a
// mis-set-up test fail loudly (the correct behavior for a test), and the raw
// FFI + slice handling mirror the production `run_jail` glue it exercises.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::redundant_closure_for_method_calls,
    clippy::map_unwrap_or
)]

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use ipe_sandbox::run_jail::{
    CanaryExit, FilesystemScope, ProcCap, RunJailDefect, RunJailTools, RunResourceLimits,
    SCOPE_SCRIPT, SandboxProfile, Scope, TEETH_SCRIPT, classify, prove, run_jail_argv,
};
use ipe_sandbox::{CanonicalPath, JailMounts};

/// Serialize the jailed runs: each creates an inheritable `memfd`, which is a
/// process-global fd-table mutation — running two in parallel races on fd
/// numbers. A single lock makes the whole harness deterministic regardless of
/// `--test-threads`.
static JAIL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Skip unless `IPE_E2E=1`, the jail tools are present, AND a jail can actually
/// be established in this environment.
///
/// Tool presence alone is not enough: on some CI runners and containers `bwrap`
/// is installed but the kernel denies the namespace/loopback setup a real jail
/// needs (`bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`). There
/// the tests could not pass no matter how correct the jail is, so they must skip.
/// The [`jail_can_establish`] canary settles this once.
fn e2e_tools() -> Option<RunJailTools> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return None;
    }
    let caps = ipe_sandbox::probe();
    let bwrap = caps.bwrap?;
    let prlimit = caps.prlimit?;
    let tools = RunJailTools {
        bwrap,
        prlimit,
        timeout: caps.timeout,
    };
    // The proof's canaries spawn children, so they run under the lock that
    // keeps every inheritable memfd to its one jail.
    let proven = {
        let _guard = JAIL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        prove(&tools)
    };
    // A host whose jail can boot but whose cap counts the whole user (or no
    // one) is exactly the host production refuses: a real failure here.
    assert!(
        !matches!(proven, Err(RunJailDefect::ProcCapUnscoped { .. })),
        "the jail's process cap is not scoped to the jail on this host: {proven:?}"
    );
    if let Err(defect) = proven {
        eprintln!(
            "run_jail_e2e: skipping — the process-cap canary jail cannot run here: {defect:?}"
        );
        return None;
    }
    if !jail_can_establish(&tools) {
        return None;
    }
    Some(tools)
}

/// Whether a real jail can be *established* in this environment — a one-time,
/// cached canary establishment run.
///
/// It jails `/bin/true` under the most-isolated profile (the same
/// `--unshare-net` + scoped-fs setup the assertions use, and the one that fails
/// on a locked-down runner). `/bin/true` cannot itself misbehave, so the outcome
/// isolates the *establishment* step from any payload behavior:
///
/// - jail established → `/bin/true` exits 0 → the environment can run the jail.
/// - jail could not be established (bwrap fails to set up the namespace/loopback,
///   e.g. `RTM_NEWADDR: Operation not permitted`, an `unshare` `EPERM`, or any
///   other setup denial) → `/bin/true` never runs, the exit is non-zero, and
///   `bwrap` names the failure on stderr → the environment cannot run the jail.
///
/// Only an establishment failure gates skipping; a *successful* canary lets the
/// real assertions run and catch a genuine jail bug. This is inert on the
/// production path — it lives in the test harness and never touches how
/// `ipe dev run` / `ipe release run` decide to refuse.
fn jail_can_establish(tools: &RunJailTools) -> bool {
    static CANARY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CANARY.get_or_init(|| {
        let payload = vec![OsString::from("/bin/true")];
        let outcome = run_jailed_capturing(tools, &isolated(), &payload);
        let established = canary_established(&outcome);
        if !established {
            eprintln!(
                "run_jail_e2e: skipping — the jail cannot be established here (bwrap exited {:?}; stderr: {})",
                outcome.code,
                outcome.stderr.trim()
            );
        }
        established
    })
}

/// The canary's establish-vs-skip decision, factored out so it is unit-testable
/// without a broken environment: a no-op `/bin/true` payload proves the jail
/// established if and only if it exits 0. Every other outcome (a signalled
/// payload, or a non-zero `bwrap` setup exit) is an establishment failure this
/// environment cannot run.
fn canary_established(outcome: &Outcome) -> bool {
    outcome.code == Some(0)
}

/// The result of one jailed spawn: the payload's exit code (`None` if it was
/// signalled) and `bwrap`'s stderr. The assertions only read `code`; the canary
/// reads `stderr` to name an establishment failure.
struct Outcome {
    code: Option<i32>,
    stderr: String,
}

/// Compile the seccomp program for a profile and place it on an inheritable fd,
/// then build + run the jail argv for `payload`, returning the exit status code.
///
/// This mirrors `exec_in_run_jail` but *spawns* (waits) instead of `exec`-ing,
/// so the test can assert on the outcome. The seccomp fd is created with
/// `memfd_create` and its close-on-exec flag cleared so `bwrap` inherits it.
fn run_jailed(tools: &RunJailTools, profile: &SandboxProfile, payload: &[OsString]) -> Option<i32> {
    // The assertions inherit stderr (a diagnostic when one fails); only the
    // canary captures it.
    run_jailed_inner(tools, profile, None, payload, false, |_| {}).code
}

/// Like [`run_jailed`], with `tree` bound as the working tree instead of the
/// scratch.
fn run_jailed_in_tree(
    tools: &RunJailTools,
    profile: &SandboxProfile,
    tree: &Path,
    payload: &[OsString],
) -> Option<i32> {
    run_jailed_inner(tools, profile, Some(tree), payload, false, |_| {}).code
}

/// Like [`run_jailed`], but captures `bwrap`'s stderr so an establishment
/// failure can be named. Used only by the canary.
fn run_jailed_capturing(
    tools: &RunJailTools,
    profile: &SandboxProfile,
    payload: &[OsString],
) -> Outcome {
    run_jailed_inner(tools, profile, None, payload, true, |_| {})
}

/// Shared spawn core. `capture_stderr` selects whether `bwrap`'s stderr is piped
/// (canary) or inherited (assertions). The working tree is `tree`, else the
/// scratch. `after` inspects the host side of the scoped scratch once the jail
/// has exited, before it is removed. Panics (fails the test) if the spawn itself
/// could not be launched.
fn run_jailed_inner(
    tools: &RunJailTools,
    profile: &SandboxProfile,
    tree: Option<&Path>,
    payload: &[OsString],
    capture_stderr: bool,
    after: impl FnOnce(&Path),
) -> Outcome {
    // Hold the global lock across the whole spawn — the memfd + cloexec-clear is
    // a process-wide fd-table mutation.
    let _guard = JAIL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let program = ipe_sandbox::seccomp::subprocess_deny_program(profile.subprocess)
        .expect("x86_64 seccomp program");
    let bytes = ipe_sandbox::seccomp::program_bytes(&program);

    // memfd for the seccomp program, through the launcher's own safe writer.
    let seccomp = ipe_sandbox::run_jail::write_seccomp_memfd(&bytes).expect("seccomp memfd");
    let fd = seccomp.make_inheritable().expect("seccomp fd inheritable");

    let scoped = ipe_test_temp::temp_root().join(format!("ipe-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&scoped).expect("scoped tmp");
    let scoped = CanonicalPath::resolve(&scoped).expect("scoped tmp resolves");
    let system_bins = [Path::new("/usr/bin"), Path::new("/bin")]
        .map(|dir| CanonicalPath::resolve(dir).expect("system bin dir resolves"));
    let working_tree = tree.map_or_else(
        || scoped.clone(),
        |tree| CanonicalPath::resolve(tree).expect("working tree resolves"),
    );
    let mounts = JailMounts::of_invoker(scoped.clone(), working_tree, system_bins.to_vec())
        .expect("checked jail mounts");
    // `ipe_env` matches the launcher's crate-private passthrough for every name
    // but a home variable, and no profile in this file grants one.
    let host_env = |k: &str| ipe_env::var_os(k);
    let scope = prove(tools).expect("the process cap is proven scoped to the jail");
    let argv = run_jail_argv(&scope, profile, &mounts, Some(fd), &host_env, payload)
        .expect("the argv builds");
    let (prog, rest) = argv.args().split_first().expect("non-empty argv");
    let mut cmd = Command::new(prog);
    cmd.args(rest);
    if capture_stderr {
        cmd.stderr(std::process::Stdio::piped());
    }
    let out = cmd.output().expect("spawn jailed process");
    // Reap the memfd.
    drop(seccomp);
    after(scoped.as_path());
    let _ = std::fs::remove_dir_all(&scoped);
    Outcome {
        code: out.status.code(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A working tree holding a `.git` dir with a `HEAD` and a `hooks` dir, under
/// the test temp root; removed by the caller.
fn git_tree(label: &str) -> std::path::PathBuf {
    let base = ipe_test_temp::temp_root().join(format!("ipe-e2e-{label}-{}", std::process::id()));
    let hooks = base.join(".git").join("hooks");
    std::fs::create_dir_all(&hooks).expect("git hooks dir");
    std::fs::write(base.join(".git").join("HEAD"), "ref: refs/heads/main\n").expect("HEAD");
    base
}

fn tree_granted() -> SandboxProfile {
    SandboxProfile {
        filesystem: FilesystemScope::WorkingTreeReadWrite,
        ..SandboxProfile::maximally_isolated()
    }
}

#[test]
fn a_jailed_write_to_git_hooks_is_refused() {
    let Some(tools) = e2e_tools() else { return };
    let tree = git_tree("vcs-hooks");
    let hook = tree.join(".git").join("hooks").join("pre-commit");
    let source = tree.join("main.rs");
    // A builtin `echo` with a redirect: the shell writes without forking.
    let write = |path: &Path| -> Vec<OsString> {
        vec![
            OsString::from("/bin/bash"),
            OsString::from("-c"),
            OsString::from(format!("echo pwned > '{}'", path.display())),
        ]
    };
    let hook_code = run_jailed_in_tree(&tools, &tree_granted(), &tree, &write(&hook));
    let source_code = run_jailed_in_tree(&tools, &tree_granted(), &tree, &write(&source));
    let hook_written = hook.exists();
    let source_written = source.exists();
    let _ = std::fs::remove_dir_all(&tree);
    assert_eq!(
        source_code,
        Some(0),
        "the rest of a granted tree stays writable (no false-deny)"
    );
    assert!(source_written, "the control write landed on the host");
    assert_ne!(
        hook_code,
        Some(0),
        "a jailed write into .git/hooks must fail (read-only carve)"
    );
    assert!(!hook_written, "no hook reached the host");
}

#[test]
fn a_jailed_git_status_still_reads_the_repo() {
    let Some(tools) = e2e_tools() else { return };
    let tree = git_tree("vcs-read");
    let payload = vec![
        OsString::from("/bin/cat"),
        tree.join(".git").join("HEAD").into_os_string(),
    ];
    let code = run_jailed_in_tree(&tools, &tree_granted(), &tree, &payload);
    let _ = std::fs::remove_dir_all(&tree);
    assert_eq!(
        code,
        Some(0),
        "the carve is read-only, never hidden: the repo stays readable"
    );
}

#[test]
fn nested_carve_ancestor_rename_refused() {
    let Some(tools) = e2e_tools() else { return };
    let tree = std::fs::canonicalize(git_tree("vcs-pins")).expect("tree resolves");
    let store = tree.join("store");
    let repo = store.join("repo");
    std::fs::create_dir_all(repo.join(".git").join("hooks")).expect("nested git dir");
    let moved = tree.join("store2");
    let rename = vec![
        OsString::from("/bin/mv"),
        store.clone().into_os_string(),
        moved.clone().into_os_string(),
    ];
    let rename_code = run_jailed_in_tree(&tools, &tree_granted(), &tree, &rename);
    let mounted = |dir: &Path| -> Vec<OsString> {
        vec![
            OsString::from("/bin/grep"),
            OsString::from("-qF"),
            OsString::from(format!(" {} ", dir.display())),
            OsString::from("/proc/self/mountinfo"),
        ]
    };
    let pinned: Vec<(std::path::PathBuf, Option<i32>)> = [store.clone(), repo]
        .into_iter()
        .map(|dir| {
            let code = run_jailed_in_tree(&tools, &tree_granted(), &tree, &mounted(&dir));
            (dir, code)
        })
        .collect();
    let store_kept = store.is_dir();
    let moved_exists = moved.exists();
    let _ = std::fs::remove_dir_all(&tree);
    assert_ne!(
        rename_code,
        Some(0),
        "an ancestor of a nested carve cannot be renamed inside the jail"
    );
    assert!(store_kept && !moved_exists, "the host tree kept its layout");
    for (dir, code) in pinned {
        assert_eq!(
            code,
            Some(0),
            "{} is a mount point inside the jail",
            dir.display()
        );
    }
}

#[test]
fn an_in_scratch_write_succeeds_under_the_run_jail() {
    let Some(tools) = e2e_tools() else { return };
    // A builtin `printf` with a redirect into the jail's `TMPDIR` (the scoped
    // scratch): the shell writes without forking, so the isolated profile's
    // subprocess denial is not in play.
    let payload: Vec<OsString> = ["/bin/sh", "-c", "printf ok > \"$TMPDIR/ipe-e2e-write\""]
        .iter()
        .map(OsString::from)
        .collect();
    let mut written = None;
    let code = run_jailed_inner(&tools, &isolated(), None, &payload, false, |scoped| {
        written = std::fs::read_to_string(scoped.join("ipe-e2e-write")).ok();
    })
    .code;
    assert_eq!(
        code,
        Some(0),
        "a write into the scoped scratch succeeds under the isolated jail (no false-deny)"
    );
    assert_eq!(
        written.as_deref(),
        Some("ok"),
        "the in-scratch write reached the host's scoped scratch"
    );
}

fn isolated() -> SandboxProfile {
    SandboxProfile::maximally_isolated()
}

fn net_granted() -> SandboxProfile {
    SandboxProfile {
        network: true,
        ..SandboxProfile::maximally_isolated()
    }
}

fn subprocess_granted() -> SandboxProfile {
    SandboxProfile {
        subprocess: true,
        filesystem: FilesystemScope::WorkingTreeReadWrite,
        limits: RunResourceLimits::default(),
        ..SandboxProfile::maximally_isolated()
    }
}

#[test]
fn undeclared_network_is_denied_at_the_os_boundary() {
    let Some(tools) = e2e_tools() else { return };
    // A bash /dev/tcp connect to a public resolver. In an isolated jail the
    // fresh empty net namespace has no route → the connect fails (non-zero).
    let payload: Vec<OsString> = ["/bin/bash", "-c", "exec 3<>/dev/tcp/1.1.1.1/53"]
        .iter()
        .map(OsString::from)
        .collect();
    let code = run_jailed(&tools, &isolated(), &payload);
    assert_ne!(
        code,
        Some(0),
        "an isolated jail must NOT reach the network (fail-closed)"
    );
}

#[test]
fn declared_network_reaches_the_network() {
    let Some(tools) = e2e_tools() else { return };
    // The SAME connect, in a network-GRANTED jail, is not blocked by the
    // namespace. (If the host itself has no outbound route this is skipped by
    // checking the unjailed baseline first.)
    let baseline = Command::new("/bin/bash")
        .args(["-c", "exec 3<>/dev/tcp/1.1.1.1/53"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !baseline {
        return; // no outbound route on this host — nothing to prove.
    }
    let payload: Vec<OsString> = ["/bin/bash", "-c", "exec 3<>/dev/tcp/1.1.1.1/53"]
        .iter()
        .map(OsString::from)
        .collect();
    let code = run_jailed(&tools, &net_granted(), &payload);
    assert_eq!(
        code,
        Some(0),
        "a network-granted jail must reach the network (no false-deny)"
    );
}

#[test]
fn undeclared_subprocess_fork_is_denied() {
    let Some(tools) = e2e_tools() else { return };
    // `/bin/true` via a fork+exec shell: bash forks a child to exec it. In a
    // subprocess-absent jail the fork/vfork is EPERM'd → the spawn fails.
    // Force a real fork: two commands so bash cannot exec-optimize into the
    // single child (a lone external command is exec-replaced, no fork). The
    // `$(…)` substitution forks a subshell — exactly the fork the jail denies.
    let payload: Vec<OsString> = ["/bin/bash", "-c", "echo $(/bin/true); /bin/true"]
        .iter()
        .map(OsString::from)
        .collect();
    let code = run_jailed(&tools, &isolated(), &payload);
    assert_ne!(
        code,
        Some(0),
        "a subprocess-absent jail must deny fork/exec of a child (fail-closed)"
    );
}

#[test]
fn granted_subprocess_can_fork() {
    let Some(tools) = e2e_tools() else { return };
    // Same forced-fork shape as the negative test, but subprocess granted → the
    // fork/exec succeeds.
    let payload: Vec<OsString> = ["/bin/bash", "-c", "echo $(/bin/true); /bin/true"]
        .iter()
        .map(OsString::from)
        .collect();
    let code = run_jailed(&tools, &subprocess_granted(), &payload);
    assert_eq!(
        code,
        Some(0),
        "a subprocess-granted jail must permit fork/exec (no false-deny)"
    );
}

#[test]
fn a_thread_spawning_program_boots_under_the_isolated_jail() {
    let Some(tools) = e2e_tools() else { return };
    // Prove the seccomp filter's clone3/clone-thread allowance does not
    // false-deny a threaded program. `nproc` (coreutils) reads /proc and the CPU
    // affinity; a simpler thread probe is a python one-liner that spawns a
    // thread (CPython uses pthread_create → clone3 on glibc>=2.34).
    let py = "/usr/bin/python3";
    if !Path::new(py).exists() {
        return;
    }
    let payload: Vec<OsString> = [
        py,
        "-c",
        "import threading,sys; t=threading.Thread(target=lambda: None); t.start(); t.join(); print('ok')",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let code = run_jailed(&tools, &isolated(), &payload);
    assert_eq!(
        code,
        Some(0),
        "a threaded program must boot under the isolated jail (threads allowed)"
    );
}

/// The skip gate itself, tested without needing a broken environment: only a
/// clean `/bin/true` exit (code 0) counts as an established jail; every
/// establishment-failure shape must gate a skip.
#[test]
fn canary_gates_skip_on_any_establishment_failure() {
    let established = |code| {
        canary_established(&Outcome {
            code,
            stderr: String::new(),
        })
    };
    // The one success shape: the no-op payload booted and exited cleanly.
    assert!(
        established(Some(0)),
        "a clean /bin/true exit means established"
    );
    // Establishment-failure shapes → skip. A non-zero bwrap setup exit
    // (`RTM_NEWADDR`/`unshare` denials surface here) and a signalled process both
    // mean the jail never ran the payload to completion.
    assert!(
        !established(Some(1)),
        "a non-zero bwrap setup exit is a skip"
    );
    assert!(!established(None), "a signalled process is a skip");
}

#[test]
fn nproc_scope_is_proven_on_this_host() {
    let Some(tools) = e2e_tools() else { return };
    let proven = prove(&tools);
    assert!(
        proven.as_ref().is_ok_and(|scope| scope.tools() == &tools),
        "the proof must succeed and carry the tools it measured: {proven:?}"
    );
}

/// A `/bin/sh -c script` jail with `prlimit` OUTSIDE `bwrap`, so `cap` is set
/// in the invoker's namespace and counts every task the user owns.
fn user_wide_canary(tools: &RunJailTools, cap: ProcCap, script: &str) -> CanaryExit {
    let status = Command::new(&tools.prlimit)
        .arg(format!("--nproc={}", cap.get()))
        .arg("--")
        .arg(&tools.bwrap)
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--",
            "/bin/sh",
            "-c",
            script,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("spawn the user-wide canary");
    if status.success() {
        CanaryExit::Succeeded
    } else {
        CanaryExit::Failed
    }
}

#[test]
fn a_canary_with_prlimit_outside_the_namespace_is_refused() {
    let Some(tools) = e2e_tools() else { return };
    // The discriminator must tell the two scopes apart on a real kernel: the
    // same scripts under a user-wide count classify as a refusal.
    let teeth_control = user_wide_canary(&tools, ProcCap::MAX, TEETH_SCRIPT);
    let scope_run = user_wide_canary(&tools, ProcCap::CANARY, SCOPE_SCRIPT);
    let teeth_run = user_wide_canary(&tools, ProcCap::CANARY, TEETH_SCRIPT);
    assert_eq!(
        classify(teeth_control, scope_run, teeth_run),
        Err(Scope::UserWide),
        "a cap counting the whole user must be refused (control {teeth_control:?}, \
         scope {scope_run:?}, teeth {teeth_run:?})"
    );
}

/// Host children that are killed and reaped when the guard drops.
struct HostSleepers(Vec<std::process::Child>);

impl Drop for HostSleepers {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn a_busy_user_does_not_starve_a_granted_jail() {
    let Some(tools) = e2e_tools() else { return };
    // The invoker already owns more tasks than the jail's cap; a cap counting
    // only the jail still admits the jail's own fork.
    let sleepers = HostSleepers(
        (0..ProcCap::CANARY.get() + 8)
            .map(|_| {
                Command::new("sleep")
                    .arg("5")
                    .spawn()
                    .expect("spawn a host sleeper")
            })
            .collect(),
    );
    let mut profile = subprocess_granted();
    profile.limits.proc_cap = ProcCap::of::<8>();
    let payload: Vec<OsString> = ["/bin/sh", "-c", SCOPE_SCRIPT]
        .iter()
        .map(OsString::from)
        .collect();
    let code = run_jailed(&tools, &profile, &payload);
    drop(sleepers);
    assert_eq!(
        code,
        Some(0),
        "the invoker's other tasks must not count against the jail's cap"
    );
}

#[test]
fn a_fork_bomb_is_bounded_in_a_granted_jail() {
    let Some(tools) = e2e_tools() else { return };
    let payload: Vec<OsString> = [
        "/bin/sh",
        "-c",
        "i=0; while [ $i -lt 32 ]; do sleep 1 & i=$((i+1)); done; wait",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    // Control: under a cap above the payload's peak the same jail succeeds, so
    // a refusal below is the cap's and not the jail's or the payload's.
    let mut roomy = subprocess_granted();
    roomy.limits.proc_cap = ProcCap::of::<64>();
    let control = run_jailed_capturing(&tools, &roomy, &payload);
    assert_eq!(
        control.code,
        Some(0),
        "the payload must run under a cap above its peak: {}",
        control.stderr
    );
    let mut profile = subprocess_granted();
    profile.limits.proc_cap = ProcCap::of::<8>();
    let bounded = run_jailed_capturing(&tools, &profile, &payload);
    assert_ne!(
        bounded.code,
        Some(0),
        "a jail forking past its cap must be refused the excess forks"
    );
    // dash says "Cannot fork", bash "fork: ...", busybox "can't fork".
    assert!(
        bounded.stderr.to_lowercase().contains("fork"),
        "the jail must fail on a refused fork, not on another error: {}",
        bounded.stderr
    );
}

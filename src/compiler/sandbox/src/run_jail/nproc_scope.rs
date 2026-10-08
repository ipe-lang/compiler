//! The proof that a jail's process cap counts only the jail's own tasks.
//!
//! `prlimit --nproc` sets `RLIMIT_NPROC`, which the kernel charges to a user,
//! not to a process tree. Inside a user namespace on Linux 5.14 or later the
//! charge is per namespace, so the cap bounds exactly the jail. On an older
//! kernel, or without a user namespace, it counts every task the invoking user
//! owns; for root it is not enforced at all. Neither the kernel version nor the
//! uid settles which holds (a setuid `bwrap`, a namespace sysctl, a container
//! all change it), so the scope is measured: canary jails built by the same
//! argv builder production spawns through run under [`ProcCap::CANARY`], and
//! [`classify`] reads their outcomes. [`NprocScope`] is the token only a
//! passing measurement mints, and every Linux jail argv builder requires one.

use std::ffi::OsString;
use std::io::Read as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::{ProcCap, RunJailDefect, RunJailTools, SandboxProfile, jail_argv_unproven};
use crate::scratch::{ScratchDir, ScratchFile};
use crate::{CanonicalPath, JailMounts};

impl ProcCap {
    /// The cap every canary jail runs under.
    ///
    /// Measured inside the jail's own user and pid namespaces (Linux 5.15,
    /// `bwrap` 0.6): [`SCOPE_SCRIPT`] peaks at 3 tasks (`bwrap`'s pid-1 reaper,
    /// the shell and one child) and is admitted from a cap of 3; [`TEETH_SCRIPT`]
    /// peaks at 8 (the reaper, the shell and six children) and is refused below
    /// 8. Under a user-wide count the scope run's fork also charges the
    /// launcher and the outer `bwrap`, at least 5 tasks. A cap of 4 admits the
    /// scope run only when the count is per namespace and refuses the teeth run
    /// whenever the cap is enforced, each with a margin of at least one task.
    pub const CANARY: Self = Self::of::<4>();
}

/// The script whose success under [`ProcCap::CANARY`] proves a per-namespace count.
///
/// Two commands keep the shell from exec-replacing itself into the last one,
/// so one child is forked and reaped.
pub const SCOPE_SCRIPT: &str = "/bin/true; /bin/true";

/// The script whose failure under [`ProcCap::CANARY`] proves the cap is enforced.
pub const TEETH_SCRIPT: &str = "for i in 1 2 3 4 5 6; do sleep 1 & done; wait";

/// How long a canary jail may run before it is killed and the proof refused.
///
/// It is the canary's only wall clock: a jail cut off by it is a refusal, never
/// a [`CanaryExit::Failed`] that would read as the cap refusing a fork.
const CANARY_WALL: Duration = Duration::from_secs(15);

/// The interval between polls of a running canary.
const CANARY_POLL: Duration = Duration::from_millis(10);

/// The most bytes of a failed canary's stderr carried into its refusal.
const CANARY_STDERR_CAP: u64 = 4096;

/// The most `bwrap` and `prlimit` pairs whose verdict is cached.
const VERDICT_SLOTS: usize = 8;

/// Why a jail's process cap does not count only the jail's own tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The cap counts every task the invoking user owns.
    UserWide,
    /// The cap is not enforced for the invoking user.
    Inert,
}

impl Scope {
    /// The refusal's cause and remedy, as the diagnostic renders it.
    #[must_use]
    pub const fn remedy(self) -> &'static str {
        match self {
            Self::UserWide => {
                "the process cap counts every process this user owns, not only the jail's; run \
                 ipe on Linux 5.14 or later with unprivileged user namespaces enabled"
            }
            Self::Inert => {
                "the process cap does not apply to this user (root is exempt); run ipe as an \
                 unprivileged user"
            }
        }
    }
}

/// How one canary jail ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryExit {
    /// The payload exited 0.
    Succeeded,
    /// The payload or the jail exited nonzero or was signalled.
    Failed,
}

/// Decide the cap's scope from the scope run and the teeth run.
///
/// A teeth run that succeeds means the cap never bit, whatever the scope run
/// did. A scope run that fails under an enforced cap means the count reached
/// past the jail. Only a passing scope run with a refused teeth run proves the
/// cap counts exactly the jail.
///
/// # Errors
/// [`Scope::Inert`] when the teeth run succeeded; [`Scope::UserWide`] when the
/// scope run failed and the teeth run was refused.
pub const fn classify(scope_run: CanaryExit, teeth_run: CanaryExit) -> Result<(), Scope> {
    match (scope_run, teeth_run) {
        (_, CanaryExit::Succeeded) => Err(Scope::Inert),
        (CanaryExit::Failed, CanaryExit::Failed) => Err(Scope::UserWide),
        (CanaryExit::Succeeded, CanaryExit::Failed) => Ok(()),
    }
}

/// The proof that a jail built with these tools counts only its own tasks against its process cap.
///
/// Only [`prove`] mints one, so a jail argv that requires it cannot be built
/// before the scope was measured.
#[derive(Debug)]
pub struct NprocScope {
    tools: RunJailTools,
}

impl NprocScope {
    /// The tools the proof was measured with, which the jail argv names.
    #[must_use]
    pub const fn tools(&self) -> &RunJailTools {
        &self.tools
    }

    /// A proof over `tools` that was never measured, for argv-rendering tests.
    #[cfg(test)]
    pub(crate) const fn for_test(tools: RunJailTools) -> Self {
        Self { tools }
    }
}

/// One cached measurement.
struct Verdict {
    bwrap: PathBuf,
    prlimit: PathBuf,
    result: Result<(), RunJailDefect>,
}

/// Prove that a jail built with `tools` counts only its own tasks against its process cap.
///
/// The measurement runs once per `bwrap` and `prlimit` pair and its result,
/// a refusal included, is kept for the life of the process.
///
/// # Errors
/// [`RunJailDefect::ProcCapUnscoped`] when the cap counts the whole user or is
/// not enforced; [`RunJailDefect::Spawn`] or [`RunJailDefect::Path`] when a
/// canary jail cannot be established.
pub fn prove(tools: &RunJailTools) -> Result<NprocScope, RunJailDefect> {
    static VERDICTS: Mutex<Vec<Verdict>> = Mutex::new(Vec::new());
    // The lock is held across the measurement so concurrent callers run one
    // set of canaries, not one each.
    let mut verdicts = VERDICTS.lock().unwrap_or_else(PoisonError::into_inner);
    let cached = verdicts
        .iter()
        .find(|v| v.bwrap == tools.bwrap && v.prlimit == tools.prlimit)
        .map(|v| v.result.clone());
    let result = cached.unwrap_or_else(|| {
        let result = measure(tools);
        if verdicts.len() < VERDICT_SLOTS {
            verdicts.push(Verdict {
                bwrap: tools.bwrap.clone(),
                prlimit: tools.prlimit.clone(),
                result: result.clone(),
            });
        }
        result
    });
    drop(verdicts);
    result.map(|()| NprocScope {
        tools: tools.clone(),
    })
}

/// Run the canary jails and classify their outcomes.
fn measure(tools: &RunJailTools) -> Result<(), RunJailDefect> {
    let scratch = ScratchDir::new("ipe-nproc-canary").map_err(|e| RunJailDefect::Spawn {
        detail: format!("the process-cap canary's scratch directory could not be created: {e}"),
    })?;
    let scoped = CanonicalPath::resolve(scratch.path()).map_err(RunJailDefect::Path)?;
    let mounts =
        JailMounts::of_invoker(scoped.clone(), scoped, Vec::new()).map_err(RunJailDefect::Path)?;

    // A jail that cannot boot `/bin/true` under the widest cap says nothing
    // about the cap's scope: refuse, naming what `bwrap` reported.
    let mut stderr =
        ScratchFile::create("ipe-nproc-canary-stderr").map_err(|e| RunJailDefect::Spawn {
            detail: format!("the process-cap canary's stderr file could not be created: {e}"),
        })?;
    let sink = stderr.file.try_clone().map_err(|e| RunJailDefect::Spawn {
        detail: format!("the process-cap canary's stderr file could not be shared: {e}"),
    })?;
    let baseline = run_canary(
        tools,
        &canary_profile(ProcCap::MAX),
        &mounts,
        &[OsString::from("/bin/true")],
        Stdio::from(sink),
    )?;
    if baseline == CanaryExit::Failed {
        return Err(RunJailDefect::Spawn {
            detail: format!(
                "the process-cap canary jail could not be established: {}",
                capped_text(&mut stderr)
            ),
        });
    }

    let tight = canary_profile(ProcCap::CANARY);
    let scope_run = run_canary(tools, &tight, &mounts, &shell(SCOPE_SCRIPT), Stdio::null())?;
    let teeth_run = run_canary(tools, &tight, &mounts, &shell(TEETH_SCRIPT), Stdio::null())?;
    classify(scope_run, teeth_run).map_err(|reason| RunJailDefect::ProcCapUnscoped { reason })
}

/// The canary jail's profile: production's isolation with `proc_cap`, and the
/// network and subprocess axes granted so only the cap can refuse a fork.
///
/// It sets no wall clock, so no `timeout` wraps the jail: a `timeout` that
/// fired exits nonzero exactly like a refused fork, and a teeth run cut off
/// that way would prove a cap that never bit. [`CANARY_WALL`] bounds the run
/// instead and refuses the proof when it fires.
fn canary_profile(proc_cap: ProcCap) -> SandboxProfile {
    let mut profile = SandboxProfile {
        network: true,
        subprocess: true,
        ..SandboxProfile::maximally_isolated()
    };
    profile.limits.proc_cap = proc_cap;
    profile.limits.wall_secs = None;
    profile
}

/// `script` as a `/bin/sh -c` payload.
fn shell(script: &str) -> [OsString; 3] {
    [
        OsString::from("/bin/sh"),
        OsString::from("-c"),
        OsString::from(script),
    ]
}

/// Run one canary jail to completion within [`CANARY_WALL`].
fn run_canary(
    tools: &RunJailTools,
    profile: &SandboxProfile,
    mounts: &JailMounts,
    payload: &[OsString],
    stderr: Stdio,
) -> Result<CanaryExit, RunJailDefect> {
    let no_env = |_: &str| -> Option<OsString> { None };
    let argv = jail_argv_unproven(tools, profile, mounts, None, None, &no_env, payload)
        .map_err(RunJailDefect::Path)?;
    let Some((program, rest)) = argv.args().split_first() else {
        return Err(RunJailDefect::Spawn {
            detail: "the process-cap canary argv is empty".to_owned(),
        });
    };
    let mut child = Command::new(program)
        .args(rest)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .map_err(|e| RunJailDefect::Spawn {
            detail: format!("the process-cap canary jail could not be spawned: {e}"),
        })?;
    await_canary(&mut child, CANARY_WALL)
}

/// Wait for a canary, killing and reaping it once `wall` has passed.
fn await_canary(child: &mut Child, wall: Duration) -> Result<CanaryExit, RunJailDefect> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(CanaryExit::Succeeded),
            Ok(Some(_)) => return Ok(CanaryExit::Failed),
            Ok(None) if started.elapsed() < wall => std::thread::sleep(CANARY_POLL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RunJailDefect::Spawn {
                    detail: format!(
                        "the process-cap canary jail did not finish within {} ms",
                        wall.as_millis()
                    ),
                });
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RunJailDefect::Spawn {
                    detail: format!("waiting on the process-cap canary jail failed: {e}"),
                });
            }
        }
    }
}

/// The first [`CANARY_STDERR_CAP`] bytes a canary wrote to `stderr`, trimmed.
fn capped_text(stderr: &mut ScratchFile) -> String {
    let mut bytes = Vec::new();
    if stderr.rewind().is_err()
        || (&stderr.file)
            .take(CANARY_STDERR_CAP)
            .read_to_end(&mut bytes)
            .is_err()
    {
        return "its stderr could not be read".to_owned();
    }
    let text = String::from_utf8_lossy(&bytes).trim().to_owned();
    if text.is_empty() {
        "it exited nonzero with no output".to_owned()
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use super::{
        CanaryExit, ProcCap, RunJailDefect, Scope, await_canary, canary_profile, classify,
    };

    /// No canary runs under `timeout`: its firing exits nonzero like a refused
    /// fork and would prove a cap that never bit.
    #[test]
    fn no_canary_jail_runs_under_a_timeout_wall() {
        for cap in [ProcCap::MAX, ProcCap::CANARY] {
            assert_eq!(canary_profile(cap).limits.wall_secs, None);
        }
    }

    /// A canary that overruns its wall is a refusal, never a `Failed` exit.
    #[cfg(unix)]
    #[test]
    fn an_overrunning_canary_is_refused_not_read_as_a_refused_fork() {
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn a sleeper");
        let outcome = await_canary(&mut child, Duration::from_millis(50));
        assert!(
            matches!(outcome, Err(RunJailDefect::Spawn { .. })),
            "{outcome:?}"
        );
        assert!(
            matches!(child.try_wait(), Ok(Some(_))),
            "the overrunning canary is killed and reaped"
        );
    }

    #[test]
    fn classify_refuses_user_wide_and_inert_scopes() {
        use CanaryExit::{Failed, Succeeded};
        assert_eq!(classify(Succeeded, Failed), Ok(()));
        assert_eq!(classify(Failed, Failed), Err(Scope::UserWide));
        assert_eq!(classify(Succeeded, Succeeded), Err(Scope::Inert));
        assert_eq!(classify(Failed, Succeeded), Err(Scope::Inert));
    }

    #[test]
    fn each_scope_names_its_remedy() {
        assert!(Scope::UserWide.remedy().contains("5.14"));
        assert!(Scope::UserWide.remedy().contains("user namespaces"));
        assert!(Scope::Inert.remedy().contains("root is exempt"));
        assert!(Scope::Inert.remedy().contains("unprivileged user"));
    }
}

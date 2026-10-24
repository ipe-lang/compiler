//! The process's one owner of the termination request (`SIGTERM`).
//!
//! Every termination request first ends every remote transfer
//! ([`crate::remote_ingest::end_transfers`]), so no process a transfer started
//! outlives the CLI. The first request then runs the shutdown subscribers (the
//! orderly teardown of `ipe dev watch`); with none subscribed, and on every later
//! request, the CLI ends by the signal's default action. A teardown that hangs
//! is therefore ended by a second request.
//!
//! What the owner does follows what the process held for the signal before any
//! handler of the CLI was registered:
//!
//! - ignored (a CLI started under `trap '' TERM`): nothing is installed, so the
//!   CLI and its transfers keep running;
//! - the default action: as described above;
//! - caught by a handler the host process installed: transfers are ended and
//!   subscribers run, and the host's own handler decides whether the process
//!   ends, so the CLI never takes a default action over it;
//! - unreadable: as for a caught signal, so the CLI never takes a default action
//!   it may have inherited as ignored.
//!
//! The dispositions are read once per process, before this owner or the
//! transfer signal relay registers a handler, from `/proc/self/status` on Linux
//! and from `/bin/ps` elsewhere; both owners decide from that one reading.

use std::ffi::c_int;
use std::sync::{Mutex, OnceLock, PoisonError, mpsc};

use signal_hook::consts::SIGTERM;
use signal_hook::iterator::Signals;

/// What a signal does to a process that takes its default action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Ends it: a termination, interrupt, quit or hangup.
    Ends,
    /// Stops it: a terminal stop.
    Stops,
    /// Resumes it.
    Continues,
}

/// The signal-set reading a served app's runtime decides from too, so the CLI
/// and the app can never disagree on what a mask says.
pub use ipe_runtime_rust::system::SignalSet;

/// The signal dispositions the process held before the CLI registered a handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inherited {
    /// The dispositions were read.
    Known {
        /// The signals ignored.
        ignored: SignalSet,
        /// The signals a handler of the host process catches.
        caught: SignalSet,
    },
    /// The dispositions could not be read.
    Unknown,
}

/// How a signal owner handles one signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handling {
    /// Not registered: the held disposition stays in force.
    Unregistered,
    /// Acted on, then the CLI takes the default action.
    RelayThenDefault,
    /// Acted on only.
    RelayOnly,
}

impl Inherited {
    /// How an owner handles `signal`, whose default action has `effect`.
    pub fn handling(self, signal: c_int, effect: Effect) -> Handling {
        match effect {
            Effect::Continues => Handling::RelayOnly,
            Effect::Ends | Effect::Stops => match self {
                Self::Known { ignored, .. } if ignored.contains(signal) => Handling::Unregistered,
                Self::Known { caught, .. } if caught.contains(signal) => Handling::RelayOnly,
                Self::Known { .. } => Handling::RelayThenDefault,
                Self::Unknown => Handling::RelayOnly,
            },
        }
    }
}

/// The dispositions this process held, read on the first call.
///
/// Every signal owner calls this before registering a handler, so the reading
/// never sees a handler of the CLI itself.
pub fn inherited() -> Inherited {
    static READ: OnceLock<Inherited> = OnceLock::new();
    *READ.get_or_init(read)
}

/// The dispositions of this process, read from `/proc/self/status`.
#[cfg(target_os = "linux")]
fn read() -> Inherited {
    ipe_runtime_rust::system::read_self_status()
        .and_then(|status| status_masks(&status))
        .map_or(Inherited::Unknown, |(ignored, caught)| Inherited::Known {
            ignored,
            caught,
        })
}

/// The dispositions of this process, read through `ps`.
#[cfg(not(target_os = "linux"))]
fn read() -> Inherited {
    ps_masks(std::process::id()).map_or(Inherited::Unknown, |(ignored, caught)| Inherited::Known {
        ignored,
        caught,
    })
}

/// The `SigIgn:` and `SigCgt:` masks of a `/proc/<pid>/status` text.
#[cfg(target_os = "linux")]
fn status_masks(status: &str) -> Option<(SignalSet, SignalSet)> {
    use ipe_runtime_rust::system::{StatusMask, status_mask};
    Some((
        status_mask(status, StatusMask::Ignored)?,
        status_mask(status, StatusMask::Caught)?,
    ))
}

/// The most `ps` may print for one process's two masks.
#[cfg(any(not(target_os = "linux"), test))]
const PS_STDOUT_MAX_BYTES: crate::remote_ingest::ByteBudget =
    crate::remote_ingest::PROBE_STDOUT_MAX_BYTES;

/// The longest `ps` may take to report one process's masks.
#[cfg(any(not(target_os = "linux"), test))]
const PS_WALL: crate::remote_ingest::WallBudget = crate::remote_ingest::WallBudget::of_secs::<5>();

/// The ignored and caught masks of process `pid`, as `/bin/ps` reports them.
///
/// `ps` runs attached, with an empty environment and its absolute path, so
/// neither `PATH` nor the environment chooses the program; a missing or
/// failing `ps` reads as unknown.
#[cfg(any(not(target_os = "linux"), test))]
fn ps_masks(pid: u32) -> Option<(SignalSet, SignalSet)> {
    let mut command = std::process::Command::new("/bin/ps");
    command
        .env_clear()
        .args(["-o", "sigignore=", "-o", "sigcatch=", "-p"])
        .arg(pid.to_string());
    let captured = crate::remote_ingest::run_probe(command, PS_STDOUT_MAX_BYTES, PS_WALL)?;
    if !captured.status.success() {
        return None;
    }
    ps_fields(&captured.stdout)
}

/// The two hexadecimal masks `ps -o sigignore= -o sigcatch=` printed, in that order.
#[cfg(any(not(target_os = "linux"), test))]
fn ps_fields(stdout: &[u8]) -> Option<(SignalSet, SignalSet)> {
    let mut fields = std::str::from_utf8(stdout).ok()?.split_ascii_whitespace();
    let ignored = SignalSet::from_hex(fields.next()?)?;
    let caught = SignalSet::from_hex(fields.next()?)?;
    fields.next().is_none().then_some((ignored, caught))
}

/// One shutdown subscriber: run once, on the first termination request.
type Subscriber = Box<dyn FnOnce() + Send>;

/// The shutdown subscribers, and whether a termination request has arrived.
struct Requests {
    /// The subscribers not yet run.
    shutdown: Vec<Subscriber>,
    /// Whether a termination request has arrived.
    received: bool,
}

static REQUESTS: Mutex<Requests> = Mutex::new(Requests {
    shutdown: Vec::new(),
    received: false,
});

/// Whether the owner was installed, once per process.
static INSTALLED: OnceLock<Result<(), std::io::ErrorKind>> = OnceLock::new();

/// Install the owner if it is not yet installed.
///
/// # Errors
/// The owner could not be installed; no transfer may then start, since a
/// termination request would leave it running.
pub fn ensure() -> std::io::Result<()> {
    (*INSTALLED.get_or_init(install)).map_err(std::io::Error::from)
}

/// Run `subscriber` on the first termination request, instead of ending the CLI.
///
/// A request that already arrived runs it at once. Under an ignored signal
/// no request ever arrives, so it never runs.
///
/// # Errors
/// The owner could not be installed.
pub fn on_shutdown(subscriber: impl FnOnce() + Send + 'static) -> std::io::Result<()> {
    ensure()?;
    let ready = {
        let mut requests = REQUESTS.lock().unwrap_or_else(PoisonError::into_inner);
        if requests.received {
            Some(subscriber)
        } else {
            requests.shutdown.push(Box::new(subscriber));
            None
        }
    };
    if let Some(subscriber) = ready {
        subscriber();
    }
    Ok(())
}

/// Register the termination request and start the threads that answer it.
///
/// The signal thread answers every request; the shutdown thread runs the
/// subscribers the first request hands it. A subscriber that hangs therefore
/// never stops a later request from being answered.
fn install() -> Result<(), std::io::ErrorKind> {
    let handling = inherited().handling(SIGTERM, Effect::Ends);
    if handling == Handling::Unregistered {
        return Ok(());
    }
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<Vec<Subscriber>>();
    std::thread::Builder::new()
        .name("ipe-shutdown".to_owned())
        .spawn(move || {
            if let Ok(subscribers) = shutdown_rx.recv() {
                for subscriber in subscribers {
                    subscriber();
                }
            }
        })
        .map_err(|e| e.kind())?;
    let mut signals = Signals::new([SIGTERM]).map_err(|e| e.kind())?;
    std::thread::Builder::new()
        .name("ipe-terminate".to_owned())
        .spawn(move || {
            for _ in signals.forever() {
                respond(handling, &shutdown_tx);
            }
        })
        .map(drop)
        .map_err(|e| e.kind())
}

/// Answer one termination request, handing the first one's subscribers to `shutdown`.
fn respond(handling: Handling, shutdown: &mpsc::Sender<Vec<Subscriber>>) {
    crate::remote_ingest::end_transfers();
    let subscribers = {
        let mut requests = REQUESTS.lock().unwrap_or_else(PoisonError::into_inner);
        let first = !requests.received;
        requests.received = true;
        if first {
            std::mem::take(&mut requests.shutdown)
        } else {
            Vec::new()
        }
    };
    if subscribers.is_empty() {
        if handling == Handling::RelayThenDefault {
            let _ = signal_hook::low_level::emulate_default_handler(SIGTERM);
        }
    } else if let Err(mpsc::SendError(unrun)) = shutdown.send(subscribers) {
        // The shutdown thread is gone, so the teardown runs here.
        for subscriber in unrun {
            subscriber();
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::{Effect, Handling, Inherited, SignalSet, ps_fields};
    #[cfg(target_os = "linux")]
    use crate::remote_ingest::test_group;
    use signal_hook::consts::{SIGCONT, SIGHUP, SIGINT, SIGTERM, SIGTSTP};

    /// Runs an ignored test of this binary as a child process.
    #[cfg(target_os = "linux")]
    pub mod test_child {
        /// Run the ignored test `name` of this binary as a child, through `sh`
        /// running `prelude` first.
        pub fn run(prelude: &str, name: &str) -> std::process::Output {
            let exe = std::env::current_exe().expect("the test binary");
            std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("{prelude} exec \"$0\" \"$@\""))
                .arg(exe)
                .args([
                    "--exact",
                    name,
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .output()
                .expect("run the child test")
        }
    }

    /// The set holding exactly `signals`.
    fn set(signals: &[i32]) -> SignalSet {
        SignalSet(signals.iter().fold(0, |mask, signal| {
            let bit = u32::try_from(*signal - 1).expect("a signal number");
            mask | (1u64 << bit)
        }))
    }

    #[test]
    fn a_mask_bit_marks_its_signal() {
        assert!(SignalSet(0b10).contains(2));
        assert!(!SignalSet(0b10).contains(1));
        assert!(!SignalSet(u64::MAX).contains(0));
        assert!(!SignalSet(u64::MAX).contains(-1));
        assert!(!SignalSet(u64::MAX).contains(65));
    }

    #[test]
    fn an_ignored_signal_stays_unregistered_and_a_caught_one_never_takes_the_default() {
        let inherited = Inherited::Known {
            ignored: set(&[SIGHUP, SIGTSTP]),
            caught: set(&[SIGTERM, SIGHUP]),
        };
        assert_eq!(
            inherited.handling(SIGHUP, Effect::Ends),
            Handling::Unregistered
        );
        assert_eq!(
            inherited.handling(SIGTSTP, Effect::Stops),
            Handling::Unregistered
        );
        assert_eq!(
            inherited.handling(SIGTERM, Effect::Ends),
            Handling::RelayOnly
        );
        assert_eq!(
            inherited.handling(SIGINT, Effect::Ends),
            Handling::RelayThenDefault
        );
    }

    #[test]
    fn unknown_dispositions_never_take_the_default() {
        for signal in [SIGTERM, SIGINT, SIGHUP] {
            assert_eq!(
                Inherited::Unknown.handling(signal, Effect::Ends),
                Handling::RelayOnly
            );
        }
        assert_eq!(
            Inherited::Unknown.handling(SIGTSTP, Effect::Stops),
            Handling::RelayOnly
        );
    }

    #[test]
    fn continue_is_always_relayed_without_the_default() {
        for inherited in [
            Inherited::Unknown,
            Inherited::Known {
                ignored: set(&[]),
                caught: set(&[]),
            },
            Inherited::Known {
                ignored: set(&[SIGCONT]),
                caught: set(&[SIGCONT]),
            },
        ] {
            assert_eq!(
                inherited.handling(SIGCONT, Effect::Continues),
                Handling::RelayOnly
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_status_masks_parse_as_hex_and_need_both_lines() {
        let status =
            "Name:\tipe\nSigBlk:\t0\nSigIgn:\t0000000000000001\nSigCgt:\t0000000000004000\n";
        assert_eq!(
            super::status_masks(status),
            Some((SignalSet(1), SignalSet(0x4000)))
        );
        assert_eq!(super::status_masks("Name:\tipe\nSigIgn:\t1\n"), None);
        assert_eq!(super::status_masks("SigIgn:\tzz\nSigCgt:\t0\n"), None);
        assert_eq!(super::status_masks("SigIgn:\t+1\nSigCgt:\t0\n"), None);
        assert_eq!(super::status_masks("SigIgn:\t1\nSigCgt:\t\n"), None);
    }

    #[test]
    fn the_ps_output_is_exactly_two_hex_fields() {
        assert_eq!(
            ps_fields(b"00001000 0\n"),
            Some((SignalSet(0x1000), SignalSet(0)))
        );
        assert_eq!(
            ps_fields(b"  0000000000000001   4000 \n"),
            Some((SignalSet(1), SignalSet(0x4000)))
        );
        assert_eq!(ps_fields(b""), None);
        assert_eq!(ps_fields(b"1\n"), None);
        assert_eq!(ps_fields(b"1 2 3"), None);
        assert_eq!(ps_fields(b"+1 0"), None);
        assert_eq!(ps_fields(b"SIGHUP 0"), None);
        assert_eq!(ps_fields(b"\xff 0"), None);
        assert_eq!(ps_fields(b"10000000000000000 0"), None);
    }

    /// Poll `ps` for `pid` until it reports `signal` ignored, for at most 5 s.
    #[cfg(target_os = "linux")]
    fn poll_ps(pid: u32, signal: i32) -> Option<(SignalSet, SignalSet)> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let seen = super::ps_masks(pid);
            if seen.is_some_and(|(ignored, _)| ignored.contains(signal))
                || std::time::Instant::now() >= deadline
            {
                return seen;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_ps_probe_agrees_with_proc_on_an_ignored_hangup() {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "trap '' HUP; exec sleep 30"])
            .spawn()
            .expect("spawn sh");
        let pid = child.id();
        let seen = poll_ps(pid, SIGHUP);
        let proc_masks = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|status| super::status_masks(&status));
        let _ = child.kill();
        let _ = child.wait();
        let (ignored, caught) = seen.expect("ps reports both masks");
        assert!(ignored.contains(SIGHUP), "ps misses the ignored hangup");
        let (proc_ignored, proc_caught) = proc_masks.expect("SigIgn and SigCgt lines");
        assert_eq!(ignored.0 & 0xffff_ffff, proc_ignored.0 & 0xffff_ffff);
        assert_eq!(caught.0 & 0xffff_ffff, proc_caught.0 & 0xffff_ffff);
    }

    /// Printed by a child test just before it raises its first termination request.
    #[cfg(target_os = "linux")]
    const ARMED: &str = "ipe-terminate-armed";

    /// Printed by [`ignored_termination_child`] once its transfer outlived the request.
    #[cfg(target_os = "linux")]
    const SURVIVED: &str = "ipe-terminate-survived";

    /// Printed by [`second_request_child`]'s shutdown subscriber.
    #[cfg(target_os = "linux")]
    const SHUTDOWN_RAN: &str = "ipe-terminate-shutdown-ran";

    /// Printed by [`second_request_child`] once the first request ended its transfer and left it running.
    #[cfg(target_os = "linux")]
    const FIRST_ANSWERED: &str = "ipe-terminate-first-answered";

    /// Whether this process ignores or catches the termination request.
    #[cfg(target_os = "linux")]
    fn parent_holds_termination() -> bool {
        match super::inherited() {
            Inherited::Unknown => true,
            Inherited::Known { ignored, caught } => {
                ignored.contains(SIGTERM) || caught.contains(SIGTERM)
            }
        }
    }

    /// Write `line` to stdout for the parent test to read.
    #[cfg(target_os = "linux")]
    fn report(line: &str) {
        use std::io::Write as _;
        writeln!(std::io::stdout(), "{line}").expect("report a marker to the parent");
    }

    /// One process's state as its `/proc/<pid>/stat` names it.
    #[cfg(target_os = "linux")]
    #[derive(Debug, Clone, Copy)]
    enum Proc {
        Running,
        Zombie,
        Absent,
    }

    /// A process group's liveness verdict.
    #[cfg(target_os = "linux")]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    enum Group {
        Alive,
        Dead,
    }

    /// The verdict from probes taken in lifecycle order.
    ///
    /// The leader is probed first, then the rest of the group. A process only advances running, zombie, reaped, so probing the earlier
    /// state first means a transition between probes can never make a dead
    /// group read alive: every `Alive` is witnessed by a live process at the
    /// instant of the probe that returned it.
    #[cfg(target_os = "linux")]
    fn group_verdict(
        leader: impl FnOnce() -> Proc,
        live_member_besides_leader: impl FnOnce() -> bool,
        signalable: impl FnOnce() -> bool,
    ) -> Group {
        let alive = match leader() {
            Proc::Running => true,
            Proc::Zombie => live_member_besides_leader(),
            Proc::Absent => signalable() && live_member_besides_leader(),
        };
        if alive { Group::Alive } else { Group::Dead }
    }

    /// The text of `/proc/<pid>/stat`, or `None` once the process is gone.
    #[cfg(target_os = "linux")]
    fn read_stat(pid: &str) -> Option<String> {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()) =>
            {
                None
            }
            read => Some(read.expect("read a /proc stat")),
        }
    }

    /// The fields after the command name of a `/proc/<pid>/stat` line: state, parent, group, and on.
    #[cfg(target_os = "linux")]
    fn stat_fields(stat: &str) -> std::str::SplitWhitespace<'_> {
        stat.rsplit_once(") ")
            .map(|(_, rest)| rest)
            .expect("a stat line names its command")
            .split_whitespace()
    }

    /// Whether a stat state names an exited process: a zombie, or one being reaped.
    #[cfg(target_os = "linux")]
    fn exited_state(state: &str) -> bool {
        matches!(state, "Z" | "X")
    }

    /// The state of process `pid`.
    #[cfg(target_os = "linux")]
    fn proc_state(pid: i32) -> Proc {
        read_stat(&pid.to_string()).map_or(Proc::Absent, |stat| {
            let state = stat_fields(&stat).next().expect("a stat state field");
            if exited_state(state) {
                Proc::Zombie
            } else {
                Proc::Running
            }
        })
    }

    /// Whether a process other than the leader `pgid` runs in group `pgid`.
    #[cfg(target_os = "linux")]
    fn live_member_besides(pgid: i32) -> bool {
        let leader = pgid.to_string();
        for entry in std::fs::read_dir("/proc").expect("list /proc") {
            let name = entry.expect("a /proc entry").file_name();
            let Some(pid) = name.to_str() else { continue };
            if pid == leader || !pid.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            let Some(stat) = read_stat(pid) else { continue };
            let mut fields = stat_fields(&stat);
            let state = fields.next().expect("a stat state field");
            let member = fields.nth(1).expect("a stat group field") == leader;
            if member && !exited_state(state) {
                return true;
            }
        }
        false
    }

    /// Whether a signal can reach any process of group `pgid`, a zombie included.
    #[cfg(target_os = "linux")]
    fn signalable(pgid: i32) -> bool {
        rustix::process::Pid::from_raw(pgid)
            .is_some_and(|id| rustix::process::test_kill_process_group(id).is_ok())
    }

    /// Whether group `pid` holds no live process: gone, or only exited processes left unreaped.
    #[cfg(target_os = "linux")]
    fn group_is_dead(pid: i32) -> bool {
        group_verdict(
            || proc_state(pid),
            || live_member_besides(pid),
            || signalable(pid),
        ) == Group::Dead
    }

    /// What every probe of a group answers while it holds one lifecycle stage.
    #[cfg(target_os = "linux")]
    #[derive(Debug, Clone, Copy)]
    struct Stage {
        leader: Proc,
        live_member_besides_leader: bool,
        signalable: bool,
    }

    /// The verdict when the group moves from `before` to `after` after `probes` probe calls.
    #[cfg(target_os = "linux")]
    fn verdict_across(before: Stage, after: Stage, probes: usize) -> Group {
        let calls = std::cell::Cell::new(0_usize);
        let stage = || {
            let call = calls.get();
            calls.set(call.saturating_add(1));
            if call < probes { before } else { after }
        };
        group_verdict(
            || stage().leader,
            || stage().live_member_besides_leader,
            || stage().signalable,
        )
    }

    /// A group whose only process is its unreaped leader.
    #[cfg(target_os = "linux")]
    const ZOMBIE_LEADER_ALONE: Stage = Stage {
        leader: Proc::Zombie,
        live_member_besides_leader: false,
        signalable: true,
    };

    /// A group with no process left, its leader reaped.
    #[cfg(target_os = "linux")]
    const GONE: Stage = Stage {
        leader: Proc::Absent,
        live_member_besides_leader: false,
        signalable: false,
    };

    #[cfg(target_os = "linux")]
    #[test]
    fn a_reap_between_the_probes_never_reads_a_dead_group_alive() {
        let zombie_member_after_reap = Stage {
            signalable: true,
            ..GONE
        };
        for (before, after) in [
            (ZOMBIE_LEADER_ALONE, GONE),
            (ZOMBIE_LEADER_ALONE, zombie_member_after_reap),
            (zombie_member_after_reap, GONE),
        ] {
            for probes in 0..=3 {
                assert_eq!(
                    verdict_across(before, after, probes),
                    Group::Dead,
                    "{before:?} -> {after:?} after {probes} probes"
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_live_group_never_reads_dead() {
        let running = Stage {
            leader: Proc::Running,
            live_member_besides_leader: false,
            signalable: true,
        };
        let running_with_member = Stage {
            live_member_besides_leader: true,
            ..running
        };
        let zombie_leader_with_member = Stage {
            leader: Proc::Zombie,
            ..running_with_member
        };
        let member_after_reap = Stage {
            leader: Proc::Absent,
            ..running_with_member
        };
        for (before, after) in [
            (running, running),
            (running_with_member, zombie_leader_with_member),
            (zombie_leader_with_member, zombie_leader_with_member),
            (zombie_leader_with_member, member_after_reap),
            (member_after_reap, member_after_reap),
        ] {
            for probes in 0..=3 {
                assert_eq!(
                    verdict_across(before, after, probes),
                    Group::Alive,
                    "{before:?} -> {after:?} after {probes} probes"
                );
            }
        }
    }

    /// Poll `done` every 20 ms for at most 5 s, returning the reading that ended the wait.
    #[cfg(target_os = "linux")]
    fn poll_until(mut done: impl FnMut() -> bool) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut reading = done();
        while !reading && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
            reading = done();
        }
        reading
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_zombie_leader_with_a_live_member_is_not_a_dead_group() {
        let mut shell = std::process::Command::new("/bin/sh");
        shell.args(["-c", "sleep 30 & exit 0"]);
        let (mut child, id) = test_group::spawn_detached(shell).expect("spawn sh");
        let id = id.expect("a detached group");
        let pgid = id.as_raw_nonzero().get();
        let leader_exited = poll_until(|| test_group::exited(id).is_ok_and(|exited| exited));
        let dead_with_member = group_is_dead(pgid);
        test_group::kill(id);
        let dead_after_kill = poll_until(|| group_is_dead(pgid));
        test_group::forget(id);
        let _ = child.wait();
        let dead_after_reap = group_is_dead(pgid);
        assert!(leader_exited, "the group leader never exited");
        assert!(
            !dead_with_member,
            "a zombie leader with a live member read as a dead group"
        );
        assert!(dead_after_kill, "the killed group never read dead");
        assert!(dead_after_reap, "the reaped group read alive");
    }

    /// Spawn a detached `sleep 30` transfer group.
    #[cfg(target_os = "linux")]
    fn spawn_sleeper() -> (std::process::Child, rustix::process::Pid) {
        let mut sleeper = std::process::Command::new("sleep");
        sleeper.arg("30");
        let (child, id) = test_group::spawn_detached(sleeper).expect("spawn sleep");
        (child, id.expect("a detached group"))
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_termination_request_ends_the_transfer_group_and_then_the_cli() {
        use std::os::unix::process::ExitStatusExt as _;
        if parent_holds_termination() {
            return;
        }
        let output = test_child::run(
            "trap - TERM;",
            "terminate::tests::default_termination_child",
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.signal(), Some(SIGTERM), "{output:?}");
        let group = stdout
            .lines()
            .find_map(|line| line.split_once(ARMED).map(|(_, pid)| pid))
            .and_then(|pid| pid.trim().parse::<i32>().ok())
            .expect("the child reports its transfer group");
        let dead = poll_until(|| group_is_dead(group));
        assert!(dead, "the transfer group outlived the CLI");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_ignored_termination_request_leaves_the_cli_and_its_transfer_running() {
        let output = test_child::run(
            "trap '' TERM;",
            "terminate::tests::ignored_termination_child",
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "child failed: {output:?}");
        assert!(stdout.contains(SURVIVED), "child output: {output:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_second_termination_request_during_shutdown_ends_the_cli() {
        // The child's shutdown subscriber never returns, so only a second
        // request answered beside it can end the child by the signal.
        use std::os::unix::process::ExitStatusExt as _;
        if parent_holds_termination() {
            return;
        }
        let output = test_child::run("trap - TERM;", "terminate::tests::second_request_child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(SHUTDOWN_RAN), "child output: {output:?}");
        assert!(stdout.contains(FIRST_ANSWERED), "child output: {output:?}");
        assert_eq!(output.status.signal(), Some(SIGTERM), "{output:?}");
    }

    /// Printed by [`attached_child_end`] once ending every transfer killed its attached child.
    #[cfg(target_os = "linux")]
    const ATTACHED_ENDED: &str = "ipe-terminate-attached-ended";

    /// Printed by [`probe_child`] once its probe ran and no signal owner was installed.
    #[cfg(target_os = "linux")]
    const PROBE_UNOWNED: &str = "ipe-terminate-probe-unowned";

    #[cfg(target_os = "linux")]
    #[test]
    fn ending_every_transfer_kills_a_child_attached_to_the_cli_group() {
        let output = test_child::run("", "terminate::tests::attached_child_end");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "child failed: {output:?}");
        assert!(stdout.contains(ATTACHED_ENDED), "child output: {output:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_disposition_probe_installs_no_signal_owner() {
        let output = test_child::run("", "terminate::tests::probe_child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "child failed: {output:?}");
        assert!(stdout.contains(PROBE_UNOWNED), "child output: {output:?}");
    }

    /// The child half of the attached-child test.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "child half of ending_every_transfer_kills_a_child_attached_to_the_cli_group"]
    fn attached_child_end() {
        let mut sleeper = std::process::Command::new("sleep");
        sleeper.arg("30");
        let (mut child, id) = test_group::spawn_attached(sleeper).expect("spawn sleep");
        let id = id.expect("an attached child known to the termination owner");
        crate::remote_ingest::end_transfers();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut ended = false;
        while !ended && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
            ended = test_group::exited(id).expect("probe the child");
        }
        test_group::forget_attached(id);
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            ended,
            "ending every transfer left the attached child running"
        );
        report(ATTACHED_ENDED);
    }

    /// The child half of the probe test.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "child half of the_disposition_probe_installs_no_signal_owner"]
    fn probe_child() {
        let mut probe = std::process::Command::new("/bin/sh");
        probe.args(["-c", "echo 0 0"]);
        let captured =
            crate::remote_ingest::run_probe(probe, super::PS_STDOUT_MAX_BYTES, super::PS_WALL)
                .expect("the probe runs");
        assert_eq!(
            super::ps_fields(&captured.stdout),
            Some((super::SignalSet(0), super::SignalSet(0)))
        );
        assert!(
            super::INSTALLED.get().is_none(),
            "the probe installed a signal owner"
        );
        report(PROBE_UNOWNED);
    }

    /// The child half of the default termination test: the request kills the
    /// group and the CLI ends by the signal.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "child half of a_termination_request_ends_the_transfer_group_and_then_the_cli"]
    fn default_termination_child() {
        let (mut child, id) = spawn_sleeper();
        report(&format!("{ARMED}{}", id.as_raw_nonzero()));
        signal_hook::low_level::raise(SIGTERM).expect("raise the termination request");
        std::thread::sleep(std::time::Duration::from_secs(5));
        let _ = child.kill();
        let _ = child.wait();
    }

    /// The child half of the ignored termination test: a request raised while
    /// a transfer group runs leaves both the CLI and the group alive.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "child half of an_ignored_termination_request_leaves_the_cli_and_its_transfer_running"]
    fn ignored_termination_child() {
        let Inherited::Known { ignored, .. } = super::inherited() else {
            return;
        };
        if !ignored.contains(SIGTERM) {
            return;
        }
        let (mut child, id) = spawn_sleeper();
        signal_hook::low_level::raise(SIGTERM).expect("raise the termination request");
        std::thread::sleep(std::time::Duration::from_millis(500));
        let alive = !test_group::exited(id).expect("probe the group");
        test_group::kill(id);
        test_group::forget(id);
        let _ = child.wait();
        assert!(alive, "the ignored request ended the transfer group");
        report(SURVIVED);
    }

    /// The child half of the second-request test: the first request ends the
    /// transfer and starts a subscriber that never returns; the second ends
    /// the CLI.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "child half of a_second_termination_request_during_shutdown_ends_the_cli"]
    fn second_request_child() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static STARTED: AtomicBool = AtomicBool::new(false);
        super::on_shutdown(|| {
            report(SHUTDOWN_RAN);
            STARTED.store(true, Ordering::SeqCst);
            loop {
                std::thread::park();
            }
        })
        .expect("subscribe to the shutdown");
        let (mut child, id) = spawn_sleeper();
        signal_hook::low_level::raise(SIGTERM).expect("raise the first request");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut ended = false;
        while !ended && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
            ended = test_group::exited(id).expect("probe the group");
        }
        test_group::forget(id);
        let _ = child.wait();
        assert!(ended, "the first request left the transfer group running");
        while !STARTED.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        report(FIRST_ANSWERED);
        signal_hook::low_level::raise(SIGTERM).expect("raise the second request");
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

//! Parent-death floor contract for `system::spawn_hardened{,_tokio}`.
//!
//! `PR_SET_PDEATHSIG` fires when the THREAD that forked the child exits, so a
//! hardened child must be forked by the process-lifetime spawner thread:
//!
//! 1. a child requested from a thread that has since exited (a plain
//!    `std::thread`, or a reaped tokio blocking-pool thread) stays alive;
//! 2. a child whose parent PROCESS is `SIGKILL`ed dies with it;
//! 3. the tokio entry point refuses outside a runtime rather than spawning.
#![cfg(target_os = "linux")]

use ipe_runtime_rust::system::spawn_hardened;
use std::io::BufRead as _;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Set on the re-executed probe; its presence selects probe mode.
const PROBE_MODE_ENV: &str = "IPE_PDEATH_PROBE";

/// Prefix of the stdout line on which the probe reports its hardened child's pid.
const PROBE_PID_PREFIX: &str = "ipe-pdeath-probe-pid=";

/// How long a child must outlive its requesting thread to count as alive.
const OUTLIVE: Duration = Duration::from_millis(300);

/// Ceiling on every poll in this file.
const POLL_CEILING: Duration = Duration::from_secs(10);

fn sleep_30() -> Command {
    let mut cmd = Command::new("/bin/sleep");
    cmd.arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd
}

fn kill_and_reap(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn a_child_outlives_the_thread_that_requested_it() {
    let mut child = std::thread::Builder::new()
        .spawn(|| spawn_hardened(sleep_30()))
        .expect("spawn test thread")
        .join()
        .expect("requesting thread")
        .expect("hardened spawn");
    std::thread::sleep(OUTLIVE);
    let running = child.try_wait().expect("poll child").is_none();
    kill_and_reap(child);
    assert!(
        running,
        "the child must outlive the thread that requested it"
    );
}

/// One process as `/proc/<pid>/stat` reports it.
struct ProcStat {
    /// Executable name, between the first `(` and the last `)`.
    comm: String,
    /// State letter (field 3).
    state: char,
    /// Start time in clock ticks since boot (field 22).
    start_ticks: u64,
}

impl ProcStat {
    /// The pid's current stat line, or `None` once the pid no longer exists.
    fn read(pid: u32) -> Option<Self> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let (head, rest) = stat.rsplit_once(')')?;
        let (_, comm) = head.split_once('(')?;
        let mut fields = rest.split_whitespace();
        let state = fields.next()?.chars().next()?;
        let start_ticks = fields.nth(18)?.parse().ok()?;
        Some(Self {
            comm: comm.to_owned(),
            state,
            start_ticks,
        })
    }

    /// Whether `other` is this same process rather than a reuse of its pid.
    fn same_process(&self, other: &Self) -> bool {
        self.start_ticks == other.start_ticks && self.comm == other.comm
    }
}

#[test]
fn a_hardened_child_dies_with_its_killed_parent() {
    #[allow(clippy::disallowed_methods)] // an integration test has no crate-private env accessor
    let probe_mode = std::env::var_os(PROBE_MODE_ENV).is_some();
    if probe_mode {
        // Probe mode: spawn the hardened grandchild, report its pid on stdout,
        // then block on it until the outer test SIGKILLs this probe.
        let mut child = spawn_hardened(sleep_30()).expect("probe hardened spawn");
        println!("{PROBE_PID_PREFIX}{}", child.id());
        let _ = child.wait();
    } else {
        let mut probe = Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "a_hardened_child_dies_with_its_killed_parent",
                "--exact",
                "--nocapture",
            ])
            .env(PROBE_MODE_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("re-exec probe");
        let stdout = probe.stdout.take().expect("probe stdout pipe");

        // The reader ends at EOF: the probe is killed below, and the grandchild
        // holds no copy of the pipe.
        let (pid_tx, pid_rx) = std::sync::mpsc::channel::<u32>();
        let reader = std::thread::Builder::new()
            .spawn(move || {
                let reported = std::io::BufReader::new(stdout)
                    .lines()
                    .map_while(Result::ok)
                    .find_map(|line| line.strip_prefix(PROBE_PID_PREFIX)?.trim().parse().ok());
                if let Some(pid) = reported {
                    let _ = pid_tx.send(pid);
                }
            })
            .expect("spawn test thread");
        let grandchild = pid_rx.recv_timeout(POLL_CEILING).ok();
        // Captured before the probe dies, while its pid names the grandchild.
        let identity = grandchild.and_then(ProcStat::read);
        let _ = probe.kill();
        let _ = probe.wait();
        reader.join().expect("probe stdout reader");
        let grandchild = grandchild.expect("the probe must report its hardened child's pid");
        let identity = identity.expect("the hardened child must be running before its parent dies");

        let killed = Instant::now();
        let died = loop {
            match ProcStat::read(grandchild) {
                None => break true,
                Some(current) if !identity.same_process(&current) || current.state == 'Z' => {
                    break true;
                }
                Some(_) if killed.elapsed() >= POLL_CEILING => break false,
                Some(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        // Kill only the process first observed: a reused pid belongs to someone else.
        let still_ours =
            ProcStat::read(grandchild).is_some_and(|current| identity.same_process(&current));
        if !died && still_ours {
            let _ = Command::new("/bin/kill")
                .args(["-KILL", &grandchild.to_string()])
                .status();
        }
        assert!(
            died,
            "a hardened child must die when its parent process is killed"
        );
    }
}

#[cfg(feature = "web")]
mod tokio_entry {
    use super::OUTLIVE;
    use ipe_runtime_rust::system::{SpawnRefusal, spawn_hardened_tokio};
    use std::time::Duration;

    fn tokio_sleep_30() -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new("/bin/sleep");
        cmd.arg("30").kill_on_drop(true);
        cmd
    }

    #[test]
    fn a_child_outlives_the_reaped_blocking_thread_that_requested_it() {
        let keep_alive = Duration::from_millis(50);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_keep_alive(keep_alive)
            .enable_all()
            .build()
            .expect("runtime");
        let running = rt.block_on(async {
            let mut child = ipe_runtime_rust::threads::offload_blocking("pdeath-probe", || {
                spawn_hardened_tokio(tokio_sleep_30())
            })
            .expect("offload to the blocking pool")
            .await
            .expect("blocking task")
            .expect("hardened tokio spawn");
            tokio::time::sleep(keep_alive + OUTLIVE).await;
            let running = child.try_wait().expect("poll child").is_none();
            let _ = child.start_kill();
            let _ = child.wait().await;
            running
        });
        assert!(running, "the child must outlive the reaped blocking thread");
    }

    /// Called straight from a task on a current-thread runtime (the web
    /// console-proxy shape), the spawn completes: the spawner registers the
    /// child with the runtime while its only thread waits for the reply.
    #[test]
    fn a_current_thread_runtime_spawns_without_deadlock() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let status = rt.block_on(async {
            let mut cmd = tokio::process::Command::new("/bin/true");
            cmd.kill_on_drop(true);
            let mut child = spawn_hardened_tokio(cmd).expect("hardened tokio spawn");
            tokio::time::timeout(Duration::from_secs(10), child.wait()).await
        });
        let status = status
            .expect("the child must be reaped in time")
            .expect("wait");
        assert!(status.success(), "hardened /bin/true must exit 0");
    }

    #[test]
    fn the_tokio_entry_refuses_outside_a_runtime() {
        let refused = spawn_hardened_tokio(tokio::process::Command::new("/bin/true"));
        assert!(
            matches!(refused, Err(SpawnRefusal::NoRuntime)),
            "{refused:?}"
        );
    }
}

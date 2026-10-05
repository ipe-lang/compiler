//! The isolation jail every untrusted-crate compile/inspect runs inside.
//!
//! `ipe add <crate>` compiles foreign code, and compiling Rust executes
//! foreign code (`build.rs`, proc-macros) — remote code execution gated only
//! by a crate name. This crate confines that RCE surface so the FFI
//! decode/emit core (`ipe_ffi`) stays process-capability-free:
//!
//! * **bubblewrap is the jail** — `/` read-only, one scoped writable tempdir,
//!   env scrubbed to an allowlist, fresh PID/UTS/IPC/cgroup namespaces,
//!   mandatory rlimit + wall-clock caps. The two-phase driver splits a
//!   network-on `FetchOnly` phase (trusted `cargo` only, no foreign code)
//!   from a `Denied` compile/introspect phase (fresh empty net namespace, no
//!   egress) where the foreign code runs.
//! * **Refusal is the default** (`IPE-F4410`) when bubblewrap is absent OR the
//!   `timeout`/`prlimit` cap helpers are absent — an uncapped jail is never
//!   built. The only override is `IPE_FFI_ALLOW_UNSANDBOXED=1`, which the
//!   driver must surface with a printed trust warning.
//!
//! There is no shell anywhere in this crate: every invocation is a direct
//! argv (`std::process::Command`), so the quoting/injection class does not
//! exist here.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use ipe_diagnostics::{Code, Diagnostic as SharedDiag, IPE_F4410, SandboxError};

pub use covers::{JailMounts, bind_exposing, path_covers};
pub use mounts::{CanonicalPath, HomeMasks, JailPathError, MaskedDir};
pub use vcs_config::{
    ConfigFault, ConfigLimits, ConfigRefusal, ConfigRoots, ConfigSetting, Grants, Home, MAX_LINKS,
    MAX_MODULE_DEPTH, MAX_PATH_BYTES, MAX_PATH_COMPONENTS, MAX_WORDS, Named, Unprovable,
    scan as scan_vcs_config,
};
pub use vcs_metadata::{
    CarvePath, JailArm, MAX_CARVE_ENTRIES, MAX_DEPTH, MAX_HELD_NAME_BYTES, MAX_PIN_MOUNTS,
    MAX_WALK_ENTRIES, POINTER_CAP, PointerFault, VcsCarve, VcsKind, WalkCeiling, WalkLimits,
    WritableTree,
};

pub mod build_jail;
// Names every path the root `clippy.toml` denies, so a stale path breaks the
// test build instead of silently disabling its lint.
#[cfg(test)]
mod clippy_paths_resolve;
mod covers;
pub mod home;
pub mod host_env;
mod mounts;
pub mod run_jail;
pub mod scratch;
pub mod seccomp;
#[cfg(test)]
mod test_dir;
mod vcs_config;
mod vcs_keys;
mod vcs_metadata;

/// Why a jail could not be established or a jailed run failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxDefect {
    /// Bubblewrap is not available.
    NoIsolationMechanism,
    /// A mandatory cap helper (`timeout` / `prlimit`) is absent, so a
    /// jail with a wall clock and rlimits cannot be built — refuse rather
    /// than run untrusted code uncapped.
    CapsUnavailable {
        /// The helper names that were missing.
        missing: Vec<&'static str>,
    },
    /// The jailed process could not be spawned or awaited.
    Spawn {
        /// The program that failed to spawn.
        program: String,
        /// The rendered OS error.
        detail: String,
    },
    /// The jailed process produced more output than the configured cap.
    OutputCapExceeded {
        /// The configured cap in bytes.
        cap_bytes: u64,
    },
    /// A seccomp filter was requested but the `bwrap` token could not be found
    /// in the rendered argv, so `--seccomp` could not be attached. Running
    /// without the filter is fail-open, so the jail refuses instead.
    SeccompNotAttached,
    /// A path the jail would mount or hand to the payload could not be
    /// resolved, or a home it must mask is unknown.
    Path(JailPathError),
    /// The OS refused to start an output-drain thread. The child is killed
    /// and reaped before this is returned, so the jail is never left
    /// running.
    DrainThread(std::io::ErrorKind),
}

impl SandboxDefect {
    /// The stable taxonomy code (`IPE-F4410` for the whole family).
    #[must_use]
    pub const fn code(&self) -> Code {
        IPE_F4410
    }
}

impl From<SandboxDefect> for SandboxError {
    fn from(d: SandboxDefect) -> Self {
        let detail = match &d {
            SandboxDefect::NoIsolationMechanism => {
                "cannot establish an isolation jail (bwrap absent); refusing to compile \
                 an untrusted crate unsandboxed"
                    .to_owned()
            }
            SandboxDefect::CapsUnavailable { missing } => format!(
                "mandatory sandbox cap helper(s) absent ({}); refusing to run untrusted code \
                 without a wall clock and rlimits — install coreutils (timeout) and util-linux \
                 (prlimit)",
                missing.join(", ")
            ),
            SandboxDefect::Spawn { program, detail } => {
                format!("failed to run the jailed process `{program}`: {detail}")
            }
            SandboxDefect::OutputCapExceeded { cap_bytes } => {
                format!("the jailed process exceeded the {cap_bytes}-byte output cap")
            }
            SandboxDefect::SeccompNotAttached => {
                "could not attach the seccomp filter to the jail (bwrap token absent from \
                 the rendered argv); refusing to run untrusted code without its syscall filter"
                    .to_owned()
            }
            SandboxDefect::Path(e) => e.to_string(),
            SandboxDefect::DrainThread(kind) => format!(
                "the OS refused to start an output-drain thread ({kind}); the jailed process \
                 was killed and reaped"
            ),
        };
        Self::BuildJail {
            detail: detail.into(),
        }
    }
}

impl From<SandboxDefect> for SharedDiag {
    fn from(d: SandboxDefect) -> Self {
        Self::Sandbox {
            msg: SandboxError::from(d),
        }
    }
}

impl fmt::Display for SandboxDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let shared: SharedDiag = self.clone().into();
        f.write_str(&ipe_diagnostics::render(&shared, "", ""))
    }
}

impl std::error::Error for SandboxDefect {}

// ── capability probe ────────────────────────────────────────────────────────

/// The host tools the jail is built from. `timeout` and `prlimit` are
/// mandatory: an uncapped jail is never constructed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Capabilities {
    /// `bwrap` (bubblewrap) — the jail.
    pub bwrap: Option<PathBuf>,
    /// `prlimit` — resource caps (mandatory).
    pub prlimit: Option<PathBuf>,
    /// `timeout` — the wall clock (mandatory).
    pub timeout: Option<PathBuf>,
}

/// Probe `PATH` for the jail tools.
#[must_use]
pub fn probe() -> Capabilities {
    Capabilities {
        bwrap: find_in_path("bwrap"),
        prlimit: find_in_path("prlimit"),
        timeout: find_in_path("timeout"),
    }
}

/// The mandatory cap helpers this host is missing (empty ⇒ all present).
#[must_use]
pub fn missing_caps(caps: &Capabilities) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if caps.timeout.is_none() {
        missing.push("timeout");
    }
    if caps.prlimit.is_none() {
        missing.push("prlimit");
    }
    missing
}

fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path = ipe_env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .find(|candidate| candidate.is_file())
}

/// The isolation mechanism selected for a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
    /// Bubblewrap — fails closed by itself.
    Bwrap(PathBuf),
    /// Bubblewrap is not available: refuse (`IPE-F4410`).
    Refused,
}

/// Select the isolation mechanism (bubblewrap-or-refuse).
#[must_use]
pub fn select_mechanism(caps: &Capabilities) -> Mechanism {
    caps.bwrap
        .clone()
        .map_or(Mechanism::Refused, Mechanism::Bwrap)
}

/// Whether the operator explicitly opted into unsandboxed execution. The
/// driver MUST print a trust warning when honouring this.
#[must_use]
pub fn unsandboxed_override_set() -> bool {
    ipe_env::var_os("IPE_FFI_ALLOW_UNSANDBOXED").is_some_and(|v| v == "1")
}

// ── jail specification ──────────────────────────────────────────────────────

/// Network posture of one jailed phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// Compile / introspect: a NEW empty net namespace — no egress.
    Denied,
    /// The explicit fetch phase: network stays on; every other control
    /// (read-only `/`, scrubbed env, caps) still applies.
    FetchOnly,
}

/// Resource caps for one jailed invocation (env-overridable by the driver,
/// which prints a warning when it does).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Address-space cap in bytes.
    pub rss_bytes: u64,
    /// CPU-seconds cap.
    pub cpu_secs: u64,
    /// Wall-clock cap in seconds (enforced by `timeout`).
    pub wall_secs: u64,
    /// Open-file-descriptor cap.
    pub fd_cap: u64,
    /// Process-count cap.
    pub proc_cap: u64,
    /// Maximum bytes read from the jailed process's stdout.
    pub out_cap_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        // Calibrated so ONE large generated SDK crate can be inspected
        // sandboxed without any override: a crate like `async-stripe-shared`
        // (thousands of generated types) builds its whole dependency closure
        // and then rustdoc-expands under one jailed process, whose peak
        // virtual-address-space and wall-clock exceed the caps a small crate
        // needs. The install driver CHUNKS a multi-crate manifest into one
        // jailed process PER crate, so these caps bound a single crate's
        // inspection, not a whole SDK's — a runaway build script is still
        // killed, just at a ceiling a real SDK crate does not hit.
        Self {
            // Address-space (rlimit AS), not resident memory: rustdoc on a huge
            // crate maps far more virtual space than it makes resident, so the
            // 4 GiB AS cap SIGKILLs it while its resident set stays a few hundred
            // MiB. 10 GiB clears that (verified against `async-stripe-shared`)
            // while keeping resident use far below the host memory guard.
            rss_bytes: 10 * 1024 * 1024 * 1024,
            cpu_secs: 900,
            wall_secs: 900,
            fd_cap: 256,
            proc_cap: 512,
            out_cap_bytes: 256 * 1024 * 1024,
        }
    }
}

/// One jailed invocation: where it may write, what it may see, how big it
/// may grow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JailSpec {
    /// Network posture for this phase.
    pub network: NetworkPolicy,
    /// The per-invocation scoped tempdir — the ONLY writable mount, the
    /// working directory, and `TMPDIR`.
    pub scoped_tmp: CanonicalPath,
    /// Pre-fetched crate sources, bound read-only (compile jail).
    pub registry_cache: Option<CanonicalPath>,
    /// The pinned nightly toolchain name exported as `RUSTUP_TOOLCHAIN`.
    pub toolchain: Option<String>,
    /// Toolchain directories re-bound read-only through the home masks (a
    /// rustup install lives under the invoking user's home, which the masks
    /// would otherwise hide). Read-only: the payload can execute the toolchain
    /// but never mutate it.
    pub toolchain_ro_binds: Vec<CanonicalPath>,
    /// The invoker's homes, masked wherever they live; below them only the
    /// binds of this spec stay visible.
    pub homes: HomeMasks,
    /// Directories prepended to the jail's `PATH` (toolchain `bin` dirs),
    /// each also bound read-only.
    pub path_prepend: Vec<CanonicalPath>,
    /// The rustup root exported as `RUSTUP_HOME` (the env is scrubbed, so the
    /// proxy binaries cannot discover it from `$HOME`), also bound read-only.
    pub rustup_home: Option<CanonicalPath>,
    /// Resource caps.
    pub limits: ResourceLimits,
}

/// The full jail argv for one payload: `timeout … bwrap … prlimit … payload`.
///
/// Pure — no process is spawned — so the exact isolation surface is
/// unit-testable. The env is scrubbed with `--clearenv`; only the fixed
/// allowlist re-enters. There is NO shell token anywhere in the result.
///
/// `prlimit` and `timeout` are non-optional: an argv that omits the wall
/// clock or the rlimits is unrepresentable, so untrusted code can never run
/// uncapped. A host missing either helper is refused upstream
/// ([`missing_caps`]) before this is reached.
///
/// # Errors
/// Any error of [`mounts::push_mounts`].
pub fn bwrap_argv(
    bwrap: &Path,
    prlimit: &Path,
    timeout: &Path,
    spec: &JailSpec,
    payload: &[OsString],
) -> Result<Vec<OsString>, JailPathError> {
    // The wall clock wraps everything: `timeout --kill-after=5s <wall> bwrap …`.
    let mut argv: Vec<OsString> = vec![
        timeout.into(),
        "--kill-after=5s".into(),
        spec.limits.wall_secs.to_string().into(),
        bwrap.into(),
    ];
    if spec.network == NetworkPolicy::Denied {
        argv.push("--unshare-net".into());
    }
    for flag in [
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-ipc",
        "--unshare-cgroup",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
    ] {
        argv.push(flag.into());
    }
    argv.push("--ro-bind".into());
    argv.push("/".into());
    argv.push("/".into());
    // Fresh proc mask AFTER the ro-bind of root, same ordering as the run jail.
    // `--ro-bind / /` exposes the host `/proc` (leaks sibling env via
    // `/proc/<pid>/environ`, defeating `--clearenv`, and is a user-namespace
    // escape lever); `--proc /proc` masks it with a fresh minimal procfs.
    // bwrap applies mount ops in argv order, so proc-after-robind wins.
    argv.push("--proc".into());
    argv.push("/proc".into());
    // A fresh minimal devtmpfs: the ro-bound host `/dev` nodes carry no device
    // permissions inside the user namespace, so `/dev/null` opens fail EACCES
    // — which cargo hits when wiring child stdio.
    argv.push("--dev".into());
    argv.push("/dev".into());
    // Mask the homes and `/tmp`, then re-expose the crate sources and the
    // toolchain read-only and the scoped tempdir writable. Every path the
    // payload is handed below (`PATH`, `RUSTUP_HOME`, `--chdir`, `TMPDIR`) is
    // one of these bound values, so none names a masked location.
    let mut binds: Vec<mounts::Bind<'_>> = Vec::new();
    binds.extend(spec.registry_cache.iter().map(mounts::Bind::ReadOnly));
    binds.extend(spec.toolchain_ro_binds.iter().map(mounts::Bind::ReadOnly));
    binds.extend(spec.path_prepend.iter().map(mounts::Bind::ReadOnly));
    binds.extend(spec.rustup_home.iter().map(mounts::Bind::ReadOnly));
    binds.push(mounts::Bind::ReadWrite(&spec.scoped_tmp));
    mounts::push_mounts(&mut argv, &spec.homes, &binds)?;
    let scoped_tmp = spec.scoped_tmp.as_path();
    argv.push("--chdir".into());
    argv.push(scoped_tmp.into());
    let cargo_home = scoped_tmp.join("cargo-home");
    let mut path_value = String::new();
    for dir in &spec.path_prepend {
        path_value.push_str(&dir.as_path().to_string_lossy());
        path_value.push(':');
    }
    path_value.push_str("/usr/bin:/bin");
    let mut setenvs: Vec<(&str, OsString)> = Vec::new();
    // The fetch phase must reach the registry; every compile/introspect
    // phase stays offline.
    if spec.network == NetworkPolicy::Denied {
        setenvs.push(("CARGO_NET_OFFLINE", "1".into()));
    }
    setenvs.push(("CARGO_HOME", cargo_home.into()));
    setenvs.push(("PATH", path_value.into()));
    setenvs.push(("TMPDIR", scoped_tmp.into()));
    for (key, value) in setenvs {
        argv.push("--setenv".into());
        argv.push(key.into());
        argv.push(value);
    }
    if let Some(tc) = &spec.toolchain {
        argv.push("--setenv".into());
        argv.push("RUSTUP_TOOLCHAIN".into());
        argv.push(tc.into());
    }
    if let Some(rustup_home) = &spec.rustup_home {
        argv.push("--setenv".into());
        argv.push("RUSTUP_HOME".into());
        argv.push(rustup_home.as_path().into());
    }
    argv.push("--".into());
    argv.push(prlimit.into());
    argv.push(format!("--as={}", spec.limits.rss_bytes).into());
    argv.push(format!("--cpu={}", spec.limits.cpu_secs).into());
    argv.push(format!("--nofile={}", spec.limits.fd_cap).into());
    argv.push(format!("--nproc={}", spec.limits.proc_cap).into());
    argv.push(format!("--fsize={}", spec.limits.out_cap_bytes).into());
    argv.push("--".into());
    argv.extend(payload.iter().cloned());
    Ok(argv)
}

// ── jailed execution ────────────────────────────────────────────────────────

/// Output of a jailed run, with stdout bounded by the configured cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JailedOutput {
    /// Exit status code (`None` when killed by a signal / the wall clock).
    pub status: Option<i32>,
    /// Captured stdout, at most `out_cap_bytes`.
    pub stdout: Vec<u8>,
    /// Captured stderr, bounded by the same cap.
    pub stderr: Vec<u8>,
}

/// Run `payload` inside the bubblewrap jail described by `spec`.
///
/// Stdout is read with a hard byte cap — a 76k-symbol crate must not OOM
/// the host; exceeding the cap is a defect, not a truncation.
///
/// # Errors
///
/// [`SandboxDefect::Spawn`] when the jail cannot start;
/// [`SandboxDefect::OutputCapExceeded`] when the payload out-talks the cap.
pub fn run_in_bwrap_jail(
    caps: &Capabilities,
    spec: &JailSpec,
    payload: &[OsString],
) -> Result<JailedOutput, SandboxDefect> {
    run_bwrap(caps, spec, payload, None)
}

/// Run `payload` in the bubblewrap jail under a subprocess-deny seccomp filter.
///
/// The filter denies the legacy subprocess syscalls (`fork`/`vfork`/process-
/// `clone`, with thread-`clone` still allowed) — the same
/// [`seccomp::subprocess_deny_program`] the run jail installs, so the two paths
/// cannot drift.
///
/// This is the run posture for untrusted *program execution* (as opposed to a
/// build, which legitimately spawns rustc + a linker). It is a best-effort
/// narrowing of the common spawn paths, NOT absolute subprocess denial: `clone3`
/// (which modern `posix_spawn` uses) is allowed unconditionally because thread
/// creation routes through it and seccomp cannot inspect its pointer-borne flags.
/// The security boundary a spawned child cannot cross is the bubblewrap namespace
/// itself — the caller relies on `--unshare-net`, the read-only root, and the
/// `prlimit` caps to confine any child to the parent's capability set, and on
/// `--nproc` + the wall clock to bound a fork bomb.
///
/// Fail-closed: on any architecture with no compilable filter (neither `x86_64`
/// nor `aarch64`) this REFUSES rather than running the payload unfiltered.
///
/// # Errors
///
/// [`SandboxDefect::NoIsolationMechanism`] when no seccomp filter can be built for
/// this architecture (fail-closed); otherwise as [`run_in_bwrap_jail`].
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub fn run_in_bwrap_jail_deny_subprocess(
    caps: &Capabilities,
    spec: &JailSpec,
    payload: &[OsString],
) -> Result<JailedOutput, SandboxDefect> {
    // `allow_subprocess = false` ⇒ the fork/process-clone family is denied.
    let Some(program) = seccomp::subprocess_deny_program(false) else {
        // No filter can be compiled here — refuse rather than run unfiltered.
        return Err(SandboxDefect::NoIsolationMechanism);
    };
    let bytes = seccomp::program_bytes(&program);
    // The memfd is owned in the PARENT so it is closed on return — this launcher
    // `spawn`s (not `exec`s) and the server is long-lived, so a leaked fd per
    // request would exhaust the process's file-descriptor limit. The child gets
    // its own inherited copy across `spawn`, so closing the parent's copy after
    // the run does not disturb the jailed process.
    let owned = run_jail::write_seccomp_memfd(&bytes).map_err(|d| SandboxDefect::Spawn {
        program: "seccomp".to_owned(),
        detail: d.to_string(),
    })?;
    // The sealed seccomp fd MUST be inheritable so bwrap reads the filter from it
    // across the spawn. Clearing close-on-exec here, in the parent, refuses the
    // run (fail-closed) when the flag cannot be cleared, rather than run the
    // payload without its filter.
    // Known limit: between this close-on-exec clear and the spawn, a sibling child
    // forked by another thread inherits the same open file description. The seal
    // blocks writes, not a shared-offset `lseek`/`read`, so this fd must reach only
    // its one child.
    let seccomp_fd = owned.make_inheritable().map_err(|e| SandboxDefect::Spawn {
        program: "seccomp".to_owned(),
        detail: format!("clearing close-on-exec on the seccomp memfd failed: {e}"),
    })?;
    let out = run_bwrap(caps, spec, payload, Some(seccomp_fd));
    drop(owned);
    out
}

/// The shared spawn+drain core for both the plain and the subprocess-denied jail.
///
/// When `seccomp_fd` is `Some`, `--seccomp <fd>` is inserted into the bwrap argv;
/// the caller owns that sealed fd and has already made it inheritable, so bwrap
/// reads the filter from it across the exec.
fn run_bwrap(
    caps: &Capabilities,
    spec: &JailSpec,
    payload: &[OsString],
    seccomp_fd: Option<run_jail::SealedFdNumber<'_>>,
) -> Result<JailedOutput, SandboxDefect> {
    let Some(bwrap) = &caps.bwrap else {
        return Err(SandboxDefect::NoIsolationMechanism);
    };
    // Mandatory caps: refuse before building an argv rather than run an
    // uncapped jail. `bwrap_argv`'s non-optional params make this the only
    // way to reach it, so an uncapped jail is unrepresentable.
    let (Some(prlimit), Some(timeout)) = (&caps.prlimit, &caps.timeout) else {
        return Err(SandboxDefect::CapsUnavailable {
            missing: missing_caps(caps),
        });
    };
    let argv = bwrap_argv_with_seccomp(bwrap, prlimit, timeout, spec, payload, seccomp_fd)?;
    let (program, rest) = argv
        .args()
        .split_first()
        .ok_or(SandboxDefect::NoIsolationMechanism)?;
    let spawn_err = |e: std::io::Error| SandboxDefect::Spawn {
        program: program.to_string_lossy().into_owned(),
        detail: e.to_string(),
    };
    let mut cmd = std::process::Command::new(program);
    cmd.args(rest)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let child = cmd.spawn().map_err(spawn_err)?;
    drain_and_reap(child, spec.limits.out_cap_bytes, program)
}

/// Which jailed stream a drain thread read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stream {
    Stdout,
    Stderr,
}

/// One drain thread's report: which stream it read and the bounded outcome.
struct DrainOutcome {
    stream: Stream,
    result: Result<Option<Vec<u8>>, std::io::Error>,
}

/// Drain both pipes under the byte cap, killing the child the instant the cap
/// is breached, then reap it.
///
/// Stdout and stderr are read CONCURRENTLY: a payload that fills the stderr
/// pipe while stdout stays open (or vice-versa) would wedge a sequential
/// reader. Each stream is read in its own thread, and every thread reports
/// through one channel so the parent reacts to whichever finishes first rather
/// than blocking on a fixed join order.
fn drain_and_reap(
    mut child: std::process::Child,
    cap: u64,
    program: &std::ffi::OsStr,
) -> Result<JailedOutput, SandboxDefect> {
    let spawn_err = |e: std::io::Error| SandboxDefect::Spawn {
        program: program.to_string_lossy().into_owned(),
        detail: e.to_string(),
    };
    let out_handle = child.stdout.take();
    let err_handle = child.stderr.take();
    let (tx, rx) = std::sync::mpsc::channel::<DrainOutcome>();
    let out_tx = tx.clone();
    // A refused drain thread must not leave the jailed child running
    // unwatched: kill and reap it before returning the typed refusal.
    let out_thread = match std::thread::Builder::new()
        .name("ipe-jail-drain-stdout".to_owned())
        .spawn(move || {
            let _ = out_tx.send(DrainOutcome {
                stream: Stream::Stdout,
                result: read_bounded(out_handle, cap),
            });
        }) {
        Ok(handle) => handle,
        Err(e) => {
            let kind = e.kind();
            let _ = child.kill();
            let _ = child.wait();
            return Err(SandboxDefect::DrainThread(kind));
        }
    };
    let err_thread = match std::thread::Builder::new()
        .name("ipe-jail-drain-stderr".to_owned())
        .spawn(move || {
            let _ = tx.send(DrainOutcome {
                stream: Stream::Stderr,
                result: read_bounded(err_handle, cap),
            });
        }) {
        Ok(handle) => handle,
        Err(e) => {
            let kind = e.kind();
            let _ = child.kill();
            let _ = child.wait();
            let _ = out_thread.join();
            return Err(SandboxDefect::DrainThread(kind));
        }
    };
    let join_err = || SandboxDefect::Spawn {
        program: program.to_string_lossy().into_owned(),
        detail: "output-drain thread panicked".to_owned(),
    };
    let mut stdout: Option<Vec<u8>> = None;
    let mut stderr: Option<Vec<u8>> = None;
    let mut cap_exceeded = false;
    let mut read_error: Option<std::io::Error> = None;
    // Both drain threads always report exactly once, so two receives drain the
    // channel. The verdict is decided the instant the cap is breached, so kill
    // the jail on the FIRST cap breach or read error rather than waiting for
    // the still-running child to exit on its own or hit the wall clock.
    // Killing the direct child (the `timeout` wrapper) tears the whole jail
    // down through bwrap's `--die-with-parent`, which unblocks the other
    // reader (its pipe closes) and lets `child.wait()` reap promptly.
    for _ in 0..2 {
        let outcome = match rx.recv() {
            Ok(outcome) => outcome,
            // Each thread sends before returning, so a closed channel means
            // both reports are in; stop rather than block forever.
            Err(std::sync::mpsc::RecvError) => break,
        };
        match outcome.result {
            Ok(Some(bytes)) => match outcome.stream {
                Stream::Stdout => stdout = Some(bytes),
                Stream::Stderr => stderr = Some(bytes),
            },
            Ok(None) => {
                cap_exceeded = true;
                let _ = child.kill();
            }
            Err(e) => {
                read_error = Some(e);
                let _ = child.kill();
            }
        }
    }
    out_thread.join().map_err(|_| join_err())?;
    err_thread.join().map_err(|_| join_err())?;
    let status = child.wait().map_err(spawn_err)?;
    if let Some(e) = read_error {
        return Err(spawn_err(e));
    }
    if cap_exceeded {
        return Err(SandboxDefect::OutputCapExceeded { cap_bytes: cap });
    }
    match (stdout, stderr) {
        (Some(out), Some(err)) => Ok(JailedOutput {
            status: status.code(),
            stdout: out,
            stderr: err,
        }),
        // Unreachable: with no cap breach and no read error each stream yields
        // `Ok(Some(_))`, so both are populated. Fail closed on the cap defect
        // rather than fabricate an empty-output success.
        _ => Err(SandboxDefect::OutputCapExceeded { cap_bytes: cap }),
    }
}

/// [`bwrap_argv`] with an optional `--seccomp <fd>` flag injected immediately
/// after the `bwrap` program token (bwrap reads the filter from the inherited
/// fd). When `seccomp_fd` is `None` this is exactly [`bwrap_argv`].
///
/// When a filter is requested but the `bwrap` token cannot be located in the
/// rendered argv, the seccomp flag cannot be attached to bwrap — dropping it
/// would run the payload without its syscall filter (fail-open). The refusal
/// here keeps the seccomp guarantee: no filter, no run.
fn bwrap_argv_with_seccomp<'fd>(
    bwrap: &Path,
    prlimit: &Path,
    timeout: &Path,
    spec: &JailSpec,
    payload: &[OsString],
    seccomp_fd: Option<run_jail::SealedFdNumber<'fd>>,
) -> Result<run_jail::JailArgv<'fd>, SandboxDefect> {
    let mut argv = run_jail::JailArgv::fd_free(
        bwrap_argv(bwrap, prlimit, timeout, spec, payload).map_err(SandboxDefect::Path)?,
    );
    let Some(fd) = seccomp_fd else {
        return Ok(argv);
    };
    // The argv is `timeout … <wall> bwrap …`; insert `--seccomp <fd>` right after
    // the `bwrap` token so it is a bwrap option, not a timeout one.
    if !argv.attach_fd_after(bwrap.as_os_str(), "--seccomp", &fd) {
        return Err(SandboxDefect::SeccompNotAttached);
    }
    Ok(argv)
}

/// Read a stream up to `cap` bytes; `Ok(None)` when the stream exceeds it.
fn read_bounded<R: std::io::Read>(
    stream: Option<R>,
    cap: u64,
) -> Result<Option<Vec<u8>>, std::io::Error> {
    use std::io::Read;
    let Some(stream) = stream else {
        return Ok(Some(Vec::new()));
    };
    let mut buf = Vec::new();
    // Take one extra byte: reaching it proves the cap was exceeded.
    stream.take(cap.saturating_add(1)).read_to_end(&mut buf)?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > cap {
        return Ok(None);
    }
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> JailSpec {
        JailSpec {
            network: NetworkPolicy::Denied,
            scoped_tmp: CanonicalPath::assumed("/work/tmp-1"),
            registry_cache: Some(CanonicalPath::assumed("/work/registry")),
            toolchain: Some("nightly-2026-01-01".to_owned()),
            toolchain_ro_binds: Vec::new(),
            path_prepend: Vec::new(),
            rustup_home: None,
            homes: HomeMasks::unmasked(),
            limits: ResourceLimits::default(),
        }
    }

    fn rendered_argv(spec: &JailSpec) -> Vec<String> {
        let payload: Vec<OsString> = vec!["ipe-ffi-inspector".into(), "semver".into()];
        bwrap_argv(
            Path::new("/usr/bin/bwrap"),
            Path::new("/usr/bin/prlimit"),
            Path::new("/usr/bin/timeout"),
            spec,
            &payload,
        )
        .expect("the argv builds")
        .into_iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
    }

    #[test]
    fn jail_argv_denies_network_scrubs_env_and_bounds_resources() {
        let argv = rendered_argv(&spec());
        let joined = argv.join(" ");
        // Wall clock wraps everything.
        assert!(joined.starts_with("/usr/bin/timeout --kill-after=5s 900 /usr/bin/bwrap"));
        // Network denied, namespaces fresh, tty detached, env scrubbed.
        for flag in [
            "--unshare-net",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-ipc",
            "--unshare-cgroup",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
        ] {
            assert!(argv.contains(&flag.to_owned()), "missing {flag}: {joined}");
        }
        // Read-only root; tmpfs over every home; one writable mount.
        assert!(joined.contains("--ro-bind / /"), "{joined}");
        assert!(joined.contains("--tmpfs /home"), "{joined}");
        assert!(
            joined.contains("--ro-bind /work/registry /work/registry"),
            "{joined}"
        );
        assert!(
            joined.contains("--bind /work/tmp-1 /work/tmp-1"),
            "{joined}"
        );
        assert!(joined.contains("--chdir /work/tmp-1"), "{joined}");
        // Env allowlist only — offline cargo, scoped CARGO_HOME, fixed PATH.
        assert!(joined.contains("--setenv CARGO_NET_OFFLINE 1"), "{joined}");
        assert!(
            joined.contains("--setenv CARGO_HOME /work/tmp-1/cargo-home"),
            "{joined}"
        );
        assert!(joined.contains("--setenv PATH /usr/bin:/bin"), "{joined}");
        assert!(
            joined.contains("--setenv RUSTUP_TOOLCHAIN nightly-2026-01-01"),
            "{joined}"
        );
        // Resource caps via prlimit, then the payload with NO shell.
        assert!(
            joined.contains(
                "-- /usr/bin/prlimit --as=10737418240 --cpu=900 --nofile=256 --nproc=512"
            ),
            "{joined}"
        );
        assert!(joined.ends_with("-- ipe-ffi-inspector semver"), "{joined}");
        assert!(!joined.contains("sh -c"), "{joined}");
    }

    #[test]
    fn jail_argv_masks_the_invoker_homes_and_rebinds_only_the_toolchain() {
        let base_dir = crate::test_dir::TestDir::new("jail-homes").expect("test dir");
        let base = base_dir.path();
        let cargo_home = base.join("cargo");
        let user_home = base.join("user");
        std::fs::create_dir_all(cargo_home.join("bin")).expect("cargo home");
        std::fs::create_dir_all(&user_home).expect("user home");
        let cargo_home = std::fs::canonicalize(&cargo_home).expect("canonical cargo home");
        let user_home = std::fs::canonicalize(&user_home).expect("canonical user home");
        let bin = cargo_home.join("bin");
        let jail = JailSpec {
            // A whole-cargo-home bind must not survive the mask.
            toolchain_ro_binds: vec![
                CanonicalPath::resolve(&bin).expect("canonical bin"),
                CanonicalPath::resolve(&cargo_home).expect("canonical cargo home"),
            ],
            homes: HomeMasks::resolve(
                Ok(&crate::home::test_home(&user_home)),
                Some(&crate::home::test_tool_home(&cargo_home)),
            )
            .expect("homes"),
            ..spec()
        };
        let argv = rendered_argv(&jail);
        assert_eq!(mounts::bind_after_covered_mask(&argv), None, "{argv:?}");
        let at = |window: &[&str]| {
            argv.windows(window.len())
                .position(|w| w.iter().zip(window).all(|(a, b)| a == b))
        };
        let cargo = cargo_home.to_string_lossy().into_owned();
        let user = user_home.to_string_lossy().into_owned();
        let bin = bin.to_string_lossy().into_owned();
        let mask = at(&["--tmpfs", &cargo]).expect("cargo home masked");
        let rebind = at(&["--ro-bind", &bin, &bin]).expect("cargo bin re-bound");
        assert!(rebind > mask, "{argv:?}");
        assert!(
            at(&["--tmpfs", &user]).is_some(),
            "user home masked: {argv:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn every_path_handed_to_the_payload_is_a_bound_path() {
        // A symlinked rustup home, toolchain bin, and scoped tempdir: the
        // payload must be told the path the jail binds, never the link.
        let base_dir = crate::test_dir::TestDir::new("jail-symlinks").expect("test dir");
        let base = base_dir.path();
        let real = base.join("real");
        let links = base.join("links");
        for dir in ["rustup", "bin", "tmp"] {
            std::fs::create_dir_all(real.join(dir)).expect("real dir");
        }
        std::fs::create_dir_all(&links).expect("links dir");
        for dir in ["rustup", "bin", "tmp"] {
            let link = links.join(dir);
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(real.join(dir), &link).expect("symlink");
        }
        let resolve = |dir: &str| CanonicalPath::resolve(&links.join(dir)).expect("resolve link");
        let jail = JailSpec {
            scoped_tmp: resolve("tmp"),
            rustup_home: Some(resolve("rustup")),
            path_prepend: vec![resolve("bin")],
            ..spec()
        };
        let argv = rendered_argv(&jail);
        let bound: Vec<&str> = argv
            .windows(3)
            .filter_map(|w| match w {
                [flag, from, to] if (flag == "--ro-bind" || flag == "--bind") && from == to => {
                    Some(from.as_str())
                }
                _ => None,
            })
            .collect();
        let value_after = |flag: &[&str]| {
            argv.windows(flag.len() + 1)
                .find(|w| w.iter().zip(flag).all(|(a, b)| a == b))
                .and_then(|w| w.last())
                .cloned()
                .expect("flag present")
        };
        let real = std::fs::canonicalize(&real).expect("canonical real");
        let expect = |dir: &str| real.join(dir).to_string_lossy().into_owned();
        let rustup = value_after(&["--setenv", "RUSTUP_HOME"]);
        let chdir = value_after(&["--chdir"]);
        let tmpdir = value_after(&["--setenv", "TMPDIR"]);
        let path = value_after(&["--setenv", "PATH"]);
        let first_path = path.split(':').next().expect("PATH entry").to_owned();
        assert_eq!(rustup, expect("rustup"), "{argv:?}");
        assert_eq!(chdir, expect("tmp"), "{argv:?}");
        assert_eq!(tmpdir, expect("tmp"), "{argv:?}");
        assert_eq!(first_path, expect("bin"), "{argv:?}");
        for consumed in [&rustup, &chdir, &tmpdir, &first_path] {
            assert!(
                bound.contains(&consumed.as_str()),
                "{consumed} unbound: {argv:?}"
            );
        }
    }

    #[test]
    fn an_undeclared_network_capability_is_denied_fail_closed_at_build() {
        // The wrapper build/inspect runs in the Denied phase: a FRESH empty net
        // namespace with no egress. A wrapper that did not declare `network`
        // cannot reach the network at BUILD time even if its build script tries —
        // the namespace is unshared, so egress is structurally impossible, not
        // merely blocked by a rule that could be misconfigured. This is the
        // build-time half of the fail-closed capability enforcement (§5.3); the
        // run-time half awaits the emitted-app runtime jail.
        let argv = rendered_argv(&spec());
        assert!(
            argv.contains(&"--unshare-net".to_owned()),
            "the Denied phase must unshare the net namespace: {}",
            argv.join(" ")
        );
        assert!(
            argv.contains(&"--setenv".to_owned())
                && argv
                    .windows(2)
                    .any(|w| matches!(w, [k, v] if k == "CARGO_NET_OFFLINE" && v == "1")),
            "offline cargo backs the unshared namespace: {}",
            argv.join(" ")
        );
    }

    #[test]
    fn fetch_phase_keeps_network_but_every_other_control() {
        let mut s = spec();
        s.network = NetworkPolicy::FetchOnly;
        let argv = rendered_argv(&s);
        assert!(!argv.contains(&"--unshare-net".to_owned()));
        // Everything else still applies.
        assert!(argv.contains(&"--clearenv".to_owned()));
        assert!(argv.contains(&"--unshare-pid".to_owned()));
    }

    #[test]
    fn no_secret_bearing_env_enters_the_jail() {
        let argv = rendered_argv(&spec());
        let setenv_keys: Vec<&String> = argv
            .iter()
            .enumerate()
            .filter(|&(i, a)| a == "--setenv" && i + 1 < argv.len())
            .filter_map(|(i, _)| argv.get(i + 1))
            .collect();
        for key in &setenv_keys {
            assert!(
                matches!(
                    key.as_str(),
                    "CARGO_NET_OFFLINE"
                        | "CARGO_HOME"
                        | "PATH"
                        | "TMPDIR"
                        | "RUSTUP_TOOLCHAIN"
                        | "RUSTUP_HOME"
                ),
                "unexpected env var {key} enters the jail"
            );
        }
    }

    #[test]
    fn mechanism_selection_is_bwrap_or_refuse() {
        let with_bwrap = Capabilities {
            bwrap: Some("/usr/bin/bwrap".into()),
            ..Capabilities::default()
        };
        assert_eq!(
            select_mechanism(&with_bwrap),
            Mechanism::Bwrap("/usr/bin/bwrap".into())
        );
        assert_eq!(
            select_mechanism(&Capabilities::default()),
            Mechanism::Refused
        );
    }

    #[test]
    fn missing_cap_helpers_are_named_and_the_jail_refuses() {
        // A host with bwrap but no timeout/prlimit runs untrusted code with
        // no wall clock and no rlimits — refuse, naming the missing helpers.
        let caps = Capabilities {
            bwrap: Some("/usr/bin/bwrap".into()),
            prlimit: None,
            timeout: None,
        };
        assert_eq!(missing_caps(&caps), vec!["timeout", "prlimit"]);
        let r = run_in_bwrap_jail(&caps, &spec(), &["x".into()]);
        assert!(
            matches!(&r, Err(SandboxDefect::CapsUnavailable { missing }) if *missing == vec!["timeout", "prlimit"]),
            "{r:?}"
        );
        // A partial absence names only the missing one.
        let only_timeout = Capabilities {
            bwrap: Some("/usr/bin/bwrap".into()),
            prlimit: Some("/usr/bin/prlimit".into()),
            timeout: None,
        };
        assert_eq!(missing_caps(&only_timeout), vec!["timeout"]);
    }

    #[test]
    fn caps_unavailable_defect_carries_the_refusal_code_and_advice() {
        let d = SandboxDefect::CapsUnavailable {
            missing: vec!["timeout"],
        };
        assert_eq!(d.code().as_str(), "IPE-F4410");
        let s = d.to_string();
        assert!(s.contains("IPE-F4410"), "{s}");
        assert!(s.contains("timeout"), "{s}");
        assert!(s.contains("refusing"), "{s}");
    }

    #[test]
    fn concurrent_drain_does_not_wedge_on_a_stderr_heavy_stream() {
        // The real jailed run drains both pipes concurrently; here the two
        // bounded readers run in parallel over independent streams and both
        // complete, proving neither blocks the other.
        let out = b"stdout".to_vec();
        let err = vec![b'e'; 4096];
        let cap = 1024_u64;
        let ot = std::thread::Builder::new()
            .spawn(move || read_bounded(Some(&out[..]), cap))
            .expect("spawn test thread");
        let et = std::thread::Builder::new()
            .spawn(move || read_bounded(Some(&err[..]), cap))
            .expect("spawn test thread");
        let out_r = ot.join().expect("join").expect("read");
        let err_r = et.join().expect("join").expect("read");
        assert_eq!(out_r.as_deref(), Some(&b"stdout"[..]));
        // stderr exceeds the cap → flagged, never a hang.
        assert_eq!(err_r, None);
    }

    #[test]
    fn bounded_read_flags_cap_excess_instead_of_truncating() {
        let data = b"0123456789".to_vec();
        let ok = read_bounded(Some(&data[..]), 10).expect("read");
        assert_eq!(ok, Some(data.clone()));
        let over = read_bounded(Some(&data[..]), 9).expect("read");
        assert_eq!(over, None);
    }

    #[cfg(unix)]
    #[test]
    fn an_overproducing_child_is_killed_promptly_on_cap_breach() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        // A child that floods stdout forever (and never exits on its own).
        // Before the fix, the parent stopped reading at the cap but left this
        // running until the wall clock; now the cap breach must kill it.
        let mut cmd = Command::new("yes");
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let Ok(child) = cmd.spawn() else {
            // `yes` absent: skip rather than fail on a host without coreutils.
            return;
        };
        let started = Instant::now();
        let outcome = drain_and_reap(child, 64 * 1024, std::ffi::OsStr::new("yes"));
        let elapsed = started.elapsed();
        assert!(
            matches!(outcome, Err(SandboxDefect::OutputCapExceeded { .. })),
            "an overproducing child must yield the cap-exceeded defect: {outcome:?}"
        );
        // The verdict is decided at the cap; killing the child must surface it
        // in well under the 900s wall clock. A generous ceiling keeps this
        // robust on a loaded CI runner while still proving the child was killed
        // rather than waited out.
        assert!(
            elapsed < Duration::from_secs(30),
            "cap breach must kill the child promptly, took {elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_well_behaved_child_returns_its_bounded_output() {
        use std::process::{Command, Stdio};

        let mut cmd = Command::new("printf");
        cmd.arg("hello")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let Ok(child) = cmd.spawn() else {
            return;
        };
        let out = drain_and_reap(child, 1024, std::ffi::OsStr::new("printf")).expect("run");
        assert_eq!(out.stdout, b"hello");
        assert_eq!(out.status, Some(0));
    }

    // RLIMIT_NPROC is a per-process soft limit: lowering THIS test process's
    // own limit refuses only its own future thread/process creation, never
    // another process's (each process carries its own limit value, checked
    // against the real user ID's live thread count at `clone`/`fork` time).
    // No bwrap is needed: the fake child only needs to exist long enough to
    // be killed and reaped.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refused_drain_thread_kills_and_reaps_the_child() {
        use std::process::{Command, Stdio};

        let mut cmd = Command::new("sleep");
        cmd.arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let Ok(child) = cmd.spawn() else {
            return;
        };
        let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).expect("pid fits i32"))
            .expect("positive pid");

        let original = rustix::process::getrlimit(rustix::process::Resource::Nproc);
        rustix::process::setrlimit(
            rustix::process::Resource::Nproc,
            rustix::process::Rlimit {
                current: Some(1),
                maximum: original.maximum,
            },
        )
        .expect("lower this process's own thread budget");

        let outcome = drain_and_reap(child, 1024, std::ffi::OsStr::new("sleep"));
        // Lift the starved budget before any assertion, so a test runner that
        // shares this process keeps its own threads.
        let restored = rustix::process::setrlimit(rustix::process::Resource::Nproc, original);
        assert!(restored.is_ok(), "restore the thread budget: {restored:?}");
        assert!(
            matches!(outcome, Err(SandboxDefect::DrainThread(_))),
            "a starved thread budget must surface as DrainThread: {outcome:?}"
        );
        assert_eq!(
            rustix::process::test_kill_process(pid),
            Err(rustix::io::Errno::SRCH),
            "the child must be killed and reaped, not left running"
        );
    }

    #[test]
    fn default_limits_match_the_spec_table() {
        let l = ResourceLimits::default();
        // Calibrated for a single large generated SDK crate's inspection
        // (address space and wall a huge rustdoc needs), not a small crate.
        assert_eq!(l.rss_bytes, 10 * 1024 * 1024 * 1024);
        assert_eq!(l.cpu_secs, 900);
        assert_eq!(l.wall_secs, 900);
        assert_eq!(l.fd_cap, 256);
        assert_eq!(l.proc_cap, 512);
        assert_eq!(l.out_cap_bytes, 256 * 1024 * 1024);
    }

    #[test]
    fn defect_display_carries_the_refusal_code() {
        let d = SandboxDefect::NoIsolationMechanism;
        assert_eq!(d.code().as_str(), "IPE-F4410");
        assert!(d.to_string().contains("IPE-F4410"));
        assert!(d.to_string().contains("refusing"));
    }

    // ── /proc mask tests ─────────────────────────────────────────────────────

    #[test]
    fn build_argv_contains_proc_mask() {
        let argv = rendered_argv(&spec());
        let joined = argv.join(" ");
        assert!(
            joined.contains("--proc /proc"),
            "--proc /proc must be present in build jail argv: {joined}"
        );
    }

    #[test]
    fn build_argv_proc_mask_follows_ro_bind_root_and_precedes_dev() {
        let argv = rendered_argv(&spec());
        let joined = argv.join(" ");
        let ro_root = joined
            .find("--ro-bind / /")
            .expect("ro-bind root must be present");
        let proc = joined
            .find("--proc /proc")
            .expect("--proc /proc must be present");
        let dev = joined
            .find("--dev /dev")
            .expect("--dev /dev must be present");
        assert!(
            proc > ro_root,
            "--proc /proc must follow --ro-bind / / (bwrap order is load-bearing): {joined}"
        );
        assert!(dev > proc, "--dev /dev must follow --proc /proc: {joined}");
    }

    /// A live stand-in descriptor for a test `SealedFdNumber` to borrow.
    #[cfg(unix)]
    #[allow(clippy::expect_used)] // a test host with no `/dev/null` cannot build the fixture
    fn stand_in_fd() -> std::fs::File {
        std::fs::File::open("/dev/null").expect("open /dev/null")
    }

    #[cfg(unix)]
    #[test]
    fn seccomp_flag_is_injected_after_the_bwrap_token() {
        use std::os::fd::{AsFd as _, AsRawFd as _};
        let filter = stand_in_fd();
        let argv = bwrap_argv_with_seccomp(
            Path::new("/usr/bin/bwrap"),
            Path::new("/usr/bin/prlimit"),
            Path::new("/usr/bin/timeout"),
            &spec(),
            &[OsString::from("ipe-ffi-inspector")],
            Some(run_jail::SealedFdNumber::for_test(filter.as_fd())),
        )
        .expect("bwrap token present, so the seccomp flag attaches");
        let rendered: Vec<String> = argv
            .args()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let bwrap = rendered
            .iter()
            .position(|a| a == "/usr/bin/bwrap")
            .expect("bwrap token present");
        assert_eq!(
            rendered.get(bwrap + 1).map(String::as_str),
            Some("--seccomp")
        );
        let number = filter.as_raw_fd().to_string();
        assert_eq!(
            rendered.get(bwrap + 2).map(String::as_str),
            Some(number.as_str())
        );
    }

    #[cfg(unix)]
    #[test]
    fn seccomp_is_attached_and_never_silently_dropped() {
        use std::os::fd::{AsFd as _, AsRawFd as _};
        let filter = stand_in_fd();
        // A requested seccomp filter must always reach the argv, whatever the
        // bwrap path — never silently dropped, which would run the payload
        // unfiltered. The `SeccompNotAttached` arm is a fail-closed backstop
        // for the impossible case where the token the builder itself inserted
        // cannot be found again; it turns a silent drop into a hard refusal.
        let argv = bwrap_argv_with_seccomp(
            Path::new("/nonexistent/bwrap-alias"),
            Path::new("/usr/bin/prlimit"),
            Path::new("/usr/bin/timeout"),
            &spec(),
            &[OsString::from("ipe-ffi-inspector")],
            Some(run_jail::SealedFdNumber::for_test(filter.as_fd())),
        )
        .expect("a requested seccomp filter must attach, never drop");
        let rendered: Vec<String> = argv
            .args()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let bwrap = rendered
            .iter()
            .position(|a| a == "/nonexistent/bwrap-alias")
            .expect("the bwrap token is present in the argv");
        assert_eq!(
            rendered.get(bwrap + 1).map(String::as_str),
            Some("--seccomp"),
            "seccomp must be injected right after the bwrap token"
        );
        let number = filter.as_raw_fd().to_string();
        assert_eq!(
            rendered.get(bwrap + 2).map(String::as_str),
            Some(number.as_str())
        );
    }

    #[test]
    fn no_seccomp_request_is_unchanged() {
        let argv = bwrap_argv_with_seccomp(
            Path::new("/nonexistent/bwrap-alias"),
            Path::new("/usr/bin/prlimit"),
            Path::new("/usr/bin/timeout"),
            &spec(),
            &[OsString::from("ipe-ffi-inspector")],
            None,
        )
        .expect("no filter requested, so the argv renders unchanged");
        assert!(!argv.args().iter().any(|a| a.as_os_str() == "--seccomp"));
    }
}

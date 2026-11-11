//! The Linux (`x86_64`/`aarch64`) run jail: the `bwrap`+seccomp arms plus the raw
//! `memfd`/`fcntl` FFI they rest on. Compiled only on the supported Linux
//! targets; every other target gets the refuse stubs in [`super`].

#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::ffi::OsString;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use super::{
    BwrapTools, JailArgv, JailLaunch, LaunchRefusal, RunJailDefect, RunJailTools, SandboxProfile,
    SealedFdNumber, SeccompFdNumber, prove, run_jail_argv, run_jail_argv_with_delivery,
};
use crate::seccomp;
use crate::{CanonicalPath, HostTool, JailMounts};

/// Probe the host for the run-jail primitives and decide whether a jail can be
/// built, returning the tools or the fail-closed refusal.
///
/// The required primitives are per-OS, so this function is cfg-split to match the
/// same platforms [`exec_in_run_jail`] confines: on Linux (`x86_64`/`aarch64`) it requires
/// `bwrap` + `prlimit` (+ `timeout` when the profile sets a wall clock); on macOS
/// it requires `sandbox-exec`. Off both it is the refuse-gap. `wants_wall_clock`
/// selects whether `timeout` is additionally required (Linux only).
///
/// # Errors
///
/// [`RunJailDefect::UnsupportedPlatform`] off every jailed target;
/// [`RunJailDefect::PrimitiveUnavailable`] when a required primitive is absent.
pub fn probe_run_jail_tools(wants_wall_clock: bool) -> Result<RunJailTools, RunJailDefect> {
    let caps = crate::probe();
    let mut missing: Vec<&'static str> = Vec::new();
    if caps.bwrap.is_none() {
        missing.push(HostTool::Bwrap.name());
    }
    if caps.prlimit.is_none() {
        missing.push(HostTool::Prlimit.name());
    }
    if wants_wall_clock && caps.timeout.is_none() {
        missing.push(HostTool::Timeout.name());
    }
    if !missing.is_empty() {
        return Err(RunJailDefect::PrimitiveUnavailable { missing });
    }
    // The probes above guarantee these are `Some`.
    let (Some(bwrap), Some(prlimit)) = (caps.bwrap, caps.prlimit) else {
        return Err(RunJailDefect::PrimitiveUnavailable {
            missing: vec![HostTool::Bwrap.name(), HostTool::Prlimit.name()],
        });
    };
    Ok(RunJailTools::Bwrap(BwrapTools {
        bwrap,
        prlimit,
        timeout: caps.timeout,
    }))
}

/// Return `true` when bwrap can successfully establish a `--unshare-net`
/// namespace on this host.
///
/// Unprivileged user namespaces on some Linux configurations (notably GitHub
/// Actions runners) cannot configure loopback inside a net namespace — bwrap
/// auto-runs `RTM_NEWADDR` to bring up 127.0.0.1 and the kernel rejects it
/// with `EPERM`, killing bwrap before any payload executes. Callers that
/// require `--unshare-net` should call this first and skip (not fail) when it
/// returns `false`.
///
/// This is a capability check, not an isolation bypass: the `--unshare-net`
/// flag itself is never removed from the real jail argv; the result only
/// determines whether the host can even start the jail.
#[must_use]
pub fn netns_jail_available(bwrap: &std::path::Path) -> bool {
    // Run bwrap with the minimal net-isolation flags, wrapping /bin/true.
    // Exit 0 → the netns came up cleanly. Any non-zero (including the
    // "loopback: Failed RTM_NEWADDR: Operation not permitted" bwrap error)
    // → the netns jail cannot be established on this host.
    std::process::Command::new(bwrap)
        .args(["--unshare-net", "--ro-bind", "/", "/", "--", "/bin/true"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The read-only binds re-exposing the app binary past the home/tmp tmpfs masks.
///
/// Only the app FILE itself is bound, never its parent directory. A user-placed
/// binary can sit directly in `$HOME` (`~/myapp`) or a bundle unpacked into home,
/// and the `--tmpfs /home` mask hides it — but binding the whole PARENT would
/// re-expose that entire tree read-only inside the jail, defeating the mask and
/// resurfacing masked secrets (e.g. `~/.ssh`) to a network-granted payload. bwrap
/// binds a regular file at a file target, so the app can exec but never mutate it,
/// with nothing else in its directory reachable.
fn app_ro_binds(app: &CanonicalPath) -> Vec<CanonicalPath> {
    vec![app.clone()]
}

/// Run the emitted `app` binary inside the run jail described by `profile`,
/// replacing the current process on success (Unix `exec`).
///
/// This compiles the seccomp program for the profile's subprocess axis, places
/// it on a sealed memfd, builds the `bwrap` argv naming it, and `exec`s through
/// the runtime descriptor floor: `bwrap` inherits stdio and the sealed seccomp
/// fd, and no other descriptor of this process.
///
/// On a non-Linux target this is a compile-time refusal shape — the whole body
/// is `cfg(target_os = "linux")`; other targets return
/// [`RunJailDefect::UnsupportedPlatform`].
///
/// # Errors
///
/// Any [`RunJailDefect`]; [`RunJailDefect::Path`] when `scoped_tmp`,
/// `working_tree`, or `app` does not resolve, the invoker's homes are unknown,
/// a path would expose the cargo home, or a granted working tree's
/// version-control metadata cannot be kept read-only or its configuration names
/// code inside a writable grant. On success (Linux) it does not return.
pub fn exec_in_run_jail(
    tools: &RunJailTools,
    profile: &SandboxProfile,
    scoped_tmp: &Path,
    working_tree: &Path,
    app: &Path,
    app_args: &[OsString],
) -> Result<std::convert::Infallible, RunJailDefect> {
    // The process cap must count only the jail's tasks.
    let scope = prove(tools)?;
    // Resolve every path once: the app the payload execs and the dirs it is
    // handed are exactly the paths the jail binds.
    let scoped_tmp = CanonicalPath::resolve(scoped_tmp).map_err(RunJailDefect::Path)?;
    let working_tree = CanonicalPath::resolve(working_tree).map_err(RunJailDefect::Path)?;
    let app = CanonicalPath::resolve(app).map_err(RunJailDefect::Path)?;
    let mounts = JailMounts::of_invoker(scoped_tmp, working_tree, app_ro_binds(&app))
        .map_err(RunJailDefect::Path)?;

    // Compile the seccomp program for this profile. `None` ⇒ this architecture
    // has no filter we can emit — refuse (fail-closed), never run unfiltered.
    let Some(program) = seccomp::subprocess_deny_program(profile.subprocess) else {
        return Err(RunJailDefect::UnsupportedPlatform {
            reason: "no seccomp filter can be compiled for this architecture",
        });
    };
    let mut payload: Vec<OsString> = Vec::with_capacity(app_args.len().saturating_add(1));
    payload.push(app.as_path().as_os_str().to_owned());
    payload.extend(app_args.iter().cloned());

    let host_env = crate::host_env::granted;
    let launch = write_seccomp_memfd(&program)?
        .launch(|seccomp_fd| {
            run_jail_argv(&scope, profile, &mounts, seccomp_fd, &host_env, &payload)
                .map_err(RunJailDefect::Path)
        })
        .map_err(LaunchRefusal::into_defect)?;

    Err(launch.exec())
}

/// Exec an embedded app held only in a sealed anonymous descriptor.
///
/// Delivering the app into the jail from that descriptor rather than from a host
/// path closes the verify/exec identity gap for `ipe-wrapper` embed mode.
///
/// The wrapper writes the embedded bytes to a sealed memfd
/// ([`write_sealed_app_memfd`]), verifies the capability floor by reading the
/// SEALED fd, then calls this, which names a duplicate of that fd in the exec
/// through the runtime descriptor floor. bwrap inherits it across the process
/// replacement and materialises the app inside a jail-private tmpfs via
/// `--file` — so the bytes executed are provably the sealed bytes that were
/// verified, a same-uid attacker has no host path to pre-seed or swap, and no
/// copy of the app is left on the host.
///
/// # Errors
///
/// Any [`RunJailDefect`]; [`RunJailDefect::Path`] when `scoped_tmp` or
/// `working_tree` does not resolve, the invoker's homes are unknown, a path
/// would expose the cargo home, or a granted working tree is refused as in
/// [`exec_in_run_jail`]. On success (Linux) it does not return.
pub fn exec_embedded_in_run_jail(
    tools: &RunJailTools,
    profile: &SandboxProfile,
    scoped_tmp: &Path,
    working_tree: &Path,
    app: &SealedApp,
    app_args: &[OsString],
) -> Result<std::convert::Infallible, RunJailDefect> {
    let scope = prove(tools)?;
    let scoped_tmp = CanonicalPath::resolve(scoped_tmp).map_err(RunJailDefect::Path)?;
    let working_tree = CanonicalPath::resolve(working_tree).map_err(RunJailDefect::Path)?;
    let mounts = JailMounts::of_invoker(scoped_tmp, working_tree, Vec::new())
        .map_err(RunJailDefect::Path)?;

    let Some(program) = seccomp::subprocess_deny_program(profile.subprocess) else {
        return Err(RunJailDefect::UnsupportedPlatform {
            reason: "no seccomp filter can be compiled for this architecture",
        });
    };
    // The builder owns the in-jail destination: a jail-private tmpfs under
    // `scoped_tmp`, so no copy of the app reaches the host directory.
    let host_env = crate::host_env::granted;
    let launch = write_seccomp_memfd(&program)?
        .launch_delivering(app, |seccomp_fd, app_fd| {
            run_jail_argv_with_delivery(
                &scope, profile, &mounts, seccomp_fd, app_fd, &host_env, app_args,
            )
            .map_err(RunJailDefect::Path)
        })
        .map_err(LaunchRefusal::into_defect)?;

    Err(launch.exec())
}

/// Write all of `bytes` to `fd`, treating a zero-length write as a failure.
///
/// A short write is a hard error: a truncated seccomp program is a malformed
/// filter and a truncated app is a corrupt executable, so the caller refuses.
fn write_all_fd(fd: BorrowedFd<'_>, bytes: &[u8]) -> std::io::Result<()> {
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let n = rustix::io::write(fd, remaining)?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        remaining = remaining.get(n..).unwrap_or_default();
    }
    Ok(())
}

/// Rewind `fd` to offset 0.
fn rewind_fd(fd: BorrowedFd<'_>) -> std::io::Result<()> {
    rustix::fs::seek(fd, rustix::fs::SeekFrom::Start(0))?;
    Ok(())
}

/// The four seals that freeze a memfd's bytes and size for the fd's lifetime:
/// no write, no shrink, no grow, and no seal change.
fn freezing_seals() -> rustix::fs::SealFlags {
    use rustix::fs::SealFlags;
    SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL
}

/// Create a sealing-capable, close-on-exec memfd named `name`, write all of
/// `bytes`, freeze it with [`freezing_seals`], and rewind it to offset 0.
///
/// `what` names the payload in the refusal detail.
fn write_frozen_memfd(
    name: &std::ffi::CStr,
    what: &str,
    bytes: &[u8],
) -> Result<OwnedFd, RunJailDefect> {
    use rustix::fs::MemfdFlags;
    let spawn = |detail: String| RunJailDefect::Spawn { detail };
    // Close-on-exec from birth and for its whole life in this process: only the
    // child a launch forks or execs clears the flag, in its own descriptor
    // table, so no concurrent spawn ever inherits the fd.
    let fd = rustix::fs::memfd_create(name, MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC)
        .map_err(|e| {
            spawn(format!(
                "memfd_create for the {what} failed: {}",
                std::io::Error::from(e)
            ))
        })?;
    write_all_fd(fd.as_fd(), bytes)
        .map_err(|e| spawn(format!("writing the {what} to the memfd failed: {e}")))?;
    rustix::fs::fcntl_add_seals(fd.as_fd(), freezing_seals()).map_err(|e| {
        spawn(format!(
            "sealing the {what} memfd failed: {}",
            std::io::Error::from(e)
        ))
    })?;
    rewind_fd(fd.as_fd()).map_err(|e| spawn(format!("rewinding the {what} memfd failed: {e}")))?;
    Ok(fd)
}

/// A sealed anonymous file holding a compiled seccomp program, owning its
/// descriptor (closed on drop).
///
/// Built only by [`write_seccomp_memfd`] from a [`seccomp::JailProgram`], and
/// sealed after the write, so the filter bwrap loads is exactly the program
/// this crate compiled: no process holding the fd, the jailed payload included,
/// can rewrite or resize it.
///
/// It mints its [`SeccompFdNumber`] only inside [`SealedSeccompFd::launch`], and
/// the number cannot escape the render it is lent to:
///
/// ```compile_fail,E0521
/// # use ipe_sandbox::run_jail::write_seccomp_memfd;
/// # fn stale() -> Option<()> {
/// let sealed = write_seccomp_memfd(&ipe_sandbox::seccomp::subprocess_deny_program(false)?).ok()?;
/// let mut kept = None;
/// let _ = sealed.launch(|number| -> Result<_, ()> {
///     kept = Some(number);
///     Err(())
/// });
/// drop(kept);
/// # Some(())
/// # }
/// ```
///
/// Nor can the argv rendered from it outlive the launch that hands the
/// descriptor over:
///
/// ```compile_fail,E0521
/// # use std::ffi::OsString;
/// # use std::path::Path;
/// # use ipe_sandbox::run_jail::{
/// #     BwrapTools, RunJailTools, SandboxProfile, prove, run_jail_argv, write_seccomp_memfd,
/// # };
/// # use ipe_sandbox::{CanonicalPath, HostTool, JailMounts, host_tool};
/// # fn stale() -> Option<usize> {
/// # let tools = RunJailTools::Bwrap(BwrapTools {
/// #     bwrap: host_tool::resolve(HostTool::Bwrap).ok()?,
/// #     prlimit: host_tool::resolve(HostTool::Prlimit).ok()?,
/// #     timeout: None,
/// # });
/// # let scope = prove(&tools).ok()?;
/// # let root = CanonicalPath::resolve(Path::new("/")).ok()?;
/// # let mounts = JailMounts::of_invoker(root.clone(), root, Vec::new()).ok()?;
/// # let no_env = |_: &str| None;
/// let sealed = write_seccomp_memfd(&ipe_sandbox::seccomp::subprocess_deny_program(false)?).ok()?;
/// let mut kept = None;
/// let _ = sealed.launch(|number| -> Result<_, ()> {
///     kept = run_jail_argv(
///         &scope,
///         &SandboxProfile::maximally_isolated(),
///         &mounts,
///         number,
///         &no_env,
///         &[OsString::from("app")],
///     )
///     .ok();
///     Err(())
/// });
/// Some(kept?.args().len())
/// # }
/// ```
///
/// And a payload argv cannot be built without one — no filter, no argv:
///
/// ```compile_fail,E0308
/// # use std::ffi::OsString;
/// # use std::path::Path;
/// # use ipe_sandbox::run_jail::{BwrapTools, RunJailTools, SandboxProfile, prove, run_jail_argv};
/// # use ipe_sandbox::{CanonicalPath, HostTool, JailMounts, host_tool};
/// # fn unfiltered() -> Option<usize> {
/// # let tools = RunJailTools::Bwrap(BwrapTools {
/// #     bwrap: host_tool::resolve(HostTool::Bwrap).ok()?,
/// #     prlimit: host_tool::resolve(HostTool::Prlimit).ok()?,
/// #     timeout: None,
/// # });
/// # let scope = prove(&tools).ok()?;
/// # let root = CanonicalPath::resolve(Path::new("/")).ok()?;
/// # let mounts = JailMounts::of_invoker(root.clone(), root, Vec::new()).ok()?;
/// # let no_env = |_: &str| None;
/// let argv = run_jail_argv(
///     &scope,
///     &SandboxProfile::maximally_isolated(),
///     &mounts,
///     None,
///     &no_env,
///     &[OsString::from("app")],
/// )
/// .ok()?;
/// Some(argv.args().len())
/// # }
/// ```
///
/// The filter and the delivered app are distinct roles: the builder takes the
/// filter's number first and the app's second,
///
/// ```no_run
/// # use std::ffi::OsString;
/// # use std::path::Path;
/// # use ipe_sandbox::run_jail::{
/// #     BwrapTools, RunJailTools, SandboxProfile, prove, run_jail_argv_with_delivery,
/// #     write_sealed_app_memfd, write_seccomp_memfd,
/// # };
/// # use ipe_sandbox::seccomp::subprocess_deny_program;
/// # use ipe_sandbox::{CanonicalPath, HostTool, JailMounts, host_tool};
/// # fn ordered() -> Option<usize> {
/// # let tools = RunJailTools::Bwrap(BwrapTools {
/// #     bwrap: host_tool::resolve(HostTool::Bwrap).ok()?,
/// #     prlimit: host_tool::resolve(HostTool::Prlimit).ok()?,
/// #     timeout: None,
/// # });
/// # let scope = prove(&tools).ok()?;
/// # let root = CanonicalPath::resolve(Path::new("/")).ok()?;
/// # let mounts = JailMounts::of_invoker(root.clone(), root, Vec::new()).ok()?;
/// # let no_env = |_: &str| None;
/// let seccomp = write_seccomp_memfd(&subprocess_deny_program(false)?).ok()?;
/// let app = write_sealed_app_memfd(b"app").ok()?;
/// let launch = seccomp
///     .launch_delivering(&app, |seccomp_fd, app_fd| {
///         run_jail_argv_with_delivery(
///             &scope,
///             &SandboxProfile::maximally_isolated(),
///             &mounts,
///             seccomp_fd,
///             app_fd,
///             &no_env,
///             &[],
///         )
///     })
///     .ok()?;
/// Some(launch.args().count())
/// # }
/// ```
///
/// and a swap of the two does not compile:
///
/// ```compile_fail,E0308
/// # use std::ffi::OsString;
/// # use std::path::Path;
/// # use ipe_sandbox::run_jail::{
/// #     BwrapTools, RunJailTools, SandboxProfile, prove, run_jail_argv_with_delivery,
/// #     write_sealed_app_memfd, write_seccomp_memfd,
/// # };
/// # use ipe_sandbox::seccomp::subprocess_deny_program;
/// # use ipe_sandbox::{CanonicalPath, HostTool, JailMounts, host_tool};
/// # fn swapped() -> Option<usize> {
/// # let tools = RunJailTools::Bwrap(BwrapTools {
/// #     bwrap: host_tool::resolve(HostTool::Bwrap).ok()?,
/// #     prlimit: host_tool::resolve(HostTool::Prlimit).ok()?,
/// #     timeout: None,
/// # });
/// # let scope = prove(&tools).ok()?;
/// # let root = CanonicalPath::resolve(Path::new("/")).ok()?;
/// # let mounts = JailMounts::of_invoker(root.clone(), root, Vec::new()).ok()?;
/// # let no_env = |_: &str| None;
/// let seccomp = write_seccomp_memfd(&subprocess_deny_program(false)?).ok()?;
/// let app = write_sealed_app_memfd(b"app").ok()?;
/// let launch = seccomp
///     .launch_delivering(&app, |seccomp_fd, app_fd| {
///         run_jail_argv_with_delivery(
///             &scope,
///             &SandboxProfile::maximally_isolated(),
///             &mounts,
///             app_fd,
///             seccomp_fd,
///             &no_env,
///             &[],
///         )
///     })
///     .ok()?;
/// Some(launch.args().count())
/// # }
/// ```
///
/// Nor can a descriptor be sealed as the jail's filter from bytes this crate's
/// program builder did not produce:
///
/// ```compile_fail,E0308
/// # fn forged() -> Option<()> {
/// let sealed = ipe_sandbox::run_jail::write_seccomp_memfd(b"allow-all").ok()?;
/// # drop(sealed);
/// # Some(())
/// # }
/// ```
pub struct SealedSeccompFd {
    fd: OwnedFd,
}

impl AsFd for SealedSeccompFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl SealedSeccompFd {
    /// Render the jail argv from this filter's `--seccomp <fd>` number and
    /// build the [`JailLaunch`] that hands exactly this descriptor to it.
    ///
    /// The `Command` is built while the number is lent to `render`; the owner
    /// then moves into the launch's named set, still close-on-exec, so the
    /// number stays this descriptor until the launch starts and only that
    /// child inherits it.
    ///
    /// # Errors
    ///
    /// [`LaunchRefusal::Render`] when `render` refuses;
    /// [`LaunchRefusal::Handoff`] when the argv is empty or the runtime floor
    /// refuses the descriptor. The descriptor is closed either way.
    pub fn launch<E>(
        self,
        render: impl for<'fd> FnOnce(SeccompFdNumber<'fd>) -> Result<JailArgv<'fd>, E>,
    ) -> Result<JailLaunch, LaunchRefusal<E>> {
        let command = {
            let argv = render(SeccompFdNumber(SealedFdNumber(self.fd.as_fd())))
                .map_err(LaunchRefusal::Render)?;
            argv.command().map_err(LaunchRefusal::Handoff)?
        };
        let mut launch = JailLaunch::new(command, ipe_runtime_rust::system::NamedFds::none());
        launch.name(self.fd).map_err(LaunchRefusal::Handoff)?;
        Ok(launch)
    }

    /// [`Self::launch`] for an argv that also delivers `app` through
    /// `--file <fd> <dest>`: `render` receives the filter's number and the
    /// number of a close-on-exec duplicate of `app`'s sealed descriptor (the
    /// same sealed inode), and the launch hands both to the child.
    ///
    /// # Errors
    ///
    /// As [`Self::launch`]; also [`LaunchRefusal::Handoff`] when `app`'s
    /// descriptor cannot be duplicated.
    pub fn launch_delivering<E>(
        self,
        app: &SealedApp,
        render: impl for<'fd> FnOnce(
            SeccompFdNumber<'fd>,
            SealedFdNumber<'fd>,
        ) -> Result<JailArgv<'fd>, E>,
    ) -> Result<JailLaunch, LaunchRefusal<E>> {
        let app_fd = app.fd.try_clone().map_err(|e| {
            LaunchRefusal::Handoff(RunJailDefect::Spawn {
                detail: format!("duplicating the sealed app memfd failed: {e}"),
            })
        })?;
        let command = {
            let argv = render(
                SeccompFdNumber(SealedFdNumber(self.fd.as_fd())),
                SealedFdNumber(app_fd.as_fd()),
            )
            .map_err(LaunchRefusal::Render)?;
            argv.command().map_err(LaunchRefusal::Handoff)?
        };
        let mut launch = JailLaunch::new(command, ipe_runtime_rust::system::NamedFds::none());
        launch.name(self.fd).map_err(LaunchRefusal::Handoff)?;
        launch.name(app_fd).map_err(LaunchRefusal::Handoff)?;
        Ok(launch)
    }
}

/// Write the compiled seccomp program to a sealed anonymous in-memory file,
/// rewound to offset 0, ready for `bwrap --seccomp <fd>`.
///
/// A `memfd` is used rather than a temp file so the program bytes never touch
/// the filesystem (nothing to race or tamper on disk) and the fd is
/// self-cleaning when closed. It is close-on-exec for its whole life here and
/// reaches a child only through [`SealedSeccompFd::launch`].
///
/// # Errors
///
/// [`RunJailDefect::Spawn`] on any `memfd_create`, write, seal, or seek failure
/// — a truncated, unwritten, or unsealed filter would let the payload run
/// under a program other than the one compiled, so the jail refuses.
pub fn write_seccomp_memfd(
    program: &seccomp::JailProgram,
) -> Result<SealedSeccompFd, RunJailDefect> {
    let bytes = seccomp::program_bytes(program);
    let fd = write_frozen_memfd(c"ipe-seccomp", "seccomp program", &bytes)?;
    Ok(SealedSeccompFd { fd })
}

/// A sealed anonymous file holding the embedded app binary, owning its
/// descriptor (closed on drop).
///
/// The bytes are frozen by `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW |
/// F_SEAL_SEAL`, so what a caller verifies by reading the fd is exactly what the
/// jail delivers from the same fd — there is no on-disk name to race, and no
/// writable re-open is possible even for a process holding the fd.
pub struct SealedApp {
    fd: OwnedFd,
}

impl AsFd for SealedApp {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl SealedApp {
    /// Read the full sealed contents by reading through the fd.
    ///
    /// Reads from offset 0 without disturbing the caller's later use of the fd
    /// (bwrap re-reads it from 0 itself via `--file`, but this rewinds after to
    /// be safe).  The bytes returned are the sealed bytes — the same inode the
    /// jail will deliver.
    ///
    /// # Errors
    ///
    /// [`RunJailDefect::Spawn`] on any seek or read failure.
    pub fn read_sealed_bytes(&self) -> Result<Vec<u8>, RunJailDefect> {
        let spawn = |detail: String| RunJailDefect::Spawn { detail };
        let fd = self.fd.as_fd();
        rewind_fd(fd).map_err(|e| spawn(format!("rewinding the sealed app memfd failed: {e}")))?;
        let mut out: Vec<u8> = Vec::new();
        // Heap-allocated read buffer (a large on-stack array is a stack-size
        // hazard).
        let mut chunk = vec![0u8; 65536];
        loop {
            let n = rustix::io::read(fd, &mut chunk).map_err(|e| {
                spawn(format!(
                    "reading the sealed app memfd failed: {}",
                    std::io::Error::from(e)
                ))
            })?;
            if n == 0 {
                break;
            }
            if let Some(slice) = chunk.get(..n) {
                out.extend_from_slice(slice);
            }
        }
        // Rewind so a subsequent consumer reads from the start.
        rewind_fd(fd).map_err(|e| {
            spawn(format!(
                "rewinding the sealed app memfd after read failed: {e}"
            ))
        })?;
        Ok(out)
    }
}

/// Write `bytes` to an anonymous, sealing-capable in-memory file, seal it
/// against any further write/resize, and return the owned [`SealedApp`].
///
/// The fd is close-on-exec for its whole life here and reaches a child only
/// through [`SealedSeccompFd::launch_delivering`], the wrapper→bwrap process
/// replacement that lets bwrap materialise the app inside the jail from the
/// same sealed inode via `--file`. Sealing (`F_SEAL_WRITE | F_SEAL_SHRINK |
/// F_SEAL_GROW | F_SEAL_SEAL`) makes the verified-then-executed bytes provably
/// identical: no path lookup, no writable re-open.
///
/// # Errors
///
/// [`RunJailDefect::Spawn`] on any syscall failure.
pub fn write_sealed_app_memfd(bytes: &[u8]) -> Result<SealedApp, RunJailDefect> {
    let fd = write_frozen_memfd(c"ipe-embedded-app", "embedded app", bytes)?;
    Ok(SealedApp { fd })
}

#[cfg(test)]
mod tests {
    use super::{JailArgv, app_ro_binds, write_sealed_app_memfd, write_seccomp_memfd};
    use crate::CanonicalPath;
    use crate::seccomp::JailProgram;
    use std::os::fd::AsFd as _;

    /// Whether `fd` carries close-on-exec.
    fn is_cloexec(fd: std::os::fd::BorrowedFd<'_>) -> bool {
        rustix::io::fcntl_getfd(fd).is_ok_and(|flags| flags.contains(rustix::io::FdFlags::CLOEXEC))
    }

    #[test]
    fn a_write_to_the_sealed_seccomp_fd_is_refused() {
        let sealed = write_seccomp_memfd(&JailProgram::for_test()).expect("sealed seccomp memfd");
        let refused = rustix::io::write(sealed.as_fd(), b"x");
        assert_eq!(refused, Err(rustix::io::Errno::PERM));
        assert_eq!(
            rustix::fs::fcntl_get_seals(sealed.as_fd()),
            Ok(super::freezing_seals())
        );
    }

    #[test]
    fn a_resize_of_the_sealed_seccomp_fd_is_refused() {
        let sealed = write_seccomp_memfd(&JailProgram::for_test()).expect("sealed seccomp memfd");
        assert_eq!(
            rustix::fs::ftruncate(sealed.as_fd(), 0),
            Err(rustix::io::Errno::PERM)
        );
        assert_eq!(
            rustix::fs::ftruncate(sealed.as_fd(), 4096),
            Err(rustix::io::Errno::PERM)
        );
    }

    #[test]
    fn the_launched_seccomp_fd_stays_close_on_exec_at_the_number_its_argv_names() {
        use std::os::fd::AsRawFd as _;
        let sealed = write_seccomp_memfd(&JailProgram::for_test()).expect("sealed seccomp memfd");
        assert!(is_cloexec(sealed.as_fd()), "born inheritable");
        let raw = sealed.as_fd().as_raw_fd();
        let launch = sealed
            .launch(|fd| -> Result<_, std::convert::Infallible> {
                let mut argv = JailArgv::fd_free(vec!["bwrap".into(), "--".into()]);
                assert!(argv.attach_seccomp_after(std::ffi::OsStr::new("bwrap"), &fd));
                Ok(argv)
            })
            .expect("launch");
        let args: Vec<String> = launch
            .args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            ["--seccomp".to_owned(), raw.to_string(), "--".to_owned()]
        );
        // The launch holds the descriptor at that number, still close-on-exec:
        // only the child the floor forks or execs inherits it.
        let held = std::fs::read_link(format!("/proc/self/fd/{raw}")).expect("held fd");
        assert!(
            held.to_string_lossy().starts_with("/memfd:ipe-seccomp"),
            "{held:?}"
        );
        let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{raw}")).expect("fdinfo");
        let flags = fdinfo
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .and_then(|octal| u32::from_str_radix(octal.trim(), 8).ok());
        assert!(
            // `O_CLOEXEC` is octal `02000000`, bit 19 of the `flags:` field.
            flags.is_some_and(|bits| (bits >> 19) % 2 == 1),
            "inheritable in the parent: {fdinfo}"
        );
        drop(launch);
    }

    #[test]
    fn a_write_to_the_sealed_app_fd_is_refused() {
        let sealed = write_sealed_app_memfd(b"app").expect("sealed app memfd");
        assert!(is_cloexec(sealed.as_fd()), "born inheritable");
        assert_eq!(
            rustix::io::write(sealed.as_fd(), b"x"),
            Err(rustix::io::Errno::PERM)
        );
        assert_eq!(sealed.read_sealed_bytes().expect("read"), b"app".to_vec());
    }

    #[test]
    fn app_ro_bind_is_the_file_not_its_parent() {
        // A user-placed binary directly in home must be re-exposed as the FILE
        // itself, never as its parent directory: binding the parent would re-expose
        // all of `$HOME` (including `~/.ssh`) read-only past the `/home` mask.
        let app = CanonicalPath::assumed("/home/alice/myapp");
        let binds = app_ro_binds(&app);
        assert_eq!(binds, vec![CanonicalPath::assumed("/home/alice/myapp")]);
        // The parent directory must NOT be bound.
        assert!(
            !binds.contains(&CanonicalPath::assumed("/home/alice")),
            "the app's parent directory must not be re-exposed: {binds:?}"
        );
    }

    #[test]
    fn app_ro_bind_of_a_binary_at_home_root_does_not_expose_home() {
        // A bundle unpacked into `$HOME` itself (app parent == the masked root) must
        // still bind only the file, so the mask over `/home` is not defeated.
        let app = CanonicalPath::assumed("/home/bob/.local/bin/app");
        let binds = app_ro_binds(&app);
        assert_eq!(
            binds,
            vec![CanonicalPath::assumed("/home/bob/.local/bin/app")]
        );
        for masked in ["/home", "/home/bob", "/home/bob/.local/bin"] {
            assert!(
                !binds.contains(&CanonicalPath::assumed(masked)),
                "no ancestor directory may be bound ({masked}): {binds:?}"
            );
        }
    }
}

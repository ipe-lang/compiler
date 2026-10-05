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
    JailArgv, RunJailDefect, RunJailTools, SandboxProfile, SealedFdNumber, run_jail_argv,
    run_jail_argv_with_delivery,
};
use crate::seccomp;
use crate::{CanonicalPath, JailMounts};

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
        missing.push("bwrap");
    }
    if caps.prlimit.is_none() {
        missing.push("prlimit");
    }
    if wants_wall_clock && caps.timeout.is_none() {
        missing.push("timeout");
    }
    if !missing.is_empty() {
        return Err(RunJailDefect::PrimitiveUnavailable { missing });
    }
    // The probes above guarantee these are `Some`.
    let (Some(bwrap), Some(prlimit)) = (caps.bwrap, caps.prlimit) else {
        return Err(RunJailDefect::PrimitiveUnavailable {
            missing: vec!["bwrap", "prlimit"],
        });
    };
    Ok(RunJailTools {
        bwrap,
        prlimit,
        timeout: caps.timeout,
    })
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
/// it on a sealed memfd, makes that fd inheritable, builds the `bwrap` argv
/// referencing it, and `exec`s it. Only the sealed seccomp fd loses its
/// close-on-exec flag, so `bwrap` inherits it; every other fd stays cloexec.
///
/// On a non-Linux target this is a compile-time refusal shape — the whole body
/// is `cfg(target_os = "linux")`; other targets return
/// [`RunJailDefect::UnsupportedPlatform`].
///
/// # Errors
///
/// Any [`RunJailDefect`]; [`RunJailDefect::Path`] when `scoped_tmp`,
/// `working_tree`, or `app` does not resolve, the invoker's homes are unknown,
/// or a path would expose the cargo home. On success (Linux) it does not return.
pub fn exec_in_run_jail(
    tools: &RunJailTools,
    profile: &SandboxProfile,
    scoped_tmp: &Path,
    working_tree: &Path,
    app: &Path,
    app_args: &[OsString],
) -> Result<std::convert::Infallible, RunJailDefect> {
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
    let bytes = seccomp::program_bytes(&program);
    let seccomp = write_seccomp_memfd(&bytes)?;
    // The seccomp fd MUST survive exec so bwrap can read the program from it.
    // `exec` replaces THIS process (no fork), so clearing close-on-exec here is
    // the same fd-table state a pre-exec hook would see. A failure refuses
    // rather than run the app without the filter.
    let seccomp_fd = seccomp
        .make_inheritable()
        .map_err(|e| RunJailDefect::Spawn {
            detail: format!("clearing close-on-exec on the seccomp memfd failed: {e}"),
        })?;

    let mut payload: Vec<OsString> = Vec::with_capacity(app_args.len() + 1);
    payload.push(app.as_path().as_os_str().to_owned());
    payload.extend(app_args.iter().cloned());

    let host_env = crate::host_env::granted;
    let argv = run_jail_argv(
        tools,
        profile,
        &mounts,
        Some(seccomp_fd),
        &host_env,
        &payload,
    );

    Err(exec_jail_argv(&argv))
}

/// Exec an embedded app held only in a sealed anonymous descriptor.
///
/// Delivering the app into the jail from that descriptor rather than from a host
/// path closes the verify/exec identity gap for `ipe-wrapper` embed mode.
///
/// The wrapper writes the embedded bytes to a sealed memfd
/// ([`write_sealed_app_memfd`]), verifies the capability floor by reading the
/// SEALED fd, then calls this, which makes the sealed fd inheritable. bwrap
/// inherits it across the process replacement and materialises the app inside
/// a jail-private tmpfs via `--file` — so the bytes executed are provably the
/// sealed bytes that were verified, a same-uid attacker has no host path to
/// pre-seed or swap, and no copy of the app is left on the host.
///
/// # Errors
///
/// Any [`RunJailDefect`]; [`RunJailDefect::Path`] when `scoped_tmp` or
/// `working_tree` does not resolve, the invoker's homes are unknown, or a path
/// would expose the cargo home. On
/// success (Linux) it does not return.
pub fn exec_embedded_in_run_jail(
    tools: &RunJailTools,
    profile: &SandboxProfile,
    scoped_tmp: &Path,
    working_tree: &Path,
    app: &SealedApp,
    app_args: &[OsString],
) -> Result<std::convert::Infallible, RunJailDefect> {
    let scoped_tmp = CanonicalPath::resolve(scoped_tmp).map_err(RunJailDefect::Path)?;
    let working_tree = CanonicalPath::resolve(working_tree).map_err(RunJailDefect::Path)?;
    let mounts = JailMounts::of_invoker(scoped_tmp, working_tree, Vec::new())
        .map_err(RunJailDefect::Path)?;

    let Some(program) = seccomp::subprocess_deny_program(profile.subprocess) else {
        return Err(RunJailDefect::UnsupportedPlatform {
            reason: "no seccomp filter can be compiled for this architecture",
        });
    };
    let bytes = seccomp::program_bytes(&program);
    let seccomp = write_seccomp_memfd(&bytes)?;
    // Both the seccomp filter fd and the sealed app fd MUST survive the exec so
    // bwrap can read them. `exec` replaces THIS process (no fork), so clearing
    // close-on-exec here is the same fd-table state a pre-exec hook would see. A
    // failure refuses rather than run the app without its filter or without a
    // delivered binary.
    let cloexec_err = |what: &str, e: std::io::Error| RunJailDefect::Spawn {
        detail: format!("clearing close-on-exec on the {what} failed: {e}"),
    };
    let seccomp_fd = seccomp
        .make_inheritable()
        .map_err(|e| cloexec_err("seccomp memfd", e))?;
    let app_fd = app
        .make_inheritable()
        .map_err(|e| cloexec_err("sealed app memfd", e))?;

    // The builder owns the in-jail destination: a jail-private tmpfs under
    // `scoped_tmp`, so no copy of the app reaches the host directory.
    let host_env = crate::host_env::granted;
    let argv = run_jail_argv_with_delivery(
        tools,
        profile,
        &mounts,
        Some(seccomp_fd),
        app_fd,
        &host_env,
        app_args,
    );

    Err(exec_jail_argv(&argv))
}

/// Replace this process with the jail `argv` names; returns only on failure.
///
/// Taking the [`JailArgv`] by reference holds every sealed fd owner it borrows
/// open until the `exec` has handed the descriptors to `bwrap`.
fn exec_jail_argv(argv: &JailArgv<'_>) -> RunJailDefect {
    use std::os::unix::process::CommandExt as _;
    let Some((program, rest)) = argv.args().split_first() else {
        return RunJailDefect::Spawn {
            detail: "empty jail argv".to_owned(),
        };
    };
    let err = std::process::Command::new(program).args(rest).exec();
    RunJailDefect::Spawn {
        detail: err.to_string(),
    }
}

/// Clear the close-on-exec flag on `fd` so a sealed memfd survives an exec.
///
/// Reached only through the sealed owners' `make_inheritable`, so no unsealed
/// descriptor is ever made inheritable.
///
/// # Errors
///
/// [`std::io::Error`] when either `fcntl` fails.
fn clear_cloexec(fd: BorrowedFd<'_>) -> std::io::Result<()> {
    let flags = rustix::io::fcntl_getfd(fd)?;
    rustix::io::fcntl_setfd(fd, flags.difference(rustix::io::FdFlags::CLOEXEC))?;
    Ok(())
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
    // Close-on-exec from birth: no concurrent spawn inherits the fd while it is
    // being written. The owner clears the flag only once sealed, right before
    // the hand-off to bwrap.
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
/// Built only by [`write_seccomp_memfd`], which seals the fd after the write,
/// so the filter bwrap loads is exactly the program compiled here: no process
/// holding the fd, the jailed payload included, can rewrite or resize it.
///
/// The [`SealedFdNumber`] it mints cannot outlive it:
///
/// ```compile_fail,E0597
/// # fn stale() -> Option<String> {
/// let number = {
///     let sealed = ipe_sandbox::run_jail::write_seccomp_memfd(b"filter").ok()?;
///     sealed.make_inheritable().ok()?
/// };
/// Some(format!("{number:?}"))
/// # }
/// ```
///
/// Nor can it be dropped while a [`JailArgv`] naming its number is still to be
/// spawned or exec'd:
///
/// ```compile_fail,E0505
/// # use std::ffi::OsString;
/// # use std::path::Path;
/// # use ipe_sandbox::run_jail::{RunJailTools, SandboxProfile, run_jail_argv, write_seccomp_memfd};
/// # use ipe_sandbox::{CanonicalPath, JailMounts};
/// # fn stale() -> Option<usize> {
/// # let tools = RunJailTools { bwrap: "bwrap".into(), prlimit: "prlimit".into(), timeout: None };
/// # let root = CanonicalPath::resolve(Path::new("/")).ok()?;
/// # let mounts = JailMounts::of_invoker(root.clone(), root, Vec::new()).ok()?;
/// # let no_env = |_: &str| None;
/// let sealed = write_seccomp_memfd(b"filter").ok()?;
/// let argv = run_jail_argv(
///     &tools,
///     &SandboxProfile::maximally_isolated(),
///     &mounts,
///     Some(sealed.make_inheritable().ok()?),
///     &no_env,
///     &[OsString::from("app")],
/// );
/// drop(sealed);
/// Some(argv.args().len())
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
    /// Clear close-on-exec so the next exec (bwrap) inherits the sealed fd, and
    /// return the number the `--seccomp <fd>` argument names.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when either `fcntl` fails.
    pub fn make_inheritable(&self) -> std::io::Result<SealedFdNumber<'_>> {
        clear_cloexec(self.fd.as_fd())?;
        Ok(SealedFdNumber(self.fd.as_fd()))
    }
}

/// Write the compiled seccomp program to a sealed anonymous in-memory file,
/// rewound to offset 0, ready for `bwrap --seccomp <fd>`.
///
/// A `memfd` is used rather than a temp file so the program bytes never touch
/// the filesystem (nothing to race or tamper on disk) and the fd is
/// self-cleaning when closed. It is born close-on-exec and becomes inheritable
/// only through [`SealedSeccompFd::make_inheritable`].
///
/// # Errors
///
/// [`RunJailDefect::Spawn`] on any `memfd_create`, write, seal, or seek failure
/// — a truncated, unwritten, or unsealed filter would let the payload run
/// under a program other than the one compiled, so the jail refuses.
pub fn write_seccomp_memfd(bytes: &[u8]) -> Result<SealedSeccompFd, RunJailDefect> {
    let fd = write_frozen_memfd(c"ipe-seccomp", "seccomp program", bytes)?;
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
    /// Clear close-on-exec so the next exec (bwrap) inherits the sealed fd, and
    /// return the number the `--file <fd> <dest>` delivery names.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when either `fcntl` fails.
    pub fn make_inheritable(&self) -> std::io::Result<SealedFdNumber<'_>> {
        clear_cloexec(self.fd.as_fd())?;
        Ok(SealedFdNumber(self.fd.as_fd()))
    }

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
/// The fd is born close-on-exec and becomes inheritable only through
/// [`SealedApp::make_inheritable`], right before the wrapper→bwrap process
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
    use super::{app_ro_binds, write_sealed_app_memfd, write_seccomp_memfd};
    use crate::CanonicalPath;
    use std::os::fd::AsFd as _;

    /// Whether `fd` carries close-on-exec.
    fn is_cloexec(fd: std::os::fd::BorrowedFd<'_>) -> bool {
        rustix::io::fcntl_getfd(fd).is_ok_and(|flags| flags.contains(rustix::io::FdFlags::CLOEXEC))
    }

    #[test]
    fn a_write_to_the_sealed_seccomp_fd_is_refused() {
        let sealed = write_seccomp_memfd(b"filter").expect("sealed seccomp memfd");
        let refused = rustix::io::write(sealed.as_fd(), b"x");
        assert_eq!(refused, Err(rustix::io::Errno::PERM));
        assert_eq!(
            rustix::fs::fcntl_get_seals(sealed.as_fd()),
            Ok(super::freezing_seals())
        );
    }

    #[test]
    fn a_resize_of_the_sealed_seccomp_fd_is_refused() {
        let sealed = write_seccomp_memfd(b"filter").expect("sealed seccomp memfd");
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
    fn the_seccomp_fd_is_close_on_exec_until_made_inheritable() {
        let sealed = write_seccomp_memfd(b"filter").expect("sealed seccomp memfd");
        assert!(is_cloexec(sealed.as_fd()), "born inheritable");
        sealed.make_inheritable().expect("clear close-on-exec");
        assert!(!is_cloexec(sealed.as_fd()), "still close-on-exec");
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

//! The runtime jail around the *emitted app* (as opposed to the build-time jail
//! around an untrusted crate compile in [`crate`]).
//!
//! A program's capability set is inferred from pure Ipê and declared for native
//! `Rust.` code, but nothing confines the emitted binary when it *runs*: a Tier
//! 2 wrapper is arbitrary native Rust that can make any syscall. This module is
//! the fail-closed jail that runs the binary confined to exactly its
//! declared-plus-inferred set — declared effects work, undeclared ones are
//! impossible.
//!
//! The pipeline is: a [`Capability`] set → a platform-independent
//! [`SandboxProfile`] ([`profile_from_capabilities`]) → a `bwrap` argv + a
//! seccomp program ([`run_jail_argv`] + [`crate::seccomp`]). The profile is the
//! serializable value the built artifact carries (`ipe.profile`); the argv is
//! what a launcher execs.
//!
//! ## Invariants
//!
//! - **Deny-by-default, structurally.** [`profile_from_capabilities`] is an
//!   exhaustive `match Capability` with no `_` catch-all, so a newly-added
//!   capability variant fails to *compile* until it is classified — an
//!   unclassified variant can never default to "allowed". [`SandboxProfile`] has
//!   no `Default` that yields an all-allowed value: the empty set lowers to the
//!   maximally-isolated profile.
//! - **Fail-closed on an unknown database driver.** `database` lowers to
//!   `network` or `filesystem` per the driver; an unknown/missing driver is an
//!   error, never a silently-dropped axis.
//! - **Reuse the mechanism, not the numbers.** The argv reuses the build jail's
//!   `bwrap`/`prlimit` flag vocabulary but defines its own [`RunResourceLimits`]
//!   (no wall-clock kill by default — a long-lived server is legitimate) and
//!   adds the baseline denials the build argv lacks (`--proc /proc`,
//!   `no_new_privs`, the seccomp filter).

#[cfg(test)]
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;

use ipe_diagnostics::{Code, Diagnostic as SharedDiag, IPE_F4413, SandboxError};
use ipe_kernels::Capability;

use crate::{JailMounts, JailPathError};

/// Stamp `$item` with the `#[cfg(...)]` for the targets that HAVE a real run
/// jail compiled into [`exec_in_run_jail`], and the negation on a matching `no:`
/// item — the ONE place the supported-target set is written as a predicate.
///
/// The supported set is Linux `x86_64`/`aarch64` (the `bwrap`+seccomp jail), macOS (the
/// `sandbox-exec` SBPL jail), and Windows (the Job Object + `AppContainer` +
/// launcher-scrub jail). The value [`platform_supports_jail`] returns
/// (`JAIL_COMPILED_IN`) is stamped through this macro, and the refuse-stub
/// `exec_in_run_jail` arm is gated on the NEGATION of this same predicate. So
/// `platform_supports_jail` is `true` exactly where a real jail arm compiles: the
/// admit verdict (`Holds` vs `RefuseGap`) and the jail actually compiled in cannot
/// drift, and a target with only the stub arm reports "refuse", fail-closed. The
/// per-OS real arms keep their own precise `#[cfg]` (their bodies differ), and the
/// `platform_supports_jail_matches_the_compiled_in_jail_arm` unit test asserts the
/// predicate spelled here equals the one those arms use.
///
/// Being a jailed target makes [`platform_supports_jail`] `true`; it does NOT
/// imply the target confines EVERY axis. Linux and macOS confine the full set,
/// but Windows is PARTIAL (see [`platform_confined_axes`]): its jail confines
/// subprocess + env, and filesystem + network + database only under
/// `AppContainer` on an ACL volume. [`CONFINED_AXES`] is therefore NOT stamped by
/// this macro — it is a separate per-OS `#[cfg]` so a jailed-but-partial target
/// can list fewer axes than it compiles an arm for.
macro_rules! on_jailed_target {
    (yes: { $($yes:item)* } no: { $($no:item)* }) => {
        $(
            #[cfg(any(
                all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")),
                target_os = "macos",
                target_os = "windows"
            ))]
            $yes
        )*
        $(
            #[cfg(not(any(
                all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")),
                target_os = "macos",
                target_os = "windows"
            )))]
            $no
        )*
    };
}

pub(crate) mod profile;
pub use profile::*;

pub(crate) mod linux;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use linux::*;

pub(crate) mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

pub(crate) mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;
// `windows_scrubbed_env` and its `WindowsBaseEnv` set are pure and
// host-independent (the Windows env scrub, unit-tested on any host), so they
// are re-exported on every target: the workspace env scan pins the base set's
// home names from any host.
#[cfg(not(target_os = "windows"))]
pub use windows::WindowsBaseEnv;
pub use windows::windows_scrubbed_env;

/// The number of a sealed, inheritable descriptor `bwrap` reads from.
///
/// It names the `--seccomp <fd>` filter and the `--file <fd> <dest>` app
/// delivery. Only a sealed memfd owner mints one (`SealedSeccompFd::make_inheritable`,
/// `SealedApp::make_inheritable`), and only after sealing and clearing
/// close-on-exec, so a jail argv can never name a writable, unsealed, or
/// non-inherited descriptor.
///
/// It borrows the owner's descriptor, is neither `Copy` nor `Clone`, and renders
/// only into a [`JailArgv`] carrying that same borrow. Every spawn and exec
/// builds its `Command` from a borrowed [`JailArgv`], so the owner is held open
/// through the hand-off to `bwrap` and a closed-then-reused fd number cannot
/// reach a jail. A copy of the rendered strings (`args().to_vec()`, `Debug`)
/// carries no borrow; the guarantee covers the spawn paths, which never take one. Both rejections — a number
/// outliving its owner, an owner dropped before its argv is consumed — are
/// pinned as `compile_fail` doctests on `SealedSeccompFd`.
#[cfg(unix)]
#[derive(Debug)]
pub struct SealedFdNumber<'fd>(std::os::fd::BorrowedFd<'fd>);

/// The number of a sealed, inheritable descriptor `bwrap` reads from.
///
/// Uninhabited off Unix: a target without file descriptors mints none, so no
/// jail argv there can name a sealed fd.
#[cfg(not(unix))]
#[derive(Debug)]
pub struct SealedFdNumber<'fd>(std::convert::Infallible, std::marker::PhantomData<&'fd ()>);

impl SealedFdNumber<'_> {
    /// The decimal fd number as `bwrap` reads it. Private to the run-jail
    /// module, whose only caller is [`JailArgv`] rendering.
    #[cfg(unix)]
    fn render(&self) -> OsString {
        use std::os::fd::AsRawFd as _;
        self.0.as_raw_fd().to_string().into()
    }

    /// Uninhabited off Unix.
    #[cfg(not(unix))]
    const fn render(&self) -> OsString {
        match self.0 {}
    }
}

/// A rendered jail argv whose sealed fd numbers stay borrowed from their owners.
///
/// Every `--seccomp <fd>` / `--file <fd>` it names was rendered from a
/// [`SealedFdNumber`] and its `'fd` is carried here, so while the argv, or the
/// slice [`Self::args`] borrows from it, is live, every owner is live. The spawn
/// and exec paths take `&JailArgv` and build their `Command` inside that borrow,
/// so no owner can be dropped before `bwrap` receives its descriptor.
#[derive(Debug)]
pub struct JailArgv<'fd> {
    argv: Vec<OsString>,
    fds: std::marker::PhantomData<SealedFdNumber<'fd>>,
}

impl<'fd> JailArgv<'fd> {
    /// An argv naming no sealed fd. Fd-free by construction: a number renders
    /// only inside this module, and only into a [`JailArgv`] tied to its owner.
    pub(crate) const fn fd_free(argv: Vec<OsString>) -> Self {
        Self {
            argv,
            fds: std::marker::PhantomData,
        }
    }

    /// Insert `flag <fd>` right after the first `token`, tying `fd`'s owner to
    /// this argv. `false`, with the argv unchanged, when `token` is absent.
    pub(crate) fn attach_fd_after(
        &mut self,
        token: &std::ffi::OsStr,
        flag: &str,
        fd: &SealedFdNumber<'fd>,
    ) -> bool {
        let Some(pos) = self.argv.iter().position(|a| a.as_os_str() == token) else {
            return false;
        };
        let tail = self.argv.split_off(pos.saturating_add(1));
        self.argv.push(flag.into());
        self.argv.push(fd.render());
        self.argv.extend(tail);
        true
    }

    /// The rendered arguments, program first. The slice borrows `self`, so it
    /// keeps every fd owner alive for as long as it is used.
    #[must_use]
    pub const fn args(&self) -> &[OsString] {
        self.argv.as_slice()
    }
}

#[cfg(all(test, unix))]
impl<'fd> SealedFdNumber<'fd> {
    /// A number borrowed from a live stand-in descriptor, for argv-rendering tests.
    pub(crate) const fn for_test(fd: std::os::fd::BorrowedFd<'fd>) -> Self {
        Self(fd)
    }
}

// ── the Linux jail argv builder ─────────────────────────────────────────────

/// The paths of the host tools the run jail needs. `bwrap` and `prlimit` are
/// mandatory; `timeout` is only needed when the profile sets a wall-clock cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunJailTools {
    /// `bwrap` — the namespaces + `--seccomp` loader.
    pub bwrap: PathBuf,
    /// `prlimit` — the resource caps (mandatory).
    pub prlimit: PathBuf,
    /// `timeout` — the wall clock, needed only when `limits.wall_secs` is set.
    pub timeout: Option<PathBuf>,
}

/// Build the `bwrap` argv that runs `payload` under the jail `profile`
/// describes.
///
/// Pure — no process is spawned — so the exact isolation surface is
/// unit-testable, exactly like the build jail's `bwrap_argv`. This does NOT
/// share code with `bwrap_argv`: that builder's non-optional `timeout` prefix is
/// load-bearing for the *build* jail (an untrusted compile must always have a
/// wall clock), whereas the run jail wants no wall clock for a long-lived
/// server. Reusing the *flag vocabulary* is deliberate; sharing the *builder*
/// would couple two different resource-limit policies.
///
/// `mounts` carries the one writable tempdir (used both as the `Isolated`
/// filesystem's sole writable mount and as `TMPDIR`), the working tree (bound
/// read-write only under [`FilesystemScope::WorkingTreeReadWrite`]), the
/// read-only binds, and the home masks; below the masks only the binds stay
/// visible, and none of them exposes the cargo home. Every path is canonical,
/// so the `--chdir` and `TMPDIR` the payload receives are exactly the paths
/// bound.
/// `seccomp_fd` is the sealed, inheritable descriptor carrying the compiled
/// seccomp program (passed to `bwrap --seccomp <fd>`); `None` means
/// no filter is attached (the caller must have refused already if a filter was
/// required).
///
/// The env is scrubbed with `--clearenv`; only the fixed minimal allowlist
/// (`PATH`, `TMPDIR`, `LANG`) plus the profile's `env_allowlist` re-enter. There
/// is NO shell token anywhere in the result.
#[must_use]
pub fn run_jail_argv<'fd>(
    tools: &RunJailTools,
    profile: &SandboxProfile,
    mounts: &JailMounts,
    seccomp_fd: Option<SealedFdNumber<'fd>>,
    host_env: &dyn Fn(&str) -> Option<OsString>,
    payload: &[OsString],
) -> JailArgv<'fd> {
    jail_argv(tools, profile, mounts, seccomp_fd, None, host_env, payload)
}

/// The directory, under the scoped tempdir, the delivered app is materialised in.
///
/// It is a mount point for a jail-private tmpfs, so the delivered copy lives
/// only in the jail's memory: nothing of the app is ever written to the host
/// directory `scoped_tmp` binds. The scoped tempdir is created fresh per run,
/// so no other bind can lie beneath it and be shadowed by the tmpfs.
const DELIVERY_DIR: &str = ".ipe-app";

/// The delivered app's file name inside [`DELIVERY_DIR`].
const DELIVERY_FILE: &str = "ipe-app";

/// The in-jail path the delivered app is materialised at and run from.
#[must_use]
pub fn delivered_app_path(mounts: &JailMounts) -> PathBuf {
    mounts
        .scoped_tmp()
        .as_path()
        .join(DELIVERY_DIR)
        .join(DELIVERY_FILE)
}

/// [`run_jail_argv`] for an app delivered from an inherited sealed descriptor.
///
/// The builder owns the destination: it mounts a jail-private tmpfs at
/// `<scoped_tmp>/.ipe-app` AFTER every bind, copies the app from `app_fd`
/// into it owner-executable (`--perms 0700 --file`), remounts the tmpfs
/// read-only, and runs `[<delivered path>, app_args...]` as the payload. bwrap
/// reads the bytes from the inherited (sealed, non-cloexec) descriptor, so
/// the delivered file is exactly the bytes the caller verified, with no host
/// path lookup to race and no copy left on the host when the jail exits.
#[must_use]
pub fn run_jail_argv_with_delivery<'fd>(
    tools: &RunJailTools,
    profile: &SandboxProfile,
    mounts: &JailMounts,
    seccomp_fd: Option<SealedFdNumber<'fd>>,
    app_fd: SealedFdNumber<'fd>,
    host_env: &dyn Fn(&str) -> Option<OsString>,
    app_args: &[OsString],
) -> JailArgv<'fd> {
    let mut payload: Vec<OsString> = Vec::with_capacity(app_args.len().saturating_add(1));
    payload.push(delivered_app_path(mounts).into_os_string());
    payload.extend(app_args.iter().cloned());
    jail_argv(
        tools,
        profile,
        mounts,
        seccomp_fd,
        Some(app_fd),
        host_env,
        &payload,
    )
}

/// The one run-jail argv builder behind [`run_jail_argv`] and
/// [`run_jail_argv_with_delivery`].
fn jail_argv<'fd>(
    tools: &RunJailTools,
    profile: &SandboxProfile,
    mounts: &JailMounts,
    seccomp_fd: Option<SealedFdNumber<'fd>>,
    app_fd: Option<SealedFdNumber<'fd>>,
    host_env: &dyn Fn(&str) -> Option<OsString>,
    payload: &[OsString],
) -> JailArgv<'fd> {
    let (scoped_tmp, working_tree) = (mounts.scoped_tmp(), mounts.working_tree());
    let mut argv: Vec<OsString> = Vec::new();

    // Optional wall clock (only when the profile sets one AND `timeout` is
    // present; the caller refuses a wall-clock profile with no `timeout`).
    if let (Some(wall), Some(timeout)) = (profile.limits.wall_secs, &tools.timeout) {
        argv.push(timeout.clone().into());
        argv.push("--kill-after=5s".into());
        argv.push(wall.to_string().into());
    }

    argv.push(tools.bwrap.clone().into());

    // The network namespace is unshared UNLESS `network` is granted. IPC/UTS/
    // cgroup are unconditionally unshared (SysV shmem / abstract sockets are
    // covert channels that ride IPC independent of the network axis). PID is
    // unconditionally unshared (no host-PID visibility even when subprocess is
    // granted).
    if !profile.network {
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

    // Read-only root, then a FRESH proc mask OVER it. Order matters: the
    // `--ro-bind / /` exposes the host `/proc` (which leaks sibling env via
    // `/proc/<pid>/environ`, defeating `--clearenv`, and is a user-namespace
    // escape lever); the later `--proc /proc` masks it. bwrap applies mount ops
    // in argv order, so proc-after-robind wins.
    argv.push("--ro-bind".into());
    argv.push("/".into());
    argv.push("/".into());
    argv.push("--proc".into());
    argv.push("/proc".into());
    // A fresh minimal devtmpfs (the ro-bound host `/dev` nodes carry no device
    // permissions inside the user namespace).
    argv.push("--dev".into());
    argv.push("/dev".into());
    // Mask the homes and `/tmp` wherever they live, then re-expose through the
    // masks: the extra paths read-only, the scoped tempdir writable, and the
    // working tree writable only when the filesystem axis is granted. The
    // emitted app binary commonly lives under `$HOME` (e.g. a
    // `CARGO_TARGET_DIR` in `~/.cache`); the caller binds the app FILE itself,
    // never its parent directory.
    let working = crate::mounts::WorkingTree::granted_by(&profile.filesystem);
    let binds = crate::mounts::jail_binds(mounts, working);
    crate::mounts::push_mounts(&mut argv, mounts.homes(), &binds);
    argv.push("--chdir".into());
    argv.push(
        match working {
            crate::mounts::WorkingTree::ReadWrite => working_tree,
            crate::mounts::WorkingTree::Unbound => scoped_tmp,
        }
        .as_path()
        .into(),
    );

    // The seccomp filter (subprocess denial + baseline denials). Attached via a
    // pre-arranged fd. `no_new_privs` is set by bubblewrap by default (it always
    // calls `PR_SET_NO_NEW_PRIVS` unless `--cap-add` is used, which the run jail
    // never does), so the "no privilege gain" claim is mechanical.
    if let Some(fd) = seccomp_fd {
        argv.push("--seccomp".into());
        argv.push(fd.render());
    }

    // Scrubbed env: the fixed minimal allowlist, then the profile's declared
    // env names re-exported from the host (only when `env` was granted). A named
    // var absent from the host is simply not re-exported (never a placeholder).
    argv.push("--setenv".into());
    argv.push("PATH".into());
    argv.push("/usr/bin:/bin".into());
    argv.push("--setenv".into());
    argv.push("TMPDIR".into());
    argv.push(scoped_tmp.as_path().into());
    if let Some(lang) = host_env("LANG") {
        argv.push("--setenv".into());
        argv.push("LANG".into());
        argv.push(lang);
    }
    for name in &profile.env_allowlist {
        if let Some(value) = host_env(name) {
            argv.push("--setenv".into());
            argv.push(name.into());
            argv.push(value);
        }
    }

    // Materialise the app inside the jail from the inherited sealed descriptor,
    // AFTER all mounts and BEFORE the payload: a fresh tmpfs at the delivery
    // dir (jail memory, never the host dir `scoped_tmp` binds), the
    // owner-execute copy from `fd` into it, then the tmpfs remounted read-only
    // so the app cannot rewrite its own image. `--perms 0700` applies to the
    // `--file` that follows it.
    if let Some(fd) = app_fd {
        let dir = scoped_tmp.as_path().join(DELIVERY_DIR);
        argv.push("--tmpfs".into());
        argv.push(dir.clone().into());
        argv.push("--perms".into());
        argv.push("0700".into());
        argv.push("--file".into());
        argv.push(fd.render());
        argv.push(dir.join(DELIVERY_FILE).into());
        argv.push("--remount-ro".into());
        argv.push(dir.into());
    }

    // Resource caps via prlimit, then the payload with NO shell. The wall clock
    // (if any) is the outer `timeout`; prlimit bounds AS/CPU/FDs/procs.
    argv.push("--".into());
    argv.push(tools.prlimit.clone().into());
    argv.push(format!("--as={}", profile.limits.as_bytes).into());
    argv.push(format!("--cpu={}", profile.limits.cpu_secs).into());
    argv.push(format!("--nofile={}", profile.limits.fd_cap).into());
    argv.push(format!("--nproc={}", profile.limits.proc_cap).into());
    argv.push("--".into());
    argv.extend(payload.iter().cloned());
    // `'fd` is the borrow of every number rendered above.
    JailArgv {
        argv,
        fds: std::marker::PhantomData,
    }
}

// ── refusal + the fail-closed platform decision ─────────────────────────────

/// Why the run jail could not be established, or refused to run. The whole
/// family carries the [`IPE_F4413`] taxonomy code, the run-jail sibling of the
/// build jail's [`crate::SandboxDefect`] / `IPE-F4410`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunJailDefect {
    /// A required jail primitive is absent on this host (`bwrap`/`prlimit`, or a
    /// wall-clock profile with no `timeout`). Fail-closed: refuse, never run
    /// unconfined.
    PrimitiveUnavailable {
        /// The missing primitive name(s).
        missing: Vec<&'static str>,
    },
    /// No sound jail can be built on this platform (not Linux, or seccomp cannot
    /// be compiled for this architecture). The documented refuse-gap: a
    /// non-empty native/high-value set refuses to run here.
    UnsupportedPlatform {
        /// A short reason for the diagnostic.
        reason: &'static str,
    },
    /// The capability profile could not be built (see [`ProfileError`]).
    Profile(ProfileError),
    /// The jailed process could not be spawned.
    Spawn {
        /// The rendered OS error.
        detail: String,
    },
    /// A jail-root mount (or unmount) could not be established while building the
    /// confinement — the read-only root, a read-write scratch/working-tree mount,
    /// the fresh devfs, or the masked `/proc`. Distinct from [`Self::Spawn`] so a
    /// failure to *build* the jail root is never conflated with a failure to
    /// *launch* the payload: a half-built root refuses before any process runs.
    /// Fail-closed — the untrusted payload never runs against an
    /// incompletely-mounted root.
    MountFailed {
        /// The mount target that could not be established.
        target: PathBuf,
        /// The rendered OS error or non-success detail for the mount attempt.
        detail: String,
    },
    /// A tampered `ipe.profile` requested *less* isolation than the capability
    /// floor embedded in the binary. Refuse — a weaker profile cannot widen the
    /// jail below what the binary was built for.
    ProfileWeakerThanFloor,
    /// A path the jail would mount or hand to the payload could not be
    /// resolved, or a home it must mask is unknown.
    Path(JailPathError),
}

impl RunJailDefect {
    /// The stable taxonomy code (`IPE-F4413` for the whole family).
    #[must_use]
    pub const fn code(&self) -> Code {
        IPE_F4413
    }
}

impl From<RunJailDefect> for SandboxError {
    fn from(d: RunJailDefect) -> Self {
        let detail = match &d {
            RunJailDefect::PrimitiveUnavailable { missing } => format!(
                "cannot establish a runtime jail around the app — missing {} — refusing to run \
                 a capability-bearing program unconfined; install bubblewrap (bwrap) and \
                 util-linux (prlimit)",
                missing.join(", ")
            ),
            RunJailDefect::UnsupportedPlatform { reason } => format!(
                "no runtime jail can be built on this platform ({reason}); refusing to run a \
                 native-capability program unconfined"
            ),
            RunJailDefect::Profile(e) => e.to_string(),
            RunJailDefect::Spawn { detail } => {
                format!("failed to spawn the jailed app: {detail}")
            }
            RunJailDefect::MountFailed { target, detail } => format!(
                "could not establish the jail-root mount at {} ({detail}); refusing to run the \
                 untrusted payload against an incompletely-mounted root",
                target.display()
            ),
            RunJailDefect::ProfileWeakerThanFloor => {
                "the artifact's ipe.profile requests less isolation than the capability floor \
                 embedded in the binary — refusing to run under a weakened profile"
                    .to_owned()
            }
            RunJailDefect::Path(e) => e.to_string(),
        };
        Self::RunJail {
            detail: detail.into(),
        }
    }
}

impl From<RunJailDefect> for SharedDiag {
    fn from(d: RunJailDefect) -> Self {
        Self::Sandbox {
            msg: SandboxError::from(d),
        }
    }
}

impl std::fmt::Display for RunJailDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let shared: SharedDiag = self.clone().into();
        f.write_str(&ipe_diagnostics::render(&shared, "", ""))
    }
}

impl std::error::Error for RunJailDefect {}

/// The build-time platform verdict: can a sound run jail be built on THIS
/// target at all?
///
/// Linux `x86_64`/`aarch64` (the `bwrap`+seccomp jail), macOS (the `sandbox-exec` SBPL
/// jail), and Windows (the Job Object + `AppContainer` + launcher-scrub jail) →
/// yes. Everything else is the documented refuse-gap.
///
/// "Yes" means a jail ARM is compiled in, not that every axis is confined:
/// Windows is a jailed target with a PARTIAL confined set (see
/// [`platform_confined_axes`]). This is a `const` reflection of the compile
/// target, independent of host tool availability (which [`RunJailTools`] /
/// `sandbox-exec` probing covers). Both this constant and the real
/// [`exec_in_run_jail`] arm are stamped by the SAME [`on_jailed_target`] macro,
/// so the verdict is `true` EXACTLY on the targets a jail is compiled for. There
/// is no second hand-kept copy to drift: the FFI admit path can never claim a
/// jail that is not compiled for the target, and a target with only the stub
/// `exec_in_run_jail` reports "refuse".
#[must_use]
pub const fn platform_supports_jail() -> bool {
    JAIL_COMPILED_IN
}

on_jailed_target! {
    yes: {
        /// True on the targets [`exec_in_run_jail`] has a real (non-stub) arm.
        /// Stamped by [`on_jailed_target`] so it cannot disagree with the arm.
        const JAIL_COMPILED_IN: bool = true;
    }
    no: {
        /// False on the targets [`exec_in_run_jail`] is only the refuse stub.
        const JAIL_COMPILED_IN: bool = false;
    }
}

/// The runtime-enforced axes the compiled-in [`exec_in_run_jail`] arm confines.
///
/// This is the single source the FFI admit path keys off, so it can never claim
/// an axis the jail does not enforce on this target.
///
/// The set is per-OS `#[cfg]` (NOT stamped by [`on_jailed_target`], because a
/// jailed target need not confine every axis):
///
/// - **Linux** (`bwrap`+seccomp) and **macOS** (`sandbox-exec`+launcher-scrub)
///   confine the FULL set — network + filesystem (net namespace / SBPL deny;
///   `--ro-bind`+tmpfs / SBPL deny-write), subprocess (seccomp / SBPL
///   process-deny), env (`--clearenv` / launcher scrub) — and native-ffi is
///   contained by the whole-process jail regardless of what native code does.
/// - **Windows** is PARTIAL: the Job Object confines subprocess and the launcher
///   scrub confines env unconditionally; filesystem and network are confined
///   only under `AppContainer` on an ACL volume (see the design doc's refuse-gap
///   policy). The compiled-in Windows arm establishes `AppContainer` + an ACL
///   scratch, so it lists filesystem and network too — the restricted-token /
///   non-ACL-volume refuse-gaps are runtime conditions the arm fails-closed on,
///   not a compile-time axis removal.
/// - Off every jailed target the stub arm confines NOTHING (the fail-closed
///   empty set), so a capability-bearing wrapper is refused, never run
///   unconfined.
///
/// **`database` is DERIVED, never a standalone asserted bit.** `database` lowers
/// to `network` (a TCP driver) or `filesystem` (a file driver) before it reaches
/// the jail; which one is a per-project runtime fact unknown here. So the honest
/// platform predicate is "database is confined iff BOTH the axes it can lower
/// into are confined" — [`database_confined`] over this target's net + fs
/// membership. On a FULL target (Linux/macOS) net and fs are both confined, so
/// database is confined exactly as before. On a PARTIAL target that confined, say,
/// filesystem but not network, database would be OMITTED — a file-backed database
/// would still be admitted through its `filesystem` lowering, but the standalone
/// `database` claim would over-promise for a TCP driver, so it is not made. This
/// is guardian Nit-1 from the per-axis review.
///
/// The list is `Capability` values so the FFI admit path folds them straight
/// into its confined-axis set; the ordering is irrelevant (folded into a set).
#[must_use]
pub const fn platform_confined_axes() -> &'static [Capability] {
    CONFINED_AXES
}

/// Whether the `database` axis is confined, DERIVED from whether both axes it can
/// lower into — `network` (TCP driver) and `filesystem` (file driver) — are
/// confined on this target.
///
/// `database` carries no OS control of its own; it is confined iff EVERY axis it
/// could lower into is confined, so that neither a TCP nor a file driver escapes.
/// This is the single source that keeps `database` from being over-claimed on a
/// partial target (guardian Nit-1): it is never asserted directly in
/// [`CONFINED_AXES`] — it appears there only when this derivation holds.
#[must_use]
pub const fn database_confined(network_confined: bool, filesystem_confined: bool) -> bool {
    network_confined && filesystem_confined
}

/// The `FILE_PERSISTENT_ACLS` filesystem-capability bit as reported by
/// `GetVolumeInformationW`'s `lpFileSystemFlags`. A volume that clears this bit
/// (FAT/exFAT, some redirected `%TEMP%` and network shares) neither persists nor
/// enforces DACLs: `SetNamedSecurityInfoW` returns `ERROR_SUCCESS` while
/// persisting/enforcing nothing.
///
/// It is written here as the raw Win32 value (kept in lockstep with
/// `windows_sys::Win32::System::SystemServices::FILE_PERSISTENT_ACLS`) so the
/// [`volume_flags_confine_filesystem`] decision is a pure, cross-platform
/// function unit-testable on any host, not gated behind `cfg(windows)`.
///
/// Consumed by the Windows arm (the `const _` lockstep assertion) and by the
/// cross-platform unit tests; on a non-Windows non-test build it has no caller,
/// hence the scoped `dead_code` allow.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub(crate) const FILE_PERSISTENT_ACLS_FLAG: u32 = 0x0000_0008;

/// The typed "parse the volume capability" decision: given the filesystem flags
/// `GetVolumeInformationW` reports for a volume, is the ACL boundary the Windows
/// run-jail arm relies on actually enforceable there?
///
/// The Windows arm confines `filesystem` (and, via [`database_confined`],
/// `database`) by `ACLing` the scratch/working-tree DACL to the container SID.
/// That boundary is a NO-OP on a volume without `FILE_PERSISTENT_ACLS`, where
/// `SetNamedSecurityInfoW` succeeds without persisting or enforcing anything. So
/// the ACL claim is honest only when this bit is present.
///
/// `true` ⇒ the volume persists+enforces DACLs, so the arm may proceed to ACL and
/// launch. `false` ⇒ the arm must fail closed (never launch on a volume where the
/// ACL boundary the admit path already trusted is a no-op). This is the parse
/// step: probe once → a typed proceed/refuse decision, not an inference from a
/// success return that does not mean what the caller assumed.
#[must_use]
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub(crate) const fn volume_flags_confine_filesystem(filesystem_flags: u32) -> bool {
    filesystem_flags & FILE_PERSISTENT_ACLS_FLAG != 0
}

/// Linux/macOS confine the full set. `database` is present because
/// [`database_confined`] holds (both net and fs are confined); the
/// `database_membership_is_derived_from_net_and_fs` test proves the list matches
/// the derivation rather than asserting `database` standalone.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
))]
const CONFINED_AXES: &[Capability] = &[
    Capability::Network,
    Capability::Filesystem,
    Capability::Database,
    Capability::Env,
    Capability::Subprocess,
    Capability::NativeFfi,
];

/// Windows confines subprocess + env unconditionally, and filesystem + network
/// under the `AppContainer` + ACL-scratch arm the launcher establishes.
/// `database` is present because [`database_confined`] holds over Windows's net +
/// fs membership (both are in the list). Were a future Windows configuration to
/// drop `network` or `filesystem`, `database` would have to leave too — the
/// `database_membership_is_derived_from_net_and_fs` test enforces exactly that,
/// so the derivation cannot silently over-claim. native-ffi is contained by the
/// whole-process Job Object + token, so it is listed.
#[cfg(target_os = "windows")]
const CONFINED_AXES: &[Capability] = &[
    Capability::Network,
    Capability::Filesystem,
    Capability::Database,
    Capability::Env,
    Capability::Subprocess,
    Capability::NativeFfi,
];

/// The stub arm confines nothing — the fail-closed empty set.
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "windows"
)))]
const CONFINED_AXES: &[Capability] = &[];

/// On non-Linux targets bwrap is not the jail mechanism, so there is no
/// `--unshare-net` netns to probe; return `false` so callers skip the
/// bwrap-netns-dependent tests unconditionally off Linux.
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[must_use]
// Kept a plain `fn` (not `const fn`) so its signature matches the Linux arm.
#[allow(clippy::missing_const_for_fn)]
pub fn netns_jail_available(_bwrap: &std::path::Path) -> bool {
    false
}

/// Off every jailed target the run jail is a documented refuse-gap: no primitive
/// this crate builds would confine the app here.
///
/// # Errors
///
/// Always [`RunJailDefect::UnsupportedPlatform`].
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "windows"
)))]
#[allow(clippy::missing_const_for_fn)]
pub fn probe_run_jail_tools(_wants_wall_clock: bool) -> Result<RunJailTools, RunJailDefect> {
    Err(RunJailDefect::UnsupportedPlatform {
        reason: "runtime jail is compiled only for Linux (x86_64/aarch64), macOS, and Windows",
    })
}

/// Off every jailed target the run jail is a documented refuse-gap.
///
/// # Errors
///
/// Always [`RunJailDefect::UnsupportedPlatform`]: no sound run jail can be built
/// here, so a capability-bearing program refuses to run rather than run
/// unconfined. This arm is gated on the negation of the [`on_jailed_target`]
/// predicate, so it compiles EXACTLY where [`platform_supports_jail`] is false.
// Kept a plain `fn` (not `const fn`) so its signature matches the real
// `exec_in_run_jail` arms, which cannot be `const`.
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "windows"
)))]
#[allow(clippy::missing_const_for_fn)]
pub fn exec_in_run_jail(
    _tools: &RunJailTools,
    _profile: &SandboxProfile,
    _scoped_tmp: &std::path::Path,
    _working_tree: &std::path::Path,
    _app: &std::path::Path,
    _app_args: &[OsString],
) -> Result<std::convert::Infallible, RunJailDefect> {
    Err(RunJailDefect::UnsupportedPlatform {
        reason: "runtime jail is compiled only for Linux (x86_64/aarch64), macOS, and Windows",
    })
}

/// Embedded-app holder on platforms without the sealed-fd delivery path.
///
/// Windows and unsupported targets lack the sealed-fd / exclusive-scratch
/// delivery. Embed mode is a Unix deploy feature; this arm keeps the wrapper
/// compiling everywhere and refuses at run time rather than running unconfined.
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
)))]
pub struct SealedApp {
    bytes: Vec<u8>,
}

#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
)))]
impl SealedApp {
    /// Return the held bytes for the capability-floor verification scan.
    ///
    /// # Errors
    ///
    /// Never; returns `Result` for arm-parity with the Linux variant.
    pub fn read_sealed_bytes(&self) -> Result<Vec<u8>, RunJailDefect> {
        Ok(self.bytes.clone())
    }
}

/// Hold the embedded app bytes on a platform without sealed-fd delivery.
///
/// # Errors
///
/// Never; returns `Result` for arm-parity with the Linux variant.
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
)))]
pub fn write_sealed_app_memfd(bytes: &[u8]) -> Result<SealedApp, RunJailDefect> {
    Ok(SealedApp {
        bytes: bytes.to_vec(),
    })
}

/// Embedded exec is a documented refuse-gap on platforms without a run jail.
///
/// # Errors
///
/// Always [`RunJailDefect::UnsupportedPlatform`].
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
)))]
#[allow(clippy::missing_const_for_fn)]
pub fn exec_embedded_in_run_jail(
    _tools: &RunJailTools,
    _profile: &SandboxProfile,
    _scoped_tmp: &std::path::Path,
    _working_tree: &std::path::Path,
    _app: &SealedApp,
    _app_args: &[OsString],
) -> Result<std::convert::Infallible, RunJailDefect> {
    Err(RunJailDefect::UnsupportedPlatform {
        reason: "runtime jail is compiled only for Linux (x86_64/aarch64), macOS, and Windows",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CanonicalPath, HomeMasks};
    use std::path::Path;

    /// An absent anchor token attaches nothing and leaves the argv byte-identical.
    #[cfg(unix)]
    #[test]
    fn attach_fd_after_refuses_a_missing_token_and_keeps_the_argv() {
        use std::os::fd::AsFd as _;
        let stdin = std::io::stdin();
        let number = SealedFdNumber(stdin.as_fd());
        let before: Vec<OsString> = ["bwrap", "--ro-bind", "/a", "/a", "--", "prog"]
            .into_iter()
            .map(OsString::from)
            .collect();
        let mut argv = JailArgv::fd_free(before.clone());
        assert!(!argv.attach_fd_after(std::ffi::OsStr::new("--absent"), "--seccomp", &number));
        assert_eq!(argv.args(), before.as_slice());
        assert!(argv.attach_fd_after(std::ffi::OsStr::new("bwrap"), "--seccomp", &number));
        assert_eq!(
            argv.args().get(1).map(OsString::as_os_str),
            Some(std::ffi::OsStr::new("--seccomp"))
        );
        assert_eq!(argv.args().len(), before.len().saturating_add(2));
    }

    /// A newline or escape in a run-jail defect's OS error or mount target stays on its owning line.
    #[test]
    fn a_run_jail_defect_cannot_forge_an_output_line() {
        const FORGED: &str = "x\nerror: forged\u{1b}[2K";
        let defects = [
            RunJailDefect::Spawn {
                detail: FORGED.to_owned(),
            },
            RunJailDefect::MountFailed {
                target: PathBuf::from(FORGED),
                detail: FORGED.to_owned(),
            },
        ];
        for defect in defects {
            let text = defect.to_string();
            assert!(text.contains("error: forged"), "{text}");
            assert!(!text.contains("[2K"), "{text}");
            assert!(
                text.lines().all(|line| !line.starts_with("error: forged")),
                "{text}"
            );
        }
    }

    fn set(caps: &[Capability]) -> BTreeSet<Capability> {
        caps.iter().copied().collect()
    }

    // The volume-capability decision the Windows run-jail arm uses to keep its
    // always-confined `Filesystem` claim honest. These exercise the pure
    // `volume_flags_confine_filesystem` on the raw filesystem-flags value, so they
    // run on ANY host — no self-hosted FAT/exFAT runner is needed for the negative
    // proof. The Windows arm's `probe_volume_persists_acls` feeds
    // `GetVolumeInformationW`'s flags straight into this function and fails closed
    // on `false`.

    #[test]
    fn volume_without_persistent_acls_refuses() {
        // FAT/exFAT-style flags: the FILE_PERSISTENT_ACLS bit is clear. Even with
        // other capability bits set (case-preserving, unicode-on-disk), the
        // decision is refuse — the ACL boundary would be a no-op there.
        let no_acls = 0x0000_0001 | 0x0000_0002 | 0x0000_0004; // not FILE_PERSISTENT_ACLS
        assert!(
            !volume_flags_confine_filesystem(no_acls),
            "a volume without FILE_PERSISTENT_ACLS must refuse (flags = {no_acls:#x})"
        );
        // Exactly zero flags also refuses.
        assert!(!volume_flags_confine_filesystem(0));
    }

    #[test]
    fn volume_with_persistent_acls_proceeds() {
        // NTFS-style flags: the FILE_PERSISTENT_ACLS bit is set.
        assert!(volume_flags_confine_filesystem(FILE_PERSISTENT_ACLS_FLAG));
        // Set alongside unrelated capability bits, it still proceeds.
        let ntfs_like = FILE_PERSISTENT_ACLS_FLAG | 0x0000_0001 | 0x0000_0002 | 0x0010_0000;
        assert!(volume_flags_confine_filesystem(ntfs_like));
    }

    #[test]
    fn persistent_acls_flag_is_the_win32_bit() {
        // The pure flag value must equal the documented Win32 FILE_PERSISTENT_ACLS
        // (0x8). On Windows a `const _` assertion additionally ties it to
        // `windows-sys`; this keeps the value pinned on every host.
        assert_eq!(FILE_PERSISTENT_ACLS_FLAG, 0x0000_0008);
    }

    #[test]
    fn empty_set_lowers_to_maximally_isolated() {
        let p = profile_from_capabilities(
            &BTreeSet::new(),
            &BTreeSet::new(),
            DatabaseAxis::NotApplicable,
            &[],
        )
        .expect("empty set lowers");
        assert_eq!(p, SandboxProfile::maximally_isolated());
        assert!(!p.network);
        assert_eq!(p.filesystem, FilesystemScope::Isolated);
        assert!(!p.subprocess);
        assert!(p.env_allowlist.is_empty());
    }

    #[test]
    fn network_capability_grants_network_only() {
        let p = profile_from_capabilities(
            &set(&[Capability::Network]),
            &BTreeSet::new(),
            DatabaseAxis::NotApplicable,
            &[],
        )
        .expect("lowers");
        assert!(p.network);
        assert_eq!(p.filesystem, FilesystemScope::Isolated);
        assert!(!p.subprocess);
    }

    #[test]
    fn the_union_of_inferred_and_declared_is_used() {
        // inferred = {filesystem}, declared = {network}: both must be granted
        // (no false-deny — a declared axis is relaxed even if not inferred).
        let p = profile_from_capabilities(
            &set(&[Capability::Filesystem]),
            &set(&[Capability::Network]),
            DatabaseAxis::NotApplicable,
            &[],
        )
        .expect("lowers");
        assert!(p.network);
        assert_eq!(p.filesystem, FilesystemScope::WorkingTreeReadWrite);
    }

    #[test]
    fn database_lowers_to_network_or_filesystem_per_driver() {
        let net = profile_from_capabilities(
            &set(&[Capability::Database]),
            &BTreeSet::new(),
            DatabaseAxis::Network,
            &[],
        )
        .expect("lowers");
        assert!(net.network);
        assert_eq!(net.filesystem, FilesystemScope::Isolated);

        let file = profile_from_capabilities(
            &set(&[Capability::Database]),
            &BTreeSet::new(),
            DatabaseAxis::Filesystem,
            &[],
        )
        .expect("lowers");
        assert!(!file.network);
        assert_eq!(file.filesystem, FilesystemScope::WorkingTreeReadWrite);
    }

    #[test]
    fn database_with_an_unknown_driver_fails_closed() {
        let r = profile_from_capabilities(
            &set(&[Capability::Database]),
            &BTreeSet::new(),
            DatabaseAxis::NotApplicable,
            &[],
        );
        assert_eq!(r, Err(ProfileError::UnknownDatabaseDriver));
    }

    #[test]
    fn env_capability_re_exports_the_named_allowlist() {
        let p = profile_from_capabilities(
            &set(&[Capability::Env]),
            &BTreeSet::new(),
            DatabaseAxis::NotApplicable,
            &["DATABASE_URL".to_owned(), "API_KEY".to_owned()],
        )
        .expect("lowers");
        assert_eq!(p.env_allowlist, vec!["DATABASE_URL", "API_KEY"]);
    }

    #[test]
    fn clock_and_random_carry_no_control() {
        let p = profile_from_capabilities(
            &set(&[Capability::Clock, Capability::Random]),
            &BTreeSet::new(),
            DatabaseAxis::NotApplicable,
            &[],
        )
        .expect("lowers");
        // No axis is opened by clock/random.
        assert_eq!(p, SandboxProfile::maximally_isolated());
    }

    #[test]
    fn native_ffi_alone_opens_no_control() {
        let p = profile_from_capabilities(
            &set(&[Capability::NativeFfi]),
            &BTreeSet::new(),
            DatabaseAxis::NotApplicable,
            &[],
        )
        .expect("lowers");
        assert_eq!(p, SandboxProfile::maximally_isolated());
    }

    #[test]
    fn floor_comparison_refuses_a_widened_profile() {
        let floor = SandboxProfile::maximally_isolated();
        // A profile that grants network is weaker than a maximally-isolated
        // floor → refuse.
        let widened = SandboxProfile {
            network: true,
            ..SandboxProfile::maximally_isolated()
        };
        assert!(!widened.is_at_least_as_isolated_as(&floor));
        // The floor itself is at least as isolated as itself.
        assert!(floor.is_at_least_as_isolated_as(&floor));
    }

    #[test]
    fn floor_comparison_allows_a_tighter_profile() {
        // floor grants network; a profile that does NOT grant it is tighter →
        // allowed (more isolation than the floor is never a violation).
        let floor = SandboxProfile {
            network: true,
            filesystem: FilesystemScope::WorkingTreeReadWrite,
            ..SandboxProfile::maximally_isolated()
        };
        let tighter = SandboxProfile::maximally_isolated();
        assert!(tighter.is_at_least_as_isolated_as(&floor));
    }

    #[test]
    fn floor_comparison_checks_env_var_subset() {
        let floor = SandboxProfile {
            env_allowlist: vec!["A".to_owned()],
            ..SandboxProfile::maximally_isolated()
        };
        // Granting an env var the floor does not is a violation.
        let extra_env = SandboxProfile {
            env_allowlist: vec!["A".to_owned(), "SECRET".to_owned()],
            ..SandboxProfile::maximally_isolated()
        };
        assert!(!extra_env.is_at_least_as_isolated_as(&floor));
        // A subset is fine.
        let subset = SandboxProfile {
            env_allowlist: vec!["A".to_owned()],
            ..SandboxProfile::maximally_isolated()
        };
        assert!(subset.is_at_least_as_isolated_as(&floor));
    }

    fn tools() -> RunJailTools {
        RunJailTools {
            bwrap: PathBuf::from("/usr/bin/bwrap"),
            prlimit: PathBuf::from("/usr/bin/prlimit"),
            timeout: Some(PathBuf::from("/usr/bin/timeout")),
        }
    }

    /// Mounts over paths that need not exist, checked against a cargo home
    /// none of them covers.
    fn mounts_of(
        scoped_tmp: CanonicalPath,
        working_tree: CanonicalPath,
        read_only: Vec<CanonicalPath>,
        homes: HomeMasks,
    ) -> JailMounts {
        JailMounts::checked_against(
            scoped_tmp,
            working_tree,
            read_only,
            homes,
            Path::new("/nonexistent-ipe-cargo-home"),
        )
        .expect("no mount covers the stand-in cargo home")
    }

    fn work_mounts() -> JailMounts {
        mounts_of(
            CanonicalPath::assumed("/work/tmp-1"),
            CanonicalPath::assumed("/work/tree"),
            Vec::new(),
            HomeMasks::unmasked(),
        )
    }

    fn rendered(profile: &SandboxProfile, seccomp_fd: Option<SealedFdNumber<'_>>) -> Vec<String> {
        let no_env = |_: &str| None;
        run_jail_argv(
            &tools(),
            profile,
            &work_mounts(),
            seccomp_fd,
            &no_env,
            &[OsString::from("/work/tree/target/debug/ipe-app")],
        )
        .args()
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
    }

    #[test]
    fn run_jail_masks_a_home_outside_home_and_keeps_the_working_tree_visible() {
        let base_dir = crate::test_dir::TestDir::new("run-jail-homes").expect("test dir");
        let base = base_dir.path();
        let user_home = base.join("user");
        let tree = user_home.join("project");
        std::fs::create_dir_all(&tree).expect("working tree");
        let user_home = std::fs::canonicalize(&user_home).expect("canonical home");
        let tree = std::fs::canonicalize(&tree).expect("canonical tree");
        let home_bind = CanonicalPath::resolve(&user_home).expect("resolve home");
        let tree_bind = CanonicalPath::resolve(&tree).expect("resolve tree");
        let profile = SandboxProfile {
            filesystem: FilesystemScope::WorkingTreeReadWrite,
            ..SandboxProfile::maximally_isolated()
        };
        let no_env = |_: &str| None;
        let mounts = mounts_of(
            CanonicalPath::assumed("/work/tmp-1"),
            tree_bind,
            // A bind of the whole home must not survive its mask.
            vec![home_bind],
            HomeMasks::resolve(Ok(&crate::home::test_home(&user_home)), None).expect("homes"),
        );
        let argv: Vec<String> = run_jail_argv(
            &tools(),
            &profile,
            &mounts,
            None,
            &no_env,
            &[OsString::from("app")],
        )
        .args()
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
        assert_eq!(
            crate::mounts::bind_after_covered_mask(&argv),
            None,
            "{argv:?}"
        );
        let at = |window: &[&str]| {
            argv.windows(window.len())
                .position(|w| w.iter().zip(window).all(|(a, b)| a == b))
        };
        let home = user_home.to_string_lossy().into_owned();
        let tree = tree.to_string_lossy().into_owned();
        let mask = at(&["--tmpfs", &home]).expect("home masked");
        let bind = at(&["--bind", &tree, &tree]).expect("working tree bound");
        let chdir = at(&["--chdir", &tree]).expect("chdir into the tree");
        assert!(mask < bind && bind < chdir, "{argv:?}");
    }

    #[cfg(unix)]
    #[test]
    fn the_run_jail_chdir_and_tmpdir_are_the_bound_paths() {
        // Symlinked scratch and working tree: the payload's `--chdir` and
        // `TMPDIR` must be the paths the jail binds, never the links.
        let base_dir = crate::test_dir::TestDir::new("run-jail-symlinks").expect("test dir");
        let base = base_dir.path();
        let real = base.join("real");
        let links = base.join("links");
        for dir in ["tmp", "tree"] {
            std::fs::create_dir_all(real.join(dir)).expect("real dir");
        }
        std::fs::create_dir_all(&links).expect("links dir");
        for dir in ["tmp", "tree"] {
            let link = links.join(dir);
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(real.join(dir), &link).expect("symlink");
        }
        let scoped_tmp = CanonicalPath::resolve(&links.join("tmp")).expect("resolve tmp");
        let tree = CanonicalPath::resolve(&links.join("tree")).expect("resolve tree");
        let real = std::fs::canonicalize(&real).expect("canonical real");
        let no_env = |_: &str| None;
        for (filesystem, workdir) in [
            (FilesystemScope::Isolated, "tmp"),
            (FilesystemScope::WorkingTreeReadWrite, "tree"),
        ] {
            let profile = SandboxProfile {
                filesystem,
                ..SandboxProfile::maximally_isolated()
            };
            let mounts = mounts_of(
                scoped_tmp.clone(),
                tree.clone(),
                Vec::new(),
                HomeMasks::unmasked(),
            );
            let argv: Vec<String> = run_jail_argv(
                &tools(),
                &profile,
                &mounts,
                None,
                &no_env,
                &[OsString::from("app")],
            )
            .args()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
            let at = |window: &[&str]| {
                argv.windows(window.len())
                    .position(|w| w.iter().zip(window).all(|(a, b)| a == b))
            };
            let tmp = real.join("tmp").to_string_lossy().into_owned();
            let cwd = real.join(workdir).to_string_lossy().into_owned();
            assert!(at(&["--bind", &tmp, &tmp]).is_some(), "{argv:?}");
            assert!(at(&["--bind", &cwd, &cwd]).is_some(), "{argv:?}");
            assert!(at(&["--chdir", &cwd]).is_some(), "{argv:?}");
            assert!(at(&["--setenv", "TMPDIR", &tmp]).is_some(), "{argv:?}");
        }
    }

    /// A live stand-in descriptor for a test `SealedFdNumber` to borrow.
    #[cfg(unix)]
    #[allow(clippy::expect_used)] // a test host with no `/dev/null` cannot build the fixture
    fn stand_in_fd() -> std::fs::File {
        std::fs::File::open("/dev/null").expect("open /dev/null")
    }

    #[cfg(unix)]
    #[test]
    fn maximally_isolated_argv_denies_net_masks_proc_and_scrubs_env() {
        use std::os::fd::{AsFd as _, AsRawFd as _};
        let filter = stand_in_fd();
        let argv = rendered(
            &SandboxProfile::maximally_isolated(),
            Some(SealedFdNumber::for_test(filter.as_fd())),
        );
        let joined = argv.join(" ");
        // No wall clock (default RunResourceLimits has wall_secs = None), so
        // bwrap is the first program.
        assert!(joined.starts_with("/usr/bin/bwrap"), "{joined}");
        // Net unshared (network absent), namespaces fresh, env scrubbed.
        for flag in [
            "--unshare-net",
            "--unshare-pid",
            "--unshare-ipc",
            "--clearenv",
        ] {
            assert!(argv.contains(&flag.to_owned()), "missing {flag}: {joined}");
        }
        // Fresh proc mask AFTER the ro-bind of root — the ordering that masks
        // the host /proc.
        let ro_root = joined.find("--ro-bind / /").expect("ro-bind root");
        let proc = joined.find("--proc /proc").expect("proc mask");
        assert!(
            proc > ro_root,
            "proc mask must follow the ro-bind: {joined}"
        );
        // Seccomp filter attached.
        let seccomp = format!("--seccomp {}", filter.as_raw_fd());
        assert!(joined.contains(&seccomp), "{joined}");
        // Resource caps then the payload, no shell.
        assert!(joined.contains("-- /usr/bin/prlimit --as="), "{joined}");
        assert!(
            joined.ends_with("-- /work/tree/target/debug/ipe-app"),
            "{joined}"
        );
        assert!(!joined.contains("sh -c"), "{joined}");
    }

    /// Every bwrap mount op before the payload separator, as `(op, target)` in argv order.
    fn mount_targets(argv: &[String]) -> Vec<(String, String)> {
        let mut ops = Vec::new();
        let mut rest = argv.iter();
        while let Some(token) = rest.next() {
            let operands = match token.as_str() {
                "--" => break,
                "--bind" | "--ro-bind" | "--dev-bind" | "--bind-try" | "--ro-bind-try"
                | "--file" => 2,
                "--tmpfs" | "--proc" | "--dev" | "--dir" | "--remount-ro" => 1,
                _ => continue,
            };
            let target = rest.by_ref().take(operands).last().cloned();
            ops.push((token.clone(), target.expect("mount op operand")));
        }
        ops
    }

    #[cfg(unix)]
    #[test]
    fn app_delivery_lands_on_a_jail_private_tmpfs_never_the_host_scratch_bind() {
        use std::os::fd::{AsFd as _, AsRawFd as _};
        let (filter, app) = (stand_in_fd(), stand_in_fd());
        let no_env = |_: &str| None;
        let mounts = work_mounts();
        let dest = delivered_app_path(&mounts);
        let argv: Vec<String> = run_jail_argv_with_delivery(
            &tools(),
            &SandboxProfile::maximally_isolated(),
            &mounts,
            Some(SealedFdNumber::for_test(filter.as_fd())),
            SealedFdNumber::for_test(app.as_fd()),
            &no_env,
            &[OsString::from("--port"), OsString::from("8080")],
        )
        .args()
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
        let joined = argv.join(" ");
        let dest_str = dest.to_string_lossy().into_owned();
        let dir = dest.parent().expect("delivery dir");
        assert!(
            dir.starts_with("/work/tmp-1") && dir != Path::new("/work/tmp-1"),
            "the delivery dir must be its own mount point beneath the scratch dir: {joined}"
        );
        let ops = mount_targets(&argv);
        let file_at = ops
            .iter()
            .position(|(op, target)| op == "--file" && *target == dest_str)
            .expect("delivery --file op");
        // The mount the copy lands on is the LAST op before it whose target
        // contains the destination: it must be a fresh tmpfs, never the
        // host-bound scratch dir (whose writes reach the host and outlive the run).
        let (landing_op, landing) = ops
            .get(..file_at)
            .expect("ops before the copy")
            .iter()
            .rev()
            .find(|(op, target)| op != "--remount-ro" && dest.starts_with(target))
            .expect("a mount covering the destination");
        assert_eq!(
            (landing_op.as_str(), Path::new(landing)),
            ("--tmpfs", dir),
            "the delivered app must land on a jail-private tmpfs: {joined}"
        );
        assert!(
            ops.iter()
                .any(|(op, target)| op == "--bind" && target == "/work/tmp-1"),
            "the scratch dir stays bound writable: {joined}"
        );
        // Owner-execute perms on the copy, then the tmpfs remounted read-only.
        assert!(
            joined.contains(&format!(
                "--perms 0700 --file {} {dest_str} --remount-ro {}",
                app.as_raw_fd(),
                dir.display()
            )),
            "delivery sequence missing: {joined}"
        );
        // The payload execs the delivered in-jail path with the app args.
        assert!(
            joined.ends_with(&format!("-- {dest_str} --port 8080")),
            "payload must exec the delivered path: {joined}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn no_delivery_emits_no_file_op() {
        use std::os::fd::AsFd as _;
        // The default `run_jail_argv` (no delivery) must not emit `--file`.
        let filter = stand_in_fd();
        let joined = rendered(
            &SandboxProfile::maximally_isolated(),
            Some(SealedFdNumber::for_test(filter.as_fd())),
        )
        .join(" ");
        assert!(!joined.contains("--file"), "unexpected --file: {joined}");
        assert!(!joined.contains("--perms"), "unexpected --perms: {joined}");
    }

    #[test]
    fn network_granted_shares_the_net_namespace() {
        let p = SandboxProfile {
            network: true,
            ..SandboxProfile::maximally_isolated()
        };
        let argv = rendered(&p, None);
        assert!(
            !argv.contains(&"--unshare-net".to_owned()),
            "network granted must NOT unshare net: {}",
            argv.join(" ")
        );
        // IPC is still unshared unconditionally.
        assert!(argv.contains(&"--unshare-ipc".to_owned()));
    }

    #[test]
    fn filesystem_granted_binds_the_working_tree_read_write() {
        let p = SandboxProfile {
            filesystem: FilesystemScope::WorkingTreeReadWrite,
            ..SandboxProfile::maximally_isolated()
        };
        let joined = rendered(&p, None).join(" ");
        assert!(
            joined.contains("--bind /work/tree /work/tree"),
            "working tree not bound rw: {joined}"
        );
        assert!(joined.contains("--chdir /work/tree"), "{joined}");
    }

    #[test]
    fn run_jail_mounts_are_the_shared_jail_plan() {
        // The run jail renders exactly the bind set `jail_binds` derives from
        // its `JailMounts`, through the one mount plan, for every filesystem
        // scope: a bind added to or dropped from one jail alone breaks this.
        let base_dir = crate::test_dir::TestDir::new("run-jail-plan").expect("test dir");
        let user_home = base_dir.path().join("user");
        let tree = user_home.join("project");
        let bin = user_home.join("tools").join("bin");
        for dir in [&tree, &bin] {
            std::fs::create_dir_all(dir).expect("fixture dir");
        }
        let canonical = |path: &Path| CanonicalPath::resolve(path).expect("fixture path");
        let no_env = |_: &str| None;
        for (filesystem, working) in [
            (
                FilesystemScope::Isolated,
                crate::mounts::WorkingTree::Unbound,
            ),
            (
                FilesystemScope::WorkingTreeReadWrite,
                crate::mounts::WorkingTree::ReadWrite,
            ),
        ] {
            assert_eq!(crate::mounts::WorkingTree::granted_by(&filesystem), working);
            let profile = SandboxProfile {
                filesystem,
                ..SandboxProfile::maximally_isolated()
            };
            let mounts = mounts_of(
                CanonicalPath::assumed("/work/tmp-1"),
                canonical(&tree),
                vec![canonical(&bin)],
                HomeMasks::resolve(Ok(&crate::home::test_home(&user_home)), None).expect("homes"),
            );
            let argv: Vec<OsString> = run_jail_argv(
                &tools(),
                &profile,
                &mounts,
                None,
                &no_env,
                &[OsString::from("app")],
            )
            .args()
            .to_vec();
            let mut expected: Vec<OsString> =
                ["--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev"]
                    .into_iter()
                    .map(OsString::from)
                    .collect();
            crate::mounts::push_mounts(
                &mut expected,
                mounts.homes(),
                &crate::mounts::jail_binds(&mounts, working),
            );
            expected.push("--chdir".into());
            expected.push(
                match working {
                    crate::mounts::WorkingTree::ReadWrite => mounts.working_tree(),
                    crate::mounts::WorkingTree::Unbound => mounts.scoped_tmp(),
                }
                .as_path()
                .into(),
            );
            let start = argv
                .windows(3)
                .position(|w| w == ["--ro-bind", "/", "/"])
                .expect("the read-only root is bound");
            assert_eq!(
                argv.get(start..start + expected.len()),
                Some(expected.as_slice()),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn env_allowlist_re_exports_only_named_present_vars() {
        let p = SandboxProfile {
            env_allowlist: vec!["DATABASE_URL".to_owned(), "ABSENT".to_owned()],
            ..SandboxProfile::maximally_isolated()
        };
        let host = |k: &str| {
            if k == "DATABASE_URL" {
                Some(OsString::from("postgres://x"))
            } else {
                None
            }
        };
        let argv = run_jail_argv(
            &tools(),
            &p,
            &work_mounts(),
            None,
            &host,
            &[OsString::from("app")],
        );
        let joined: Vec<String> = argv
            .args()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let s = joined.join(" ");
        assert!(s.contains("--setenv DATABASE_URL postgres://x"), "{s}");
        // An absent named var is simply not re-exported.
        assert!(!s.contains("ABSENT"), "{s}");
    }

    #[test]
    fn scan_capfloor_finds_the_embedded_marker() {
        let p = SandboxProfile {
            network: true,
            filesystem: FilesystemScope::WorkingTreeReadWrite,
            env_allowlist: vec!["A".to_owned(), "B".to_owned()],
            subprocess: false,
            limits: RunResourceLimits::default(),
        };
        // Simulate a binary: arbitrary bytes, the floor line in .rodata, more bytes.
        let mut buf: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef];
        buf.extend_from_slice(p.to_capfloor_line(FloorIntent::Release).as_bytes());
        buf.push(0); // NUL-terminated as in .rodata
        buf.extend_from_slice(&[0x11, 0x22]);
        let floor = scan_capfloor(&buf).expect("found").axes;
        assert!(floor.network);
        assert_eq!(floor.filesystem, FilesystemScope::WorkingTreeReadWrite);
        assert_eq!(floor.env_allowlist, vec!["A".to_owned(), "B".to_owned()]);
    }

    #[test]
    fn scan_capfloor_intersects_env_names_of_multiple_copies() {
        // A legitimate floor grants {A, B}; an appended forged copy grants {B, C}
        // (same count, swapped name). The strictest merged floor is the name-set
        // intersection {B}, so the forged copy cannot smuggle C into the ceiling.
        let legit = SandboxProfile {
            env_allowlist: vec!["A".to_owned(), "B".to_owned()],
            ..SandboxProfile::maximally_isolated()
        };
        let forged = SandboxProfile {
            env_allowlist: vec!["B".to_owned(), "C".to_owned()],
            ..SandboxProfile::maximally_isolated()
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(legit.to_capfloor_line(FloorIntent::Release).as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(forged.to_capfloor_line(FloorIntent::Release).as_bytes());
        buf.push(0);
        let floor = scan_capfloor(&buf).expect("found").axes;
        assert_eq!(floor.env_allowlist, vec!["B".to_owned()]);
        // A profile granting C is refused: C is not in the intersected floor.
        let wants_c = SandboxProfile {
            env_allowlist: vec!["C".to_owned()],
            ..SandboxProfile::maximally_isolated()
        };
        assert!(!wants_c.satisfies_capfloor(&floor));
    }

    #[test]
    fn scan_capfloor_takes_the_strictest_of_multiple_copies() {
        // A legitimate strict floor, plus a forged permissive one appended by an
        // attacker: the strictest (least-granting) must win so the forgery cannot
        // relax the ceiling.
        let strict = SandboxProfile::maximally_isolated();
        let forged = SandboxProfile {
            network: true,
            subprocess: true,
            filesystem: FilesystemScope::WorkingTreeReadWrite,
            ..SandboxProfile::maximally_isolated()
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(strict.to_capfloor_line(FloorIntent::Release).as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(forged.to_capfloor_line(FloorIntent::Release).as_bytes());
        buf.push(0);
        let floor = scan_capfloor(&buf).expect("found").axes;
        // The strict floor wins: no axis granted.
        assert!(!floor.network);
        assert!(!floor.subprocess);
        assert_eq!(floor.filesystem, FilesystemScope::Isolated);
    }

    #[test]
    fn scan_capfloor_absent_is_none() {
        assert_eq!(scan_capfloor(b"no floor here"), None);
    }

    #[test]
    fn profile_string_round_trips() {
        let p = SandboxProfile {
            network: true,
            filesystem: FilesystemScope::WorkingTreeReadWrite,
            env_allowlist: vec!["DATABASE_URL".to_owned(), "API_KEY".to_owned()],
            subprocess: true,
            limits: RunResourceLimits::default(),
        };
        let text = p.to_profile_string();
        let parsed = parse_profile(&text).expect("round-trips");
        assert_eq!(parsed, p);
    }

    #[test]
    fn parse_profile_rejects_unknown_keys_and_missing_fields() {
        // Unknown key → refuse.
        assert!(parse_profile("ipe-profile 1\nnetwork true\nbogus x\n").is_err());
        // Missing header → refuse.
        assert!(parse_profile("network true\n").is_err());
        // Missing required field → refuse.
        assert!(parse_profile("ipe-profile 1\nnetwork true\n").is_err());
        // Malformed boolean → refuse.
        assert!(
            parse_profile("ipe-profile 1\nnetwork yes\nfilesystem isolated\nsubprocess false\n")
                .is_err()
        );
    }

    #[test]
    fn capfloor_line_round_trips_axes_and_env_names() {
        let p = SandboxProfile {
            network: true,
            filesystem: FilesystemScope::WorkingTreeReadWrite,
            // Out of order on purpose: the line is sorted, so the round-trip is
            // canonical regardless of the source order.
            env_allowlist: vec!["B".to_owned(), "A".to_owned()],
            subprocess: false,
            limits: RunResourceLimits::default(),
        };
        let line = p.to_capfloor_line(FloorIntent::Release);
        assert_eq!(
            line,
            "ipe-capfloor 1 net=true fs=rw sub=false env=A,B intent=release"
        );
        let floor = parse_capfloor(&line).expect("round-trips").axes;
        assert!(floor.network);
        assert_eq!(floor.filesystem, FilesystemScope::WorkingTreeReadWrite);
        assert!(!floor.subprocess);
        // The names round-trip exactly (sorted), not merely their count.
        assert_eq!(floor.env_allowlist, vec!["A".to_owned(), "B".to_owned()]);
    }

    #[test]
    fn capfloor_line_empty_env_round_trips() {
        let p = SandboxProfile::maximally_isolated();
        let line = p.to_capfloor_line(FloorIntent::Release);
        assert_eq!(
            line,
            "ipe-capfloor 1 net=false fs=isolated sub=false env= intent=release"
        );
        let floor = parse_capfloor(&line).expect("round-trips").axes;
        assert!(floor.env_allowlist.is_empty());
    }

    #[test]
    fn satisfies_capfloor_refuses_a_widened_profile() {
        // floor = maximally isolated; a profile granting network must be refused.
        let floor = parse_capfloor(
            &SandboxProfile::maximally_isolated().to_capfloor_line(FloorIntent::Release),
        )
        .expect("floor")
        .axes;
        let widened = SandboxProfile {
            network: true,
            ..SandboxProfile::maximally_isolated()
        };
        assert!(!widened.satisfies_capfloor(&floor));
        assert!(SandboxProfile::maximally_isolated().satisfies_capfloor(&floor));
    }

    #[test]
    fn satisfies_capfloor_refuses_more_env_than_the_floor() {
        // floor grants 1 env var; a profile granting 2 exceeds it → refuse.
        let floor_profile = SandboxProfile {
            env_allowlist: vec!["A".to_owned()],
            ..SandboxProfile::maximally_isolated()
        };
        let floor = parse_capfloor(&floor_profile.to_capfloor_line(FloorIntent::Release))
            .expect("floor")
            .axes;
        let two_env = SandboxProfile {
            env_allowlist: vec!["A".to_owned(), "B".to_owned()],
            ..SandboxProfile::maximally_isolated()
        };
        assert!(!two_env.satisfies_capfloor(&floor));
        // A profile granting exactly the floor's named var is accepted.
        let same_env = SandboxProfile {
            env_allowlist: vec!["A".to_owned()],
            ..SandboxProfile::maximally_isolated()
        };
        assert!(same_env.satisfies_capfloor(&floor));
    }

    #[test]
    fn satisfies_capfloor_refuses_a_same_count_env_name_swap() {
        // The env-swap attack: the source proves it needs {PATH, HOME}, so the
        // floor records those two names. A doctored ipe.profile swaps in a
        // DIFFERENT pair of the SAME count ({AWS_SECRET_ACCESS_KEY,
        // SSH_AUTH_SOCK}). The count matches (2 == 2), so a count-only check would
        // pass; the name subset check must REFUSE, because neither swapped name is
        // in the floor.
        let floor_profile = SandboxProfile {
            env_allowlist: vec!["PATH".to_owned(), "HOME".to_owned()],
            ..SandboxProfile::maximally_isolated()
        };
        let floor = parse_capfloor(&floor_profile.to_capfloor_line(FloorIntent::Release))
            .expect("floor")
            .axes;
        let swapped = SandboxProfile {
            env_allowlist: vec![
                "AWS_SECRET_ACCESS_KEY".to_owned(),
                "SSH_AUTH_SOCK".to_owned(),
            ],
            ..SandboxProfile::maximally_isolated()
        };
        assert!(
            !swapped.satisfies_capfloor(&floor),
            "a same-count env name swap must be refused"
        );
        // A single swapped name (one legitimate, one smuggled) is also refused —
        // the smuggled one is not in the floor.
        let partial_swap = SandboxProfile {
            env_allowlist: vec!["PATH".to_owned(), "AWS_SECRET_ACCESS_KEY".to_owned()],
            ..SandboxProfile::maximally_isolated()
        };
        assert!(!partial_swap.satisfies_capfloor(&floor));
        // The legitimate subset (⊆ the floor's names) still passes.
        let legit = SandboxProfile {
            env_allowlist: vec!["HOME".to_owned()],
            ..SandboxProfile::maximally_isolated()
        };
        assert!(legit.satisfies_capfloor(&floor));
        // Granting exactly the floor's names passes.
        assert!(floor_profile.satisfies_capfloor(&floor));
    }

    #[test]
    fn parse_capfloor_refuses_a_malformed_env_name() {
        // A name with a stray comma (empty element) or a non-POSIX char cannot be
        // emitted by `to_capfloor_line`; if a tampered floor carries one, the
        // launcher must refuse rather than silently parse a smuggled separator.
        assert!(parse_capfloor("ipe-capfloor 1 net=false fs=isolated sub=false env=A,,B").is_err());
        assert!(parse_capfloor("ipe-capfloor 1 net=false fs=isolated sub=false env=,A").is_err());
        assert!(parse_capfloor("ipe-capfloor 1 net=false fs=isolated sub=false env=1BAD").is_err());
        assert!(parse_capfloor("ipe-capfloor 1 net=false fs=isolated sub=false env=A-B").is_err());
    }

    #[test]
    fn capfloor_intent_round_trips_and_absent_is_development() {
        let p = SandboxProfile::maximally_isolated();
        for intent in [FloorIntent::Release, FloorIntent::Development] {
            let floor = parse_capfloor(&p.to_capfloor_line(intent)).expect("round-trips");
            assert_eq!(floor.intent, intent);
        }
        // A floor naming no intent never counts as a release build's.
        let bare =
            parse_capfloor("ipe-capfloor 1 net=false fs=isolated sub=false env=").expect("parses");
        assert_eq!(bare.intent, FloorIntent::Development);
        // An unknown or repeated intent is a malformed floor.
        assert!(parse_capfloor("ipe-capfloor 1 env= intent=prod").is_err());
        assert!(parse_capfloor("ipe-capfloor 1 env= intent=release intent=release").is_err());
    }

    #[test]
    fn scan_capfloor_is_release_only_when_every_copy_is() {
        let p = SandboxProfile::maximally_isolated();
        let mut buf = Vec::new();
        buf.extend_from_slice(p.to_capfloor_line(FloorIntent::Development).as_bytes());
        buf.push(0);
        buf.extend_from_slice(p.to_capfloor_line(FloorIntent::Release).as_bytes());
        buf.push(0);
        let floor = scan_capfloor(&buf).expect("found");
        assert_eq!(
            floor.intent,
            FloorIntent::Development,
            "a release line beside a development floor must not make it a release build"
        );
    }

    #[test]
    fn verify_release_floor_refuses_a_development_build() {
        let p = SandboxProfile::maximally_isolated();
        let dev = p.to_capfloor_line(FloorIntent::Development).into_bytes();
        assert_eq!(
            verify_release_floor(&p, &dev),
            Err(FloorRefusal::NotRelease)
        );
        assert!(
            FloorRefusal::NotRelease
                .to_string()
                .contains("rebuild it with `ipe release build`"),
            "the refusal names the remedy"
        );
        let release = p.to_capfloor_line(FloorIntent::Release).into_bytes();
        assert_eq!(verify_release_floor(&p, &release), Ok(()));
        assert_eq!(
            verify_release_floor(&p, b"no floor"),
            Err(FloorRefusal::Unreadable)
        );
        let widened = SandboxProfile {
            network: true,
            ..SandboxProfile::maximally_isolated()
        };
        assert_eq!(
            verify_release_floor(&widened, &release),
            Err(FloorRefusal::ProfileWider)
        );
    }

    #[test]
    fn parse_capfloor_refuses_an_unreadable_floor() {
        assert!(parse_capfloor("garbage").is_err());
        assert!(parse_capfloor("ipe-capfloor 2 net=true").is_err());
        assert!(parse_capfloor("ipe-capfloor 1 fs=bogus").is_err());
    }

    #[test]
    fn platform_supports_jail_matches_the_compiled_in_jail_arm() {
        // The single-source guard: `platform_supports_jail()` returns exactly the
        // `on_jailed_target!` predicate (the value stamped onto `JAIL_COMPILED_IN`
        // by the same macro that selects the real `exec_in_run_jail` arm). This
        // spells that predicate independently and asserts equality, so a future
        // edit that flips one without the other fails this test.
        let compiled_in_here = cfg!(any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            target_os = "macos",
            target_os = "windows"
        ));
        assert_eq!(
            platform_supports_jail(),
            compiled_in_here,
            "platform_supports_jail() must equal the compiled-in run-jail predicate"
        );
    }

    #[test]
    fn database_membership_is_derived_from_net_and_fs() {
        // Guardian Nit-1: `database` is confined iff BOTH axes it can lower into
        // (network for a TCP driver, filesystem for a file driver) are confined —
        // never a standalone asserted bit. This asserts the compiled-in
        // `CONFINED_AXES` on THIS host agrees with the `database_confined`
        // derivation, so a partial target that dropped net or fs could not keep
        // an over-claimed `database`.
        let axes = platform_confined_axes();
        let net = axes.contains(&Capability::Network);
        let fs = axes.contains(&Capability::Filesystem);
        let db = axes.contains(&Capability::Database);
        assert_eq!(
            db,
            database_confined(net, fs),
            "database membership must equal database_confined(net, fs): net={net}, fs={fs}"
        );
    }

    #[test]
    fn database_confined_requires_both_net_and_fs() {
        // The derivation itself: only both-confined yields a confined database.
        assert!(database_confined(true, true));
        assert!(!database_confined(true, false));
        assert!(!database_confined(false, true));
        assert!(!database_confined(false, false));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_is_a_jailed_target_with_the_partial_arm_axes() {
        // Windows has a real (non-stub) run-jail arm, so it is a jailed target.
        assert!(platform_supports_jail());
        // The compiled-in Windows arm establishes the Job Object (subprocess), the
        // launcher scrub (env), and AppContainer + an ACL scratch (filesystem +
        // network), and fails closed when AppContainer/ACL is unavailable — so it
        // lists those axes plus the whole-process-contained native-ffi and the
        // net+fs-derived database.
        let axes = platform_confined_axes();
        for cap in [
            Capability::Subprocess,
            Capability::Env,
            Capability::Filesystem,
            Capability::Network,
            Capability::NativeFfi,
            Capability::Database,
        ] {
            assert!(axes.contains(&cap), "Windows must confine {cap:?}");
        }
    }

    #[test]
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn linux_x86_64_is_a_jail_holds_target() {
        // On the Linux/x86_64 build host the run jail is compiled in, so the FFI
        // admit predicate must see a jail-holds target.
        assert!(platform_supports_jail());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_is_a_jail_holds_target() {
        // On macOS the sandbox-exec SBPL run-jail arm is compiled in, so the FFI
        // admit predicate flips to jail-holds.
        assert!(platform_supports_jail());
    }

    #[test]
    fn a_wall_clock_profile_wraps_in_timeout() {
        let p = SandboxProfile {
            limits: RunResourceLimits {
                wall_secs: Some(30),
                ..RunResourceLimits::default()
            },
            ..SandboxProfile::maximally_isolated()
        };
        let joined = rendered(&p, None).join(" ");
        assert!(
            joined.starts_with("/usr/bin/timeout --kill-after=5s 30 /usr/bin/bwrap"),
            "{joined}"
        );
    }
}

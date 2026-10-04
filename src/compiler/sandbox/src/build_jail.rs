//! The *returning* build jail: run a command under the same confinement the
//! runtime jail uses, then decode its result into a typed [`JailOutcome`].
//!
//! The runtime jail ([`crate::run_jail::exec_in_run_jail`]) `exec`s the emitted
//! app and never returns — it is the launcher of a confined process. Tier-2
//! package admission needs the opposite shape: run an untrusted native build (or
//! a capability probe) inside a jail scoped to the package's *declared*
//! capability set, then observe the *outcome* and reconcile declared-vs-demanded.
//! This module is that returning entry.
//!
//! ## The confinement is not forked
//!
//! The jail is lowered from the SAME [`crate::run_jail::SandboxProfile`] the
//! runtime jail runs under. On Linux (`x86_64`/`aarch64`) it lowers via the SAME
//! [`crate::run_jail::run_jail_argv`] + [`crate::seccomp`] program the runtime
//! jail uses; on macOS it lowers the SAME profile to a Seatbelt SBPL profile
//! ([`checked_sbpl`]) enforced by `sandbox-exec`. Either way there is a
//! single source of the confining profile: what Tier-2 confines a build to and
//! what the shipped artifact is confined to at run time cannot drift.
//!
//! ## The denial signal is wrapper-owned
//!
//! Untrusted code inside the jail must not be able to forge a clean result. The
//! per-axis denial signal is the admission probe's own **exit-code contract**
//! (a fixed disjoint code range, [`AXIS_EXIT_NETWORK`] / [`AXIS_EXIT_FILESYSTEM`]),
//! not scraped from the payload's stdout. A [`JailOutcome::Clean`] is only ever
//! produced by *positive proof* of the probe's clean exit; every unrecognised
//! exit, signal, or ambiguous state decodes to a non-`Clean` outcome.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::JailMounts;
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
))]
use crate::run_jail::JailArgv;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use crate::run_jail::run_jail_argv;
use crate::run_jail::{RunJailDefect, RunJailTools, SandboxProfile};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use crate::seccomp;
// The SBPL text is a pure function of the profile, so its deny/allow surface is
// unit-testable on any host (compiled under `test` on Linux); the macOS jail
// that feeds it to `sandbox-exec` is `cfg(target_os = "macos")`. `FilesystemScope`
// names the profile's write scope the SBPL lowers.
#[cfg(any(target_os = "macos", test))]
use crate::run_jail::FilesystemScope;

// ── the per-axis denial exit-code contract ──────────────────────────────────
//
// These codes are the wrapper-owned signal the Tier-2 admission probe emits
// (`tests/fixtures/admission/untrusted-build.sh`, `PROBE_MODE=tier2`). They live
// in a disjoint range from the enforce/control codes (2–5) so a differential
// denial can never be confused with a broken-jail control failure. A single
// source of truth: the fixture and this decoder must agree, asserted by the
// crate's build-jail tests.

/// The probe exited cleanly: every action it attempted under the
/// declared-scoped jail succeeded — no withheld axis was demanded.
pub const AXIS_EXIT_CLEAN: i32 = 0;

/// The wrapper's untrusted child build failed for an ordinary (non-capability)
/// reason and no withheld axis was demanded — an ordinary build-fails-in-jail.
///
/// It is NOT a per-axis denial, so it decodes to [`JailOutcome::BuildFailed`]
/// (a reject), never [`JailOutcome::Clean`]. The load-bearing hinge: the wrapper
/// never exits `AXIS_EXIT_CLEAN` when the child build failed, or a broken build
/// would forge a clean certify.
pub const TIER2_EXIT_BUILD_FAILED: i32 = 6;

/// The probe's network action was denied by the jail — the native code demanded
/// the `network` axis the declared-scoped jail withheld.
pub const AXIS_EXIT_NETWORK: i32 = 10;

/// The probe's out-of-scratch filesystem write was denied by the jail — the
/// native code demanded the `filesystem` axis the declared-scoped jail withheld.
pub const AXIS_EXIT_FILESYSTEM: i32 = 11;

// ── the capability axis a denial names ───────────────────────────────────────

/// The confinement axis a per-axis denial names.
///
/// Only the axes the admission probe can actually exercise are representable — a
/// denial can name `network` or `filesystem`, never `clock` (which carries no OS
/// control) or `native-ffi` (an epistemic marker). Making the non-probeable axes
/// unrepresentable here means [`JailOutcome::Denied`] can only ever carry an axis
/// the probe genuinely observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityAxis {
    /// Outbound/inbound network — a socket the probe opened was denied.
    Network,
    /// An out-of-scratch filesystem write the probe attempted was denied.
    Filesystem,
}

impl CapabilityAxis {
    /// The stable lowercase axis name, matching the capability wire vocabulary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Filesystem => "filesystem",
        }
    }

    /// Decode a wrapper-owned per-axis exit code, or `None` when the code is not
    /// a recognised per-axis denial. `None` is the fail-closed hinge: the caller
    /// never treats an unrecognised code as clean.
    #[must_use]
    const fn from_exit_code(code: i32) -> Option<Self> {
        match code {
            AXIS_EXIT_NETWORK => Some(Self::Network),
            AXIS_EXIT_FILESYSTEM => Some(Self::Filesystem),
            _ => None,
        }
    }
}

// ── the typed outcome ────────────────────────────────────────────────────────

/// The outcome of a build/probe run inside the declared-scoped jail.
///
/// Make-invalid-states-unrepresentable: the illegal state — "admitted despite a
/// denial" — is not expressible. There is exactly one clean variant, produced
/// only by positive proof of the probe's clean exit; every other observable
/// result (a named denial, an ordinary build failure, an unestablished jail) is
/// a distinct non-clean variant. A caller that admits only on [`Self::Clean`]
/// cannot be fooled into admitting a jail that never ran or a payload that was
/// denied a capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JailOutcome {
    /// The jail was established and the probe exited cleanly: no withheld axis
    /// was demanded. The ONLY outcome an admit path may accept.
    Clean,
    /// The jail was established and the probe was denied a capability the
    /// declared-scoped jail withheld. `axis` names which — the used-but-undeclared
    /// signal.
    Denied {
        /// The confinement axis the denial named.
        axis: CapabilityAxis,
    },
    /// The jail was established and the payload exited non-zero for a reason that
    /// is NOT a recognised per-axis denial — an ordinary compile/link/test error,
    /// a signal, or an unrecognised exit code. Fail-closed: an ambiguous failure
    /// is never `Clean`.
    BuildFailed {
        /// A short, non-sensitive reason for the diagnostic (never the payload's
        /// own stdout — that is untrusted).
        reason: String,
    },
    /// No jail could be established (a missing primitive, an unsupported
    /// platform, an unbuildable profile, a spawn failure). The untrusted build
    /// was NOT run unconfined — the outcome is a refusal, never a clean pass.
    Unavailable {
        /// The refusal that prevented the jail from being established.
        defect: RunJailDefect,
    },
}

impl JailOutcome {
    /// Whether this outcome is the single admit-eligible one. The admit predicate
    /// lives here so it is total over the outcome and inspectable by tests.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        matches!(self, Self::Clean)
    }

    /// Decode a completed jailed run into a typed outcome, fail-closed.
    ///
    /// `exit` is the payload's exit code, `None` when it was killed by a signal
    /// or the wall clock. The decode is the security-load-bearing §2.4 mechanic:
    ///
    /// - a clean exit (`0`) ⇒ [`Self::Clean`] — the only positive-proof branch;
    /// - a recognised per-axis code ⇒ [`Self::Denied`] naming the axis;
    /// - a signal / no exit code ⇒ [`Self::BuildFailed`] (never clean);
    /// - any other non-zero exit ⇒ [`Self::BuildFailed`] (an ordinary build
    ///   error, or an unrecognised code — both non-clean, both reject).
    #[must_use]
    pub fn decode(exit: Option<i32>) -> Self {
        let Some(code) = exit else {
            return Self::BuildFailed {
                reason: "the jailed probe was killed by a signal or the wall clock \
                         (no exit code) — treated as a build failure, never clean"
                    .to_owned(),
            };
        };
        if code == AXIS_EXIT_CLEAN {
            return Self::Clean;
        }
        if let Some(axis) = CapabilityAxis::from_exit_code(code) {
            return Self::Denied { axis };
        }
        Self::BuildFailed {
            reason: format!(
                "the jailed probe exited {code}, which is neither a clean exit nor a \
                 recognised per-axis denial — treated as a build failure, never clean"
            ),
        }
    }
}

// ── the safe-mount-path invariant, made unrepresentable-if-violated ──────────

/// An absolute, lexically-normalised mount path — no `..` (`ParentDir`)
/// components.
///
/// Parse-don't-validate: the only constructor ([`Self::new`]) is the single
/// gate. A value of this type is proof that the wrapped path is:
/// - absolute (starts with `/`), AND
/// - free of `..` (`ParentDir`) components.
///
/// These conditions together make `root.join(strip_leading_slash(inner))`
/// provably nest INSIDE `root` — a `..` after the root is the escape vector,
/// and this type makes that vector unrepresentable. The FreeBSD jail re-mounts
/// paths at `<root>/<path-stripped-of-leading-/>` (see `under_root`); a path
/// carrying `..` would mount OUTSIDE the jail root, which this type forecloses
/// by construction.
///
/// Note: Rust's `Path::components()` elides `.` (`CurDir`) segments from
/// absolute paths, so `/./tmp` is treated identically to `/tmp` at the
/// component level and is accepted. The load-bearing rejection gate is `..`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(any(target_os = "freebsd", test)), allow(dead_code))]
pub(crate) struct SafeMountPath(PathBuf);

impl SafeMountPath {
    /// Construct from a path, rejecting any path that is not absolute or that
    /// contains a `..` or `.` component. The sole way to build a
    /// [`SafeMountPath`]: a returned value is proof of both invariants, so
    /// callers do not re-check.
    ///
    /// # Errors
    ///
    /// [`RunJailDefect::MountFailed`] naming the offending path when it is not
    /// absolute, or when any component is `..` or `.`.
    #[cfg_attr(not(any(target_os = "freebsd", test)), allow(dead_code))]
    pub(crate) fn new(path: &Path) -> Result<Self, RunJailDefect> {
        use std::path::Component;
        if !path.is_absolute() {
            return Err(RunJailDefect::MountFailed {
                target: path.to_path_buf(),
                detail: format!(
                    "mount path {} is not absolute; cannot root the jail at a fixed location",
                    path.display()
                ),
            });
        }
        for component in path.components() {
            match component {
                Component::ParentDir => {
                    return Err(RunJailDefect::MountFailed {
                        target: path.to_path_buf(),
                        detail: format!(
                            "mount path {} contains a `..` component; \
                             a `..` after the root escapes the jail chroot",
                            path.display()
                        ),
                    });
                }
                Component::CurDir => {
                    return Err(RunJailDefect::MountFailed {
                        target: path.to_path_buf(),
                        detail: format!(
                            "mount path {} contains a `.` component; \
                             only a fully-normalised path is a safe mount source",
                            path.display()
                        ),
                    });
                }
                Component::RootDir | Component::Normal(_) | Component::Prefix(_) => {}
            }
        }
        Ok(Self(path.to_path_buf()))
    }

    /// Borrow the wrapped path.
    #[cfg_attr(not(any(target_os = "freebsd", test)), allow(dead_code))]
    pub(crate) fn as_path(&self) -> &Path {
        &self.0
    }
}

// ── the returning build-jail entry ───────────────────────────────────────────

/// Confirm every jail path still resolves to itself and exposes no cargo home.
///
/// The caller resolved each path once and handed the same values to the
/// payload; a path swapped for a symlink since then is refused rather than
/// bound at a spelling the payload was not told about.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "windows",
    target_os = "freebsd"
))]
fn recheck_mounts(mounts: &JailMounts) -> Result<(), JailOutcome> {
    mounts.recheck().map_err(|e| JailOutcome::Unavailable {
        defect: RunJailDefect::Path(e),
    })
}

/// Run `payload` inside a jail lowered from `profile`, wait for it, and return
/// the decoded [`JailOutcome`].
///
/// This is the returning counterpart to [`crate::run_jail::exec_in_run_jail`]:
/// it spawns the confined process and waits, rather than replacing the current
/// process. The confinement is identical — the same seccomp program for the
/// profile's subprocess axis, the same [`run_jail_argv`] flag vocabulary — so a
/// build observed under Tier-2 is confined exactly as the shipped artifact will
/// be at run time.
///
/// A jail that cannot be established (unsupported platform, a seccomp program
/// that cannot be compiled for this architecture, a jail path that moved or
/// would expose the cargo home, a spawn failure) yields
/// [`JailOutcome::Unavailable`] — the untrusted payload is never run unconfined
/// on any path.
///
/// # Errors
///
/// This function does not return `Err`: every failure to establish or run the
/// jail is folded into a non-`Clean` [`JailOutcome`], so a caller reconciling
/// declared-vs-demanded has a total value to match on and cannot mistake an
/// establishment failure for a clean run.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[must_use]
pub fn build_in_jail(
    tools: &RunJailTools,
    profile: &SandboxProfile,
    mounts: &JailMounts,
    payload: &[OsString],
) -> JailOutcome {
    if let Err(outcome) = recheck_mounts(mounts) {
        return outcome;
    }
    let Some(program) = seccomp::subprocess_deny_program(profile.subprocess) else {
        return JailOutcome::Unavailable {
            defect: RunJailDefect::UnsupportedPlatform {
                reason: "no seccomp filter can be compiled for this architecture",
            },
        };
    };
    let bytes = seccomp::program_bytes(&program);
    // The memfd is owned so it is closed when this function returns. bwrap reads the
    // seccomp filter by fd number during jail setup — before the child runs — so
    // closing it after the child is waited on is safe. Unlike the run jail
    // (which `exec`s and never returns), this build jail RETURNS and is called
    // once per axis in the audit tightening loop; a raw fd would leak one memfd
    // per call in the long-lived audit/CI process. It is sealed and born
    // close-on-exec; clearing the flag only now, right before the spawn, lets
    // bwrap inherit it. A failure refuses rather than run the build unfiltered.
    let seccomp_owned = match crate::run_jail::write_seccomp_memfd(&bytes) {
        Ok(fd) => fd,
        Err(defect) => return JailOutcome::Unavailable { defect },
    };
    // Known limit: between this close-on-exec clear and the spawn, a sibling child
    // forked by another thread inherits the same open file description. The seal
    // blocks writes, not a shared-offset `lseek`/`read`, so this fd must reach only
    // its one child.
    let seccomp_fd = match seccomp_owned.make_inheritable() {
        Ok(fd) => fd,
        Err(e) => {
            return JailOutcome::Unavailable {
                defect: RunJailDefect::Spawn {
                    detail: format!("clearing close-on-exec on the seccomp memfd failed: {e}"),
                },
            };
        }
    };

    let host_env = crate::host_env::granted;
    let argv = run_jail_argv(tools, profile, mounts, Some(seccomp_fd), &host_env, payload);

    // The Linux jail's env is scrubbed inside the bwrap argv (`--clearenv` +
    // allowlisted re-export), so no launcher-side env override is needed here.
    // `argv` borrows `seccomp_owned`, so the memfd stays open until the child is
    // waited on inside `spawn_and_decode` and closes when this function returns.
    spawn_and_decode(&argv, None)
}

/// Run `payload` inside a `sandbox-exec` Seatbelt jail lowered from `profile`,
/// wait for it, and return the decoded [`JailOutcome`] (macOS).
///
/// The macOS counterpart to the `Linux` [`build_in_jail`]: it lowers the
/// SAME [`SandboxProfile`] to a Seatbelt SBPL profile ([`checked_sbpl`])
/// and spawns `sandbox-exec -p <profile> <payload>`, so a build observed under
/// Tier-2 is confined exactly as the shipped artifact will be at run time
/// (single source of the confining profile). The profile travels in argv, never
/// through a file the payload could rewrite.
///
/// The mounts' scratch is the one always-writable directory; the working tree
/// is writable only when the profile grants the filesystem axis. The read-only
/// binds are unused on macOS (Seatbelt filters an existing view of the real
/// filesystem rather than constructing a bind mount namespace).
///
/// A jail that cannot be established (no `sandbox-exec`, a jail path that moved
/// or would expose the cargo home, a spawn failure) yields
/// [`JailOutcome::Unavailable`] — the
/// untrusted payload is never run unconfined on any path. Fail-closed.
///
/// The macOS jail's actual deny behaviour is verified by the `macos-latest` CI
/// job (`audit_native` E2E + the admission enforce-vs-control duality), not by a
/// local run: this crate builds and unit-tests the pure SBPL lowering on any
/// host, but only a real macOS runner exercises `sandbox-exec`.
///
/// # Errors
///
/// This function does not return `Err`: every failure to establish or run the
/// jail is folded into a non-`Clean` [`JailOutcome`].
#[cfg(target_os = "macos")]
#[must_use]
pub fn build_in_jail(
    _tools: &RunJailTools,
    profile: &SandboxProfile,
    mounts: &JailMounts,
    payload: &[OsString],
) -> JailOutcome {
    if let Err(outcome) = recheck_mounts(mounts) {
        return outcome;
    }
    let scoped_tmp = mounts.scoped_tmp().as_path();
    // `sandbox-exec` is the mandatory macOS jail primitive. Absent ⇒ refuse; the
    // untrusted payload is never run unconfined.
    let Some(sandbox_exec) = find_in_path("sandbox-exec") else {
        return JailOutcome::Unavailable {
            defect: RunJailDefect::PrimitiveUnavailable {
                missing: vec!["sandbox-exec"],
            },
        };
    };

    // argv: sandbox-exec -p <profile> <payload…>. The profile is an argument,
    // so the payload has no file to rewrite before a later run applies it. No
    // shell token anywhere — the payload is a direct argv, so the
    // quoting/injection class does not exist.
    let sbpl = match checked_sbpl(profile, mounts) {
        Ok(sbpl) => sbpl,
        Err(e) => {
            return JailOutcome::Unavailable {
                defect: RunJailDefect::Path(e),
            };
        }
    };
    let mut argv: Vec<OsString> = Vec::with_capacity(payload.len() + 3);
    argv.push(sandbox_exec.into_os_string());
    argv.push("-p".into());
    argv.push(sbpl.into());
    argv.extend(payload.iter().cloned());
    let argv = JailArgv::fd_free(argv);

    // Enforce the `env` axis in the launcher (Seatbelt cannot scrub env),
    // mirroring the run jail and the Linux build jail's bwrap `--clearenv`, so a
    // Tier-2 build is confined on the env axis exactly as the shipped app is.
    let host_env = crate::host_env::granted;
    let scrubbed_env = macos_scrubbed_env(profile, scoped_tmp, &host_env);

    spawn_and_decode(&argv, Some(&scrubbed_env))
}

/// Run `payload` inside a Windows Job Object + AppContainer jail lowered from
/// `profile`, wait for it, and return the decoded [`JailOutcome`] (Windows).
///
/// The Windows counterpart to the `Linux` and macOS [`build_in_jail`]: it
/// lowers the SAME [`SandboxProfile`] through the SAME Win32 sequence the run jail
/// uses ([`crate::run_jail::build_windows_jailed`] → `windows_jail::run_confined`)
/// — a Job Object (subprocess axis, kill-on-close so no orphan survives the audit
/// call), an AppContainer lowbox token (filesystem + network axes: the
/// `internetClient` capability SID is added iff `profile.network`, and the scratch
/// — plus the working tree when the filesystem axis is granted — is ACLed to the
/// container SID), and a launcher-side environment scrub (env axis). So a build
/// observed under Tier-2 is confined exactly as the shipped artifact is at run
/// time (one jail source, no fork).
///
/// The `FILE_PERSISTENT_ACLS` volume probe gates the launch BEFORE spawn: on a
/// volume that does not persist+enforce DACLs the ACL boundary is a no-op, so the
/// jail refuses ([`JailOutcome::Unavailable`]) rather than run the untrusted build
/// with a silently-unconfined filesystem axis (the probe lives inside
/// `windows_jail::run_confined`, ahead of `CreateProcessW`).
///
/// The mounts' read-only binds are unused on Windows (AppContainer filters an
/// existing view of the real filesystem rather than constructing a bind-mount
/// namespace); the scratch and working tree are rechecked before the launch.
///
/// A jail that cannot be established (a Job Object / token / capability SID / ACL
/// / attribute list / `CreateProcessW` that cannot be built, or a non-ACL scratch
/// volume) yields [`JailOutcome::Unavailable`] — the untrusted payload is never
/// run unconfined on any path. Fail-closed. Every kernel object is RAII-released
/// on every path, so the audit's per-axis tightening loop leaks nothing.
///
/// The jail's actual deny behaviour is proven by the `windows-tier2` CI job on a
/// real `windows-2022` runner (a hosted runner — a Job Object / AppContainer is a
/// plain Win32 sequence, no Docker Windows daemon needed); this crate builds the
/// arm and unit-tests the pure pieces on any host.
///
/// # Errors
///
/// This function does not return `Err`: every failure to establish or run the
/// jail is folded into a non-`Clean` [`JailOutcome`].
#[cfg(target_os = "windows")]
#[must_use]
#[allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
pub fn build_in_jail(
    _tools: &RunJailTools,
    profile: &SandboxProfile,
    mounts: &JailMounts,
    payload: &[OsString],
) -> JailOutcome {
    if let Err(outcome) = recheck_mounts(mounts) {
        return outcome;
    }
    // The Windows jail RETURNS the child's exit code (Windows has no `exec`-
    // replace), which decodes through the SAME `JailOutcome::decode` the Linux
    // and macOS arms use: `0` is the sole `Clean` branch; a per-axis code names
    // the axis; any ambiguous exit is `BuildFailed`. A jail that could not be
    // established (a missing primitive, a non-ACL scratch volume gated by the
    // pre-spawn `FILE_PERSISTENT_ACLS` probe, a failed `CreateProcessW`) is a
    // `RunJailDefect` → `Unavailable`; the untrusted build never runs unconfined.
    match crate::run_jail::build_windows_jailed(
        profile,
        mounts.scoped_tmp().as_path(),
        mounts.working_tree().as_path(),
        payload,
    ) {
        Ok(code) => JailOutcome::decode(Some(win_exit_to_i32(code))),
        Err(defect) => JailOutcome::Unavailable { defect },
    }
}

/// Map a Windows process exit code (`u32` from `GetExitCodeProcess`) to the
/// signed exit the wrapper-owned per-axis contract is decoded against.
///
/// The Tier-2 probe's exit codes (`0`, `6`, `10`, `11`) are small non-negative
/// values that round-trip identically; a value above `i32::MAX` (a process that
/// exited with a high-bit code) cannot be a recognised per-axis code, so it
/// saturates to a value that [`JailOutcome::decode`] treats as `BuildFailed`
/// (fail-closed — never `Clean`, never a spurious named denial).
#[cfg(any(target_os = "windows", test))]
const fn win_exit_to_i32(code: u32) -> i32 {
    // A reinterpreting cast would fold `0x8000_0000..` into negative codes that
    // could alias a legitimate signed value; instead clamp anything past
    // `i32::MAX` to `i32::MAX`, which decodes to `BuildFailed`.
    #[allow(clippy::cast_possible_wrap)]
    if code <= i32::MAX as u32 {
        code as i32
    } else {
        i32::MAX
    }
}

/// Run `payload` inside a FreeBSD `jail(8)` lowered from `profile`, wait for it,
/// and return the decoded [`JailOutcome`] (FreeBSD).
///
/// The FreeBSD counterpart to the other [`build_in_jail`] arms. FreeBSD has no
/// run-jail arm today, so this introduces the returning build-jail lowering
/// directly onto a scratch-rooted `jail(2)` (established via the `jail(8)` CLI —
/// the same external-primitive shape the macOS arm uses with `sandbox-exec`, so
/// no new `unsafe` FFI is introduced). Per ADR 0004 the `jail(2)` posture is a
/// sanctioned alternative to `cap_enter` for lowering the axes:
///
/// - **network** — withheld ⇒ `vnet=new`: the jail gets a brand-new, EMPTY network
///   stack (only a down `lo0`, no configured interface, no route), so an outbound
///   socket has no reachable destination and is denied at the kernel → the probe's
///   exit-`10` decodes to `Denied { network }`. A non-vnet `ip4=disable` jail shares
///   the host's network stack and can still open outbound sockets, so a fresh empty
///   vnet — not mere address disabling — is what actually withholds the axis.
///   Granted ⇒ `vnet=inherit` shares the host stack so a granted effect is not
///   false-denied.
/// - **filesystem** — the jail is chrooted (`path=`) to a fresh root over which the
///   whole host `/` is nullfs-mounted READ-ONLY, with ONLY the scratch (and, when
///   the axis is granted, the working tree) nullfs-mounted READ-WRITE at their
///   original absolute paths inside it — the FreeBSD counterpart of the Linux arm's
///   `--ro-bind / /` + one writable mount. An out-of-scratch write targets the
///   read-only mount and is denied by the mount flag (never reliant on host file
///   ownership) → exit-`11` decodes to `Denied { filesystem }`. The payload also
///   runs as an unprivileged user (`exec.jail_user`) as defence in depth.
///   Over that read-only root a FRESH minimal `devfs` masks the jail's `/dev` and
///   an EMPTY read-only nullfs masks its `/proc`, so the host device nodes and host
///   process metadata (e.g. `/proc/<pid>/environ`, a covert-channel/enumeration
///   surface) the ro-root would otherwise expose read-only are not visible —
///   matching the Linux arm's fresh `--dev`/`--proc`. These layer AFTER the
///   read-only root and BEFORE the jailed process starts, and are unmounted in
///   reverse order on teardown.
/// - **subprocess** — a withheld subprocess axis is a genuine kernel denial of
///   process creation, not mere omission: the jail is created with a process
///   limit (`children.max=0`) so `fork`/`pdfork`/`exec` of a NEW process inside
///   the jail is denied by the kernel. Its observable is the killed child's
///   `BuildFailed` (subprocess is confined-but-not-differentially-probed — only
///   `Network`/`Filesystem` are `Denied { axis }`-nameable), a reject either way.
/// - **env** — scrubbed in the launcher (a jail does not scrub the inherited
///   environment), via the SAME allowlist the macOS/Windows arms use.
///
/// Over the read-only root the jail applies the SAME mount plan the Linux arm
/// renders for bwrap ([`crate::mounts::mount_plan`]): every home and `/tmp` is
/// masked by a fresh root-owned tmpfs, and the read-only binds (the cargo tool
/// dirs), the scratch, and the granted working tree are re-exposed through the
/// masks by `mount_nullfs`. Every path is rechecked before the jail is built, and
/// a mask that cannot mount refuses the jail rather than run it over an unmasked
/// home.
///
/// A jail that cannot be established (`jail` absent, a scratch that cannot be
/// created/chowned, a `jail(8)` invocation that fails to enter the jail) yields
/// [`JailOutcome::Unavailable`] — the untrusted payload is never run unconfined on
/// any path. Fail-closed. The scratch is removed on return so nothing leaks across
/// the audit's per-axis tightening loop.
///
/// The jail's actual deny behaviour is proven by the `freebsd-tier2` CI job inside
/// a `vmactions/freebsd-vm` VM (no native FreeBSD GitHub runner exists); this
/// crate builds the arm and unit-tests the pure lowering on any host.
///
/// # Errors
///
/// This function does not return `Err`: every failure to establish or run the
/// jail is folded into a non-`Clean` [`JailOutcome`].
#[cfg(target_os = "freebsd")]
#[must_use]
#[allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
pub fn build_in_jail(
    _tools: &RunJailTools,
    profile: &SandboxProfile,
    mounts: &JailMounts,
    payload: &[OsString],
) -> JailOutcome {
    if let Err(outcome) = recheck_mounts(mounts) {
        return outcome;
    }
    freebsd_jail::build_in_jail(profile, mounts, payload)
}

/// Off Linux (x86_64/aarch64), macOS, Windows, and FreeBSD the returning build jail is a
/// documented refuse-gap, mirroring [`crate::run_jail::exec_in_run_jail`].
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "windows",
    target_os = "freebsd"
)))]
#[must_use]
// Kept a plain `fn` (not `const fn`) so its signature matches the real
// `build_in_jail` arms, which cannot be `const` (they spawn a process).
#[allow(clippy::missing_const_for_fn)]
pub fn build_in_jail(
    _tools: &RunJailTools,
    _profile: &SandboxProfile,
    _mounts: &JailMounts,
    _payload: &[OsString],
) -> JailOutcome {
    JailOutcome::Unavailable {
        defect: RunJailDefect::UnsupportedPlatform {
            reason: "build jail is wired only on Linux (x86_64/aarch64), macOS, Windows, and FreeBSD",
        },
    }
}

/// Spawn the jail argv, wait, and decode the exit into a [`JailOutcome`].
///
/// A spawn failure is [`JailOutcome::Unavailable`] (the payload never ran); a
/// wait failure is a [`JailOutcome::BuildFailed`] (the jail ran but its result
/// is unobservable — never clean).
///
/// `env_override`, when `Some`, clears the inherited environment and sets exactly
/// the given `(name, value)` pairs — the macOS jails' `env`-axis enforcement (the
/// Linux jail scrubs env inside bwrap, so it passes `None`).
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
))]
fn spawn_and_decode(
    argv: &JailArgv<'_>,
    env_override: Option<&[(OsString, OsString)]>,
) -> JailOutcome {
    let Some((program, rest)) = argv.args().split_first() else {
        return JailOutcome::Unavailable {
            defect: RunJailDefect::Spawn {
                detail: "empty jail argv".to_owned(),
            },
        };
    };
    let mut command = std::process::Command::new(program);
    command.args(rest).stdin(std::process::Stdio::null());
    if let Some(pairs) = env_override {
        command.env_clear();
        for (name, value) in pairs {
            command.env(name, value);
        }
    }
    let child = command.spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            return JailOutcome::Unavailable {
                defect: RunJailDefect::Spawn {
                    detail: e.to_string(),
                },
            };
        }
    };
    match child.wait() {
        Ok(status) => JailOutcome::decode(status.code()),
        Err(e) => JailOutcome::BuildFailed {
            reason: format!("could not await the jailed probe: {e}"),
        },
    }
}

// ── the macOS SBPL lowering ──────────────────────────────────────────────────

/// Lower a [`SandboxProfile`] to a Seatbelt SBPL profile text for `sandbox-exec`.
///
/// PURE TEXT — no process is spawned — so the exact deny/allow surface is
/// unit-testable on any host, exactly like the Linux [`run_jail_argv`]. The
/// macOS jail's *runtime* deny behaviour is the `macos-latest` CI job; this
/// function is what that jail enforces, proven correct here.
///
/// The profile is a `(allow default)` base with *targeted denials*, mirroring
/// `tools/scripts/admission/jail-macos.sh`: on recent macOS a `(deny default)` base
/// blocks so many benign system operations that even explicit `(allow …)`
/// overrides leave the shell and its tools unable to run, so the working base is
/// allow-default plus the two threat denials Tier-2 differentially confines:
///
/// - **network**: withheld (`!profile.network`) ⇒ `(deny network*)` and the
///   low-level socket operations, so a probe socket is denied and the
///   `network` axis is observable. Granted ⇒ no network denial.
/// - **filesystem writes**: the scratch (`scoped_tmp`) is always writable; the
///   working tree is writable ONLY when the profile grants the filesystem axis. A
///   blanket `(deny file-write*)` withholds every other path, so an
///   out-of-scratch write under a filesystem-withholding profile is denied and
///   the `filesystem` axis is observable.
/// - **filesystem reads**: denied by default (`(deny file-read*)`), then
///   re-allowed only for the fixed system/toolchain roots the shell and compiler
///   need, the scratch, and the working tree (the source being built). The
///   invoking user's home is NOT in the allow set, so a network-granted build
///   cannot read `~/.ssh` (or any home secret) to exfiltrate it — the macOS
///   analogue of the Linux jail's `--tmpfs /home` read mask. Without this the
///   allow-default base would leave the whole home directory readable.
/// - **subprocess**: withheld (`!profile.subprocess`) ⇒ `(deny process-fork)`,
///   the NEW-process denial. Every way to create a new process
///   (`fork`/`vfork`/`posix_spawn`) forks under Seatbelt, so a fork denial
///   confines the app to a single process — mirroring the Linux jail's seccomp
///   denial of the task-creation family, and closing the `native-ffi`-via-a-
///   helper escape (a helper is a new process, so it must fork). `process-exec*`
///   is deliberately NOT denied: Seatbelt applies the profile before
///   `sandbox-exec` execs the target in place, so an exec denial would refuse
///   that mandatory initial exec and the app would never start. An in-place
///   `execve` (no fork) replaces the one jailed process rather than creating a
///   second, so it is within the single-process contract. Granted ⇒ no process
///   denial, so the allow-default base leaves spawning reachable.
///
/// The scratch and (when granted) the working tree are written as `(subpath …)`
/// allow rules so the probe's benign write and a granted filesystem effect
/// succeed. The scratch is the ONLY unconditional write allow: the launcher
/// writes only into it and points `TMPDIR` at it, so no broader system-temp
/// tree is allowed. Allowing the per-user temp tree would re-permit every
/// sibling of the scratch (the scratch itself lives under it), so an
/// out-of-scratch write next to the scratch would leak — the fail-closed jail
/// allows only the resolved scratch subpath.
///
/// The `env` axis is NOT enforced here: Seatbelt cannot scrub environment
/// variables, so the run/build launcher clears the environment down to the
/// profile's `env_allowlist` (mirroring the Linux jail's `--clearenv`) BEFORE
/// handing control to `sandbox-exec`. See [`macos_scrubbed_env`].
/// The fixed hardware/kernel sysctls the C library reads during process
/// bring-up (thread-pool sizing, allocator page geometry, OS-version probes).
/// Re-allowed by EXACT name after the blanket `sysctl-read` deny so a
/// dynamically-linked child can start, while bulk sysctl enumeration — the
/// fingerprinting surface — stays denied. Each is a read-only scalar; none
/// exposes a per-process secret or a mutable/authority operation.
#[cfg(any(target_os = "macos", test))]
const BRING_UP_SYSCTL_NAMES: &[&str] = &[
    "hw.ncpu",
    "hw.activecpu",
    "hw.physicalcpu",
    "hw.logicalcpu",
    "hw.memsize",
    "hw.pagesize",
    "hw.cachelinesize",
    "hw.cpufamily",
    "hw.busfrequency",
    "hw.cpufrequency",
    "kern.osversion",
    "kern.osproductversion",
    "kern.osrelease",
    "kern.ostype",
    "kern.version",
    "kern.hv_vmm_present",
    "kern.secure_kernel",
    "machdep.cpu.brand_string",
];

/// The fixed bootstrap Mach services a dynamically-linked process must reach to
/// load and initialise: the dyld/XPC bootstrap surface, the libinfo/
/// opendirectory lookups a shell's user/group resolution performs, and the
/// unified-log/diagnostics endpoints libSystem opens at init. Re-allowed by
/// EXACT `global-name` after the blanket `mach-lookup` deny (last-match-wins),
/// so each named service overrides the deny for that one service while every
/// other Mach service — the cross-process IPC and escape surface — stays
/// denied. None of these grants network, arbitrary file, task-for-pid, or
/// dynamic-code capability.
#[cfg(any(target_os = "macos", test))]
const BRING_UP_MACH_SERVICES: &[&str] = &[
    "com.apple.system.notification_center",
    "com.apple.system.logger",
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.opendirectoryd.membership",
    "com.apple.system.DirectoryService.libinfo_v1",
    "com.apple.system.DirectoryService.membership_v1",
    "com.apple.logd",
    "com.apple.diagnosticd",
    "com.apple.xpc.activity.unmanaged",
    "com.apple.CoreServices.coreservicesd",
    "com.apple.coreservices.launchservicesd",
    "com.apple.SecurityServer",
    "com.apple.SystemConfiguration.configd",
    "com.apple.trustd.agent",
    "com.apple.trustd",
];

/// The fixed system/toolchain trees the Seatbelt profile allows reading.
///
/// The profile masks nothing beneath them, so [`checked_sbpl`] refuses a cargo home
/// at or under any of them before a profile is rendered.
#[cfg(any(target_os = "macos", test))]
pub const MACOS_READ_ROOTS: [&str; 11] = [
    "/usr",
    "/bin",
    "/sbin",
    "/System",
    "/Library",
    "/Applications",
    "/opt",
    "/dev",
    "/private/etc",
    "/private/var/db",
    "/private/var/folders",
];

/// Render the Seatbelt profile for `mounts`, refusing first when a fixed read
/// root would expose the cargo home.
///
/// # Errors
/// [`crate::JailPathError::ExposesCargoHome`] when a [`MACOS_READ_ROOTS`] entry
/// equals or contains the cargo home.
#[cfg(any(target_os = "macos", test))]
pub fn checked_sbpl(
    profile: &SandboxProfile,
    mounts: &JailMounts,
) -> Result<String, crate::JailPathError> {
    mounts.refuse_fixed_exposing(&MACOS_READ_ROOTS)?;
    let carve: Vec<&Path> = mounts
        .writable_tree()
        .carve()
        .paths()
        .map(crate::CanonicalPath::as_path)
        .collect();
    Ok(sbpl_from_profile(
        profile,
        mounts.scoped_tmp().as_path(),
        mounts.working_tree().as_path(),
        &carve,
    ))
}

/// The Seatbelt regex matching a path with a [`crate::VcsKind::ALL`] entry name
/// as any component, letters matched case-insensitively.
///
/// Generated from the SSOT, so a new kind is denied without a second list.
#[cfg(any(target_os = "macos", test))]
#[must_use]
fn vcs_name_regex() -> String {
    let names: Vec<String> = crate::VcsKind::ALL
        .iter()
        .map(|kind| {
            kind.entry_name()
                .chars()
                .map(|ch| match ch {
                    '.' => String::from("\\."),
                    ch if ch.is_ascii_alphabetic() => {
                        format!("[{}{}]", ch.to_ascii_uppercase(), ch.to_ascii_lowercase())
                    }
                    ch => ch.to_string(),
                })
                .collect()
        })
        .collect();
    format!("/({})(/|$)", names.join("|"))
}

#[cfg(any(target_os = "macos", test))]
#[must_use]
fn sbpl_from_profile(
    profile: &SandboxProfile,
    scoped_tmp: &Path,
    working_tree: &Path,
    carve: &[&Path],
) -> String {
    use std::fmt::Write as _;

    // SBPL string literals are double-quoted; a path with an embedded `"` or `\`
    // would break the grammar. Escape both so a crafted scratch path cannot
    // inject SBPL. Writing to a String is infallible.
    let quote = |p: &Path| -> String {
        let mut out = String::from("\"");
        for ch in p.to_string_lossy().chars() {
            if ch == '"' || ch == '\\' {
                out.push('\\');
            }
            out.push(ch);
        }
        out.push('"');
        out
    };

    let mut s = String::from("(version 1)\n\n");
    // Allow-default base: the shell and its tools work; we selectively deny the
    // threats Tier-2 confines.
    s.push_str("(allow default)\n\n");

    // Baseline denials — unconditional, independent of the capability set.
    // These are the macOS Seatbelt equivalents of the Linux seccomp
    // baseline-denied set: escape and exfiltration primitives no legitimate
    // declared effect needs.
    //
    // - `process-info*`: covers `proc_info` and friends — the ptrace-equivalent
    //   inspection surface. A jailed process must not enumerate or inspect host
    //   or sibling process state (environment, memory maps, open files). This
    //   mirrors the Linux baseline denial of `ptrace` + `process_vm_readv/writev`.
    //
    // - `mach-task-name`: acquiring another process's Mach task port is the
    //   macOS mechanism for cross-process memory read and code injection. A jailed
    //   process must not obtain a foreign task port. (The jailed process may still
    //   use its own task port, which the default Seatbelt exceptions cover.)
    //
    // - `sysctl-read`: blocks bulk sysctl reads that leak host topology, hardware
    //   identifiers, and other fingerprinting surfaces. Legitimate tool use (shell,
    //   compiler) does not require broad sysctl enumeration. The narrow set of
    //   fixed hardware/kernel sysctls the C library reads during process bring-up
    //   (CPU count, page size, physical memory) is re-allowed by name below, so a
    //   dynamically-linked child can start while bulk enumeration stays denied.
    s.push_str("(deny process-info*)\n");
    s.push_str("(deny mach-task-name)\n");
    s.push_str("(deny sysctl-read)\n");
    // Re-allow ONLY the specific bring-up sysctls the C library reads while it
    // initialises (thread pool sizing, allocator page geometry). Last-match-wins
    // ordering: this narrow allow overrides the blanket `sysctl-read` deny above
    // for exactly these names, leaving every other sysctl — the fingerprinting
    // surface — denied. Named individually so a new name cannot slip in under a
    // wildcard; a genuinely-needed addition is a one-line, reviewed entry in
    // `BRING_UP_SYSCTL_NAMES`.
    for name in BRING_UP_SYSCTL_NAMES {
        let _ = writeln!(s, "(allow sysctl-read (sysctl-name \"{name}\"))");
    }
    // Deny the macOS Seatbelt equivalents of the Linux seccomp baseline
    // primitives that the run jail (seccomp.rs) blocks unconditionally:
    //
    // - `mach-lookup`: arbitrary bootstrap/system Mach service reach — the
    //   macOS mechanism for cross-process IPC. Mirrors the Linux denial of
    //   `bpf`/`perf_event_open` and the broader kernel-authority surface.
    //   The fixed set of system bootstrap services the dynamic loader, the C
    //   library, and the unified-log/allocator init reach while a process starts
    //   is re-allowed by exact `global-name` below (last-match-wins), so a
    //   dynamically-linked child can bring up while arbitrary service reach stays
    //   denied.
    //
    // - `iokit-open` family: direct driver/hardware access path. Mirrors the
    //   Linux denial of `iopl`/`ioperm` and raw device access primitives.
    //
    // - `ipc-posix-shm*`: POSIX shared-memory segments — a covert channel
    //   between jailed and host processes. Mirrors the Linux denial of
    //   `shmget`/`shmat` and related IPC primitives.
    s.push_str("(deny mach-lookup)\n");
    // Re-allow ONLY the fixed bootstrap services a dynamically-linked process
    // must reach to load and initialise: the dyld/XPC bootstrap surface, the
    // libinfo/opendirectory lookups a shell's user/group resolution performs, and
    // the unified-log/diagnostics endpoints libSystem opens at init. Last-match
    // wins, so each exact `global-name` overrides the blanket deny above for that
    // one service while every other Mach service — the cross-process IPC and
    // escape surface — stays denied. Named individually (never a prefix wildcard)
    // so no unlisted service is reachable; a new bring-up dependency is a
    // one-line, reviewed entry in `BRING_UP_MACH_SERVICES`.
    for service in BRING_UP_MACH_SERVICES {
        let _ = writeln!(s, "(allow mach-lookup (global-name \"{service}\"))");
    }
    s.push_str("(deny iokit-open)\n");
    s.push_str("(deny iokit-open-user-client)\n");
    s.push_str("(deny iokit-open-service)\n");
    s.push_str("(deny iokit-set-properties)\n");
    s.push_str("(deny iokit-get-properties)\n");
    s.push_str("(deny ipc-posix-shm*)\n\n");

    // Network: deny unless the profile grants it. When granted, no denial is
    // emitted, so the allow-default base leaves the network reachable.
    if !profile.network {
        s.push_str("(deny network*)\n");
        s.push_str("(deny network-outbound)\n");
        s.push_str("(deny network-inbound)\n");
        s.push_str("(deny network-bind)\n\n");
    }

    // Filesystem: deny writes everywhere, then re-allow the always-writable
    // scratch and — only when the axis is granted — the working tree. The
    // blanket deny makes an out-of-scratch write observable as the filesystem
    // axis under a withholding profile.
    //
    // The scratch (`scoped_tmp`) is the ONLY unconditional write allow. The
    // launcher points `TMPDIR` at it (`macos_scrubbed_env`), so a well-behaved
    // child's temp writes land there; the launcher itself stages nothing there
    // (the profile travels in argv). No broader system-temp tree is allowed:
    // `scoped_tmp` itself lives under the per-user temp tree (`/private/var/folders/…` — `$TMPDIR`
    // resolved through the `/var → /private/var` symlink), so a blanket allow
    // over that tree would re-permit every sibling of the scratch, defeating the
    // differential confinement — an out-of-scratch write next to the scratch
    // would leak. Fail-closed: allow only the resolved scratch subpath.
    //
    // The subpath is rendered in its SYMLINK-RESOLVED form. Seatbelt matches a
    // `(subpath X)` rule against the kernel-RESOLVED write path, and on macOS the
    // per-user temp tree is reached through the `/var → /private/var` symlink: a
    // scratch handed in as `/var/folders/…/T/…` is written by the kernel as
    // `/private/var/folders/…/T/…`. An allow rule bearing the unresolved `/var`
    // form would therefore NOT cover the resolved write, false-denying a
    // legitimate in-scratch write. [`macos_resolved_subpath`] resolves the path so
    // the allow matches the kernel-resolved write. Resolution only rewrites the
    // path to its canonical location; it never widens the allow to a parent, so
    // the out-of-scratch deny is untouched (a sibling of the scratch resolves to a
    // sibling of the resolved scratch, still outside the allowed subtree).
    s.push_str("(deny file-write*)\n");
    let _ = writeln!(
        s,
        "(allow file-write* (subpath {}))",
        quote(&macos_resolved_subpath(scoped_tmp))
    );
    // The working tree's version-control metadata stays read-only under its
    // write allow: a later rule wins, so each carved path is denied after the
    // allow, and so is any VCS entry name at any depth of the tree, matched
    // case-insensitively as the default APFS volume resolves it. The name rule
    // also covers metadata the child creates after the jail starts.
    if matches!(profile.filesystem, FilesystemScope::WorkingTreeReadWrite) {
        let tree = quote(&macos_resolved_subpath(working_tree));
        let _ = writeln!(s, "(allow file-write* (subpath {tree}))");
        for path in carve {
            let _ = writeln!(
                s,
                "(deny file-write* (subpath {}))",
                quote(&macos_resolved_subpath(path))
            );
        }
        let _ = writeln!(
            s,
            "(deny file-write* (require-all (subpath {tree}) (regex #\"{}\")))",
            vcs_name_regex()
        );
    }
    s.push('\n');

    // File READS are denied by default, then re-allowed only for the paths a build
    // legitimately needs. Without this, the allow-default base leaves the whole
    // home directory readable, so a network-granted build could read `~/.ssh` (or
    // any secret) and exfiltrate it — the macOS analogue of the Linux jail's
    // `--tmpfs /home` mask, which makes home unreadable inside the jail. Reads are
    // confined to the system/toolchain trees the shell and compiler need, the
    // always-readable scratch, and the working tree (the source being built). The
    // invoking user's home is NOT in the allow set, so its secrets stay unreadable
    // even when the network axis is granted. Fail-closed: a path outside the
    // allow set is denied, never read.
    s.push_str("(deny file-read*)\n");
    // The fixed system/toolchain read roots. These are the OS-owned, non-secret
    // trees the shell, its tools, and the Rust toolchain resolve at fixed paths;
    // none live under the invoking user's home. `/private/var/db`/`/private/etc`
    // hold the system databases (dyld cache, timezone, resolver config) the loader
    // and libc read; user secrets are not here.
    for root in MACOS_READ_ROOTS {
        let _ = writeln!(s, "(allow file-read* (subpath \"{root}\"))");
    }
    // The scratch is always readable (the child's temp files live there); the
    // working tree is the source being built, so it
    // is readable whether or not the filesystem axis grants WRITE access. Both are
    // rendered in symlink-resolved form so the allow matches the kernel-resolved
    // read, exactly like the write allows above.
    let _ = writeln!(
        s,
        "(allow file-read* (subpath {}))",
        quote(&macos_resolved_subpath(scoped_tmp))
    );
    let _ = writeln!(
        s,
        "(allow file-read* (subpath {}))",
        quote(&macos_resolved_subpath(working_tree))
    );
    s.push('\n');

    // Subprocess: deny NEW-process creation unless the profile grants it. On
    // macOS `sandbox-exec -p <profile> <app>` applies the profile and THEN
    // `execve`s <app> in place (no fork) — so a `(deny process-exec*)` here would
    // catch that mandatory initial exec and the app would never start. Denying
    // `process-fork` alone is the correct lowering: every way to create a NEW
    // process (`fork`/`vfork`/`posix_spawn`, all of which fork under Seatbelt)
    // requires the fork primitive, so a fork denial confines the app to a single
    // process. An `execve` that does NOT fork (an in-place image replacement)
    // stays permitted so the launcher's own initial exec of the target runs; that
    // replaces the one jailed process rather than creating a second one, so it is
    // within the single-process contract, not an escape (the Seatbelt profile
    // persists across the replacing exec, so network/filesystem stay confined for
    // the new image). This mirrors the Linux jail's seccomp denial of the
    // task-creation family, which — because Linux installs the filter AFTER the
    // initial exec — can deny the exec family outright; Seatbelt applies the
    // profile BEFORE the target exec, so only the fork axis is denied here. The
    // `native-ffi`-via-exec escape (opaque native code shelling out to a HELPER)
    // is still closed: a helper is a new process and so must fork. When granted,
    // no denial is emitted, so the allow-default base leaves spawning reachable.
    if !profile.subprocess {
        s.push_str("(deny process-fork)\n");
    }

    s
}

/// Resolve a write-allow path to the form Seatbelt matches against — the
/// kernel-RESOLVED path — so a `(subpath …)` allow covers the actual write.
///
/// Seatbelt evaluates a `(subpath X)` rule against the path the kernel resolves a
/// write to, not the literal string the caller held. On macOS the per-user temp
/// tree (`$TMPDIR`) and `/tmp` are reached through firmlinks/symlinks
/// (`/var → /private/var`, `/tmp → /private/tmp`): a scratch handed in as
/// `/var/folders/…/T/…` is written by the kernel as `/private/var/folders/…/T/…`.
/// An allow rule bearing the unresolved form would not cover the resolved write,
/// FALSE-DENYING a legitimate in-scratch write. This maps the caller's path to the
/// resolved form the kernel will match.
///
/// [`std::fs::canonicalize`] is authoritative — it resolves every symlink on the
/// real path, which at profile-build time already exists — and is used when it
/// succeeds. When it cannot (the path does not exist on this host, e.g. a unit
/// test on Linux), the two macOS firmlink prefixes are rewritten explicitly so the
/// lowering is still deterministic and host-independently testable. Both paths
/// only rewrite a leading component to its canonical location; neither widens the
/// allow to a parent, so the enclosing per-user temp tree is never blanket-allowed
/// and the out-of-scratch deny is preserved.
///
/// PURE up to a filesystem read of the (already-existing) scratch: it takes an
/// owned resolved path so `sbpl_from_profile` stays a total function of its inputs
/// plus the host's symlink layout, exactly what the kernel will enforce.
#[cfg(any(target_os = "macos", test))]
#[must_use]
fn macos_resolved_subpath(path: &Path) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical;
    }
    // Fallback when the path cannot be canonicalized on this host: rewrite the two
    // macOS firmlink prefixes to their `/private`-rooted resolved form. A path
    // already under `/private/…`, or under neither prefix, is returned unchanged.
    for (link, resolved) in [("/var/", "/private/var/"), ("/tmp/", "/private/tmp/")] {
        if let Ok(rest) = path.strip_prefix(link) {
            return PathBuf::from(resolved).join(rest);
        }
    }
    path.to_path_buf()
}

/// The environment the macOS launcher `exec`s `sandbox-exec` under — the `env`
/// axis's enforcement point.
///
/// Seatbelt cannot scrub environment variables, so — exactly as the Linux jail's
/// `--clearenv` + allowlisted re-export does inside `run_jail_argv` — the macOS
/// launcher clears the inherited environment down to a fixed minimal base
/// (`PATH`, `TMPDIR`) plus `LANG` (when the host sets it) plus ONLY the names in
/// `profile.env_allowlist` (when the host sets them). A name absent from the
/// host is simply not re-exported (never a placeholder); a name the profile does
/// not allow is absent from the child even if the host sets it.
///
/// PURE — it maps a host-env lookup to the child's `(name, value)` pairs — so the
/// exact scrub surface is unit-testable on any host and provable by the e2e
/// duality (`sandbox-exec` inherits exactly this env), with no second env list to
/// drift from the launcher.
///
/// `TMPDIR` is set to the always-writable scratch, matching the Linux jail (the
/// child's temp writes land in the one writable mount, not a masked host temp).
///
/// The FreeBSD build-jail arm reuses this SAME function (a jail does not scrub the
/// inherited environment either), so there is ONE launcher-side env allowlist for
/// every non-Linux arm — no second list that can drift from `profile.env_allowlist`.
#[cfg(any(target_os = "macos", target_os = "freebsd", test))]
#[must_use]
pub fn macos_scrubbed_env(
    profile: &SandboxProfile,
    scoped_tmp: &Path,
    host_env: &dyn Fn(&str) -> Option<OsString>,
) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = Vec::new();
    // The fixed minimal base, mirroring the Linux jail's re-exported allowlist.
    env.push((OsString::from("PATH"), OsString::from("/usr/bin:/bin")));
    env.push((OsString::from("TMPDIR"), scoped_tmp.as_os_str().to_owned()));
    if let Some(lang) = host_env("LANG") {
        env.push((OsString::from("LANG"), lang));
    }
    // Only the profile's declared env names re-enter, and only when the host
    // actually sets them (granted-but-unset ⇒ simply absent, never a placeholder).
    for name in &profile.env_allowlist {
        if let Some(value) = host_env(name) {
            env.push((OsString::from(name), value));
        }
    }
    env
}

/// Resolve a program name to an absolute path via `PATH`, or `None` when absent.
/// The macOS build/run jails (`sandbox-exec`) and the FreeBSD build jail (`jail`)
/// both refuse (fail-closed) when their mandatory primitive is missing, so the
/// resolver is shared.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path = ipe_env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .find(|candidate| candidate.is_file())
}

/// The user-private root for per-run FreeBSD jail scratch dirs, under `home`.
///
/// PURE over the parsed home so the refusal is unit-testable on any host. The
/// scratch must live under a user-private root: with no [`HomeDir`] it refuses,
/// naming the [`HomeRefusal`], rather than fall back to a world-writable `/tmp`
/// (a cross-user symlink-plant vector at an intermediate ancestor under a
/// root-run jail) or a relative path (resolved against whatever the working
/// directory is).
///
/// [`HomeDir`]: crate::home::HomeDir
/// [`HomeRefusal`]: crate::home::HomeRefusal
#[cfg(any(target_os = "freebsd", test))]
pub(crate) fn freebsd_jail_cache_root(
    home: Result<crate::home::HomeDir, crate::home::HomeRefusal>,
) -> Result<PathBuf, RunJailDefect> {
    match home {
        Ok(home) => Ok(home.join(".cache").join("ipe").join("jail")),
        Err(refusal) => Err(RunJailDefect::MountFailed {
            target: Path::new(".cache").join("ipe").join("jail"),
            detail: format!(
                "{refusal}; refusing a jail scratch root outside the user-private home"
            ),
        }),
    }
}

/// The FreeBSD jail's network-axis parameters for the given grant.
///
/// PURE — no process spawned — so the exact deny/grant surface is unit-testable on
/// any host, exactly like the macOS [`checked_sbpl`] and the Linux
/// [`run_jail_argv`]. Withheld ⇒ a fresh EMPTY vnet (`vnet=new`): a brand-new
/// network stack with no configured interface and no route, so an outbound socket
/// has no reachable destination and is denied at the kernel. The disabled address
/// families are belt-and-braces. A non-vnet `ip4=disable` jail shares the host's
/// stack and can still open outbound sockets, so the empty vnet — not address
/// disabling alone — is what withholds the axis. Granted ⇒ `vnet=inherit` shares the
/// host stack so a granted effect is not false-denied.
#[cfg(any(target_os = "freebsd", test))]
#[must_use]
pub(crate) fn freebsd_jail_network_params(network_granted: bool) -> Vec<OsString> {
    if network_granted {
        vec![
            OsString::from("vnet=inherit"),
            OsString::from("ip4=inherit"),
            OsString::from("ip6=inherit"),
        ]
    } else {
        vec![
            OsString::from("vnet=new"),
            OsString::from("ip4=disable"),
            OsString::from("ip6=disable"),
            OsString::from("allow.raw_sockets=0"),
        ]
    }
}

/// Join a safe, absolute, normalised `inner` path under the jail `root`.
///
/// The scratch, the working tree, and every mask land at their original
/// absolute paths inside the chroot, so the payload's `SCRATCH_DIR=<abs>`
/// resolves to the writable mount. `inner` is a [`SafeMountPath`], so both
/// absoluteness and `..`/`.`-freedom are proven by construction and
/// `root.join(stripped)` nests inside `root`.
#[cfg(any(target_os = "freebsd", test))]
fn under_root(root: &Path, inner: &SafeMountPath) -> PathBuf {
    let rel = inner.as_path().strip_prefix("/").unwrap_or(inner.as_path());
    root.join(rel)
}

/// One mount the FreeBSD jail applies under its chroot root.
///
/// The FreeBSD rendering of one [`crate::mounts::MountStep`]: a mask is a fresh
/// root-owned tmpfs (the counterpart of bwrap's `--tmpfs`), a bind a
/// `mount_nullfs` of the host path onto the same path inside the root.
#[cfg(any(target_os = "freebsd", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FreebsdMountOp {
    /// `mount -t tmpfs -o uid=0,gid=0,mode=0755 tmpfs <target>`: an empty
    /// mask no user but root can write.
    Mask {
        /// The masked directory inside the jail root.
        target: PathBuf,
    },
    /// `mount_nullfs -o ro <source> <target>`.
    ReadOnlyBind {
        /// The host path.
        source: PathBuf,
        /// The same path inside the jail root.
        target: PathBuf,
    },
    /// `mount_nullfs <source> <target>`.
    ReadWriteBind {
        /// The host path.
        source: PathBuf,
        /// The same path inside the jail root.
        target: PathBuf,
    },
}

#[cfg(any(target_os = "freebsd", test))]
impl FreebsdMountOp {
    /// The mountpoint inside the jail root.
    pub(crate) fn target(&self) -> &Path {
        match self {
            Self::Mask { target }
            | Self::ReadOnlyBind { target, .. }
            | Self::ReadWriteBind { target, .. } => target,
        }
    }
}

/// Render the mount plan `plan` as the mounts the FreeBSD jail applies under
/// `root`, in plan order.
///
/// # Errors
///
/// [`RunJailDefect::MountFailed`] when a step's path is not absolute or carries
/// a `..`/`.` component, so it cannot be re-rooted inside the jail.
#[cfg(any(target_os = "freebsd", test))]
pub(crate) fn freebsd_mount_ops(
    root: &Path,
    plan: &[crate::mounts::MountStep<'_>],
) -> Result<Vec<FreebsdMountOp>, RunJailDefect> {
    use crate::mounts::{Bind, MountStep};
    plan.iter()
        .map(|step| {
            Ok(match step {
                MountStep::Mask(mask) => FreebsdMountOp::Mask {
                    target: under_root(root, &SafeMountPath::new(mask)?),
                },
                MountStep::Bind(Bind::ReadOnly(path)) => {
                    let safe = SafeMountPath::new(path.as_path())?;
                    FreebsdMountOp::ReadOnlyBind {
                        target: under_root(root, &safe),
                        source: safe.0,
                    }
                }
                MountStep::Bind(Bind::ReadWrite(path)) => {
                    let safe = SafeMountPath::new(path.as_path())?;
                    FreebsdMountOp::ReadWriteBind {
                        target: under_root(root, &safe),
                        source: safe.0,
                    }
                }
                MountStep::Bind(Bind::WorkingTree(tree)) => {
                    let path = freebsd_working_tree_plan(tree).map_err(RunJailDefect::Path)?;
                    let safe = SafeMountPath::new(path.as_path())?;
                    FreebsdMountOp::ReadWriteBind {
                        target: under_root(root, &safe),
                        source: safe.0,
                    }
                }
            })
        })
        .collect()
}

/// The path the FreeBSD jail binds read-write for `tree`, which it grants only
/// when the tree holds no version-control metadata.
///
/// A `mount_nullfs -o ro` of a carve path names it by path at mount time, so a
/// swap between the carve and the mount would bind a different directory; the
/// arm refuses until it mounts the carve through a held handle.
///
/// # Errors
/// [`crate::JailPathError::VcsMetadataUncarvable`] naming the first carved path
/// when the carve is not empty.
#[cfg(any(target_os = "freebsd", test))]
pub(crate) fn freebsd_working_tree_plan(
    tree: &crate::WritableTree,
) -> Result<&crate::CanonicalPath, crate::JailPathError> {
    tree.carve().paths().next().map_or_else(
        || Ok(tree.tree()),
        |first| {
            Err(crate::JailPathError::VcsMetadataUncarvable {
                arm: crate::JailArm::Freebsd,
                path: first.as_path().to_path_buf(),
            })
        },
    )
}

/// Apply `ops` in order through `mount`, stopping at the first failure.
///
/// A mask that cannot mount refuses the whole jail: no later bind runs over an
/// unmasked home.
///
/// # Errors
///
/// The first error `mount` returns.
#[cfg(any(target_os = "freebsd", test))]
pub(crate) fn apply_mount_ops(
    ops: &[FreebsdMountOp],
    mount: impl FnMut(&FreebsdMountOp) -> Result<(), RunJailDefect>,
) -> Result<(), RunJailDefect> {
    ops.iter().try_for_each(mount)
}

/// The `mount -t tmpfs` options of every tmpfs the FreeBSD jail mounts.
///
/// A tmpfs root takes its owner from the directory it covers unless told
/// otherwise; the explicit root owner keeps every mask and provisioned
/// directory writable by root alone, so [`root_only_dir`] holds for it.
#[cfg(any(target_os = "freebsd", test))]
const JAIL_TMPFS_OPTIONS: &str = "uid=0,gid=0,mode=0755";

/// Whether a directory owned by `uid` with permission bits `mode` lets no user
/// but root create, rename, or remove its entries.
#[cfg(any(target_os = "freebsd", test))]
const fn root_only_dir(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

/// What a directory on a mount target's path inside the jail view guarantees
/// about the names it holds.
#[cfg(any(target_os = "freebsd", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ViewDirTrust {
    /// Root-owned and writable by no group or other user: only root can rename
    /// or replace its entries.
    RootOnly,
    /// Another user can rename its entries, so a name below it can be swapped
    /// for a symlink while the root-run launcher mounts on it.
    Writable,
    /// Absent from the view.
    Missing,
    /// Not a directory, or it cannot be inspected.
    Unusable,
}

/// The shallowest directory strictly between `root` and `target` whose entries
/// a user other than root can rename, judged by `trust`.
///
/// The launcher runs as root and names every mount target by path through the
/// jail view, which passes host changes through. `Some(dir)` means a fresh
/// tmpfs must cover `dir` before `target` is created and mounted on, so no
/// other user can redirect the mount; `None` means every present directory on
/// the path is root-only (a missing one ends the walk: what lies below it does
/// not exist in the view and is created afresh).
///
/// # Errors
///
/// [`RunJailDefect::MountFailed`] when `target` does not lie strictly inside
/// `root`, or a directory on the path is [`ViewDirTrust::Unusable`].
#[cfg(any(target_os = "freebsd", test))]
pub(crate) fn untrusted_mount_ancestor(
    root: &Path,
    target: &Path,
    mut trust: impl FnMut(&Path) -> ViewDirTrust,
) -> Result<Option<PathBuf>, RunJailDefect> {
    let outside = || RunJailDefect::MountFailed {
        target: target.to_path_buf(),
        detail: format!(
            "mount target is not inside the jail root {}",
            root.display()
        ),
    };
    let relative = target.strip_prefix(root).map_err(|_| outside())?;
    let mut components: Vec<std::path::Component<'_>> = relative.components().collect();
    if components.pop().is_none() {
        return Err(outside());
    }
    let mut dir = root.to_path_buf();
    for component in components {
        dir.push(component);
        match trust(&dir) {
            ViewDirTrust::RootOnly => {}
            ViewDirTrust::Writable => return Ok(Some(dir)),
            ViewDirTrust::Missing => return Ok(None),
            ViewDirTrust::Unusable => {
                return Err(RunJailDefect::MountFailed {
                    target: target.to_path_buf(),
                    detail: format!(
                        "{} on the mount target's path is not a usable directory",
                        dir.display()
                    ),
                });
            }
        }
    }
    Ok(None)
}

/// How to move the jail directories, which live under `$HOME/.cache/ipe/jail`,
/// below a home only root can write.
#[cfg(any(target_os = "freebsd", test))]
const JAIL_DIR_HOME_HINT: &str = "the jail directories live under $HOME/.cache/ipe/jail, so run \
     with HOME set to a home only root can write (for example `sudo -H`)";

/// Refuse `path` unless every directory above it, from `/` down, is a
/// directory only root can rename entries in, judged by `trust`.
///
/// The root-run launcher names the jail root and the `/proc`-mask source by
/// path on every mount; a directory above either that another user can write
/// would let that user swap the next name and redirect every mount.
///
/// # Errors
///
/// [`RunJailDefect::MountFailed`] when `path` is not absolute, or a directory
/// above it is [`ViewDirTrust::Writable`], missing, or not a directory.
#[cfg(any(target_os = "freebsd", test))]
pub(crate) fn require_root_only_ancestors(
    path: &Path,
    mut trust: impl FnMut(&Path) -> ViewDirTrust,
) -> Result<(), RunJailDefect> {
    let refuse = |detail: String| RunJailDefect::MountFailed {
        target: path.to_path_buf(),
        detail,
    };
    let parent = path
        .parent()
        .filter(|_| path.is_absolute())
        .ok_or_else(|| refuse("the jail directory is not an absolute path below /".to_owned()))?;
    let mut dir = PathBuf::new();
    for component in parent.components() {
        dir.push(component);
        match trust(&dir) {
            ViewDirTrust::RootOnly => {}
            ViewDirTrust::Writable => {
                return Err(refuse(format!(
                    "{} above the jail directory is writable by a user other than root; \
                     {JAIL_DIR_HOME_HINT}",
                    dir.display()
                )));
            }
            ViewDirTrust::Missing | ViewDirTrust::Unusable => {
                return Err(refuse(format!(
                    "{} above the jail directory is not a usable directory; \
                     {JAIL_DIR_HOME_HINT}",
                    dir.display()
                )));
            }
        }
    }
    Ok(())
}

/// The FreeBSD returning build-jail arm: establish a scratch-rooted `jail(2)`
/// (via the `jail(8)` CLI) lowering the profile's axes, scrub the env in the
/// launcher, run the payload confined, wait, and decode the exit into a
/// [`JailOutcome`] — fail-closed at every establishment step.
#[cfg(target_os = "freebsd")]
mod freebsd_jail {
    use super::{
        FreebsdMountOp, JAIL_TMPFS_OPTIONS, JailOutcome, SafeMountPath, ViewDirTrust,
        apply_mount_ops, find_in_path, freebsd_mount_ops, macos_scrubbed_env,
        require_root_only_ancestors, root_only_dir, under_root,
    };
    use crate::JailMounts;
    use crate::mounts::{WorkingTree, jail_binds, mount_plan};
    use crate::run_jail::{FilesystemScope, RunJailDefect, SandboxProfile};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    /// The unprivileged user the jailed payload runs as. A second, defence-in-depth
    /// layer under the read-only jail root: even the writable scratch is owned by
    /// this user, so nothing runs privileged inside the confinement.
    const JAIL_USER: &str = "nobody";

    /// Run `payload` inside a `jail(8)`-established jail lowered from `profile` and
    /// decode the outcome. See [`super::build_in_jail`] (FreeBSD) for the per-axis
    /// lowering and the fail-closed contract.
    pub(super) fn build_in_jail(
        profile: &SandboxProfile,
        mounts: &JailMounts,
        payload: &[OsString],
    ) -> JailOutcome {
        // `jail` is the mandatory primitive. Absent ⇒ refuse; the untrusted build
        // is never run unconfined.
        let Some(jail_bin) = find_in_path("jail") else {
            return JailOutcome::Unavailable {
                defect: RunJailDefect::PrimitiveUnavailable {
                    missing: vec!["jail"],
                },
            };
        };

        // The filesystem axis is confined STRUCTURALLY, not by DAC ownership: the
        // jail is chrooted (`path=`) to a fresh root that is a READ-ONLY nullfs view
        // of the host `/`, plus a FRESH minimal devfs and an EMPTY `/proc` (its
        // nullfs source rooted OUTSIDE the writable scratch, so the payload cannot
        // write it) masking the host's, then the jail's mount plan: every home and
        // `/tmp` masked, and only the planned binds (the scratch and, when the
        // filesystem axis is granted, the working tree read-write) re-exposed.
        // This is the exact FreeBSD counterpart of the Linux arm's `--ro-bind / /` +
        // fresh `--dev`/`--proc` + the same plan: an out-of-scratch write targets
        // the read-only root and is denied by the mount flag, never reliant on host
        // file permissions. Absent the mount root the untrusted build is never run —
        // fail-closed. Every planned path is a `SafeMountPath` (absolute, no
        // `..`/`.`), so it re-roots inside the jail root and nowhere else.
        let jail_root = match RoRootMount::establish(mounts, profile) {
            Ok(root) => root,
            Err(defect) => return JailOutcome::Unavailable { defect },
        };
        let (scoped_tmp, working_tree) = (mounts.scoped_tmp(), mounts.working_tree());

        // A withheld subprocess axis MUST be a genuine kernel denial of process
        // creation, not mere omission (ADR 0004). `rctl(8)` with
        // `jail:NAME:maxproc:deny=1` is the jail posture that denies `fork`/
        // `pdfork`/`exec` of a new process at the kernel boundary: the rule is
        // pre-registered by jail name and the kernel enforces it when the jail is
        // created below (the documented rctl.conf pre-registration pattern). It
        // requires the `racct`/`rctl` kernel facility; if that facility is off,
        // `rctl -a` fails and this refuses (`Unavailable`) — a withheld-subprocess
        // jail that cannot deny process creation is a refuse-gap, never a silent
        // `Clean` that ran the build unconfined. When subprocess is GRANTED no such
        // rule is added, so the differentially-probed net/fs canary (which grants
        // subprocess so the probe can fork its python3/nc/rm helper) does not depend
        // on rctl at all.
        let rctl = if profile.subprocess {
            None
        } else {
            match find_in_path("rctl") {
                Some(path) => Some(path),
                None => {
                    return JailOutcome::Unavailable {
                        defect: RunJailDefect::PrimitiveUnavailable {
                            // Without rctl a withheld-subprocess jail cannot deny
                            // process creation — a refuse-gap, never an unconfined run.
                            missing: vec!["rctl"],
                        },
                    };
                }
            }
        };

        // The one writable mount (the scratch) must be writable to the unprivileged
        // jail user; the launcher (root on the FreeBSD CI VM, as jail creation
        // requires) chowns it. A failed chown refuses — a scratch the payload cannot
        // write is a broken jail, never run. Defence in depth atop the read-only
        // root: even the writable mount is only reachable by an unprivileged user.
        // The scratch is a per-run directory under the private cache root, discarded
        // after the run, so its ownership need not be restored.
        if let Err(defect) = chown_to_jail_user(scoped_tmp.as_path()) {
            return JailOutcome::Unavailable { defect };
        }
        // The working tree is the user's REAL project directory (nullfs is a
        // pass-through: chowning the mount target chowns the source inode). Chowning
        // it to the jail user so a granted filesystem effect can write it must NOT
        // outlive the run — a persistent host mutation from a confined build is a
        // trust-boundary violation. Record the original owner and restore it on drop
        // regardless of outcome, so the user's tree ownership is left untouched.
        let tree_owner_guard = if profile.filesystem == FilesystemScope::WorkingTreeReadWrite {
            match RestoredOwnership::chown_to_jail_user(working_tree.as_path()) {
                Ok(guard) => Some(guard),
                Err(defect) => return JailOutcome::Unavailable { defect },
            }
        } else {
            None
        };

        let jail_name = per_run_jail_name();
        let argv = jail_argv(&jail_bin, &jail_name, jail_root.root(), profile, payload);

        // Env scrub in the launcher (the jail does not scrub the inherited env),
        // via the SAME allowlist the macOS/Windows arms use — one env list.
        let host_env = crate::host_env::granted;
        let scrubbed = macos_scrubbed_env(profile, scoped_tmp.as_path(), &host_env);

        // Apply the rctl process-cap rule (withheld subprocess only) BEFORE the
        // jail runs, then remove it on return regardless of outcome so nothing
        // leaks across the audit's per-axis tightening loop.
        let _rctl_guard = match &rctl {
            Some(rctl_bin) => match RctlRule::apply(rctl_bin, &jail_name) {
                Ok(guard) => Some(guard),
                Err(defect) => return JailOutcome::Unavailable { defect },
            },
            None => None,
        };

        let outcome = spawn_and_decode(&argv, &scrubbed);
        // The jail is `persist=0`, so it is torn down when the payload exits. The
        // read-only root's nullfs mounts and the rctl rule are unmounted/removed by
        // their guards on drop (in reverse order) as this scope ends, leaving no
        // residue across the audit's per-axis tightening loop.
        drop(jail_root);
        // Restore the working tree's original ownership only AFTER the mounts are
        // torn down, so the user's real tree is left exactly as it was found.
        drop(tree_owner_guard);
        outcome
    }

    /// Build the `jail -c … command=<payload>` argv lowering the profile's axes.
    ///
    /// - `path=<jail_root>` chroots the jail to a fresh read-only nullfs view of the
    ///   host root (established by [`RoRootMount`]) with only the scratch mounted
    ///   read-write inside it — so an out-of-scratch write hits the read-only mount
    ///   and is denied structurally, not by file ownership.
    /// - network withheld ⇒ `vnet=new` gives the jail a BRAND-NEW, empty network
    ///   stack (only a `lo0` that is down, no configured interface, no route), so an
    ///   outbound socket has no reachable destination and is denied at the kernel;
    ///   `ip4=disable ip6=disable allow.raw_sockets=0` further deny address families.
    ///   Granted ⇒ `vnet=inherit ip4=inherit ip6=inherit` shares the host stack so a
    ///   granted effect is not false-denied. A non-vnet `ip4=disable` jail shares the
    ///   host stack and can still open outbound sockets; a fresh empty vnet cannot.
    /// - `exec.jail_user=nobody` runs the payload unprivileged (defence in depth
    ///   under the read-only root).
    /// - `persist=0` tears the jail down when the payload exits (no orphan jail).
    fn jail_argv(
        jail_bin: &Path,
        jail_name: &str,
        jail_root: &Path,
        profile: &SandboxProfile,
        payload: &[OsString],
    ) -> Vec<OsString> {
        let mut argv: Vec<OsString> = Vec::new();
        argv.push(jail_bin.as_os_str().to_owned());
        argv.push(OsString::from("-c"));
        argv.push(OsString::from(format!("name={jail_name}")));
        let mut path_param = OsString::from("path=");
        path_param.push(jail_root.as_os_str());
        argv.push(path_param);
        argv.push(OsString::from("host.hostname=ipe-tier2-jail"));
        // Network: withheld ⇒ a fresh EMPTY vnet (no interface, no route) so an
        // outbound socket cannot reach anything and is denied → the probe's exit-10
        // decodes to Denied { network }; address families are disabled too. Granted
        // ⇒ inherit the host stack so a granted effect is not false-denied. The pure
        // param list is unit-tested on any host via `freebsd_jail_network_params`.
        argv.extend(super::freebsd_jail_network_params(profile.network));
        argv.push(OsString::from("allow.sysvipc=0"));
        argv.push(OsString::from("persist=0"));
        argv.push(OsString::from(format!("exec.jail_user={JAIL_USER}")));
        // The command: `jail(8)`'s `command` parameter collects EVERYTHING on the
        // command line following it as the argv to `execvp` inside the jail — one
        // command-line argument per argv slot, with NO shell and NO quote removal.
        // So the payload's first token rides on `command=<tok0>` and every
        // remaining token is pushed as its OWN separate argv element to the `jail`
        // process. Each stays one OS-level argument end to end (Rust hands each
        // `arg` to `jail` as a distinct `execve` slot, and `jail` forwards them as
        // distinct slots to the payload), so a scratch, working-tree, or
        // `CARGO_HOME` path bearing whitespace survives byte-for-byte with no
        // quoting and no re-split — there is no single space-joined string for
        // `jail` to mis-tokenise, and no shell to interpret metacharacters.
        let mut command = OsString::from("command=");
        let Some((first, rest)) = payload.split_first() else {
            // An empty payload cannot be run; the caller decodes the resulting
            // spawn/exec failure as a non-clean outcome (never a silent Clean).
            argv.push(command);
            return argv;
        };
        command.push(first);
        argv.push(command);
        for tok in rest {
            argv.push(tok.clone());
        }
        argv
    }

    /// Chown `path` to the unprivileged jail user so the confined payload can write
    /// it. Uses the `chown(8)` CLI (no new `unsafe` FFI); a failure refuses.
    ///
    /// `spec` is a `chown(8)` owner spec: a bare user (`nobody`) or a numeric
    /// `uid:gid` pair used to restore the original ownership.
    fn run_chown(spec: &str, path: &Path) -> Result<(), RunJailDefect> {
        let Some(chown) = find_in_path("chown") else {
            return Err(RunJailDefect::PrimitiveUnavailable {
                missing: vec!["chown"],
            });
        };
        let status = std::process::Command::new(chown)
            .arg(spec)
            .arg(path)
            .status();
        match status {
            Ok(s) if s.success() => Ok(()),
            Ok(s) => Err(RunJailDefect::Spawn {
                detail: format!("chown {spec} {} failed ({s})", path.display()),
            }),
            Err(e) => Err(RunJailDefect::Spawn {
                detail: format!("could not run chown for {}: {e}", path.display()),
            }),
        }
    }

    /// Chown `path` to the unprivileged jail user so the confined payload can write
    /// its scratch. The scratch is a discarded per-run directory, so its ownership
    /// need not be restored.
    fn chown_to_jail_user(path: &Path) -> Result<(), RunJailDefect> {
        run_chown(JAIL_USER, path)
    }

    /// Chown a path to the jail user for the duration of a jailed run, restoring its
    /// original ownership on drop.
    ///
    /// The working tree is the user's REAL project directory. Making it writable to
    /// the unprivileged jail user requires a chown (nullfs is a pass-through, so the
    /// mount target and the source inode are one), but a confined build must not
    /// leave a persistent host mutation behind. This guard records the original
    /// `uid`/`gid` before the chown and restores it on drop regardless of outcome, so
    /// the user's tree ownership is left exactly as it was found.
    struct RestoredOwnership {
        path: PathBuf,
        original: String,
    }

    impl RestoredOwnership {
        fn chown_to_jail_user(path: &Path) -> Result<Self, RunJailDefect> {
            use std::os::unix::fs::MetadataExt as _;

            // Read the current owner BEFORE any mutation so a failure to observe it
            // refuses rather than chowning a tree we could not later restore.
            let metadata = std::fs::metadata(path).map_err(|e| RunJailDefect::Spawn {
                detail: format!("could not stat {} before chown: {e}", path.display()),
            })?;
            let original = format!("{}:{}", metadata.uid(), metadata.gid());
            run_chown(JAIL_USER, path)?;
            Ok(Self {
                path: path.to_path_buf(),
                original,
            })
        }
    }

    impl Drop for RestoredOwnership {
        fn drop(&mut self) {
            // Best-effort restore: the run is over, so a failure here cannot be
            // surfaced as a jail outcome, but it must be attempted so the user's tree
            // ownership is not left changed.
            let _ = run_chown(&self.original, &self.path);
        }
    }

    /// Run `mount_nullfs [opts] <source> <target>`, refusing (fail-closed) on any
    /// non-success so the untrusted payload never runs against a half-built root.
    fn mount_nullfs(
        mount_nullfs_bin: &Path,
        read_only: bool,
        source: &Path,
        target: &Path,
    ) -> Result<(), RunJailDefect> {
        let mut command = std::process::Command::new(mount_nullfs_bin);
        if read_only {
            command.arg("-o").arg("ro");
        }
        let status = command.arg(source).arg(target).status();
        match status {
            Ok(s) if s.success() => Ok(()),
            Ok(s) => Err(RunJailDefect::MountFailed {
                target: target.to_path_buf(),
                detail: format!(
                    "mount_nullfs {} {} failed ({s})",
                    if read_only { "ro" } else { "rw" },
                    source.display(),
                ),
            }),
            Err(e) => Err(RunJailDefect::MountFailed {
                target: target.to_path_buf(),
                detail: format!(
                    "could not run mount_nullfs (source {}): {e}",
                    source.display()
                ),
            }),
        }
    }

    /// Mount a FRESH minimal `devfs` at `target` (the jail's `/dev`), refusing
    /// (fail-closed) on any non-success. This gives the jail the default devfs
    /// ruleset — a minimal `/dev` (null/zero/random/…) — NOT the host devfs the
    /// read-only root nullfs-exposed, so the jail sees a fresh minimal `/dev` and
    /// the host device nodes are not enumerable (matching the Linux arm's `--dev`).
    ///
    /// FreeBSD does not ship a standalone `mount_devfs` binary; devfs is mounted
    /// via `mount -t devfs devfs <target>` (the `mount(8)` binary, which IS a
    /// stable base-system primitive on every supported FreeBSD release).
    fn mount_devfs(mount_bin: &Path, target: &Path) -> Result<(), RunJailDefect> {
        let status = std::process::Command::new(mount_bin)
            .arg("-t")
            .arg("devfs")
            .arg("devfs")
            .arg(target)
            .status();
        match status {
            Ok(s) if s.success() => Ok(()),
            Ok(s) => Err(RunJailDefect::MountFailed {
                target: target.to_path_buf(),
                detail: format!("mount -t devfs devfs failed ({s})"),
            }),
            Err(e) => Err(RunJailDefect::MountFailed {
                target: target.to_path_buf(),
                detail: format!("could not run mount -t devfs: {e}"),
            }),
        }
    }

    /// Mount a FRESH root-owned `tmpfs` with mode `0755` at `target`
    /// ([`JAIL_TMPFS_OPTIONS`]), refusing (fail-closed) on any non-success.
    ///
    /// It serves two roles: a mask of the mount plan (the counterpart of bwrap's
    /// `--tmpfs`), and the provisioned parent a missing mountpoint leaf is created
    /// on. Root ownership and mode `0755` keep both writable by root alone,
    /// whatever the owner and mode of the directory it covers. `mount(8)` — the
    /// stable base-system primitive, the same binary used for devfs — carries the
    /// tmpfs type on every supported FreeBSD release.
    fn mount_tmpfs(mount_bin: &Path, target: &Path) -> Result<(), RunJailDefect> {
        let status = std::process::Command::new(mount_bin)
            .arg("-t")
            .arg("tmpfs")
            .arg("-o")
            .arg(JAIL_TMPFS_OPTIONS)
            .arg("tmpfs")
            .arg(target)
            .status();
        match status {
            Ok(s) if s.success() => Ok(()),
            Ok(s) => Err(RunJailDefect::MountFailed {
                target: target.to_path_buf(),
                detail: format!("mount -t tmpfs -o {JAIL_TMPFS_OPTIONS} tmpfs failed ({s})"),
            }),
            Err(e) => Err(RunJailDefect::MountFailed {
                target: target.to_path_buf(),
                detail: format!("could not run mount -t tmpfs: {e}"),
            }),
        }
    }

    /// Create an empty directory named `name` under `parent`, used as the read-only
    /// nullfs source that masks the jail's `/proc` with an EMPTY tree. A creation
    /// failure refuses (fail-closed) — a `/proc` that cannot be masked would leave
    /// the host `/proc` exposed, never run against.
    ///
    /// `parent` MUST be a location the jailed payload cannot write: the source's
    /// vnode is what the read-only `/proc` mask exposes, so a payload that could
    /// write it could surface files under its own `/proc`. The caller roots it
    /// OUTSIDE the writable scratch (a per-run sibling of the jail root) so the
    /// payload has no mount into it — the `/proc` mask is immutable to the payload.
    ///
    /// Uses `create_dir` (not `create_dir_all`) so a pre-existing entry at the
    /// exact leaf path is an error, not a silent reuse. The parent is already an
    /// exclusively-created private directory (`proc_mask_source_dir`), so
    /// `create_dir_all` on the parent is safe; only the leaf must be exclusive.
    fn mount_dir_under(parent: &Path, name: &str) -> Result<PathBuf, RunJailDefect> {
        let dir = parent.join(name);
        match std::fs::create_dir(&dir) {
            Ok(()) => Ok(dir),
            Err(e) => Err(RunJailDefect::MountFailed {
                target: dir,
                detail: format!("could not create the empty /proc mask source: {e}"),
            }),
        }
    }

    /// How far the directory `dir` of the jail view can be trusted to keep its
    /// entries: root-owned and writable by no group or other user, or not.
    fn view_dir_trust(dir: &Path) -> ViewDirTrust {
        use std::os::unix::fs::MetadataExt as _;
        match std::fs::symlink_metadata(dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ViewDirTrust::Missing,
            Err(_) => ViewDirTrust::Unusable,
            Ok(meta) if !meta.file_type().is_dir() => ViewDirTrust::Unusable,
            Ok(meta) if root_only_dir(meta.uid(), meta.mode()) => ViewDirTrust::RootOnly,
            Ok(_) => ViewDirTrust::Writable,
        }
    }

    /// The read-only jail root, built from one [`JailMounts`] value.
    ///
    /// A fresh directory over which the whole host `/` is nullfs-mounted
    /// READ-ONLY, with a FRESH minimal devfs over `/dev` and an EMPTY read-only
    /// `/proc` mask over `/proc`, then the shared mount plan
    /// ([`crate::mounts::mount_plan`]) applied at the planned paths' original
    /// absolute locations inside it: every home and static mask as a root-owned
    /// tmpfs, the read-only binds, the scratch read-write, and the working tree
    /// read-write when the filesystem axis is granted. This is the FreeBSD
    /// counterpart of the Linux arm's `--ro-bind / /` + fresh `--dev`/`--proc` +
    /// the same rendered plan: `jail path=<root>` chroots the payload here, so an
    /// out-of-scratch write targets a read-only mount and is denied by the mount
    /// flag — never reliant on host file permissions — and no home is readable
    /// except what a planned bind re-exposes. A planned mountpoint the read-only
    /// view lacks is created on a fresh tmpfs layered over its parent. Every mount
    /// and the root dir are torn down on drop, in reverse mount order.
    struct RoRootMount {
        umount_bin: PathBuf,
        root: PathBuf,
        /// The empty dir the read-only `/proc` mask is nullfs-mounted FROM. It is
        /// rooted OUTSIDE the writable scratch (a sibling of `root`), so the jailed
        /// payload — which only has the scratch and granted working tree mounted
        /// read-write inside the chroot — has no mount to it and cannot write it, so
        /// the `/proc` mask stays immutable to the payload. Removed on drop.
        proc_mask_source: PathBuf,
        /// Every mounted target, in mount order; unmounted in reverse on drop.
        mounted: Vec<PathBuf>,
        /// In-root directories a fresh tmpfs has been layered over, so a mountpoint
        /// can be created on a filesystem only this jail reaches (the read-only
        /// host view is `EROFS`, and a user-writable directory in it lets that user
        /// swap names). Deduplicated: two targets below one directory are
        /// provisioned by a single tmpfs. Each is also recorded in `mounted` so it
        /// is unmounted on drop.
        tmpfs_parents: Vec<PathBuf>,
    }

    impl RoRootMount {
        /// Establish the read-only root, `/dev`, `/proc`, and the mount plan of
        /// `mounts`.
        ///
        /// Any missing primitive or failed mount — a mask included — refuses
        /// (`Err`), so the payload never runs against an incompletely-confined or
        /// unmasked root.
        fn establish(mounts: &JailMounts, profile: &SandboxProfile) -> Result<Self, RunJailDefect> {
            let Some(mount_nullfs_bin) = find_in_path("mount_nullfs") else {
                return Err(RunJailDefect::PrimitiveUnavailable {
                    missing: vec!["mount_nullfs"],
                });
            };
            // `mount` is the stable primitive; FreeBSD does not ship a standalone
            // `mount_devfs` binary — devfs is mounted via `mount -t devfs devfs`.
            let Some(mount_devfs_bin) = find_in_path("mount") else {
                return Err(RunJailDefect::PrimitiveUnavailable {
                    missing: vec!["mount"],
                });
            };
            let Some(umount_bin) = find_in_path("umount") else {
                return Err(RunJailDefect::PrimitiveUnavailable {
                    missing: vec!["umount"],
                });
            };

            // The jail root is created exclusively under the private cache root
            // (`~/.cache/ipe/jail/`), not world-writable `/tmp`, so a local attacker
            // cannot pre-plant or symlink it before the nullfs mount. The returned
            // path is verified to be a real directory owned by the current uid. It
            // is canonicalised once, so every planned mountpoint under it can be
            // checked to resolve to itself.
            let created = jail_root_dir()?;
            let root = std::fs::canonicalize(&created).map_err(|e| RunJailDefect::MountFailed {
                target: created.clone(),
                detail: format!("could not resolve the jail root: {e}"),
            })?;
            require_root_only_ancestors(&root, view_dir_trust)?;

            // The `/proc`-mask source: an empty dir rooted OUTSIDE the writable
            // scratch, under the same private cache root as the jail root. It is NOT
            // under the scratch (which is nullfs-mounted READ-WRITE inside the chroot)
            // and NOT under the chroot root (over which host `/` is mounted read-only),
            // so the jailed payload has no mount to it and cannot write it — the
            // read-only `/proc` mask it feeds stays immutable to the payload. Created
            // exclusively; a creation failure refuses (fail-closed).
            let created_mask_source = mount_dir_under(&proc_mask_source_dir()?, "empty-proc")?;
            let proc_mask_source = std::fs::canonicalize(&created_mask_source).map_err(|e| {
                RunJailDefect::MountFailed {
                    target: created_mask_source.clone(),
                    detail: format!("could not resolve the /proc mask source: {e}"),
                }
            })?;
            require_root_only_ancestors(&proc_mask_source, view_dir_trust)?;

            let mut mount = Self {
                umount_bin,
                root,
                proc_mask_source,
                mounted: Vec::new(),
                tmpfs_parents: Vec::new(),
            };

            // 1. The whole host `/`, READ-ONLY, as the jail root. Everything the
            //    payload can read (the shell, its tools) is here; nothing is writable.
            //    This also nullfs-exposes the host `/dev` and `/proc` READ-ONLY, so
            //    steps 2–3 layer a FRESH minimal `/dev` and an EMPTY `/proc` over them
            //    before the jailed process starts — matching the Linux arm's fresh
            //    `--dev`/`--proc`, which mask the ro-bound host nodes.
            mount_nullfs(&mount_nullfs_bin, true, Path::new("/"), &mount.root)?;
            mount.mounted.push(mount.root.clone());

            // 2. A FRESH minimal devfs over the jail's `/dev`, layered on top of the
            //    read-only host `/dev` the ro-root exposed. Without this the jail sees
            //    the HOST devfs read-only — a metadata/enumeration leak (every host
            //    device node is visible, a covert-channel/enumeration surface). A
            //    fresh `mount -t devfs devfs` gives the jail the minimal default devfs
            //    ruleset (null/zero/random/…), NOT the host's, matching the Linux
            //    arm's fresh `--dev /dev`.
            let dev_target = under_root(&mount.root, &SafeMountPath::new(Path::new("/dev"))?);
            mount_devfs(&mount_devfs_bin, &dev_target)?;
            mount.mounted.push(dev_target);

            // 3. Mask the jail's `/proc` with a FRESH EMPTY read-only nullfs of an
            //    empty dir rooted OUTSIDE the writable scratch, layered over the
            //    read-only host `/proc` the ro-root exposed. An unmasked host `/proc`
            //    would leak sibling env via `/proc/<pid>/environ` (defeating the
            //    launcher env scrub) and expose host process metadata — a
            //    covert-channel surface. This empties it, matching the Linux arm's
            //    fresh `--proc /proc`. (A jail with an empty net stack and its own PID
            //    view has no meaningful procfs to publish; an empty `/proc` is the
            //    fail-closed choice over the host's.)
            //
            //    The mask source is `mount.proc_mask_source` — a per-run sibling of
            //    the jail root, NOT under the read-write scratch — so the payload has
            //    no mount to it and cannot surface files under its own `/proc`. The
            //    mount is read-only regardless, so `/proc` is truly immutable.
            let proc_target = under_root(&mount.root, &SafeMountPath::new(Path::new("/proc"))?);
            mount_nullfs(
                &mount_nullfs_bin,
                true,
                &mount.proc_mask_source,
                &proc_target,
            )?;
            mount.mounted.push(proc_target);

            // 4. The mount plan shared with the bwrap arm: every home and static
            //    mask as a fresh root-owned tmpfs, each bind right after the mask
            //    that most closely contains it, the working tree only when the
            //    filesystem axis is granted. A step that cannot mount refuses the
            //    whole jail, so no bind ever runs over an unmasked home.
            let binds = jail_binds(mounts, WorkingTree::granted_by(&profile.filesystem));
            let ops = freebsd_mount_ops(&mount.root, &mount_plan(mounts.homes(), &binds))?;
            apply_mount_ops(&ops, |op| {
                mount.mount_op(&mount_nullfs_bin, &mount_devfs_bin, op)
            })?;

            Ok(mount)
        }

        /// Apply one planned mount under the root and record it for teardown.
        ///
        /// # Errors
        ///
        /// [`RunJailDefect::MountFailed`] when the mountpoint cannot be made ready
        /// or the mount itself fails.
        fn mount_op(
            &mut self,
            mount_nullfs_bin: &Path,
            mount_bin: &Path,
            op: &FreebsdMountOp,
        ) -> Result<(), RunJailDefect> {
            let target = op.target();
            self.ensure_mountpoint(mount_bin, target)?;
            match op {
                FreebsdMountOp::Mask { .. } => mount_tmpfs(mount_bin, target)?,
                FreebsdMountOp::ReadOnlyBind { source, .. } => {
                    mount_nullfs(mount_nullfs_bin, true, source, target)?;
                }
                FreebsdMountOp::ReadWriteBind { source, .. } => {
                    mount_nullfs(mount_nullfs_bin, false, source, target)?;
                }
            }
            self.mounted.push(target.to_path_buf());
            Ok(())
        }

        /// Make `target` an existing directory that resolves to itself, named
        /// only through directories no user but root can rename entries in.
        ///
        /// A `mount_nullfs` or `tmpfs` target must ALREADY exist — the tools never
        /// create their mountpoint. The read-only nullfs of `/` supplies the
        /// directories of the ROOT filesystem only; it does not cross into
        /// filesystems mounted under it (a tmpfs `/tmp`, a separate `/home`), and it
        /// cannot be `mkdir`'d into (`EROFS`). The view passes host changes through,
        /// so a directory on the target's path that another user can write lets
        /// that user swap the next name for a symlink between this check and the
        /// root-run mount. The shallowest such directory is covered by a fresh
        /// tmpfs first ([`super::untrusted_mount_ancestor`]), so the target is
        /// created on a root-owned filesystem only root can write. A target whose
        /// path is root-only and present is used as is; one on a tmpfs this jail
        /// mounted is created there; otherwise a fresh tmpfs is layered over its
        /// parent to hold the leaf — the FreeBSD counterpart of bwrap materialising
        /// its mount targets inside the namespace.
        ///
        /// # Errors
        ///
        /// [`RunJailDefect::MountFailed`] when a directory on the path is not a
        /// directory or cannot be inspected, when the leaf cannot be provisioned, or
        /// when the target resolves anywhere but itself.
        fn ensure_mountpoint(
            &mut self,
            mount_bin: &Path,
            target: &Path,
        ) -> Result<(), RunJailDefect> {
            match super::untrusted_mount_ancestor(&self.root, target, view_dir_trust)? {
                Some(anchor) => self.provision_tmpfs_over(mount_bin, &anchor, target)?,
                None => {
                    if !target.is_dir() && std::fs::create_dir_all(target).is_err() {
                        let parent = target.parent().ok_or_else(|| RunJailDefect::MountFailed {
                            target: target.to_path_buf(),
                            detail: "mount target has no parent to provision".to_owned(),
                        })?;
                        self.provision_tmpfs_over(mount_bin, parent, target)?;
                    }
                }
            }
            let resolved =
                std::fs::canonicalize(target).map_err(|e| RunJailDefect::MountFailed {
                    target: target.to_path_buf(),
                    detail: format!("could not resolve the mount target: {e}"),
                })?;
            if resolved == target {
                Ok(())
            } else {
                Err(RunJailDefect::MountFailed {
                    target: target.to_path_buf(),
                    detail: format!(
                        "mount target does not resolve to itself inside the jail root (it resolves to {})",
                        resolved.display()
                    ),
                })
            }
        }

        /// Create the mountpoint `target` on a fresh tmpfs over `dir`, one of its
        /// ancestors inside the jail root.
        ///
        /// A FRESH root-owned tmpfs is layered over `dir` (once per distinct
        /// directory), then the missing path down to `target` is created on it.
        ///
        /// # Errors
        ///
        /// [`RunJailDefect::MountFailed`] when `dir` is the jail root, is or holds
        /// an earlier mount (a tmpfs there would hide it), when the tmpfs mount
        /// fails, or when the leaf cannot be created — fail-closed: the payload
        /// never runs against a half-built root.
        fn provision_tmpfs_over(
            &mut self,
            mount_bin: &Path,
            dir: &Path,
            target: &Path,
        ) -> Result<(), RunJailDefect> {
            // A single tmpfs per distinct directory: mounting a second over the
            // same stub would mask the first, hiding the leaf already created on it.
            if !self.tmpfs_parents.iter().any(|p| p == dir) {
                if dir == self.root {
                    return Err(RunJailDefect::MountFailed {
                        target: target.to_path_buf(),
                        detail: "provisioning this mountpoint would hide the jail root".to_owned(),
                    });
                }
                if self.mounted.iter().any(|earlier| earlier.starts_with(dir)) {
                    return Err(RunJailDefect::MountFailed {
                        target: target.to_path_buf(),
                        detail: "provisioning this mountpoint would hide an earlier mount"
                            .to_owned(),
                    });
                }
                mount_tmpfs(mount_bin, dir)?;
                self.tmpfs_parents.push(dir.to_path_buf());
                // Unmounted in reverse mount order on drop with the rest.
                self.mounted.push(dir.to_path_buf());
            }
            std::fs::create_dir_all(target).map_err(|e| RunJailDefect::MountFailed {
                target: target.to_path_buf(),
                detail: format!("could not create the mountpoint: {e}"),
            })
        }

        fn root(&self) -> &Path {
            &self.root
        }
    }

    impl Drop for RoRootMount {
        fn drop(&mut self) {
            // Unmount in reverse order (writable mounts before the read-only root that
            // contains them), then remove the now-empty root dir. Best-effort: a
            // `persist=0` jail is already gone, and a leftover mount on a torn-down
            // scratch is inert — but clean up so the audit loop leaves no residue.
            for target in self.mounted.iter().rev() {
                let _ = std::process::Command::new(&self.umount_bin)
                    .arg("-f")
                    .arg(target)
                    .status();
            }
            let _ = std::fs::remove_dir(&self.root);
            // Remove the `/proc`-mask source dir (a sibling of the root, outside the
            // scratch) AFTER its read-only `/proc` mount is unmounted above, then its
            // per-run parent. Best-effort — a leftover empty dir is inert.
            let _ = std::fs::remove_dir(&self.proc_mask_source);
            if let Some(parent) = self.proc_mask_source.parent() {
                let _ = std::fs::remove_dir(parent);
            }
        }
    }

    /// The private cache root for per-run FreeBSD jail scratch directories.
    ///
    /// Rooted under the invoking user's home cache (`~/.cache/ipe/jail/`) rather
    /// than the world-writable `/tmp`. A user-private directory is not accessible
    /// to other local users, removing the class of pre-plant / symlink-swap attacks
    /// that world-writable `/tmp` enables. An unset or relative home is refused.
    fn private_cache_root() -> Result<PathBuf, RunJailDefect> {
        super::freebsd_jail_cache_root(crate::home::home_dir())
    }

    /// Create a per-run directory EXCLUSIVELY under `parent`, using a random
    /// unique leaf name prefixed with `prefix`.
    ///
    /// The leaf is created with `create_dir` (not `create_dir_all`) after ensuring
    /// the parent exists. `create_dir` returns `ErrorKind::AlreadyExists` when the
    /// leaf already exists — any pre-existing entry (whether a directory, file, or
    /// symlink) is treated as a fail-closed refusal, never silently reused. This
    /// closes the TOCTOU window that `create_dir_all` leaves open on a pre-planted
    /// or symlinked path.
    ///
    /// After creation each component of the returned path is verified to be a real
    /// directory owned by the current uid via `symlink_metadata`, so a symlink
    /// planted between the `create_dir` and the use is caught.
    ///
    /// # Errors
    ///
    /// [`RunJailDefect::MountFailed`] when the parent cannot be created, when the
    /// exclusive leaf creation fails (including pre-existing), or when any
    /// component fails the ownership check.
    fn create_exclusive_private_dir(
        parent: &std::path::Path,
        prefix: &str,
    ) -> Result<PathBuf, RunJailDefect> {
        use std::os::unix::fs::MetadataExt as _;

        // Ensure the private parent exists. `create_dir_all` is safe here: the
        // parent (`~/.cache/ipe/jail/`) is user-owned and not itself a
        // security boundary — it is the LEAF that must be exclusive.
        if let Err(e) = std::fs::create_dir_all(parent) {
            return Err(RunJailDefect::MountFailed {
                target: parent.to_path_buf(),
                detail: format!("could not create private cache parent: {e}"),
            });
        }

        // Generate a random 16-byte hex suffix. Read from /dev/urandom directly
        // (no external crate) — 16 bytes give 128 bits of randomness, making a
        // collision or a successful pre-plant computationally infeasible.
        let random_suffix = {
            use std::io::Read as _;
            let mut buf = [0u8; 16];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut buf))
                .map_err(|e| RunJailDefect::MountFailed {
                    target: parent.to_path_buf(),
                    detail: format!("could not read /dev/urandom for random dir suffix: {e}"),
                })?;
            buf.iter().fold(String::with_capacity(32), |mut hex, b| {
                use std::fmt::Write as _;
                // Writing into a `String` cannot fail.
                let _ = write!(hex, "{b:02x}");
                hex
            })
        };

        let leaf = parent.join(format!("{prefix}-{random_suffix}"));

        // Exclusive create: EEXIST is a hard refusal, not a retry. A pre-existing
        // entry at this path — even with 128 bits of randomness — means either a
        // collision (astronomically unlikely) or an active attacker; either way,
        // fail closed rather than reuse an entry we did not create.
        std::fs::DirBuilder::new()
            .recursive(false)
            .create(&leaf)
            .map_err(|e| RunJailDefect::MountFailed {
                target: leaf.clone(),
                detail: format!(
                    "exclusive create of per-run jail dir failed (pre-existing or \
                     permission denied): {e}"
                ),
            })?;

        // Verify every newly-created component is a real directory owned by the
        // current uid. `symlink_metadata` does NOT follow symlinks, so a symlink
        // planted between `create_dir` and here is caught as a non-directory
        // entry and refused.
        // The effective uid owns what this process creates.
        let current_uid = rustix::process::geteuid().as_raw();
        for ancestor in [parent, leaf.as_path()] {
            let meta =
                std::fs::symlink_metadata(ancestor).map_err(|e| RunJailDefect::MountFailed {
                    target: ancestor.to_path_buf(),
                    detail: format!("could not stat jail dir component: {e}"),
                })?;
            if !meta.is_dir() {
                return Err(RunJailDefect::MountFailed {
                    target: ancestor.to_path_buf(),
                    detail: "jail dir component is not a real directory (symlink or file \
                             present at expected location)"
                        .to_owned(),
                });
            }
            if meta.uid() != current_uid {
                return Err(RunJailDefect::MountFailed {
                    target: ancestor.to_path_buf(),
                    detail: format!(
                        "jail dir component is owned by uid {} not the current uid {}; \
                         refusing to use a directory we do not own",
                        meta.uid(),
                        current_uid,
                    ),
                });
            }
        }

        Ok(leaf)
    }

    /// A per-run jail-root dir, created exclusively under the private cache root.
    ///
    /// Uses a random unique name under `~/.cache/ipe/jail/` (not world-writable
    /// `/tmp`) so a local same-user-class attacker cannot pre-plant or symlink the
    /// path before the nullfs mount.
    fn jail_root_dir() -> Result<PathBuf, RunJailDefect> {
        create_exclusive_private_dir(&private_cache_root()?, "jailroot")
    }

    /// A per-run parent dir for the empty `/proc`-mask source, created exclusively
    /// under the private cache root — NOT under the read-write scratch and NOT
    /// under the chroot root. The jailed payload has no mount into it, so the
    /// empty dir it holds (the read-only `/proc` mask's nullfs source) is immutable
    /// to the payload: it cannot surface files under its own `/proc`. Uses a
    /// random unique name under `~/.cache/ipe/jail/` (not world-writable `/tmp`).
    fn proc_mask_source_dir() -> Result<PathBuf, RunJailDefect> {
        create_exclusive_private_dir(&private_cache_root()?, "procmask")
    }

    /// A per-run jail name unique enough that concurrent audit calls do not collide.
    fn per_run_jail_name() -> String {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        format!("ipe_tier2_{pid}_{nanos}")
    }

    /// An `rctl(8)` process-cap rule (`jail:NAME:maxproc:deny=1`) applied for a
    /// withheld-subprocess jail and removed on drop, so a withheld subprocess axis
    /// is a genuine kernel denial of process creation and no rule leaks across the
    /// audit loop.
    struct RctlRule {
        rctl_bin: std::path::PathBuf,
        rule: String,
    }

    impl RctlRule {
        fn apply(rctl_bin: &Path, jail_name: &str) -> Result<Self, RunJailDefect> {
            let rule = format!("jail:{jail_name}:maxproc:deny=1");
            let status = std::process::Command::new(rctl_bin)
                .arg("-a")
                .arg(&rule)
                .status();
            match status {
                Ok(s) if s.success() => Ok(Self {
                    rctl_bin: rctl_bin.to_path_buf(),
                    rule,
                }),
                Ok(s) => Err(RunJailDefect::Spawn {
                    detail: format!(
                        "rctl could not deny process creation for the withheld-subprocess jail \
                         ({s}); refusing to run without a kernel process-creation denial"
                    ),
                }),
                Err(e) => Err(RunJailDefect::Spawn {
                    detail: format!("could not run rctl to deny process creation: {e}"),
                }),
            }
        }
    }

    impl Drop for RctlRule {
        fn drop(&mut self) {
            // Best-effort removal of the rule this guard added; a leftover rule on a
            // torn-down (`persist=0`) jail is inert, but remove it so the audit loop
            // leaves no residue.
            let _ = std::process::Command::new(&self.rctl_bin)
                .arg("-r")
                .arg(&self.rule)
                .status();
        }
    }

    /// Spawn the jail argv with the scrubbed environment, wait, and decode the exit
    /// into a [`JailOutcome`]. A spawn failure is `Unavailable` (the payload never
    /// ran); a wait failure is `BuildFailed` (the jail ran but its result is
    /// unobservable — never clean); the exit code decodes through the SAME
    /// [`JailOutcome::decode`] the other arms use.
    fn spawn_and_decode(argv: &[OsString], scrubbed: &[(OsString, OsString)]) -> JailOutcome {
        let Some((program, rest)) = argv.split_first() else {
            return JailOutcome::Unavailable {
                defect: RunJailDefect::Spawn {
                    detail: "empty jail argv".to_owned(),
                },
            };
        };
        let mut command = std::process::Command::new(program);
        command.args(rest).stdin(std::process::Stdio::null());
        command.env_clear();
        for (name, value) in scrubbed {
            command.env(name, value);
        }
        let child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                return JailOutcome::Unavailable {
                    defect: RunJailDefect::Spawn {
                        detail: e.to_string(),
                    },
                };
            }
        };
        let mut child = child;
        match child.wait() {
            Ok(status) => JailOutcome::decode(status.code()),
            Err(e) => JailOutcome::BuildFailed {
                reason: format!("could not await the jailed probe: {e}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_exit_is_the_only_clean_outcome() {
        assert_eq!(
            JailOutcome::decode(Some(AXIS_EXIT_CLEAN)),
            JailOutcome::Clean
        );
        assert!(JailOutcome::decode(Some(AXIS_EXIT_CLEAN)).is_clean());
    }

    #[test]
    fn a_network_denial_exit_names_the_network_axis() {
        assert_eq!(
            JailOutcome::decode(Some(AXIS_EXIT_NETWORK)),
            JailOutcome::Denied {
                axis: CapabilityAxis::Network
            }
        );
    }

    #[test]
    fn a_filesystem_denial_exit_names_the_filesystem_axis() {
        assert_eq!(
            JailOutcome::decode(Some(AXIS_EXIT_FILESYSTEM)),
            JailOutcome::Denied {
                axis: CapabilityAxis::Filesystem
            }
        );
    }

    #[test]
    fn an_ordinary_nonzero_exit_is_a_build_failure_never_clean() {
        // A compile error (exit 1) is a build failure, not a capability denial —
        // both reject, the distinction only shapes the diagnostic.
        let o = JailOutcome::decode(Some(1));
        assert!(matches!(o, JailOutcome::BuildFailed { .. }));
        assert!(!o.is_clean());
    }

    #[test]
    fn an_unrecognised_exit_code_decodes_fail_closed_to_non_clean() {
        // A garbled / unexpected exit code is NOT clean and NOT a named denial —
        // fail-closed to BuildFailed so ambiguity can never admit.
        for code in [7, 42, 99, 125, 255, i32::MIN, i32::MAX] {
            let o = JailOutcome::decode(Some(code));
            assert!(
                matches!(o, JailOutcome::BuildFailed { .. }),
                "exit {code} must decode to BuildFailed, got {o:?}"
            );
            assert!(!o.is_clean(), "exit {code} must not be clean");
        }
    }

    #[test]
    fn a_signal_kill_with_no_exit_code_is_a_build_failure_never_clean() {
        // Killed by a signal or the wall clock ⇒ no exit code ⇒ never clean.
        let o = JailOutcome::decode(None);
        assert!(matches!(o, JailOutcome::BuildFailed { .. }));
        assert!(!o.is_clean());
    }

    #[test]
    fn the_tier2_build_failed_hinge_decodes_to_build_failed_never_clean() {
        // The wrapper's ordinary-child-build-failure code (6) MUST decode to a
        // reject, never Clean — the hinge on which a false certify would turn.
        let o = JailOutcome::decode(Some(TIER2_EXIT_BUILD_FAILED));
        assert!(matches!(o, JailOutcome::BuildFailed { .. }), "got {o:?}");
        assert!(!o.is_clean());
        // It is NOT a per-axis denial (disjoint from 10/11 and from the clean 0).
        assert!(CapabilityAxis::from_exit_code(TIER2_EXIT_BUILD_FAILED).is_none());
        assert_ne!(TIER2_EXIT_BUILD_FAILED, AXIS_EXIT_CLEAN);
    }

    #[test]
    fn the_per_axis_codes_are_disjoint_from_the_control_range() {
        // The Tier-2 per-axis codes must not collide with the enforce/control
        // codes 2–5, or a broken-jail control failure would read as a denial.
        for control in [2, 3, 4, 5] {
            assert!(CapabilityAxis::from_exit_code(control).is_none());
        }
        assert_eq!(
            CapabilityAxis::from_exit_code(AXIS_EXIT_NETWORK),
            Some(CapabilityAxis::Network)
        );
        assert_eq!(
            CapabilityAxis::from_exit_code(AXIS_EXIT_FILESYSTEM),
            Some(CapabilityAxis::Filesystem)
        );
    }

    #[test]
    fn axis_names_match_the_capability_wire_vocabulary() {
        assert_eq!(CapabilityAxis::Network.as_str(), "network");
        assert_eq!(CapabilityAxis::Filesystem.as_str(), "filesystem");
    }

    #[test]
    fn only_the_clean_variant_is_admit_eligible() {
        assert!(JailOutcome::Clean.is_clean());
        assert!(
            !JailOutcome::Denied {
                axis: CapabilityAxis::Network
            }
            .is_clean()
        );
        assert!(
            !JailOutcome::BuildFailed {
                reason: "x".to_owned()
            }
            .is_clean()
        );
        assert!(
            !JailOutcome::Unavailable {
                defect: RunJailDefect::UnsupportedPlatform { reason: "x" }
            }
            .is_clean()
        );
    }

    // ── the macOS SBPL lowering (pure text — runs on any host) ────────────────
    //
    // These prove the SBPL the macOS jail feeds `sandbox-exec` denies exactly the
    // withheld axis and confines writes to the scratch. They are the primary
    // local verification of the macOS confinement; the jail's *runtime* deny
    // behaviour is the macos-latest CI job.

    fn scoped(network: bool, filesystem: FilesystemScope) -> SandboxProfile {
        SandboxProfile {
            network,
            filesystem,
            ..SandboxProfile::maximally_isolated()
        }
    }

    fn sbpl_mounts(cargo_home: &str) -> Result<JailMounts, crate::JailPathError> {
        JailMounts::checked_against(
            crate::CanonicalPath::assumed("/work/scratch"),
            crate::CanonicalPath::assumed("/work/tree"),
            Vec::new(),
            crate::HomeMasks::unmasked(),
            Path::new(cargo_home),
        )
    }

    #[test]
    fn checked_sbpl_refuses_a_cargo_home_under_a_fixed_read_root() {
        let p = SandboxProfile::maximally_isolated();
        for cargo_home in ["/usr/local/cargo", "/opt/cargo", "/usr", "/Library/cargo"] {
            let mounts = sbpl_mounts(cargo_home).expect("no mount covers the cargo home");
            assert!(
                matches!(
                    checked_sbpl(&p, &mounts),
                    Err(crate::JailPathError::ExposesCargoHome { .. })
                ),
                "a Seatbelt read root covering {cargo_home} is refused"
            );
        }
        let mounts = sbpl_mounts("/nonexistent-ipe-user/.cargo").expect("disjoint cargo home");
        let sbpl = checked_sbpl(&p, &mounts).expect("no read root covers the cargo home");
        for root in MACOS_READ_ROOTS {
            assert!(
                sbpl.contains(&format!("(allow file-read* (subpath \"{root}\"))")),
                "read root {root} is allowed: {sbpl}"
            );
        }
        assert!(!sbpl.contains("/nonexistent-ipe-user"), "{sbpl}");
    }

    #[test]
    fn sbpl_denies_network_when_the_network_axis_is_withheld() {
        let p = scoped(false, FilesystemScope::Isolated);
        let sbpl = sbpl_from_profile(&p, Path::new("/tmp/scratch"), Path::new("/work/tree"), &[]);
        assert!(sbpl.starts_with("(version 1)"), "{sbpl}");
        assert!(sbpl.contains("(allow default)"), "{sbpl}");
        // Every network-denial rule is present when the axis is withheld.
        for rule in [
            "(deny network*)",
            "(deny network-outbound)",
            "(deny network-inbound)",
            "(deny network-bind)",
        ] {
            assert!(sbpl.contains(rule), "missing {rule}: {sbpl}");
        }
    }

    #[test]
    fn sbpl_allows_network_when_the_network_axis_is_granted() {
        let p = scoped(true, FilesystemScope::Isolated);
        let sbpl = sbpl_from_profile(&p, Path::new("/tmp/scratch"), Path::new("/work/tree"), &[]);
        // A granted network axis emits NO network denial, so the allow-default
        // base leaves the network reachable.
        assert!(
            !sbpl.contains("(deny network"),
            "network granted must emit no network denial: {sbpl}"
        );
    }

    #[test]
    fn sbpl_confines_writes_to_the_scratch_when_filesystem_is_withheld() {
        let p = scoped(false, FilesystemScope::Isolated);
        // A non-firmlink scratch prefix, so this structural assertion is about the
        // deny+re-allow shape, not the macOS symlink resolution (which its own
        // tests cover); such a path is rendered unchanged.
        let sbpl = sbpl_from_profile(&p, Path::new("/work/scratch"), Path::new("/work/tree"), &[]);
        // A blanket write denial, then the scratch re-allowed — an out-of-scratch
        // write is denied so the filesystem axis is observable.
        assert!(sbpl.contains("(deny file-write*)"), "{sbpl}");
        assert!(
            sbpl.contains("(allow file-write* (subpath \"/work/scratch\"))"),
            "scratch must be writable: {sbpl}"
        );
        // The working tree is NOT writable under a filesystem-withholding profile.
        assert!(
            !sbpl.contains("(allow file-write* (subpath \"/work/tree\"))"),
            "the working tree must not be writable when filesystem is withheld: {sbpl}"
        );
    }

    #[test]
    fn sbpl_does_not_blanket_allow_the_per_user_temp_tree() {
        // The scratch lives under the macOS per-user temp tree (`$TMPDIR`, which
        // resolves through the `/var → /private/var` symlink to
        // `/private/var/folders/…`). A blanket write allow over that tree — or
        // over `/private/tmp` — would re-permit every SIBLING of the scratch, so
        // an out-of-scratch write placed next to the scratch would succeed and
        // the differential filesystem confinement would leak. The ONLY write
        // allow must be the scratch subpath itself; the enclosing temp tree must
        // NOT be allowed. Guards the fail-closed intent host-independently (the
        // real deny is proven by the `macos-run-jail` E2E on a macOS runner).
        let scratch = Path::new("/private/var/folders/ab/xxxx/T/ipe-run-scratch");
        let p = scoped(false, FilesystemScope::Isolated);
        let sbpl = sbpl_from_profile(&p, scratch, Path::new("/work/tree"), &[]);
        assert!(
            sbpl.contains(
                "(allow file-write* (subpath \"/private/var/folders/ab/xxxx/T/ipe-run-scratch\"))"
            ),
            "the scratch subpath must be the write allow: {sbpl}"
        );
        assert!(
            !sbpl.contains("(allow file-write* (subpath \"/private/var/folders\"))"),
            "the per-user temp tree must NOT be blanket-allowed (it encloses the \
             scratch, so it would re-permit an out-of-scratch sibling write): {sbpl}"
        );
        assert!(
            !sbpl.contains("(allow file-write* (subpath \"/private/tmp\"))"),
            "the system temp tree must NOT be blanket-allowed: {sbpl}"
        );
    }

    #[test]
    fn sbpl_renders_the_scratch_allow_in_its_symlink_resolved_form() {
        // Seatbelt matches a `(subpath …)` allow against the KERNEL-RESOLVED write
        // path. On macOS the per-user temp tree is reached through the
        // `/var → /private/var` firmlink, so a scratch handed in as
        // `/var/folders/…/T/…` is written by the kernel as `/private/var/folders/…`.
        // The allow MUST therefore render in the resolved `/private/var` form, or a
        // legitimate in-scratch write is FALSE-DENIED (the E2E
        // `an_in_scratch_write_succeeds_under_the_run_jail` regression). This asserts
        // the resolution host-independently via the explicit-firmlink fallback (the
        // scratch path does not exist on a Linux CI host, so `canonicalize` cannot
        // run — the deterministic prefix rewrite is exercised). The real runner
        // proves the same allow via `canonicalize` on the macos-run-jail E2E.
        let unresolved = Path::new("/var/folders/ab/xxxx/T/ipe-run-scratch");
        let p = scoped(false, FilesystemScope::Isolated);
        let sbpl = sbpl_from_profile(&p, unresolved, Path::new("/work/tree"), &[]);
        assert!(
            sbpl.contains(
                "(allow file-write* (subpath \"/private/var/folders/ab/xxxx/T/ipe-run-scratch\"))"
            ),
            "the scratch allow must render in the resolved /private/var form so it \
             covers the kernel-resolved write: {sbpl}"
        );
        // The unresolved `/var` form must NOT appear — it would not match the write.
        assert!(
            !sbpl.contains("(subpath \"/var/folders/ab/xxxx/T/ipe-run-scratch\"))"),
            "the unresolved /var form must not be emitted (it would false-deny): {sbpl}"
        );
        // Resolving must NOT widen the allow to the enclosing per-user temp tree:
        // the out-of-scratch deny stays intact (a sibling of the scratch resolves to
        // a sibling of the resolved scratch, still outside the allowed subtree).
        assert!(
            !sbpl.contains("(allow file-write* (subpath \"/private/var/folders\"))"),
            "resolving must not blanket-allow the enclosing temp tree: {sbpl}"
        );
        assert!(
            !sbpl.contains("(allow file-write* (subpath \"/private/var\"))"),
            "resolving must not blanket-allow /private/var: {sbpl}"
        );
    }

    #[test]
    fn sbpl_denies_file_reads_by_default_and_does_not_allow_home() {
        // The macOS jail must confine file READS: without a `(deny file-read*)`
        // base, the allow-default profile leaves the whole home directory readable,
        // so a network-granted build could read `~/.ssh` and exfiltrate it. The read
        // allow set must be the system/toolchain roots plus the scratch and working
        // tree — never the user's home. Home stays denied even when network is
        // granted.
        let p = scoped(true, FilesystemScope::Isolated);
        let sbpl = sbpl_from_profile(&p, Path::new("/work/scratch"), Path::new("/work/tree"), &[]);
        assert!(
            sbpl.contains("(deny file-read*)"),
            "reads must be denied by default: {sbpl}"
        );
        // The scratch and the source tree are readable (the build reads its source
        // whether or not it may WRITE it).
        assert!(
            sbpl.contains("(allow file-read* (subpath \"/work/scratch\"))"),
            "the scratch must be readable: {sbpl}"
        );
        assert!(
            sbpl.contains("(allow file-read* (subpath \"/work/tree\"))"),
            "the working tree must be readable: {sbpl}"
        );
        // The system/toolchain roots the shell and compiler need are readable.
        for root in ["/usr", "/System", "/Library"] {
            assert!(
                sbpl.contains(&format!("(allow file-read* (subpath \"{root}\"))")),
                "the system root {root} must be readable: {sbpl}"
            );
        }
        // The user's home is NOT re-allowed — no read allow covers `/Users` or
        // `/home`, so a home secret stays unreadable even with network granted.
        assert!(
            !sbpl.contains("(allow file-read* (subpath \"/Users\"))"),
            "the user home must NOT be blanket-read-allowed: {sbpl}"
        );
        assert!(
            !sbpl.contains("(allow file-read* (subpath \"/home\"))"),
            "the user home must NOT be blanket-read-allowed: {sbpl}"
        );
    }

    #[test]
    fn sbpl_read_allow_for_the_working_tree_is_independent_of_the_write_grant() {
        // A build reads its source tree regardless of whether the filesystem axis
        // grants WRITE access. The read allow for the working tree must therefore be
        // present under BOTH an isolated and a read-write filesystem scope, while the
        // WRITE allow stays gated on the grant.
        let isolated = scoped(false, FilesystemScope::Isolated);
        let sbpl_iso = sbpl_from_profile(
            &isolated,
            Path::new("/work/scratch"),
            Path::new("/work/tree"),
            &[],
        );
        assert!(
            sbpl_iso.contains("(allow file-read* (subpath \"/work/tree\"))"),
            "the source tree must be readable even when writes are withheld: {sbpl_iso}"
        );
        assert!(
            !sbpl_iso.contains("(allow file-write* (subpath \"/work/tree\"))"),
            "the working tree must NOT be writable when the axis is withheld: {sbpl_iso}"
        );
    }

    #[test]
    fn macos_resolved_subpath_rewrites_firmlink_prefixes_without_widening() {
        // The resolver maps the two macOS firmlink prefixes to their resolved form
        // and leaves every other path (including an already-resolved one) untouched
        // — a pure prefix rewrite, never a widening to a parent. (The `canonicalize`
        // branch cannot run for these non-existent paths, so the fallback is
        // exercised deterministically on any host.)
        assert_eq!(
            macos_resolved_subpath(Path::new("/var/folders/x/T/s")),
            PathBuf::from("/private/var/folders/x/T/s")
        );
        assert_eq!(
            macos_resolved_subpath(Path::new("/tmp/s")),
            PathBuf::from("/private/tmp/s")
        );
        // Already resolved — unchanged (no double `/private`).
        assert_eq!(
            macos_resolved_subpath(Path::new("/private/var/folders/x/T/s")),
            PathBuf::from("/private/var/folders/x/T/s")
        );
        // A non-firmlink path — unchanged.
        assert_eq!(
            macos_resolved_subpath(Path::new("/work/tree")),
            PathBuf::from("/work/tree")
        );
        // Component-wise matching: `/variant` is NOT under the `/var` firmlink, so
        // it must not be rewritten (a naive string prefix would corrupt it).
        assert_eq!(
            macos_resolved_subpath(Path::new("/variant/x")),
            PathBuf::from("/variant/x")
        );
    }

    #[test]
    fn sbpl_grants_the_working_tree_write_when_filesystem_is_granted() {
        let p = scoped(false, FilesystemScope::WorkingTreeReadWrite);
        let sbpl = sbpl_from_profile(&p, Path::new("/work/scratch"), Path::new("/work/tree"), &[]);
        // The blanket deny stays (so a path outside BOTH scratch and tree is
        // still denied), and the working tree is re-allowed.
        assert!(sbpl.contains("(deny file-write*)"), "{sbpl}");
        assert!(
            sbpl.contains("(allow file-write* (subpath \"/work/tree\"))"),
            "the working tree must be writable when filesystem is granted: {sbpl}"
        );
    }

    #[test]
    fn sbpl_denies_vcs_writes_at_any_depth_case_insensitively() {
        let p = scoped(false, FilesystemScope::WorkingTreeReadWrite);
        let carve = [Path::new("/work/tree/.git"), Path::new("/work/scratch/gd")];
        let sbpl = sbpl_from_profile(
            &p,
            Path::new("/work/scratch"),
            Path::new("/work/tree"),
            &carve,
        );
        let at = |rule: &str| sbpl.find(rule);
        let names = format!(
            "(deny file-write* (require-all (subpath \"/work/tree\") (regex #\"{}\")))",
            vcs_name_regex()
        );
        let found = (
            at("(allow file-write* (subpath \"/work/scratch\"))"),
            at("(allow file-write* (subpath \"/work/tree\"))"),
            at("(deny file-write* (subpath \"/work/tree/.git\"))"),
            at("(deny file-write* (subpath \"/work/scratch/gd\"))"),
            at(&names),
        );
        assert!(
            matches!(
                found,
                (Some(scratch), Some(tree), Some(git), Some(gd), Some(name))
                    if scratch < tree && tree < git && git < gd && gd < name
            ),
            "each carve and the name rule are denied after both write allows, so they win: {found:?} in {sbpl}"
        );
        let isolated = sbpl_from_profile(
            &scoped(false, FilesystemScope::Isolated),
            Path::new("/work/scratch"),
            Path::new("/work/tree"),
            &carve,
        );
        assert!(
            !isolated.contains("/work/tree/.git") && !isolated.contains(&names),
            "an ungranted tree is never writable, so it renders no carve: {isolated}"
        );
    }

    #[test]
    fn sbpl_vcs_regex_matches_the_ssot() {
        assert_eq!(
            vcs_name_regex(),
            r"/(\.[Gg][Ii][Tt]|\.[Hh][Gg]|\.[Jj][Jj]|_[Dd][Aa][Rr][Cc][Ss])(/|$)"
        );
        let regex = vcs_name_regex();
        for kind in crate::VcsKind::ALL {
            let upper = kind.entry_name().to_ascii_uppercase();
            let letters: String = upper.chars().filter(char::is_ascii_alphabetic).collect();
            let classes: String = regex
                .split('|')
                .find(|alt| {
                    alt.chars()
                        .filter(char::is_ascii_uppercase)
                        .eq(letters.chars())
                })
                .unwrap_or_default()
                .to_owned();
            assert!(
                !classes.is_empty(),
                "{kind} has an alternative in the name rule: {regex}"
            );
        }
        assert_eq!(
            regex.matches('|').count(),
            crate::VcsKind::ALL.len(),
            "one alternative per kind, plus the `(/|$)` tail: {regex}"
        );
    }

    #[test]
    fn sbpl_carve_path_cannot_break_out_of_its_string() {
        let p = scoped(false, FilesystemScope::WorkingTreeReadWrite);
        let crafted = Path::new(r#"/work/tree/x") (allow file-write* (subpath "/"#);
        let sbpl = sbpl_from_profile(
            &p,
            Path::new("/work/scratch"),
            Path::new("/work/tree"),
            &[crafted],
        );
        assert!(
            sbpl.contains(
                r#"(deny file-write* (subpath "/work/tree/x\") (allow file-write* (subpath \"/"))"#
            ),
            "the carve stays one escaped string: {sbpl}"
        );
        assert!(
            !sbpl.contains(r#"(allow file-write* (subpath "/"))"#),
            "no rule is injected: {sbpl}"
        );
    }

    #[test]
    fn sbpl_escapes_quotes_and_backslashes_in_paths() {
        // A scratch path with an embedded quote/backslash must not break the SBPL
        // grammar — both are escaped so a crafted path cannot inject a rule.
        let p = scoped(false, FilesystemScope::Isolated);
        // A non-firmlink prefix isolates this assertion to the escaping, not the
        // macOS symlink resolution.
        let sbpl = sbpl_from_profile(
            &p,
            Path::new("/work/scr\"atch\\x"),
            Path::new("/work/tree"),
            &[],
        );
        assert!(
            sbpl.contains("(allow file-write* (subpath \"/work/scr\\\"atch\\\\x\"))"),
            "the quote and backslash must be escaped: {sbpl}"
        );
    }

    #[test]
    fn sbpl_maximally_isolated_denies_network_and_confines_writes() {
        // The floor: nothing granted → network denied, writes confined to scratch.
        let sbpl = sbpl_from_profile(
            &SandboxProfile::maximally_isolated(),
            Path::new("/s"),
            Path::new("/w"),
            &[],
        );
        assert!(sbpl.contains("(deny network*)"), "{sbpl}");
        assert!(sbpl.contains("(deny file-write*)"), "{sbpl}");
        assert!(
            !sbpl.contains("(allow file-write* (subpath \"/w\"))"),
            "no working-tree write on the isolated floor: {sbpl}"
        );
    }

    fn with_subprocess(subprocess: bool) -> SandboxProfile {
        SandboxProfile {
            subprocess,
            ..SandboxProfile::maximally_isolated()
        }
    }

    #[test]
    fn sbpl_denies_process_creation_when_the_subprocess_axis_is_withheld() {
        // Withheld subprocess ⇒ the NEW-process denial (`process-fork`) is present,
        // mirroring the Linux seccomp denial of the task-creation family and
        // closing the native-ffi-via-a-helper escape (a helper is a new process, so
        // it must fork). `process-exec*` is deliberately NOT denied: Seatbelt
        // applies the profile before `sandbox-exec` execs the target in place, so an
        // exec denial would refuse that mandatory initial exec and the app would
        // never start (see `sbpl_from_profile`). A fork denial alone confines the
        // app to a single process while permitting the launcher's initial exec.
        let sbpl = sbpl_from_profile(
            &with_subprocess(false),
            Path::new("/tmp/scratch"),
            Path::new("/work/tree"),
            &[],
        );
        assert!(sbpl.contains("(deny process-fork)"), "{sbpl}");
        assert!(
            !sbpl.contains("(deny process-exec"),
            "the initial target exec must stay permitted (Seatbelt applies the \
             profile before exec'ing the target): {sbpl}"
        );
    }

    #[test]
    fn sbpl_allows_process_creation_when_the_subprocess_axis_is_granted() {
        // Granted subprocess ⇒ NO process denial, so the allow-default base
        // leaves spawning reachable (no false-deny of a granted axis).
        let sbpl = sbpl_from_profile(
            &with_subprocess(true),
            Path::new("/tmp/scratch"),
            Path::new("/work/tree"),
            &[],
        );
        assert!(
            !sbpl.contains("(deny process-exec"),
            "subprocess granted must emit no process-exec denial: {sbpl}"
        );
        assert!(
            !sbpl.contains("(deny process-fork)"),
            "subprocess granted must emit no process-fork denial: {sbpl}"
        );
    }

    #[test]
    fn maximally_isolated_sbpl_denies_all_four_confinement_axes() {
        // The floor enforces every runtime-enforced axis Seatbelt CAN enforce:
        // network, filesystem, subprocess. (Env is enforced by the launcher, not
        // the SBPL — see `macos_scrubbed_env`.) This is the `Holds`-is-honest
        // invariant: `Holds` may only claim axes the jail actually confines. The
        // subprocess axis is the NEW-process denial (`process-fork`); the initial
        // target exec must stay permitted, so `process-exec*` is NOT denied (see
        // `sbpl_from_profile`).
        let sbpl = sbpl_from_profile(
            &SandboxProfile::maximally_isolated(),
            Path::new("/s"),
            Path::new("/w"),
            &[],
        );
        assert!(sbpl.contains("(deny network*)"), "network: {sbpl}");
        assert!(sbpl.contains("(deny file-write*)"), "filesystem: {sbpl}");
        assert!(
            sbpl.contains("(deny process-fork)"),
            "subprocess fork: {sbpl}"
        );
        assert!(
            !sbpl.contains("(deny process-exec"),
            "the initial target exec must stay permitted: {sbpl}"
        );
    }

    #[test]
    fn sbpl_unconditionally_denies_the_inspection_and_exfiltration_baseline() {
        // The baseline deny set must appear in EVERY SBPL, independent of the
        // profile's axis grants. These are the macOS counterparts of the Linux
        // seccomp baseline-denied set — escape and exfiltration primitives no
        // legitimate declared effect needs. Asserting them on both the maximally
        // isolated and the fully-granted profile proves they are unconditional.
        for profile in [
            SandboxProfile::maximally_isolated(),
            SandboxProfile {
                network: true,
                filesystem: FilesystemScope::WorkingTreeReadWrite,
                env_allowlist: vec!["PATH".to_owned()],
                subprocess: true,
                ..SandboxProfile::maximally_isolated()
            },
        ] {
            let sbpl = sbpl_from_profile(&profile, Path::new("/s"), Path::new("/w"), &[]);
            assert!(
                sbpl.contains("(deny process-info*)"),
                "process-info* (ptrace-equivalent inspection) must be unconditionally \
                 denied: {sbpl}"
            );
            assert!(
                sbpl.contains("(deny mach-task-name)"),
                "mach-task-name (cross-process task-port / memory-injection surface) \
                 must be unconditionally denied: {sbpl}"
            );
            assert!(
                sbpl.contains("(deny sysctl-read)"),
                "sysctl-read (host fingerprinting surface) must be unconditionally \
                 denied: {sbpl}"
            );
        }
    }

    // ── the macOS env-axis launcher scrub (pure — runs on any host) ───────────

    fn env_map(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, OsString> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(*v)))
            .collect()
    }

    #[test]
    fn scrubbed_env_keeps_only_the_base_when_no_env_axis_is_granted() {
        // An env-withholding profile re-exports only the fixed base (PATH, TMPDIR,
        // and LANG when the host sets it); every other host var is dropped.
        let host = env_map(&[("SECRET", "leak"), ("LANG", "en_US.UTF-8")]);
        let lookup = |k: &str| host.get(k).cloned();
        let env = macos_scrubbed_env(
            &SandboxProfile::maximally_isolated(),
            Path::new("/tmp/scratch"),
            &lookup,
        );
        let names: Vec<&str> = env
            .iter()
            .map(|(n, _)| n.to_str().unwrap_or_default())
            .collect();
        assert!(names.contains(&"PATH"), "{names:?}");
        assert!(names.contains(&"TMPDIR"), "{names:?}");
        assert!(names.contains(&"LANG"), "{names:?}");
        assert!(
            !names.contains(&"SECRET"),
            "a non-allowlisted host var must be dropped: {names:?}"
        );
        // TMPDIR is the scratch, matching the Linux jail.
        let tmpdir = env
            .iter()
            .find(|(n, _)| n == "TMPDIR")
            .map(|(_, v)| v.clone());
        assert_eq!(tmpdir, Some(OsString::from("/tmp/scratch")));
    }

    #[test]
    fn scrubbed_env_re_exports_only_allowlisted_names_that_the_host_sets() {
        // A granted env name that the host sets re-enters; a granted name the host
        // does NOT set is simply absent (never a placeholder); a host var not on
        // the allowlist stays dropped.
        let host = env_map(&[("ALLOWED", "yes"), ("SECRET", "leak")]);
        let lookup = |k: &str| host.get(k).cloned();
        let profile = SandboxProfile {
            env_allowlist: vec!["ALLOWED".to_owned(), "GRANTED_BUT_UNSET".to_owned()],
            ..SandboxProfile::maximally_isolated()
        };
        let env = macos_scrubbed_env(&profile, Path::new("/s"), &lookup);
        let by_name: std::collections::HashMap<String, OsString> = env
            .iter()
            .map(|(n, v)| (n.to_string_lossy().into_owned(), v.clone()))
            .collect();
        assert_eq!(by_name.get("ALLOWED"), Some(&OsString::from("yes")));
        assert!(
            !by_name.contains_key("GRANTED_BUT_UNSET"),
            "a granted-but-unset name must be absent, not a placeholder"
        );
        assert!(
            !by_name.contains_key("SECRET"),
            "a non-allowlisted host var must be dropped even when the host sets it"
        );
    }

    // ── the Windows exit-code mapping (pure — runs on any host) ───────────────
    //
    // The Windows arm reads a `u32` from `GetExitCodeProcess` and decodes it
    // through the SAME `JailOutcome::decode` the other arms use. These prove the
    // `u32 -> i32` bridge keeps the wrapper-owned per-axis contract intact and
    // fails closed on an out-of-range code.

    #[test]
    fn windows_exit_maps_the_per_axis_codes_identically() {
        // The wrapper-owned codes (clean/build-failed/network/filesystem) round-trip
        // unchanged, so the Windows arm decodes them exactly as the Unix arms do.
        for code in [
            AXIS_EXIT_CLEAN,
            TIER2_EXIT_BUILD_FAILED,
            AXIS_EXIT_NETWORK,
            AXIS_EXIT_FILESYSTEM,
        ] {
            let mapped = win_exit_to_i32(u32::try_from(code).expect("small code"));
            assert_eq!(mapped, code, "code {code} must round-trip");
        }
    }

    #[test]
    fn windows_clean_exit_decodes_to_clean_and_only_clean() {
        assert_eq!(
            JailOutcome::decode(Some(win_exit_to_i32(0))),
            JailOutcome::Clean
        );
        // A network / filesystem denial names its axis after the u32 bridge.
        assert_eq!(
            JailOutcome::decode(Some(win_exit_to_i32(10))),
            JailOutcome::Denied {
                axis: CapabilityAxis::Network
            }
        );
        assert_eq!(
            JailOutcome::decode(Some(win_exit_to_i32(11))),
            JailOutcome::Denied {
                axis: CapabilityAxis::Filesystem
            }
        );
    }

    #[test]
    fn windows_high_bit_exit_is_build_failed_never_clean_or_denied() {
        // A high-bit exit code (a process that exited with e.g. 0xC000_0005) must
        // never alias a per-axis code or the clean 0 — it saturates to a value that
        // decodes to BuildFailed. Fail-closed: ambiguity can never admit.
        for code in [0x8000_0000u32, 0xC000_0005u32, u32::MAX] {
            let outcome = JailOutcome::decode(Some(win_exit_to_i32(code)));
            assert!(
                matches!(outcome, JailOutcome::BuildFailed { .. }),
                "high-bit exit {code:#x} must decode to BuildFailed, got {outcome:?}"
            );
            assert!(!outcome.is_clean());
        }
    }

    // The FreeBSD `jail_argv` builder lives behind `cfg(target_os = "freebsd")`, so
    // its exact argv cannot be asserted off FreeBSD. What is portable — and is the
    // property the CI failure hinged on — is that the payload is threaded to
    // `jail(8)` as ONE OS-level argv element per token (no space-joined string, no
    // quoting): `command=<tok0>` plus each remaining token as its own element. This
    // pure helper models exactly that mapping so the space-bearing-path invariant is
    // provable on any host; `jail_argv` calls the same shape.
    fn jail_command_args(payload: &[std::ffi::OsString]) -> Vec<std::ffi::OsString> {
        let mut out: Vec<std::ffi::OsString> = Vec::new();
        let mut command = std::ffi::OsString::from("command=");
        let Some((first, rest)) = payload.split_first() else {
            out.push(command);
            return out;
        };
        command.push(first);
        out.push(command);
        for tok in rest {
            out.push(tok.clone());
        }
        out
    }

    #[test]
    fn each_payload_token_is_its_own_jail_command_arg_intact() {
        use std::ffi::OsString;

        // `jail(8)` execvp's `command` with NO shell and NO quote removal — one
        // command-line argument per argv slot. A path with a space, an embedded
        // single quote, and a shell metacharacter must each stay exactly one intact
        // argv element (the space must NOT split a path, the quote/metachar must NOT
        // be interpreted), which passing each token as its own OS-level argument
        // guarantees.
        let payload = [
            OsString::from("/usr/bin/env"),
            OsString::from("PROBE_MODE=tier2"),
            OsString::from("/tmp/dir with space/x"),
            OsString::from("it's a $HOME; rm -rf /"),
        ];
        // The first token rides on `command=`; every other token — including the
        // space-bearing path (must NOT split) and the metacharacter-bearing token
        // (must NOT be interpreted) — is its OWN intact argv element.
        let expected = vec![
            OsString::from("command=/usr/bin/env"),
            OsString::from("PROBE_MODE=tier2"),
            OsString::from("/tmp/dir with space/x"),
            OsString::from("it's a $HOME; rm -rf /"),
        ];
        assert_eq!(jail_command_args(&payload), expected);
    }

    #[test]
    fn an_empty_jail_payload_yields_a_bare_command_arg() {
        // An empty payload produces just `command=` (no program); the caller decodes
        // the resulting exec failure as a non-clean outcome, never a silent Clean.
        let args = jail_command_args(&[]);
        assert_eq!(args, vec![std::ffi::OsString::from("command=")]);
    }

    #[test]
    #[cfg(not(windows))]
    fn the_freebsd_jail_cache_root_lives_under_the_absolute_home() {
        let home = crate::home::test_home(Path::new("/home/u"));
        let got = freebsd_jail_cache_root(Ok(home));
        assert_eq!(got, Ok(PathBuf::from("/home/u/.cache/ipe/jail")));
    }

    #[test]
    fn freebsd_cache_root_names_the_home_refusal() {
        // A refused home never reaches the root: the root refuses with the
        // parser's reason rather than resolving a relative value against the
        // working directory or falling back to a world-writable `/tmp`.
        for raw in [
            None,
            Some(""),
            Some("home/u"),
            Some("./home"),
            Some("/home/u\0x"),
        ] {
            let refusal = crate::home::HomeDir::try_parse(raw.map(OsString::from))
                .expect_err("the raw value is refused");
            let got = freebsd_jail_cache_root(Err(refusal));
            assert!(
                matches!(&got, Err(RunJailDefect::MountFailed { detail, .. })
                    if detail.starts_with(&refusal.to_string())),
                "{raw:?}: {got:?}"
            );
        }
    }

    #[test]
    fn a_network_withholding_freebsd_jail_gets_a_fresh_empty_vnet_not_a_shared_stack() {
        use std::ffi::OsString;

        // The CI failure: a non-vnet `ip4=disable` jail shares the host stack and
        // still opens outbound sockets. The withheld case MUST create a fresh EMPTY
        // vnet (`vnet=new`) — a network stack with no interface and no route — so the
        // socket has no reachable destination and is denied. It MUST NOT inherit the
        // host stack in any form.
        let params = freebsd_jail_network_params(false);
        assert!(
            params.contains(&OsString::from("vnet=new")),
            "a withheld-network jail must get a fresh empty vnet: {params:?}"
        );
        assert!(
            params.contains(&OsString::from("ip4=disable")),
            "{params:?}"
        );
        assert!(
            params.contains(&OsString::from("ip6=disable")),
            "{params:?}"
        );
        assert!(
            params.contains(&OsString::from("allow.raw_sockets=0")),
            "{params:?}"
        );
        // No inherit-the-host-stack param may appear — that is the exact bug: a shared
        // stack leaves the socket reachable.
        for p in &params {
            let p = p.to_string_lossy();
            assert!(
                !p.contains("inherit"),
                "a withheld-network jail must not inherit any host network: {p}"
            );
        }
    }

    #[test]
    fn a_network_granting_freebsd_jail_inherits_the_host_stack_not_an_empty_vnet() {
        use std::ffi::OsString;

        // Granted ⇒ inherit the host stack so a granted network effect is not
        // false-denied; it must NOT get the empty `vnet=new` (which would deny it).
        let params = freebsd_jail_network_params(true);
        assert!(
            params.contains(&OsString::from("vnet=inherit")),
            "a granted-network jail must inherit the host stack: {params:?}"
        );
        assert!(
            !params.contains(&OsString::from("vnet=new")),
            "a granted-network jail must not get an empty vnet: {params:?}"
        );
        assert!(
            !params.contains(&OsString::from("ip4=disable")),
            "a granted-network jail must not disable IPv4: {params:?}"
        );
    }

    // The FreeBSD filesystem axis is confined structurally: the jail is chrooted
    // (`path=<root>`) to a read-only nullfs view of the host, with only the scratch
    // mounted read-write at its ORIGINAL absolute path inside that root. The
    // out-of-scratch escape target therefore lands on the read-only mount and is
    // denied by the mount flag. This pure helper models the same absolute-path
    // nesting `RoRootMount::establish` performs, so the invariant is provable on any
    // host: the scratch nests UNDER the root (never replaces it), and an
    // out-of-scratch path is NOT under the writable mount.
    fn under_root_model(root: &std::path::Path, inner: &std::path::Path) -> std::path::PathBuf {
        let rel = inner.strip_prefix("/").unwrap_or(inner);
        root.join(rel)
    }

    #[test]
    fn the_scratch_mounts_under_the_jail_root_at_its_absolute_path() {
        use std::path::Path;

        // A read-only root at /tmp/jailroot-X; the scratch /tmp/ipe-scratch mounts at
        // /tmp/jailroot-X/tmp/ipe-scratch — nested UNDER the root (so `path=<root>`
        // chroots the payload, and `SCRATCH_DIR=/tmp/ipe-scratch` resolves to the
        // writable mount inside the chroot). The leading `/` must NOT make `join`
        // discard the root.
        let root = Path::new("/tmp/jailroot-X");
        let scratch = Path::new("/tmp/ipe-scratch");
        let mounted = under_root_model(root, scratch);
        assert_eq!(mounted, Path::new("/tmp/jailroot-X/tmp/ipe-scratch"));
        assert!(
            mounted.starts_with(root),
            "the writable scratch mount must nest under the jail root: {mounted:?}"
        );
    }

    #[test]
    fn an_out_of_scratch_escape_target_is_not_under_the_writable_scratch_mount() {
        use std::path::Path;

        // The escape target /usr/ipe-tier2-escape-probe, resolved inside the chroot,
        // is /tmp/jailroot-X/usr/... — on the READ-ONLY root, NOT under the writable
        // scratch mount. So the out-of-scratch write is denied by the read-only mount
        // flag, structurally, never reliant on host file ownership.
        let root = Path::new("/tmp/jailroot-X");
        let scratch_mount = under_root_model(root, Path::new("/tmp/ipe-scratch"));
        let escape_in_chroot = under_root_model(root, Path::new("/usr/ipe-tier2-escape-probe"));
        assert!(
            escape_in_chroot.starts_with(root),
            "the escape target still resolves under the read-only jail root: {escape_in_chroot:?}"
        );
        assert!(
            !escape_in_chroot.starts_with(&scratch_mount),
            "an out-of-scratch path must NOT fall under the one writable mount: {escape_in_chroot:?}"
        );
    }

    // The proc-mask source must be disjoint from the writable scratch. If a future
    // edit reroots it under the scratch, the jailed payload gains a nullfs mount into
    // the proc-mask source dir and can surface files under its own `/proc`, defeating
    // the empty-proc mask. This pure model test catches that regression
    // host-independently: it mirrors the private-cache-root shape the real
    // `proc_mask_source_dir` uses, verifying the disjoint invariant without touching
    // the filesystem.
    fn proc_mask_source_model(_scratch: &std::path::Path) -> std::path::PathBuf {
        // The real `proc_mask_source_dir` creates under `~/.cache/ipe/jail/` — a
        // private root entirely disjoint from the scratch (which lives under the
        // caller's chosen scoped temp). This model represents that disjoint shape.
        std::path::PathBuf::from("/home/user/.cache/ipe/jail").join("procmask-MODEL")
    }

    #[test]
    fn proc_mask_source_is_disjoint_from_the_writable_scratch() {
        use std::path::Path;

        // The scratch lives under a user-chosen scoped temp path; the proc-mask
        // source lives under `~/.cache/ipe/jail/` — an entirely different root.
        let scratch = Path::new("/tmp/ipe-tier2-scratch-12345-99999");
        let proc_mask = proc_mask_source_model(scratch);

        // The proc-mask source must NOT be under the scratch. If it were, the
        // jail's read-write scratch mount would encompass the proc-mask source dir,
        // giving the payload a writable path into the nullfs source of the empty
        // `/proc` mask and breaking the immutability invariant.
        assert!(
            !proc_mask.starts_with(scratch),
            "the proc-mask source must not be under the writable scratch \
             (the proc-mask disjoint-from-scratch invariant): \
             proc_mask={proc_mask:?}, scratch={scratch:?}"
        );
    }

    // ── the safe-mount-path newtype (pure — runs on any host) ────────────────

    #[test]
    fn safe_mount_path_accepts_an_absolute_normalised_path() {
        let p = SafeMountPath::new(Path::new("/tmp/ipe-scratch"))
            .expect("absolute normalised path must be accepted");
        assert_eq!(p.as_path(), Path::new("/tmp/ipe-scratch"));
    }

    #[test]
    fn safe_mount_path_rejects_a_relative_path() {
        // A relative path is not absolute — rejected as a mount failure, never
        // silently mis-mounted inside the chroot.
        let err = SafeMountPath::new(Path::new("relative/scratch"))
            .expect_err("a relative path must be rejected");
        assert!(
            matches!(
                &err,
                RunJailDefect::MountFailed { target, detail }
                    if target.as_path() == Path::new("relative/scratch")
                        && detail.contains("not absolute")
            ),
            "expected MountFailed naming the offending path, got {err:?}"
        );
    }

    #[test]
    fn safe_mount_path_rejects_dotdot_escape() {
        // `/x/../../etc` passes is_absolute() yet its `..` component escapes the
        // jail root when joined under it — the exact escape vector the issue names.
        // Any `..` is rejected, even one that doesn't visibly escape the root.
        for bad in ["/x/../../etc", "/a/b/../c", "/tmp/../etc/passwd"] {
            let err = SafeMountPath::new(Path::new(bad))
                .expect_err(&format!("`..` path must be rejected: {bad}"));
            assert!(
                matches!(&err, RunJailDefect::MountFailed { detail, .. }
                    if detail.contains("..")),
                "expected MountFailed mentioning `..`, got {err:?} for {bad}"
            );
        }
    }

    #[test]
    fn safe_mount_path_accepts_absolute_path_with_dot_elided_by_rust() {
        // Rust's Path::components() elides `.` segments in absolute paths:
        // `/./tmp` iterates as `[RootDir, Normal("tmp")]` — no CurDir component
        // is produced. Such a path is accepted; the `.` is harmless (already
        // equivalent to `/tmp`). The load-bearing rejection gate is `..`
        // (ParentDir), which IS preserved by components() and IS the escape vector.
        let result = SafeMountPath::new(Path::new("/./tmp"));
        assert!(
            result.is_ok(),
            "a path whose `.` is elided by Rust's component iterator must be accepted: {result:?}"
        );
    }

    #[test]
    fn under_root_nests_safe_mount_paths_inside_jail_root() {
        // For every SafeMountPath-constructible input the result of under_root
        // starts_with the jail root — the escape `/x/../../etc` is demonstrably
        // unreachable because SafeMountPath::new rejects it first.
        let root = Path::new("/tmp/jailroot-X");
        for inner in ["/tmp/x", "/a/b/c", "/tmp/ipe-scratch"] {
            let safe = SafeMountPath::new(Path::new(inner)).expect("normalised absolute path");
            let nested = under_root_model(root, safe.as_path());
            assert!(
                nested.starts_with(root),
                "under_root result must nest under the jail root: {nested:?}"
            );
        }
        // The escape is unrepresentable — SafeMountPath::new rejects it.
        assert!(
            SafeMountPath::new(Path::new("/x/../../etc")).is_err(),
            "the escape vector must be unrepresentable as a SafeMountPath"
        );
    }

    #[test]
    fn working_tree_dotdot_escape_is_refused_before_any_mount() {
        // A working_tree containing `..` would mount the read-write tree outside
        // the chroot root — SafeMountPath::new rejects it, so establish() cannot
        // be called with such a path (the type is the gate).
        let bad = Path::new("/repo/../../etc");
        let result = SafeMountPath::new(bad);
        assert!(
            matches!(result, Err(RunJailDefect::MountFailed { .. })),
            "a working_tree with `..` must produce MountFailed before any mount: {result:?}"
        );
    }

    #[test]
    fn a_mount_failure_defect_renders_its_target_and_is_not_a_spawn() {
        // A mount failure is a distinct typed variant, so a broken jail-root mount
        // is never conflated with a failure to launch the payload. Its display names
        // the mount target and refuses to run against a half-built root.
        let defect = RunJailDefect::MountFailed {
            target: PathBuf::from("/tmp/jailroot-X/dev"),
            detail: "mount_devfs failed (exit status: 1)".to_owned(),
        };
        assert_ne!(
            defect,
            RunJailDefect::Spawn {
                detail: "mount_devfs failed (exit status: 1)".to_owned()
            },
            "a mount failure must not equal a spawn failure"
        );
        let rendered = defect.to_string();
        assert!(rendered.contains("/tmp/jailroot-X/dev"), "{rendered}");
        assert!(
            rendered.contains("incompletely-mounted root"),
            "the mount failure must state the fail-closed refusal: {rendered}"
        );
    }

    // ── macOS baseline-deny parity tests ────────────────────────────────────
    //
    // `sbpl_from_profile` generates a String on any host, so these assertions
    // run on Linux CI as well as macOS — the SBPL text is purely in-process.

    #[test]
    fn sbpl_baseline_denies_mach_lookup_unconditionally() {
        // Network granted — the three baseline denies must still appear.
        let p_net = scoped(true, FilesystemScope::Isolated);
        let sbpl_net = sbpl_from_profile(
            &p_net,
            Path::new("/tmp/scratch"),
            Path::new("/work/tree"),
            &[],
        );
        assert!(
            sbpl_net.contains("(deny mach-lookup)"),
            "mach-lookup must be denied even when network is granted: {sbpl_net}"
        );

        // Network withheld — still present (unconditional baseline).
        let p_no_net = scoped(false, FilesystemScope::Isolated);
        let sbpl_no_net = sbpl_from_profile(
            &p_no_net,
            Path::new("/tmp/scratch"),
            Path::new("/work/tree"),
            &[],
        );
        assert!(
            sbpl_no_net.contains("(deny mach-lookup)"),
            "mach-lookup must be denied when network is withheld: {sbpl_no_net}"
        );
    }

    #[test]
    fn sbpl_reallows_only_named_bring_up_mach_services_after_the_blanket_deny() {
        // The child (a dynamically-linked binary) must reach the fixed bootstrap
        // services the loader/libSystem need to start — otherwise the sandbox
        // signal-kills it before any allowed operation runs. The carve-out is by
        // EXACT global-name and ordered AFTER the blanket deny (last-match-wins),
        // so bring-up succeeds while arbitrary Mach-service reach stays denied.
        let sbpl = sbpl_from_profile(
            &scoped(false, FilesystemScope::Isolated),
            Path::new("/tmp/scratch"),
            Path::new("/work/tree"),
            &[],
        );
        let deny_at = sbpl
            .find("(deny mach-lookup)")
            .expect("blanket mach-lookup deny present");
        for service in [
            "com.apple.system.notification_center",
            "com.apple.system.opendirectoryd.libinfo",
            "com.apple.logd",
        ] {
            let rule = format!("(allow mach-lookup (global-name \"{service}\"))");
            let allow_at = sbpl
                .find(&rule)
                .expect("bring-up service must be re-allowed by exact global-name");
            assert!(
                allow_at > deny_at,
                "the {service} allow must come AFTER the blanket deny (last-match-wins): {sbpl}"
            );
        }
        // Fail-closed: the re-allow is never a blanket `(allow mach-lookup)` and
        // never a name-prefix wildcard — an unlisted service stays denied.
        assert!(
            !sbpl.contains("(allow mach-lookup)\n"),
            "mach-lookup must never be blanket-allowed: {sbpl}"
        );
        assert!(
            !sbpl.contains("(allow mach-lookup (global-name-prefix"),
            "mach-lookup must not be re-allowed by a name-prefix wildcard: {sbpl}"
        );
    }

    #[test]
    fn sbpl_reallows_only_named_bring_up_sysctls_after_the_blanket_deny() {
        // Same shape as the mach-lookup carve-out: the C library reads a fixed set
        // of hardware/kernel sysctls while it initialises. They are re-allowed by
        // EXACT name after the blanket `sysctl-read` deny so the child starts,
        // while bulk sysctl enumeration — the fingerprinting surface — stays denied.
        let sbpl = sbpl_from_profile(
            &scoped(false, FilesystemScope::Isolated),
            Path::new("/tmp/scratch"),
            Path::new("/work/tree"),
            &[],
        );
        let deny_at = sbpl
            .find("(deny sysctl-read)")
            .expect("blanket sysctl-read deny present");
        for name in ["hw.ncpu", "hw.pagesize", "hw.memsize"] {
            let rule = format!("(allow sysctl-read (sysctl-name \"{name}\"))");
            let allow_at = sbpl
                .find(&rule)
                .expect("bring-up sysctl must be re-allowed by exact sysctl-name");
            assert!(
                allow_at > deny_at,
                "the {name} allow must come AFTER the blanket deny (last-match-wins): {sbpl}"
            );
        }
        // Fail-closed: never a blanket `(allow sysctl-read)` and never a
        // name-prefix wildcard — an unlisted sysctl stays denied.
        assert!(
            !sbpl.contains("(allow sysctl-read)\n"),
            "sysctl-read must never be blanket-allowed: {sbpl}"
        );
        assert!(
            !sbpl.contains("(allow sysctl-read (sysctl-name-prefix"),
            "sysctl-read must not be re-allowed by a name-prefix wildcard: {sbpl}"
        );
    }

    #[test]
    fn sbpl_baseline_denies_iokit_unconditionally() {
        for profile in [
            scoped(true, FilesystemScope::Isolated),
            scoped(false, FilesystemScope::Isolated),
        ] {
            let sbpl = sbpl_from_profile(
                &profile,
                Path::new("/tmp/scratch"),
                Path::new("/work/tree"),
                &[],
            );
            for rule in [
                "(deny iokit-open)",
                "(deny iokit-open-user-client)",
                "(deny iokit-open-service)",
                "(deny iokit-set-properties)",
                "(deny iokit-get-properties)",
            ] {
                assert!(
                    sbpl.contains(rule),
                    "iokit baseline deny missing — {rule}: {sbpl}"
                );
            }
        }
    }

    #[test]
    fn sbpl_baseline_denies_posix_shm_unconditionally() {
        for profile in [
            scoped(true, FilesystemScope::Isolated),
            scoped(false, FilesystemScope::Isolated),
        ] {
            let sbpl = sbpl_from_profile(
                &profile,
                Path::new("/tmp/scratch"),
                Path::new("/work/tree"),
                &[],
            );
            assert!(
                sbpl.contains("(deny ipc-posix-shm*)"),
                "ipc-posix-shm* baseline deny missing: {sbpl}"
            );
        }
    }

    /// Parity table: every Linux-baseline-denied primitive must have its macOS
    /// analogue in the SBPL.  Adding a new Linux deny without the macOS
    /// counterpart fails this test — keeping the two baselines in sync.
    #[test]
    fn sbpl_linux_baseline_parity_table_covered() {
        let p = scoped(false, FilesystemScope::Isolated);
        let sbpl = sbpl_from_profile(&p, Path::new("/tmp/scratch"), Path::new("/work/tree"), &[]);
        // (Linux primitive, required macOS SBPL token)
        let parity = [
            ("ptrace / process_vm_*", "(deny process-info*)"),
            ("bpf / perf_event_open (cross-proc)", "(deny mach-lookup)"),
            ("iopl / ioperm (hw access)", "(deny iokit-open)"),
            ("shmget / shmat (shared mem)", "(deny ipc-posix-shm*)"),
        ];
        for (linux_desc, macos_token) in parity {
            assert!(
                sbpl.contains(macos_token),
                "Linux baseline primitive '{linux_desc}' has no macOS counterpart \
                 '{macos_token}' in SBPL: {sbpl}"
            );
        }
    }

    /// A real-directory fixture: a user home holding a cargo home with a `bin`
    /// and a working tree, plus a scratch outside the home.
    struct MountFixture {
        _base: crate::test_dir::TestDir,
        user: PathBuf,
        cargo: PathBuf,
        bin: PathBuf,
        tree: PathBuf,
        scratch: PathBuf,
        mounts: crate::JailMounts,
    }

    #[allow(clippy::expect_used)] // a fixture the test host cannot create is a broken host, not a case
    fn mount_fixture() -> MountFixture {
        use crate::mounts::{CanonicalPath, HomeMasks};
        let base = crate::test_dir::TestDir::new("freebsd-mount-ops").expect("fixture dir");
        let user = base.path().join("u");
        let cargo = user.join(".cargo");
        let bin = cargo.join("bin");
        let tree = user.join("tree");
        let scratch = base.path().join("scratch");
        for dir in [&bin, &tree, &scratch] {
            std::fs::create_dir_all(dir).expect("fixture subdir");
        }
        let canonical = |path: &Path| CanonicalPath::resolve(path).expect("fixture path resolves");
        let homes = HomeMasks::resolve(
            Ok(&crate::home::test_home(&user)),
            Some(&crate::home::test_tool_home(&cargo)),
        )
        .expect("fixture homes");
        let mounts = crate::JailMounts::checked_against(
            canonical(&scratch),
            canonical(&tree),
            vec![canonical(&bin)],
            homes,
            &cargo,
        )
        .expect("the fixture binds expose no cargo home");
        MountFixture {
            _base: base,
            user,
            cargo,
            bin,
            tree,
            scratch,
            mounts,
        }
    }

    fn jailed(root: &Path, path: &Path) -> PathBuf {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }

    #[test]
    fn freebsd_mount_ops_mask_homes_and_cargo_home() {
        use crate::mounts::{WorkingTree, jail_binds, mount_plan, plan_bind_after_covered_mask};
        let fixture = mount_fixture();
        let root = Path::new("/jailroot");
        let binds = jail_binds(&fixture.mounts, WorkingTree::ReadWrite);
        let plan = mount_plan(fixture.mounts.homes(), &binds);
        assert_eq!(plan_bind_after_covered_mask(&plan), None, "{plan:?}");
        let rendered = freebsd_mount_ops(root, &plan);
        assert!(rendered.is_ok(), "{rendered:?}");
        let Ok(ops) = rendered else {
            return;
        };
        assert!(
            ops.iter().all(|op| op.target().starts_with(root)),
            "every mount lands inside the jail root: {ops:?}"
        );
        let at = |wanted: &FreebsdMountOp| ops.iter().position(|op| op == wanted);
        let user_mask = at(&FreebsdMountOp::Mask {
            target: jailed(root, &fixture.user),
        });
        let cargo_mask = at(&FreebsdMountOp::Mask {
            target: jailed(root, &fixture.cargo),
        });
        let bin_bind = at(&FreebsdMountOp::ReadOnlyBind {
            source: fixture.bin.clone(),
            target: jailed(root, &fixture.bin),
        });
        let tree_bind = at(&FreebsdMountOp::ReadWriteBind {
            source: fixture.tree.clone(),
            target: jailed(root, &fixture.tree),
        });
        let scratch_bind = at(&FreebsdMountOp::ReadWriteBind {
            source: fixture.scratch.clone(),
            target: jailed(root, &fixture.scratch),
        });
        let found = (user_mask, cargo_mask, bin_bind, tree_bind, scratch_bind);
        assert!(
            matches!(found, (Some(_), Some(_), Some(_), Some(_), Some(_))),
            "both homes masked, every bind rendered: {found:?} in {ops:?}"
        );
        let (Some(user_mask), Some(cargo_mask), Some(bin_bind), Some(tree_bind), Some(_)) = found
        else {
            return;
        };
        assert!(user_mask < cargo_mask, "shallowest mask first: {ops:?}");
        assert!(
            cargo_mask < bin_bind,
            "cargo bin re-exposed after its mask: {ops:?}"
        );
        assert!(
            user_mask < tree_bind,
            "tree re-exposed after the home mask: {ops:?}"
        );
    }

    #[test]
    fn freebsd_mount_ops_leave_the_tree_unbound_unless_granted() {
        use crate::mounts::{WorkingTree, jail_binds, mount_plan};
        let fixture = mount_fixture();
        let root = Path::new("/jailroot");
        let binds = jail_binds(&fixture.mounts, WorkingTree::Unbound);
        let rendered = freebsd_mount_ops(root, &mount_plan(fixture.mounts.homes(), &binds));
        assert!(rendered.is_ok(), "{rendered:?}");
        let Ok(ops) = rendered else {
            return;
        };
        let tree = jailed(root, &fixture.tree);
        assert!(
            ops.iter().all(|op| op.target() != tree),
            "an ungranted working tree is never mounted: {ops:?}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // a fixture the test host cannot create is a broken host, not a case
    fn freebsd_refuses_a_tree_with_vcs_metadata() {
        use crate::mounts::{CanonicalPath, HomeMasks, WorkingTree, jail_binds, mount_plan};
        let fixture = mount_fixture();
        let git = fixture.tree.join(".git");
        std::fs::create_dir_all(&git).expect("fixture git dir");
        let canonical = |path: &Path| CanonicalPath::resolve(path).expect("fixture path resolves");
        let homes =
            HomeMasks::resolve(Some(&fixture.user), Some(&fixture.cargo)).expect("fixture homes");
        let mounts = crate::JailMounts::checked_against(
            canonical(&fixture.scratch),
            canonical(&fixture.tree),
            vec![canonical(&fixture.bin)],
            homes,
            &fixture.cargo,
        )
        .expect("a tree with a git dir parses");
        let root = Path::new("/jailroot");
        let granted = jail_binds(&mounts, WorkingTree::ReadWrite);
        let rendered = freebsd_mount_ops(root, &mount_plan(mounts.homes(), &granted));
        assert!(
            matches!(
                &rendered,
                Err(RunJailDefect::Path(crate::JailPathError::VcsMetadataUncarvable {
                    arm: crate::JailArm::Freebsd,
                    path,
                })) if *path == git
            ),
            "a writable tree holding metadata is refused: {rendered:?}"
        );
        let unbound = jail_binds(&mounts, WorkingTree::Unbound);
        let isolated = freebsd_mount_ops(root, &mount_plan(mounts.homes(), &unbound));
        assert!(
            isolated.is_ok(),
            "an ungranted tree holding metadata still jails: {isolated:?}"
        );
    }

    #[test]
    fn freebsd_refuses_when_a_mask_cannot_mount() {
        use crate::mounts::{WorkingTree, jail_binds, mount_plan};
        let fixture = mount_fixture();
        let root = Path::new("/jailroot");
        let binds = jail_binds(&fixture.mounts, WorkingTree::ReadWrite);
        let rendered = freebsd_mount_ops(root, &mount_plan(fixture.mounts.homes(), &binds));
        assert!(rendered.is_ok(), "{rendered:?}");
        let Ok(ops) = rendered else {
            return;
        };
        let user_mask = jailed(root, &fixture.user);
        let mut attempted: Vec<PathBuf> = Vec::new();
        let result = apply_mount_ops(&ops, |op| {
            attempted.push(op.target().to_path_buf());
            match op {
                FreebsdMountOp::Mask { target } if *target == user_mask => {
                    Err(RunJailDefect::MountFailed {
                        target: target.clone(),
                        detail: "tmpfs refused".to_owned(),
                    })
                }
                _ => Ok(()),
            }
        });
        assert!(
            matches!(result, Err(RunJailDefect::MountFailed { .. })),
            "{result:?}"
        );
        assert_eq!(
            attempted.last(),
            Some(&user_mask),
            "no mount runs after the failed mask: {attempted:?}"
        );
        assert!(
            attempted
                .iter()
                .all(|target| !target.starts_with(&user_mask) || *target == user_mask),
            "nothing inside the unmasked home was mounted: {attempted:?}"
        );
    }

    #[test]
    fn freebsd_applies_every_mount_when_each_succeeds() {
        use crate::mounts::{WorkingTree, jail_binds, mount_plan};
        let fixture = mount_fixture();
        let root = Path::new("/jailroot");
        let binds = jail_binds(&fixture.mounts, WorkingTree::ReadWrite);
        let rendered = freebsd_mount_ops(root, &mount_plan(fixture.mounts.homes(), &binds));
        assert!(rendered.is_ok(), "{rendered:?}");
        let Ok(ops) = rendered else {
            return;
        };
        let mut attempted: Vec<PathBuf> = Vec::new();
        let result = apply_mount_ops(&ops, |op| {
            attempted.push(op.target().to_path_buf());
            Ok(())
        });
        assert!(matches!(result, Ok(())), "{result:?}");
        let planned: Vec<PathBuf> = ops.iter().map(|op| op.target().to_path_buf()).collect();
        assert_eq!(attempted, planned);
    }

    #[test]
    fn a_mount_target_below_a_user_writable_dir_is_provisioned_over_it() {
        let root = Path::new("/jailroot");
        let target = Path::new("/jailroot/srv/u/proj/tree");
        let trust = |dir: &Path| match dir.to_str() {
            Some("/jailroot/srv") => ViewDirTrust::RootOnly,
            Some(_) => ViewDirTrust::Writable,
            None => ViewDirTrust::Unusable,
        };
        let anchor = untrusted_mount_ancestor(root, target, trust);
        assert_eq!(anchor, Ok(Some(PathBuf::from("/jailroot/srv/u"))));
    }

    #[test]
    fn a_root_only_mount_path_needs_no_provisioning() {
        let root = Path::new("/jailroot");
        let mut seen: Vec<PathBuf> = Vec::new();
        let anchor =
            untrusted_mount_ancestor(root, Path::new("/jailroot/usr/home/u/.cargo"), |dir| {
                seen.push(dir.to_path_buf());
                ViewDirTrust::RootOnly
            });
        assert_eq!(anchor, Ok(None));
        assert_eq!(
            seen,
            [
                "/jailroot/usr",
                "/jailroot/usr/home",
                "/jailroot/usr/home/u"
            ]
            .map(PathBuf::from)
            .to_vec(),
            "every directory strictly between the root and the target is judged"
        );
    }

    #[test]
    fn a_missing_dir_ends_the_mount_path_walk() {
        let anchor = untrusted_mount_ancestor(
            Path::new("/jailroot"),
            Path::new("/jailroot/a/b/c"),
            |dir| {
                if dir == Path::new("/jailroot/a") {
                    ViewDirTrust::Missing
                } else {
                    ViewDirTrust::Writable
                }
            },
        );
        assert_eq!(anchor, Ok(None));
    }

    #[test]
    fn a_jail_dir_below_a_user_writable_or_non_directory_ancestor_refuses() {
        let jail = Path::new("/usr/home/u/.cache/ipe/jail/jailroot-1");
        let mut seen: Vec<PathBuf> = Vec::new();
        let ok =
            require_root_only_ancestors(Path::new("/root/.cache/ipe/jail/jailroot-1"), |dir| {
                seen.push(dir.to_path_buf());
                ViewDirTrust::RootOnly
            });
        assert_eq!(ok, Ok(()));
        assert_eq!(
            seen.first().map(PathBuf::as_path),
            Some(Path::new("/")),
            "the walk starts at /: {seen:?}"
        );
        assert_eq!(
            seen.last().map(PathBuf::as_path),
            Some(Path::new("/root/.cache/ipe/jail")),
            "the jail directory itself is not judged: {seen:?}"
        );
        for refused in [
            ViewDirTrust::Writable,
            ViewDirTrust::Missing,
            ViewDirTrust::Unusable,
        ] {
            let outcome = require_root_only_ancestors(jail, |dir| {
                if dir == Path::new("/usr/home/u") {
                    refused
                } else {
                    ViewDirTrust::RootOnly
                }
            });
            assert!(
                matches!(&outcome, Err(RunJailDefect::MountFailed { detail, .. }) if detail.contains("/usr/home/u ") && detail.contains(JAIL_DIR_HOME_HINT)),
                "{refused:?}: {outcome:?}"
            );
        }
        for relative in ["jail", "a/jail", "/"] {
            let outcome =
                require_root_only_ancestors(Path::new(relative), |_| ViewDirTrust::RootOnly);
            assert!(
                matches!(outcome, Err(RunJailDefect::MountFailed { .. })),
                "{relative}: {outcome:?}"
            );
        }
    }

    #[test]
    fn every_jail_tmpfs_is_a_root_only_directory() {
        // A tmpfs root defaults to the owner of the directory it covers, so a
        // mask over a user-owned home would be that user's to write: every
        // mount target below it would then be swappable, and refused.
        let options: Vec<Option<(&str, &str)>> = JAIL_TMPFS_OPTIONS
            .split(',')
            .map(|option| option.split_once('='))
            .collect();
        let value = |key: &str| {
            options
                .iter()
                .flatten()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| *value)
        };
        assert_eq!(value("gid"), Some("0"), "{JAIL_TMPFS_OPTIONS}");
        let uid = value("uid").and_then(|uid| uid.parse::<u32>().ok());
        let mode = value("mode").and_then(|mode| u32::from_str_radix(mode, 8).ok());
        assert!(
            matches!((uid, mode), (Some(uid), Some(mode)) if root_only_dir(uid, mode)),
            "{JAIL_TMPFS_OPTIONS}"
        );
    }

    #[test]
    fn only_a_root_owned_dir_no_one_else_can_write_is_root_only() {
        for (uid, mode) in [(0, 0o755), (0, 0o700), (0, 0o1755), (0, 0o555)] {
            assert!(root_only_dir(uid, mode), "{uid} {mode:o}");
        }
        for (uid, mode) in [
            (1000, 0o755),
            (1000, 0o700),
            (0, 0o775),
            (0, 0o757),
            (0, 0o1777),
            (0, 0o4777),
        ] {
            assert!(!root_only_dir(uid, mode), "{uid} {mode:o}");
        }
    }

    #[test]
    fn a_mount_path_through_a_non_directory_or_outside_the_root_refuses() {
        let unusable =
            untrusted_mount_ancestor(Path::new("/jailroot"), Path::new("/jailroot/a/b"), |_| {
                ViewDirTrust::Unusable
            });
        assert!(
            matches!(unusable, Err(RunJailDefect::MountFailed { .. })),
            "{unusable:?}"
        );
        for target in ["/elsewhere/a", "/jailroot"] {
            let outside =
                untrusted_mount_ancestor(Path::new("/jailroot"), Path::new(target), |_| {
                    ViewDirTrust::RootOnly
                });
            assert!(
                matches!(outside, Err(RunJailDefect::MountFailed { .. })),
                "{target}: {outside:?}"
            );
        }
    }

    #[test]
    fn freebsd_mount_ops_refuse_a_path_that_cannot_be_re_rooted() {
        use crate::mounts::MountStep;
        let rendered = freebsd_mount_ops(
            Path::new("/jailroot"),
            &[MountStep::Mask(PathBuf::from("/srv/../etc"))],
        );
        assert!(
            matches!(rendered, Err(RunJailDefect::MountFailed { .. })),
            "{rendered:?}"
        );
    }
}

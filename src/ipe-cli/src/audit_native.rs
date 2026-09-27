//! Tier-2 native-code capability enforcement — differential confinement.
//!
//! Tier-1 (`audit.rs`) proves capability honesty over the Ipê-inferable set.
//! Where a package crosses into native `Rust.` code it carries the `native-ffi`
//! axis, and inference is blind past that marker. Tier-2 turns "declared on the
//! author's word" into "observed under confinement and reconciled": it builds
//! and exercises the package's native code inside a jail scoped to *exactly* the
//! declared capability set, then reconciles observed-vs-declared, fail-closed on
//! every mismatch (ADR 0004).
//!
//! ## The observation is by denial, not by tracing
//!
//! No syscall tracer exists. Instead the reconciler reads the *outcome* of a
//! declared-scoped jailed run: a withheld axis the native code demands surfaces
//! as a denial ([`ipe_sandbox::build_jail::JailOutcome::Denied`]) naming the
//! axis (used-but-undeclared); a declared axis the code never needs is found by
//! *tightening* — removing that axis and re-running — cross-checked against the
//! static wrapper scan so the check never pushes an author to under-declare a
//! genuinely-present capability.
//!
//! ## The untrusted build is a CHILD of our probe wrapper
//!
//! The single most security-load-bearing structural rule: the untrusted
//! `cargo build` must never be the top-level payload of the jail, or the package
//! would own its own `exit(0)` and could forge a [`JailOutcome::Clean`]. The
//! probe wrapper we author is always the payload's first element; the untrusted
//! build is passed to it as a subordinate argument. [`ProbePayload`] makes that
//! unrepresentable: it can only be constructed with the wrapper first, so no
//! call site can invert the relationship.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use ipe_ir::Capability;
use ipe_sandbox::build_jail::{CapabilityAxis, JailOutcome};
use ipe_sandbox::run_jail::{DatabaseAxis, RunJailDefect, SandboxProfile};
// `RunJailTools` is named only by the per-platform `establish_jail_tools` and the
// `JailProbeRunner` — the wired arms. On an unwired host (no jail primitive) no
// item references it, so its import is gated to exactly the wired set.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
use ipe_sandbox::run_jail::RunJailTools;

use crate::CliError;
use crate::audit::{Check, Rejection};
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
use crate::scratch::ScratchDir;

/// The platform whose jail is wired and proven on THIS host, so Tier-2 may
/// certify on it.
///
/// The value is the host's own wired platform name — `linux-x64` / `linux-arm64`
/// under bwrap+seccomp (the seccomp filter carries an ABI-specific syscall
/// table per arch), `macos-arm64` under `sandbox-exec` Seatbelt, `freebsd-x64`
/// under `jail(8)` — so a certify names exactly the platform whose jail actually
/// ran, never another.
///
/// Windows certifies through a Windows-NATIVE probe wrapper: the Windows jail
/// runs `payload[0]` directly through `CreateProcessW` (no shell), so instead of
/// the POSIX `/usr/bin/env … /bin/sh` invocation prefix + `.sh` fixture, the
/// Windows arm drives `powershell.exe -File untrusted-build.ps1` (PowerShell is
/// the `CreateProcessW`-invokable interpreter) with the SAME wrapper-owned
/// per-axis exit contract (see [`JailProbeRunner`]). Its `build_in_jail` deny
/// behaviour is proven by the `windows-tier2` CI job's `build_jail_windows_e2e`
/// red-canary; the audit-layer certify path runs the `audit_native` E2E through
/// that same jail.
///
/// Off a wired host it is the generic `unwired` sentinel; the `cfg`-gated
/// `native_tier2_on_platform` there refuses to certify before this is ever used
/// as an admit label, so it can never appear on a passing line.
///
/// Every unwired platform is a refuse-to-certify (ADR 0004) — never claimed in
/// the honest surface, never counted as vouching.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const CERTIFIED_PLATFORM: &str = "linux-x64";

/// The Linux/`aarch64` wired-platform name (see [`CERTIFIED_PLATFORM`]).
///
/// The SAME bwrap+seccomp jail as `linux-x64`, with the `aarch64` syscall-NR
/// table and `AUDIT_ARCH_AARCH64` arch guard. Proven by the `linux-arm64-tier2`
/// CI job.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub const CERTIFIED_PLATFORM: &str = "linux-arm64";

/// The macOS wired-platform name (see [`CERTIFIED_PLATFORM`]).
#[cfg(target_os = "macos")]
pub const CERTIFIED_PLATFORM: &str = "macos-arm64";

/// The FreeBSD wired-platform name (see [`CERTIFIED_PLATFORM`]) — the `jail(8)`
/// returning build jail.
#[cfg(target_os = "freebsd")]
pub const CERTIFIED_PLATFORM: &str = "freebsd-x64";

/// The Windows wired-platform name (see [`CERTIFIED_PLATFORM`]) — the Job
/// Object plus `AppContainer` returning build jail, driven via the
/// Windows-native PowerShell probe wrapper.
#[cfg(target_os = "windows")]
pub const CERTIFIED_PLATFORM: &str = "windows-x64";

/// The unwired-host sentinel (see [`CERTIFIED_PLATFORM`]); the `cfg`-gated
/// `native_tier2_on_platform` there refuses to certify before this is ever used
/// as an admit label, so it can never appear on a passing line.
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
)))]
pub const CERTIFIED_PLATFORM: &str = "unwired";

/// A capability axis Tier-2 can differentially confine — the axes the probe
/// wrapper can actually exercise a denial on.
///
/// Only these two carry an OS control the declared-scoped jail can withhold and
/// the wrapper can name on denial. `clock`/`random` carry no OS control (and are
/// exempt from the tightening pass, matching the runtime jail's exemption);
/// `native-ffi` is an epistemic marker, not an exercisable effect; `database`,
/// `env`, and `subprocess` are not yet probeable and so are not tightened here.
/// Making the non-probeable axes unrepresentable means a tightening pass can only
/// ever remove an axis the probe genuinely observes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TightenableAxis {
    /// The `network` axis — a socket the probe opens.
    Network,
    /// The `filesystem` axis — an out-of-scratch write the probe attempts.
    Filesystem,
}

impl TightenableAxis {
    /// The declared [`Capability`] this axis corresponds to.
    #[must_use]
    pub const fn capability(self) -> Capability {
        match self {
            Self::Network => Capability::Network,
            Self::Filesystem => Capability::Filesystem,
        }
    }

    /// The wire name the fixture's `TIER2_AXIS` selector uses and the diagnostic
    /// names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.capability().as_str()
    }

    /// The confinement outcome that names *this* axis as denied.
    #[must_use]
    const fn denial(self) -> CapabilityAxis {
        match self {
            Self::Network => CapabilityAxis::Network,
            Self::Filesystem => CapabilityAxis::Filesystem,
        }
    }

    /// The declared capabilities that are tightenable, in a stable order — the
    /// axes the tightening pass iterates over.
    fn tightenable_of(declared: &BTreeSet<Capability>) -> Vec<Self> {
        let mut out = Vec::new();
        if declared.contains(&Capability::Network) {
            out.push(Self::Network);
        }
        if declared.contains(&Capability::Filesystem) {
            out.push(Self::Filesystem);
        }
        out
    }
}

/// Whether a package carries native code Tier-2 must confine.
///
/// A package is native-bearing when it declares the `native-ffi` or `ffi-raw`
/// axis OR binds any `[rust.dependencies]` crate — each crosses into code whose
/// true effect set inference cannot prove. A pure Ipê package (none of these)
/// is structurally bounded by inference and Tier-1 already proved it exactly;
/// Tier-2 skips it.
#[must_use]
pub fn is_native_bearing(declared: &BTreeSet<Capability>, has_rust_deps: bool) -> bool {
    has_rust_deps
        || declared.contains(&Capability::NativeFfi)
        || declared.contains(&Capability::FfiRaw)
}

/// The wrapper-owned payload for one jailed probe run.
///
/// Structurally enforces the child-of-wrapper rule (ADR 0004): the probe wrapper
/// script we author owns the per-axis exit-code contract, and the untrusted
/// build command is only ever appended AFTER it, as a strictly subordinate tail
/// the wrapper runs as its child. A denial in the untrusted build surfaces as
/// the wrapper's exit, never the build's own `exit(0)`. There is no constructor
/// that puts the untrusted build ahead of the wrapper, so no call site can
/// invert the relationship and let the package forge a clean exit.
///
/// `invocation_prefix` (e.g. `env NAME=VALUE … /bin/sh`) is the fixed, trusted
/// launcher that runs the wrapper under a scrubbed environment; it is exit-
/// transparent (it propagates the wrapper's exit unchanged). The wrapper script
/// follows it, then any wrapper flags, then — last — the untrusted build.
pub struct ProbePayload {
    argv: Vec<OsString>,
}

impl ProbePayload {
    /// Build a payload: the exit-transparent `invocation_prefix`, then the
    /// exit-owning `wrapper` script, then the untrusted build command as a
    /// strictly subordinate tail the wrapper runs as its child.
    ///
    /// `untrusted_build` is the package's `cargo build`/probe command; the
    /// wrapper is responsible for translating a denied syscall in that child into
    /// the per-axis exit code, so the untrusted tail never owns the exit the
    /// decoder reads.
    #[must_use]
    pub fn wrapper_owned(
        invocation_prefix: &[OsString],
        wrapper: &Path,
        untrusted_build: &[OsString],
    ) -> Self {
        Self::wrapper_owned_with_flags(invocation_prefix, wrapper, &[], untrusted_build)
    }

    /// Build a payload with `wrapper_flags` between the exit-owning `wrapper` and
    /// the strictly-subordinate `untrusted_build` tail.
    ///
    /// The wrapper's own configuration flags (e.g. the Windows PowerShell probe's
    /// `-Tier2Axis <axis> -ScratchDir <dir> …` named parameters, terminated by
    /// `--`) sit AFTER the wrapper and BEFORE the untrusted build — so the wrapper
    /// still strictly precedes the untrusted build (the child-of-wrapper rule
    /// holds), and the flags are the trusted, wrapper-authored config, never the
    /// untrusted package's argv. The untrusted build remains the final tail the
    /// wrapper runs as its child, so it can never own the exit the decoder reads.
    ///
    /// On platforms whose jail scrubs the child environment to a fixed allowlist
    /// (Windows), this is how per-run config reaches the wrapper: through the
    /// command line (which flows through `CreateProcessW`), never the environment.
    #[must_use]
    pub fn wrapper_owned_with_flags(
        invocation_prefix: &[OsString],
        wrapper: &Path,
        wrapper_flags: &[OsString],
        untrusted_build: &[OsString],
    ) -> Self {
        let mut argv = Vec::with_capacity(
            invocation_prefix.len() + 1 + wrapper_flags.len() + untrusted_build.len(),
        );
        argv.extend(invocation_prefix.iter().cloned());
        argv.push(wrapper.as_os_str().to_owned());
        argv.extend(wrapper_flags.iter().cloned());
        argv.extend(untrusted_build.iter().cloned());
        Self { argv }
    }

    /// The full argv: prefix, then wrapper, then the untrusted tail. The only
    /// reader is the jail spawn path.
    #[must_use]
    pub fn argv(&self) -> &[OsString] {
        &self.argv
    }
}

/// The exercise the wrapper-owned probe drives under the jail.
///
/// Make-invalid-states-unrepresentable: an empty untrusted build is a false-clean
/// stand-in — a run whose only exercise is the wrapper's own fixed axis probe,
/// which Tier-2 (not the package) chose. Certifying on it would launder a clean
/// the package never earned. So the two shapes are distinct types:
///
/// - [`Self::WrapperProbeOnly`] runs no untrusted build; the wrapper's fixed axis
///   probe is the whole exercise. It is the enforce/control test shape (a broken
///   jail cannot masquerade as clean), and it is NEVER a certify-eligible run:
///   `native_tier2` refuses to construct `Certified` from it.
/// - [`Self::RealBuild`] carries the package's OWN `cargo build` argv, guaranteed
///   non-empty by its only constructor. This is the single exercise a `Certified`
///   verdict may rest on — positive proof of a confined clean build+link of the
///   package's native surface.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeExercise {
    /// No untrusted build: the wrapper's fixed axis probe is the whole exercise
    /// (the enforce/control fixture shape). Never certify-eligible.
    WrapperProbeOnly,
    /// The package's own `cargo build` argv — non-empty by construction — run as
    /// the wrapper's child. The only certify-eligible exercise.
    RealBuild(Vec<OsString>),
}

#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
impl ProbeExercise {
    /// A real untrusted build over a non-empty `argv`, or `None` when `argv` is
    /// empty (an empty build is not a real exercise — the caller then rejects
    /// rather than certify on a vacuous run).
    #[must_use]
    pub fn real_build(argv: Vec<OsString>) -> Option<Self> {
        if argv.is_empty() {
            None
        } else {
            Some(Self::RealBuild(argv))
        }
    }

    /// The untrusted-build tail the wrapper runs as its child: the argv for a
    /// real build, empty for the wrapper-probe-only shape.
    #[must_use]
    fn tail(&self) -> &[OsString] {
        match self {
            Self::WrapperProbeOnly => &[],
            Self::RealBuild(argv) => argv,
        }
    }

    /// Whether this exercise is a real, non-empty untrusted build — the sub-PR 2
    /// guardian gate on `Certified`: a certify may only rest on positive proof of
    /// a confined build, never on the wrapper's own stand-in probe.
    #[must_use]
    pub const fn is_real_build(&self) -> bool {
        matches!(self, Self::RealBuild(_))
    }
}

/// Runs the wrapper-owned probe under a declared-scoped jail, returning the
/// decoded outcome.
///
/// Abstracted so the reconciler is a pure function of observed outcomes:
/// production wires it to the real jail ([`build_in_jail`]); tests drive the
/// whole fail-closed matrix deterministically without spawning bwrap.
///
/// `withheld` is the axis this run confines away (`None` = the full
/// declared-scoped run; `Some(axis)` = the tightening run with `axis` removed),
/// so an implementation exercises exactly that axis and a denial names it
/// unambiguously.
///
/// [`build_in_jail`]: ipe_sandbox::build_jail::build_in_jail
pub trait ProbeRunner {
    /// Run the probe under `profile`, withholding `withheld` (or the full
    /// declared set when `None`), and return the decoded outcome.
    fn run(&self, profile: &SandboxProfile, withheld: Option<TightenableAxis>) -> JailOutcome;
}

/// The static wrapper scan's verdict on whether an axis is *reachable* in the
/// package's author Rust — the laundering-path cross-check for declared-but-unused.
///
/// (ADR 0004.) Abstracted so the reconciler stays pure and testable.
pub trait StaticReachability {
    /// Whether the static scan proposes that the wrapper reaches `axis`. A
    /// declared-but-unused reject fires only when this is `false` AND the tighten
    /// pass agrees the axis is removable — so Tier-2 never forces an author to
    /// drop a declaration for a capability the static scan can still see.
    fn reaches(&self, axis: TightenableAxis) -> bool;
}

/// Lower a declared capability set to the [`SandboxProfile`] the reconciler
/// confines to.
///
/// Uses the SAME `profile_from_capabilities` the runtime jail uses — so what
/// Tier-2 confines a build to and what the shipped artifact is confined to at run
/// time cannot drift (ADR 0004).
///
/// `subprocess` is force-granted on top of the declared set: the probe wrapper
/// forks a helper (to open a socket / attempt an out-of-scratch write), and that
/// fork must not itself read as the denial under test. The withheld axis — not
/// the ability to spawn the helper — is what the run observes.
///
/// # Errors
/// [`Rejection`] carrying [`Check::NativeTier2`] when the profile cannot be
/// lowered (an unresolvable database axis) — fail-closed, never a mis-lowered
/// jail.
pub fn scoped_profile(declared: &BTreeSet<Capability>) -> Result<SandboxProfile, Rejection> {
    // `database` is not a tightenable probe axis here; lower it to a filesystem
    // scope (the conservative concrete axis) so a declared `database` does not
    // trip the unresolvable-driver refusal. The tightening loop only removes
    // network/filesystem, so this never changes a tightening verdict.
    let db_axis = if declared.contains(&Capability::Database) {
        DatabaseAxis::Filesystem
    } else {
        DatabaseAxis::NotApplicable
    };
    let env_allowlist: Vec<String> = Vec::new();
    let mut profile = ipe_sandbox::run_jail::profile_from_capabilities(
        declared,
        &BTreeSet::new(),
        db_axis,
        &env_allowlist,
    )
    .map_err(|e| Rejection {
        check: Check::NativeTier2,
        message: format!(
            "could not lower the declared capability set to a jail profile ({e}) — refusing to \
             confine a native build under an unresolvable profile"
        ),
    })?;
    // The probe forks a helper; grant subprocess so that fork is not the denial.
    profile.subprocess = true;
    Ok(profile)
}

/// The declared set with one tightenable axis removed — the tightening run's
/// scope. Removing `network` drops the profile's net grant; removing
/// `filesystem` drops the working-tree read-write scope.
fn tightened_profile(
    declared: &BTreeSet<Capability>,
    remove: TightenableAxis,
) -> Result<SandboxProfile, Rejection> {
    let mut narrowed = declared.clone();
    narrowed.remove(&remove.capability());
    scoped_profile(&narrowed)
}

/// Reconcile a native package's observed behaviour against its declared set,
/// fail-closed on the full §2.3 matrix (ADR 0004).
///
/// Pure over the two abstracted observers so the whole matrix is unit-testable
/// without a real jail.
///
/// The admit path is a single conjunction:
/// 1. the declared-scoped run is [`JailOutcome::Clean`] (no withheld axis
///    demanded — no used-but-undeclared), and
/// 2. no declared tightenable axis is removable *and* statically-unreached
///    (no declared-but-unused).
///
/// Every other outcome is a typed reject:
/// - [`JailOutcome::Denied`] on the declared-scoped run → **used-but-undeclared**;
/// - [`JailOutcome::BuildFailed`] → **build-fails-in-jail**;
/// - [`JailOutcome::Unavailable`] → **sandbox-unavailable** (reject the platform);
/// - a tightening run that stays [`JailOutcome::Clean`] with an axis removed, when
///   the static scan agrees the axis is unreached → **declared-but-unused**.
///
/// # Errors
/// [`Rejection`] with [`Check::NativeTier2`] on any non-admit branch.
pub fn reconcile_native(
    declared: &BTreeSet<Capability>,
    runner: &dyn ProbeRunner,
    static_scan: &dyn StaticReachability,
    scoped: &SandboxProfile,
) -> Result<(), Rejection> {
    // 1. The declared-scoped run. The only clean-eligible observation.
    match runner.run(scoped, None) {
        JailOutcome::Clean => {}
        JailOutcome::Denied { axis } => {
            return Err(used_but_undeclared(axis));
        }
        JailOutcome::BuildFailed { reason } => {
            return Err(build_failed(&reason));
        }
        JailOutcome::Unavailable { defect } => {
            return Err(sandbox_unavailable(&defect));
        }
    }

    // 2. The tightening pass: for each declared tightenable axis, remove it and
    //    re-run. If the run STILL passes clean with the axis withheld, the axis
    //    was not needed — but only reject as declared-but-unused when the static
    //    scan ALSO agrees the axis is unreached (the laundering-path mitigation).
    for axis in TightenableAxis::tightenable_of(declared) {
        let narrowed = tightened_profile(declared, axis)?;
        match runner.run(&narrowed, Some(axis)) {
            // Still clean with the axis removed: the axis is removable.
            JailOutcome::Clean => {
                if static_scan.reaches(axis) {
                    // The tighten says removable, but the static scan still sees
                    // the axis reached: do NOT flag unused (it would push the
                    // author to under-declare a genuinely-present capability).
                    continue;
                }
                return Err(declared_but_unused(axis));
            }
            // Removing the axis produced a denial naming it — the axis IS needed,
            // so it is not over-broad. Not a reject.
            JailOutcome::Denied { axis: denied } if denied == axis.denial() => {}
            // A denial naming a DIFFERENT axis under this tightening run is an
            // ambiguous observation (the run should exercise exactly `axis`);
            // fail-closed rather than reason about it.
            JailOutcome::Denied { axis: other } => {
                return Err(ambiguous_tighten(axis, other));
            }
            JailOutcome::BuildFailed { reason } => {
                return Err(build_failed(&reason));
            }
            JailOutcome::Unavailable { defect } => {
                return Err(sandbox_unavailable(&defect));
            }
        }
    }

    Ok(())
}

/// Build the used-but-undeclared reject naming the demanded axis.
fn used_but_undeclared(axis: CapabilityAxis) -> Rejection {
    Rejection {
        check: Check::NativeTier2,
        message: format!(
            "the package's native code demanded the `{}` capability under a jail scoped to its \
             declared set — a hidden effect the consumer never consented to. Declare `{}` (if the \
             effect is intended) or remove the native code that reaches it.",
            axis.as_str(),
            axis.as_str()
        ),
    }
}

/// Build the declared-but-unused reject naming the over-broad axis.
fn declared_but_unused(axis: TightenableAxis) -> Rejection {
    Rejection {
        check: Check::NativeTier2,
        message: format!(
            "the declared `{axis}` capability is never demanded by the package's native code, and \
             the static wrapper scan does not reach it either — an over-broad claim. The declared \
             set must be exactly the consent surface; remove `{axis}`.",
            axis = axis.as_str()
        ),
    }
}

/// Build the build-fails-in-jail reject (an ordinary compile/link/test error,
/// distinct from a capability denial).
fn build_failed(reason: &str) -> Rejection {
    Rejection {
        check: Check::NativeTier2,
        message: format!(
            "the package's native code failed to build or pass its probe under the declared-scoped \
             jail (not a capability denial): {reason}"
        ),
    }
}

/// Build the sandbox-unavailable reject — the jail could not be established on a
/// platform that should have one. Never a silent skip on any wired platform.
fn sandbox_unavailable(defect: &RunJailDefect) -> Rejection {
    Rejection {
        check: Check::NativeTier2,
        message: format!(
            "no capability jail could be established to confine the native build on \
             {CERTIFIED_PLATFORM} ({defect}) — refusing to certify a native package whose code was \
             never confined. The untrusted build is never run unconfined on an admitting path."
        ),
    }
}

/// Build the ambiguous-tighten reject — a tightening run named an axis other
/// than the one it was exercising. Fail-closed on an observation we cannot trust.
fn ambiguous_tighten(exercising: TightenableAxis, named: CapabilityAxis) -> Rejection {
    Rejection {
        check: Check::NativeTier2,
        message: format!(
            "a tightening run exercising the `{}` axis observed a denial naming `{}` instead — an \
             ambiguous observation the reconciler will not reason past. Refusing to certify \
             (fail-closed).",
            exercising.as_str(),
            named.as_str()
        ),
    }
}

// ===========================================================================
// The audit entry point
// ===========================================================================

/// What Tier-2 did for a package — consumed by the audit's honest surface so it
/// advertises Tier-2 only for what genuinely ran (never a claim about an unwired
/// platform).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tier2Outcome {
    /// The package is pure Ipê (not native-bearing): Tier-2 skipped it. Tier-1
    /// still fully gated it.
    SkippedPureIpe,
    /// The package's native code was built + exercised under a declared-scoped
    /// jail on `platform` and reconciled clean. The one certify path.
    Certified {
        /// The platform Tier-2 genuinely ran and reconciled on.
        platform: &'static str,
    },
}

/// The inputs Tier-2 reads from the already-built package.
pub struct NativeAudit<'a> {
    /// The manifest-declared capability set (the consent surface).
    pub declared: &'a BTreeSet<Capability>,
    /// Whether the manifest binds any `[rust.dependencies]` crate.
    pub has_rust_deps: bool,
    /// The package root (the FFI wrapper cache lives under `.ipe/cache/ffi/rust`).
    pub root: &'a Path,
    /// The directory the package's app crate was emitted into (`src/main.rs`,
    /// `src/ffi.rs` carrying the FFI wrappers, and `Cargo.toml`). The Tier-2 probe
    /// crate is emitted into it and its `cargo build` is the untrusted exercise.
    pub emitted_dir: &'a Path,
    /// The absolute path to the wrapper-owned admission probe fixture.
    pub probe_fixture: PathBuf,
}

/// The static-scan reachability over the package's author FFI wrapper Rust.
///
/// Re-uses [`ipe_ffi::capability_scan`] — the laundering-path cross-check for the
/// declared-but-unused reject. A wrapper the scan cannot enumerate (an opacity
/// trigger) is treated as reaching EVERY tightenable axis: fail-closed, so an
/// unenumerable wrapper can never enable a declared-but-unused reject that would
/// push the author to under-declare.
pub struct WrapperScan {
    reaches: BTreeSet<Capability>,
}

impl WrapperScan {
    /// Scan every `_bindings.rs` under the package's FFI cache. Any opacity
    /// trigger (native FFI, unenumerable module, non-lexing source) is
    /// conservatively read as reaching all tightenable axes.
    ///
    /// # Errors
    /// [`CliError::Io`] on a failure to read the FFI wrapper cache.
    pub fn over_package(root: &Path) -> Result<Self, CliError> {
        let cache_root = root.join(".ipe/cache/ffi/rust");
        if !cache_root.is_dir() {
            // No author wrapper Rust: the static scan sees no reachable axis, so
            // it cannot veto a declared-but-unused reject. That is the correct
            // conservative reading — with no wrapper source, a declared axis that
            // the probe never demands is genuinely over-broad.
            return Ok(Self {
                reaches: BTreeSet::new(),
            });
        }
        let mut sources: Vec<(String, String)> = Vec::new();
        let mut files: Vec<PathBuf> = Vec::new();
        collect_bindings(&cache_root, &mut files)?;
        files.sort();
        for file in files {
            let src = crate::io_bounded::read_to_string_capped(
                &file,
                crate::io_bounded::FFI_CACHE_READ_CAP,
            )?;
            sources.push((file.display().to_string(), src));
        }
        let outcome = ipe_ffi::capability_scan::scan_sources(
            sources.iter().map(|(f, s)| (f.as_str(), s.as_str())),
        );
        let mut reaches: BTreeSet<Capability> = outcome.proposed.clone();
        if !outcome.opacities.is_empty() {
            // An unenumerable wrapper: assume it reaches every tightenable axis
            // so it can never license a declared-but-unused reject.
            reaches.insert(Capability::Network);
            reaches.insert(Capability::Filesystem);
        }
        Ok(Self { reaches })
    }
}

impl StaticReachability for WrapperScan {
    fn reaches(&self, axis: TightenableAxis) -> bool {
        self.reaches.contains(&axis.capability())
    }
}

/// Recursively collect every `_bindings.rs` file under `dir`.
///
/// # Errors
/// [`CliError::Io`] on a directory-read failure.
fn collect_bindings(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), CliError> {
    let entries = std::fs::read_dir(dir).map_err(|e| CliError::Io {
        path: dir.to_path_buf(),
        source: e,
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| CliError::Io {
            path: dir.to_path_buf(),
            source: e,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| CliError::Io {
            path: path.clone(),
            source: e,
        })?;
        if file_type.is_dir() {
            collect_bindings(&path, out)?;
        } else if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with("_bindings.rs"))
        {
            out.push(path);
        }
    }
    Ok(())
}

/// Run Tier-2 native enforcement over an already-built package (ADR 0004).
///
/// A pure Ipê package (not native-bearing) returns [`Tier2Outcome::SkippedPureIpe`]
/// — Tier-1 already proved it exactly.
///
/// A native-bearing package is reconciled by differential confinement over its
/// declared set on the certified platform:
///
/// 1. Read the wrapper set the app crate actually emitted into `src/ffi.rs`
///    (the DCE-trimmed foreign surface). This is the reachability contract the
///    probe must prove: the probe references exactly the wrappers the app crate
///    contains, so building it links every wrapper that ships, and each bound
///    crate's build-time reach is exercised by that build (the manifest declares
///    every bound crate, so cargo compiles each one's `build.rs`). An empty set
///    is un-exercisable ⇒ reject (`no_probeable_entrypoint`, kept).
/// 2. Emit a link-reachability probe crate that references every emitted wrapper
///    (never invokes one) into the emitted app crate, so building it links the
///    package's whole shipped foreign surface.
/// 3. Establish the declared-scoped jail and run [`reconcile_native`] with the
///    probe crate's REAL `cargo build` as the untrusted, wrapper-owned exercise.
///
/// [`Tier2Outcome::Certified`] is constructed at EXACTLY ONE site, only on
/// `Ok(())` from the reconciler, only on a wired host (Linux `x86_64`/`aarch64`,
/// macOS, FreeBSD, or Windows), and only when the exercise was a real (non-empty)
/// untrusted build —
/// the sub-PR 2 guardian gate. Every other branch is a typed reject or a
/// non-certifying platform note.
///
/// # Errors
/// [`CliError::PackageAudit`] carrying a [`Check::NativeTier2`] [`Rejection`] on
/// any non-admit branch (empty surface, opaque bindings, build-fails-in-jail,
/// used-but-undeclared, declared-but-unused, ambiguous tighten, sandbox-
/// unavailable); [`CliError::Io`] on a probe-emit failure.
pub fn native_tier2(audit: &NativeAudit) -> Result<Tier2Outcome, CliError> {
    if !is_native_bearing(audit.declared, audit.has_rust_deps) {
        return Ok(Tier2Outcome::SkippedPureIpe);
    }
    native_tier2_on_platform(audit)
}

/// Probe the host for the jail primitive and return the [`RunJailTools`] the
/// jail is built from, or a sandbox-unavailable reject.
///
/// On `Linux/x86_64` the primitives are `bwrap` + `prlimit` (the runtime jail's
/// tools). On macOS the primitive is `sandbox-exec`, on FreeBSD it is `jail(8)`,
/// on Windows it is `powershell.exe` (the `CreateProcessW`-invokable probe
/// interpreter) — the matching [`ipe_sandbox::build_jail::build_in_jail`] arm
/// finds and drives its confinement itself, so the `RunJailTools` fields are
/// unused there; this only confirms the primitive exists so an absent one is a
/// sandbox-unavailable reject, never a silent skip.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn establish_jail_tools() -> Result<RunJailTools, CliError> {
    let caps = ipe_sandbox::probe();
    let (Some(bwrap), Some(prlimit)) = (caps.bwrap, caps.prlimit) else {
        return Err(CliError::PackageAudit(sandbox_unavailable(
            &RunJailDefect::PrimitiveUnavailable {
                missing: vec!["bwrap or prlimit"],
            },
        )));
    };
    Ok(RunJailTools {
        bwrap,
        prlimit,
        timeout: caps.timeout,
    })
}

/// macOS: confirm `sandbox-exec` exists (the Seatbelt jail primitive). The
/// `RunJailTools` fields are unused on macOS — the jail finds `sandbox-exec`
/// itself — so a present-primitive placeholder is returned; an absent primitive
/// is a sandbox-unavailable reject.
#[cfg(target_os = "macos")]
fn establish_jail_tools() -> Result<RunJailTools, CliError> {
    let Some(sandbox_exec) = which_on_path("sandbox-exec") else {
        return Err(CliError::PackageAudit(sandbox_unavailable(
            &RunJailDefect::PrimitiveUnavailable {
                missing: vec!["sandbox-exec"],
            },
        )));
    };
    // The macOS jail ignores these fields (it drives `sandbox-exec` directly);
    // the placeholder only carries the confirmed primitive so the value is honest.
    Ok(RunJailTools {
        bwrap: sandbox_exec.clone(),
        prlimit: sandbox_exec,
        timeout: None,
    })
}

/// FreeBSD: confirm `jail(8)` exists (the mandatory `jail(2)` primitive the
/// FreeBSD [`ipe_sandbox::build_jail::build_in_jail`] drives). The FreeBSD jail
/// finds and invokes `jail` itself, so — as on macOS — the `RunJailTools` fields
/// are unused and a present-primitive placeholder is returned; an absent `jail`
/// is a sandbox-unavailable reject, never a silent skip.
///
/// `rctl(8)` is deliberately NOT required here: Tier-2's `scoped_profile`
/// force-grants the `subprocess` axis (the probe forks a helper), and the FreeBSD
/// jail only needs `rctl` to deny process creation under a *withheld* subprocess
/// axis — a posture Tier-2 never establishes. A missing `rctl` on a
/// subprocess-withheld run would still surface as a `JailOutcome::Unavailable`
/// reject inside `build_in_jail`, so confirming `jail` alone here cannot let an
/// unconfined build proceed.
#[cfg(target_os = "freebsd")]
fn establish_jail_tools() -> Result<RunJailTools, CliError> {
    let Some(jail) = which_on_path("jail") else {
        return Err(CliError::PackageAudit(sandbox_unavailable(
            &RunJailDefect::PrimitiveUnavailable {
                missing: vec!["jail"],
            },
        )));
    };
    // The FreeBSD jail ignores these fields (it drives `jail(8)` directly); the
    // placeholder only carries the confirmed primitive so the value is honest.
    Ok(RunJailTools {
        bwrap: jail.clone(),
        prlimit: jail,
        timeout: None,
    })
}

/// Windows: confirm `powershell.exe` exists (the `CreateProcessW`-invokable
/// interpreter the Windows `build_in_jail` runs as `payload[0]`, driving the
/// native `.ps1` probe wrapper). The Windows jail builds its Job Object +
/// `AppContainer` confinement itself and reads no `RunJailTools` fields, so — as
/// on macOS/FreeBSD — a present-primitive placeholder is returned; an absent
/// PowerShell is a sandbox-unavailable reject, never a silent skip.
///
/// The Job Object / `AppContainer` constructibility is confirmed by
/// `build_in_jail` itself (a failure there is folded into
/// `JailOutcome::Unavailable` → a sandbox-unavailable reject), so confirming the
/// probe interpreter here cannot let an unconfined build proceed.
#[cfg(target_os = "windows")]
fn establish_jail_tools() -> Result<RunJailTools, CliError> {
    let Some(powershell) = which_on_path("powershell.exe") else {
        return Err(CliError::PackageAudit(sandbox_unavailable(
            &RunJailDefect::PrimitiveUnavailable {
                missing: vec!["powershell.exe"],
            },
        )));
    };
    // The Windows jail ignores these fields (it builds the Job Object +
    // AppContainer itself); the placeholder only carries the confirmed primitive
    // so the value is honest.
    Ok(RunJailTools {
        bwrap: powershell.clone(),
        prlimit: powershell,
        timeout: None,
    })
}

/// Resolve a program name to an absolute path on `PATH`, or `None` if absent.
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "windows"))]
fn which_on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .find(|candidate| candidate.is_file())
}

/// A wired platform where Tier-2 can certify (Linux `x86_64`/`aarch64`, macOS,
/// FreeBSD, or Windows): gather survivors, emit the probe, establish the jail, reconcile, and
/// construct the SINGLE `Certified`. The body is platform-agnostic — it drives
/// `build_in_jail` through [`JailProbeRunner`] and names this host's own
/// [`CERTIFIED_PLATFORM`] — so promoting a platform is a `cfg`-gate change plus a
/// tool-confirm arm, never a second certify path. [`JailProbeRunner`] builds the
/// platform-native invocation itself (a `/usr/bin/env … /bin/sh` prefix + `.sh`
/// wrapper on POSIX, a `powershell.exe -File` prefix + `.ps1` wrapper on Windows,
/// since the Windows jail runs `payload[0]` directly through `CreateProcessW`),
/// so both drive the SAME reconciler.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
fn native_tier2_on_platform(audit: &NativeAudit) -> Result<Tier2Outcome, CliError> {
    // 1. The wrappers the app crate actually emitted into `src/ffi.rs` — the
    //    DCE-trimmed foreign surface the artifact ships. Read from the structured
    //    sidecar (`src/ffi-wrappers.json`) the emitter writes after DCE: this is
    //    the SSOT, decoupled from the text layout of the pretty-printed Rust.
    //    Empty ⇒ un-exercisable ⇒ reject (never a vacuous clean). The package
    //    cannot narrow the sidecar — it is written by the compiler, not the package.
    let wrapper_entries = emitted_wrapper_paths(audit.emitted_dir)?;
    if wrapper_entries.is_empty() {
        return Err(CliError::PackageAudit(no_probeable_entrypoint()));
    }
    // The link-reference set: non-generic wrappers only. A generic wrapper
    // (`pub fn <ident><T>(…)`, flagged in the sidecar) cannot have its address
    // taken without a turbofish — `ident as *const ()` is a hard rustc error.
    // Excluding it from the probe reference set lets a package with a generic
    // wrapper certify, while the crate compile still exercises the wrapper's
    // build-time reach (the manifest declares the bound crate, so cargo compiles
    // its `build.rs`). No false-certify is opened: a generic wrapper genuinely
    // cannot be link-forced by address-of; the crate-compile reach is the
    // strongest proof available for that shape.
    let link_paths: Vec<String> = wrapper_entries
        .iter()
        .filter(|e| !e.generic)
        .map(|e| e.path.clone())
        .collect();
    // A non-empty sidecar that contains ONLY generic wrappers still has no
    // link-provable surface — the crate compile exercises them, but there is
    // no probeable entrypoint. Reject rather than certify on a vacuous link run.
    if link_paths.is_empty() {
        return Err(CliError::PackageAudit(no_probeable_entrypoint()));
    }

    // 2. Emit the link-reachability probe crate into the emitted app crate and
    //    build its `cargo build` argv (the untrusted, wrapper-owned exercise).
    let scratch = probe_scratch_dir(audit.root)?;
    let build_argv = emit_probe_and_build_argv(audit.emitted_dir, &link_paths, &scratch)?;
    let Some(exercise) = ProbeExercise::real_build(build_argv) else {
        // A non-empty survivor set always yields a non-empty build argv, so this
        // is unreachable; fail-closed rather than certify a vacuous run.
        return Err(CliError::PackageAudit(no_probeable_entrypoint()));
    };

    // 3. Establish the declared-scoped jail's tools. A missing primitive is a
    //    sandbox-unavailable reject (never a silent skip on a wired platform).
    let tools = establish_jail_tools()?;

    // The wrapper the jail runs must be readable inside the scratch; copy the
    // trusted fixture in (it owns the per-axis exit contract). Keep the fixture's
    // own file name so its extension is preserved — `.ps1` on Windows (PowerShell
    // resolves the wrapper by extension), `.sh` elsewhere.
    let wrapper_name = audit.probe_fixture.file_name().map_or_else(
        || OsString::from("untrusted-build"),
        std::ffi::OsStr::to_owned,
    );
    let wrapper = scratch.join(wrapper_name);
    std::fs::copy(&audit.probe_fixture, &wrapper).map_err(|e| CliError::Io {
        path: wrapper.clone(),
        source: e,
    })?;
    let working_tree = scratch.join("worktree");
    std::fs::create_dir_all(&working_tree).map_err(|e| CliError::Io {
        path: working_tree.clone(),
        source: e,
    })?;

    let scoped = scoped_profile(audit.declared).map_err(CliError::PackageAudit)?;
    // On the real-build path the exercise IS the child cargo build: the full
    // declared-scoped run is child-exit-only (no fixed axis probe, which would
    // fabricate a demand the package never made), and each tightening run probes
    // the single declared axis under test. The `exercised` field below is unused
    // on this path (it drives only the wrapper-probe-only shape's full run).
    let mut ro_binds = default_ro_binds();
    ro_binds.extend(toolchain_ro_binds()?);
    // The jailed `cargo build` reads the emitted app crate (which carries the
    // probe bin) and every crate its manifest pins by absolute path (the runtime
    // and each bound Rust dependency). Re-expose them read-only so the build can
    // read but never write them. Under the jail's `--ro-bind / /`, a crate under
    // an unmasked path is already readable and re-binding is idempotent; the
    // re-bind only matters when a crate lives under a masked tree (`/tmp`, home).
    ro_binds.extend(emitted_crate_ro_binds(audit.emitted_dir));
    let runner = JailProbeRunner::new(
        &tools,
        wrapper,
        scratch.clone(),
        working_tree,
        ro_binds,
        // Unused on the real-build path (the full run is child-exit-only and the
        // tightening runs probe the single declared axis under test), but the
        // field is shared with the wrapper-probe-only shape.
        vec![TightenableAxis::Network, TightenableAxis::Filesystem],
        exercise,
    );
    let static_scan = WrapperScan::over_package(audit.root)?;

    let verdict = reconcile_native(audit.declared, &runner, &static_scan, &scoped);
    // Best-effort scratch cleanup; a leftover scratch is inert.
    let _ = std::fs::remove_dir_all(&scratch);

    verdict.map_err(CliError::PackageAudit)?;

    // ── THE SINGLE `Certified` CONSTRUCTION SITE ──────────────────────────────
    // Reached only when: the package is native-bearing (checked above), the
    // survivor surface was non-empty, the exercise was a REAL non-empty untrusted
    // build (`runner.is_real_build()`), the host is a wired platform (this `cfg`:
    // linux-x86_64, macOS, FreeBSD, or Windows), and the reconciler returned
    // `Ok(())`
    // (declared-scoped `Clean` + no removable-and-unreached axis). `platform`
    // names exactly this host's wired jail (`CERTIFIED_PLATFORM`), so a certify
    // never claims a platform whose jail did not run. Any weaker condition
    // returned above.
    if runner.is_real_build() {
        Ok(Tier2Outcome::Certified {
            platform: CERTIFIED_PLATFORM,
        })
    } else {
        // Unreachable — `exercise` is a `RealBuild` by construction here — but a
        // wrapper-probe-only run must NEVER certify, so fail-closed rather than
        // trust the flow.
        Err(CliError::PackageAudit(no_probeable_entrypoint()))
    }
}

/// Off every wired platform Tier-2 NEVER constructs `Certified`: it rejects
/// fail-closed (an unwired host cannot confine the build, so it cannot vouch for
/// the native surface). Only the CI matrix on a wired platform admits (ADR 0004).
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
)))]
fn native_tier2_on_platform(_audit: &NativeAudit) -> Result<Tier2Outcome, CliError> {
    Err(CliError::PackageAudit(Rejection {
        check: Check::NativeTier2,
        message:
            "native Tier-2 capability enforcement is not wired on this host, so the native surface \
             cannot be confined and reconciled here. Tier-2 refuses to certify a native package on \
             an unwired platform (fail-closed) — the index CI matrix certifies on a wired platform \
             (linux-x64, macos-arm64, or freebsd-x64)."
                .to_owned(),
    }))
}

/// Create and return an exclusive Tier-2 probe scratch directory under the OS
/// temp root. The name is unpredictable (128-bit OS entropy) so a same-user
/// attacker cannot pre-seed or symlink it.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
fn probe_scratch_dir(root: &Path) -> Result<PathBuf, CliError> {
    let slug: String = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("pkg")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let prefix = format!("ipe-tier2-probe-{slug}");
    let scratch = ScratchDir::new(&prefix).map_err(|e| CliError::Io {
        path: std::path::PathBuf::from(&prefix),
        source: e,
    })?;
    let path = scratch.path().to_path_buf();
    // Caller cleans up via `remove_dir_all` (line ~981); skip Drop here.
    std::mem::forget(scratch);
    Ok(path)
}

/// One wrapper entry from the structured FFI sidecar.
///
/// The sidecar records both the fully-qualified probe path and whether the
/// wrapper is generic. A generic wrapper's address cannot be taken without a
/// turbofish, so it is excluded from the link-reference set in the probe while
/// the crate compile still exercises its build-time reach.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct WrapperEntry {
    /// Fully-qualified path: `crate::ffi::<slug>::<ident>`.
    path: String,
    /// Whether the wrapper is generic (`pub fn <ident><T: …>(…)`). A generic
    /// wrapper's build-time reach is exercised by the crate compile; its
    /// link-reach is not provable by address-of without a turbofish, so it is
    /// excluded from the probe's link-reference set.
    generic: bool,
}

/// Read the structured FFI sidecar (`src/ffi-wrappers.json`) emitted alongside
/// `src/ffi.rs` and return the full wrapper entry set.
///
/// The sidecar is the SSOT the emitter writes after DCE: it carries exactly
/// the surviving wrapper paths and their generic flags, so Tier-2 does not
/// re-parse the pretty-printed Rust text. Fail-closed on every parse failure:
/// a missing sidecar (the emitted crate was built without this hardening) or
/// a malformed entry → typed reject, never a false certify. An absent sidecar
/// alongside an absent `src/ffi.rs` → empty set (no surface to probe).
///
/// # Errors
/// [`CliError::PackageAudit`] with [`Check::NativeTier2`] when the sidecar
/// exists but is missing, unreadable, or structurally malformed — fail-closed,
/// the same typed reject the empty-survivor path produces.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
fn emitted_wrapper_paths(emitted_dir: &Path) -> Result<Vec<WrapperEntry>, CliError> {
    let sidecar_path = emitted_dir.join("src").join("ffi-wrappers.json");
    // When neither the sidecar nor `src/ffi.rs` exists the package has no FFI
    // surface — an empty set, not a parse error.
    let ffi_rs = emitted_dir.join("src").join("ffi.rs");
    if !sidecar_path.is_file() && !ffi_rs.is_file() {
        return Ok(Vec::new());
    }
    // A present `src/ffi.rs` with no sidecar means the emitted crate predates
    // this hardening: fail-closed rather than fall back to the line-scan.
    if !sidecar_path.is_file() {
        return Err(CliError::PackageAudit(Rejection {
            check: Check::NativeTier2,
            message: "the emitted crate carries `src/ffi.rs` but no `src/ffi-wrappers.json` \
                      sidecar — re-build the package with the current compiler to generate the \
                      structured sidecar Tier-2 reads (fail-closed)"
                .to_owned(),
        }));
    }
    let text = crate::io_bounded::read_to_string_capped(
        &sidecar_path,
        crate::io_bounded::FFI_CACHE_READ_CAP,
    )?;
    parse_ffi_wrappers_sidecar(&text, &sidecar_path)
}

/// Parse the JSON sidecar text into wrapper entries. Fail-closed: any
/// structural deviation — not a JSON object, missing `wrappers` array, a
/// wrapper entry that is not an object with `path` (string) and `generic`
/// (bool) — is a typed reject, never a vacuous clean.
///
/// Parsing is done without an external JSON library: the sidecar is compact,
/// one-line, machine-generated JSON with a fixed structure, so a hand-written
/// extractor is simpler than a full serde dependency and keeps the audit path
/// dependency-free.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
fn parse_ffi_wrappers_sidecar(text: &str, path: &Path) -> Result<Vec<WrapperEntry>, CliError> {
    let malformed = |detail: &str| {
        CliError::PackageAudit(Rejection {
            check: Check::NativeTier2,
            message: format!(
                "the FFI wrapper sidecar `{}` is malformed: {detail} — \
                 re-build the package with the current compiler (fail-closed)",
                path.display()
            ),
        })
    };
    // The sidecar is compact one-line JSON produced by the emitter; extract
    // entries via a simple state machine rather than a full parser.
    // Expected shape: {"wrappers":[{"path":"…","generic":true/false},…]}
    let text = text.trim();
    let inner = text
        .strip_prefix("{\"wrappers\":[")
        .and_then(|s| {
            s.strip_suffix("]}\n")
                .or_else(|| s.strip_suffix("]}"))
                .or_else(|| s.strip_suffix("]}\r\n"))
        })
        .ok_or_else(|| malformed("outer envelope `{\"wrappers\":[…]}` not found"))?;
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<WrapperEntry> = Vec::new();
    // Split on `},{` to iterate raw entry objects; each is `{"path":"…","generic":bool}`.
    let raw_entries: Vec<&str> = split_json_objects(inner);
    for raw in raw_entries {
        let raw = raw.trim_start_matches('{').trim_end_matches('}');
        let path_val = extract_json_string(raw, "path")
            .ok_or_else(|| malformed("wrapper entry missing `path` string"))?;
        let generic_val = extract_json_bool(raw, "generic")
            .ok_or_else(|| malformed("wrapper entry missing `generic` boolean"))?;
        // The path must be a valid Rust module path segment: letters, digits,
        // underscores, and `::`. Reject any path that does not start with
        // `crate::ffi::` — a tampered sidecar cannot forge a path the probe
        // would reference if the emitter never wrote it.
        if !path_val.starts_with("crate::ffi::") {
            return Err(malformed("wrapper path does not start with `crate::ffi::`"));
        }
        if path_val
            .chars()
            .any(|c| !c.is_alphanumeric() && c != '_' && c != ':')
        {
            return Err(malformed("wrapper path contains illegal characters"));
        }
        entries.push(WrapperEntry {
            path: path_val,
            generic: generic_val,
        });
    }
    Ok(entries)
}

/// Split a JSON array body (no outer `[…]`) into individual raw object strings
/// by tracking brace depth, so `},{` within a string value does not falsely
/// split. The sidecar's string values are Rust paths (`crate::ffi::…`) which
/// never contain `{` or `}`, so a simpler depth-tracker is sufficient.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
fn split_json_objects(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth: usize = 0;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    out.push(&s[start..=i]);
                    start = i + 1;
                    // Skip a leading `,` between entries.
                    if s[start..].starts_with(',') {
                        start += 1;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Extract a JSON string value for `key` from a flat key-value sequence.
/// Returns `None` when the key is absent or the value is not a JSON string.
/// Does not handle escaped quotes in values (not needed for Rust paths).
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
fn extract_json_string(obj: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = obj.find(&needle)? + needle.len();
    let rest = &obj[start..];
    // The sidecar's string values are Rust paths — no embedded `"` or `\`.
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// Extract a JSON boolean value for `key` from a flat key-value sequence.
/// Returns `None` when the key is absent or the value is not `true`/`false`.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
fn extract_json_bool(obj: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{key}\":");
    let start = obj.find(&needle)? + needle.len();
    let rest = obj[start..].trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Emit the link-reachability probe crate into the emitted app crate and return
/// the `cargo build` argv that builds it under the jail.
///
/// The probe is a second binary target whose crate root (`src/tier2_probe.rs`)
/// declares `mod ffi;` and references every surviving wrapper at
/// `crate::ffi::<slug>::<ident>`, so building it links the whole foreign surface.
/// The build is `--offline` with a scratch-local target dir: crate sources are
/// vendored/pre-fetched before the jailed build (design §5), so an ordinary build
/// needs no network, and a build that DOES reach the network is a genuine,
/// deterministic used-but-undeclared signal — not flake.
///
/// # Errors
/// [`CliError::Io`] when the probe source or the patched manifest cannot be
/// written.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
fn emit_probe_and_build_argv(
    emitted_dir: &Path,
    wrapper_paths: &[String],
    scratch: &Path,
) -> Result<Vec<OsString>, CliError> {
    std::fs::create_dir_all(scratch).map_err(|e| CliError::Io {
        path: scratch.to_path_buf(),
        source: e,
    })?;
    // The probe bin is its own crate root, so it does not inherit `main.rs`'s
    // crate-root runtime prelude. `src/ffi.rs` opens with `use crate::*;` and
    // names `IpeResult` / `IpeError` / `ok_res` / `ipe_error_from_panic`
    // unqualified, expecting the crate root to re-export the runtime — exactly
    // what `main.rs` provides. Re-export the SAME runtime prelude here (then
    // `mod ffi;`, which re-reads the SSOT `src/ffi.rs`) so the shared wrappers
    // resolve against the probe crate root too. The runtime is an extern crate in
    // the emitted app crate (the dep-model emit the audit build produces), so the
    // glob resolves against it directly.
    let crate_prelude = "pub use ipe_runtime::*;\npub use ipe_runtime::error::IpeError;\nmod ffi;";
    let probe_src = ipe_ffi::probe::emit_probe_main(wrapper_paths, crate_prelude);
    let probe_file = emitted_dir.join("src").join("tier2_probe.rs");
    std::fs::write(&probe_file, &probe_src).map_err(|e| CliError::Io {
        path: probe_file.clone(),
        source: e,
    })?;

    // Append the probe `[[bin]]` to the emitted manifest (idempotent: a re-audit
    // rewrites the whole file from the emitted base + this one appended target).
    let manifest_path = emitted_dir.join("Cargo.toml");
    let base = crate::io_bounded::read_to_string_capped(
        &manifest_path,
        crate::io_bounded::SMALL_FILE_READ_CAP,
    )?;
    let bin_stanza = "\n[[bin]]\nname = \"tier2_probe\"\npath = \"src/tier2_probe.rs\"\n";
    if !base.contains("name = \"tier2_probe\"") {
        let patched = format!("{base}{bin_stanza}");
        std::fs::write(&manifest_path, patched).map_err(|e| CliError::Io {
            path: manifest_path.clone(),
            source: e,
        })?;
    }

    let target_dir = scratch.join("target");
    let cargo = absolute_cargo().unwrap_or_else(|| PathBuf::from("cargo"));

    // Resolve the dependency graph to a `Cargo.lock` in the emitted crate BEFORE
    // the jailed build runs. The jail binds the emitted crate read-only, so a
    // build that had to write the lock in-place would fail on the read-only mount.
    // Generating the lock here (outside the jail, from the toolchain's pre-fetched
    // registry cache) lets the jailed build run `--locked --offline`: it reads the
    // resolved graph and writes nothing but its own scratch-local target dir. A
    // lock-generation failure is not itself a jail verdict; the jailed `--locked`
    // build surfaces any residual resolution gap as a build failure, fail-closed.
    let _ = std::process::Command::new(&cargo)
        .arg("generate-lockfile")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output();

    Ok(vec![
        cargo.into_os_string(),
        OsString::from("build"),
        OsString::from("--offline"),
        OsString::from("--locked"),
        OsString::from("--bin"),
        OsString::from("tier2_probe"),
        OsString::from("--manifest-path"),
        manifest_path.into_os_string(),
        OsString::from("--target-dir"),
        target_dir.into_os_string(),
    ])
}

/// The un-exercised reject: a native-bearing package with no probeable entrypoint
/// for the differential probe to drive. Fail-closed — never a silent clean.
///
/// Only [`native_tier2_on_platform`]'s wired arm calls this; on an unwired host
/// the refuse-to-certify is decided earlier and this is never reached, so its
/// definition is gated to the same wired set (used-or-absent per platform).
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
fn no_probeable_entrypoint() -> Rejection {
    Rejection {
        check: Check::NativeTier2,
        message: format!(
            "this package is native-bearing (it declares `native-ffi` or binds a Rust dependency), \
             but exposes no capability-probe entrypoint for Tier-2 to exercise its native code \
             under a declared-scoped jail on {CERTIFIED_PLATFORM}. Tier-2 refuses to certify a \
             native package it cannot exercise, rather than admit it un-observed (fail-closed)."
        ),
    }
}

/// The read-only tool binds the wrapper needs re-exposed past the jail's tmpfs
/// masks (the interpreters `/bin/sh`, `/usr/bin/env`, python3/nc for the net
/// probe). Only existing paths are bound.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd"
))]
#[must_use]
pub fn default_ro_binds() -> Vec<PathBuf> {
    [
        PathBuf::from("/usr"),
        PathBuf::from("/bin"),
        PathBuf::from("/lib"),
        PathBuf::from("/lib64"),
    ]
    .into_iter()
    .filter(|p| p.exists())
    .collect()
}

/// Windows: the jail reads no read-only tool binds, so the bind set is empty.
///
/// The Job Object plus `AppContainer` grants reach by ACL-ing the scratch and
/// working-tree, not by binding host tool paths past a tmpfs mask (there is no
/// tmpfs mask on Windows). The `powershell.exe` interpreter resolves through the
/// scrubbed `PATH`/`SystemRoot` the jail re-exports.
#[cfg(target_os = "windows")]
#[must_use]
pub const fn default_ro_binds() -> Vec<PathBuf> {
    Vec::new()
}

/// The read-only toolchain binds a real `cargo build` needs inside the jail.
///
/// The Cargo home (`~/.cargo` or `$CARGO_HOME` — the `cargo`/`rustc` shims and the
/// registry cache of pre-fetched crate sources) and the Rustup home (`~/.rustup`
/// or `$RUSTUP_HOME` — the actual toolchain binaries the shims resolve to). Bound
/// READ-ONLY: the jail's own scratch-local target dir is the only writable output,
/// so binding the toolchain read-only cannot let the untrusted build escape. Only
/// existing paths are bound.
///
/// These are ADDED to [`default_ro_binds`] on the real-build path only; the
/// wrapper-probe-only control fixture needs no toolchain, so its bind set is
/// unchanged.
///
/// # Errors
/// [`CliError::EnvDirNotAbsolute`] when `CARGO_HOME` or `RUSTUP_HOME` is set
/// but relative — binding the home default instead would expose a toolchain the
/// host `cargo` never uses.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd"
))]
pub fn toolchain_ro_binds() -> Result<Vec<PathBuf>, CliError> {
    Ok([
        crate::env_dir::tool_home("CARGO_HOME", ".cargo")?,
        crate::env_dir::tool_home("RUSTUP_HOME", ".rustup")?,
    ]
    .into_iter()
    .flatten()
    .filter(|p| p.exists())
    .collect())
}

/// Windows: the jail reads no read-only tool binds, so the toolchain bind set is
/// empty.
///
/// A real Windows `cargo build` reaches its toolchain through the ACL-granted
/// scratch and the jail's scrubbed `PATH` (see [`default_ro_binds`]), not host
/// path binds.
///
/// # Errors
/// Never; the signature matches the fallible POSIX resolution.
#[cfg(target_os = "windows")]
#[allow(clippy::unnecessary_wraps)] // shares the fallible POSIX signature
pub const fn toolchain_ro_binds() -> Result<Vec<PathBuf>, CliError> {
    Ok(Vec::new())
}

/// The read-only binds the emitted app crate (carrying the probe bin) and every
/// crate its manifest pins by absolute `path = "…"` need inside the jail.
///
/// The jailed `cargo build` reads `emitted_dir` (the probe crate's manifest and
/// `src/`) and each absolute path dependency the emitted `Cargo.toml` declares —
/// the vendored runtime and any bound Rust crate pinned to a local path. Each is
/// re-exposed read-only so the build can read but never write it. A `path = "…"`
/// value that is not absolute, or that does not exist, is skipped: only a
/// resolvable directory is bound.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd"
))]
fn emitted_crate_ro_binds(emitted_dir: &Path) -> Vec<PathBuf> {
    let mut binds: Vec<PathBuf> = Vec::new();
    if emitted_dir.is_dir() {
        binds.push(emitted_dir.to_path_buf());
    }
    let manifest = emitted_dir.join("Cargo.toml");
    if let Ok(text) =
        crate::io_bounded::read_to_string_capped(&manifest, crate::io_bounded::SMALL_FILE_READ_CAP)
    {
        for path in manifest_path_dependencies(&text) {
            if path.is_absolute() && path.exists() {
                if let Some(root) = cargo_workspace_root(&path) {
                    binds.push(root);
                } else {
                    binds.push(path);
                }
            }
        }
    }
    binds
}

/// The Cargo workspace root that governs the crate at `crate_dir`, or `None` when
/// the crate is standalone (its own `Cargo.toml` declares `[workspace]`, or no
/// ancestor does).
///
/// A path dependency whose `Cargo.toml` inherits a field from the workspace
/// (`version.workspace = true`) fails to build unless the workspace root manifest
/// is also readable. Binding the workspace root instead of the bare crate dir
/// re-exposes both the crate and the root manifest it inherits from.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd"
))]
fn cargo_workspace_root(crate_dir: &Path) -> Option<PathBuf> {
    let declares_workspace = |dir: &Path| -> bool {
        crate::io_bounded::read_to_string_capped(
            &dir.join("Cargo.toml"),
            crate::io_bounded::SMALL_FILE_READ_CAP,
        )
        .is_ok_and(|t| t.lines().any(|l| l.trim_start().starts_with("[workspace]")))
    };
    if declares_workspace(crate_dir) {
        return None;
    }
    let mut dir = crate_dir.parent();
    while let Some(candidate) = dir {
        if declares_workspace(candidate) {
            return Some(candidate.to_path_buf());
        }
        dir = candidate.parent();
    }
    None
}

/// Windows: the jail ACL-grants an existing view of the real filesystem rather
/// than building a bind-mount namespace, so no path re-binds are needed.
#[cfg(target_os = "windows")]
fn emitted_crate_ro_binds(_emitted_dir: &Path) -> Vec<PathBuf> {
    Vec::new()
}

/// Every `path = "<value>"` under a `[…dependencies]` table in a `Cargo.toml`,
/// as a [`PathBuf`]. A parse-free scan: a manifest line whose trimmed form is
/// `path = "…"`, or that carries an inline `path = "…"` key, yields the quoted
/// value. Values are returned in manifest order; the caller filters to absolute,
/// existing directories.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd"
))]
fn manifest_path_dependencies(manifest: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for line in manifest.lines() {
        let mut rest = line;
        while let Some(pos) = rest.find("path") {
            let after = &rest[pos + "path".len()..];
            let after = after.trim_start();
            let Some(after) = after.strip_prefix('=') else {
                rest = &rest[pos + "path".len()..];
                continue;
            };
            let after = after.trim_start();
            let Some(after) = after.strip_prefix('"') else {
                rest = after;
                continue;
            };
            if let Some(end) = after.find('"') {
                out.push(PathBuf::from(&after[..end]));
                rest = &after[end + 1..];
            } else {
                break;
            }
        }
    }
    out
}

/// The Cargo/Rustup home env the jailed `cargo build` needs to resolve its
/// toolchain: `CARGO_HOME`, `RUSTUP_HOME`, and `HOME` (the shims' fallback). Only
/// present, existing homes are returned; the wrapper sets them in the payload's
/// own env, never the process-global environment.
///
/// POSIX-only: the Windows probe payload carries no toolchain-home assignments
/// (the Windows jail's own env scrub provides `SystemRoot`/`PATH`/`TMP`, and a
/// real Windows Tier-2 build allowlists the homes through the declared `env`
/// axis), so this is not compiled on Windows.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd"
))]
fn cargo_home_env() -> Result<Vec<(String, std::ffi::OsString)>, CliError> {
    let existing = |dir: Option<PathBuf>| dir.filter(|p| p.exists()).map(PathBuf::into_os_string);
    let mut out: Vec<(String, std::ffi::OsString)> = Vec::new();
    if let Some(v) = existing(crate::env_dir::tool_home("CARGO_HOME", ".cargo")?) {
        out.push(("CARGO_HOME".to_owned(), v));
    }
    if let Some(v) = existing(crate::env_dir::tool_home("RUSTUP_HOME", ".rustup")?) {
        out.push(("RUSTUP_HOME".to_owned(), v));
    }
    if let Some(h) = existing(crate::env_dir::home()) {
        out.push(("HOME".to_owned(), h));
    }
    Ok(out)
}

/// The absolute path to `cargo`, resolved from `PATH` (the in-jail PATH is a
/// fixed `/usr/bin:/bin`, so a bare `cargo` is unfindable inside the jail; the
/// toolchain bind makes the absolute path executable). `None` when cargo is not
/// on the host `PATH`.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
fn absolute_cargo() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|p| p.join("cargo"))
        .find(|p| p.is_file())
}

/// The production probe runner: establishes the real Linux jail and runs the
/// wrapper-owned probe under it via [`build_in_jail`], so the untrusted build is
/// a child of our exit-owning wrapper.
///
/// Public so an end-to-end test can drive [`reconcile_native`] through the REAL
/// jail exactly as production does, proving the wiring (a denial names the axis,
/// a clean run requires the probe's positive clean exit) at the OS boundary.
///
/// [`build_in_jail`]: ipe_sandbox::build_jail::build_in_jail
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
pub struct JailProbeRunner<'a> {
    tools: &'a RunJailTools,
    wrapper: PathBuf,
    scoped_tmp: PathBuf,
    working_tree: PathBuf,
    ro_binds: Vec<PathBuf>,
    /// The axes the native code (the wrapper stand-in) actually EXERCISES on the
    /// full declared-scoped run — a property of the code, not of the declaration,
    /// so a used-but-undeclared axis (exercised but not declared, hence withheld)
    /// is observed as a denial. The tightening runs override this with the single
    /// axis under test.
    exercised: Vec<TightenableAxis>,
    /// The exercise the wrapper drives: the package's OWN `cargo build` as the
    /// wrapper's child (the certify-eligible shape), or the wrapper's fixed axis
    /// probe alone (the enforce/control shape, never certify-eligible).
    exercise: ProbeExercise,
}

#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
impl<'a> JailProbeRunner<'a> {
    /// Build a jail-backed runner over an established set of jail `tools`, the
    /// exit-owning `wrapper` script (readable inside the jail — the caller must
    /// place it in the scratch), the always-writable `scoped_tmp`, the
    /// filesystem-axis-gated `working_tree`, the read-only tool `ro_binds`, and
    /// the axes the native code `exercised` on the full run. `exercise` is the
    /// strictly subordinate build tail (or the wrapper-probe-only shape).
    #[must_use]
    pub const fn new(
        tools: &'a RunJailTools,
        wrapper: PathBuf,
        scoped_tmp: PathBuf,
        working_tree: PathBuf,
        ro_binds: Vec<PathBuf>,
        exercised: Vec<TightenableAxis>,
        exercise: ProbeExercise,
    ) -> Self {
        Self {
            tools,
            wrapper,
            scoped_tmp,
            working_tree,
            ro_binds,
            exercised,
            exercise,
        }
    }

    /// Whether this runner drives a real, non-empty untrusted build — the
    /// [`Tier2Outcome::Certified`] guard reads it so a certify can never rest on
    /// the wrapper-probe-only stand-in shape.
    #[must_use]
    pub const fn is_real_build(&self) -> bool {
        self.exercise.is_real_build()
    }
}

#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
impl ProbeRunner for JailProbeRunner<'_> {
    fn run(&self, profile: &SandboxProfile, withheld: Option<TightenableAxis>) -> JailOutcome {
        // The axis selector the fixture reads.
        //
        // - A TIGHTENING run (`Some(axis)`) probes exactly that one axis. The axis
        //   is one the author DECLARED, so probing it fabricates no demand: the
        //   run can only KEEP the axis (denied → needed) or reject, never certify.
        // - The FULL declared-scoped run (`None`) of a REAL build is child-exit-
        //   only (`none`): NO fixed axis probe runs, because a fixed probe would
        //   fabricate a demand the package never made, so no declared set other
        //   than {network,filesystem} could ever certify. The verdict is the child
        //   build's own exit (a withheld axis is withheld by capability removal, so
        //   a build reaching it fails; a build that caught the error did no effect).
        // - The FULL run of the wrapper-probe-only shape (the enforce/control test
        //   fixture) keeps the fixed-probe selector over the axes it EXERCISES.
        let axis_sel: OsString = match withheld {
            Some(a) => OsString::from(a.as_str()),
            None if self.exercise.is_real_build() => OsString::from("none"),
            None => match exercised_selector(&self.exercised) {
                Some(sel) => OsString::from(sel),
                // The stand-in exercises no tightenable axis, so a declared-scoped
                // jail cannot deny it: Clean by construction, never a forged exit.
                None => return JailOutcome::Clean,
            },
        };
        // The fs-escape target lives in the WORKING TREE (bound read-write only
        // when the filesystem axis is granted), not the always-writable scratch —
        // so the write succeeds under a filesystem-granted jail and is denied
        // under a filesystem-withholding one, making the axis differentially
        // observable.
        let escape = self.working_tree.join("tier2-escape-probe");
        // Build the platform-native wrapper payload (POSIX `/bin/sh` vs Windows
        // `powershell.exe -File`), both enforcing the child-of-wrapper rule.
        // A toolchain home that cannot be resolved faithfully fails the run
        // closed rather than building against a toolchain the host never uses.
        let payload = match self.probe_payload(axis_sel.as_os_str(), &escape) {
            Ok(payload) => payload,
            Err(err) => {
                return JailOutcome::BuildFailed {
                    reason: err.to_string(),
                };
            }
        };
        ipe_sandbox::build_jail::build_in_jail(
            self.tools,
            profile,
            &self.scoped_tmp,
            &self.working_tree,
            &self.ro_binds,
            payload.argv(),
        )
    }
}

// The POSIX (`/bin/sh`) and Windows (`powershell.exe`) wrapper-payload builders.
// Both enforce the child-of-wrapper rule via `ProbePayload`; they differ only in
// how per-run config reaches the wrapper — env assignments through
// `/usr/bin/env` on POSIX (whose `--clearenv` jail re-exports them via the
// payload), named parameters on the command line on Windows (whose jail scrubs
// the child environment to a fixed allowlist, so config must travel through
// argv, which flows through `CreateProcessW`).

#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd"
))]
impl JailProbeRunner<'_> {
    /// The POSIX payload: `env PROBE_MODE=tier2 TIER2_AXIS=… SCRATCH_DIR=…
    /// ESCAPE_PATH=… [toolchain homes] /bin/sh <wrapper.sh> <untrusted tail>`.
    fn probe_payload(
        &self,
        axis_sel: &std::ffi::OsStr,
        escape: &Path,
    ) -> Result<ProbePayload, CliError> {
        // The fixed, trusted, exit-transparent launcher: `env NAME=VALUE … /bin/sh`
        // runs the wrapper under a scrubbed environment (per-run config travels
        // through the payload, never the process-global environment). It
        // propagates the wrapper's exit unchanged.
        let mut invocation_prefix = vec![
            OsString::from("/usr/bin/env"),
            OsString::from("PROBE_MODE=tier2"),
            assignment("TIER2_AXIS", axis_sel),
            assignment("SCRATCH_DIR", self.scoped_tmp.as_os_str()),
            assignment("ESCAPE_PATH", escape.as_os_str()),
        ];
        // A real `cargo build` inside the scrubbed jail needs the toolchain homes
        // to resolve (the `cargo`/`rustc` rustup shims read `CARGO_HOME`/
        // `RUSTUP_HOME`, falling back to `$HOME`). These are passed through the
        // payload's own env — never the process-global environment — and the homes
        // are bound read-only, so the untrusted build can read the toolchain but
        // cannot write it. On the wrapper-probe-only shape they are absent.
        if self.exercise.is_real_build() {
            for (name, value) in cargo_home_env()? {
                invocation_prefix.push(assignment(&name, value.as_os_str()));
            }
        }
        invocation_prefix.push(OsString::from("/bin/sh"));
        // The wrapper script owns the exit contract; the untrusted build is a
        // strictly subordinate tail it runs as its child (ProbePayload enforces
        // the ordering). The untrusted build can never own the exit.
        Ok(ProbePayload::wrapper_owned(
            &invocation_prefix,
            &self.wrapper,
            self.exercise.tail(),
        ))
    }
}

#[cfg(target_os = "windows")]
impl JailProbeRunner<'_> {
    /// The Windows payload: `powershell.exe -NoProfile -NonInteractive -File
    /// <wrapper.ps1> -Tier2Axis <axis> -ScratchDir <scratch> -EscapePath <escape>
    /// -- <untrusted tail>`.
    ///
    /// PowerShell is `payload[0]` — the `CreateProcessW`-invokable interpreter the
    /// Windows jail runs directly (no shell). The wrapper's config travels as
    /// NAMED PARAMETERS between the wrapper and the `--` terminator (the untrusted
    /// build follows `--`, captured in the wrapper's `$args`): the Windows jail
    /// scrubs the child environment to a fixed allowlist, so env-carried config
    /// would be dropped or require widening the `env` axis. `ProbePayload`'s
    /// wrapper-flags constructor keeps the wrapper strictly before the untrusted
    /// tail, so the child-of-wrapper rule holds — the untrusted build can never
    /// own the exit the decoder reads.
    ///
    /// The toolchain homes a real `cargo build` needs (`CARGO_HOME`/`RUSTUP_HOME`)
    /// are NOT injected here: the Windows jail's own env scrub carries `SystemRoot`
    /// / `PATH` / `TMP` / `TEMP`, and a real Windows Tier-2 build would allowlist
    /// the toolchain homes through the declared `env` axis. The wrapper-probe-only
    /// and offline-probe shapes the CI E2E exercises need none.
    #[allow(clippy::unnecessary_wraps)] // shares the fallible POSIX signature
    fn probe_payload(
        &self,
        axis_sel: &std::ffi::OsStr,
        escape: &Path,
    ) -> Result<ProbePayload, CliError> {
        let invocation_prefix = vec![
            self.tools.bwrap.clone().into_os_string(),
            OsString::from("-NoProfile"),
            OsString::from("-NonInteractive"),
            OsString::from("-ExecutionPolicy"),
            OsString::from("Bypass"),
            OsString::from("-File"),
        ];
        // The wrapper's own trusted config, as named parameters, terminated by
        // `--` so the untrusted build tail is captured in `$args`, never parsed as
        // a wrapper parameter.
        let wrapper_flags = vec![
            OsString::from("-Tier2Axis"),
            axis_sel.to_owned(),
            OsString::from("-ScratchDir"),
            self.scoped_tmp.as_os_str().to_owned(),
            OsString::from("-EscapePath"),
            escape.as_os_str().to_owned(),
            OsString::from("--"),
        ];
        Ok(ProbePayload::wrapper_owned_with_flags(
            &invocation_prefix,
            &self.wrapper,
            &wrapper_flags,
            self.exercise.tail(),
        ))
    }
}

/// The fixture's `TIER2_AXIS` value for a set of exercised axes: `both`,
/// `network`, `filesystem`, or `None` when the native code exercises no
/// tightenable axis (the caller then produces a Clean-by-construction outcome
/// without a spawn).
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
fn exercised_selector(exercised: &[TightenableAxis]) -> Option<&'static str> {
    let net = exercised.contains(&TightenableAxis::Network);
    let fs = exercised.contains(&TightenableAxis::Filesystem);
    match (net, fs) {
        (true, true) => Some("both"),
        (true, false) => Some("network"),
        (false, true) => Some("filesystem"),
        (false, false) => None,
    }
}

/// Build a single `NAME=VALUE` token for `env(1)`. The value is an `OsStr` so a
/// scratch path with non-UTF-8 bytes survives without a lossy round-trip.
///
/// POSIX-only: the Windows probe payload carries config as named command-line
/// parameters, not `env(1)` assignments, so this is not compiled on Windows.
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "freebsd"
))]
fn assignment(name: &str, value: &std::ffi::OsStr) -> OsString {
    let mut a = OsString::from(name);
    a.push("=");
    a.push(value);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(caps: &[Capability]) -> BTreeSet<Capability> {
        caps.iter().copied().collect()
    }

    /// A scripted runner: answers each `(withheld)` query from a fixed table so a
    /// test drives the exact matrix branch it targets. An unlisted query is a
    /// deliberate `BuildFailed` (never accidentally clean).
    struct ScriptedRunner {
        /// Outcome for the full declared-scoped run (`withheld == None`).
        full: JailOutcome,
        /// Outcome for each tightening run keyed by the withheld axis name.
        tighten: std::collections::BTreeMap<&'static str, JailOutcome>,
    }

    impl ProbeRunner for ScriptedRunner {
        fn run(&self, _profile: &SandboxProfile, withheld: Option<TightenableAxis>) -> JailOutcome {
            withheld.map_or_else(
                || self.full.clone(),
                |a| {
                    self.tighten.get(a.as_str()).cloned().unwrap_or_else(|| {
                        JailOutcome::BuildFailed {
                            reason: "unscripted tighten query".to_owned(),
                        }
                    })
                },
            )
        }
    }

    /// A static scan that reports a fixed reachable set.
    struct FixedScan {
        reaches: BTreeSet<Capability>,
    }

    impl StaticReachability for FixedScan {
        fn reaches(&self, axis: TightenableAxis) -> bool {
            self.reaches.contains(&axis.capability())
        }
    }

    fn scan(reaches: &[Capability]) -> FixedScan {
        FixedScan {
            reaches: reaches.iter().copied().collect(),
        }
    }

    fn scripted(full: JailOutcome, tighten: &[(&'static str, JailOutcome)]) -> ScriptedRunner {
        ScriptedRunner {
            full,
            tighten: tighten.iter().cloned().collect(),
        }
    }

    fn profile() -> SandboxProfile {
        SandboxProfile::maximally_isolated()
    }

    #[test]
    fn native_bearing_is_rust_deps_or_declared_native_ffi() {
        assert!(!is_native_bearing(&set(&[Capability::Network]), false));
        assert!(is_native_bearing(&set(&[Capability::NativeFfi]), false));
        assert!(is_native_bearing(&BTreeSet::new(), true));
        assert!(!is_native_bearing(&BTreeSet::new(), false));
    }

    #[test]
    fn a_used_but_undeclared_axis_rejects_naming_it() {
        // Declared `[]`; the declared-scoped run is DENIED naming network — a
        // hidden effect. Reject naming the network axis.
        let declared = BTreeSet::new();
        let runner = scripted(
            JailOutcome::Denied {
                axis: CapabilityAxis::Network,
            },
            &[],
        );
        let r = reconcile_native(&declared, &runner, &scan(&[]), &profile())
            .expect_err("a denied withheld axis must reject");
        assert_eq!(r.check, Check::NativeTier2);
        assert!(r.message.contains("network"), "{}", r.message);
        assert!(r.message.contains("hidden effect"), "{}", r.message);
    }

    #[test]
    fn a_used_but_undeclared_filesystem_axis_rejects_naming_filesystem() {
        let declared = set(&[Capability::Clock]);
        let runner = scripted(
            JailOutcome::Denied {
                axis: CapabilityAxis::Filesystem,
            },
            &[],
        );
        let r = reconcile_native(&declared, &runner, &scan(&[]), &profile())
            .expect_err("a denied filesystem axis must reject");
        assert!(r.message.contains("filesystem"), "{}", r.message);
    }

    #[test]
    fn a_declared_but_unused_axis_rejects_when_static_scan_agrees() {
        // Declares network; the declared-scoped run is clean, the tighten run
        // (network removed) STAYS clean, and the static scan does NOT reach
        // network → over-broad → reject.
        let declared = set(&[Capability::Network]);
        let runner = scripted(JailOutcome::Clean, &[("network", JailOutcome::Clean)]);
        let r = reconcile_native(&declared, &runner, &scan(&[]), &profile())
            .expect_err("an unused declared axis must reject");
        assert!(r.message.contains("network"), "{}", r.message);
        assert!(r.message.contains("over-broad"), "{}", r.message);
    }

    #[test]
    fn a_declared_but_unused_axis_is_not_flagged_when_the_static_scan_still_reaches_it() {
        // The tighten says removable, but the static scan STILL reaches network —
        // flagging would push the author to under-declare a present capability
        // (the laundering path). Do not reject on the tighten alone → admit.
        let declared = set(&[Capability::Network]);
        let runner = scripted(JailOutcome::Clean, &[("network", JailOutcome::Clean)]);
        reconcile_native(
            &declared,
            &runner,
            &scan(&[Capability::Network]),
            &profile(),
        )
        .expect("static scan reaches the axis → not flagged unused → admit");
    }

    #[test]
    fn a_needed_declared_axis_is_not_over_broad() {
        // Declares network; the tighten run (network removed) is DENIED naming
        // network — the axis IS needed, so it is not over-broad → admit.
        let declared = set(&[Capability::Network]);
        let runner = scripted(
            JailOutcome::Clean,
            &[(
                "network",
                JailOutcome::Denied {
                    axis: CapabilityAxis::Network,
                },
            )],
        );
        reconcile_native(&declared, &runner, &scan(&[]), &profile())
            .expect("a needed declared axis must admit");
    }

    #[test]
    fn a_build_failure_in_jail_rejects_distinctly_from_a_denial() {
        let declared = BTreeSet::new();
        let runner = scripted(
            JailOutcome::BuildFailed {
                reason: "rustc error E0308".to_owned(),
            },
            &[],
        );
        let r = reconcile_native(&declared, &runner, &scan(&[]), &profile())
            .expect_err("a build failure must reject");
        assert!(r.message.contains("failed to build"), "{}", r.message);
        assert!(
            !r.message.contains("hidden effect"),
            "must not be a used-but-undeclared diagnostic: {}",
            r.message
        );
    }

    #[test]
    fn sandbox_unavailable_rejects_the_platform_never_skips() {
        let declared = BTreeSet::new();
        let runner = scripted(
            JailOutcome::Unavailable {
                defect: RunJailDefect::PrimitiveUnavailable {
                    missing: vec!["bwrap"],
                },
            },
            &[],
        );
        let r = reconcile_native(&declared, &runner, &scan(&[]), &profile())
            .expect_err("an unavailable jail must reject, never skip");
        assert!(r.message.contains(CERTIFIED_PLATFORM), "{}", r.message);
        assert!(r.message.contains("never run unconfined"), "{}", r.message);
    }

    #[test]
    fn a_benign_package_declaring_exactly_its_axes_admits() {
        // Declares network; the declared-scoped run is clean; the tighten run
        // (network removed) is DENIED naming network (the axis is needed) → the
        // declaration is exactly right → admit.
        let declared = set(&[Capability::Network]);
        let runner = scripted(
            JailOutcome::Clean,
            &[(
                "network",
                JailOutcome::Denied {
                    axis: CapabilityAxis::Network,
                },
            )],
        );
        reconcile_native(
            &declared,
            &runner,
            &scan(&[Capability::Network]),
            &profile(),
        )
        .expect("a benign package declaring exactly its axes must admit");
    }

    #[test]
    fn a_clean_package_with_no_declared_axes_admits() {
        // Declares nothing tightenable; the declared-scoped run is clean; no
        // tightening pass runs → admit.
        let declared = set(&[Capability::Clock]);
        let runner = scripted(JailOutcome::Clean, &[]);
        reconcile_native(&declared, &runner, &scan(&[]), &profile())
            .expect("a clock-only native package with a clean probe must admit");
    }

    #[test]
    fn an_ambiguous_tighten_denial_naming_a_different_axis_rejects() {
        // Declares network AND filesystem; the network-tighten run is DENIED
        // naming filesystem — an observation the reconciler will not reason past.
        let declared = set(&[Capability::Network, Capability::Filesystem]);
        let runner = scripted(
            JailOutcome::Clean,
            &[(
                "network",
                JailOutcome::Denied {
                    axis: CapabilityAxis::Filesystem,
                },
            )],
        );
        let r = reconcile_native(&declared, &runner, &scan(&[]), &profile())
            .expect_err("an axis-mismatched denial must reject fail-closed");
        assert!(r.message.contains("ambiguous"), "{}", r.message);
    }

    #[test]
    fn the_probe_payload_puts_the_wrapper_before_the_untrusted_build() {
        // The child-of-wrapper structural rule: the exit-owning wrapper precedes
        // the untrusted build, which is only ever a strictly subordinate tail.
        let prefix = vec![OsString::from("/usr/bin/env"), OsString::from("/bin/sh")];
        let wrapper = PathBuf::from("/probe/untrusted-build.sh");
        let untrusted = vec![OsString::from("cargo"), OsString::from("build")];
        let payload = ProbePayload::wrapper_owned(&prefix, &wrapper, &untrusted);
        let argv = payload.argv();
        // The untrusted build is never at argv[0] — the trusted prefix is.
        assert_eq!(argv.first(), Some(&OsString::from("/usr/bin/env")));
        assert_eq!(argv.last(), Some(&OsString::from("build")));
        // The wrapper script strictly precedes the untrusted build command.
        let wrapper_idx = argv
            .iter()
            .position(|a| a == &OsString::from("/probe/untrusted-build.sh"))
            .expect("wrapper present");
        let cargo_idx = argv
            .iter()
            .position(|a| a == &OsString::from("cargo"))
            .expect("untrusted build present");
        assert!(
            wrapper_idx < cargo_idx,
            "the wrapper must precede the untrusted build: {argv:?}"
        );
    }

    #[test]
    fn wrapper_flags_sit_between_the_wrapper_and_the_untrusted_build() {
        // The Windows-shaped payload: the wrapper's OWN trusted config flags
        // (`-Tier2Axis … --`) sit AFTER the wrapper and BEFORE the untrusted build,
        // so the wrapper still strictly precedes the untrusted tail (child-of-
        // wrapper holds) and the flags are never the untrusted package's argv.
        let prefix = vec![OsString::from("powershell.exe"), OsString::from("-File")];
        let wrapper = PathBuf::from("C:/probe/untrusted-build.ps1");
        let flags = vec![
            OsString::from("-Tier2Axis"),
            OsString::from("network"),
            OsString::from("--"),
        ];
        let untrusted = vec![OsString::from("cargo"), OsString::from("build")];
        let payload = ProbePayload::wrapper_owned_with_flags(&prefix, &wrapper, &flags, &untrusted);
        let argv = payload.argv();
        // The trusted prefix is argv[0], never the untrusted build.
        assert_eq!(argv.first(), Some(&OsString::from("powershell.exe")));
        assert_eq!(argv.last(), Some(&OsString::from("build")));
        let idx = |needle: &str| {
            argv.iter()
                .position(|a| a == &OsString::from(needle))
                .expect("token present in the payload argv")
        };
        let wrapper_idx = idx("C:/probe/untrusted-build.ps1");
        let axis_idx = idx("-Tier2Axis");
        let sep_idx = idx("--");
        let cargo_idx = idx("cargo");
        // wrapper < flags < `--` < untrusted build: the ordering the child-of-
        // wrapper invariant depends on, so an untrusted token can never bind a
        // wrapper parameter nor own the exit.
        assert!(
            wrapper_idx < axis_idx && axis_idx < sep_idx && sep_idx < cargo_idx,
            "wrapper, then flags, then `--`, then the untrusted build: {argv:?}"
        );
    }

    #[cfg(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    #[test]
    fn emitted_wrapper_paths_reads_sidecar_not_ffi_rs_text() {
        // Tier-2 reads the structured sidecar (`src/ffi-wrappers.json`) emitted
        // alongside `src/ffi.rs`, not the pretty-printed Rust text. The sidecar
        // is the SSOT: it carries the DCE-shaken set as structured data, decoupled
        // from Rust formatting.
        let dir = std::env::temp_dir().join(format!("ipe-sidecar-read-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).expect("src dir");
        // Write a sidecar with two non-generic and one generic wrapper.
        std::fs::write(
            dir.join("src").join("ffi-wrappers.json"),
            "{\"wrappers\":[\
             {\"path\":\"crate::ffi::other::other_go\",\"generic\":false},\
             {\"path\":\"crate::ffi::tm::tm_classify\",\"generic\":false},\
             {\"path\":\"crate::ffi::tm::tm_shift\",\"generic\":false}]}\n",
        )
        .expect("write ffi-wrappers.json");
        // Also write ffi.rs so the sidecar-absent guard does not fire.
        std::fs::write(dir.join("src").join("ffi.rs"), "// placeholder\n").expect("write ffi.rs");
        let entries = emitted_wrapper_paths(&dir).expect("read sidecar");
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "crate::ffi::other::other_go",
                "crate::ffi::tm::tm_classify",
                "crate::ffi::tm::tm_shift",
            ],
            "sidecar yields one sorted entry per wrapper"
        );
        assert!(
            entries.iter().all(|e| !e.generic),
            "all entries are non-generic"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    #[test]
    fn missing_sidecar_when_ffi_rs_present_rejects_fail_closed() {
        // A present `src/ffi.rs` with no sidecar → typed reject (fail-closed).
        // This guards against an emitted crate that predates the sidecar or a
        // sidecar that was manually deleted: never fall back to text-scan.
        let dir = std::env::temp_dir().join(format!("ipe-no-sidecar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).expect("src dir");
        std::fs::write(
            dir.join("src").join("ffi.rs"),
            "pub mod tm { pub fn f() {} }\n",
        )
        .expect("write ffi.rs");
        let err = emitted_wrapper_paths(&dir).expect_err("missing sidecar must reject");
        assert!(
            matches!(err, crate::CliError::PackageAudit(ref r) if r.check == Check::NativeTier2),
            "a missing sidecar is a Tier-2 typed reject: {err:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    #[test]
    fn corrupt_sidecar_rejects_fail_closed() {
        // A sidecar with malformed JSON → typed reject (fail-closed), never a
        // vacuous clean.
        let dir = std::env::temp_dir().join(format!("ipe-corrupt-sidecar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).expect("src dir");
        std::fs::write(dir.join("src").join("ffi.rs"), "// placeholder\n").expect("write ffi.rs");
        std::fs::write(
            dir.join("src").join("ffi-wrappers.json"),
            "NOT VALID JSON\n",
        )
        .expect("write corrupt sidecar");
        let err = emitted_wrapper_paths(&dir).expect_err("corrupt sidecar must reject");
        assert!(
            matches!(err, crate::CliError::PackageAudit(ref r) if r.check == Check::NativeTier2),
            "a corrupt sidecar is a Tier-2 typed reject: {err:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    #[test]
    fn generic_wrappers_are_flagged_in_sidecar_and_excluded_from_link_set() {
        // A sidecar with one generic and one non-generic wrapper: the generic
        // wrapper is read correctly (flagged `generic: true`) and would be
        // excluded from the probe's link-reference set. The non-generic is
        // included. Both are returned from `emitted_wrapper_paths`.
        let dir = std::env::temp_dir().join(format!("ipe-generic-sidecar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).expect("src dir");
        std::fs::write(
            dir.join("src").join("ffi-wrappers.json"),
            "{\"wrappers\":[\
             {\"path\":\"crate::ffi::box1::box1_make\",\"generic\":true},\
             {\"path\":\"crate::ffi::box1::box1_drop\",\"generic\":false}]}\n",
        )
        .expect("write ffi-wrappers.json");
        std::fs::write(dir.join("src").join("ffi.rs"), "// placeholder\n").expect("write ffi.rs");
        let entries = emitted_wrapper_paths(&dir).expect("read sidecar");
        assert_eq!(entries.len(), 2, "both entries returned");
        let generic_entry = entries.iter().find(|e| e.generic).expect("generic entry");
        assert_eq!(generic_entry.path, "crate::ffi::box1::box1_make");
        let non_generic = entries
            .iter()
            .find(|e| !e.generic)
            .expect("non-generic entry");
        assert_eq!(non_generic.path, "crate::ffi::box1::box1_drop");
        // The link-reference set (what the probe would use) excludes generic wrappers.
        let link_paths: Vec<&str> = entries
            .iter()
            .filter(|e| !e.generic)
            .map(|e| e.path.as_str())
            .collect();
        assert_eq!(link_paths, vec!["crate::ffi::box1::box1_drop"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    #[test]
    fn emitted_wrapper_paths_is_empty_when_neither_sidecar_nor_ffi_rs() {
        // When neither `src/ffi-wrappers.json` nor `src/ffi.rs` exists the
        // package has no FFI surface → empty set (not an error).
        let dir = std::env::temp_dir().join(format!("ipe-emitted-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).expect("src dir");
        assert!(
            emitted_wrapper_paths(&dir)
                .expect("no sidecar and no ffi.rs is empty")
                .is_empty(),
            "a package with no emitted src/ffi.rs or sidecar has no probeable surface"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "freebsd"
    ))]
    #[test]
    fn manifest_path_dependencies_extracts_absolute_and_inline_paths() {
        let manifest = "[dependencies]\n\
             ipe_runtime = { package = \"ipe-runtime-rust\", path = \"/abs/runtime\" }\n\
             csum = { path = \"/abs/csum\" }\n\
             serde = \"1\"\n";
        let deps = manifest_path_dependencies(manifest);
        assert_eq!(
            deps,
            vec![PathBuf::from("/abs/runtime"), PathBuf::from("/abs/csum")],
            "every `path = \"…\"` value, in manifest order"
        );
    }
}

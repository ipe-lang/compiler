//! Execute an emitted `wasm32-wasip1` module in an EMBEDDED wasmtime engine —
//! the run-side of `ipe run --target wasi` (issue #2461).
//!
//! ## Why embedded, and why deny-by-default
//!
//! Ipê's whole execution model is a fail-closed, deny-by-default capability
//! jail. The native run confines the emitted binary with seccomp + a bind-mount
//! namespace derived from the program's declared capability floor
//! ([`crate::run_sandbox`] → [`ipe_sandbox::run_jail`]). The WASI run enforces
//! the SAME floor, expressed as a [`wasmtime_wasi::WasiCtxBuilder`] context
//! instead: preopen ONLY the declared filesystem, pass ONLY the declared env
//! allowlist, forward args, and deny the network unless the floor grants it.
//! There is NO ambient authority — a capability the floor does not grant has no
//! representation in the built [`wasmtime_wasi::preview1::WasiP1Ctx`], so the
//! guest cannot reach it. This is defend-in-depth: one capability model, two
//! independent enforcement surfaces.
//!
//! Embedding (rather than shelling out to an external `wasmtime` binary) is what
//! lets us BUILD that context ourselves. An external binary would receive
//! capabilities only through coarse CLI flags, may be absent, and may drift in
//! version/behaviour — forcing us to trust its sandbox rather than derive ours.
//!
//! ## Bounded by construction — the same resource floor, both surfaces
//!
//! The native jail ALWAYS caps a run's address space, CPU, and wall clock from
//! the profile's [`ipe_sandbox::run_jail::RunResourceLimits`] (`prlimit` +
//! `timeout`). The embedded WASI run ports the SAME floor: the store carries a
//! [`wasmtime::StoreLimits`] built from `limits.as_bytes` (linear-memory growth
//! past the declared address-space ceiling traps, never exhausts the host heap),
//! and the engine runs under an epoch deadline armed from the wall-clock floor
//! (`limits.wall_secs`, or `limits.cpu_secs` when no wall clock is set — a
//! server has no wall kill but a busy-loop is still bounded). A guest that
//! allocates or spins past the floor is turned back with a typed
//! [`CliError::WasiRunFailed`], never a hung or OOM-killed host. One capability
//! AND resource model, two independent enforcement surfaces.
//!
//! ## The `wasi_run` feature
//!
//! wasmtime is a large dependency (a full wasm engine + the preview1 shim), so
//! it sits behind the `wasi_run` cargo feature — OFF for the lean dev/test
//! build, ON for release packaging. With the feature OFF, [`ensure_available`]
//! returns a typed [`CliError::WasiRunFeatureDisabled`] naming the feature —
//! never a panic, never a silent fall-through to a native run.

use ipe_sandbox::run_jail::{FilesystemScope, SandboxProfile};

/// The forwarded module's `argv[0]` — a conventional program name for the guest
/// (the wasip1 module carries no host path of its own).
#[cfg(feature = "wasi_run")]
const MODULE_ARGV0: &str = "ipe-app";

/// The filesystem grant a WASI preopen mirrors from the declared floor.
///
/// Read straight off the SAME [`SandboxProfile`] the native jail lowers, and
/// kept as a tiny typed value (parse, don't validate) so the feature-on builder
/// and the feature-off path agree on what a "grant" is, and a test can assert
/// the deny-by-default mapping without linking the engine.
///
/// - [`Self::ScopedTmpOnly`] mirrors [`FilesystemScope::Isolated`]: the guest
///   gets ONE writable scratch dir and nothing of the host tree.
/// - [`Self::WorkingTreeReadWrite`] mirrors
///   [`FilesystemScope::WorkingTreeReadWrite`]: the working tree is preopened
///   read-write, exactly the coarse grant the native jail binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsGrant {
    /// Only a scoped writable scratch dir is preopened (the maximally-isolated
    /// view). No host path is reachable.
    ScopedTmpOnly,
    /// The working tree is preopened read-write.
    WorkingTreeReadWrite,
}

impl FsGrant {
    /// Derive the filesystem grant from the profile's scope — the single mapping
    /// from the capability floor's FS axis to what a WASI preopen may expose.
    #[must_use]
    pub const fn from_profile(profile: &SandboxProfile) -> Self {
        match profile.filesystem {
            FilesystemScope::Isolated => Self::ScopedTmpOnly,
            FilesystemScope::WorkingTreeReadWrite => Self::WorkingTreeReadWrite,
        }
    }
}

/// Whether the WASI context may open sockets — the SINGLE network decision.
///
/// Fail-closed: the network is allowed ONLY when the declared floor grants it;
/// the maximally-isolated floor (and any floor without the `network` axis)
/// denies it. Exposed as a pure predicate so the deny-by-default mapping is
/// pinned by a test without linking the engine (mirroring the native jail's
/// socket-deny proofs).
#[must_use]
pub const fn network_allowed(profile: &SandboxProfile) -> bool {
    profile.network
}

/// The address-space ceiling a WASI store's linear-memory limiter enforces.
///
/// Read straight off the SAME profile the native jail lowers (`limits.as_bytes`,
/// the `prlimit --as` cap). Saturated into `usize` so a 64-bit cap on a 32-bit
/// host clamps to the host maximum rather than wrapping — the floor never widens
/// by truncation.
#[must_use]
pub fn memory_ceiling_bytes(profile: &SandboxProfile) -> usize {
    usize::try_from(profile.limits.as_bytes).unwrap_or(usize::MAX)
}

/// The wall-clock ceiling (in seconds) the epoch deadline arms from.
///
/// The SAME floor the native jail's `timeout`/`--cpu` enforces. A profile with
/// an explicit `wall_secs` uses it; a long-lived app (`wall_secs = None`, no
/// wall kill) still bounds a busy-loop by the mandatory `cpu_secs` ceiling, so a
/// CPU-bomb is turned back either way. Never `0` — a zero ceiling would arm a
/// deadline already past, killing the guest before it starts; clamped to at
/// least one second.
#[must_use]
pub const fn wall_ceiling_secs(profile: &SandboxProfile) -> u64 {
    let secs = match profile.limits.wall_secs {
        Some(w) => w,
        None => profile.limits.cpu_secs,
    };
    if secs == 0 { 1 } else { secs }
}

#[cfg(feature = "wasi_run")]
mod engine {
    use super::{FsGrant, MODULE_ARGV0, memory_ceiling_bytes, wall_ceiling_secs};
    use crate::{CliError, Path};
    use ipe_sandbox::run_jail::SandboxProfile;
    use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};
    use wasmtime_wasi::p2::WasiCtxBuilder;
    use wasmtime_wasi::preview1::{self, WasiP1Ctx};
    use wasmtime_wasi::{DirPerms, FilePerms, I32Exit};

    /// The store's host data: the floor-derived WASI context PLUS the
    /// address-space limiter. Both live in the store so the resource floor is
    /// enforced by the same value the guest runs under — the WASI preview1
    /// linker reaches the ctx through the accessor, and wasmtime reaches the
    /// limiter through [`Store::limiter`].
    struct HostState {
        wasi: WasiP1Ctx,
        limits: StoreLimits,
    }

    /// The `wasi_run` feature is compiled in: the embedded engine is available.
    ///
    /// # Errors
    /// Never — the engine is linked, so this always returns `Ok`. The `Result`
    /// shape matches the feature-off twin so callers are feature-agnostic.
    pub const fn ensure_available() -> Result<(), CliError> {
        Ok(())
    }

    /// The wall-clock kill switch: a background thread that bumps the engine's
    /// epoch ONCE after the wall-clock floor elapses, so a guest that overruns
    /// its floor traps (a typed error) instead of hanging the host. Armed on
    /// construction and disarmed on drop — the guest signalling completion ends
    /// the thread's wait promptly rather than blocking the whole wall period.
    struct WallDeadline {
        done: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
        watchdog: Option<std::thread::JoinHandle<()>>,
    }

    impl WallDeadline {
        /// Arm the deadline against `engine` for `wall_secs` seconds.
        fn arm(engine: &Engine, wall_secs: u64) -> Self {
            let done =
                std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
            let watchdog_done = std::sync::Arc::clone(&done);
            let watchdog_engine = engine.clone();
            let watchdog = std::thread::spawn(move || {
                let (lock, cvar) = &*watchdog_done;
                let mut finished = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let mut remaining = std::time::Duration::from_secs(wall_secs);
                while !*finished && !remaining.is_zero() {
                    let start = std::time::Instant::now();
                    let (guard, timeout) = cvar
                        .wait_timeout(finished, remaining)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    finished = guard;
                    if timeout.timed_out() {
                        break;
                    }
                    remaining = remaining.saturating_sub(start.elapsed());
                }
                if !*finished {
                    // The guest is still running past its wall-clock floor: fire
                    // the deadline. One increment suffices — the store deadline
                    // is 1.
                    watchdog_engine.increment_epoch();
                }
            });
            Self {
                done,
                watchdog: Some(watchdog),
            }
        }
    }

    impl Drop for WallDeadline {
        fn drop(&mut self) {
            let (lock, cvar) = &*self.done;
            {
                let mut finished = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *finished = true;
            }
            cvar.notify_all();
            if let Some(handle) = self.watchdog.take() {
                let _ = handle.join();
            }
        }
    }

    /// Build the deny-by-default [`WasiP1Ctx`] from the declared capability
    /// floor. Every axis is granted ONLY when the floor grants it; nothing is
    /// ambient.
    ///
    /// - **args** — forwarded (the program's own argv; not a host capability).
    /// - **stdio** — inherited (stdin/stdout/stderr), so the run behaves like the
    ///   native run for a Direct script's I/O.
    /// - **env** — ONLY the floor's `env_allowlist` names, each read from the
    ///   host and passed through; an un-allowlisted var is never visible.
    /// - **filesystem** — a single scoped writable scratch dir is ALWAYS
    ///   preopened as the guest's `.` (the isolated view's sole writable mount);
    ///   the working tree is additionally preopened read-write ONLY when the
    ///   floor grants [`crate::wasi_run::FsGrant::WorkingTreeReadWrite`]. No other
    ///   host path is reachable.
    /// - **network** — DENIED unless the floor grants it (`allow_tcp`/`allow_udp`
    ///   stay false and the network is not inherited); a socket attempt then
    ///   fails inside the guest with no host reachability.
    /// - **clock/random** — the preview1 defaults (no capability axis governs
    ///   them in the floor; they carry no host authority to gate).
    fn build_ctx(
        profile: &SandboxProfile,
        scratch: &Path,
        working_tree: &Path,
        args: &[String],
    ) -> Result<WasiP1Ctx, CliError> {
        let mut builder = WasiCtxBuilder::new();
        builder.inherit_stdio();
        // argv[0] is a conventional program name; the forwarded args follow
        // (mirroring the native run's `cmd.args(&bin_args)`).
        builder.arg(MODULE_ARGV0);
        for a in args {
            builder.arg(a);
        }

        // env: ONLY the floor's allowlisted names, and only those actually
        // present in the host environment. An absent allowlisted var is simply
        // not passed (never an empty-string surprise), and a var outside the
        // allowlist is never visible — the same subset the native jail scrubs to.
        for name in &profile.env_allowlist {
            if let Some(value) = std::env::var_os(name) {
                builder.env(name, value.to_string_lossy());
            }
        }

        // filesystem: the scoped scratch is the guest's `.` (always writable, the
        // isolated view's sole mount). Only a working-tree-rw grant additionally
        // exposes the host tree, read-write, mirroring the native bind-mount.
        builder
            .preopened_dir(scratch, ".", DirPerms::all(), FilePerms::all())
            .map_err(|e| CliError::WasiRunFailed {
                detail: crate::style::TerminalSafe::sanitize(&format!(
                    "could not preopen the scoped scratch dir: {e}"
                )),
            })?;
        if matches!(
            FsGrant::from_profile(profile),
            FsGrant::WorkingTreeReadWrite
        ) {
            builder
                .preopened_dir(working_tree, "/work", DirPerms::all(), FilePerms::all())
                .map_err(|e| CliError::WasiRunFailed {
                    detail: crate::style::TerminalSafe::sanitize(&format!(
                        "could not preopen the working tree: {e}"
                    )),
                })?;
        }

        // network: fail-closed. Only a network grant enables sockets; without it
        // the context inherits no network and refuses TCP/UDP.
        if super::network_allowed(profile) {
            builder.inherit_network();
            builder.allow_tcp(true);
            builder.allow_udp(true);
        } else {
            builder.allow_tcp(false);
            builder.allow_udp(false);
        }

        Ok(builder.build_p1())
    }

    /// Instantiate and run the emitted `wasm32-wasip1` module under embedded
    /// wasmtime.
    ///
    /// The guest is confined by the floor-derived [`WasiP1Ctx`] AND the
    /// floor-derived resource ceilings: a [`StoreLimits`] bounds linear-memory
    /// growth to `limits.as_bytes` and an epoch deadline (armed from the
    /// wall-clock floor) bounds run time. Its WASI exit code is propagated, and
    /// any trap — including a memory-ceiling or wall-clock-deadline trap — maps
    /// to a typed [`CliError`], never a host panic, host OOM, or host hang.
    ///
    /// `module_file` is the emitted `wasm32-wasip1` artifact, resolved by the
    /// caller from `cargo metadata` (the authoritative target dir).
    ///
    /// # Errors
    /// - [`CliError::WasiRunFailed`] when the scratch dir, module load, linker
    ///   wiring, instantiation, or `_start` lookup fails, or the guest traps
    ///   without a clean WASI exit.
    /// - [`CliError::WasiRunExited`] when the guest runs to completion and
    ///   returns a non-zero WASI exit code.
    pub fn run_wasi_module(
        module_file: &Path,
        profile: &SandboxProfile,
        working_tree: &Path,
        args: &[String],
    ) -> Result<(), CliError> {
        // A scoped scratch dir is the guest's sole always-writable mount — the
        // WASI analogue of the native run's scoped tempdir. Dropped when this
        // returns, so nothing persists past the run.
        let scratch = crate::scratch::ScratchDir::new("ipe-wasi-run").map_err(|e| {
            CliError::WasiRunFailed {
                detail: crate::style::TerminalSafe::sanitize(&format!(
                    "could not create the scoped scratch dir: {e}"
                )),
            }
        })?;

        // Epoch interruption is the wall-clock kill switch: the engine is built
        // from a Config with it enabled, the store arms a one-tick deadline, and
        // a background thread bumps the epoch once after the wall-clock floor —
        // so a busy-loop traps (a typed error) instead of hanging the host. This
        // mirrors the native jail's `timeout`/`--cpu`.
        let mut config = Config::new();
        config.epoch_interruption(true);
        let engine = Engine::new(&config).map_err(|e| CliError::WasiRunFailed {
            detail: crate::style::TerminalSafe::sanitize(&format!(
                "could not build the wasmtime engine: {e}"
            )),
        })?;

        let module =
            Module::from_file(&engine, module_file).map_err(|e| CliError::WasiRunFailed {
                detail: crate::style::TerminalSafe::sanitize(&format!(
                    "could not load the module at {}: {e}",
                    module_file.display()
                )),
            })?;

        let mut linker: Linker<HostState> = Linker::new(&engine);
        preview1::add_to_linker_sync(&mut linker, |s: &mut HostState| &mut s.wasi).map_err(
            |e| CliError::WasiRunFailed {
                detail: crate::style::TerminalSafe::sanitize(&format!(
                    "could not wire the WASI preview1 imports: {e}"
                )),
            },
        )?;

        let ctx = build_ctx(profile, scratch.path(), working_tree, args)?;
        // Address-space ceiling: linear memory may not grow past the declared
        // `as_bytes` floor. `trap_on_grow_failure` turns an over-cap `memory.grow`
        // into a trap (→ typed `WasiRunFailed`) rather than a silent -1, so a
        // heap-bomb is turned back, never allowed to exhaust the host.
        let limits = StoreLimitsBuilder::new()
            .memory_size(memory_ceiling_bytes(profile))
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(&engine, HostState { wasi: ctx, limits });
        store.limiter(|s: &mut HostState| &mut s.limits);
        store.set_epoch_deadline(1);

        // Arm the wall-clock deadline; it disarms (signals + joins the watchdog)
        // when `_deadline` drops at the end of this scope, whichever path we
        // leave by — a `?` error return included.
        let _deadline = WallDeadline::arm(&engine, wall_ceiling_secs(profile));

        let instance =
            linker
                .instantiate(&mut store, &module)
                .map_err(|e| CliError::WasiRunFailed {
                    detail: crate::style::TerminalSafe::sanitize(&format!(
                        "could not instantiate the module: {e}"
                    )),
                })?;

        // A wasip1 command module exports `_start` with signature `() -> ()`.
        let start = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|e| CliError::WasiRunFailed {
                detail: crate::style::TerminalSafe::sanitize(&format!(
                    "the module has no wasip1 `_start` entry point: {e}"
                )),
            })?;

        match start.call(&mut store, ()) {
            Ok(()) => Ok(()),
            Err(trap) => {
                // A clean WASI exit surfaces as an `I32Exit` trap: exit 0 is
                // success, non-zero is the guest's own outcome (propagated as
                // `ipe run`'s non-zero exit). Any other trap is a genuine run
                // failure — including a memory-ceiling trap (linear memory grew
                // past `limits.as_bytes`) or a wall-clock epoch-deadline trap
                // (the guest overran its wall floor) — a typed error, never a
                // host panic, OOM, or hang.
                if let Some(exit) = trap.downcast_ref::<I32Exit>() {
                    let code = exit.0;
                    return if code == 0 {
                        Ok(())
                    } else {
                        Err(CliError::WasiRunExited { code })
                    };
                }
                Err(CliError::WasiRunFailed {
                    detail: crate::style::TerminalSafe::sanitize(&format!(
                        "the module trapped during execution: {trap}"
                    )),
                })
            }
        }
    }
}

#[cfg(not(feature = "wasi_run"))]
mod engine {
    use crate::{CliError, Path};
    use ipe_sandbox::run_jail::SandboxProfile;

    /// The `wasi_run` feature is NOT compiled in: no embedded engine is linked.
    ///
    /// Fail closed with a typed refusal naming the feature — never a panic, never
    /// a silent native fallback.
    ///
    /// # Errors
    /// Always returns [`CliError::WasiRunFeatureDisabled`] — there is no engine to
    /// make available.
    pub const fn ensure_available() -> Result<(), CliError> {
        Err(CliError::WasiRunFeatureDisabled)
    }

    /// Unreachable at runtime: [`ensure_available`] gates every caller before a
    /// module is built, so this returns the same typed refusal rather than
    /// running anything.
    ///
    /// # Errors
    /// Always returns [`CliError::WasiRunFeatureDisabled`] — the engine that would
    /// run the module is not linked into this build.
    pub const fn run_wasi_module(
        _module_file: &Path,
        _profile: &SandboxProfile,
        _working_tree: &Path,
        _args: &[String],
    ) -> Result<(), CliError> {
        Err(CliError::WasiRunFeatureDisabled)
    }
}

pub use engine::{ensure_available, run_wasi_module};

#[cfg(test)]
mod tests {
    use super::{FsGrant, memory_ceiling_bytes, network_allowed, wall_ceiling_secs};
    use ipe_sandbox::run_jail::{FilesystemScope, RunResourceLimits, SandboxProfile};

    #[test]
    fn isolated_scope_maps_to_scoped_tmp_only() {
        // Deny-by-default filesystem: the maximally-isolated floor exposes no
        // host path — only the scoped scratch is preopened.
        let p = SandboxProfile::maximally_isolated();
        assert_eq!(FsGrant::from_profile(&p), FsGrant::ScopedTmpOnly);
    }

    #[test]
    fn working_tree_rw_scope_maps_to_working_tree_grant() {
        // A working-tree grant — and ONLY that grant — exposes the host tree
        // read-write, mirroring the native jail's bind-mount.
        let p = SandboxProfile {
            filesystem: FilesystemScope::WorkingTreeReadWrite,
            ..SandboxProfile::maximally_isolated()
        };
        assert_eq!(FsGrant::from_profile(&p), FsGrant::WorkingTreeReadWrite);
    }

    #[test]
    fn network_is_denied_by_default() {
        // The refusal proof (mirroring the native jail's socket-deny): the
        // maximally-isolated floor denies the network, so the WASI ctx never
        // opens a socket. Fail-closed — network is reachable ONLY on an explicit
        // grant.
        let denied = SandboxProfile::maximally_isolated();
        assert!(
            !network_allowed(&denied),
            "an undeclared network capability MUST be denied by the WASI context",
        );
        let granted = SandboxProfile {
            network: true,
            ..SandboxProfile::maximally_isolated()
        };
        assert!(
            network_allowed(&granted),
            "an explicitly-granted network capability is the ONLY way sockets open",
        );
    }

    #[test]
    fn memory_ceiling_is_read_from_the_profiles_address_space_floor() {
        // The WASI store's linear-memory limiter reads the SAME `as_bytes` cap
        // the native jail lowers into `prlimit --as` — not a hardcoded number —
        // so the wasm memory floor equals the native floor by construction.
        let p = SandboxProfile {
            limits: RunResourceLimits {
                as_bytes: 512 * 1024 * 1024,
                ..RunResourceLimits::default()
            },
            ..SandboxProfile::maximally_isolated()
        };
        assert_eq!(memory_ceiling_bytes(&p), 512 * 1024 * 1024);
    }

    #[test]
    fn memory_ceiling_saturates_rather_than_wrapping() {
        // A 64-bit cap wider than the host pointer clamps to the host maximum:
        // the floor can never *widen* by truncation (fail-closed on overflow).
        let p = SandboxProfile {
            limits: RunResourceLimits {
                as_bytes: u64::MAX,
                ..RunResourceLimits::default()
            },
            ..SandboxProfile::maximally_isolated()
        };
        assert_eq!(memory_ceiling_bytes(&p), usize::MAX);
    }

    #[test]
    fn wall_deadline_uses_the_explicit_wall_floor_when_present() {
        // An explicit wall-clock floor arms the epoch deadline directly — the
        // WASI wall kill mirrors the native jail's `timeout`.
        let p = SandboxProfile {
            limits: RunResourceLimits {
                wall_secs: Some(30),
                ..RunResourceLimits::default()
            },
            ..SandboxProfile::maximally_isolated()
        };
        assert_eq!(wall_ceiling_secs(&p), 30);
    }

    #[test]
    fn wall_deadline_falls_back_to_the_cpu_floor_when_no_wall_clock() {
        // A long-lived app has no wall kill (`wall_secs = None`), but a busy-loop
        // is still bounded — the mandatory `cpu_secs` ceiling arms the deadline,
        // so a CPU-bomb is turned back either way (never an unbounded host hang).
        let p = SandboxProfile {
            limits: RunResourceLimits {
                wall_secs: None,
                cpu_secs: 3600,
                ..RunResourceLimits::default()
            },
            ..SandboxProfile::maximally_isolated()
        };
        assert_eq!(wall_ceiling_secs(&p), 3600);
    }

    #[test]
    fn wall_deadline_never_arms_at_zero() {
        // A zero ceiling would fire a deadline already in the past, killing the
        // guest before its first instruction; it is clamped to at least one
        // second so the bound is real, not a self-inflicted instant kill.
        let p = SandboxProfile {
            limits: RunResourceLimits {
                wall_secs: Some(0),
                cpu_secs: 0,
                ..RunResourceLimits::default()
            },
            ..SandboxProfile::maximally_isolated()
        };
        assert_eq!(wall_ceiling_secs(&p), 1);
    }
}

//! Execute an emitted `wasm32-wasip1` module in an EMBEDDED wasmtime engine —
//! the run side of `ipe dev run --target wasi`.
//!
//! ## Ambient authority, bounded resources
//!
//! `ipe dev` checks no capabilities: the native dev binary runs unjailed with
//! the developer's own permissions. The WASI dev run grants the guest the same
//! authority through [`WasiCtx::dev_ambient`], the one constructor of the run
//! context — the working directory preopened read-write as `.`, stdio and the
//! environment inherited, the network allowed. No capability profile reaches
//! this module, and no release path runs a module through it.
//!
//! Embedding (rather than shelling out to an external `wasmtime` binary) keeps
//! the engine version pinned with `ipe` and the run context built here, not
//! trusted to a binary that may be absent or drift.
//!
//! The resource bounds stay: the store carries a [`wasmtime::StoreLimits`]
//! built from the context's `as_bytes` (linear-memory growth past it traps,
//! never exhausts the host heap), and the engine runs under an epoch deadline
//! armed from `wall_secs`, or `cpu_secs` when no wall clock is set. A guest that
//! allocates or spins past its bound is turned back with a typed
//! [`CliError::WasiRunFailed`], never a hung or OOM-killed host.
//!
//! ## The `wasi_run` feature
//!
//! wasmtime is a large dependency (a full wasm engine + the preview1 shim), so
//! it sits behind the `wasi_run` cargo feature — OFF for the lean dev/test
//! build, ON for release packaging. With the feature OFF, [`ensure_available`]
//! returns a typed [`CliError::WasiRunFeatureDisabled`] naming the feature —
//! never a panic, never a silent fall-through to a native run.

use ipe_sandbox::run_jail::RunResourceLimits;

/// The forwarded module's `argv[0]` — a conventional program name for the guest
/// (the wasip1 module carries no host path of its own).
#[cfg(feature = "wasi_run")]
const MODULE_ARGV0: &str = "ipe-app";

/// The context a WASI module runs under.
///
/// Constructible only through [`Self::dev_ambient`]: there is no empty or
/// profile-derived form a caller could pass to reach the ambient grant by
/// another name.
#[derive(Debug, Clone, Copy)]
pub struct WasiCtx {
    limits: RunResourceLimits,
}

impl WasiCtx {
    /// The `ipe dev` context: the working directory read-write, stdio and the
    /// environment inherited, the network allowed — the authority the unjailed
    /// native dev binary has — under the default resource bounds.
    #[must_use]
    pub fn dev_ambient() -> Self {
        Self {
            limits: RunResourceLimits::default(),
        }
    }

    /// The resource bounds the store limiter and the epoch deadline enforce.
    #[must_use]
    pub const fn limits(&self) -> &RunResourceLimits {
        &self.limits
    }
}

/// The address-space ceiling a WASI store's linear-memory limiter enforces.
///
/// Saturated into `usize` so a 64-bit cap on a 32-bit host clamps to the host
/// maximum rather than wrapping — the bound never widens by truncation.
#[must_use]
pub fn memory_ceiling_bytes(limits: &RunResourceLimits) -> usize {
    usize::try_from(limits.as_bytes).unwrap_or(usize::MAX)
}

/// The wall-clock ceiling (in seconds) the epoch deadline arms from.
///
/// An explicit `wall_secs` is used as is; with no wall clock a busy-loop is
/// still bounded by the mandatory `cpu_secs` ceiling. Never `0` — a zero
/// ceiling would arm a deadline already past, killing the guest before it
/// starts; clamped to at least one second.
#[must_use]
pub const fn wall_ceiling_secs(limits: &RunResourceLimits) -> u64 {
    let secs = match limits.wall_secs {
        Some(w) => w,
        None => limits.cpu_secs,
    };
    if secs == 0 { 1 } else { secs }
}

#[cfg(feature = "wasi_run")]
mod engine {
    use super::{MODULE_ARGV0, WasiCtx, memory_ceiling_bytes, wall_ceiling_secs};
    use crate::threads::{self, ThreadRole};
    use crate::{CliError, Path};
    use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};
    use wasmtime_wasi::p2::WasiCtxBuilder;
    use wasmtime_wasi::preview1::{self, WasiP1Ctx};
    use wasmtime_wasi::{DirPerms, FilePerms, I32Exit};

    /// The store's host data: the WASI context PLUS the address-space limiter.
    /// Both live in the store so the resource bound is enforced by the same
    /// value the guest runs under — the WASI preview1 linker reaches the ctx
    /// through the accessor, and wasmtime reaches the limiter through
    /// [`Store::limiter`].
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
    /// epoch ONCE after the wall-clock bound elapses, so a guest that overruns
    /// its bound traps (a typed error) instead of hanging the host. Armed on
    /// construction and disarmed on drop — the guest signalling completion ends
    /// the thread's wait promptly rather than blocking the whole wall period.
    struct WallDeadline {
        done: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
        watchdog: Option<std::thread::JoinHandle<()>>,
    }

    impl WallDeadline {
        /// Arm the deadline against `engine` for `wall_secs` seconds.
        ///
        /// A guest never starts without its deadline: an OS refusal of the
        /// watchdog thread is the run's error.
        fn arm(engine: &Engine, wall_secs: u64) -> Result<Self, CliError> {
            let done =
                std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
            let watchdog_done = std::sync::Arc::clone(&done);
            let watchdog_engine = engine.clone();
            let watchdog = threads::spawn_named(ThreadRole::WasiWallClock, move || {
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
                    // The guest is still running past its wall-clock bound: fire
                    // the deadline. One increment suffices — the store deadline
                    // is 1.
                    watchdog_engine.increment_epoch();
                }
            })?;
            Ok(Self {
                done,
                watchdog: Some(watchdog),
            })
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

    /// Build the [`WasiP1Ctx`] the [`WasiCtx::dev_ambient`] context grants.
    ///
    /// - **args** — `argv[0]` then the forwarded program args.
    /// - **stdio** and **env** — inherited from `ipe`.
    /// - **filesystem** — the working tree preopened read-write as `.`.
    /// - **network** — inherited; TCP, UDP and name lookup allowed.
    fn build_ctx(working_tree: &Path, args: &[String]) -> Result<WasiP1Ctx, CliError> {
        let mut builder = WasiCtxBuilder::new();
        builder.inherit_stdio();
        builder.arg(MODULE_ARGV0);
        for a in args {
            builder.arg(a);
        }
        builder.inherit_env();
        builder
            .preopened_dir(working_tree, ".", DirPerms::all(), FilePerms::all())
            .map_err(|e| CliError::WasiRunFailed {
                detail: crate::style::TerminalSafe::sanitize(&format!(
                    "could not preopen the working tree: {e}"
                )),
            })?;
        builder.inherit_network();
        builder.allow_tcp(true);
        builder.allow_udp(true);
        builder.allow_ip_name_lookup(true);
        Ok(builder.build_p1())
    }

    /// Instantiate and run the emitted `wasm32-wasip1` module under embedded
    /// wasmtime, with the authority `ctx` grants.
    ///
    /// A [`StoreLimits`] bounds linear-memory growth to the context's
    /// `as_bytes` and an epoch deadline bounds run time. The guest's WASI exit
    /// code is propagated, and any trap — including a memory-ceiling or
    /// wall-clock-deadline trap — maps to a typed [`CliError`], never a host
    /// panic, host OOM, or host hang.
    ///
    /// `module_file` is the emitted `wasm32-wasip1` artifact, resolved by the
    /// caller from cargo's artifact stream.
    ///
    /// # Errors
    /// - [`CliError::WasiRunFailed`] when the preopen, module load, linker
    ///   wiring, instantiation, or `_start` lookup fails, or the guest traps
    ///   without a clean WASI exit.
    /// - [`CliError::WasiRunExited`] when the guest runs to completion and
    ///   returns a non-zero WASI exit code.
    pub fn run_wasi_module(
        module_file: &Path,
        ctx: &WasiCtx,
        working_tree: &Path,
        args: &[String],
    ) -> Result<(), CliError> {
        // Epoch interruption is the wall-clock kill switch: the engine is built
        // from a Config with it enabled, the store arms a one-tick deadline, and
        // a background thread bumps the epoch once after the wall-clock bound —
        // so a busy-loop traps (a typed error) instead of hanging the host.
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

        let wasi = build_ctx(working_tree, args)?;
        // Address-space ceiling: linear memory may not grow past the context's
        // `as_bytes` bound. `trap_on_grow_failure` turns an over-cap
        // `memory.grow` into a trap (→ typed `WasiRunFailed`) rather than a
        // silent -1, so a heap-bomb is turned back, never allowed to exhaust
        // the host.
        let limits = StoreLimitsBuilder::new()
            .memory_size(memory_ceiling_bytes(ctx.limits()))
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(&engine, HostState { wasi, limits });
        store.limiter(|s: &mut HostState| &mut s.limits);
        store.set_epoch_deadline(1);

        // Arm the wall-clock deadline; it disarms (signals + joins the watchdog)
        // when `_deadline` drops at the end of this scope, whichever path we
        // leave by — a `?` error return included.
        let _deadline = WallDeadline::arm(&engine, wall_ceiling_secs(ctx.limits()))?;

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
                // `ipe dev run`'s non-zero exit). Any other trap is a genuine run
                // failure — including a memory-ceiling trap or a wall-clock
                // epoch-deadline trap — a typed error, never a host panic, OOM,
                // or hang.
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

    #[cfg(test)]
    mod tests {
        use super::WallDeadline;
        use crate::CliError;
        use crate::threads::{ThreadRole, refusal};
        use wasmtime::{Config, Engine};

        #[test]
        fn a_refused_wall_clock_thread_refuses_the_run() {
            refusal::refuse(ThreadRole::WasiWallClock);
            let mut config = Config::new();
            config.epoch_interruption(true);
            let engine = Engine::new(&config);
            assert!(engine.is_ok(), "the test engine builds");
            let Ok(engine) = engine else { return };
            assert!(matches!(
                WallDeadline::arm(&engine, 1),
                Err(CliError::ThreadRefused {
                    role: ThreadRole::WasiWallClock,
                    ..
                })
            ));
        }
    }
}

#[cfg(not(feature = "wasi_run"))]
mod engine {
    use super::WasiCtx;
    use crate::{CliError, Path};

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
        _ctx: &WasiCtx,
        _working_tree: &Path,
        _args: &[String],
    ) -> Result<(), CliError> {
        Err(CliError::WasiRunFeatureDisabled)
    }
}

pub use engine::{ensure_available, run_wasi_module};

#[cfg(test)]
mod tests {
    use super::{WasiCtx, memory_ceiling_bytes, wall_ceiling_secs};
    use ipe_sandbox::run_jail::RunResourceLimits;

    #[test]
    fn the_dev_context_keeps_the_default_resource_bounds() {
        // Ambient authority is not unbounded resources: the dev context still
        // carries the default address-space, CPU and wall-clock ceilings.
        let ctx = WasiCtx::dev_ambient();
        let defaults = RunResourceLimits::default();
        assert_eq!(ctx.limits().as_bytes, defaults.as_bytes);
        assert_eq!(ctx.limits().cpu_secs, defaults.cpu_secs);
        assert_eq!(ctx.limits().wall_secs, defaults.wall_secs);
    }

    #[test]
    fn memory_ceiling_is_read_from_the_address_space_bound() {
        let limits = RunResourceLimits {
            as_bytes: 512 * 1024 * 1024,
            ..RunResourceLimits::default()
        };
        assert_eq!(memory_ceiling_bytes(&limits), 512 * 1024 * 1024);
    }

    #[test]
    fn memory_ceiling_saturates_rather_than_wrapping() {
        // A 64-bit cap wider than the host pointer clamps to the host maximum:
        // the bound can never widen by truncation.
        let limits = RunResourceLimits {
            as_bytes: u64::MAX,
            ..RunResourceLimits::default()
        };
        assert_eq!(memory_ceiling_bytes(&limits), usize::MAX);
    }

    #[test]
    fn wall_deadline_uses_the_explicit_wall_bound_when_present() {
        let limits = RunResourceLimits {
            wall_secs: Some(30),
            ..RunResourceLimits::default()
        };
        assert_eq!(wall_ceiling_secs(&limits), 30);
    }

    #[test]
    fn wall_deadline_falls_back_to_the_cpu_bound_when_no_wall_clock() {
        // No wall kill, yet a busy-loop is still bounded by `cpu_secs`.
        let limits = RunResourceLimits {
            wall_secs: None,
            cpu_secs: 3600,
            ..RunResourceLimits::default()
        };
        assert_eq!(wall_ceiling_secs(&limits), 3600);
    }

    #[test]
    fn wall_deadline_never_arms_at_zero() {
        // A zero ceiling would fire a deadline already in the past, killing the
        // guest before its first instruction; it is clamped to one second.
        let limits = RunResourceLimits {
            wall_secs: Some(0),
            cpu_secs: 0,
            ..RunResourceLimits::default()
        };
        assert_eq!(wall_ceiling_secs(&limits), 1);
    }
}

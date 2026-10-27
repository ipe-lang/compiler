//! The one door every `ipe` command's OS thread starts through.
//!
//! `std::thread::spawn` panics when the OS refuses a thread (a thread or
//! memory limit reached), so a refused spawn would abort the command instead
//! of reporting it. Every thread here starts through
//! [`std::thread::Builder::spawn`], and the refusal comes back as a typed
//! [`CliError::ThreadRefused`] naming the thread's [`ThreadRole`]. The root
//! `clippy.toml` bans the panicking spawns, so no other door exists.
//!
//! A role that compiles Ipê declares its stack ([`COMPILE_STACK_BYTES`]), so
//! the program a compile admits is the same on every OS rather than bounded by
//! whatever main-thread stack the platform hands out.

use std::fmt;
use std::io;
use std::thread::{Builder, JoinHandle};

pub use ipe_diagnostics::nesting::COMPILE_STACK_BYTES;

use crate::{CliError, text};

/// The job a thread an `ipe` command starts does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ThreadRole {
    /// Runs an `ipe dev watch` session.
    WatchSession,
    /// Coalesces `ipe dev watch` file events into one rebuild.
    WatchCoalesce,
    /// Relays filesystem events into the `ipe dev watch` orchestrator.
    WatchFsRelay,
    /// Relays a stop request into the `ipe dev watch` orchestrator.
    WatchStopRelay,
    /// Retries an `ipe dev watch` dependency resolve after a delay.
    WatchResolveRetry,
    /// Runs one `ipe dev watch` compile.
    WatchCompile,
    /// Runs one compile of a one-shot command (`build`, `check`, `run`).
    Compile,
    /// Waits on an `ipe dev watch` cargo build and reports its exit.
    WatchCargoWaiter,
    /// Enforces a WASI run's wall-clock ceiling.
    WasiWallClock,
}

impl ThreadRole {
    /// The OS-level thread name, shown by debuggers and panic messages.
    #[must_use]
    pub const fn thread_name(self) -> &'static str {
        match self {
            Self::WatchSession => "ipe-watch-session",
            Self::WatchCoalesce => "ipe-watch-coalesce",
            Self::WatchFsRelay => "ipe-watch-fs-relay",
            Self::WatchStopRelay => "ipe-watch-stop-relay",
            Self::WatchResolveRetry => "ipe-watch-resolve-retry",
            Self::WatchCompile => "ipe-watch-compile",
            Self::Compile => "ipe-compile",
            Self::WatchCargoWaiter => "ipe-watch-cargo-waiter",
            Self::WasiWallClock => "ipe-wasi-wall-clock",
        }
    }

    /// The stack this role's thread is started with.
    ///
    /// `None` keeps the platform default; a compiling role declares
    /// [`COMPILE_STACK_BYTES`].
    #[must_use]
    pub const fn stack_bytes(self) -> Option<usize> {
        match self {
            Self::Compile | Self::WatchCompile => Some(COMPILE_STACK_BYTES),
            Self::WatchSession
            | Self::WatchCoalesce
            | Self::WatchFsRelay
            | Self::WatchStopRelay
            | Self::WatchResolveRetry
            | Self::WatchCargoWaiter
            | Self::WasiWallClock => None,
        }
    }

    /// A thread builder carrying this role's name and declared stack.
    fn builder(self) -> Builder {
        let builder = Builder::new().name(self.thread_name().to_owned());
        match self.stack_bytes() {
            Some(bytes) => builder.stack_size(bytes),
            None => builder,
        }
    }
}

impl fmt::Display for ThreadRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WatchSession => text::thread_role_watch_session(),
            Self::WatchCoalesce => text::thread_role_watch_coalesce(),
            Self::WatchFsRelay => text::thread_role_watch_fs_relay(),
            Self::WatchStopRelay => text::thread_role_watch_stop_relay(),
            Self::WatchResolveRetry => text::thread_role_watch_resolve_retry(),
            Self::WatchCompile => text::thread_role_watch_compile(),
            Self::Compile => text::thread_role_compile(),
            Self::WatchCargoWaiter => text::thread_role_watch_cargo_waiter(),
            Self::WasiWallClock => text::thread_role_wasi_wall_clock(),
        })
    }
}

/// Start a thread for `role`, handing back the OS's refusal as an `io::Error`.
///
/// For a caller whose own error channel is `io::Result`; every other caller
/// takes [`spawn_named`].
///
/// # Errors
///
/// The OS refused the thread.
pub fn spawn_os<F, T>(role: ThreadRole, body: F) -> io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    #[cfg(test)]
    if refusal::refused(role) {
        return Err(io::Error::from(io::ErrorKind::WouldBlock));
    }
    role.builder().spawn(body)
}

/// Start a thread for `role`, handing back the OS's refusal as a typed error.
///
/// # Errors
///
/// [`CliError::ThreadRefused`] when the OS refused the thread.
pub fn spawn_named<F, T>(role: ThreadRole, body: F) -> Result<JoinHandle<T>, CliError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    spawn_os(role, body).map_err(|source| CliError::ThreadRefused { role, source })
}

/// Run one compile on a [`ThreadRole::Compile`] thread and wait for it.
///
/// The body may borrow from the caller. A panic inside it resumes on the
/// caller, exactly as if the body had run there.
///
/// # Errors
///
/// [`CliError::ThreadRefused`] when the OS refused the thread.
pub fn run_compile<F, T>(body: F) -> Result<T, CliError>
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    let role = ThreadRole::Compile;
    #[cfg(test)]
    if refusal::refused(role) {
        return Err(CliError::ThreadRefused {
            role,
            source: io::Error::from(io::ErrorKind::WouldBlock),
        });
    }
    std::thread::scope(|scope| {
        let handle = role
            .builder()
            .spawn_scoped(scope, body)
            .map_err(|source| CliError::ThreadRefused { role, source })?;
        match handle.join() {
            Ok(value) => Ok(value),
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })
}

/// A test-only switch that makes the OS refuse a role's thread.
///
/// Each test runs in its own process under nextest, so a role refused here
/// stays refused for that one test.
#[cfg(test)]
pub mod refusal {
    use std::sync::{Mutex, PoisonError};

    use super::ThreadRole;

    static REFUSED: Mutex<Vec<ThreadRole>> = Mutex::new(Vec::new());

    /// Make every later spawn for `role` fail as the OS refusing it.
    pub fn refuse(role: ThreadRole) {
        let mut refused = REFUSED.lock().unwrap_or_else(PoisonError::into_inner);
        if !refused.contains(&role) {
            refused.push(role);
        }
    }

    /// Whether spawns for `role` are refused.
    pub fn refused(role: ThreadRole) -> bool {
        REFUSED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&role)
    }
}

#[cfg(test)]
mod tests {
    use super::{COMPILE_STACK_BYTES, ThreadRole, refusal, run_compile, spawn_named};
    use crate::CliError;

    #[test]
    fn a_refused_spawn_is_a_typed_error_naming_its_role() {
        refusal::refuse(ThreadRole::WatchCompile);
        let refused = spawn_named(ThreadRole::WatchCompile, || ());
        assert!(matches!(
            refused,
            Err(CliError::ThreadRefused {
                role: ThreadRole::WatchCompile,
                ..
            })
        ));
        let Err(err) = refused else { return };
        assert_eq!(err.machine_kind(), "thread-refused");
        assert!(
            err.to_string().contains(text_role()),
            "the message names the refused thread: {err}"
        );
    }

    #[test]
    fn an_allowed_spawn_runs_its_body_on_a_named_thread() {
        let handle = spawn_named(ThreadRole::WatchSession, || {
            std::thread::current().name().map(str::to_owned)
        });
        let name = handle.ok().and_then(|h| h.join().ok()).flatten();
        assert_eq!(name.as_deref(), Some("ipe-watch-session"));
    }

    #[test]
    fn a_compile_runs_on_a_named_thread_with_the_declared_stack() {
        assert_eq!(ThreadRole::Compile.stack_bytes(), Some(COMPILE_STACK_BYTES));
        assert_eq!(
            ThreadRole::WatchCompile.stack_bytes(),
            Some(COMPILE_STACK_BYTES)
        );
        let name = run_compile(|| std::thread::current().name().map(str::to_owned));
        assert_eq!(name.ok().flatten().as_deref(), Some("ipe-compile"));
    }

    #[test]
    fn a_refused_compile_thread_is_a_typed_error() {
        refusal::refuse(ThreadRole::Compile);
        let refused = run_compile(|| ());
        assert!(matches!(
            refused,
            Err(CliError::ThreadRefused {
                role: ThreadRole::Compile,
                ..
            })
        ));
    }

    fn text_role() -> &'static str {
        crate::text::thread_role_watch_compile()
    }
}

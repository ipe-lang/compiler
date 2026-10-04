//! Thread starts that refuse with a typed error instead of panicking.
//!
//! Every OS thread the runtime starts goes through [`spawn_named`], and every
//! offload onto tokio's blocking pool through `offload_blocking`: the OS
//! refusing a thread is a [`ThreadRefused`] the caller routes into its own
//! error channel, never a panic. The runtime `clippy.toml` denies the
//! panicking starts (`std::thread::spawn`, `std::thread::Scope::spawn`,
//! `tokio::task::spawn_blocking`, `tokio::runtime::Handle::spawn_blocking`).

use std::fmt;
use std::thread::JoinHandle;

/// Why a thread could not be started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCause {
    /// The OS refused a new thread.
    Os(std::io::ErrorKind),
    /// tokio's blocking pool had no thread to run the work on.
    BlockingPool,
    /// No tokio runtime is running on the calling thread.
    NoRuntime,
}

/// A thread the runtime could not start, named by the work it was for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadRefused {
    role: &'static str,
    cause: RefusalCause,
}

impl ThreadRefused {
    /// The refusal of the thread for `role` by the OS error `err`.
    #[must_use]
    pub fn os(role: &'static str, err: &std::io::Error) -> Self {
        Self {
            role,
            cause: RefusalCause::Os(err.kind()),
        }
    }

    /// The work the refused thread was for.
    #[must_use]
    pub const fn role(&self) -> &'static str {
        self.role
    }

    /// Why the thread could not be started.
    #[must_use]
    pub const fn cause(&self) -> RefusalCause {
        self.cause
    }

    /// The refusal as the caller's error, kinded `Unavailable`.
    #[must_use]
    pub fn into_error<E: crate::FromUnavailable>(self) -> E {
        E::from_unavailable(self.to_string())
    }
}

impl fmt::Display for ThreadRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.cause {
            RefusalCause::Os(kind) => {
                write!(f, "{}: the OS refused a thread ({kind})", self.role)
            }
            RefusalCause::BlockingPool => write!(
                f,
                "{}: the blocking pool could not start a thread",
                self.role
            ),
            RefusalCause::NoRuntime => {
                write!(f, "{}: no async runtime is running", self.role)
            }
        }
    }
}

impl std::error::Error for ThreadRefused {}

/// Starts an OS thread named `name`, or returns the OS refusal.
///
/// # Errors
///
/// The OS refused the thread.
pub fn spawn_named<F, T>(name: &'static str, f: F) -> std::io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    #[cfg(all(test, not(target_arch = "wasm32")))]
    if refusal_hook::refuses(name) {
        return Err(std::io::Error::other(format!(
            "thread `{name}` refused by the test hook"
        )));
    }
    std::thread::Builder::new().name(name.to_owned()).spawn(f)
}

/// Starts an OS thread named `name` with a `stack_size`-byte stack, or
/// returns the OS refusal.
///
/// # Errors
///
/// The OS refused the thread.
pub fn spawn_sized<F, T>(
    name: &'static str,
    stack_size: usize,
    f: F,
) -> std::io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    #[cfg(all(test, not(target_arch = "wasm32")))]
    if refusal_hook::refuses(name) {
        return Err(std::io::Error::other(format!(
            "thread `{name}` refused by the test hook"
        )));
    }
    std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(stack_size)
        .spawn(f)
}

/// Why blocking work produced no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockingFailure {
    /// No thread could be started to run it.
    Refused(ThreadRefused),
    /// It panicked or was cancelled before returning.
    Panicked,
}

impl BlockingFailure {
    /// The failure as the caller's error: a refusal kinded `Unavailable`, a
    /// panic as the `panicked` message.
    #[must_use]
    pub fn into_error<E: From<String> + crate::FromUnavailable>(self, panicked: &str) -> E {
        match self {
            Self::Refused(refused) => refused.into_error(),
            Self::Panicked => E::from(panicked.to_owned()),
        }
    }
}

#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
mod blocking {
    // tokio reports a refused blocking-pool thread only by panicking, so the
    // typed refusal rests on catching that unwind.
    #[cfg(panic = "abort")]
    compile_error!(
        "`threads::offload_blocking` catches tokio's thread-start panic to return a typed \
         refusal; a `panic = \"abort\"` build cannot catch it"
    );

    use super::{BlockingFailure, RefusalCause, ThreadRefused};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    /// Moves `f` onto tokio's blocking pool, or returns why it could not.
    ///
    /// # Errors
    ///
    /// No runtime is running on the calling thread, or the pool could not
    /// start a thread for `f`.
    #[allow(clippy::disallowed_methods)] // the one blocking-pool start; its thread-start panic is caught here
    pub fn offload_blocking<F, R>(
        role: &'static str,
        f: F,
    ) -> Result<tokio::task::JoinHandle<R>, ThreadRefused>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        #[cfg(test)]
        if super::refusal_hook::refuses(role) {
            return Err(ThreadRefused {
                role,
                cause: RefusalCause::BlockingPool,
            });
        }
        let handle = tokio::runtime::Handle::try_current().map_err(|_| ThreadRefused {
            role,
            cause: RefusalCause::NoRuntime,
        })?;
        catch_unwind(AssertUnwindSafe(|| handle.spawn_blocking(f))).map_err(|_| ThreadRefused {
            role,
            cause: RefusalCause::BlockingPool,
        })
    }

    /// Runs `f` on tokio's blocking pool and returns its value.
    ///
    /// # Errors
    ///
    /// No thread could be started for `f`, or `f` panicked.
    pub async fn join_blocking<F, T>(role: &'static str, f: F) -> Result<T, BlockingFailure>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        offload_blocking(role, f)
            .map_err(BlockingFailure::Refused)?
            .await
            .map_err(|_| BlockingFailure::Panicked)
    }
}

#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
pub use blocking::{join_blocking, offload_blocking};

/// Runs `f` inline: without a blocking pool there is no thread to start.
///
/// # Errors
///
/// Never; the signature matches the pooled form.
#[cfg(any(not(feature = "tokio"), target_arch = "wasm32"))]
// `async` keeps the pooled form's signature, so callers `.await` in every build.
#[allow(clippy::unused_async)]
pub async fn join_blocking<F, T>(_role: &'static str, f: F) -> Result<T, BlockingFailure>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    Ok(f())
}

/// Runs the fallible blocking `f` off the async worker, as the caller's error.
///
/// A refused thread is kinded `Unavailable`; a panic in `f` becomes the
/// `panicked` message.
///
/// # Errors
///
/// `f` failed, no thread could be started for it, or it panicked.
pub async fn run_blocking<T, E, F>(role: &'static str, panicked: &'static str, f: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
    E: From<String> + crate::FromUnavailable,
{
    match join_blocking(role, f).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(message)) => Err(E::from(message)),
        Err(failure) => Err(failure.into_error(panicked)),
    }
}

/// Refuses thread starts by name, for tests that drive the refusal paths.
///
/// The refusal is per calling thread, so tests running in parallel in one
/// process never refuse each other's threads.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub mod refusal_hook {
    use std::cell::RefCell;

    thread_local! {
        static REFUSED: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
    }

    /// Refuses every start of a thread named `name` on this thread until the
    /// guard drops.
    #[must_use]
    pub fn refuse(name: &'static str) -> Refusing {
        REFUSED.with_borrow_mut(|names| names.push(name));
        Refusing { name }
    }

    /// Whether a start of a thread named `name` is refused on this thread.
    pub fn refuses(name: &str) -> bool {
        REFUSED.with_borrow(|names| names.contains(&name))
    }

    /// Lifts the refusal of one name when dropped.
    pub struct Refusing {
        name: &'static str,
    }

    impl Drop for Refusing {
        fn drop(&mut self) {
            REFUSED.with_borrow_mut(|names| {
                if let Some(at) = names.iter().position(|n| *n == self.name) {
                    names.swap_remove(at);
                }
            });
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn a_refused_name_is_an_os_error_without_a_thread() {
        let _refusing = refusal_hook::refuse("ipe-test-refused");
        assert!(spawn_named("ipe-test-refused", || ()).is_err());
    }

    #[test]
    fn an_unrefused_name_starts_its_thread() {
        let _refusing = refusal_hook::refuse("ipe-test-other");
        let started = spawn_named("ipe-test-started", || 7).map(JoinHandle::join);
        assert!(matches!(started, Ok(Ok(7))));
    }

    #[test]
    fn the_refusal_lifts_when_its_guard_drops() {
        drop(refusal_hook::refuse("ipe-test-lifted"));
        assert!(!refusal_hook::refuses("ipe-test-lifted"));
    }

    #[test]
    fn a_refusal_is_kinded_unavailable() {
        let err: crate::IpeError =
            ThreadRefused::os("ipe-test", &std::io::Error::other("no threads")).into_error();
        assert_eq!(crate::ipe_error_kind(err), crate::IpeErrorKind::Unavailable);
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn a_refused_offload_is_a_typed_refusal() {
        let _refusing = refusal_hook::refuse("ipe-test-offload");
        assert!(matches!(
            offload_blocking("ipe-test-offload", || ()),
            Err(refused) if refused.cause() == RefusalCause::BlockingPool
        ));
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn an_offload_outside_a_runtime_is_refused_not_a_panic() {
        assert!(matches!(
            offload_blocking("ipe-test-no-runtime", || ()),
            Err(refused) if refused.cause() == RefusalCause::NoRuntime
        ));
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn a_refused_run_is_kinded_unavailable() {
        let _refusing = refusal_hook::refuse("ipe-test-run");
        let ran: Result<(), crate::IpeError> =
            run_blocking("ipe-test-run", "panicked", || Ok(())).await;
        assert!(matches!(
            ran.map_err(crate::ipe_error_kind),
            Err(crate::IpeErrorKind::Unavailable)
        ));
    }
}

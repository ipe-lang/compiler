//! Thread starts that refuse with a typed error instead of panicking.
//!
//! Every OS thread the runtime starts goes through [`spawn_named`], and every
//! offload onto tokio's blocking pool through `offload_blocking`: the OS
//! refusing a thread is a [`ThreadRefused`] the caller routes into its own
//! error channel, never a panic. The runtime `clippy.toml` denies the
//! panicking starts (`std::thread::spawn`, `std::thread::Scope::spawn`,
//! `tokio::task::spawn_blocking`, `tokio::runtime::Handle::spawn_blocking`).
//!
//! Every async task the runtime starts goes through [`spawn_task`] or
//! [`IpeJoinSet`]: its scope is chosen ([`TaskScope`]), its handle aborts
//! the task when dropped, a join resumes a [`crate::core::RuntimeTrip`] on
//! the joiner, and a detached task names who answers for its end
//! ([`Detached`]). The `clippy.toml` denies the other starts and joins.

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
    /// The failure as the caller's error, each cause under its own kind.
    ///
    /// A refusal is kinded `Unavailable`; a panic or cancel is the `panicked`
    /// message kinded `Unexpected`, since it is a defect in runtime work.
    #[must_use]
    pub fn into_error<E: crate::FromUnavailable + crate::FromIpeError>(self, panicked: &str) -> E {
        match self {
            Self::Refused(refused) => refused.into_error(),
            Self::Panicked => E::from_ipe_error(crate::IpeError::unexpected(panicked.to_owned())),
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
    /// A [`crate::core::RuntimeTrip`] raised in `f` is resumed on the awaiting
    /// task, so it reaches that task's boundary as its typed error rather than
    /// ending here as an untyped [`BlockingFailure::Panicked`].
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
            .map_err(|failed| {
                if let Ok(payload) = failed.try_into_panic() {
                    drop(crate::core::resume_runtime_trip(payload));
                }
                BlockingFailure::Panicked
            })
    }
}

#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
pub use blocking::{join_blocking, offload_blocking};

#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
mod tasks {
    use super::{RefusalCause, ThreadRefused};
    use crate::core::{ClosureUnwind, RuntimeTrip, closure_unwind};
    use crate::task::AbortOnDrop;
    use std::fmt;
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, OnceLock};

    /// The task-local scopes a started task runs in.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TaskScope {
        /// Its starter's: the task works on the caller's behalf, so a
        /// credential it verifies binds to the caller's session or request.
        Caller,
        /// None: runtime-owned work; the text says why no caller scope applies.
        RuntimeOwned(&'static str),
    }

    /// How a joined task ended without its output; a trip never reaches here.
    pub enum TaskEnded {
        /// The task was aborted, or its runtime shut down first.
        Cancelled(tokio::task::JoinError),
        /// The task panicked with a payload that is not a trip.
        Panicked(Box<dyn std::any::Any + Send>),
    }

    impl fmt::Debug for TaskEnded {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Cancelled(join_err) => f.debug_tuple("Cancelled").field(join_err).finish(),
                Self::Panicked(_) => f.write_str("Panicked(..)"),
            }
        }
    }

    impl TaskEnded {
        /// Whether the task was cancelled rather than panicking.
        #[must_use]
        pub const fn is_cancelled(&self) -> bool {
            matches!(self, Self::Cancelled(_))
        }

        /// The end as the caller's error, kinded `Unexpected`.
        ///
        /// A panic or a cancel is a defect in runtime or compiled code: the
        /// error names `role` and the end, its detail logged under the
        /// correlation id it shows.
        #[must_use]
        pub fn into_error<E: crate::FromIpeError>(self, role: &str) -> E {
            match self {
                Self::Panicked(payload) => crate::core::ipe_error_from_unwind(
                    crate::core::UnwindBoundary::Task(&format!("{role} panicked")),
                    payload,
                ),
                Self::Cancelled(join_err) => {
                    E::from_ipe_error(crate::IpeError::unexpected(format!(
                        "{role} cancelled (ref {})",
                        crate::core::note_foreign_error(join_err)
                    )))
                }
            }
        }
    }

    /// How a contained join ended without its output, the trip kept a value.
    #[derive(Debug)]
    pub enum Unjoined {
        /// The task's Ipê code raised the runtime's typed trip.
        Trip(RuntimeTrip),
        /// The task panicked otherwise, or was cancelled.
        Ended(TaskEnded),
    }

    /// The one classification of a task's `JoinError`.
    fn classify(failed: tokio::task::JoinError) -> Unjoined {
        match failed.try_into_panic() {
            Ok(payload) => match closure_unwind(payload) {
                ClosureUnwind::Trip(fault) => Unjoined::Trip(fault),
                ClosureUnwind::Foreign(other) => Unjoined::Ended(TaskEnded::Panicked(other)),
            },
            Err(cancelled) => Unjoined::Ended(TaskEnded::Cancelled(cancelled)),
        }
    }

    /// A task end, with a trip resumed on the calling task.
    fn resume_trip(unjoined: Unjoined) -> TaskEnded {
        match unjoined {
            Unjoined::Trip(fault) => std::panic::resume_unwind(Box::new(fault)),
            Unjoined::Ended(ended) => ended,
        }
    }

    /// Who answers for a detached task once nothing joins it.
    #[derive(Debug)]
    pub enum Detached {
        /// The task runs no Ipê code, so no trip can end it; the text says
        /// what it runs.
        NoIpeCode(&'static str),
        /// The task may run Ipê code: its trip or panic is delivered to the
        /// owner of this sink, which ends its own run with the typed error.
        IpeOwned(TripSink),
    }

    /// A started async task: joined, detached, or aborted when dropped.
    #[must_use = "a dropped handle aborts its task; join it or detach it"]
    pub struct TaskHandle<T> {
        role: &'static str,
        handle: tokio::task::JoinHandle<T>,
        guard: AbortOnDrop,
        runtime: tokio::runtime::Handle,
    }

    impl<T> fmt::Debug for TaskHandle<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("TaskHandle")
                .field("role", &self.role)
                .finish_non_exhaustive()
        }
    }

    impl<T> TaskHandle<T> {
        /// The task's output, a trip in it resumed on this task.
        ///
        /// # Errors
        ///
        /// The task panicked with another payload, or was cancelled.
        pub async fn joined(self) -> Result<T, TaskEnded> {
            self.join_contained().await.map_err(resume_trip)
        }

        /// The task's output, a trip in it returned as a value.
        ///
        /// For a joiner no unwind may leave, such as a future a foreign
        /// executor polls.
        ///
        /// # Errors
        ///
        /// The task tripped, panicked, or was cancelled.
        pub async fn join_contained(self) -> Result<T, Unjoined> {
            let Self { handle, guard, .. } = self;
            let joined = handle.await;
            guard.defuse();
            joined.map_err(classify)
        }

        /// The task's output as [`Self::join_contained`] gives it, the task
        /// running on to its end when this join is dropped first.
        ///
        /// # Errors
        ///
        /// The task tripped, panicked, or was cancelled.
        pub async fn join_shielded(self) -> Result<T, Unjoined> {
            let Self { handle, guard, .. } = self;
            guard.defuse();
            handle.await.map_err(classify)
        }

        /// A handle that aborts the task without joining it.
        #[must_use]
        pub fn abort_handle(&self) -> tokio::task::AbortHandle {
            self.handle.abort_handle()
        }

        /// Aborts the task; a join then ends `Cancelled` unless it finished.
        pub fn abort(&self) {
            self.handle.abort();
        }

        /// Whether the task has finished.
        #[must_use]
        pub fn is_finished(&self) -> bool {
            self.handle.is_finished()
        }
    }

    impl<T: Send + 'static> TaskHandle<T> {
        /// Lets the task run on unjoined, answered for by `owner`.
        pub fn detach(self, owner: Detached) {
            let Self {
                role,
                handle,
                guard,
                runtime,
            } = self;
            guard.defuse();
            match owner {
                Detached::NoIpeCode(_) => drop(handle),
                Detached::IpeOwned(sink) => {
                    let watch = async move {
                        if let Err(failed) = handle.await {
                            sink.deliver(role, failed);
                        }
                    };
                    // The watcher runs no Ipê code: it only delivers the
                    // watched task's end.
                    #[allow(clippy::disallowed_methods)]
                    drop(runtime.spawn(watch));
                }
            }
        }
    }

    /// Starts `task` on the running runtime in `scope`.
    ///
    /// # Errors
    ///
    /// No tokio runtime is running on the calling thread.
    pub fn spawn_task<F>(
        role: &'static str,
        scope: TaskScope,
        task: F,
    ) -> Result<TaskHandle<F::Output>, ThreadRefused>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| ThreadRefused {
            role,
            cause: RefusalCause::NoRuntime,
        })?;
        Ok(spawn_task_on(role, &runtime, scope, task))
    }

    /// Starts `task` on `runtime` in `scope`.
    #[allow(clippy::disallowed_methods)] // the one task start: its handle joins typed and aborts on drop
    pub fn spawn_task_on<F>(
        role: &'static str,
        runtime: &tokio::runtime::Handle,
        scope: TaskScope,
        task: F,
    ) -> TaskHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let handle = match scope {
            TaskScope::Caller => runtime.spawn(crate::task::on_behalf_of_caller(task)),
            TaskScope::RuntimeOwned(_) => runtime.spawn(task),
        };
        let guard = AbortOnDrop::new(handle.abort_handle());
        TaskHandle {
            role,
            handle,
            guard,
            runtime: runtime.clone(),
        }
    }

    /// Starts `task` runtime-owned and detached, for a service that runs no
    /// Ipê code; `runs` says what it runs.
    ///
    /// # Errors
    ///
    /// No tokio runtime is running on the calling thread.
    pub fn spawn_service<F>(
        role: &'static str,
        runs: &'static str,
        task: F,
    ) -> Result<(), ThreadRefused>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        spawn_task(role, TaskScope::RuntimeOwned(runs), task)?.detach(Detached::NoIpeCode(runs));
        Ok(())
    }

    /// Starts `task` in its caller's scopes as a bare tokio handle.
    ///
    /// The start of the callers not yet behind [`TaskHandle`]; it panics
    /// with no runtime running.
    pub fn spawn_unmigrated<F>(task: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        tokio::spawn(crate::task::on_behalf_of_caller(task))
    }

    /// A set of tasks joined in completion order, each join resuming a trip.
    #[allow(clippy::disallowed_types)] // the one `JoinSet`: its joins resume trips
    pub struct IpeJoinSet<T> {
        role: &'static str,
        set: tokio::task::JoinSet<T>,
    }

    impl<T> fmt::Debug for IpeJoinSet<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("IpeJoinSet")
                .field("role", &self.role)
                .finish_non_exhaustive()
        }
    }

    #[allow(clippy::disallowed_types, clippy::disallowed_methods)] // the one `JoinSet`: its joins resume trips
    impl<T: Send + 'static> IpeJoinSet<T> {
        /// An empty set whose tasks do the work of `role`.
        #[must_use]
        pub fn new(role: &'static str) -> Self {
            Self {
                role,
                set: tokio::task::JoinSet::new(),
            }
        }

        /// Starts `task` in the set, in `scope`.
        ///
        /// # Errors
        ///
        /// No tokio runtime is running on the calling thread.
        pub fn start<F>(&mut self, scope: TaskScope, task: F) -> Result<(), ThreadRefused>
        where
            F: Future<Output = T> + Send + 'static,
        {
            let runtime = tokio::runtime::Handle::try_current().map_err(|_| ThreadRefused {
                role: self.role,
                cause: RefusalCause::NoRuntime,
            })?;
            let started = match scope {
                TaskScope::Caller => self
                    .set
                    .spawn_on(crate::task::on_behalf_of_caller(task), &runtime),
                TaskScope::RuntimeOwned(_) => self.set.spawn_on(task, &runtime),
            };
            drop(started);
            Ok(())
        }

        /// The next task to finish, a trip in it resumed on this task.
        ///
        /// `None` once the set is empty.
        pub async fn next_joined(&mut self) -> Option<Result<T, TaskEnded>> {
            let joined = self.set.join_next().await?;
            Some(joined.map_err(|failed| resume_trip(classify(failed))))
        }
    }

    /// How a detached task that may run Ipê code ended.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum OwnerEnd {
        /// Its Ipê code raised the runtime's typed trip.
        Trip(RuntimeTrip),
        /// It panicked otherwise; the payload is logged under `reference`.
        Panicked {
            /// The work the task did.
            role: &'static str,
            /// The correlation id the payload is logged under.
            reference: String,
        },
    }

    impl OwnerEnd {
        /// The end as the owner's typed error.
        ///
        /// A trip keeps its kind; a panic is kinded `Unexpected`, naming only
        /// the task's role and the correlation id.
        #[must_use]
        pub fn to_ipe_error(&self) -> crate::IpeError {
            match self {
                Self::Trip(fault) => fault.to_ipe_error(),
                Self::Panicked { role, reference } => {
                    crate::IpeError::unexpected(format!("{role}: task panicked (ref {reference})"))
                }
            }
        }
    }

    #[derive(Debug, Default)]
    struct SinkCell {
        end: OnceLock<OwnerEnd>,
        ended: tokio::sync::Notify,
        owned: AtomicBool,
    }

    /// Where detached tasks deliver their end; the first end wins.
    #[derive(Debug, Clone, Default)]
    pub struct TripSink(Arc<SinkCell>);

    /// A second owner registration on one [`TripSink`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TripSinkTaken;

    impl fmt::Display for TripSinkTaken {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("the trip sink already has an owner")
        }
    }

    impl std::error::Error for TripSinkTaken {}

    impl TripSink {
        /// A sink with no end and no owner yet.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// The sink's one owner.
        ///
        /// # Errors
        ///
        /// The sink already has an owner.
        pub fn owner(&self) -> Result<TripOwner, TripSinkTaken> {
            if self.0.owned.swap(true, Ordering::AcqRel) {
                return Err(TripSinkTaken);
            }
            Ok(TripOwner(Arc::clone(&self.0)))
        }

        /// Records the end of a detached task, unless one is recorded already.
        fn deliver(&self, role: &'static str, failed: tokio::task::JoinError) {
            let end = match classify(failed) {
                Unjoined::Trip(fault) => OwnerEnd::Trip(fault),
                Unjoined::Ended(TaskEnded::Panicked(payload)) => OwnerEnd::Panicked {
                    role,
                    reference: crate::core::classify_and_log_panic(payload.as_ref()),
                },
                Unjoined::Ended(TaskEnded::Cancelled(_)) => return,
            };
            if self.0.end.set(end).is_ok() {
                self.0.ended.notify_waiters();
            }
        }
    }

    /// The one owner of a [`TripSink`]: it awaits the first delivered end.
    #[derive(Debug)]
    pub struct TripOwner(Arc<SinkCell>);

    impl TripOwner {
        /// The first end a detached task delivered, once one has.
        pub async fn ended(&self) -> OwnerEnd {
            loop {
                let notified = self.0.ended.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if let Some(end) = self.0.end.get() {
                    return end.clone();
                }
                notified.await;
            }
        }
    }
}

#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
pub use tasks::{
    Detached, IpeJoinSet, OwnerEnd, TaskEnded, TaskHandle, TaskScope, TripOwner, TripSink,
    TripSinkTaken, Unjoined, spawn_service, spawn_task, spawn_task_on, spawn_unmigrated,
};

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
/// `f`'s own failure keeps its kind; a refused thread is kinded
/// `Unavailable`; a panic in `f` becomes the `panicked` message.
///
/// # Errors
///
/// `f` failed, no thread could be started for it, or it panicked.
pub async fn run_blocking<T, E, F>(role: &'static str, panicked: &'static str, f: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, crate::KernelFailure> + Send + 'static,
    T: Send + 'static,
    E: crate::KernelErrorSink,
{
    match join_blocking(role, f).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(failure)) => Err(failure.into_error()),
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

    // A trip raised in blocking work is the runtime's typed fault, not a
    // defect of the offloaded work: it resumes on the awaiting task, so that
    // task's boundary types it instead of `join_blocking` absorbing it.
    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn a_trip_in_blocking_work_resumes_on_the_awaiting_task() {
        use crate::core::{RuntimeTrip, runtime_trip, trip};
        let awaiting = tokio::spawn(async {
            join_blocking("ipe-test-trip", || -> i64 {
                trip(RuntimeTrip::RecursionLimit)
            })
            .await
        });
        let joined = awaiting.await;
        assert!(
            joined.is_err(),
            "the trip must leave `join_blocking`: {joined:?}"
        );
        let Err(failed) = joined else { return };
        let payload = failed.try_into_panic();
        assert!(
            payload.is_ok(),
            "the awaiting task must unwind, not be cancelled"
        );
        let Ok(payload) = payload else { return };
        assert_eq!(
            runtime_trip(payload.as_ref()),
            Some(RuntimeTrip::RecursionLimit)
        );
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn a_non_trip_panic_in_blocking_work_is_panicked() {
        let joined = join_blocking("ipe-test-panic", || -> i64 {
            std::panic::resume_unwind(Box::new("blocking work failed"))
        })
        .await;
        assert!(matches!(joined, Err(BlockingFailure::Panicked)));
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

    #[cfg(feature = "tokio")]
    fn tripping() -> i64 {
        crate::core::trip(crate::core::RuntimeTrip::RecursionLimit)
    }

    #[cfg(feature = "tokio")]
    fn foreign_panic() -> i64 {
        std::panic::resume_unwind(Box::new("sk_live_SECRET"))
    }

    #[cfg(feature = "tokio")]
    const DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn a_trip_in_a_joined_task_resumes_on_the_joiner() {
        let outer = spawn_task("ipe-test-outer", TaskScope::RuntimeOwned("test"), async {
            let inner = spawn_task("ipe-test-inner", TaskScope::Caller, async { tripping() });
            if let Ok(inner) = inner {
                drop(inner.joined().await);
            }
        });
        assert!(outer.is_ok(), "a runtime is running");
        let Ok(outer) = outer else { return };
        let joined = outer.join_contained().await;
        assert!(
            matches!(
                joined,
                Err(Unjoined::Trip(crate::core::RuntimeTrip::RecursionLimit))
            ),
            "the inner trip must leave the joiner's join as the same trip: {joined:?}"
        );
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn a_joinset_member_trip_resumes_on_the_joiner() {
        let outer = spawn_task("ipe-test-outer", TaskScope::RuntimeOwned("test"), async {
            let mut set = IpeJoinSet::new("ipe-test-member");
            if set.start(TaskScope::Caller, async { tripping() }).is_ok() {
                drop(set.next_joined().await);
            }
        });
        assert!(outer.is_ok(), "a runtime is running");
        let Ok(outer) = outer else { return };
        let joined = outer.join_contained().await;
        assert!(
            matches!(
                joined,
                Err(Unjoined::Trip(crate::core::RuntimeTrip::RecursionLimit))
            ),
            "a member's trip must leave `next_joined` as the same trip: {joined:?}"
        );
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn spawn_without_a_runtime_refuses_typed() {
        let started = spawn_task("ipe-test-none", TaskScope::Caller, async { 7_i64 });
        assert!(
            matches!(&started, Err(refused) if refused.cause() == RefusalCause::NoRuntime),
            "{started:?}"
        );
        let mut set = IpeJoinSet::new("ipe-test-none");
        let member = set.start(TaskScope::RuntimeOwned("test"), async { 7_i64 });
        assert!(
            matches!(&member, Err(refused) if refused.cause() == RefusalCause::NoRuntime),
            "{member:?}"
        );
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn an_ipe_owned_detached_trip_reaches_its_owner() {
        let sink = TripSink::new();
        let owner = sink.owner();
        assert!(owner.is_ok(), "a fresh sink has no owner");
        let Ok(owner) = owner else { return };
        let started = spawn_task("ipe-test-detached", TaskScope::Caller, async { tripping() });
        assert!(started.is_ok(), "a runtime is running");
        let Ok(started) = started else { return };
        started.detach(Detached::IpeOwned(sink));
        let ended = tokio::time::timeout(DEADLINE, owner.ended()).await;
        assert!(
            matches!(
                &ended,
                Ok(OwnerEnd::Trip(crate::core::RuntimeTrip::RecursionLimit))
            ),
            "{ended:?}"
        );
        let Ok(end) = ended else { return };
        assert_eq!(
            crate::ipe_error_kind(end.to_ipe_error()),
            crate::IpeErrorKind::LimitExceeded
        );
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn an_ipe_owned_detached_panic_reaches_its_owner_redacted() {
        let sink = TripSink::new();
        let owner = sink.owner();
        assert!(owner.is_ok(), "a fresh sink has no owner");
        let Ok(owner) = owner else { return };
        let started = spawn_task("ipe-test-detached", TaskScope::Caller, async {
            foreign_panic()
        });
        assert!(started.is_ok(), "a runtime is running");
        let Ok(started) = started else { return };
        started.detach(Detached::IpeOwned(sink));
        let ended = tokio::time::timeout(DEADLINE, owner.ended()).await;
        assert!(
            matches!(
                &ended,
                Ok(OwnerEnd::Panicked {
                    role: "ipe-test-detached",
                    ..
                })
            ),
            "{ended:?}"
        );
        let Ok(end) = ended else { return };
        let err = end.to_ipe_error();
        assert_eq!(
            crate::ipe_error_kind(err.clone()),
            crate::IpeErrorKind::Unexpected
        );
        assert!(!crate::ipe_error_message(err).contains("sk_live_SECRET"));
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn a_second_sink_registration_is_refused() {
        let sink = TripSink::new();
        let first = sink.owner();
        assert!(first.is_ok(), "a fresh sink has no owner");
        let shared = sink.clone();
        assert!(matches!(shared.owner(), Err(TripSinkTaken)));
        assert!(matches!(sink.owner(), Err(TripSinkTaken)));
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn a_dropped_unjoined_handle_cancels_its_task() {
        let (held, released) = tokio::sync::oneshot::channel::<()>();
        let started = spawn_task("ipe-test-dropped", TaskScope::RuntimeOwned("test"), async {
            let _held = held;
            std::future::pending::<()>().await;
        });
        assert!(started.is_ok(), "a runtime is running");
        drop(started);
        let released = tokio::time::timeout(DEADLINE, released).await;
        assert!(
            matches!(released, Ok(Err(_))),
            "dropping the handle must abort the task and drop its state: {released:?}"
        );
    }
}

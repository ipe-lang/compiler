// Task combinators — generic over error type E.
use super::*;
use std::future::ready;
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
use std::sync::OnceLock;

// The tokio-backed async spine (`block_on`, the shared reactor, foreign-task
// abort guards) has no denotation on `wasm32-unknown-unknown`: the browser
// client runs on a single event loop with no OS threads for `tokio::spawn`,
// and `tokio` is not a wasm dependency. The whole spine is gated off for wasm;
// the wasm client drives its TEA loop through `web_sys`/`wasm-bindgen` instead.
//
// The reactor spine is ALSO gated off the native `tokio`-less build: a program
// whose reachable kernels never touch the reactor (pure computation + `Io`,
// `String`, `List`, `Math`, `Json`, the pure `Task` monad ops) drops the
// `tokio` crate entirely and enters through the std-only `block_on` below. The
// reactor-driven entries (`task_parallel`, `task_retry_with`,
// `block_on_current_thread`, the shared runtime, the abort guard) are
// `#[cfg(feature = "tokio")]`; the entries a pure program's prelude still names
// unconditionally (`block_on`, `task_run`, `task_parallel`) each have a
// `#[cfg(not(feature = "tokio"))]` std counterpart, so the emitted crate
// compiles either way. The gating kernel classification
// (`KernelFn::requires_async_runtime`) is fail-closed: a pure program never
// CALLS a reactor entry, so its std counterpart is dead code, present only to
// resolve the prelude wrapper.

/// Process-global tokio runtime shared by every `block_on` entry.
///
/// A reactor-registered value constructed inside one `block_on` (an FFI client
/// handle held across entries, a pooled connection) is only usable while its
/// owning reactor lives. A fresh `Runtime` per entry drops that reactor
/// between entries, so a handle crossing two entries hits a dead reactor. One
/// shared runtime keeps every reactor-registered handle live for the process
/// lifetime; a shared reactor is strictly more available than a fresh one.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
static GLOBAL_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
fn global_runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    if let Some(rt) = GLOBAL_RUNTIME.get() {
        return Ok(rt);
    }
    // A uniform 8 MiB stack on every worker (axum handlers, `drive_session`,
    // `task_parallel` workers, the blocking pool) makes the recursion guard's
    // depth budget calibrated and the trip depth identical across shapes; the
    // `on_thread_start` hook records each worker's stack floor so the guard's
    // red-zone probe has a reference point on every runtime-owned thread.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(crate::core::RUNTIME_THREAD_STACK_SIZE)
        .on_thread_start(|| {
            crate::core::record_stack_floor(crate::core::RUNTIME_THREAD_STACK_SIZE);
        })
        .build()
        .map_err(|e| format!("tokio runtime init failed: {e}"))?;
    // A racing initializer's spare runtime is dropped unused (no tasks on it).
    Ok(GLOBAL_RUNTIME.get_or_init(|| rt))
}

/// Aborts a spawned foreign task when its owning guard is dropped before
/// completion (`Task.parallel` early-cancel drops the losing wrapper future),
/// so a cancelled FFI call cannot keep producing side effects. `defuse`
/// disarms after a normal join.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
pub struct AbortOnDrop(Option<tokio::task::AbortHandle>);

#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
impl AbortOnDrop {
    #[must_use]
    pub fn new(handle: tokio::task::AbortHandle) -> Self {
        Self(Some(handle))
    }

    pub fn defuse(mut self) {
        self.0 = None;
    }
}

#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            h.abort();
        }
    }
}

/// The single spawn choke-point every emitted async FFI wrapper routes through.
///
/// STRUCTURAL GUARANTEE. Spawning a foreign future and arming its cancel guard
/// are one indivisible operation here: there is no way to obtain the spawned
/// task's outcome without the `AbortOnDrop` guard having been armed on the same
/// `AbortHandle` first. So an emitted wrapper cannot spawn a foreign task and
/// forget the guard — the emitter has no spawn primitive of its own; it can only
/// call this, and this always arms. That closes the class of bug where one async
/// binding shape drops the guard while the others keep it.
///
/// CANCEL HONESTY. If the wrapper future is dropped before this returns (a
/// `Task.parallel` early-cancel drops the losing sibling, a `Task` timeout drops
/// the whole chain), the guard's `Drop` aborts the inner foreign task, so a
/// cancelled foreign call cannot keep running and fire a post-cancel side effect
/// (a duplicate DB write, a duplicate charge). A normal completion `defuse`s the
/// guard before it can abort a task that already finished.
///
/// PANIC HONESTY. A poll-time panic inside the foreign future surfaces as a
/// `JoinError`. Its payload is foreign-controlled (it can echo secrets / PII /
/// internal paths just like a foreign error's `Debug`), so it is NEVER returned
/// to Ipê: the panic payload routes through the redacting `ipe_error_from_panic`
/// funnel (raw detail logged server-side under a correlation id, a generic typed
/// message to Ipê); a non-panic `JoinError` (a cancel that still resolved a join)
/// routes through `ipe_error_from_foreign`. Either way the caller gets a typed
/// `Err`, never a process abort and never a silent hang.
///
/// The success value `T` is returned verbatim (`Ok(T)`); the caller applies its
/// own shape-specific lift/fold to it (`ok_res`, the fallible `Result` unwrap,
/// the `Option` fold). TOTALITY: no unwrap/expect/panic/indexing.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
pub async fn ffi_spawn_guarded<F>(future: F) -> Result<F::Output, IpeError>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let handle = spawn_in_current_scope(future);
    let guard = AbortOnDrop::new(handle.abort_handle());
    let joined = handle.await;
    guard.defuse();
    match joined {
        Ok(output) => Ok(output),
        Err(join_err) => match join_err.try_into_panic() {
            Ok(payload) => Err(ipe_error_from_panic("foreign async task panicked", payload)),
            Err(join_err) => Err(ipe_error_from_foreign(join_err)),
        },
    }
}

/// The name of the entry thread [`block_on`] drives its task on.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
const BLOCK_ON_THREAD: &str = "ipe-block-on";

/// `task`, carried into every task-local scope its caller runs in, so code
/// that runs on another task or thread on the caller's behalf sees the scopes
/// the caller sees (a credential it verifies binds to the request that owns
/// it).
///
/// Every caller-owned task-local scope is carried here and only here: a new
/// one wraps the result, `carry_new_scope(carry_request_streams(..))`, and
/// every spawn of this module inherits it.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
#[allow(clippy::missing_const_for_fn)] // const only in builds that carry no scope
fn on_behalf_of_caller<F: std::future::Future>(
    task: F,
) -> impl std::future::Future<Output = F::Output> {
    carry_request_streams(carry_server_request(task))
}

/// `task`, kept inside the stream table of the `Server` request its caller
/// handles, so a `stream` it registers belongs to that request.
#[cfg(all(feature = "tokio", feature = "server", not(target_arch = "wasm32")))]
fn carry_request_streams<F: std::future::Future>(
    task: F,
) -> impl std::future::Future<Output = F::Output> {
    crate::server_stream::inherit_stream_scope(task)
}

/// `task` as it is: without `server` no request stream table exists.
#[cfg(all(
    feature = "tokio",
    not(feature = "server"),
    not(target_arch = "wasm32")
))]
const fn carry_request_streams<F: std::future::Future>(task: F) -> F {
    task
}

/// `task`, kept inside the binding set of the `Server` request its caller
/// handles.
#[cfg(all(
    feature = "tokio",
    feature = "server",
    feature = "jwt",
    not(target_arch = "wasm32")
))]
fn carry_server_request<F: std::future::Future>(
    task: F,
) -> impl std::future::Future<Output = F::Output> {
    crate::server::inherit_request_scope(task)
}

/// `task` as it is: without `server` and `jwt` no request scope exists.
#[cfg(all(
    feature = "tokio",
    not(all(feature = "server", feature = "jwt")),
    not(target_arch = "wasm32")
))]
const fn carry_server_request<F: std::future::Future>(task: F) -> F {
    task
}

/// Spawn `task` on the runtime inside every scope its caller runs in.
///
/// The one runtime spawn of this module: a bare spawn starts the task outside
/// the caller's task-locals, where a credential it verifies binds to nothing.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
fn spawn_in_current_scope<F>(task: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(on_behalf_of_caller(task))
}

#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
pub fn block_on<E, A>(future: IpeTask<E, A>) -> IpeResult<E, A>
where
    E: From<String> + crate::FromUnavailable + Send + 'static,
    A: Send + 'static,
{
    let rt = match global_runtime() {
        Ok(r) => r,
        Err(e) => return IpeResult::Err(e.into()),
    };
    let future = on_behalf_of_caller(future);
    // The spawned OS thread keeps the entry poll outside any runtime context
    // (a nested `block_on` inside a worker thread would panic) and lets a
    // panicking future be `.join()`-mapped to `Err` instead of aborting. The
    // caught payload routes through the redacting foreign-panic funnel: raw
    // detail goes to the server log under a correlation id, and the typed
    // Ipê error carries only the generic message plus that id.
    //
    // The entry thread is spawned with the uniform 8 MiB stack and records its
    // floor first thing, so a guarded recursion entered directly from `block_on`
    // (a synchronous CLI computation) trips at the same depth as one entered on a
    // tokio worker, and the red-zone probe has a floor here too.
    let spawned = crate::threads::spawn_sized(
        BLOCK_ON_THREAD,
        crate::core::RUNTIME_THREAD_STACK_SIZE,
        move || {
            crate::core::record_stack_floor(crate::core::RUNTIME_THREAD_STACK_SIZE);
            rt.block_on(future)
        },
    );
    let handle = match spawned {
        Ok(h) => h,
        Err(e) => {
            return IpeResult::Err(
                crate::threads::ThreadRefused::os(BLOCK_ON_THREAD, &e).into_error(),
            );
        }
    };
    match handle.join() {
        Ok(r) => r,
        Err(payload) => IpeResult::Err(ipe_error_from_panic("async task panicked", payload)),
    }
}

// Std-only entry for a program that reaches NO reactor-requiring kernel: its
// `ipe_main()` future resolves without a timer, a spawn, or a socket, so it
// needs no tokio reactor. This driver polls the future to completion on the
// current thread with a real park/unpark `Waker` — no busy-spin, no external
// crate. It is the `block_on` a `tokio`-less emitted crate links.
//
// CORRECTNESS. The future is pinned on the stack and polled. On `Poll::Ready`
// the result returns. On `Poll::Pending` the thread PARKS until the waker
// unparks it, then re-polls — the standard park/unpark loop. A pure Ipê
// future never actually yields `Pending` (every whitelisted kernel resolves on
// first poll), but the loop is written for the general case so it can never
// busy-spin: a spurious wake re-polls, a real wake re-polls, and absent a wake
// the thread sleeps. `thread::park` may return spuriously, which is harmless —
// it just re-polls.
//
// SOUNDNESS (no missed wakeup). The waker sets an `Arc<AtomicBool>` "notified"
// flag BEFORE unparking the target thread, and the loop CHECKS-AND-CLEARS that
// flag before parking. So a wake that lands between the `poll` returning
// `Pending` and the `park` call is not lost: the flag is already set, the
// pre-park check sees it, clears it, and re-polls instead of parking. This is
// the canonical race-free park/unpark handshake.
//
// TOTALITY: no unwrap/expect/panic/indexing. A panic inside the future
// propagates to the entry boundary's synchronous-panic classifier (the same
// place the tokio path's non-spawned webview driver relies on) — there is no
// spawn here to `.join()`, matching `block_on_current_thread`'s contract.
// The std-only single-thread poll loop — no tokio, no spawn. It is the LIVE
// `block_on` on two targets: a `tokio`-less host build, AND co-located WASI
// (`wasm32-wasip1`), whose single-threaded reactor has no tokio *crate* (tokio
// is native-only in the manifest) even when a WASI build sets the `tokio`
// feature flag via `async`. `std::thread::current`/`park` resolve on WASI, so a
// `Direct` (`Task Error ()`) WASI program's `main` drives to completion here.
// Only the browser `wasm-client` sink drives its loop elsewhere (`spawn_local`).
#[cfg(all(
    not(all(target_arch = "wasm32", feature = "wasm-client")),
    any(not(feature = "tokio"), target_arch = "wasm32")
))]
pub fn block_on<E, A>(future: IpeTask<E, A>) -> IpeResult<E, A>
where
    E: From<String> + Send + 'static,
    A: Send + 'static,
{
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    // A `Waker` that records a notification and unparks the blocked driver
    // thread. Recording BEFORE unparking closes the wake-before-park race.
    struct ThreadWaker {
        thread: std::thread::Thread,
        notified: Arc<AtomicBool>,
    }
    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.notified.store(true, Ordering::Release);
            self.thread.unpark();
        }
    }

    let notified = Arc::new(AtomicBool::new(false));
    let waker: Waker = Arc::new(ThreadWaker {
        thread: std::thread::current(),
        notified: Arc::clone(&notified),
    })
    .into();
    let mut cx = Context::from_waker(&waker);

    let mut future = future;
    let mut pinned = std::pin::Pin::new(&mut future);
    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(r) => return r,
            Poll::Pending => {
                // Park until woken. The pre-park check consumes a notification
                // that arrived while polling, so a wake is never lost; absent
                // one, `park` sleeps until the waker unparks. A spurious wake
                // simply re-polls.
                while !notified.swap(false, Ordering::Acquire) {
                    std::thread::park();
                }
            }
        }
    }
}

// Main-thread driver for the Ipe.WebView entry shape.
//
// `block_on` (above) drives the entry future on a SPAWNED OS thread (so a
// panic inside the future can be `.join()`-mapped to an `Err` instead of
// aborting the process). That spawn is fatal for Ipe.WebView: tao/winit's
// `EventLoop` and Cocoa's `NSApplication` MUST be created and run on the
// process's TRUE main thread on macOS (a hard Cocoa requirement — there is no
// any-thread escape hatch), and Windows likewise expects the main thread. The
// webview `event_loop.run(...)` lives inside the entry Task's future, so the
// future itself has to be polled on the main thread.
//
// This driver runs the future on the CURRENT (main) thread via a
// `current_thread` tokio runtime — no `std::thread::spawn`, so `event_loop.run`
// constructs and runs on the main thread on every OS. The current-thread
// runtime still drives any async work the webview Task chain does BEFORE it
// hands the thread to `event_loop.run` (pre-webview `andThen` I/O, etc.),
// because `block_on` on a `current_thread` runtime cooperatively polls the
// whole future tree on this one thread. `enable_all()` keeps timers + I/O
// drivers available.
//
// TOTALITY: runtime-init failure returns `Err` (no unwrap/expect/panic). There
// is no spawn here, so there is no `.join()` panic-catch — a panic inside the
// webview future would propagate (the synchronous-panic gate at the entry
// boundary classifies it). That is acceptable for the webview shape: the
// webview path itself is total (window/webview construction failure returns
// `IpeResult::Err`), so a panic would be a genuine compiler/runtime bug, not a
// well-typed-Ipê-reachable abort.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
pub fn block_on_current_thread<E, A>(future: IpeTask<E, A>) -> IpeResult<E, A>
where
    E: From<String> + Send + 'static,
    A: Send + 'static,
{
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => return IpeResult::Err(format!("tokio runtime init failed: {}", e).into()),
    };
    rt.block_on(future)
}

pub fn task_succeed<E: Send + 'static, A: Send + 'static>(a: A) -> IpeTask<E, A> {
    Box::pin(ready(ok_res::<E, A>(a)))
}

pub fn task_map<E, A, B>(
    f: impl FnOnce(A) -> B + Send + 'static,
    task: IpeTask<E, A>,
) -> IpeTask<E, B>
where
    E: Send + 'static,
    A: Send + 'static,
    B: Send + 'static,
{
    Box::pin(async move {
        match task.await {
            IpeResult::Ok(a) => ok_res(f(a)),
            IpeResult::Err(e) => IpeResult::Err(e),
        }
    })
}

// `task_map2`..`task_map5` — combine 2..5 independent tasks with an N-ary
// function. Elm-compatible: the tasks await in argument order and an early
// `Err` short-circuits, so a later task's effects never fire. The value
// dependence is none (the function sees all results at once); only the effect
// order is fixed.
pub fn task_map2<E, A, B, R>(
    f: impl FnOnce(A, B) -> R + Send + 'static,
    ta: IpeTask<E, A>,
    tb: IpeTask<E, B>,
) -> IpeTask<E, R>
where
    E: Send + 'static,
    A: Send + 'static,
    B: Send + 'static,
    R: Send + 'static,
{
    Box::pin(async move {
        let a = match ta.await {
            IpeResult::Ok(a) => a,
            IpeResult::Err(e) => return IpeResult::Err(e),
        };
        let b = match tb.await {
            IpeResult::Ok(b) => b,
            IpeResult::Err(e) => return IpeResult::Err(e),
        };
        ok_res(f(a, b))
    })
}

pub fn task_map3<E, A, B, C, R>(
    f: impl FnOnce(A, B, C) -> R + Send + 'static,
    ta: IpeTask<E, A>,
    tb: IpeTask<E, B>,
    tc: IpeTask<E, C>,
) -> IpeTask<E, R>
where
    E: Send + 'static,
    A: Send + 'static,
    B: Send + 'static,
    C: Send + 'static,
    R: Send + 'static,
{
    Box::pin(async move {
        let a = match ta.await {
            IpeResult::Ok(a) => a,
            IpeResult::Err(e) => return IpeResult::Err(e),
        };
        let b = match tb.await {
            IpeResult::Ok(b) => b,
            IpeResult::Err(e) => return IpeResult::Err(e),
        };
        let c = match tc.await {
            IpeResult::Ok(c) => c,
            IpeResult::Err(e) => return IpeResult::Err(e),
        };
        ok_res(f(a, b, c))
    })
}

pub fn task_map4<E, A, B, C, D, R>(
    f: impl FnOnce(A, B, C, D) -> R + Send + 'static,
    ta: IpeTask<E, A>,
    tb: IpeTask<E, B>,
    tc: IpeTask<E, C>,
    td: IpeTask<E, D>,
) -> IpeTask<E, R>
where
    E: Send + 'static,
    A: Send + 'static,
    B: Send + 'static,
    C: Send + 'static,
    D: Send + 'static,
    R: Send + 'static,
{
    Box::pin(async move {
        let a = match ta.await {
            IpeResult::Ok(a) => a,
            IpeResult::Err(e) => return IpeResult::Err(e),
        };
        let b = match tb.await {
            IpeResult::Ok(b) => b,
            IpeResult::Err(e) => return IpeResult::Err(e),
        };
        let c = match tc.await {
            IpeResult::Ok(c) => c,
            IpeResult::Err(e) => return IpeResult::Err(e),
        };
        let d = match td.await {
            IpeResult::Ok(d) => d,
            IpeResult::Err(e) => return IpeResult::Err(e),
        };
        ok_res(f(a, b, c, d))
    })
}

pub fn task_map5<E, A, B, C, D, G, R>(
    f: impl FnOnce(A, B, C, D, G) -> R + Send + 'static,
    ta: IpeTask<E, A>,
    tb: IpeTask<E, B>,
    tc: IpeTask<E, C>,
    td: IpeTask<E, D>,
    te: IpeTask<E, G>,
) -> IpeTask<E, R>
where
    E: Send + 'static,
    A: Send + 'static,
    B: Send + 'static,
    C: Send + 'static,
    D: Send + 'static,
    G: Send + 'static,
    R: Send + 'static,
{
    Box::pin(async move {
        let a = match ta.await {
            IpeResult::Ok(a) => a,
            IpeResult::Err(e) => return IpeResult::Err(e),
        };
        let b = match tb.await {
            IpeResult::Ok(b) => b,
            IpeResult::Err(e) => return IpeResult::Err(e),
        };
        let c = match tc.await {
            IpeResult::Ok(c) => c,
            IpeResult::Err(e) => return IpeResult::Err(e),
        };
        let d = match td.await {
            IpeResult::Ok(d) => d,
            IpeResult::Err(e) => return IpeResult::Err(e),
        };
        let g = match te.await {
            IpeResult::Ok(g) => g,
            IpeResult::Err(e) => return IpeResult::Err(e),
        };
        ok_res(f(a, b, c, d, g))
    })
}

pub fn task_and_then<E, A, B>(
    task: IpeTask<E, A>,
    f: impl FnOnce(A) -> IpeTask<E, B> + Send + 'static,
) -> IpeTask<E, B>
where
    E: Send + 'static,
    A: Send + 'static,
    B: Send + 'static,
{
    Box::pin(async move {
        match task.await {
            IpeResult::Ok(a) => f(a).await,
            IpeResult::Err(e) => IpeResult::Err(e),
        }
    })
}

pub fn task_map_error<E1, E2, A>(
    f: impl FnOnce(E1) -> E2 + Send + 'static,
    task: IpeTask<E1, A>,
) -> IpeTask<E2, A>
where
    E1: Send + 'static,
    E2: Send + 'static,
    A: Send + 'static,
{
    Box::pin(async move {
        match task.await {
            IpeResult::Ok(a) => ok_res(a),
            IpeResult::Err(e) => IpeResult::Err(f(e)),
        }
    })
}

/// `Task.lazy : (() -> Task e a) -> Task e a`.
/// Ipê closures of type `() -> Task e a` are lowered as `FnOnce(()) -> IpeTask`
/// (unit-arg), so the wrapper must accept `(())` and pass it through.
pub fn task_lazy<E: Send + 'static, A: Send + 'static>(
    f: impl FnOnce(()) -> IpeTask<E, A> + Send + 'static,
) -> IpeTask<E, A> {
    Box::pin(async move { f(()).await })
}

pub fn task_from_result<E: Send + 'static, A: Send + 'static>(r: IpeResult<E, A>) -> IpeTask<E, A> {
    Box::pin(ready(r))
}

pub fn task_and_then_result<E, A, B>(
    f: impl FnOnce(A) -> IpeResult<E, B> + Send + 'static,
    task: IpeTask<E, A>,
) -> IpeTask<E, B>
where
    E: Send + 'static,
    A: Send + 'static,
    B: Send + 'static,
{
    Box::pin(async move {
        match task.await {
            IpeResult::Ok(a) => f(a),
            IpeResult::Err(e) => IpeResult::Err(e),
        }
    })
}

pub fn task_on_error<E, A>(
    f: impl FnOnce(E) -> IpeTask<E, A> + Send + 'static,
    task: IpeTask<E, A>,
) -> IpeTask<E, A>
where
    E: Send + 'static,
    A: Send + 'static,
{
    Box::pin(async move {
        match task.await {
            IpeResult::Ok(a) => ok_res(a),
            IpeResult::Err(e) => f(e).await,
        }
    })
}

pub fn task_fail<E: Send + 'static, A: Send + 'static>(e: E) -> IpeTask<E, A> {
    Box::pin(ready(IpeResult::Err(e)))
}

pub fn task_perform<E: Send + 'static, A: Send + 'static>(task: IpeTask<E, A>) -> IpeTask<E, ()> {
    Box::pin(async move {
        match task.await {
            IpeResult::Ok(_) => ok_res(()),
            IpeResult::Err(e) => IpeResult::Err(e),
        }
    })
}

pub fn task_sequence<E: Send + 'static, A: Send + 'static>(
    tasks: Vec<IpeTask<E, A>>,
) -> IpeTask<E, Vec<A>> {
    Box::pin(async move {
        let mut out = Vec::with_capacity(tasks.len());
        for t in tasks {
            match t.await {
                IpeResult::Ok(a) => out.push(a),
                IpeResult::Err(e) => return IpeResult::Err(e),
            }
        }
        ok_res(out)
    })
}

/// The outcome of one `Task.loop` step: carry a new state, or finish with a result.
///
/// The runtime-side twin of `Ipe.Task.Step`; the emitter bridges the emitted
/// `Step` enum to it variant for variant.
pub enum LoopStep<S, A> {
    Continue(S),
    Done(A),
}

/// A `Task.loop` ceiling: the most times the step may run.
///
/// Non-zero by construction, so a ceiling below one has no representation once
/// [`LoopCeiling::parse`] has accepted it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoopCeiling(std::num::NonZeroU64);

impl LoopCeiling {
    /// Parse the caller's raw ceiling; anything below 1 is refused.
    ///
    /// # Errors
    /// [`LoopRefusal::CeilingBelowOne`] carrying `raw` when `raw < 1`.
    pub fn parse(raw: i64) -> Result<Self, LoopRefusal> {
        u64::try_from(raw)
            .ok()
            .and_then(std::num::NonZeroU64::new)
            .map(Self)
            .ok_or(LoopRefusal::CeilingBelowOne(raw))
    }

    /// The ceiling as a step count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Why a `Task.loop` stopped without a `Done`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopRefusal {
    /// The declared ceiling is below 1; no step ran.
    CeilingBelowOne(i64),
    /// The step ran `ceiling` times and still returned `Continue`.
    Exhausted(LoopCeiling),
}

/// Opening text of the below-one refusal; the raw ceiling and `)` follow.
const LOOP_CEILING_BELOW_ONE: &str = "Task.loop needs a step ceiling of at least 1 (got ";
/// Opening text of the exhaustion refusal; the ceiling follows.
const LOOP_EXHAUSTED_PREFIX: &str = "Task.loop ran its step ";
/// Closing text of the exhaustion refusal.
const LOOP_EXHAUSTED_SUFFIX: &str = " times, its ceiling, without reaching Done";

impl From<LoopRefusal> for IpeError {
    /// The one place a loop refusal becomes an `Error`.
    ///
    /// Both refusals are `InvalidInput`: neither is retryable, since re-running
    /// the same loop reaches the same outcome. The message carries only the
    /// ceiling, never the loop state (which may hold a secret).
    fn from(refusal: LoopRefusal) -> Self {
        match refusal {
            LoopRefusal::CeilingBelowOne(raw) => {
                Self::invalid_input(format!("{LOOP_CEILING_BELOW_ONE}{raw})"))
            }
            LoopRefusal::Exhausted(ceiling) => Self::invalid_input(format!(
                "{LOOP_EXHAUSTED_PREFIX}{}{LOOP_EXHAUSTED_SUFFIX}",
                ceiling.get()
            )),
        }
    }
}

/// `Task.loop : Int -> s -> (s -> Task Error (Step s a)) -> Task Error a`.
///
/// Runs `step` from `init` until it returns `Done`, at most `ceiling` times.
/// The ceiling is parsed before the first step, so a ceiling below 1 runs no
/// step. Each step's future is awaited to completion and dropped before the
/// next one is built, so the poll stack holds this driver plus one step future
/// at every step: the depth never grows with the step count. A failing step
/// ends the loop with its error unchanged. `classify` maps the emitted `Step`
/// value onto [`LoopStep`].
pub fn task_loop<S, A, T>(
    ceiling: i64,
    init: S,
    step: impl Fn(S) -> IpeTask<IpeError, T> + Send + 'static,
    classify: impl Fn(T) -> LoopStep<S, A> + Send + 'static,
) -> IpeTask<IpeError, A>
where
    S: Send + 'static,
    A: Send + 'static,
    T: Send + 'static,
{
    Box::pin(async move {
        let ceiling = match LoopCeiling::parse(ceiling) {
            Ok(c) => c,
            Err(refusal) => return IpeResult::Err(refusal.into()),
        };
        let mut state = init;
        let mut ran: u64 = 0;
        loop {
            // `ran` never exceeds the ceiling (at most `i64::MAX`), so the add
            // cannot overflow; the checked form keeps the loop panic-free anyway.
            let Some(count) = ran.checked_add(1) else {
                return IpeResult::Err(LoopRefusal::Exhausted(ceiling).into());
            };
            ran = count;
            let outcome = match step(state).await {
                IpeResult::Ok(t) => classify(t),
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            match outcome {
                LoopStep::Done(a) => return ok_res(a),
                LoopStep::Continue(next) => {
                    if ran >= ceiling.get() {
                        return IpeResult::Err(LoopRefusal::Exhausted(ceiling).into());
                    }
                    state = next;
                }
            }
        }
    })
}

// `Task.run` drives an entry task to completion through `block_on`. Native-ish
// (host native AND co-located WASI); only the browser `wasm-client` sink runs
// its entry differently (`spawn_local`), so it is excluded there but present on
// `wasm32-wasip1`, where a `Direct` program's `main` calls it.
#[cfg(not(all(target_arch = "wasm32", feature = "wasm-client")))]
pub fn task_run<E: From<String> + crate::FromUnavailable + Send + 'static, A: Send + 'static>(
    task: IpeTask<E, A>,
) -> IpeResult<E, A> {
    block_on(task)
}

// Task.parallel : List (Task e a) -> Task e (List a)
//
// Runs every task concurrently, collecting the `Ok` values in INPUT order.
//
// EARLY-CANCEL (the load-bearing correctness property). On the first
// failure we return `Err` immediately AND abort every still-running sibling.
// Aborting is mandatory: a tokio `JoinHandle` that is merely DROPPED becomes
// DETACHED — the spawned task keeps running to completion in the background.
// For an effectful Ipê task that means its observable side effect (a second DB
// write, a duplicate charge, a duplicate email) would still fire AFTER the
// batch has already been reported as failed — a double-write / double-charge
// hazard. `abort()` on each survivor closes that hole. (Reference: ../ipe's
// Early-cancel shape for the Rust
// runtime.)
//
// DETERMINISM — Ok order AND error order.
//   * Ok results are pushed in INPUT order: we await the tasks front-to-back
//     (`VecDeque::pop_front`), so `out[i]` is task `i`'s result. This is the
//     documented contract and is unchanged from the previous implementation.
//   * The `Err` that WINS when several tasks fail is the FIRST failure in INPUT
//     order — never the wall-clock-first one. Because we observe results in
//     input order, a given list of inputs always yields the same error value,
//     run to run. This is the strictly more deterministic choice.
//
// TRADEOFF (documented, deliberate). Observing failures in input order means a
// fast failure at index `k` is not ACTED ON until indices `0..k` have resolved.
// Survivors are aborted the instant the winning (input-order-first) failure is
// observed, not the instant the wall-clock-first failure occurs — so the abort
// window can be slightly wider than a race-to-first-failure design. We trade a
// marginally later abort for a deterministic, reproducible error result. The
// correctness guarantee still holds unconditionally: once the batch is reported
// failed, NO task ordered after the failing one can fire its side effect (they
// are all aborted before this future resolves).
//
// TOTALITY: no unwrap/expect/panic/indexing. A `JoinError` from `h.await` is a
// panic inside the spawned task (we never `.await` a handle after issuing its
// abort, so the cancelled-handle case is unreachable on this path); its payload
// routes through the redacting foreign-panic funnel — detail server-side under
// a correlation id, a generic typed `Err` to Ipê. The cancelled arm stays
// total via the foreign-error funnel rather than an unreachable assumption.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
pub fn task_parallel<E: From<String> + Send + 'static, A: Send + 'static>(
    tasks: Vec<IpeTask<E, A>>,
) -> IpeTask<E, Vec<A>> {
    Box::pin(async move {
        // Spawn every task up front so they run concurrently. `VecDeque` lets us
        // pop the front (input order) to await while the un-awaited tail stays
        // addressable for `abort()` on failure.
        // Each spawned task stays inside the request scope this one runs in.
        let mut handles: std::collections::VecDeque<tokio::task::JoinHandle<IpeResult<E, A>>> =
            tasks.into_iter().map(spawn_in_current_scope).collect();
        let mut out = Vec::with_capacity(handles.len());
        while let Some(h) = handles.pop_front() {
            let result = match h.await {
                Ok(r) => r,
                Err(join_err) => match join_err.try_into_panic() {
                    Ok(payload) => {
                        IpeResult::Err(ipe_error_from_panic("parallel task panicked", payload))
                    }
                    Err(join_err) => IpeResult::Err(ipe_error_from_foreign(join_err)),
                },
            };
            match result {
                IpeResult::Ok(a) => out.push(a),
                IpeResult::Err(e) => {
                    // First failure (input order). Abort every survivor still in
                    // the queue (all ordered AFTER this task) so none of their
                    // side effects can fire once we have reported failure.
                    // Already-awaited tasks (`Ok`, popped) are complete — nothing
                    // to abort. `abort()` on a finished handle is a harmless no-op.
                    for survivor in &handles {
                        survivor.abort();
                    }
                    return IpeResult::Err(e);
                }
            }
        }
        ok_res(out)
    })
}

// Std-only `Task.parallel` for the `tokio`-less emitted crate. `Task.parallel`
// is reactor-classified (`KernelFn::requires_async_runtime` reports it async),
// so a program that CALLS it always links tokio and gets the concurrent
// spawn-based version above; this counterpart exists ONLY so the always-emitted
// prelude wrapper resolves in a pure crate that never calls it (dead code,
// stripped from the release binary).
//
// Semantics if ever reached: runs the tasks SEQUENTIALLY in input order,
// collecting `Ok` values and short-circuiting on the first `Err` (input order)
// — observably the SAME result value the concurrent version yields (that
// version deliberately observes results in input order and reports the
// input-order-first failure), only without concurrency. So a hypothetical
// misclassification degrades to sequential execution, never a hang or a wrong
// result. TOTALITY: no unwrap/expect/panic/indexing.
// The sequential std-only `Task.parallel`. Live on a `tokio`-less host build AND
// co-located WASI (`wasm32-wasip1`), which is single-threaded with no tokio
// spawn — so genuine concurrency is unavailable and the tasks run SEQUENTIALLY
// in input order, short-circuiting on the first `Err`. The result value is
// identical to the concurrent version (which also observes results in input
// order); the divergence is timing, not semantics — never a hang or a wrong
// answer. On WASI this is the LIVE `Task.parallel`, not dead code.
#[cfg(all(
    not(all(target_arch = "wasm32", feature = "wasm-client")),
    any(not(feature = "tokio"), target_arch = "wasm32")
))]
pub fn task_parallel<E: From<String> + Send + 'static, A: Send + 'static>(
    tasks: Vec<IpeTask<E, A>>,
) -> IpeTask<E, Vec<A>> {
    Box::pin(async move {
        let mut out = Vec::with_capacity(tasks.len());
        for t in tasks {
            match t.await {
                IpeResult::Ok(a) => out.push(a),
                IpeResult::Err(e) => return IpeResult::Err(e),
            }
        }
        ok_res(out)
    })
}

/// The four backoff strategies for `RetryPolicy`.
///
/// Replaces the old `kind: i64` + `jitter: bool` pair. Each constructor names
/// the combination unambiguously; invalid states (any `Int` value for `kind`,
/// any `Bool` value for `jitter`) are not representable.
///
/// - `Linear` — constant delay of `baseMs` on every retry.
/// - `LinearWithJitter` — constant delay with uniform [0.5×, 1.5×) jitter.
/// - `Exponential` — delay doubles each attempt: `baseMs × 2^(attempt-1)`.
/// - `ExponentialWithJitter` — exponential delay with the same jitter band.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackoffStrategy {
    Linear,
    LinearWithJitter,
    Exponential,
    ExponentialWithJitter,
}

crate::stringify::show_row!("BackoffStrategy", Value, [] BackoffStrategy, |b| match b {
    BackoffStrategy::Linear => "Linear".to_owned(),
    BackoffStrategy::LinearWithJitter => "LinearWithJitter".to_owned(),
    BackoffStrategy::Exponential => "Exponential".to_owned(),
    BackoffStrategy::ExponentialWithJitter => "ExponentialWithJitter".to_owned(),
});

// Task.retryWith : RetryPolicy e -> Task e a -> Task e a
//
// A real retry loop, faithful to  The two things
// Rust could not give the old run-once stub — re-running the one-shot
// `IpeTask` future, and reading the generated, runtime-unnameable `RetryPolicy`
// / `ShouldRetry` ADT fields — are both supplied by CODEGEN now:
//   * The policy is DESTRUCTURED at the call site into `max_attempts`,
//     `base_ms`, a `BackoffStrategy`, and a `should_retry` closure.
//   * The task argument is wrapped in a re-runnable `make_task : impl Fn() ->
//     IpeTask<E, A>` closure, so each attempt rebuilds a fresh future (the
//     side effects re-fire per attempt).
//
// Semantics (mirror  `Task_retryWith` loop):
//   attempt 1..=max_attempts:
//     run make_task().await
//       Ok(a)  → return Ok(a)
//       Err(e) → if attempt == max_attempts → return Err(e)   (last attempt)
//                else if !should_retry(&e)  → return Err(e)   (short-circuit)
//                else sleep(compute_delay(...)) and loop
// The final Err is the LAST attempt's error (so the caller still sees a real
// error). `max_attempts` is clamped to ≥ 1 (0 / 1 both mean "run once").
//
// TOTALITY: no unwrap / expect / panic / indexing. Jitter randomness comes from
// the runtime's existing total `lcg_next()` LCG (same source as Random.*),
// never `thread_rng` (which could panic on a poisoned global).
//
// `Task.retryWith` sleeps between attempts (`tokio::time::sleep`), so it is
// reactor-classified: a program that reaches it always links tokio. Gated off
// the `tokio`-less build (no prelude wrapper names it, so no std counterpart is
// needed).
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
pub fn task_retry_with<E, A>(
    max_attempts: i64,
    base_ms: i64,
    strategy: BackoffStrategy,
    should_retry: impl Fn(&E) -> bool + Send + 'static,
    make_task: impl Fn() -> IpeTask<E, A> + Send + 'static,
) -> IpeTask<E, A>
where
    E: Send + 'static,
    A: Send + 'static,
{
    Box::pin(async move {
        let attempts = if max_attempts < 1 { 1 } else { max_attempts };
        let base = if base_ms < 0 { 0 } else { base_ms };
        let mut attempt: i64 = 1;
        loop {
            match make_task().await {
                IpeResult::Ok(a) => return ok_res(a),
                IpeResult::Err(e) => {
                    if attempt >= attempts {
                        return IpeResult::Err(e);
                    }
                    if !should_retry(&e) {
                        return IpeResult::Err(e);
                    }
                    let delay = retry_compute_delay(strategy, base, attempt);
                    if delay > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(delay as u64)).await;
                    }
                    attempt += 1;
                }
            }
        }
    })
}

// Backoff cap (ms). Implements `retryDelayCapMs` — exponential growth and the
// post-jitter delay are both clamped here so a huge attempt count or base can't
// produce an unbounded sleep. Used only by the reactor-gated `task_retry_with`,
// so gated with it.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
const RETRY_DELAY_CAP_MS: i64 = 30_000;

// Port of  `computeDelay`. Wait before attempt n+1 (1-indexed: attempt 1
// runs, then sleep compute_delay(1), then attempt 2, ...).
//
// `Linear*`   → `base` every time.
// `Exponential*` → `base * 2^(attempt-1)` capped at 30 s.
// `*WithJitter` variants multiply by a uniform factor in [0.5, 1.5).
//
// Total: saturating arithmetic, no overflow panic, result clamped to
// [0, RETRY_DELAY_CAP_MS]. Called only by the reactor-gated `task_retry_with`.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
fn retry_compute_delay(strategy: BackoffStrategy, base_ms: i64, attempt: i64) -> i64 {
    let exponential = matches!(
        strategy,
        BackoffStrategy::Exponential | BackoffStrategy::ExponentialWithJitter
    );
    let jitter = matches!(
        strategy,
        BackoffStrategy::LinearWithJitter | BackoffStrategy::ExponentialWithJitter
    );

    let mut d = base_ms;
    if exponential {
        // base * 2^(attempt-1). Guard the shift (and the multiply) against
        // overflow on large attempt counts — saturate to the cap instead.
        if (1..=30).contains(&attempt) {
            let factor: i64 = 1i64 << (attempt - 1);
            d = base_ms.saturating_mul(factor);
        } else {
            d = RETRY_DELAY_CAP_MS;
        }
    }
    if d > RETRY_DELAY_CAP_MS {
        d = RETRY_DELAY_CAP_MS;
    }
    if jitter && d > 0 {
        // Uniform in [0.5*d, 1.5*d). lcg_next() is the runtime's total LCG;
        // map its top 53 bits to a float in [0, 1) like random_float does.
        super::random::lcg_init();
        let unit = (super::random::lcg_next() >> 11) as f64 * (1.0 / 9_007_199_254_740_992.0);
        let scaled = (d as f64) * (0.5 + unit);
        // round-to-nearest, then re-clamp.
        d = scaled.round() as i64;
        if d > RETRY_DELAY_CAP_MS {
            d = RETRY_DELAY_CAP_MS;
        }
    }
    if d < 0 {
        d = 0;
    }
    d
}

// Exercises the reactor-gated `task_retry_with` (a `tokio::time::sleep` loop),
// so it compiles only when the `tokio` feature is on.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
#[cfg(test)]
mod retry_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    // ── compute_delay: linear, exponential, cap, jitter-bounds ──

    #[test]
    fn delay_linear_is_constant() {
        assert_eq!(retry_compute_delay(BackoffStrategy::Linear, 100, 1), 100);
        assert_eq!(retry_compute_delay(BackoffStrategy::Linear, 100, 5), 100);
    }

    #[test]
    fn delay_exponential_doubles() {
        assert_eq!(
            retry_compute_delay(BackoffStrategy::Exponential, 100, 1),
            100
        );
        assert_eq!(
            retry_compute_delay(BackoffStrategy::Exponential, 100, 2),
            200
        );
        assert_eq!(
            retry_compute_delay(BackoffStrategy::Exponential, 100, 3),
            400
        );
        assert_eq!(
            retry_compute_delay(BackoffStrategy::Exponential, 100, 4),
            800
        );
    }

    #[test]
    fn delay_capped_at_30s() {
        // A large exponential must clamp to RETRY_DELAY_CAP_MS, never overflow.
        assert_eq!(
            retry_compute_delay(BackoffStrategy::Exponential, 1000, 20),
            RETRY_DELAY_CAP_MS
        );
        assert_eq!(
            retry_compute_delay(BackoffStrategy::Exponential, 1000, 99),
            RETRY_DELAY_CAP_MS
        );
        assert_eq!(
            retry_compute_delay(BackoffStrategy::Exponential, i64::MAX, 5),
            RETRY_DELAY_CAP_MS
        );
    }

    #[test]
    fn delay_zero_base_is_zero() {
        assert_eq!(retry_compute_delay(BackoffStrategy::Linear, 0, 3), 0);
        assert_eq!(retry_compute_delay(BackoffStrategy::Exponential, 0, 3), 0);
        // jitter on a zero delay stays zero (guarded by `d > 0`).
        assert_eq!(
            retry_compute_delay(BackoffStrategy::ExponentialWithJitter, 0, 3),
            0
        );
    }

    #[test]
    fn delay_jitter_stays_in_bounds() {
        // Jitter multiplies by a uniform factor in [0.5, 1.5); result must land
        // in [0.5*d, 1.5*d] and never exceed the cap. Probe many draws.
        let base = 1000;
        for _ in 0..1000 {
            let d = retry_compute_delay(BackoffStrategy::LinearWithJitter, base, 1);
            assert!(d >= 500, "jitter delay {} below 0.5*base", d);
            assert!(d <= 1500, "jitter delay {} above 1.5*base", d);
            assert!(d <= RETRY_DELAY_CAP_MS);
        }
    }

    // ── task_retry_with loop semantics ──

    // A re-runnable task factory backed by a shared counter: increments on every
    // attempt, fails until the counter reaches `threshold`, then succeeds.
    fn transient_factory(
        counter: Arc<AtomicI64>,
        threshold: i64,
    ) -> impl Fn() -> IpeTask<String, i64> + Send + Sync + 'static {
        move || {
            let counter = counter.clone();
            Box::pin(async move {
                let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                if n >= threshold {
                    ok_res::<String, i64>(n)
                } else {
                    IpeResult::Err(format!("boom-{}", n))
                }
            })
        }
    }

    #[test]
    fn retry_transient_succeeds() {
        // Fails attempts 1-2, succeeds on attempt 3; maxAttempts=5 → Ok(3).
        let counter = Arc::new(AtomicI64::new(0));
        let task = task_retry_with(
            5,
            0,
            BackoffStrategy::Linear,
            |_e: &String| true,
            transient_factory(counter.clone(), 3),
        );
        match block_on(task) {
            IpeResult::Ok(n) => assert_eq!(n, 3),
            IpeResult::Err(e) => panic!("expected Ok(3), got Err({})", e),
        }
        assert_eq!(counter.load(Ordering::SeqCst), 3, "task ran 3 times");
    }

    #[test]
    fn retry_always_fails_returns_last_err_after_max() {
        // threshold unreachable; maxAttempts=4 → Err after exactly 4 runs.
        let counter = Arc::new(AtomicI64::new(0));
        let task = task_retry_with(
            4,
            0,
            BackoffStrategy::Linear,
            |_e: &String| true,
            transient_factory(counter.clone(), 999),
        );
        match block_on(task) {
            IpeResult::Ok(n) => panic!("expected Err, got Ok({})", n),
            IpeResult::Err(e) => assert_eq!(e, "boom-4", "last attempt's err"),
        }
        assert_eq!(counter.load(Ordering::SeqCst), 4, "ran exactly maxAttempts");
    }

    #[test]
    fn retry_short_circuits_when_should_retry_false() {
        // should_retry → false: stop after the first Err (1 run), maxAttempts=5.
        let counter = Arc::new(AtomicI64::new(0));
        let task = task_retry_with(
            5,
            0,
            BackoffStrategy::Linear,
            |_e: &String| false,
            transient_factory(counter.clone(), 999),
        );
        match block_on(task) {
            IpeResult::Ok(n) => panic!("expected Err, got Ok({})", n),
            IpeResult::Err(e) => assert_eq!(e, "boom-1", "first attempt's err"),
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1, "short-circuited after 1");
    }

    #[test]
    fn retry_should_retry_predicate_consulted_on_err() {
        // Retry only while the err is "boom-1"; once it's "boom-2", stop.
        // threshold high so it never succeeds; predicate gates the loop.
        let counter = Arc::new(AtomicI64::new(0));
        let task = task_retry_with(
            10,
            0,
            BackoffStrategy::Linear,
            |e: &String| e == "boom-1",
            transient_factory(counter.clone(), 999),
        );
        match block_on(task) {
            IpeResult::Ok(n) => panic!("expected Err, got Ok({})", n),
            // attempt1 → boom-1 (retry), attempt2 → boom-2 (predicate false → stop).
            IpeResult::Err(e) => assert_eq!(e, "boom-2"),
        }
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn retry_max_attempts_clamped_to_one() {
        // maxAttempts=0 means "run once" (clamped to 1), no retry.
        let counter = Arc::new(AtomicI64::new(0));
        let task = task_retry_with(
            0,
            0,
            BackoffStrategy::Linear,
            |_e: &String| true,
            transient_factory(counter.clone(), 999),
        );
        match block_on(task) {
            IpeResult::Ok(n) => panic!("expected Err, got Ok({})", n),
            IpeResult::Err(e) => assert_eq!(e, "boom-1"),
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1, "clamped to a single run");
    }

    #[test]
    fn retry_succeeds_first_try_runs_once() {
        // Threshold 1: succeeds on the first attempt; no further runs.
        let counter = Arc::new(AtomicI64::new(0));
        let task = task_retry_with(
            5,
            0,
            BackoffStrategy::Linear,
            |_e: &String| true,
            transient_factory(counter.clone(), 1),
        );
        match block_on(task) {
            IpeResult::Ok(n) => assert_eq!(n, 1),
            IpeResult::Err(e) => panic!("expected Ok(1), got Err({})", e),
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1, "ran once on success");
    }

    // ── map2..5: combine, short-circuit on first Err, effects ordered ──

    #[test]
    fn map2_combines_two_oks() {
        let task = task_map2(
            |a: i64, b: i64| a + b,
            task_succeed::<String, i64>(2),
            task_succeed::<String, i64>(3),
        );
        match block_on(task) {
            IpeResult::Ok(n) => assert_eq!(n, 5),
            IpeResult::Err(e) => panic!("expected Ok(5), got Err({})", e),
        }
    }

    #[test]
    fn map2_short_circuits_first_err() {
        // The first Err (leftmost) is reported; the later task never contributes.
        let task = task_map2(
            |a: i64, b: i64| a + b,
            task_fail::<String, i64>("left".to_owned()),
            task_succeed::<String, i64>(3),
        );
        match block_on(task) {
            IpeResult::Ok(n) => panic!("expected Err, got Ok({})", n),
            IpeResult::Err(e) => assert_eq!(e, "left"),
        }
    }

    #[test]
    fn map2_later_err_wins_when_first_ok() {
        let task = task_map2(
            |a: i64, b: i64| a + b,
            task_succeed::<String, i64>(2),
            task_fail::<String, i64>("right".to_owned()),
        );
        match block_on(task) {
            IpeResult::Ok(n) => panic!("expected Err, got Ok({})", n),
            IpeResult::Err(e) => assert_eq!(e, "right"),
        }
    }

    #[test]
    fn map3_map4_map5_combine() {
        let t3 = task_map3(
            |a: i64, b: i64, c: i64| a + b + c,
            task_succeed::<String, i64>(1),
            task_succeed::<String, i64>(2),
            task_succeed::<String, i64>(3),
        );
        assert!(matches!(block_on(t3), IpeResult::Ok(6)));

        let t4 = task_map4(
            |a: i64, b: i64, c: i64, d: i64| a + b + c + d,
            task_succeed::<String, i64>(1),
            task_succeed::<String, i64>(2),
            task_succeed::<String, i64>(3),
            task_succeed::<String, i64>(4),
        );
        assert!(matches!(block_on(t4), IpeResult::Ok(10)));

        let t5 = task_map5(
            |a: i64, b: i64, c: i64, d: i64, e: i64| a + b + c + d + e,
            task_succeed::<String, i64>(1),
            task_succeed::<String, i64>(2),
            task_succeed::<String, i64>(3),
            task_succeed::<String, i64>(4),
            task_succeed::<String, i64>(5),
        );
        assert!(matches!(block_on(t5), IpeResult::Ok(15)));
    }
}

// Task.parallel early-cancel / abort regression.
//
// Proves the two guarantees of the reworked `task_parallel`:
//   1. On the FIRST `Err`, every still-running sibling is ABORTED — its
//      delayed, observable side effect must NOT fire after the batch failed.
//      (Under the old detach-on-drop behaviour the sibling would run to
//      completion and fire; this test fails against that behaviour, so it is
//      non-vacuous.)
//   2. An all-`Ok` run returns the results in INPUT order regardless of the
//      order in which the tasks actually complete.
//
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
#[cfg(test)]
mod block_on_refusal_tests {
    use super::*;

    #[test]
    fn a_refused_entry_thread_is_an_unavailable_error() {
        let _refusing = crate::threads::refusal_hook::refuse(BLOCK_ON_THREAD);
        let task: IpeTask<crate::IpeError, i64> = Box::pin(async { IpeResult::Ok(1) });
        match block_on(task) {
            IpeResult::Err(e) => {
                assert_eq!(crate::ipe_error_kind(e), crate::IpeErrorKind::Unavailable);
            }
            IpeResult::Ok(v) => panic!("a refused entry thread must not run the task, got Ok({v})"),
        }
    }
}

// Exercises the concurrent spawn-based `task_parallel` (`tokio::spawn` + abort),
// so it compiles only when the `tokio` feature is on.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
#[cfg(test)]
mod parallel_abort_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::time::{Duration, sleep};

    // A task that (would) record an observable side effect — bumping `counter`
    // — but only AFTER `delay_ms`. If it is aborted before the delay elapses the
    // side effect never happens, which is exactly what we assert.
    fn side_effect_task(
        counter: Arc<AtomicU64>,
        delay_ms: u64,
        value: i64,
    ) -> IpeTask<String, i64> {
        Box::pin(async move {
            sleep(Duration::from_millis(delay_ms)).await;
            counter.fetch_add(1, Ordering::SeqCst);
            IpeResult::Ok(value)
        })
    }

    #[tokio::test]
    async fn first_err_aborts_siblings_before_their_side_effect_fires() {
        let counter = Arc::new(AtomicU64::new(0));

        // Index 0 fails immediately; indices 1..=3 would each bump the counter
        // after 200 ms. Input-order await observes the index-0 failure first and
        // must abort the three survivors mid-sleep.
        let tasks: Vec<IpeTask<String, i64>> = vec![
            Box::pin(async { IpeResult::Err("boom".to_string()) }),
            side_effect_task(counter.clone(), 200, 1),
            side_effect_task(counter.clone(), 200, 2),
            side_effect_task(counter.clone(), 200, 3),
        ];

        let result = task_parallel(tasks).await;
        match result {
            IpeResult::Err(e) => assert_eq!(e, "boom"),
            IpeResult::Ok(v) => panic!("expected Err(boom), got Ok({:?})", v),
        }

        // Wait comfortably past the siblings' 200 ms delay. If they had merely
        // been DETACHED (the old behaviour) they would each fire here, driving
        // the counter to 3. Aborted, they stay at 0.
        sleep(Duration::from_millis(500)).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "aborted siblings must not fire their side effect after the batch failed"
        );
    }

    #[tokio::test]
    async fn all_ok_preserves_input_order() {
        let counter = Arc::new(AtomicU64::new(0));

        // Completion order is the REVERSE of input order: task 0 sleeps longest,
        // task 3 finishes first. The result Vec must still be [0, 1, 2, 3].
        let tasks: Vec<IpeTask<String, i64>> = vec![
            side_effect_task(counter.clone(), 120, 0),
            side_effect_task(counter.clone(), 90, 1),
            side_effect_task(counter.clone(), 60, 2),
            side_effect_task(counter.clone(), 30, 3),
        ];

        match task_parallel(tasks).await {
            IpeResult::Ok(v) => assert_eq!(v, vec![0, 1, 2, 3], "Ok results in input order"),
            IpeResult::Err(e) => panic!("expected Ok, got Err({})", e),
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            4,
            "every Ok task ran to completion"
        );
    }

    #[tokio::test]
    async fn panicked_parallel_task_folds_through_the_funnel() {
        // A panic inside one spawned parallel task is a `JoinError` whose
        // payload routes through the redacting funnel: the typed `Err` carries
        // the generic message + correlation id, never the raw payload.
        let tasks: Vec<IpeTask<String, i64>> = vec![
            side_effect_task(Arc::new(AtomicU64::new(0)), 1, 0),
            Box::pin(async { panic!("parallel poll panic") }),
        ];
        match task_parallel(tasks).await {
            IpeResult::Err(e) => assert!(
                e.starts_with("parallel task panicked (ref "),
                "parallel panic must fold to the funnel message: {e}"
            ),
            IpeResult::Ok(v) => panic!("expected a typed Err, got Ok({v:?})"),
        }
    }

    #[tokio::test]
    async fn error_order_is_input_order_not_wall_clock() {
        // Two tasks fail. Index 1 fails FAST (wall-clock first); index 3 fails
        // only after a delay. Input-order await must still surface the FIRST
        // failure in INPUT order — which is index 1 here (index 0 is Ok). The
        // point: the winning error is deterministic w.r.t. input order.
        let counter = Arc::new(AtomicU64::new(0));
        let tasks: Vec<IpeTask<String, i64>> = vec![
            side_effect_task(counter.clone(), 10, 0),
            Box::pin(async { IpeResult::Err("first-in-order".to_string()) }),
            side_effect_task(counter.clone(), 300, 2),
            Box::pin(async {
                sleep(Duration::from_millis(5)).await;
                IpeResult::Err("later-in-order".to_string())
            }),
        ];

        match task_parallel(tasks).await {
            IpeResult::Err(e) => assert_eq!(
                e, "first-in-order",
                "winning error is the first failure in INPUT order"
            ),
            IpeResult::Ok(v) => panic!("expected Err, got Ok({:?})", v),
        }

        // The index-2 survivor (300 ms) must have been aborted, not detached.
        sleep(Duration::from_millis(500)).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "only the index-0 Ok task fired; the index-2 survivor was aborted"
        );
    }
}

// Proves the std-only `block_on` (the `tokio`-less entry) drives a future to
// completion correctly: a ready future returns immediately, and a future that
// yields `Pending` once — then is woken from another thread — is re-polled and
// completes without busy-spinning (the park/unpark handshake). Runs only in the
// `tokio`-less config, which is the one that links that `block_on`.
#[cfg(all(not(feature = "tokio"), not(target_arch = "wasm32")))]
#[cfg(test)]
mod std_block_on_tests {
    use super::*;

    #[test]
    fn ready_future_completes_immediately() {
        let got = block_on::<IpeError, i64>(Box::pin(ready(ok_res(7))));
        assert!(matches!(got, IpeResult::Ok(7)));
    }

    #[test]
    fn pure_task_chain_completes() {
        // A `succeed |> map` chain — the exact pure-`Task` shape a synchronous
        // program emits — resolves under the std executor.
        let t = task_map(|n: i64| n + 1, task_succeed::<IpeError, i64>(41));
        assert!(matches!(block_on(t), IpeResult::Ok(42)));
    }

    #[test]
    fn pending_then_woken_completes_without_busy_spin() {
        use std::future::Future;
        use std::pin::Pin;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Context, Poll};

        // A future that returns `Pending` on the first poll (arming a background
        // thread to wake it after a short delay) and `Ready` on the second. The
        // poll counter proves the driver parks between the two polls rather than
        // spinning: exactly two polls occur for a single wake.
        struct WakeOnce {
            polls: Arc<AtomicUsize>,
            armed: bool,
        }
        impl Future for WakeOnce {
            type Output = IpeResult<IpeError, i64>;
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                self.polls.fetch_add(1, Ordering::SeqCst);
                if self.armed {
                    return Poll::Ready(ok_res(99));
                }
                self.armed = true;
                let waker = cx.waker().clone();
                std::thread::Builder::new()
                    .spawn(move || {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        waker.wake();
                    })
                    .expect("spawn test thread");
                Poll::Pending
            }
        }

        let polls = Arc::new(AtomicUsize::new(0));
        let fut = WakeOnce {
            polls: Arc::clone(&polls),
            armed: false,
        };
        let got = block_on::<IpeError, i64>(Box::pin(fut));
        assert!(matches!(got, IpeResult::Ok(99)));
        // Exactly two polls: the initial `Pending` and the post-wake `Ready`.
        // A busy-spin would show many more.
        assert_eq!(
            polls.load(Ordering::SeqCst),
            2,
            "driver must park, not spin"
        );
    }
}

// Stack-floor recording on runtime-owned threads. The tokio `on_thread_start`
// hook records each worker's floor; the `block_on` entry thread records its own.
// Gated to the tokio native path — the only build where `global_runtime` and the
// spawning `block_on` exist.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
#[cfg(test)]
mod stack_floor_tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    // A future that resolves to whether the thread it is polled on has a recorded
    // stack floor, letting a test observe the TLS state of a tokio worker.
    struct ReadFloor;
    impl Future for ReadFloor {
        type Output = IpeResult<String, bool>;
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(ok_res::<String, bool>(
                crate::core::stack_floor_for_test().is_some(),
            ))
        }
    }

    #[test]
    fn tokio_worker_records_stack_floor() {
        let task: IpeTask<String, bool> = Box::pin(ReadFloor);
        match block_on(task) {
            IpeResult::Ok(has_floor) => assert!(
                has_floor,
                "every tokio worker must record its stack floor via on_thread_start"
            ),
            IpeResult::Err(e) => panic!("block_on failed: {e}"),
        }
    }

    // A future that records the floor of whatever thread FIRST polls it (a tokio
    // worker), then reads it back — proving `record_stack_floor` from within the
    // async spine both writes and reads the same thread's TLS. The entry thread's
    // own recording (before `rt.block_on`) is exercised by every `block_on` call.
    struct RecordThenRead;
    impl Future for RecordThenRead {
        type Output = IpeResult<String, bool>;
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            crate::core::record_stack_floor(crate::core::RUNTIME_THREAD_STACK_SIZE);
            Poll::Ready(ok_res::<String, bool>(
                crate::core::stack_floor_for_test().is_some(),
            ))
        }
    }

    #[test]
    fn record_stack_floor_writes_and_reads_same_thread_tls() {
        let task: IpeTask<String, bool> = Box::pin(RecordThenRead);
        assert!(matches!(block_on(task), IpeResult::Ok(true)));
    }
}

// `Task.loop` driver: the ceiling is the exact step bound, refusals are typed
// and fixed-text, a failing step's error passes through unchanged, and the poll
// stack stays flat however many steps run. `block_on` is the entry on both the
// tokio and the std-only builds, so these run in either feature set.
#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod loop_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    type Outcome = IpeResult<IpeError, u64>;
    /// The lowest and highest stack pointer a probe has seen.
    type Probes = Arc<Mutex<(usize, usize)>>;

    const fn identity(step: LoopStep<u64, u64>) -> LoopStep<u64, u64> {
        step
    }

    /// Run a loop from 0 whose step counts its own invocations and returns
    /// `Done` with the step number on step `done_at`.
    ///
    /// Returns the loop's result and the number of step invocations.
    fn run_counting(ceiling: i64, done_at: u64) -> (Outcome, u64) {
        let calls = Arc::new(AtomicU64::new(0));
        let seen = Arc::clone(&calls);
        let task = task_loop(
            ceiling,
            0_u64,
            move |n: u64| {
                seen.fetch_add(1, Ordering::SeqCst);
                let next = n.saturating_add(1);
                let step = if next >= done_at {
                    LoopStep::Done(next)
                } else {
                    LoopStep::Continue(next)
                };
                task_succeed::<IpeError, LoopStep<u64, u64>>(step)
            },
            identity,
        );
        let result = block_on(task);
        (result, calls.load(Ordering::SeqCst))
    }

    /// The kind and message of a refused loop, or `None` when it succeeded.
    fn refusal(result: Outcome) -> Option<(IpeErrorKind, String)> {
        match result {
            IpeResult::Err(IpeError::Error(kind, info)) => Some((kind, info.message)),
            IpeResult::Ok(_) => None,
        }
    }

    #[test]
    fn ceiling_exact_steps_succeeds() {
        let (result, calls) = run_counting(7, 7);
        assert!(matches!(result, IpeResult::Ok(7)), "got {result:?}");
        assert_eq!(calls, 7);
    }

    #[test]
    fn ceiling_one_short_is_typed_limit() {
        let (result, calls) = run_counting(6, 7);
        assert_eq!(
            refusal(result),
            Some((
                IpeErrorKind::InvalidInput,
                "Task.loop ran its step 6 times, its ceiling, without reaching Done".to_owned()
            ))
        );
        assert_eq!(calls, 6, "the seventh step must never run");
    }

    #[test]
    fn ceiling_zero_refused_before_first_step() {
        let (result, calls) = run_counting(0, 1);
        assert_eq!(
            refusal(result),
            Some((
                IpeErrorKind::InvalidInput,
                "Task.loop needs a step ceiling of at least 1 (got 0)".to_owned()
            ))
        );
        assert_eq!(calls, 0, "no step may run under a refused ceiling");
    }

    #[test]
    fn ceiling_negative_and_min_refused() {
        for raw in [-1, i64::MIN] {
            let (result, calls) = run_counting(raw, 1);
            assert_eq!(
                refusal(result),
                Some((
                    IpeErrorKind::InvalidInput,
                    format!("Task.loop needs a step ceiling of at least 1 (got {raw})")
                )),
                "ceiling {raw}"
            );
            assert_eq!(calls, 0, "ceiling {raw}: no step may run");
        }
    }

    #[test]
    fn ceiling_i64_max_no_overflow() {
        let (result, calls) = run_counting(i64::MAX, 3);
        assert!(matches!(result, IpeResult::Ok(3)), "got {result:?}");
        assert_eq!(calls, 3);
    }

    #[test]
    fn erroring_step_stops_loop_verbatim() {
        let failure = IpeError::conflict("x".to_owned())
            .with_details(IpeErrorDetails::Custom("detail".to_owned()));
        let expected = failure.clone();
        let calls = Arc::new(AtomicU64::new(0));
        let seen = Arc::clone(&calls);
        let task = task_loop(
            10,
            0_u64,
            move |n: u64| {
                seen.fetch_add(1, Ordering::SeqCst);
                let next = n.saturating_add(1);
                if next == 4 {
                    task_fail::<IpeError, LoopStep<u64, u64>>(failure.clone())
                } else {
                    task_succeed::<IpeError, LoopStep<u64, u64>>(LoopStep::Continue(next))
                }
            },
            identity,
        );
        let result = block_on(task);
        assert_eq!(result, IpeResult::Err(expected));
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn done_first_step_short_circuits() {
        let (result, calls) = run_counting(1, 1);
        assert!(matches!(result, IpeResult::Ok(1)), "got {result:?}");
        assert_eq!(calls, 1);
    }

    #[test]
    fn ceiling_parse_keeps_the_raw_refused_value() {
        assert_eq!(LoopCeiling::parse(0), Err(LoopRefusal::CeilingBelowOne(0)));
        assert_eq!(
            LoopCeiling::parse(i64::MIN),
            Err(LoopRefusal::CeilingBelowOne(i64::MIN))
        );
        assert_eq!(LoopCeiling::parse(1).map(LoopCeiling::get), Ok(1));
    }

    fn new_probes() -> Probes {
        Arc::new(Mutex::new((usize::MAX, 0)))
    }

    /// Record the calling frame's stack pointer into `probes`.
    fn record(probes: &Probes) {
        let sp = crate::core::stack_pointer_for_test();
        if let Ok(mut seen) = probes.lock() {
            seen.0 = seen.0.min(sp);
            seen.1 = seen.1.max(sp);
        }
    }

    /// The distance between the lowest and highest pointer `probes` recorded.
    fn spread(probes: &Probes) -> usize {
        probes
            .lock()
            .map_or(0, |seen| seen.1.saturating_sub(seen.0))
    }

    /// A self-recursive `task_and_then` walk `depth` levels deep that records
    /// the stack pointer at every level: the nesting `Task.loop` replaces.
    fn nested_walk(depth: usize, probes: Probes) -> IpeTask<IpeError, ()> {
        task_and_then(task_succeed::<IpeError, ()>(()), move |()| {
            record(&probes);
            if depth == 0 {
                task_succeed::<IpeError, ()>(())
            } else {
                nested_walk(depth.saturating_sub(1), probes)
            }
        })
    }

    #[test]
    fn constant_stack_depth_far_past_guard() {
        // Far past both the guard's depth budget (10,000) and the red-zone trip
        // a nested walk hits near 5,000 steps on an 8 MiB stack.
        const STEPS: u64 = 200_000;
        // Every nested level adds at least one non-inlinable poll frame (a
        // return address plus alignment: 16 bytes or more), so the control's
        // spread exceeds this whenever the probe measures real nesting.
        const CONTROL_DEPTH: usize = 4_000;
        const CONTROL_MIN_SPREAD: usize = CONTROL_DEPTH * 16;
        const LOOP_MAX_SPREAD: usize = 4 * 1024;

        // The std-only `block_on` polls on the calling thread; give that thread
        // a stack that holds the nested control comfortably.
        let worker = std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let probes = new_probes();
                let seen = Arc::clone(&probes);
                let task = task_loop(
                    i64::try_from(STEPS).unwrap_or(i64::MAX),
                    0_u64,
                    move |n: u64| {
                        record(&seen);
                        let next = n.saturating_add(1);
                        let step = if next >= STEPS {
                            LoopStep::Done(next)
                        } else {
                            LoopStep::Continue(next)
                        };
                        task_succeed::<IpeError, LoopStep<u64, u64>>(step)
                    },
                    identity,
                );
                let looped = block_on(task);
                let control = new_probes();
                let nested = block_on(nested_walk(CONTROL_DEPTH, Arc::clone(&control)));
                (looped, spread(&probes), nested, spread(&control))
            });
        let joined = worker.map(std::thread::JoinHandle::join);
        assert!(
            matches!(joined, Ok(Ok(_))),
            "the measuring thread must run to completion"
        );
        let Ok(Ok((looped, loop_spread, nested, control_spread))) = joined else {
            return;
        };
        assert!(
            matches!(looped, IpeResult::Ok(STEPS)),
            "the loop must finish: {looped:?}"
        );
        assert!(
            matches!(nested, IpeResult::Ok(())),
            "the control walk must finish: {nested:?}"
        );
        assert!(
            control_spread > CONTROL_MIN_SPREAD,
            "the probe must see a nested walk grow the stack \
             (spread {control_spread} bytes over {CONTROL_DEPTH} levels)"
        );
        assert!(
            loop_spread <= LOOP_MAX_SPREAD,
            "Task.loop must hold the stack flat across {STEPS} steps \
             (spread {loop_spread} bytes)"
        );
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod spawn_scope_scan_tests {
    /// A spelling that starts a task on a runtime or a thread pool.
    const RAW_SPAWNS: [&str; 7] = [
        "tokio::spawn",
        "task::spawn",
        "spawn_local",
        "spawn_blocking",
        "JoinSet",
        "Handle::spawn",
        ".spawn(",
    ];

    /// The production source of this module: everything before its first
    /// test module, refused if any non-test item follows that module.
    fn production_source() -> &'static str {
        let source = include_str!("task.rs");
        let Some((production, tests)) = source.split_once("#[cfg(test)]") else {
            panic!("task.rs carries its test modules");
        };
        for line in tests.lines() {
            let top_level = !line.is_empty() && !line.starts_with(char::is_whitespace);
            assert!(
                !top_level
                    || ["#[", "mod ", "}", "//"]
                        .iter()
                        .any(|item| line.starts_with(item)),
                "production code follows a test module in task.rs, so the spawn scan \
                 cannot see it; move it above the first test module: {line}"
            );
        }
        production
    }

    #[test]
    fn task_spawns_only_through_the_scope_carrier() {
        let mut carriers = 0;
        for line in production_source().lines() {
            let code = line.trim();
            if code.starts_with("//") {
                continue;
            }
            if code == "tokio::spawn(on_behalf_of_caller(task))" {
                carriers += 1;
                continue;
            }
            assert!(
                !RAW_SPAWNS.iter().any(|raw| code.contains(raw)),
                "a spawn in task.rs drops the caller's request scope; route it \
                 through `spawn_in_current_scope`: {code}"
            );
            assert!(
                !(code.starts_with("use ") && code.contains("tokio") && code.contains("spawn")),
                "a spawn imported into task.rs escapes the scan: {code}"
            );
        }
        assert_eq!(
            carriers, 1,
            "`spawn_in_current_scope` is the one runtime spawn"
        );
    }

    #[test]
    fn block_on_thread_carries_the_scope() {
        let production = production_source();
        let carried = production.find("let future = on_behalf_of_caller(future);");
        let spawned = production.find("crate::threads::spawn_sized(");
        assert!(
            matches!((carried, spawned), (Some(c), Some(s)) if c < s),
            "`block_on` carries the caller's scope before its entry thread starts"
        );
        assert_eq!(
            production.matches("spawn_sized(").count(),
            1,
            "`block_on` is the one thread spawn of task.rs"
        );
    }
}

//! Ipê TEA runtime core — Cmd/Sub + the Ipe.Console line-oriented loop.
//!
//! Cmd/Sub are generic over the message type M (NOT `any`): the intermediate
//! value `a` in `Cmd.perform` is erased inside a boxed M-producing future, but M
//! stays concrete. This file ships the types, the kernels, the keyed
//! subscription reconcile every TEA loop re-evaluates `Sub.every` tickers and
//! subscription sources through, the `SubManager` that also holds the active
//! terminal input handlers (`Tui.Sub.onKey` / `Cli.Sub.onLine`), and the Cli.tea
//! loop (stdin line -> active `onLine` handlers -> update -> view).

use super::*;
use std::future::Future;
use std::pin::Pin;

/// Ipê `Cmd msg`. Perform carries a boxed thunk producing the message (the
/// task's success/error type is erased inside; M is concrete).
pub enum IpeCmd<M> {
    None,
    Batch(Vec<IpeCmd<M>>),
    Perform(PerformThunk<M>),
    /// pub/sub broadcast. The thunk receives the publishing session's sid (the
    /// origin), injected by the Web dispatch loop, and returns the subscriber
    /// count. Not generic over the payload type T — T is captured inside the
    /// thunk (the same erasure-free pattern as `Perform`'s boxed future).
    Publish(Box<dyn FnOnce(&str) -> i64 + Send>),
}

/// The boxed message-producing thunk inside [`IpeCmd::Perform`]. Same
/// cfg-split rationale as `IpeTask` (`core.rs`): wasm futures touch the DOM
/// and are `!Send`; the native bound backs `tokio::spawn`.
#[cfg(not(target_arch = "wasm32"))]
pub type PerformThunk<M> = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = M> + Send>> + Send>;
#[cfg(target_arch = "wasm32")]
pub type PerformThunk<M> = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = M>>>>;

/// A custom subscription event source: given an `emit` callback, spawn a task
/// that pushes messages into the loop, returning its JoinHandle (aborted on
/// re-subscribe). Keeps IpeSub decoupled from source-specific runtimes (e.g. the
/// WebSocket client builds one of these for `onMessage`).
#[cfg(not(target_arch = "wasm32"))]
pub type SubSpawn<M> =
    Box<dyn FnOnce(std::sync::Arc<dyn Fn(M) + Send + Sync>) -> tokio::task::JoinHandle<()> + Send>;
/// wasm: single-threaded, no tokio — a source registers its emit callback and
/// returns a teardown closure the scheduler runs on re-subscribe/unmount (the
/// wasm analogue of aborting the native `JoinHandle`). The M4 pub/sub broker
/// (`wasm::pubsub::sub_subscribe_topic`) is the first constructor of this
/// type on wasm; every source MUST return a real unregister thunk (never a
/// no-op) so the scheduler's teardown-then-respawn of sources on every
/// re-evaluation (mirroring native's `SubRuntime`) cannot accumulate duplicate
/// listeners.
#[cfg(target_arch = "wasm32")]
pub type SubSpawn<M> = Box<dyn FnOnce(std::rc::Rc<dyn Fn(M)>) -> Box<dyn FnOnce()>>;

/// A `Tui.Sub.onKey` handler over a key's flat `(kind, value)` pair.
///
/// The emitter builds the `KeyEvent` record inside it. `Send` so the terminal
/// loop's future stays `Send`; called only on the loop's own task, so no `Sync`
/// is needed.
#[cfg(not(target_arch = "wasm32"))]
pub type KeyHandler<M> = Box<dyn Fn(String, String) -> M + Send>;
/// A `Cli.Sub.onLine` handler over one stdin line.
#[cfg(not(target_arch = "wasm32"))]
pub type LineHandler<M> = Box<dyn Fn(String) -> M + Send>;

/// Ipê `Sub msg`.
pub enum IpeSub<M> {
    None,
    Batch(Vec<IpeSub<M>>),
    Every {
        ms: i64,
        msg: M,
    },
    Source(SubSpawn<M>),
    /// `Tui.Sub.onKey`, read by the Tui loop.
    ///
    /// The loop hands each key to every active key handler. Native-only: a
    /// terminal never runs in a browser.
    #[cfg(not(target_arch = "wasm32"))]
    OnKey(KeyHandler<M>),
    /// `Cli.Sub.onLine`, read by the Cli loop.
    ///
    /// The loop hands each stdin line to every active line handler.
    #[cfg(not(target_arch = "wasm32"))]
    OnLine(LineHandler<M>),
}

// ─── Cmd kernels ──────────────────────────────────────────────────────────

pub fn cmd_none<M>() -> IpeCmd<M> {
    IpeCmd::None
}
pub fn cmd_batch<M>(list: Vec<IpeCmd<M>>) -> IpeCmd<M> {
    IpeCmd::Batch(list)
}

/// Cmd.perform : Task err a -> (Result err a -> msg) -> Cmd msg.
/// Composes the task and the toMsg decoder (which receives the IpeResult) into a
/// single message-producing thunk fired by the run loop.
#[cfg(not(target_arch = "wasm32"))]
pub fn cmd_perform<E, A, M, F>(task: IpeTask<E, A>, to_msg: F) -> IpeCmd<M>
where
    E: Send + 'static,
    A: Send + 'static,
    M: Send + 'static,
    F: FnOnce(IpeResult<E, A>) -> M + Send + 'static,
{
    IpeCmd::Perform(Box::new(move || {
        Box::pin(async move { to_msg(task.await) })
    }))
}

/// wasm: same composition, minus the `Send` bounds (single-threaded browser
/// event loop; the thunk is driven by `spawn_local`).
#[cfg(target_arch = "wasm32")]
pub fn cmd_perform<E, A, M, F>(task: IpeTask<E, A>, to_msg: F) -> IpeCmd<M>
where
    E: 'static,
    A: 'static,
    M: 'static,
    F: FnOnce(IpeResult<E, A>) -> M + 'static,
{
    IpeCmd::Perform(Box::new(move || {
        Box::pin(async move { to_msg(task.await) })
    }))
}

/// Cmd.map : (a -> msg) -> Cmd a -> Cmd msg — retag every message a command
/// would produce. Rebuilds the command tree, composing `f` over each leaf's
/// payload: `Perform`'s produced value is fed through `f`; `Batch` maps its
/// children; `None` passes through. `Publish` carries no `M`-typed payload (its
/// thunk yields the subscriber count `i64`; `M` is phantom there), so it is
/// re-tagged by identity — the one leaf where `f` is not applied.
///
/// `f` is shared (`Arc`) because a `Batch` fans it across children and a
/// `Perform` thunk captures it to run later; the composition stays lazy — no
/// message is produced until the run loop fires the thunk.
#[cfg(not(target_arch = "wasm32"))]
pub fn cmd_map<A, M, F>(cmd: IpeCmd<A>, f: F) -> IpeCmd<M>
where
    A: Send + 'static,
    M: Send + 'static,
    F: Fn(A) -> M + Send + Sync + 'static,
{
    cmd_map_arc(cmd, std::sync::Arc::new(f))
}

#[cfg(not(target_arch = "wasm32"))]
fn cmd_map_arc<A, M>(cmd: IpeCmd<A>, f: std::sync::Arc<dyn Fn(A) -> M + Send + Sync>) -> IpeCmd<M>
where
    A: Send + 'static,
    M: Send + 'static,
{
    match cmd {
        IpeCmd::None => IpeCmd::None,
        IpeCmd::Batch(items) => IpeCmd::Batch(
            items
                .into_iter()
                .map(|c| cmd_map_arc(c, f.clone()))
                .collect(),
        ),
        IpeCmd::Perform(thunk) => IpeCmd::Perform(Box::new(move || {
            Box::pin(async move {
                let a = thunk().await;
                f(a)
            })
        })),
        IpeCmd::Publish(thunk) => IpeCmd::Publish(thunk),
    }
}

/// wasm: same tree rebuild, `Rc`-shared `f`, no `Send`/`Sync` bounds
/// (single-threaded browser event loop). `Publish` re-tags by identity, as on
/// native.
#[cfg(target_arch = "wasm32")]
pub fn cmd_map<A, M, F>(cmd: IpeCmd<A>, f: F) -> IpeCmd<M>
where
    A: 'static,
    M: 'static,
    F: Fn(A) -> M + 'static,
{
    cmd_map_rc(cmd, std::rc::Rc::new(f))
}

#[cfg(target_arch = "wasm32")]
fn cmd_map_rc<A, M>(cmd: IpeCmd<A>, f: std::rc::Rc<dyn Fn(A) -> M>) -> IpeCmd<M>
where
    A: 'static,
    M: 'static,
{
    match cmd {
        IpeCmd::None => IpeCmd::None,
        IpeCmd::Batch(items) => IpeCmd::Batch(
            items
                .into_iter()
                .map(|c| cmd_map_rc(c, f.clone()))
                .collect(),
        ),
        IpeCmd::Perform(thunk) => IpeCmd::Perform(Box::new(move || {
            Box::pin(async move {
                let a = thunk().await;
                f(a)
            })
        })),
        IpeCmd::Publish(thunk) => IpeCmd::Publish(thunk),
    }
}

// ─── Sub kernels ──────────────────────────────────────────────────────────

pub fn sub_none<M>() -> IpeSub<M> {
    IpeSub::None
}
pub fn sub_batch<M>(list: Vec<IpeSub<M>>) -> IpeSub<M> {
    IpeSub::Batch(list)
}

/// Sub.every : Int -> msg -> Sub msg — dispatch `msg` every `ms` milliseconds.
pub fn sub_every<M>(ms: i64, msg: M) -> IpeSub<M> {
    IpeSub::Every { ms, msg }
}

/// `Tui.Sub.onKey : (KeyEvent -> msg) -> Sub msg` — subscribe to terminal keys.
///
/// `on_key` receives the key's `(kind, value)`; the emitter wraps the user's
/// `KeyEvent -> msg` handler so the record is built there.
#[cfg(not(target_arch = "wasm32"))]
pub fn tui_sub_on_key<M, F>(on_key: F) -> IpeSub<M>
where
    F: Fn(String, String) -> M + Send + 'static,
{
    IpeSub::OnKey(Box::new(on_key))
}

/// `Cli.Sub.onLine : (String -> msg) -> Sub msg` — subscribe to stdin lines.
#[cfg(not(target_arch = "wasm32"))]
pub fn cli_sub_on_line<M, F>(on_line: F) -> IpeSub<M>
where
    F: Fn(String) -> M + Send + 'static,
{
    IpeSub::OnLine(Box::new(on_line))
}

/// Time.every : Int -> msg -> Sub msg — alias of `Sub.every` (matches
/// `Time_every`, which delegates to `Sub_every`). The `Time_every` kernel name
/// lowers to this.
pub fn time_every<M>(ms: i64, msg: M) -> IpeSub<M> {
    sub_every(ms, msg)
}

/// Sub.map : (a -> msg) -> Sub a -> Sub msg — retag every message a
/// subscription would deliver. Rebuilds the subscription tree: `Every`'s stored
/// `msg` is retagged eagerly (`f msg`); `Batch` maps its children; `None`
/// passes through; a `Source` is rewrapped so the emit callback it receives
/// first pushes each `a` through `f` before handing the resulting `msg` to the
/// scheduler's real emit — the source stays oblivious to the retagging and its
/// teardown handle is preserved unchanged. A terminal input handler is composed
/// with `f`, so each key / line it maps yields the retagged message.
#[cfg(not(target_arch = "wasm32"))]
pub fn sub_map<A, M, F>(sub: IpeSub<A>, f: F) -> IpeSub<M>
where
    A: Send + 'static,
    M: Send + 'static,
    F: Fn(A) -> M + Send + Sync + 'static,
{
    sub_map_arc(sub, std::sync::Arc::new(f))
}

#[cfg(not(target_arch = "wasm32"))]
fn sub_map_arc<A, M>(sub: IpeSub<A>, f: std::sync::Arc<dyn Fn(A) -> M + Send + Sync>) -> IpeSub<M>
where
    A: Send + 'static,
    M: Send + 'static,
{
    match sub {
        IpeSub::None => IpeSub::None,
        IpeSub::Batch(items) => IpeSub::Batch(
            items
                .into_iter()
                .map(|s| sub_map_arc(s, f.clone()))
                .collect(),
        ),
        IpeSub::Every { ms, msg } => IpeSub::Every { ms, msg: f(msg) },
        IpeSub::Source(spawn) => IpeSub::Source(Box::new(
            move |emit_outer: std::sync::Arc<dyn Fn(M) + Send + Sync>| {
                let emit_inner: std::sync::Arc<dyn Fn(A) + Send + Sync> =
                    std::sync::Arc::new(move |a| emit_outer(f(a)));
                spawn(emit_inner)
            },
        )),
        IpeSub::OnKey(on_key) => IpeSub::OnKey(Box::new(move |kind: String, value: String| {
            f(on_key(kind, value))
        })),
        IpeSub::OnLine(on_line) => IpeSub::OnLine(Box::new(move |line: String| f(on_line(line)))),
    }
}

/// wasm: same tree rebuild, `Rc`-shared `f`, no `Send`/`Sync` bounds. The
/// `Source` rewrap preserves the source's teardown thunk unchanged.
#[cfg(target_arch = "wasm32")]
pub fn sub_map<A, M, F>(sub: IpeSub<A>, f: F) -> IpeSub<M>
where
    A: 'static,
    M: 'static,
    F: Fn(A) -> M + 'static,
{
    sub_map_rc(sub, std::rc::Rc::new(f))
}

#[cfg(target_arch = "wasm32")]
fn sub_map_rc<A, M>(sub: IpeSub<A>, f: std::rc::Rc<dyn Fn(A) -> M>) -> IpeSub<M>
where
    A: 'static,
    M: 'static,
{
    match sub {
        IpeSub::None => IpeSub::None,
        IpeSub::Batch(items) => IpeSub::Batch(
            items
                .into_iter()
                .map(|s| sub_map_rc(s, f.clone()))
                .collect(),
        ),
        IpeSub::Every { ms, msg } => IpeSub::Every { ms, msg: f(msg) },
        IpeSub::Source(spawn) => {
            IpeSub::Source(Box::new(move |emit_outer: std::rc::Rc<dyn Fn(M)>| {
                let emit_inner: std::rc::Rc<dyn Fn(A)> =
                    std::rc::Rc::new(move |a| emit_outer(f(a)));
                spawn(emit_inner)
            }))
        }
    }
}

// `Ipe.Http.Stream.chunks` → `Sub_subscribeStream` lives in `http_stream.rs`
// now (alongside the stream registry it drains + the bridged `ChunkEvent` enum).
// It returns a `IpeSub::Source` driven by this module's `SubRuntime`.

// ─── Subscription reconciliation (shared by every TEA loop) ─────────────────

/// A `Sub.every` period in milliseconds, always positive.
///
/// The key a running timer persists under while its interval stays requested.
#[cfg(any(
    all(feature = "tokio", not(target_arch = "wasm32")),
    all(target_arch = "wasm32", feature = "wasm-client")
))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EveryInterval(std::num::NonZeroU64);

#[cfg(any(
    all(feature = "tokio", not(target_arch = "wasm32")),
    all(target_arch = "wasm32", feature = "wasm-client")
))]
impl EveryInterval {
    /// The period of `Sub.every ms`, or `None` for a non-positive `ms` that never fires.
    pub(crate) fn from_millis(ms: i64) -> Option<Self> {
        u64::try_from(ms)
            .ok()
            .and_then(std::num::NonZeroU64::new)
            .map(Self)
    }

    /// The period in milliseconds.
    pub(crate) const fn millis(self) -> u64 {
        self.0.get()
    }

    /// The period as a browser timer delay, saturated at the largest one browsers honour.
    ///
    /// `setInterval` treats a delay past `i32::MAX` milliseconds as 1 ms, so an
    /// unsaturated long period would fire continuously.
    #[cfg(any(test, target_arch = "wasm32"))]
    pub(crate) fn browser_delay_ms(self) -> u32 {
        const MAX_BROWSER_DELAY_MS: u32 = 2_147_483_647;
        u32::try_from(self.millis()).map_or(MAX_BROWSER_DELAY_MS, |ms| ms.min(MAX_BROWSER_DELAY_MS))
    }
}

/// The `Sub.every` messages requested per interval, in subscription order.
#[cfg(any(
    all(feature = "tokio", not(target_arch = "wasm32")),
    all(target_arch = "wasm32", feature = "wasm-client")
))]
pub(crate) type EveryPlan<M> = std::collections::BTreeMap<EveryInterval, Vec<M>>;

/// One evaluation of `subscriptions(model)`, flattened.
///
/// `Sub.every` messages are grouped by interval, so one timer per interval
/// delivers every message requested at that period.
#[cfg(any(
    all(feature = "tokio", not(target_arch = "wasm32")),
    all(target_arch = "wasm32", feature = "wasm-client")
))]
pub(crate) struct SubPlan<M> {
    pub(crate) every: EveryPlan<M>,
    pub(crate) sources: Vec<SubSpawn<M>>,
    #[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
    pub(crate) key_handlers: Vec<KeyHandler<M>>,
    #[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
    pub(crate) line_handlers: Vec<LineHandler<M>>,
}

#[cfg(any(
    all(feature = "tokio", not(target_arch = "wasm32")),
    all(target_arch = "wasm32", feature = "wasm-client")
))]
impl<M> SubPlan<M> {
    /// Flatten a `Sub` tree into the subscriptions it requests.
    pub(crate) fn of(sub: IpeSub<M>) -> Self {
        let mut plan = Self {
            every: EveryPlan::new(),
            sources: Vec::new(),
            #[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
            key_handlers: Vec::new(),
            #[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
            line_handlers: Vec::new(),
        };
        plan.add(sub);
        plan
    }

    fn add(&mut self, sub: IpeSub<M>) {
        match sub {
            IpeSub::None => {}
            IpeSub::Batch(items) => {
                for item in items {
                    self.add(item);
                }
            }
            IpeSub::Every { ms, msg } => {
                // A non-positive interval never fires (no busy loop).
                if let Some(interval) = EveryInterval::from_millis(ms) {
                    self.every.entry(interval).or_default().push(msg);
                }
            }
            IpeSub::Source(spawn) => self.sources.push(spawn),
            #[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
            IpeSub::OnKey(on_key) => self.key_handlers.push(on_key),
            #[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
            IpeSub::OnLine(on_line) => self.line_handlers.push(on_line),
            // Terminal input exists only in a terminal app, so a loop built
            // without one has no input to hand these handlers.
            #[cfg(all(not(target_arch = "wasm32"), not(feature = "tui")))]
            IpeSub::OnKey(_) | IpeSub::OnLine(_) => {}
        }
    }
}

/// A running `Sub.every` timer whose delivered messages can be swapped in place.
#[cfg(any(
    all(feature = "tokio", not(target_arch = "wasm32")),
    all(target_arch = "wasm32", feature = "wasm-client")
))]
pub(crate) trait EveryTimer<M> {
    /// Replace the messages each later tick delivers, keeping the timer's phase.
    fn retarget(&self, msgs: Vec<M>);
}

/// The running `Sub.every` timers, one per requested interval.
///
/// Dropping a timer stops it. [`EveryTimers::reconcile`] is the one rule every
/// TEA loop re-evaluates subscriptions through: a still-requested interval keeps
/// its timer and phase and only swaps the messages it delivers, a newly
/// requested one starts, and one no longer requested stops. Re-evaluating
/// faster than an interval therefore never starves it.
#[cfg(any(
    all(feature = "tokio", not(target_arch = "wasm32")),
    all(target_arch = "wasm32", feature = "wasm-client")
))]
pub(crate) struct EveryTimers<T> {
    running: std::collections::BTreeMap<EveryInterval, T>,
}

#[cfg(any(
    all(feature = "tokio", not(target_arch = "wasm32")),
    all(target_arch = "wasm32", feature = "wasm-client")
))]
impl<T> Default for EveryTimers<T> {
    fn default() -> Self {
        Self {
            running: std::collections::BTreeMap::new(),
        }
    }
}

#[cfg(any(
    all(feature = "tokio", not(target_arch = "wasm32")),
    all(target_arch = "wasm32", feature = "wasm-client")
))]
impl<T> EveryTimers<T> {
    /// Bring the running timers in line with `wanted`, starting new intervals through `start`.
    pub(crate) fn reconcile<M>(
        &mut self,
        wanted: EveryPlan<M>,
        mut start: impl FnMut(EveryInterval, Vec<M>) -> T,
    ) where
        T: EveryTimer<M>,
    {
        self.running
            .retain(|interval, _| wanted.contains_key(interval));
        for (interval, msgs) in wanted {
            match self.running.entry(interval) {
                std::collections::btree_map::Entry::Occupied(timer) => {
                    timer.get().retarget(msgs);
                }
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(start(interval, msgs));
                }
            }
        }
    }

    /// The number of running timers.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn len(&self) -> usize {
        self.running.len()
    }
}

/// Where a native TEA loop's subscriptions deliver their messages.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
pub(crate) trait SubSink<M>: Clone + Send + Sync + 'static {
    /// Deliver one timer message, resolving to `false` once the loop is gone.
    fn deliver(&self, msg: M) -> impl Future<Output = bool> + Send;
    /// Deliver one subscription-source message without waiting.
    fn emit(&self, msg: M);
}

/// A spawned task aborted when its owner drops it.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
struct AbortOnDrop(tokio::task::JoinHandle<()>);

#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The messages a native timer delivers per tick, shared with its task.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
type TickMsgs<M> = std::sync::Arc<std::sync::Mutex<Vec<M>>>;

/// A native `Sub.every` ticker task.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
struct NativeEvery<M> {
    msgs: TickMsgs<M>,
    _task: AbortOnDrop,
}

#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
impl<M> EveryTimer<M> for NativeEvery<M> {
    fn retarget(&self, msgs: Vec<M>) {
        *self
            .msgs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = msgs;
    }
}

/// The running subscriptions of one native TEA loop.
///
/// Timers persist across re-evaluation through [`EveryTimers`]. A subscription
/// source has no identity to match a re-evaluated one against, so every
/// re-evaluation stops the running sources and spawns the requested ones.
/// Dropping the runtime stops everything.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
pub(crate) struct SubRuntime<M, S> {
    sink: S,
    every: EveryTimers<NativeEvery<M>>,
    sources: Vec<AbortOnDrop>,
}

#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
impl<M: Clone + Send + 'static, S: SubSink<M>> SubRuntime<M, S> {
    /// A runtime with nothing subscribed, delivering into `sink`.
    pub(crate) fn new(sink: S) -> Self {
        Self {
            sink,
            every: EveryTimers::default(),
            sources: Vec::new(),
        }
    }

    /// Re-evaluate the loop's subscriptions against a fresh `subscriptions(model)`.
    pub(crate) fn reconcile(&mut self, sub: IpeSub<M>) {
        let SubPlan { every, sources, .. } = SubPlan::of(sub);
        self.apply(every, sources);
    }

    /// Re-evaluate against the timers and sources of an already flattened plan.
    pub(crate) fn apply(&mut self, every: EveryPlan<M>, sources: Vec<SubSpawn<M>>) {
        let sink = &self.sink;
        self.every.reconcile(every, |interval, msgs| {
            let msgs: TickMsgs<M> = std::sync::Arc::new(std::sync::Mutex::new(msgs));
            let tick_msgs = std::sync::Arc::clone(&msgs);
            let sink = sink.clone();
            let period = std::time::Duration::from_millis(interval.millis());
            // First tick one period after the interval is first requested.
            let task = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(period).await;
                    let batch = tick_msgs
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();
                    for msg in batch {
                        if !sink.deliver(msg).await {
                            return;
                        }
                    }
                }
            });
            NativeEvery {
                msgs,
                _task: AbortOnDrop(task),
            }
        });
        self.sources.clear();
        for spawn in sources {
            let sink = self.sink.clone();
            let emit: std::sync::Arc<dyn Fn(M) + Send + Sync> =
                std::sync::Arc::new(move |msg| sink.emit(msg));
            self.sources.push(AbortOnDrop(spawn(emit)));
        }
    }

    /// The number of running timers and sources, each of which can still deliver.
    pub(crate) fn live(&self) -> usize {
        self.every.len().saturating_add(self.sources.len())
    }
}

// ─── TEA event loop plumbing (Sub.every tickers + Cmd firing) ───────────────

/// Internal loop event: a raw stdin line (Cli), a decoded key as (kind, value)
/// (Tui — Strings keep this free of the feature-gated TuiKey type), a ticker or
/// subscription Msg, a resolved `Cmd.perform`/`Task.attempt` result, or EOF.
/// Shared by `console_app` and `tui_app` so both reuse `SubManager` (Tick) +
/// `cli_run_cmd`.
///
/// `PerformDone` and `Msg` carry the same payload but are kept distinct so the
/// Cli loop can tell a one-shot effect's result apart from an unbounded ticker
/// or subscription emission: only `PerformDone` counts toward the outstanding
/// one-shot effects that must be delivered before EOF may terminate the loop. A
/// ticker `Msg` can arrive forever and so must never keep the loop alive.
///
/// Terminal-loop-only: both drivers that consume it (`console_app`, `tui_app`)
/// are `feature = "tui"`-gated, so a tui-less `tokio` build (web/server) drops
/// the shared TEA event plumbing rather than carrying it as dead code.
#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
pub(crate) enum CliEvent<M> {
    /// A stdin line, holding its share of the reader's [`InputBudget`].
    Line(String, InputPermit),
    // Constructed only by the `tui` raw-key reader; console_app matches it
    // defensively (keys are ignored under Cli).
    Key(String, String, InputPermit),
    Msg(M),
    PerformDone(M),
    Eof,
}

/// The most terminal input events the loop may hold queued but not yet taken.
///
/// Past it the blocking reader waits (backpressure), so a flood of piped stdin
/// or held-down keys can never outrun the loop into an unbounded queue.
#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
pub(crate) const MAX_QUEUED_INPUT: usize = 256;

/// The longest stdin line the Cli loop delivers, in bytes without its terminator.
///
/// A longer line is dropped whole (never truncated: a prefix of a line can mean
/// something different from the line), and at most this many bytes of it are
/// ever buffered.
#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
pub(crate) const MAX_LINE_BYTES: usize = 64 * 1024;

/// The shared count of queued input events behind an [`InputBudget`].
#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
type QueuedInput = std::sync::Arc<(std::sync::Mutex<usize>, std::sync::Condvar)>;

/// A ceiling on the terminal input events queued for the loop.
///
/// The blocking reader takes one [`InputPermit`] per event before queuing it and
/// waits while `capacity` are outstanding; the loop returns a permit by dropping
/// it when it takes the event.
#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
pub(crate) struct InputBudget {
    queued: QueuedInput,
    capacity: usize,
}

/// One queued input event's share of an [`InputBudget`], returned on drop.
#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
pub(crate) struct InputPermit {
    queued: QueuedInput,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
impl InputBudget {
    /// A budget of `capacity` queued events (at least one).
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            queued: std::sync::Arc::new((std::sync::Mutex::new(0), std::sync::Condvar::new())),
            capacity: capacity.max(1),
        }
    }

    /// Wait until one more event may be queued, or `None` once `closed` reports the loop gone.
    ///
    /// `closed` is polled while waiting, so a reader parked on a full budget
    /// still exits after the loop drops its receiver.
    pub(crate) fn acquire(&self, closed: impl Fn() -> bool) -> Option<InputPermit> {
        let (lock, ready) = &*self.queued;
        let mut queued = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *queued >= self.capacity {
            if closed() {
                return None;
            }
            let (guard, _timeout) = ready
                .wait_timeout(queued, std::time::Duration::from_millis(50))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            queued = guard;
        }
        *queued = queued.saturating_add(1);
        Some(InputPermit {
            queued: std::sync::Arc::clone(&self.queued),
        })
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
impl Drop for InputPermit {
    fn drop(&mut self) {
        let (lock, ready) = &*self.queued;
        let mut queued = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *queued = queued.saturating_sub(1);
        ready.notify_one();
    }
}

/// One stdin line read under [`MAX_LINE_BYTES`].
#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BoundedLine {
    /// A complete line within the ceiling, its `\n` / `\r\n` terminator removed.
    Line(String),
    /// A line past the ceiling, consumed through its terminator and dropped.
    TooLong,
    /// A line within the ceiling that is not UTF-8.
    NotUtf8,
}

/// Read the next line from `reader`, buffering at most `max_bytes` of it.
///
/// Returns `Ok(None)` at end of input. A final line without a terminator is
/// still a line. A line longer than `max_bytes` is consumed through its
/// terminator without being buffered past the ceiling and reported as
/// [`BoundedLine::TooLong`].
#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
pub(crate) fn read_bounded_line<R: std::io::BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> std::io::Result<Option<BoundedLine>> {
    let mut line: Vec<u8> = Vec::new();
    let mut too_long = false;
    let mut read_any = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if !read_any {
                return Ok(None);
            }
            break;
        }
        read_any = true;
        let newline = available.iter().position(|b| *b == b'\n');
        let chunk = match newline {
            Some(at) => available.get(..at).unwrap_or(available),
            None => available,
        };
        if !too_long {
            if line.len().saturating_add(chunk.len()) > max_bytes.saturating_add(1) {
                // One byte of slack admits a `\r` of a `\r\n` terminator.
                too_long = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(chunk);
            }
        }
        let consumed = chunk.len().saturating_add(usize::from(newline.is_some()));
        reader.consume(consumed);
        if newline.is_some() {
            break;
        }
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if too_long || line.len() > max_bytes {
        return Ok(Some(BoundedLine::TooLong));
    }
    Ok(Some(
        String::from_utf8(line).map_or(BoundedLine::NotUtf8, BoundedLine::Line),
    ))
}

/// The terminal loop as a subscription sink.
#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
impl<M: Send + 'static> SubSink<M> for tokio::sync::mpsc::UnboundedSender<CliEvent<M>> {
    fn deliver(&self, msg: M) -> impl Future<Output = bool> + Send {
        std::future::ready(self.send(CliEvent::Msg(msg)).is_ok())
    }
    fn emit(&self, msg: M) {
        // A closed loop drops the message; the source is stopped with the loop.
        let _ = self.send(CliEvent::Msg(msg));
    }
}

/// Tracks the running subscriptions and the active terminal input handlers.
///
/// Timers and sources run in a [`SubRuntime`]; the handlers are the
/// `Tui.Sub.onKey` / `Cli.Sub.onLine` ones. `update` re-evaluates against the
/// new Sub (one program, one model, re-evaluated each update), so an input
/// event is always dispatched against the handlers the CURRENT model
/// subscribes to while a still-requested `Sub.every` keeps its phase.
///
/// Terminal-loop-only (see [`CliEvent`]): both consuming drivers are
/// `feature = "tui"`-gated.
#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
pub(crate) struct SubManager<M> {
    subs: SubRuntime<M, tokio::sync::mpsc::UnboundedSender<CliEvent<M>>>,
    key_handlers: Vec<KeyHandler<M>>,
    line_handlers: Vec<LineHandler<M>>,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
impl<M: Clone + Send + 'static> SubManager<M> {
    pub(crate) fn new(tx: tokio::sync::mpsc::UnboundedSender<CliEvent<M>>) -> Self {
        SubManager {
            subs: SubRuntime::new(tx),
            key_handlers: Vec::new(),
            line_handlers: Vec::new(),
        }
    }
    pub(crate) fn stop_all(&mut self) {
        self.subs.reconcile(IpeSub::None);
        self.key_handlers.clear();
        self.line_handlers.clear();
    }
    /// The messages every active `Tui.Sub.onKey` handler maps one key to.
    ///
    /// In subscription order; empty when no key subscription is active (the key
    /// is then unobserved).
    pub(crate) fn key_msgs(&self, kind: &str, value: &str) -> Vec<M> {
        self.key_handlers
            .iter()
            .map(|on_key| on_key(kind.to_owned(), value.to_owned()))
            .collect()
    }
    /// The messages every active `Cli.Sub.onLine` handler maps one stdin line to.
    ///
    /// In subscription order; empty when no line subscription is active.
    pub(crate) fn line_msgs(&self, line: &str) -> Vec<M> {
        self.line_handlers
            .iter()
            .map(|on_line| on_line(line.to_owned()))
            .collect()
    }
    pub(crate) fn update(&mut self, sub: IpeSub<M>) {
        let SubPlan {
            every,
            sources,
            key_handlers,
            line_handlers,
        } = SubPlan::of(sub);
        self.subs.apply(every, sources);
        self.key_handlers = key_handlers;
        self.line_handlers = line_handlers;
    }
}

/// Fire a Cmd: None/Batch recurse; Perform spawns the composed task→toMsg thunk
/// and pushes the resulting Msg back into the loop channel. The Tui driver
/// (which exits on a quit key, not stdin EOF) does not track outstanding
/// effects, so it fires without a counter.
// Only the Tui driver fires Cmds untracked; the Cli loop uses the tracked
// variant directly. Gate this wrapper on the same feature as its sole caller so
// a Tui-less feature combo does not see it as dead code.
#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
pub(crate) fn cli_run_cmd<M: Send + 'static>(
    cmd: IpeCmd<M>,
    tx: &tokio::sync::mpsc::UnboundedSender<CliEvent<M>>,
) {
    cli_run_cmd_tracked(cmd, tx, None);
}

/// As `cli_run_cmd`, but when `outstanding` is `Some`, each spawned `Perform`
/// increments it before spawning and its result is delivered as a
/// `CliEvent::PerformDone` (the Cli loop decrements the counter on dequeue).
/// This lets the Cli loop keep running past stdin EOF until every one-shot
/// effect an `init`/`update` issued has delivered its Msg — without letting
/// unbounded ticker/subscription `Msg`s (which never touch the counter) keep
/// the loop alive.
///
/// Both callers (`cli_run_cmd`, the Tui driver's untracked wrapper, and
/// `console_app`) are `feature = "tui"`-gated, so this shares the gate — a
/// tui-less `tokio` build would otherwise flag it as dead code under
/// `-D warnings`.
#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
pub(crate) fn cli_run_cmd_tracked<M: Send + 'static>(
    cmd: IpeCmd<M>,
    tx: &tokio::sync::mpsc::UnboundedSender<CliEvent<M>>,
    outstanding: Option<&std::sync::Arc<std::sync::atomic::AtomicUsize>>,
) {
    match cmd {
        IpeCmd::None => {}
        IpeCmd::Batch(items) => {
            for c in items {
                cli_run_cmd_tracked(c, tx, outstanding);
            }
        }
        IpeCmd::Perform(thunk) => {
            let tx = tx.clone();
            // A tracked Perform is counted as outstanding at spawn and delivers a
            // `PerformDone`; an untracked one (Tui) delivers a plain `Msg`.
            let counter = outstanding.cloned();
            if let Some(c) = &counter {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            // Fire-and-forget: a panic inside the composed task→toMsg thunk aborts
            // only this task and is intentionally swallowed — that is the
            // Task-boundary recover contract (an effectful task that faults must
            // not crash the TEA loop). On a fault the JoinHandle is dropped and
            // no event is sent; the Cli loop's counter would then never be
            // decremented for this effect, so the spawned task decrements the
            // counter on the fault path (drop guard) to preserve the EOF
            // invariant. Structured-warn observability on this path is a known
            // follow-up (would require awaiting the JoinHandle's JoinError).
            tokio::spawn(async move {
                // Decrement on any exit from this task (normal or panic-unwind)
                // so a faulting effect can never wedge the EOF-drain invariant.
                struct OutstandingGuard(Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>);
                impl Drop for OutstandingGuard {
                    fn drop(&mut self) {
                        if let Some(c) = &self.0 {
                            c.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                }
                match counter {
                    Some(c) => {
                        // Counter decremented by the loop on `PerformDone` dequeue
                        // (below) for the delivered case; the guard covers only the
                        // panic-unwind case where no event reaches the loop.
                        let mut guard = OutstandingGuard(Some(c));
                        let msg = thunk().await;
                        guard.0 = None; // delivered → loop owns the decrement
                        // A send failure means the loop already exited (rx
                        // dropped); the leaked count is then unobservable, so it
                        // is intentionally not decremented here.
                        let _ = tx.send(CliEvent::PerformDone(msg));
                    }
                    None => {
                        let msg = thunk().await;
                        let _ = tx.send(CliEvent::Msg(msg));
                    }
                }
            });
        }
        IpeCmd::Publish(thunk) => {
            // No Web session in a Cli program; publish with an empty origin
            // (no subscriber's owner_sid matches "" → echo-default no-op).
            let _ = thunk("");
        }
    }
}

// ─── Ipe.Terminal — line-oriented TEA loop ─────────────────────────────────────

/// The name of the `console_app` stdin reader thread.
#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
const STDIN_READER_THREAD: &str = "ipe-stdin-reader";

/// Cli.tea { init, update, view, subscriptions } : Task Error ().
///
/// init -> fire cmd -> subs -> view; then fold each event (a stdin line through
/// every active `Cli.Sub.onLine` handler, a ticker/Cmd.perform Msg) through
/// update -> re-fire cmd -> re-subs -> view, until stdin EOF. A line no handler
/// subscribes to is unobserved (no update, no render). Stdin is read on a blocking task; tickers + perform
/// results merge into the same single-threaded update sequence via one channel.
///
/// Gated on `feature = "tui"`: the `Lines msg` view rasterizes through
/// `crate::tui::render_lines_view`, which shares the terminal runtime module
/// with `tui_app`. A `Cli.tea` program selects the `tui` feature, so a plain
/// `tokio` program (web/server, no terminal shape) never compiles this entry.
///
/// A `--debugger` build takes the program's session `codec` too: the recorder
/// dumps the trace and typed log through it on exit, and with
/// `IPE_DEBUGGER_REPLAY` set the loop never starts — the named log is replayed
/// instead (see [`crate::debugger::session_log`]).
#[cfg(all(not(target_arch = "wasm32"), feature = "tui"))]
pub fn console_app<
    Model,
    Msg,
    E,
    FInit,
    FUpdate,
    FView,
    FSubs,
    #[cfg(feature = "debugger")] Codec: crate::debugger::session_log::SessionCodec<Msg, Model> + Send + 'static,
>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
    #[cfg(feature = "debugger")] codec: Codec,
) -> IpeTask<E, ()>
where
    E: From<String> + crate::FromUnavailable + Send + 'static,
    Model: Clone + Send + crate::stringify::IpeStringify + 'static,
    Msg: Clone + Send + crate::stringify::IpeStringify + 'static,
    FInit: Fn(()) -> (Model, IpeCmd<Msg>) + Send + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + 'static,
    FView: Fn(Model) -> crate::tui::LinesView<Msg> + Send + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + Send + 'static,
{
    Box::pin(async move {
        use std::io::Write;
        // A replay run folds the recorded log and never starts the live loop:
        // no stdin is read, no `Cmd` (not even `init`'s) and no `Sub` runs.
        #[cfg(feature = "debugger")]
        if let Some(log) = crate::debugger::session_log::replay_request() {
            let (init_model, _unrun) = init(());
            return match crate::debugger::session_log::replay_file(
                &codec, &log, init_model, &update,
            ) {
                Ok(()) => ok_res(()),
                Err(refusal) => IpeResult::Err(E::from(refusal.to_string())),
            };
        }
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<CliEvent<Msg>>();

        // Blocking stdin reader → raw Line events, then Eof. The line handlers are
        // applied in the main task (keeps them off the blocking thread).
        //
        // Bounded by construction: each line is read under `MAX_LINE_BYTES` (an
        // over-long line is dropped whole) and queued only with an
        // `InputBudget` permit, so at most `MAX_QUEUED_INPUT` lines wait for the
        // loop; past that the reader blocks until the loop catches up.
        //
        // KNOWN LEAK (intentional, bounded): this detached thread is never joined
        // or signalled — if the returned future is dropped/cancelled the thread
        // stays parked on its stdin read until the next line (or process exit).
        // Benign for a one-shot Cli `main` (the process is exiting anyway); a
        // shutdown flag wouldn't help since the read blocks until the next line
        // regardless. Do NOT compose `console_app` under a cancelling parent or
        // invoke it twice in one process without first accounting for this.
        //
        // A refused reader thread ends the app with an `Unavailable` error
        // before any input is read.
        let line_tx = tx.clone();
        let started = crate::threads::spawn_named(STDIN_READER_THREAD, move || {
            let budget = InputBudget::new(MAX_QUEUED_INPUT);
            let stdin = std::io::stdin();
            let mut reader = stdin.lock();
            loop {
                let line = match read_bounded_line(&mut reader, MAX_LINE_BYTES) {
                    Ok(Some(BoundedLine::Line(l))) => l,
                    Ok(Some(BoundedLine::TooLong)) => continue,
                    // End of input, a non-UTF-8 line, or a read error ends input.
                    Ok(None | Some(BoundedLine::NotUtf8)) | Err(_) => break,
                };
                let Some(permit) = budget.acquire(|| line_tx.is_closed()) else {
                    return;
                };
                if line_tx.send(CliEvent::Line(line, permit)).is_err() {
                    return;
                }
            }
            let _ = line_tx.send(CliEvent::Eof);
        });
        if let Err(e) = started {
            return IpeResult::Err(
                crate::threads::ThreadRefused::os(STDIN_READER_THREAD, &e).into_error(),
            );
        }

        // Count of one-shot `Perform` effects that were issued but whose Msg has
        // not yet been folded through `update`. EOF must not terminate the loop
        // while this is non-zero, or an init/update-issued effect's result would
        // be silently dropped on empty/early-closing stdin.
        let outstanding = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut eof_seen = false;

        let (mut model, cmd0) = init(());
        // Time-travel recorder above the sink: cfg-gated, records each accepted
        // `(msg, model)` after `update`. Bounded ring (`DEFAULT_HISTORY_CAP`);
        // zero code when the feature is off.
        #[cfg(feature = "debugger")]
        let mut recorder =
            crate::debugger::RecordBuffer::new(model.clone(), crate::debugger::DEFAULT_HISTORY_CAP);
        cli_run_cmd_tracked(cmd0, &tx, Some(&outstanding));
        let mut submgr = SubManager::new(tx.clone());
        submgr.update(subscriptions(model.clone()));
        // Inline render (a closure borrowing `view` would make the future non-Send).
        // Fallible writes (NOT print!/println!, which panic on a broken pipe).
        //
        // A render rasterizes the model's `Lines` view to a styled terminal
        // string via `render_lines_view` and writes it to stdout with NO forced
        // trailing "\n": the prompt formatting is the view's own to decide, so a
        // view whose last line ends `"> "` keeps the cursor on the prompt line
        // for the user's input. Exactly one terminating newline is written after
        // the event loop exits. A view that wants each render on its own line
        // supplies its own trailing empty line.
        //
        // The initial render is skipped when `init` issued an outstanding
        // effect: that effect's Msg folds through `update` and renders the
        // settled model below, so an eager render here would paint the
        // pre-effect model and duplicate the frame. An effect-free `init`
        // (`Cmd.none`) has nothing to settle, so its initial model renders now
        // (the `lines: 0` frame the separator fixture pins).
        if outstanding.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            let rendered = crate::tui::render_lines_view(view(model.clone()));
            let _ = std::io::stdout().write_all(rendered.as_bytes());
            let _ = std::io::stdout().flush();
        }

        while let Some(ev) = rx.recv().await {
            let msgs: Vec<Msg> = match ev {
                // Every active line handler sees the line; none → unobserved.
                // The permit returns to the reader's budget as the line is taken.
                CliEvent::Line(l, _permit) => submgr.line_msgs(&l),
                CliEvent::Key(..) => continue, // Cli has no keys
                CliEvent::Msg(m) => vec![m],
                CliEvent::PerformDone(m) => {
                    // A one-shot effect delivered its result: this effect is no
                    // longer outstanding. If EOF already arrived and this was the
                    // last outstanding effect, fold it and then let EOF terminate.
                    outstanding.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    vec![m]
                }
                CliEvent::Eof => {
                    // EOF terminates only once every outstanding one-shot effect
                    // has delivered. If effects are still in flight, remember EOF
                    // and keep folding their results; the check after each fold
                    // (below) breaks once the count reaches zero.
                    if outstanding.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                        break;
                    }
                    eof_seen = true;
                    continue;
                }
            };
            if msgs.is_empty() {
                continue;
            }
            // Fold each message in order; the subscriptions are re-evaluated
            // after each, so the next message meets the model it produced.
            for msg in msgs {
                #[cfg(feature = "debugger")]
                let msg_for_recorder = msg.clone();
                let (next, cmd) = update(msg, model);
                model = next;
                #[cfg(feature = "debugger")]
                recorder.record(msg_for_recorder, model.clone(), &update);
                cli_run_cmd_tracked(cmd, &tx, Some(&outstanding));
                submgr.update(subscriptions(model.clone()));
            }
            let rendered = crate::tui::render_lines_view(view(model.clone()));
            let _ = std::io::stdout().write_all(rendered.as_bytes());
            let _ = std::io::stdout().flush();
            // After folding an effect's result, if EOF was already seen and no
            // effects remain outstanding, terminate as EOF would have.
            if eof_seen && outstanding.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                break;
            }
        }
        submgr.stop_all();
        let _ = std::io::stdout().write_all(b"\n");
        // Dump the recorded session (plain trace + typed log) to the
        // `IPE_DEBUGGER_RECORD` destination, a no-op when that env var is unset.
        // The recorder ring already bounds the log.
        #[cfg(feature = "debugger")]
        crate::debugger::record_sink::dump_session(&recorder, &update, &codec);
        ok_res(())
    })
}

// ─── Shape opaque app-leaf types ──────────────────────────────────────────
//
// Each entry builder (`Web.tea`, `Tui.tea`, `Cli.tea`) returns one of these
// opaque handles instead of
// `IpeTask<E, ()>`. The handle wraps the underlying task and exposes a single
// `run_blocking` method consumed by the emitted `fn main()`. This erases the
// msg/model type parameters from the program's `main` type signature while
// keeping the emit path concrete (no `dyn`).

/// A concrete-erased builder that, given a mount base-path prefix, produces the
/// embedded web app's fully-layered axum `Router` (the same router the
/// standalone `serve_web` binds). Boxed so `WebApp` stays non-generic — the box
/// is over the *builder*, NOT the app's handlers: `init`/`update`/`view`/`subs`
/// are concrete monomorphised closures captured inside, so the mounted app is
/// erased-free at the handler level (§9: no `dyn` over the app / handlers).
#[cfg(all(not(target_arch = "wasm32"), feature = "web"))]
pub type MountBuilder = Box<
    dyn FnOnce(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = axum::Router> + Send>>
        + Send,
>;

/// Opaque app handle returned by `Web.tea` / `Web.appRouted` / `Web.appWith`
/// (standalone) or `Web.embed` (mountable). The `WebApp(...)` tuple form is the
/// leaf-constructor the backend's shape-app entry switch detects; the inner
/// [`WebAppKind`] selects the run mode.
#[cfg(not(target_arch = "wasm32"))]
pub struct WebApp(pub WebAppKind);

/// The two run modes a `WebApp` leaf can carry.
///
/// * `Standalone` — from `Web.tea`: a fully-built server task that binds its
///   own listener. `run_blocking` drives it.
/// * `Mountable` — from `Web.embed`: carries BOTH a standalone `serve` task (so
///   a top-level `main = Web.embed { … }` still runs on its own port) AND a
///   `router` builder that `Server.mountApp` nests under a prefix on the shared
///   server port (one listener).
#[cfg(not(target_arch = "wasm32"))]
pub enum WebAppKind {
    Standalone(IpeTask<crate::error::IpeError, ()>),
    #[cfg(feature = "web")]
    Mountable {
        serve: IpeTask<crate::error::IpeError, ()>,
        router: MountBuilder,
    },
}

#[cfg(not(target_arch = "wasm32"))]
impl WebApp {
    /// Blocking entry: drives the underlying task to completion on a
    /// fresh tokio runtime. Returns the task's `IpeResult`. A mountable handle
    /// used top-level runs its standalone `serve` task (binds its own port).
    pub fn run_blocking(self) -> crate::IpeResult<crate::error::IpeError, ()> {
        match self.0 {
            WebAppKind::Standalone(task) => crate::task::block_on(task),
            #[cfg(feature = "web")]
            WebAppKind::Mountable { serve, .. } => crate::task::block_on(serve),
        }
    }

    /// Take the mount router-builder, if this is an embedded (mountable) handle.
    /// `Server.mountApp` calls this; a `Web.tea` (standalone) handle yields
    /// `None`, which the mount path turns into a fail-closed diagnostic route
    /// (unreachable for well-typed source: `mountApp` only accepts `Web.embed`
    /// / `Web.tea` handles, and `Web.tea` handles are still mountable-capable
    /// only via `embed`).
    #[cfg(feature = "web")]
    pub fn into_mount_builder(self) -> Option<MountBuilder> {
        match self.0 {
            WebAppKind::Mountable { router, .. } => Some(router),
            WebAppKind::Standalone(_) => None,
        }
    }
}

/// Opaque app handle for the webview-native host of a `Web.tea` (a `web desktop`
/// delivery). Backed by a boxed `IpeTask<IpeError, ()>`; run via `run_blocking` on
/// the current thread (tao/Cocoa mandates the process main thread on macOS).
#[cfg(not(target_arch = "wasm32"))]
pub struct WebViewApp(pub IpeTask<crate::error::IpeError, ()>);

#[cfg(not(target_arch = "wasm32"))]
impl WebViewApp {
    /// Blocking entry on the CURRENT thread (required by tao/Cocoa on macOS).
    pub fn run_blocking(self) -> crate::IpeResult<crate::error::IpeError, ()> {
        crate::task::block_on_current_thread(self.0)
    }
}

/// Opaque app handle returned by `Tui.tea`.
/// Backed by a boxed `IpeTask<IpeError, ()>`; run via `run_blocking`.
#[cfg(not(target_arch = "wasm32"))]
pub struct TuiApp(pub IpeTask<crate::error::IpeError, ()>);

#[cfg(not(target_arch = "wasm32"))]
impl TuiApp {
    /// Blocking entry: drives the underlying task to completion.
    pub fn run_blocking(self) -> crate::IpeResult<crate::error::IpeError, ()> {
        crate::task::block_on(self.0)
    }
}

/// Opaque app handle returned by `Cli.tea`.
/// Backed by a boxed `IpeTask<IpeError, ()>`; run via `run_blocking`.
#[cfg(not(target_arch = "wasm32"))]
pub struct CliApp(pub IpeTask<crate::error::IpeError, ()>);

#[cfg(not(target_arch = "wasm32"))]
impl CliApp {
    /// Blocking entry: drives the underlying task to completion.
    pub fn run_blocking(self) -> crate::IpeResult<crate::error::IpeError, ()> {
        crate::task::block_on(self.0)
    }
}

// ─── Ipe.Tea.Worker.tea — view-less co-located TEA loop ────────────────────────────

/// The event a view-less worker's run loop folds. A worker has no input stream
/// (no stdin, no keys): its only events are the messages its own `Cmd`s and
/// `Sub`s produce, so the enum is exactly those two shapes.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
enum WorkerEvent<M> {
    /// A message from a `Sub` (a ticker or a source).
    Msg(M),
    /// A one-shot `Cmd.perform` effect delivered its result.
    PerformDone(M),
}

/// Fire a worker `Cmd`: None/Batch recurse; Perform spawns the composed
/// task→toMsg thunk and delivers a `PerformDone`. Every spawned `Perform` is
/// counted as outstanding so an effect-only worker (empty `Sub`) still folds its
/// results before the loop terminates. `Publish` has no Web session here, so it
/// fires with an empty origin (no subscriber matches → no-op), matching the Cli
/// loop's co-located behaviour.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
fn worker_run_cmd<M: Send + 'static>(
    cmd: IpeCmd<M>,
    tx: &tokio::sync::mpsc::UnboundedSender<WorkerEvent<M>>,
    outstanding: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    match cmd {
        IpeCmd::None => {}
        IpeCmd::Batch(items) => {
            for c in items {
                worker_run_cmd(c, tx, outstanding);
            }
        }
        IpeCmd::Perform(thunk) => {
            let tx = tx.clone();
            let counter = outstanding.clone();
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                // Decrement on any exit (normal or panic-unwind) so a faulting
                // effect can never wedge the drain invariant — the same
                // Task-boundary recover contract the Cli loop uses.
                struct OutstandingGuard(Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>);
                impl Drop for OutstandingGuard {
                    fn drop(&mut self) {
                        if let Some(c) = &self.0 {
                            c.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                }
                let mut guard = OutstandingGuard(Some(counter));
                let msg = thunk().await;
                guard.0 = None; // delivered → loop owns the decrement
                let _ = tx.send(WorkerEvent::PerformDone(msg));
            });
        }
        IpeCmd::Publish(thunk) => {
            let _ = thunk("");
        }
    }
}

/// The worker loop as a subscription sink.
///
/// Terminal input handlers in a worker's `Sub` are dropped by
/// [`SubRuntime::reconcile`]: a worker reads no stream, so they never deliver
/// and never keep the worker alive.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
impl<M: Send + 'static> SubSink<M> for tokio::sync::mpsc::UnboundedSender<WorkerEvent<M>> {
    fn deliver(&self, msg: M) -> impl Future<Output = bool> + Send {
        std::future::ready(self.send(WorkerEvent::Msg(msg)).is_ok())
    }
    fn emit(&self, msg: M) {
        // A closed loop drops the message; the source is stopped with the loop.
        let _ = self.send(WorkerEvent::Msg(msg));
    }
}

/// `Ipe.Tea.Worker.tea { init, update, subscriptions } : Task Error ()`.
///
/// A view-less TEA loop (Elm `Platform.worker` shape): `init` yields the first
/// model and `Cmd`; each `Sub` message and each `Cmd.perform` result folds
/// through `update`, re-firing its `Cmd` and re-evaluating `subscriptions`. No
/// view is rendered and no input stream is read — a worker's only inputs are its
/// own effects and subscriptions.
///
/// The loop holds the single sender the whole time, so it never wedges: it
/// terminates deterministically once the model has settled with NO active
/// subscription (no ticker / source can deliver again) AND no outstanding
/// one-shot effect. An effect-only worker runs until its effects drain; a
/// subscription worker runs until its subscriptions become `Sub.none`. A worker
/// whose `init` issues neither an effect nor a subscription completes at once.
///
/// A `--debugger` build takes the program's session `codec` too, exactly as
/// `console_app` does: record on exit, or replay instead of running when
/// `IPE_DEBUGGER_REPLAY` is set.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
pub fn worker_app<
    Model,
    Msg,
    E,
    FInit,
    FUpdate,
    FSubs,
    #[cfg(feature = "debugger")] Codec: crate::debugger::session_log::SessionCodec<Msg, Model> + Send + 'static,
>(
    init: FInit,
    update: FUpdate,
    subscriptions: FSubs,
    #[cfg(feature = "debugger")] codec: Codec,
) -> IpeTask<E, ()>
where
    E: From<String> + Send + 'static,
    Model: Clone + Send + crate::stringify::IpeStringify + 'static,
    Msg: Clone + Send + crate::stringify::IpeStringify + 'static,
    FInit: Fn(()) -> (Model, IpeCmd<Msg>) + Send + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + Send + 'static,
{
    Box::pin(async move {
        // A replay run folds the recorded log and never starts the live loop:
        // no `Cmd` (not even `init`'s) and no `Sub` runs.
        #[cfg(feature = "debugger")]
        if let Some(log) = crate::debugger::session_log::replay_request() {
            let (init_model, _unrun) = init(());
            return match crate::debugger::session_log::replay_file(
                &codec, &log, init_model, &update,
            ) {
                Ok(()) => ok_res(()),
                Err(refusal) => IpeResult::Err(E::from(refusal.to_string())),
            };
        }
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<WorkerEvent<Msg>>();
        let outstanding = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let (mut model, cmd0) = init(());
        // Time-travel recorder above the view-less worker sink: cfg-gated,
        // records each accepted `(msg, model)` after `update`. Bounded ring
        // (`DEFAULT_HISTORY_CAP`); zero code when the feature is off. A worker has
        // no view surface, so no appearance hot-swap applies — the recorder is
        // for replay/inspection only.
        #[cfg(feature = "debugger")]
        let mut recorder =
            crate::debugger::RecordBuffer::new(model.clone(), crate::debugger::DEFAULT_HISTORY_CAP);
        worker_run_cmd(cmd0, &tx, &outstanding);
        let mut subs = SubRuntime::new(tx.clone());
        subs.reconcile(subscriptions(model.clone()));
        let mut live_subs = subs.live();

        // Settled at start: `init` issued no effect and no subscription, so no
        // event can ever arrive — terminate rather than block forever on `recv`.
        if live_subs == 0 && outstanding.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            #[cfg(feature = "debugger")]
            crate::debugger::record_sink::dump_session(&recorder, &update, &codec);
            return ok_res(());
        }

        while let Some(ev) = rx.recv().await {
            let msg = match ev {
                WorkerEvent::Msg(m) => m,
                WorkerEvent::PerformDone(m) => {
                    outstanding.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    m
                }
            };
            #[cfg(feature = "debugger")]
            let msg_for_recorder = msg.clone();
            let (next, cmd) = update(msg, model);
            model = next;
            #[cfg(feature = "debugger")]
            recorder.record(msg_for_recorder, model.clone(), &update);
            worker_run_cmd(cmd, &tx, &outstanding);
            subs.reconcile(subscriptions(model.clone()));
            live_subs = subs.live();
            // The model has settled: no live subscription can deliver again and no
            // one-shot effect is in flight, so no further event will arrive.
            // Terminate rather than block on a channel only this loop still holds.
            if live_subs == 0 && outstanding.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                break;
            }
        }
        drop(subs);
        // Dump the recorded session (plain trace + typed log) to the
        // `IPE_DEBUGGER_RECORD` destination, a no-op when that env var is unset.
        // A worker has no view surface, so this dump is its only debugger output.
        #[cfg(feature = "debugger")]
        crate::debugger::record_sink::dump_session(&recorder, &update, &codec);
        ok_res(())
    })
}

/// Opaque app handle returned by `Ipe.Tea.Worker.tea`.
/// Backed by a boxed `IpeTask<IpeError, ()>`; run via `run_blocking`.
#[cfg(not(target_arch = "wasm32"))]
pub struct WorkerApp(pub IpeTask<crate::error::IpeError, ()>);

#[cfg(not(target_arch = "wasm32"))]
impl WorkerApp {
    /// Blocking entry: drives the underlying task to completion.
    pub fn run_blocking(self) -> crate::IpeResult<crate::error::IpeError, ()> {
        crate::task::block_on(self.0)
    }
}

// ─── Cmd.map / Sub.map unit tests ──────────────────────────────────────────

#[cfg(all(test, not(target_arch = "wasm32")))]
mod map_tests {
    use super::*;

    // Two distinct message types so the retag is observable at the type level:
    // `sub_map`/`cmd_map` carry `Child` into `Parent`.
    #[derive(Clone, Debug, PartialEq)]
    enum Child {
        Tick(i64),
        Key(String),
        Line(String),
    }
    #[derive(Clone, Debug, PartialEq)]
    enum Parent {
        FromChild(Child),
    }

    fn wrap(c: Child) -> Parent {
        Parent::FromChild(c)
    }

    #[test]
    fn sub_map_every_retags_stored_msg() {
        let mapped = sub_map(sub_every(50, Child::Tick(7)), wrap);
        match mapped {
            IpeSub::Every { ms, msg } => {
                assert_eq!(ms, 50);
                assert_eq!(msg, Parent::FromChild(Child::Tick(7)));
            }
            _ => panic!("expected Every"),
        }
    }

    #[test]
    fn sub_map_batch_and_none_recurse() {
        let mapped = sub_map(
            sub_batch(vec![sub_every(1, Child::Tick(1)), sub_none()]),
            wrap,
        );
        match mapped {
            IpeSub::Batch(items) => {
                assert_eq!(items.len(), 2);
                assert!(matches!(items[0], IpeSub::Every { ms: 1, .. }));
                assert!(matches!(items[1], IpeSub::None));
            }
            _ => panic!("expected Batch"),
        }
    }

    #[test]
    fn sub_map_source_retags_emitted_value() {
        // A source that emits one Child::Tick(9); after mapping, the emit
        // callback must receive Parent::FromChild(Child::Tick(9)).
        let src: IpeSub<Child> = IpeSub::Source(Box::new(
            |emit: std::sync::Arc<dyn Fn(Child) + Send + Sync>| {
                tokio::spawn(async move {
                    emit(Child::Tick(9));
                })
            },
        ));
        let mapped = sub_map(src, wrap);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let got = rt.block_on(async move {
            let (tx, rx) = std::sync::mpsc::channel::<Parent>();
            let emit: std::sync::Arc<dyn Fn(Parent) + Send + Sync> =
                std::sync::Arc::new(move |m| {
                    let _ = tx.send(m);
                });
            let IpeSub::Source(spawn) = mapped else {
                panic!("expected Source");
            };
            let handle = spawn(emit);
            let _ = handle.await;
            rx.recv().expect("one message")
        });
        assert_eq!(got, Parent::FromChild(Child::Tick(9)));
    }

    #[test]
    fn sub_map_composes_terminal_input_handlers() {
        let key = sub_map(
            tui_sub_on_key(|kind, value| Child::Key(format!("{kind}:{value}"))),
            wrap,
        );
        assert!(matches!(key, IpeSub::OnKey(_)));
        if let IpeSub::OnKey(on_key) = key {
            assert_eq!(
                on_key("char".into(), "q".into()),
                Parent::FromChild(Child::Key("char:q".into()))
            );
        }
        let line = sub_map(cli_sub_on_line(Child::Line), wrap);
        assert!(matches!(line, IpeSub::OnLine(_)));
        if let IpeSub::OnLine(on_line) = line {
            assert_eq!(
                on_line("hi".into()),
                Parent::FromChild(Child::Line("hi".into()))
            );
        }
    }

    #[test]
    fn cmd_map_perform_retags_produced_msg() {
        let cmd: IpeCmd<Child> = IpeCmd::Perform(Box::new(|| Box::pin(async { Child::Tick(4) })));
        let mapped = cmd_map(cmd, wrap);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let got = rt.block_on(async move {
            let IpeCmd::Perform(thunk) = mapped else {
                panic!("expected Perform");
            };
            thunk().await
        });
        assert_eq!(got, Parent::FromChild(Child::Tick(4)));
    }

    #[test]
    fn cmd_map_batch_and_none_recurse() {
        let cmd: IpeCmd<Child> = cmd_batch(vec![
            IpeCmd::Perform(Box::new(|| Box::pin(async { Child::Tick(2) }))),
            cmd_none(),
        ]);
        let mapped = cmd_map(cmd, wrap);
        match mapped {
            IpeCmd::Batch(items) => {
                assert_eq!(items.len(), 2);
                assert!(matches!(items[0], IpeCmd::Perform(_)));
                assert!(matches!(items[1], IpeCmd::None));
            }
            _ => panic!("expected Batch"),
        }
    }

    #[test]
    fn cmd_map_publish_retags_by_identity() {
        // Publish yields the subscriber count (i64), not an M — mapping keeps
        // the thunk intact and only changes the phantom M in the type.
        let cmd: IpeCmd<Child> = IpeCmd::Publish(Box::new(|_origin| 3));
        let mapped: IpeCmd<Parent> = cmd_map(cmd, wrap);
        match mapped {
            IpeCmd::Publish(thunk) => assert_eq!(thunk("sid"), 3),
            _ => panic!("expected Publish"),
        }
    }
}

// ─── Worker shape: appearance hot-swap is N/A by construction ───────────────
//
// A worker (`worker_app`) has no view surface, so the watch-mode appearance
// hot-swap (a `ViewPatch` per changed view; `HotSwap.views`) cannot apply to
// it — there is no view to patch. This is excluded by construction, not
// silently attempted: `worker_app`'s config is exactly `(init, update,
// subscriptions)` with NO `view` argument, and `WorkerApp` exposes only
// `run_blocking` (no appearance-apply entry). The recorder above the worker
// sink still applies for replay/inspection; update/subscription edits are a
// structural rebuild by definition.
#[cfg(all(test, feature = "tokio", not(target_arch = "wasm32")))]
mod worker_appearance_na_tests {
    use super::*;

    use crate::stringify::IpeStringify;

    #[derive(Clone)]
    struct WModel;
    #[derive(Clone)]
    enum WMsg {}

    // The recorder above the worker sink renders `(msg, model)` through
    // `IpeStringify::ipe_show` for its replay log, so both types carry the bound
    // the emitter derives for every real worker's Model/Msg.
    impl IpeStringify for WModel {
        fn ipe_show(&self) -> String {
            "WModel".to_owned()
        }
    }
    impl IpeStringify for WMsg {
        fn ipe_show(&self) -> String {
            // `WMsg` is uninhabited: no value can reach this arm.
            match *self {}
        }
    }

    fn w_init(_: ()) -> (WModel, IpeCmd<WMsg>) {
        (WModel, IpeCmd::None)
    }
    fn w_update(msg: WMsg, _m: WModel) -> (WModel, IpeCmd<WMsg>) {
        // `WMsg` is uninhabited: a worker with no reachable message. The empty
        // match is the total handling — no arm, no wildcard, no unreachable tail.
        match msg {}
    }
    fn w_subs(_: WModel) -> IpeSub<WMsg> {
        IpeSub::None
    }

    // `worker_app` binds to a 3-argument (view-less) shape. If a `view`
    // parameter — the only thing an appearance patch could target — were added
    // to the worker entry, this binding would fail to type-check. The absence of
    // a view is thus pinned at compile time, not merely by convention.
    #[test]
    fn worker_entry_has_no_view_or_appearance_argument() {
        // The exact view-less arity the worker entry must keep, named so the
        // shape is a single declaration rather than an inline complex type.
        #[cfg(not(feature = "debugger"))]
        type WorkerEntry = fn(
            fn(()) -> (WModel, IpeCmd<WMsg>),
            fn(WMsg, WModel) -> (WModel, IpeCmd<WMsg>),
            fn(WModel) -> IpeSub<WMsg>,
        ) -> IpeTask<crate::error::IpeError, ()>;
        // With the debugger the only extra argument is the session codec.
        #[cfg(feature = "debugger")]
        type WorkerEntry = fn(
            fn(()) -> (WModel, IpeCmd<WMsg>),
            fn(WMsg, WModel) -> (WModel, IpeCmd<WMsg>),
            fn(WModel) -> IpeSub<WMsg>,
            crate::debugger::session_log::TraceOnly,
        ) -> IpeTask<crate::error::IpeError, ()>;
        // A fn item of that arity: binding `worker_app` to it is the assertion.
        let entry: WorkerEntry = worker_app;
        // Referencing the fn item is the assertion; do NOT drive the loop (it
        // would block on the worker's own effects/subs).
        let _ = entry;
        let _ = (w_init, w_update, w_subs);
    }

    // The worker's opaque app handle exposes exactly one entry — `run_blocking`
    // — and NO appearance-apply surface. Constructing one and confirming the
    // only consuming method is `run_blocking` pins that no hot-appearance path
    // exists on the worker handle.
    #[test]
    fn worker_app_handle_has_only_run_blocking() {
        let handle: WorkerApp = WorkerApp(Box::pin(async { ok_res(()) }));
        // The sole consuming method. If an appearance-apply method were added it
        // would be a second consumer; there is none.
        let _run: fn(WorkerApp) -> crate::IpeResult<crate::error::IpeError, ()> =
            WorkerApp::run_blocking;
        let _ = handle;
    }
}

// ─── Subscription reconcile unit tests ──────────────────────────────────────

// Every TEA loop re-evaluates `subscriptions(model)` after each update (and the
// Web session driver on each page entry). A still-requested `Sub.every` must
// keep its timer and phase across those re-evaluations, or a loop updating
// faster than the interval never sees a tick. Paused tokio time makes each
// expected tick instant exact.
#[cfg(all(test, feature = "tokio", not(target_arch = "wasm32")))]
mod sub_reconcile_tests {
    use super::*;

    use std::time::Duration;
    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Tick {
        Fast,
        Slow,
        A,
        B,
    }

    type Runtime = SubRuntime<Tick, UnboundedSender<WorkerEvent<Tick>>>;

    fn runtime() -> (Runtime, UnboundedReceiver<WorkerEvent<Tick>>) {
        let (tx, rx) = unbounded_channel();
        (SubRuntime::new(tx), rx)
    }

    fn every(ms: i64, msg: Tick) -> IpeSub<Tick> {
        IpeSub::Every { ms, msg }
    }

    /// Every message already delivered, in delivery order.
    fn drain(rx: &mut UnboundedReceiver<WorkerEvent<Tick>>) -> Vec<Tick> {
        let mut out = Vec::new();
        while let Ok(WorkerEvent::Msg(msg)) = rx.try_recv() {
            out.push(msg);
        }
        out
    }

    async fn sleep_ms(ms: u64) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn re_evaluating_faster_than_the_interval_still_ticks() {
        let (mut subs, mut rx) = runtime();
        for _ in 0..20 {
            subs.reconcile(every(100, Tick::A));
            sleep_ms(50).await;
        }
        sleep_ms(10).await;
        // Ticks at 100, 200, …, 1000 ms; a reset per re-evaluation yields none.
        assert_eq!(drain(&mut rx), vec![Tick::A; 10]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_interval_fires_while_a_fast_one_drives_updates() {
        let (mut subs, mut rx) = runtime();
        let both = || IpeSub::Batch(vec![every(100, Tick::Fast), every(1000, Tick::Slow)]);
        subs.reconcile(both());
        let (mut fast, mut slow) = (0_u32, 0_u32);
        while fast < 25 {
            let received = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await;
            let Ok(Some(WorkerEvent::Msg(msg))) = received else {
                break;
            };
            match msg {
                Tick::Fast => fast += 1,
                Tick::Slow => slow += 1,
                Tick::A | Tick::B => {}
            }
            // Each delivered message is an update, which re-evaluates.
            subs.reconcile(both());
        }
        assert_eq!(fast, 25);
        // The 1000 ms timer fired at 1000 and 2000 ms, before the 25th fast tick.
        assert_eq!(slow, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_interval_stops_its_timer() {
        let (mut subs, mut rx) = runtime();
        subs.reconcile(IpeSub::Batch(vec![
            every(100, Tick::A),
            every(300, Tick::B),
        ]));
        assert_eq!(subs.live(), 2);
        subs.reconcile(every(100, Tick::A));
        assert_eq!(subs.live(), 1);
        sleep_ms(1010).await;
        assert_eq!(drain(&mut rx), vec![Tick::A; 10]);
        subs.reconcile(IpeSub::None);
        assert_eq!(subs.live(), 0);
        sleep_ms(1000).await;
        assert_eq!(drain(&mut rx), Vec::<Tick>::new());
    }

    #[tokio::test(start_paused = true)]
    async fn a_kept_interval_delivers_its_new_msg_without_a_phase_reset() {
        let (mut subs, mut rx) = runtime();
        subs.reconcile(every(100, Tick::A));
        sleep_ms(150).await;
        subs.reconcile(every(100, Tick::B));
        sleep_ms(60).await;
        // B is due at 200 ms, on the original phase; a restarted timer would
        // fire at 250 ms instead.
        assert_eq!(drain(&mut rx), vec![Tick::A, Tick::B]);
    }

    #[tokio::test(start_paused = true)]
    async fn one_interval_delivers_every_msg_requested_at_it() {
        let (mut subs, mut rx) = runtime();
        subs.reconcile(IpeSub::Batch(vec![
            every(100, Tick::A),
            every(100, Tick::B),
        ]));
        assert_eq!(subs.live(), 1);
        sleep_ms(110).await;
        assert_eq!(drain(&mut rx), vec![Tick::A, Tick::B]);
    }

    #[test]
    fn a_non_positive_interval_never_runs() {
        assert_eq!(EveryInterval::from_millis(0), None);
        assert_eq!(EveryInterval::from_millis(-5), None);
        let plan = SubPlan::of(IpeSub::Batch(vec![every(0, Tick::A), every(-1, Tick::B)]));
        assert!(plan.every.is_empty());
    }

    #[test]
    fn a_browser_delay_saturates_at_the_largest_honoured_one() {
        let delay = |ms| EveryInterval::from_millis(ms).map(EveryInterval::browser_delay_ms);
        assert_eq!(delay(1000), Some(1000));
        assert_eq!(delay(2_147_483_647), Some(2_147_483_647));
        assert_eq!(delay(2_147_483_648), Some(2_147_483_647));
        assert_eq!(delay(i64::MAX), Some(2_147_483_647));
    }
}

// ─── Terminal input dispatch unit tests ────────────────────────────────────

#[cfg(all(test, not(target_arch = "wasm32"), feature = "tui"))]
mod input_dispatch_tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    enum Msg {
        Key(String),
        Line(String),
    }

    fn manager() -> SubManager<Msg> {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<CliEvent<Msg>>();
        SubManager::new(tx)
    }

    #[test]
    fn every_active_handler_sees_the_input_in_subscription_order() {
        let mut mgr = manager();
        mgr.update(sub_batch(vec![
            tui_sub_on_key(|kind, _value| Msg::Key(kind)),
            tui_sub_on_key(|_kind, value| Msg::Key(value)),
            cli_sub_on_line(Msg::Line),
        ]));
        assert_eq!(
            mgr.key_msgs("char", "x"),
            vec![Msg::Key("char".into()), Msg::Key("x".into())]
        );
        assert_eq!(mgr.line_msgs("hello"), vec![Msg::Line("hello".into())]);
    }

    #[test]
    fn input_with_no_active_handler_is_unobserved() {
        let mut mgr = manager();
        mgr.update(sub_none());
        assert!(mgr.key_msgs("char", "x").is_empty());
        assert!(mgr.line_msgs("hello").is_empty());
    }

    #[test]
    fn resubscribing_replaces_the_handler_set() {
        // A model whose `subscriptions` stops listening drops every handler.
        let mut mgr = manager();
        mgr.update(cli_sub_on_line(Msg::Line));
        assert_eq!(mgr.line_msgs("a").len(), 1);
        mgr.update(sub_none());
        assert!(mgr.line_msgs("a").is_empty());
        mgr.stop_all();
        assert!(mgr.key_msgs("char", "x").is_empty());
    }
}

// ─── Bounded terminal input unit tests ─────────────────────────────────────

#[cfg(all(test, not(target_arch = "wasm32"), feature = "tui"))]
mod bounded_input_tests {
    use super::*;

    fn lines(input: &[u8], max: usize) -> Vec<BoundedLine> {
        let mut reader = std::io::BufReader::with_capacity(4, input);
        let mut out = Vec::new();
        while let Ok(Some(line)) = read_bounded_line(&mut reader, max) {
            out.push(line);
        }
        out
    }

    #[test]
    fn lines_within_the_cap_are_delivered_without_terminators() {
        assert_eq!(
            lines(b"ab\r\ncd\nef", 8),
            vec![
                BoundedLine::Line("ab".into()),
                BoundedLine::Line("cd".into()),
                BoundedLine::Line("ef".into()),
            ]
        );
    }

    #[test]
    fn a_line_at_exactly_the_cap_is_delivered() {
        assert_eq!(lines(b"abcd\n", 4), vec![BoundedLine::Line("abcd".into())]);
        assert_eq!(
            lines(b"abcd\r\n", 4),
            vec![BoundedLine::Line("abcd".into())]
        );
    }

    #[test]
    fn a_line_one_byte_past_the_cap_is_dropped_whole() {
        // The over-long line is consumed through its terminator; the next line
        // is read intact, never a truncated prefix of the dropped one.
        assert_eq!(
            lines(b"abcde\nok\n", 4),
            vec![BoundedLine::TooLong, BoundedLine::Line("ok".into())]
        );
        assert_eq!(lines(b"abcde", 4), vec![BoundedLine::TooLong]);
    }

    #[test]
    fn a_non_utf8_line_is_reported() {
        assert_eq!(lines(&[0xff, b'\n'], 4), vec![BoundedLine::NotUtf8]);
    }

    #[test]
    fn the_budget_blocks_past_its_capacity_until_a_permit_returns() {
        let budget = InputBudget::new(2);
        let first = budget.acquire(|| false);
        let second = budget.acquire(|| false);
        assert!(first.is_some() && second.is_some());
        // Full: a closed loop makes the waiting reader give up instead of queuing.
        assert!(budget.acquire(|| true).is_none());
        drop(first);
        assert!(budget.acquire(|| true).is_some());
    }
}

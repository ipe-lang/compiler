//! The one shutdown owner of a served app.
//!
//! A serve site arms the owner before it binds and hands the [`Armed`] token to
//! `serve_app`, whose only success value is [`Stopped`]. [`Stopped`] is built
//! only from [`PoolsClosed`], which only [`close_owned_pools`] mints, so a
//! served app that returns `Ok` has drained and closed every owned pool.
//!
//! The first `SIGTERM` or `SIGINT` (Windows: Ctrl-C, Ctrl-Break, or a console
//! close, logoff or shutdown event) runs the serve sites' teardown hooks,
//! writes the one `shutting down` line and flips the phase to draining. Every
//! long-lived task (an SSE body, an upgraded WebSocket, a stream body) selects
//! on [`Drain::wait`] and ends. A second signal during the drain ends the
//! process at once with `128 + signo`. Every wait is bounded by the grace
//! window, measured from the first signal, or by an internal deadline.
//!
//! Work that can reach an owned pool (a request, a web Cmd) holds a
//! [`WorkGuard`]. The drain lets that work finish within the grace; then
//! [`Armed::cancel_work`] flips the phase to closing, which cancels the work
//! still running, and mints the [`WorkSettled`] proof [`close_owned_pools`]
//! requires, so no counted work outlives the pools it uses.
//!
//! A signal the process inherited as ignored stays ignored (Linux).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::{Notify, mpsc, watch};
use tokio::time::Instant;

/// How long one owned pool's close may take.
#[cfg(feature = "db")]
pub const DB_CLOSE_DEADLINE: Duration = Duration::from_secs(2);

/// How long cancelled work may take to stop before the pools close anyway.
pub const WORK_CANCEL_DEADLINE: Duration = Duration::from_millis(500);

/// The longest the stop may take past the grace: the work-cancel deadline,
/// then one [`DB_CLOSE_DEADLINE`] per close stage, the stages running one
/// after another. The bound the shutdown tests hold the exit to;
/// `server_shutdown_e2e` mirrors it.
#[cfg(all(feature = "db", test))]
pub const POOLS_CLOSE_BOUND: Duration = DB_CLOSE_DEADLINE
    .saturating_mul(crate::db::CLOSE_STAGES as u32)
    .saturating_add(WORK_CANCEL_DEADLINE);

/// How long a draining WebSocket's close frame may take to send.
pub const WS_CLOSE_DEADLINE: Duration = Duration::from_secs(1);

/// The most long-lived tasks the drain tracks at once.
const LIVE_CEILING: usize = 1 << 20;

/// The most units of pool-reaching work the shutdown counts at once.
pub const WORK_CEILING: usize = 1 << 20;

/// The bit of the work state that marks the phase closing; the bits below
/// it are the count.
const CLOSING_BIT: usize = 1 << (usize::BITS - 1);

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the work ceiling could reach the closing bit [ledger #boundary]
const _: () = assert!(WORK_CEILING < CLOSING_BIT);

/// The most signals queued between the OS listeners and the owner.
const SIGNAL_QUEUE: usize = 8;

/// The grace window a drain waits for in-flight work, from the first signal.
///
/// Zero is accepted and means the drain does not wait.
pub const SHUTDOWN_GRACE_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_WEB_SHUTDOWN_GRACE_MS",
    1500,
    crate::system::ZeroCeiling::Accepted,
    "decimal millisecond count",
);

/// The shutdown grace window, resolved by a serve site before it arms.
///
/// # Errors
///
/// The refusal of a set `IPE_WEB_SHUTDOWN_GRACE_MS` that is not a millisecond
/// count.
pub fn shutdown_grace() -> Result<Duration, crate::system::EnvCeilingRefusal> {
    SHUTDOWN_GRACE_CEILING.read().map(Duration::from_millis)
}

/// Whether a served app still accepts work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Accepting connections.
    Serving,
    /// Draining after the first signal: streams end, work may still finish.
    Draining,
    /// Closing after the grace: work still running is cancelled.
    Closing,
}

/// A request to stop the process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// `SIGINT`, Ctrl-C or Ctrl-Break.
    Interrupt,
    /// `SIGTERM`, or a Windows console close, logoff or shutdown event.
    Terminate,
}

impl Signal {
    /// The exit status of a process this signal forces to end: `128 + signo`.
    #[must_use]
    pub const fn forced_exit_code(self) -> i32 {
        match self {
            Self::Interrupt => 130,
            Self::Terminate => 143,
        }
    }
}

/// Proof that the phase is closing and the counted work was given its
/// deadline to stop; only [`Armed::cancel_work`] mints one.
#[derive(Debug)]
pub struct WorkSettled {
    _private: (),
}

/// Proof that every owned pool's close ran under its deadline.
#[derive(Debug)]
pub struct PoolsClosed {
    _private: (),
}

/// Proof that a served app drained and closed its owned pools.
#[derive(Debug)]
pub struct Stopped {
    _proof: PoolsClosed,
}

impl Stopped {
    /// The stop the closed pools prove.
    #[must_use]
    pub const fn after(proof: PoolsClosed) -> Self {
        Self { _proof: proof }
    }
}

/// One teardown step a serve site runs on the first signal.
pub type Hook = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

/// A serve site's log tag and the teardown hooks its first signal runs.
pub struct ShutdownPlan {
    tag: &'static str,
    hooks: Vec<Hook>,
}

impl ShutdownPlan {
    /// A plan logged under `tag` whose first hook marks readiness as draining.
    #[must_use]
    pub fn new(tag: &'static str) -> Self {
        Self::bare(tag).then(|| async { mark_draining() })
    }

    /// The `Server.listen` plan.
    #[must_use]
    pub fn server() -> Self {
        Self::new("http.server")
    }

    /// A plan with no hooks.
    #[must_use]
    pub const fn bare(tag: &'static str) -> Self {
        Self {
            tag,
            hooks: Vec::new(),
        }
    }

    /// This plan with `hook` run after its other hooks.
    #[must_use]
    pub fn then<F, Fut>(mut self, hook: F) -> Self
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.hooks.push(Box::new(move || Box::pin(hook())));
        self
    }
}

/// Flip readiness to draining.
#[cfg(feature = "web")]
fn mark_draining() {
    crate::web::observability::mark_draining();
}
/// Flip readiness to draining: no readiness probe without the served `web` surface.
#[cfg(not(feature = "web"))]
const fn mark_draining() {}

/// How the owner ends the process on a second signal.
type Exit = Box<dyn Fn(i32) + Send + Sync>;

/// The pool registry a stop closes.
#[cfg(feature = "db")]
type PoolSet = &'static crate::db::OwnedPools;
/// The pool registry a stop closes: none without `db`.
#[cfg(not(feature = "db"))]
type PoolSet = NoPools;

/// The empty pool registry of a build without `db`.
#[cfg(not(feature = "db"))]
#[derive(Clone, Copy)]
struct NoPools;

/// The process's pool registry.
#[cfg(feature = "db")]
fn process_pools() -> PoolSet {
    crate::db::process_pools()
}
/// The process's pool registry: none without `db`.
#[cfg(not(feature = "db"))]
const fn process_pools() -> PoolSet {
    NoPools
}

/// The long-lived tasks in flight and the wake-up for their last end.
struct Live {
    count: AtomicUsize,
    idle: Notify,
}

/// The pool-reaching work in flight and the wake-up for its last end.
///
/// The count and the closing mark share one atomic, so a unit either is
/// counted before the mark is set, or sees the mark and is born cancelled.
#[derive(Default)]
struct Work {
    state: AtomicUsize,
    idle: Notify,
}

impl Work {
    /// The units in flight.
    fn count(&self) -> usize {
        self.state.load(Ordering::SeqCst) & !CLOSING_BIT
    }

    /// Resolve once no unit is in flight.
    async fn settled(&self) {
        loop {
            let idle = self.idle.notified();
            tokio::pin!(idle);
            idle.as_mut().enable();
            if self.count() == 0 {
                return;
            }
            idle.await;
        }
    }
}

/// The shutdown state one armed owner keeps.
struct Shutdown {
    tag: &'static str,
    phase: watch::Sender<Phase>,
    plans: Mutex<Vec<ShutdownPlan>>,
    signalled_at: OnceLock<Instant>,
    grace: Duration,
    live: Arc<Live>,
    work: Arc<Work>,
    pools: PoolSet,
}

impl Shutdown {
    /// The grace left since the first signal; the whole grace before it.
    fn remaining_grace(&self) -> Duration {
        self.signalled_at
            .get()
            .map_or(self.grace, |at| self.grace.saturating_sub(at.elapsed()))
    }

    /// Run every plan's hooks under the grace, write the line, then drain.
    async fn teardown(&self) {
        let _ = self.signalled_at.set(Instant::now());
        let plans = std::mem::take(&mut *self.plans.lock().unwrap_or_else(|e| e.into_inner()));
        for hook in plans.into_iter().flat_map(|plan| plan.hooks) {
            let _ = tokio::time::timeout(self.remaining_grace(), hook()).await;
        }
        crate::system::emit_runtime_log_stdout(self.tag, "shutting down");
        self.phase.send_if_modified(|phase| {
            let serving = *phase == Phase::Serving;
            if serving {
                *phase = Phase::Draining;
            }
            serving
        });
    }

    /// A drain handle over this owner.
    fn drain(&self) -> Drain {
        Drain {
            phase: Some(self.phase.subscribe()),
            live: Some(Arc::clone(&self.live)),
        }
    }

    /// Count one unit of work, cancelled once the phase is closing.
    ///
    /// A unit started after the closing mark is uncounted and born cancelled.
    fn work_guard(&self) -> Result<WorkGuard, WorkFull> {
        let counted = self
            .work
            .state
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |state| {
                if state & CLOSING_BIT == 0 {
                    state.checked_add(1).filter(|_| state < WORK_CEILING)
                } else {
                    None
                }
            });
        match counted {
            Ok(_) => Ok(WorkGuard {
                cancel: Cancel::OnClosing(self.phase.subscribe()),
                work: Some(Arc::clone(&self.work)),
            }),
            Err(state) if state & CLOSING_BIT != 0 => Ok(WorkGuard {
                cancel: Cancel::Already,
                work: None,
            }),
            Err(_) => Err(WorkFull),
        }
    }
}

/// Run the teardown on the first signal; end the process on the second.
///
/// The teardown runs alongside the source, so a second signal is honoured
/// even while a hook is still running.
async fn run_signals(shutdown: Arc<Shutdown>, mut source: mpsc::Receiver<Signal>, exit: Exit) {
    if source.recv().await.is_none() {
        return;
    }
    let teardown = shutdown.teardown();
    tokio::pin!(teardown);
    let mut torn_down = false;
    loop {
        tokio::select! {
            biased;
            next = source.recv() => {
                match next {
                    Some(signal) => {
                        crate::system::emit_runtime_log(
                            shutdown.tag,
                            "forcing exit (second signal)",
                        );
                        exit(signal.forced_exit_code());
                    }
                    None if !torn_down => teardown.as_mut().await,
                    None => {}
                }
                return;
            }
            () = teardown.as_mut(), if !torn_down => torn_down = true,
        }
    }
}

/// A slot holding the armed owner, if any.
type Slot = Mutex<Option<Arc<Shutdown>>>;

/// The process's armed owner.
static PROCESS: Slot = Mutex::new(None);

/// Proof that the shutdown owner was armed for a serve site.
pub struct Armed {
    shutdown: Arc<Shutdown>,
}

impl Armed {
    /// A drain handle over the armed owner.
    #[must_use]
    pub fn drain(&self) -> Drain {
        self.shutdown.drain()
    }

    /// Whether the first signal already flipped the phase.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        *self.shutdown.phase.borrow() != Phase::Serving
    }

    /// The work count of the armed owner, for a serve site's own work.
    #[must_use]
    pub fn work_count(&self) -> WorkCount {
        WorkCount {
            shutdown: Some(Arc::clone(&self.shutdown)),
        }
    }

    /// The grace left since the first signal.
    #[must_use]
    pub fn remaining_grace(&self) -> Duration {
        self.shutdown.remaining_grace()
    }

    /// The long-lived tasks in flight.
    #[cfg(test)]
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.shutdown.live.count.load(Ordering::SeqCst)
    }

    /// Wait until no long-lived task and no unit of work is in flight, at
    /// most the grace left.
    pub async fn settle_live(&self) {
        let live = &self.shutdown.live;
        let work = &self.shutdown.work;
        let settled = async {
            loop {
                let live_idle = live.idle.notified();
                let work_idle = work.idle.notified();
                tokio::pin!(live_idle, work_idle);
                live_idle.as_mut().enable();
                work_idle.as_mut().enable();
                if live.count.load(Ordering::SeqCst) == 0 && work.count() == 0 {
                    return;
                }
                tokio::select! {
                    () = live_idle => {}
                    () = work_idle => {}
                }
            }
        };
        let _ = tokio::time::timeout(self.remaining_grace(), settled).await;
    }

    /// Flip the phase to closing, cancelling the work still running, and wait
    /// at most [`WORK_CANCEL_DEADLINE`] for it to stop.
    ///
    /// The first call logs the units it cancelled and any that did not stop.
    pub async fn cancel_work(&self) -> WorkSettled {
        let tag = self.shutdown.tag;
        self.cancel_logging(|line| crate::system::emit_runtime_log(tag, &line))
            .await
    }

    /// [`Armed::cancel_work`], its log lines written through `log`.
    async fn cancel_logging(&self, mut log: impl FnMut(String)) -> WorkSettled {
        let shutdown = &self.shutdown;
        let before = shutdown.work.state.fetch_or(CLOSING_BIT, Ordering::SeqCst);
        shutdown.phase.send_replace(Phase::Closing);
        let first = before & CLOSING_BIT == 0;
        let running = before & !CLOSING_BIT;
        if first && running > 0 {
            log(cancelled_line(running, shutdown.grace));
        }
        let _ = tokio::time::timeout(WORK_CANCEL_DEADLINE, shutdown.work.settled()).await;
        let left = shutdown.work.count();
        if first && left > 0 {
            log(stuck_line(left));
        }
        WorkSettled { _private: () }
    }
}

/// The line naming the work the grace cut.
fn cancelled_line(running: usize, grace: Duration) -> String {
    format!(
        "shutting down: cancelled {running} tasks still running after the {} ms grace ({})",
        grace.as_millis(),
        SHUTDOWN_GRACE_CEILING.name(),
    )
}

/// The line naming the work that outlived its cancel deadline.
fn stuck_line(left: usize) -> String {
    format!(
        "{left} tasks did not stop within {} ms; closing the pools anyway",
        WORK_CANCEL_DEADLINE.as_millis(),
    )
}

/// A handle that counts work on one armed owner, or on none.
#[derive(Clone)]
pub struct WorkCount {
    shutdown: Option<Arc<Shutdown>>,
}

impl WorkCount {
    /// Count one unit of work on this owner.
    ///
    /// # Errors
    ///
    /// [`WorkFull`] when the owner already counts [`WORK_CEILING`] units.
    pub fn guard(&self) -> Result<WorkGuard, WorkFull> {
        self.shutdown
            .as_ref()
            .map_or_else(|| Ok(WorkGuard::never()), |shutdown| shutdown.work_guard())
    }
}

/// The work count of the process's armed owner, or of none.
#[must_use]
pub fn work_count() -> WorkCount {
    WorkCount {
        shutdown: PROCESS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned(),
    }
}

/// Count one unit of pool-reaching work on the process's armed owner.
///
/// With no armed owner the guard is never cancelled.
///
/// # Errors
///
/// [`WorkFull`] when the owner already counts [`WORK_CEILING`] units.
pub fn work() -> Result<WorkGuard, WorkFull> {
    work_count().guard()
}

/// The refusal of a unit of work past [`WORK_CEILING`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkFull;

/// When a unit of work is cancelled.
enum Cancel {
    /// No armed owner: never.
    Never,
    /// When the owner's phase turns closing.
    OnClosing(watch::Receiver<Phase>),
    /// Started after the closing mark: at once.
    Already,
}

/// One unit of pool-reaching work, counted until it drops.
pub struct WorkGuard {
    cancel: Cancel,
    work: Option<Arc<Work>>,
}

impl WorkGuard {
    /// A guard no owner counts or cancels.
    #[must_use]
    pub const fn never() -> Self {
        Self {
            cancel: Cancel::Never,
            work: None,
        }
    }

    /// Resolve once this work is cancelled; never for an unarmed guard.
    ///
    /// Cancel-safe: the current phase is read on every call. An owner gone
    /// before the close cancels too.
    pub async fn cancelled(&mut self) {
        match &mut self.cancel {
            Cancel::Never => std::future::pending::<()>().await,
            Cancel::Already => {}
            Cancel::OnClosing(phase) => {
                let _ = phase.wait_for(|p| *p == Phase::Closing).await;
            }
        }
    }
}

impl Drop for WorkGuard {
    fn drop(&mut self) {
        let Some(work) = self.work.as_ref() else {
            return;
        };
        let before = work.state.fetch_sub(1, Ordering::SeqCst);
        if before & !CLOSING_BIT == 1 {
            work.idle.notify_waiters();
        }
    }
}

/// Arm the process's shutdown owner for a serve site, before it binds.
///
/// The first arm registers the signal listeners; a later one adds its plan to
/// the armed owner and keeps the first grace.
///
/// # Errors
///
/// A signal listener that cannot be registered refuses startup, as does an
/// arm outside a tokio runtime.
pub fn arm(plan: ShutdownPlan, grace: Duration) -> std::io::Result<Armed> {
    arm_in(
        &PROCESS,
        plan,
        grace,
        os_signals,
        Box::new(|code| {
            crate::system::exit_process(code);
        }),
        process_pools(),
    )
}

/// Arm the owner held in `slot`, its signals from `register`.
fn arm_in(
    slot: &Slot,
    plan: ShutdownPlan,
    grace: Duration,
    register: impl FnOnce() -> std::io::Result<mpsc::Receiver<Signal>>,
    exit: Exit,
    pools: PoolSet,
) -> std::io::Result<Armed> {
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|_| std::io::Error::other("the shutdown owner needs a running async runtime"))?;
    let mut held = slot.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(shutdown) = held.as_ref() {
        shutdown
            .plans
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(plan);
        return Ok(Armed {
            shutdown: Arc::clone(shutdown),
        });
    }
    let source = register()?;
    let (phase, _) = watch::channel(Phase::Serving);
    let shutdown = Arc::new(Shutdown {
        tag: plan.tag,
        phase,
        plans: Mutex::new(vec![plan]),
        signalled_at: OnceLock::new(),
        grace,
        live: Arc::new(Live {
            count: AtomicUsize::new(0),
            idle: Notify::new(),
        }),
        work: Arc::new(Work::default()),
        pools,
    });
    runtime.spawn(run_signals(Arc::clone(&shutdown), source, exit));
    *held = Some(Arc::clone(&shutdown));
    Ok(Armed { shutdown })
}

/// Close every owned pool, each under the pool-close deadline; the spill pool last.
///
/// The [`WorkSettled`] proof orders the close after the work that may reach
/// a pool was cancelled.
pub async fn close_owned_pools(armed: &Armed, _settled: WorkSettled) -> PoolsClosed {
    #[cfg(feature = "db")]
    armed.shutdown.pools.close_all(DB_CLOSE_DEADLINE).await;
    #[cfg(not(feature = "db"))]
    let NoPools = armed.shutdown.pools;
    PoolsClosed { _private: () }
}

/// A long-lived task's view of the shutdown: when to end, and its live count.
#[derive(Clone)]
pub struct Drain {
    phase: Option<watch::Receiver<Phase>>,
    live: Option<Arc<Live>>,
}

impl Drain {
    /// A handle that never drains, for a task no armed owner serves.
    #[must_use]
    pub const fn never() -> Self {
        Self {
            phase: None,
            live: None,
        }
    }

    /// Resolve once the phase is past serving; never for an unarmed handle.
    ///
    /// Cancel-safe: the current phase is read on every call.
    pub async fn wait(&mut self) {
        if let Some(phase) = self.phase.as_mut()
            && phase.wait_for(|p| *p != Phase::Serving).await.is_ok()
        {
            return;
        }
        std::future::pending::<()>().await;
    }

    /// Count one long-lived task until the guard drops.
    ///
    /// `None` when the drain already tracks its ceiling of tasks.
    #[must_use]
    pub fn hold(&self) -> Option<LiveGuard> {
        let Some(live) = self.live.as_ref() else {
            return Some(LiveGuard { live: None });
        };
        live.count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                n.checked_add(1).filter(|_| n < LIVE_CEILING)
            })
            .ok()
            .map(|_| LiveGuard {
                live: Some(Arc::clone(live)),
            })
    }
}

/// The drain handle of the process's armed owner, or one that never drains.
#[must_use]
pub fn drain() -> Drain {
    PROCESS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map_or_else(Drain::never, |shutdown| shutdown.drain())
}

/// One long-lived task the drain waits for, counted until it drops.
pub struct LiveGuard {
    live: Option<Arc<Live>>,
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        let Some(live) = self.live.as_ref() else {
            return;
        };
        let before = live
            .count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                Some(n.saturating_sub(1))
            });
        if matches!(before, Ok(1)) {
            live.idle.notify_waiters();
        }
    }
}

/// Forward each delivery of `listener` into `tx` as `signal`, on its own task.
macro_rules! forward {
    ($listener:expr, $tx:expr, $signal:expr) => {{
        let mut listener = $listener;
        let tx = $tx;
        tokio::spawn(async move {
            while listener.recv().await.is_some() {
                if tx.send($signal).await.is_err() {
                    return;
                }
            }
        });
    }};
}

/// Register the `SIGTERM` and `SIGINT` listeners the process did not inherit
/// as ignored.
#[cfg(unix)]
fn os_signals() -> std::io::Result<mpsc::Receiver<Signal>> {
    use tokio::signal::unix::{SignalKind, signal};
    let ignored = inherited_ignored();
    let (tx, rx) = mpsc::channel(SIGNAL_QUEUE);
    for (kind, which) in [
        (SignalKind::terminate(), Signal::Terminate),
        (SignalKind::interrupt(), Signal::Interrupt),
    ] {
        if !ignored.contains(kind.as_raw_value()) {
            forward!(signal(kind)?, tx.clone(), which);
        }
    }
    Ok(rx)
}

/// A Windows console control event.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConsoleEvent {
    CtrlC,
    CtrlBreak,
    Close,
    Logoff,
    Shutdown,
}

#[cfg(any(windows, test))]
impl ConsoleEvent {
    /// The stop request this event makes.
    const fn signal(self) -> Signal {
        match self {
            Self::CtrlC | Self::CtrlBreak => Signal::Interrupt,
            Self::Close | Self::Logoff | Self::Shutdown => Signal::Terminate,
        }
    }
}

/// Register the console control listeners: Ctrl-C and Ctrl-Break must
/// register; close, logoff and shutdown start the drain when they can.
#[cfg(windows)]
fn os_signals() -> std::io::Result<mpsc::Receiver<Signal>> {
    use tokio::signal::windows;
    let (tx, rx) = mpsc::channel(SIGNAL_QUEUE);
    forward!(windows::ctrl_c()?, tx.clone(), ConsoleEvent::CtrlC.signal());
    forward!(
        windows::ctrl_break()?,
        tx.clone(),
        ConsoleEvent::CtrlBreak.signal()
    );
    if let Ok(close) = windows::ctrl_close() {
        forward!(close, tx.clone(), ConsoleEvent::Close.signal());
    }
    if let Ok(logoff) = windows::ctrl_logoff() {
        forward!(logoff, tx.clone(), ConsoleEvent::Logoff.signal());
    }
    if let Ok(shutdown) = windows::ctrl_shutdown() {
        forward!(shutdown, tx, ConsoleEvent::Shutdown.signal());
    }
    Ok(rx)
}

/// No stop request can be registered on this platform: startup is refused.
#[cfg(not(any(unix, windows)))]
fn os_signals() -> std::io::Result<mpsc::Receiver<Signal>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no stop signal can be registered on this platform",
    ))
}

/// A set of signals, bit `n - 1` standing for signal `n`.
/// The signals this process inherited as ignored, read once; none when the
/// status cannot be read or parsed, so a stop request is never lost to a
/// misreading.
#[cfg(target_os = "linux")]
fn inherited_ignored() -> crate::system::SignalSet {
    use crate::system::{SignalSet, StatusMask, read_self_status, status_mask};
    static READ: OnceLock<SignalSet> = OnceLock::new();
    *READ.get_or_init(|| {
        read_self_status()
            .and_then(|status| status_mask(&status, StatusMask::Ignored))
            .unwrap_or(SignalSet(0))
    })
}

/// The signals this process inherited as ignored: unread off Linux, so every
/// stop signal is registered.
#[cfg(all(unix, not(target_os = "linux")))]
const fn inherited_ignored() -> crate::system::SignalSet {
    crate::system::SignalSet(0)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::atomic::AtomicI32;

    /// How long a test waits for any one event before it fails.
    const BUDGET: Duration = Duration::from_secs(5);

    /// A drain that already tracks its ceiling of tasks, so `hold` refuses.
    #[must_use]
    pub fn full_drain() -> Drain {
        Drain {
            phase: None,
            live: Some(Arc::new(Live {
                count: AtomicUsize::new(LIVE_CEILING),
                idle: Notify::new(),
            })),
        }
    }

    /// A fresh slot, armed with `plan` over an injected signal source, whose
    /// forced exit records its code in `exited`.
    #[allow(clippy::expect_used)] // a test helper fails its test on a broken fixture
    pub fn armed_with(
        plan: ShutdownPlan,
        grace: Duration,
        exited: Arc<AtomicI32>,
    ) -> (Armed, mpsc::Sender<Signal>) {
        let slot: &'static Slot = Box::leak(Box::new(Mutex::new(None)));
        let (tx, rx) = mpsc::channel(SIGNAL_QUEUE);
        let armed = arm_in(
            slot,
            plan,
            grace,
            move || Ok(rx),
            Box::new(move |code| exited.store(code, Ordering::SeqCst)),
            test_pools(),
        )
        .expect("an injected source arms");
        (armed, tx)
    }

    /// Two serve sites armed on one fresh owner, as two listeners of one
    /// process share it.
    #[allow(clippy::expect_used)] // a test helper fails its test on a broken fixture
    #[must_use]
    pub fn armed_pair(grace: Duration) -> (Armed, Armed, mpsc::Sender<Signal>) {
        let slot: &'static Slot = Box::leak(Box::new(Mutex::new(None)));
        let (tx, rx) = mpsc::channel(SIGNAL_QUEUE);
        let pools = test_pools();
        let first = arm_in(
            slot,
            ShutdownPlan::bare("first"),
            grace,
            move || Ok(rx),
            Box::new(|_| {}),
            pools,
        )
        .expect("an injected source arms");
        let second = arm_in(
            slot,
            ShutdownPlan::bare("second"),
            grace,
            || Err(std::io::Error::other("a later arm never registers")),
            Box::new(|_| {}),
            pools,
        )
        .expect("a later arm joins the armed owner");
        (first, second, tx)
    }

    #[cfg(feature = "db")]
    fn test_pools() -> PoolSet {
        Box::leak(Box::new(crate::db::OwnedPools::new()))
    }
    #[cfg(not(feature = "db"))]
    const fn test_pools() -> PoolSet {
        NoPools
    }

    /// Wait until `exited` records a code, within the budget.
    #[allow(clippy::expect_used)] // a test helper fails its test on a broken fixture
    async fn exit_code(exited: &AtomicI32) -> i32 {
        let recorded = async {
            loop {
                let code = exited.load(Ordering::SeqCst);
                if code != 0 {
                    return code;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(BUDGET, recorded)
            .await
            .expect("the forced exit runs")
    }

    #[tokio::test]
    async fn the_first_signal_drains_once_and_the_second_forces_its_own_exit_code() {
        for (signal, code) in [(Signal::Terminate, 143), (Signal::Interrupt, 130)] {
            let runs = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&runs);
            let plan = ShutdownPlan::bare("test").then(move || async move {
                counted.fetch_add(1, Ordering::SeqCst);
            });
            let exited = Arc::new(AtomicI32::new(0));
            let (armed, tx) = armed_with(plan, Duration::from_secs(1), Arc::clone(&exited));
            let mut drain = armed.drain();
            tx.send(signal).await.expect("the owner listens");
            tokio::time::timeout(BUDGET, drain.wait())
                .await
                .expect("the first signal drains");
            assert!(armed.is_draining());
            assert_eq!(exited.load(Ordering::SeqCst), 0, "one signal never forces");
            tx.send(signal).await.expect("the owner still listens");
            assert_eq!(exit_code(&exited).await, code);
            assert_eq!(runs.load(Ordering::SeqCst), 1, "the hooks run once");
        }
    }

    #[tokio::test]
    async fn a_second_signal_during_a_stuck_hook_still_forces_the_exit() {
        let plan = ShutdownPlan::bare("test").then(std::future::pending::<()>);
        let exited = Arc::new(AtomicI32::new(0));
        let (_armed, tx) = armed_with(plan, Duration::from_secs(3600), Arc::clone(&exited));
        tx.send(Signal::Interrupt).await.expect("the owner listens");
        tx.send(Signal::Terminate).await.expect("the owner listens");
        assert_eq!(exit_code(&exited).await, 143);
    }

    #[tokio::test]
    async fn a_signal_before_serve_skips_accepting_and_still_stops() {
        let exited = Arc::new(AtomicI32::new(0));
        let (armed, tx) = armed_with(
            ShutdownPlan::bare("test"),
            Duration::from_secs(3600),
            exited,
        );
        let mut drain = armed.drain();
        tx.send(Signal::Terminate).await.expect("the owner listens");
        tokio::time::timeout(BUDGET, drain.wait())
            .await
            .expect("the signal drains");
        let host = crate::server::RecordedHost::record(crate::app_config::ListenHost::Loopback(
            crate::app_config::LoopbackIp::DEFAULT,
        ));
        let app = crate::server::bind_app_listener("test", host, 0)
            .await
            .expect("a loopback port binds");
        let served = tokio::time::timeout(
            BUDGET,
            crate::server::serve_app(app, axum::Router::new(), armed),
        )
        .await
        .expect("a drained owner never accepts");
        assert!(matches!(served, Ok(Stopped { .. })));
    }

    #[tokio::test]
    async fn a_listener_that_cannot_register_refuses_the_arm() {
        let slot = Mutex::new(None);
        let refused = arm_in(
            &slot,
            ShutdownPlan::bare("test"),
            Duration::ZERO,
            || Err(std::io::Error::other("refused")),
            Box::new(|_| {}),
            test_pools(),
        );
        assert!(refused.is_err());
        assert!(slot.lock().expect("no test panicked").is_none());
    }

    #[test]
    fn an_arm_outside_a_runtime_is_refused() {
        let slot = Mutex::new(None);
        let refused = arm_in(
            &slot,
            ShutdownPlan::bare("test"),
            Duration::ZERO,
            || Ok(mpsc::channel(1).1),
            Box::new(|_| {}),
            test_pools(),
        );
        assert!(refused.is_err());
    }

    #[test]
    fn the_grace_ceiling_honours_the_shared_contract() {
        crate::system::assert_env_ceiling_contract(SHUTDOWN_GRACE_CEILING);
    }

    #[test]
    fn the_live_count_refuses_past_its_ceiling_and_frees_on_drop() {
        let live = Arc::new(Live {
            count: AtomicUsize::new(LIVE_CEILING),
            idle: Notify::new(),
        });
        let drain = Drain {
            phase: None,
            live: Some(Arc::clone(&live)),
        };
        assert!(drain.hold().is_none(), "the ceiling refuses one more");
        live.count.store(0, Ordering::SeqCst);
        let held = drain.hold();
        assert!(held.is_some());
        assert_eq!(live.count.load(Ordering::SeqCst), 1);
        drop(held);
        assert_eq!(live.count.load(Ordering::SeqCst), 0);
    }

    /// An owner armed over an injected source that never signals.
    fn quiet_owner(grace: Duration) -> (Armed, mpsc::Sender<Signal>) {
        armed_with(
            ShutdownPlan::bare("test"),
            grace,
            Arc::new(AtomicI32::new(0)),
        )
    }

    #[allow(clippy::expect_used)] // a refused guard fails the test
    #[tokio::test(start_paused = true)]
    async fn counted_work_holds_the_settle_until_its_guard_drops() {
        let (armed, _tx) = quiet_owner(Duration::from_secs(3600));
        let guard = armed.work_count().guard().expect("one unit fits");
        assert_eq!(armed.shutdown.work.count(), 1);
        let settle = armed.settle_live();
        tokio::pin!(settle);
        let held = tokio::time::timeout(Duration::from_secs(1), settle.as_mut()).await;
        assert!(held.is_err(), "a counted unit holds the settle");
        drop(guard);
        tokio::time::timeout(Duration::from_secs(1), settle)
            .await
            .expect("the last unit's drop ends the settle");
    }

    #[allow(clippy::expect_used)] // a refused guard fails the test
    #[tokio::test(start_paused = true)]
    async fn past_the_grace_the_cancel_ends_the_work_still_running() {
        let (armed, _tx) = quiet_owner(Duration::ZERO);
        let mut guard = armed.work_count().guard().expect("one unit fits");
        let unit = tokio::spawn(async move { guard.cancelled().await });
        armed.settle_live().await;
        let started = Instant::now();
        let mut lines = Vec::new();
        let _settled = armed.cancel_logging(|line| lines.push(line)).await;
        assert!(
            started.elapsed() < WORK_CANCEL_DEADLINE,
            "a cancelled unit stops before the deadline"
        );
        assert_eq!(*armed.shutdown.phase.borrow(), Phase::Closing);
        assert_eq!(armed.shutdown.work.count(), 0);
        assert_eq!(
            lines,
            [
                "shutting down: cancelled 1 tasks still running after the 0 ms grace \
                 (IPE_WEB_SHUTDOWN_GRACE_MS)"
            ]
        );
        unit.await.expect("the cancelled unit ends");
    }

    #[allow(clippy::expect_used)] // a refused guard fails the test
    #[tokio::test(start_paused = true)]
    async fn work_that_never_stops_holds_the_cancel_only_to_its_deadline() {
        let (armed, _tx) = quiet_owner(Duration::ZERO);
        let _stuck = armed.work_count().guard().expect("one unit fits");
        let started = Instant::now();
        let mut lines = Vec::new();
        let _settled = tokio::time::timeout(
            WORK_CANCEL_DEADLINE.saturating_add(Duration::from_secs(1)),
            armed.cancel_logging(|line| lines.push(line)),
        )
        .await
        .expect("the cancel wait is bounded");
        assert!(started.elapsed() >= WORK_CANCEL_DEADLINE);
        assert_eq!(
            lines,
            [
                "shutting down: cancelled 1 tasks still running after the 0 ms grace \
                 (IPE_WEB_SHUTDOWN_GRACE_MS)",
                "1 tasks did not stop within 500 ms; closing the pools anyway",
            ]
        );
    }

    #[allow(clippy::expect_used)] // a refused guard fails the test
    #[tokio::test(start_paused = true)]
    async fn work_after_the_close_is_born_cancelled_and_the_ceiling_refuses() {
        let (armed, _tx) = quiet_owner(Duration::ZERO);
        let count = armed.work_count();
        armed
            .shutdown
            .work
            .state
            .store(WORK_CEILING, Ordering::SeqCst);
        assert_eq!(count.guard().err(), Some(WorkFull), "the ceiling refuses");
        armed.shutdown.work.state.store(0, Ordering::SeqCst);
        let _settled = armed.cancel_work().await;
        let mut late = count.guard().expect("a unit past the close is admitted");
        assert_eq!(armed.shutdown.work.count(), 0, "it is not counted");
        tokio::time::timeout(Duration::from_millis(1), late.cancelled())
            .await
            .expect("it is born cancelled");
        let mut unowned = WorkGuard::never();
        let waited = tokio::time::timeout(Duration::from_secs(1), unowned.cancelled()).await;
        assert!(waited.is_err(), "work no owner counts is never cancelled");
    }

    #[tokio::test]
    async fn a_closing_phase_still_drains_and_a_late_signal_keeps_it() {
        let (armed, tx) = quiet_owner(Duration::ZERO);
        let mut drain = armed.drain();
        let _settled = armed.cancel_work().await;
        tokio::time::timeout(BUDGET, drain.wait())
            .await
            .expect("closing is past serving");
        assert!(armed.is_draining());
        tx.send(Signal::Terminate).await.expect("the owner listens");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(*armed.shutdown.phase.borrow(), Phase::Closing);
    }

    /// `server_shutdown_e2e` restates this bound as a literal; a change here
    /// must change it there.
    #[cfg(feature = "db")]
    #[test]
    fn the_pools_close_bound_is_the_one_the_e2e_mirrors() {
        assert_eq!(POOLS_CLOSE_BOUND, Duration::from_millis(4500));
    }

    #[cfg(unix)]
    #[test]
    fn an_inherited_ignore_mask_is_read_per_signal() {
        use crate::system::{StatusMask, status_mask};
        use tokio::signal::unix::SignalKind;
        let status = "Name:\tapp\nSigIgn:\t0000000000004002\nSigCgt:\t0\n";
        let ignored = status_mask(status, StatusMask::Ignored);
        assert!(ignored.is_some_and(|set| set.contains(SignalKind::terminate().as_raw_value())));
        assert!(ignored.is_some_and(|set| set.contains(SignalKind::interrupt().as_raw_value())));
        assert!(ignored.is_some_and(|set| !set.contains(SignalKind::hangup().as_raw_value())));
        assert_eq!(status_mask("SigIgn:\tnot-hex\n", StatusMask::Ignored), None);
    }

    #[test]
    fn console_events_map_to_their_stop_request() {
        assert_eq!(ConsoleEvent::CtrlC.signal(), Signal::Interrupt);
        assert_eq!(ConsoleEvent::CtrlBreak.signal(), Signal::Interrupt);
        assert_eq!(ConsoleEvent::Close.signal(), Signal::Terminate);
        assert_eq!(ConsoleEvent::Logoff.signal(), Signal::Terminate);
        assert_eq!(ConsoleEvent::Shutdown.signal(), Signal::Terminate);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn a_console_close_event_starts_the_drain() {
        let exited = Arc::new(AtomicI32::new(0));
        let (armed, tx) = armed_with(ShutdownPlan::bare("test"), Duration::ZERO, exited);
        let mut drain = armed.drain();
        tx.send(ConsoleEvent::Close.signal())
            .await
            .expect("the owner listens");
        tokio::time::timeout(BUDGET, drain.wait())
            .await
            .expect("a close event drains");
        assert!(armed.is_draining());
    }
}

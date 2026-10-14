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

/// How long a draining WebSocket's close frame may take to send.
pub const WS_CLOSE_DEADLINE: Duration = Duration::from_secs(1);

/// The most long-lived tasks the drain tracks at once.
const LIVE_CEILING: usize = 1 << 20;

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
    /// Draining after the first signal.
    Draining,
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
#[cfg(feature = "web-core")]
fn mark_draining() {
    crate::web::observability::mark_draining();
}
/// Flip readiness to draining: no readiness probe without `web-core`.
#[cfg(not(feature = "web-core"))]
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

/// The shutdown state one armed owner keeps.
struct Shutdown {
    tag: &'static str,
    phase: watch::Sender<Phase>,
    plans: Mutex<Vec<ShutdownPlan>>,
    signalled_at: OnceLock<Instant>,
    grace: Duration,
    live: Arc<Live>,
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
        self.phase.send_replace(Phase::Draining);
    }

    /// A drain handle over this owner.
    fn drain(&self) -> Drain {
        Drain {
            phase: Some(self.phase.subscribe()),
            live: Some(Arc::clone(&self.live)),
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
        *self.shutdown.phase.borrow() == Phase::Draining
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

    /// Wait until no long-lived task is in flight, at most the grace left.
    pub async fn settle_live(&self) {
        let live = &self.shutdown.live;
        let settled = async {
            loop {
                let idle = live.idle.notified();
                tokio::pin!(idle);
                idle.as_mut().enable();
                if live.count.load(Ordering::SeqCst) == 0 {
                    return;
                }
                idle.await;
            }
        };
        let _ = tokio::time::timeout(self.remaining_grace(), settled).await;
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
        pools,
    });
    runtime.spawn(run_signals(Arc::clone(&shutdown), source, exit));
    *held = Some(Arc::clone(&shutdown));
    Ok(Armed { shutdown })
}

/// Close every owned pool, each under the pool-close deadline; the spill pool last.
pub async fn close_owned_pools(armed: &Armed) -> PoolsClosed {
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

    /// Resolve once the phase is draining; never for an unarmed handle.
    ///
    /// Cancel-safe: the current phase is read on every call.
    pub async fn wait(&mut self) {
        if let Some(phase) = self.phase.as_mut()
            && phase.wait_for(|p| *p == Phase::Draining).await.is_ok()
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
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SignalSet(u64);

#[cfg(unix)]
impl SignalSet {
    /// Whether `signal` is in the set; a number outside `1..=64` never is.
    fn contains(self, signal: std::ffi::c_int) -> bool {
        u32::try_from(signal)
            .ok()
            .and_then(|number| number.checked_sub(1))
            .and_then(|bit| 1u64.checked_shl(bit))
            .is_some_and(|bit| self.0 & bit != 0)
    }
}

/// The most of `/proc/self/status` read for its `SigIgn:` line.
#[cfg(target_os = "linux")]
const STATUS_READ_CEILING: u64 = 64 * 1024;

/// The signals this process inherited as ignored, read once; none when the
/// status cannot be read, so a stop request is never lost to a misreading.
#[cfg(target_os = "linux")]
fn inherited_ignored() -> SignalSet {
    static READ: OnceLock<SignalSet> = OnceLock::new();
    *READ.get_or_init(|| {
        use std::io::Read as _;
        let mut status = String::new();
        let read = std::fs::File::open("/proc/self/status")
            .and_then(|file| file.take(STATUS_READ_CEILING).read_to_string(&mut status));
        if read.is_err() {
            return SignalSet(0);
        }
        SignalSet(ignored_mask(&status).unwrap_or(0))
    })
}

/// The signals this process inherited as ignored: unread off Linux, so every
/// stop signal is registered.
#[cfg(all(unix, not(target_os = "linux")))]
const fn inherited_ignored() -> SignalSet {
    SignalSet(0)
}

/// The `SigIgn:` mask of a `/proc/<pid>/status` text.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn ignored_mask(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("SigIgn:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::atomic::AtomicI32;

    /// How long a test waits for any one event before it fails.
    const BUDGET: Duration = Duration::from_secs(5);

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

    #[cfg(unix)]
    #[test]
    fn an_inherited_ignore_mask_is_read_per_signal() {
        let status = "Name:\tapp\nSigIgn:\t0000000000004002\nSigCgt:\t0\n";
        let ignored = SignalSet(ignored_mask(status).expect("the mask parses"));
        assert!(ignored.contains(15), "SIGTERM is bit 14");
        assert!(ignored.contains(2), "SIGINT is bit 1");
        assert!(!ignored.contains(1));
        assert!(!ignored.contains(0));
        assert!(!ignored.contains(65));
        assert_eq!(ignored_mask("SigIgn:\tnot-hex\n"), None);
        assert_eq!(ignored_mask("Name:\tapp\n"), None);
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

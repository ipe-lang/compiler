//! The budgets a web session's resident state and in-flight Cmds are charged against.
//!
//! Each session holds one [`Charge`] on its own [`SessionBudget`] of
//! [`SESSION_CEILING`], nested in the one process budget of [`SESSION_BUDGET`]
//! every app of the process shares. Each in-flight Cmd holds one [`CmdPermit`]
//! on its session's [`SessionCmds`] of [`SESSION_CMD_CEILING`], nested in the
//! one process budget of [`PROCESS_CMD_BUDGET`]. Both run on one engine,
//! [`Budget`]: a charge takes its units from every budget of the chain or from
//! none, each step one atomic `fetch_update`, so no budget's `used` ever passes
//! its `limit`; the units return only when the charge drops.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use crate::retained::Bytes;

/// The bytes every session of the process may hold resident together.
pub const SESSION_BUDGET: Bytes = Bytes::mib(512);

/// The bytes one session may hold resident.
pub const SESSION_CEILING: Bytes = Bytes::mib(16);

/// The fixed charge for a session's state no measure walks.
///
/// It stands for the driver task, its channels' first blocks, the
/// subscription runtime, the tab table and the store's map slot.
pub const ENTRY_OVERHEAD: Bytes = Bytes::new(256 * 1024);

/// How long an admission waits for evicted sessions to release their bytes.
pub const EVICT_WAIT: Duration = Duration::from_millis(250);

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if one session's fixed charge alone could pass its ceiling [ledger #boundary]
const _: () = assert!(ENTRY_OVERHEAD.get() < SESSION_CEILING.get());
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if one session's ceiling could pass the process budget [ledger #boundary]
const _: () = assert!(SESSION_CEILING.get() < SESSION_BUDGET.get());

/// A count a [`Budget`] is kept in.
pub trait Quantity: Copy + std::fmt::Debug {
    /// The count as a number of units.
    fn units(self) -> u64;
    /// The count of `units` units.
    fn of_units(units: u64) -> Self;
}

impl Quantity for Bytes {
    fn units(self) -> u64 {
        self.get()
    }

    fn of_units(units: u64) -> Self {
        Self::new(units)
    }
}

/// A count of in-flight Cmds, a role distinct from [`Bytes`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Cmds(u64);

impl Cmds {
    /// The count of `n` Cmds.
    #[must_use]
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    /// The count as a number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Quantity for Cmds {
    fn units(self) -> u64 {
        self.0
    }

    fn of_units(units: u64) -> Self {
        Self(units)
    }
}

/// The Cmds one session may have in flight.
pub const SESSION_CMD_CEILING: Cmds = Cmds::new(64);

/// The Cmds every session of the process may have in flight together.
///
/// It also counts the Cmds an evicted session left running, so evicting and
/// rejoining cannot escape [`SESSION_CMD_CEILING`].
pub const PROCESS_CMD_BUDGET: Cmds = Cmds::new(16_384);

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a session could admit no Cmd at all [ledger #boundary]
const _: () = assert!(SESSION_CMD_CEILING.get() > 0);
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if one session's Cmd ceiling could pass the process Cmd budget [ledger #boundary]
const _: () = assert!(SESSION_CMD_CEILING.get() < PROCESS_CMD_BUDGET.get());

/// The process budget every app's sessions are charged against.
#[must_use]
pub fn shared() -> Arc<SessionBudget> {
    static SHARED: std::sync::LazyLock<Arc<SessionBudget>> =
        std::sync::LazyLock::new(|| SessionBudget::process(SESSION_BUDGET));
    Arc::clone(&SHARED)
}

/// Which bound a refused charge would have passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverBudget {
    /// The session's own ceiling.
    Session,
    /// The process budget every session shares.
    Process,
}

/// The process Cmd budget every session's [`SessionCmds`] is nested in.
#[must_use]
pub fn shared_cmds() -> Arc<Budget<Cmds>> {
    static SHARED: std::sync::LazyLock<Arc<Budget<Cmds>>> =
        std::sync::LazyLock::new(|| Budget::process(PROCESS_CMD_BUDGET));
    Arc::clone(&SHARED)
}

/// The byte budget of a session or of the process.
pub type SessionBudget = Budget<Bytes>;

/// Bytes held against a byte budget chain, returned when dropped.
pub type Charge = Held<Bytes>;

/// A limit and the units charged against it.
#[derive(Debug)]
pub struct Budget<U> {
    limit: U,
    used: AtomicU64,
    /// The budget this one is nested in; `None` for the process budget.
    parent: Option<Arc<Self>>,
    /// Woken whenever a charge returns units to this budget.
    freed: tokio::sync::Notify,
}

impl<U: Quantity> Budget<U> {
    /// A process budget of `limit`.
    #[must_use]
    pub fn process(limit: U) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicU64::new(0),
            parent: None,
            freed: tokio::sync::Notify::new(),
        })
    }

    /// A session budget of `limit` nested in `process`.
    #[must_use]
    pub fn session(process: &Arc<Self>, limit: U) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicU64::new(0),
            parent: Some(Arc::clone(process)),
            freed: tokio::sync::Notify::new(),
        })
    }

    /// The process budget this one is nested in, itself when it is the process budget.
    #[must_use]
    pub fn process_of(self: &Arc<Self>) -> Arc<Self> {
        Arc::clone(self.parent.as_ref().unwrap_or(self))
    }

    /// The units charged against this budget now.
    #[must_use]
    pub fn used(&self) -> U {
        U::of_units(self.used.load(Ordering::Acquire))
    }

    /// The units still free under this budget's limit.
    #[must_use]
    pub fn room(&self) -> U {
        U::of_units(self.limit.units().saturating_sub(self.used().units()))
    }

    /// A future woken the next time a charge returns units to this budget.
    pub fn freed(&self) -> tokio::sync::futures::Notified<'_> {
        self.freed.notified()
    }

    /// The bound this budget's refusal names.
    const fn refusal(&self) -> OverBudget {
        if self.parent.is_some() {
            OverBudget::Session
        } else {
            OverBudget::Process
        }
    }

    /// Charge `amount` to this budget alone, or refuse leaving it unchanged.
    fn take(&self, amount: U) -> Result<(), OverBudget> {
        let limit = self.limit.units();
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(amount.units()).filter(|now| *now <= limit)
            })
            .map(drop)
            .map_err(|_| self.refusal())
    }

    /// Return `amount` to this budget alone.
    fn give(&self, amount: U) {
        // A charge returns only what it took, so the subtraction never floors;
        // saturating keeps a broken pairing from wrapping into a huge `used`.
        let _ = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                Some(used.saturating_sub(amount.units()))
            });
        self.freed.notify_waiters();
    }

    /// Charge `amount` to this budget and every budget it is nested in, or to none.
    fn take_chain(&self, amount: U) -> Result<(), OverBudget> {
        self.take(amount)?;
        if let Some(parent) = &self.parent
            && let Err(refusal) = parent.take_chain(amount)
        {
            self.give(amount);
            return Err(refusal);
        }
        Ok(())
    }

    /// Return `amount` to this budget and every budget it is nested in.
    fn give_chain(&self, amount: U) {
        self.give(amount);
        if let Some(parent) = &self.parent {
            parent.give_chain(amount);
        }
    }

    /// Charge `amount` to this budget and its parents.
    ///
    /// # Errors
    ///
    /// The [`OverBudget`] bound the charge would pass; nothing is charged then.
    pub fn try_charge(self: &Arc<Self>, amount: U) -> Result<Held<U>, OverBudget> {
        self.take_chain(amount)?;
        Ok(Held {
            budget: Arc::clone(self),
            held: amount,
        })
    }
}

/// Units held against a budget chain, returned when dropped.
#[derive(Debug)]
#[must_use = "a dropped charge returns its units at once"]
pub struct Held<U: Quantity> {
    budget: Arc<Budget<U>>,
    held: U,
}

impl Held<Bytes> {
    /// A charge of no bytes against a fresh session budget of its own.
    #[cfg(test)]
    pub fn detached() -> Self {
        let process = SessionBudget::process(SESSION_BUDGET);
        Self {
            budget: SessionBudget::session(&process, SESSION_CEILING),
            held: Bytes::ZERO,
        }
    }
}

impl<U: Quantity> Held<U> {
    /// The units this charge holds.
    #[must_use]
    pub const fn held(&self) -> U {
        self.held
    }

    /// The budget this charge holds units against.
    #[must_use]
    pub const fn budget(&self) -> &Arc<Budget<U>> {
        &self.budget
    }

    /// Grow or shrink the charge to `now`.
    ///
    /// # Errors
    ///
    /// The [`OverBudget`] bound growing would pass; the charge keeps holding
    /// what it held before.
    pub fn recharge(&mut self, now: U) -> Result<(), OverBudget> {
        let (now_n, held_n) = (now.units(), self.held.units());
        if let Some(grow) = now_n.checked_sub(held_n) {
            self.budget.take_chain(U::of_units(grow))?;
        } else {
            self.budget
                .give_chain(U::of_units(held_n.saturating_sub(now_n)));
        }
        self.held = now;
        Ok(())
    }
}

impl<U: Quantity> Drop for Held<U> {
    fn drop(&mut self) {
        self.budget.give_chain(self.held);
    }
}

/// One in-flight Cmd's unit, held against its session and the process.
///
/// It is not `Clone` and holds exactly one unit; dropping it returns the unit
/// to both budgets.
#[derive(Debug)]
#[must_use = "a dropped permit returns its Cmd unit at once"]
pub struct CmdPermit {
    _held: Held<Cmds>,
}

/// Whether a process-bound Cmd refusal has been logged yet.
static PROCESS_CMDS_WARNED: AtomicBool = AtomicBool::new(false);

/// One session's in-flight Cmd budget, nested in the process Cmd budget.
#[derive(Debug)]
pub struct SessionCmds {
    budget: Arc<Budget<Cmds>>,
    /// Whether this session's first refusal has been logged yet.
    warned: AtomicBool,
    /// Whether this session's first dropped refusal has been logged yet.
    dropped_warned: AtomicBool,
}

impl SessionCmds {
    /// A session budget of [`SESSION_CMD_CEILING`] under [`shared_cmds`].
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::under(&shared_cmds(), SESSION_CMD_CEILING)
    }

    /// A session budget of `session` under `process`, for boundary tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_limits(process: &Arc<Budget<Cmds>>, session: Cmds) -> Self {
        Self::under(process, session)
    }

    fn under(process: &Arc<Budget<Cmds>>, session: Cmds) -> Self {
        Self {
            budget: Budget::session(process, session),
            warned: AtomicBool::new(false),
            dropped_warned: AtomicBool::new(false),
        }
    }

    /// One Cmd's unit from this session and the process.
    ///
    /// # Errors
    ///
    /// The [`OverBudget`] bound the unit would pass; nothing is held then.
    pub(crate) fn try_permit(&self) -> Result<CmdPermit, OverBudget> {
        self.budget
            .try_charge(Cmds::new(1))
            .map(|held| CmdPermit { _held: held })
    }

    /// The Cmds this session has in flight now.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn used(&self) -> Cmds {
        self.budget.used()
    }

    /// Whether this refusal of `why` is the first one worth logging.
    ///
    /// True once per session for its first refusal, and once per process for
    /// the first refusal by the process bound.
    pub(crate) fn first_refusal(&self, why: OverBudget) -> bool {
        let session_first = !self.warned.swap(true, Ordering::AcqRel);
        let process_first =
            why == OverBudget::Process && !PROCESS_CMDS_WARNED.swap(true, Ordering::AcqRel);
        session_first || process_first
    }

    /// Whether this is the session's first refusal its full queue dropped.
    pub(crate) fn first_dropped_refusal(&self) -> bool {
        !self.dropped_warned.swap(true, Ordering::AcqRel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned per-session Cmd ceiling of the binding decision.
    #[test]
    fn cmd_ceiling_value_pin() {
        assert_eq!(SESSION_CMD_CEILING, Cmds::new(64));
        assert_eq!(PROCESS_CMD_BUDGET, Cmds::new(16_384));
    }

    /// Exactly the ceiling's permits admit; the next refuses naming the
    /// session; dropping one admits exactly one more.
    #[test]
    fn cmd_ceiling_boundary() {
        let cmds = SessionCmds::new();
        let mut held: Vec<CmdPermit> = Vec::new();
        for _ in 0..SESSION_CMD_CEILING.get() {
            let permit = cmds.try_permit();
            assert!(permit.is_ok(), "a permit under the ceiling admits");
            held.extend(permit.ok());
        }
        assert_eq!(cmds.used(), SESSION_CMD_CEILING);
        assert_eq!(
            cmds.try_permit().err(),
            Some(OverBudget::Session),
            "one Cmd past the ceiling refuses"
        );
        assert_eq!(cmds.used(), SESSION_CMD_CEILING, "a refusal holds nothing");
        drop(held.pop());
        let again = cmds.try_permit();
        assert!(again.is_ok(), "a returned unit admits one more");
        assert_eq!(cmds.try_permit().err(), Some(OverBudget::Session));
        drop((held, again));
        assert_eq!(cmds.used(), Cmds::new(0));
    }

    /// The process bound refuses across sessions and rolls the session unit back.
    #[test]
    fn cmd_process_boundary() {
        let process = Budget::process(Cmds::new(6));
        let a = SessionCmds::with_limits(&process, Cmds::new(4));
        let b = SessionCmds::with_limits(&process, Cmds::new(4));
        let held: Vec<_> = [&a, &a, &a, &a, &b, &b]
            .into_iter()
            .map(SessionCmds::try_permit)
            .collect();
        assert!(held.iter().all(Result::is_ok), "six units fit the process");
        assert_eq!(process.used(), Cmds::new(6));
        assert_eq!(
            b.try_permit().err(),
            Some(OverBudget::Process),
            "the seventh unit passes the process bound"
        );
        assert_eq!(
            b.used(),
            Cmds::new(2),
            "a process refusal leaks no session unit"
        );
        assert_eq!(process.used(), Cmds::new(6));
        drop(held);
        assert_eq!(process.used(), Cmds::new(0));
    }

    /// A permit held by a cancelled task returns its unit.
    #[tokio::test]
    async fn cmd_permit_cancelled_holder_returns() {
        let process = Budget::process(Cmds::new(8));
        let cmds = SessionCmds::with_limits(&process, Cmds::new(4));
        let permit = cmds.try_permit();
        assert!(permit.is_ok());
        let holder = tokio::spawn(async move {
            let _permit = permit;
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        assert_eq!((cmds.used(), process.used()), (Cmds::new(1), Cmds::new(1)));
        holder.abort();
        let _ = holder.await;
        assert_eq!((cmds.used(), process.used()), (Cmds::new(0), Cmds::new(0)));
    }

    /// Racing threads never hold more permits than the ceiling.
    #[test]
    fn cmd_permit_concurrent_race() {
        const THREADS: usize = 16;
        const TRIES: usize = 16;
        for _ in 0..50 {
            let process = Budget::process(PROCESS_CMD_BUDGET);
            let cmds = SessionCmds::with_limits(&process, SESSION_CMD_CEILING);
            let barrier = std::sync::Barrier::new(THREADS);
            let (barrier, racing) = (&barrier, &cmds);
            let held: Vec<CmdPermit> = std::thread::scope(|scope| {
                let workers: Vec<_> = (0..THREADS)
                    .map(move |_| {
                        std::thread::Builder::new()
                            .spawn_scoped(scope, move || {
                                barrier.wait();
                                (0..TRIES)
                                    .filter_map(|_| racing.try_permit().ok())
                                    .collect::<Vec<_>>()
                            })
                            .expect("the race test spawns its worker thread")
                    })
                    .collect();
                workers
                    .into_iter()
                    .filter_map(|w| w.join().ok())
                    .flatten()
                    .collect()
            });
            let admitted = u64::try_from(held.len()).unwrap_or(u64::MAX);
            assert_eq!(
                admitted,
                SESSION_CMD_CEILING.get(),
                "exactly the ceiling admits"
            );
            assert_eq!(process.used(), SESSION_CMD_CEILING);
            drop(held);
            assert_eq!((cmds.used(), process.used()), (Cmds::new(0), Cmds::new(0)));
        }
    }

    /// The first refusal of a session is logged once; a later one is not.
    #[test]
    fn first_refusal_once_per_session() {
        let process = Budget::process(Cmds::new(8));
        let cmds = SessionCmds::with_limits(&process, Cmds::new(1));
        assert!(cmds.first_refusal(OverBudget::Session));
        assert!(!cmds.first_refusal(OverBudget::Session));
        let other = SessionCmds::with_limits(&process, Cmds::new(1));
        assert!(
            other.first_refusal(OverBudget::Session),
            "each session logs once"
        );
    }

    /// A process budget of `process` bytes and one session budget of `session` in it.
    fn chain(process: u64, session: u64) -> (Arc<SessionBudget>, Arc<SessionBudget>) {
        let process = SessionBudget::process(Bytes::new(process));
        let session = SessionBudget::session(&process, Bytes::new(session));
        (process, session)
    }

    /// A charge of exactly the room admits; one byte more refuses, naming the bound.
    #[test]
    fn budget_boundary() {
        let (process, session) = chain(100, 40);
        let at_ceiling = session.try_charge(Bytes::new(40));
        assert!(at_ceiling.is_ok(), "a charge equal to the room admits");
        assert_eq!(session.used(), Bytes::new(40));
        assert_eq!(process.used(), Bytes::new(40));
        assert_eq!(
            session.try_charge(Bytes::new(1)).err(),
            Some(OverBudget::Session),
            "one byte past the session ceiling refuses"
        );
        drop(at_ceiling);
        assert_eq!(session.used(), Bytes::ZERO);

        // The process bound: three sessions fill it, the next byte refuses
        // and leaves its own session budget untouched.
        let sessions: Vec<_> = (0..3)
            .map(|_| SessionBudget::session(&process, Bytes::new(40)))
            .collect();
        let held: Vec<_> = sessions
            .iter()
            .zip([40, 40, 20])
            .map(|(s, n)| s.try_charge(Bytes::new(n)))
            .collect();
        assert!(held.iter().all(Result::is_ok));
        assert_eq!(process.used(), Bytes::new(100));
        let refused = session.try_charge(Bytes::new(1));
        assert_eq!(refused.err(), Some(OverBudget::Process));
        assert_eq!(
            session.used(),
            Bytes::ZERO,
            "a refused charge is rolled back"
        );
        assert_eq!(process.used(), Bytes::new(100));
        drop(held);
        assert_eq!(process.used(), Bytes::ZERO, "every drop returns its bytes");
    }

    /// A recharge grows and shrinks; a refused growth keeps the old charge.
    #[test]
    fn recharge_grows_shrinks_and_refuses_in_place() {
        let (process, session) = chain(100, 40);
        let charge = session.try_charge(Bytes::new(10));
        assert!(charge.is_ok(), "a charge under both bounds admits");
        let Ok(mut charge) = charge else {
            return;
        };
        assert_eq!(charge.recharge(Bytes::new(40)), Ok(()));
        assert_eq!(process.used(), Bytes::new(40));
        assert_eq!(
            charge.recharge(Bytes::new(41)),
            Err(OverBudget::Session),
            "one byte past the ceiling refuses"
        );
        assert_eq!(charge.held(), Bytes::new(40));
        assert_eq!(session.used(), Bytes::new(40));
        assert_eq!(charge.recharge(Bytes::new(5)), Ok(()));
        assert_eq!(process.used(), Bytes::new(5));
        drop(charge);
        assert_eq!((session.used(), process.used()), (Bytes::ZERO, Bytes::ZERO));
    }

    /// A charge held by a cancelled future returns its bytes.
    #[tokio::test]
    async fn a_cancelled_holder_returns_its_bytes() {
        let (process, session) = chain(100, 40);
        let held = session.try_charge(Bytes::new(30));
        let holder = tokio::spawn(async move {
            let _held = held;
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        assert_eq!(process.used(), Bytes::new(30));
        holder.abort();
        let _ = holder.await;
        assert_eq!(process.used(), Bytes::ZERO);
    }

    /// A drop wakes a waiter on the freed signal.
    #[tokio::test]
    async fn a_drop_wakes_the_freed_waiter() {
        let (process, session) = chain(100, 40);
        let held = session.try_charge(Bytes::new(30));
        let freed = process.freed();
        tokio::pin!(freed);
        freed.as_mut().enable();
        drop(held);
        let woke = tokio::time::timeout(EVICT_WAIT, freed).await;
        assert!(woke.is_ok(), "the release must wake the waiter");
    }

    /// Racing charges never pass the process budget: with every admitted
    /// charge still held, exactly the charges that fit are admitted, and the
    /// budget accounts for each of them, over many racing rounds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_charges_never_pass_the_budget() {
        const TASKS: u64 = 16;
        const ROUNDS: u64 = 200;
        const CHUNK: u64 = 63;
        const LIMIT: u64 = 1_000;
        // 15 chunks (945 bytes) fit the limit; a 16th (1008) does not.
        const FITS: u64 = 15;
        const FITS_BYTES: u64 = 945;
        for _ in 0..ROUNDS {
            let process = SessionBudget::process(Bytes::new(LIMIT));
            // Every task parks on the barrier before charging, so all race at once.
            let barrier = Arc::new(tokio::sync::Barrier::new(16));
            let mut tasks = Vec::new();
            for _ in 0..TASKS {
                let process = Arc::clone(&process);
                let barrier = Arc::clone(&barrier);
                tasks.push(tokio::spawn(async move {
                    let session = SessionBudget::session(&process, Bytes::new(LIMIT));
                    barrier.wait().await;
                    session.try_charge(Bytes::new(CHUNK)).ok()
                }));
            }
            let mut held = Vec::new();
            for task in tasks {
                if let Ok(Some(charge)) = task.await {
                    held.push(charge);
                }
            }
            let admitted = u64::try_from(held.len()).unwrap_or(u64::MAX);
            assert_eq!(admitted, FITS, "exactly the charges that fit are admitted");
            assert_eq!(
                process.used(),
                Bytes::new(FITS_BYTES),
                "every admitted charge is accounted"
            );
            drop(held);
            assert_eq!(process.used(), Bytes::ZERO);
        }
    }
}

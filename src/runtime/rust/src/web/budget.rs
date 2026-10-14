//! The byte budgets a web session's resident state is charged against.
//!
//! Each session holds one [`Charge`] on its own [`SessionBudget`] of
//! [`SESSION_CEILING`], nested in the one process budget of [`SESSION_BUDGET`]
//! every app of the process shares. A charge takes its bytes from every budget of the chain or
//! from none, each step one atomic `fetch_update`, so no budget's `used` ever
//! passes its `limit`; the bytes return only when the charge drops.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// A byte limit and the bytes charged against it.
#[derive(Debug)]
pub struct SessionBudget {
    limit: Bytes,
    used: AtomicU64,
    /// The budget this one is nested in; `None` for the process budget.
    parent: Option<Arc<Self>>,
    /// Woken whenever a charge returns bytes to this budget.
    freed: tokio::sync::Notify,
}

impl SessionBudget {
    /// A process budget of `limit` bytes.
    #[must_use]
    pub fn process(limit: Bytes) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicU64::new(0),
            parent: None,
            freed: tokio::sync::Notify::new(),
        })
    }

    /// A session budget of `limit` bytes nested in `process`.
    #[must_use]
    pub fn session(process: &Arc<Self>, limit: Bytes) -> Arc<Self> {
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

    /// The bytes charged against this budget now.
    #[must_use]
    pub fn used(&self) -> Bytes {
        Bytes::new(self.used.load(Ordering::Acquire))
    }

    /// The bytes still free under this budget's limit.
    #[must_use]
    pub fn room(&self) -> Bytes {
        Bytes::new(self.limit.get().saturating_sub(self.used().get()))
    }

    /// A future woken the next time a charge returns bytes to this budget.
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

    /// Charge `bytes` to this budget alone, or refuse leaving it unchanged.
    fn take(&self, bytes: Bytes) -> Result<(), OverBudget> {
        let limit = self.limit.get();
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes.get()).filter(|now| *now <= limit)
            })
            .map(drop)
            .map_err(|_| self.refusal())
    }

    /// Return `bytes` to this budget alone.
    fn give(&self, bytes: Bytes) {
        // A charge returns only what it took, so the subtraction never floors;
        // saturating keeps a broken pairing from wrapping into a huge `used`.
        let _ = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                Some(used.saturating_sub(bytes.get()))
            });
        self.freed.notify_waiters();
    }

    /// Charge `bytes` to this budget and every budget it is nested in, or to none.
    fn take_chain(&self, bytes: Bytes) -> Result<(), OverBudget> {
        self.take(bytes)?;
        if let Some(parent) = &self.parent
            && let Err(refusal) = parent.take_chain(bytes)
        {
            self.give(bytes);
            return Err(refusal);
        }
        Ok(())
    }

    /// Return `bytes` to this budget and every budget it is nested in.
    fn give_chain(&self, bytes: Bytes) {
        self.give(bytes);
        if let Some(parent) = &self.parent {
            parent.give_chain(bytes);
        }
    }

    /// Charge `bytes` to this budget and its parents.
    ///
    /// # Errors
    ///
    /// The [`OverBudget`] bound the charge would pass; nothing is charged then.
    pub fn try_charge(self: &Arc<Self>, bytes: Bytes) -> Result<Charge, OverBudget> {
        self.take_chain(bytes)?;
        Ok(Charge {
            budget: Arc::clone(self),
            held: bytes,
        })
    }
}

/// Bytes held against a budget chain, returned when dropped.
#[derive(Debug)]
#[must_use = "a dropped charge returns its bytes at once"]
pub struct Charge {
    budget: Arc<SessionBudget>,
    held: Bytes,
}

impl Charge {
    /// A charge of no bytes against a fresh session budget of its own.
    #[cfg(test)]
    pub fn detached() -> Self {
        let process = SessionBudget::process(SESSION_BUDGET);
        Self {
            budget: SessionBudget::session(&process, SESSION_CEILING),
            held: Bytes::ZERO,
        }
    }

    /// The bytes this charge holds.
    #[must_use]
    pub const fn held(&self) -> Bytes {
        self.held
    }

    /// The budget this charge holds bytes against.
    #[must_use]
    pub const fn budget(&self) -> &Arc<SessionBudget> {
        &self.budget
    }

    /// Grow or shrink the charge to `now` bytes.
    ///
    /// # Errors
    ///
    /// The [`OverBudget`] bound growing would pass; the charge keeps holding
    /// what it held before.
    pub fn recharge(&mut self, now: Bytes) -> Result<(), OverBudget> {
        let (now_n, held_n) = (now.get(), self.held.get());
        if let Some(grow) = now_n.checked_sub(held_n) {
            self.budget.take_chain(Bytes::new(grow))?;
        } else {
            self.budget
                .give_chain(Bytes::new(held_n.saturating_sub(now_n)));
        }
        self.held = now;
        Ok(())
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.budget.give_chain(self.held);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Racing charges never pass the process budget, and some are refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_charges_never_pass_the_budget() {
        const TASKS: u64 = 16;
        const LIMIT: u64 = 1_000;
        let process = SessionBudget::process(Bytes::new(LIMIT));
        // Every task parks on the barrier before charging, so all race at once.
        let barrier = Arc::new(tokio::sync::Barrier::new(16));
        let peak = Arc::new(AtomicU64::new(0));
        let mut tasks = Vec::new();
        for _ in 0..TASKS {
            let process = Arc::clone(&process);
            let barrier = Arc::clone(&barrier);
            let peak = Arc::clone(&peak);
            tasks.push(tokio::spawn(async move {
                let session = SessionBudget::session(&process, Bytes::new(LIMIT));
                barrier.wait().await;
                let held = session.try_charge(Bytes::new(LIMIT / TASKS + 1));
                peak.fetch_max(process.used().get(), Ordering::AcqRel);
                tokio::task::yield_now().await;
                peak.fetch_max(process.used().get(), Ordering::AcqRel);
                held.is_ok()
            }));
        }
        let mut admitted = 0_u64;
        for task in tasks {
            if matches!(task.await, Ok(true)) {
                admitted += 1;
            }
        }
        assert!(
            peak.load(Ordering::Acquire) <= LIMIT,
            "used passed the limit"
        );
        assert!(admitted < TASKS, "at least one charge must be refused");
        assert!(admitted > 0, "the race must admit some charge");
        assert_eq!(process.used(), Bytes::ZERO);
    }
}

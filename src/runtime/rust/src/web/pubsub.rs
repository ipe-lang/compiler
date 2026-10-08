//! In-process pub/sub broker for the Rust backend.
//!
//! One `Broker<T>` per concrete payload type `T`, held in a global registry
//! keyed by `TypeId`. The payload travels as its real Rust type `T` end-to-end
//! and is NEVER erased or downcast — the only `dyn Any` is the broker-container
//! indirection, which is correct by construction (a `Broker<T>` is only ever
//! stored under `TypeId::of::<T>()`). This is the no-runtime-errors design from
//! A statically-typed broker: no reflect-based dispatch, no type erasure on the
//! payload path.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::broadcast;

use crate::core::{IpeResult, IpeTask, ok_res};
use crate::tea::{IpeCmd, IpeSub};

/// Per-topic broadcast buffer. A subscriber that lags more than this many
/// messages gets `RecvError::Lagged` (handled by skipping, never panicking).
const TOPIC_CAP: usize = 256;

/// One broadcast envelope. `origin` is the publishing session's sid;
/// `skip_origin` requests receiver-side echo-suppression (publishNoEcho).
#[derive(Clone)]
pub(crate) struct Event<T> {
    pub payload: T,
    pub origin: String,
    pub skip_origin: bool,
}

/// One broker per concrete payload type `T`. A topic is a single broadcast
/// channel shared by all of that topic's subscribers; SkipOrigin is filtered
/// receiver-side (see `sub_subscribe_topic`), so the broker stays a plain
/// `topic -> Sender` map.
pub(crate) struct Broker<T> {
    topics: Mutex<HashMap<String, broadcast::Sender<Event<T>>>>,
}

impl<T: Clone + Send + 'static> Broker<T> {
    fn new() -> Self {
        Broker {
            topics: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, broadcast::Sender<Event<T>>>> {
        // Poison-tolerant: a panic elsewhere must not abort the whole app; the
        // map is still valid data.
        self.topics.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register a subscriber on `topic`, creating the channel if needed.
    pub(crate) fn subscribe(&self, topic: &str) -> broadcast::Receiver<Event<T>> {
        let mut g = self.lock();
        // Opportunistically reclaim abandoned topics: a topic whose subscribers
        // all dropped but was never published-to again is never seen by the
        // publish-path prune, so it would leak forever. Cheap to sweep here —
        // `receiver_count()` is an atomic load. Pruning a zero-receiver Sender
        // is safe: a concurrent publish to it would deliver to nobody anyway,
        // and the requested topic (if stale) is rebuilt below — a fresh
        // broadcast channel is equivalent, since a subscriber only ever sees
        // messages sent after it subscribed.
        g.retain(|_, tx| tx.receiver_count() > 0);
        let tx = g
            .entry(topic.to_string())
            .or_insert_with(|| broadcast::channel(TOPIC_CAP).0);
        tx.subscribe()
    }

    /// Broadcast `payload` to every subscriber on `topic`. Returns the subscriber
    /// count **at the time of send** — not a delivery guarantee (subscribers may
    /// drop concurrently; pub/sub is fire-and-forget). A topic whose subscribers
    /// have all dropped is lazily pruned and returns 0. Fire-and-forget — `send`
    /// failing (no receivers) is not an error.
    pub(crate) fn publish(&self, topic: &str, payload: T, origin: &str, skip_origin: bool) -> i64 {
        let mut g = self.lock();
        match g.get(topic) {
            Some(tx) => {
                let n = tx.receiver_count() as i64;
                if n == 0 {
                    g.remove(topic); // lazy prune
                    return 0;
                }
                let _ = tx.send(Event {
                    payload,
                    origin: origin.to_string(),
                    skip_origin,
                });
                n
            }
            None => 0,
        }
    }
}

/// Global per-type registry. The ONE `downcast_ref` is keyed by `TypeId`, so it
/// is correct by construction; the impossible `None` arm rebuilds rather than
/// `unwrap` (no panic). The payload type is never involved in this cast.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel, 2026-06-13) — TypeId-keyed broker CONTAINER only; one Arc<Broker<T>> per TypeId, payload never erased; downcast can't fail, impossible None rebuilds [ledger #4]
fn registry() -> &'static Mutex<HashMap<TypeId, Box<dyn Any + Send + Sync>>> {
    static R: OnceLock<Mutex<HashMap<TypeId, Box<dyn Any + Send + Sync>>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Get (or lazily create) the broker for payload type `T`.
pub(crate) fn broker<T: Clone + Send + 'static>() -> Arc<Broker<T>> {
    let mut g = registry().lock().unwrap_or_else(|e| e.into_inner());
    let entry = g
        .entry(TypeId::of::<T>())
        .or_insert_with(|| Box::new(Arc::new(Broker::<T>::new())));
    match entry.downcast_ref::<Arc<Broker<T>>>() {
        Some(b) => b.clone(),
        None => {
            // Unreachable by construction (the registry only ever stores an
            // Arc<Broker<T>> under TypeId::of::<T>()). If it somehow fired it
            // would discard live subscribers, so log a bug report rather than
            // fail silently, then return a fresh broker (never panic).
            crate::system::write_stderr_line(&format!(
                "[ipe-runtime BUG] pubsub broker downcast mismatch for {:?} — please report",
                TypeId::of::<T>()
            ));
            let b = Arc::new(Broker::<T>::new());
            *entry = Box::new(b.clone());
            b
        }
    }
}

// ─── Web-running flag (for PubSub.publish's Unavailable) ───────────────────

static WEB_RUNNING: AtomicBool = AtomicBool::new(false);

/// Called by `serve_web` once the router is built, just before the TCP bind.
/// After this point `PubSub.publish` tasks succeed (the flag is write-once and
/// never reset). A publish racing startup before this fires gets a single
/// retry-able `Unavailable` — benign for fire-and-forget pub/sub.
pub fn mark_web_running() {
    WEB_RUNNING.store(true, Ordering::Release);
}

fn web_running() -> bool {
    WEB_RUNNING.load(Ordering::Acquire)
}

/// `PubSub.publish topic payload : Task Error Int` — callable from any context
/// (raw handlers, post-init, scheduled jobs). Resolves to the subscriber count,
/// or an error when no Web app is running in this process (`Unavailable`).
/// Server-side publishes carry an empty origin, so echo-default is a no-op.
pub fn pubsub_publish<T, E>(topic: String, payload: T) -> IpeTask<E, i64>
where
    T: Clone + Send + 'static,
    E: From<String> + Send + 'static,
{
    Box::pin(async move {
        if !web_running() {
            return IpeResult::Err(E::from(
                "PubSub.publish: no Web.tea running in this process".to_string(),
            ));
        }
        ok_res(broker::<T>().publish(&topic, payload, "", false))
    })
}

/// `PubSub.publishNoEcho` — same, with the SkipOrigin bit set.
pub fn pubsub_publish_no_echo<T, E>(topic: String, payload: T) -> IpeTask<E, i64>
where
    T: Clone + Send + 'static,
    E: From<String> + Send + 'static,
{
    Box::pin(async move {
        if !web_running() {
            return IpeResult::Err(E::from(
                "PubSub.publishNoEcho: no Web.tea running in this process".to_string(),
            ));
        }
        ok_res(broker::<T>().publish(&topic, payload, "", true))
    })
}

/// `Cmd.publish topic payload` — echo-by-default broadcast. The payload `T` is
/// captured in the thunk; the dispatch loop supplies the origin sid.
pub fn cmd_publish<T, M>(topic: String, payload: T) -> IpeCmd<M>
where
    T: Clone + Send + 'static,
{
    IpeCmd::Publish(Box::new(move |origin| {
        broker::<T>().publish(&topic, payload, origin, false)
    }))
}

/// `Cmd.publishNoEcho topic payload` — sets the SkipOrigin bit; the publisher's
/// own subscription is suppressed receiver-side.
pub fn cmd_publish_no_echo<T, M>(topic: String, payload: T) -> IpeCmd<M>
where
    T: Clone + Send + 'static,
{
    IpeCmd::Publish(Box::new(move |origin| {
        broker::<T>().publish(&topic, payload, origin, true)
    }))
}

/// The session a call into user code runs on behalf of.
///
/// `sid` keys pub/sub echo-suppression and the port transport; `bindings` is
/// the session's credential set, the one `Auth.verifyToken` binds an admitted
/// token into and the driver rechecks before applying each action. Cloning a
/// scope shares the set (an `Arc`), so a spawned `Cmd` binds into the same
/// session that dispatched it.
#[derive(Clone)]
pub struct SessionScope {
    sid: String,
    #[cfg(feature = "jwt")]
    bindings: Arc<Mutex<crate::revocation::SessionBindings>>,
}

impl SessionScope {
    /// A scope for `sid` with a fresh, empty credential set.
    ///
    /// Used where no live session entry exists yet; the Web runtime builds a
    /// live session's scope with [`SessionScope::with_bindings`] so the set is
    /// the entry's own.
    #[must_use]
    pub fn new(sid: String) -> Self {
        Self {
            sid,
            #[cfg(feature = "jwt")]
            bindings: Arc::default(),
        }
    }

    /// A scope for `sid` sharing the session entry's credential set.
    #[cfg(feature = "jwt")]
    #[must_use]
    pub fn with_bindings(
        sid: String,
        bindings: Arc<Mutex<crate::revocation::SessionBindings>>,
    ) -> Self {
        Self { sid, bindings }
    }

    /// The session id this scope runs on behalf of.
    #[must_use]
    pub fn sid(&self) -> &str {
        &self.sid
    }

    /// The session's shared credential set.
    #[cfg(feature = "jwt")]
    #[must_use]
    pub fn bindings(&self) -> &Arc<Mutex<crate::revocation::SessionBindings>> {
        &self.bindings
    }

    /// Run `fut` with this scope in effect across every poll.
    ///
    /// The async twin of [`with_session`]: a `Cmd` future spawned by the Web
    /// runtime is wrapped in it, so a `verifyToken` the future reaches binds
    /// to the dispatching session instead of failing closed as unscoped.
    pub fn scoped<F: std::future::Future>(
        self,
        fut: F,
    ) -> impl std::future::Future<Output = F::Output> {
        SESSION.scope(self, fut)
    }
}

tokio::task_local! {
    /// The session in scope while user code runs on its behalf. Read
    /// synchronously inside the `IpeSub::Source` closure so the spawned recv
    /// loop captures the owning session's sid for SkipOrigin filtering, and by
    /// `Auth.verifyToken` to bind an admitted token. Unset outside a session.
    static SESSION: SessionScope;
}

/// Run `f` with `scope` available to [`current_session_sid`] and the
/// credential binder.
///
/// The Web runtime wraps every synchronous call into user code on behalf of a
/// session (`init`, `update`, `view`, `subscriptions`, route entry, debugger
/// replay) in this scope.
pub fn with_session<R>(scope: &SessionScope, f: impl FnOnce() -> R) -> R {
    SESSION.sync_scope(scope.clone(), f)
}

/// The sid of the session in the current task-local scope.
///
/// Empty outside any session. Public so the `Ipe.Ffi.Js` port transport can
/// bind each `js_subscribe` / `js_send` to the OWNING session's channel (read
/// synchronously while [`with_session`] is in scope), making cross-session
/// port delivery unrepresentable: a port channel handle is only ever obtained
/// from the sid in this scope, never from a process-global registry keyed by
/// port name.
#[must_use]
pub fn current_session_sid() -> String {
    SESSION.try_with(|s| s.sid.clone()).unwrap_or_default()
}

/// The credential set of the session in scope, or `None` outside any session.
#[cfg(feature = "jwt")]
#[must_use]
pub fn session_bindings() -> Option<Arc<Mutex<crate::revocation::SessionBindings>>> {
    SESSION.try_with(|s| Arc::clone(&s.bindings)).ok()
}

/// `Sub.subscribeTopic topic toMsg` — receive `topic` broadcasts as `Msg`s.
/// The codegen-facing form carries no sid; the owning session's sid is read
/// from the materialisation scope. SkipOrigin is filtered here, receiver-side.
///
/// IMPORTANT: `current_session_sid()` is called SYNCHRONOUSLY here (at call
/// time, while `with_session` is in scope), not inside the spawn closure.
/// The captured `owner_sid` is then moved into the spawn closure so the async
/// recv loop has the correct sid even after the task-local scope has ended.
pub fn sub_subscribe_topic<T, M, F>(topic: String, to_msg: F) -> IpeSub<M>
where
    T: Clone + Send + 'static,
    M: Send + 'static,
    // `to_msg` is moved exclusively into the spawned task (never shared across
    // threads), so `Send` is the minimum contract — `Sync` is not required.
    F: Fn(T) -> M + Send + 'static,
{
    // Read sid synchronously while with_session's sync_scope is active.
    let owner_sid = current_session_sid();
    IpeSub::Source(Box::new(move |emit| {
        let mut rx = broker::<T>().subscribe(&topic);
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        // Receiver-side echo-suppression: skip exactly the
                        // origin's own subscription when the publish asked for it.
                        if ev.skip_origin && ev.origin == owner_sid {
                            continue;
                        }
                        emit(to_msg(ev.payload));
                    }
                    // A slow session dropped `n` messages: drop + keep going.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    // No senders remain (defensive: unreachable while this
                    // Receiver is alive — the broker only prunes at 0 receivers).
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fan_out_to_two_subscribers() {
        let b = broker::<String>();
        let mut a = b.subscribe("room1");
        let mut c = b.subscribe("room1");
        let n = b.publish("room1", "hi".to_string(), "pub", false);
        assert_eq!(n, 2);
        assert_eq!(a.recv().await.unwrap().payload, "hi");
        assert_eq!(c.recv().await.unwrap().payload, "hi");
    }

    #[tokio::test]
    async fn zero_subscribers_returns_zero() {
        let b = broker::<i64>();
        assert_eq!(b.publish("empty-topic-xyz", 7, "", false), 0);
    }

    #[tokio::test]
    async fn per_type_isolation_same_topic_string() {
        // Same topic string "shared", two different payload types -> different
        // brokers -> no cross-talk. This is the zero-erasure safety property.
        let bs = broker::<String>();
        let bi = broker::<i64>();
        let mut s_rx = bs.subscribe("shared");
        let _i_rx = bi.subscribe("shared");
        assert_eq!(bi.publish("shared", 42, "", false), 1); // only the i64 sub
        assert_eq!(bs.publish("shared", "x".to_string(), "", false), 1); // only the String sub
        assert_eq!(s_rx.recv().await.unwrap().payload, "x");
    }

    #[tokio::test]
    async fn event_carries_origin_and_skip_flag() {
        let b = broker::<u8>();
        let mut rx = b.subscribe("t");
        b.publish("t", 1, "sid-A", true);
        let ev = rx.recv().await.unwrap();
        assert_eq!(ev.origin, "sid-A");
        assert!(ev.skip_origin);
    }

    use std::sync::{Arc, Mutex};

    // Drive a subscriber the way the Web loop does: inside with_session,
    // materialise the Source, then collect emitted Msgs.
    async fn collect_one(
        owner_sid: &str,
        topic: &str,
    ) -> (tokio::task::JoinHandle<()>, Arc<Mutex<Vec<String>>>) {
        let got = Arc::new(Mutex::new(Vec::<String>::new()));
        let got2 = got.clone();
        let emit: Arc<dyn Fn(String) + Send + Sync> =
            Arc::new(move |m| got2.lock().unwrap().push(m));
        let sub = with_session(&SessionScope::new(owner_sid.to_string()), || {
            sub_subscribe_topic::<String, String, _>(topic.to_string(), |p| p)
        });
        let handle = match sub {
            IpeSub::Source(spawn) => spawn(emit),
            _ => unreachable!("subscribeTopic builds a Source"),
        };
        tokio::time::sleep(std::time::Duration::from_millis(20)).await; // let it subscribe
        (handle, got)
    }

    #[tokio::test]
    async fn echo_default_delivers_to_origin() {
        let (h, got) = collect_one("sid-A", "echo-topic").await;
        broker::<String>().publish("echo-topic", "m".to_string(), "sid-A", false);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(*got.lock().unwrap(), vec!["m".to_string()]); // origin RECEIVES (echo)
        h.abort();
    }

    #[tokio::test]
    async fn pubsub_publish_errs_without_web_app() {
        // WEB_RUNNING starts false; no serve_web runs in a unit test.
        let t: IpeTask<String, i64> = pubsub_publish::<u8, String>("t".to_string(), 1);
        match t.await {
            IpeResult::Err(e) => assert!(e.contains("no Web.tea")),
            IpeResult::Ok(_) => panic!("expected Err Unavailable"),
        }
    }

    #[tokio::test]
    async fn pubsub_publish_no_echo_errs_without_web_app() {
        let t: IpeTask<String, i64> = pubsub_publish_no_echo::<u8, String>("t".to_string(), 1);
        match t.await {
            IpeResult::Err(e) => assert!(e.contains("no Web.tea")),
            IpeResult::Ok(_) => panic!("expected Err Unavailable"),
        }
    }

    #[tokio::test]
    async fn skip_origin_suppresses_only_origin() {
        let (ha, got_a) = collect_one("sid-A", "ne-topic").await; // the publisher's own sub
        let (hb, got_b) = collect_one("sid-B", "ne-topic").await; // a different session
        broker::<String>().publish("ne-topic", "m".to_string(), "sid-A", true); // publishNoEcho from A
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(got_a.lock().unwrap().is_empty()); // A suppressed
        assert_eq!(*got_b.lock().unwrap(), vec!["m".to_string()]); // B receives
        ha.abort();
        hb.abort();
    }
}

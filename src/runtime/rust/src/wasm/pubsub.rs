//! In-tab pub/sub broker — the browser-WASM half of `Cmd.publish` /
//! `PubSub.publish` / `Sub.subscribeTopic`.
//!
//! Single-threaded (`Rc`/`RefCell`/`thread_local!`, never `Arc`/`Mutex`): a
//! browser tab has no OS threads, so the native `live/pubsub.rs`'s
//! `tokio::sync::broadcast` channel (built for a lagging-receiver model
//! across real concurrent tasks) has no work to do here — a topic is a flat
//! `Vec` of listener closures, delivered synchronously on `publish`.
//!
//! **Echo/no-echo, preserved.** Native ties `skip_origin` to the publishing
//! *session*'s sid so a session doesn't get its own broadcast echoed back.
//! The wasm client has no session concept, but the identical shape still
//! applies at *mount-instance* granularity: each `wasm::mount_app` call gets
//! a fresh origin token (`with_origin`, set by the scheduler around every
//! `subscriptions(model)` materialisation — the direct analogue of native's
//! `with_session`), so `Cmd.publishNoEcho` from one mounted app
//! instance suppresses only THAT instance's own `Sub.subscribeTopic`
//! listeners, never a different instance's (the multi-mount-in-one-tab case,
//! e.g. several `Ipe.WebView`-style embeds on one page). `PubSub.publish`
//! (the raw-handler-callable Task-tier form) carries no owning instance —
//! same as native's server-side `pubsub_publish`, which also publishes with
//! an empty origin and therefore never self-suppresses.
//!
//! **Cross-tab is out of scope for M4** (spec Open Decision 7: an optional
//! `BroadcastChannel` add-on, not required for the MVP bridge) — this broker
//! is in-tab only, matching the "in-tab pub/sub broker" wording in the M4
//! scope.
//!
//! Container-only `dyn Any`: one `Broker<T>` per `TypeId`, the payload itself
//! is never erased or downcast — the same sanctioned class as
//! `live/pubsub.rs` (`PRINCIPLES.md` §No `dyn Any`).

use std::any::{Any, TypeId};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use crate::core::{IpeTask, ok_res};
use crate::tea::{IpeCmd, IpeSub};

/// One `topic`'s listener: `owner_origin` is the mount-instance token that
/// registered it (via [`with_origin`]); `call` fires on every non-suppressed
/// publish. Keyed by `id` so a specific subscription can be torn down
/// without disturbing others on the same topic.
struct Listener<T> {
    id: u64,
    owner_origin: String,
    call: Rc<dyn Fn(T)>,
}

struct Broker<T> {
    topics: RefCell<HashMap<String, Vec<Listener<T>>>>,
}

impl<T: Clone + 'static> Broker<T> {
    fn new() -> Self {
        Broker {
            topics: RefCell::new(HashMap::new()),
        }
    }

    fn subscribe(&self, topic: &str, owner_origin: String, call: Rc<dyn Fn(T)>) -> u64 {
        let id = next_sub_id();
        self.topics
            .borrow_mut()
            .entry(topic.to_owned())
            .or_default()
            .push(Listener {
                id,
                owner_origin,
                call,
            });
        id
    }

    fn unsubscribe(&self, topic: &str, id: u64) {
        if let Some(v) = self.topics.borrow_mut().get_mut(topic) {
            v.retain(|l| l.id != id);
        }
    }

    /// Broadcast `payload` to every subscriber on `topic`, in-tab. Returns
    /// the subscriber count at publish time (fire-and-forget, same contract
    /// as native). `skip_origin` suppresses delivery to listeners whose
    /// `owner_origin` equals `origin` — the echo-suppression check.
    fn publish(&self, topic: &str, payload: T, origin: &str, skip_origin: bool) -> i64 {
        // Snapshot the listener list before calling out: a listener callback
        // may itself subscribe/unsubscribe (re-entrant `update`), which would
        // deadlock/panic on a `RefCell` still borrowed across the call.
        let listeners: Vec<(String, Rc<dyn Fn(T)>)> = {
            let map = self.topics.borrow();
            match map.get(topic) {
                Some(v) => v
                    .iter()
                    .map(|l| (l.owner_origin.clone(), Rc::clone(&l.call)))
                    .collect(),
                None => return 0,
            }
        };
        let n = listeners.len() as i64;
        for (owner_origin, call) in listeners {
            if skip_origin && owner_origin == origin {
                continue;
            }
            call(payload.clone());
        }
        n
    }
}

thread_local! {
    static SUB_ID: Cell<u64> = const { Cell::new(1) };
}
fn next_sub_id() -> u64 {
    SUB_ID.with(|c| {
        let id = c.get();
        c.set(id + 1);
        id
    })
}

// IPE-RUST-AUDIT: container-only `Rc<dyn Any>` registry — one `Broker<T>` per
// `TypeId`, the payload `T` is never erased/downcast (same class as
// `live/pubsub.rs`'s `TypeId`-keyed broker registry; see `PRINCIPLES.md` §No
// `dyn Any`).
thread_local! {
    static REGISTRY: RefCell<HashMap<TypeId, Rc<dyn Any>>> = RefCell::new(HashMap::new());
}

fn broker<T: Clone + 'static>() -> Rc<Broker<T>> {
    REGISTRY.with(|r| {
        let mut map = r.borrow_mut();
        let entry = map
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Rc::new(Broker::<T>::new()) as Rc<dyn Any>);
        match Rc::clone(entry).downcast::<Broker<T>>() {
            Ok(b) => b,
            Err(_) => {
                // Unreachable by construction (the registry only ever stores a
                // `Broker<T>` under `TypeId::of::<T>()`); rebuild rather than
                // panic, matching `live/pubsub.rs`'s identical guard.
                let b = Rc::new(Broker::<T>::new());
                *entry = Rc::clone(&b) as Rc<dyn Any>;
                b
            }
        }
    })
}

// ─── Mount-instance origin (the `with_session` analogue) ───────────────

thread_local! {
    static CURRENT_ORIGIN: RefCell<String> = RefCell::new(String::new());
}

/// Run `f` with `origin` available to [`current_origin`] — the wasm scheduler
/// wraps every `subscriptions(model)` call in this scope (mirroring native's
/// `with_session`), so `sub_subscribe_topic` below can read its owning
/// mount instance's origin synchronously at subscribe time.
pub(crate) fn with_origin<R>(origin: &str, f: impl FnOnce() -> R) -> R {
    CURRENT_ORIGIN.with(|c| *c.borrow_mut() = origin.to_owned());
    f()
}

fn current_origin() -> String {
    CURRENT_ORIGIN.with(|c| c.borrow().clone())
}

// ─── Kernels ─────────────────────────────────────────────────────────────

/// `Cmd.publish topic payload` — echo-by-default broadcast. The dispatch loop
/// (`wasm::run_cmd`) supplies the origin (this mount instance's token).
pub fn cmd_publish<T: Clone + Send + 'static, M>(topic: String, payload: T) -> IpeCmd<M> {
    IpeCmd::Publish(Box::new(move |origin| {
        broker::<T>().publish(&topic, payload, origin, false)
    }))
}

/// `Cmd.publishNoEcho topic payload` — sets the skip-origin bit; the
/// publishing instance's own subscription (if any) is suppressed.
pub fn cmd_publish_no_echo<T: Clone + Send + 'static, M>(topic: String, payload: T) -> IpeCmd<M> {
    IpeCmd::Publish(Box::new(move |origin| {
        broker::<T>().publish(&topic, payload, origin, true)
    }))
}

/// `PubSub.publish topic payload : Task Error Int` — callable from any
/// context (e.g. a `Cmd.perform`-fired Task, not only `update`'s return).
/// Publishes with an empty origin (matches native's raw-handler-callable
/// arm), so it never self-suppresses via echo. Always available once this
/// code runs — unlike native's `Web.tea`, there is no server-bootstrap race
/// to gate on.
pub fn pubsub_publish<T: Clone + Send + 'static, E>(topic: String, payload: T) -> IpeTask<E, i64> {
    Box::pin(async move { ok_res(broker::<T>().publish(&topic, payload, "", false)) })
}

/// `PubSub.publishNoEcho` — same, with the skip-origin bit set (a no-op
/// against the empty origin, same as native).
pub fn pubsub_publish_no_echo<T: Clone + Send + 'static, E>(
    topic: String,
    payload: T,
) -> IpeTask<E, i64> {
    Box::pin(async move { ok_res(broker::<T>().publish(&topic, payload, "", true)) })
}

/// `Sub.subscribeTopic topic toMsg` — receive `topic` broadcasts as `Msg`s.
/// Registers against the CURRENT mount instance's origin (read synchronously
/// here, while [`with_origin`]'s scope is active — same discipline as
/// native's `sub_subscribe_topic` doc comment). Returns a real teardown
/// thunk so the scheduler's teardown-then-respawn of sources
/// (`wasm::subs::SubManager`) can unregister a dropped subscription instead
/// of accumulating duplicate listeners across re-renders.
pub fn sub_subscribe_topic<T, M, F>(topic: String, to_msg: F) -> IpeSub<M>
where
    T: Clone + 'static,
    M: 'static,
    F: Fn(T) -> M + 'static,
{
    let owner_origin = current_origin();
    IpeSub::Source(Box::new(move |emit: Rc<dyn Fn(M)>| {
        let call: Rc<dyn Fn(T)> = Rc::new(move |payload: T| {
            (emit)(to_msg(payload));
        });
        let id = broker::<T>().subscribe(&topic, owner_origin.clone(), call);
        let topic_for_teardown = topic.clone();
        Box::new(move || {
            broker::<T>().unsubscribe(&topic_for_teardown, id);
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn fan_out_to_two_subscribers() {
        let got_a: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let got_b: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let ga = Rc::clone(&got_a);
        let gb = Rc::clone(&got_b);
        let a: Rc<dyn Fn(String)> = Rc::new(move |m| ga.borrow_mut().push(m));
        let b: Rc<dyn Fn(String)> = Rc::new(move |m| gb.borrow_mut().push(m));
        let broker = broker::<String>();
        broker.subscribe("room1", "x".to_owned(), a);
        broker.subscribe("room1", "x".to_owned(), b);
        let n = broker.publish("room1", "hi".to_owned(), "pub", false);
        assert_eq!(n, 2);
        assert_eq!(*got_a.borrow(), vec!["hi".to_owned()]);
        assert_eq!(*got_b.borrow(), vec!["hi".to_owned()]);
    }

    #[wasm_bindgen_test]
    fn zero_subscribers_returns_zero() {
        let broker = broker::<i64>();
        assert_eq!(broker.publish("empty-topic-xyz", 7, "", false), 0);
    }

    #[wasm_bindgen_test]
    fn skip_origin_suppresses_only_owning_instance() {
        let got_a: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let got_b: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let ga = Rc::clone(&got_a);
        let gb = Rc::clone(&got_b);
        let a: Rc<dyn Fn(String)> = Rc::new(move |m| ga.borrow_mut().push(m));
        let b: Rc<dyn Fn(String)> = Rc::new(move |m| gb.borrow_mut().push(m));
        let broker = broker::<String>();
        broker.subscribe("ne-topic", "instance-A".to_owned(), a);
        broker.subscribe("ne-topic", "instance-B".to_owned(), b);
        broker.publish("ne-topic", "m".to_owned(), "instance-A", true);
        assert!(got_a.borrow().is_empty(), "instance-A should be suppressed");
        assert_eq!(*got_b.borrow(), vec!["m".to_owned()]);
    }

    #[wasm_bindgen_test]
    fn unsubscribe_stops_delivery() {
        let got: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let g = Rc::clone(&got);
        let cb: Rc<dyn Fn(String)> = Rc::new(move |m| g.borrow_mut().push(m));
        let broker = broker::<String>();
        let id = broker.subscribe("t", "x".to_owned(), cb);
        broker.unsubscribe("t", id);
        let n = broker.publish("t", "m".to_owned(), "", false);
        assert_eq!(n, 0);
        assert!(got.borrow().is_empty());
    }

    #[wasm_bindgen_test]
    fn per_type_isolation_same_topic_string() {
        let got_s: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let gs = Rc::clone(&got_s);
        let s_cb: Rc<dyn Fn(String)> = Rc::new(move |m| gs.borrow_mut().push(m));
        let i_cb: Rc<dyn Fn(i64)> = Rc::new(|_| {});
        broker::<String>().subscribe("shared", "x".to_owned(), s_cb);
        broker::<i64>().subscribe("shared", "x".to_owned(), i_cb);
        assert_eq!(broker::<i64>().publish("shared", 42, "", false), 1);
        assert_eq!(
            broker::<String>().publish("shared", "x".to_owned(), "", false),
            1
        );
        assert_eq!(*got_s.borrow(), vec!["x".to_owned()]);
    }
}

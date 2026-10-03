//! Ipe.Ffi.Js ports — the raw typed Ipê↔JS transport behind `Js.send` /
//! `Js.subscribe`.
//!
//! A port carries a plain, seal-legal value across the boundary between an Ipê
//! program and hand-written browser JavaScript. The two directions are:
//!
//! * **Outbound (`js_send : a -> Cmd msg`).** The payload is canonically
//!   seal-encoded to one wire string ([`crate::seal_codec::seal_encode`]) and
//!   handed to the browser out-channel. It is fire-and-forget, so it reuses the
//!   existing [`IpeCmd::Publish`] primitive (a `FnOnce(&str) -> i64` the dispatch
//!   loop runs); no new `IpeCmd` variant is introduced.
//! * **Inbound (`js_subscribe : Decoder a -> (a -> msg) -> Sub msg`).** Each raw
//!   string arriving from the browser in-channel is decoded fail-closed through
//!   the SAME bounded seal decoder every crossing uses
//!   ([`crate::seal_codec::seal_decode`]); a clean decode emits `to_msg(a)`, a
//!   rejected payload is DROPPED whole — no panic, no partial value. This is the
//!   same discipline as the `CustomElement.node` up-event decode.
//!
//! The transport is process-/tab-local and cfg-split, mirroring `ws_client.rs`
//! and the pub/sub broker:
//!
//! * **Native (server).** The transport is keyed PER SESSION, never process-global.
//!   Each authenticated session owns one inbound broadcast channel and one outbound
//!   sink, held in a registry keyed by the session's sid. A `js_subscribe` reads the
//!   owning session's sid from the same task-local scope the pub/sub broker uses
//!   (`pubsub::current_session_sid`, read synchronously while the driver's
//!   `with_session_sid` scope is active) and drains ONLY that session's inbound
//!   channel; a `js_send` delivers ONLY to the origin session's outbound sink (the
//!   origin sid the dispatch loop supplies). The server's inbound route
//!   (`/_ipe/port`) authenticates by session cookie + CSRF, decodes the body
//!   fail-closed through the bounded seal budget, and delivers to that sid's inbound
//!   channel alone.
//!
//!   Cross-session delivery is UNREPRESENTABLE: there is no process-global port
//!   channel and no API to send to a port by name across sessions — a channel handle
//!   is only ever obtained from a [`SessionId`]. A caller with no session sid in scope
//!   gets `None` from [`scope_sid`] and subscribes to an inert per-call channel that
//!   no route ever feeds, so an unscoped subscription receives nothing rather than
//!   another session's traffic. Channels are created on session start ([`session_open`])
//!   and dropped on session end/eviction ([`session_close`]), reusing the session
//!   store's lifecycle.
//! * **Wasm (`feature = "wasm-client"`).** In-process, no network. Outbound calls
//!   the browser-registered `window.ipeOnReceive` handler with the seal-encoded
//!   string; inbound is fed by the browser's `window.ipe.send(...)` pushing a
//!   string into an in-tab queue the `Source` drains.

use crate::seal_codec::{SealLimits, seal_encode};
use crate::tea::{IpeCmd, IpeSub};

// ─── SessionId newtype ──────────────────────────────────────────────────────

/// A validated session identifier: a non-empty, all-lowercase-hex string
/// produced by the server's CSPRNG-backed session-minting path.
///
/// The constructor [`SessionId::parse`] is the only way to build a value of
/// this type from outside this module. It rejects an empty string and any
/// string whose characters are not all lowercase hexadecimal (`[0-9a-f]`),
/// so an invalid or absent session id is unrepresentable past the parse
/// boundary — the per-call `is_empty()` guards in the native registry fall
/// away entirely.
///
/// `Display` and [`SessionId::as_str`] expose the raw hex string so the store
/// can use it as a map key and the dispatch loop can pass it to [`js_send`] via
/// `IpeCmd::Publish`'s `origin: &str` argument. `Debug` prints
/// `SessionId(<redacted>)`: the id is a bearer credential, so no `{:?}` (a log
/// line, the stringify fallback) can print it.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl SessionId {
    /// Parse a raw session-id string into a `SessionId`.
    ///
    /// Returns `None` when `raw` is empty or contains any character outside
    /// `[0-9a-f]`. The server's [`new_sid`][crate::web] always produces a
    /// 32-char lowercase-hex UUID-simple string, so every legitimately minted
    /// session id passes this check.
    pub fn parse(raw: &str) -> Option<Self> {
        if raw.is_empty() {
            return None;
        }
        if raw.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
            Some(SessionId(raw.to_string()))
        } else {
            None
        }
    }

    /// The validated hex string, borrowed.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Debug for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SessionId")
            .field(&crate::redact::Redacted::new(()))
            .finish()
    }
}

// ─── Native (server) transport ─────────────────────────────────────────────

// ─── Correlation-id wire key ────────────────────────────────────────────────

/// The JSON field name the runtime uses to carry the correlation id on both
/// the outbound request envelope and the inbound reply envelope.
///
/// The double-underscore prefix and `ipe_` namespace make this key impossible
/// to collide with a user-defined field: the seal gate rejects any value that
/// contains a field named `__ipe_id` (the sealed type is closed and declared,
/// so an extra field on an inbound value fails the decoder for any user type).
/// Runtime-private — never exported, never user-reachable.
const COR_ID_FIELD: &str = "__ipe_id";

/// Hard ceiling on outstanding (in-flight) `js_request` waiters per session.
/// A JS handler that never replies must not fill heap indefinitely; once the
/// ceiling is reached, new `js_request` calls resolve immediately with `Err`.
pub(crate) const MAX_OUTSTANDING: usize = 256;

/// Default timeout for a `js_request` waiter, in milliseconds. A JS handler
/// that does not reply within this window resolves the Task with `Err`. The
/// value is generous — it covers slow-permission-prompt flows. A per-call
/// override is a tracked follow-up.
const REQUEST_TIMEOUT_MS: u64 = 10_000;

// ─── Session-stream wire keys + bounds ──────────────────────────────────────

/// The JSON field name carrying a session's runtime-minted correlation id on
/// every open envelope, inbound frame, control cmd, and close/terminal
/// envelope. Same collision-proof discipline as [`COR_ID_FIELD`]: the sealed
/// frame/terminal type is closed and declared, so an inbound value that carries
/// this extra field fails the user decoder — the runtime strips it before the
/// payload reaches a decoder. Runtime-private, never user-reachable, never
/// derived from JS input.
const SESSION_ID_FIELD: &str = "__ipe_session";

/// The JSON field name distinguishing a session's terminal reply (delivered to
/// the one-shot close waiter) from an ordinary stream frame (broadcast to the
/// session's `sessionFrames` subscriber). A frame carrying `__ipe_terminal:
/// true` resolves the close waiter; any other framed value is a stream frame.
const SESSION_TERMINAL_FIELD: &str = "__ipe_terminal";

/// Hard ceiling on concurrently-open sessions per session sid. A host that
/// opens sessions without closing them must not fill heap indefinitely; once
/// the ceiling is reached, a new `openSession` resolves immediately with `Err`
/// (fail-closed, bounded by construction — the same shape as [`MAX_OUTSTANDING`]).
pub(crate) const MAX_OPEN_SESSIONS: usize = 64;

/// Per-session inbound-frame budget. After this many frames have been routed to
/// a session, the session is terminated fail-closed with an overflow terminal
/// `Err` and evicted — an ordered stream (e.g. audio) is NEVER allowed to lose
/// frames silently, so the bound surfaces as a terminal error, not a drop.
pub(crate) const SESSION_FRAME_BUDGET: u64 = 100_000;

/// Per-session deadline, in milliseconds. A session that is neither closed nor
/// fed a terminal within this window is terminated fail-closed (overflow/timeout
/// terminal `Err`) and evicted, so a wedged host recorder cannot leak a channel
/// indefinitely. Generous — a long recording session stays well under it.
const SESSION_DEADLINE_MS: u64 = 3_600_000;

/// Hard ceiling on outbound port frames buffered for a session whose browser
/// out-sink is not yet bound (the window between session creation and the SSE
/// connection that installs the sink). An outbound `Cmd` — `Geo.current`,
/// `Clipboard.read` — dispatched in that window is queued here and flushed in
/// FIFO order the instant the sink binds, so a fast action taken before the
/// handshake lands is delivered, never dropped fire-and-forget. Bounded by
/// construction: the queue is drop-oldest at the ceiling (the same fail-closed
/// shape as [`MAX_OUTSTANDING`]), so a remote party cannot grow it without
/// limit. The pre-bind window is sub-second, so a small ceiling covers every
/// legitimate burst.
pub(crate) const MAX_OUT_PENDING: usize = 64;

// ─── Native (server) transport ─────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use crate::error::IpeError;
    use crate::json::{Decoder, JsonVal};
    use crate::seal_codec::seal_decode;
    use std::collections::HashMap;
    use std::sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    };
    use tokio::sync::{broadcast, oneshot};

    /// Broadcast buffer for one direction. A lagging subscriber drops the gap
    /// (never panics); the size bounds the queue an inbound burst can hold.
    const PORT_CAP: usize = 256;

    /// Process-global monotonic correlation-id counter. Ids are runtime-private:
    /// they are minted here and never accepted as input — a JS-injected id cannot
    /// forge a waiter lookup because the registry key is the id minted by this
    /// counter, not an id parsed from an untrusted inbound frame.
    static NEXT_COR_ID: AtomicU64 = AtomicU64::new(1);

    fn next_cor_id() -> u64 {
        NEXT_COR_ID.fetch_add(1, Ordering::Relaxed)
    }

    /// A registered out-sink for one session: the server installs it so each
    /// outbound `js_send` frame for that session is pushed to that session's
    /// browser over its own SSE connection.
    type OutSink = Arc<dyn Fn(&str) + Send + Sync>;

    /// One session's port endpoints. The inbound channel carries browser→server
    /// frames (already through the fail-closed decode gate) to that session's
    /// `js_subscribe`; `out_sink` is that session's browser-push installed by the
    /// live server; `pending` holds in-flight `js_request` waiters keyed by their
    /// runtime-minted correlation id. All belong to exactly one sid.
    pub(crate) struct SessionPorts {
        inbound: broadcast::Sender<String>,
        out_sink: Option<OutSink>,
        /// In-flight correlated one-shot waiters. Key = runtime-minted correlation
        /// id (never derived from JS input). A reply whose id is not in this map is
        /// dropped fail-closed (unknown/duplicate/late id). Bounded by
        /// [`MAX_OUTSTANDING`]: a new waiter is refused when the map is full.
        pub(crate) pending: HashMap<u64, oneshot::Sender<JsonVal>>,
        /// Open session streams, keyed by runtime-minted session id (never derived
        /// from JS input). A frame/terminal whose id is not in this map is dropped
        /// fail-closed. Bounded by [`MAX_OPEN_SESSIONS`]: a new `openSession` is
        /// refused when the map is full.
        pub(crate) streams: HashMap<u64, SessionStream>,
        /// Outbound port frames produced before `out_sink` was bound (the window
        /// between session creation and the SSE connection that installs the
        /// sink). Flushed in FIFO order the instant the sink binds, so a `Cmd`
        /// dispatched pre-handshake — `Geo.current`, `Clipboard.read` — is
        /// delivered rather than dropped. Bounded by [`MAX_OUT_PENDING`]:
        /// drop-oldest at the ceiling, so a pre-bind flood cannot grow heap.
        pub(crate) out_pending: std::collections::VecDeque<String>,
    }

    /// One open session's state: the bounded frame channel a `sessionFrames`
    /// subscriber drains, the frame budget already spent, and the one-shot the
    /// `closeSession` waiter is parked on. Bounded by construction — the channel
    /// capacity caps the in-flight buffer and the budget caps lifetime frames.
    pub(crate) struct SessionStream {
        /// Bounded broadcast of decoded-ready inbound stream frames for THIS
        /// session. A lagging subscriber skips the gap (never panics); the
        /// capacity bounds the burst a slow subscriber can hold.
        pub(crate) frames: broadcast::Sender<String>,
        /// Frames routed to this session so far. When it reaches
        /// [`SESSION_FRAME_BUDGET`] the session is terminated fail-closed with an
        /// overflow terminal `Err` and evicted — an ordered stream never silently
        /// drops.
        pub(crate) frames_seen: u64,
        /// The `closeSession` one-shot waiter, installed when `closeSession` is
        /// called. A terminal frame (or a fail-closed overflow/timeout) resolves it
        /// exactly once, then the session is evicted. `None` until close is awaited.
        pub(crate) terminal: Option<oneshot::Sender<JsonVal>>,
    }

    impl SessionPorts {
        pub(crate) fn new() -> Self {
            SessionPorts {
                inbound: broadcast::channel(PORT_CAP).0,
                out_sink: None,
                pending: HashMap::new(),
                streams: HashMap::new(),
                out_pending: std::collections::VecDeque::new(),
            }
        }
    }

    /// The per-session port registry, keyed by session sid. A channel handle is
    /// ONLY ever obtained by looking up a [`SessionId`] here; there is no
    /// process-global channel, so no `js_send`/`js_subscribe`/inbound-route can
    /// reach a session other than the one whose sid it holds — cross-session
    /// delivery is unrepresentable.
    fn sessions() -> &'static Mutex<HashMap<String, SessionPorts>> {
        static S: OnceLock<Mutex<HashMap<String, SessionPorts>>> = OnceLock::new();
        S.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub(crate) fn lock_sessions() -> std::sync::MutexGuard<'static, HashMap<String, SessionPorts>> {
        // Poison-tolerant: a panic in one session's callback must not wedge the
        // whole registry; the map is still valid data.
        sessions().lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The sid of the session whose subscriptions/commands are being materialised
    /// in the current scope. Under the `web` server this reads the same task-local
    /// the pub/sub broker sets (via `pubsub::with_session_sid`), so a `js_subscribe`
    /// binds to the OWNING session. Outside a live server (e.g. a `tokio`-only test
    /// build with no `web` feature) there is no session scope, so it returns `None`
    /// and callers fall back to an inert private channel.
    #[cfg(feature = "web")]
    pub(super) fn scope_sid() -> Option<SessionId> {
        SessionId::parse(&crate::web::pubsub::current_session_sid())
    }
    #[cfg(not(feature = "web"))]
    pub(super) fn scope_sid() -> Option<SessionId> {
        None
    }

    /// Create a session's port endpoints on session start (idempotent). Called by
    /// the live server when it creates the session, so the inbound channel exists
    /// before the browser can POST to it.
    pub fn session_open(sid: &SessionId) {
        lock_sessions()
            .entry(sid.0.clone())
            .or_insert_with(SessionPorts::new);
    }

    /// Drop a session's port endpoints on session end/eviction. Any live
    /// `js_subscribe` receiver on the dropped inbound channel observes `Closed`
    /// and ends; no dead-session channel lingers.
    pub fn session_close(sid: &SessionId) {
        lock_sessions().remove(&sid.0);
    }

    /// Install `sid`'s browser-push sink. Called when the live server attaches the
    /// session's client transport; every subsequent `js_send` whose origin is
    /// `sid` is delivered to `sink`. Creates the session entry if the sink is
    /// wired before `session_open` (idempotent).
    pub fn register_out_sink_for(sid: &SessionId, sink: OutSink) {
        // Take the sink and drain the pre-bind buffer under one lock acquisition,
        // then deliver the drained frames after the guard drops — the sink is a
        // synchronous callback and must never run while the registry mutex is
        // held (it re-enters no lock here, but keeping delivery outside the guard
        // preserves that invariant for every sink shape).
        let buffered = {
            let mut g = lock_sessions();
            let ports = g.entry(sid.0.clone()).or_insert_with(SessionPorts::new);
            ports.out_sink = Some(sink.clone());
            std::mem::take(&mut ports.out_pending)
        };
        for encoded in buffered {
            sink(&encoded);
        }
    }

    /// Deliver one encoded outbound frame to `sid`'s browser out-sink, or buffer
    /// it fail-closed when no sink is bound yet. This is the single outbound
    /// delivery point: every `js_send`/`js_request`/`js_open_session`/
    /// `js_send_to_session` routes its frame through here, so the drop-vs-buffer
    /// policy lives in exactly one place. A frame produced before the SSE
    /// connection installs the sink is queued in the session's bounded
    /// [`SessionPorts::out_pending`] and flushed on [`register_out_sink_for`];
    /// past the [`MAX_OUT_PENDING`] ceiling the OLDEST buffered frame is dropped
    /// so a pre-bind flood cannot grow heap without limit.
    pub(crate) fn deliver_or_buffer(sid: &SessionId, encoded: &str) {
        let sink = {
            let mut g = lock_sessions();
            let ports = g.entry(sid.0.clone()).or_insert_with(SessionPorts::new);
            match &ports.out_sink {
                Some(sink) => Some(sink.clone()),
                None => {
                    if ports.out_pending.len() >= MAX_OUT_PENDING {
                        ports.out_pending.pop_front();
                    }
                    ports.out_pending.push_back(encoded.to_string());
                    None
                }
            }
        };
        if let Some(sink) = sink {
            sink(encoded);
        }
    }

    /// Feed one raw inbound string to `sid`'s port. Called by the server's inbound
    /// port route AFTER its session-cookie + CSRF + bounded-seal checks.
    ///
    /// Dispatch policy (fail-closed at each step):
    ///
    /// 1. If the raw string is valid JSON and its top-level object contains the
    ///    runtime-private `__ipe_id` field, this is a correlated reply: extract the
    ///    id and the rest of the frame, look up the matching one-shot waiter, and
    ///    resolve it. An unknown/duplicate/late id is silently dropped (no panic, no
    ///    forwarding to `js_subscribe` subscribers). The `__ipe_id` field is stripped
    ///    before the reply payload is handed to the waiter's decoder, so it is never
    ///    user-visible.
    /// 2. Otherwise forward to the session's `js_subscribe` broadcast channel.
    ///
    /// Cross-session delivery is unrepresentable: delivery reaches ONLY `sid`.
    pub fn deliver_inbound_for(sid: &SessionId, raw: String) {
        // A session-tagged frame (carrying `__ipe_session`) is routed to that
        // session's stream/terminal BEFORE the one-shot-reply check, so a session
        // frame can never be misrouted to a `js_request` waiter or a broadcast
        // subscriber. An unknown/closed/foreign session id is dropped fail-closed.
        if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&raw)
            && let Some(sess_val) = value
                .as_object_mut()
                .and_then(|o| o.remove(SESSION_ID_FIELD))
            && let Some(session_id) = sess_val.as_u64()
        {
            deliver_session_frame(sid, session_id, value);
            return;
        }
        // Peek at the raw string: if it parses as a JSON object with `__ipe_id`,
        // this is a correlated reply — route to the pending map, not subscribers.
        // Wire format: `{"__ipe_id": <u64>, "payload": <sealed_reply>}`.
        // After stripping `__ipe_id`, the remaining object's `"payload"` field is
        // the sealed reply value forwarded to the waiting decoder.
        if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&raw)
            && let Some(id_val) = value.as_object_mut().and_then(|o| o.remove(COR_ID_FIELD))
            && let Some(id) = id_val.as_u64()
        {
            // Extract the `"payload"` field from the remaining envelope,
            // falling back to the whole remaining value so an echo that omits
            // the wrapper is still decoded (fail-closed if neither decodes).
            let payload = value
                .as_object_mut()
                .and_then(|o| o.remove("payload"))
                .unwrap_or(value);
            let waiter = lock_sessions()
                .get_mut(&sid.0)
                .and_then(|p| p.pending.remove(&id));
            if let Some(tx) = waiter {
                // Resolve the one-shot with the extracted payload.
                let _ = tx.send(payload);
            }
            // Unknown/duplicate/late id: dropped fail-closed, no subscribers.
            return;
        }
        // No correlation id — forward to `js_subscribe` subscribers as before.
        let sender = lock_sessions().get(&sid.0).map(|p| p.inbound.clone());
        if let Some(tx) = sender {
            let _ = tx.send(raw);
        }
    }

    /// Route one session-tagged inbound value to the session identified by the
    /// runtime-minted `session_id` within the owning `sid`. Fail-closed at every
    /// step:
    ///
    /// * An unknown/closed/foreign `session_id` (no live stream in `sid`'s
    ///   registry) is dropped whole — no cross-session/cross-handle leak, no panic.
    /// * A value tagged `__ipe_terminal: true` resolves the session's `closeSession`
    ///   one-shot with the stripped payload and evicts the session.
    /// * Any other value is an ordinary stream frame: it counts against the frame
    ///   budget and is broadcast to the session's `sessionFrames` subscriber. When
    ///   the budget is exhausted the session is terminated with an overflow terminal
    ///   `Err` and evicted (an ordered stream never silently drops a frame).
    ///
    /// The `session_id` is the registry key minted by [`next_cor_id`]; a
    /// JS-injected id cannot forge a live session because the key is never derived
    /// from an inbound frame.
    fn deliver_session_frame(sid: &SessionId, session_id: u64, mut value: serde_json::Value) {
        let is_terminal = value
            .as_object_mut()
            .and_then(|o| o.remove(SESSION_TERMINAL_FIELD))
            .and_then(|t| t.as_bool())
            .unwrap_or(false);
        // Extract the inner `"payload"`, falling back to the whole remaining value.
        let payload = value
            .as_object_mut()
            .and_then(|o| o.remove("payload"))
            .unwrap_or(value);

        let mut g = lock_sessions();
        let Some(ports) = g.get_mut(&sid.0) else {
            return; // no such session sid — dropped fail-closed
        };
        if is_terminal {
            // Terminal reply: resolve the close waiter (if any) and evict.
            if let Some(stream) = ports.streams.remove(&session_id)
                && let Some(tx) = stream.terminal
            {
                let _ = tx.send(payload);
            }
            // Unknown/closed session id, or a terminal with no close waiter yet:
            // dropped fail-closed (the close Task resolves via its own deadline).
            return;
        }
        // Ordinary stream frame. Charge the budget FIRST; on exhaustion terminate
        // fail-closed rather than deliver-and-overflow.
        let Some(stream) = ports.streams.get_mut(&session_id) else {
            return; // unknown/closed/foreign session id — dropped fail-closed
        };
        stream.frames_seen = stream.frames_seen.saturating_add(1);
        if stream.frames_seen > SESSION_FRAME_BUDGET {
            // Overflow: terminate the session with a fail-closed terminal Err and
            // evict. A parked close waiter observes the sender drop and resolves
            // Err; a live `sessionFrames` subscriber sees the channel close and ends.
            g.get_mut(&sid.0).map(|p| p.streams.remove(&session_id));
            return;
        }
        // Deliver the frame to the session's subscriber. The value is re-encoded to
        // its canonical string; the `sessionFrames` drain decodes it fail-closed
        // through the seal gate, exactly as `js_subscribe` does.
        let _ = stream.frames.send(payload.to_string());
    }

    /// `js_send payload` — seal-encode `payload` and deliver it to the ORIGIN
    /// session's browser out-sink. Fire-and-forget via [`IpeCmd::Publish`]; the
    /// dispatch loop supplies the origin sid (the same sid it injects for
    /// `Cmd.publish`). The thunk returns 0 (a port has no subscriber-count
    /// semantics).
    pub fn js_send<T, M>(payload: T) -> IpeCmd<M>
    where
        T: serde::Serialize + Send + 'static,
    {
        IpeCmd::Publish(Box::new(move |origin| {
            // A seal-legal payload's concrete type serialises to a JSON value by
            // construction (the seal gate — IPE-L0148 — guarantees a plain, closed,
            // non-secret type), so this Err branch is unreachable for a seal-legal
            // caller. Surface it honestly instead of silently dropping the frame:
            // log the offending type and drop the single frame rather than emit a
            // malformed wire string. The seal is not loosened either way.
            match serde_json::to_value(&payload) {
                Ok(value) => {
                    let encoded = seal_encode(&value);
                    if let Some(sid) = SessionId::parse(origin) {
                        deliver_or_buffer(&sid, &encoded);
                    }
                }
                Err(e) => {
                    crate::system::write_stderr_line(&format!(
                        "[ipe-runtime BUG] js_send: payload of type {} failed serialisation ({e}); frame dropped — please report",
                        std::any::type_name::<T>()
                    ));
                }
            }
            0
        }))
    }

    /// `js_subscribe decoder to_msg` — drain the OWNING session's inbound port
    /// strings, decode each fail-closed through the bounded seal decoder, and emit
    /// `to_msg(a)` on a clean decode. A rejected payload is dropped whole.
    ///
    /// The owning session's sid is read SYNCHRONOUSLY here (while the driver's
    /// `with_session_sid` scope is active), then moved into the spawned task, so
    /// the recv loop drains exactly that session's channel and can never observe
    /// another session's inbound frames. A subscription materialised with no
    /// session sid in scope (no valid [`SessionId`]) binds an inert per-call
    /// channel that no route feeds, so it receives nothing.
    ///
    /// `to_msg` is moved into exactly one detached task and never shared behind an
    /// `Arc`, so `Send` (not `Send + Sync`) is the exact contract — the same
    /// bound `sub_subscribe_ws_message` carries.
    pub fn js_subscribe<T, M, F>(decoder: Decoder<IpeError, T>, to_msg: F) -> IpeSub<M>
    where
        M: Send + 'static,
        F: Fn(T) -> M + Send + 'static,
        T: Send + 'static,
    {
        // Read the owning sid while the materialisation scope is live, then bind
        // this session's inbound receiver. No valid sid (no live session) gets a
        // fresh private channel no route publishes to — an inert, fail-closed drain.
        let rx = match scope_sid() {
            None => broadcast::channel(PORT_CAP).1,
            Some(owner_sid) => {
                let mut g = lock_sessions();
                g.entry(owner_sid.0)
                    .or_insert_with(SessionPorts::new)
                    .inbound
                    .subscribe()
            }
        };
        IpeSub::Source(Box::new(move |emit| {
            let mut rx = rx;
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(raw) => {
                            // Fail-closed decode: a payload that does not decode to
                            // the declared type is dropped whole, never a partial
                            // value and never a panic.
                            if let Ok(value) = seal_decode(&raw, &decoder, SealLimits::default()) {
                                emit(to_msg(value));
                            }
                        }
                        // A slow consumer that lagged past the buffer skips the
                        // gap and keeps the subscription alive; a closed channel
                        // (the session was evicted) ends it.
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            })
        }))
    }

    /// `js_request payload decoder` — correlated one-shot port request.
    ///
    /// Semantics:
    ///
    /// 1. Mint a fresh runtime-private correlation id (process-global monotonic
    ///    counter; never derived from JS input, never user-observable).
    /// 2. Register a one-shot waiter keyed by that id in the OWNING session's
    ///    pending map. Fails immediately with `Err` when [`MAX_OUTSTANDING`] is
    ///    already reached (bounded — heap cannot grow unboundedly).
    /// 3. Send `payload` outbound as `{"__ipe_id": id, "payload": <sealed>}` so
    ///    the first-party JS sink can echo the id on its reply.
    /// 4. Await the one-shot with a [`REQUEST_TIMEOUT_MS`] deadline. A reply whose
    ///    id matches resolves the waiter with the stripped reply frame; the decoder
    ///    runs fail-closed over that frame. A duplicate/late/unknown id is dropped
    ///    by `deliver_inbound_for` before the waiter is ever signalled.
    /// 5. Timeout or decode-miss → typed `Err`; never a panic.
    ///
    /// No trust change: the same SEAL discipline governs both directions.
    pub fn js_request<T, R>(
        payload: T,
        decoder: Decoder<IpeError, R>,
    ) -> crate::core::IpeTask<IpeError, R>
    where
        T: serde::Serialize + Send + 'static,
        R: Send + 'static,
    {
        let cor_id = next_cor_id();
        let owner_sid = scope_sid();
        Box::pin(async move {
            // Refuse when the ceiling is already reached (fail-closed, no panic).
            {
                let mut g = lock_sessions();
                if let Some(ports) = owner_sid.as_ref().and_then(|s| g.get_mut(&s.0))
                    && ports.pending.len() >= MAX_OUTSTANDING
                {
                    return crate::core::IpeResult::Err(
                        "js_request: outstanding waiter ceiling reached"
                            .to_string()
                            .into(),
                    );
                }
            }

            // Serialize payload and wrap with the correlation id.
            let outbound_json = match serde_json::to_value(&payload) {
                Ok(v) => v,
                Err(e) => {
                    return crate::core::IpeResult::Err(
                        format!("js_request: payload serialisation failed: {e}").into(),
                    );
                }
            };
            let envelope = serde_json::json!({
                COR_ID_FIELD: cor_id,
                "payload": outbound_json,
            });
            let encoded = seal_encode(&envelope);

            // Register the one-shot waiter.
            let (tx, rx) = oneshot::channel::<JsonVal>();
            if let Some(sid) = &owner_sid {
                let mut g = lock_sessions();
                g.entry(sid.0.clone())
                    .or_insert_with(SessionPorts::new)
                    .pending
                    .insert(cor_id, tx);
            }
            // Deliver outbound to the origin session's sink, or buffer it
            // fail-closed until the SSE connection binds the sink.
            if let Some(sid) = &owner_sid {
                deliver_or_buffer(sid, &encoded);
            }

            // Await reply with deadline.
            let timeout = tokio::time::Duration::from_millis(REQUEST_TIMEOUT_MS);
            let result = tokio::time::timeout(timeout, rx).await;

            // Clean up the waiter regardless of outcome (idempotent — already
            // removed by `deliver_inbound_for` on a clean reply).
            if let Some(sid) = &owner_sid {
                lock_sessions()
                    .get_mut(&sid.0)
                    .map(|p| p.pending.remove(&cor_id));
            }

            match result {
                Ok(Ok(reply_value)) => {
                    // Decode the reply fail-closed through the seal gate.
                    match seal_decode(&reply_value.to_string(), &decoder, SealLimits::default()) {
                        Ok(v) => crate::core::IpeResult::Ok(v),
                        Err(_) => crate::core::IpeResult::Err(
                            "js_request: reply failed seal decode".to_string().into(),
                        ),
                    }
                }
                Ok(Err(_)) => {
                    // Sender dropped (session evicted or process exit) — fail closed.
                    crate::core::IpeResult::Err(
                        "js_request: session closed before reply".to_string().into(),
                    )
                }
                Err(_) => {
                    // Timeout.
                    crate::core::IpeResult::Err("js_request: timeout".to_string().into())
                }
            }
        })
    }

    /// `js_open_session open_cmd _decoder` — open a bounded, session-scoped stream.
    ///
    /// Semantics (generalising `js_request`'s one-shot correlation to a bounded
    /// multi-frame lifecycle):
    ///
    /// 1. Mint a fresh runtime-private session id (the same counter `js_request`
    ///    uses; never derived from JS input, never user-observable).
    /// 2. Refuse when [`MAX_OPEN_SESSIONS`] is already open in the owning session
    ///    (fail-closed, bounded — heap cannot grow unboundedly).
    /// 3. Register the session's bounded frame channel keyed by that id, then send
    ///    `open_cmd` outbound tagged with the id so the first-party JS glue routes
    ///    every subsequent frame/terminal back with it.
    /// 4. Return the minted id as the opaque `SessionHandle` (a runtime `i64`); the
    ///    handle is the ONLY way to address the session — cross-handle addressing is
    ///    unrepresentable because the id is never taken from JS.
    ///
    /// The `decoder` is not consumed here (the frame stream carries it in
    /// `js_session_frames`); it fixes the frame type at the type level.
    pub fn js_open_session<T, F>(
        open_cmd: T,
        _decoder: Decoder<IpeError, F>,
    ) -> crate::core::IpeTask<IpeError, i64>
    where
        T: serde::Serialize + Send + 'static,
        F: Send + 'static,
    {
        let session_id = next_cor_id();
        let owner_sid = scope_sid();
        Box::pin(async move {
            let Some(sid) = owner_sid else {
                return crate::core::IpeResult::Err(
                    "js_open_session: no session in scope".to_string().into(),
                );
            };
            // Refuse at the ceiling (fail-closed, no panic).
            {
                let mut g = lock_sessions();
                let ports = g.entry(sid.0.clone()).or_insert_with(SessionPorts::new);
                if ports.streams.len() >= MAX_OPEN_SESSIONS {
                    return crate::core::IpeResult::Err(
                        "js_open_session: open-session ceiling reached"
                            .to_string()
                            .into(),
                    );
                }
                ports.streams.insert(
                    session_id,
                    SessionStream {
                        frames: broadcast::channel(PORT_CAP).0,
                        frames_seen: 0,
                        terminal: None,
                    },
                );
            }
            // Serialize + tag the open cmd with the session id.
            let outbound_json = match serde_json::to_value(&open_cmd) {
                Ok(v) => v,
                Err(e) => {
                    lock_sessions()
                        .get_mut(&sid.0)
                        .map(|p| p.streams.remove(&session_id));
                    return crate::core::IpeResult::Err(
                        format!("js_open_session: open cmd serialisation failed: {e}").into(),
                    );
                }
            };
            let envelope = serde_json::json!({
                SESSION_ID_FIELD: session_id,
                "payload": outbound_json,
            });
            let encoded = seal_encode(&envelope);
            deliver_or_buffer(&sid, &encoded);
            crate::core::IpeResult::Ok(session_id as i64)
        })
    }

    /// `js_session_frames handle to_msg` — the inbound frame stream for ONE session.
    ///
    /// Drains only the frame channel keyed by `handle`'s runtime-minted id in the
    /// owning session, decoding each frame fail-closed through the bounded seal
    /// decoder (a rejected frame is dropped whole, never a partial value, never a
    /// panic). A `handle` with no live stream (closed/evicted/foreign) binds an
    /// inert channel no route feeds — it receives nothing.
    pub fn js_session_frames<T, M, F>(
        handle: i64,
        decoder: Decoder<IpeError, T>,
        to_msg: F,
    ) -> IpeSub<M>
    where
        M: Send + 'static,
        F: Fn(T) -> M + Send + 'static,
        T: Send + 'static,
    {
        let session_id = handle as u64;
        // Bind this session's frame receiver while the materialisation scope is
        // live. A missing session (unknown id / no scope) gets a fresh private
        // channel no route publishes to — an inert, fail-closed drain.
        let rx = match scope_sid() {
            None => broadcast::channel(PORT_CAP).1,
            Some(owner_sid) => {
                let g = lock_sessions();
                match g.get(&owner_sid.0).and_then(|p| p.streams.get(&session_id)) {
                    Some(stream) => stream.frames.subscribe(),
                    None => broadcast::channel(PORT_CAP).1,
                }
            }
        };
        IpeSub::Source(Box::new(move |emit| {
            let mut rx = rx;
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(raw) => {
                            if let Ok(value) = seal_decode(&raw, &decoder, SealLimits::default()) {
                                emit(to_msg(value));
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            })
        }))
    }

    /// `js_send_to_session handle session_cmd` — send a control cmd to ONE session.
    ///
    /// Fire-and-forget via [`IpeCmd::Publish`]; the cmd is seal-encoded, tagged with
    /// the session id, and delivered to the ORIGIN session's out-sink so the JS glue
    /// routes it to that session's host recorder. A cmd for a session that is not
    /// open is delivered to the sink but recognised by no live host recorder (the
    /// tag names a dead id) — a fail-closed no-op, never cross-session.
    pub fn js_send_to_session<T, M>(handle: i64, session_cmd: T) -> IpeCmd<M>
    where
        T: serde::Serialize + Send + 'static,
    {
        let session_id = handle as u64;
        IpeCmd::Publish(Box::new(move |origin| {
            match serde_json::to_value(&session_cmd) {
                Ok(value) => {
                    let envelope = serde_json::json!({
                        SESSION_ID_FIELD: session_id,
                        "payload": value,
                    });
                    let encoded = seal_encode(&envelope);
                    if let Some(sid) = SessionId::parse(origin) {
                        deliver_or_buffer(&sid, &encoded);
                    }
                }
                Err(e) => {
                    crate::system::write_stderr_line(&format!(
                        "[ipe-runtime BUG] js_send_to_session: cmd of type {} failed serialisation ({e}); frame dropped — please report",
                        std::any::type_name::<T>()
                    ));
                }
            }
            0
        }))
    }

    /// `js_close_session handle close_cmd decoder` — close a session and await its
    /// terminal reply.
    ///
    /// 1. Install a one-shot terminal waiter on the session (if it is still open).
    /// 2. Send `close_cmd` outbound tagged with the id so the host recorder emits
    ///    its terminal frame.
    /// 3. Await the terminal with a [`SESSION_DEADLINE_MS`] deadline; on arrival,
    ///    decode it fail-closed through the seal gate. A timeout, a decode-miss, an
    ///    overflow eviction, or an already-closed session → typed `Err`, never a
    ///    panic. The session id is evicted regardless of outcome.
    pub fn js_close_session<T, R>(
        handle: i64,
        close_cmd: T,
        decoder: Decoder<IpeError, R>,
    ) -> crate::core::IpeTask<IpeError, R>
    where
        T: serde::Serialize + Send + 'static,
        R: Send + 'static,
    {
        let session_id = handle as u64;
        let owner_sid = scope_sid();
        Box::pin(async move {
            let Some(sid) = owner_sid else {
                return crate::core::IpeResult::Err(
                    "js_close_session: no session in scope".to_string().into(),
                );
            };
            // Install the terminal waiter on the live session; fail closed if the
            // session is not open (already closed / evicted / never opened / foreign).
            let (tx, rx) = oneshot::channel::<JsonVal>();
            {
                let mut g = lock_sessions();
                match g
                    .get_mut(&sid.0)
                    .and_then(|p| p.streams.get_mut(&session_id))
                {
                    Some(stream) => stream.terminal = Some(tx),
                    None => {
                        return crate::core::IpeResult::Err(
                            "js_close_session: session not open".to_string().into(),
                        );
                    }
                }
            }
            // Serialize + tag the close cmd and deliver it.
            match serde_json::to_value(&close_cmd) {
                Ok(v) => {
                    let envelope = serde_json::json!({
                        SESSION_ID_FIELD: session_id,
                        "payload": v,
                    });
                    let encoded = seal_encode(&envelope);
                    // Route through the single delivery chokepoint so a close
                    // Cmd fired during an SSE reopen window (sink not yet
                    // rebound) is buffered in the session's bounded
                    // `out_pending` and flushed on rebind, rather than dropped
                    // fire-and-forget.
                    deliver_or_buffer(&sid, &encoded);
                }
                Err(e) => {
                    lock_sessions()
                        .get_mut(&sid.0)
                        .map(|p| p.streams.remove(&session_id));
                    return crate::core::IpeResult::Err(
                        format!("js_close_session: close cmd serialisation failed: {e}").into(),
                    );
                }
            }
            // Await the terminal with the deadline.
            let timeout = tokio::time::Duration::from_millis(SESSION_DEADLINE_MS);
            let result = tokio::time::timeout(timeout, rx).await;
            // Evict the session regardless of outcome (idempotent — the terminal
            // router already removed it on a clean terminal).
            lock_sessions()
                .get_mut(&sid.0)
                .map(|p| p.streams.remove(&session_id));

            match result {
                Ok(Ok(terminal_value)) => {
                    match seal_decode(&terminal_value.to_string(), &decoder, SealLimits::default())
                    {
                        Ok(v) => crate::core::IpeResult::Ok(v),
                        Err(_) => crate::core::IpeResult::Err(
                            "js_close_session: terminal failed seal decode"
                                .to_string()
                                .into(),
                        ),
                    }
                }
                Ok(Err(_)) => crate::core::IpeResult::Err(
                    // Sender dropped — the session was evicted (overflow/deadline)
                    // before a terminal arrived. Fail closed with an overflow Err.
                    "js_close_session: session terminated before reply"
                        .to_string()
                        .into(),
                ),
                Err(_) => {
                    crate::core::IpeResult::Err("js_close_session: timeout".to_string().into())
                }
            }
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::{
    deliver_inbound_for, js_close_session, js_open_session, js_request, js_send,
    js_send_to_session, js_session_frames, js_subscribe, register_out_sink_for, session_close,
    session_open,
};

// Consumed only by the `web`-gated `per_session` test submodule below; gate the
// re-export to match so a `db`-without-`web` test build has no unused import.
#[cfg(all(not(target_arch = "wasm32"), test, feature = "web"))]
pub(crate) use native::{SessionPorts, lock_sessions};

// ─── Wasm (browser) transport ──────────────────────────────────────────────
//
// The `Ffi.Js` port transport reaches a JS host — a browser tab (`wasm-client`)
// or the native SSE server. WASI (`wasm32-wasip1`) has neither, so this browser
// arm is gated on `wasm-client`, never bare `wasm32`; the module itself is not
// compiled for a co-located WASI build (see the `js_port` gate in `mod.rs`).
#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
mod wasm {
    use super::*;
    use crate::error::IpeError;
    use crate::json::{Decoder, JsonVal};
    use crate::seal_codec::seal_decode;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;
    use wasm_bindgen::{JsCast, JsValue};

    /// Process-local monotonic correlation-id counter for the wasm target.
    /// Single-threaded (wasm32 is `!Send`), so `Cell<u64>` is safe.
    thread_local! {
        static NEXT_ID: std::cell::Cell<u64> = const { std::cell::Cell::new(1) };
    }

    fn next_cor_id() -> u64 {
        NEXT_ID.with(|c| {
            let id = c.get();
            c.set(id.wrapping_add(1));
            id
        })
    }

    thread_local! {
        /// The in-tab inbound queue's drains. The browser's `window.ipe.send(raw)`
        /// pushes a string here (via [`push_inbound`]); each active `js_subscribe`
        /// registers a drain closure that fires on every pushed string.
        static INBOUND: RefCell<Vec<Rc<dyn Fn(&str)>>> = const { RefCell::new(Vec::new()) };

        /// In-flight correlated one-shot waiters. Key = runtime-minted id.
        /// A reply whose id is not in this map is dropped fail-closed.
        static PENDING: RefCell<HashMap<u64, Box<dyn FnOnce(JsonVal)>>> =
            RefCell::new(HashMap::new());

        /// Open session streams, keyed by runtime-minted session id (never derived
        /// from JS input). Each holds the live `sessionFrames` drains, the frame
        /// budget spent, and the one-shot terminal waiter. A frame/terminal whose id
        /// is not in this map is dropped fail-closed. Bounded by
        /// [`MAX_OPEN_SESSIONS`].
        static SESSIONS: RefCell<HashMap<u64, WasmSession>> = RefCell::new(HashMap::new());
    }

    /// One open session's browser-local state.
    struct WasmSession {
        /// The `sessionFrames` drains for THIS session (each a fail-closed decoder).
        drains: Vec<Rc<dyn Fn(&str)>>,
        /// Frames routed so far; charged before delivery so an overflow terminates
        /// the session rather than delivering past the budget.
        frames_seen: u64,
        /// The `closeSession` terminal one-shot (resolves the awaiting Task once).
        terminal: Option<Box<dyn FnOnce(JsonVal)>>,
    }

    /// The browser-facing entry the JS glue calls to push an inbound port
    /// message: `window.ipe.send(raw)` routes here.
    ///
    /// Dispatch: if the raw JSON has `__ipe_id`, route to the pending waiter
    /// (correlated reply); otherwise fan out to all `js_subscribe` drains.
    pub fn push_inbound(raw: &str) {
        // A session-tagged frame is routed to its session BEFORE the one-shot-reply
        // check, so a session frame can never be misrouted. Unknown id → dropped.
        if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(raw)
            && let Some(sess_val) = value
                .as_object_mut()
                .and_then(|o| o.remove(SESSION_ID_FIELD))
            && let Some(session_id) = sess_val.as_u64()
        {
            deliver_session_frame(session_id, value);
            return;
        }
        // Peek for a correlation id (fail-closed: a parse error falls through).
        // Wire format: `{"__ipe_id": <u64>, "payload": <sealed_reply>}`.
        if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(raw)
            && let Some(id_val) = value.as_object_mut().and_then(|o| o.remove(COR_ID_FIELD))
            && let Some(id) = id_val.as_u64()
        {
            // Extract `"payload"`, falling back to the whole remaining value.
            let payload = value
                .as_object_mut()
                .and_then(|o| o.remove("payload"))
                .unwrap_or(value);
            let waiter = PENDING.with(|p| p.borrow_mut().remove(&id));
            if let Some(cb) = waiter {
                cb(payload);
            }
            // Unknown/duplicate/late id: dropped fail-closed.
            return;
        }
        let drains: Vec<Rc<dyn Fn(&str)>> =
            INBOUND.with(|q| q.borrow().iter().map(Rc::clone).collect());
        for drain in drains {
            drain(raw);
        }
    }

    /// Route one session-tagged inbound value to the session `session_id`.
    /// Fail-closed: an unknown/closed session id is dropped whole; a terminal
    /// resolves the close waiter and evicts; an ordinary frame is charged against
    /// the budget and fanned to the session's drains, terminating on overflow.
    fn deliver_session_frame(session_id: u64, mut value: serde_json::Value) {
        let is_terminal = value
            .as_object_mut()
            .and_then(|o| o.remove(SESSION_TERMINAL_FIELD))
            .and_then(|t| t.as_bool())
            .unwrap_or(false);
        let payload = value
            .as_object_mut()
            .and_then(|o| o.remove("payload"))
            .unwrap_or(value);

        if is_terminal {
            let waiter = SESSIONS.with(|s| {
                s.borrow_mut()
                    .remove(&session_id)
                    .and_then(|sess| sess.terminal)
            });
            if let Some(cb) = waiter {
                cb(payload);
            }
            return;
        }
        // Charge the budget; on overflow evict (drops the terminal waiter → the
        // close Task resolves Err) rather than deliver past the bound.
        let drains = SESSIONS.with(|s| {
            let mut map = s.borrow_mut();
            let Some(sess) = map.get_mut(&session_id) else {
                return None;
            };
            sess.frames_seen = sess.frames_seen.saturating_add(1);
            if sess.frames_seen > SESSION_FRAME_BUDGET {
                map.remove(&session_id);
                return None;
            }
            Some(sess.drains.iter().map(Rc::clone).collect::<Vec<_>>())
        });
        if let Some(drains) = drains {
            let raw = payload.to_string();
            for drain in drains {
                drain(&raw);
            }
        }
    }

    /// Deliver one seal-encoded outbound frame to the browser by calling the
    /// registered `window.ipeOnReceive` handler. A missing or non-callable
    /// handler is a no-op (the page simply has not wired a receiver yet).
    fn deliver_outbound(encoded: &str) {
        let Some(window) = web_sys::window() else {
            return;
        };
        let Ok(handler) = js_sys::Reflect::get(&window, &JsValue::from_str("ipeOnReceive")) else {
            return;
        };
        if let Ok(func) = handler.dyn_into::<js_sys::Function>() {
            let _ = func.call1(&JsValue::NULL, &JsValue::from_str(encoded));
        }
    }

    /// `js_send payload` — seal-encode `payload` and hand it to the browser
    /// `window.ipeOnReceive` handler in-process. Fire-and-forget via
    /// [`IpeCmd::Publish`].
    pub fn js_send<T, M>(payload: T) -> IpeCmd<M>
    where
        // `IpeCmd::Publish` carries a `Send` thunk on every target (the enum
        // variant is target-neutral), so the captured payload is `Send` even
        // though the wasm delivery runs single-threaded.
        T: serde::Serialize + Send + 'static,
    {
        IpeCmd::Publish(Box::new(move |_origin| {
            if let Ok(value) = serde_json::to_value(&payload) {
                deliver_outbound(&seal_encode(&value));
            }
            0
        }))
    }

    /// `js_subscribe decoder to_msg` — register a drain that decodes each inbound
    /// string fail-closed and emits `to_msg(a)` on a clean decode. Returns a real
    /// teardown thunk so the scheduler's stop-all-then-respawn cycle can drop the
    /// drain instead of accumulating duplicates across re-renders.
    pub fn js_subscribe<T, M, F>(decoder: Decoder<IpeError, T>, to_msg: F) -> IpeSub<M>
    where
        M: 'static,
        F: Fn(T) -> M + 'static,
        T: 'static,
    {
        IpeSub::Source(Box::new(move |emit: Rc<dyn Fn(M)>| {
            let decoder = decoder.clone();
            let drain: Rc<dyn Fn(&str)> = Rc::new(move |raw: &str| {
                if let Ok(value) = seal_decode(raw, &decoder, SealLimits::default()) {
                    (emit)(to_msg(value));
                }
            });
            let drain_key = Rc::as_ptr(&drain) as *const () as usize;
            INBOUND.with(|q| q.borrow_mut().push(Rc::clone(&drain)));
            Box::new(move || {
                INBOUND.with(|q| {
                    q.borrow_mut()
                        .retain(|d| Rc::as_ptr(d) as *const () as usize != drain_key);
                });
            })
        }))
    }

    /// `js_request payload decoder` — correlated one-shot port request (wasm).
    ///
    /// Mirrors the native semantics using a `js_sys::Promise`-based future (the
    /// wasm-compatible async primitive). A `resolve`/`reject` pair is stored in
    /// `PENDING`; `push_inbound` calls `resolve` when the correlated reply arrives.
    /// A `setTimeout` races the promise: whichever fires first wins.
    pub fn js_request<T, R>(
        payload: T,
        decoder: Decoder<IpeError, R>,
    ) -> crate::core::IpeTask<IpeError, R>
    where
        T: serde::Serialize + 'static,
        R: 'static,
    {
        let cor_id = next_cor_id();
        Box::pin(async move {
            // Refuse when the ceiling is already reached.
            let at_limit = PENDING.with(|p| p.borrow().len() >= MAX_OUTSTANDING);
            if at_limit {
                return crate::core::IpeResult::Err(
                    "js_request: outstanding waiter ceiling reached"
                        .to_string()
                        .into(),
                );
            }

            // Serialize and wrap with the correlation id.
            let outbound_json = match serde_json::to_value(&payload) {
                Ok(v) => v,
                Err(e) => {
                    return crate::core::IpeResult::Err(
                        format!("js_request: payload serialisation failed: {e}").into(),
                    );
                }
            };
            let envelope = serde_json::json!({
                COR_ID_FIELD: cor_id,
                "payload": outbound_json,
            });
            let encoded = seal_encode(&envelope);

            // Build a Promise whose resolve/reject pair is stored as the waiter.
            // When `push_inbound` gets a correlated reply it calls the stored
            // callback, which resolves the promise with the reply JSON string.
            // The `Closure`s are `forget`-ed so they live until the promise
            // settles — a bounded leak (one per outstanding request, cleaned up
            // when the promise resolves or the timeout fires).
            let promise = js_sys::Promise::new(&mut |resolve, reject| {
                // `resolve` receives the reply payload JSON as a JsValue string.
                // `reject` is called by the timeout closure.
                let resolve_rc = Rc::new(resolve);
                let reject_rc = Rc::new(reject);

                // Register resolve as the waiter.
                let resolve_stored = Rc::clone(&resolve_rc);
                PENDING.with(|p| {
                    p.borrow_mut().insert(
                        cor_id,
                        Box::new(move |value: JsonVal| {
                            let s = value.to_string();
                            let _ = resolve_stored.call1(&JsValue::NULL, &JsValue::from_str(&s));
                        }),
                    );
                });

                // Set up the timeout to call reject.
                let reject_cb = wasm_bindgen::closure::Closure::once(move || {
                    let _ = reject_rc.call0(&JsValue::NULL);
                });
                let window = web_sys::window();
                if let Some(w) = window {
                    let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(
                        reject_cb.as_ref().unchecked_ref(),
                        i32::try_from(REQUEST_TIMEOUT_MS).unwrap_or(i32::MAX),
                    );
                }
                reject_cb.forget();
            });

            // Deliver outbound AFTER registering the waiter so no reply can
            // arrive before the waiter is installed.
            deliver_outbound(&encoded);

            // Await the promise (resolve = reply arrived; reject = timeout).
            let js_fut = wasm_bindgen_futures::JsFuture::from(promise);
            match js_fut.await {
                Ok(reply_js) => {
                    // Clean up (idempotent).
                    PENDING.with(|p| p.borrow_mut().remove(&cor_id));
                    let reply_str = reply_js.as_string().unwrap_or_default();
                    match serde_json::from_str::<JsonVal>(&reply_str)
                        .ok()
                        .and_then(|v| {
                            seal_decode(&v.to_string(), &decoder, SealLimits::default()).ok()
                        }) {
                        Some(v) => crate::core::IpeResult::Ok(v),
                        None => crate::core::IpeResult::Err(
                            "js_request: reply failed seal decode".to_string().into(),
                        ),
                    }
                }
                Err(_) => {
                    // Timeout (promise rejected by setTimeout) or unknown error.
                    PENDING.with(|p| p.borrow_mut().remove(&cor_id));
                    crate::core::IpeResult::Err("js_request: timeout".to_string().into())
                }
            }
        })
    }

    /// `js_open_session open_cmd _decoder` (wasm) — mint a session id, register its
    /// stream (bounded by [`MAX_OPEN_SESSIONS`]), send `open_cmd` outbound tagged
    /// with the id, and resolve the Task with the id as the opaque handle. The id is
    /// never derived from JS, so cross-handle addressing is unrepresentable.
    pub fn js_open_session<T, F>(
        open_cmd: T,
        _decoder: Decoder<IpeError, F>,
    ) -> crate::core::IpeTask<IpeError, i64>
    where
        T: serde::Serialize + 'static,
        F: 'static,
    {
        let session_id = next_cor_id();
        Box::pin(async move {
            let at_limit = SESSIONS.with(|s| s.borrow().len() >= MAX_OPEN_SESSIONS);
            if at_limit {
                return crate::core::IpeResult::Err(
                    "js_open_session: open-session ceiling reached"
                        .to_string()
                        .into(),
                );
            }
            SESSIONS.with(|s| {
                s.borrow_mut().insert(
                    session_id,
                    WasmSession {
                        drains: Vec::new(),
                        frames_seen: 0,
                        terminal: None,
                    },
                );
            });
            let outbound_json = match serde_json::to_value(&open_cmd) {
                Ok(v) => v,
                Err(e) => {
                    SESSIONS.with(|s| s.borrow_mut().remove(&session_id));
                    return crate::core::IpeResult::Err(
                        format!("js_open_session: open cmd serialisation failed: {e}").into(),
                    );
                }
            };
            let envelope = serde_json::json!({
                SESSION_ID_FIELD: session_id,
                "payload": outbound_json,
            });
            deliver_outbound(&seal_encode(&envelope));
            crate::core::IpeResult::Ok(session_id as i64)
        })
    }

    /// `js_session_frames handle to_msg` (wasm) — register a fail-closed decoder
    /// drain on the session's stream. A `handle` with no live session registers on
    /// nothing (inert). The teardown thunk removes the drain on re-render.
    pub fn js_session_frames<T, M, F>(
        handle: i64,
        decoder: Decoder<IpeError, T>,
        to_msg: F,
    ) -> IpeSub<M>
    where
        M: 'static,
        F: Fn(T) -> M + 'static,
        T: 'static,
    {
        let session_id = handle as u64;
        IpeSub::Source(Box::new(move |emit: Rc<dyn Fn(M)>| {
            let decoder = decoder.clone();
            let drain: Rc<dyn Fn(&str)> = Rc::new(move |raw: &str| {
                if let Ok(value) = seal_decode(raw, &decoder, SealLimits::default()) {
                    (emit)(to_msg(value));
                }
            });
            let drain_key = Rc::as_ptr(&drain) as *const () as usize;
            SESSIONS.with(|s| {
                if let Some(sess) = s.borrow_mut().get_mut(&session_id) {
                    sess.drains.push(Rc::clone(&drain));
                }
            });
            Box::new(move || {
                SESSIONS.with(|s| {
                    if let Some(sess) = s.borrow_mut().get_mut(&session_id) {
                        sess.drains
                            .retain(|d| Rc::as_ptr(d) as *const () as usize != drain_key);
                    }
                });
            })
        }))
    }

    /// `js_send_to_session handle session_cmd` (wasm) — seal-encode + tag the cmd
    /// and deliver it outbound. A cmd for a dead id reaches no live host recorder.
    pub fn js_send_to_session<T, M>(handle: i64, session_cmd: T) -> IpeCmd<M>
    where
        T: serde::Serialize + Send + 'static,
    {
        let session_id = handle as u64;
        IpeCmd::Publish(Box::new(move |_origin| {
            if let Ok(value) = serde_json::to_value(&session_cmd) {
                let envelope = serde_json::json!({
                    SESSION_ID_FIELD: session_id,
                    "payload": value,
                });
                deliver_outbound(&seal_encode(&envelope));
            }
            0
        }))
    }

    /// `js_close_session handle close_cmd decoder` (wasm) — install the terminal
    /// waiter, send `close_cmd` outbound tagged with the id, and await the terminal
    /// with a deadline. Timeout / decode-miss / already-closed → typed `Err`.
    pub fn js_close_session<T, R>(
        handle: i64,
        close_cmd: T,
        decoder: Decoder<IpeError, R>,
    ) -> crate::core::IpeTask<IpeError, R>
    where
        T: serde::Serialize + 'static,
        R: 'static,
    {
        let session_id = handle as u64;
        Box::pin(async move {
            let is_open = SESSIONS.with(|s| s.borrow().contains_key(&session_id));
            if !is_open {
                return crate::core::IpeResult::Err(
                    "js_close_session: session not open".to_string().into(),
                );
            }
            let outbound_json = match serde_json::to_value(&close_cmd) {
                Ok(v) => v,
                Err(e) => {
                    SESSIONS.with(|s| s.borrow_mut().remove(&session_id));
                    return crate::core::IpeResult::Err(
                        format!("js_close_session: close cmd serialisation failed: {e}").into(),
                    );
                }
            };
            let promise = js_sys::Promise::new(&mut |resolve, reject| {
                let resolve_rc = Rc::new(resolve);
                let reject_rc = Rc::new(reject);
                let resolve_stored = Rc::clone(&resolve_rc);
                SESSIONS.with(|s| {
                    if let Some(sess) = s.borrow_mut().get_mut(&session_id) {
                        sess.terminal = Some(Box::new(move |value: JsonVal| {
                            let out = value.to_string();
                            let _ = resolve_stored.call1(&JsValue::NULL, &JsValue::from_str(&out));
                        }));
                    }
                });
                let reject_cb = wasm_bindgen::closure::Closure::once(move || {
                    let _ = reject_rc.call0(&JsValue::NULL);
                });
                if let Some(w) = web_sys::window() {
                    let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(
                        reject_cb.as_ref().unchecked_ref(),
                        i32::try_from(SESSION_DEADLINE_MS).unwrap_or(i32::MAX),
                    );
                }
                reject_cb.forget();
            });
            let envelope = serde_json::json!({
                SESSION_ID_FIELD: session_id,
                "payload": outbound_json,
            });
            deliver_outbound(&seal_encode(&envelope));

            let js_fut = wasm_bindgen_futures::JsFuture::from(promise);
            let outcome = js_fut.await;
            SESSIONS.with(|s| s.borrow_mut().remove(&session_id));
            match outcome {
                Ok(reply_js) => {
                    let reply_str = reply_js.as_string().unwrap_or_default();
                    match serde_json::from_str::<JsonVal>(&reply_str)
                        .ok()
                        .and_then(|v| {
                            seal_decode(&v.to_string(), &decoder, SealLimits::default()).ok()
                        }) {
                        Some(v) => crate::core::IpeResult::Ok(v),
                        None => crate::core::IpeResult::Err(
                            "js_close_session: terminal failed seal decode"
                                .to_string()
                                .into(),
                        ),
                    }
                }
                Err(_) => {
                    crate::core::IpeResult::Err("js_close_session: timeout".to_string().into())
                }
            }
        })
    }
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
pub use wasm::{
    js_close_session, js_open_session, js_request, js_send, js_send_to_session, js_session_frames,
    js_subscribe, push_inbound,
};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::json::JsonVal;

    // ── SessionId constructor contract ────────────────────────────────────────

    #[test]
    fn session_id_rejects_empty() {
        assert!(SessionId::parse("").is_none());
    }

    #[test]
    fn session_id_rejects_non_hex() {
        assert!(SessionId::parse("abc123XYZ").is_none()); // uppercase letters
        assert!(SessionId::parse("g1234567").is_none()); // 'g' not hex
        assert!(SessionId::parse("  ").is_none()); // whitespace
        assert!(SessionId::parse("abc-def").is_none()); // hyphen
        assert!(SessionId::parse("ABCDEF").is_none()); // uppercase hex
    }

    #[test]
    fn session_id_accepts_valid_hex() {
        // 32-char lowercase hex — the shape new_sid() produces.
        let raw = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        let sid = SessionId::parse(raw).expect("valid hex must parse");
        assert_eq!(sid.as_str(), raw);
        assert_eq!(sid.to_string(), raw);
    }

    #[test]
    fn session_id_debug_prints_no_token() {
        let raw = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        let shown = format!("{:?}", SessionId::parse(raw));
        assert_eq!(shown, "Some(SessionId(<redacted>))");
    }

    // ── Feature-independent: canonical seal encoding ───────────────────────────
    #[test]
    fn outbound_encodes_record_canonically() {
        // A record payload seal-encodes to canonical sorted-key JSON.
        let value: JsonVal = serde_json::json!({ "b": 2, "a": 1 });
        assert_eq!(seal_encode(&value), r#"{"a":1,"b":2}"#);
    }

    // ── Per-session transport (needs the `web` session-sid scope) ──────────────
    //
    // The native port transport binds each `js_subscribe`/`js_send` to the OWNING
    // session's channel, read from the pub/sub session-sid task-local. These tests
    // drive that real scope, so they compile only under `web` (which provides
    // `pubsub::with_session_sid`).
    #[cfg(feature = "web")]
    mod per_session {
        use super::super::*;
        use crate::IpeResult;
        use crate::error::IpeError;
        use crate::json::{Decoder, JsonVal, json_decode_int};
        use crate::web::pubsub::with_session_sid;
        use std::sync::{Arc, Mutex};

        fn int_decoder() -> Decoder<IpeError, i64> {
            json_decode_int()
        }

        // A decoder that always fails, to pin the drop-whole contract independent
        // of the payload shape.
        fn never_decoder() -> Decoder<IpeError, i64> {
            Decoder::new(
                Box::new(|_v: &JsonVal| IpeResult::Err(IpeError::from("nope".to_string()))),
                Vec::new(),
            )
        }

        // Parse a test sid string — all test sids are valid hex by construction.
        #[allow(clippy::expect_used)]
        fn test_sid(raw: &str) -> SessionId {
            SessionId::parse(raw).expect("test sid must be valid hex")
        }

        // Materialise a `js_subscribe` Source the way the Web driver does —
        // INSIDE `with_session_sid(sid, …)`, so the subscription binds `sid`'s
        // inbound channel — and collect the emitted Msgs.
        fn collect_for(
            sid: &SessionId,
            decoder: Decoder<IpeError, i64>,
        ) -> (tokio::task::JoinHandle<()>, Arc<Mutex<Vec<i64>>>) {
            let got = Arc::new(Mutex::new(Vec::<i64>::new()));
            let got2 = got.clone();
            let emit: Arc<dyn Fn(i64) + Send + Sync> =
                Arc::new(move |m| got2.lock().unwrap_or_else(|e| e.into_inner()).push(m));
            let sub = with_session_sid(sid.to_string(), || {
                js_subscribe::<i64, i64, _>(decoder, |a| a)
            });
            let handle = match sub {
                IpeSub::Source(spawn) => spawn(emit),
                _ => unreachable!("js_subscribe builds a Source"),
            };
            (handle, got)
        }

        #[tokio::test]
        async fn inbound_clean_payload_is_emitted() {
            let sid = test_sid("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");
            session_open(&sid);
            let (h, got) = collect_for(&sid, int_decoder());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await; // let it subscribe
            deliver_inbound_for(&sid, "7".to_string());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert_eq!(*got.lock().unwrap_or_else(|e| e.into_inner()), vec![7]);
            h.abort();
            session_close(&sid);
        }

        #[tokio::test]
        async fn inbound_undecodable_payload_is_dropped_whole() {
            let sid = test_sid("b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7");
            session_open(&sid);
            let (h, got) = collect_for(&sid, int_decoder());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(&sid, "\"not an int\"".to_string()); // string, not i64
            deliver_inbound_for(&sid, "{not json".to_string()); // malformed
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(got.lock().unwrap_or_else(|e| e.into_inner()).is_empty()); // both dropped, no panic, no partial
            h.abort();
            session_close(&sid);
        }

        #[tokio::test]
        async fn inbound_failing_decoder_drops_every_payload() {
            let sid = test_sid("c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8");
            session_open(&sid);
            let (h, got) = collect_for(&sid, never_decoder());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(&sid, "1".to_string());
            deliver_inbound_for(&sid, "2".to_string());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(got.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
            h.abort();
            session_close(&sid);
        }

        #[tokio::test]
        async fn outbound_send_encodes_and_delivers_to_origin_sink() {
            let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let seen2 = seen.clone();
            let sid = test_sid("d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9");
            session_open(&sid);
            register_out_sink_for(
                &sid,
                Arc::new(move |s: &str| {
                    seen2
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(s.to_string());
                }),
            );
            let cmd: IpeCmd<i64> = js_send::<i64, i64>(42);
            match cmd {
                // The dispatch loop injects the origin sid; delivery reaches only
                // that session's sink.
                IpeCmd::Publish(thunk) => assert_eq!(thunk(sid.as_str()), 0),
                _ => unreachable!("js_send builds a Publish cmd"),
            }
            // Canonical seal encoding of the integer 42 is the string "42".
            assert_eq!(
                seen.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .last()
                    .map(String::as_str),
                Some("42")
            );
            session_close(&sid);
        }

        // A `Cmd` dispatched BEFORE the SSE connection binds the out-sink — the
        // window a fast user click lands in — must be buffered and delivered on
        // bind, never dropped fire-and-forget. This is the geo/clipboard startup
        // race root cause: Geo.current fired pre-handshake would otherwise vanish.
        #[tokio::test]
        async fn outbound_before_sink_bind_is_buffered_then_flushed_on_bind() {
            let sid = test_sid("a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3");
            session_open(&sid); // session exists, but NO out-sink bound yet

            // Two outbound frames produced while the sink is unbound.
            for payload in [1_i64, 2_i64] {
                match js_send::<i64, i64>(payload) {
                    IpeCmd::Publish(thunk) => assert_eq!(thunk(sid.as_str()), 0),
                    _ => unreachable!("js_send builds a Publish cmd"),
                }
            }

            // Nothing delivered yet — the sink is not bound.
            let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let seen2 = seen.clone();
            // Binding the sink must flush the buffered frames in FIFO order.
            register_out_sink_for(
                &sid,
                Arc::new(move |s: &str| {
                    seen2
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(s.to_string());
                }),
            );

            assert_eq!(
                seen.lock().unwrap_or_else(|e| e.into_inner()).as_slice(),
                ["1".to_string(), "2".to_string()],
                "pre-bind frames must flush in FIFO order on sink bind, not drop"
            );

            // A frame produced AFTER the sink is bound goes straight through.
            match js_send::<i64, i64>(3_i64) {
                IpeCmd::Publish(thunk) => assert_eq!(thunk(sid.as_str()), 0),
                _ => unreachable!(),
            }
            assert_eq!(
                seen.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .last()
                    .map(String::as_str),
                Some("3")
            );
            session_close(&sid);
        }

        // A `closeSession` Cmd fired during an SSE reopen window — after the old
        // connection's out-sink dropped, before the new one rebinds — must be
        // buffered and flushed on rebind, never dropped fire-and-forget. This is
        // the 5th outbound site; before the fix `js_close_session` sent through a
        // raw `if let Some(sink)` with no else, so a close in this window vanished
        // and the caller hung until the deadline instead of the host emitting a
        // terminal. Routing it through `deliver_or_buffer` closes the drop.
        #[tokio::test]
        async fn close_during_reopen_window_is_buffered_then_flushed_on_rebind() {
            let sid = test_sid("c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8");
            session_open(&sid);

            // Open a session INSIDE the sid scope so `js_close_session` finds a
            // live stream to install its terminal waiter on.
            let handle = match with_session_sid(sid.to_string(), || {
                js_open_session::<i64, i64>(0_i64, int_decoder())
            })
            .await
            {
                IpeResult::Ok(h) => h,
                IpeResult::Err(e) => unreachable!("open must succeed: {e}"),
            };

            // Reopen window: no out-sink bound. Fire the close Cmd — its future
            // awaits the terminal, so drive it on a spawned task; we only need it
            // to reach the outbound-delivery step, then observe the buffered frame.
            let close_fut = with_session_sid(sid.to_string(), || {
                js_close_session::<i64, i64>(handle, 1_i64, int_decoder())
            });
            let task = tokio::spawn(close_fut);
            // Yield so the close future runs up to (and past) the outbound send.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;

            // The close frame must be sitting in the bounded pre-bind buffer, not
            // dropped. Binding the sink now must flush it (FIFO).
            let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let seen2 = seen.clone();
            register_out_sink_for(
                &sid,
                Arc::new(move |s: &str| {
                    seen2
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(s.to_string());
                }),
            );

            // Both the open frame (payload 0) and the close frame (payload 1)
            // were produced with no sink bound, so both must be buffered and
            // flushed on rebind. The close frame's presence is the regression
            // proof: before routing through `deliver_or_buffer`, a close fired
            // in the reopen window was dropped fire-and-forget.
            let flushed = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let close_frame = format!("{{\"{SESSION_ID_FIELD}\":{handle},\"payload\":1}}");
            assert!(
                flushed.contains(&close_frame),
                "the close frame fired during the reopen window must be buffered \
                 and flushed on rebind, not dropped: {flushed:?}"
            );

            // The close future is still awaiting its terminal (never arrives in
            // this unit test) — abort it rather than block on the deadline.
            task.abort();
            session_close(&sid);
        }

        // The pre-bind buffer is bounded by construction: past MAX_OUT_PENDING the
        // OLDEST frame is dropped so a flood before the sink binds cannot grow heap
        // without limit (soundness "bounded by construction"; §1 exhaustion). The
        // surviving frames are the newest MAX_OUT_PENDING, in order.
        #[tokio::test]
        async fn pre_bind_buffer_is_bounded_drop_oldest() {
            let sid = test_sid("b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3e4");
            session_open(&sid);

            // Overflow the ceiling by pushing MAX_OUT_PENDING + overflow frames.
            let overflow = 5_usize;
            let total = MAX_OUT_PENDING + overflow;
            for i in 0..total {
                match js_send::<i64, i64>(i as i64) {
                    IpeCmd::Publish(thunk) => assert_eq!(thunk(sid.as_str()), 0),
                    _ => unreachable!(),
                }
            }

            let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let seen2 = seen.clone();
            register_out_sink_for(
                &sid,
                Arc::new(move |s: &str| {
                    seen2
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(s.to_string());
                }),
            );

            let flushed = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
            assert_eq!(
                flushed.len(),
                MAX_OUT_PENDING,
                "buffer must cap at MAX_OUT_PENDING, never grow unbounded"
            );
            // Drop-oldest: the earliest `overflow` frames were evicted, so the
            // survivors are payloads `overflow..total`, in order.
            let expected: Vec<String> = (overflow..total).map(|i| i.to_string()).collect();
            assert_eq!(
                flushed, expected,
                "drop-oldest keeps the newest MAX_OUT_PENDING frames in FIFO order"
            );
            session_close(&sid);
        }

        // THE cross-session-isolation proof. Two live sessions, A and B. A's
        // browser inbound reaches ONLY A's `js_subscribe` (B never sees it); A's
        // `js_send` outbound reaches ONLY A's out-sink (B's stays empty).
        // Cross-session delivery is unrepresentable, verified end-to-end.
        #[tokio::test]
        async fn sessions_are_isolated_inbound_and_outbound() {
            let sid_a = test_sid("e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0");
            let sid_b = test_sid("f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1");
            session_open(&sid_a);
            session_open(&sid_b);

            // Inbound: one subscriber per session, bound via the session scope.
            let (ha, got_a) = collect_for(&sid_a, int_decoder());
            let (hb, got_b) = collect_for(&sid_b, int_decoder());

            // Outbound: one out-sink per session.
            let out_a: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let out_b: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let oa = out_a.clone();
            let ob = out_b.clone();
            register_out_sink_for(
                &sid_a,
                Arc::new(move |s: &str| {
                    oa.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(s.to_string())
                }),
            );
            register_out_sink_for(
                &sid_b,
                Arc::new(move |s: &str| {
                    ob.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(s.to_string())
                }),
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await; // subscribe

            // A's browser sends 11 inbound; only A's subscriber must see it.
            deliver_inbound_for(&sid_a, "11".to_string());
            // A's program sends 99 outbound; only A's sink must see it.
            match js_send::<i64, i64>(99) {
                IpeCmd::Publish(thunk) => {
                    thunk(sid_a.as_str());
                }
                _ => unreachable!(),
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;

            assert_eq!(*got_a.lock().unwrap_or_else(|e| e.into_inner()), vec![11]); // A received its inbound
            assert!(got_b.lock().unwrap_or_else(|e| e.into_inner()).is_empty()); // B saw NOTHING (no leak)
            assert_eq!(
                out_a.lock().unwrap_or_else(|e| e.into_inner()).as_slice(),
                ["99".to_string()]
            ); // A's sink
            assert!(out_b.lock().unwrap_or_else(|e| e.into_inner()).is_empty()); // B's sink saw NOTHING (no leak)

            ha.abort();
            hb.abort();
            session_close(&sid_a);
            session_close(&sid_b);
        }

        // A subscription materialised with NO session sid in scope binds an inert
        // channel that no route feeds — it must never receive another session's
        // inbound frames (fail-closed when the owner is unknown).
        #[tokio::test]
        async fn unscoped_subscription_receives_nothing() {
            let sid = test_sid("a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2");
            session_open(&sid);
            // NOTE: materialised OUTSIDE with_session_sid → owner sid is absent.
            let got = Arc::new(Mutex::new(Vec::<i64>::new()));
            let got2 = got.clone();
            let emit: Arc<dyn Fn(i64) + Send + Sync> =
                Arc::new(move |m| got2.lock().unwrap_or_else(|e| e.into_inner()).push(m));
            let sub = js_subscribe::<i64, i64, _>(int_decoder(), |a| a);
            let h = match sub {
                IpeSub::Source(spawn) => spawn(emit),
                _ => unreachable!(),
            };
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(&sid, "5".to_string());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(got.lock().unwrap_or_else(|e| e.into_inner()).is_empty()); // inert drain — nothing delivered
            h.abort();
            session_close(&sid);
        }

        // ── js_request security / refusal tests ──────────────────────────────

        // Helper: drive a `js_request` future and capture its result. The
        // closure `intercept` is called with the outbound frame immediately after
        // the future arms its waiter, so the test can echo a correlated reply.
        async fn drive_request<F>(sid: &SessionId, intercept: F) -> crate::IpeResult<IpeError, i64>
        where
            F: Fn(String) + Send + Sync + 'static,
        {
            let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let seen2 = seen.clone();
            register_out_sink_for(
                sid,
                Arc::new(move |s: &str| {
                    let s = s.to_string();
                    seen2
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(s.clone());
                    intercept(s);
                }),
            );
            with_session_sid(sid.to_string(), || {
                js_request::<i64, i64>(0_i64, int_decoder())
            })
            .await
        }

        // An unknown id delivered to the session (no waiter registered) must be
        // DROPPED fail-closed — no subscriber sees it, no panic, no cross-talk.
        #[tokio::test]
        async fn unknown_id_reply_is_dropped() {
            let sid = test_sid("f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3");
            session_open(&sid);
            let (h, got) = collect_for(&sid, int_decoder());
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            // Deliver a frame that looks like a correlated reply with an id that
            // has no pending waiter — it must not reach the subscriber.
            deliver_inbound_for(&sid, r#"{"__ipe_id":999999,"payload":42}"#.to_string());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(
                got.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "unknown-id reply must not reach subscribers"
            );
            h.abort();
            session_close(&sid);
        }

        // A clean reply resolves the Task with the decoded value.
        #[tokio::test]
        async fn clean_reply_resolves_task() {
            let sid = test_sid("1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d");
            session_open(&sid);
            let sid_clone = sid.clone();
            let result = drive_request(&sid, move |frame| {
                // Parse the outbound envelope to learn the minted id.
                let v: serde_json::Value = serde_json::from_str(&frame).unwrap_or_default();
                if let Some(id) = v.get("__ipe_id").and_then(|x| x.as_u64()) {
                    // Reply with envelope: id + "payload" = bare int 7.
                    let reply = format!(r#"{{"__ipe_id":{id},"payload":7}}"#);
                    deliver_inbound_for(&sid_clone, reply);
                }
            })
            .await;
            assert!(
                matches!(result, crate::IpeResult::Ok(7)),
                "expected Ok(7), got {result:?}"
            );
            session_close(&sid);
        }

        // A duplicate reply (same id echoed twice) does not double-resolve — the
        // second delivery finds an empty pending slot and is dropped fail-closed.
        #[tokio::test]
        async fn duplicate_reply_is_dropped() {
            let sid = test_sid("2b3c4d5e6f7a2b3c4d5e6f7a2b3c4d5e");
            session_open(&sid);
            let sid_clone = sid.clone();
            let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
            let counter2 = counter.clone();
            register_out_sink_for(
                &sid,
                Arc::new(move |frame: &str| {
                    let v: serde_json::Value = serde_json::from_str(frame).unwrap_or_default();
                    if let Some(id) = v.get("__ipe_id").and_then(|x| x.as_u64()) {
                        let n = counter2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        // Send the reply twice on the FIRST outbound only.
                        if n == 0 {
                            let r1 = format!(r#"{{"__ipe_id":{id},"payload":1}}"#);
                            let r2 = format!(r#"{{"__ipe_id":{id},"payload":2}}"#);
                            deliver_inbound_for(&sid_clone, r1);
                            deliver_inbound_for(&sid_clone, r2); // duplicate
                        }
                    }
                }),
            );
            let result = with_session_sid(sid.to_string(), || {
                js_request::<i64, i64>(0_i64, int_decoder())
            })
            .await;
            // The first reply should win; the second is silently dropped.
            assert!(
                matches!(result, crate::IpeResult::Ok(_)),
                "first reply must resolve the Task, got {result:?}"
            );
            session_close(&sid);
        }

        // Timeout: if no reply arrives within the deadline the Task resolves Err.
        // The deadline is 10 s in production; we shrink it by not supplying any
        // reply and relying on the per-test harness timeout (tokio::test has no
        // default deadline, but the runtime's deadline is 10 s which is too slow
        // for a unit test). We exercise the bounded-ceiling path instead: fill the
        // pending map to MAX_OUTSTANDING so the NEXT `js_request` is refused
        // immediately with an Err — same fail-closed outcome as a timeout.
        #[tokio::test]
        async fn outstanding_ceiling_refuses_immediately() {
            let sid = test_sid("3c4d5e6f7a8b3c4d5e6f7a8b3c4d5e6f");
            session_open(&sid);
            // Fill the pending map with synthetic entries (dummy oneshot senders).
            {
                let mut g = lock_sessions();
                let ports = g.entry(sid.0.clone()).or_insert_with(SessionPorts::new);
                for i in 0..MAX_OUTSTANDING as u64 {
                    let (tx, _rx) = tokio::sync::oneshot::channel::<JsonVal>();
                    ports.pending.insert(i, tx);
                }
            }
            // The next request must be refused immediately.
            let result = with_session_sid(sid.to_string(), || {
                js_request::<i64, i64>(0_i64, int_decoder())
            })
            .await;
            assert!(
                matches!(result, crate::IpeResult::Err(_)),
                "ceiling breach must immediately return Err"
            );
            session_close(&sid);
        }

        // Two concurrent requests resolve to their OWN replies — no cross-talk.
        #[tokio::test]
        async fn two_concurrent_requests_no_cross_talk() {
            let sid_a = test_sid("4d5e6f7a8b9c4d5e6f7a8b9c4d5e6f7a");
            let sid_b = test_sid("5e6f7a8b9c0d5e6f7a8b9c0d5e6f7a8b");
            session_open(&sid_a);
            session_open(&sid_b);

            let sid_a2 = sid_a.clone();
            register_out_sink_for(
                &sid_a,
                Arc::new(move |frame: &str| {
                    let v: serde_json::Value = serde_json::from_str(frame).unwrap_or_default();
                    if let Some(id) = v.get("__ipe_id").and_then(|x| x.as_u64()) {
                        // Reply to A's request with value 11.
                        deliver_inbound_for(
                            &sid_a2,
                            format!(r#"{{"__ipe_id":{id},"payload":11}}"#),
                        );
                    }
                }),
            );
            let sid_b2 = sid_b.clone();
            register_out_sink_for(
                &sid_b,
                Arc::new(move |frame: &str| {
                    let v: serde_json::Value = serde_json::from_str(frame).unwrap_or_default();
                    if let Some(id) = v.get("__ipe_id").and_then(|x| x.as_u64()) {
                        // Reply to B's request with value 22.
                        deliver_inbound_for(
                            &sid_b2,
                            format!(r#"{{"__ipe_id":{id},"payload":22}}"#),
                        );
                    }
                }),
            );

            let (ra, rb) = tokio::join!(
                with_session_sid(sid_a.to_string(), || {
                    js_request::<i64, i64>(0_i64, int_decoder())
                }),
                with_session_sid(sid_b.to_string(), || {
                    js_request::<i64, i64>(0_i64, int_decoder())
                }),
            );

            assert!(
                matches!(ra, crate::IpeResult::Ok(11)),
                "session A must get 11, got {ra:?}"
            );
            assert!(
                matches!(rb, crate::IpeResult::Ok(22)),
                "session B must get 22, got {rb:?}"
            );

            session_close(&sid_a);
            session_close(&sid_b);
        }

        // A malformed (non-JSON) reply frame arriving with a valid id is decoded
        // fail-closed — the Task resolves Err, no panic, no partial value.
        #[tokio::test]
        async fn malformed_reply_decoded_fail_closed() {
            let sid = test_sid("6f7a8b9c0d1e6f7a8b9c0d1e6f7a8b9c");
            session_open(&sid);
            let sid_clone = sid.clone();
            register_out_sink_for(
                &sid,
                Arc::new(move |frame: &str| {
                    let v: serde_json::Value = serde_json::from_str(frame).unwrap_or_default();
                    if let Some(id) = v.get("__ipe_id").and_then(|x| x.as_u64()) {
                        // Reply with a frame whose payload won't decode as i64.
                        let bad = format!(r#"{{"__ipe_id":{id},"payload":"not-an-int"}}"#);
                        deliver_inbound_for(&sid_clone, bad);
                    }
                }),
            );
            let result = with_session_sid(sid.to_string(), || {
                js_request::<i64, i64>(0_i64, int_decoder())
            })
            .await;
            assert!(
                matches!(result, crate::IpeResult::Err(_)),
                "malformed reply must resolve Err, got {result:?}"
            );
            session_close(&sid);
        }

        // After `session_close`, a delivery to that sid is a fire-and-forget no-op
        // (the channel is gone) and any live subscriber ends — no dead-session
        // channel lingers.
        #[tokio::test]
        async fn closed_session_delivery_is_a_noop() {
            let sid = test_sid("b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3");
            session_open(&sid);
            let (h, got) = collect_for(&sid, int_decoder());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            session_close(&sid);
            deliver_inbound_for(&sid, "1".to_string()); // no channel → dropped
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(got.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
            h.abort();
        }

        // ── Session-stream primitive: routing + refusals ─────────────────────

        // Drive `js_open_session`, capture the minted session id from the tagged
        // outbound open envelope, and return (handle, captured-outbound-frames).
        async fn open_session_capturing(sid: &SessionId) -> (i64, Arc<Mutex<Vec<String>>>) {
            let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let seen2 = seen.clone();
            register_out_sink_for(
                sid,
                Arc::new(move |s: &str| {
                    seen2
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(s.to_string());
                }),
            );
            let handle = match with_session_sid(sid.to_string(), || {
                js_open_session::<i64, i64>(0_i64, int_decoder())
            })
            .await
            {
                crate::IpeResult::Ok(h) => h,
                crate::IpeResult::Err(e) => panic!("open must succeed: {e:?}"),
            };
            (handle, seen)
        }

        // Materialise a `js_session_frames` Sub inside the session scope and collect
        // the emitted frame Msgs.
        fn collect_frames(
            sid: &SessionId,
            handle: i64,
        ) -> (tokio::task::JoinHandle<()>, Arc<Mutex<Vec<i64>>>) {
            let got = Arc::new(Mutex::new(Vec::<i64>::new()));
            let got2 = got.clone();
            let emit: Arc<dyn Fn(i64) + Send + Sync> =
                Arc::new(move |m| got2.lock().unwrap_or_else(|e| e.into_inner()).push(m));
            let sub = with_session_sid(sid.to_string(), || {
                js_session_frames::<i64, i64, _>(handle, int_decoder(), |a| a)
            });
            let h = match sub {
                IpeSub::Source(spawn) => spawn(emit),
                _ => unreachable!("js_session_frames builds a Source"),
            };
            (h, got)
        }

        // A framed value tagged with the session id reaches ONLY that session's
        // `sessionFrames` subscriber, decoded fail-closed.
        #[tokio::test]
        async fn session_frame_routes_to_its_subscriber() {
            let sid = test_sid("aa11bb22cc33dd44ee55ff66aa11bb22");
            session_open(&sid);
            let (handle, _out) = open_session_capturing(&sid).await;
            let (h, got) = collect_frames(&sid, handle);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(&sid, format!(r#"{{"__ipe_session":{handle},"payload":7}}"#));
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert_eq!(*got.lock().unwrap_or_else(|e| e.into_inner()), vec![7]);
            h.abort();
            session_close(&sid);
        }

        // A frame tagged with an UNKNOWN/foreign session id is dropped fail-closed:
        // no live subscriber sees it, no cross-session leak.
        #[tokio::test]
        async fn unknown_session_id_frame_is_dropped() {
            let sid = test_sid("bb22cc33dd44ee55ff66aa11bb22cc33");
            session_open(&sid);
            let (handle, _out) = open_session_capturing(&sid).await;
            let (h, got) = collect_frames(&sid, handle);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            // A frame for a DIFFERENT (never-minted) id must not reach the drain.
            deliver_inbound_for(&sid, r#"{"__ipe_session":999999,"payload":42}"#.to_string());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(
                got.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "foreign session-id frame must not reach the subscriber"
            );
            h.abort();
            session_close(&sid);
        }

        // A frame arriving AFTER the session is closed is dropped fail-closed.
        #[tokio::test]
        async fn closed_session_frame_is_dropped() {
            let sid = test_sid("cc33dd44ee55ff66aa11bb22cc33dd44");
            session_open(&sid);
            let (handle, _out) = open_session_capturing(&sid).await;
            let (h, got) = collect_frames(&sid, handle);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            // Close (terminal) evicts the session; a later frame finds no stream.
            deliver_inbound_for(
                &sid,
                format!(r#"{{"__ipe_session":{handle},"__ipe_terminal":true,"payload":0}}"#),
            );
            deliver_inbound_for(&sid, format!(r#"{{"__ipe_session":{handle},"payload":5}}"#));
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(
                got.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "a frame after close must be dropped"
            );
            h.abort();
            session_close(&sid);
        }

        // Overflow past the frame budget terminates the session with a fail-closed
        // terminal `Err` (the awaiting close Task resolves Err) — NOT a silent drop.
        #[tokio::test]
        async fn frame_budget_overflow_terminates_with_err() {
            let sid = test_sid("dd44ee55ff66aa11bb22cc33dd44ee55");
            session_open(&sid);
            // Mint a session directly and shrink its remaining budget to 0 so the
            // NEXT frame overflows (driving 100k frames in a unit test is wasteful).
            let handle = match with_session_sid(sid.to_string(), || {
                js_open_session::<i64, i64>(0_i64, int_decoder())
            })
            .await
            {
                crate::IpeResult::Ok(h) => h,
                crate::IpeResult::Err(e) => panic!("open must succeed: {e:?}"),
            };
            {
                let mut g = lock_sessions();
                if let Some(stream) = g
                    .get_mut(&sid.0)
                    .and_then(|p| p.streams.get_mut(&(handle as u64)))
                {
                    stream.frames_seen = SESSION_FRAME_BUDGET;
                }
            }
            // Park a close waiter, then push the overflowing frame; the close Task
            // must resolve Err (session terminated, not a silent drop).
            let sid_clone = sid.clone();
            let close = tokio::spawn(with_session_sid(sid.to_string(), move || {
                js_close_session::<i64, i64>(handle, 0_i64, int_decoder())
            }));
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(
                &sid_clone,
                format!(r#"{{"__ipe_session":{handle},"payload":1}}"#),
            );
            let result = close.await.expect("close task joins");
            assert!(
                matches!(result, crate::IpeResult::Err(_)),
                "budget overflow must terminate the session with Err, got {result:?}"
            );
            session_close(&sid);
        }

        // The open-session ceiling is enforced: once MAX_OPEN_SESSIONS are open,
        // the next `openSession` is refused immediately with `Err`.
        #[tokio::test]
        async fn open_session_ceiling_refuses() {
            let sid = test_sid("ee55ff66aa11bb22cc33dd44ee55ff66");
            session_open(&sid);
            register_out_sink_for(&sid, Arc::new(|_s: &str| {}));
            for _ in 0..MAX_OPEN_SESSIONS {
                let r = with_session_sid(sid.to_string(), || {
                    js_open_session::<i64, i64>(0_i64, int_decoder())
                })
                .await;
                assert!(
                    matches!(r, crate::IpeResult::Ok(_)),
                    "under ceiling must open"
                );
            }
            let over = with_session_sid(sid.to_string(), || {
                js_open_session::<i64, i64>(0_i64, int_decoder())
            })
            .await;
            assert!(
                matches!(over, crate::IpeResult::Err(_)),
                "open past the ceiling must be refused with Err"
            );
            session_close(&sid);
        }

        // A clean terminal resolves the `closeSession` Task with the decoded value.
        #[tokio::test]
        async fn close_session_resolves_on_terminal() {
            let sid = test_sid("ff66aa11bb22cc33dd44ee55ff66aa11");
            session_open(&sid);
            let (handle, _out) = open_session_capturing(&sid).await;
            let sid_clone = sid.clone();
            let close = tokio::spawn(with_session_sid(sid.to_string(), move || {
                js_close_session::<i64, i64>(handle, 0_i64, int_decoder())
            }));
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(
                &sid_clone,
                format!(r#"{{"__ipe_session":{handle},"__ipe_terminal":true,"payload":9}}"#),
            );
            let result = close.await.expect("close joins");
            assert!(
                matches!(result, crate::IpeResult::Ok(9)),
                "clean terminal must resolve Ok(9), got {result:?}"
            );
            session_close(&sid);
        }

        // A malformed terminal (payload that won't decode) resolves the close Task
        // fail-closed with `Err`, no panic, no partial value.
        #[tokio::test]
        async fn malformed_terminal_resolves_err() {
            let sid = test_sid("a1a2a3a4b1b2b3b4c1c2c3c4d1d2d3d4");
            session_open(&sid);
            let (handle, _out) = open_session_capturing(&sid).await;
            let sid_clone = sid.clone();
            let close = tokio::spawn(with_session_sid(sid.to_string(), move || {
                js_close_session::<i64, i64>(handle, 0_i64, int_decoder())
            }));
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(
                &sid_clone,
                format!(
                    r#"{{"__ipe_session":{handle},"__ipe_terminal":true,"payload":"not-an-int"}}"#
                ),
            );
            let result = close.await.expect("close joins");
            assert!(
                matches!(result, crate::IpeResult::Err(_)),
                "malformed terminal must resolve Err, got {result:?}"
            );
            session_close(&sid);
        }

        // Two open sessions are isolated: a frame for A never reaches B's subscriber.
        #[tokio::test]
        async fn two_sessions_isolated() {
            let sid = test_sid("b1b2b3b4c1c2c3c4d1d2d3d4e1e2e3e4");
            session_open(&sid);
            let (ha_handle, _oa) = open_session_capturing(&sid).await;
            let (hb_handle, _ob) = open_session_capturing(&sid).await;
            let (ha, got_a) = collect_frames(&sid, ha_handle);
            let (hb, got_b) = collect_frames(&sid, hb_handle);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(
                &sid,
                format!(r#"{{"__ipe_session":{ha_handle},"payload":11}}"#),
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert_eq!(*got_a.lock().unwrap_or_else(|e| e.into_inner()), vec![11]);
            assert!(
                got_b.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "session B must not see session A's frame"
            );
            ha.abort();
            hb.abort();
            session_close(&sid);
        }
    }
}

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
//!   `with_session` scope is active) and drains ONLY that session's inbound
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
//!   another session's traffic. A sid's endpoints exist exactly while one
//!   [`PortLease`] from [`session_open`] holds them: the live server opens the lease
//!   once the store owns the session and drops it when the session's driver exits.
//!   Every other reach is a lookup that refuses or drops when no lease holds the
//!   sid, so no reach recreates the endpoints of a closed session.
//! * **Wasm (`feature = "wasm-client"`).** In-process, no network. Outbound calls
//!   the browser-registered `window.ipeOnReceive` handler with the seal-encoded
//!   string; inbound is fed by the browser's `window.ipe.send(...)` pushing a
//!   string into an in-tab queue the `Source` drains.

#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
use crate::entropy::EntropyError;
#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
use crate::json::JsonVal;
use crate::seal_codec::{SealLimits, seal_encode};
use crate::tea::{IpeCmd, IpeSub};

/// The error a reply or terminal frame that fails its seal decode surfaces
/// as: `LimitExceeded` when the byte or depth budget turned it back,
/// `Unexpected` otherwise. Both carry `message`.
#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
fn seal_refusal_error(
    refused: &crate::seal_codec::SealDecodeError,
    message: &str,
) -> crate::error::IpeError {
    if refused.is_ceiling() {
        crate::error::IpeError::limit_exceeded(message)
    } else {
        crate::error::IpeError::unexpected(message.to_owned())
    }
}

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

// ─── Correlation-id wire key ────────────────────────────────────────────────

/// The JSON field carrying a request's correlation token on the outbound envelope and its reply.
///
/// The value is a [`PortToken`] in its wire spelling: 128 bits minted per
/// request, scoped to the minting sid (native) or tab (wasm), and consumed by
/// the first reply that carries it. Page JS sees the token and echoes it, so
/// inside the page realm it addresses a waiter; it does not authenticate one.
/// [`classify_inbound`] removes the field before a payload reaches a decoder,
/// and the browser glue renders its spelling from this constant.
pub(crate) const COR_ID_FIELD: &str = "__ipe_id";

/// Hard ceiling on outstanding (in-flight) `js_request` waiters per session.
/// A JS handler that never replies must not fill heap indefinitely; once the
/// ceiling is reached, new `js_request` calls resolve immediately with `Err`.
pub(crate) const MAX_OUTSTANDING: usize = 256;

/// Default timeout for a `js_request` waiter, in milliseconds. A JS handler
/// that does not reply within this window resolves the Task with `Err`. The
/// value is generous — it covers slow-permission-prompt flows. A per-call
/// override is a tracked follow-up.
pub const REQUEST_TIMEOUT_MS: u64 = 10_000;

// ─── Session-stream wire keys + bounds ──────────────────────────────────────

/// The JSON field carrying a session's wire token on every session envelope and frame.
///
/// The value is a [`PortToken`] in its wire spelling, minted per
/// `openSession` and scoped like [`COR_ID_FIELD`]. It is never the Ipê-side
/// `SessionHandle`: the handle stays in the program, the token goes on the
/// wire. Page JS sees and echoes it; [`classify_inbound`] removes the field
/// before a payload reaches a decoder.
const SESSION_ID_FIELD: &str = "__ipe_session";

/// The JSON field marking a session frame as the terminal reply.
///
/// A frame carrying `__ipe_terminal: true` resolves the close waiter and
/// `false` marks an ordinary stream frame. Any other value, or the field on a
/// frame with no session token, is refused by [`classify_inbound`].
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

// ─── Port tokens and the inbound classifier ─────────────────────────────────

/// The three fields that route an inbound frame to a waiter or a session.
#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
const RESERVED_ROUTING_KEYS: [&str; 3] = [COR_ID_FIELD, SESSION_ID_FIELD, SESSION_TERMINAL_FIELD];

/// Bytes of entropy in one [`PortToken`].
#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
const PORT_TOKEN_BYTES: usize = 16;

/// Length of a [`PortToken`]'s wire spelling: two hex digits per byte.
#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
const PORT_TOKEN_WIRE_LEN: usize = PORT_TOKEN_BYTES * 2;

/// A runtime-minted port address: 128 bits from the OS random source.
///
/// The only ways in are [`PortToken::mint`] and [`PortToken::parse`]; the only
/// way out is [`PortToken::wire`]. Registries key on it through a `HashMap`,
/// never an ordered map, and `Debug` prints no bits of it.
#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PortToken([u8; PORT_TOKEN_BYTES]);

#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
impl PortToken {
    /// Draw a fresh token from the OS random source.
    ///
    /// # Errors
    ///
    /// [`EntropyError`] when the OS random source refuses the draw.
    pub(crate) fn mint() -> Result<Self, EntropyError> {
        Self::mint_from(crate::entropy::fill_entropy)
    }

    /// Draw a token through `fill`, the entropy source.
    fn mint_from(
        fill: impl FnOnce(&mut [u8]) -> Result<(), EntropyError>,
    ) -> Result<Self, EntropyError> {
        let mut bytes = [0_u8; PORT_TOKEN_BYTES];
        fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// The token's one wire spelling: 32 lowercase hex digits.
    pub(crate) fn wire(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(PORT_TOKEN_WIRE_LEN);
        for byte in self.0 {
            // Writing to a `String` cannot fail.
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// Parse the wire spelling back into a token.
    ///
    /// Exactly 32 bytes, each `0-9` or `a-f`; anything else is `None`.
    pub(crate) fn parse(wire: &str) -> Option<Self> {
        let digits = wire.as_bytes();
        if digits.len() != PORT_TOKEN_WIRE_LEN {
            return None;
        }
        let mut bytes = [0_u8; PORT_TOKEN_BYTES];
        let (pairs, _) = digits.as_chunks::<2>();
        for (slot, [high, low]) in bytes.iter_mut().zip(pairs) {
            *slot = (hex_digit_value(*high)? << 4) | hex_digit_value(*low)?;
        }
        Some(Self(bytes))
    }
}

#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
impl std::fmt::Debug for PortToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PortToken(<opaque>)")
    }
}

/// The value of one lowercase hex digit; any other byte is `None`.
#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
const fn hex_digit_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// Bytes drawn for one [`PortHandle`].
#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
const PORT_HANDLE_BYTES: usize = 8;

/// The Ipê-side `SessionHandle` of one open port session: a positive value from the OS random source.
///
/// The only ways in are [`PortHandle::mint`] and [`PortHandle::parse`]; the
/// only way out is [`PortHandle::to_ipe`]. A handle never goes on the wire. It
/// is drawn, not counted, so a handle carried over from another life of the
/// same sid, another process or another replica names no stream of this one.
#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct PortHandle(std::num::NonZeroI64);

#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
impl PortHandle {
    /// Draw a fresh handle from the OS random source.
    ///
    /// `None` when the source refuses the draw or the draw is zero.
    pub(crate) fn mint() -> Option<Self> {
        Self::mint_from(crate::entropy::fill_entropy)
    }

    /// Draw a handle through `fill`, the entropy source: the draw's top 63 bits.
    ///
    /// `None` when `fill` refuses or the 63 bits are all zero.
    fn mint_from(fill: impl FnOnce(&mut [u8]) -> Result<(), EntropyError>) -> Option<Self> {
        let mut bytes = [0_u8; PORT_HANDLE_BYTES];
        fill(&mut bytes).ok()?;
        let drawn = i64::try_from(u64::from_le_bytes(bytes) >> 1).ok()?;
        std::num::NonZeroI64::new(drawn).map(Self)
    }

    /// The handle as the program holds it.
    pub(crate) const fn to_ipe(self) -> i64 {
        self.0.get()
    }

    /// Parse a program-held handle; zero and negative values are `None`.
    pub(crate) fn parse(raw: i64) -> Option<Self> {
        std::num::NonZeroI64::new(raw)
            .filter(|value| value.get() > 0)
            .map(Self)
    }
}

/// The refusal a port call reports when it cannot mint a fresh token.
///
/// A failed draw and a draw that collides with a live token both land here.
#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
fn entropy_refusal(call: &str) -> crate::error::IpeError {
    crate::error::IpeError::unavailable(format!("{call}: {EntropyError}"))
}

/// Where one inbound port frame goes, decided once from its reserved fields.
#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
pub(crate) enum Inbound {
    /// A reply to the `js_request` waiter holding `token`.
    Reply { token: PortToken, payload: JsonVal },
    /// An ordinary frame for the session holding `token`.
    SessionFrame { token: PortToken, payload: JsonVal },
    /// The terminal reply for the session holding `token`.
    SessionTerminal { token: PortToken, payload: JsonVal },
    /// No reserved field: the original raw string goes to `js_subscribe`.
    Broadcast,
    /// A reserved field is present but the frame is no legal routed frame.
    Refused,
}

/// Classify one raw inbound frame by its reserved routing fields.
///
/// A frame that is not a JSON object, or carries no reserved field, is a
/// [`Inbound::Broadcast`]. A frame with a reserved field routes only when its
/// token is a JSON string [`PortToken::parse`] accepts and the fields form one
/// legal shape; every other combination is [`Inbound::Refused`], so a reserved
/// field never reaches a `js_subscribe` decoder. The payload is the `payload`
/// field, else the object left once the routing fields are removed.
#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
pub(crate) fn classify_inbound(raw: &str) -> Inbound {
    let Ok(mut value) = serde_json::from_str::<JsonVal>(raw) else {
        return Inbound::Broadcast;
    };
    let Some(fields) = value.as_object_mut() else {
        return Inbound::Broadcast;
    };
    let [cor_id, session_id, terminal] = RESERVED_ROUTING_KEYS.map(|key| fields.swap_remove(key));
    let token_of = |id: &JsonVal| id.as_str().and_then(PortToken::parse);
    let route = match (cor_id, session_id, terminal) {
        (None, None, None) => return Inbound::Broadcast,
        (Some(id), None, None) => token_of(&id).map(|token| (token, Route::Reply)),
        (None, Some(id), None) => token_of(&id).map(|token| (token, Route::Frame)),
        (None, Some(id), Some(flag)) => match (token_of(&id), flag.as_bool()) {
            (Some(token), Some(true)) => Some((token, Route::Terminal)),
            (Some(token), Some(false)) => Some((token, Route::Frame)),
            (None, _) | (Some(_), None) => None,
        },
        (Some(_), Some(_), _) | (Some(_), None, Some(_)) | (None, None, Some(_)) => None,
    };
    let Some((token, route)) = route else {
        return Inbound::Refused;
    };
    let payload = fields.swap_remove("payload").unwrap_or(value);
    match route {
        Route::Reply => Inbound::Reply { token, payload },
        Route::Frame => Inbound::SessionFrame { token, payload },
        Route::Terminal => Inbound::SessionTerminal { token, payload },
    }
}

/// The routed shape [`classify_inbound`] settles on before it takes the payload.
#[cfg(any(not(target_arch = "wasm32"), feature = "wasm-client"))]
enum Route {
    Reply,
    Frame,
    Terminal,
}

// ─── Native (server) transport ─────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use crate::error::IpeError;
    use crate::json::{Decoder, JsonVal};
    use crate::seal_codec::seal_decode;
    use crate::tea::SourceTask;
    use std::collections::HashMap;
    use std::collections::hash_map::Entry;
    use std::sync::{Arc, Mutex, OnceLock};
    use tokio::sync::{broadcast, oneshot};

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
    pub(super) const MAX_OUT_PENDING: usize = 64;

    /// Broadcast buffer for one direction. A lagging subscriber drops the gap
    /// (never panics); the size bounds the queue an inbound burst can hold.
    const PORT_CAP: usize = 256;

    /// A registered out-sink for one session: the server installs it so each
    /// outbound `js_send` frame for that session is pushed to that session's
    /// browser over its own SSE connection.
    type OutSink = Arc<dyn Fn(&str) + Send + Sync>;

    /// One session's port endpoints. The inbound channel carries browser→server
    /// frames (already through the fail-closed decode gate) to that session's
    /// `js_subscribe`; `out_sink` is that session's browser-push installed by the
    /// live server; `pending` holds in-flight `js_request` waiters keyed by their
    /// [`PortToken`]. All belong to exactly one sid.
    pub(crate) struct SessionPorts {
        /// The life of the [`PortLease`] that built this entry; only that
        /// lease's drop removes it.
        life: PortLife,
        inbound: broadcast::Sender<String>,
        out_sink: Option<OutSink>,
        /// In-flight correlated one-shot waiters, keyed by the token minted for
        /// each request. A reply whose token is not in this map is dropped
        /// fail-closed (unknown, duplicate or late). Bounded by
        /// [`MAX_OUTSTANDING`]: a new waiter is refused when the map is full.
        pub(crate) pending: HashMap<PortToken, oneshot::Sender<JsonVal>>,
        /// Open session streams, keyed by the wire token minted for each
        /// session. A frame or terminal whose token is not in this map is
        /// dropped fail-closed. Bounded by [`MAX_OPEN_SESSIONS`]: a new
        /// `openSession` is refused when the map is full.
        pub(crate) streams: HashMap<PortToken, SessionStream>,
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
        /// The Ipê-side `SessionHandle` this stream answers to. It never goes on
        /// the wire; the stream's map key is its wire token.
        pub(crate) handle: PortHandle,
    }

    impl SessionPorts {
        /// Empty endpoints for `life`; built only by [`session_open`].
        fn new(life: PortLife) -> Self {
            SessionPorts {
                life,
                inbound: broadcast::channel(PORT_CAP).0,
                out_sink: None,
                pending: HashMap::new(),
                streams: HashMap::new(),
                out_pending: std::collections::VecDeque::new(),
            }
        }

        /// The open stream `handle` names, with its wire token.
        ///
        /// A linear scan: the map holds at most [`MAX_OPEN_SESSIONS`] entries.
        pub(crate) fn stream_by_handle(
            &mut self,
            handle: PortHandle,
        ) -> Option<(PortToken, &mut SessionStream)> {
            self.streams
                .iter_mut()
                .find(|(_, stream)| stream.handle == handle)
                .map(|(token, stream)| (*token, stream))
        }
    }

    /// The generation of one port life, distinguishing overlapping lives of one sid.
    ///
    /// Internal: it never goes on the wire or into the program.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) struct PortLife(u64);

    impl PortLife {
        /// The next unused life, or `None` once lives are exhausted.
        fn next() -> Option<Self> {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            NEXT.fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |n| n.checked_add(1),
            )
            .ok()
            .map(Self)
        }
    }

    /// Ownership of one sid's port endpoints for one session life.
    ///
    /// Built only by [`session_open`] and never cloned. Dropping it removes the
    /// sid's entry only while that entry is still the one this lease built, so
    /// the close of a superseded life never touches the life that replaced it.
    pub struct PortLease {
        sid: SessionId,
        life: PortLife,
    }

    impl Drop for PortLease {
        fn drop(&mut self) {
            let ended = {
                let mut g = lock_sessions();
                if g.get(&self.sid.0).is_some_and(|p| p.life == self.life) {
                    g.remove(&self.sid.0)
                } else {
                    None
                }
            };
            // Waiters, streams and the sink drop outside the registry lock.
            drop(ended);
        }
    }

    /// The refusal [`register_out_sink_for`] answers when no lease holds the sid.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PortClosed;

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
    /// the pub/sub broker sets (via `pubsub::with_session`), so a `js_subscribe`
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

    /// Open a new port life for `sid` and return the lease that owns it.
    ///
    /// The live server calls this once the store has made the session's handle
    /// the sid's owner, before any program code of that life can reach the
    /// port. Fresh endpoints REPLACE any entry already there: such an entry
    /// belongs to a superseded life, whose waiters then end with `Err`, whose
    /// streams close and whose sink drops. `None` only once lives are
    /// exhausted; every reach for the sid then refuses, so the port is inert.
    pub fn session_open(sid: &SessionId) -> Option<PortLease> {
        let life = PortLife::next()?;
        let superseded = lock_sessions().insert(sid.0.clone(), SessionPorts::new(life));
        drop(superseded);
        Some(PortLease {
            sid: sid.clone(),
            life,
        })
    }

    /// Install `sid`'s browser-push sink. Called when the live server attaches the
    /// session's client transport; every subsequent `js_send` whose origin is
    /// `sid` is delivered to `sink`.
    ///
    /// # Errors
    ///
    /// [`PortClosed`] when no lease holds `sid`; no sink is stored.
    pub fn register_out_sink_for(sid: &SessionId, sink: OutSink) -> Result<(), PortClosed> {
        // Take the sink and drain the pre-bind buffer under one lock acquisition,
        // then deliver the drained frames after the guard drops — the sink is a
        // synchronous callback and must never run while the registry mutex is
        // held (it re-enters no lock here, but keeping delivery outside the guard
        // preserves that invariant for every sink shape).
        let buffered = {
            let mut g = lock_sessions();
            let ports = g.get_mut(&sid.0).ok_or(PortClosed)?;
            ports.out_sink = Some(sink.clone());
            std::mem::take(&mut ports.out_pending)
        };
        for encoded in buffered {
            sink(&encoded);
        }
        Ok(())
    }

    /// Deliver one encoded outbound frame to `sid`'s browser out-sink, or buffer
    /// it fail-closed when no sink is bound yet. This is the single outbound
    /// delivery point: every `js_send`/`js_request`/`js_open_session`/
    /// `js_send_to_session` routes its frame through here, so the drop-vs-buffer
    /// policy lives in exactly one place. A frame produced before the SSE
    /// connection installs the sink is queued in the session's bounded
    /// [`SessionPorts::out_pending`] and flushed on [`register_out_sink_for`];
    /// past the [`MAX_OUT_PENDING`] ceiling the OLDEST buffered frame is dropped
    /// so a pre-bind flood cannot grow heap without limit. A frame for a sid no
    /// lease holds is dropped: no entry, no buffer.
    pub(crate) fn deliver_or_buffer(sid: &SessionId, encoded: &str) {
        let sink = {
            let mut g = lock_sessions();
            let Some(ports) = g.get_mut(&sid.0) else {
                return;
            };
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

    /// Feed one raw inbound string to `sid`'s port.
    ///
    /// Called by the server's inbound port route after its session-cookie,
    /// CSRF and bounded-seal checks. [`classify_inbound`] decides the route
    /// once, and each outcome is handled here:
    ///
    /// * a reply resolves the waiter its token names in `sid`'s pending map,
    ///   consuming it; an unknown, duplicate or late token is dropped;
    /// * a session frame or terminal goes to the stream its token names in
    ///   `sid`'s registry;
    /// * a frame with no reserved field goes to `sid`'s `js_subscribe`
    ///   broadcast as the original string;
    /// * a refused frame (a reserved field that does not form a legal routed
    ///   frame) is dropped whole: no waiter, no stream, no broadcast.
    ///
    /// The tokens are visible to page JS, which echoes them, so inside the page
    /// realm they address a waiter rather than authenticate one. They are
    /// scoped to `sid`: delivery reaches only `sid`'s own registries.
    pub fn deliver_inbound_for(sid: &SessionId, raw: String) {
        match classify_inbound(&raw) {
            Inbound::Reply { token, payload } => {
                let waiter = lock_sessions()
                    .get_mut(&sid.0)
                    .and_then(|p| p.pending.remove(&token));
                if let Some(tx) = waiter {
                    let _ = tx.send(payload);
                }
            }
            Inbound::SessionFrame { token, payload } => {
                deliver_session_frame(sid, token, &payload);
            }
            Inbound::SessionTerminal { token, payload } => {
                deliver_session_terminal(sid, token, payload);
            }
            Inbound::Broadcast => {
                let sender = lock_sessions().get(&sid.0).map(|p| p.inbound.clone());
                if let Some(tx) = sender {
                    let _ = tx.send(raw);
                }
            }
            Inbound::Refused => {}
        }
    }

    /// Route one stream frame to the session `token` names within `sid`.
    ///
    /// A token with no live stream in `sid`'s registry (unknown, closed, or
    /// another sid's) is dropped whole. A live stream charges the frame against
    /// its budget first: on exhaustion the session is evicted, which resolves a
    /// parked close waiter with `Err` and ends the `sessionFrames` subscriber,
    /// so an ordered stream never silently loses a frame. Otherwise the payload
    /// is broadcast to the session's `sessionFrames` subscriber, which decodes
    /// it fail-closed through the seal gate.
    fn deliver_session_frame(sid: &SessionId, token: PortToken, payload: &JsonVal) {
        let mut g = lock_sessions();
        let Some(ports) = g.get_mut(&sid.0) else {
            return;
        };
        let Some(stream) = ports.streams.get_mut(&token) else {
            return;
        };
        stream.frames_seen = stream.frames_seen.saturating_add(1);
        if stream.frames_seen > SESSION_FRAME_BUDGET {
            ports.streams.remove(&token);
            return;
        }
        let _ = stream.frames.send(payload.to_string());
    }

    /// Resolve the close waiter of the session `token` names within `sid`.
    ///
    /// The session is evicted, so the token is consumed. A token with no live
    /// stream, or a terminal that arrives before `closeSession` parked its
    /// waiter, is dropped; the close `Task` then resolves through its own
    /// deadline.
    fn deliver_session_terminal(sid: &SessionId, token: PortToken, payload: JsonVal) {
        let waiter = lock_sessions()
            .get_mut(&sid.0)
            .and_then(|p| p.streams.remove(&token))
            .and_then(|stream| stream.terminal);
        if let Some(tx) = waiter {
            let _ = tx.send(payload);
        }
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
                    let encoded = seal_encode(&JsonVal::from_serde(value));
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
    /// `with_session` scope is active), then moved into the source body, so
    /// the recv loop drains exactly that session's channel and can never observe
    /// another session's inbound frames. A subscription materialised with no
    /// session sid in scope (no valid [`SessionId`]) binds an inert per-call
    /// channel that no route feeds, so it receives nothing.
    ///
    /// `to_msg` is moved into exactly one source body and never shared behind an
    /// `Arc`, so `Send` (not `Send + Sync`) is the exact contract — the same
    /// bound `sub_subscribe_ws_message` carries.
    pub fn js_subscribe<T, M, F>(decoder: Decoder<IpeError, T>, to_msg: F) -> IpeSub<M>
    where
        M: Send + 'static,
        F: Fn(T) -> M + Send + 'static,
        T: Send + 'static,
    {
        // Read the owning sid while the materialisation scope is live, then bind
        // this session's inbound receiver. No valid sid, or a sid no lease holds,
        // gets a fresh private channel no route publishes to — an inert,
        // fail-closed drain.
        let held = scope_sid().and_then(|owner_sid| {
            lock_sessions()
                .get(&owner_sid.0)
                .map(|p| p.inbound.subscribe())
        });
        let rx = held.unwrap_or_else(|| broadcast::channel(PORT_CAP).1);
        IpeSub::Source(Box::new(move |emit| {
            let mut rx = rx;
            SourceTask::Tracked(Box::pin(async move {
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
            }))
        }))
    }

    /// `js_request payload decoder` — correlated one-shot port request.
    ///
    /// Semantics:
    ///
    /// 1. Mint a fresh [`PortToken`] for this request. A failed draw refuses
    ///    with `Unavailable`; there is no fallback id.
    /// 2. Under one registry lock, refuse with `Unavailable` when the owning
    ///    session already holds [`MAX_OUTSTANDING`] waiters (bounded; it frees
    ///    as replies arrive) or when the token collides with a live waiter.
    /// 3. Register a one-shot waiter under that token in the OWNING session's
    ///    pending map, then send `payload` outbound as
    ///    `{"__ipe_id": "<token>", "payload": <sealed>}`.
    /// 4. Await the one-shot with a [`REQUEST_TIMEOUT_MS`] deadline. The first
    ///    reply carrying the token consumes the waiter; the decoder runs
    ///    fail-closed over its payload. A duplicate, late or unknown token is
    ///    dropped by `deliver_inbound_for`.
    /// 5. Timeout or decode-miss → typed `Err`; never a panic.
    ///
    /// The token is visible to page JS, which echoes it on the reply: inside
    /// the page realm it addresses the waiter, it does not authenticate the
    /// reply. It is scoped to the owning sid and unpredictable across sids.
    pub fn js_request<T, R>(
        payload: T,
        decoder: Decoder<IpeError, R>,
    ) -> crate::core::IpeTask<IpeError, R>
    where
        T: serde::Serialize + Send + 'static,
        R: Send + 'static,
    {
        request_with_mint(payload, decoder, PortToken::mint)
    }

    /// [`js_request`] with its token drawn through `mint`.
    pub(crate) fn request_with_mint<T, R, M>(
        payload: T,
        decoder: Decoder<IpeError, R>,
        mint: M,
    ) -> crate::core::IpeTask<IpeError, R>
    where
        T: serde::Serialize + Send + 'static,
        R: Send + 'static,
        M: FnOnce() -> Result<PortToken, EntropyError> + Send + 'static,
    {
        let owner_sid = scope_sid();
        Box::pin(async move {
            let Ok(token) = mint() else {
                return crate::core::IpeResult::Err(entropy_refusal("js_request"));
            };

            // Serialize payload and wrap with the correlation token.
            let outbound_json = match serde_json::to_value(&payload) {
                Ok(v) => v,
                Err(e) => {
                    return crate::core::IpeResult::Err(
                        format!("js_request: payload serialisation failed: {e}").into(),
                    );
                }
            };
            let envelope = serde_json::json!({
                COR_ID_FIELD: token.wire(),
                "payload": outbound_json,
            });
            let encoded = seal_encode(&JsonVal::from_serde(envelope));

            // Register the one-shot waiter. The ceiling is checked under the
            // same lock that inserts, so concurrent requests cannot overshoot
            // it; a token already live is refused, never overwritten.
            let (tx, rx) = oneshot::channel::<JsonVal>();
            if let Some(sid) = &owner_sid {
                let mut g = lock_sessions();
                let Some(ports) = g.get_mut(&sid.0) else {
                    return crate::core::IpeResult::Err(IpeError::unavailable(
                        "js_request: session closed".to_owned(),
                    ));
                };
                if ports.pending.len() >= MAX_OUTSTANDING {
                    return crate::core::IpeResult::Err(IpeError::unavailable(
                        "js_request: outstanding waiter ceiling reached".to_owned(),
                    ));
                }
                match ports.pending.entry(token) {
                    Entry::Occupied(_) => {
                        return crate::core::IpeResult::Err(entropy_refusal("js_request"));
                    }
                    Entry::Vacant(slot) => {
                        slot.insert(tx);
                    }
                }
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
                    .map(|p| p.pending.remove(&token));
            }

            match result {
                Ok(Ok(reply_value)) => {
                    // Decode the reply fail-closed through the seal gate.
                    match seal_decode(&reply_value.to_string(), &decoder, SealLimits::default()) {
                        Ok(v) => crate::core::IpeResult::Ok(v),
                        Err(refused) => crate::core::IpeResult::Err(seal_refusal_error(
                            &refused,
                            "js_request: reply failed seal decode",
                        )),
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
    /// 1. Mint a fresh [`PortToken`] as the session's wire token. A failed
    ///    draw, or one that collides with a live stream, refuses with
    ///    `Unavailable`.
    /// 2. Refuse when [`MAX_OPEN_SESSIONS`] is already open in the owning session
    ///    (fail-closed, bounded — heap cannot grow unboundedly).
    /// 3. Register the session's bounded frame channel under the token, then
    ///    send `open_cmd` outbound tagged with it so the JS glue routes every
    ///    later frame and terminal back with it.
    /// 4. Return a separate Ipê-side handle drawn from the OS random source. A
    ///    failed or zero draw, or one equal to a live stream's handle, refuses
    ///    with `Unavailable` and overwrites nothing. The handle never goes on
    ///    the wire and the token never reaches the program, so a frame carrying
    ///    the handle routes nowhere.
    ///
    /// The token is visible to page JS, which echoes it: inside the page realm
    /// it addresses the session, it does not authenticate a frame.
    ///
    /// The `decoder` is not consumed here (the frame stream carries it in
    /// `js_session_frames`); it fixes the frame type at the type level.
    pub fn js_open_session<T, F>(
        open_cmd: T,
        decoder: Decoder<IpeError, F>,
    ) -> crate::core::IpeTask<IpeError, i64>
    where
        T: serde::Serialize + Send + 'static,
        F: Send + 'static,
    {
        open_session_with_mint(open_cmd, decoder, PortToken::mint, PortHandle::mint)
    }

    /// [`js_open_session`] with its token drawn through `mint` and its handle through `mint_handle`.
    pub(crate) fn open_session_with_mint<T, F, M, H>(
        open_cmd: T,
        _decoder: Decoder<IpeError, F>,
        mint: M,
        mint_handle: H,
    ) -> crate::core::IpeTask<IpeError, i64>
    where
        T: serde::Serialize + Send + 'static,
        F: Send + 'static,
        M: FnOnce() -> Result<PortToken, EntropyError> + Send + 'static,
        H: FnOnce() -> Option<PortHandle> + Send + 'static,
    {
        let owner_sid = scope_sid();
        Box::pin(async move {
            let Some(sid) = owner_sid else {
                return crate::core::IpeResult::Err(
                    "js_open_session: no session in scope".to_string().into(),
                );
            };
            let Ok(token) = mint() else {
                return crate::core::IpeResult::Err(entropy_refusal("js_open_session"));
            };
            let Some(handle) = mint_handle() else {
                return crate::core::IpeResult::Err(entropy_refusal("js_open_session"));
            };
            // Refuse at the ceiling (fail-closed, no panic).
            {
                let mut g = lock_sessions();
                let Some(ports) = g.get_mut(&sid.0) else {
                    return crate::core::IpeResult::Err(IpeError::unavailable(
                        "js_open_session: session closed".to_owned(),
                    ));
                };
                if ports.streams.len() >= MAX_OPEN_SESSIONS {
                    return crate::core::IpeResult::Err(IpeError::unavailable(
                        "js_open_session: open-session ceiling reached".to_owned(),
                    ));
                }
                if ports.stream_by_handle(handle).is_some() {
                    return crate::core::IpeResult::Err(entropy_refusal("js_open_session"));
                }
                match ports.streams.entry(token) {
                    Entry::Occupied(_) => {
                        return crate::core::IpeResult::Err(entropy_refusal("js_open_session"));
                    }
                    Entry::Vacant(slot) => {
                        slot.insert(SessionStream {
                            frames: broadcast::channel(PORT_CAP).0,
                            frames_seen: 0,
                            terminal: None,
                            handle,
                        });
                    }
                }
            }
            // Serialize + tag the open cmd with the session token.
            let outbound_json = match serde_json::to_value(&open_cmd) {
                Ok(v) => v,
                Err(e) => {
                    lock_sessions()
                        .get_mut(&sid.0)
                        .map(|p| p.streams.remove(&token));
                    return crate::core::IpeResult::Err(
                        format!("js_open_session: open cmd serialisation failed: {e}").into(),
                    );
                }
            };
            let envelope = serde_json::json!({
                SESSION_ID_FIELD: token.wire(),
                "payload": outbound_json,
            });
            let encoded = seal_encode(&JsonVal::from_serde(envelope));
            deliver_or_buffer(&sid, &encoded);
            crate::core::IpeResult::Ok(handle.to_ipe())
        })
    }

    /// `js_session_frames handle to_msg` — the inbound frame stream for ONE session.
    ///
    /// Drains only the frame channel of the stream `handle` names in the owning
    /// session, decoding each frame fail-closed through the bounded seal
    /// decoder (a rejected frame is dropped whole, never a partial value, never
    /// a panic). A zero or negative `handle`, or one with no live stream (closed,
    /// evicted, another sid's), binds an inert channel no route feeds.
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
        // Bind this session's frame receiver while the materialisation scope is
        // live. A missing session (unheld handle / no scope) gets a fresh private
        // channel no route publishes to — an inert, fail-closed drain.
        let rx = match (scope_sid(), PortHandle::parse(handle)) {
            (Some(owner_sid), Some(handle)) => {
                let mut g = lock_sessions();
                match g
                    .get_mut(&owner_sid.0)
                    .and_then(|p| p.stream_by_handle(handle))
                {
                    Some((_, stream)) => stream.frames.subscribe(),
                    None => broadcast::channel(PORT_CAP).1,
                }
            }
            (None, _) | (_, None) => broadcast::channel(PORT_CAP).1,
        };
        IpeSub::Source(Box::new(move |emit| {
            let mut rx = rx;
            SourceTask::Tracked(Box::pin(async move {
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
            }))
        }))
    }

    /// `js_send_to_session handle session_cmd` — send a control cmd to ONE session.
    ///
    /// Fire-and-forget via [`IpeCmd::Publish`]; the cmd is seal-encoded, tagged
    /// with the wire token of the stream `handle` names in the ORIGIN session,
    /// and delivered to that session's out-sink so the JS glue routes it to the
    /// session's host operation. A negative handle, or one with no open stream
    /// in the origin session, sends nothing.
    pub fn js_send_to_session<T, M>(handle: i64, session_cmd: T) -> IpeCmd<M>
    where
        T: serde::Serialize + Send + 'static,
    {
        let handle = PortHandle::parse(handle);
        IpeCmd::Publish(Box::new(move |origin| {
            let Some(sid) = SessionId::parse(origin) else {
                return 0;
            };
            let token = handle.and_then(|handle| {
                lock_sessions()
                    .get_mut(&sid.0)
                    .and_then(|p| p.stream_by_handle(handle))
                    .map(|(token, _)| token)
            });
            let Some(token) = token else {
                return 0;
            };
            match serde_json::to_value(&session_cmd) {
                Ok(value) => {
                    let envelope = serde_json::json!({
                        SESSION_ID_FIELD: token.wire(),
                        "payload": value,
                    });
                    let encoded = seal_encode(&JsonVal::from_serde(envelope));
                    deliver_or_buffer(&sid, &encoded);
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
    /// 1. Install a one-shot terminal waiter on the stream `handle` names in the
    ///    owning session; a negative or unheld handle is an `Err` at once.
    /// 2. Send `close_cmd` outbound tagged with the stream's wire token so the
    ///    host operation emits its terminal frame.
    /// 3. Await the terminal with a [`SESSION_DEADLINE_MS`] deadline; on arrival,
    ///    decode it fail-closed through the seal gate. A timeout, a decode-miss, an
    ///    overflow eviction, or an already-closed session → typed `Err`, never a
    ///    panic. The session is evicted regardless of outcome.
    pub fn js_close_session<T, R>(
        handle: i64,
        close_cmd: T,
        decoder: Decoder<IpeError, R>,
    ) -> crate::core::IpeTask<IpeError, R>
    where
        T: serde::Serialize + Send + 'static,
        R: Send + 'static,
    {
        let handle = PortHandle::parse(handle);
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
            let token = {
                let mut g = lock_sessions();
                let stream = handle
                    .and_then(|handle| g.get_mut(&sid.0).and_then(|p| p.stream_by_handle(handle)));
                let Some((token, stream)) = stream else {
                    return crate::core::IpeResult::Err(
                        "js_close_session: session not open".to_string().into(),
                    );
                };
                stream.terminal = Some(tx);
                token
            };
            // Serialize + tag the close cmd and deliver it.
            match serde_json::to_value(&close_cmd) {
                Ok(v) => {
                    let envelope = serde_json::json!({
                        SESSION_ID_FIELD: token.wire(),
                        "payload": v,
                    });
                    let encoded = seal_encode(&JsonVal::from_serde(envelope));
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
                        .map(|p| p.streams.remove(&token));
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
                .map(|p| p.streams.remove(&token));

            match result {
                Ok(Ok(terminal_value)) => {
                    match seal_decode(&terminal_value.to_string(), &decoder, SealLimits::default())
                    {
                        Ok(v) => crate::core::IpeResult::Ok(v),
                        Err(refused) => crate::core::IpeResult::Err(seal_refusal_error(
                            &refused,
                            "js_close_session: terminal failed seal decode",
                        )),
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
    PortClosed, PortLease, deliver_inbound_for, js_close_session, js_open_session, js_request,
    js_send, js_send_to_session, js_session_frames, js_subscribe, register_out_sink_for,
    session_open,
};

// Consumed only by the `web`-gated `per_session` test submodule below; gate the
// re-export to match so a `db`-without-`web` test build has no unused import.
#[cfg(all(not(target_arch = "wasm32"), test, feature = "web"))]
pub(crate) use native::{lock_sessions, open_session_with_mint, request_with_mint};

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
    use std::collections::hash_map::Entry;
    use std::rc::Rc;
    use wasm_bindgen::{JsCast, JsValue};

    /// One inbound-string drain: a `js_subscribe` or `sessionFrames` decoder.
    type Drain = Rc<dyn Fn(&str)>;

    /// A one-shot waiter resolved by a correlated reply or a session terminal.
    type ReplyWaiter = Box<dyn FnOnce(JsonVal)>;

    thread_local! {
        /// The in-tab inbound queue's drains. The browser's `window.ipe.send(raw)`
        /// pushes a string here (via [`push_inbound`]); each active `js_subscribe`
        /// registers a drain closure that fires on every pushed string.
        static INBOUND: RefCell<Vec<Drain>> = const { RefCell::new(Vec::new()) };

        /// In-flight correlated one-shot waiters, keyed by the token minted for
        /// each request. A reply whose token is not in this map is dropped
        /// fail-closed (unknown, duplicate or late).
        static PENDING: RefCell<HashMap<PortToken, ReplyWaiter>> =
            RefCell::new(HashMap::new());

        /// This tab's open session streams.
        static SESSIONS: RefCell<WasmSessions> = RefCell::new(WasmSessions::new());
    }

    /// This tab's open sessions.
    struct WasmSessions {
        /// Open session streams, keyed by the wire token minted for each
        /// session. A frame or terminal whose token is not in this map is
        /// dropped fail-closed. Bounded by [`MAX_OPEN_SESSIONS`].
        streams: HashMap<PortToken, WasmSession>,
    }

    impl WasmSessions {
        fn new() -> Self {
            Self {
                streams: HashMap::new(),
            }
        }

        /// The wire token of the open stream `handle` names.
        ///
        /// A linear scan: the map holds at most [`MAX_OPEN_SESSIONS`] entries.
        fn token_of(&self, handle: PortHandle) -> Option<PortToken> {
            self.streams
                .iter()
                .find(|(_, session)| session.handle == handle)
                .map(|(token, _)| *token)
        }
    }

    /// One open session's browser-local state.
    struct WasmSession {
        /// The `sessionFrames` drains for THIS session (each a fail-closed decoder).
        drains: Vec<Drain>,
        /// Frames routed so far; charged before delivery so an overflow terminates
        /// the session rather than delivering past the budget.
        frames_seen: u64,
        /// The `closeSession` terminal one-shot (resolves the awaiting Task once).
        terminal: Option<ReplyWaiter>,
        /// The Ipê-side `SessionHandle` this stream answers to. It never goes on
        /// the wire; the stream's map key is its wire token.
        handle: PortHandle,
    }

    /// The browser-facing entry the JS glue calls to push an inbound port
    /// message: `window.ipe.send(raw)` routes here.
    ///
    /// [`classify_inbound`] decides the route once: a reply resolves the
    /// waiter its token names, a session frame or terminal goes to the stream
    /// its token names, a frame with no reserved field fans out to every
    /// `js_subscribe` drain, and a refused frame is dropped whole. An unknown,
    /// duplicate or late token is dropped.
    pub fn push_inbound(raw: &str) {
        match classify_inbound(raw) {
            Inbound::Reply { token, payload } => {
                let waiter = PENDING.with(|p| p.borrow_mut().remove(&token));
                if let Some(cb) = waiter {
                    cb(payload);
                }
            }
            Inbound::SessionFrame { token, payload } => deliver_session_frame(token, &payload),
            Inbound::SessionTerminal { token, payload } => {
                deliver_session_terminal(token, payload);
            }
            Inbound::Broadcast => {
                let drains: Vec<Drain> =
                    INBOUND.with(|q| q.borrow().iter().map(Rc::clone).collect());
                for drain in drains {
                    drain(raw);
                }
            }
            Inbound::Refused => {}
        }
    }

    /// Route one stream frame to the session `token` names.
    ///
    /// A token with no live stream is dropped whole. A live stream charges the
    /// frame against its budget first; on overflow the session is evicted
    /// (dropping the terminal waiter, so the close `Task` resolves `Err`)
    /// rather than delivering past the bound.
    fn deliver_session_frame(token: PortToken, payload: &JsonVal) {
        let drains = SESSIONS.with(|s| {
            let mut sessions = s.borrow_mut();
            let sess = sessions.streams.get_mut(&token)?;
            sess.frames_seen = sess.frames_seen.saturating_add(1);
            if sess.frames_seen > SESSION_FRAME_BUDGET {
                sessions.streams.remove(&token);
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

    /// Resolve the close waiter of the session `token` names and evict it.
    ///
    /// A token with no live stream, or a stream with no parked waiter, is
    /// dropped.
    fn deliver_session_terminal(token: PortToken, payload: JsonVal) {
        let waiter = SESSIONS.with(|s| {
            s.borrow_mut()
                .streams
                .remove(&token)
                .and_then(|sess| sess.terminal)
        });
        if let Some(cb) = waiter {
            cb(payload);
        }
    }

    /// What became of one outbound frame handed to the page host.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DeliverOutcome {
        /// The host took the frame.
        Delivered,
        /// No callable `window.ipeOnReceive` exists, or it answered that nothing
        /// on the page takes the frame.
        NoHost,
        /// The host threw while taking the frame.
        HostThrew,
    }

    impl DeliverOutcome {
        /// The typed refusal a call reports when its frame found no host.
        ///
        /// `None` when the frame was delivered.
        fn refusal(self, call: &str) -> Option<IpeError> {
            match self {
                Self::Delivered => None,
                Self::NoHost => Some(IpeError::unavailable(format!(
                    "{call}: no page host takes port frames"
                ))),
                Self::HostThrew => Some(IpeError::unavailable(format!(
                    "{call}: the page host threw on the port frame"
                ))),
            }
        }

        /// Report a fire-and-forget frame no host took.
        ///
        /// The line names the call only, never the payload.
        fn warn_undelivered(self, call: &str) {
            if let Some(refusal) = self.refusal(call) {
                crate::wasm::console_warn(&refusal.to_string());
            }
        }
    }

    /// Deliver one seal-encoded outbound frame to the page host.
    ///
    /// The host is the registered `window.ipeOnReceive` handler. A handler that
    /// answers `false` reports that no sink or receiver on the page takes the
    /// frame; any other answer is a delivery.
    pub fn deliver_outbound(encoded: &str) -> DeliverOutcome {
        let Some(window) = web_sys::window() else {
            return DeliverOutcome::NoHost;
        };
        let Ok(handler) = js_sys::Reflect::get(&window, &JsValue::from_str("ipeOnReceive")) else {
            return DeliverOutcome::NoHost;
        };
        let Ok(func) = handler.dyn_into::<js_sys::Function>() else {
            return DeliverOutcome::NoHost;
        };
        match func.call1(&JsValue::NULL, &JsValue::from_str(encoded)) {
            Ok(answer) if answer.as_bool() == Some(false) => DeliverOutcome::NoHost,
            Ok(_) => DeliverOutcome::Delivered,
            Err(_) => DeliverOutcome::HostThrew,
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
                deliver_outbound(&seal_encode(&JsonVal::from_serde(value)))
                    .warn_undelivered("js_send");
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
            let drain: Drain = Rc::new(move |raw: &str| {
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
    /// wasm-compatible async primitive). A fresh [`PortToken`] is minted per
    /// request (a failed or colliding draw refuses with `Unavailable`); the
    /// `resolve` callback is stored in `PENDING` under it, and `push_inbound`
    /// calls it when the reply carrying the token arrives. A `setTimeout` races
    /// the promise: whichever fires first wins.
    pub fn js_request<T, R>(
        payload: T,
        decoder: Decoder<IpeError, R>,
    ) -> crate::core::IpeTask<IpeError, R>
    where
        T: serde::Serialize + 'static,
        R: 'static,
    {
        Box::pin(async move {
            // Refuse when the ceiling is already reached.
            let at_limit = PENDING.with(|p| p.borrow().len() >= MAX_OUTSTANDING);
            if at_limit {
                return crate::core::IpeResult::Err(IpeError::unavailable(
                    "js_request: outstanding waiter ceiling reached".to_owned(),
                ));
            }
            let Ok(token) = PortToken::mint() else {
                return crate::core::IpeResult::Err(entropy_refusal("js_request"));
            };

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
                COR_ID_FIELD: token.wire(),
                "payload": outbound_json,
            });
            let encoded = seal_encode(&JsonVal::from_serde(envelope));

            // Build a Promise whose resolve/reject pair is stored as the waiter.
            // When `push_inbound` gets a correlated reply it calls the stored
            // callback, which resolves the promise with the reply JSON string.
            // The `Closure`s are `forget`-ed so they live until the promise
            // settles — a bounded leak (one per outstanding request, cleaned up
            // when the promise resolves or the timeout fires).
            // The frame is delivered inside the executor, after the waiter is
            // registered, so no reply can arrive before the waiter exists and a
            // frame no host takes rejects the promise at once.
            let mut outcome = DeliverOutcome::Delivered;
            let mut collided = false;
            let promise = js_sys::Promise::new(&mut |resolve, reject| {
                // `resolve` receives the reply payload JSON as a JsValue string.
                // `reject` is called by the timeout closure, or at once when no
                // host takes the frame or the token is already live.
                let resolve_rc = Rc::new(resolve);
                let reject_rc = Rc::new(reject);

                // Register resolve as the waiter; a token already live belongs
                // to another waiter and is never overwritten.
                let resolve_stored = Rc::clone(&resolve_rc);
                let registered = PENDING.with(|p| match p.borrow_mut().entry(token) {
                    Entry::Occupied(_) => false,
                    Entry::Vacant(slot) => {
                        slot.insert(Box::new(move |value: JsonVal| {
                            let s = value.to_string();
                            let _ = resolve_stored.call1(&JsValue::NULL, &JsValue::from_str(&s));
                        }));
                        true
                    }
                });
                if !registered {
                    collided = true;
                    let _ = reject_rc.call0(&JsValue::NULL);
                    return;
                }

                outcome = deliver_outbound(&encoded);
                if outcome != DeliverOutcome::Delivered {
                    PENDING.with(|p| p.borrow_mut().remove(&token));
                    let _ = reject_rc.call0(&JsValue::NULL);
                    return;
                }

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

            // Await the promise (resolve = reply arrived; reject = no host or
            // timeout).
            let js_fut = wasm_bindgen_futures::JsFuture::from(promise);
            let settled = js_fut.await;
            if collided {
                // The live entry under this token is another waiter's; leave it.
                return crate::core::IpeResult::Err(entropy_refusal("js_request"));
            }
            match settled {
                Ok(reply_js) => {
                    // Clean up (idempotent).
                    PENDING.with(|p| p.borrow_mut().remove(&token));
                    let reply_str = reply_js.as_string().unwrap_or_default();
                    match seal_decode(&reply_str, &decoder, SealLimits::default()) {
                        Ok(v) => crate::core::IpeResult::Ok(v),
                        Err(refused) => crate::core::IpeResult::Err(seal_refusal_error(
                            &refused,
                            "js_request: reply failed seal decode",
                        )),
                    }
                }
                Err(_) => {
                    PENDING.with(|p| p.borrow_mut().remove(&token));
                    crate::core::IpeResult::Err(
                        outcome
                            .refusal("js_request")
                            .unwrap_or_else(|| "js_request: timeout".to_string().into()),
                    )
                }
            }
        })
    }

    /// `js_open_session open_cmd _decoder` (wasm) — open a session stream.
    ///
    /// Mints a fresh [`PortToken`] and a fresh [`PortHandle`] (a failed draw,
    /// or one colliding with a live stream's token or handle, refuses with
    /// `Unavailable`), registers the stream under the token (bounded by
    /// [`MAX_OPEN_SESSIONS`]), sends `open_cmd` outbound tagged with the token,
    /// and resolves the Task with the handle. The handle never goes on the
    /// wire and the token never reaches the program.
    pub fn js_open_session<T, F>(
        open_cmd: T,
        _decoder: Decoder<IpeError, F>,
    ) -> crate::core::IpeTask<IpeError, i64>
    where
        T: serde::Serialize + 'static,
        F: 'static,
    {
        Box::pin(async move {
            let Ok(token) = PortToken::mint() else {
                return crate::core::IpeResult::Err(entropy_refusal("js_open_session"));
            };
            let Some(handle) = PortHandle::mint() else {
                return crate::core::IpeResult::Err(entropy_refusal("js_open_session"));
            };
            let registered = SESSIONS.with(|s| {
                let mut sessions = s.borrow_mut();
                if sessions.streams.len() >= MAX_OPEN_SESSIONS {
                    return Err(IpeError::unavailable(
                        "js_open_session: open-session ceiling reached".to_owned(),
                    ));
                }
                if sessions.token_of(handle).is_some() {
                    return Err(entropy_refusal("js_open_session"));
                }
                match sessions.streams.entry(token) {
                    Entry::Occupied(_) => Err(entropy_refusal("js_open_session")),
                    Entry::Vacant(slot) => {
                        slot.insert(WasmSession {
                            drains: Vec::new(),
                            frames_seen: 0,
                            terminal: None,
                            handle,
                        });
                        Ok(handle.to_ipe())
                    }
                }
            });
            let handle = match registered {
                Ok(handle) => handle,
                Err(refusal) => return crate::core::IpeResult::Err(refusal),
            };
            let outbound_json = match serde_json::to_value(&open_cmd) {
                Ok(v) => v,
                Err(e) => {
                    SESSIONS.with(|s| s.borrow_mut().streams.remove(&token));
                    return crate::core::IpeResult::Err(
                        format!("js_open_session: open cmd serialisation failed: {e}").into(),
                    );
                }
            };
            let envelope = serde_json::json!({
                SESSION_ID_FIELD: token.wire(),
                "payload": outbound_json,
            });
            let outcome = deliver_outbound(&seal_encode(&JsonVal::from_serde(envelope)));
            if let Some(refusal) = outcome.refusal("js_open_session") {
                SESSIONS.with(|s| s.borrow_mut().streams.remove(&token));
                return crate::core::IpeResult::Err(refusal);
            }
            crate::core::IpeResult::Ok(handle)
        })
    }

    /// `js_session_frames handle to_msg` (wasm) — register a fail-closed decoder
    /// drain on the stream `handle` names. A zero or negative `handle`, or one with no
    /// live session, registers on nothing (inert). The teardown thunk removes
    /// the drain on re-render.
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
        let handle = PortHandle::parse(handle);
        IpeSub::Source(Box::new(move |emit: Rc<dyn Fn(M)>| {
            let decoder = decoder.clone();
            let drain: Drain = Rc::new(move |raw: &str| {
                if let Ok(value) = seal_decode(raw, &decoder, SealLimits::default()) {
                    (emit)(to_msg(value));
                }
            });
            let drain_key = Rc::as_ptr(&drain) as *const () as usize;
            let token = handle.and_then(|handle| {
                SESSIONS.with(|s| {
                    let mut sessions = s.borrow_mut();
                    let token = sessions.token_of(handle)?;
                    sessions
                        .streams
                        .get_mut(&token)?
                        .drains
                        .push(Rc::clone(&drain));
                    Some(token)
                })
            });
            Box::new(move || {
                let Some(token) = token else {
                    return;
                };
                SESSIONS.with(|s| {
                    if let Some(sess) = s.borrow_mut().streams.get_mut(&token) {
                        sess.drains
                            .retain(|d| Rc::as_ptr(d) as *const () as usize != drain_key);
                    }
                });
            })
        }))
    }

    /// `js_send_to_session handle session_cmd` (wasm) — seal-encode the cmd, tag
    /// it with the wire token of the stream `handle` names, and deliver it
    /// outbound. A negative handle, or one with no open stream, sends nothing.
    pub fn js_send_to_session<T, M>(handle: i64, session_cmd: T) -> IpeCmd<M>
    where
        T: serde::Serialize + Send + 'static,
    {
        let handle = PortHandle::parse(handle);
        IpeCmd::Publish(Box::new(move |_origin| {
            let token = handle.and_then(|handle| SESSIONS.with(|s| s.borrow().token_of(handle)));
            let Some(token) = token else {
                return 0;
            };
            if let Ok(value) = serde_json::to_value(&session_cmd) {
                let envelope = serde_json::json!({
                    SESSION_ID_FIELD: token.wire(),
                    "payload": value,
                });
                deliver_outbound(&seal_encode(&JsonVal::from_serde(envelope)))
                    .warn_undelivered("js_send_to_session");
            }
            0
        }))
    }

    /// `js_close_session handle close_cmd decoder` (wasm) — install the terminal
    /// waiter, send `close_cmd` outbound tagged with the stream's wire token, and
    /// await the terminal with a deadline. Timeout / decode-miss / a negative,
    /// unheld or already-closed handle → typed `Err`.
    pub fn js_close_session<T, R>(
        handle: i64,
        close_cmd: T,
        decoder: Decoder<IpeError, R>,
    ) -> crate::core::IpeTask<IpeError, R>
    where
        T: serde::Serialize + 'static,
        R: 'static,
    {
        let handle = PortHandle::parse(handle);
        Box::pin(async move {
            let token = handle.and_then(|handle| SESSIONS.with(|s| s.borrow().token_of(handle)));
            let Some(token) = token else {
                return crate::core::IpeResult::Err(
                    "js_close_session: session not open".to_string().into(),
                );
            };
            let outbound_json = match serde_json::to_value(&close_cmd) {
                Ok(v) => v,
                Err(e) => {
                    SESSIONS.with(|s| s.borrow_mut().streams.remove(&token));
                    return crate::core::IpeResult::Err(
                        format!("js_close_session: close cmd serialisation failed: {e}").into(),
                    );
                }
            };
            let envelope = serde_json::json!({
                SESSION_ID_FIELD: token.wire(),
                "payload": outbound_json,
            });
            let encoded = seal_encode(&JsonVal::from_serde(envelope));
            // Delivered inside the executor, after the terminal waiter is
            // installed, so a frame no host takes rejects the promise at once.
            let mut delivered = DeliverOutcome::Delivered;
            let promise = js_sys::Promise::new(&mut |resolve, reject| {
                let resolve_rc = Rc::new(resolve);
                let reject_rc = Rc::new(reject);
                let resolve_stored = Rc::clone(&resolve_rc);
                SESSIONS.with(|s| {
                    if let Some(sess) = s.borrow_mut().streams.get_mut(&token) {
                        sess.terminal = Some(Box::new(move |value: JsonVal| {
                            let out = value.to_string();
                            let _ = resolve_stored.call1(&JsValue::NULL, &JsValue::from_str(&out));
                        }));
                    }
                });
                delivered = deliver_outbound(&encoded);
                if delivered != DeliverOutcome::Delivered {
                    let _ = reject_rc.call0(&JsValue::NULL);
                    return;
                }
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

            let js_fut = wasm_bindgen_futures::JsFuture::from(promise);
            let outcome = js_fut.await;
            SESSIONS.with(|s| s.borrow_mut().streams.remove(&token));
            match outcome {
                Ok(reply_js) => {
                    let reply_str = reply_js.as_string().unwrap_or_default();
                    match seal_decode(&reply_str, &decoder, SealLimits::default()) {
                        Ok(v) => crate::core::IpeResult::Ok(v),
                        Err(refused) => crate::core::IpeResult::Err(seal_refusal_error(
                            &refused,
                            "js_close_session: terminal failed seal decode",
                        )),
                    }
                }
                Err(_) => crate::core::IpeResult::Err(
                    delivered
                        .refusal("js_close_session")
                        .unwrap_or_else(|| "js_close_session: timeout".to_string().into()),
                ),
            }
        })
    }
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
pub use wasm::{
    DeliverOutcome, deliver_outbound, js_close_session, js_open_session, js_request, js_send,
    js_send_to_session, js_session_frames, js_subscribe, push_inbound,
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
        let value: JsonVal = crate::json_val::json_val!({ "b": 2, "a": 1 });
        assert_eq!(seal_encode(&value), r#"{"a":1,"b":2}"#);
    }

    // ── Port tokens and the inbound classifier ──────────────────────────────────

    /// A well-formed token no registry minted.
    const UNMINTED_TOKEN: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn minted_tokens_are_distinct_and_round_trip() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let minted = PortToken::mint();
            assert!(
                minted.is_ok(),
                "the OS random source must serve a test mint"
            );
            let Ok(token) = minted else {
                return;
            };
            let wire = token.wire();
            assert_eq!(wire.len(), 32);
            assert!(
                wire.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                "the wire spelling is lowercase hex: {wire}"
            );
            assert_eq!(PortToken::parse(&wire), Some(token));
            assert!(seen.insert(wire), "1000 mints never repeat");
        }
        assert_eq!(
            format!("{:?}", PortToken::parse(UNMINTED_TOKEN)),
            "Some(PortToken(<opaque>))"
        );
    }

    #[test]
    fn mint_refuses_without_entropy() {
        assert!(matches!(
            PortToken::mint_from(|_| Err(EntropyError)),
            Err(EntropyError)
        ));
        assert_eq!(
            entropy_refusal("js_request"),
            crate::error::IpeError::unavailable(
                "js_request: the OS random source is unavailable".to_owned()
            )
        );
    }

    #[test]
    fn port_ids_are_never_counters() {
        // The needles are split so this test does not match itself.
        let source = include_str!("js_port.rs");
        for needle in [
            concat!("Cell<", "u64>"),
            concat!("next_", "cor_id"),
            concat!("next_", "handle"),
            concat!("take_", "handle"),
        ] {
            assert!(
                !source.contains(needle),
                "a port id must be a minted token, never a counter: found `{needle}`"
            );
        }
        // The one counter is the internal life generation, which never leaves
        // the registry: every atomic counter sits inside `impl PortLife`.
        let life_start = source.find(concat!("impl Port", "Life {"));
        assert!(life_start.is_some(), "the life generation is implemented");
        let Some(life_start) = life_start else {
            return;
        };
        let life_len = source
            .get(life_start..)
            .and_then(|rest| rest.find("\n    }\n"))
            .unwrap_or(0);
        let counters: Vec<usize> = source
            .match_indices(concat!("Atomic", "U64"))
            .map(|(at, _)| at)
            .collect();
        assert!(
            !counters.is_empty()
                && counters
                    .iter()
                    .all(|at| (life_start..life_start + life_len).contains(at)),
            "an atomic counter outside the life generation: a port id must be minted"
        );
    }

    #[test]
    fn port_handle_parse_refuses_out_of_range() {
        assert_eq!(PortHandle::parse(0), None);
        assert_eq!(PortHandle::parse(-1), None);
        assert_eq!(PortHandle::parse(i64::MIN), None);
        assert_eq!(
            PortHandle::parse(i64::MAX).map(PortHandle::to_ipe),
            Some(i64::MAX)
        );
        assert_eq!(
            PortHandle::mint_from(|bytes| {
                bytes.fill(0);
                Ok(())
            }),
            None
        );
        assert_eq!(PortHandle::mint_from(|_| Err(EntropyError)), None);
        assert!(
            PortHandle::mint_from(|bytes| {
                bytes.fill(0xff);
                Ok(())
            })
            .is_some_and(|h| h.to_ipe() == i64::MAX)
        );
    }

    #[test]
    fn session_ports_are_built_only_by_session_open() {
        // The needles are split so this test does not match itself.
        let full = include_str!("js_port.rs");
        let end = full
            .find(concat!(
                "#[cfg(all(test, not(target_arch = \"wasm32\")))]\nmod ",
                "tests"
            ))
            .unwrap_or(full.len());
        let source: String = full
            .get(..end)
            .unwrap_or_default()
            .lines()
            .map(|line| line.split("//").next().unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n");

        let ctor = concat!("SessionPorts", "::new(");
        let ctors: Vec<usize> = source.match_indices(ctor).map(|(at, _)| at).collect();
        let open_at = source.find(concat!("pub fn session", "_open("));
        assert!(open_at.is_some(), "session_open exists");
        let Some(open_at) = open_at else {
            return;
        };
        let open_end = source
            .get(open_at + 1..)
            .and_then(|rest| {
                rest.find("\n    pub fn ")
                    .or_else(|| rest.find("\n    fn "))
            })
            .map_or(source.len(), |len| open_at + 1 + len);
        assert!(
            ctors.len() == 1 && ctors.iter().all(|at| (open_at..open_end).contains(at)),
            "SessionPorts is built only inside session_open, found at {ctors:?}"
        );
        let literals = source.matches(concat!("SessionPorts", " {")).count()
            - source.matches(concat!("struct ", "SessionPorts {")).count()
            - source.matches(concat!("impl ", "SessionPorts {")).count();
        assert_eq!(literals, 1, "SessionPorts has one literal, in `new`");
        for needle in [
            concat!("impl Default for ", "SessionPorts"),
            concat!(".or_insert", "_with("),
            concat!("lock_sessions().", "entry("),
            concat!("g.", "entry("),
        ] {
            assert!(
                !source.contains(needle),
                "no reach may create a sid's entry: found `{needle}`"
            );
        }
    }

    #[test]
    fn reserved_key_frames_are_refused() {
        let unparsable_ids = [
            "null".to_owned(),
            "1".to_owned(),
            "1.5".to_owned(),
            "-1".to_owned(),
            "true".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            format!("\"{}\"", &UNMINTED_TOKEN[..31]),
            format!("\"{UNMINTED_TOKEN}0\""),
            format!("\"+{}\"", &UNMINTED_TOKEN[1..]),
            format!("\" {}\"", &UNMINTED_TOKEN[1..]),
            format!("\"{}\"", UNMINTED_TOKEN.to_uppercase()),
            "\"\"".to_owned(),
        ];
        for key in [COR_ID_FIELD, SESSION_ID_FIELD] {
            for id in &unparsable_ids {
                let raw = format!(r#"{{"{key}":{id},"payload":1}}"#);
                assert!(
                    matches!(classify_inbound(&raw), Inbound::Refused),
                    "an id that does not parse is refused, never broadcast: {raw}"
                );
            }
        }
        let t = UNMINTED_TOKEN;
        for raw in [
            format!(r#"{{"__ipe_id":"{t}","__ipe_session":"{t}","payload":1}}"#),
            format!(r#"{{"__ipe_id":"{t}","__ipe_session":"{t}","__ipe_terminal":true}}"#),
            r#"{"__ipe_terminal":true,"payload":1}"#.to_owned(),
            format!(r#"{{"__ipe_id":"{t}","__ipe_terminal":true,"payload":1}}"#),
            format!(r#"{{"__ipe_session":"{t}","__ipe_terminal":"yes","payload":1}}"#),
            format!(r#"{{"__ipe_session":"{t}","__ipe_terminal":1,"payload":1}}"#),
            format!(r#"{{"__ipe_session":"{t}","__ipe_terminal":null,"payload":1}}"#),
        ] {
            assert!(
                matches!(classify_inbound(&raw), Inbound::Refused),
                "an illegal reserved-field shape is refused: {raw}"
            );
        }
        for raw in [
            "1",
            "not json",
            "[1,2]",
            r#"{"payload":1}"#,
            r#"{"ipe_id":1}"#,
        ] {
            assert!(
                matches!(classify_inbound(raw), Inbound::Broadcast),
                "a frame with no reserved field is a broadcast: {raw}"
            );
        }
        let Some(expected) = PortToken::parse(t) else {
            return;
        };
        assert!(matches!(
            classify_inbound(&format!(r#"{{"__ipe_id":"{t}","payload":7}}"#)),
            Inbound::Reply { token, payload } if token == expected && payload.to_string() == "7"
        ));
        assert!(matches!(
            classify_inbound(&format!(r#"{{"__ipe_id":"{t}","a":2}}"#)),
            Inbound::Reply { token, payload } if token == expected && payload.to_string() == r#"{"a":2}"#
        ));
        assert!(matches!(
            classify_inbound(&format!(r#"{{"__ipe_session":"{t}","payload":8}}"#)),
            Inbound::SessionFrame { token, payload } if token == expected && payload.to_string() == "8"
        ));
        assert!(matches!(
            classify_inbound(&format!(
                r#"{{"__ipe_session":"{t}","__ipe_terminal":false,"payload":8}}"#
            )),
            Inbound::SessionFrame { token, .. } if token == expected
        ));
        assert!(matches!(
            classify_inbound(&format!(
                r#"{{"__ipe_session":"{t}","__ipe_terminal":true,"payload":9}}"#
            )),
            Inbound::SessionTerminal { token, payload } if token == expected && payload.to_string() == "9"
        ));
    }

    // ── Per-session transport (needs the `web` session-sid scope) ──────────────
    //
    // The native port transport binds each `js_subscribe`/`js_send` to the OWNING
    // session's channel, read from the pub/sub session-sid task-local. These tests
    // drive that real scope, so they compile only under `web` (which provides
    // `pubsub::with_session`).
    #[cfg(feature = "web")]
    mod per_session {
        use super::super::native::MAX_OUT_PENDING;
        use super::super::*;
        use super::UNMINTED_TOKEN;
        use crate::IpeResult;
        use crate::error::IpeError;
        use crate::json::{Decoder, JsonVal, json_decode_int};
        use crate::web::pubsub::{SessionScope, with_session};
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

        // Bind `sid`'s out-sink; the test holds a lease for `sid`.
        fn bind_sink(sid: &SessionId, sink: Arc<dyn Fn(&str) + Send + Sync>) {
            assert_eq!(register_out_sink_for(sid, sink), Ok(()));
        }

        // Materialise a `js_subscribe` Source the way the Web driver does —
        // INSIDE `with_session(scope, …)`, so the subscription binds `sid`'s
        // inbound channel — and collect the emitted Msgs.
        fn collect_for(
            sid: &SessionId,
            decoder: Decoder<IpeError, i64>,
        ) -> (crate::tea::RunningSource, Arc<Mutex<Vec<i64>>>) {
            let got = Arc::new(Mutex::new(Vec::<i64>::new()));
            let got2 = got.clone();
            let emit: Arc<dyn Fn(i64) + Send + Sync> =
                Arc::new(move |m| got2.lock().unwrap_or_else(|e| e.into_inner()).push(m));
            let sub = with_session(&SessionScope::new(sid.to_string()), || {
                js_subscribe::<i64, i64, _>(decoder, |a| a)
            });
            let handle = match sub {
                IpeSub::Source(spawn) => crate::tea::start_source(spawn(emit)),
                _ => unreachable!("js_subscribe builds a Source"),
            };
            (handle, got)
        }

        #[tokio::test]
        async fn inbound_clean_payload_is_emitted() {
            let sid = test_sid("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");
            let lease = session_open(&sid);
            let (h, got) = collect_for(&sid, int_decoder());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await; // let it subscribe
            deliver_inbound_for(&sid, "7".to_string());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert_eq!(*got.lock().unwrap_or_else(|e| e.into_inner()), vec![7]);
            drop(h);
            drop(lease);
        }

        #[tokio::test]
        async fn inbound_undecodable_payload_is_dropped_whole() {
            let sid = test_sid("b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7");
            let lease = session_open(&sid);
            let (h, got) = collect_for(&sid, int_decoder());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(&sid, "\"not an int\"".to_string()); // string, not i64
            deliver_inbound_for(&sid, "{not json".to_string()); // malformed
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(got.lock().unwrap_or_else(|e| e.into_inner()).is_empty()); // both dropped, no panic, no partial
            drop(h);
            drop(lease);
        }

        #[tokio::test]
        async fn inbound_failing_decoder_drops_every_payload() {
            let sid = test_sid("c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8");
            let lease = session_open(&sid);
            let (h, got) = collect_for(&sid, never_decoder());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(&sid, "1".to_string());
            deliver_inbound_for(&sid, "2".to_string());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(got.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
            drop(h);
            drop(lease);
        }

        #[tokio::test]
        async fn outbound_send_encodes_and_delivers_to_origin_sink() {
            let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let seen2 = seen.clone();
            let sid = test_sid("d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9");
            let lease = session_open(&sid);
            bind_sink(
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
            drop(lease);
        }

        // A `Cmd` dispatched BEFORE the SSE connection binds the out-sink — the
        // window a fast user click lands in — must be buffered and delivered on
        // bind, never dropped fire-and-forget. This is the geo/clipboard startup
        // race root cause: Geo.current fired pre-handshake would otherwise vanish.
        #[tokio::test]
        async fn outbound_before_sink_bind_is_buffered_then_flushed_on_bind() {
            let sid = test_sid("a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3");
            let lease = session_open(&sid); // session exists, but NO out-sink bound yet

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
            bind_sink(
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
            drop(lease);
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
            let lease = session_open(&sid);

            // Open a session INSIDE the sid scope so `js_close_session` finds a
            // live stream to install its terminal waiter on.
            let handle = match with_session(&SessionScope::new(sid.to_string()), || {
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
            let close_fut = with_session(&SessionScope::new(sid.to_string()), || {
                js_close_session::<i64, i64>(handle, 1_i64, int_decoder())
            });
            let task = tokio::spawn(close_fut);
            // Yield so the close future runs up to (and past) the outbound send.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;

            // The close frame must be sitting in the bounded pre-bind buffer, not
            // dropped. Binding the sink now must flush it (FIFO).
            let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let seen2 = seen.clone();
            bind_sink(
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
            let token = wire_token_of(&sid, handle);
            let close_frame = format!("{{\"{SESSION_ID_FIELD}\":\"{token}\",\"payload\":1}}");
            assert!(
                flushed.contains(&close_frame),
                "the close frame fired during the reopen window must be buffered \
                 and flushed on rebind, not dropped: {flushed:?}"
            );

            // The close future is still awaiting its terminal (never arrives in
            // this unit test) — abort it rather than block on the deadline.
            task.abort();
            drop(lease);
        }

        // The pre-bind buffer is bounded by construction: past MAX_OUT_PENDING the
        // OLDEST frame is dropped so a flood before the sink binds cannot grow heap
        // without limit (soundness "bounded by construction"; §1 exhaustion). The
        // surviving frames are the newest MAX_OUT_PENDING, in order.
        #[tokio::test]
        async fn pre_bind_buffer_is_bounded_drop_oldest() {
            let sid = test_sid("b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3e4");
            let lease = session_open(&sid);

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
            bind_sink(
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
            drop(lease);
        }

        // THE cross-session-isolation proof. Two live sessions, A and B. A's
        // browser inbound reaches ONLY A's `js_subscribe` (B never sees it); A's
        // `js_send` outbound reaches ONLY A's out-sink (B's stays empty).
        // Cross-session delivery is unrepresentable, verified end-to-end.
        #[tokio::test]
        async fn sessions_are_isolated_inbound_and_outbound() {
            let sid_a = test_sid("e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0");
            let sid_b = test_sid("f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1");
            let lease_a = session_open(&sid_a);
            let lease_b = session_open(&sid_b);

            // Inbound: one subscriber per session, bound via the session scope.
            let (ha, got_a) = collect_for(&sid_a, int_decoder());
            let (hb, got_b) = collect_for(&sid_b, int_decoder());

            // Outbound: one out-sink per session.
            let out_a: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let out_b: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let oa = out_a.clone();
            let ob = out_b.clone();
            bind_sink(
                &sid_a,
                Arc::new(move |s: &str| {
                    oa.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(s.to_string())
                }),
            );
            bind_sink(
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

            drop(ha);
            drop(hb);
            drop(lease_a);
            drop(lease_b);
        }

        // A subscription materialised with NO session sid in scope binds an inert
        // channel that no route feeds — it must never receive another session's
        // inbound frames (fail-closed when the owner is unknown).
        #[tokio::test]
        async fn unscoped_subscription_receives_nothing() {
            let sid = test_sid("a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2");
            let lease = session_open(&sid);
            // NOTE: materialised OUTSIDE with_session → owner sid is absent.
            let got = Arc::new(Mutex::new(Vec::<i64>::new()));
            let got2 = got.clone();
            let emit: Arc<dyn Fn(i64) + Send + Sync> =
                Arc::new(move |m| got2.lock().unwrap_or_else(|e| e.into_inner()).push(m));
            let sub = js_subscribe::<i64, i64, _>(int_decoder(), |a| a);
            let h = match sub {
                IpeSub::Source(spawn) => crate::tea::start_source(spawn(emit)),
                _ => unreachable!(),
            };
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(&sid, "5".to_string());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(got.lock().unwrap_or_else(|e| e.into_inner()).is_empty()); // inert drain — nothing delivered
            drop(h);
            drop(lease);
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
            bind_sink(
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
            with_session(&SessionScope::new(sid.to_string()), || {
                js_request::<i64, i64>(0_i64, int_decoder())
            })
            .await
        }

        // An unknown id delivered to the session (no waiter registered) must be
        // DROPPED fail-closed — no subscriber sees it, no panic, no cross-talk.
        #[tokio::test]
        async fn unknown_id_reply_is_dropped() {
            let sid = test_sid("f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3");
            let lease = session_open(&sid);
            let (h, got) = collect_for(&sid, int_decoder());
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            // Deliver a frame that looks like a correlated reply with a token
            // that has no pending waiter — it must not reach the subscriber.
            deliver_inbound_for(
                &sid,
                format!(r#"{{"__ipe_id":"{UNMINTED_TOKEN}","payload":42}}"#),
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(
                got.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "unknown-id reply must not reach subscribers"
            );
            drop(h);
            drop(lease);
        }

        // A clean reply resolves the Task with the decoded value.
        #[tokio::test]
        async fn clean_reply_resolves_task() {
            let sid = test_sid("1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d");
            let lease = session_open(&sid);
            let sid_clone = sid.clone();
            let result = drive_request(&sid, move |frame| {
                // Parse the outbound envelope to learn the minted id.
                let v: serde_json::Value = serde_json::from_str(&frame).unwrap_or_default();
                if let Some(id) = v.get("__ipe_id").and_then(|x| x.as_str()) {
                    // Reply with envelope: id + "payload" = bare int 7.
                    let reply = format!(r#"{{"__ipe_id":"{id}","payload":7}}"#);
                    deliver_inbound_for(&sid_clone, reply);
                }
            })
            .await;
            assert!(
                matches!(result, crate::IpeResult::Ok(7)),
                "expected Ok(7), got {result:?}"
            );
            drop(lease);
        }

        // A duplicate reply (same id echoed twice) does not double-resolve — the
        // second delivery finds an empty pending slot and is dropped fail-closed.
        #[tokio::test]
        async fn duplicate_reply_is_dropped() {
            let sid = test_sid("2b3c4d5e6f7a2b3c4d5e6f7a2b3c4d5e");
            let lease = session_open(&sid);
            let sid_clone = sid.clone();
            let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
            let counter2 = counter.clone();
            bind_sink(
                &sid,
                Arc::new(move |frame: &str| {
                    let v: serde_json::Value = serde_json::from_str(frame).unwrap_or_default();
                    if let Some(id) = v.get("__ipe_id").and_then(|x| x.as_str()) {
                        let n = counter2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        // Send the reply twice on the FIRST outbound only.
                        if n == 0 {
                            let r1 = format!(r#"{{"__ipe_id":"{id}","payload":1}}"#);
                            let r2 = format!(r#"{{"__ipe_id":"{id}","payload":2}}"#);
                            deliver_inbound_for(&sid_clone, r1);
                            deliver_inbound_for(&sid_clone, r2); // duplicate
                        }
                    }
                }),
            );
            let result = with_session(&SessionScope::new(sid.to_string()), || {
                js_request::<i64, i64>(0_i64, int_decoder())
            })
            .await;
            // The first reply should win; the second is silently dropped.
            assert!(
                matches!(result, crate::IpeResult::Ok(_)),
                "first reply must resolve the Task, got {result:?}"
            );
            drop(lease);
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
            let lease = session_open(&sid);
            // Fill the pending map with synthetic entries (dummy oneshot senders).
            {
                let mut g = lock_sessions();
                let ports = g.get_mut(&sid.0);
                assert!(ports.is_some(), "the lease holds the sid's entry");
                let Some(ports) = ports else {
                    return;
                };
                for _ in 0..MAX_OUTSTANDING {
                    let minted = PortToken::mint();
                    assert!(
                        minted.is_ok(),
                        "the OS random source must serve a test mint"
                    );
                    let Ok(token) = minted else {
                        return;
                    };
                    let (tx, _rx) = tokio::sync::oneshot::channel::<JsonVal>();
                    ports.pending.insert(token, tx);
                }
            }
            // The next request must be refused immediately.
            let result = with_session(&SessionScope::new(sid.to_string()), || {
                js_request::<i64, i64>(0_i64, int_decoder())
            })
            .await;
            assert!(
                matches!(&result, crate::IpeResult::Err(e) if *e == IpeError::unavailable(
                    "js_request: outstanding waiter ceiling reached".to_owned()
                )),
                "a ceiling breach is refused at once as Unavailable: it frees as replies arrive"
            );
            drop(lease);
        }

        // Two concurrent requests resolve to their OWN replies — no cross-talk.
        #[tokio::test]
        async fn two_concurrent_requests_no_cross_talk() {
            let sid_a = test_sid("4d5e6f7a8b9c4d5e6f7a8b9c4d5e6f7a");
            let sid_b = test_sid("5e6f7a8b9c0d5e6f7a8b9c0d5e6f7a8b");
            let lease_a = session_open(&sid_a);
            let lease_b = session_open(&sid_b);

            let sid_a2 = sid_a.clone();
            bind_sink(
                &sid_a,
                Arc::new(move |frame: &str| {
                    let v: serde_json::Value = serde_json::from_str(frame).unwrap_or_default();
                    if let Some(id) = v.get("__ipe_id").and_then(|x| x.as_str()) {
                        // Reply to A's request with value 11.
                        deliver_inbound_for(
                            &sid_a2,
                            format!(r#"{{"__ipe_id":"{id}","payload":11}}"#),
                        );
                    }
                }),
            );
            let sid_b2 = sid_b.clone();
            bind_sink(
                &sid_b,
                Arc::new(move |frame: &str| {
                    let v: serde_json::Value = serde_json::from_str(frame).unwrap_or_default();
                    if let Some(id) = v.get("__ipe_id").and_then(|x| x.as_str()) {
                        // Reply to B's request with value 22.
                        deliver_inbound_for(
                            &sid_b2,
                            format!(r#"{{"__ipe_id":"{id}","payload":22}}"#),
                        );
                    }
                }),
            );

            let (ra, rb) = tokio::join!(
                with_session(&SessionScope::new(sid_a.to_string()), || {
                    js_request::<i64, i64>(0_i64, int_decoder())
                }),
                with_session(&SessionScope::new(sid_b.to_string()), || {
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

            drop(lease_a);
            drop(lease_b);
        }

        // A malformed (non-JSON) reply frame arriving with a valid id is decoded
        // fail-closed — the Task resolves Err, no panic, no partial value.
        #[tokio::test]
        async fn malformed_reply_decoded_fail_closed() {
            let sid = test_sid("6f7a8b9c0d1e6f7a8b9c0d1e6f7a8b9c");
            let lease = session_open(&sid);
            let sid_clone = sid.clone();
            bind_sink(
                &sid,
                Arc::new(move |frame: &str| {
                    let v: serde_json::Value = serde_json::from_str(frame).unwrap_or_default();
                    if let Some(id) = v.get("__ipe_id").and_then(|x| x.as_str()) {
                        // Reply with a frame whose payload won't decode as i64.
                        let bad = format!(r#"{{"__ipe_id":"{id}","payload":"not-an-int"}}"#);
                        deliver_inbound_for(&sid_clone, bad);
                    }
                }),
            );
            let result = with_session(&SessionScope::new(sid.to_string()), || {
                js_request::<i64, i64>(0_i64, int_decoder())
            })
            .await;
            assert!(
                matches!(&result, crate::IpeResult::Err(e) if *e == IpeError::unexpected(
                    "js_request: reply failed seal decode".to_owned()
                )),
                "a reply of the wrong shape is no ceiling: Unexpected, got {result:?}"
            );
            drop(lease);
        }

        // A reply past the seal byte budget resolves the Task with a
        // `LimitExceeded` error carrying the same message as a shape refusal.
        #[tokio::test]
        async fn oversized_reply_is_limit_exceeded() {
            let sid = test_sid("7a8b9c0d1e2f7a8b9c0d1e2f7a8b9c0d");
            let lease = session_open(&sid);
            let sid_clone = sid.clone();
            let past_budget = "a".repeat(crate::seal_codec::DEFAULT_SEAL_MAX_INPUT_BYTES);
            let result = drive_request(&sid, move |frame| {
                let v: serde_json::Value = serde_json::from_str(&frame).unwrap_or_default();
                if let Some(id) = v.get("__ipe_id").and_then(|x| x.as_str()) {
                    // The quoted string is two bytes past the budget.
                    let reply = format!(r#"{{"__ipe_id":"{id}","payload":"{past_budget}"}}"#);
                    deliver_inbound_for(&sid_clone, reply);
                }
            })
            .await;
            assert!(
                matches!(&result, crate::IpeResult::Err(e) if *e == IpeError::limit_exceeded(
                    "js_request: reply failed seal decode"
                )),
                "a reply past the byte budget is LimitExceeded, got {result:?}"
            );
            drop(lease);
        }

        // After the lease drops, a delivery to that sid is a fire-and-forget no-op
        // (the channel is gone) and any live subscriber ends — no dead-session
        // channel lingers.
        #[tokio::test]
        async fn closed_session_delivery_is_a_noop() {
            let sid = test_sid("b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3");
            let lease = session_open(&sid);
            let (h, got) = collect_for(&sid, int_decoder());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            drop(lease);
            deliver_inbound_for(&sid, "1".to_string()); // no channel → dropped
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(got.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
            drop(h);
        }

        // ── Session-stream primitive: routing + refusals ─────────────────────

        // The wire token of the open stream `handle` names in `sid`, or an empty
        // string when none is open.
        fn wire_token_of(sid: &SessionId, handle: i64) -> String {
            let Some(handle) = PortHandle::parse(handle) else {
                return String::new();
            };
            lock_sessions()
                .get_mut(&sid.0)
                .and_then(|p| p.stream_by_handle(handle))
                .map_or_else(String::new, |(token, _)| token.wire())
        }

        // Drive `js_open_session` and return (handle, the stream's wire token,
        // captured-outbound-frames).
        async fn open_session_capturing(sid: &SessionId) -> (i64, String, Arc<Mutex<Vec<String>>>) {
            let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let seen2 = seen.clone();
            bind_sink(
                sid,
                Arc::new(move |s: &str| {
                    seen2
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(s.to_string());
                }),
            );
            let handle = match with_session(&SessionScope::new(sid.to_string()), || {
                js_open_session::<i64, i64>(0_i64, int_decoder())
            })
            .await
            {
                crate::IpeResult::Ok(h) => h,
                crate::IpeResult::Err(e) => panic!("open must succeed: {e:?}"),
            };
            (handle, wire_token_of(sid, handle), seen)
        }

        // Materialise a `js_session_frames` Sub inside the session scope and collect
        // the emitted frame Msgs.
        fn collect_frames(
            sid: &SessionId,
            handle: i64,
        ) -> (crate::tea::RunningSource, Arc<Mutex<Vec<i64>>>) {
            let got = Arc::new(Mutex::new(Vec::<i64>::new()));
            let got2 = got.clone();
            let emit: Arc<dyn Fn(i64) + Send + Sync> =
                Arc::new(move |m| got2.lock().unwrap_or_else(|e| e.into_inner()).push(m));
            let sub = with_session(&SessionScope::new(sid.to_string()), || {
                js_session_frames::<i64, i64, _>(handle, int_decoder(), |a| a)
            });
            let h = match sub {
                IpeSub::Source(spawn) => crate::tea::start_source(spawn(emit)),
                _ => unreachable!("js_session_frames builds a Source"),
            };
            (h, got)
        }

        // A framed value tagged with the session id reaches ONLY that session's
        // `sessionFrames` subscriber, decoded fail-closed.
        #[tokio::test]
        async fn session_frame_routes_to_its_subscriber() {
            let sid = test_sid("aa11bb22cc33dd44ee55ff66aa11bb22");
            let lease = session_open(&sid);
            let (handle, token, _out) = open_session_capturing(&sid).await;
            let (h, got) = collect_frames(&sid, handle);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(
                &sid,
                format!(r#"{{"__ipe_session":"{token}","payload":7}}"#),
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert_eq!(*got.lock().unwrap_or_else(|e| e.into_inner()), vec![7]);
            drop(h);
            drop(lease);
        }

        // A frame tagged with an UNKNOWN/foreign session id is dropped fail-closed:
        // no live subscriber sees it, no cross-session leak.
        #[tokio::test]
        async fn unknown_session_id_frame_is_dropped() {
            let sid = test_sid("bb22cc33dd44ee55ff66aa11bb22cc33");
            let lease = session_open(&sid);
            let (handle, token, _out) = open_session_capturing(&sid).await;
            let (h, got) = collect_frames(&sid, handle);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            // A frame for a DIFFERENT (never-minted) token must not reach the drain.
            deliver_inbound_for(
                &sid,
                format!(r#"{{"__ipe_session":"{UNMINTED_TOKEN}","payload":42}}"#),
            );
            assert_ne!(token, UNMINTED_TOKEN);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(
                got.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "foreign session-id frame must not reach the subscriber"
            );
            drop(h);
            drop(lease);
        }

        // A frame arriving AFTER the session is closed is dropped fail-closed.
        #[tokio::test]
        async fn closed_session_frame_is_dropped() {
            let sid = test_sid("cc33dd44ee55ff66aa11bb22cc33dd44");
            let lease = session_open(&sid);
            let (handle, token, _out) = open_session_capturing(&sid).await;
            let (h, got) = collect_frames(&sid, handle);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            // Close (terminal) evicts the session; a later frame finds no stream.
            deliver_inbound_for(
                &sid,
                format!(r#"{{"__ipe_session":"{token}","__ipe_terminal":true,"payload":0}}"#),
            );
            deliver_inbound_for(
                &sid,
                format!(r#"{{"__ipe_session":"{token}","payload":5}}"#),
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(
                got.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "a frame after close must be dropped"
            );
            drop(h);
            drop(lease);
        }

        // Overflow past the frame budget terminates the session with a fail-closed
        // terminal `Err` (the awaiting close Task resolves Err) — NOT a silent drop.
        #[tokio::test]
        async fn frame_budget_overflow_terminates_with_err() {
            let sid = test_sid("dd44ee55ff66aa11bb22cc33dd44ee55");
            let lease = session_open(&sid);
            // Mint a session directly and shrink its remaining budget to 0 so the
            // NEXT frame overflows (driving 100k frames in a unit test is wasteful).
            let handle = match with_session(&SessionScope::new(sid.to_string()), || {
                js_open_session::<i64, i64>(0_i64, int_decoder())
            })
            .await
            {
                crate::IpeResult::Ok(h) => h,
                crate::IpeResult::Err(e) => panic!("open must succeed: {e:?}"),
            };
            {
                let mut g = lock_sessions();
                if let Some((_, stream)) = g.get_mut(&sid.0).and_then(|p| {
                    PortHandle::parse(handle).and_then(|handle| p.stream_by_handle(handle))
                }) {
                    stream.frames_seen = SESSION_FRAME_BUDGET;
                }
            }
            let token = wire_token_of(&sid, handle);
            // Park a close waiter, then push the overflowing frame; the close Task
            // must resolve Err (session terminated, not a silent drop).
            let sid_clone = sid.clone();
            let close = tokio::spawn(with_session(
                &SessionScope::new(sid.to_string()),
                move || js_close_session::<i64, i64>(handle, 0_i64, int_decoder()),
            ));
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(
                &sid_clone,
                format!(r#"{{"__ipe_session":"{token}","payload":1}}"#),
            );
            let result = close.await.expect("close task joins");
            assert!(
                matches!(result, crate::IpeResult::Err(_)),
                "budget overflow must terminate the session with Err, got {result:?}"
            );
            drop(lease);
        }

        // The open-session ceiling is enforced: once MAX_OPEN_SESSIONS are open,
        // the next `openSession` is refused immediately with `Err`.
        #[tokio::test]
        async fn open_session_ceiling_refuses() {
            let sid = test_sid("ee55ff66aa11bb22cc33dd44ee55ff66");
            let lease = session_open(&sid);
            bind_sink(&sid, Arc::new(|_s: &str| {}));
            for _ in 0..MAX_OPEN_SESSIONS {
                let r = with_session(&SessionScope::new(sid.to_string()), || {
                    js_open_session::<i64, i64>(0_i64, int_decoder())
                })
                .await;
                assert!(
                    matches!(r, crate::IpeResult::Ok(_)),
                    "under ceiling must open"
                );
            }
            let over = with_session(&SessionScope::new(sid.to_string()), || {
                js_open_session::<i64, i64>(0_i64, int_decoder())
            })
            .await;
            assert!(
                matches!(&over, crate::IpeResult::Err(e) if *e == IpeError::unavailable(
                    "js_open_session: open-session ceiling reached".to_owned()
                )),
                "an open past the ceiling is refused as Unavailable: it frees as sessions close"
            );
            drop(lease);
        }

        // A clean terminal resolves the `closeSession` Task with the decoded value.
        #[tokio::test]
        async fn close_session_resolves_on_terminal() {
            let sid = test_sid("ff66aa11bb22cc33dd44ee55ff66aa11");
            let lease = session_open(&sid);
            let (handle, token, _out) = open_session_capturing(&sid).await;
            let sid_clone = sid.clone();
            let close = tokio::spawn(with_session(
                &SessionScope::new(sid.to_string()),
                move || js_close_session::<i64, i64>(handle, 0_i64, int_decoder()),
            ));
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(
                &sid_clone,
                format!(r#"{{"__ipe_session":"{token}","__ipe_terminal":true,"payload":9}}"#),
            );
            let result = close.await.expect("close joins");
            assert!(
                matches!(result, crate::IpeResult::Ok(9)),
                "clean terminal must resolve Ok(9), got {result:?}"
            );
            drop(lease);
        }

        // A malformed terminal (payload that won't decode) resolves the close Task
        // fail-closed with `Err`, no panic, no partial value.
        #[tokio::test]
        async fn malformed_terminal_resolves_err() {
            let sid = test_sid("a1a2a3a4b1b2b3b4c1c2c3c4d1d2d3d4");
            let lease = session_open(&sid);
            let (handle, token, _out) = open_session_capturing(&sid).await;
            let sid_clone = sid.clone();
            let close = tokio::spawn(with_session(
                &SessionScope::new(sid.to_string()),
                move || js_close_session::<i64, i64>(handle, 0_i64, int_decoder()),
            ));
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(
                &sid_clone,
                format!(
                    r#"{{"__ipe_session":"{token}","__ipe_terminal":true,"payload":"not-an-int"}}"#
                ),
            );
            let result = close.await.expect("close joins");
            assert!(
                matches!(&result, crate::IpeResult::Err(e) if *e == IpeError::unexpected(
                    "js_close_session: terminal failed seal decode".to_owned()
                )),
                "a terminal of the wrong shape is no ceiling: Unexpected, got {result:?}"
            );
            drop(lease);
        }

        // A terminal past the seal byte budget resolves the close Task with a
        // `LimitExceeded` error.
        #[tokio::test]
        async fn oversized_terminal_is_limit_exceeded() {
            let sid = test_sid("c5c6c7c8d5d6d7d8e5e6e7e8f5f6f7f8");
            let lease = session_open(&sid);
            let (handle, token, _out) = open_session_capturing(&sid).await;
            let sid_clone = sid.clone();
            let close = tokio::spawn(with_session(
                &SessionScope::new(sid.to_string()),
                move || js_close_session::<i64, i64>(handle, 0_i64, int_decoder()),
            ));
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let past_budget = "a".repeat(crate::seal_codec::DEFAULT_SEAL_MAX_INPUT_BYTES);
            deliver_inbound_for(
                &sid_clone,
                format!(
                    r#"{{"__ipe_session":"{token}","__ipe_terminal":true,"payload":"{past_budget}"}}"#
                ),
            );
            let result = close.await.expect("close joins");
            assert!(
                matches!(&result, crate::IpeResult::Err(e) if *e == IpeError::limit_exceeded(
                    "js_close_session: terminal failed seal decode"
                )),
                "a terminal past the byte budget is LimitExceeded, got {result:?}"
            );
            drop(lease);
        }

        // Two open sessions are isolated: a frame for A never reaches B's subscriber.
        #[tokio::test]
        async fn two_sessions_isolated() {
            let sid = test_sid("b1b2b3b4c1c2c3c4d1d2d3d4e1e2e3e4");
            let lease = session_open(&sid);
            let (ha_handle, ha_token, _oa) = open_session_capturing(&sid).await;
            let (hb_handle, _hb_token, _ob) = open_session_capturing(&sid).await;
            let (ha, got_a) = collect_frames(&sid, ha_handle);
            let (hb, got_b) = collect_frames(&sid, hb_handle);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(
                &sid,
                format!(r#"{{"__ipe_session":"{ha_token}","payload":11}}"#),
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert_eq!(*got_a.lock().unwrap_or_else(|e| e.into_inner()), vec![11]);
            assert!(
                got_b.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "session B must not see session A's frame"
            );
            drop(ha);
            drop(hb);
            drop(lease);
        }

        // ── Correlation tokens: only the minted token routes ─────────────────

        // A decoder that accepts every payload, so any frame a drain receives
        // is seen.
        fn any_decoder() -> Decoder<IpeError, i64> {
            Decoder::new(Box::new(|_v: &JsonVal| IpeResult::Ok(1)), Vec::new())
        }

        // Whether `sid` still holds a pending waiter under `wire`.
        fn is_pending(sid: &SessionId, wire: &str) -> bool {
            PortToken::parse(wire).is_some_and(|token| {
                lock_sessions()
                    .get(&sid.0)
                    .is_some_and(|p| p.pending.contains_key(&token))
            })
        }

        // Run a fire-and-forget port `Cmd` with `sid` as its origin.
        fn publish_from(sid: &SessionId, cmd: IpeCmd<i64>) -> Option<i64> {
            match cmd {
                IpeCmd::Publish(thunk) => Some(thunk(sid.as_str())),
                _ => None,
            }
        }

        // A reply spelled one step off the minted token (last nibble flipped,
        // uppercased, one char longer) leaves the waiter pending; only the
        // token's own spelling resolves it.
        #[tokio::test]
        async fn guessed_token_reply_is_not_delivered() {
            tokio::time::pause();
            let sid = test_sid("0a1b2c3d4e5f0a1b2c3d4e5f0a1b2c3d");
            let lease = session_open(&sid);
            let sid_clone = sid.clone();
            let still_pending = Arc::new(Mutex::new(Vec::<bool>::new()));
            let still_pending2 = still_pending.clone();
            let result = drive_request(&sid, move |frame| {
                let v: serde_json::Value = serde_json::from_str(&frame).unwrap_or_default();
                let Some(wire) = v.get("__ipe_id").and_then(|x| x.as_str()) else {
                    return;
                };
                let flipped_last = if wire.ends_with('0') { '1' } else { '0' };
                let mut guesses = vec![
                    format!("{}{flipped_last}", &wire[..wire.len() - 1]),
                    format!("{wire}0"),
                ];
                let upper = wire.to_uppercase();
                if upper != wire {
                    guesses.push(upper);
                }
                for guess in guesses {
                    deliver_inbound_for(
                        &sid_clone,
                        format!(r#"{{"__ipe_id":"{guess}","payload":666}}"#),
                    );
                    still_pending2
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(is_pending(&sid_clone, wire));
                }
                deliver_inbound_for(
                    &sid_clone,
                    format!(r#"{{"__ipe_id":"{wire}","payload":7}}"#),
                );
            })
            .await;
            let checks = still_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            assert!(
                checks.len() >= 2 && checks.iter().all(|&pending| pending),
                "a guessed token must leave the waiter pending: {checks:?}"
            );
            assert!(
                matches!(result, crate::IpeResult::Ok(7)),
                "only the minted token resolves the waiter, got {result:?}"
            );
            drop(lease);
        }

        // Numeric ids are refused whole: they resolve no waiter and never reach
        // a `js_subscribe` drain.
        #[tokio::test]
        async fn numeric_id_is_dropped_not_broadcast() {
            let sid = test_sid("1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e");
            let lease = session_open(&sid);
            let (h, got) = collect_for(&sid, any_decoder());
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let sid_clone = sid.clone();
            let result = drive_request(&sid, move |frame| {
                let v: serde_json::Value = serde_json::from_str(&frame).unwrap_or_default();
                let Some(wire) = v.get("__ipe_id").and_then(|x| x.as_str()) else {
                    return;
                };
                for id in 1..=512_u32 {
                    deliver_inbound_for(
                        &sid_clone,
                        format!(r#"{{"__ipe_id":{id},"payload":666}}"#),
                    );
                    deliver_inbound_for(
                        &sid_clone,
                        format!(r#"{{"__ipe_id":"{id}","payload":666}}"#),
                    );
                }
                deliver_inbound_for(
                    &sid_clone,
                    format!(r#"{{"__ipe_id":"{wire}","payload":7}}"#),
                );
            })
            .await;
            assert!(
                matches!(result, crate::IpeResult::Ok(7)),
                "no numeric id resolves the waiter, got {result:?}"
            );
            // A frame with no reserved field still reaches the drain, so the
            // drain was live while the numeric ids arrived.
            deliver_inbound_for(&sid, r#"{"plain":1}"#.to_string());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert_eq!(
                *got.lock().unwrap_or_else(|e| e.into_inner()),
                vec![1],
                "only the plain frame reaches the drain"
            );
            drop(h);
            drop(lease);
        }

        // Every outbound correlation and session id is a parseable token string.
        #[tokio::test]
        async fn envelope_ids_are_tokens() {
            let sid = test_sid("2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f");
            let lease = session_open(&sid);
            let sid_clone = sid.clone();
            let request_ids = Arc::new(Mutex::new(Vec::<String>::new()));
            let request_ids2 = request_ids.clone();
            let result = drive_request(&sid, move |frame| {
                let v: serde_json::Value = serde_json::from_str(&frame).unwrap_or_default();
                let Some(wire) = v.get("__ipe_id").and_then(|x| x.as_str()) else {
                    return;
                };
                request_ids2
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(wire.to_owned());
                deliver_inbound_for(
                    &sid_clone,
                    format!(r#"{{"__ipe_id":"{wire}","payload":7}}"#),
                );
            })
            .await;
            assert!(matches!(result, crate::IpeResult::Ok(7)));
            let request_ids = request_ids
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            assert_eq!(request_ids.len(), 1);
            assert!(request_ids.iter().all(|id| PortToken::parse(id).is_some()));

            let (handle, token, out) = open_session_capturing(&sid).await;
            assert!(PortToken::parse(&token).is_some());
            let frames = out.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let session_ids: Vec<String> = frames
                .iter()
                .filter_map(|frame| {
                    let v: serde_json::Value = serde_json::from_str(frame).ok()?;
                    v.get("__ipe_session")?.as_str().map(str::to_owned)
                })
                .collect();
            assert_eq!(
                session_ids,
                vec![token.clone()],
                "the open frame carries the token"
            );
            assert_ne!(
                token,
                handle.to_string(),
                "the handle is not the wire token"
            );
            drop(lease);
        }

        // A failed mint refuses the request before any frame or waiter exists.
        #[tokio::test]
        async fn request_refuses_without_entropy() {
            let sid = test_sid("3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a");
            let lease = session_open(&sid);
            let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let seen2 = seen.clone();
            bind_sink(
                &sid,
                Arc::new(move |s: &str| {
                    seen2
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(s.to_string());
                }),
            );
            let result = with_session(&SessionScope::new(sid.to_string()), || {
                request_with_mint::<i64, i64, _>(0_i64, int_decoder(), || Err(EntropyError))
            })
            .await;
            assert!(
                matches!(&result, crate::IpeResult::Err(e) if *e == IpeError::unavailable(
                    format!("js_request: {EntropyError}")
                )),
                "a failed mint is Unavailable, got {result:?}"
            );
            assert!(seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
            assert!(
                lock_sessions()
                    .get(&sid.0)
                    .is_none_or(|p| p.pending.is_empty()),
                "a failed mint registers no waiter"
            );
            drop(lease);
        }

        // The Ipê-side handle, as a number or a string, addresses no stream;
        // only the wire token does.
        #[tokio::test]
        async fn session_handle_is_not_the_wire_token() {
            let sid = test_sid("4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7b");
            let lease = session_open(&sid);
            let (handle, token, _out) = open_session_capturing(&sid).await;
            let (h, got) = collect_frames(&sid, handle);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(&sid, format!(r#"{{"__ipe_session":{handle},"payload":1}}"#));
            deliver_inbound_for(
                &sid,
                format!(r#"{{"__ipe_session":"{handle}","payload":2}}"#),
            );
            deliver_inbound_for(
                &sid,
                format!(r#"{{"__ipe_session":"{token}","payload":3}}"#),
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert_eq!(*got.lock().unwrap_or_else(|e| e.into_inner()), vec![3]);
            drop(h);
            drop(lease);
        }

        // A send to a handle the origin sid does not hold puts nothing on the
        // wire; a held handle sends one frame tagged with its token.
        #[tokio::test]
        async fn send_to_unheld_handle_sends_nothing() {
            let sid = test_sid("5f6a7b8c9d0e5f6a7b8c9d0e5f6a7b8c");
            let other = test_sid("6a7b8c9d0e1f6a7b8c9d0e1f6a7b8c9d");
            let lease = session_open(&sid);
            let lease_other = session_open(&other);
            let (handle, token, out) = open_session_capturing(&sid).await;
            let other_seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let other_seen2 = other_seen.clone();
            bind_sink(
                &other,
                Arc::new(move |s: &str| {
                    other_seen2
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(s.to_string());
                }),
            );
            out.lock().unwrap_or_else(|e| e.into_inner()).clear();

            let unheld = handle ^ 1;
            assert_eq!(
                publish_from(&sid, js_send_to_session::<i64, i64>(unheld, 5)),
                Some(0)
            );
            assert_eq!(
                publish_from(&other, js_send_to_session::<i64, i64>(handle, 5)),
                Some(0)
            );
            assert!(out.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
            assert!(
                other_seen
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .is_empty()
            );

            assert_eq!(
                publish_from(&sid, js_send_to_session::<i64, i64>(handle, 5)),
                Some(0)
            );
            assert_eq!(
                *out.lock().unwrap_or_else(|e| e.into_inner()),
                vec![format!(r#"{{"__ipe_session":"{token}","payload":5}}"#)]
            );
            drop(lease);
            drop(lease_other);
        }

        // A minted token that is already live refuses the new request and
        // leaves the live waiter in place: no overwrite, no eviction.
        #[tokio::test]
        async fn colliding_request_token_evicts_no_waiter() {
            tokio::time::pause();
            let sid = test_sid("8c9d0e1f2a3b8c9d0e1f2a3b8c9d0e1f");
            let lease = session_open(&sid);
            let Some(token) = PortToken::parse(super::UNMINTED_TOKEN) else {
                return;
            };
            let (tx, mut rx) = tokio::sync::oneshot::channel::<JsonVal>();
            let seeded = lock_sessions()
                .get_mut(&sid.0)
                .map(|p| p.pending.insert(token, tx));
            assert!(seeded.is_some(), "the lease holds the sid's entry");
            let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let seen2 = seen.clone();
            bind_sink(
                &sid,
                Arc::new(move |s: &str| {
                    seen2
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(s.to_string());
                }),
            );
            let result = with_session(&SessionScope::new(sid.to_string()), || {
                request_with_mint::<i64, i64, _>(0_i64, int_decoder(), move || Ok(token))
            })
            .await;
            assert!(
                matches!(&result, crate::IpeResult::Err(e) if *e == IpeError::unavailable(
                    format!("js_request: {EntropyError}")
                )),
                "a colliding token is Unavailable, got {result:?}"
            );
            assert!(
                seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "a colliding request sends nothing"
            );
            assert!(
                matches!(
                    rx.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty)
                ),
                "the live waiter keeps its sender"
            );
            assert!(is_pending(&sid, super::UNMINTED_TOKEN));
            drop(lease);
        }

        // A minted session token that is already live refuses the new open
        // and leaves the live stream, and its handle, in place.
        #[tokio::test]
        async fn colliding_session_token_evicts_no_stream() {
            let sid = test_sid("9d0e1f2a3b4c9d0e1f2a3b4c9d0e1f2a");
            let lease = session_open(&sid);
            let (handle, token, out) = open_session_capturing(&sid).await;
            out.lock().unwrap_or_else(|e| e.into_inner()).clear();
            let Some(live) = PortToken::parse(&token) else {
                return;
            };
            let result = with_session(&SessionScope::new(sid.to_string()), || {
                open_session_with_mint::<i64, i64, _, _>(
                    0_i64,
                    int_decoder(),
                    move || Ok(live),
                    PortHandle::mint,
                )
            })
            .await;
            assert!(
                matches!(&result, crate::IpeResult::Err(e) if *e == IpeError::unavailable(
                    format!("js_open_session: {EntropyError}")
                )),
                "a colliding session token is Unavailable, got {result:?}"
            );
            assert!(
                out.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "a colliding open sends nothing"
            );
            assert_eq!(
                wire_token_of(&sid, handle),
                token,
                "the live stream keeps its handle"
            );
            drop(lease);
        }

        // A negative handle never wraps onto a stream: the drain is inert, the
        // send puts nothing on the wire, and the close is an `Err`.
        #[tokio::test]
        async fn negative_handle_is_inert() {
            let sid = test_sid("7b8c9d0e1f2a7b8c9d0e1f2a7b8c9d0e");
            let lease = session_open(&sid);
            let (_handle, token, out) = open_session_capturing(&sid).await;
            out.lock().unwrap_or_else(|e| e.into_inner()).clear();
            for negative in [0_i64, -1, i64::MIN] {
                let (h, got) = collect_frames(&sid, negative);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                deliver_inbound_for(
                    &sid,
                    format!(r#"{{"__ipe_session":"{token}","payload":4}}"#),
                );
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                assert!(got.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
                drop(h);

                assert_eq!(
                    publish_from(&sid, js_send_to_session::<i64, i64>(negative, 5)),
                    Some(0)
                );
                assert!(out.lock().unwrap_or_else(|e| e.into_inner()).is_empty());

                let closed = with_session(&SessionScope::new(sid.to_string()), || {
                    js_close_session::<i64, i64>(negative, 0_i64, int_decoder())
                })
                .await;
                assert!(
                    matches!(&closed, crate::IpeResult::Err(e)
                        if *e == IpeError::from("js_close_session: session not open".to_string())),
                    "a negative handle closes nothing, got {closed:?}"
                );
            }
            drop(lease);
        }
        // Capture every frame `sid`'s sink receives, binding a fresh sink.
        fn capture_sink(sid: &SessionId) -> Arc<Mutex<Vec<String>>> {
            let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let seen2 = seen.clone();
            bind_sink(
                sid,
                Arc::new(move |s: &str| {
                    seen2
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(s.to_string());
                }),
            );
            seen
        }

        // Open a stream in `sid` whose handle is `handle`.
        async fn open_with_handle(sid: &SessionId, handle: i64) -> crate::IpeResult<IpeError, i64> {
            with_session(&SessionScope::new(sid.to_string()), || {
                open_session_with_mint::<i64, i64, _, _>(
                    0_i64,
                    int_decoder(),
                    PortToken::mint,
                    move || PortHandle::parse(handle),
                )
            })
            .await
        }

        // Once a life's lease drops, no reach for its sid recreates the entry:
        // each refuses or drops.
        #[tokio::test]
        async fn a_reach_after_close_creates_nothing() {
            let sid = test_sid("e0f1a2b3c4d5e0f1a2b3c4d5e0f1a2b3");
            let lease = session_open(&sid);
            assert!(lease.is_some());
            drop(lease);

            assert_eq!(publish_from(&sid, js_send::<i64, i64>(5)), Some(0));
            assert_eq!(
                register_out_sink_for(&sid, Arc::new(|_s: &str| {})),
                Err(PortClosed)
            );
            let requested = with_session(&SessionScope::new(sid.to_string()), || {
                request_with_mint::<i64, i64, _>(0_i64, int_decoder(), PortToken::mint)
            })
            .await;
            assert!(
                matches!(&requested, crate::IpeResult::Err(e)
                    if *e == IpeError::unavailable("js_request: session closed".to_owned())),
                "a request after close refuses, got {requested:?}"
            );
            let opened = open_with_handle(&sid, 3).await;
            assert!(
                matches!(&opened, crate::IpeResult::Err(e)
                    if *e == IpeError::unavailable("js_open_session: session closed".to_owned())),
                "an open after close refuses, got {opened:?}"
            );
            let (h, got) = collect_for(&sid, int_decoder());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(&sid, "1".to_string());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(got.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
            drop(h);
            assert!(
                !lock_sessions().contains_key(&sid.0),
                "no reach after close recreates the sid's entry"
            );
        }

        // A handle from a closed life names nothing in the life that follows.
        #[tokio::test]
        async fn a_stale_handle_after_reopen_is_inert() {
            let sid = test_sid("f1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4");
            let lease_a = session_open(&sid);
            let _seen_a = capture_sink(&sid);
            let opened_a = open_with_handle(&sid, 1).await;
            assert!(matches!(opened_a, crate::IpeResult::Ok(1)));
            drop(lease_a);

            let lease_b = session_open(&sid);
            let seen_b = capture_sink(&sid);
            let opened_b = open_with_handle(&sid, 2).await;
            assert!(matches!(opened_b, crate::IpeResult::Ok(2)));
            let token_b = wire_token_of(&sid, 2);
            assert!(!token_b.is_empty());
            assert!(wire_token_of(&sid, 1).is_empty());
            seen_b.lock().unwrap_or_else(|e| e.into_inner()).clear();

            assert_eq!(
                publish_from(&sid, js_send_to_session::<i64, i64>(1, 5)),
                Some(0)
            );
            assert!(
                seen_b.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "a stale handle sends nothing"
            );
            let closed = with_session(&SessionScope::new(sid.to_string()), || {
                js_close_session::<i64, i64>(1, 0_i64, int_decoder())
            })
            .await;
            assert!(
                matches!(&closed, crate::IpeResult::Err(e)
                    if *e == IpeError::from("js_close_session: session not open".to_string())),
                "a stale handle closes nothing, got {closed:?}"
            );
            let (h, got) = collect_frames(&sid, 1);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            deliver_inbound_for(
                &sid,
                format!(r#"{{"__ipe_session":"{token_b}","payload":4}}"#),
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            assert!(
                got.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "a stale handle drains nothing of the new life"
            );
            drop(h);
            drop(lease_b);
        }

        // The close of a superseded life leaves the life that replaced it.
        #[tokio::test]
        async fn a_superseded_lease_closes_nothing() {
            let sid = test_sid("a2b3c4d5e6f7a2b3c4d5e6f7a2b3c4d5");
            let lease_a = session_open(&sid);
            let seen_a = capture_sink(&sid);
            let lease_b = session_open(&sid);
            let seen_b = capture_sink(&sid);
            drop(lease_a);

            assert!(lock_sessions().contains_key(&sid.0));
            assert_eq!(publish_from(&sid, js_send::<i64, i64>(5)), Some(0));
            assert_eq!(seen_b.lock().unwrap_or_else(|e| e.into_inner()).len(), 1);
            assert!(seen_a.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
            drop(lease_b);
            assert!(!lock_sessions().contains_key(&sid.0));
        }

        // A drawn handle equal to a live stream's handle refuses the open and
        // leaves the live stream in place.
        #[tokio::test]
        async fn a_handle_collision_with_a_live_stream_is_refused() {
            let sid = test_sid("b3c4d5e6f7a8b3c4d5e6f7a8b3c4d5e6");
            let lease = session_open(&sid);
            let seen = capture_sink(&sid);
            let first = open_with_handle(&sid, 7).await;
            assert!(matches!(first, crate::IpeResult::Ok(7)));
            let token = wire_token_of(&sid, 7);
            seen.lock().unwrap_or_else(|e| e.into_inner()).clear();

            let second = open_with_handle(&sid, 7).await;
            assert!(
                matches!(&second, crate::IpeResult::Err(e) if *e == IpeError::unavailable(
                    format!("js_open_session: {EntropyError}")
                )),
                "a colliding handle is Unavailable, got {second:?}"
            );
            assert!(
                seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "a colliding open sends nothing"
            );
            assert_eq!(
                wire_token_of(&sid, 7),
                token,
                "the live stream keeps its handle"
            );
            drop(lease);
        }
    }
}

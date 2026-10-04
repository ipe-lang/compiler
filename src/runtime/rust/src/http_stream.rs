//! Ipe.Http.Stream — incremental HTTP response bodies (client side).
//!
//! Reads an outbound HTTP response body chunk-by-chunk via reqwest's
//! `bytes_stream()` instead of buffering the whole body (`Http.get`).
//!
//! Surface ported on the Rust backend:
//!
//!   * `open : HttpRequest -> Task Error StreamId`  — fire the request, resolve
//!     once the response headers arrive; register the byte stream under a
//!     freshly minted handle.
//!   * `forEachChunk : StreamId -> (String -> Task Error ()) -> Task Error ()`
//!     — synchronous drain (the relay shape — usable inside a plain
//!     Ipe.Http.Server handler, no TEA loop required).
//!   * `close : StreamId -> Task Error ()` — drop the stream / release the conn.
//!
//! The Sub-tier `chunks` (dispatching `ChunkEvent` Msgs into a TEA update loop)
//! is ported via `sub_subscribe_stream` + the bridged `ChunkEvent` enum below —
//! it drives a `Cli.tea` (or any `console_app`-hosted) TEA loop, the same
//! way `ws_client`'s `onMessage` does.
//!
//! A `StreamId` is an unforgeable capability: only `open` mints one (a 128-bit
//! key from the OS CSPRNG), no source form names one, every decode parses the
//! exact 32-char lowercase-hex wire form once, and `Debug` never renders the
//! key. The one registry refuses every handle it does not hold with a typed
//! `InvalidInput`, so no party reaches a stream it did not open.
//!
//! Every live upstream connection is owned by one value that also holds one of
//! `CLIENT_STREAMS_MAX` connection permits, and every wait for upstream bytes
//! (the response headers, then each chunk) ends within the idle ceiling. A
//! drain holds its connection only while its registry slot holds the drain's
//! cancel half, so a `close` stops it at once, even while it waits on the
//! upstream.

use super::*;
use crate::http_client::VettingResolver;
use crate::ssrf::DialPolicy;
use futures_util::{Stream, StreamExt};
use std::collections::HashMap;
use std::convert::Infallible;
use std::num::{NonZeroU64, NonZeroU128};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

/// Opaque handle for an in-flight HTTP streaming response.
///
/// Backs the opaque `StreamId` type of `Ipe.Http.Stream`. The key is private:
/// the only constructors are `open`'s mint and the parsing `Deserialize`.
/// `Copy` so it can be passed by value to Task closures without cloning.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpeStreamId {
    key: StreamKey,
}

/// The registry key behind a `StreamId`: nonzero, so no zeroed value names a stream.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct StreamKey(NonZeroU128);

/// Hex digits in the wire form of a key (128 bits, 4 per digit).
const KEY_HEX_LEN: usize = 32;

/// Draws a mint makes before giving up on a zero or colliding key.
const MINT_ATTEMPTS: usize = 4;

/// The fixed refusal of every malformed wire handle; it never echoes the input.
const INVALID_ID: &str = "invalid stream id";
const UNKNOWN_STREAM: &str = "http stream: unknown or ended stream";
const STREAM_BUSY: &str = "http stream: already being consumed";
const TOO_MANY_STREAMS: &str = "http stream: too many open streams";
const MINT_EXHAUSTED: &str = "http stream: key mint exhausted";
const ENTROPY_UNAVAILABLE: &str = "http stream: entropy unavailable";
const SEQUENCE_EXHAUSTED: &str = "http stream: sequence exhausted";

impl StreamKey {
    /// Parses the exact wire form: 32 lowercase hex digits, value nonzero.
    fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != KEY_HEX_LEN {
            return None;
        }
        let mut acc: u128 = 0;
        for &b in bytes {
            let digit = match b {
                b'0'..=b'9' | b'a'..=b'f' => char::from(b).to_digit(16)?,
                _ => return None,
            };
            acc = (acc << 4) | u128::from(digit);
        }
        NonZeroU128::new(acc).map(Self)
    }
}

impl std::fmt::Debug for IpeStreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamId(<opaque>)")
    }
}

impl serde::Serialize for IpeStreamId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{:032x}", self.key.0.get()))
    }
}

impl<'de> serde::Deserialize<'de> for IpeStreamId {
    /// Parses the exact key string once; every refusal (an integer, a
    /// malformed string, any other shape) is the fixed `INVALID_ID` text, so
    /// no decoder error echoes the input.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_str(StreamIdVisitor)
            .map_err(|_| serde::de::Error::custom(INVALID_ID))
    }
}

/// Accepts only a string in the exact key form; every other shape falls to
/// the visitor's default refusal.
struct StreamIdVisitor;

impl serde::de::Visitor<'_> for StreamIdVisitor {
    type Value = IpeStreamId;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a stream id")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<IpeStreamId, E> {
        StreamKey::parse(v)
            .map(|key| IpeStreamId { key })
            .ok_or_else(|| E::custom(INVALID_ID))
    }
}

/// Mints a fresh key from `source`, redrawing a zero or a `live` collision.
///
/// At most `MINT_ATTEMPTS` draws; then `Unavailable`. A failing source is
/// `Unavailable` at once.
fn mint_with<S, L>(mut source: S, live: L) -> Result<StreamKey, IpeError>
where
    S: FnMut(&mut [u8; 16]) -> Result<(), getrandom::Error>,
    L: Fn(StreamKey) -> bool,
{
    for _ in 0..MINT_ATTEMPTS {
        let mut buf = [0u8; 16];
        source(&mut buf).map_err(|_| IpeError::unavailable(ENTROPY_UNAVAILABLE.to_owned()))?;
        if let Some(raw) = NonZeroU128::new(u128::from_le_bytes(buf)) {
            let key = StreamKey(raw);
            if !live(key) {
                return Ok(key);
            }
        }
    }
    Err(IpeError::unavailable(MINT_EXHAUSTED.to_owned()))
}

/// The OS CSPRNG, the production key source.
fn os_entropy(buf: &mut [u8; 16]) -> Result<(), getrandom::Error> {
    getrandom::getrandom(buf)
}

/// `Ipe.Http.Stream.ChunkEvent` — one incremental event on a stream.
/// Bridged (via `runtimeOpaqueTypes`) so the runtime can CONSTRUCT it to hand to
/// the user's `toMsg : ChunkEvent -> msg` callback; user code only ever
/// pattern-matches it. Generic over the Ipê error type `E` (always `IpeError`
/// in practice — pinned at the call site) because `Errored` carries an `Error`.
/// Variant names match the Ipê constructors verbatim so codegen's match arms
/// (`ChunkEvent::Chunk(s)` / `::Done` / `::Errored(e)`) resolve through the
/// `pub type` alias the bridge emits.
// Serde derives: a Web `Msg` may carry a `ChunkEvent` payload, and Web
// messages round-trip through the session store (serde boundary). The derive
// bounds require `E: Serialize/Deserialize`, which holds for both inhabitants
// (`String` and `IpeError`).
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ChunkEvent<E> {
    Chunk(String),
    Done,
    Errored(E),
}

/// Live upstream connections allowed at once: the live-table cap and the
/// connection-permit count.
const CLIENT_STREAMS_MAX: usize = 1024;

// The permit semaphore must be constructible at the cap: a cap above
// `Semaphore::MAX_PERMITS` underflows this item and breaks the build.
const _: usize = Semaphore::MAX_PERMITS - CLIENT_STREAMS_MAX;

/// The longest wait for upstream progress: the response headers, then each chunk.
///
/// Held as a nonzero millisecond count, so a zero ceiling is unrepresentable.
#[derive(Clone, Copy, Debug)]
struct IdleCeiling {
    millis: NonZeroU64,
}

impl IdleCeiling {
    const fn from_millis(millis: NonZeroU64) -> Self {
        Self { millis }
    }

    const fn as_duration(self) -> Duration {
        Duration::from_millis(self.millis.get())
    }
}

/// 300 s: an upstream silent for longer ends the open or the drain with a `Timeout`.
const STREAM_IDLE_CEILING: IdleCeiling =
    IdleCeiling::from_millis(NonZeroU64::MIN.saturating_add(299_999));

/// The fixed text of the idle-ceiling `Timeout`; it never carries the URL.
const STREAM_IDLE_TIMED_OUT: &str = "http stream: no data within the idle ceiling";

fn idle_timeout() -> IpeError {
    IpeError::timeout().with_message(STREAM_IDLE_TIMED_OUT.to_owned())
}

/// The registry's half of a drain's cancel signal.
///
/// Dropping it cancels the drain, and nothing can be sent on it, so every way
/// out of `Draining` (a close, an eviction, the registry itself going away)
/// cancels.
struct CancelHalf {
    _revoke: oneshot::Sender<Infallible>,
}

/// The drain's half of its cancel signal: resolves once the slot's `CancelHalf` drops.
struct DrainCancel {
    revoked: oneshot::Receiver<Infallible>,
}

impl DrainCancel {
    /// Completes when the registry gives the drain up; never polled again after that.
    async fn revoked(&mut self) {
        let _ = (&mut self.revoked).await;
    }
}

fn cancel_pair() -> (CancelHalf, DrainCancel) {
    let (revoke, revoked) = oneshot::channel();
    (CancelHalf { _revoke: revoke }, DrainCancel { revoked })
}

/// One of `CLIENT_STREAMS_MAX` connection permits.
///
/// It lives in the value that owns the connection, so the connection count is
/// the permit count whatever the registry holds.
struct ConnPermit {
    _held: OwnedSemaphorePermit,
}

/// A stream a drain can read: its chunk source and the permit it holds.
trait LiveStream: Send + 'static {
    /// The foreign read error of the chunk source.
    type Fault: Send + 'static;
    /// The chunk source, as UTF-8 text per chunk.
    type Body: Stream<Item = Result<String, Self::Fault>> + Unpin + Send + 'static;

    /// Splits the stream into its chunk source and its permit.
    fn into_parts(self) -> (Self::Body, ConnPermit);

    /// The typed error a read fault becomes; a foreign error is redacted here.
    fn fault<E: From<String>>(fault: Self::Fault) -> E;
}

/// A response that holds its connection permit; the only constructor takes one.
struct LiveResponse {
    resp: reqwest::Response,
    permit: ConnPermit,
}

type ResponseBody = Pin<Box<dyn Stream<Item = Result<String, reqwest::Error>> + Send>>;

#[allow(clippy::disallowed_methods)] // a streamed chunk reaches Ipê as `String` text
fn chunk_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

impl LiveStream for LiveResponse {
    type Fault = reqwest::Error;
    type Body = ResponseBody;

    fn into_parts(self) -> (ResponseBody, ConnPermit) {
        let body: ResponseBody = Box::pin(
            self.resp
                .bytes_stream()
                .map(|read| read.map(|bytes| chunk_text(&bytes))),
        );
        (body, self.permit)
    }

    // [B8] The reqwest error `Debug`/`Display` can echo the target URL, request
    // headers, or a bearer / API key; `redacted_transport_error` logs the raw
    // detail under a ref id and returns a fixed generic message.
    fn fault<E: From<String>>(fault: reqwest::Error) -> E {
        crate::http_client::redacted_transport_error(fault)
    }
}

/// Ended handles remembered at once; a full table forgets its oldest.
const TOMBSTONES_MAX: usize = CLIENT_STREAMS_MAX;

/// Where a live stream is in its life.
enum Slot<V> {
    /// Opened, its response parked until a drain or a close.
    Parked(V),
    /// One drain owns the response; dropping the half cancels it.
    Draining(CancelHalf),
}

/// One live registry entry: an insertion order (never an identity) and its slot.
struct Entry<V> {
    seq: u64,
    slot: Slot<V>,
}

/// A parked response handed to its one drain.
struct Claimed<V> {
    value: V,
    cancel: DrainCancel,
    /// The entry's `seq`: the drain's lease ends only an entry carrying it.
    seq: u64,
}

/// Another drain owns the slot.
struct Busy;

/// Moves a parked entry to `Draining`, or reports that a drain already owns it.
fn claim<V>(entry: &mut Entry<V>) -> Result<Claimed<V>, Busy> {
    let (half, cancel) = cancel_pair();
    match std::mem::replace(&mut entry.slot, Slot::Draining(half)) {
        Slot::Parked(value) => Ok(Claimed {
            value,
            cancel,
            seq: entry.seq,
        }),
        // The running drain's half goes back; the one just installed drops.
        running @ Slot::Draining(_) => {
            entry.slot = running;
            Err(Busy)
        }
    }
}

/// When a stream ended, relative to every other ended stream.
///
/// Stamped at the moment its tombstone is recorded, so the tombstone table
/// forgets the stream that ended first, not the one that opened first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct EndStamp(u64);

/// Hands out `EndStamp`s in strictly increasing order.
///
/// A spent clock hands out none, so no stamp ever repeats or wraps.
struct EndClock {
    next: u64,
}

impl EndClock {
    const fn new() -> Self {
        Self { next: 0 }
    }

    fn tick(&mut self) -> Option<EndStamp> {
        let stamp = self.next;
        self.next = stamp.checked_add(1)?;
        Some(EndStamp(stamp))
    }
}

/// What a `chunks` subscribe must do.
enum Subscription<V> {
    /// First subscribe of a parked stream: drain this response.
    Drain(Claimed<V>),
    /// The stream is draining or ended, or nothing more can be recorded: nothing to start.
    Active,
    /// The handle names no stream: emit one `Errored`; a tombstone now dedups it.
    Refused,
}

/// The one registry of client streams; every state change is one method under one lock.
struct StreamRegistry<V> {
    /// Streams holding a connection, parked or draining: at most `CLIENT_STREAMS_MAX`.
    live: HashMap<StreamKey, Entry<V>>,
    /// Tombstones of ended streams with when each ended, so a re-subscribe stays quiet.
    ///
    /// A table of its own: a tombstone holds no connection, so no churn of ended
    /// streams can crowd out a live one, and no live stream can crowd out a tombstone.
    ended: HashMap<StreamKey, EndStamp>,
    next_seq: u64,
    end_clock: EndClock,
    conns: Arc<Semaphore>,
}

impl<V> StreamRegistry<V> {
    fn new() -> Self {
        Self {
            live: HashMap::new(),
            ended: HashMap::new(),
            next_seq: 0,
            end_clock: EndClock::new(),
            conns: Arc::new(Semaphore::new(CLIENT_STREAMS_MAX)),
        }
    }

    fn oldest_parked(&self) -> Option<StreamKey> {
        self.live
            .iter()
            .filter(|(_, e)| matches!(e.slot, Slot::Parked(_)))
            .min_by_key(|(_, e)| e.seq)
            .map(|(k, _)| *k)
    }

    fn oldest_ended(&self) -> Option<StreamKey> {
        self.ended
            .iter()
            .min_by_key(|(_, ended)| **ended)
            .map(|(k, _)| *k)
    }

    fn bump_seq(&mut self) -> Result<u64, IpeError> {
        let seq = self.next_seq;
        self.next_seq = seq
            .checked_add(1)
            .ok_or_else(|| IpeError::unavailable(SEQUENCE_EXHAUSTED.to_owned()))?;
        Ok(seq)
    }

    fn try_permit(&self) -> Option<ConnPermit> {
        Arc::clone(&self.conns)
            .try_acquire_owned()
            .ok()
            .map(|held| ConnPermit { _held: held })
    }

    /// Claims one connection permit for a request about to go out.
    ///
    /// With no permit free the registry gives up its oldest parked stream (its
    /// response drops at once and returns its permit); with nothing parked it
    /// refuses. The claim and the eviction share the registry lock, so no other
    /// claimant can take the freed permit in between.
    fn reserve(&mut self) -> Result<ConnPermit, IpeError> {
        let refused = || IpeError::unavailable(TOO_MANY_STREAMS.to_owned());
        if let Some(permit) = self.try_permit() {
            return Ok(permit);
        }
        let parked = self.oldest_parked().ok_or_else(refused)?;
        self.live.remove(&parked);
        self.try_permit().ok_or_else(refused)
    }

    /// Remembers `key` as ended now; a full table first forgets the stream that ended first.
    ///
    /// A spent end clock records nothing and reports `false`: the handle is then
    /// unknown, and a later subscribe, unable to record a refusal, starts nothing.
    fn tombstone(&mut self, key: StreamKey) -> bool {
        let Some(stamp) = self.end_clock.tick() else {
            return false;
        };
        if self.ended.len() >= TOMBSTONES_MAX
            && !self.ended.contains_key(&key)
            && let Some(oldest) = self.oldest_ended()
        {
            self.ended.remove(&oldest);
        }
        self.ended.insert(key, stamp);
        true
    }

    /// Parks `value` under a freshly minted handle.
    fn open<S>(&mut self, value: V, source: S) -> Result<IpeStreamId, IpeError>
    where
        S: FnMut(&mut [u8; 16]) -> Result<(), getrandom::Error>,
    {
        // Every live stream holds a permit, so the table is never full here
        // unless the permit count and the table drift: refuse then, fail closed.
        if self.live.len() >= CLIENT_STREAMS_MAX {
            return Err(IpeError::unavailable(TOO_MANY_STREAMS.to_owned()));
        }
        let key = mint_with(source, |k| {
            self.live.contains_key(&k) || self.ended.contains_key(&k)
        })?;
        let seq = self.bump_seq()?;
        self.live.insert(
            key,
            Entry {
                seq,
                slot: Slot::Parked(value),
            },
        );
        Ok(IpeStreamId { key })
    }

    /// Hands a parked response to one drain; any other state is a typed refusal.
    fn take_for_drain(&mut self, key: StreamKey) -> Result<Claimed<V>, IpeError> {
        let Some(entry) = self.live.get_mut(&key) else {
            return Err(IpeError::invalid_input(UNKNOWN_STREAM.to_owned()));
        };
        claim(entry).map_err(|Busy| IpeError::conflict(STREAM_BUSY.to_owned()))
    }

    /// Releases a live stream. A handle naming no live stream (never opened,
    /// already closed, ended, or evicted) is a typed refusal that leaves the
    /// registry unchanged.
    fn close(&mut self, key: StreamKey) -> Result<(), IpeError> {
        match self.live.remove(&key) {
            Some(Entry {
                slot: Slot::Draining(cancel),
                ..
            }) => {
                // A spent end clock leaves the handle unknown, never live.
                self.tombstone(key);
                // The drain sees its cancel half drop and releases the connection.
                drop(cancel);
                Ok(())
            }
            // A parked response nothing reads drops with its entry.
            Some(Entry {
                slot: Slot::Parked(_),
                ..
            }) => Ok(()),
            None => Err(IpeError::invalid_input(UNKNOWN_STREAM.to_owned())),
        }
    }

    /// Decides one `chunks` subscribe.
    fn subscribe(&mut self, key: StreamKey) -> Subscription<V> {
        if let Some(entry) = self.live.get_mut(&key) {
            return match claim(entry) {
                Ok(claimed) => Subscription::Drain(claimed),
                Err(Busy) => Subscription::Active,
            };
        }
        if self.ended.contains_key(&key) {
            return Subscription::Active;
        }
        if self.tombstone(key) {
            Subscription::Refused
        } else {
            // A spent end clock records nothing more, so a refusal could not be
            // deduplicated: start nothing.
            Subscription::Active
        }
    }

    /// Ends a drain: the entry the drain owns (`seq`) becomes a tombstone.
    ///
    /// An entry the drain does not own (another `seq`, or not draining) is left alone.
    fn finish_drain(&mut self, key: StreamKey, seq: u64) {
        let owned = self
            .live
            .get(&key)
            .is_some_and(|e| e.seq == seq && matches!(e.slot, Slot::Draining(_)));
        if owned {
            self.live.remove(&key);
            // A spent end clock leaves the handle unknown, never live.
            self.tombstone(key);
        }
    }
}

// Contract: every `open` should be paired with a `forEachChunk`/`chunks` drain
// or a `close` — each releases the parked response and its permit. The idle
// ceiling bounds the header wait and every chunk wait; `CLIENT_STREAMS_MAX`
// bounds live connections under abandoned-stream workloads.
fn registry() -> &'static Mutex<StreamRegistry<LiveResponse>> {
    static R: OnceLock<Mutex<StreamRegistry<LiveResponse>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(StreamRegistry::new()))
}

/// Runs `f` under `reg`'s lock.
///
/// A poisoned lock is recovered: no method leaves a cross-entry invariant
/// half-written.
fn with_registry<V, T>(
    reg: &Mutex<StreamRegistry<V>>,
    f: impl FnOnce(&mut StreamRegistry<V>) -> T,
) -> T {
    let mut guard = reg.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

/// Ends a drain when dropped, so a cancelled drain never pins its slot as draining.
struct DrainLease<V: 'static> {
    reg: &'static Mutex<StreamRegistry<V>>,
    key: StreamKey,
    seq: u64,
}

impl<V: 'static> Drop for DrainLease<V> {
    fn drop(&mut self) {
        with_registry(self.reg, |r| r.finish_drain(self.key, self.seq));
    }
}

/// What ended a drain.
enum DrainEnd<X, E> {
    /// The upstream finished cleanly.
    Eof,
    /// The registry gave the drain up (a close, an eviction, the registry dropped).
    Cancelled,
    /// No bytes arrived within the idle ceiling.
    Idle,
    /// The upstream read failed.
    ReadFault(X),
    /// The per-chunk step failed.
    BodyFailed(E),
}

/// A drain's resources: the chunk source, its permit, its cancel signal and its ceiling.
struct Pump<S> {
    stream: S,
    permit: ConnPermit,
    cancel: DrainCancel,
    idle: IdleCeiling,
}

impl<S, X> Pump<S>
where
    S: Stream<Item = Result<String, X>> + Unpin + Send,
    X: Send,
{
    /// Reads chunks until the upstream ends, the registry cancels, or the idle ceiling passes.
    ///
    /// Every wait is a biased `select!` with the cancel signal first, so a
    /// cancelled drain neither reads nor starts another chunk. A cancel during a
    /// step drops the stream and the permit at once, then lets the step finish:
    /// the connection is released, the caller's effect is never torn. Every arm
    /// is irrefutable and unconditional, so no `select!` can find all arms disabled.
    async fn run<E, F, Fut>(self, mut on_chunk: F) -> DrainEnd<X, E>
    where
        E: Send,
        F: FnMut(String) -> Fut + Send,
        Fut: Future<Output = Result<(), E>> + Send,
    {
        let Self {
            mut stream,
            permit,
            mut cancel,
            idle,
        } = self;
        loop {
            let next = tokio::select! {
                biased;
                () = cancel.revoked() => return DrainEnd::Cancelled,
                next = tokio::time::timeout(idle.as_duration(), stream.next()) => next,
            };
            let chunk = match next {
                Err(_elapsed) => return DrainEnd::Idle,
                Ok(None) => return DrainEnd::Eof,
                Ok(Some(Err(fault))) => return DrainEnd::ReadFault(fault),
                Ok(Some(Ok(chunk))) => chunk,
            };
            let step = on_chunk(chunk);
            tokio::pin!(step);
            tokio::select! {
                biased;
                () = cancel.revoked() => {
                    drop(stream);
                    drop(permit);
                    return match step.await {
                        Ok(()) => DrainEnd::Cancelled,
                        Err(e) => DrainEnd::BodyFailed(e),
                    };
                }
                done = &mut step => {
                    if let Err(e) = done {
                        return DrainEnd::BodyFailed(e);
                    }
                }
            }
        }
    }
}

/// `forEachChunk` over `reg`: drains `key` through `body`, bounded by `idle`.
async fn for_each_chunk_in<V, E, F>(
    reg: &'static Mutex<StreamRegistry<V>>,
    key: StreamKey,
    idle: IdleCeiling,
    body: F,
) -> IpeResult<E, ()>
where
    V: LiveStream,
    E: From<String> + From<IpeError> + Send + 'static,
    F: Fn(String) -> IpeTask<E, ()> + Send + 'static,
{
    let claimed = match with_registry(reg, |r| r.take_for_drain(key)) {
        Ok(claimed) => claimed,
        Err(e) => return IpeResult::Err(E::from(e)),
    };
    let _lease = DrainLease {
        reg,
        key,
        seq: claimed.seq,
    };
    let (stream, permit) = claimed.value.into_parts();
    let pump = Pump {
        stream,
        permit,
        cancel: claimed.cancel,
        idle,
    };
    let end = pump
        .run(move |chunk| {
            let step = body(chunk);
            async move {
                match step.await {
                    IpeResult::Ok(()) => Ok(()),
                    IpeResult::Err(e) => Err(e),
                }
            }
        })
        .await;
    match end {
        DrainEnd::Eof | DrainEnd::Cancelled => IpeResult::Ok(()),
        DrainEnd::Idle => IpeResult::Err(E::from(idle_timeout())),
        DrainEnd::ReadFault(fault) => IpeResult::Err(V::fault::<E>(fault)),
        DrainEnd::BodyFailed(e) => IpeResult::Err(e),
    }
}

/// Hands each `ChunkEvent` to the subscription loop as its `Msg`.
struct ChunkRelay<M, F> {
    to_msg: F,
    emit: Arc<dyn Fn(M) + Send + Sync>,
}

impl<M, F> ChunkRelay<M, F> {
    fn send<E>(&mut self, event: ChunkEvent<E>)
    where
        F: Fn(ChunkEvent<E>) -> M,
    {
        (self.emit)((self.to_msg)(event));
    }
}

/// `chunks` over `reg`: a subscription source draining `key` into `to_msg` Msgs.
fn subscribe_in<V, E, M, F>(
    reg: &'static Mutex<StreamRegistry<V>>,
    key: StreamKey,
    idle: IdleCeiling,
    to_msg: F,
) -> IpeSub<M>
where
    V: LiveStream,
    E: From<String> + From<IpeError> + Send + 'static,
    M: Send + 'static,
    F: Fn(ChunkEvent<E>) -> M + Send + 'static,
{
    IpeSub::Source(Box::new(move |emit| {
        let mut relay = ChunkRelay { to_msg, emit };
        match with_registry(reg, |r| r.subscribe(key)) {
            Subscription::Drain(claimed) => {
                // The lease moves into the task, so a task dropped before its
                // first poll still ends the slot.
                let lease = DrainLease {
                    reg,
                    key,
                    seq: claimed.seq,
                };
                tokio::spawn(async move {
                    let (stream, permit) = claimed.value.into_parts();
                    let pump = Pump {
                        stream,
                        permit,
                        cancel: claimed.cancel,
                        idle,
                    };
                    let end = pump
                        .run(|chunk| {
                            relay.send::<E>(ChunkEvent::Chunk(chunk));
                            std::future::ready(Ok::<(), Infallible>(()))
                        })
                        .await;
                    // The slot ends before the final event, so a re-subscribe
                    // the event provokes finds the tombstone.
                    drop(lease);
                    match end {
                        DrainEnd::Eof => relay.send::<E>(ChunkEvent::Done),
                        DrainEnd::Idle => {
                            relay.send::<E>(ChunkEvent::Errored(E::from(idle_timeout())));
                        }
                        DrainEnd::ReadFault(fault) => {
                            relay.send::<E>(ChunkEvent::Errored(V::fault::<E>(fault)));
                        }
                        DrainEnd::Cancelled => {}
                        DrainEnd::BodyFailed(never) => match never {},
                    }
                });
            }
            Subscription::Refused => {
                relay.send::<E>(ChunkEvent::Errored(E::from(IpeError::invalid_input(
                    UNKNOWN_STREAM.to_owned(),
                ))));
            }
            Subscription::Active => {}
        }
        tokio::spawn(async {}) // dummy handle for `SubRuntime` to abort harmlessly
    }))
}

/// `open` over `reg`: fires `req` under `policy`, bounded by `idle`, parks the response.
async fn open_in<E>(
    reg: &'static Mutex<StreamRegistry<LiveResponse>>,
    req: HttpRequest,
    policy: DialPolicy,
    idle: IdleCeiling,
) -> IpeResult<E, IpeStreamId>
where
    E: From<String> + From<IpeError> + Send + 'static,
{
    // SSRF guard: resolve + validate + pin, and the per-redirect re-check,
    // through the shared helper, identical to Http.get/post.
    let builder = reqwest::Client::builder().connect_timeout(Duration::from_secs(30));
    let builder = match crate::http_client::ssrf_apply_with(
        builder,
        &req.url,
        req.redirects,
        policy,
        VettingResolver::system(),
    )
    .await
    {
        Ok(b) => b,
        Err(refusal) => {
            return IpeResult::Err(E::from(IpeError::invalid_input(format!("http: {refusal}"))));
        }
    };
    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            return IpeResult::Err(E::from(IpeError::unavailable(format!(
                "http.stream.open: client: {e}"
            ))));
        }
    };
    // The permit is claimed before the request goes out, so a header wait in
    // flight counts against the cap; every early return gives it back.
    let permit = match with_registry(reg, StreamRegistry::reserve) {
        Ok(permit) => permit,
        Err(e) => return IpeResult::Err(E::from(e)),
    };
    // `HttpMethod` is an ADT — every variant maps to a known reqwest
    // constant (no runtime failure possible here).
    let method = crate::http_client::method_to_reqwest(req.method);
    let mut rb = client.request(method, &req.url);
    for (k, v) in &req.headers {
        rb = rb.header(k.as_str(), v.as_str());
    }
    if !req.body.is_empty() {
        rb = rb.body(req.body.clone());
    }
    // No whole-request timeout — streams may run for minutes (LLM completions).
    // The idle ceiling bounds the wait for the headers; the 30 s connect
    // timeout above bounds only the connect phase of it.
    let resp = match tokio::time::timeout(idle.as_duration(), rb.send()).await {
        Err(_elapsed) => return IpeResult::Err(E::from(idle_timeout())),
        Ok(Ok(r)) => r,
        // [B8] The reqwest error `Debug`/`Display` (and `req.url`) can echo the
        // target URL / request headers / bearer / API key. Route through the
        // correlation-id redaction helper: raw detail → server log under a ref
        // id; Ipê sees only a fixed generic message.
        Ok(Err(e)) => return IpeResult::Err(crate::http_client::redacted_transport_error(e)),
    };
    // HTTP error statuses (4xx/5xx) still surface as a stream — the body may
    // carry the error payload the caller wants to read. Mirrors Http.get
    // returning Ok with a 4xx status.
    match with_registry(reg, |r| r.open(LiveResponse { resp, permit }, os_entropy)) {
        Ok(sid) => IpeResult::Ok(sid),
        Err(e) => IpeResult::Err(E::from(e)),
    }
}

/// `Ipe.Http.Stream.open : HttpRequest -> Task Error StreamId`
///
/// Returns a freshly minted `IpeStreamId` handle for the parked response.
///
/// No whole-request timeout — streams may run for minutes (LLM completions).
/// The response headers must arrive within the idle ceiling (300 s), else
/// `Err Timeout`. The request holds one connection permit from before it goes
/// out; a registry at the cap with nothing parked refuses with `Err Unavailable`.
pub fn http_stream_open<E: From<String> + From<IpeError> + Send + 'static>(
    req: HttpRequest,
) -> IpeTask<E, IpeStreamId> {
    Box::pin(
        async move { open_in(registry(), req, DialPolicy::from_env(), STREAM_IDLE_CEILING).await },
    )
}

/// `Ipe.Http.Stream.forEachChunk : StreamId -> (String -> Task Error ()) -> Task Error ()`
///
/// Drains the stream synchronously from the calling task, invoking `body chunk`
/// per chunk. Bridges the client consumer to a server producer
/// (`Server.Stream.emit`) inside one Ipe.Http.Server handler — the relay shape.
///
/// Semantics:
///   * clean EOF                     → Ok ()
///   * upstream read error           → Err e
///   * no bytes within the idle ceiling (300 s, per read) → Err `Timeout`
///   * `body chunk` returns Err      → abort, close, Err e (fail-fast)
///   * `close` during the drain      → stops at once, even blocked on the
///     upstream, releases the connection, Ok ()
///   * a handle no open stream holds → Err `InvalidInput`
///   * a stream another drain owns   → Err `Conflict`
///   * the connection is always released on exit.
///
/// Backpressure: `body` runs synchronously per chunk; if it blocks on a slow
/// downstream (`Server.Stream.emit` to a bounded channel) the upstream read
/// naturally throttles. Time spent in `body` is not upstream idleness, so the
/// ceiling does not count it.
pub fn http_stream_for_each_chunk<E, F>(sid: IpeStreamId, body: F) -> IpeTask<E, ()>
where
    E: From<String> + From<IpeError> + Send + 'static,
    F: Fn(String) -> IpeTask<E, ()> + Send + 'static,
{
    Box::pin(for_each_chunk_in(
        registry(),
        sid.key,
        STREAM_IDLE_CEILING,
        body,
    ))
}

/// `Ipe.Http.Stream.close : StreamId -> Task Error ()`
///
/// Releases a live stream: a parked response drops at once, a stream being
/// drained stops at once and releases its connection, even while blocked
/// waiting on the upstream. A handle naming no live stream (never opened,
/// already closed, ended by its drain, or evicted) is `Err InvalidInput`, so a
/// double close or a forged handle never passes for a release. A caller
/// wanting idempotence opts in with `Task.onError`.
pub fn http_stream_close<E: From<String> + From<IpeError> + Send + 'static>(
    sid: IpeStreamId,
) -> IpeTask<E, ()> {
    let key = sid.key;
    Box::pin(async move {
        match with_registry(registry(), |r| r.close(key)) {
            Ok(()) => IpeResult::Ok(()),
            Err(e) => IpeResult::Err(E::from(e)),
        }
    })
}

// ─── Sub-tier: chunks → ChunkEvent Msgs ─────────────────────────────────────

/// Ipe.Http.Stream.chunks → `Sub_subscribeStream`.
///
/// Returns a `IpeSub::Source` that, on first subscribe for a parked stream,
/// spawns a detached task draining the response and dispatching a `ChunkEvent`
/// Msg per chunk: `Chunk s` per UTF-8 byte chunk, `Done` on clean EOF,
/// `Errored e` on a read fault or when no bytes arrive within the idle ceiling
/// (300 s, per read, a `Timeout`); a `close` during the drain stops it at once,
/// even blocked on the upstream, with no further event. `subscriptions` is
/// re-evaluated on every TEA `update`, so a re-subscribe to a draining or
/// ended stream starts nothing — the registry decides that under its one lock.
/// A handle no open stream holds gets exactly one `Errored InvalidInput` (its
/// tombstone dedups every re-subscribe). The drain is DETACHED —
/// `SubRuntime`'s abort-on-respawn only ever hits the dummy handle, never the
/// drain. `E` is pinned to `IpeError` at the call site.
/// `to_msg` is moved exclusively into the ONE detached `tokio::spawn` task
/// below (never behind a shared `Arc`, never read from two threads at once) --
/// the same shape as the sibling `sub_subscribe_topic` (`pubsub.rs`), whose
/// doc comment states the identical rationale. `Send` is therefore the full
/// and correct contract; `Sync` is NOT required. Over-declaring `+ Sync` would
/// be unsatisfiable: the codegen's generic first-class-function-value
/// rendering boxes the closure as `Box<dyn Fn(..) -> .. + Send + 'static>`
/// (deliberately `+Send`-only, since a trait object's auto-trait set is
/// exactly its bound list), so a `+ Sync` bound could never hold regardless of
/// what the boxed closure captured and every `Http.Stream.chunks` subscription
/// would fail `cargo build` with E0277 despite `ipe` accepting the program (a
/// THE-SEAL violation). The bound matches the actual (Send-only) usage rather
/// than re-wrapping the box in a fresh closure at the emit site (the technique
/// used for `html_on_raw_` / `ui_on_submit_` / `Ui.on*`), because THOSE
/// runtime slots are genuinely `Arc<dyn Fn + Send + Sync>` shared across a live
/// session's concurrently-serviced dispatch table -- a structurally different,
/// stronger requirement this kernel never has.
pub fn sub_subscribe_stream<E, M, F>(sid: IpeStreamId, to_msg: F) -> IpeSub<M>
where
    E: From<String> + From<IpeError> + Send + 'static,
    M: Send + 'static,
    F: Fn(ChunkEvent<E>) -> M + Send + 'static,
{
    subscribe_in(registry(), sid.key, STREAM_IDLE_CEILING, to_msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{FutureExt, stream};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Notify;
    use tokio::task::JoinHandle;
    use tokio::time::Instant;

    /// A deterministic key source: the n-th draw is the key `n`.
    fn counting_source() -> impl FnMut(&mut [u8; 16]) -> Result<(), getrandom::Error> {
        let mut next: u128 = 0;
        move |buf: &mut [u8; 16]| {
            next += 1;
            *buf = next.to_le_bytes();
            Ok(())
        }
    }

    fn key(n: u128) -> StreamKey {
        StreamKey(NonZeroU128::new(n).unwrap_or(NonZeroU128::MIN))
    }

    fn kind(e: &IpeError) -> IpeErrorKind {
        let IpeError::Error(k, _) = e;
        *k
    }

    fn message(e: &IpeError) -> &str {
        let IpeError::Error(_, info) = e;
        &info.message
    }

    fn slot_of(reg: &StreamRegistry<()>, k: StreamKey) -> Option<&Slot<()>> {
        reg.live.get(&k).map(|e| &e.slot)
    }

    fn is_draining<V>(reg: &StreamRegistry<V>, k: StreamKey) -> bool {
        matches!(reg.live.get(&k).map(|e| &e.slot), Some(Slot::Draining(_)))
    }

    fn is_ended<V>(reg: &StreamRegistry<V>, k: StreamKey) -> bool {
        reg.ended.contains_key(&k)
    }

    fn draining_in<V>(reg: &Mutex<StreamRegistry<V>>, k: StreamKey) -> bool {
        with_registry(reg, |r| is_draining(r, k))
    }

    fn ended_in<V>(reg: &Mutex<StreamRegistry<V>>, k: StreamKey) -> bool {
        with_registry(reg, |r| is_ended(r, k))
    }

    fn free_permits<V>(reg: &Mutex<StreamRegistry<V>>) -> usize {
        with_registry(reg, |r| r.conns.available_permits())
    }

    fn ms(n: u64) -> IdleCeiling {
        IdleCeiling::from_millis(NonZeroU64::new(n).unwrap_or(NonZeroU64::MIN))
    }

    fn into_err<A>(result: IpeResult<IpeError, A>) -> Option<IpeError> {
        match result {
            IpeResult::Err(e) => Some(e),
            IpeResult::Ok(_) => None,
        }
    }

    fn into_ok<A>(result: IpeResult<IpeError, A>) -> Option<A> {
        match result {
            IpeResult::Ok(a) => Some(a),
            IpeResult::Err(_) => None,
        }
    }

    // ─── Fake upstream ──────────────────────────────────────────────────────

    type FakeBody = Pin<Box<dyn Stream<Item = Result<String, String>> + Send>>;

    /// A scripted connection: its body, and the permit it holds.
    struct FakeConn {
        body: FakeBody,
        permit: ConnPermit,
    }

    impl LiveStream for FakeConn {
        type Fault = String;
        type Body = FakeBody;

        fn into_parts(self) -> (FakeBody, ConnPermit) {
            (self.body, self.permit)
        }

        fn fault<E: From<String>>(fault: String) -> E {
            E::from(fault)
        }
    }

    /// One step of a scripted upstream.
    enum Beat {
        /// Wait this many milliseconds, then yield the text.
        Chunk(u64, &'static str),
        /// Never yield again.
        Stall,
    }

    /// The beats in order, then EOF.
    fn scripted(beats: Vec<Beat>) -> FakeBody {
        Box::pin(stream::unfold(
            VecDeque::from(beats),
            |mut beats| async move {
                match beats.pop_front()? {
                    Beat::Chunk(wait, text) => {
                        if wait > 0 {
                            tokio::time::sleep(Duration::from_millis(wait)).await;
                        }
                        Some((Ok::<String, String>(text.to_owned()), beats))
                    }
                    Beat::Stall => std::future::pending().await,
                }
            },
        ))
    }

    /// A chunk every millisecond, forever.
    fn ticking() -> FakeBody {
        Box::pin(stream::unfold((), |()| async {
            tokio::time::sleep(Duration::from_millis(1)).await;
            Some((Ok::<String, String>("x".to_owned()), ()))
        }))
    }

    /// Sets its flag when dropped.
    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// A body that reports its own drop.
    struct Watched {
        inner: FakeBody,
        _signal: DropSignal,
    }

    impl Stream for Watched {
        type Item = Result<String, String>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.inner.as_mut().poll_next(cx)
        }
    }

    fn new_reg<V: Send + 'static>() -> &'static Mutex<StreamRegistry<V>> {
        Box::leak(Box::new(Mutex::new(StreamRegistry::new())))
    }

    /// Parks `body` under a fresh handle; the flag is set when the body drops.
    fn park(
        reg: &'static Mutex<StreamRegistry<FakeConn>>,
        body: FakeBody,
    ) -> (IpeStreamId, Arc<AtomicBool>) {
        let dropped = Arc::new(AtomicBool::new(false));
        let body: FakeBody = Box::pin(Watched {
            inner: body,
            _signal: DropSignal(Arc::clone(&dropped)),
        });
        let sid = with_registry(reg, |r| {
            let permit = r.reserve().unwrap();
            r.open(FakeConn { body, permit }, os_entropy)
        })
        .unwrap();
        (sid, dropped)
    }

    /// Parks an empty stream in a local registry.
    fn park_local(
        reg: &mut StreamRegistry<FakeConn>,
        source: &mut impl FnMut(&mut [u8; 16]) -> Result<(), getrandom::Error>,
    ) -> IpeStreamId {
        let permit = reg.reserve().unwrap();
        let body = scripted(Vec::new());
        reg.open(FakeConn { body, permit }, &mut *source).unwrap()
    }

    fn counting_body(
        calls: &Arc<AtomicUsize>,
    ) -> impl Fn(String) -> IpeTask<IpeError, ()> + Send + 'static {
        let calls = Arc::clone(calls);
        move |_chunk: String| -> IpeTask<IpeError, ()> {
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::ready(IpeResult::Ok(())))
        }
    }

    type Events = Arc<Mutex<Vec<ChunkEvent<IpeError>>>>;

    /// Subscribes to `key` and runs the source on the current runtime.
    fn start_subscription(
        reg: &'static Mutex<StreamRegistry<FakeConn>>,
        key: StreamKey,
        idle: IdleCeiling,
    ) -> Events {
        let events: Events = Arc::default();
        let sink = Arc::clone(&events);
        let sub =
            subscribe_in::<FakeConn, IpeError, ChunkEvent<IpeError>, _>(reg, key, idle, |event| {
                event
            });
        if let IpeSub::Source(spawn) = sub {
            let emit: Arc<dyn Fn(ChunkEvent<IpeError>) + Send + Sync> =
                Arc::new(move |event: ChunkEvent<IpeError>| sink.lock().unwrap().push(event));
            drop(spawn(emit));
        }
        events
    }

    fn labels(events: &Events) -> Vec<String> {
        events
            .lock()
            .unwrap()
            .iter()
            .map(|event| match event {
                ChunkEvent::Chunk(text) => text.clone(),
                ChunkEvent::Done => "<done>".to_owned(),
                ChunkEvent::Errored(_) => "<errored>".to_owned(),
            })
            .collect()
    }

    fn errored_kinds(events: &Events) -> Vec<IpeErrorKind> {
        events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|event| match event {
                ChunkEvent::Errored(e) => Some(kind(e)),
                ChunkEvent::Chunk(_) | ChunkEvent::Done => None,
            })
            .collect()
    }

    // ─── Cancel: a close stops a drain wherever it waits ────────────────────

    #[tokio::test(start_paused = true)]
    async fn close_stops_a_drain_blocked_on_the_upstream() {
        let reg = new_reg::<FakeConn>();
        let calls = Arc::new(AtomicUsize::new(0));
        let (sid, dropped) = park(reg, scripted(vec![Beat::Stall]));
        let drain = tokio::spawn(for_each_chunk_in(
            reg,
            sid.key,
            ms(7_200_000),
            counting_body(&calls),
        ));
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(draining_in(reg, sid.key));
        assert_eq!(free_permits(reg), CLIENT_STREAMS_MAX - 1);
        let started = Instant::now();
        assert!(with_registry(reg, |r| r.close(sid.key)).is_ok());
        let outcome = tokio::time::timeout(Duration::from_secs(3_600), drain).await;
        assert!(matches!(outcome, Ok(Ok(IpeResult::Ok(())))));
        assert!(started.elapsed() < Duration::from_secs(3_600));
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(free_permits(reg), CLIENT_STREAMS_MAX);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn close_during_a_body_step_releases_the_connection_at_once() {
        let reg = new_reg::<FakeConn>();
        let (sid, dropped) = park(reg, scripted(vec![Beat::Chunk(0, "a"), Beat::Stall]));
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let body = {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            move |_chunk: String| -> IpeTask<IpeError, ()> {
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                Box::pin(async move {
                    entered.notify_one();
                    release.notified().await;
                    IpeResult::Ok(())
                })
            }
        };
        let drain = tokio::spawn(for_each_chunk_in(reg, sid.key, ms(7_200_000), body));
        entered.notified().await;
        assert!(with_registry(reg, |r| r.close(sid.key)).is_ok());
        tokio::time::sleep(Duration::from_millis(1)).await;
        // The connection is gone while the body step is still pending.
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(free_permits(reg), CLIENT_STREAMS_MAX);
        assert!(!drain.is_finished());
        release.notify_one();
        assert!(matches!(drain.await, Ok(IpeResult::Ok(()))));
    }

    /// A chunk at once, every time it is asked for, forever.
    fn always_ready() -> FakeBody {
        Box::pin(stream::repeat_with(|| Ok::<String, String>("x".to_owned())))
    }

    /// Where a body closes its own stream.
    #[derive(Clone, Copy)]
    enum CloseAt {
        /// When the body is called, before its step is first polled.
        Call,
        /// Inside the step, as it completes.
        Step,
    }

    /// Drains `upstream` through a body that closes its own stream on every call.
    ///
    /// A second call means a chunk was read after the close; its close is then
    /// refused, so the drain ends `Err`.
    async fn drain_closing_in_the_body(upstream: FakeBody, at: CloseAt) {
        let reg = new_reg::<FakeConn>();
        let (sid, dropped) = park(reg, upstream);
        let key = sid.key;
        let calls = Arc::new(AtomicUsize::new(0));
        let body = {
            let calls = Arc::clone(&calls);
            move |_chunk: String| -> IpeTask<IpeError, ()> {
                calls.fetch_add(1, Ordering::SeqCst);
                let close = move || match with_registry(reg, |r| r.close(key)) {
                    Ok(()) => IpeResult::Ok(()),
                    Err(e) => IpeResult::Err(e),
                };
                match at {
                    CloseAt::Call => Box::pin(std::future::ready(close())),
                    CloseAt::Step => Box::pin(async move { close() }),
                }
            }
        };
        let drained = tokio::time::timeout(
            Duration::from_secs(60),
            for_each_chunk_in(reg, key, ms(7_200_000), body),
        )
        .await;
        assert!(matches!(drained, Ok(IpeResult::Ok(()))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(free_permits(reg), CLIENT_STREAMS_MAX);
    }

    /// Runs of the always-ready scenario: an unbiased wait picks the read with
    /// probability one half each run, so all of them passing by luck is 2^-64.
    const ALWAYS_READY_RUNS: usize = 64;

    #[tokio::test(start_paused = true)]
    async fn close_inside_the_body_reads_no_further_chunk() {
        drain_closing_in_the_body(ticking(), CloseAt::Call).await;
        drain_closing_in_the_body(ticking(), CloseAt::Step).await;
        // With a chunk always ready, only the cancel arm's priority stops the
        // next read: both arms are ready together at every wait.
        for _ in 0..ALWAYS_READY_RUNS {
            drain_closing_in_the_body(always_ready(), CloseAt::Call).await;
            drain_closing_in_the_body(always_ready(), CloseAt::Step).await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_drain_relays_every_chunk_then_ends_the_slot() {
        let reg = new_reg::<FakeConn>();
        let calls = Arc::new(AtomicUsize::new(0));
        let beats = vec![Beat::Chunk(0, "a"), Beat::Chunk(1, "b")];
        let (sid, dropped) = park(reg, scripted(beats));
        let drained = for_each_chunk_in(reg, sid.key, ms(5_000), counting_body(&calls)).await;
        assert!(matches!(drained, IpeResult::Ok(())));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(dropped.load(Ordering::SeqCst));
        assert!(ended_in(reg, sid.key));
        assert_eq!(free_permits(reg), CLIENT_STREAMS_MAX);
    }

    // ─── Idle ceiling ───────────────────────────────────────────────────────

    #[tokio::test(start_paused = true)]
    async fn a_silent_upstream_ends_the_drain_at_the_idle_ceiling() {
        let reg = new_reg::<FakeConn>();
        let calls = Arc::new(AtomicUsize::new(0));
        let (sid, dropped) = park(reg, scripted(vec![Beat::Stall]));
        let started = Instant::now();
        // The outer bound turns a missing idle ceiling into a failure, not a hang.
        let drained = tokio::time::timeout(
            Duration::from_secs(3_600),
            for_each_chunk_in(reg, sid.key, ms(5_000), counting_body(&calls)),
        )
        .await;
        let waited = started.elapsed();
        assert!(drained.is_ok());
        let refused = drained.ok().and_then(into_err);
        assert!(matches!(&refused, Some(e) if kind(e) == IpeErrorKind::Timeout));
        assert!(matches!(&refused, Some(e) if message(e) == STREAM_IDLE_TIMED_OUT));
        assert!(waited >= Duration::from_secs(5));
        assert!(waited < Duration::from_millis(5_050));
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(free_permits(reg), CLIENT_STREAMS_MAX);
        assert!(ended_in(reg, sid.key));
    }

    #[tokio::test(start_paused = true)]
    async fn a_chunk_inside_the_ceiling_is_not_idle() {
        let reg = new_reg::<FakeConn>();
        let calls = Arc::new(AtomicUsize::new(0));
        let (sid, _dropped) = park(reg, scripted(vec![Beat::Chunk(4_000, "a")]));
        let started = Instant::now();
        let drained = for_each_chunk_in(reg, sid.key, ms(5_000), counting_body(&calls)).await;
        assert!(matches!(drained, IpeResult::Ok(())));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn the_ceiling_is_per_read_not_per_drain() {
        let reg = new_reg::<FakeConn>();
        let calls = Arc::new(AtomicUsize::new(0));
        let beats = vec![
            Beat::Chunk(4_000, "a"),
            Beat::Chunk(4_000, "b"),
            Beat::Stall,
        ];
        let (sid, _dropped) = park(reg, scripted(beats));
        let started = Instant::now();
        // The outer bound turns a missing idle ceiling into a failure, not a hang.
        let drained = tokio::time::timeout(
            Duration::from_secs(3_600),
            for_each_chunk_in(reg, sid.key, ms(5_000), counting_body(&calls)),
        )
        .await;
        let waited = started.elapsed();
        assert!(drained.is_ok());
        let refused = drained.ok().and_then(into_err);
        assert!(matches!(&refused, Some(e) if kind(e) == IpeErrorKind::Timeout));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // Two reads of 4 s each stay under the ceiling; the stall then costs one ceiling.
        assert!(waited >= Duration::from_secs(13));
        assert!(waited < Duration::from_millis(13_050));
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_upstream_errors_a_subscription_once() {
        let reg = new_reg::<FakeConn>();
        let (sid, dropped) = park(reg, scripted(vec![Beat::Stall]));
        let events = start_subscription(reg, sid.key, ms(5_000));
        tokio::time::sleep(Duration::from_secs(6)).await;
        assert!(errored_kinds(&events) == [IpeErrorKind::Timeout]);
        assert_eq!(labels(&events).len(), 1);
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(free_permits(reg), CLIENT_STREAMS_MAX);
        // A re-subscribe finds the tombstone and starts nothing.
        let again = start_subscription(reg, sid.key, ms(5_000));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(labels(&again).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_subscription_relays_chunks_then_done() {
        let reg = new_reg::<FakeConn>();
        let beats = vec![Beat::Chunk(0, "a"), Beat::Chunk(0, "b")];
        let (sid, _dropped) = park(reg, scripted(beats));
        let events = start_subscription(reg, sid.key, ms(5_000));
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(labels(&events) == ["a", "b", "<done>"]);
        assert!(ended_in(reg, sid.key));
        assert_eq!(free_permits(reg), CLIENT_STREAMS_MAX);
    }

    #[tokio::test(start_paused = true)]
    async fn close_stops_a_subscription_without_an_event() {
        let reg = new_reg::<FakeConn>();
        let (sid, dropped) = park(reg, scripted(vec![Beat::Stall]));
        let events = start_subscription(reg, sid.key, ms(7_200_000));
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(draining_in(reg, sid.key));
        assert!(with_registry(reg, |r| r.close(sid.key)).is_ok());
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(dropped.load(Ordering::SeqCst));
        assert!(labels(&events).is_empty());
        assert!(ended_in(reg, sid.key));
        assert_eq!(free_permits(reg), CLIENT_STREAMS_MAX);
    }

    // ─── Real sockets: the headers wait and the connection itself ───────────

    fn loopback_request(port: u16) -> HttpRequest {
        HttpRequest {
            body: String::new(),
            headers: Vec::new(),
            method: HttpMethod::Get,
            redirects: RedirectPolicy::NoRedirects,
            timeout: 0,
            url: format!("http://127.0.0.1:{port}/"),
        }
    }

    /// Accepts one connection, writes `reply`, then holds the socket.
    async fn serve_once(reply: &'static [u8]) -> (u16, JoinHandle<TcpStream>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let held = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            if !reply.is_empty() {
                socket.write_all(reply).await.unwrap();
            }
            socket
        });
        (port, held)
    }

    #[tokio::test]
    async fn open_times_out_when_the_headers_never_arrive() {
        let reg = new_reg::<LiveResponse>();
        let (port, _server) = serve_once(b"").await;
        let started = Instant::now();
        let opened = tokio::time::timeout(
            Duration::from_secs(30),
            open_in::<IpeError>(reg, loopback_request(port), DialPolicy::AllowAll, ms(300)),
        )
        .await;
        let waited = started.elapsed();
        let refused = opened.ok().and_then(into_err);
        assert!(matches!(&refused, Some(e) if kind(e) == IpeErrorKind::Timeout));
        assert!(matches!(&refused, Some(e) if message(e) == STREAM_IDLE_TIMED_OUT));
        assert!(waited >= Duration::from_millis(300));
        assert_eq!(free_permits(reg), CLIENT_STREAMS_MAX);
    }

    #[tokio::test]
    async fn open_inside_the_ceiling_parks_a_response_holding_a_permit() {
        let reg = new_reg::<LiveResponse>();
        let reply = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
        let (port, _server) = serve_once(reply).await;
        let opened = tokio::time::timeout(
            Duration::from_secs(30),
            open_in::<IpeError>(
                reg,
                loopback_request(port),
                DialPolicy::AllowAll,
                ms(30_000),
            ),
        )
        .await;
        let sid = opened.ok().and_then(into_ok);
        assert!(sid.is_some());
        assert_eq!(free_permits(reg), CLIENT_STREAMS_MAX - 1);
        let Some(sid) = sid else { return };
        assert!(with_registry(reg, |r| r.close(sid.key)).is_ok());
        assert_eq!(free_permits(reg), CLIENT_STREAMS_MAX);
    }

    #[tokio::test]
    async fn close_shuts_the_socket_of_a_drain_blocked_on_a_silent_peer() {
        let reg = new_reg::<LiveResponse>();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Chunked headers, no chunks; then read until the client closes.
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let head = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n";
            socket.write_all(head).await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        let opened = tokio::time::timeout(
            Duration::from_secs(30),
            open_in::<IpeError>(
                reg,
                loopback_request(port),
                DialPolicy::AllowAll,
                ms(60_000),
            ),
        )
        .await;
        let sid = opened.ok().and_then(into_ok);
        assert!(sid.is_some());
        let Some(sid) = sid else { return };
        let calls = Arc::new(AtomicUsize::new(0));
        let drain = tokio::spawn(for_each_chunk_in(
            reg,
            sid.key,
            ms(60_000),
            counting_body(&calls),
        ));
        for _ in 0..500 {
            if draining_in(reg, sid.key) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(draining_in(reg, sid.key));
        // Let the drain reach its blocked read.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(with_registry(reg, |r| r.close(sid.key)).is_ok());
        let drained = tokio::time::timeout(Duration::from_secs(10), drain).await;
        assert!(matches!(drained, Ok(Ok(IpeResult::Ok(())))));
        let peer = tokio::time::timeout(Duration::from_secs(10), server).await;
        assert!(matches!(peer, Ok(Ok(()))));
        assert_eq!(free_permits(reg), CLIENT_STREAMS_MAX);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    // ─── Permits ────────────────────────────────────────────────────────────

    #[test]
    fn an_ended_stream_keeps_its_permit_while_its_value_lives() {
        let mut reg = StreamRegistry::<FakeConn>::new();
        let mut source = counting_source();
        let mut held = Vec::new();
        for _ in 0..CLIENT_STREAMS_MAX {
            let sid = park_local(&mut reg, &mut source);
            let claimed = reg.take_for_drain(sid.key).unwrap();
            reg.finish_drain(sid.key, claimed.seq);
            held.push(claimed);
        }
        assert_eq!(reg.conns.available_permits(), 0);
        let refused = reg.reserve();
        assert!(matches!(&refused, Err(e) if kind(e) == IpeErrorKind::Unavailable));
        assert!(matches!(&refused, Err(e) if message(e) == TOO_MANY_STREAMS));
        // Happy twin: one connection ending frees exactly one permit.
        drop(held.pop());
        assert!(reg.reserve().is_ok());
    }

    #[test]
    fn a_full_parked_registry_gives_up_its_oldest_for_a_permit() {
        let mut reg = StreamRegistry::<FakeConn>::new();
        let mut source = counting_source();
        for _ in 0..CLIENT_STREAMS_MAX {
            park_local(&mut reg, &mut source);
        }
        assert_eq!(reg.conns.available_permits(), 0);
        let permit = reg.reserve();
        assert!(permit.is_ok());
        let evicted = reg.take_for_drain(key(1));
        assert!(matches!(&evicted, Err(e) if kind(e) == IpeErrorKind::InvalidInput));
        // The next-oldest is still held.
        assert!(reg.take_for_drain(key(2)).is_ok());
    }

    #[test]
    fn a_stale_lease_does_not_end_a_newer_drain() {
        let mut reg = StreamRegistry::<()>::new();
        let sid = reg.open((), counting_source()).unwrap();
        let claimed = reg.take_for_drain(sid.key).unwrap();
        reg.finish_drain(sid.key, claimed.seq + 1);
        assert!(is_draining(&reg, sid.key));
        reg.finish_drain(sid.key, claimed.seq);
        assert!(is_ended(&reg, sid.key));
    }

    #[test]
    fn a_refused_second_claim_leaves_the_first_drain_running() {
        let mut reg = StreamRegistry::<()>::new();
        let sid = reg.open((), counting_source()).unwrap();
        let mut claimed = reg.take_for_drain(sid.key).unwrap();
        let second = reg.take_for_drain(sid.key);
        assert!(matches!(&second, Err(e) if kind(e) == IpeErrorKind::Conflict));
        assert!(is_draining(&reg, sid.key));
        assert!(claimed.cancel.revoked().now_or_never().is_none());
        // Closing is what cancels it.
        assert!(reg.close(sid.key).is_ok());
        assert!(claimed.cancel.revoked().now_or_never().is_some());
    }

    /// Spawns a pump over a stalled stream claimed from `reg`.
    fn start_pump(
        reg: &mut StreamRegistry<FakeConn>,
        idle: IdleCeiling,
    ) -> (StreamKey, JoinHandle<DrainEnd<String, String>>) {
        let permit = reg.reserve().unwrap();
        let body = scripted(vec![Beat::Stall]);
        let sid = reg.open(FakeConn { body, permit }, os_entropy).unwrap();
        let claimed = reg.take_for_drain(sid.key).unwrap();
        let (stream, permit) = claimed.value.into_parts();
        let pump = Pump {
            stream,
            permit,
            cancel: claimed.cancel,
            idle,
        };
        let task = tokio::spawn(pump.run(|_chunk| std::future::ready(Ok::<(), String>(()))));
        (sid.key, task)
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_registry_cancels_a_running_drain() {
        let mut reg = StreamRegistry::<FakeConn>::new();
        let (_key, task) = start_pump(&mut reg, ms(7_200_000));
        tokio::time::sleep(Duration::from_millis(1)).await;
        drop(reg);
        let end = tokio::time::timeout(Duration::from_secs(3_600), task).await;
        assert!(matches!(end, Ok(Ok(DrainEnd::Cancelled))));
    }

    #[tokio::test(start_paused = true)]
    async fn overwriting_a_draining_entry_cancels_its_drain() {
        let mut reg = StreamRegistry::<FakeConn>::new();
        let (key, task) = start_pump(&mut reg, ms(7_200_000));
        tokio::time::sleep(Duration::from_millis(1)).await;
        reg.live.remove(&key);
        let end = tokio::time::timeout(Duration::from_secs(3_600), task).await;
        assert!(matches!(end, Ok(Ok(DrainEnd::Cancelled))));
    }

    // ─── Registry state machine ─────────────────────────────────────────────

    #[test]
    fn for_each_chunk_unknown_key_is_invalid_input() {
        let mut reg = StreamRegistry::<()>::new();
        let refused = reg.take_for_drain(key(7));
        assert!(matches!(&refused, Err(e) if kind(e) == IpeErrorKind::InvalidInput));
        let Err(e) = refused else { return };
        assert_eq!(message(&e), UNKNOWN_STREAM);
        // Happy twin: an opened handle drains.
        let sid = reg.open((), counting_source()).unwrap();
        assert!(reg.take_for_drain(sid.key).is_ok());
    }

    fn assert_unknown(refused: &Result<(), IpeError>) {
        assert!(matches!(refused, Err(e) if kind(e) == IpeErrorKind::InvalidInput));
        assert!(matches!(refused, Err(e) if message(e) == UNKNOWN_STREAM));
    }

    #[test]
    fn close_unknown_key_refused() {
        let mut reg = StreamRegistry::<()>::new();
        let sid = reg.open((), counting_source()).unwrap();
        // A forged handle the registry never held.
        assert_unknown(&reg.close(key(99)));
        assert_eq!(reg.live.len(), 1);
        assert!(slot_of(&reg, key(99)).is_none());
        assert!(matches!(slot_of(&reg, sid.key), Some(Slot::Parked(()))));
        // Happy twin: closing the held handle removes it.
        assert!(reg.close(sid.key).is_ok());
        assert!(reg.live.is_empty());
    }

    #[test]
    fn close_twice_second_refused() {
        let mut reg = StreamRegistry::<()>::new();
        let parked = reg.open((), counting_source()).unwrap();
        assert!(reg.close(parked.key).is_ok());
        assert_unknown(&reg.close(parked.key));
        // A draining stream: the first close ends it, the second is refused
        // and leaves the tombstone in place.
        let mut reg = StreamRegistry::<()>::new();
        let draining = reg.open((), counting_source()).unwrap();
        assert!(reg.take_for_drain(draining.key).is_ok());
        assert!(reg.close(draining.key).is_ok());
        assert_unknown(&reg.close(draining.key));
        assert!(is_ended(&reg, draining.key));
    }

    #[test]
    fn close_after_drain_end_refused() {
        let mut reg = StreamRegistry::<()>::new();
        let sid = reg.open((), counting_source()).unwrap();
        let claimed = reg.take_for_drain(sid.key).unwrap();
        reg.finish_drain(sid.key, claimed.seq);
        assert_unknown(&reg.close(sid.key));
        assert!(is_ended(&reg, sid.key));
    }

    #[test]
    fn for_each_chunk_twice_second_is_conflict() {
        let mut reg = StreamRegistry::<()>::new();
        let sid = reg.open((), counting_source()).unwrap();
        assert!(reg.take_for_drain(sid.key).is_ok());
        let second = reg.take_for_drain(sid.key);
        assert!(matches!(&second, Err(e) if kind(e) == IpeErrorKind::Conflict));
        assert!(is_draining(&reg, sid.key));
    }

    #[test]
    fn for_each_chunk_after_end_is_invalid_input() {
        let mut reg = StreamRegistry::<()>::new();
        let sid = reg.open((), counting_source()).unwrap();
        let claimed = reg.take_for_drain(sid.key).unwrap();
        reg.finish_drain(sid.key, claimed.seq);
        let again = reg.take_for_drain(sid.key);
        assert!(matches!(&again, Err(e) if kind(e) == IpeErrorKind::InvalidInput));
        assert!(is_ended(&reg, sid.key));
    }

    #[test]
    fn close_during_drain_ends_the_drain() {
        let mut reg = StreamRegistry::<()>::new();
        let sid = reg.open((), counting_source()).unwrap();
        let claimed = reg.take_for_drain(sid.key).unwrap();
        assert!(is_draining(&reg, sid.key));
        assert!(reg.close(sid.key).is_ok());
        assert!(!is_draining(&reg, sid.key));
        assert!(is_ended(&reg, sid.key));
        // The drain's own lease then ends nothing further.
        reg.finish_drain(sid.key, claimed.seq);
        assert!(is_ended(&reg, sid.key));
    }

    #[test]
    fn chunks_unknown_key_emits_one_errored_then_dedups() {
        let mut reg = StreamRegistry::<()>::new();
        assert!(matches!(reg.subscribe(key(5)), Subscription::Refused));
        assert!(matches!(reg.subscribe(key(5)), Subscription::Active));
        assert!(matches!(reg.subscribe(key(5)), Subscription::Active));
        // Happy twin: a parked stream drains once, then dedups.
        let sid = reg.open((), counting_source()).unwrap();
        assert!(matches!(reg.subscribe(sid.key), Subscription::Drain(_)));
        assert!(matches!(reg.subscribe(sid.key), Subscription::Active));
    }

    fn assert_refused(json: &str, input: &str) {
        let decoded = serde_json::from_str::<IpeStreamId>(json);
        assert!(decoded.is_err(), "{json} must not decode");
        let text = decoded.err().map(|e| e.to_string()).unwrap_or_default();
        // serde_json appends only " at line L column C" to the custom text.
        let head = text.split(" at line ").next().unwrap_or_default();
        assert_eq!(head, INVALID_ID, "{text}");
        assert!(!head.contains(input), "{text} echoes {input}");
    }

    #[test]
    fn deserialize_refuses_integer() {
        assert_refused("5", "5");
        assert_refused("-12345", "12345");
        assert_refused("1.5e3", "1.5");
    }

    #[test]
    fn deserialize_refuses_wrong_length() {
        let short = "1".repeat(31);
        let long = "1".repeat(33);
        assert_refused(&format!("\"{short}\""), &short);
        assert_refused(&format!("\"{long}\""), &long);
        assert_refused("\"\"", "\"");
    }

    #[test]
    fn deserialize_refuses_uppercase_hex() {
        let upper = "ABCDEF0123456789ABCDEF0123456789";
        assert_refused(&format!("\"{upper}\""), upper);
    }

    #[test]
    fn deserialize_refuses_non_hex() {
        let bad = "0123456789abcdef0123456789abcdeg";
        assert_refused(&format!("\"{bad}\""), bad);
        let spaced = " 123456789abcdef0123456789abcdef";
        assert_refused(&format!("\"{spaced}\""), spaced);
    }

    #[test]
    fn deserialize_refuses_all_zero() {
        let zero = "0".repeat(32);
        assert_refused(&format!("\"{zero}\""), &zero);
    }

    #[test]
    fn deserialize_refuses_non_string_shapes() {
        assert_refused("null", "null");
        assert_refused("true", "true");
        assert_refused("[1]", "[1]");
        assert_refused("{\"key\":1}", "key");
    }

    #[test]
    fn serde_round_trip_exact_32_lower_hex() {
        let mut reg = StreamRegistry::<()>::new();
        let mut top = u128::MAX.to_le_bytes();
        top[15] = 0xab;
        let sid = reg
            .open((), |buf: &mut [u8; 16]| {
                *buf = top;
                Ok(())
            })
            .unwrap();
        let wire = serde_json::to_string(&sid).unwrap();
        assert_eq!(wire, "\"abffffffffffffffffffffffffffffff\"");
        let back: IpeStreamId = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, sid);
        let one: IpeStreamId =
            serde_json::from_str("\"00000000000000000000000000000001\"").unwrap();
        assert!(one.key == key(1));
    }

    #[test]
    fn debug_does_not_render_key() {
        let mut reg = StreamRegistry::<()>::new();
        let sid = reg
            .open((), |buf: &mut [u8; 16]| {
                *buf = [0xcd; 16];
                Ok(())
            })
            .unwrap();
        let shown = format!("{sid:?}");
        assert_eq!(shown, "StreamId(<opaque>)");
        assert!(!shown.contains("cdcd"));
        assert!(!format!("{:?}", Some(sid)).contains("cdcd"));
    }

    #[test]
    fn mint_redraws_zero_and_live_collision() {
        let draws = [0u128, 3, 9];
        let mut i = 0;
        let source = |buf: &mut [u8; 16]| {
            *buf = draws.get(i).copied().unwrap_or(0).to_le_bytes();
            i += 1;
            Ok(())
        };
        let minted = mint_with(source, |k| k == key(3));
        assert!(matches!(minted, Ok(k) if k == key(9)));
    }

    #[test]
    fn mint_exhausts_after_4_to_unavailable() {
        let mut draws = 0;
        let zeros = |buf: &mut [u8; 16]| {
            draws += 1;
            *buf = [0; 16];
            Ok(())
        };
        let minted = mint_with(zeros, |_| false);
        assert!(matches!(&minted, Err(e) if kind(e) == IpeErrorKind::Unavailable));
        assert_eq!(draws, MINT_ATTEMPTS);
        let Err(e) = minted else { return };
        assert_eq!(message(&e), MINT_EXHAUSTED);
        // A source that only ever collides exhausts the same way.
        let always_live = mint_with(counting_source(), |_| true);
        assert!(matches!(&always_live, Err(e) if kind(e) == IpeErrorKind::Unavailable));
    }

    #[test]
    fn mint_entropy_failure_is_unavailable() {
        let broken = |_: &mut [u8; 16]| Err(getrandom::Error::UNSUPPORTED);
        let minted = mint_with(broken, |_| false);
        assert!(matches!(&minted, Err(e) if kind(e) == IpeErrorKind::Unavailable));
        let Err(e) = minted else { return };
        assert_eq!(message(&e), ENTROPY_UNAVAILABLE);
    }

    /// Fills `reg` to the cap with parked streams keyed `1..=CLIENT_STREAMS_MAX`.
    fn fill(
        reg: &mut StreamRegistry<()>,
        source: &mut impl FnMut(&mut [u8; 16]) -> Result<(), getrandom::Error>,
    ) {
        for _ in 0..CLIENT_STREAMS_MAX {
            assert!(reg.open((), &mut *source).is_ok());
        }
    }

    #[test]
    fn open_at_the_live_cap_is_unavailable() {
        let mut reg = StreamRegistry::<()>::new();
        let mut source = counting_source();
        fill(&mut reg, &mut source);
        let refused = reg.open((), &mut source);
        assert!(matches!(&refused, Err(e) if kind(e) == IpeErrorKind::Unavailable));
        let Err(e) = refused else { return };
        assert_eq!(message(&e), TOO_MANY_STREAMS);
        assert_eq!(reg.live.len(), CLIENT_STREAMS_MAX);
        // Happy twin: one close frees a slot.
        assert!(reg.close(key(1)).is_ok());
        assert!(reg.open((), &mut source).is_ok());
    }

    // Tombstones live in a table of their own, bounded and oldest-first.
    #[test]
    fn the_tombstone_table_is_bounded_and_forgets_its_oldest() {
        let mut reg = StreamRegistry::<()>::new();
        let mut source = counting_source();
        let parked = reg.open((), &mut source).unwrap();
        let first = 10_000;
        for n in 1..=CLIENT_STREAMS_MAX {
            let n = u128::try_from(n).unwrap();
            assert!(matches!(
                reg.subscribe(key(first + n)),
                Subscription::Refused
            ));
        }
        assert_eq!(reg.ended.len(), TOMBSTONES_MAX);
        assert!(is_ended(&reg, key(first + 1)));
        // One more refusal forgets the oldest tombstone and keeps the rest.
        let over = first + u128::try_from(CLIENT_STREAMS_MAX).unwrap() + 1;
        assert!(matches!(reg.subscribe(key(over)), Subscription::Refused));
        assert_eq!(reg.ended.len(), TOMBSTONES_MAX);
        assert!(!is_ended(&reg, key(first + 1)));
        assert!(is_ended(&reg, key(first + 2)));
        assert!(is_ended(&reg, key(over)));
        // Tombstone churn never touches a live entry.
        assert_eq!(reg.live.len(), 1);
        assert!(matches!(slot_of(&reg, parked.key), Some(Slot::Parked(()))));
        // A forgotten handle is unknown again: close refuses it, subscribe re-records it.
        assert_unknown(&reg.close(key(first + 1)));
        assert!(matches!(
            reg.subscribe(key(first + 1)),
            Subscription::Refused
        ));
        // Happy twin: a remembered handle stays quiet.
        assert!(matches!(reg.subscribe(key(over)), Subscription::Active));
    }

    #[test]
    fn a_full_tombstone_table_forgets_the_stream_that_ended_first() {
        let mut reg = StreamRegistry::<()>::new();
        let mut source = counting_source();
        // Opened before every other handle, ended after all of them.
        let long_lived = reg.open((), &mut source).unwrap();
        let claimed = reg.take_for_drain(long_lived.key).unwrap();
        let first = 10_000;
        for n in 1..=TOMBSTONES_MAX {
            let n = u128::try_from(n).unwrap();
            assert!(matches!(
                reg.subscribe(key(first + n)),
                Subscription::Refused
            ));
        }
        reg.finish_drain(long_lived.key, claimed.seq);
        assert!(is_ended(&reg, long_lived.key));
        assert!(!is_ended(&reg, key(first + 1)));
        // One more tombstone forgets the next to end, never the newest end.
        let over = first + u128::try_from(TOMBSTONES_MAX).unwrap() + 1;
        assert!(matches!(reg.subscribe(key(over)), Subscription::Refused));
        assert_eq!(reg.ended.len(), TOMBSTONES_MAX);
        assert!(!is_ended(&reg, key(first + 2)));
        assert!(is_ended(&reg, long_lived.key));
        // A re-subscribe after its `Done` stays quiet: no stray `Errored`.
        assert!(matches!(
            reg.subscribe(long_lived.key),
            Subscription::Active
        ));
    }

    #[test]
    fn a_spent_end_clock_records_nothing_and_starts_nothing() {
        let mut reg = StreamRegistry::<()>::new();
        let mut source = counting_source();
        let sid = reg.open((), &mut source).unwrap();
        assert!(reg.take_for_drain(sid.key).is_ok());
        // The clock's last stamp is `u64::MAX - 1`; past it, none is handed out.
        reg.end_clock = EndClock { next: u64::MAX - 1 };
        assert!(matches!(reg.subscribe(key(77)), Subscription::Refused));
        assert!(is_ended(&reg, key(77)));
        // Spent: an unknown handle is neither recorded nor refused.
        assert!(matches!(reg.subscribe(key(78)), Subscription::Active));
        assert!(!is_ended(&reg, key(78)));
        assert!(matches!(reg.subscribe(key(78)), Subscription::Active));
        // A close still ends the drain; its handle is unknown, never live.
        assert!(reg.close(sid.key).is_ok());
        assert!(!is_draining(&reg, sid.key));
        assert!(!is_ended(&reg, sid.key));
        assert_unknown(&reg.close(sid.key));
        assert!(matches!(reg.subscribe(sid.key), Subscription::Active));
        assert_eq!(reg.ended.len(), 1);
    }

    #[test]
    fn evicted_parked_key_then_refused() {
        let mut reg = StreamRegistry::<FakeConn>::new();
        let mut source = counting_source();
        for _ in 0..CLIENT_STREAMS_MAX {
            park_local(&mut reg, &mut source);
        }
        // A new request evicts the oldest parked stream for its permit.
        let permit = reg.reserve().unwrap();
        assert_eq!(reg.live.len(), CLIENT_STREAMS_MAX - 1);
        let body = scripted(Vec::new());
        assert!(reg.open(FakeConn { body, permit }, &mut source).is_ok());
        assert_eq!(reg.live.len(), CLIENT_STREAMS_MAX);
        let evicted = reg.take_for_drain(key(1));
        assert!(matches!(&evicted, Err(e) if kind(e) == IpeErrorKind::InvalidInput));
        // The next-oldest is still held.
        assert!(reg.take_for_drain(key(2)).is_ok());
    }

    #[test]
    fn close_evicted_key_refused() {
        let mut reg = StreamRegistry::<FakeConn>::new();
        let mut source = counting_source();
        for _ in 0..CLIENT_STREAMS_MAX {
            park_local(&mut reg, &mut source);
        }
        assert!(reg.reserve().is_ok());
        assert_unknown(&reg.close(key(1)));
        assert!(reg.close(key(2)).is_ok());
    }

    // A registry full of draining streams still dedups an unknown subscribe.
    #[test]
    fn all_draining_registry_still_refuses_and_dedups_an_unknown_subscribe() {
        let mut reg = StreamRegistry::<FakeConn>::new();
        let mut source = counting_source();
        let mut held = Vec::new();
        for _ in 0..CLIENT_STREAMS_MAX {
            let sid = park_local(&mut reg, &mut source);
            held.push(reg.take_for_drain(sid.key).unwrap());
        }
        let refused = reg.reserve();
        assert!(matches!(&refused, Err(e) if kind(e) == IpeErrorKind::Unavailable));
        assert!(matches!(&refused, Err(e) if message(e) == TOO_MANY_STREAMS));
        assert_eq!(reg.live.len(), CLIENT_STREAMS_MAX);
        // The unknown handle is refused once, then deduplicated.
        let unknown = key(u128::MAX);
        assert!(matches!(reg.subscribe(unknown), Subscription::Refused));
        assert!(matches!(reg.subscribe(unknown), Subscription::Active));
        assert!(is_ended(&reg, unknown));
        // No live drain was disturbed.
        assert_eq!(reg.live.len(), CLIENT_STREAMS_MAX);
        assert!(is_draining(&reg, key(1)));
        // Happy twin: one drain ending frees its permit for a new request.
        drop(held.pop());
        assert!(reg.reserve().is_ok());
    }

    #[cfg(feature = "web-core")]
    #[derive(serde::Deserialize)]
    struct StreamForm {
        sid: IpeStreamId,
    }

    #[cfg(feature = "web-core")]
    fn form(value: &str) -> crate::html::FormData {
        [("sid".to_owned(), value.to_owned())].into_iter().collect()
    }

    #[cfg(feature = "web-core")]
    #[test]
    fn decode_form_refuses_integer_stream_id() {
        let decoded = crate::dom::form::decode_form::<StreamForm>(form("5"));
        assert!(matches!(
            &decoded,
            Err(crate::dom::form::FormDecodeError::Decode(_))
        ));
        let Err(e) = decoded else { return };
        assert!(e.to_string().ends_with(INVALID_ID), "{e}");
        // Happy twin: the exact wire form decodes to the same handle.
        let wire = "000000000000000000000000000000ff";
        let decoded = crate::dom::form::decode_form::<StreamForm>(form(wire));
        assert!(matches!(&decoded, Ok(f) if f.sid.key == key(0xff)));
    }
}

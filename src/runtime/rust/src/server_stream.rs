//! Ipe.Http.Server.Stream — server-side streaming HTTP responses (chunked / SSE).
//!
//! Mirror of `http_stream.rs`. Where `http_stream.rs` reads an upstream body
//! chunk-by-chunk, this writes a response body chunk-by-chunk to the client
//! over a long-lived connection.
//!
//! Integration with the axum server (server.rs):
//!
//!   1. `stream ct handler` registers the (E-erased) handler in the
//!      [`RequestStreams`] table of the `Server` request it runs in, under a
//!      fresh ticket, and returns a normal `ServerResponse` whose body is the
//!      sentinel `__ipe_stream:<ticket>`. This survives the `ServerResponse`
//!      bridge (which has no handler field).
//!
//!   2. `to_axum_response` (server.rs) hands the response body and that same
//!      request's table to `claim_streaming_sentinel`. A ticket resolves only
//!      in the table of the request that minted it, so a sentinel copied into
//!      another request's body names nothing there. On a hit it takes the
//!      handler, builds the response head through the one assembler every
//!      response goes through (`ServerResponseHead`), and only then
//!      `ServerPendingStream::serve`s: open a bounded mpsc channel, register
//!      the sender under a stream id, spawn the handler driving a
//!      `StreamWriter(id)`, and return the response whose body streams the
//!      channel (`Body::from_stream`). The head is committed when this
//!      response is returned, before the first chunk, as SSE requires. A
//!      refused head answers 500 and the handler never runs.
//!
//!   3. `emit chunk writer` resolves the id → sender and `send(chunk).await`s
//!      (bounded → backpressure). `finish writer` drops the sender (ends the
//!      stream). `withContentType` is a no-op once the head is committed (which
//!      it always is by the time the handler runs — set the type via `stream`).
//!
//! `StreamWriter` is bridged (runtimeOpaqueTypes) so the runtime can construct
//! it and the stdlib's `case writer of StreamWriter raw` lowers onto it.
//!
//! The table lives and dies with its request: a handler the response never
//! claims (a middleware replaced the stream response) drops with it.

use super::*;
use std::collections::HashMap;
use std::future::Future;
use std::num::NonZeroU128;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

/// Ipe.Http.Server.Stream.StreamWriter — opaque writer handle. The variant name
/// matches the Ipê constructor so `case w of StreamWriter raw` lowers onto it.
#[derive(Clone, Copy, Debug)]
pub enum StreamWriter {
    StreamWriter(i64),
}

crate::stringify::show_row!("StreamWriter", Internals, [] StreamWriter, |_| "<Ipe.Http.Server.StreamWriter>".to_owned());

/// Handler with its Ipê error type E erased: the effect IS the emits, the
/// IpeResult is discarded (await`).
type ErasedStreamHandler =
    Arc<dyn Fn(StreamWriter) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// A `stream()`-registered handler waiting for its request to claim it.
struct PendingHandler {
    handler: ErasedStreamHandler,
    /// The credentials of the request that called `stream()`, which the
    /// served body inherits.
    credentials: crate::server::ChannelCredentials,
}

fn stream_senders() -> &'static Mutex<HashMap<i64, tokio::sync::mpsc::Sender<String>>> {
    static R: OnceLock<Mutex<HashMap<i64, tokio::sync::mpsc::Sender<String>>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_STREAM_ID: AtomicI64 = AtomicI64::new(1);

const SENTINEL_PREFIX: &str = "__ipe_stream:";

/// Hex digits in the wire form of a ticket (128 bits, 4 per digit).
const TICKET_HEX_LEN: usize = 32;

/// Draws a mint makes before giving up on a zero or colliding ticket.
const MINT_ATTEMPTS: usize = 4;

/// Streams one request may hold pending at once.
const MAX_PENDING_STREAMS: usize = 4;

const OUTSIDE_REQUEST: &str = "Server.Stream.stream: called outside a Server request";
const AFTER_RESPONSE: &str = "Server.Stream.stream: called after its response was sent";
const MINT_EXHAUSTED: &str = "Server.Stream.stream: ticket mint exhausted";
const ENTROPY_UNAVAILABLE: &str = "Server.Stream.stream: entropy unavailable";
const CLIENT_DISCONNECTED: &str = "server.stream emit: client disconnected";

/// The refusal of a request registering one stream past the ceiling.
fn too_many_streams() -> String {
    format!("Server.Stream.stream: a request holds at most {MAX_PENDING_STREAMS} pending streams")
}

// Bounded channel — matches the streamChanBuffer (16). emit's
// `send().await` blocks when full → backpressure to the producer/relay.
const STREAM_CHAN_BUFFER: usize = 16;

/// The name a stream response body gives its pending handler.
///
/// Drawn from the OS CSPRNG and meaningful only in the table of the request
/// that minted it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct StreamTicket(NonZeroU128);

impl StreamTicket {
    /// Parses the exact wire form: 32 lowercase hex digits, value nonzero.
    fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != TICKET_HEX_LEN {
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

    /// The response body that names this ticket.
    fn sentinel(self) -> String {
        format!("{SENTINEL_PREFIX}{:032x}", self.0.get())
    }
}

impl std::fmt::Debug for StreamTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamTicket(<opaque>)")
    }
}

/// Mints a fresh ticket from `source`, redrawing a zero or a `live` collision.
///
/// At most `MINT_ATTEMPTS` draws; then `Unavailable`. A failing source is
/// `Unavailable` at once.
fn mint_with<S, L>(mut source: S, live: L) -> Result<StreamTicket, IpeError>
where
    S: FnMut(&mut [u8; 16]) -> Result<(), getrandom::Error>,
    L: Fn(StreamTicket) -> bool,
{
    for _ in 0..MINT_ATTEMPTS {
        let mut buf = [0u8; 16];
        source(&mut buf).map_err(|_| IpeError::unavailable(ENTROPY_UNAVAILABLE.to_owned()))?;
        if let Some(raw) = NonZeroU128::new(u128::from_le_bytes(buf)) {
            let ticket = StreamTicket(raw);
            if !live(ticket) {
                return Ok(ticket);
            }
        }
    }
    Err(IpeError::unavailable(MINT_EXHAUSTED.to_owned()))
}

/// The OS CSPRNG, the production ticket source.
fn os_entropy(buf: &mut [u8; 16]) -> Result<(), getrandom::Error> {
    getrandom::getrandom(buf)
}

/// A request's stream table: open while its handler runs, served once its
/// response is claimed.
enum TableState {
    Open(HashMap<StreamTicket, PendingHandler>),
    Served,
}

/// The table one request and the tasks spawned on its behalf share.
type SharedTable = Arc<Mutex<TableState>>;

tokio::task_local! {
    /// The stream table of the `Server` request the current task handles.
    static REQUEST_STREAMS: SharedTable;
}

/// The stream handlers one `Server` request registered.
///
/// Created by the one request dispatch and consumed by the one claim of its
/// response, so a request claims at most once.
#[must_use]
pub struct RequestStreams(SharedTable);

impl RequestStreams {
    /// An open, empty table.
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(TableState::Open(HashMap::new()))))
    }

    /// Mark the table served and take the handlers it held.
    ///
    /// A `stream` call after this is refused.
    fn into_pending(self) -> HashMap<StreamTicket, PendingHandler> {
        let state = std::mem::replace(
            &mut *self.0.lock().unwrap_or_else(PoisonError::into_inner),
            TableState::Served,
        );
        match state {
            TableState::Open(pending) => pending,
            TableState::Served => HashMap::new(),
        }
    }
}

impl Drop for RequestStreams {
    /// A request that ends without claiming its response (an upgraded
    /// socket, a failed handler, a dropped connection) serves its table too:
    /// a sub-task still carrying it registers nothing, and every handler it
    /// held drops here.
    fn drop(&mut self) {
        let unclaimed = std::mem::replace(
            &mut *self.0.lock().unwrap_or_else(PoisonError::into_inner),
            TableState::Served,
        );
        drop(unclaimed);
    }
}

/// Run `request` with a fresh stream table in scope.
///
/// Returns the request's output beside the table it registered into.
pub(crate) async fn in_stream_scope<F: Future>(request: F) -> (F::Output, RequestStreams) {
    let streams = RequestStreams::new();
    let output = REQUEST_STREAMS.scope(Arc::clone(&streams.0), request).await;
    (output, streams)
}

/// `task`, run inside the stream table of the `Server` request its caller
/// handles, so a stream it registers belongs to that request.
///
/// The table is read when this is called, on the caller's task.
pub(crate) fn inherit_stream_scope<F: Future>(task: F) -> impl Future<Output = F::Output> {
    let table = REQUEST_STREAMS.try_with(Arc::clone).ok();
    async move {
        match table {
            Some(table) => REQUEST_STREAMS.scope(table, task).await,
            None => task.await,
        }
    }
}

/// Register `handler` in the current request's table under a fresh ticket.
///
/// Refused outside a request, after the request's response was claimed, and
/// past `MAX_PENDING_STREAMS`.
fn register(handler: ErasedStreamHandler) -> Result<StreamTicket, IpeError> {
    let table = REQUEST_STREAMS
        .try_with(Arc::clone)
        .map_err(|_| IpeError::invalid_input(OUTSIDE_REQUEST.to_owned()))?;
    let credentials = crate::server::ChannelCredentials::of_request();
    let mut state = table.lock().unwrap_or_else(PoisonError::into_inner);
    let TableState::Open(pending) = &mut *state else {
        return Err(IpeError::invalid_input(AFTER_RESPONSE.to_owned()));
    };
    if pending.len() >= MAX_PENDING_STREAMS {
        return Err(IpeError::invalid_input(too_many_streams()));
    }
    let ticket = mint_with(os_entropy, |t| pending.contains_key(&t))?;
    pending.insert(
        ticket,
        PendingHandler {
            handler,
            credentials,
        },
    );
    drop(state);
    Ok(ticket)
}

/// Ipe.Http.Server.Stream.stream
///   : String -> (StreamWriter -> Task Error ()) -> Task Error Response
///
/// The Ipê codegen (Rust backend) lowers the handler argument as `StreamWriter`
/// because the HM type scheme uses the `StreamWriter` opaque type for
/// `Stream.emit` / `Stream.finish` / `Stream.withContentType`.  The user
/// closure receives a `StreamWriter` and passes it directly to those kernels.
///
/// The handler belongs to the `Server` request the task runs in. Outside one,
/// after that request's response was sent, or past `MAX_PENDING_STREAMS`
/// pending streams, the task fails `InvalidInput`; a ticket the OS CSPRNG
/// cannot mint fails `Unavailable`.
pub fn server_stream_stream<E, H>(content_type: String, handler: H) -> IpeTask<E, ServerResponse>
where
    E: crate::FromIpeError + Send + 'static,
    H: Fn(StreamWriter) -> IpeTask<E, ()> + Send + Sync + 'static,
{
    // Erase E: the table can't name the project's error type. The handler's
    // returned task is driven to completion; its result is dropped.
    let erased: ErasedStreamHandler = Arc::new(move |w: StreamWriter| {
        let task = handler(w);
        Box::pin(async move {
            let _ = task.await;
        }) as Pin<Box<dyn Future<Output = ()> + Send>>
    });
    let ct = if content_type.is_empty() {
        "application/octet-stream".to_string()
    } else {
        content_type
    };
    Box::pin(async move {
        // Registered when the task runs, inside the request it answers, so the
        // handler is captured with that request's table and credentials.
        match register(erased) {
            Ok(ticket) => IpeResult::Ok(ServerResponse {
                status: 200,
                body: ticket.sentinel(),
                headers: HashMap::new(),
                contentType: ct,
                cookies: Vec::new(),
            }),
            Err(refusal) => IpeResult::Err(E::from_ipe_error(refusal)),
        }
    })
}

/// Ipe.Http.Server.Stream.emit : String -> StreamWriter -> Task Error ()
/// Sends the chunk + flushes (the channel feeds an unbuffered axum body).
/// emit-after-finish is a no-op.
pub fn server_stream_emit<E: From<String> + crate::FromUnavailable + Send + 'static>(
    chunk: String,
    writer: StreamWriter,
) -> IpeTask<E, ()> {
    let StreamWriter::StreamWriter(id) = writer;
    Box::pin(async move {
        let sender = stream_senders()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .cloned();
        match sender {
            Some(tx) => match tx.send(chunk).await {
                Ok(()) => IpeResult::Ok(()),
                // Receiver dropped — client disconnected. Surface as an error so
                // a relay's forEachChunk fail-fast stops pulling the upstream.
                Err(_) => IpeResult::Err(E::from_unavailable(CLIENT_DISCONNECTED.to_owned())),
            },
            None => IpeResult::Ok(()),
        }
    })
}

/// Ipe.Http.Server.Stream.finish : StreamWriter -> Task Error ()
/// Idempotent — drops the sender (ends the body stream). Implicit at handler
/// return; explicit when the handler wants to release the connection early.
pub fn server_stream_finish<E: From<String> + Send + 'static>(
    writer: StreamWriter,
) -> IpeTask<E, ()> {
    let StreamWriter::StreamWriter(id) = writer;
    Box::pin(async move {
        stream_senders()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        IpeResult::Ok(())
    })
}

/// Ipe.Http.Server.Stream.withContentType : String -> StreamWriter -> Task Error ()
/// Best-effort: the head is already committed by the time the handler runs in
/// this model (axum sends headers when the streaming Response is returned), so
/// this is a no-op. Set the Content-Type via the `stream` argument instead.
pub fn server_stream_with_content_type<E: From<String> + Send + 'static>(
    _ct: String,
    _writer: StreamWriter,
) -> IpeTask<E, ()> {
    Box::pin(async move { IpeResult::Ok(()) })
}

/// What a response body is to its request's stream table.
pub enum ServerStreamClaim {
    /// Names no stream: the body is served as it is.
    Buffered,
    /// The exact sentinel of a ticket the request held, whose handler this
    /// claim now holds.
    Stream(ServerPendingStream),
    /// Sentinel text the request cannot serve: a ticket it does not hold, or
    /// a held ticket's sentinel wrapped in other text. It has no body to send.
    Refused,
}

/// A claimed stream handler, run only by [`ServerPendingStream::serve`].
pub struct ServerPendingStream {
    handler: ErasedStreamHandler,
    credentials: crate::server::ChannelCredentials,
}

/// Claim the stream handler `body` names from the table of the request that
/// answers with it.
///
/// The claim marks the table served first, so every handler it does not claim
/// drops here. A body that starts with the sentinel prefix is
/// [`ServerStreamClaim::Stream`] only when the rest is exactly a ticket this
/// table held; any other prefixed body (malformed, foreign, already served) is
/// [`ServerStreamClaim::Refused`]. A body without the prefix that still
/// contains a held ticket's sentinel is [`ServerStreamClaim::Refused`] too, so
/// a live ticket never reaches the client.
#[must_use]
pub fn claim_streaming_sentinel(body: &str, streams: RequestStreams) -> ServerStreamClaim {
    let mut pending = streams.into_pending();
    if let Some(ticket_text) = body.strip_prefix(SENTINEL_PREFIX) {
        return StreamTicket::parse(ticket_text)
            .and_then(|ticket| pending.remove(&ticket))
            .map_or(ServerStreamClaim::Refused, |claimed| {
                ServerStreamClaim::Stream(ServerPendingStream {
                    handler: claimed.handler,
                    credentials: claimed.credentials,
                })
            });
    }
    if pending
        .keys()
        .any(|ticket| body.contains(&ticket.sentinel()))
    {
        ServerStreamClaim::Refused
    } else {
        ServerStreamClaim::Buffered
    }
}

impl ServerPendingStream {
    /// Serve the stream under `head`, which the shared response assembler built.
    ///
    /// Opens the bounded channel, registers its sender under a fresh stream id,
    /// spawns the handler driving a `StreamWriter(id)`, and returns the response
    /// whose body streams the channel. The head is committed when the response
    /// is returned, before the first chunk, as SSE requires.
    ///
    /// A body opened under the credentials the request bound ends on a
    /// coalesced revocation and at the earliest deadline; the receiver drops,
    /// so the handler's next `emit` reports the client gone. A gate that
    /// cannot prove those credentials now answers 401 and never runs the
    /// handler (fail closed).
    #[must_use]
    pub fn serve(self, head: ServerResponseHead) -> axum::response::Response {
        use axum::response::IntoResponse;
        let Self {
            handler,
            credentials,
        } = self;
        let Some(gate) = crate::server::ChannelGate::open(&credentials).ok() else {
            return axum::http::StatusCode::UNAUTHORIZED.into_response();
        };
        let (tx, rx) = tokio::sync::mpsc::channel::<String>(STREAM_CHAN_BUFFER);
        let id = loop {
            let n = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
            if n != 0 {
                break n;
            }
        };
        stream_senders()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, tx);

        // Drive the handler in its own task, inside the request's binding set
        // so a token it verifies binds to this stream; on completion drop the
        // sender so the body stream terminates even if the handler forgot to
        // call `finish`. The task runs outside the request's stream table, so
        // a `stream` call inside the handler is refused.
        tokio::spawn(async move {
            credentials
                .scoped(|| handler(StreamWriter::StreamWriter(id)))
                .await;
            stream_senders()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&id);
        });

        // Receiver to byte stream: unfold yields each chunk; `None` ends the
        // body once every sender has dropped (finish / handler exit), or once
        // the gate denies, which drops the receiver. A chunk is written only
        // after the gate settles, so a credential the handler bound, or a
        // revocation already due, is proved before the chunk leaves.
        let body_stream =
            futures_util::stream::unfold((rx, gate), |(mut rx, mut gate)| async move {
                tokio::select! {
                    biased;
                    () = crate::server::channel_denial(&mut gate) => None,
                    chunk = rx.recv() => match chunk {
                        Some(chunk) if !crate::server::channel_unsettled(&mut gate) => {
                            Some((Ok::<String, std::io::Error>(chunk), (rx, gate)))
                        }
                        Some(_) | None => None,
                    },
                }
            });
        head.into_response(axum::body::Body::from_stream(body_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kind and message of a refused task, or `None` when it succeeded.
    fn refusal<A>(result: IpeResult<IpeError, A>) -> Option<(IpeErrorKind, String)> {
        match result {
            IpeResult::Ok(_) => None,
            IpeResult::Err(e) => Some((
                crate::ipe_error_kind(e.clone()),
                crate::ipe_error_message(e),
            )),
        }
    }

    /// A stream handler that emits nothing.
    fn idle(_w: StreamWriter) -> IpeTask<IpeError, ()> {
        Box::pin(async { IpeResult::Ok(()) })
    }

    /// A `stream` task with an idle handler.
    fn stream_idle() -> IpeTask<IpeError, ServerResponse> {
        server_stream_stream::<IpeError, _>("text/event-stream".to_owned(), idle)
    }

    /// The ticket whose value is `n`, or `None` for zero.
    fn ticket(n: u128) -> Option<StreamTicket> {
        NonZeroU128::new(n).map(StreamTicket)
    }

    /// `stream` refuses to register outside any `Server` request; inside one
    /// it registers.
    #[tokio::test]
    async fn stream_outside_a_server_request_is_refused() {
        assert_eq!(
            refusal(stream_idle().await),
            Some((IpeErrorKind::InvalidInput, OUTSIDE_REQUEST.to_owned()))
        );
        let (inside, streams) = in_stream_scope(stream_idle()).await;
        assert_eq!(refusal(inside), None);
        drop(streams);
    }

    /// A sub-task carried from a request registers before its response is
    /// claimed and is refused after.
    #[tokio::test]
    async fn a_stream_after_its_response_was_sent_is_refused() {
        let ((early, late), streams) = in_stream_scope(async {
            (
                inherit_stream_scope(stream_idle()),
                inherit_stream_scope(stream_idle()),
            )
        })
        .await;
        let early = early.await;
        assert!(
            matches!(early, IpeResult::Ok(_)),
            "a carried sub-task registers before the claim"
        );
        let IpeResult::Ok(registered) = early else {
            return;
        };
        assert!(registered.body.starts_with(SENTINEL_PREFIX));
        assert!(matches!(
            claim_streaming_sentinel("ok", streams),
            ServerStreamClaim::Buffered
        ));
        assert_eq!(
            refusal(late.await),
            Some((IpeErrorKind::InvalidInput, AFTER_RESPONSE.to_owned()))
        );
    }

    /// A request dropped without claiming its response releases every
    /// handler it held and refuses a sub-task still carrying its table.
    #[tokio::test]
    async fn a_request_dropped_unclaimed_serves_its_table() {
        let held = Arc::new(());
        let captured = Arc::clone(&held);
        let ((registered, late), streams) = in_stream_scope(async move {
            let registered = server_stream_stream::<IpeError, _>(
                "text/plain".to_owned(),
                move |_w: StreamWriter| {
                    let _keep = Arc::clone(&captured);
                    Box::pin(async { IpeResult::Ok(()) }) as IpeTask<IpeError, ()>
                },
            )
            .await;
            (registered, inherit_stream_scope(stream_idle()))
        })
        .await;
        assert_eq!(refusal(registered), None);
        assert_eq!(Arc::strong_count(&held), 2, "the pending handler holds it");
        drop(streams);
        assert_eq!(Arc::strong_count(&held), 1, "the unclaimed handler dropped");
        assert_eq!(
            refusal(late.await),
            Some((IpeErrorKind::InvalidInput, AFTER_RESPONSE.to_owned()))
        );
    }

    /// A request registers `MAX_PENDING_STREAMS` streams; the next is refused.
    #[tokio::test]
    async fn the_pending_stream_ceiling_refuses_one_past_the_limit() {
        let (outcomes, streams) = in_stream_scope(async {
            let mut outcomes = Vec::new();
            for _ in 0..=MAX_PENDING_STREAMS {
                outcomes.push(refusal(stream_idle().await));
            }
            outcomes
        })
        .await;
        drop(streams);
        let (allowed, past) = outcomes.split_at(MAX_PENDING_STREAMS);
        assert!(allowed.iter().all(Option::is_none), "{allowed:?}");
        assert_eq!(
            past,
            [Some((IpeErrorKind::InvalidInput, too_many_streams()))]
        );
    }

    /// The mint redraws a zero and a collision, refuses once its draws run
    /// out, and refuses a failing source at once.
    #[test]
    fn ticket_mint_redraws_zero_and_collisions_and_refuses_a_dead_source() {
        let draws = [0u128, 3, 9];
        let mut i = 0;
        let source = |buf: &mut [u8; 16]| {
            *buf = draws.get(i).copied().unwrap_or(0).to_le_bytes();
            i += 1;
            Ok(())
        };
        let minted = mint_with(source, |t| Some(t) == ticket(3));
        assert!(matches!(minted, Ok(t) if Some(t) == ticket(9)));

        let mut zero_draws = 0;
        let zeros = |buf: &mut [u8; 16]| {
            zero_draws += 1;
            *buf = [0; 16];
            Ok(())
        };
        let exhausted = mint_with(zeros, |_| false).map(|_| ());
        assert_eq!(zero_draws, MINT_ATTEMPTS);
        assert!(
            matches!(&exhausted, Err(e) if crate::ipe_error_kind(e.clone()) == IpeErrorKind::Unavailable)
        );
        assert!(
            matches!(&exhausted, Err(e) if crate::ipe_error_message(e.clone()) == MINT_EXHAUSTED)
        );

        let ones = |buf: &mut [u8; 16]| {
            *buf = [1; 16];
            Ok(())
        };
        let colliding = mint_with(ones, |_| true).map(|_| ());
        assert!(
            matches!(&colliding, Err(e) if crate::ipe_error_message(e.clone()) == MINT_EXHAUSTED)
        );

        let broken = |_: &mut [u8; 16]| Err(getrandom::Error::UNSUPPORTED);
        let dead = mint_with(broken, |_| false).map(|_| ());
        assert!(
            matches!(&dead, Err(e) if crate::ipe_error_kind(e.clone()) == IpeErrorKind::Unavailable)
        );
        assert!(
            matches!(&dead, Err(e) if crate::ipe_error_message(e.clone()) == ENTROPY_UNAVAILABLE)
        );
    }

    /// A ticket parses only from exactly 32 lowercase hex digits naming a
    /// nonzero value; a minted ticket round-trips through its sentinel.
    #[test]
    fn ticket_parse_accepts_only_the_canonical_form() {
        let digits = "0123456789abcdef0123456789abcdef";
        assert!(StreamTicket::parse(digits).is_some());
        for refused in [
            "0123456789ABCDEF0123456789abcdef",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "00000000000000000000000000000000",
            "+123456789abcdef0123456789abcdef",
            " 123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdeg",
            "",
        ] {
            assert!(StreamTicket::parse(refused).is_none(), "{refused:?}");
        }
        assert_eq!(
            StreamTicket::parse("00000000000000000000000000000001"),
            ticket(1)
        );
        let minted = mint_with(os_entropy, |_| false).ok();
        let back = minted.and_then(|t| {
            t.sentinel()
                .strip_prefix(SENTINEL_PREFIX)
                .and_then(StreamTicket::parse)
        });
        assert!(minted.is_some());
        assert_eq!(back, minted);
    }

    /// A ticket's `Debug` names no digit of its value.
    #[test]
    fn a_ticket_debug_renders_opaque() {
        let cd = |buf: &mut [u8; 16]| {
            *buf = [0xcd; 16];
            Ok(())
        };
        let minted = mint_with(cd, |_| false).ok();
        assert!(minted.is_some());
        let shown = format!("{minted:?}");
        assert_eq!(shown, "Some(StreamTicket(<opaque>))");
        assert!(!shown.contains("cdcd"));
    }

    /// `emit` to a writer whose client is gone fails `Unavailable`; to a live
    /// client it sends the chunk.
    #[tokio::test]
    async fn emit_after_client_disconnect_is_unavailable() {
        let id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(STREAM_CHAN_BUFFER);
        stream_senders()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, tx);
        let writer = StreamWriter::StreamWriter(id);
        let sent = server_stream_emit::<IpeError>("a".to_owned(), writer).await;
        assert_eq!(refusal(sent), None);
        assert_eq!(rx.recv().await.as_deref(), Some("a"));
        drop(rx);
        let gone = server_stream_emit::<IpeError>("b".to_owned(), writer).await;
        stream_senders()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        assert_eq!(
            refusal(gone),
            Some((IpeErrorKind::Unavailable, CLIENT_DISCONNECTED.to_owned()))
        );
    }
}

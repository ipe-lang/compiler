//! The dev-only blue-green front proxy for `ipe dev watch`.
//!
//! DEV ONLY. This proxy is owned by the `ipe dev watch` process and NEVER exists
//! in a release binary or an emitted app — it is watch-loop plumbing, not a
//! runtime supervisor baked into the product.
//!
//! ## Why it exists
//!
//! Without a proxy, `ipe dev watch` binds the user's port directly onto the
//! supervised app binary. A rebuild must therefore kill the old binary to
//! free the port before the new one can bind it — and killing the old binary
//! drops every browser connection it was holding (the SSE stream in
//! particular), so the page visibly reconnects on every save.
//!
//! The proxy breaks that coupling. It — not the app — holds the user's port,
//! persistently, for the whole watch session. The app binary runs BEHIND it
//! on an internal loopback port. On a rebuild the new binary is spawned on a
//! FRESH internal port; once it reports ready (`/_ipe/readyz`), the proxy
//! atomically flips its upstream to the new port and drains the old — and
//! because the listening socket is never closed and the client-facing TCP
//! connection is terminated AT the proxy (not spliced straight through to one
//! upstream socket), a client using HTTP/1.1 keep-alive keeps the SAME socket
//! alive across the swap. The next request on that socket is simply routed to
//! the new upstream.
//!
//! ## Framing
//!
//! This is an HTTP/1.1-framed proxy, not a blind byte splice: the client
//! connection is kept open across requests (keep-alive), and each request is
//! forwarded to WHATEVER upstream is current at the moment the request
//! arrives. A blind bidirectional splice would bind one client socket to one
//! upstream socket for its whole life, so an upstream swap would still tear
//! the client connection — exactly what this proxy exists to avoid.
//!
//! The proxy and the app behind it both read the same byte stream, so they
//! must agree on where every body ends; where two readers of one stream
//! disagree, the bytes one calls "the next request" the other calls "this
//! body" (request smuggling, response desync). One parser, [`Head::parse`],
//! turns a header block into a typed [`BodyFraming`] — a fixed
//! `Content-Length`, `Transfer-Encoding: chunked`, or no self-delimiting
//! framing — and the copy loops are driven only by that value. The grammar it
//! admits is a strict subset of the upstream server's: every head the proxy
//! forwards is one the server frames identically, and every head on which the
//! two could differ (a length beside a transfer-encoding, two lengths, a
//! transfer-encoding whose last token is not `chunked`, whitespace in a header
//! name, a signed or non-digit length, an obs-fold continuation) is refused
//! before a byte reaches the other side: `400` for a request, `502` for a
//! response, and the connection closes.
//!
//! A response with no `Content-Length` and no `chunked` framing (an SSE
//! stream, or any `Connection: close` response) is copied byte-for-byte until
//! the upstream half closes; that terminates the client keep-alive too (the
//! response has no self-delimiting length), which is the correct HTTP/1.1
//! behaviour and matches how a streaming response ends. A response to a
//! `HEAD` request, or with a 204/304 status, carries no body whatever its
//! headers say. An interim 1xx response (`100 Continue`) is relayed head-only
//! and the final response read after it, at most [`MAX_INTERIM_RESPONSES`]
//! times. A `101 Switching Protocols` is refused with a `502`: the bytes after
//! it are another protocol, which this per-message framer does not carry.
//!
//! ## Soundness
//!
//! `#![forbid(unsafe_code)]` (crate-level). Every accept/read/write failure
//! degrades a single connection, never the proxy: a per-connection worker
//! thread that errors simply returns, and the accept loop keeps serving. All
//! copy loops are bounded either by a declared length, by the chunk framing,
//! or by the upstream closing — never an unbounded in-memory buffer.

use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// Per-request read timeout on the client socket. Bounds a stalled client
/// connection so a per-connection worker thread cannot park forever holding a
/// file descriptor. Generous: a keep-alive connection idle between requests is
/// expected to sit here, so this is the "client vanished without closing"
/// ceiling, not a request deadline.
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_mins(5);

/// Connect timeout when the proxy dials the current upstream for one request.
/// Short — the upstream is always loopback and, by construction, the proxy
/// only routes to an upstream that has already passed its readiness probe.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

/// Upper bound on one message's header block, and on one chunked trailer. A
/// head whose lines exceed this is rejected rather than buffered unboundedly —
/// a memory-DoS guard on the one part of the message the proxy must buffer to
/// re-emit verbatim (the bodies are streamed, never fully buffered).
const MAX_REQUEST_HEADER_BYTES: usize = 64 * 1024;

/// Most interim (1xx) responses relayed ahead of one final response; an
/// upstream sending more is answered with the proxy's `502`.
const MAX_INTERIM_RESPONSES: usize = 8;

/// Copy-loop buffer size for streaming bodies/responses.
const COPY_BUF_BYTES: usize = 16 * 1024;

/// Upper bound on concurrently live per-client worker threads. Without a
/// cap, a local peer opening connections faster than they close could start
/// an unbounded number of OS threads (PRINCIPLES 3, bounded by construction).
/// A connection past the cap is closed at once rather than queued.
const MAX_PROXY_CLIENTS: usize = 256;

/// Most digits a `Content-Length` value may carry; every value this long fits
/// a `u64`, so the admitted lengths are exactly the ones the upstream reads.
const MAX_CONTENT_LENGTH_DIGITS: usize = 19;

/// Most hex digits a chunk size may carry: exactly the `u64` range.
const MAX_CHUNK_SIZE_HEX_DIGITS: usize = 16;

/// A running dev proxy: the persistent front the browser talks to.
///
/// Holds the user's port for the whole watch session. The current upstream
/// (the internal port the live app binary is bound to) is an atomic the
/// cutover flips; `0` means "no upstream yet" (before the first binary is
/// ready), and a request arriving then gets a `502`.
pub struct DevProxy {
    /// The user-facing port the proxy bound (echoed back so the caller can
    /// confirm it, and used in diagnostics).
    port: u16,
    /// The internal loopback port of the CURRENT live upstream. `0` until the
    /// first ready binary is cut over. Read on every proxied request, written
    /// once per cutover.
    upstream: Arc<AtomicU16>,
    /// Set on `shutdown` so the accept loop stops taking new connections. The
    /// listener is also dropped, which unblocks the blocking `accept`.
    stopped: Arc<AtomicBool>,
    /// The accept-loop thread handle, joined on `shutdown`.
    accept_handle: Option<thread::JoinHandle<()>>,
    /// Test-only introspection of the live per-client worker count, so a test
    /// can poll the real state instead of guessing a sleep duration.
    #[cfg(test)]
    live_clients: Arc<AtomicUsize>,
}

impl DevProxy {
    /// Bind `127.0.0.1:port` and start the accept loop. The proxy is live (it
    /// answers, with `502`, before any upstream exists) the moment this
    /// returns.
    ///
    /// # Errors
    /// An I/O error if the user's port cannot be bound (typically already in
    /// use) — the caller surfaces this the same way a direct port bind failure
    /// is surfaced.
    pub fn bind(port: u16) -> io::Result<Self> {
        let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = TcpListener::bind(addr)?;
        // A short accept timeout lets the loop observe the `stopped` flag
        // promptly on shutdown even if no connection arrives to unblock it.
        let upstream = Arc::new(AtomicU16::new(0));
        let stopped = Arc::new(AtomicBool::new(false));
        let live_clients = Arc::new(AtomicUsize::new(0));

        // Dropping `listener` on a refused spawn releases the port, same as
        // any other bind failure.
        let accept_handle = {
            let upstream = Arc::clone(&upstream);
            let stopped = Arc::clone(&stopped);
            let live_clients = Arc::clone(&live_clients);
            thread::Builder::new()
                .name("ipe-watch-proxy-accept".to_owned())
                .spawn(move || accept_loop(&listener, &upstream, &stopped, &live_clients))?
        };

        Ok(Self {
            port,
            upstream,
            stopped,
            accept_handle: Some(accept_handle),
            #[cfg(test)]
            live_clients,
        })
    }

    /// The user-facing port this proxy holds.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Atomically route all subsequent requests to `internal_port`. Called by
    /// the cutover once the new binary has passed its readiness probe on that
    /// port. Existing kept-alive client connections pick this up on their next
    /// request (the atomic is read per request); connections mid-stream on the
    /// old upstream are unaffected until they close.
    pub fn set_upstream(&self, internal_port: u16) {
        self.upstream.store(internal_port, Ordering::SeqCst);
    }

    /// The current upstream port (`0` if none yet). Diagnostics/tests only.
    #[must_use]
    pub fn current_upstream(&self) -> u16 {
        self.upstream.load(Ordering::SeqCst)
    }

    /// The current count of live per-client worker slots. Test-only: lets a
    /// test poll the real state of the [`MAX_PROXY_CLIENTS`] cap instead of
    /// guessing a sleep duration.
    #[cfg(test)]
    fn live_client_count(&self) -> usize {
        self.live_clients.load(Ordering::SeqCst)
    }

    /// Stop accepting new connections and join the accept loop. In-flight
    /// per-connection workers are detached — they finish or die with their
    /// sockets when the process exits; the proxy exists only for the lifetime
    /// of the watch session and this is the session teardown.
    pub fn shutdown(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        // Unblock the accept loop's own dial to the listener: connect to our
        // own port so a parked `accept()` returns and observes `stopped`.
        let _ = TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], self.port)),
            Duration::from_millis(100),
        );
        if let Some(h) = self.accept_handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for DevProxy {
    fn drop(&mut self) {
        // Idempotent: `shutdown` no-ops if already joined (`accept_handle` is
        // `None`), so an explicit `shutdown()` followed by scope-drop is safe.
        self.shutdown();
    }
}

/// Releases one reserved live-client slot when a per-client worker ends, on
/// every exit path: normal return, panic unwind, or the worker thread never
/// having started at all (a refused spawn drops this still inside the
/// un-run closure).
struct LiveClientSlot(Arc<AtomicUsize>);

impl Drop for LiveClientSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Accept connections until `stopped`, spawning a worker thread per client,
/// up to [`MAX_PROXY_CLIENTS`] concurrently live.
fn accept_loop(
    listener: &TcpListener,
    upstream: &Arc<AtomicU16>,
    stopped: &Arc<AtomicBool>,
    live_clients: &Arc<AtomicUsize>,
) {
    for stream in listener.incoming() {
        if stopped.load(Ordering::SeqCst) {
            return;
        }
        let Ok(client) = stream else {
            // A transient accept error (e.g. the wake-up self-connect on
            // shutdown, or a client that reset before accept completed) never
            // kills the loop; keep serving.
            continue;
        };
        if live_clients.fetch_add(1, Ordering::SeqCst) >= MAX_PROXY_CLIENTS {
            // Over the live-client cap: close this connection at once rather
            // than start another unbounded worker thread.
            live_clients.fetch_sub(1, Ordering::SeqCst);
            drop(client);
            continue;
        }
        let upstream = Arc::clone(upstream);
        let slot = LiveClientSlot(Arc::clone(live_clients));
        // A refused worker thread drops `client` and `slot` right here,
        // inside the never-run closure: the connection closes and the
        // reserved slot releases, exactly as a worker that ran and returned
        // would. Keep accepting either way.
        let _ = thread::Builder::new()
            .name("ipe-watch-proxy-client".to_owned())
            .spawn(move || {
                let _slot = slot;
                // A worker that errors just closes its own connection.
                let _ = serve_client(client, &upstream);
            });
    }
}

/// Serve one client connection: read HTTP/1.1 requests in a keep-alive loop,
/// forwarding each to the CURRENT upstream. The client socket is held open
/// across requests, which is what lets it survive an upstream swap.
fn serve_client(client: TcpStream, upstream: &Arc<AtomicU16>) -> io::Result<()> {
    client.set_read_timeout(Some(CLIENT_IDLE_TIMEOUT))?;
    let mut client_reader = BufReader::new(client.try_clone()?);
    let mut client_writer = client;

    loop {
        // Read one request's header block (request line + headers, up to the
        // blank line). An EOF here is the client closing the keep-alive
        // connection — a clean end, not an error.
        let Some(raw) = read_head_block(&mut client_reader)? else {
            return Ok(());
        };
        let head = match Head::<RequestStart>::parse(raw) {
            Ok(head) => head,
            Err(refusal) => {
                // Nothing was forwarded. The refused body was never consumed,
                // so the connection cannot carry another request: close it.
                write_refusal(
                    &mut client_writer,
                    RefusalStatus::BadRequest,
                    refusal.text(),
                )?;
                return Ok(());
            }
        };

        let port = upstream.load(Ordering::SeqCst);
        if port == 0 {
            // No upstream is ready yet (pre-first-build). Answer directly so a
            // client that connects during the very first cold build gets a
            // definite response rather than a hang.
            write_refusal(
                &mut client_writer,
                RefusalStatus::BadGateway,
                "no upstream ready",
            )?;
            // No body was consumed; a client that sent a body would desync, so
            // close rather than attempt another keep-alive request.
            return Ok(());
        }

        let upstream_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let Ok(mut upstream_conn) =
            TcpStream::connect_timeout(&upstream_addr, UPSTREAM_CONNECT_TIMEOUT)
        else {
            write_refusal(
                &mut client_writer,
                RefusalStatus::BadGateway,
                "upstream connect failed",
            )?;
            return Ok(());
        };

        // Forward the request head verbatim, then its body per its framing.
        upstream_conn.write_all(&head.raw)?;
        forward_request_body(head.framing, &mut client_reader, &mut upstream_conn)?;
        upstream_conn.flush()?;

        // Relay the response back. `keep_alive` reports whether both sides may
        // reuse the connection for another request; if not (streaming response
        // or an explicit close on either side), the loop ends after this
        // response.
        let keep_alive = relay_response(&upstream_conn, &mut client_writer, head.start.method)?;
        if !keep_alive || head.connection_close {
            return Ok(());
        }
    }
}

/// How one message body is delimited, decided once from its head.
///
/// `None` is "no self-delimiting framing": a request then has no body, and a
/// response is copied until the upstream closes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyFraming {
    None,
    Length(u64),
    Chunked,
}

/// The request method as far as response framing cares: a `HEAD` answer
/// carries no body whatever its headers declare.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    Head,
    Other,
}

/// Which side of the exchange a head belongs to.
///
/// Decides what a `Transfer-Encoding` without a final `chunked` means: a
/// request is refused, a response is close-delimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Request,
    Response,
}

/// A head the proxy refuses to forward: the proxy and the server behind it
/// could frame it differently, or it is malformed in a way the server rejects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FramingRefusal {
    MissingStartLine,
    MalformedStatusLine,
    LineWithoutColon,
    SpaceBeforeColon,
    HeaderNameNotToken,
    HeaderValueInvalidByte,
    ObsFold,
    ContentLengthNotDigits,
    ContentLengthTooLong,
    DuplicateContentLength,
    LengthWithTransferEncoding,
    TransferEncodingNotFinalChunked,
    DuplicateTransferEncoding,
    MalformedChunkSize,
    ChunkDataNotCrlfTerminated,
    TrailerLineMalformed,
    TruncatedTrailer,
    TooManyInterimResponses,
    ProtocolUpgrade,
}

impl FramingRefusal {
    /// The proxy's own phrase for the refusal; never echoes peer bytes.
    const fn text(self) -> &'static str {
        match self {
            Self::MissingStartLine => "no request line",
            Self::MalformedStatusLine => "status code is not three digits",
            Self::LineWithoutColon => "header line without a colon",
            Self::SpaceBeforeColon => "whitespace before the header colon",
            Self::HeaderNameNotToken => "header name is not a token",
            Self::HeaderValueInvalidByte => "control byte in a header value",
            Self::ObsFold => "obsolete header line folding",
            Self::ContentLengthNotDigits => "content-length is not a plain decimal",
            Self::ContentLengthTooLong => "content-length has too many digits",
            Self::DuplicateContentLength => "more than one content-length value",
            Self::LengthWithTransferEncoding => "content-length beside transfer-encoding",
            Self::TransferEncodingNotFinalChunked => {
                "transfer-encoding does not end in a single chunked"
            }
            Self::DuplicateTransferEncoding => "more than one transfer-encoding line",
            Self::MalformedChunkSize => "malformed chunk size line",
            Self::ChunkDataNotCrlfTerminated => "chunk data not followed by CRLF",
            Self::TrailerLineMalformed => "malformed chunked trailer line",
            Self::TruncatedTrailer => "connection closed inside the chunked trailer",
            Self::TooManyInterimResponses => "too many interim responses",
            Self::ProtocolUpgrade => "the dev proxy does not carry protocol upgrades",
        }
    }
}

impl fmt::Display for FramingRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text())
    }
}

impl From<FramingRefusal> for io::Error {
    fn from(refusal: FramingRefusal) -> Self {
        Self::new(io::ErrorKind::InvalidData, refusal.text())
    }
}

/// The start line of one role, parsed from the first line of its head.
trait StartLine: Sized {
    const ROLE: Role;
    fn parse(line: &[u8]) -> Result<Self, FramingRefusal>;
}

/// A request line: only the method bears on framing.
struct RequestStart {
    method: Method,
}

impl StartLine for RequestStart {
    const ROLE: Role = Role::Request;

    fn parse(line: &[u8]) -> Result<Self, FramingRefusal> {
        let method = line.split(|&b| b == b' ').next().unwrap_or(&[]);
        if method.is_empty() {
            return Err(FramingRefusal::MissingStartLine);
        }
        Ok(Self {
            method: if method == b"HEAD" {
                Method::Head
            } else {
                Method::Other
            },
        })
    }
}

/// What a response's status code says about the exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResponseStatus {
    /// A 1xx other than 101: an interim answer; a final one still follows.
    Interim,
    Final(FinalStatus),
}

/// A final response's status, as far as body framing cares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FinalStatus {
    /// 101: the bytes after the head are another protocol, not HTTP.
    SwitchingProtocols,
    /// 204 or 304: no body whatever the headers say.
    NoBody,
    Body,
}

/// A status line: its three-digit code tells interim, upgrade and no-body
/// answers apart.
struct ResponseStart {
    status: ResponseStatus,
}

impl StartLine for ResponseStart {
    const ROLE: Role = Role::Response;

    fn parse(line: &[u8]) -> Result<Self, FramingRefusal> {
        let code = line
            .split(u8::is_ascii_whitespace)
            .filter(|token| !token.is_empty())
            .nth(1)
            .unwrap_or(&[]);
        let status = match *code {
            [b'1', b'0', b'1'] => ResponseStatus::Final(FinalStatus::SwitchingProtocols),
            [b'1', b'0'..=b'9', b'0'..=b'9'] => ResponseStatus::Interim,
            [b'2' | b'3', b'0', b'4'] => ResponseStatus::Final(FinalStatus::NoBody),
            [b'0'..=b'9', b'0'..=b'9', b'0'..=b'9'] => ResponseStatus::Final(FinalStatus::Body),
            _ => return Err(FramingRefusal::MalformedStatusLine),
        };
        Ok(Self { status })
    }
}

/// One parsed head: the raw bytes re-emitted verbatim to the other side plus
/// the typed framing facts the proxy copies the body by.
struct Head<S> {
    raw: Vec<u8>,
    start: S,
    framing: BodyFraming,
    connection_close: bool,
}

impl<S: StartLine> Head<S> {
    /// Parse one complete header block (start line through the blank line).
    ///
    /// The single reader of the framing headers: `Content-Length`,
    /// `Transfer-Encoding` and `Connection` are judged here, once, into typed
    /// values, and every shape the server behind the proxy could frame
    /// differently is a [`FramingRefusal`].
    fn parse(raw: Vec<u8>) -> Result<Self, FramingRefusal> {
        let mut lines = raw.split_inclusive(|&b| b == b'\n').map(strip_line_end);
        let start = S::parse(lines.next().unwrap_or(&[]))?;
        let mut framing = FramingHeaders::default();
        let mut connection_close = false;
        for line in lines {
            if line.is_empty() {
                break;
            }
            let (name, value) = split_header(line)?;
            if name.eq_ignore_ascii_case(b"content-length") {
                framing.content_length(value)?;
            } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
                framing.transfer_encoding(value)?;
            } else if name.eq_ignore_ascii_case(b"connection") {
                connection_close |= has_token(value, b"close");
            }
        }
        let framing = framing.finish(S::ROLE)?;
        Ok(Self {
            raw,
            start,
            framing,
            connection_close,
        })
    }
}

/// What a `Transfer-Encoding` value says about the body's end.
#[derive(Clone, Copy)]
enum TransferEncoding {
    Chunked,
    NotFinalChunked,
}

/// The body-framing headers seen so far in one head, at most one line each.
#[derive(Default)]
struct FramingHeaders {
    content_length: Option<u64>,
    transfer_encoding: Option<TransferEncoding>,
}

impl FramingHeaders {
    /// Record a `Content-Length` line: exactly one line, one plain decimal.
    fn content_length(&mut self, value: &[u8]) -> Result<(), FramingRefusal> {
        if self.content_length.is_some() || value.contains(&b',') {
            return Err(FramingRefusal::DuplicateContentLength);
        }
        self.content_length = Some(parse_content_length(value)?);
        Ok(())
    }

    /// Record a `Transfer-Encoding` line: exactly one line.
    fn transfer_encoding(&mut self, value: &[u8]) -> Result<(), FramingRefusal> {
        if self.transfer_encoding.is_some() {
            return Err(FramingRefusal::DuplicateTransferEncoding);
        }
        self.transfer_encoding = Some(parse_transfer_encoding(value));
        Ok(())
    }

    /// Decide the framing from the headers seen; a length beside a
    /// transfer-encoding is never arbitrated, only refused.
    const fn finish(self, role: Role) -> Result<BodyFraming, FramingRefusal> {
        match (self.content_length, self.transfer_encoding) {
            (Some(_), Some(_)) => Err(FramingRefusal::LengthWithTransferEncoding),
            (Some(len), None) => Ok(BodyFraming::Length(len)),
            (None, Some(TransferEncoding::Chunked)) => Ok(BodyFraming::Chunked),
            (None, Some(TransferEncoding::NotFinalChunked)) => match role {
                Role::Request => Err(FramingRefusal::TransferEncodingNotFinalChunked),
                Role::Response => Ok(BodyFraming::None),
            },
            (None, None) => Ok(BodyFraming::None),
        }
    }
}

/// A `Content-Length` value: `1*DIGIT`, at most [`MAX_CONTENT_LENGTH_DIGITS`].
fn parse_content_length(value: &[u8]) -> Result<u64, FramingRefusal> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(FramingRefusal::ContentLengthNotDigits);
    }
    if value.len() > MAX_CONTENT_LENGTH_DIGITS {
        return Err(FramingRefusal::ContentLengthTooLong);
    }
    value
        .iter()
        .try_fold(0u64, |acc, &digit| {
            acc.checked_mul(10)?
                .checked_add(u64::from(digit.checked_sub(b'0')?))
        })
        .ok_or(FramingRefusal::ContentLengthTooLong)
}

/// A `Transfer-Encoding` value is chunked only when it is all ASCII (the
/// server reads a value with obs-text as not chunked), its last token is
/// `chunked`, and no other token is.
fn parse_transfer_encoding(value: &[u8]) -> TransferEncoding {
    if !value.is_ascii() {
        return TransferEncoding::NotFinalChunked;
    }
    let mut chunked_tokens = 0usize;
    let mut last_is_chunked = false;
    for token in value.split(|&b| b == b',').map(trim_ows) {
        last_is_chunked = token.eq_ignore_ascii_case(b"chunked");
        if last_is_chunked {
            chunked_tokens = chunked_tokens.saturating_add(1);
        }
    }
    if last_is_chunked && chunked_tokens == 1 {
        TransferEncoding::Chunked
    } else {
        TransferEncoding::NotFinalChunked
    }
}

/// Whether a comma-separated token list names `token` (ASCII case-insensitive).
fn has_token(value: &[u8], token: &[u8]) -> bool {
    value
        .split(|&b| b == b',')
        .map(trim_ows)
        .any(|candidate| candidate.eq_ignore_ascii_case(token))
}

/// Split one header line into its name and trimmed value.
///
/// Refuses every name shape the server rejects: a continuation line, a line
/// without a colon, whitespace before the colon, a name that is not a token.
fn split_header(line: &[u8]) -> Result<(&[u8], &[u8]), FramingRefusal> {
    if line.first().is_some_and(|&b| is_ows(b)) {
        return Err(FramingRefusal::ObsFold);
    }
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or(FramingRefusal::LineWithoutColon)?;
    let (name, rest) = line.split_at(colon);
    if name.iter().any(|&b| is_ows(b)) {
        return Err(FramingRefusal::SpaceBeforeColon);
    }
    if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
        return Err(FramingRefusal::HeaderNameNotToken);
    }
    let value = rest.get(1..).unwrap_or(&[]);
    if !value.iter().all(|&b| is_field_value_byte(b)) {
        return Err(FramingRefusal::HeaderValueInvalidByte);
    }
    Ok((name, trim_ows(value)))
}

/// A header-value byte the server's parser admits: HTAB, visible ASCII, SP,
/// or obs-text. A CR, LF, NUL, DEL or other control byte is refused, so no
/// line the proxy reads is one the server would skip or split differently.
const fn is_field_value_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=0x7e | 0x80..=0xff)
}

/// Drop the line terminator (CRLF or bare LF) from one head line.
const fn strip_line_end(line: &[u8]) -> &[u8] {
    match line {
        [rest @ .., b'\r', b'\n'] | [rest @ .., b'\n'] => rest,
        _ => line,
    }
}

/// Optional whitespace around a header value: SP or HTAB.
const fn is_ows(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

/// A header-name byte (RFC 9110 `tchar`).
const fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Trim optional whitespace (SP / HTAB) from both ends.
const fn trim_ows(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes {
        if is_ows(*first) {
            bytes = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = bytes {
        if is_ows(*last) {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

/// Read one header block (start line through the blank line) within the head
/// byte cap.
///
/// Empty lines before the start line are skipped, as the server behind the
/// proxy skips them (RFC 9112 section 2.2), and never forwarded; they count
/// against the cap. `None` is a clean EOF before any start line — a
/// keep-alive peer closing between messages. An EOF after a partial head is
/// an error.
fn read_head_block(reader: &mut BufReader<TcpStream>) -> io::Result<Option<Vec<u8>>> {
    let mut raw = Vec::new();
    let mut skipped = 0usize;
    loop {
        let mut line = Vec::new();
        let budget = MAX_REQUEST_HEADER_BYTES
            .saturating_sub(raw.len())
            .saturating_sub(skipped);
        let n = read_line_capped(reader, &mut line, budget)?;
        if n == 0 {
            if raw.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed mid-head",
            ));
        }
        let is_blank = strip_line_end(&line).is_empty();
        if is_blank && raw.is_empty() {
            skipped = skipped.saturating_add(n);
            continue;
        }
        raw.extend_from_slice(&line);
        if is_blank {
            return Ok(Some(raw));
        }
    }
}

/// Forward the request body to the upstream according to its framing.
fn forward_request_body(
    framing: BodyFraming,
    client_reader: &mut BufReader<TcpStream>,
    upstream: &mut TcpStream,
) -> io::Result<()> {
    match framing {
        BodyFraming::None => Ok(()),
        BodyFraming::Length(len) => copy_exact(client_reader, upstream, len),
        BodyFraming::Chunked => copy_chunked_strict(client_reader, upstream),
    }
}

/// Relay one HTTP/1.1 response from the upstream back to the client, framed by
/// the response's own head. Returns whether the connection may be reused for a
/// subsequent keep-alive request.
///
/// A head the proxy refuses is answered with the proxy's own `502` and not one
/// upstream byte. A response the proxy cannot self-delimit (no
/// `Content-Length`, not `chunked`) is copied until the upstream closes — the
/// SSE / `Connection: close` case — and reports `false` (the connection ends
/// with the stream).
fn relay_response(
    upstream: &TcpStream,
    client: &mut TcpStream,
    request_method: Method,
) -> io::Result<bool> {
    let mut upstream_reader = BufReader::new(upstream.try_clone()?);
    let mut interim_left = MAX_INTERIM_RESPONSES;
    let (head, status) = loop {
        let Some(raw) = read_head_block(&mut upstream_reader)? else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "upstream closed before responding",
            ));
        };
        let refusal = match Head::<ResponseStart>::parse(raw) {
            Ok(head) => match head.start.status {
                ResponseStatus::Final(status) => break (head, status),
                // An interim answer (`100 Continue`, `103 Early Hints`) is
                // relayed head-only; the final answer follows on the same
                // upstream connection.
                ResponseStatus::Interim => match interim_left.checked_sub(1) {
                    Some(left) => {
                        interim_left = left;
                        client.write_all(&head.raw)?;
                        client.flush()?;
                        continue;
                    }
                    None => FramingRefusal::TooManyInterimResponses,
                },
            },
            Err(refusal) => refusal,
        };
        write_refusal(client, RefusalStatus::BadGateway, refusal.text())?;
        return Ok(false);
    };

    let body = match (status, request_method) {
        // The bytes after a `101` head are another protocol: the proxy frames
        // only HTTP/1.1 messages, so it refuses before relaying one byte.
        (FinalStatus::SwitchingProtocols, _) => {
            write_refusal(
                client,
                RefusalStatus::BadGateway,
                FramingRefusal::ProtocolUpgrade.text(),
            )?;
            return Ok(false);
        }
        (FinalStatus::NoBody, _) | (FinalStatus::Body, Method::Head) => None,
        (FinalStatus::Body, Method::Other) => Some(head.framing),
    };
    client.write_all(&head.raw)?;
    let keep_alive = match body {
        None => !head.connection_close,
        Some(BodyFraming::Length(len)) => {
            copy_exact(&mut upstream_reader, client, len)?;
            !head.connection_close
        }
        Some(BodyFraming::Chunked) => {
            copy_chunked_strict(&mut upstream_reader, client)?;
            !head.connection_close
        }
        Some(BodyFraming::None) => {
            copy_until_eof(&mut upstream_reader, client)?;
            false
        }
    };
    client.flush()?;
    Ok(keep_alive)
}

/// Copy exactly `len` bytes from `src` to `dst`.
fn copy_exact(src: &mut BufReader<TcpStream>, dst: &mut impl Write, len: u64) -> io::Result<()> {
    let mut remaining = len;
    let mut buf = [0u8; COPY_BUF_BYTES];
    while remaining > 0 {
        // `want` is capped at the buffer length so the read slot is in-bounds,
        // and the read is limited to what the caller declared remains so the
        // copy never over-reads past this body's length.
        let want = usize::try_from(remaining)
            .unwrap_or(COPY_BUF_BYTES)
            .min(COPY_BUF_BYTES);
        let Some(slot) = buf.get_mut(..want) else {
            break;
        };
        let read = src.read(slot)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "closed before the declared length was read",
            ));
        }
        let chunk = buf.get(..read).unwrap_or(&buf);
        dst.write_all(chunk)?;
        remaining -= read as u64;
    }
    Ok(())
}

/// Copy a `Transfer-Encoding: chunked` body chunk by chunk through the
/// zero-length chunk and its trailer, refusing every chunk line the server
/// behind the proxy would.
///
/// A refusal here is an `InvalidData` error: the head is already forwarded,
/// so the only sound outcome is closing both connections.
fn copy_chunked_strict(src: &mut BufReader<TcpStream>, dst: &mut impl Write) -> io::Result<()> {
    loop {
        let mut size_line = Vec::new();
        let n = read_line_capped(src, &mut size_line, MAX_REQUEST_HEADER_BYTES)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "closed mid-chunk-size",
            ));
        }
        let size = parse_chunk_size(&size_line)?;
        dst.write_all(&size_line)?;
        if size == 0 {
            return copy_trailer(src, dst);
        }
        copy_exact(src, dst, size)?;
        let mut crlf = [0u8; 2];
        src.read_exact(&mut crlf)?;
        if crlf != *b"\r\n" {
            return Err(FramingRefusal::ChunkDataNotCrlfTerminated.into());
        }
        dst.write_all(&crlf)?;
    }
}

/// A chunk-size line: `1*HEXDIG` (at most [`MAX_CHUNK_SIZE_HEX_DIGITS`]), an
/// optional `;` extension, one CRLF and no other CR.
fn parse_chunk_size(line: &[u8]) -> Result<u64, FramingRefusal> {
    let content = line
        .strip_suffix(b"\r\n")
        .filter(|content| !content.contains(&b'\r'))
        .ok_or(FramingRefusal::MalformedChunkSize)?;
    let hex = content.split(|&b| b == b';').next().unwrap_or(&[]);
    if hex.is_empty()
        || hex.len() > MAX_CHUNK_SIZE_HEX_DIGITS
        || !hex.iter().all(u8::is_ascii_hexdigit)
    {
        return Err(FramingRefusal::MalformedChunkSize);
    }
    hex.iter()
        .try_fold(0u64, |acc, &digit| {
            let digit = char::from(digit).to_digit(16)?;
            acc.checked_mul(16)?.checked_add(u64::from(digit))
        })
        .ok_or(FramingRefusal::MalformedChunkSize)
}

/// Copy a chunked trailer through its blank line: every line ends in its only
/// CRLF and is header-shaped, the whole trailer within the head byte cap.
fn copy_trailer(src: &mut BufReader<TcpStream>, dst: &mut impl Write) -> io::Result<()> {
    let mut total = 0usize;
    loop {
        let mut line = Vec::new();
        let budget = MAX_REQUEST_HEADER_BYTES.saturating_sub(total);
        let n = read_line_capped(src, &mut line, budget)?;
        if n == 0 {
            return Err(FramingRefusal::TruncatedTrailer.into());
        }
        total = total.saturating_add(n);
        let content = line
            .strip_suffix(b"\r\n")
            .filter(|content| !content.contains(&b'\r'))
            .ok_or(FramingRefusal::TrailerLineMalformed)?;
        if !content.is_empty() {
            split_header(content).map_err(|_| FramingRefusal::TrailerLineMalformed)?;
        }
        dst.write_all(&line)?;
        if content.is_empty() {
            return Ok(());
        }
    }
}

/// Copy from `src` to `dst` until the source closes (EOF). Used for a response
/// with no self-delimiting framing (SSE / `Connection: close`).
fn copy_until_eof(src: &mut BufReader<TcpStream>, dst: &mut impl Write) -> io::Result<()> {
    let mut buf = [0u8; COPY_BUF_BYTES];
    loop {
        let read = match src.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            // A read timeout on a streaming upstream is not an error to surface
            // — the stream is simply idle. But the proxy's client socket has no
            // timeout on this path, and the upstream carries its own; a genuine
            // error closes the stream, which is the correct end for it.
            Err(e) => return Err(e),
        };
        // A broken client (page closed) surfaces here as a write error and
        // ends the stream copy cleanly for this connection.
        let chunk = buf.get(..read).unwrap_or(&buf);
        dst.write_all(chunk)?;
        dst.flush()?;
    }
}

/// Read one line (through and including its `\n`) into `out`, capped at `cap`
/// bytes so a header line cannot grow unboundedly. Returns the number of bytes
/// read (`0` at EOF).
fn read_line_capped(
    reader: &mut BufReader<TcpStream>,
    out: &mut Vec<u8>,
    cap: usize,
) -> io::Result<usize> {
    let mut total = 0;
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            return Ok(total);
        }
        if let Some(nl) = available.iter().position(|&b| b == b'\n') {
            let take = nl + 1;
            if total + take > cap {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "header line exceeds cap",
                ));
            }
            let line = available.get(..take).unwrap_or(available);
            out.extend_from_slice(line);
            reader.consume(take);
            return Ok(total + take);
        }
        let take = available.len();
        if total + take > cap {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header line exceeds cap",
            ));
        }
        out.extend_from_slice(available);
        reader.consume(take);
        total += take;
    }
}

/// The status a refused exchange is answered with: the proxy's own verdict,
/// never relayed bytes.
#[derive(Clone, Copy)]
enum RefusalStatus {
    BadRequest,
    BadGateway,
}

impl RefusalStatus {
    const fn line(self) -> &'static str {
        match self {
            Self::BadRequest => "400 Bad Request",
            Self::BadGateway => "502 Bad Gateway",
        }
    }
}

/// Answer the client with the proxy's own refusal and `Connection: close`.
fn write_refusal(client: &mut TcpStream, status: RefusalStatus, reason: &str) -> io::Result<()> {
    let status = status.line();
    let body = format!("{status} (ipe dev watch proxy): {reason}\n");
    let resp = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(resp.as_bytes())?;
    client.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Shutdown;
    use std::sync::Mutex;

    /// Everything a test upstream observed: connections accepted, connections
    /// ended, and every request byte it consumed (head and body), in order.
    #[derive(Default)]
    struct Captured {
        connections: AtomicUsize,
        closed: AtomicUsize,
        bytes: Mutex<Vec<u8>>,
    }

    impl Captured {
        fn bytes(&self) -> Vec<u8> {
            self.bytes.lock().unwrap().clone()
        }

        /// Poll until `closed` connections are observed or 5 s pass.
        fn wait_closed(&self, expected: usize) -> usize {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                let count = self.closed.load(Ordering::SeqCst);
                if count >= expected || std::time::Instant::now() >= deadline {
                    return count;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    /// Whether the test upstream consumes each request's body (by its own
    /// independent reading of `Content-Length` / chunked) before answering, or
    /// answers as soon as the head ends.
    #[derive(Clone, Copy)]
    enum BodyRead {
        Framed,
        HeadOnly,
    }

    /// What a test upstream answers every request with. A `HEAD` request gets
    /// the head only, as a real server would.
    #[derive(Clone)]
    struct Script {
        body_read: BodyRead,
        reply_head: Vec<u8>,
        reply_body: Vec<u8>,
        close_after_reply: bool,
    }

    impl Script {
        /// A keep-alive `200` with a fixed `Content-Length` body.
        fn ok(body: &str) -> Self {
            Self {
                body_read: BodyRead::Framed,
                reply_head: format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .into_bytes(),
                reply_body: body.as_bytes().to_vec(),
                close_after_reply: false,
            }
        }

        /// Raw reply bytes written as soon as a head ends; the body is never
        /// read.
        fn raw(reply_head: &[u8], reply_body: &[u8], close_after_reply: bool) -> Self {
            Self {
                body_read: BodyRead::HeadOnly,
                reply_head: reply_head.to_vec(),
                reply_body: reply_body.to_vec(),
                close_after_reply,
            }
        }
    }

    /// A scripted HTTP/1.1 upstream on an ephemeral loopback port, recording
    /// what it sees into the returned [`Captured`].
    fn spawn_upstream(script: Script) -> (u16, Arc<Captured>) {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(Captured::default());
        let seen = Arc::clone(&captured);
        thread::Builder::new()
            .spawn(move || {
                for conn in listener.incoming() {
                    let Ok(conn) = conn else { continue };
                    seen.connections.fetch_add(1, Ordering::SeqCst);
                    let seen = Arc::clone(&seen);
                    let script = script.clone();
                    thread::Builder::new()
                        .spawn(move || {
                            serve_scripted(conn, &script, &seen);
                            seen.closed.fetch_add(1, Ordering::SeqCst);
                        })
                        .expect("spawn test thread");
                }
            })
            .expect("spawn test thread");
        (port, captured)
    }

    /// One upstream connection: consume requests per the script, record their
    /// bytes, reply; return when the peer closes or the script says so.
    fn serve_scripted(mut conn: TcpStream, script: &Script, captured: &Captured) {
        let mut reader = BufReader::new(conn.try_clone().unwrap());
        loop {
            let Ok(Some(mut seen)) = read_head_block(&mut reader) else {
                return;
            };
            let is_head_request = seen.starts_with(b"HEAD ");
            if matches!(script.body_read, BodyRead::Framed)
                && read_body_into(&mut reader, &mut seen).is_none()
            {
                return;
            }
            captured.bytes.lock().unwrap().extend_from_slice(&seen);
            if conn.write_all(&script.reply_head).is_err() {
                return;
            }
            if !is_head_request && conn.write_all(&script.reply_body).is_err() {
                return;
            }
            if script.close_after_reply {
                return;
            }
        }
    }

    /// The test upstream's own body reader (independent of the proxy's):
    /// `Content-Length` bytes, or chunks through the trailer's blank line.
    fn read_body_into(reader: &mut BufReader<TcpStream>, seen: &mut Vec<u8>) -> Option<()> {
        let head = String::from_utf8_lossy(seen).to_ascii_lowercase();
        if let Some(len) = header_value(&head, "content-length:") {
            let mut body = vec![0u8; len.trim().parse().ok()?];
            reader.read_exact(&mut body).ok()?;
            seen.extend_from_slice(&body);
            return Some(());
        }
        if !header_value(&head, "transfer-encoding:").is_some_and(|v| v.contains("chunked")) {
            return Some(());
        }
        loop {
            let mut size_line = Vec::new();
            if read_line_capped(reader, &mut size_line, 64 * 1024).ok()? == 0 {
                return None;
            }
            seen.extend_from_slice(&size_line);
            let text = String::from_utf8_lossy(&size_line);
            let size = usize::from_str_radix(text.split(';').next()?.trim(), 16).ok()?;
            if size == 0 {
                loop {
                    let mut trailer = Vec::new();
                    if read_line_capped(reader, &mut trailer, 64 * 1024).ok()? == 0 {
                        return None;
                    }
                    seen.extend_from_slice(&trailer);
                    if trailer == b"\r\n" {
                        return Some(());
                    }
                }
            }
            let mut data = vec![0u8; size + 2];
            reader.read_exact(&mut data).ok()?;
            seen.extend_from_slice(&data);
        }
    }

    fn header_value<'a>(head: &'a str, name_colon: &str) -> Option<&'a str> {
        head.lines().find_map(|line| line.strip_prefix(name_colon))
    }

    fn spawn_fixed_upstream(body: &str) -> u16 {
        spawn_upstream(Script::ok(body)).0
    }

    fn connect(port: u16) -> TcpStream {
        let stream = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
    }

    /// Read one response (head, then its `Content-Length` body) from `reader`.
    fn read_response(reader: &mut BufReader<TcpStream>) -> Option<(Vec<u8>, Vec<u8>)> {
        let head = read_head_block(reader).ok()??;
        let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
        let len =
            header_value(&text, "content-length:").map_or(Some(0), |v| v.trim().parse().ok())?;
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).ok()?;
        Some((head, body))
    }

    fn get_body_on(stream: &mut TcpStream) -> Option<String> {
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .ok()?;
        let mut reader = BufReader::new(stream.try_clone().ok()?);
        let (_head, body) = read_response(&mut reader)?;
        Some(String::from_utf8_lossy(&body).into_owned())
    }

    /// Send `raw` on a fresh connection, half-close, and read until the proxy
    /// closes. `closed` is false when the read timed out instead.
    fn send_raw(port: u16, raw: &[u8]) -> (Vec<u8>, bool) {
        let mut client = connect(port);
        let _ = client.write_all(raw);
        let _ = client.shutdown(Shutdown::Write);
        let mut reply = Vec::new();
        let closed = client.read_to_end(&mut reply).is_ok();
        (reply, closed)
    }

    /// Bind the proxy on a known-free ephemeral port: learn one by binding a
    /// throwaway listener, then drop it and hand the port to the proxy.
    fn bind_proxy_on_free_port() -> DevProxy {
        let scratch = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let proxy_port = scratch.local_addr().unwrap().port();
        drop(scratch);
        DevProxy::bind(proxy_port).unwrap()
    }

    /// A proxy routed to a fresh upstream running `script`.
    fn proxy_over(script: Script) -> (DevProxy, Arc<Captured>) {
        let (upstream_port, captured) = spawn_upstream(script);
        let proxy = bind_proxy_on_free_port();
        proxy.set_upstream(upstream_port);
        (proxy, captured)
    }

    const PROBE: &[u8] = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";

    /// Drive one raw request at a live proxy and assert the refusal contract:
    /// the proxy's own `400`, a closed connection, and an upstream that saw
    /// exactly one connection carrying only the probe `GET` sent afterwards.
    fn assert_request_refused(raw: &[u8], phrase: &str) {
        let (proxy, captured) = proxy_over(Script::ok("ok"));
        let (reply, closed) = send_raw(proxy.port(), raw);
        let text = String::from_utf8_lossy(&reply);
        assert!(
            text.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{phrase}: expected the proxy's 400, got {text:?}"
        );
        assert!(
            text.contains(phrase),
            "{phrase}: refusal text missing in {text:?}"
        );
        assert_eq!(
            text.matches("HTTP/1.1 ").count(),
            1,
            "{phrase}: exactly one response, got {text:?}"
        );
        assert!(closed, "{phrase}: the connection must close after the 400");

        let mut probe = connect(proxy.port());
        assert_eq!(
            get_body_on(&mut probe).as_deref(),
            Some("ok"),
            "{phrase}: probe"
        );
        assert_eq!(
            captured.connections.load(Ordering::SeqCst),
            1,
            "{phrase}: the refused request must never open an upstream connection"
        );
        assert_eq!(
            captured.bytes(),
            PROBE.to_vec(),
            "{phrase}: the upstream must see only the probe"
        );
    }

    #[test]
    fn upstream_starts_unset_before_any_binary_is_ready() {
        let proxy = bind_proxy_on_free_port();
        assert_eq!(
            proxy.current_upstream(),
            0,
            "no upstream is routed until the first ready cutover"
        );
    }

    #[test]
    fn a_502_is_returned_before_any_upstream_is_ready() {
        let proxy = bind_proxy_on_free_port();
        let proxy_port = proxy.port();
        let mut client =
            TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], proxy_port))).unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .unwrap();
        let mut buf = Vec::new();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let _ = client.read_to_end(&mut buf);
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.starts_with("HTTP/1.1 502"),
            "a request before any upstream is ready must get a 502: {text}"
        );
    }

    #[test]
    fn proxy_forwards_to_the_current_upstream_and_survives_a_swap() {
        let up_a = spawn_fixed_upstream("VERSION-A");
        let up_b = spawn_fixed_upstream("VERSION-B");

        let proxy = bind_proxy_on_free_port();
        let proxy_port = proxy.port();
        proxy.set_upstream(up_a);

        // One persistent client socket, kept alive across the swap.
        let mut client =
            TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], proxy_port))).unwrap();

        let first = get_body_on(&mut client).expect("first request must succeed");
        assert_eq!(first, "VERSION-A", "routes to the initial upstream");

        // Cut over to the new upstream — the SAME client socket must keep
        // working and now see the new binary's response.
        proxy.set_upstream(up_b);
        let second = get_body_on(&mut client).expect("same socket must survive the swap");
        assert_eq!(
            second, "VERSION-B",
            "the kept-alive client socket routes to the NEW upstream after cutover"
        );
    }

    /// A malformed request degrades EXACTLY its own connection and never the
    /// accept loop — the standing pin for the "one bad connection can't take
    /// the proxy down" guarantee. Two hostile connections are driven against a
    /// live proxy: (1) a header block that runs past `MAX_REQUEST_HEADER_BYTES`
    /// without ever terminating, and (2) a `Transfer-Encoding: chunked` body
    /// with a non-hex (bad) chunk size. Each is expected to have its own
    /// connection closed/errored by the proxy; then a THIRD, well-formed
    /// request on a fresh connection must still be served cleanly — proving the
    /// accept loop kept running throughout.
    #[test]
    fn a_malformed_request_degrades_only_its_own_connection() {
        let upstream = spawn_fixed_upstream("CLEAN-OK");
        let proxy = bind_proxy_on_free_port();
        let proxy_port = proxy.port();
        proxy.set_upstream(upstream);
        let addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));

        // (1) Oversized header block: a valid request line, then header bytes
        // that never reach the terminating blank line, pushed well past the
        // 64 KiB cap. The proxy must reject (close) this connection rather than
        // buffer unboundedly. `write_all` may itself error once the peer half-
        // closes; either "write failed" or "read yields EOF" is an acceptable
        // observation of the degrade — what matters is it does not hang and
        // does not wedge the loop.
        {
            let mut bad = TcpStream::connect(addr).expect("connect for oversized header");
            bad.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = bad.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n");
            let filler = vec![b'a'; MAX_REQUEST_HEADER_BYTES + 4096];
            // A long header line with no CRLF: crosses the cap mid-line.
            let _ = bad.write_all(b"X-Huge: ");
            let _ = bad.write_all(&filler);
            // Whether the write fully lands or errors, the connection must end
            // (EOF) rather than serve a body — read to end and assert no
            // upstream body leaked through.
            let mut buf = Vec::new();
            let _ = bad.read_to_end(&mut buf);
            let text = String::from_utf8_lossy(&buf);
            assert!(
                !text.contains("CLEAN-OK"),
                "an oversized-header connection must never be routed to the upstream: {text:?}"
            );
        }

        // (2) Bad chunk size: a well-formed head declaring a chunked body, then
        // a non-hex chunk-size line. The chunk copy must fail on the malformed
        // size and close this connection — again, only this one.
        {
            let mut bad = TcpStream::connect(addr).expect("connect for bad chunk");
            bad.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = bad.write_all(
                b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            );
            // `zzzz` is not a hex chunk size.
            let _ = bad.write_all(b"zzzz\r\n");
            let mut buf = Vec::new();
            let _ = bad.read_to_end(&mut buf);
            let text = String::from_utf8_lossy(&buf);
            assert!(
                !text.contains("CLEAN-OK"),
                "a bad-chunk-size connection must not be served an upstream body: {text:?}"
            );
        }

        // (3) THE GUARANTEE: after both hostile connections, a fresh well-formed
        // request is still served cleanly — the accept loop survived.
        let mut good = TcpStream::connect(addr).expect("connect for the clean request");
        good.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let served = get_body_on(&mut good);
        assert_eq!(
            served.as_deref(),
            Some("CLEAN-OK"),
            "the accept loop must still serve a clean request after malformed ones: {served:?}"
        );
    }

    /// Poll `proxy`'s live-client count until it reaches `expected` or
    /// `timeout` elapses, returning the last-observed count. A bounded
    /// deadline-poll, not a flat sleep: the test that calls this needs to
    /// know the accept loop has actually reserved every slot before it opens
    /// the over-cap connection, not merely that some arbitrary delay passed.
    fn wait_until_live_clients(proxy: &DevProxy, expected: usize, timeout: Duration) -> usize {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let count = proxy.live_client_count();
            if count >= expected || std::time::Instant::now() >= deadline {
                return count;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// The standing pin for [`MAX_PROXY_CLIENTS`]: once that many connections
    /// are live, the next one is closed at once rather than queued or served
    /// by an unbounded extra worker thread.
    #[test]
    fn a_connection_past_the_live_client_cap_is_closed_at_once() {
        let proxy = bind_proxy_on_free_port();
        let proxy_port = proxy.port();
        let addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));

        let mut idle = Vec::with_capacity(MAX_PROXY_CLIENTS);
        for _ in 0..MAX_PROXY_CLIENTS {
            idle.push(TcpStream::connect(addr).expect("connect idle client"));
        }
        let reached = wait_until_live_clients(&proxy, MAX_PROXY_CLIENTS, Duration::from_secs(5));
        assert_eq!(
            reached, MAX_PROXY_CLIENTS,
            "every idle connection must be reserved a live-client slot before the cap test proceeds"
        );

        let mut over_cap = TcpStream::connect(addr).expect("connect over-cap client");
        over_cap
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buf = [0u8; 1];
        let n = over_cap
            .read(&mut buf)
            .expect("must see EOF, not a timeout");
        assert_eq!(
            n, 0,
            "a connection past MAX_PROXY_CLIENTS must be closed at once"
        );

        drop(idle);
    }

    // ---- the framing grammar: every refusal, by variant ------------------

    /// `Head::parse` names the exact refusal for every request head shape the
    /// upstream server would frame differently or reject.
    #[test]
    fn request_head_refusals_by_variant() {
        let cases: &[(&[u8], FramingRefusal)] = &[
            (
                b"POST / HTTP/1.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
                FramingRefusal::LengthWithTransferEncoding,
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
                FramingRefusal::DuplicateContentLength,
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
                FramingRefusal::DuplicateContentLength,
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: 5, 6\r\n\r\n",
                FramingRefusal::DuplicateContentLength,
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: 5, 5\r\n\r\n",
                FramingRefusal::DuplicateContentLength,
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length : 5\r\n\r\n",
                FramingRefusal::SpaceBeforeColon,
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: +5\r\n\r\n",
                FramingRefusal::ContentLengthNotDigits,
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: -0\r\n\r\n",
                FramingRefusal::ContentLengthNotDigits,
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length:\r\n\r\n",
                FramingRefusal::ContentLengthNotDigits,
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: 12345678901234567890\r\n\r\n",
                FramingRefusal::ContentLengthTooLong,
            ),
            (
                b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked, identity\r\n\r\n",
                FramingRefusal::TransferEncodingNotFinalChunked,
            ),
            (
                b"POST / HTTP/1.1\r\nTransfer-Encoding: xchunkedx\r\n\r\n",
                FramingRefusal::TransferEncodingNotFinalChunked,
            ),
            (
                b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
                FramingRefusal::TransferEncodingNotFinalChunked,
            ),
            (
                b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked, chunked\r\n\r\n",
                FramingRefusal::TransferEncodingNotFinalChunked,
            ),
            (
                b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
                FramingRefusal::DuplicateTransferEncoding,
            ),
        ];
        for (raw, expected) in cases {
            let parsed = Head::<RequestStart>::parse(raw.to_vec()).map(|head| head.framing);
            assert_eq!(parsed, Err(*expected), "{}", String::from_utf8_lossy(raw));
        }
    }

    /// `Head::parse` names the exact refusal for every malformed line shape.
    #[test]
    fn request_head_line_refusals_by_variant() {
        let cases: &[(&[u8], FramingRefusal)] = &[
            (
                b"GET / HTTP/1.1\r\nHost: h\r\n continued\r\n\r\n",
                FramingRefusal::ObsFold,
            ),
            (
                b"GET / HTTP/1.1\r\nHost h\r\n\r\n",
                FramingRefusal::LineWithoutColon,
            ),
            (
                b"GET / HTTP/1.1\r\n: h\r\n\r\n",
                FramingRefusal::HeaderNameNotToken,
            ),
            (
                b"GET / HTTP/1.1\r\nHo\"st: h\r\n\r\n",
                FramingRefusal::HeaderNameNotToken,
            ),
            (
                b"\r\nGET / HTTP/1.1\r\n\r\n",
                FramingRefusal::MissingStartLine,
            ),
            (b" GET / HTTP/1.1\r\n\r\n", FramingRefusal::MissingStartLine),
            (
                b"GET / HTTP/1.1\r\nX: a\x01b\r\n\r\n",
                FramingRefusal::HeaderValueInvalidByte,
            ),
            (
                b"GET / HTTP/1.1\r\nX: a\rb\r\n\r\n",
                FramingRefusal::HeaderValueInvalidByte,
            ),
            (
                b"GET / HTTP/1.1\r\nX: a\x7fb\r\n\r\n",
                FramingRefusal::HeaderValueInvalidByte,
            ),
            (
                b"GET / HTTP/1.1\r\nX: a\x00\r\n\r\n",
                FramingRefusal::HeaderValueInvalidByte,
            ),
            (
                b"POST / HTTP/1.1\r\nTransfer-Encoding: g\xc3zip, chunked\r\n\r\n",
                FramingRefusal::TransferEncodingNotFinalChunked,
            ),
        ];
        for (raw, expected) in cases {
            let parsed = Head::<RequestStart>::parse(raw.to_vec()).map(|head| head.framing);
            assert_eq!(parsed, Err(*expected), "{}", String::from_utf8_lossy(raw));
        }
    }

    /// The admitted request grammar frames exactly as the upstream does.
    #[test]
    fn request_head_admitted_shapes() {
        let cases: &[(&[u8], BodyFraming, bool)] = &[
            (
                b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
                BodyFraming::None,
                false,
            ),
            (
                b"POST / HTTP/1.1\r\ncontent-length:7\r\n\r\n",
                BodyFraming::Length(7),
                false,
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: \t 9999999999999999999 \r\n\r\n",
                BodyFraming::Length(9_999_999_999_999_999_999),
                false,
            ),
            (
                b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n",
                BodyFraming::Chunked,
                false,
            ),
            (
                b"GET / HTTP/1.1\nHost: h\nConnection: keep-alive, Close\n\n",
                BodyFraming::None,
                true,
            ),
            (
                b"GET / HTTP/1.1\r\nConnection: not-close-at-all\r\n\r\n",
                BodyFraming::None,
                false,
            ),
            (
                b"GET / HTTP/1.1\r\nX-Name: caf\xc3\xa9\t!\r\n\r\n",
                BodyFraming::None,
                false,
            ),
        ];
        for (raw, framing, close) in cases {
            let head = Head::<RequestStart>::parse(raw.to_vec());
            assert!(head.is_ok(), "{}", String::from_utf8_lossy(raw));
            let Ok(head) = head else { return };
            assert_eq!(head.framing, *framing, "{}", String::from_utf8_lossy(raw));
            assert_eq!(
                head.connection_close,
                *close,
                "{}",
                String::from_utf8_lossy(raw)
            );
            assert_eq!(head.raw, raw.to_vec(), "raw bytes are kept verbatim");
        }
    }

    /// A response head reads its status class from the start line and treats a
    /// transfer-encoding without a final `chunked` as close-delimited.
    #[test]
    fn response_head_shapes() {
        let cases: &[(&[u8], Result<ResponseStatus, FramingRefusal>)] = &[
            (
                b"HTTP/1.1 100 Continue\r\n\r\n",
                Ok(ResponseStatus::Interim),
            ),
            (
                b"HTTP/1.1 103 Early Hints\r\n\r\n",
                Ok(ResponseStatus::Interim),
            ),
            (
                b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
                Ok(ResponseStatus::Final(FinalStatus::SwitchingProtocols)),
            ),
            (
                b"HTTP/1.1 204 No Content\r\n\r\n",
                Ok(ResponseStatus::Final(FinalStatus::NoBody)),
            ),
            (
                b"HTTP/1.1 304 Not Modified\r\n\r\n",
                Ok(ResponseStatus::Final(FinalStatus::NoBody)),
            ),
            (
                b"HTTP/1.1 200 OK\r\n\r\n",
                Ok(ResponseStatus::Final(FinalStatus::Body)),
            ),
            (
                b"HTTP/1.1 20 OK\r\n\r\n",
                Err(FramingRefusal::MalformedStatusLine),
            ),
            (
                b"HTTP/1.1 2000 OK\r\n\r\n",
                Err(FramingRefusal::MalformedStatusLine),
            ),
            (
                b"HTTP/1.1 2x0 OK\r\n\r\n",
                Err(FramingRefusal::MalformedStatusLine),
            ),
            (
                b"HTTP/1.1\r\n\r\n",
                Err(FramingRefusal::MalformedStatusLine),
            ),
        ];
        for (raw, expected) in cases {
            let parsed = Head::<ResponseStart>::parse(raw.to_vec()).map(|head| head.start.status);
            assert_eq!(parsed, *expected, "{}", String::from_utf8_lossy(raw));
        }
        let gzip = Head::<ResponseStart>::parse(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n".to_vec(),
        );
        assert!(gzip.as_ref().is_ok_and(|head| {
            head.framing == BodyFraming::None
                && head.start.status == ResponseStatus::Final(FinalStatus::Body)
        }));
        let both = Head::<ResponseStart>::parse(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
        )
        .map(|head| head.framing);
        assert_eq!(both, Err(FramingRefusal::LengthWithTransferEncoding));
    }

    /// Chunk-size lines: hex digits, an optional extension, CRLF — nothing else.
    #[test]
    fn chunk_size_lines() {
        assert_eq!(parse_chunk_size(b"5\r\n"), Ok(5));
        assert_eq!(parse_chunk_size(b"1F;ext=1\r\n"), Ok(31));
        assert_eq!(parse_chunk_size(b"ffffffffffffffff\r\n"), Ok(u64::MAX));
        for bad in [
            &b"5\n"[..],
            b"\r\n",
            b" 5\r\n",
            b"zzzz\r\n",
            b"+5\r\n",
            b"1ffffffffffffffff\r\n",
            b";ext\r\n",
            b"5;a\rb\r\n",
            b"5\r\r\n",
        ] {
            assert_eq!(
                parse_chunk_size(bad),
                Err(FramingRefusal::MalformedChunkSize),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    // ---- request-side refusals on the wire ------------------------------

    #[test]
    fn length_with_chunked_is_refused() {
        assert_request_refused(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
            FramingRefusal::LengthWithTransferEncoding.text(),
        );
    }

    #[test]
    fn two_content_lengths_are_refused() {
        assert_request_refused(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
            FramingRefusal::DuplicateContentLength.text(),
        );
        assert_request_refused(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
            FramingRefusal::DuplicateContentLength.text(),
        );
    }

    #[test]
    fn space_before_colon_is_refused() {
        assert_request_refused(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length : 5\r\n\r\nhello",
            FramingRefusal::SpaceBeforeColon.text(),
        );
    }

    #[test]
    fn signed_content_length_is_refused() {
        assert_request_refused(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: +5\r\n\r\nhello",
            FramingRefusal::ContentLengthNotDigits.text(),
        );
        assert_request_refused(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: -0\r\n\r\n",
            FramingRefusal::ContentLengthNotDigits.text(),
        );
    }

    #[test]
    fn content_length_list_is_refused() {
        assert_request_refused(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5, 6\r\n\r\nhello",
            FramingRefusal::DuplicateContentLength.text(),
        );
        assert_request_refused(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5, 5\r\n\r\nhello",
            FramingRefusal::DuplicateContentLength.text(),
        );
    }

    #[test]
    fn twenty_digit_content_length_is_refused() {
        assert_request_refused(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 12345678901234567890\r\n\r\n",
            FramingRefusal::ContentLengthTooLong.text(),
        );
    }

    #[test]
    fn transfer_encoding_not_final_chunked_is_refused() {
        for value in ["chunked, identity", "xchunkedx", "gzip"] {
            let raw = format!("POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: {value}\r\n\r\n");
            assert_request_refused(
                raw.as_bytes(),
                FramingRefusal::TransferEncodingNotFinalChunked.text(),
            );
        }
    }

    #[test]
    fn obs_fold_is_refused() {
        assert_request_refused(
            b"GET / HTTP/1.1\r\nHost: h\r\n continued\r\n\r\n",
            FramingRefusal::ObsFold.text(),
        );
    }

    #[test]
    fn header_without_colon_is_refused() {
        assert_request_refused(
            b"GET / HTTP/1.1\r\nHost h\r\n\r\n",
            FramingRefusal::LineWithoutColon.text(),
        );
    }

    /// The smuggling instance: a `Content-Length: 0` beside a chunked body that
    /// carries a second request. The proxy answers one `400` and the upstream
    /// never sees `GET /other`.
    #[test]
    fn smuggled_request_in_chunked_body_never_reaches_upstream() {
        assert_request_refused(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n\
              2d\r\nGET /other HTTP/1.1\r\nHost: h\r\nX: y\r\n\r\n0\r\n\r\n",
            FramingRefusal::LengthWithTransferEncoding.text(),
        );
    }

    /// Drive a chunked request whose body the proxy refuses mid-copy: the head
    /// is already forwarded, so no `400` — both connections close and no
    /// response is relayed.
    fn assert_mid_body_refused(raw: &[u8], what: &str) {
        let (proxy, captured) = proxy_over(Script::raw(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n",
            b"ok",
            false,
        ));
        let (reply, closed) = send_raw(proxy.port(), raw);
        assert!(closed, "{what}: the client connection must close");
        assert!(
            reply.is_empty(),
            "{what}: no response may be relayed after a mid-body refusal: {:?}",
            String::from_utf8_lossy(&reply)
        );
        assert_eq!(
            captured.wait_closed(1),
            1,
            "{what}: the upstream connection must close too"
        );
    }

    /// Chunk data must be followed by CRLF; anything else closes both.
    #[test]
    fn chunk_without_crlf_terminator_closes_both() {
        assert_mid_body_refused(
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello!!\r\n0\r\n\r\n",
            "chunk data without CRLF",
        );
    }

    /// `0\r\n` then EOF is a truncated trailer: an error, never a completed body.
    #[test]
    fn truncated_trailer_is_an_error() {
        assert_mid_body_refused(
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n",
            "truncated trailer",
        );
    }

    /// A trailer line that is not header-shaped, or carries a bare CR, closes
    /// both rather than completing the body.
    #[test]
    fn malformed_trailer_line_closes_both() {
        assert_mid_body_refused(
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nnot a header\r\n\r\n",
            "trailer line without a colon",
        );
        assert_mid_body_refused(
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: a\rb\r\n\r\n",
            "trailer line with a bare CR",
        );
    }

    /// `Connection` is a token list: `close` among the tokens closes after the
    /// response, a token merely containing `close` does not.
    #[test]
    fn connection_close_is_a_token() {
        let (proxy, _captured) = proxy_over(Script::ok("ok"));
        let (reply, closed) = send_raw(
            proxy.port(),
            b"GET / HTTP/1.1\r\nHost: h\r\nConnection: keep-alive, close\r\n\r\n",
        );
        assert!(String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 200 OK"));
        assert!(closed, "`close` among the tokens closes after the response");

        let mut client = connect(proxy.port());
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: h\r\nConnection: unclose\r\n\r\n")
            .unwrap();
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let first = read_response(&mut reader).expect("first response");
        assert_eq!(first.1, b"ok");
        assert_eq!(
            get_body_on(&mut client).as_deref(),
            Some("ok"),
            "a token merely containing `close` keeps the connection alive"
        );
    }

    /// A well-formed chunked request reaches the upstream byte-identical,
    /// extensions and trailer included.
    #[test]
    fn chunked_request_is_relayed_intact() {
        let (proxy, captured) = proxy_over(Script::ok("ok"));
        let request: &[u8] = b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n\
                               5;ext=1\r\nhello\r\n0\r\nX-Trailer: v\r\n\r\n";
        let mut client = connect(proxy.port());
        client.write_all(request).unwrap();
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let (_head, body) = read_response(&mut reader).expect("response");
        assert_eq!(body, b"ok");
        assert_eq!(captured.bytes(), request.to_vec());
    }

    // ---- response-side refusals and framing ------------------------------

    /// Drive a probe `GET` at a proxy over `script`; assert the proxy's own
    /// `502`, a closed connection, and not one upstream byte relayed.
    fn assert_response_refused(script: Script, phrase: &str) {
        let (proxy, _captured) = proxy_over(script);
        let (reply, closed) = send_raw(proxy.port(), PROBE);
        let text = String::from_utf8_lossy(&reply);
        assert!(
            text.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
            "{phrase}: expected the proxy's 502, got {text:?}"
        );
        assert!(
            text.contains(phrase),
            "{phrase}: refusal text missing in {text:?}"
        );
        assert_eq!(
            text.matches("HTTP/1.1 ").count(),
            1,
            "{phrase}: upstream bytes leaked: {text:?}"
        );
        assert!(closed, "{phrase}: the connection must close after the 502");
    }

    #[test]
    fn switching_protocols_is_refused() {
        assert_response_refused(
            Script::raw(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                b"\x81\x02hi",
                false,
            ),
            FramingRefusal::ProtocolUpgrade.text(),
        );
    }

    #[test]
    fn malformed_status_line_is_refused() {
        assert_response_refused(
            Script::raw(b"HTTP/1.1 20 OK\r\nContent-Length: 2\r\n\r\n", b"ok", false),
            FramingRefusal::MalformedStatusLine.text(),
        );
    }

    /// A `100 Continue` is relayed head-only, the final response after it,
    /// and the socket stays in step for the next exchange.
    #[test]
    fn interim_response_is_relayed_before_the_final_one() {
        let (proxy, _captured) = proxy_over(Script::raw(
            b"HTTP/1.1 100 Continue\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            false,
        ));
        let mut client = connect(proxy.port());
        let mut reader = BufReader::new(client.try_clone().unwrap());
        for exchange in ["first", "second"] {
            client.write_all(PROBE).unwrap();
            let interim = read_head_block(&mut reader).unwrap().expect("interim head");
            assert_eq!(
                interim,
                b"HTTP/1.1 100 Continue\r\n\r\n".to_vec(),
                "{exchange}"
            );
            let (head, body) = read_response(&mut reader).expect("final response");
            assert!(head.starts_with(b"HTTP/1.1 200 OK\r\n"), "{exchange}");
            assert_eq!(body, b"ok", "{exchange}");
        }
    }

    /// More interim responses than [`MAX_INTERIM_RESPONSES`] end in the
    /// proxy's `502`, never the upstream's final response.
    #[test]
    fn interim_flood_is_refused() {
        let interim: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
        let flood = interim.repeat(MAX_INTERIM_RESPONSES + 1);
        let (proxy, _captured) = proxy_over(Script::raw(
            &flood,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            false,
        ));
        let (reply, closed) = send_raw(proxy.port(), PROBE);
        let text = String::from_utf8_lossy(&reply);
        assert_eq!(
            text.matches("HTTP/1.1 100 Continue\r\n").count(),
            MAX_INTERIM_RESPONSES,
            "{text:?}"
        );
        assert!(
            text.contains(FramingRefusal::TooManyInterimResponses.text())
                && text.contains("HTTP/1.1 502 Bad Gateway\r\n"),
            "{text:?}"
        );
        assert!(!text.contains("200 OK"), "{text:?}");
        assert!(closed);
    }

    // ---- start-line and header-value bytes on the wire -------------------

    /// Empty lines before a request line are skipped as the server skips
    /// them, and never forwarded.
    #[test]
    fn leading_empty_lines_are_skipped_not_forwarded() {
        let (proxy, captured) = proxy_over(Script::ok("ok"));
        let mut client = connect(proxy.port());
        client.write_all(b"\r\n\n").unwrap();
        assert_eq!(get_body_on(&mut client).as_deref(), Some("ok"));
        assert_eq!(captured.bytes(), PROBE.to_vec());
    }

    /// A connection that sends only empty lines and closes never reaches the
    /// upstream, and its worker returns.
    #[test]
    fn blank_lines_only_never_reach_upstream() {
        let (proxy, captured) = proxy_over(Script::ok("ok"));
        let (reply, closed) = send_raw(proxy.port(), b"\r\n\r\n\n");
        assert!(reply.is_empty(), "{:?}", String::from_utf8_lossy(&reply));
        assert!(closed, "the proxy must close, not wait on the upstream");
        let mut probe = connect(proxy.port());
        assert_eq!(get_body_on(&mut probe).as_deref(), Some("ok"));
        assert_eq!(captured.connections.load(Ordering::SeqCst), 1);
        assert_eq!(captured.bytes(), PROBE.to_vec());
    }

    #[test]
    fn header_value_control_byte_is_refused() {
        assert_request_refused(
            b"GET / HTTP/1.1\r\nHost: h\r\nX: a\x01b\r\n\r\n",
            FramingRefusal::HeaderValueInvalidByte.text(),
        );
        assert_request_refused(
            b"GET / HTTP/1.1\r\nHost: h\r\nX: a\rb\r\n\r\n",
            FramingRefusal::HeaderValueInvalidByte.text(),
        );
    }

    #[test]
    fn response_length_with_chunked_is_refused() {
        assert_response_refused(
            Script::raw(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
                b"2\r\nok\r\n0\r\n\r\n",
                false,
            ),
            FramingRefusal::LengthWithTransferEncoding.text(),
        );
    }

    #[test]
    fn response_two_content_lengths_are_refused() {
        assert_response_refused(
            Script::raw(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n",
                b"ok!",
                false,
            ),
            FramingRefusal::DuplicateContentLength.text(),
        );
    }

    /// A response transfer-encoding without a final `chunked` is not refused:
    /// the body is copied until the upstream closes and the connection ends.
    #[test]
    fn response_transfer_encoding_gzip_is_close_delimited() {
        let (proxy, _captured) = proxy_over(Script::raw(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            b"GZIP-BYTES",
            true,
        ));
        let (reply, closed) = send_raw(proxy.port(), PROBE);
        assert_eq!(
            reply,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nGZIP-BYTES".to_vec()
        );
        assert!(
            closed,
            "a close-delimited response ends the client connection"
        );
    }

    /// A `Connection` token merely containing `close` on a response keeps the
    /// connection alive.
    #[test]
    fn response_connection_token_is_exact() {
        let (proxy, _captured) = proxy_over(Script::raw(
            b"HTTP/1.1 200 OK\r\nConnection: not-close-at-all\r\nContent-Length: 2\r\n\r\n",
            b"ok",
            false,
        ));
        let mut client = connect(proxy.port());
        assert_eq!(get_body_on(&mut client).as_deref(), Some("ok"));
        assert_eq!(
            get_body_on(&mut client).as_deref(),
            Some("ok"),
            "second request on the same socket"
        );
    }

    /// A response to `HEAD` carries no body whatever `Content-Length` says; the
    /// kept-alive socket answers the next request.
    #[test]
    fn head_response_carries_no_body() {
        let (proxy, _captured) = proxy_over(Script::raw(
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n",
            b"hello world",
            false,
        ));
        let mut client = connect(proxy.port());
        client
            .write_all(b"HEAD / HTTP/1.1\r\nHost: h\r\n\r\n")
            .unwrap();
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let head = read_head_block(&mut reader)
            .unwrap()
            .expect("HEAD response head");
        assert!(head.starts_with(b"HTTP/1.1 200 OK\r\n"));
        client.write_all(PROBE).unwrap();
        let (_head, body) = read_response(&mut reader).expect("GET after HEAD on the same socket");
        assert_eq!(body, b"hello world");
    }

    /// The production half of this file has exactly one reader of the framing
    /// headers: no byte-window search, no stringly parse, one spelling of each
    /// framing header name.
    #[test]
    fn proxy_has_one_framing_reader() {
        let source = include_str!("proxy.rs");
        let (production, tests) = source
            .split_once("#[cfg(test)]\nmod tests")
            .expect("test module marker");
        assert!(
            production.contains("fn parse(raw: Vec<u8>)") && tests.contains("fn read_body_into"),
            "the split must land between production and tests"
        );
        for banned in [
            "windows(",
            "parse::<",
            ".parse(",
            "from_utf8",
            "to_ascii_lowercase",
            "to_lowercase",
        ] {
            assert!(
                !production.contains(banned),
                "a second framing reader: `{banned}` in the production half"
            );
        }
        // Case-folded, so a second spelling (`b"Content-Length"`, a `&str`
        // literal) counts against the one site too.
        let folded = production.to_ascii_lowercase();
        for needle in [
            "\"content-length\"",
            "\"transfer-encoding\"",
            "\"chunked\"",
            "\"close\"",
        ] {
            assert_eq!(
                folded.matches(needle).count(),
                1,
                "`{needle}` must be judged at exactly one site"
            );
        }
    }
}

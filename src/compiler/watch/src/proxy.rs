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
//! Request framing handles the three HTTP/1.1 body-delimitation cases plus
//! the streaming (unbounded, upstream-closes-to-end) response case that SSE
//! and `/_ipe/sse` ride:
//! - a fixed `Content-Length` body (bounded copy),
//! - a `Transfer-Encoding: chunked` body (chunk-framed copy to the 0-chunk),
//! - no body (GET/HEAD and the like).
//!
//! A response with no `Content-Length` and no `chunked` framing (an SSE
//! stream, or any `Connection: close` response) is copied byte-for-byte until
//! the upstream half closes; that terminates the client keep-alive too (the
//! response has no self-delimiting length), which is the correct HTTP/1.1
//! behaviour and matches how a streaming response ends.
//!
//! ## Soundness
//!
//! `#![forbid(unsafe_code)]` (crate-level). Every accept/read/write failure
//! degrades a single connection, never the proxy: a per-connection worker
//! thread that errors simply returns, and the accept loop keeps serving. All
//! copy loops are bounded either by a declared length, by the chunk framing,
//! or by the upstream closing — never an unbounded in-memory buffer.

use std::io::{BufRead, BufReader, Read, Write};
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

/// Upper bound on one request's header block. A request whose headers exceed
/// this is rejected rather than buffered unboundedly — a memory-DoS guard on
/// the one part of the request the proxy must buffer to re-emit verbatim (the
/// bodies are streamed, never fully buffered).
const MAX_REQUEST_HEADER_BYTES: usize = 64 * 1024;

/// Copy-loop buffer size for streaming bodies/responses.
const COPY_BUF_BYTES: usize = 16 * 1024;

/// Upper bound on concurrently live per-client worker threads. Without a
/// cap, a local peer opening connections faster than they close could start
/// an unbounded number of OS threads (PRINCIPLES 3, bounded by construction).
/// A connection past the cap is closed at once rather than queued.
const MAX_PROXY_CLIENTS: usize = 256;

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
    pub fn bind(port: u16) -> std::io::Result<Self> {
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
fn serve_client(client: TcpStream, upstream: &Arc<AtomicU16>) -> std::io::Result<()> {
    client.set_read_timeout(Some(CLIENT_IDLE_TIMEOUT))?;
    let mut client_reader = BufReader::new(client.try_clone()?);
    let mut client_writer = client;

    loop {
        // Read one request's header block (request line + headers, up to the
        // blank line). An EOF here is the client closing the keep-alive
        // connection — a clean end, not an error.
        let Some(head) = read_head(&mut client_reader)? else {
            return Ok(());
        };

        let port = upstream.load(Ordering::SeqCst);
        if port == 0 {
            // No upstream is ready yet (pre-first-build). Answer directly so a
            // client that connects during the very first cold build gets a
            // definite response rather than a hang.
            write_502(&mut client_writer, "no upstream ready")?;
            // No body was consumed; a client that sent a body would desync, so
            // close rather than attempt another keep-alive request.
            return Ok(());
        }

        let upstream_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let Ok(mut upstream_conn) =
            TcpStream::connect_timeout(&upstream_addr, UPSTREAM_CONNECT_TIMEOUT)
        else {
            write_502(&mut client_writer, "upstream connect failed")?;
            return Ok(());
        };

        // Forward the request head verbatim, then its body per its framing.
        upstream_conn.write_all(&head.raw)?;
        forward_request_body(&head, &mut client_reader, &mut upstream_conn)?;
        upstream_conn.flush()?;

        // Relay the response back. `keep_alive` reports whether both sides may
        // reuse the connection for another request; if not (streaming response
        // or an explicit close), the loop ends after this response.
        let keep_alive = relay_response(&upstream_conn, &mut client_writer)?;
        if !keep_alive {
            return Ok(());
        }
    }
}

/// The parsed head of one HTTP/1.1 request: the raw header bytes (re-emitted
/// verbatim to the upstream) plus the framing facts the proxy needs to copy
/// the body.
struct RequestHead {
    raw: Vec<u8>,
    content_length: Option<u64>,
    chunked: bool,
}

/// Read one request's header block, returning `None` on a clean keep-alive EOF
/// (the client closed between requests).
fn read_head(reader: &mut BufReader<TcpStream>) -> std::io::Result<Option<RequestHead>> {
    let mut raw = Vec::new();
    let mut content_length: Option<u64> = None;
    let mut chunked = false;
    let mut first_line = true;

    loop {
        let mut line = Vec::new();
        let n = read_line_capped(reader, &mut line, MAX_REQUEST_HEADER_BYTES - raw.len())?;
        if n == 0 {
            // EOF. A clean end only if no partial request was buffered.
            if raw.is_empty() {
                return Ok(None);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed mid-request-head",
            ));
        }
        raw.extend_from_slice(&line);

        // The blank line (CRLF or bare LF) terminates the header block.
        let is_blank = line == b"\r\n" || line == b"\n";
        if is_blank && !first_line {
            return Ok(Some(RequestHead {
                raw,
                content_length,
                chunked,
            }));
        }
        if !first_line {
            parse_body_framing_header(&line, &mut content_length, &mut chunked);
        }
        first_line = false;
    }
}

/// Inspect one header line for the two body-framing headers the proxy cares
/// about. Case-insensitive on the header name (HTTP header names are
/// case-insensitive).
fn parse_body_framing_header(line: &[u8], content_length: &mut Option<u64>, chunked: &mut bool) {
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return;
    };
    let (name, rest) = line.split_at(colon);
    let value = trim_ascii(rest.get(1..).unwrap_or(&[]));

    if name.eq_ignore_ascii_case(b"content-length") {
        if let Ok(text) = std::str::from_utf8(value)
            && let Ok(len) = text.trim().parse::<u64>()
        {
            *content_length = Some(len);
        }
    } else if name.eq_ignore_ascii_case(b"transfer-encoding")
        && value
            .to_ascii_lowercase()
            .windows(7)
            .any(|w| w == b"chunked")
    {
        *chunked = true;
    }
}

/// Forward the request body to the upstream according to its framing.
fn forward_request_body(
    head: &RequestHead,
    client_reader: &mut BufReader<TcpStream>,
    upstream: &mut TcpStream,
) -> std::io::Result<()> {
    if let Some(len) = head.content_length {
        copy_exact(client_reader, upstream, len)?;
    } else if head.chunked {
        copy_chunked(client_reader, upstream)?;
    }
    // No body otherwise (GET/HEAD/etc.).
    Ok(())
}

/// Relay one HTTP/1.1 response from the upstream back to the client, framed by
/// the response's own headers. Returns whether the connection may be reused
/// for a subsequent keep-alive request.
///
/// A response the proxy cannot self-delimit (no `Content-Length`, not
/// `chunked`) is copied until the upstream closes — the SSE / `Connection:
/// close` case — and reports `false` (the connection ends with the stream).
fn relay_response(upstream: &TcpStream, client: &mut TcpStream) -> std::io::Result<bool> {
    let mut upstream_reader = BufReader::new(upstream.try_clone()?);

    let mut raw = Vec::new();
    let mut content_length: Option<u64> = None;
    let mut chunked = false;
    let mut connection_close = false;
    let mut status_no_body = false;
    let mut first_line = true;

    loop {
        let mut line = Vec::new();
        let n = read_line_capped(&mut upstream_reader, &mut line, MAX_REQUEST_HEADER_BYTES)?;
        if n == 0 {
            if raw.is_empty() {
                // Upstream closed with no response at all.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "upstream closed before responding",
                ));
            }
            break;
        }
        raw.extend_from_slice(&line);
        let is_blank = line == b"\r\n" || line == b"\n";
        if is_blank && !first_line {
            break;
        }
        if first_line {
            status_no_body = status_line_has_no_body(&line);
        } else {
            parse_body_framing_header(&line, &mut content_length, &mut chunked);
            if header_is_connection_close(&line) {
                connection_close = true;
            }
        }
        first_line = false;
    }

    client.write_all(&raw)?;

    if status_no_body {
        client.flush()?;
        return Ok(!connection_close);
    }
    if let Some(len) = content_length {
        copy_exact(&mut upstream_reader, client, len)?;
        client.flush()?;
        Ok(!connection_close)
    } else if chunked {
        copy_chunked(&mut upstream_reader, client)?;
        client.flush()?;
        Ok(!connection_close)
    } else {
        // No self-delimiting framing: stream until the upstream closes (SSE,
        // `Connection: close`). The connection ends with the stream.
        copy_until_eof(&mut upstream_reader, client)?;
        client.flush()?;
        Ok(false)
    }
}

/// A 1xx/204/304 status carries no response body regardless of headers.
fn status_line_has_no_body(line: &[u8]) -> bool {
    // "HTTP/1.1 204 ..." — find the status code token.
    let text = String::from_utf8_lossy(line);
    let mut parts = text.split_whitespace();
    let _version = parts.next();
    let Some(code) = parts.next() else {
        return false;
    };
    matches!(code, "204" | "304") || code.starts_with('1')
}

fn header_is_connection_close(line: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return false;
    };
    let (name, rest) = line.split_at(colon);
    if !name.eq_ignore_ascii_case(b"connection") {
        return false;
    }
    trim_ascii(rest.get(1..).unwrap_or(&[]))
        .to_ascii_lowercase()
        .windows(5)
        .any(|w| w == b"close")
}

/// Copy exactly `len` bytes from `src` to `dst`.
fn copy_exact(
    src: &mut BufReader<TcpStream>,
    dst: &mut impl Write,
    len: u64,
) -> std::io::Result<()> {
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed before the declared length was read",
            ));
        }
        let chunk = buf.get(..read).unwrap_or(&buf);
        dst.write_all(chunk)?;
        remaining -= read as u64;
    }
    Ok(())
}

/// Copy a `Transfer-Encoding: chunked` body verbatim, chunk by chunk, through
/// the terminating zero-length chunk and its trailer.
fn copy_chunked(src: &mut BufReader<TcpStream>, dst: &mut impl Write) -> std::io::Result<()> {
    loop {
        let mut size_line = Vec::new();
        let n = read_line_capped(src, &mut size_line, MAX_REQUEST_HEADER_BYTES)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed mid-chunk-size",
            ));
        }
        dst.write_all(&size_line)?;
        // The chunk size is the hex prefix before any `;` extension.
        let text = String::from_utf8_lossy(&size_line);
        let hex = text.split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(hex, 16).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed chunk size")
        })?;
        if size == 0 {
            // Copy the trailer (headers up to the final blank line) verbatim.
            loop {
                let mut line = Vec::new();
                let m = read_line_capped(src, &mut line, MAX_REQUEST_HEADER_BYTES)?;
                if m == 0 {
                    return Ok(());
                }
                dst.write_all(&line)?;
                if line == b"\r\n" || line == b"\n" {
                    return Ok(());
                }
            }
        }
        // Copy the chunk data plus its trailing CRLF.
        copy_exact(src, dst, size)?;
        let mut crlf = Vec::new();
        read_line_capped(src, &mut crlf, 4)?;
        dst.write_all(&crlf)?;
    }
}

/// Copy from `src` to `dst` until the source closes (EOF). Used for a response
/// with no self-delimiting framing (SSE / `Connection: close`).
fn copy_until_eof(src: &mut BufReader<TcpStream>, dst: &mut impl Write) -> std::io::Result<()> {
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
) -> std::io::Result<usize> {
    let mut total = 0;
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            return Ok(total);
        }
        if let Some(nl) = available.iter().position(|&b| b == b'\n') {
            let take = nl + 1;
            if total + take > cap {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "header line exceeds cap",
            ));
        }
        out.extend_from_slice(available);
        reader.consume(take);
        total += take;
    }
}

fn write_502(client: &mut TcpStream, reason: &str) -> std::io::Result<()> {
    let body = format!("502 Bad Gateway (ipe dev watch proxy): {reason}\n");
    let resp = format!(
        "HTTP/1.1 502 Bad Gateway\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(resp.as_bytes())?;
    client.flush()
}

/// `[u8]::trim_ascii` is stable but keeping a local mirror avoids an MSRV
/// coupling in this dependency-light crate; it trims ASCII whitespace on both
/// ends.
const fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = bytes {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny fixed-response HTTP/1.1 upstream: binds an ephemeral loopback
    /// port, answers each request on its own connection with `body`, and
    /// reports its port. Keep-alive is honoured (one connection can serve many
    /// requests) so the framing tests can reuse a client socket.
    fn spawn_fixed_upstream(body: &'static str) -> u16 {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::Builder::new()
            .spawn(move || {
                for conn in listener.incoming() {
                    let Ok(mut conn) = conn else { continue };
                    thread::Builder::new()
                        .spawn(move || {
                            let mut reader = BufReader::new(conn.try_clone().unwrap());
                            'conn: loop {
                                // Read one request head (up to the blank line). An
                                // EOF on the FIRST line is the client closing
                                // between requests.
                                let mut lines = 0usize;
                                loop {
                                    let mut line = Vec::new();
                                    let n =
                                        read_line_capped(&mut reader, &mut line, 64 * 1024)
                                            .unwrap();
                                    if n == 0 {
                                        if lines == 0 {
                                            return;
                                        }
                                        break 'conn;
                                    }
                                    lines += 1;
                                    if line == b"\r\n" || line == b"\n" {
                                        break;
                                    }
                                }
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                                    body.len()
                                );
                                if conn.write_all(resp.as_bytes()).is_err() {
                                    return;
                                }
                            }
                        })
                        .expect("spawn test thread");
                }
            })
            .expect("spawn test thread");
        port
    }

    fn get_body_on(stream: &mut TcpStream) -> Option<String> {
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .ok()?;
        // Read status + headers, then the Content-Length body.
        let mut reader = BufReader::new(stream.try_clone().ok()?);
        let mut content_length = 0usize;
        loop {
            let mut line = Vec::new();
            let n = read_line_capped(&mut reader, &mut line, 64 * 1024).ok()?;
            if n == 0 {
                return None;
            }
            if let Ok(text) = std::str::from_utf8(&line)
                && let Some(v) = text.strip_prefix("Content-Length:")
            {
                content_length = v.trim().parse().ok()?;
            }
            if line == b"\r\n" || line == b"\n" {
                break;
            }
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).ok()?;
        Some(String::from_utf8_lossy(&body).into_owned())
    }

    /// Bind the proxy on a known-free ephemeral port: learn one by binding a
    /// throwaway listener, then drop it and hand the port to the proxy.
    fn bind_proxy_on_free_port() -> DevProxy {
        let scratch = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let proxy_port = scratch.local_addr().unwrap().port();
        drop(scratch);
        DevProxy::bind(proxy_port).unwrap()
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
        // a non-hex chunk-size line. `copy_chunked` must fail on the malformed
        // size and close this connection — again, only this one.
        {
            let mut bad = TcpStream::connect(addr).expect("connect for bad chunk");
            bad.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = bad.write_all(
                b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            );
            // `zzzz` is not a hex chunk size — `u64::from_str_radix(.., 16)` fails.
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
}

//! The one loopback HTTP server: `ipe doc --serve` and a served `web client` bundle.
//!
//! A single-threaded, read-only HTTP/1.1 loop over a listener bound to
//! [`LOOPBACK`] only. Each connection's head is read under
//! [`REQUEST_HEAD_CAP`] and an [`IO_BUDGET`] wall-clock deadline, its target
//! authority is judged (an IP literal or a loopback name; a rebound DNS name
//! is a `421`), and the request is answered by a [`Site`] from bytes it
//! already holds. Every response leaves through [`write_reply`] with the
//! site's policy, `nosniff`, no referrer, `no-store` and `Connection: close`.
//!
//! A browser is opened only through the opener [`announce`] takes: the
//! production callers pass [`crate::browser::open_url`], and a test passes a
//! recording closure, so no test starts a browser.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

use ipe_runtime_rust::bundle_route::{MediaType, Route, route};
use ipe_runtime_rust::encoding::{BundlePath, MountBase};
use ipe_runtime_rust::env_grammar::{EnvRefusal, ListenPort};
use ipe_runtime_rust::inbound_authority::{Authority, AuthorityRefusal, DeclaredNames};

use crate::CliError;
use crate::browser::{BrowserOrigin, BrowserUrl, OpenOutcome};
use crate::text::{self, Message};

/// The one address every loopback listener binds: IPv4 loopback, never a parameter.
pub const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// The most bytes the server reads of one request head, request line and
/// headers together.
///
/// A few kilobytes covers any real head, and the cap turns a client that
/// streams bytes without ending its head into a bounded read rather than
/// unbounded buffer growth.
pub const REQUEST_HEAD_CAP: usize = 16 * 1024;

/// The wall-clock the server spends reading one request head, and again
/// writing one response, before it abandons the connection.
///
/// The bound is on the whole head and the whole response, not on each read or
/// write: a peer that never sends, drips a byte at a time, or never reads its
/// response stalls the one-connection-at-a-time loop briefly, never forever.
pub const IO_BUDGET: Duration = Duration::from_secs(10);

/// The fixed body of a `421` answered to a request whose host is not admitted.
pub const REFUSED_HOST_BODY: &str = r#"{"status":"host_not_admitted"}"#;

/// The status of one response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// `200`: the body is the named file.
    Ok,
    /// `400`: the head is not well-formed.
    BadRequest,
    /// `404`: the path names nothing the site holds.
    NotFound,
    /// `405`: the method is not `GET` or `HEAD`.
    MethodNotAllowed,
    /// `421`: the request's host is not admitted.
    Misdirected,
    /// `431`: the head fills [`REQUEST_HEAD_CAP`] without ending.
    HeadTooLarge,
}

impl Status {
    /// The status line's code and reason phrase.
    #[must_use]
    pub const fn line(self) -> &'static str {
        match self {
            Self::Ok => "200 OK",
            Self::BadRequest => "400 Bad Request",
            Self::NotFound => "404 Not Found",
            Self::MethodNotAllowed => "405 Method Not Allowed",
            Self::Misdirected => "421 Misdirected Request",
            Self::HeadTooLarge => "431 Request Header Fields Too Large",
        }
    }
}

/// A request's method, as the server tells them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// `GET`.
    Get,
    /// `HEAD`: answered as `GET`, with no body written.
    Head,
    /// Any other token.
    Other,
}

impl Method {
    /// The method a request line's first token names, case-sensitive.
    fn of(token: &str) -> Self {
        match token {
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            _ => Self::Other,
        }
    }
}

/// Whether a response may be framed by another page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// `X-Frame-Options: DENY`.
    Deny,
    /// No `X-Frame-Options` header: the policy alone governs framing.
    Policy,
}

/// The headers a site sets on every one of its responses.
#[derive(Clone, Copy, Debug)]
pub struct SiteHeaders<'s> {
    /// The `Content-Security-Policy` header value.
    pub csp: &'s str,
    /// Whether the response may be framed.
    pub framing: Framing,
}

/// One answer a [`Site`] gives.
#[derive(Clone, Copy, Debug)]
pub struct Reply<'s> {
    /// The status.
    pub status: Status,
    /// The `Content-Type` header value.
    pub content_type: &'static str,
    /// The body bytes.
    pub body: &'s [u8],
}

impl Reply<'static> {
    /// The plain-text answer `status` carries with `body`.
    const fn plain(status: Status, body: &'static str) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.as_bytes(),
        }
    }
}

/// What a loopback server answers from: bytes it already holds.
pub trait Site {
    /// The headers every response of this site carries.
    fn headers(&self) -> SiteHeaders<'_>;

    /// The answer to an admitted request for `path` (the request target's
    /// path, its query and fragment included).
    fn respond(&self, method: Method, path: &str) -> Reply<'_>;
}

/// Serve `site` on `listener`, one connection at a time, until the process ends.
///
/// A single dropped connection must not take the server down; `flatten` skips
/// the `Err`s and serves each accepted stream. `budget` bounds each
/// connection's head read and response write, each in wall-clock.
pub fn serve_site<S: Site + ?Sized>(listener: &TcpListener, site: &S, budget: Duration) {
    for conn in listener.incoming().flatten() {
        serve_one(&conn, site, budget);
    }
}

/// Serve one HTTP/1.1 request from `site`, read-only.
///
/// Reads the request head under [`REQUEST_HEAD_CAP`] and a `budget` deadline,
/// judges the request's target authority, and writes, under a fresh `budget`
/// deadline, the site's answer, a `421` when the host is not admitted, a `431`
/// for a head past the cap, or a `400` for a malformed one. The body, if any,
/// is ignored (nothing here writes or executes).
pub fn serve_one<S: Site + ?Sized>(conn: &TcpStream, site: &S, budget: Duration) {
    use std::io::{BufReader, Read};

    let Some(deadline) = Instant::now().checked_add(budget) else {
        return;
    };
    let mut reader = BufReader::new(DeadlineConn { conn, deadline }.take(REQUEST_HEAD_CAP as u64));
    let (method, reply) = match read_head(&mut reader) {
        Err(HeadRefusal::Abandoned) => return,
        Err(HeadRefusal::TooLarge) => (
            Method::Get,
            Reply::plain(Status::HeadTooLarge, "request head too large\n"),
        ),
        Err(HeadRefusal::Malformed) => (
            Method::Get,
            Reply::plain(Status::BadRequest, "malformed request head\n"),
        ),
        Ok(head) => match head.admitted_path() {
            Ok(Some(path)) => (head.method, site.respond(head.method, path)),
            Ok(None) | Err(_) => (
                head.method,
                Reply {
                    status: Status::Misdirected,
                    content_type: "application/json",
                    body: REFUSED_HOST_BODY.as_bytes(),
                },
            ),
        },
    };
    let Some(deadline) = Instant::now().checked_add(budget) else {
        return;
    };
    let _ = write_reply(
        &mut DeadlineConn { conn, deadline },
        site.headers(),
        method,
        &reply,
    );
}

/// The head of a complete HTTP/1.1 response whose body is `len` bytes.
///
/// Every status and content type carries the site's policy, `nosniff`, no
/// referrer, the site's framing, an explicit `Content-Length`, a
/// `Connection: close` (the loop serves one request per connection), and
/// `Cache-Control: no-store` (the site is a live preview held in memory). A
/// `405` names the methods served.
#[must_use]
pub fn response_head(
    headers: SiteHeaders<'_>,
    status: Status,
    content_type: &str,
    len: usize,
) -> String {
    let allow = if status == Status::MethodNotAllowed {
        "Allow: GET, HEAD\r\n"
    } else {
        ""
    };
    let framing = match headers.framing {
        Framing::Deny => "X-Frame-Options: DENY\r\n",
        Framing::Policy => "",
    };
    format!(
        "HTTP/1.1 {}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {len}\r\nCache-Control: no-store\r\n\
         Content-Security-Policy: {}\r\nX-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\n{framing}{allow}\
         Connection: close\r\n\r\n",
        status.line(),
        headers.csp,
    )
}

/// Write `reply` to `out`: the one sink every served byte leaves through.
///
/// A `HEAD` request gets the head alone, its `Content-Length` the body's.
///
/// # Errors
/// The write's own error.
pub fn write_reply<W: std::io::Write>(
    out: &mut W,
    headers: SiteHeaders<'_>,
    method: Method,
    reply: &Reply<'_>,
) -> std::io::Result<()> {
    let head = response_head(headers, reply.status, reply.content_type, reply.body.len());
    out.write_all(head.as_bytes())?;
    if method != Method::Head {
        out.write_all(reply.body)?;
    }
    out.flush()
}

/// One connection's socket under a wall-clock deadline: each read or write
/// waits at most the time left, and none starts once the deadline has passed.
struct DeadlineConn<'a> {
    conn: &'a TcpStream,
    deadline: Instant,
}

impl DeadlineConn<'_> {
    /// The time left before the deadline.
    ///
    /// # Errors
    ///
    /// [`std::io::ErrorKind::TimedOut`] once the deadline has passed.
    fn time_left(&self) -> std::io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err(std::io::ErrorKind::TimedOut.into())
        } else {
            Ok(left)
        }
    }
}

impl std::io::Read for DeadlineConn<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.conn.set_read_timeout(Some(self.time_left()?))?;
        let mut conn = self.conn;
        std::io::Read::read(&mut conn, buf)
    }
}

impl std::io::Write for DeadlineConn<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.conn.set_write_timeout(Some(self.time_left()?))?;
        let mut conn = self.conn;
        std::io::Write::write(&mut conn, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut conn = self.conn;
        std::io::Write::flush(&mut conn)
    }
}

/// The `Host` headers one request head carries.
#[derive(Debug, PartialEq, Eq)]
enum HostHeader {
    /// No `Host` header.
    Absent,
    /// Exactly one `Host` header, its value trimmed of optional whitespace.
    One(String),
    /// Two or more `Host` headers.
    Duplicate,
}

/// The parts of a request head the server acts on.
#[derive(Debug)]
struct RequestHead {
    /// The request line's method.
    method: Method,
    /// The request target, as the request line spells it.
    target: String,
    /// The head's `Host` headers.
    host: HostHeader,
}

/// Why a request head is not read to its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeadRefusal {
    /// The head fills [`REQUEST_HEAD_CAP`] without ending: `431`.
    TooLarge,
    /// A line is not UTF-8 or not a `name: value` header field: `400`.
    Malformed,
    /// The peer closed or stalled before ending the head: nothing is answered.
    Abandoned,
}

impl RequestHead {
    /// The path to serve, when the request's target authority is admitted.
    ///
    /// The server declares no DNS name, so only an IP literal or a loopback
    /// name admits: a rebound DNS name pointed at the loopback server is refused.
    ///
    /// # Errors
    ///
    /// The [`AuthorityRefusal`] of an absent, duplicated, disagreeing or
    /// malformed authority, or [`AuthorityRefusal::Malformed`] for a target in
    /// neither origin nor absolute form; `Ok(None)` for an undeclared DNS name.
    fn admitted_path(&self) -> Result<Option<&str>, AuthorityRefusal> {
        let (path, target_authority) = split_request_target(&self.target)?;
        let authority = request_authority(target_authority, &self.host)?;
        Ok(DeclaredNames::none()
            .admits(authority.host())
            .then_some(path))
    }
}

/// Split a request target into the path to serve and the authority it names.
///
/// Origin form (`/path`) names no authority; absolute form
/// (`scheme://authority/path`) names its authority.
///
/// # Errors
///
/// [`AuthorityRefusal::Malformed`] for any other form.
fn split_request_target(target: &str) -> Result<(&str, Option<&str>), AuthorityRefusal> {
    if target.starts_with('/') {
        return Ok((target, None));
    }
    let (_, rest) = target
        .split_once("://")
        .ok_or(AuthorityRefusal::Malformed)?;
    let (authority, path) = rest
        .find(['/', '?', '#'])
        .and_then(|end| rest.split_at_checked(end))
        .unwrap_or((rest, ""));
    Ok((if path.is_empty() { "/" } else { path }, Some(authority)))
}

/// The request's target authority: the absolute-form target's, else the one
/// `Host` header's.
///
/// # Errors
///
/// [`AuthorityRefusal::Duplicate`] for two `Host` headers,
/// [`AuthorityRefusal::Absent`] for neither source,
/// [`AuthorityRefusal::Disagrees`] when both are present and differ, and
/// [`AuthorityRefusal::Malformed`] when either does not parse.
fn request_authority(
    target_authority: Option<&str>,
    host: &HostHeader,
) -> Result<Authority, AuthorityRefusal> {
    let header = match host {
        HostHeader::Duplicate => return Err(AuthorityRefusal::Duplicate),
        HostHeader::Absent => None,
        HostHeader::One(value) => Some(value.as_str()),
    };
    match (target_authority, header) {
        (None, None) => Err(AuthorityRefusal::Absent),
        (Some(raw), None) | (None, Some(raw)) => Authority::parse(raw),
        (Some(target), Some(value)) => {
            let target = Authority::parse(target)?;
            if Authority::parse(value)? == target {
                Ok(target)
            } else {
                Err(AuthorityRefusal::Disagrees)
            }
        }
    }
}

/// Read one request head: its request line, then header lines up to the blank
/// line that ends it.
///
/// Every line read consumes at least its newline from the capped reader, so the
/// loop ends within [`REQUEST_HEAD_CAP`] bytes.
///
/// # Errors
///
/// [`HeadRefusal::TooLarge`] when the cap runs out first,
/// [`HeadRefusal::Malformed`] for a request line with no target or a line
/// that is not a header field, and
/// [`HeadRefusal::Abandoned`] when the peer stops sending.
fn read_head<R: std::io::Read>(
    reader: &mut std::io::BufReader<std::io::Take<R>>,
) -> Result<RequestHead, HeadRefusal> {
    let mut line = String::new();
    read_head_line(reader, &mut line)?;
    let mut request_line = line.split_whitespace();
    let method = Method::of(request_line.next().ok_or(HeadRefusal::Malformed)?);
    let target = request_line
        .next()
        .ok_or(HeadRefusal::Malformed)?
        .to_owned();
    let mut host = HostHeader::Absent;
    loop {
        read_head_line(reader, &mut line)?;
        if line.is_empty() {
            return Ok(RequestHead {
                method,
                target,
                host,
            });
        }
        let (name, value) = header_field(&line).ok_or(HeadRefusal::Malformed)?;
        if name.eq_ignore_ascii_case("host") {
            host = match host {
                HostHeader::Absent => HostHeader::One(value.to_owned()),
                HostHeader::One(_) | HostHeader::Duplicate => HostHeader::Duplicate,
            };
        }
    }
}

/// Read one head line into `line`, its `\n` or `\r\n` terminator removed.
///
/// # Errors
///
/// [`HeadRefusal::TooLarge`] for a line the cap cuts short,
/// [`HeadRefusal::Malformed`] for a line that is not UTF-8, and
/// [`HeadRefusal::Abandoned`] for a peer that closes or stalls mid-line.
fn read_head_line<R: std::io::Read>(
    reader: &mut std::io::BufReader<std::io::Take<R>>,
    line: &mut String,
) -> Result<(), HeadRefusal> {
    use std::io::BufRead;

    line.clear();
    match reader.read_line(line) {
        Ok(_) if line.ends_with('\n') => {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
            Ok(())
        }
        Ok(_) if reader.get_ref().limit() == 0 => Err(HeadRefusal::TooLarge),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => Err(HeadRefusal::Malformed),
        Ok(_) | Err(_) => Err(HeadRefusal::Abandoned),
    }
}

/// A header line's name and its value trimmed of optional whitespace.
///
/// `None` for a folded continuation line or a line that is not `name: value`.
fn header_field(line: &str) -> Option<(&str, &str)> {
    let (name, value) = line.split_once(':')?;
    let token = !name.is_empty() && name.bytes().all(|b| b.is_ascii_graphic());
    token.then(|| (name, value.trim_matches([' ', '\t'])))
}

/// Bind a listener on [`LOOPBACK`] at `port`; `0` lets the OS pick a free port.
///
/// # Errors
/// The bind's own error.
pub fn bind_loopback(port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind(SocketAddrV4::new(LOOPBACK, port))
}

/// The port a served bundle listens on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundlePort {
    /// The operator named this port; a taken one refuses the run.
    Pinned(ListenPort),
    /// No port was named: the OS picks a free one at the bind.
    Ephemeral,
}

/// The port a served bundle listens on, from the one read of its variable.
///
/// # Errors
/// [`CliError::EnvRefused`] carrying the refusal when the variable is set but
/// is not a port: a refused value never falls back to a free port.
pub fn bundle_listen_port(
    read: Result<Option<ListenPort>, EnvRefusal>,
) -> Result<BundlePort, CliError> {
    match read {
        Ok(Some(port)) => Ok(BundlePort::Pinned(port)),
        Ok(None) => Ok(BundlePort::Ephemeral),
        Err(refusal) => Err(CliError::EnvRefused(refusal)),
    }
}

/// Bind the served bundle's listener on [`LOOPBACK`] at `port`.
///
/// # Errors
/// [`CliError::ServePortTaken`] when a pinned port is already in use (no other
/// port is tried); [`CliError::Io`] naming the address for any other failure.
pub fn bind_bundle(port: BundlePort) -> Result<TcpListener, CliError> {
    let number = match port {
        BundlePort::Pinned(pinned) => pinned.get(),
        BundlePort::Ephemeral => 0,
    };
    bind_loopback(number).map_err(|e| match port {
        BundlePort::Pinned(pinned) if e.kind() == std::io::ErrorKind::AddrInUse => {
            CliError::ServePortTaken { port: pinned }
        }
        BundlePort::Pinned(_) | BundlePort::Ephemeral => {
            let addr = SocketAddrV4::new(LOOPBACK, number).to_string();
            crate::io_err(Path::new(&addr), e)
        }
    })
}

/// Print the URL `listener` serves `dir_url` at, then hand it to `opener`.
///
/// The status line `serving(url)` is printed first, so the URL is on screen
/// whatever the opener does. When `opener` is given and does not report
/// [`OpenOutcome::Opened`], one note naming the URL follows; no outcome stops
/// the server. A `None` opener opens nothing. Returns that note.
///
/// # Errors
/// [`CliError::Io`] when the listener's address cannot be read;
/// [`CliError::Pipeline`] (an internal bug) when the URL built from the bound
/// loopback address is not a loopback [`BrowserUrl`].
pub fn announce<O: FnOnce(&BrowserUrl) -> OpenOutcome>(
    listener: &TcpListener,
    dir_url: &str,
    serving: impl FnOnce(&BrowserUrl) -> Message,
    opener: Option<O>,
) -> Result<Option<Message>, CliError> {
    let bound = listener
        .local_addr()
        .map_err(|e| crate::io_err(Path::new("127.0.0.1"), e))?;
    let raw = format!("http://{bound}{dir_url}");
    let url =
        BrowserUrl::parse(&raw, BrowserOrigin::Loopback).map_err(|reason| CliError::Pipeline {
            file: std::path::PathBuf::from(dir_url),
            src: String::new(),
            diag: Box::new(ipe_diagnostics::Diagnostic::CompilerBug {
                where_: "ipe_cli::loopback_http::announce",
                detail: format!("the URL of a bound loopback listener is refused: {reason:?}"),
            }),
        })?;
    crate::screen::status(
        crate::screen::Stream::Stdout,
        true,
        &crate::style::TerminalSafe::sanitize(serving(&url).as_str()),
    );
    let note = opener.and_then(|open| match open(&url) {
        OpenOutcome::Opened => None,
        OpenOutcome::OpenerFailed(_)
        | OpenOutcome::OpenerMissing
        | OpenOutcome::Spawn(_)
        | OpenOutcome::WaitFailed(_)
        | OpenOutcome::Refused(_) => Some(text::msg::serve_open_failed(&url.as_str())),
    });
    if let Some(note) = &note {
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            note.as_str(),
        );
    }
    Ok(note)
}

/// A held client bundle: every asset's media type and bytes, keyed by its bundle path.
///
/// Built once, from the bytes the bundle's publish read through its held
/// directory; nothing a request names reaches the filesystem.
#[derive(Debug, Default)]
pub struct BundleSnapshot {
    assets: HashMap<BundlePath, (MediaType, Vec<u8>)>,
}

impl BundleSnapshot {
    /// Hold `bytes` as the asset at `path`.
    pub fn insert(&mut self, path: BundlePath, bytes: Vec<u8>) {
        let media = MediaType::of(&path);
        self.assets.insert(path, (media, bytes));
    }

    /// Whether the snapshot holds an asset at `path`.
    #[must_use]
    pub fn contains(&self, path: &BundlePath) -> bool {
        self.assets.contains_key(path)
    }

    /// The media type and bytes of the asset at `path`.
    #[must_use]
    pub fn get(&self, path: &BundlePath) -> Option<(MediaType, &[u8])> {
        self.assets
            .get(path)
            .map(|(media, bytes)| (*media, bytes.as_slice()))
    }

    /// The bytes of the top-level `index.html`.
    #[must_use]
    pub fn index_html(&self) -> Option<&[u8]> {
        BundlePath::parse("index.html")
            .ok()
            .and_then(|index| self.get(&index))
            .map(|(_, bytes)| bytes)
    }
}

/// A served client bundle: its snapshot, under its mount base, with its policy.
#[derive(Debug)]
pub struct BundleSite {
    /// The path prefix every asset is served under.
    pub base: MountBase,
    /// Every byte the site answers with.
    pub snapshot: BundleSnapshot,
    /// The bundle's `Content-Security-Policy`, the value its page's meta carries.
    pub csp: String,
}

impl Site for BundleSite {
    fn headers(&self) -> SiteHeaders<'_> {
        SiteHeaders {
            csp: &self.csp,
            framing: Framing::Policy,
        }
    }

    fn respond(&self, method: Method, path: &str) -> Reply<'_> {
        const NOT_FOUND: Reply<'static> = Reply::plain(Status::NotFound, "not found\n");
        if method == Method::Other {
            return Reply::plain(Status::MethodNotAllowed, "method not allowed\n");
        }
        match route(&self.base, path, |asset| self.snapshot.contains(asset)) {
            Route::Asset(asset) | Route::Index(asset) => {
                self.snapshot
                    .get(&asset)
                    .map_or(NOT_FOUND, |(media, body)| Reply {
                        status: Status::Ok,
                        content_type: media.header_value(),
                        body,
                    })
            }
            Route::NotFound => NOT_FOUND,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    use ipe_runtime_rust::csp::{BundleWorker, ContentSecurityPolicy};
    use ipe_runtime_rust::encoding::ServerOrigins;

    /// A site holding `files` under `base`, with the policy `csp`.
    fn bundle_site(base: &str, files: &[(&str, &[u8])], csp: &str) -> BundleSite {
        let mut snapshot = BundleSnapshot::default();
        for (path, bytes) in files {
            snapshot.insert(
                BundlePath::parse(path).expect("a bundle path"),
                bytes.to_vec(),
            );
        }
        BundleSite {
            base: if base == "/" {
                MountBase::root()
            } else {
                MountBase::parse(base).expect("a mount base")
            },
            snapshot,
            csp: csp.to_owned(),
        }
    }

    /// The plain bundle: a page, a script and a wasm module at the root.
    fn plain_site() -> BundleSite {
        bundle_site(
            "/",
            &[
                ("index.html", b"<html>page"),
                ("boot.js", b"boot()"),
                ("pkg/ipe_app_bg.wasm", b"\0asm"),
            ],
            "default-src 'self'",
        )
    }

    /// The whole response `site` writes to one `request` over a loopback socket.
    fn exchange(site: &BundleSite, request: &[u8]) -> String {
        let listener = bind_loopback(0).expect("bind loopback");
        let addr = listener.local_addr().expect("bound address");
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .spawn_scoped(scope, || {
                    if let Ok((conn, _)) = listener.accept() {
                        serve_one(&conn, site, Duration::from_secs(5));
                    }
                })
                .expect("spawn the server");
            let mut client = TcpStream::connect(addr).expect("connect");
            client.write_all(request).expect("send the request");
            let mut response = String::new();
            client
                .read_to_string(&mut response)
                .expect("read the response");
            response
        })
    }

    /// A `method` request for `target` naming the loopback host.
    fn request(method: &str, target: &str) -> Vec<u8> {
        format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").into_bytes()
    }

    /// The value of the response header `name`, when present once.
    fn header<'r>(response: &'r str, name: &str) -> Option<&'r str> {
        let head = response.split("\r\n\r\n").next()?;
        let mut values = head.split("\r\n").skip(1).filter_map(|line| {
            line.split_once(": ")
                .filter(|(field, _)| field.eq_ignore_ascii_case(name))
                .map(|(_, value)| value)
        });
        let (Some(value), None) = (values.next(), values.next()) else {
            return None;
        };
        Some(value)
    }

    /// The body of a response.
    fn body(response: &str) -> &str {
        response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
    }

    #[test]
    fn bundle_site_refuses_dot_dot_and_encoded_traversal() {
        let site = plain_site();
        for target in [
            "/../index.html",
            "/pkg/../index.html",
            "/./boot.js",
            "/%2e%2e/index.html",
            "/%2E%2E%2Fboot.js",
            "/pkg%2fipe_app_bg.wasm",
            "/boot.js%00",
            "/pkg\\ipe_app_bg.wasm",
            "//boot.js",
        ] {
            let reply = site.respond(Method::Get, target);
            assert_eq!(reply.status, Status::NotFound, "{target}");
            assert_eq!(reply.body, b"not found\n", "{target}");
        }
        let response = exchange(&site, &request("GET", "/../../etc/passwd"));
        assert!(
            response.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{response}"
        );
        assert_eq!(body(&response), "not found\n");
    }

    #[test]
    fn bundle_site_never_lists_a_directory() {
        let site = plain_site();
        for target in ["/pkg/", "/pkg"] {
            let reply = site.respond(Method::Get, target);
            assert_ne!(reply.body, b"\0asm", "{target}");
            assert!(
                !String::from_utf8_lossy(reply.body).contains("ipe_app_bg.wasm"),
                "{target} names no entry of the directory"
            );
        }
        assert_eq!(site.respond(Method::Get, "/pkg/").status, Status::NotFound);
        let root = site.respond(Method::Get, "/");
        assert_eq!(
            (root.status, root.body),
            (Status::Ok, b"<html>page".as_slice())
        );
    }

    #[test]
    fn bundle_site_refuses_a_path_outside_the_mount_base() {
        let site = bundle_site(
            "/app",
            &[("index.html", b"<html>app"), ("boot.js", b"boot()")],
            "default-src 'self'",
        );
        let ok = site.respond(Method::Get, "/app/boot.js");
        assert_eq!((ok.status, ok.body), (Status::Ok, b"boot()".as_slice()));
        for target in ["/boot.js", "/apple/boot.js", "/index.html", "/", "/other/x"] {
            assert_eq!(
                site.respond(Method::Get, target).status,
                Status::NotFound,
                "{target}"
            );
        }
    }

    #[test]
    fn bundle_site_refuses_a_foreign_host_with_421() {
        let site = plain_site();
        for host in [
            "attacker.example",
            "attacker.example:80",
            "localhost.attacker.example",
        ] {
            let response = exchange(
                &site,
                format!("GET /boot.js HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
            );
            assert!(
                response.starts_with("HTTP/1.1 421 Misdirected Request\r\n"),
                "{host}: {response}"
            );
            assert_eq!(body(&response), REFUSED_HOST_BODY, "{host}");
        }
        let absent = exchange(&site, b"GET /boot.js HTTP/1.1\r\n\r\n");
        assert!(absent.starts_with("HTTP/1.1 421 "), "{absent}");
        let admitted = exchange(&site, &request("GET", "/boot.js"));
        assert!(admitted.starts_with("HTTP/1.1 200 OK\r\n"), "{admitted}");
        assert_eq!(body(&admitted), "boot()");
    }

    #[test]
    fn bundle_site_answers_post_with_405() {
        let site = plain_site();
        for method in ["POST", "PUT", "DELETE", "OPTIONS", "get"] {
            let response = exchange(&site, &request(method, "/boot.js"));
            assert!(
                response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
                "{method}: {response}"
            );
            assert_eq!(header(&response, "Allow"), Some("GET, HEAD"), "{method}");
            assert_ne!(body(&response), "boot()", "{method}");
        }
        let head = exchange(&site, &request("HEAD", "/boot.js"));
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert_eq!(header(&head, "Content-Length"), Some("6"));
        assert_eq!(body(&head), "", "a HEAD answer carries no body");
    }

    #[test]
    fn loopback_http_binds_only_ipv4_loopback() {
        assert_eq!(LOOPBACK.octets(), [127, 0, 0, 1]);
        let listener = bind_loopback(0).expect("bind loopback");
        let bound = listener.local_addr().expect("bound address");
        assert_eq!(bound.ip(), std::net::IpAddr::V4(LOOPBACK));
        let listener = bind_bundle(BundlePort::Ephemeral).expect("bind a free port");
        let bound = listener.local_addr().expect("bound address");
        assert_eq!(bound.ip(), std::net::IpAddr::V4(LOOPBACK));
        assert_ne!(bound.port(), 0);
    }

    #[test]
    fn bundle_responses_carry_nosniff_and_a_csp_header_equal_to_the_meta() {
        let servers = ServerOrigins::none();
        let candidates: Vec<(String, String)> = [BundleWorker::None, BundleWorker::Push]
            .into_iter()
            .map(|worker| {
                let policy = ContentSecurityPolicy::bundle(&servers, worker);
                (policy.header_value(), policy.meta_element())
            })
            .collect();
        for (header_value, meta) in &candidates {
            let page = format!("<html><head>{meta}</head></html>");
            let (chosen, _) =
                crate::bundle_www::sole_policy(&page, &candidates, |(_, m)| m.as_str())
                    .expect("the page carries one policy");
            assert_eq!(chosen, header_value);
            let site = bundle_site(
                "/",
                &[("index.html", page.as_bytes()), ("x.unknown", b"x")],
                chosen,
            );
            for target in ["/", "/index.html", "/x.unknown", "/missing.js"] {
                let response = exchange(&site, &request("GET", target));
                assert_eq!(
                    header(&response, "Content-Security-Policy"),
                    Some(header_value.as_str()),
                    "{target}"
                );
                assert!(meta.contains(header_value.as_str()), "{target}");
                assert_eq!(
                    header(&response, "X-Content-Type-Options"),
                    Some("nosniff"),
                    "{target}"
                );
                assert_eq!(header(&response, "Referrer-Policy"), Some("no-referrer"));
                assert_eq!(header(&response, "Cache-Control"), Some("no-store"));
                assert_eq!(header(&response, "X-Frame-Options"), None, "{target}");
            }
            let unknown = exchange(&site, &request("GET", "/x.unknown"));
            assert_eq!(
                header(&unknown, "Content-Type"),
                Some("application/octet-stream")
            );
        }
        let wasm = exchange(&plain_site(), &request("GET", "/pkg/ipe_app_bg.wasm"));
        assert_eq!(header(&wasm, "Content-Type"), Some("application/wasm"));
        let both: String = candidates.iter().map(|(_, meta)| meta.as_str()).collect();
        assert!(
            crate::bundle_www::sole_policy(&both, &candidates, |(_, m)| m.as_str()).is_none(),
            "a page carrying two policies is refused"
        );
    }

    #[test]
    fn bundle_port_refuses_a_malformed_ipe_web_port() {
        use ipe_runtime_rust::env_registry::web::WEB_PORT;
        for raw in ["abc", "", "0", "65536", "+80", " 80", "-1", "80 "] {
            let read = WEB_PORT.parse(Ok(raw.to_owned()));
            let expected = read.clone().expect_err("a malformed port is refused");
            let refused = bundle_listen_port(read);
            assert!(
                matches!(&refused, Err(CliError::EnvRefused(refusal)) if *refusal == expected),
                "{raw:?}: {refused:?}"
            );
            let shown = refused.map(drop).expect_err("refused").to_string();
            assert!(shown.contains("IPE_WEB_PORT"), "{raw:?}: {shown}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt as _;
            let raw = std::ffi::OsString::from_vec(vec![0x38, 0xFF]);
            let read = WEB_PORT.parse(Err(std::env::VarError::NotUnicode(raw)));
            let refused = bundle_listen_port(read);
            assert!(
                matches!(&refused, Err(CliError::EnvRefused(_))),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn bundle_port_unset_is_ephemeral() {
        use ipe_runtime_rust::env_registry::web::WEB_PORT;
        let read = WEB_PORT.parse(Err(std::env::VarError::NotPresent));
        assert_eq!(
            bundle_listen_port(read).expect("unset is admitted"),
            BundlePort::Ephemeral
        );
    }

    #[test]
    fn bundle_port_set_is_pinned() {
        use ipe_runtime_rust::env_registry::web::WEB_PORT;
        let read = WEB_PORT.parse(Ok("8123".to_owned()));
        assert_eq!(
            bundle_listen_port(read).expect("a port is admitted"),
            BundlePort::Pinned(ListenPort::parse("8123").expect("a port"))
        );
    }

    #[test]
    fn bundle_server_refuses_a_taken_port_with_a_typed_error() {
        let held = bind_loopback(0).expect("hold a port");
        let taken = held.local_addr().expect("held address").port();
        let pinned = ListenPort::parse(&taken.to_string()).expect("a port");
        let refused = bind_bundle(BundlePort::Pinned(pinned));
        assert!(
            matches!(&refused, Err(CliError::ServePortTaken { port }) if *port == pinned),
            "{refused:?}"
        );
        let shown = refused.map(drop).expect_err("refused").to_string();
        assert!(shown.contains(&taken.to_string()), "{shown}");
        assert!(shown.contains("IPE_WEB_PORT"), "{shown}");
    }

    #[test]
    fn dev_run_client_opens_the_served_url_through_the_one_opener() {
        let site = plain_site();
        let listener = bind_bundle(BundlePort::Ephemeral).expect("bind");
        let port = listener.local_addr().expect("bound").port();
        let mut opened = Vec::new();
        let note = announce(
            &listener,
            "/",
            |url| text::msg::serve_open_failed(&url.as_str()),
            Some(|url: &BrowserUrl| {
                opened.push(url.as_str().to_owned());
                OpenOutcome::Opened
            }),
        )
        .expect("announce");
        let expected = format!("http://127.0.0.1:{port}/");
        assert_eq!(
            opened,
            std::slice::from_ref(&expected),
            "the opener is called once, with the URL"
        );
        assert!(note.is_none(), "an opened browser leaves no note");
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .spawn_scoped(scope, || {
                    if let Ok((conn, _)) = listener.accept() {
                        serve_one(&conn, &site, Duration::from_secs(5));
                    }
                })
                .expect("spawn the server");
            let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connect");
            client
                .write_all(format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes())
                .expect("send");
            let mut response = String::new();
            client.read_to_string(&mut response).expect("read");
            assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
            assert_eq!(body(&response), "<html>page");
        });
    }

    #[test]
    fn dev_run_client_keeps_serving_when_no_opener_exists() {
        let site = plain_site();
        for outcome in [
            OpenOutcome::OpenerMissing,
            OpenOutcome::WaitFailed(std::io::ErrorKind::Other),
        ] {
            let listener = bind_bundle(BundlePort::Ephemeral).expect("bind");
            let port = listener.local_addr().expect("bound").port();
            let note = announce(
                &listener,
                "/",
                |url| text::msg::serve_open_failed(&url.as_str()),
                Some(|_: &BrowserUrl| outcome),
            )
            .expect("a missing opener does not stop the run");
            let note = note.expect("a note names the URL");
            let url = format!("http://127.0.0.1:{port}/");
            assert!(note.as_str().contains(&url), "{note:?}");
            std::thread::scope(|scope| {
                std::thread::Builder::new()
                    .spawn_scoped(scope, || {
                        if let Ok((conn, _)) = listener.accept() {
                            serve_one(&conn, &site, Duration::from_secs(5));
                        }
                    })
                    .expect("spawn the server");
                let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connect");
                client
                    .write_all(
                        format!("GET /boot.js HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
                            .as_bytes(),
                    )
                    .expect("send");
                let mut response = String::new();
                client.read_to_string(&mut response).expect("read");
                assert_eq!(body(&response), "boot()");
            });
        }
        let listener = bind_bundle(BundlePort::Ephemeral).expect("bind");
        let none = announce(
            &listener,
            "/",
            |url| text::msg::serve_open_failed(&url.as_str()),
            None::<fn(&BrowserUrl) -> OpenOutcome>,
        )
        .expect("no opener");
        assert!(none.is_none());
    }

    #[test]
    fn request_authority_refusals_are_typed() {
        let one = |v: &str| HostHeader::One(v.to_owned());
        assert_eq!(
            request_authority(None, &HostHeader::Absent),
            Err(AuthorityRefusal::Absent)
        );
        assert_eq!(
            request_authority(None, &HostHeader::Duplicate),
            Err(AuthorityRefusal::Duplicate)
        );
        assert_eq!(
            request_authority(Some("127.0.0.1"), &HostHeader::Duplicate),
            Err(AuthorityRefusal::Duplicate)
        );
        assert_eq!(
            request_authority(Some("127.0.0.1:80"), &one("127.0.0.1")),
            Err(AuthorityRefusal::Disagrees)
        );
        assert_eq!(
            request_authority(None, &one("user@127.0.0.1")),
            Err(AuthorityRefusal::Malformed)
        );
        assert_eq!(
            split_request_target("index.html"),
            Err(AuthorityRefusal::Malformed)
        );
        assert_eq!(
            request_authority(Some("127.0.0.1:80"), &one("127.0.0.1:80")),
            Authority::parse("127.0.0.1:80"),
            "an agreeing pair is the one authority"
        );
        assert_eq!(
            split_request_target("http://127.0.0.1:80?x"),
            Ok(("?x", Some("127.0.0.1:80")))
        );
        assert_eq!(split_request_target("http://a"), Ok(("/", Some("a"))));
    }
}

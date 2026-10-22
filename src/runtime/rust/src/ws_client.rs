//! Ipe.WebSocket — outbound WebSocket client (tokio-tungstenite).
//!
//! Task-tier: connect/connectWith/send/sendBinary/close/closeWithCode via a
//! per-socket registry (a write-command mpsc + a frames broadcast). Receive:
//! `Sub_subscribeWebSocket` builds a IpeSub::Source that drains the frames
//! broadcast and emits messages into the TEA loop — completing `onMessage`.
//!
//! WebSocketMessage/CloseCode are bridged to runtime enums so the runtime can
//! construct frames/codes for the user's toMsg. All four event kinds
//! (onOpen/onMessage/onClose/onError) route through their own typed kernel
//! below — one per heterogeneous toMsg shape, so no bounded fn is shared and
//! no stdlib override is needed. `emit_expr.rs`'s `SubSubscribeWebSocket`
//! peephole splits the single `Sub_subscribeWebSocket` kernel call on its
//! compile-time-literal `kind` string into a call to one of these four typed
//! fns, so the surface is reachable on the native target: importing
//! `Ipe.WebSocket` and calling any of the stdlib `on*` wrappers compiles and
//! runs end-to-end. `F`'s bound is `Send` (not `Send + Sync`) because `to_msg`
//! is moved into exactly one detached source body per subscription,
//! never shared behind an `Arc` — the same contract `sub_subscribe_stream`
//! uses.
//!
//! `--target wasm` gets its own substitute (`wasm_client` below, `web_sys`
//! event-handler slots instead of the broadcast channel this native half
//! uses) — see `ipe_kernels::StdlibKernel::wasm_client_available`'s
//! `KernelClass::Tea` arm for the allowlist tag that makes it resolvable.

use super::*;
#[cfg(not(target_arch = "wasm32"))]
use crate::tea::SourceTask;
#[cfg(not(target_arch = "wasm32"))]
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::{AtomicI64, Ordering};
#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Mutex, OnceLock};
#[cfg(not(target_arch = "wasm32"))]
use tokio_tungstenite::tungstenite::Message;

/// Ipe.WebSocket.WebSocketMessage — bridged so the runtime can build frames.
/// Variant names match the Ipê constructors (Text / Binary).
///
/// The backend emits this type AS the Ipê `WebSocketMessage` ADT (the enum decl
/// is bridged, not user-emitted), so it must carry the same derives a real Ipê
/// enum gets — `serde::{Serialize, Deserialize}` in particular, since a Web
/// `Msg` variant like `GotFrame WebSocketMessage` is serialized to/from the
/// session store and the wire.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum WsClientMessage {
    Text(String),
    /// Binary frames carry raw bytes (`Vec<u8>`) — no Latin-1 bridge. Ipê code
    /// that needs to inspect binary payload passes it through `Bytes.*` kernels.
    Binary(Vec<u8>),
}

/// Ipe.WebSocket.CloseCode — bridged so the runtime can build close codes
/// for onClose's toMsg. Variant names match the Ipê constructors. Carries the
/// same serde derives as [`WsClientMessage`] for the same Web-`Msg` reason.
#[allow(non_snake_case)]
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum WsCloseCode {
    Normal,
    GoingAway,
    UnsupportedData,
    InternalError,
    Custom(i64),
}

impl crate::retained::RetainedBytes for WsClientMessage {
    fn retained_bytes(&self) -> Option<crate::retained::Bytes> {
        let inline = crate::retained::Bytes::inline::<Self>()?;
        match self {
            Self::Text(text) => inline.plus(text),
            Self::Binary(bytes) => inline.plus(bytes),
        }
    }
}

// Every close code is held inline: the inline size is the whole measure.
crate::retained::inline_measure!(WsCloseCode);

fn ws_close_code(code: i64) -> WsCloseCode {
    match code {
        1000 => WsCloseCode::Normal,
        1001 => WsCloseCode::GoingAway,
        1003 => WsCloseCode::UnsupportedData,
        1011 => WsCloseCode::InternalError,
        n => WsCloseCode::Custom(n),
    }
}

/// Internal per-socket event broadcast to onMessage/onClose/onError subs.
#[derive(Clone, Debug)]
#[cfg(not(target_arch = "wasm32"))]
enum WsEvent {
    Message(WsClientMessage),
    Closed(i64),
    Error(WsSide, WsFailure),
}

/// Which half of a socket failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(not(target_arch = "wasm32"))]
enum WsSide {
    /// Reading the peer's frames.
    Read,
    /// Writing the program's frames.
    Write,
}

/// The close code reported when the closing handshake did not finish.
///
/// RFC 6455 section 7.4.1: no close frame was received from the peer.
#[cfg(not(target_arch = "wasm32"))]
const WS_ABNORMAL_CLOSURE: i64 = 1006;

/// A close frame's reason text, at most [`CloseReason::MAX_BYTES`] bytes.
///
/// RFC 6455 caps a control frame's payload at 125 bytes, two of them the
/// close code. A peer refuses a longer close frame as a protocol error and a
/// browser refuses to send one, so the reason is cut once, here, and every
/// close path takes this type.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(any(
    not(target_arch = "wasm32"),
    all(target_arch = "wasm32", feature = "wasm-client")
))]
struct CloseReason(String);

#[cfg(any(
    not(target_arch = "wasm32"),
    all(target_arch = "wasm32", feature = "wasm-client")
))]
impl CloseReason {
    /// The most bytes a close reason may hold.
    const MAX_BYTES: usize = 123;

    /// `reason`, cut at the last character boundary within [`Self::MAX_BYTES`].
    fn new(mut reason: String) -> Self {
        let kept = reason.floor_char_boundary(Self::MAX_BYTES);
        reason.truncate(kept);
        Self(reason)
    }

    /// The reason text.
    fn as_str(&self) -> &str {
        &self.0
    }

    /// The reason text, owned.
    #[cfg(not(target_arch = "wasm32"))]
    fn into_string(self) -> String {
        self.0
    }
}

/// Ipe.WebSocket.WebSocketCfg — built in Ipê (defaultCfg + with*).
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct WsClientCfg {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub timeout: i64,
    pub pingInterval: i64,
}

// The dev view names every field; a credential header's value renders as the
// marker.
crate::stringify::show_row!(
    "WebSocketClientCfg",
    Redacted(Reveal),
    [] WsClientCfg,
    shown: |_| crate::stringify::REDACTED_SHOW.to_owned(),
    dev: |c, _| crate::stringify::dev_record(
        "WebSocketCfg",
        &[
            ("url", c.url.clone()),
            ("headers", crate::stringify::dev_header_list(&c.headers)),
            ("timeout", c.timeout.to_string()),
            ("pingInterval", c.pingInterval.to_string()),
        ],
    ),
);

// The headers (`Authorization`) and URL (a token in the query) can carry a
// credential; the Ipê record fixes the field types, so the masking lives in
// `Debug`.
crate::redact::redacting_debug!(WsClientCfg {
    shown: [timeout, pingInterval],
    masked: [url, headers],
});

#[cfg(not(target_arch = "wasm32"))]
enum WsCmd {
    Text(String),
    Binary(Vec<u8>),
    Close,
    CloseWithCode(u16, CloseReason),
}

#[cfg(not(target_arch = "wasm32"))]
struct ClientEntry {
    // Bounded (not unbounded) so a remote peer that stalls reads — wedging the
    // writer on `write.send().await` — can't make this outbound queue grow
    // without limit (memory DoS). A full queue makes send_cmd refuse the
    // command (try_send) rather than buffering forever.
    cmd_tx: tokio::sync::mpsc::Sender<WsCmd>,
    frames_tx: tokio::sync::broadcast::Sender<WsEvent>,
    // The one task that owns both halves of the socket. A Close that can't be
    // enqueued (full queue ⇒ the writer is wedged on a stalled peer) is
    // honoured by aborting it, which drops both halves at once, so a close
    // request can never strand an open socket. See send_cmd.
    task: tokio::task::AbortHandle,
    // Wakes the socket task once a close is queued, so it bounds the closing
    // handshake even while the writer is still draining.
    closing: std::sync::Arc<tokio::sync::Notify>,
    /// The message ceiling the socket was opened under; an outbound payload
    /// past it is refused before it is queued.
    ceiling: usize,
}

/// Why `send_cmd` did not queue a command.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendRefusal {
    /// No open socket has this id.
    NoSocket,
    /// The outbound queue is full: the peer is not reading.
    QueueFull,
    /// The socket's task has ended; it is being torn down.
    Closed,
    /// The payload is larger than the socket's message ceiling.
    TooLarge { len: usize, ceiling: usize },
}

#[cfg(not(target_arch = "wasm32"))]
impl SendRefusal {
    /// This refusal as the error of the `op` kernel on socket `id`.
    fn into_error<E: From<String> + FromLimitExceeded>(self, op: &str, id: i64) -> E {
        match self {
            Self::NoSocket => format!("{op}: no socket {id}").into(),
            Self::QueueFull => format!("{op}: socket {id} outbound queue is full").into(),
            Self::Closed => format!("{op}: socket {id} is closed").into(),
            Self::TooLarge { len, ceiling } => E::from_limit_exceeded(format!(
                "{op}: message of {len} bytes exceeds the {ceiling}-byte limit"
            )),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn registry() -> &'static Mutex<HashMap<i64, ClientEntry>> {
    static R: OnceLock<Mutex<HashMap<i64, ClientEntry>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Remove a socket from the registry and drop its subscribe-once markers so the
/// associated tasks wind down and the maps don't grow across reconnects.
#[cfg(not(target_arch = "wasm32"))]
fn deregister(id: i64) {
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id);
    ws_subscribed()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|&(sid, _)| sid != id);
}

#[cfg(not(target_arch = "wasm32"))]
static WS_CLIENT_NEXT_ID: AtomicI64 = AtomicI64::new(1);

/// Why a WebSocket dial or read failed, as a fixed class.
///
/// Built from the transport's error without keeping its text: a TLS or URL
/// error can quote the server name or the whole URL, token included.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WsFailure {
    /// The TCP dial of the vetted address failed.
    Dial(std::io::ErrorKind),
    /// The connection was closed.
    Closed,
    /// An I/O error of the given class.
    Io(std::io::ErrorKind),
    /// TLS setup or verification failed.
    Tls,
    /// A message or frame exceeded the size limit.
    Capacity,
    /// The peer broke the WebSocket protocol.
    Protocol,
    /// The outbound buffer was full.
    WriteBufferFull,
    /// A text frame was not UTF-8.
    Utf8,
    /// The peer's traffic matched a known attack pattern.
    AttackAttempt,
    /// The URL cannot be dialled.
    Url,
    /// The server answered the handshake with a non-upgrade HTTP status.
    HttpStatus(u16),
    /// The handshake's HTTP was malformed.
    HttpFormat,
}

#[cfg(not(target_arch = "wasm32"))]
impl WsFailure {
    /// The class of `error`.
    fn of(error: &tokio_tungstenite::tungstenite::Error) -> Self {
        use tokio_tungstenite::tungstenite::Error;
        match error {
            Error::ConnectionClosed | Error::AlreadyClosed => Self::Closed,
            Error::Io(io) => Self::Io(io.kind()),
            Error::Tls(_) => Self::Tls,
            Error::Capacity(_) => Self::Capacity,
            Error::Protocol(_) => Self::Protocol,
            Error::WriteBufferFull(_) => Self::WriteBufferFull,
            Error::Utf8(_) => Self::Utf8,
            Error::AttackAttempt => Self::AttackAttempt,
            Error::Url(_) => Self::Url,
            Error::Http(response) => Self::HttpStatus(response.status().as_u16()),
            Error::HttpFormat(_) => Self::HttpFormat,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl WsFailure {
    /// Whether this failure is a declared size ceiling turning the traffic back.
    const fn is_ceiling(self) -> bool {
        match self {
            Self::Capacity => true,
            Self::Dial(_)
            | Self::Closed
            | Self::Io(_)
            | Self::Tls
            | Self::Protocol
            | Self::WriteBufferFull
            | Self::Utf8
            | Self::AttackAttempt
            | Self::Url
            | Self::HttpStatus(_)
            | Self::HttpFormat => false,
        }
    }

    /// This failure of `side` as the `onError` subscriber's error.
    fn into_error<E: From<String> + FromLimitExceeded>(self, side: WsSide) -> E {
        let message = match side {
            WsSide::Read => format!("ws read error: {self}"),
            WsSide::Write => format!("ws write error: {self}"),
        };
        if self.is_ceiling() {
            E::from_limit_exceeded(message)
        } else {
            message.into()
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl std::fmt::Display for WsFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dial(kind) => write!(f, "dial of the vetted address failed: {kind}"),
            Self::Closed => f.write_str("connection closed"),
            Self::Io(kind) => write!(f, "I/O error: {kind}"),
            Self::Tls => f.write_str("TLS error"),
            Self::Capacity => f.write_str("message or frame exceeds the size limit"),
            Self::Protocol => f.write_str("WebSocket protocol error"),
            Self::WriteBufferFull => f.write_str("write buffer full"),
            Self::Utf8 => f.write_str("text frame is not UTF-8"),
            Self::AttackAttempt => f.write_str("attack attempt detected"),
            Self::Url => f.write_str("the URL cannot be dialled"),
            Self::HttpStatus(status) => write!(f, "server answered HTTP {status}"),
            Self::HttpFormat => f.write_str("malformed HTTP handshake"),
        }
    }
}

/// Why `WebSocket.connect` failed, as the Ipê program sees it.
///
/// Holds no foreign text and no dialled address: the URL only as
/// [`DisplayableUrl`](super::ssrf::DisplayableUrl) shows it, a header only by
/// its position, and a transport failure only as its [`WsFailure`] class.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug, PartialEq, Eq)]
enum WsConnectError {
    /// The SSRF gate refused the URL.
    Refused(super::ssrf::UrlRefusal),
    /// `IPE_WS_MAX_MESSAGE_BYTES` is present but malformed.
    Ceiling(crate::system::EnvCeilingRefusal),
    /// The URL is not a WebSocket handshake target.
    BadUrl(super::ssrf::DisplayableUrl),
    /// A caller-supplied header name does not parse.
    InvalidHeaderName {
        /// The URL as it may be shown.
        url: super::ssrf::DisplayableUrl,
        /// The header's 1-based position in the caller's list.
        position: usize,
    },
    /// A caller-supplied header value does not parse.
    InvalidHeaderValue {
        /// The URL as it may be shown.
        url: super::ssrf::DisplayableUrl,
        /// The header's 1-based position in the caller's list.
        position: usize,
    },
    /// A `wss://` URL under deny-private, whose pinned dial carries no TLS.
    TlsUnderPin(super::ssrf::DisplayableUrl),
    /// The TLS provider admits none of the safe default protocol versions.
    TlsSetup(super::ssrf::DisplayableUrl),
    /// A `wss://` URL whose host is no name a certificate can be valid for.
    TlsServerName(super::ssrf::DisplayableUrl),
    /// The dial or handshake failed.
    Failed {
        /// The URL as it may be shown.
        url: super::ssrf::DisplayableUrl,
        /// What failed.
        failure: WsFailure,
    },
    /// The handshake did not finish before the deadline.
    TimedOut {
        /// The URL as it may be shown.
        url: super::ssrf::DisplayableUrl,
        /// The deadline, in milliseconds.
        after_ms: u64,
    },
}

#[cfg(not(target_arch = "wasm32"))]
impl std::fmt::Display for WsConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "ws: {refusal}"),
            Self::Ceiling(refusal) => write!(f, "ws: {refusal}"),
            Self::BadUrl(url) => write!(f, "WebSocket.connect {url}: bad url"),
            Self::InvalidHeaderName { url, position } => write!(
                f,
                "WebSocket.connect {url}: header {position} has an invalid name"
            ),
            Self::InvalidHeaderValue { url, position } => write!(
                f,
                "WebSocket.connect {url}: header {position} has an invalid value"
            ),
            Self::TlsUnderPin(url) => write!(
                f,
                "WebSocket.connect {url}: wss:// with IPE_HTTP_DENY_PRIVATE is unsupported \
                 (SSRF-pinned dial bypasses TLS; disable IPE_HTTP_DENY_PRIVATE or use ws:// \
                 for this endpoint)"
            ),
            Self::TlsSetup(url) => write!(
                f,
                "WebSocket.connect {url}: no safe TLS protocol version is available"
            ),
            Self::TlsServerName(url) => write!(
                f,
                "WebSocket.connect {url}: the host is not a valid TLS server name"
            ),
            Self::Failed { url, failure } => write!(f, "WebSocket.connect {url}: {failure}"),
            Self::TimedOut { url, after_ms } => write!(
                f,
                "WebSocket.connect {url}: handshake timed out after {after_ms}ms"
            ),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl WsConnectError {
    /// Whether this failure is a declared size ceiling turning the handshake back.
    const fn is_ceiling(&self) -> bool {
        match self {
            Self::Failed { failure, .. } => failure.is_ceiling(),
            Self::Refused(_)
            | Self::Ceiling(_)
            | Self::BadUrl(_)
            | Self::InvalidHeaderName { .. }
            | Self::InvalidHeaderValue { .. }
            | Self::TlsUnderPin(_)
            | Self::TlsSetup(_)
            | Self::TlsServerName(_)
            | Self::TimedOut { .. } => false,
        }
    }

    /// This failure as the task's error.
    fn into_task<E: From<String> + FromLimitExceeded>(self) -> IpeResult<E, i64> {
        let message = self.to_string();
        IpeResult::Err(if self.is_ceiling() {
            E::from_limit_exceeded(message)
        } else {
            message.into()
        })
    }
}

/// Inbound WebSocket message and frame cap: `IPE_WS_MAX_MESSAGE_BYTES`, default 1 MiB.
#[cfg(not(target_arch = "wasm32"))]
const WS_MESSAGE_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_WS_MAX_MESSAGE_BYTES",
    1024 * 1024,
    crate::system::ZeroCeiling::Refused,
    "decimal byte count",
);

/// The write-buffer fill tungstenite reaches before it writes to the socket.
#[cfg(not(target_arch = "wasm32"))]
const WS_WRITE_BUFFER_TARGET: usize = 128 * 1024;

/// The largest header a WebSocket frame carries, in bytes.
#[cfg(not(target_arch = "wasm32"))]
const WS_FRAME_HEADER_MAX: usize = 14;

/// The most bytes the outbound buffer may hold when messages are capped at
/// `ceiling` bytes: the write target plus one framed message.
///
/// Always above [`WS_WRITE_BUFFER_TARGET`], which tungstenite requires of it.
#[cfg(not(target_arch = "wasm32"))]
const fn ws_write_buffer_bound(ceiling: usize) -> usize {
    WS_WRITE_BUFFER_TARGET
        .saturating_add(ceiling)
        .saturating_add(WS_FRAME_HEADER_MAX)
}

/// The socket configuration for messages and frames capped at `ceiling` bytes.
///
/// Caps the inbound message and frame at `ceiling` and the outbound buffer at
/// [`ws_write_buffer_bound`], so neither side of the socket can grow without a
/// limit.
#[cfg(not(target_arch = "wasm32"))]
fn ws_config(ceiling: usize) -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .write_buffer_size(WS_WRITE_BUFFER_TARGET)
        .max_write_buffer_size(ws_write_buffer_bound(ceiling))
        .max_message_size(Some(ceiling))
        .max_frame_size(Some(ceiling))
}

/// A client TLS configuration over the `ring` provider that trusts exactly `roots`.
///
/// `None` when the provider admits none of the safe default protocol versions.
#[cfg(not(target_arch = "wasm32"))]
fn tls_client_config(roots: rustls::RootCertStore) -> Option<rustls::ClientConfig> {
    rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .ok()
    .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}

/// The `wss://` client TLS configuration, trusting the webpki root store.
///
/// Built once per process.
#[cfg(not(target_arch = "wasm32"))]
fn wss_tls_config() -> Option<std::sync::Arc<rustls::ClientConfig>> {
    static CONFIG: OnceLock<Option<std::sync::Arc<rustls::ClientConfig>>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            tls_client_config(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .map(std::sync::Arc::new)
        })
        .clone()
}

/// The TLS handshake of a `wss://` dial over `tcp`, verifying the server's
/// certificate for `name` against `config`'s roots.
#[cfg(not(target_arch = "wasm32"))]
async fn tls_handshake(
    tcp: tokio::net::TcpStream,
    name: rustls::pki_types::ServerName<'static>,
    config: std::sync::Arc<rustls::ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, WsFailure> {
    tokio_rustls::TlsConnector::from(config)
        .connect(name, tcp)
        .await
        .map_err(|_| WsFailure::Tls)
}

/// Where the TCP dial of a connect goes.
#[cfg(not(target_arch = "wasm32"))]
enum DialTarget {
    /// The address the SSRF gate vetted.
    Vetted(std::net::SocketAddr),
    /// A host the policy lets the dial resolve by name.
    Named {
        /// The URL's host, IPv6 brackets stripped.
        host: String,
        /// The URL's port, or its scheme's default.
        port: u16,
    },
}

/// What runs over the TCP stream before the WebSocket handshake.
#[cfg(not(target_arch = "wasm32"))]
enum Transport {
    /// The handshake runs on the TCP stream itself (`ws://`).
    Plain,
    /// The handshake runs inside TLS to `name` (`wss://`).
    Tls {
        /// The name the server's certificate must be valid for.
        name: rustls::pki_types::ServerName<'static>,
        /// The client TLS configuration.
        config: std::sync::Arc<rustls::ClientConfig>,
    },
}

/// How a failed dial of a [`DialTarget`] is classed.
#[cfg(not(target_arch = "wasm32"))]
type DialFailure = fn(std::io::ErrorKind) -> WsFailure;

/// The addresses to dial for `target`, and how a failed dial of them is classed.
///
/// A vetted dial keeps only its class: the address may re-encode an IP-literal
/// host the displayable URL withholds.
#[cfg(not(target_arch = "wasm32"))]
async fn dial_addrs(
    target: DialTarget,
) -> Result<(Vec<std::net::SocketAddr>, DialFailure), WsFailure> {
    match target {
        DialTarget::Vetted(addr) => Ok((vec![addr], WsFailure::Dial)),
        DialTarget::Named { host, port } => {
            let addrs = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|e| WsFailure::Io(e.kind()))?;
            Ok((addrs.collect(), WsFailure::Io))
        }
    }
}

/// Run `transport` and the WebSocket handshake for `req` over the dialled
/// `tcp`, then start the socket; returns its id.
#[cfg(not(target_arch = "wasm32"))]
async fn open_over(
    tcp: tokio::net::TcpStream,
    transport: Transport,
    req: tokio_tungstenite::tungstenite::handshake::client::Request,
    ceiling: usize,
    ping_interval_ms: i64,
) -> Result<i64, WsFailure> {
    match transport {
        Transport::Plain => open_socket(req, tcp, ceiling, ping_interval_ms).await,
        Transport::Tls { name, config } => {
            let stream = tls_handshake(tcp, name, config).await?;
            open_socket(req, stream, ceiling, ping_interval_ms).await
        }
    }
}

/// Run the WebSocket handshake for `req` over `stream` with messages capped at
/// `ceiling`, then start the socket; returns its id.
#[cfg(not(target_arch = "wasm32"))]
async fn open_socket<S>(
    req: tokio_tungstenite::tungstenite::handshake::client::Request,
    stream: S,
    ceiling: usize,
    ping_interval_ms: i64,
) -> Result<i64, WsFailure>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (socket, _response) =
        tokio_tungstenite::client_async_with_config(req, stream, Some(ws_config(ceiling)))
            .await
            .map_err(|e| WsFailure::of(&e))?;
    Ok(start_socket(socket, ceiling, ping_interval_ms))
}

#[cfg(not(target_arch = "wasm32"))]
async fn do_connect<E: From<String> + FromLimitExceeded + Send + 'static>(
    url: String,
    headers: Vec<(String, String)>,
    timeout_ms: i64,
    ping_interval_ms: i64,
) -> IpeResult<E, i64> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
    // Every error below shows this form of the URL, never the raw `url`.
    let safe_url = super::ssrf::DisplayableUrl::of(&url);
    // SSRF gate, before the handshake: under deny-private the host is resolved
    // ONCE through the shared gate (bounded deadline, a host with any blocked
    // answer refused whole) and the dial below is pinned to the vetted address,
    // so the dial never re-resolves the name to a rebind target.
    let dial = match super::ssrf::VettedDial::for_url(&url).await {
        Ok(dial) => dial,
        Err(refusal) => return WsConnectError::Refused(refusal).into_task(),
    };
    // Build the handshake request so custom headers (e.g. Authorization) from
    // connectWith's cfg.headers are sent.
    let Ok(mut req) = url.as_str().into_client_request() else {
        return WsConnectError::BadUrl(safe_url).into_task();
    };
    // The host, port and scheme come from the parse the gate vetted, never from
    // the raw text, which may differ in case or leading whitespace.
    let Ok(parsed) = ::url::Url::parse(&url) else {
        return WsConnectError::BadUrl(safe_url).into_task();
    };
    let (Some(host), Some(port)) = (parsed.host_str(), parsed.port_or_known_default()) else {
        return WsConnectError::BadUrl(safe_url).into_task();
    };
    let host = super::ssrf::strip_ipv6_brackets(host).to_owned();
    // Fail CLOSED on an unparseable caller-supplied header: a credential (e.g.
    // an Authorization bearer) that can't be attached must abort the connect,
    // never connect unauthenticated. The header is named only by its position:
    // its name and value may both carry the secret.
    for (index, (k, v)) in headers.iter().enumerate() {
        let position = index.saturating_add(1);
        let Ok(name) = k.parse::<HeaderName>() else {
            return WsConnectError::InvalidHeaderName {
                url: safe_url,
                position,
            }
            .into_task();
        };
        let Ok(val) = HeaderValue::from_str(v) else {
            return WsConnectError::InvalidHeaderValue {
                url: safe_url,
                position,
            }
            .into_task();
        };
        req.headers_mut().insert(name, val);
    }
    // Cap inbound frame/message size to prevent a remote server from forcing the
    // client to buffer an arbitrarily large payload. Default 1 MiB (matches the
    // server-side cap): with the 64-deep broadcast buffer below, a larger cap
    // multiplies the worst-case retention per socket under a lagging
    // subscriber. Override via IPE_WS_MAX_MESSAGE_BYTES for apps that
    // legitimately need larger frames.
    let max_msg: usize = match WS_MESSAGE_CEILING.read() {
        Ok(cap) => cap,
        Err(refusal) => return WsConnectError::Ceiling(refusal).into_task(),
    };
    let (target, transport) = match dial {
        super::ssrf::VettedDial::Pinned(addr) => {
            // When SSRF-pinning is active (IPE_HTTP_DENY_PRIVATE), the dial goes
            // to the already-vetted IP, never to the name. The pinned dial
            // carries no TLS context, so a `wss://` URL cannot be serviced here:
            // refuse rather than dial plaintext to what the caller believes is a
            // secure endpoint.
            if parsed.scheme() != "ws" {
                return WsConnectError::TlsUnderPin(safe_url).into_task();
            }
            (DialTarget::Vetted(addr.socket_addr()), Transport::Plain)
        }
        super::ssrf::VettedDial::Unrestricted => {
            let transport = match parsed.scheme() {
                "ws" => Transport::Plain,
                "wss" => {
                    let Some(config) = wss_tls_config() else {
                        return WsConnectError::TlsSetup(safe_url).into_task();
                    };
                    let Ok(name) = rustls::pki_types::ServerName::try_from(host.clone()) else {
                        return WsConnectError::TlsServerName(safe_url).into_task();
                    };
                    Transport::Tls { name, config }
                }
                _ => {
                    return WsConnectError::Failed {
                        url: safe_url,
                        failure: WsFailure::Url,
                    }
                    .into_task();
                }
            };
            (DialTarget::Named { host, port }, transport)
        }
    };
    // Floor the handshake timeout: a non-positive cfg.timeout must NOT disable it
    // (an unreachable / silently-stalling host would otherwise hang the connect
    // forever, leaking the task + FD). Default 30 s. The one deadline bounds the
    // name lookup, the TCP dial, the TLS handshake and the WebSocket handshake.
    let to_ms: u64 = if timeout_ms > 0 {
        timeout_ms as u64
    } else {
        30_000
    };
    let opening = async move {
        let (addrs, dial_failure) = dial_addrs(target).await?;
        let tcp = tokio::net::TcpStream::connect(addrs.as_slice())
            .await
            .map_err(|e| dial_failure(e.kind()))?;
        open_over(tcp, transport, req, max_msg, ping_interval_ms).await
    };
    match tokio::time::timeout(std::time::Duration::from_millis(to_ms), opening).await {
        Ok(Ok(id)) => ok_res(id),
        Ok(Err(failure)) => WsConnectError::Failed {
            url: safe_url,
            failure,
        }
        .into_task(),
        Err(_) => WsConnectError::TimedOut {
            url: safe_url,
            after_ms: to_ms,
        }
        .into_task(),
    }
}

/// How long a closing socket waits for the peer's close frame.
///
/// Past it the socket is dropped and reported closed with
/// [`WS_ABNORMAL_CLOSURE`], so a peer that never answers the close, or never
/// drains what is queued before it, cannot hold the socket open.
#[cfg(not(target_arch = "wasm32"))]
const WS_CLOSE_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// How many times a send makes room in a full outbound buffer before the
/// writer gives up on the socket.
#[cfg(not(target_arch = "wasm32"))]
const WS_SEND_ATTEMPTS: usize = 4;

/// The write half of a socket.
#[cfg(not(target_arch = "wasm32"))]
type WsWrite<S> = futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<S>, Message>;

/// The read half of a socket.
#[cfg(not(target_arch = "wasm32"))]
type WsRead<S> = futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<S>>;

/// How a socket's writer stopped.
#[cfg(not(target_arch = "wasm32"))]
enum WriterEnd {
    /// The writer sent, or tried to send, the close frame.
    Closing,
    /// A write failed; the socket cannot carry the program's frames.
    Failed(WsFailure),
}

/// How a socket's reader stopped.
#[cfg(not(target_arch = "wasm32"))]
enum ReaderEnd {
    /// The peer sent a close frame with this code.
    Closed(i64),
    /// A read failed.
    Failed(WsFailure),
    /// The stream ended without a close frame.
    Ended,
}

#[cfg(not(target_arch = "wasm32"))]
impl ReaderEnd {
    /// The event that reports this end to the socket's subscribers.
    const fn into_event(self) -> WsEvent {
        match self {
            Self::Closed(code) => WsEvent::Closed(code),
            Self::Failed(failure) => WsEvent::Error(WsSide::Read, failure),
            Self::Ended => WsEvent::Closed(WS_ABNORMAL_CLOSURE),
        }
    }
}

/// What ends the first phase of a socket's life.
#[cfg(not(target_arch = "wasm32"))]
enum FirstEnd {
    /// The writer stopped.
    Writer(WriterEnd),
    /// The reader stopped.
    Reader(ReaderEnd),
    /// A close was queued.
    Closing,
}

/// Send `msg`, first writing out what the outbound buffer holds.
///
/// The read half buffers a pong for every ping the peer sends, so the buffer
/// can be full when the program's own frame arrives; tungstenite then hands the
/// frame back, and it is sent again once the buffer is written out. A buffer
/// that refills [`WS_SEND_ATTEMPTS`] times in a row fails the send.
#[cfg(not(target_arch = "wasm32"))]
async fn send_making_room<S>(write: &mut WsWrite<S>, mut msg: Message) -> Result<(), WsFailure>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio_tungstenite::tungstenite::Error;
    for _ in 0..WS_SEND_ATTEMPTS {
        write.flush().await.map_err(|e| WsFailure::of(&e))?;
        match write.send(msg).await {
            Ok(()) => return Ok(()),
            Err(Error::WriteBufferFull(back)) => msg = *back,
            Err(e) => return Err(WsFailure::of(&e)),
        }
    }
    Err(WsFailure::WriteBufferFull)
}

/// Drain the outbound commands into `write` until a close or a failed write.
///
/// When `ping_interval_ms` is positive it also sends a Ping that often, so an
/// idle connection survives proxy and server idle timeouts. A closed command
/// queue means no handle can send any more, so it closes the socket too.
#[cfg(not(target_arch = "wasm32"))]
async fn run_writer<S>(
    write: &mut WsWrite<S>,
    mut cmd_rx: tokio::sync::mpsc::Receiver<WsCmd>,
    ping_interval_ms: i64,
) -> WriterEnd
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // `interval` ticks immediately on the first poll; skip that first tick so
    // we ping after the interval, not at t=0.
    let mut ping_iv = if ping_interval_ms > 0 {
        let mut iv =
            tokio::time::interval(std::time::Duration::from_millis(ping_interval_ms as u64));
        iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        Some(iv)
    } else {
        None
    };
    let mut first_tick = true;
    loop {
        let cmd = match &mut ping_iv {
            Some(iv) => tokio::select! {
                _ = iv.tick() => {
                    if first_tick { first_tick = false; continue; }
                    let ping = Message::Ping(tokio_tungstenite::tungstenite::Bytes::new());
                    if let Err(failure) = send_making_room(write, ping).await {
                        return WriterEnd::Failed(failure);
                    }
                    continue;
                }
                c = cmd_rx.recv() => c,
            },
            None => cmd_rx.recv().await,
        };
        let msg = match cmd {
            Some(WsCmd::Text(s)) => Message::Text(s.into()),
            Some(WsCmd::Binary(b)) => Message::Binary(b.into()),
            Some(WsCmd::Close) | None => {
                // A close frame that cannot be sent still ends in the closing
                // handshake's grace period.
                let _ = send_making_room(write, Message::Close(None)).await;
                return WriterEnd::Closing;
            }
            Some(WsCmd::CloseWithCode(code, reason)) => {
                let frame = tokio_tungstenite::tungstenite::protocol::CloseFrame {
                    code: code.into(),
                    reason: reason.into_string().into(),
                };
                let _ = send_making_room(write, Message::Close(Some(frame))).await;
                return WriterEnd::Closing;
            }
        };
        if let Err(failure) = send_making_room(write, msg).await {
            return WriterEnd::Failed(failure);
        }
    }
}

/// Broadcast the peer's messages on `frames` until the peer closes or a read
/// fails.
///
/// Pings, pongs and raw frames are tungstenite's to answer.
#[cfg(not(target_arch = "wasm32"))]
async fn run_reader<S>(
    read: &mut WsRead<S>,
    frames: &tokio::sync::broadcast::Sender<WsEvent>,
) -> ReaderEnd
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Some(item) = read.next().await {
        match item {
            Ok(Message::Text(t)) => {
                let text = t.as_str().to_owned();
                let _ = frames.send(WsEvent::Message(WsClientMessage::Text(text)));
            }
            Ok(Message::Binary(b)) => {
                let _ = frames.send(WsEvent::Message(WsClientMessage::Binary(Vec::from(b))));
            }
            Ok(Message::Close(cf)) => {
                return ReaderEnd::Closed(cf.map_or(1000, |f| i64::from(u16::from(f.code))));
            }
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {}
            Err(e) => return ReaderEnd::Failed(WsFailure::of(&e)),
        }
    }
    ReaderEnd::Ended
}

/// Finish a closing socket: wait, at most [`WS_CLOSE_GRACE`], for the writer
/// to send its close frame and for the peer's answer.
///
/// `writer_done` says the writer has already stopped and must not be polled.
#[cfg(not(target_arch = "wasm32"))]
async fn closing_handshake<W, R>(
    mut writer: std::pin::Pin<&mut W>,
    mut writer_done: bool,
    mut reader: std::pin::Pin<&mut R>,
) -> WsEvent
where
    W: std::future::Future<Output = WriterEnd>,
    R: std::future::Future<Output = ReaderEnd>,
{
    let handshake = async {
        loop {
            tokio::select! {
                end = writer.as_mut(), if !writer_done => match end {
                    WriterEnd::Closing => writer_done = true,
                    WriterEnd::Failed(failure) => return WsEvent::Error(WsSide::Write, failure),
                },
                end = reader.as_mut() => return end.into_event(),
            }
        }
    };
    tokio::time::timeout(WS_CLOSE_GRACE, handshake)
        .await
        .unwrap_or(WsEvent::Closed(WS_ABNORMAL_CLOSURE))
}

/// The one task that owns socket `id`: it writes, reads, and tears down.
///
/// Every way the socket ends leaves through the same exit: the socket is
/// deregistered, the event that ended it goes to its subscribers, and both
/// halves are dropped together.
#[cfg(not(target_arch = "wasm32"))]
async fn run_socket<S>(
    id: i64,
    socket: tokio_tungstenite::WebSocketStream<S>,
    cmd_rx: tokio::sync::mpsc::Receiver<WsCmd>,
    frames: tokio::sync::broadcast::Sender<WsEvent>,
    closing: std::sync::Arc<tokio::sync::Notify>,
    ping_interval_ms: i64,
    registered: tokio::sync::oneshot::Receiver<()>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // The socket is registered before it can end, so its teardown always
    // finds the entry it removes.
    let _ = registered.await;
    let (mut write, mut read) = socket.split();
    let writer = run_writer(&mut write, cmd_rx, ping_interval_ms);
    let reader = run_reader(&mut read, &frames);
    tokio::pin!(writer, reader);
    let first = tokio::select! {
        end = writer.as_mut() => FirstEnd::Writer(end),
        end = reader.as_mut() => FirstEnd::Reader(end),
        () = closing.notified() => FirstEnd::Closing,
    };
    let event = match first {
        FirstEnd::Writer(WriterEnd::Failed(failure)) => WsEvent::Error(WsSide::Write, failure),
        FirstEnd::Writer(WriterEnd::Closing) => {
            closing_handshake(writer.as_mut(), true, reader.as_mut()).await
        }
        FirstEnd::Reader(end) => end.into_event(),
        FirstEnd::Closing => closing_handshake(writer.as_mut(), false, reader.as_mut()).await,
    };
    deregister(id);
    let _ = frames.send(event);
}

/// Start the task of an open `socket` whose messages are capped at `ceiling`,
/// and register it; returns its id.
#[cfg(not(target_arch = "wasm32"))]
fn start_socket<S>(
    socket: tokio_tungstenite::WebSocketStream<S>,
    ceiling: usize,
    ping_interval_ms: i64,
) -> i64
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let id = WS_CLIENT_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<WsCmd>(1024);
    let (frames_tx, _) = tokio::sync::broadcast::channel::<WsEvent>(64);
    let closing = std::sync::Arc::new(tokio::sync::Notify::new());
    let (registered_tx, registered) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(run_socket(
        id,
        socket,
        cmd_rx,
        frames_tx.clone(),
        std::sync::Arc::clone(&closing),
        ping_interval_ms,
        registered,
    ));
    registry().lock().unwrap_or_else(|e| e.into_inner()).insert(
        id,
        ClientEntry {
            cmd_tx,
            frames_tx,
            task: task.abort_handle(),
            closing,
            ceiling,
        },
    );
    let _ = registered_tx.send(());
    id
}

/// WebSocket.connect : String -> Task Error Int (raw id; Ipê wraps in WebSocket)
#[cfg(not(target_arch = "wasm32"))]
pub fn web_socket_connect<E: From<String> + FromLimitExceeded + Send + 'static>(
    url: String,
) -> IpeTask<E, i64> {
    Box::pin(do_connect(url, Vec::new(), 30000, 0))
}

/// WebSocket.connectWith : WebSocketCfg -> Task Error Int. Applies the cfg's
/// custom headers, handshake timeout, and pingInterval (when > 0, the client
/// sends a periodic Ping frame to keep the connection alive through idle proxies;
/// tungstenite auto-pongs inbound pings on the read side).
#[cfg(not(target_arch = "wasm32"))]
pub fn web_socket_connect_with<E: From<String> + FromLimitExceeded + Send + 'static>(
    cfg: WsClientCfg,
) -> IpeTask<E, i64> {
    Box::pin(do_connect(
        cfg.url,
        cfg.headers,
        cfg.timeout,
        cfg.pingInterval,
    ))
}

#[cfg(not(target_arch = "wasm32"))]
fn send_cmd(id: i64, cmd: WsCmd) -> Result<(), SendRefusal> {
    use tokio::sync::mpsc::error::TrySendError;
    let is_close = matches!(cmd, WsCmd::Close | WsCmd::CloseWithCode(..));
    // Clone what we need, then RELEASE the registry lock before try_send / abort /
    // deregister (deregister re-locks the registry — holding it here would deadlock).
    let handles = {
        let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        reg.get(&id).map(|e| {
            (
                e.cmd_tx.clone(),
                e.frames_tx.clone(),
                e.task.clone(),
                std::sync::Arc::clone(&e.closing),
                e.ceiling,
            )
        })
    };
    let (tx, frames, task, closing, ceiling) = handles.ok_or(SendRefusal::NoSocket)?;
    // A close reason is bounded by `CloseReason`, not by the message ceiling.
    let len = match &cmd {
        WsCmd::Text(text) => text.len(),
        WsCmd::Binary(bytes) => bytes.len(),
        WsCmd::Close | WsCmd::CloseWithCode(..) => 0,
    };
    if len > ceiling {
        return Err(SendRefusal::TooLarge { len, ceiling });
    }
    match tx.try_send(cmd) {
        Ok(()) => {
            if is_close {
                closing.notify_one();
            }
            Ok(())
        }
        // For a Close, the full queue means the writer is wedged on a stalled
        // peer, so a queued Close would never be sent — guarantee teardown by
        // aborting the socket's task (drops both halves → the connection
        // closes), notifying subscribers, and deregistering. Close "succeeds".
        Err(TrySendError::Full(_)) if is_close => {
            task.abort();
            let _ = frames.send(WsEvent::Closed(1000));
            deregister(id);
            Ok(())
        }
        Err(TrySendError::Full(_)) => Err(SendRefusal::QueueFull),
        // The socket's task has ended and is tearing the socket down.
        Err(TrySendError::Closed(_)) if is_close => {
            deregister(id);
            Ok(())
        }
        Err(TrySendError::Closed(_)) => Err(SendRefusal::Closed),
    }
}

/// WebSocket.send : Int -> String -> Task Error ()
#[cfg(not(target_arch = "wasm32"))]
pub fn web_socket_send<E: From<String> + FromLimitExceeded + Send + 'static>(
    id: i64,
    msg: String,
) -> IpeTask<E, ()> {
    Box::pin(async move {
        match send_cmd(id, WsCmd::Text(msg)) {
            Ok(()) => ok_res(()),
            Err(refusal) => IpeResult::Err(refusal.into_error("WebSocket.send", id)),
        }
    })
}

/// WebSocket.sendBinary : Int -> Bytes -> Task Error ()
#[cfg(not(target_arch = "wasm32"))]
pub fn web_socket_send_binary<E: From<String> + FromLimitExceeded + Send + 'static>(
    id: i64,
    msg: Vec<u8>,
) -> IpeTask<E, ()> {
    Box::pin(async move {
        match send_cmd(id, WsCmd::Binary(msg)) {
            Ok(()) => ok_res(()),
            Err(refusal) => IpeResult::Err(refusal.into_error("WebSocket.sendBinary", id)),
        }
    })
}

/// WebSocket.close : Int -> Task Error () (idempotent)
#[cfg(not(target_arch = "wasm32"))]
pub fn web_socket_close<E: From<String> + Send + 'static>(id: i64) -> IpeTask<E, ()> {
    Box::pin(async move {
        let _ = send_cmd(id, WsCmd::Close);
        deregister(id);
        ok_res(())
    })
}

/// WebSocket.closeWithCode : Int -> String -> Int -> Task Error ()
#[cfg(not(target_arch = "wasm32"))]
pub fn web_socket_close_with_code<E: From<String> + Send + 'static>(
    code: i64,
    reason: String,
    id: i64,
) -> IpeTask<E, ()> {
    Box::pin(async move {
        // A WebSocket close code is a u16 (RFC 6455 §7.4). A bare `code as u16`
        // SILENTLY TRUNCATES a Ipê `Int` outside 0..=65535 (e.g. 70000 → 4464),
        // which is worse than rejecting it because the wrapped value can land on
        // a *different valid* code. Out-of-range → 1000 (normal closure).
        let ws_code = u16::try_from(code).unwrap_or(1000);
        let _ = send_cmd(id, WsCmd::CloseWithCode(ws_code, CloseReason::new(reason)));
        deregister(id);
        ok_res(())
    })
}

// The four onX wrappers all call subscribeWebSocketRaw with a compile-time
// literal kind; the Builder peephole routes each to its own typed kernel below
// (so the heterogeneous toMsg shapes never share one bounded fn — no stdlib
// override needed). Each subscribes to the per-socket WsEvent broadcast and
// filters the events it cares about.

#[cfg(not(target_arch = "wasm32"))]
fn subscribe_events(socket_id: i64) -> Option<tokio::sync::broadcast::Receiver<WsEvent>> {
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&socket_id)
        .map(|e| e.frames_tx.subscribe())
}

// WS subscriptions are set up ONCE per (socket, kind): the `SubRuntime`
// reconciler stops and restarts every tracked source on each update, but a
// broadcast has no replay, so a restarted receiver would miss frames sent during
// the gap. So the first subscribe returns the real listener as a
// `SourceTask::Detached` body, which re-evaluation never stops, and every
// re-subscribe returns `SourceTask::Idle`. The emit callback funnels into the
// loop channel, stable for the program's lifetime.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
#[cfg(not(target_arch = "wasm32"))]
enum WsSubKind {
    Message,
    Open,
    Close,
    Error,
}

#[cfg(not(target_arch = "wasm32"))]
fn ws_subscribed() -> &'static Mutex<std::collections::HashSet<(i64, WsSubKind)>> {
    static S: OnceLock<Mutex<std::collections::HashSet<(i64, WsSubKind)>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}
#[cfg(not(target_arch = "wasm32"))]
fn ws_mark_subscribed(socket_id: i64, kind: WsSubKind) -> bool {
    ws_subscribed()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert((socket_id, kind))
}
// True iff the socket is currently in the registry. Gate ws_mark_subscribed on
// this (registry-check FIRST, short-circuiting the insert) so subscribing to a
// never-connected / already-closed id doesn't leave a permanent marker behind
// (socket ids are monotonic, so a leaked marker is never reclaimed by
// deregister). The guard drops at return, so the registry + ws_subscribed locks
// are never held simultaneously.
#[cfg(not(target_arch = "wasm32"))]
fn ws_registered(socket_id: i64) -> bool {
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&socket_id)
}

/// onMessage : (WebSocketMessage -> msg) -> Sub msg
///
/// `to_msg` is moved exclusively into the one detached source body
/// below (never behind a shared `Arc`, never read from two threads at once) —
/// the same shape as the sibling `sub_subscribe_stream` (`http_stream.rs`) and
/// `sub_subscribe_topic` (`pubsub.rs`), whose doc comments state the identical
/// rationale. `Send` is therefore the full and correct contract; `Sync` is NOT
/// required. An over-declared `+ Sync` here is exactly the bound the codegen's
/// generic first-class-function-value rendering
/// (`Box<dyn Fn(..) -> .. + Send + 'static>` — deliberately `+Send`-only)
/// requires, matching the reachable `emit_expr.rs::SubSubscribeWebSocket`
/// peephole's generic first-class-function-value render path.
#[cfg(not(target_arch = "wasm32"))]
pub fn sub_subscribe_ws_message<M, F>(socket_id: i64, to_msg: F) -> IpeSub<M>
where
    M: Send + 'static,
    F: Fn(WsClientMessage) -> M + Send + 'static,
{
    IpeSub::Source(Box::new(move |emit| {
        if ws_registered(socket_id) && ws_mark_subscribed(socket_id, WsSubKind::Message) {
            SourceTask::Detached(Box::pin(async move {
                let mut rx = match subscribe_events(socket_id) {
                    Some(rx) => rx,
                    None => return,
                };
                loop {
                    match rx.recv().await {
                        Ok(WsEvent::Message(m)) => emit(to_msg(m)),
                        Ok(_) => {}
                        // A momentarily-slow consumer that lags past the buffer gets
                        // a Lagged error — skip the gap and keep the subscription
                        // alive (do NOT treat it as terminal). Closed channel ends it.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }))
        } else {
            SourceTask::Idle
        }
    }))
}

/// onOpen : msg -> Sub msg — dispatch `msg` once when connected.
#[cfg(not(target_arch = "wasm32"))]
pub fn sub_subscribe_ws_open<M>(socket_id: i64, msg: M) -> IpeSub<M>
where
    M: Send + 'static,
{
    IpeSub::Source(Box::new(move |emit| {
        if ws_registered(socket_id) && ws_mark_subscribed(socket_id, WsSubKind::Open) {
            emit(msg);
        }
        SourceTask::Idle
    }))
}

/// onClose : (CloseCode -> msg) -> Sub msg
///
/// Same `Send`-only bound rationale as [`sub_subscribe_ws_message`]:
/// `to_msg` is moved into the one detached source body below and never
/// shared behind an `Arc`, so `Send + 'static` is the exact contract.
#[cfg(not(target_arch = "wasm32"))]
pub fn sub_subscribe_ws_close<M, F>(socket_id: i64, to_msg: F) -> IpeSub<M>
where
    M: Send + 'static,
    F: Fn(WsCloseCode) -> M + Send + 'static,
{
    IpeSub::Source(Box::new(move |emit| {
        if ws_registered(socket_id) && ws_mark_subscribed(socket_id, WsSubKind::Close) {
            SourceTask::Detached(Box::pin(async move {
                let mut rx = match subscribe_events(socket_id) {
                    Some(rx) => rx,
                    None => return,
                };
                loop {
                    match rx.recv().await {
                        Ok(WsEvent::Closed(code)) => {
                            emit(to_msg(ws_close_code(code)));
                            break;
                        }
                        Ok(_) => {}
                        // Transient lag: skip the gap, keep waiting for the close event.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }))
        } else {
            SourceTask::Idle
        }
    }))
}

/// onError : (Error -> msg) -> Sub msg. E is the project error (From<String>).
///
/// Same `Send`-only bound rationale as [`sub_subscribe_ws_message`]:
/// `to_msg` is moved into the one detached source body below and never
/// shared behind an `Arc`, so `Send + 'static` is the exact contract.
#[cfg(not(target_arch = "wasm32"))]
pub fn sub_subscribe_ws_error<E, M, F>(socket_id: i64, to_msg: F) -> IpeSub<M>
where
    E: From<String> + FromLimitExceeded + Send + 'static,
    M: Send + 'static,
    F: Fn(E) -> M + Send + 'static,
{
    IpeSub::Source(Box::new(move |emit| {
        if ws_registered(socket_id) && ws_mark_subscribed(socket_id, WsSubKind::Error) {
            SourceTask::Detached(Box::pin(async move {
                let mut rx = match subscribe_events(socket_id) {
                    Some(rx) => rx,
                    None => return,
                };
                loop {
                    match rx.recv().await {
                        Ok(WsEvent::Error(side, failure)) => {
                            emit(to_msg(failure.into_error(side)));
                            break;
                        }
                        Ok(_) => {}
                        // Transient lag: skip the gap, keep waiting for the error event.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }))
        } else {
            SourceTask::Idle
        }
    }))
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_ceilings_honour_the_shared_contract() {
        crate::system::assert_env_ceiling_contract(WS_MESSAGE_CEILING);
    }

    #[test]
    fn cfg_debug_prints_neither_url_nor_headers() {
        let cfg = WsClientCfg {
            url: "wss://live.example/socket?token=URLT0K".to_owned(),
            headers: vec![("Authorization".to_owned(), "Bearer H34D3R".to_owned())],
            timeout: 10,
            pingInterval: 5,
        };
        let shown = format!("{cfg:?}");
        assert!(!shown.contains("URLT0K"), "{shown}");
        assert!(!shown.contains("H34D3R"), "{shown}");
        assert!(shown.contains("pingInterval: 5"), "{shown}");
    }

    /// Every connect failure shows the URL only as scheme, host, and port,
    /// withholds a host read from ambiguous userinfo, and never shows the
    /// address an IP-literal host re-encodes to.
    #[test]
    fn connect_errors_never_show_credentials_or_the_dialled_address() {
        let secrets = [
            "1234567890",
            "73.150.2.210",
            "pw",
            "x.example",
            "t0k3n",
            "s3ss10n",
            "Bearer",
        ];
        for raw in [
            "ws://1234567890?pw@x.example/",
            "ws://1234567890/pw@x.example/",
            "ws://1234567890\\pw@x.example/",
            "ws://host.example/ws/s3ss10n?access_token=t0k3n",
        ] {
            let url = || super::super::ssrf::DisplayableUrl::of(raw);
            for error in [
                WsConnectError::BadUrl(url()),
                WsConnectError::InvalidHeaderName {
                    url: url(),
                    position: 1,
                },
                WsConnectError::InvalidHeaderValue {
                    url: url(),
                    position: 2,
                },
                WsConnectError::TlsUnderPin(url()),
                WsConnectError::TlsSetup(url()),
                WsConnectError::TlsServerName(url()),
                WsConnectError::Failed {
                    url: url(),
                    failure: WsFailure::Dial(std::io::ErrorKind::ConnectionRefused),
                },
                WsConnectError::Failed {
                    url: url(),
                    failure: WsFailure::Tls,
                },
                WsConnectError::TimedOut {
                    url: url(),
                    after_ms: 30_000,
                },
            ] {
                for shown in [error.to_string(), format!("{error:?}")] {
                    for secret in secrets {
                        assert!(!shown.contains(secret), "{secret:?} leaked into {shown}");
                    }
                }
            }
        }
    }

    /// A dial URL whose credential may run into its host or path is refused
    /// by the gate before any dial, under every policy.
    #[tokio::test]
    async fn connect_refuses_misplaced_userinfo_without_echoing_it() {
        use super::super::ssrf::{DialPolicy, UrlRefusal, test_resolvers::NoDns, vet_url_with};
        for raw in [
            "ws://1234567890\\pw@x.example/",
            "ws://10.0.0.1\\s3cr3t@x.example/",
        ] {
            for policy in [DialPolicy::DenyPrivate, DialPolicy::AllowAll] {
                let refused =
                    vet_url_with(policy, &NoDns, raw, std::time::Duration::from_secs(5)).await;
                assert_eq!(refused, Err(UrlRefusal::MisplacedUserinfo), "{raw:?}");
                if let Err(refusal) = refused {
                    let shown = WsConnectError::Refused(refusal).to_string();
                    for secret in [
                        "1234567890",
                        "73.150.2.210",
                        "10.0.0.1",
                        "s3cr3t",
                        "x.example",
                    ] {
                        assert!(!shown.contains(secret), "{secret:?} leaked into {shown}");
                    }
                }
            }
        }
    }

    /// A frame past the message ceiling is a `LimitExceeded` refusal at the
    /// handshake and on the read side; every other class keeps its kind.
    #[test]
    fn capacity_failures_are_limit_exceeded() {
        use tokio_tungstenite::tungstenite::error::CapacityError;
        let too_long =
            tokio_tungstenite::tungstenite::Error::Capacity(CapacityError::MessageTooLong {
                size: 1025,
                max_size: 1024,
            });
        let failure = WsFailure::of(&too_long);
        assert_eq!(failure, WsFailure::Capacity);
        let url = super::super::ssrf::DisplayableUrl::of("ws://x.example/");
        let refused: IpeResult<IpeError, i64> = WsConnectError::Failed {
            url: url.clone(),
            failure,
        }
        .into_task();
        assert_eq!(
            refused,
            IpeResult::Err(IpeError::limit_exceeded(format!(
                "WebSocket.connect {url}: message or frame exceeds the size limit"
            )))
        );
        assert_eq!(
            failure.into_error::<IpeError>(WsSide::Read),
            IpeError::limit_exceeded("ws read error: message or frame exceeds the size limit")
        );
        assert_eq!(
            WsFailure::Protocol.into_error::<IpeError>(WsSide::Read),
            IpeError::unexpected("ws read error: WebSocket protocol error".to_owned())
        );
        assert_eq!(
            WsFailure::WriteBufferFull.into_error::<IpeError>(WsSide::Write),
            IpeError::unexpected("ws write error: write buffer full".to_owned())
        );
        let timed_out = WsConnectError::TimedOut { url, after_ms: 5 };
        let shown = timed_out.to_string();
        assert_eq!(
            timed_out.into_task::<IpeError>(),
            IpeResult::Err(IpeError::unexpected(shown)),
            "a failure that is no ceiling keeps the Unexpected kind"
        );
    }

    /// A transport failure keeps only its class, never the error's text.
    #[test]
    fn transport_failures_keep_only_their_class() {
        use tokio_tungstenite::tungstenite::error::UrlError;
        let unable = tokio_tungstenite::tungstenite::Error::Url(UrlError::UnableToConnect(
            "wss://admin:s3cr3t@x.example/?token=t0k3n".to_owned(),
        ));
        assert_eq!(WsFailure::of(&unable), WsFailure::Url);
        let shown = WsFailure::of(&unable).to_string();
        for secret in ["admin", "s3cr3t", "x.example", "t0k3n"] {
            assert!(!shown.contains(secret), "{secret:?} leaked into {shown}");
        }
        let io = tokio_tungstenite::tungstenite::Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "pinned dial 73.150.2.210:80 failed",
        ));
        assert_eq!(
            WsFailure::of(&io),
            WsFailure::Io(std::io::ErrorKind::ConnectionRefused)
        );
        assert!(!WsFailure::of(&io).to_string().contains("73.150.2.210"));
    }

    /// A message at the ceiling is read whole and one byte past it is a
    /// capacity failure, under the configuration every connect uses.
    #[tokio::test]
    async fn a_message_past_the_ceiling_is_a_capacity_failure() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut socket = tokio_tungstenite::accept_async(server_io).await.ok()?;
            for len in [16, 17] {
                socket
                    .send(Message::Text("x".repeat(len).into()))
                    .await
                    .ok()?;
            }
            Some(socket)
        });
        let req = "ws://peer.example/".into_client_request();
        assert!(req.is_ok(), "{req:?}");
        let Ok(req) = req else { return };
        let opened =
            tokio_tungstenite::client_async_with_config(req, client_io, Some(ws_config(16))).await;
        assert!(opened.is_ok(), "{:?}", opened.as_ref().err());
        let Ok((mut socket, _)) = opened else { return };
        let at_ceiling = socket.next().await;
        assert!(
            matches!(at_ceiling, Some(Ok(Message::Text(ref t))) if t.len() == 16),
            "{at_ceiling:?}"
        );
        let past_ceiling = socket.next().await;
        let failure = match past_ceiling {
            Some(Err(ref e)) => Some(WsFailure::of(e)),
            _ => None,
        };
        assert_eq!(failure, Some(WsFailure::Capacity), "{past_ceiling:?}");
        drop(socket);
        let _server = server.await;
    }

    /// The outbound buffer is finite: the write target plus one framed message.
    #[test]
    fn the_write_buffer_is_bounded_by_the_ceiling() {
        for ceiling in [1, 1024 * 1024, usize::MAX] {
            let config = ws_config(ceiling);
            assert_eq!(
                config.max_write_buffer_size,
                (128 * 1024_usize)
                    .saturating_add(ceiling)
                    .saturating_add(14),
                "ceiling {ceiling}"
            );
            assert!(
                config.max_write_buffer_size > config.write_buffer_size,
                "ceiling {ceiling}: tungstenite refuses a bound at or below the write target"
            );
            assert_eq!(config.max_message_size, Some(ceiling));
            assert_eq!(config.max_frame_size, Some(ceiling));
        }
        assert!(ws_config(1024 * 1024).max_write_buffer_size < usize::MAX);
    }

    /// The CA that signed [`TLS_SERVER_PEM`]; in no public root store.
    const TLS_CA_PEM: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/pg_tls/ca.pem"
    ));

    /// A server certificate valid only for [`TLS_HOST`].
    const TLS_SERVER_PEM: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/pg_tls/server.pem"
    ));

    /// The private key of [`TLS_SERVER_PEM`].
    const TLS_SERVER_KEY: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/pg_tls/server.key"
    ));

    /// The only name [`TLS_SERVER_PEM`] is valid for.
    const TLS_HOST: &str = "db.example.test";

    /// The local TLS server's configuration, serving [`TLS_SERVER_PEM`].
    fn tls_server_config() -> Option<rustls::ServerConfig> {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let certs = CertificateDer::pem_slice_iter(TLS_SERVER_PEM)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        let key = PrivateKeyDer::from_pem_slice(TLS_SERVER_KEY).ok()?;
        rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .ok()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .ok()
    }

    /// Serve one TLS client on `listener`; whether its handshake completed.
    fn serve_one_tls_client(listener: std::net::TcpListener) -> Option<bool> {
        let (mut tcp, _) = listener.accept().ok()?;
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok()?;
        let mut tls =
            rustls::ServerConnection::new(std::sync::Arc::new(tls_server_config()?)).ok()?;
        while tls.is_handshaking() {
            if tls.complete_io(&mut tcp).is_err() {
                break;
            }
        }
        Some(!tls.is_handshaking())
    }

    /// The runtime's TLS handshake as [`TLS_HOST`] against a local server, under
    /// `config`; and whether the server finished its side.
    async fn tls_handshake_with(
        config: std::sync::Arc<rustls::ClientConfig>,
    ) -> (Result<(), WsFailure>, Option<bool>) {
        let setup = Err(WsFailure::Io(std::io::ErrorKind::Other));
        let listener = std::net::TcpListener::bind("127.0.0.1:0");
        assert!(listener.is_ok(), "{:?}", listener.as_ref().err());
        let Ok(listener) = listener else {
            return (setup, None);
        };
        let Ok(addr) = listener.local_addr() else {
            return (setup, None);
        };
        #[allow(clippy::expect_used)] // a test thread that cannot start must fail the test
        let server = std::thread::Builder::new()
            .spawn(move || serve_one_tls_client(listener))
            .expect("spawn test thread");
        let tcp = tokio::net::TcpStream::connect(addr).await;
        assert!(tcp.is_ok(), "{:?}", tcp.as_ref().err());
        let Ok(tcp) = tcp else {
            return (setup, None);
        };
        let name = rustls::pki_types::ServerName::try_from(TLS_HOST);
        assert!(name.is_ok(), "{name:?}");
        let Ok(name) = name else {
            return (setup, None);
        };
        let outcome = tls_handshake(tcp, name, config).await.map(drop);
        (outcome, server.join().ok().flatten())
    }

    /// A `wss://` server whose certificate chains to no webpki root is refused
    /// with the typed TLS failure; the same server passes under a store that
    /// trusts its CA, so the refusal is the root store's.
    #[tokio::test]
    async fn wss_refuses_a_certificate_outside_the_webpki_roots() {
        let webpki = wss_tls_config();
        assert!(
            webpki.is_some(),
            "the ring provider admits a safe protocol version"
        );
        let Some(webpki) = webpki else { return };
        let (refused, server_done) = tls_handshake_with(webpki).await;
        assert_eq!(refused, Err(WsFailure::Tls));
        assert_eq!(
            server_done,
            Some(false),
            "the server saw a completed handshake"
        );

        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        for ca in CertificateDer::pem_slice_iter(TLS_CA_PEM) {
            assert!(ca.is_ok(), "{:?}", ca.as_ref().err());
            if let Ok(ca) = ca {
                assert!(roots.add(ca).is_ok(), "the test CA parses");
            }
        }
        let trusting = tls_client_config(roots).map(std::sync::Arc::new);
        assert!(trusting.is_some());
        let Some(trusting) = trusting else { return };
        let (accepted, _) = tls_handshake_with(trusting).await;
        assert_eq!(accepted, Ok(()), "a trusted server must pass");
    }

    /// A subscription sink collecting every emitted message.
    #[derive(Clone)]
    struct Inbox(tokio::sync::mpsc::UnboundedSender<WsClientMessage>);

    impl crate::tea::SubSink<WsClientMessage> for Inbox {
        fn deliver(&self, msg: WsClientMessage) -> impl std::future::Future<Output = bool> + Send {
            std::future::ready(self.0.send(msg).is_ok())
        }

        fn emit(&self, msg: WsClientMessage) {
            let _ = self.0.send(msg);
        }
    }

    /// An outbound payload past the socket's ceiling is a `LimitExceeded`
    /// refusal and is never queued; one at the ceiling is queued, and a full
    /// queue or an unknown id is refused by name.
    #[tokio::test]
    async fn an_outbound_message_past_the_ceiling_is_refused_before_queueing() {
        let id = WS_CLIENT_NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<WsCmd>(1);
        let (frames_tx, _) = tokio::sync::broadcast::channel::<WsEvent>(8);
        let task = tokio::spawn(std::future::pending::<()>());
        registry().lock().unwrap_or_else(|e| e.into_inner()).insert(
            id,
            ClientEntry {
                cmd_tx,
                frames_tx,
                task: task.abort_handle(),
                closing: std::sync::Arc::new(tokio::sync::Notify::new()),
                ceiling: 4,
            },
        );

        assert_eq!(
            web_socket_send::<IpeError>(id, "12345".to_owned()).await,
            IpeResult::Err(IpeError::limit_exceeded(
                "WebSocket.send: message of 5 bytes exceeds the 4-byte limit"
            ))
        );
        assert_eq!(
            web_socket_send_binary::<IpeError>(id, vec![0; 5]).await,
            IpeResult::Err(IpeError::limit_exceeded(
                "WebSocket.sendBinary: message of 5 bytes exceeds the 4-byte limit"
            ))
        );
        assert!(cmd_rx.try_recv().is_err(), "a refused payload was queued");

        assert_eq!(
            web_socket_send::<IpeError>(id, "1234".to_owned()).await,
            ok_res(())
        );
        assert_eq!(
            web_socket_send_binary::<IpeError>(id, vec![0; 4]).await,
            IpeResult::Err(IpeError::unexpected(format!(
                "WebSocket.sendBinary: socket {id} outbound queue is full"
            )))
        );
        assert!(matches!(cmd_rx.try_recv(), Ok(WsCmd::Text(t)) if t == "1234"));

        deregister(id);
        task.abort();
        assert_eq!(
            web_socket_send::<IpeError>(id, String::new()).await,
            IpeResult::Err(IpeError::unexpected(format!(
                "WebSocket.send: no socket {id}"
            )))
        );
    }

    /// The `onMessage` listener started by the first subscribe keeps running
    /// when the loop re-evaluates its subscriptions, and a re-subscribe starts
    /// no second listener.
    #[tokio::test]
    async fn ws_message_listener_survives_reconcile() {
        const DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
        let id = WS_CLIENT_NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let (cmd_tx, _cmd_rx) = tokio::sync::mpsc::channel::<WsCmd>(1);
        let (frames_tx, _) = tokio::sync::broadcast::channel::<WsEvent>(8);
        let task = tokio::spawn(std::future::pending::<()>());
        registry().lock().unwrap_or_else(|e| e.into_inner()).insert(
            id,
            ClientEntry {
                cmd_tx,
                frames_tx: frames_tx.clone(),
                task: task.abort_handle(),
                closing: std::sync::Arc::new(tokio::sync::Notify::new()),
                ceiling: 1024,
            },
        );

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut subs = crate::tea::SubRuntime::new(Inbox(tx));
        let on_message = || sub_subscribe_ws_message(id, |m: WsClientMessage| m);
        subs.reconcile(on_message());
        subs.reconcile(on_message());
        let subscribed = tokio::time::timeout(DEADLINE, async {
            while frames_tx.receiver_count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(subscribed.is_ok(), "the listener survives re-evaluation");
        assert_eq!(
            frames_tx.receiver_count(),
            1,
            "a re-subscribe starts no second listener"
        );

        let sent = frames_tx.send(WsEvent::Message(WsClientMessage::Text("hi".to_owned())));
        assert!(sent.is_ok());
        let first = tokio::time::timeout(DEADLINE, rx.recv()).await;
        assert!(
            matches!(&first, Ok(Some(WsClientMessage::Text(t))) if t == "hi"),
            "the frame reaches the loop"
        );
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            rx.try_recv().is_err(),
            "the frame reaches the loop exactly once"
        );

        drop(subs);
        deregister(id);
        task.abort();
    }

    /// A started client socket over `client` with messages capped at
    /// `ceiling`, and the peer's end of it over `server`.
    async fn started_pair<C>(
        client: C,
        server: tokio::io::DuplexStream,
        ceiling: usize,
    ) -> Option<(
        i64,
        tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
    )>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let peer = tokio::spawn(tokio_tungstenite::accept_async(server));
        let req = "ws://peer.example/".into_client_request().ok()?;
        let (socket, _) =
            tokio_tungstenite::client_async_with_config(req, client, Some(ws_config(ceiling)))
                .await
                .ok()?;
        let peer = peer.await.ok()?.ok()?;
        Some((start_socket(socket, ceiling, 0), peer))
    }

    /// A stream whose writes fail once `broken` is set; reads pass through.
    struct WritesFail {
        io: tokio::io::DuplexStream,
        broken: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl tokio::io::AsyncRead for WritesFail {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for WritesFail {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if this.broken.load(Ordering::SeqCst) {
                return std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            std::pin::Pin::new(&mut this.io).poll_write(cx, buf)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().io).poll_flush(cx)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
        }
    }

    /// A send made while the outbound buffer is full of pongs to a peer that
    /// pinged without reading reaches the peer once it reads again.
    #[tokio::test]
    async fn a_send_behind_a_pong_backlog_reaches_the_peer() {
        const DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
        // Enough pings that their pongs fill the write buffer past its bound.
        const PINGS: usize = 32 * 1024;
        let (client_io, server_io) = tokio::io::duplex(1024);
        let pair = started_pair(client_io, server_io, 16).await;
        assert!(pair.is_some(), "the socket opens");
        let Some((id, mut peer)) = pair else { return };
        let events = subscribe_events(id);
        assert!(events.is_some(), "the socket is registered");
        let Some(mut events) = events else { return };

        let pinged = tokio::time::timeout(DEADLINE, async {
            for _ in 0..PINGS {
                let ping = Message::Ping(tokio_tungstenite::tungstenite::Bytes::new());
                peer.send(ping).await.ok()?;
            }
            peer.send(Message::Text("mark".into())).await.ok()
        })
        .await;
        assert!(matches!(pinged, Ok(Some(()))), "the peer pings");
        let mark = tokio::time::timeout(DEADLINE, events.recv()).await;
        assert!(
            matches!(&mark, Ok(Ok(WsEvent::Message(WsClientMessage::Text(t)))) if t == "mark"),
            "every ping was read: {mark:?}"
        );

        assert_eq!(
            web_socket_send::<IpeError>(id, "payload".to_owned()).await,
            ok_res(())
        );
        let received = tokio::time::timeout(DEADLINE, async {
            while let Some(Ok(message)) = peer.next().await {
                if let Message::Text(text) = message {
                    return Some(text.as_str().to_owned());
                }
            }
            None
        })
        .await;
        assert!(
            matches!(&received, Ok(Some(t)) if t == "payload"),
            "the send was lost: {received:?}"
        );
        deregister(id);
    }

    /// A close the peer never answers ends the socket after the grace period,
    /// reported as an abnormal closure.
    #[tokio::test(start_paused = true)]
    async fn an_unanswered_close_ends_the_socket() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let pair = started_pair(client_io, server_io, 16).await;
        assert!(pair.is_some(), "the socket opens");
        // The peer is held but never read, so it never answers the close.
        let Some((id, _peer)) = pair else { return };
        let events = subscribe_events(id);
        assert!(events.is_some(), "the socket is registered");
        let Some(mut events) = events else { return };

        assert_eq!(web_socket_close::<IpeError>(id).await, ok_res(()));
        let wait = WS_CLOSE_GRACE.saturating_mul(4);
        let closed = tokio::time::timeout(wait, events.recv()).await;
        assert!(
            matches!(closed, Ok(Ok(WsEvent::Closed(WS_ABNORMAL_CLOSURE)))),
            "{closed:?}"
        );
        let ended = tokio::time::timeout(wait, events.recv()).await;
        assert!(
            matches!(
                ended,
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed))
            ),
            "the socket's task ended: {ended:?}"
        );
    }

    /// A failed write tears the socket down: the subscribers see the write
    /// error and the id no longer names a socket.
    #[tokio::test]
    async fn a_failed_write_tears_the_socket_down() {
        const DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let broken = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let client = WritesFail {
            io: client_io,
            broken: std::sync::Arc::clone(&broken),
        };
        let pair = started_pair(client, server_io, 16).await;
        assert!(pair.is_some(), "the socket opens");
        let Some((id, _peer)) = pair else { return };
        let events = subscribe_events(id);
        assert!(events.is_some(), "the socket is registered");
        let Some(mut events) = events else { return };

        broken.store(true, Ordering::SeqCst);
        assert_eq!(
            web_socket_send::<IpeError>(id, "x".to_owned()).await,
            ok_res(())
        );
        let failed = tokio::time::timeout(DEADLINE, events.recv()).await;
        assert!(
            matches!(
                failed,
                Ok(Ok(WsEvent::Error(
                    WsSide::Write,
                    WsFailure::Io(std::io::ErrorKind::BrokenPipe)
                )))
            ),
            "{failed:?}"
        );
        assert!(!ws_registered(id), "the failed socket is deregistered");
        assert_eq!(
            web_socket_send::<IpeError>(id, "x".to_owned()).await,
            IpeResult::Err(IpeError::unexpected(format!(
                "WebSocket.send: no socket {id}"
            )))
        );
    }

    /// A send to a socket whose task has ended is refused as closed, never as
    /// a full queue, and a close of it deregisters it.
    #[tokio::test]
    async fn a_send_to_an_ended_socket_is_refused_as_closed() {
        let id = WS_CLIENT_NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<WsCmd>(1);
        drop(cmd_rx);
        let (frames_tx, _) = tokio::sync::broadcast::channel::<WsEvent>(8);
        let task = tokio::spawn(std::future::ready(()));
        registry().lock().unwrap_or_else(|e| e.into_inner()).insert(
            id,
            ClientEntry {
                cmd_tx,
                frames_tx,
                task: task.abort_handle(),
                closing: std::sync::Arc::new(tokio::sync::Notify::new()),
                ceiling: 16,
            },
        );
        assert_eq!(
            web_socket_send::<IpeError>(id, "x".to_owned()).await,
            IpeResult::Err(IpeError::unexpected(format!(
                "WebSocket.send: socket {id} is closed"
            )))
        );
        assert_eq!(
            send_cmd(id, WsCmd::Close),
            Ok(()),
            "a close of an ended socket succeeds"
        );
        assert!(!ws_registered(id), "and deregisters it");
    }

    /// A close reason keeps at most 123 bytes, cut on a character boundary.
    #[test]
    fn a_close_reason_is_cut_to_the_control_frame_bound() {
        let at_bound = "a".repeat(123);
        assert_eq!(CloseReason::new(at_bound.clone()).as_str(), at_bound);
        assert_eq!(CloseReason::new("a".repeat(124)).as_str(), at_bound);
        // `é` is two bytes: 61 of them fill 122, a 62nd would pass 123.
        assert_eq!(CloseReason::new("é".repeat(62)).as_str(), "é".repeat(61));
        assert_eq!(CloseReason::new(String::new()).as_str(), "");
    }

    /// `closeWithCode` with an over-long reason sends a close frame the peer
    /// accepts, the reason cut to the control-frame bound.
    #[tokio::test]
    async fn close_with_code_sends_a_bounded_reason() {
        const DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let pair = started_pair(client_io, server_io, 16).await;
        assert!(pair.is_some(), "the socket opens");
        let Some((id, mut peer)) = pair else { return };

        assert_eq!(
            web_socket_close_with_code::<IpeError>(4000, "é".repeat(200), id).await,
            ok_res(())
        );
        let close = tokio::time::timeout(DEADLINE, peer.next()).await;
        assert!(
            matches!(close, Ok(Some(Ok(Message::Close(Some(_)))))),
            "the peer refused the close frame: {close:?}"
        );
        let Ok(Some(Ok(Message::Close(Some(frame))))) = close else {
            return;
        };
        assert_eq!(u16::from(frame.code), 4000);
        assert_eq!(frame.reason.as_str(), "é".repeat(61));
    }

    #[test]
    fn close_code_mapping() {
        assert_eq!(ws_close_code(1000), WsCloseCode::Normal);
        assert_eq!(ws_close_code(1001), WsCloseCode::GoingAway);
        assert_eq!(ws_close_code(1003), WsCloseCode::UnsupportedData);
        assert_eq!(ws_close_code(1011), WsCloseCode::InternalError);
        assert_eq!(ws_close_code(4000), WsCloseCode::Custom(4000));
    }
}

// ---------------------------------------------------------------------------
// wasm32 browser substitute — `web_sys::WebSocket`
// ---------------------------------------------------------------------------
//
// Task-tier (connect/connectWith/send/sendBinary/close/closeWithCode) PLUS
// the Sub-tier receive surface (onOpen/onMessage/onClose/onError), both via
// `web_sys::WebSocket`. The four `on*` handlers are wired against the
// browser's own single-slot `onopen`/`onmessage`/`onclose`/`onerror`
// properties (see the `sub_subscribe_ws_*` fns below) — the `KernelFn`
// arm that routes codegen here (`emit_expr.rs`'s `SubSubscribeWebSocket`
// peephole) is target-neutral and was already wired; the wasm side just had
// no runtime symbol to land on before this.
//
// No SSRF guard here (unlike the native `do_connect`, which resolves + pins
// the host): a browser tab cannot open a raw socket or bypass the browser's
// own network stack, so `IPE_HTTP_DENY_PRIVATE`'s DNS-pin mechanism has no
// browser analogue — same rationale as the `fetch` substitute in
// `http_client.rs`. A connect failure (refused, CORS-equivalent origin block,
// TLS error, DNS failure) surfaces through the socket's `error`/`close` event,
// which this substitute maps to `Task.fail` on `send`/`close` calls against a
// never-opened id — never a panic/trap.
// The browser `WebSocket` substitute is gated on `all(wasm32, wasm-client)`,
// never a bare `wasm32`: the co-located WASI target (`wasm32-wasip1`,
// `wasm-client` off) carries no `web-sys`/`wasm-bindgen`, so a bare-`wasm32`
// arm would compile these browser bindings into a WASI build and fail cargo.
// `websocket_client` is not WASI-viable (its native arm is `tokio/net`, which
// does not build for wasm), so on WASI this substitute stays absent entirely.
#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
mod wasm_client {
    use super::{HashMap, IpeResult, IpeSub, IpeTask, ok_res};
    use std::cell::{Cell, RefCell};
    use std::collections::HashSet;
    use std::rc::Rc;
    use wasm_bindgen::JsCast;
    use wasm_bindgen::closure::Closure;

    thread_local! {
        static SOCKETS: RefCell<HashMap<i64, web_sys::WebSocket>> = RefCell::new(HashMap::new());
    }
    thread_local! {
        static NEXT_ID: Cell<i64> = const { Cell::new(1) };
    }

    fn next_id() -> i64 {
        NEXT_ID.with(|c| {
            let id = c.get();
            c.set(id + 1);
            id
        })
    }

    /// `IpeResult` has no `From<Result<A, E>>` impl (the ADT is Ipê-shaped, not
    /// a `std::result` newtype) — this is the total bridge every fn below uses.
    fn to_ipe<E, A>(r: Result<A, E>) -> IpeResult<E, A> {
        match r {
            Ok(a) => IpeResult::Ok(a),
            Err(e) => IpeResult::Err(e),
        }
    }

    fn open_socket<E: From<String> + 'static>(url: &str) -> Result<i64, E> {
        // Neither the URL nor the browser's exception is echoed: the URL can
        // carry credentials and the exception text quotes it verbatim.
        let ws = web_sys::WebSocket::new(url).map_err(|_| {
            E::from(
                "WebSocket.connect: the browser refused the URL (malformed, or a scheme or \
                 port it blocks)"
                    .to_owned(),
            )
        })?;
        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);
        let id = next_id();
        SOCKETS.with(|s| s.borrow_mut().insert(id, ws));
        Ok(id)
    }

    /// `WebSocket.connect : String -> Task Error Int` — `web_sys::WebSocket::new`
    /// starts connecting asynchronously and returns immediately (readyState
    /// `CONNECTING`), matching the native surface's raw-id contract; `send`
    /// before the handshake completes is rejected below rather than trapping.
    pub fn web_socket_connect<E: From<String> + 'static>(url: String) -> IpeTask<E, i64> {
        Box::pin(async move { to_ipe(open_socket(&url)) })
    }

    /// `WebSocket.connectWith : WebSocketCfg -> Task Error Int`. `cfg.headers`
    /// cannot be attached: the browser `WebSocket` constructor has no header
    /// parameter (a real platform limitation, not a dropped feature on our
    /// side) — surfaced as a console warning rather than a silent drop.
    /// `cfg.timeout`/`cfg.pingInterval` have no browser-substitute wiring yet
    /// (the browser auto-manages ping/pong at the protocol level).
    pub fn web_socket_connect_with<E: From<String> + 'static>(
        cfg: super::WsClientCfg,
    ) -> IpeTask<E, i64> {
        Box::pin(async move {
            if !cfg.headers.is_empty() {
                crate::wasm::console_warn(
                    "Ipe.WebSocket.connectWith: custom headers are not settable via the \
                     browser WebSocket API; ignored",
                );
            }
            to_ipe(open_socket(&cfg.url))
        })
    }

    fn with_open_socket<E: From<String> + 'static, R>(
        id: i64,
        op_name: &str,
        f: impl FnOnce(&web_sys::WebSocket) -> Result<R, wasm_bindgen::JsValue>,
    ) -> Result<R, E> {
        SOCKETS.with(|s| {
            let sockets = s.borrow();
            let Some(ws) = sockets.get(&id) else {
                return Err(E::from(format!("{op_name}: no socket {id}")));
            };
            if ws.ready_state() != web_sys::WebSocket::OPEN {
                return Err(E::from(format!("{op_name}: socket {id} is not open")));
            }
            // The browser's exception text is not echoed: it may quote the
            // socket's URL, which can carry credentials.
            f(ws).map_err(|_| E::from(format!("{op_name}: the browser refused the operation")))
        })
    }

    /// `WebSocket.send : Int -> String -> Task Error ()`.
    pub fn web_socket_send<E: From<String> + 'static>(id: i64, msg: String) -> IpeTask<E, ()> {
        Box::pin(async move {
            to_ipe(with_open_socket(id, "WebSocket.send", |ws| {
                ws.send_with_str(&msg)
            }))
        })
    }

    /// `WebSocket.sendBinary : Int -> Bytes -> Task Error ()`.
    pub fn web_socket_send_binary<E: From<String> + 'static>(
        id: i64,
        msg: Vec<u8>,
    ) -> IpeTask<E, ()> {
        Box::pin(async move {
            to_ipe(with_open_socket(id, "WebSocket.sendBinary", |ws| {
                ws.send_with_u8_array(&msg)
            }))
        })
    }

    fn close_socket(id: i64, code: Option<(u16, CloseReason)>) {
        SOCKETS.with(|s| {
            if let Some(ws) = s.borrow_mut().remove(&id) {
                // The browser refuses a code outside 1000 and 3000..=4999; the
                // socket is closed plainly then, never left open without a
                // handle.
                let coded = match code {
                    Some((c, reason)) => ws.close_with_code_and_reason(c, reason.as_str()),
                    None => ws.close(),
                };
                if coded.is_err() {
                    let _ = ws.close();
                }
            }
        });
        // Mirrors the native `deregister`'s `ws_subscribed()` cleanup — ids
        // are monotonic and never reused, so this is hygiene (bounding
        // `WS_ONCE_OPEN`'s size across a long page session), not correctness.
        WS_ONCE_OPEN.with(|s| {
            s.borrow_mut().remove(&id);
        });
    }

    /// `WebSocket.close : Int -> Task Error ()` (idempotent, matches native).
    pub fn web_socket_close<E: 'static>(id: i64) -> IpeTask<E, ()> {
        Box::pin(async move {
            close_socket(id, None);
            ok_res(())
        })
    }

    /// `WebSocket.closeWithCode : Int -> String -> Int -> Task Error ()`. Same
    /// truncation guard as the native arm — an out-of-range code falls back to
    /// 1000 (normal closure) rather than silently wrapping.
    pub fn web_socket_close_with_code<E: 'static>(
        code: i64,
        reason: String,
        id: i64,
    ) -> IpeTask<E, ()> {
        Box::pin(async move {
            let ws_code = u16::try_from(code).unwrap_or(1000);
            close_socket(id, Some((ws_code, CloseReason::new(reason))));
            ok_res(())
        })
    }

    // ── Sub-tier: onOpen / onMessage / onClose / onError ───────────────────
    //
    // `web_sys::WebSocket`'s event-handler slots (`onopen`/`onmessage`/
    // `onclose`/`onerror`) are single-slot — setting one replaces whatever was
    // there before. `wasm::subs::SubManager::update` tears down every active
    // `IpeSub::Source` (running its teardown thunk) BEFORE respawning from the
    // freshly computed `Sub` tree, so the old handler is always cleared before
    // a new one is installed — no duplicate-delivery risk the native arm's
    // `ws_subscribed()` re-spawn dedupe exists to prevent.
    //
    // `onOpen` is the one exception: it must still fire AT MOST ONCE across the
    // socket's lifetime (mirrors the native contract + this module's stdlib doc
    // comment), and the browser's own `open` event only fires once natively —
    // the wasm-specific hazard is the RACE where the socket is already `OPEN`
    // by subscribe time (every later re-render respawns every active `Sub`,
    // including this one, well after the handshake completed) and a naive
    // "emit immediately if already open" check would refire on every
    // subsequent re-render. `WS_ONCE_OPEN` is the persistent (never torn down
    // by `stop_all`) one-shot marker that prevents that.
    thread_local! {
        static WS_ONCE_OPEN: RefCell<HashSet<i64>> = RefCell::new(HashSet::new());
    }

    /// Returns `true` the FIRST time it is called for a given `socket_id`
    /// (and records it), `false` on every call after — the one-shot gate
    /// `sub_subscribe_ws_open` uses to guarantee at-most-once delivery.
    fn ws_mark_open_once(socket_id: i64) -> bool {
        WS_ONCE_OPEN.with(|s| s.borrow_mut().insert(socket_id))
    }

    /// Decode a browser `MessageEvent.data()` into the Ipê `WebSocketMessage`
    /// shape. `open_socket` pins `set_binary_type(Arraybuffer)`, so a binary
    /// frame always arrives as an `ArrayBuffer`, never a `Blob`; a text frame
    /// arrives as a JS string. Any other payload shape is unreachable from a
    /// spec-compliant browser given that pin, so it is dropped rather than
    /// guessed at — fail-closed, never invents a frame.
    fn decode_message_event(ev: &web_sys::MessageEvent) -> Option<super::WsClientMessage> {
        let data = ev.data();
        if let Some(text) = data.as_string() {
            return Some(super::WsClientMessage::Text(text));
        }
        if let Ok(buf) = data.dyn_into::<js_sys::ArrayBuffer>() {
            return Some(super::WsClientMessage::Binary(
                js_sys::Uint8Array::new(&buf).to_vec(),
            ));
        }
        None
    }

    /// `onOpen : WebSocket -> msg -> Sub msg` — dispatch `msg` once the
    /// socket is connected. `M` needs no `Send`/`Sync` bound (wasm32 is
    /// single-threaded — same relaxation `wasm::pubsub` already uses).
    pub fn sub_subscribe_ws_open<M: 'static>(socket_id: i64, msg: M) -> IpeSub<M> {
        IpeSub::Source(Box::new(move |emit: Rc<dyn Fn(M)>| {
            let already_open = SOCKETS.with(|s| {
                s.borrow()
                    .get(&socket_id)
                    .is_some_and(|ws| ws.ready_state() == web_sys::WebSocket::OPEN)
            });
            if already_open {
                if ws_mark_open_once(socket_id) {
                    emit(msg);
                }
                return Box::new(|| {}) as Box<dyn FnOnce()>;
            }
            let sid = socket_id;
            // `RefCell<Option<M>>` (not a plain move into the closure) so the
            // handler type-checks as `FnMut` while still only ever handing
            // `msg` to `emit` once — `.take()` makes the second call (there
            // never should be one; browsers fire `open` exactly once) a no-op
            // instead of a double-emit.
            let msg_cell: Rc<RefCell<Option<M>>> = Rc::new(RefCell::new(Some(msg)));
            let closure_slot: Rc<RefCell<Option<Closure<dyn FnMut(web_sys::Event)>>>> =
                Rc::new(RefCell::new(None));
            SOCKETS.with(|s| {
                if let Some(ws) = s.borrow().get(&sid) {
                    let emit = Rc::clone(&emit);
                    let msg_cell = Rc::clone(&msg_cell);
                    let closure = Closure::wrap(Box::new(move |_ev: web_sys::Event| {
                        if ws_mark_open_once(sid)
                            && let Some(m) = msg_cell.borrow_mut().take()
                        {
                            emit(m);
                        }
                    })
                        as Box<dyn FnMut(web_sys::Event)>);
                    ws.set_onopen(Some(closure.as_ref().unchecked_ref()));
                    *closure_slot.borrow_mut() = Some(closure);
                }
            });
            Box::new(move || {
                SOCKETS.with(|s| {
                    if let Some(ws) = s.borrow().get(&sid) {
                        ws.set_onopen(None);
                    }
                });
                drop(closure_slot);
                drop(msg_cell);
            })
        }))
    }

    /// `onMessage : WebSocket -> (WebSocketMessage -> msg) -> Sub msg`.
    pub fn sub_subscribe_ws_message<M, F>(socket_id: i64, to_msg: F) -> IpeSub<M>
    where
        M: 'static,
        F: Fn(super::WsClientMessage) -> M + 'static,
    {
        IpeSub::Source(Box::new(move |emit: Rc<dyn Fn(M)>| {
            let sid = socket_id;
            let closure_slot: Rc<RefCell<Option<Closure<dyn FnMut(web_sys::MessageEvent)>>>> =
                Rc::new(RefCell::new(None));
            SOCKETS.with(|s| {
                if let Some(ws) = s.borrow().get(&sid) {
                    let emit = Rc::clone(&emit);
                    let closure = Closure::wrap(Box::new(move |ev: web_sys::MessageEvent| {
                        if let Some(m) = decode_message_event(&ev) {
                            emit(to_msg(m));
                        }
                    })
                        as Box<dyn FnMut(web_sys::MessageEvent)>);
                    ws.set_onmessage(Some(closure.as_ref().unchecked_ref()));
                    *closure_slot.borrow_mut() = Some(closure);
                }
            });
            Box::new(move || {
                SOCKETS.with(|s| {
                    if let Some(ws) = s.borrow().get(&sid) {
                        ws.set_onmessage(None);
                    }
                });
                drop(closure_slot);
            })
        }))
    }

    /// `onClose : WebSocket -> (CloseCode -> msg) -> Sub msg`.
    pub fn sub_subscribe_ws_close<M, F>(socket_id: i64, to_msg: F) -> IpeSub<M>
    where
        M: 'static,
        F: Fn(super::WsCloseCode) -> M + 'static,
    {
        IpeSub::Source(Box::new(move |emit: Rc<dyn Fn(M)>| {
            let sid = socket_id;
            let closure_slot: Rc<RefCell<Option<Closure<dyn FnMut(web_sys::CloseEvent)>>>> =
                Rc::new(RefCell::new(None));
            SOCKETS.with(|s| {
                if let Some(ws) = s.borrow().get(&sid) {
                    let emit = Rc::clone(&emit);
                    let closure = Closure::wrap(Box::new(move |ev: web_sys::CloseEvent| {
                        let code = super::ws_close_code(i64::from(ev.code()));
                        emit(to_msg(code));
                    })
                        as Box<dyn FnMut(web_sys::CloseEvent)>);
                    ws.set_onclose(Some(closure.as_ref().unchecked_ref()));
                    *closure_slot.borrow_mut() = Some(closure);
                }
            });
            Box::new(move || {
                SOCKETS.with(|s| {
                    if let Some(ws) = s.borrow().get(&sid) {
                        ws.set_onclose(None);
                    }
                });
                drop(closure_slot);
            })
        }))
    }

    /// `onError : WebSocket -> (Error -> msg) -> Sub msg`. `E` is the
    /// project error type (`From<String>`).
    ///
    /// The browser's WebSocket `error` event is a plain `Event` carrying no
    /// diagnostic detail by spec (a same-origin-policy privacy rule — this is
    /// not a dropped feature on our side); `close` fires immediately after
    /// every `error` with a real code/reason, so `WebSocket.onClose` is where
    /// app code gets the detail. The message here stays generic rather than
    /// inventing detail the platform never exposes.
    pub fn sub_subscribe_ws_error<E, M, F>(socket_id: i64, to_msg: F) -> IpeSub<M>
    where
        E: From<String> + 'static,
        M: 'static,
        F: Fn(E) -> M + 'static,
    {
        IpeSub::Source(Box::new(move |emit: Rc<dyn Fn(M)>| {
            let sid = socket_id;
            let closure_slot: Rc<RefCell<Option<Closure<dyn FnMut(web_sys::Event)>>>> =
                Rc::new(RefCell::new(None));
            SOCKETS.with(|s| {
                if let Some(ws) = s.borrow().get(&sid) {
                    let emit = Rc::clone(&emit);
                    let closure = Closure::wrap(Box::new(move |_ev: web_sys::Event| {
                        emit(to_msg(E::from(format!(
                            "WebSocket {sid} error (see the close event for a code/reason)"
                        ))));
                    })
                        as Box<dyn FnMut(web_sys::Event)>);
                    ws.set_onerror(Some(closure.as_ref().unchecked_ref()));
                    *closure_slot.borrow_mut() = Some(closure);
                }
            });
            Box::new(move || {
                SOCKETS.with(|s| {
                    if let Some(ws) = s.borrow().get(&sid) {
                        ws.set_onerror(None);
                    }
                });
                drop(closure_slot);
            })
        }))
    }
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
pub use wasm_client::*;

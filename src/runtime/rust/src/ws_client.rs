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
//! is moved into exactly one detached `tokio::spawn` task per subscription,
//! never shared behind an `Arc` — the same contract `sub_subscribe_stream`
//! uses.
//!
//! `--target wasm` gets its own substitute (`wasm_client` below, `web_sys`
//! event-handler slots instead of the broadcast channel this native half
//! uses) — see `ipe_kernels::StdlibKernel::wasm_client_available`'s
//! `KernelClass::Tea` arm for the allowlist tag that makes it resolvable.

use super::*;
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
    Error(String),
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

crate::stringify::show_row!("WebSocketClientCfg", Redacted, [] WsClientCfg, |_| crate::stringify::REDACTED_SHOW.to_owned());

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
    CloseWithCode(u16, String),
}

#[cfg(not(target_arch = "wasm32"))]
struct ClientEntry {
    // Bounded (not unbounded) so a remote peer that stalls reads — wedging the
    // writer task on `write.send().await` — can't make this outbound queue grow
    // without limit (memory DoS). A full queue makes send_cmd return false
    // (try_send) rather than buffering forever.
    cmd_tx: tokio::sync::mpsc::Sender<WsCmd>,
    frames_tx: tokio::sync::broadcast::Sender<WsEvent>,
    // Abort handles for the writer + reader tasks. A Close that can't be enqueued
    // (full queue ⇒ the writer is wedged on a stalled peer) is honoured by
    // aborting BOTH halves — dropping just one leaves the split stream open — so a
    // close request can never strand an open socket. See send_cmd.
    writer_abort: tokio::task::AbortHandle,
    reader_abort: tokio::task::AbortHandle,
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
            Error::Utf8 => Self::Utf8,
            Error::AttackAttempt => Self::AttackAttempt,
            Error::Url(_) => Self::Url,
            Error::Http(response) => Self::HttpStatus(response.status().as_u16()),
            Error::HttpFormat(_) => Self::HttpFormat,
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
    /// This failure as the task's error.
    fn into_task<E: From<String>>(self) -> IpeResult<E, i64> {
        IpeResult::Err(self.to_string().into())
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

#[cfg(not(target_arch = "wasm32"))]
async fn do_connect<E: From<String> + Send + 'static>(
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
    // so tokio-tungstenite never re-resolves the name to a rebind target.
    let dial = match super::ssrf::VettedDial::for_url(&url).await {
        Ok(dial) => dial,
        Err(refusal) => return WsConnectError::Refused(refusal).into_task(),
    };
    // Build the handshake request so custom headers (e.g. Authorization) from
    // connectWith's cfg.headers are sent.
    let Ok(mut req) = url.as_str().into_client_request() else {
        return WsConnectError::BadUrl(safe_url).into_task();
    };
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
    // server-side cap): the prior 16 MiB × the 64-deep broadcast buffer below was
    // ~1 GiB worst-case retained per socket under a lagging subscriber. Override
    // via IPE_WS_MAX_MESSAGE_BYTES for apps that legitimately need larger frames.
    //
    // tokio-tungstenite 0.24 exposes connect_async_with_config which passes a
    // tungstenite::protocol::WebSocketConfig directly to the handshake.
    let max_msg: usize = match WS_MESSAGE_CEILING.read() {
        Ok(cap) => cap,
        Err(refusal) => return WsConnectError::Ceiling(refusal).into_task(),
    };
    let ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
        max_message_size: Some(max_msg),
        max_frame_size: Some(max_msg),
        ..Default::default()
    };
    type WsConnOut = Result<
        (
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            tokio_tungstenite::tungstenite::handshake::client::Response,
        ),
        WsFailure,
    >;
    let connect_fut: std::pin::Pin<Box<dyn std::future::Future<Output = WsConnOut> + Send>> =
        match dial {
            super::ssrf::VettedDial::Pinned(addr) => {
                // When SSRF-pinning is active (IPE_HTTP_DENY_PRIVATE), we dial
                // the already-vetted IP directly via a raw TCP socket, bypassing
                // the name-resolution step. A raw TCP socket carries no TLS
                // context, so a `wss://` URL cannot be serviced here — TLS
                // requires the full resolver path (`connect_async_with_config`,
                // the `Unrestricted` arm below). Refuse rather than dial plaintext
                // to what the caller believes is a secure endpoint. The scheme is
                // read from the parse the gate vetted, never from the raw text,
                // which may differ in case or leading whitespace.
                if !::url::Url::parse(&url).is_ok_and(|parsed| parsed.scheme() == "ws") {
                    return WsConnectError::TlsUnderPin(safe_url).into_task();
                }
                // Dial INSIDE the future so the single handshake timeout below
                // also bounds the pinned TCP connect — otherwise an unreachable
                // / silently-stalling pinned addr would hang here, outside the
                // timeout guard, leaking the task + FD. The failure keeps only
                // its class: the address may re-encode an IP-literal host the
                // displayable URL withholds.
                Box::pin(async move {
                    let tcp = tokio::net::TcpStream::connect(addr.socket_addr())
                        .await
                        .map_err(|e| WsFailure::Dial(e.kind()))?;
                    tokio_tungstenite::client_async_with_config(
                        req,
                        tokio_tungstenite::MaybeTlsStream::Plain(tcp),
                        Some(ws_config),
                    )
                    .await
                    .map_err(|e| WsFailure::of(&e))
                })
            }
            super::ssrf::VettedDial::Unrestricted => Box::pin(async move {
                tokio_tungstenite::connect_async_with_config(req, Some(ws_config), false)
                    .await
                    .map_err(|e| WsFailure::of(&e))
            }),
        };
    // Floor the handshake timeout: a non-positive cfg.timeout must NOT disable it
    // (an unreachable / silently-stalling host would otherwise hang connect_async
    // forever, leaking the task + FD). Default 30 s.
    let to_ms: u64 = if timeout_ms > 0 {
        timeout_ms as u64
    } else {
        30_000
    };
    let (stream, _resp) =
        match tokio::time::timeout(std::time::Duration::from_millis(to_ms), connect_fut).await {
            Ok(Ok(ok)) => ok,
            Ok(Err(failure)) => {
                return WsConnectError::Failed {
                    url: safe_url,
                    failure,
                }
                .into_task();
            }
            Err(_) => {
                return WsConnectError::TimedOut {
                    url: safe_url,
                    after_ms: to_ms,
                }
                .into_task();
            }
        };
    let id = WS_CLIENT_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let (mut write, mut read) = stream.split();
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<WsCmd>(1024);
    let (frames_tx, _) = tokio::sync::broadcast::channel::<WsEvent>(64);

    // Writer task: drain outbound commands → ws frames. When pingInterval > 0,
    // also send a periodic Ping so idle connections survive proxy/server idle
    // timeouts (tungstenite auto-pongs inbound pings on the read side).
    let writer = tokio::spawn(async move {
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
                        if write.send(Message::Ping(Vec::new())).await.is_err() { break; }
                        continue;
                    }
                    c = cmd_rx.recv() => c,
                },
                None => cmd_rx.recv().await,
            };
            let cmd = match cmd {
                Some(c) => c,
                None => break,
            };
            let msg = match cmd {
                WsCmd::Text(s) => Message::Text(s),
                WsCmd::Binary(b) => Message::Binary(b),
                WsCmd::Close => {
                    let _ = write.send(Message::Close(None)).await;
                    break;
                }
                WsCmd::CloseWithCode(code, reason) => {
                    let frame = tokio_tungstenite::tungstenite::protocol::CloseFrame {
                        code: code.into(),
                        reason: reason.into(),
                    };
                    let _ = write.send(Message::Close(Some(frame))).await;
                    break;
                }
            };
            if write.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Reader task: ws frames → frames broadcast (subscriptions drain it). On
    // close/error it deregisters the socket so the writer + subscription tasks
    // wind down (dropping the last frames_tx makes their recv() error) — no leak
    // on server-initiated close / reconnect.
    let writer_abort = writer.abort_handle();
    let frames = frames_tx.clone();
    let reader = tokio::spawn(async move {
        while let Some(item) = read.next().await {
            match item {
                Ok(Message::Text(t)) => {
                    let _ = frames.send(WsEvent::Message(WsClientMessage::Text(t)));
                }
                Ok(Message::Binary(b)) => {
                    // `b` is already `Vec<u8>` from tungstenite — no conversion needed.
                    let _ = frames.send(WsEvent::Message(WsClientMessage::Binary(b)));
                }
                Ok(Message::Close(cf)) => {
                    let code = cf.map(|f| u16::from(f.code) as i64).unwrap_or(1000);
                    let _ = frames.send(WsEvent::Closed(code));
                    break;
                }
                Err(e) => {
                    let failure = WsFailure::of(&e);
                    let _ = frames.send(WsEvent::Error(format!("ws read error: {failure}")));
                    break;
                }
                _ => {} // Ping/Pong handled by tungstenite
            }
        }
        deregister(id);
    });

    let reader_abort = reader.abort_handle();
    registry().lock().unwrap_or_else(|e| e.into_inner()).insert(
        id,
        ClientEntry {
            cmd_tx,
            frames_tx,
            writer_abort,
            reader_abort,
        },
    );
    ok_res(id)
}

/// WebSocket.connect : String -> Task Error Int (raw id; Ipê wraps in WebSocket)
#[cfg(not(target_arch = "wasm32"))]
pub fn web_socket_connect<E: From<String> + Send + 'static>(url: String) -> IpeTask<E, i64> {
    Box::pin(do_connect(url, Vec::new(), 30000, 0))
}

/// WebSocket.connectWith : WebSocketCfg -> Task Error Int. Applies the cfg's
/// custom headers, handshake timeout, and pingInterval (when > 0, the client
/// sends a periodic Ping frame to keep the connection alive through idle proxies;
/// tungstenite auto-pongs inbound pings on the read side).
#[cfg(not(target_arch = "wasm32"))]
pub fn web_socket_connect_with<E: From<String> + Send + 'static>(
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
fn send_cmd(id: i64, cmd: WsCmd) -> bool {
    let is_close = matches!(cmd, WsCmd::Close | WsCmd::CloseWithCode(..));
    // Clone what we need, then RELEASE the registry lock before try_send / abort /
    // deregister (deregister re-locks the registry — holding it here would deadlock).
    let handles = {
        let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        reg.get(&id).map(|e| {
            (
                e.cmd_tx.clone(),
                e.frames_tx.clone(),
                e.writer_abort.clone(),
                e.reader_abort.clone(),
            )
        })
    };
    let (tx, frames, writer_abort, reader_abort) = match handles {
        Some(h) => h,
        None => return false,
    };
    match tx.try_send(cmd) {
        Ok(()) => true,
        Err(_) => {
            // Queue full. For a non-close command we drop it (caller sees false).
            // For a Close, the full queue means the writer is wedged on a stalled
            // peer, so a queued Close would never be sent — guarantee teardown by
            // aborting BOTH halves (drops the split stream → the connection
            // closes), notifying subscribers, and deregistering. Close "succeeds".
            if is_close {
                writer_abort.abort();
                reader_abort.abort();
                let _ = frames.send(WsEvent::Closed(1000));
                deregister(id);
                true
            } else {
                false
            }
        }
    }
}

/// WebSocket.send : Int -> String -> Task Error ()
#[cfg(not(target_arch = "wasm32"))]
pub fn web_socket_send<E: From<String> + Send + 'static>(id: i64, msg: String) -> IpeTask<E, ()> {
    Box::pin(async move {
        if send_cmd(id, WsCmd::Text(msg)) {
            ok_res(())
        } else {
            IpeResult::Err(format!("WebSocket.send: no socket {}", id).into())
        }
    })
}

/// WebSocket.sendBinary : Int -> Bytes -> Task Error ()
#[cfg(not(target_arch = "wasm32"))]
pub fn web_socket_send_binary<E: From<String> + Send + 'static>(
    id: i64,
    msg: Vec<u8>,
) -> IpeTask<E, ()> {
    Box::pin(async move {
        if send_cmd(id, WsCmd::Binary(msg)) {
            ok_res(())
        } else {
            IpeResult::Err(format!("WebSocket.sendBinary: no socket {}", id).into())
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
        let _ = send_cmd(id, WsCmd::CloseWithCode(ws_code, reason));
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
// reconciler aborts + respawns every source on each update, but a broadcast has
// no replay, so a re-spawned receiver would miss frames sent during the gap. So
// the real listener is spawned DETACHED (not the handle `SubRuntime` tracks) the first
// time, and re-subscribes are no-ops — matching  "subsequent re-subscriptions
// are no-ops". The emit callback funnels into the loop channel, stable for the
// program's lifetime.
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
/// `to_msg` is moved exclusively into the ONE detached `tokio::spawn` task
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
            tokio::spawn(async move {
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
            });
        }
        tokio::spawn(async {}) // dummy handle for `SubRuntime` to abort harmlessly
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
        tokio::spawn(async {})
    }))
}

/// onClose : (CloseCode -> msg) -> Sub msg
///
/// Same `Send`-only bound rationale as [`sub_subscribe_ws_message`]:
/// `to_msg` is moved into the single detached `tokio::spawn` below and never
/// shared behind an `Arc`, so `Send + 'static` is the exact contract.
#[cfg(not(target_arch = "wasm32"))]
pub fn sub_subscribe_ws_close<M, F>(socket_id: i64, to_msg: F) -> IpeSub<M>
where
    M: Send + 'static,
    F: Fn(WsCloseCode) -> M + Send + 'static,
{
    IpeSub::Source(Box::new(move |emit| {
        if ws_registered(socket_id) && ws_mark_subscribed(socket_id, WsSubKind::Close) {
            tokio::spawn(async move {
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
            });
        }
        tokio::spawn(async {})
    }))
}

/// onError : (Error -> msg) -> Sub msg. E is the project error (From<String>).
///
/// Same `Send`-only bound rationale as [`sub_subscribe_ws_message`]:
/// `to_msg` is moved into the single detached `tokio::spawn` below and never
/// shared behind an `Arc`, so `Send + 'static` is the exact contract.
#[cfg(not(target_arch = "wasm32"))]
pub fn sub_subscribe_ws_error<E, M, F>(socket_id: i64, to_msg: F) -> IpeSub<M>
where
    E: From<String> + Send + 'static,
    M: Send + 'static,
    F: Fn(E) -> M + Send + 'static,
{
    IpeSub::Source(Box::new(move |emit| {
        if ws_registered(socket_id) && ws_mark_subscribed(socket_id, WsSubKind::Error) {
            tokio::spawn(async move {
                let mut rx = match subscribe_events(socket_id) {
                    Some(rx) => rx,
                    None => return,
                };
                loop {
                    match rx.recv().await {
                        Ok(WsEvent::Error(s)) => {
                            emit(to_msg(s.into()));
                            break;
                        }
                        Ok(_) => {}
                        // Transient lag: skip the gap, keep waiting for the error event.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
        }
        tokio::spawn(async {})
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

    fn close_socket(id: i64, code: Option<(u16, &str)>) {
        SOCKETS.with(|s| {
            if let Some(ws) = s.borrow_mut().remove(&id) {
                let _ = match code {
                    Some((c, reason)) => ws.close_with_code_and_reason(c, reason),
                    None => ws.close(),
                };
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
            close_socket(id, Some((ws_code, &reason)));
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

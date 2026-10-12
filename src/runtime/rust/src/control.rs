//! Shape-agnostic dev-loop control wire — the single parent→child transport
//! definition shared by hot-swap (`ipe dev watch` appearance edits) and the
//! time-travel debugger across the tui/cli/worker/web shapes.
//!
//! ## Why one wire
//!
//! Both features are the same structural problem: a dev-loop capability that
//! `ipe dev watch` (the parent) must deliver into the spawned child. Rather than two
//! ad-hoc message formats — the web hot-appearance JSON body and a separate
//! debugger command channel — every message rides ONE [`ControlFrame`] so the
//! wire is defined exactly once. The per-shape transport (loopback HTTP for web,
//! a loopback control socket for tui/cli/worker) carries this frame unchanged.
//!
//! ## Availability
//!
//! Compiled only when a dev-loop surface is present: the `web` feature (the
//! existing hot-appearance endpoints), the `debugger` feature (the recorder), or
//! `control-wire` (the parent-side `ipe dev watch` sender, which links the codec +
//! `transport` primitives ALONE — no `server` accept-loop). Each implies
//! `serde` + `crypto-core`, so the frame's derives and the constant-time token
//! check are unconditional here. A pure `ipe release` artifact carries none of
//! them, so this module — and every control surface built on it — is absent from
//! production by construction. The tokio `server` accept-loop compiles under
//! the child-side surfaces (`web`/`debugger`) on a native target only, and even
//! then it is inert unless launched with both a control port and a token.
//!
//! ## Bounded by construction
//!
//! A decoded frame is length-delimited and capped at [`MAX_FRAME_LEN`]: a length
//! prefix beyond the cap is rejected before a single payload byte is read, so no
//! remote-supplied length can drive an unbounded allocation.
//!
//! ## No type erasure
//!
//! The frame carries serialized, concrete payloads — an [`AppearancePatch`] or a
//! [`DebugCmd`] — never a `dyn Any`. A shape's transport monomorphizes on its own
//! concrete `(Msg, Model)`; the frame is the wire between them, not an erased
//! carrier of them.

use serde::{Deserialize, Serialize};

/// The largest control frame accepted off the wire, in bytes.
///
/// A length prefix exceeding this cap is refused by [`decode_frame`] before the
/// body is read. The dev-loop's frames are small (an appearance patch or a
/// scrub command); the cap is a generous ceiling that still forecloses an
/// unbounded allocation driven by a malformed or hostile length prefix.
pub const MAX_FRAME_LEN: usize = 1 << 20;

/// An appearance-only hot-swap patch, in wire form.
///
/// Mirrors the classifier's `ViewPatch` (`ipe`-cli `hot_classify`): the running
/// app's PREVIOUS baked-defaults signature (the key its compiled `view` passes to
/// `from_defaults`, hence the runtime overlay's match key) plus the
/// `(index, new_value)` deltas to overlay. The app is never recompiled, so it
/// still bakes the old signature — the patch carries the OLD defaults, not the
/// new. This is the runtime-owned single source of truth for the appearance wire;
/// the classifier's `ViewPatch` mirrors this shape. Collapsing `ViewPatch` into a
/// type alias of this struct is pending the `ipe`-cli-side integration (the tui/
/// cli/worker delivery + apply work), which lands separately.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AppearancePatch {
    /// The PREVIOUS baked defaults, in emit order — the overlay's match key.
    /// An absent field decodes as empty (a patch touching nothing), matching the
    /// tolerant body the web hot-appearance endpoint has always accepted.
    #[serde(default)]
    pub defaults: Vec<String>,
    /// The appearance delta: `(index, new_value)` per changed default.
    #[serde(default)]
    pub patch: Vec<(usize, String)>,
}

/// A time-travel debugger command from `ipe dev watch` (parent) to the child.
///
/// Each variant maps to an operation the recorder already supports on its
/// bounded message ring (`debugger::{History, RecordBuffer}`): stepping the
/// scrub cursor, resetting to the base model, inspecting a step's model, or
/// resuming live tailing. Reconstruction re-folds `update` over the retained
/// messages and re-fires no `Cmd`, so a scrub never perturbs the live model.
#[cfg(feature = "debugger")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugCmd {
    /// Move the scrub cursor to step `n` (reconstruct the model at that step).
    StepTo(usize),
    /// Step the cursor one step toward the base.
    Back,
    /// Step the cursor one step toward the live tail.
    Forward,
    /// Reset the cursor to the base model and resume live mode.
    Reset,
    /// Ask the child to render the model at step `n` and reply with a
    /// [`ControlFrame::ModelSnapshot`].
    InspectModel(usize),
    /// Leave scrub mode and resume tailing live messages.
    LiveTail,
}

/// The one wire message shared by every dev-loop control surface.
///
/// Parent→child carries a hot-swap patch or a debug command; child→parent
/// carries a reply ([`ControlFrame::Ack`] or [`ControlFrame::ModelSnapshot`]).
/// A single enum keeps the wire to one definition — the web loopback endpoints
/// and the tui/cli/worker loopback socket agree by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlFrame {
    /// Parent→child: apply an appearance-only hot-swap (#2749). Re-render the
    /// current model against the patched literals and diff-repaint — never
    /// replay through `update`.
    HotAppearance(AppearancePatch),
    /// Parent→child: a time-travel debugger command (#2587).
    #[cfg(feature = "debugger")]
    Debug(DebugCmd),
    /// Child→parent: the outcome of applying a frame. `ok = false` with a
    /// `detail` lets the parent fall back (e.g. to a full rebuild) rather than
    /// proceed on a silently-dropped command.
    Ack {
        /// Whether the frame was applied.
        ok: bool,
        /// A short, human-readable outcome note (never a secret).
        detail: String,
    },
    /// Child→parent: the rendered model at a scrub step, in reply to
    /// [`DebugCmd::InspectModel`].
    ModelSnapshot {
        /// The step index the snapshot reflects.
        step: usize,
        /// The model rendered via `IpeStringify` (read-only; never re-fires a
        /// `Cmd`).
        rendered: String,
    },
}

/// Why a frame could not be decoded off the wire.
///
/// A typed error channel (never a bare `String`): the transport parses the
/// untrusted byte stream into a `ControlFrame` at exactly one point, and every
/// rejection is one of these named, fail-closed outcomes.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The declared frame length exceeds [`MAX_FRAME_LEN`]; refused before the
    /// body is read.
    TooLong {
        /// The declared length that was refused.
        declared: usize,
    },
    /// The byte slice is shorter than the declared frame length.
    Truncated,
    /// The frame body is not a valid serialized [`ControlFrame`].
    Malformed,
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameError::TooLong { declared } => {
                write!(
                    f,
                    "control frame length {declared} exceeds the {MAX_FRAME_LEN}-byte cap"
                )
            }
            FrameError::Truncated => write!(f, "control frame is truncated"),
            FrameError::Malformed => write!(f, "control frame body is malformed"),
        }
    }
}

/// Encode a frame as a length-delimited record: a 4-byte big-endian length
/// prefix followed by the JSON body.
///
/// Returns `None` only when the serialized body would exceed [`MAX_FRAME_LEN`]
/// — the same ceiling the decoder enforces, so a sender never emits a record the
/// receiver would refuse.
pub fn encode_frame(frame: &ControlFrame) -> Option<Vec<u8>> {
    let body = serde_json::to_vec(frame).ok()?;
    if body.len() > MAX_FRAME_LEN {
        return None;
    }
    // `body.len() <= MAX_FRAME_LEN` (1 MiB) fits a u32 on every target.
    let len = u32::try_from(body.len()).ok()?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Some(out)
}

/// Decode one length-delimited frame from the front of `bytes`, returning the
/// frame and the number of bytes consumed.
///
/// Fail-closed at the boundary: a length prefix beyond [`MAX_FRAME_LEN`] is
/// refused before the body is touched, a short slice is `Truncated`, and a body
/// that is not a valid frame is `Malformed` — no partial value, no panic.
pub fn decode_frame(bytes: &[u8]) -> Result<(ControlFrame, usize), FrameError> {
    let Some(len_prefix) = bytes.get(..4) else {
        return Err(FrameError::Truncated);
    };
    // The slice is exactly 4 bytes, so the array conversion cannot fail.
    let Ok(len_arr) = <[u8; 4]>::try_from(len_prefix) else {
        return Err(FrameError::Malformed);
    };
    // u32 → usize is a widening conversion on every supported target.
    let Ok(declared) = usize::try_from(u32::from_be_bytes(len_arr)) else {
        return Err(FrameError::Malformed);
    };
    if declared > MAX_FRAME_LEN {
        return Err(FrameError::TooLong { declared });
    }
    let end = 4usize.checked_add(declared).ok_or(FrameError::Truncated)?;
    let Some(body) = bytes.get(4..end) else {
        return Err(FrameError::Truncated);
    };
    let frame = decode_frame_body(body)?;
    Ok((frame, end))
}

/// Decode a frame from a bare, already-de-framed body — the JSON payload with no
/// length prefix. This is the one place a body becomes a [`ControlFrame`], shared
/// by [`decode_frame`] (which strips the prefix first) and the stream server
/// (whose `read_record` has already stripped it), so a wire byte is never framed
/// twice nor parsed two different ways.
///
/// Fail-closed: a body that is not a valid frame is `Malformed` — no partial
/// value, no panic.
pub fn decode_frame_body(body: &[u8]) -> Result<ControlFrame, FrameError> {
    serde_json::from_slice(body).map_err(|_| FrameError::Malformed)
}

/// The fail-closed security core of the tui/cli/worker loopback control
/// transport.
///
/// This is the SCEF-critical surface: a NEW parent→child control channel. Its
/// guarantees are structural, not conventional —
///
/// - **Loopback only.** [`control_bind_addr`] can only ever produce a
///   `127.0.0.1` address; there is no parameter through which a caller could
///   ask it to bind a routable interface, so a LAN peer can never reach the
///   channel.
/// - **Token-gated, fail-closed.** [`is_authorized`] returns `true` only when a
///   token was both minted (by `ipe dev watch`) and presented, and the two match in
///   constant time. An absent expected token, an absent presented token, or a
///   mismatch all yield `false` — the child then runs with no control surface
///   and `ipe dev watch` falls back to a full rebuild, never a degraded path.
/// - **Release-absent.** The whole `control` module is gated on a dev-loop
///   feature, so this transport cannot be compiled into an `ipe release`
///   artifact.
pub mod transport {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// The env var carrying the loopback control-socket port `ipe dev watch`
    /// allocated for the child, beside the listener relocation var
    /// [`crate::LISTEN_PORT_RELOCATION_ENV`].
    pub const CONTROL_PORT_ENV: &str = "IPE_CONTROL_PORT";

    /// The env var carrying the per-session control token. Reuses the same
    /// secret `ipe dev watch` already mints for the web hot-appearance endpoint, so
    /// one token authenticates every shape's control surface.
    pub const CONTROL_TOKEN_ENV: &str = "IPE_WATCH_HOT_TOKEN";

    /// The loopback socket address the child binds its control listener to.
    ///
    /// Always `127.0.0.1:<port>` — the interface is fixed, so no input can steer
    /// the bind onto a routable address. This is the make-invalid-states-
    /// unrepresentable form of "loopback only": the non-loopback bind has no way
    /// to be expressed.
    #[must_use]
    pub fn control_bind_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    /// Whether an incoming control connection is authorized.
    ///
    /// Fail-closed: authorization requires that a token was minted (`expected`
    /// is `Some` and non-empty) AND presented (`presented` is `Some`), and that
    /// the two are byte-equal in constant time. Every other case — no token
    /// minted, none presented, or a mismatch — is unauthorized.
    #[must_use]
    pub fn is_authorized(expected: Option<&str>, presented: Option<&str>) -> bool {
        match (expected, presented) {
            (Some(exp), Some(got)) if !exp.is_empty() => {
                crate::ct_eq::ct_bytes_eq(exp.as_bytes(), got.as_bytes())
            }
            _ => false,
        }
    }

    /// Read the control token this process was launched with, treating an empty
    /// value as absent (fail-closed: an empty token never authorizes anything).
    #[must_use]
    pub fn control_token_from_env() -> Option<String> {
        crate::system::read_env_var(CONTROL_TOKEN_ENV)
            .ok()
            .filter(|t| !t.is_empty())
    }

    /// Read the loopback control-socket port this process was launched with, if
    /// any. Absent or unparseable ⇒ `None` ⇒ the child opens no control socket
    /// (fail-closed to "no control surface").
    #[must_use]
    pub fn control_port_from_env() -> Option<u16> {
        crate::system::read_env_var(CONTROL_PORT_ENV)
            .ok()
            .and_then(|p| p.parse().ok())
    }

    #[cfg(test)]
    #[cfg(not(target_arch = "wasm32"))]
    mod transport_tests {
        use super::*;

        #[test]
        fn bind_addr_is_always_loopback() {
            for port in [0u16, 1, 8080, 65535] {
                let addr = control_bind_addr(port);
                assert!(
                    addr.ip().is_loopback(),
                    "the control socket must bind loopback only, got {addr}"
                );
                assert_eq!(addr.port(), port);
            }
        }

        #[test]
        fn no_token_minted_is_unauthorized() {
            assert!(!is_authorized(None, Some("anything")));
            assert!(!is_authorized(Some(""), Some("anything")));
        }

        #[test]
        fn no_token_presented_is_unauthorized() {
            assert!(!is_authorized(Some("secret"), None));
        }

        #[test]
        fn wrong_token_is_unauthorized() {
            assert!(!is_authorized(Some("secret"), Some("guess")));
            // A prefix of the real token must not authorize.
            assert!(!is_authorized(Some("secret"), Some("sec")));
        }

        #[test]
        fn matching_token_is_authorized() {
            assert!(is_authorized(Some("s3cr3t-hex"), Some("s3cr3t-hex")));
        }
    }
}

/// The child-side loopback accept-loop: the moving end of the control transport.
///
/// Compiled only on a native dev-loop build (`tokio` present, non-wasm) under the
/// same `web`/`debugger` gate as the wire itself, so a pure `ipe release` build —
/// which selects none of those features — carries no accept-loop at all. Where
/// the code is present it is inert unless launched with both a control port and a
/// token, so a child with no `ipe dev watch` parent opens no socket. Every guarantee
/// is fail-closed:
///
/// - **Bind is loopback-only** — the listener address comes from
///   [`transport::control_bind_addr`], which admits no routable interface.
/// - **No surface without a session** — [`serve_control`] returns cleanly (binds
///   nothing) unless BOTH the port and the token env vars are present, so a child
///   with no `ipe dev watch` parent runs with no control socket at all.
/// - **Every frame is token-checked** — a connection presents its token as a
///   length-delimited record ahead of the frame; a frame whose token is absent,
///   empty, or mismatched is dropped before the handler ever sees it.
/// - **Bounded reads** — each record's declared length is refused past
///   [`MAX_FRAME_LEN`] before a single body byte is allocated, so no remote length
///   prefix drives an unbounded allocation.
/// - **Bounded connections** — each connection is served on its own task under a
///   read deadline, so a peer that connects but never sends is dropped rather
///   than parking the surface, and one slow peer cannot wedge the accept loop.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
pub mod server {
    use super::{
        ControlFrame, FrameError, MAX_FRAME_LEN, decode_frame_body, encode_frame, transport,
    };
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    /// The ceiling on how long one connection may take to present its token and
    /// frame before it is dropped.
    ///
    /// A peer that connects but never completes a record holds a task under this
    /// deadline and no longer; the surface stays live for the next peer. The
    /// dev-loop's records are tiny and loopback-local, so this is a generous
    /// ceiling that only ever fires on a stalled or hostile peer.
    const CONN_DEADLINE: Duration = Duration::from_secs(10);

    /// The ceiling on how long the clean-teardown drain waits for a peer to close
    /// after it has been sent a FIN.
    ///
    /// A well-behaved peer closes promptly once its `read_to_end` returns; this
    /// bounds the wait so a peer that holds the connection open cannot park the
    /// teardown, without so short a window that a loopback peer's normal close is
    /// missed.
    const DRAIN_DEADLINE: Duration = Duration::from_secs(2);

    /// Why a connection could not be served to a dispatchable frame.
    ///
    /// A typed channel (never a bare `String`): the untrusted byte stream is
    /// parsed to a `(token, frame)` pair at exactly one point, and every rejection
    /// is one of these named, fail-closed outcomes. `Unauthorized` and `Frame` are
    /// distinct so the accept loop can drop an unauthorized peer without ever
    /// decoding — let alone dispatching — its frame.
    #[derive(Debug)]
    pub enum ServeError {
        /// The socket read failed or closed mid-record.
        Io(std::io::Error),
        /// A record's declared length exceeded [`MAX_FRAME_LEN`], refused before
        /// the body was read.
        TooLong {
            /// The declared length that was refused.
            declared: usize,
        },
        /// The presented token was absent, empty, or did not match the session
        /// token in constant time — the frame is never decoded.
        Unauthorized,
        /// The frame body was read and authorized but is not a valid
        /// [`ControlFrame`].
        Frame(FrameError),
    }

    impl From<std::io::Error> for ServeError {
        fn from(e: std::io::Error) -> Self {
            ServeError::Io(e)
        }
    }

    /// Read one length-delimited record's body off `stream`, refusing an
    /// over-[`MAX_FRAME_LEN`] declared length BEFORE allocating the body.
    ///
    /// The 4-byte big-endian length prefix is read first and checked against the
    /// cap; only a within-cap length reaches the allocation, so no remote prefix
    /// can drive an unbounded read — the same ceiling [`decode_frame`] enforces,
    /// applied one boundary earlier (defense in depth).
    async fn read_record(stream: &mut TcpStream) -> Result<Vec<u8>, ServeError> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        // u32 → usize is a widening conversion on every supported target.
        let declared = u32::from_be_bytes(len_buf) as usize;
        if declared > MAX_FRAME_LEN {
            return Err(ServeError::TooLong { declared });
        }
        let mut body = vec![0u8; declared];
        stream.read_exact(&mut body).await?;
        Ok(body)
    }

    /// Cleanly half-close a connection the peer can always read to EOF.
    ///
    /// A `TcpStream` finally dropped with bytes still unread in its receive buffer
    /// closes with an RST, which the peer observes as a transport error rather than
    /// a clean end-of-stream. This shuts the write half down first — sending the
    /// peer a FIN, so its `read_to_end` returns exactly the reply already written
    /// (or nothing, on a refusal) and then closes its own side — and only then
    /// drains the receive buffer to that peer FIN, so the final drop finds no
    /// unread bytes and closes cleanly. Shutting down first is what breaks the
    /// otherwise-deadlocking "each side waits for the other's EOF" symmetry.
    ///
    /// The drain is bounded on both size and time: it reads into a fixed scratch
    /// buffer and stops at the peer's EOF, any read error, or a short deadline — so
    /// it can neither be steered into an unbounded read nor block on a peer that
    /// holds the connection open without ever closing.
    async fn finish_conn(stream: &mut TcpStream) -> std::io::Result<()> {
        // FIN first: let the peer read our reply to EOF and close its side.
        stream.shutdown().await?;
        let mut scratch = [0u8; 1024];
        // A well-behaved peer closes promptly once it has read the reply; a peer
        // that instead holds the connection open is dropped at this deadline (a
        // reset there is acceptable — it is the peer that refused to close).
        let _ = tokio::time::timeout(DRAIN_DEADLINE, async {
            loop {
                match stream.read(&mut scratch).await {
                    Ok(0) => break,
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }
        })
        .await;
        Ok(())
    }

    /// Serve one connection: read the presented-token record, authorize it against
    /// the session token, read the frame record, and — only if authorized — decode
    /// and dispatch it, writing the handler's reply frame back.
    ///
    /// Fail-closed: an unauthorized token short-circuits to [`ServeError::Unauthorized`]
    /// before the frame is decoded, so an attacker's frame is never parsed or
    /// dispatched. The token is presented as its own record, kept off the
    /// [`ControlFrame`] enum — a presented credential is a separate typed input,
    /// not a wire payload.
    ///
    /// However the connection ends — served, refused, or malformed — the write half
    /// is cleanly half-closed via [`finish_conn`] so the peer reads a deterministic
    /// EOF (exactly the reply written, or none) rather than an RST.
    pub(crate) async fn serve_conn<H, Fut>(
        mut stream: TcpStream,
        handler: &H,
    ) -> Result<(), ServeError>
    where
        H: Fn(ControlFrame) -> Fut,
        Fut: core::future::Future<Output = ControlFrame>,
    {
        let outcome = dispatch_conn(&mut stream, handler).await;
        // Half-close regardless of outcome: a refused/malformed peer still gets a
        // clean EOF, and a served peer's reply is followed by FIN, not a reset.
        let _ = finish_conn(&mut stream).await;
        outcome
    }

    /// The dispatch core of [`serve_conn`]: read + authorize + dispatch, writing
    /// the reply. Kept separate so [`serve_conn`] can always half-close the stream
    /// afterward, whatever this returns.
    async fn dispatch_conn<H, Fut>(stream: &mut TcpStream, handler: &H) -> Result<(), ServeError>
    where
        H: Fn(ControlFrame) -> Fut,
        Fut: core::future::Future<Output = ControlFrame>,
    {
        let token_bytes = read_record(stream).await?;
        let presented = String::from_utf8(token_bytes).ok();
        let expected = transport::control_token_from_env();
        if !transport::is_authorized(expected.as_deref(), presented.as_deref()) {
            return Err(ServeError::Unauthorized);
        }
        let frame_bytes = read_record(stream).await?;
        // `read_record` has already stripped the length prefix, so the body is
        // decoded directly — running it back through `decode_frame` would read the
        // JSON's first bytes as a second length prefix.
        let frame = decode_frame_body(&frame_bytes).map_err(ServeError::Frame)?;
        // The handler is async: for the tui shape it enqueues the frame onto the
        // run loop and AWAITS the run loop's reply one-shot. Awaiting (never a
        // `blocking_recv`) keeps the dispatch flavor-independent — it never blocks
        // a runtime worker, so it is sound whether the child runs on a
        // multi-thread or a current-thread runtime.
        let reply = handler(frame).await;
        // A reply that exceeds the cap cannot be sent; drop the connection rather
        // than emit a record the peer would refuse (fail-closed, never partial).
        if let Some(out) = encode_frame(&reply) {
            stream.write_all(&out).await?;
            stream.flush().await?;
        }
        Ok(())
    }

    /// Bind the loopback control listener and serve connections until the process
    /// exits, dispatching every authorized frame through `handler`.
    ///
    /// Returns `Ok(None)` — binding nothing — when the child was not launched with
    /// both a control port and a token (the no-parent case: the child runs with no
    /// control surface). Otherwise it binds `127.0.0.1:<port>` and loops; a
    /// per-connection error is logged-and-dropped, never fatal, so one malformed or
    /// unauthorized peer cannot take the surface down.
    ///
    /// `handler` maps an authorized [`ControlFrame`] to its reply. For the shared
    /// transport this is the seam the per-shape lanes plug into (tui apply /
    /// recorder inspect); a caller with no shape-specific behaviour can pass the
    /// [`ack_handler`] echo stub.
    ///
    /// Each accepted connection is served on its own task, so one slow or hung
    /// peer never blocks the loop from accepting the next; the handler is shared
    /// across those tasks behind an `Arc` (`Fn + Send + Sync`), so per-connection
    /// reply logic is a pure mapping and any shared state the caller needs lives
    /// behind the handler's own interior mutability — never a `dyn Any`. Each
    /// per-connection read runs under [`CONN_DEADLINE`], so a peer that connects
    /// but never sends a complete record is dropped at the deadline rather than
    /// holding a task forever.
    ///
    /// # Errors
    /// An I/O error if the listener cannot bind the loopback port.
    pub async fn serve_control<H, Fut>(handler: H) -> std::io::Result<Option<()>>
    where
        H: Fn(ControlFrame) -> Fut + Send + Sync + 'static,
        Fut: core::future::Future<Output = ControlFrame> + Send,
    {
        let Some(port) = transport::control_port_from_env() else {
            return Ok(None);
        };
        if transport::control_token_from_env().is_none() {
            return Ok(None);
        }
        let addr = transport::control_bind_addr(port);
        // Defense in depth: `control_bind_addr` can only produce a loopback
        // address, but re-check at the one site a socket is opened and refuse to
        // bind anything routable — fail closed to "no control surface" rather than
        // ever expose the channel on a reachable interface.
        if !addr.ip().is_loopback() {
            return Ok(None);
        }
        let listener = TcpListener::bind(addr).await?;
        let handler = Arc::new(handler);
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    // A single connection is served on its own task under a read
                    // deadline: one slow or hung peer never blocks the accept loop,
                    // and a peer that stalls mid-record is dropped at the deadline.
                    // Its failure is isolated — logged-and-dropped, never fatal.
                    spawn_conn(stream, Arc::clone(&handler), CONN_DEADLINE);
                }
                // An accept error (fd exhaustion, transient) must not kill the loop.
                Err(_) => continue,
            }
        }
    }

    /// Serve one accepted connection on its own task, bounded by `deadline`.
    ///
    /// The single source of truth for per-connection isolation: the task is
    /// detached (one peer never blocks the accept loop), the serve runs under a
    /// read deadline (a peer that connects but never completes a record is dropped
    /// when it fires), and any outcome is discarded (a bad peer never propagates a
    /// failure into the loop). The handler is shared across tasks behind an `Arc`.
    fn spawn_conn<H, Fut>(stream: TcpStream, handler: Arc<H>, deadline: Duration)
    where
        H: Fn(ControlFrame) -> Fut + Send + Sync + 'static,
        Fut: core::future::Future<Output = ControlFrame> + Send,
    {
        tokio::spawn(async move {
            let _ = tokio::time::timeout(deadline, serve_conn(stream, &*handler)).await;
        });
    }

    /// The echo/ack handler: reply to every frame with a positive
    /// [`ControlFrame::Ack`]. The shared transport's default seam — the per-shape
    /// handlers (tui apply / recorder inspect) replace it in their own lanes.
    pub async fn ack_handler(_frame: ControlFrame) -> ControlFrame {
        ControlFrame::Ack {
            ok: true,
            detail: "ack".to_string(),
        }
    }

    #[cfg(test)]
    #[cfg(not(target_arch = "wasm32"))]
    mod tests {
        use super::super::{AppearancePatch, decode_frame};
        use super::*;
        use crate::system::locked_set_var;
        use std::net::{Ipv4Addr, SocketAddr};

        // A frame record framed exactly as the wire expects: a 4-byte big-endian
        // length prefix over the JSON body.
        #[allow(clippy::expect_used)] // test helper — an unencodable frame is a test failure
        fn frame_record(frame: &ControlFrame) -> Vec<u8> {
            encode_frame(frame).expect("a small frame must encode")
        }

        // A token record: the same length-delimited framing over the raw token
        // bytes the parent presents ahead of its frame.
        #[allow(clippy::cast_possible_truncation)] // test — a short token fits u32
        fn token_record(token: &str) -> Vec<u8> {
            let body = token.as_bytes();
            let mut out = (body.len() as u32).to_be_bytes().to_vec();
            out.extend_from_slice(body);
            out
        }

        // Drive one connection against `serve_conn` with the ack stub, returning
        // the raw reply bytes (empty when the connection was dropped unanswered).
        async fn round_trip_conn(session_token: &str, wire: Vec<u8>) -> Vec<u8> {
            locked_set_var(transport::CONTROL_TOKEN_ENV, session_token);
            let listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
                .await
                .expect("bind an ephemeral loopback listener");
            let addr = listener.local_addr().expect("listener has a local addr");
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept the test client");
                serve_conn(stream, &ack_handler).await
            });
            let mut client = TcpStream::connect(addr)
                .await
                .expect("connect to the listener");
            client.write_all(&wire).await.expect("write the wire");
            client.flush().await.expect("flush the wire");
            let mut reply = Vec::new();
            client
                .read_to_end(&mut reply)
                .await
                .expect("read the reply to EOF");
            let _ = server.await.expect("server task joins");
            reply
        }

        #[tokio::test]
        async fn authorized_frame_is_acked() {
            let frame = ControlFrame::HotAppearance(AppearancePatch::default());
            let mut wire = token_record("session-secret");
            wire.extend_from_slice(&frame_record(&frame));
            let reply = round_trip_conn("session-secret", wire).await;
            let (decoded, _) = decode_frame(&reply).expect("an authorized frame is acked");
            assert!(
                matches!(decoded, ControlFrame::Ack { ok: true, .. }),
                "the ack stub replies with a positive Ack, got {decoded:?}"
            );
        }

        #[tokio::test]
        async fn wrong_token_is_refused_not_dispatched() {
            let frame = ControlFrame::HotAppearance(AppearancePatch::default());
            let mut wire = token_record("guess");
            wire.extend_from_slice(&frame_record(&frame));
            let reply = round_trip_conn("session-secret", wire).await;
            assert!(
                reply.is_empty(),
                "a wrong token is dropped with no reply, got {} bytes",
                reply.len()
            );
        }

        #[tokio::test]
        async fn empty_token_is_refused() {
            let frame = ControlFrame::HotAppearance(AppearancePatch::default());
            let mut wire = token_record("");
            wire.extend_from_slice(&frame_record(&frame));
            let reply = round_trip_conn("session-secret", wire).await;
            assert!(reply.is_empty(), "an empty token never authorizes");
        }

        #[tokio::test]
        async fn over_cap_length_prefix_is_refused_before_the_body() {
            // A hostile token-record length prefix claiming more than the cap must
            // be turned back before any body byte is read.
            let declared = MAX_FRAME_LEN + 1;
            #[allow(clippy::cast_possible_truncation)] // test — cap + 1 fits u32
            let prefix = (declared as u32).to_be_bytes();
            // Only one real byte follows a prefix claiming `declared` bytes.
            let wire = [prefix.as_slice(), b"x"].concat();
            locked_set_var(transport::CONTROL_TOKEN_ENV, "session-secret");
            let listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
                .await
                .expect("bind an ephemeral loopback listener");
            let addr = listener.local_addr().expect("listener has a local addr");
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept the test client");
                serve_conn(stream, &ack_handler).await
            });
            let mut client = TcpStream::connect(addr)
                .await
                .expect("connect to the listener");
            client.write_all(&wire).await.expect("write the wire");
            client.flush().await.expect("flush the wire");
            // Read the refusal EOF like any peer would, then close — so the server's
            // clean teardown drain sees this side close instead of waiting it out.
            let mut reply = Vec::new();
            client
                .read_to_end(&mut reply)
                .await
                .expect("read the refusal EOF");
            assert!(
                reply.is_empty(),
                "an over-cap prefix yields no frame reply, got {} bytes",
                reply.len()
            );
            let outcome = server.await.expect("server task joins");
            assert!(
                matches!(outcome, Err(ServeError::TooLong { declared: d }) if d == declared),
                "an over-cap length prefix is refused before the body, got {outcome:?}"
            );
        }

        #[tokio::test]
        async fn hung_peer_is_dropped_and_the_surface_stays_live() {
            use std::sync::atomic::{AtomicUsize, Ordering};

            // A peer that connects but never sends its token/frame must be dropped
            // at the deadline, and it must NOT prevent a second, well-formed
            // authorized peer from being served on the same listener.
            locked_set_var(transport::CONTROL_TOKEN_ENV, "session-secret");
            let listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
                .await
                .expect("bind an ephemeral loopback listener");
            let addr = listener.local_addr().expect("listener has a local addr");

            // The dispatch counter proves the hung peer never reaches the handler.
            let dispatches = Arc::new(AtomicUsize::new(0));
            let handler = {
                let dispatches = Arc::clone(&dispatches);
                Arc::new(move |_frame: ControlFrame| {
                    let dispatches = Arc::clone(&dispatches);
                    async move {
                        dispatches.fetch_add(1, Ordering::SeqCst);
                        ControlFrame::Ack {
                            ok: true,
                            detail: "ack".to_string(),
                        }
                    }
                })
            };

            // The accept loop under test: mirrors `serve_control`'s per-connection
            // isolation via the shared `spawn_conn`, with a short deadline so the
            // hung peer is dropped promptly.
            let accept_handler = Arc::clone(&handler);
            let accept = tokio::spawn(async move {
                let deadline = Duration::from_millis(200);
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            spawn_conn(stream, Arc::clone(&accept_handler), deadline);
                        }
                        Err(_) => continue,
                    }
                }
            });

            // A hung peer: connects, sends nothing, holds the connection open.
            let _hung = TcpStream::connect(addr).await.expect("hung peer connects");

            // A well-formed authorized peer on the SAME listener must still be
            // served — the hung peer never wedged the surface.
            let frame = ControlFrame::HotAppearance(AppearancePatch::default());
            let mut wire = token_record("session-secret");
            wire.extend_from_slice(&frame_record(&frame));
            let mut good = TcpStream::connect(addr).await.expect("good peer connects");
            good.write_all(&wire).await.expect("write the good wire");
            good.flush().await.expect("flush the good wire");
            let mut reply = Vec::new();
            good.read_to_end(&mut reply)
                .await
                .expect("read the good reply to EOF");
            let (decoded, _) = decode_frame(&reply).expect("the good peer is acked");
            assert!(
                matches!(decoded, ControlFrame::Ack { ok: true, .. }),
                "the live surface acks the good peer, got {decoded:?}"
            );

            // Exactly one dispatch: the good peer. The hung peer never dispatched.
            assert_eq!(
                dispatches.load(Ordering::SeqCst),
                1,
                "only the well-formed peer reaches the handler"
            );
            accept.abort();
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    fn appearance() -> AppearancePatch {
        AppearancePatch {
            defaults: vec!["padding: 12px".to_string()],
            patch: vec![(0, "padding: 16px".to_string())],
        }
    }

    // Encode a frame and decode it back, asserting a lossless round-trip that
    // consumes exactly the encoded record.
    #[allow(clippy::expect_used)] // test helper — a failed round-trip is a test failure
    fn assert_round_trip(frame: &ControlFrame) {
        let bytes = encode_frame(frame).expect("a small frame must encode");
        let (decoded, consumed) = decode_frame(&bytes).expect("a self-encoded frame must decode");
        assert_eq!(&decoded, frame, "round-trip preserves the frame");
        assert_eq!(consumed, bytes.len(), "one frame consumes its whole record");
    }

    #[test]
    fn hot_appearance_frame_round_trips() {
        assert_round_trip(&ControlFrame::HotAppearance(appearance()));
    }

    #[test]
    fn ack_and_snapshot_round_trip() {
        assert_round_trip(&ControlFrame::Ack {
            ok: true,
            detail: "applied".to_string(),
        });
        assert_round_trip(&ControlFrame::ModelSnapshot {
            step: 7,
            rendered: "Model { count = 7 }".to_string(),
        });
    }

    #[cfg(feature = "debugger")]
    #[test]
    fn debug_cmd_frames_round_trip() {
        for cmd in [
            DebugCmd::StepTo(3),
            DebugCmd::Back,
            DebugCmd::Forward,
            DebugCmd::Reset,
            DebugCmd::InspectModel(9),
            DebugCmd::LiveTail,
        ] {
            assert_round_trip(&ControlFrame::Debug(cmd));
        }
    }

    #[test]
    fn oversized_length_prefix_is_refused_before_the_body() {
        // A hostile length prefix claiming far more than the cap must be turned
        // back before any body byte is read — no allocation the prefix dictates.
        let declared = MAX_FRAME_LEN + 1;
        #[allow(clippy::expect_used)] // test — the cap fits u32 on every target
        let declared_u32 = u32::try_from(declared).expect("cap + 1 fits u32");
        let mut wire = declared_u32.to_be_bytes().to_vec();
        // Only one real body byte follows: a naive reader that trusts the prefix
        // would try to read `declared` bytes.
        wire.push(b'x');
        assert_eq!(
            decode_frame(&wire),
            Err(FrameError::TooLong { declared }),
            "an over-cap length is refused before the body"
        );
    }

    #[test]
    fn truncated_slice_is_rejected_not_panicked() {
        // Fewer than 4 length bytes.
        assert_eq!(decode_frame(&[0, 0, 1]), Err(FrameError::Truncated));
        // A valid length prefix but a body shorter than declared.
        let mut wire = 8u32.to_be_bytes().to_vec();
        wire.extend_from_slice(b"ab");
        assert_eq!(decode_frame(&wire), Err(FrameError::Truncated));
    }

    #[test]
    fn appearance_patch_matches_the_classifiers_wire_shape() {
        // `ipe dev watch` (`push_appearance_patches`) POSTs an appearance edit as
        // `{"defaults":[...],"patch":[[i,"v"],...]}` — the classifier's
        // `ViewPatch` shape. `AppearancePatch` is the single runtime-owned
        // definition of that wire; pin that the exact bytes the sender emits
        // deserialize into it, so the two forms cannot drift.
        let wire = r#"{"defaults":["padding: 12px"],"patch":[[0,"padding: 16px"]]}"#;
        #[allow(clippy::expect_used)] // test — a shape mismatch is a test failure
        let decoded: AppearancePatch =
            serde_json::from_str(wire).expect("the classifier wire shape decodes");
        assert_eq!(decoded, appearance(), "the runtime wire matches the sender");
        #[allow(clippy::expect_used)] // test — a shape mismatch is a test failure
        let reencoded = serde_json::to_string(&decoded).expect("it re-serializes");
        assert_eq!(reencoded, wire, "the shape re-serializes byte-identically");
    }

    #[test]
    fn malformed_body_is_rejected() {
        let mut wire = 3u32.to_be_bytes().to_vec();
        wire.extend_from_slice(b"{ [");
        assert_eq!(decode_frame(&wire), Err(FrameError::Malformed));
    }

    #[test]
    fn encode_refuses_a_body_over_the_cap() {
        // A patch whose serialized body exceeds the cap is refused at encode
        // time, so the sender never emits a record the decoder would reject.
        let huge = "v".repeat(MAX_FRAME_LEN);
        let frame = ControlFrame::HotAppearance(AppearancePatch {
            defaults: vec![huge],
            patch: vec![],
        });
        assert!(
            encode_frame(&frame).is_none(),
            "a body past the cap does not encode"
        );
    }
}

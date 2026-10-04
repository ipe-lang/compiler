//! Ipe.Tui — the `tui_app` TEA loop.
//!
//! Mirrors `console_app` (tea.rs) exactly — same `CliEvent` channel, `SubManager`
//! (so `Sub.every` → Tick works) and `cli_run_cmd` (so `Cmd.perform` works) — but
//! reads RAW key bytes (raw mode + `decode_key`) instead of stdin lines, and
//! paints into the alternate screen. A Ipe.Tui app quits by calling `System.exit`
//! from `update` (the `Quit` Msg) or by stdin EOF.
//!
//! No panic vectors: a `TuiGuard` restores the TTY (cooked mode, cursor, main
//! screen) on Drop — normal exit AND panic unwind — so no path leaves the
//! terminal wedged. Missing an interactive terminal (piped stdio, `TERM=dumb`,
//! no controlling terminal) is a typed, `Unavailable`-kinded refusal from
//! `terminal_access::probe()`, checked before raw mode is ever entered.

use super::super::core::{IpeResult, IpeTask, ok_res};
#[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
use super::super::debugger::tui::TuiDebugger;
use super::super::stringify::IpeStringify;
use super::super::tea::{
    CliEvent, InputBudget, IpeCmd, IpeSub, MAX_QUEUED_INPUT, SubManager, cli_run_cmd,
};
use super::CellsView;
use super::focus::{
    Focusable, InputRegistry, clamp_focus, edit_input, ensure_focus_visible, extract_click_msg,
    extract_input_msg, extract_msg_named, hit_test, parse_mouse,
};
use super::key::{TuiKey, decode_key};
use super::layout::render_with_focus;
use std::io::{Read, Write};

const ALT_SCREEN_ON: &str = "\x1b[?1049h";
const ALT_SCREEN_OFF: &str = "\x1b[?1049l";
const CLEAR_HOME: &str = "\x1b[2J\x1b[H";
const HIDE_CURSOR: &str = "\x1b[?25l";
const SHOW_CURSOR: &str = "\x1b[?25h";
// Click tracking (1000) + SGR extended coords (1006) — wheel reports as buttons
// 64/65, clicks as button 0. Only the Element backend (`tui_app_ui`) enables it.
const MOUSE_ON: &str = "\x1b[?1000;1006h";
const MOUSE_OFF: &str = "\x1b[?1000;1006l";

/// The name of the key reader thread every TUI app starts.
const KEY_READER_THREAD: &str = "ipe-tui-keys";

use std::sync::atomic::{AtomicBool, Ordering};

/// Whether a TUI session is currently active (terminal in raw mode + alt screen).
/// Gates `tui_teardown` so the restore runs exactly once, from whichever path
/// fires first (Drop on a clean break / panic unwind, OR the System.exit hook).
static TUI_RESTORE_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Whether mouse reporting was enabled (so the teardown emits MOUSE_OFF).
static TUI_MOUSE: AtomicBool = AtomicBool::new(false);

/// Idempotent terminal restore: mouse off → cursor shown → main screen → cooked
/// mode. Runs once (AtomicBool gate). Called from EITHER the `TuiGuard` Drop
/// (clean break / panic unwind) OR the `System.exit` hook — the latter is the
/// load-bearing path: `std::process::exit` bypasses Drop, so without the hook a
/// `Cmd.perform (System.exit n)` quit would leave the TTY in raw mode + the
/// alternate screen (needing `reset`). Implements `tuiTeardown`. Never panics.
fn tui_teardown() {
    if !TUI_RESTORE_ACTIVE.swap(false, Ordering::SeqCst) {
        return; // already restored, or never entered
    }
    let mut out = std::io::stdout();
    if TUI_MOUSE.load(Ordering::SeqCst) {
        let _ = out.write_all(MOUSE_OFF.as_bytes());
    }
    let _ = out.write_all(SHOW_CURSOR.as_bytes());
    let _ = out.write_all(ALT_SCREEN_OFF.as_bytes());
    let _ = out.flush();
    let _ = crossterm::terminal::disable_raw_mode();
}

/// RAII terminal-state guard — restores cooked mode + cursor + main screen (and
/// mouse reporting, when enabled) on Drop (normal exit or panic unwind) AND via
/// the registered `System.exit` hook (process::exit bypasses Drop). Best-effort,
/// never panics.
struct TuiGuard;

/// Why `TuiGuard::enter*` refused to start a Tui session — typed so a caller
/// can classify a "no terminal" refusal as `Unavailable` instead of folding
/// every failure into `Unexpected` through a bare `String`.
enum TuiEnterError {
    /// `terminal_access::probe()` already named which fact failed, before any
    /// raw-mode syscall ran.
    NoTerminal(crate::terminal_access::NoTerminal),
    /// A residual `enable_raw_mode` failure the probe did not predict; kept
    /// with its raw OS context.
    RawMode(std::io::Error),
}

impl TuiEnterError {
    fn into_task_error<E: From<String> + crate::FromUnavailable>(self) -> E {
        match self {
            Self::NoTerminal(reason) => E::from_unavailable(reason.text().to_owned()),
            Self::RawMode(e) => format!("Tui: enable raw mode: {e}").into(),
        }
    }
}

/// Classify a residual `enable_raw_mode` failure the probe did not catch.
/// `ENXIO` ("no such device or address") means the OS found no controlling
/// terminal post hoc, the same fact `NoControllingTerminal` names — so it maps
/// to that typed refusal rather than staying an opaque `Unexpected`.
#[cfg(unix)]
fn classify_raw_mode_error(e: std::io::Error) -> TuiEnterError {
    if e.raw_os_error() == Some(rustix::io::Errno::NXIO.raw_os_error()) {
        TuiEnterError::NoTerminal(crate::terminal_access::NoTerminal::NoControllingTerminal)
    } else {
        TuiEnterError::RawMode(e)
    }
}

#[cfg(not(unix))]
fn classify_raw_mode_error(e: std::io::Error) -> TuiEnterError {
    TuiEnterError::RawMode(e)
}

impl TuiGuard {
    /// String-view driver (`tui_app`, the raw-cell path) — no mouse reporting.
    fn enter() -> Result<Self, TuiEnterError> {
        Self::enter_with(false)
    }
    /// Element-view driver (`tui_app_ui` / `Tui.tea`) — enables mouse reporting
    /// for focus-click + wheel scroll.
    fn enter_mouse() -> Result<Self, TuiEnterError> {
        Self::enter_with(true)
    }
    fn enter_with(mouse: bool) -> Result<Self, TuiEnterError> {
        if let crate::terminal_access::TerminalAccess::Refused(reason) =
            crate::terminal_access::probe()
        {
            return Err(TuiEnterError::NoTerminal(reason));
        }
        if let Err(e) = crossterm::terminal::enable_raw_mode() {
            return Err(classify_raw_mode_error(e));
        }
        TUI_MOUSE.store(mouse, Ordering::SeqCst);
        TUI_RESTORE_ACTIVE.store(true, Ordering::SeqCst);
        // Register the teardown so a `System.exit` quit restores the terminal even
        // though process::exit skips Drop. Idempotent with the Drop path below.
        crate::system::register_exit_hook(tui_teardown);
        let mut out = std::io::stdout();
        let _ = out.write_all(ALT_SCREEN_ON.as_bytes());
        let _ = out.write_all(HIDE_CURSOR.as_bytes());
        if mouse {
            let _ = out.write_all(MOUSE_ON.as_bytes());
        }
        let _ = out.flush();
        Ok(TuiGuard)
    }
}

impl Drop for TuiGuard {
    fn drop(&mut self) {
        tui_teardown();
    }
}

fn paint(frame: &str) {
    // Clear and frame content are concatenated into one buffer so the terminal
    // emulator receives a single write: the prior content disappears and the new
    // frame appears in one step, never leaving a visible blank between them.
    // Two separate write_all calls (clear then frame) would each flush to the tty
    // independently, letting the emulator render the blank clear before the content
    // arrives — the structural cause of the cursor-move flicker.
    let mut buf = String::with_capacity(CLEAR_HOME.len() + frame.len());
    buf.push_str(CLEAR_HOME);
    buf.push_str(frame);
    let mut out = std::io::stdout();
    let _ = out.write_all(buf.as_bytes());
    let _ = out.flush();
}

/// Fire `onBlur` for the previously-focused element + `onFocus` for the newly-
/// focused one (when those events are bound), enqueuing each Msg on the event
/// channel so it flows through the same `update` sequence as everything else.
/// Implements `tuiDispatchFocusChange`. A send failure (receiver gone) is
/// ignored — the loop is tearing down anyway. No-op when focus didn't move.
fn dispatch_focus_change<Msg: Clone + Send + 'static>(
    focusables: &[Focusable<Msg>],
    old_idx: usize,
    new_idx: usize,
    tx: &tokio::sync::mpsc::UnboundedSender<CliEvent<Msg>>,
) {
    if old_idx == new_idx {
        return;
    }
    if let Some(msg) = focusables
        .get(old_idx)
        .and_then(|f| extract_msg_named(&f.events, "blur"))
    {
        let _ = tx.send(CliEvent::Msg(msg));
    }
    if let Some(msg) = focusables
        .get(new_idx)
        .and_then(|f| extract_msg_named(&f.events, "focus"))
    {
        let _ = tx.send(CliEvent::Msg(msg));
    }
}

/// Current terminal size in cells; `(80, 24)` if it can't be queried (e.g. the
/// stream isn't a TTY). Re-queried each paint so the Element renderer reflows on
/// resize.
fn term_size() -> (usize, usize) {
    // Fall back to 80×24 when the size can't be determined OR is reported as 0 in
    // either dimension (a pty with no winsize set / a non-interactive pipe reports
    // (0, 0); crossterm passes that through). Clamping a 0 to 1 — as the old code
    // did — rendered a 1×1 canvas, i.e. an (almost) blank frame, diverging
    // (which defaults to 80×24). Only a genuine non-zero size is honoured.
    match crossterm::terminal::size() {
        Ok((w, h)) if w > 0 && h > 0 => (w as usize, h as usize),
        _ => (80, 24),
    }
}

/// Longest key sequence `decode_key` recognises (`ESC [ 1 ; <mod> <final>` = 6
/// bytes); padded to 8 so any tail at least this long is decoded, never carried.
const MAX_KEY_SEQ: usize = 8;

/// Bytes a UTF-8 lead byte announces (1 for ASCII / continuation / invalid lead).
fn utf8_seq_len(lead: u8) -> usize {
    match lead {
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

/// Whether `tail` — the bytes left at the end of a COMPLETELY FILLED read — might
/// be the truncated prefix of a longer key sequence and so should be carried into
/// the next read rather than decoded now. ESC sequences are variable-length; a
/// multibyte UTF-8 char needs all its continuation bytes. Carrying a tail that is
/// in fact already complete is harmless — it is decoded on the next read with the
/// following bytes prepended (one-read latency, never a drop or mis-decode).
fn tail_maybe_truncated(tail: &[u8]) -> bool {
    match tail.first() {
        Some(&0x1b) => tail.len() < MAX_KEY_SEQ,
        Some(&b) if b >= 0x80 => tail.len() < utf8_seq_len(b),
        _ => false,
    }
}

/// Blocking raw-key reader: decodes stdin bytes into `CliEvent::Key(kind, value)`
/// events via `decode_key`, then a final `Eof`. Reassembles escape / UTF-8 key
/// sequences that straddle the fixed 64-byte read boundary by carrying the
/// unconsumed tail into the next read — a fixed-buffer decode would otherwise
/// mis-decode or corrupt a split sequence (e.g. a multibyte char inside a paste
/// larger than 64 bytes). `map_kind` turns the decoded `TuiKey` into the wire
/// `(kind, value)` pair (`tui_app_ui` folds the ctrl modifier into the kind for
/// the input editor's word-jumps; `tui_app` passes it through). Runs on its own
/// blocking thread so the key handlers stay off it. Each key is queued only with
/// an [`InputBudget`] permit, so at most [`MAX_QUEUED_INPUT`] keys wait for the
/// loop; past that the reader blocks until the loop catches up.
fn read_keys_loop<Msg, FMap>(tx: &tokio::sync::mpsc::UnboundedSender<CliEvent<Msg>>, map_kind: FMap)
where
    FMap: Fn(TuiKey) -> (String, String),
{
    let budget = InputBudget::new(MAX_QUEUED_INPUT);
    let mut stdin = std::io::stdin();
    let mut buf = [0u8; 64];
    let mut carry: Vec<u8> = Vec::new();
    loop {
        let n = match stdin.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let mut data = std::mem::take(&mut carry);
        data.extend_from_slice(buf.get(..n).unwrap_or(&[]));
        // A completely filled read signals more bytes are likely queued, so a
        // trailing partial sequence should wait for them; a short read is taken
        // as the full input (so a solo Escape stays responsive).
        let filled = n == buf.len();
        let mut i = 0;
        while i < data.len() {
            let rest = data.get(i..).unwrap_or(&[]);
            if filled && tail_maybe_truncated(rest) {
                break;
            }
            let (k, consumed) = decode_key(rest);
            if consumed == 0 {
                break;
            }
            i += consumed;
            let (kind, value) = map_kind(k);
            let Some(permit) = budget.acquire(|| tx.is_closed()) else {
                return;
            };
            if tx.send(CliEvent::Key(kind, value, permit)).is_err() {
                return;
            }
        }
        carry = data.get(i..).map(|tail| tail.to_vec()).unwrap_or_default();
    }
    // Drain any carried tail before EOF (decode greedily — no more bytes coming).
    let mut i = 0;
    while i < carry.len() {
        let (k, consumed) = decode_key(carry.get(i..).unwrap_or(&[]));
        if consumed == 0 {
            break;
        }
        i += consumed;
        let (kind, value) = map_kind(k);
        let Some(permit) = budget.acquire(|| tx.is_closed()) else {
            return;
        };
        if tx.send(CliEvent::Key(kind, value, permit)).is_err() {
            return;
        }
    }
    let _ = tx.send(CliEvent::Eof);
}

/// One authorized control frame delivered from the loopback accept-loop to the
/// synchronous TEA run loop, paired with the one-shot the run loop replies on.
///
/// This is the async→sync bridge. The accept-loop's handler (an async task) and
/// the run loop (which OWNS `Model`/view/`dbg`) run on different execution
/// contexts; rather than share `Model` behind a lock — which would open a
/// data-race window and let a control apply interleave a live `update` mid-fold —
/// the handler merely ENQUEUES a `ControlRequest` and the run loop folds it into
/// its own event select, applying it single-threaded on its own task. So the
/// live model is only ever touched from one thread and determinism
/// (`reconstruct(n) == live`) is preserved by construction: the seam borrows the
/// model read-only and re-fires no `Cmd`.
///
/// Gated on `control-wire` (a superset of `debugger`), so a DEFAULT `ipe dev watch`
/// on a tui app mounts the bridge for the appearance hot-swap path; `--debugger`
/// (which implies `control-wire`) additionally carries the scrub/inspect frames.
#[cfg(all(feature = "control-wire", not(target_arch = "wasm32")))]
struct ControlRequest {
    frame: crate::control::ControlFrame,
    reply: tokio::sync::oneshot::Sender<crate::control::ControlFrame>,
}

/// The reply future the bridge handler returns: it enqueues the frame and awaits
/// the run loop's reply one-shot, resolving to the reply `ControlFrame`. Boxed
/// (and `Send`) so the handler is a single nameable
/// `Fn(ControlFrame) -> ControlReplyFuture` type, and awaited — never
/// `blocking_recv`d — on the serving task, so the serve side never blocks a
/// runtime worker on any flavor.
#[cfg(all(feature = "control-wire", not(target_arch = "wasm32")))]
type ControlReplyFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = crate::control::ControlFrame> + Send>>;

/// The async→sync bridge's channel + handler, split out so it can be driven in a
/// test without opening a socket. The handler is the async
/// `Fn(ControlFrame) -> impl Future<Output = ControlFrame>`
/// [`serve_control`](crate::control::server::serve_control) wants; it enqueues
/// each frame with a fresh reply one-shot and AWAITS the run loop's answer on the
/// serving (detached, per-connection) task. Awaiting the reply one-shot — never a
/// `blocking_recv` — keeps the serve side flavor-independent: it yields the worker
/// instead of blocking it, so it is sound on a multi-thread OR a current-thread
/// runtime, and can never trip tokio's "cannot block the current thread from
/// within a runtime" panic. A dropped run loop (child exiting) makes the enqueue
/// or the reply await fail, so the handler falls closed to a rejecting `Ack`
/// rather than hanging.
#[cfg(all(feature = "control-wire", not(target_arch = "wasm32")))]
fn control_bridge_channel() -> (
    impl Fn(crate::control::ControlFrame) -> ControlReplyFuture + Send + Sync + 'static,
    tokio::sync::mpsc::UnboundedReceiver<ControlRequest>,
) {
    let (req_tx, req_rx) = tokio::sync::mpsc::unbounded_channel::<ControlRequest>();
    let handler = move |frame: crate::control::ControlFrame| {
        let req_tx = req_tx.clone();
        Box::pin(async move {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            // The run loop owns the receiver; if it has already exited, the send
            // fails and we fall closed to a rejecting Ack rather than block forever.
            if req_tx
                .send(ControlRequest {
                    frame,
                    reply: reply_tx,
                })
                .is_err()
            {
                return crate::control::ControlFrame::Ack {
                    ok: false,
                    detail: "control run loop is not accepting frames".to_owned(),
                };
            }
            match reply_rx.await {
                Ok(reply) => reply,
                // The run loop dropped the reply sender without answering (it is
                // shutting down): fail closed, never a silent success.
                Err(_) => crate::control::ControlFrame::Ack {
                    ok: false,
                    detail: "control run loop did not reply".to_owned(),
                },
            }
        }) as ControlReplyFuture
    };
    (handler, req_rx)
}

/// Spawn the loopback control accept-loop for this tui child, returning the
/// receiver the run loop drains.
///
/// Fail-closed and dev-loop-only: [`serve_control`](crate::control::server::serve_control)
/// itself binds nothing unless BOTH `IPE_CONTROL_PORT` and the session token env
/// vars are present (a child with no `ipe dev watch` parent opens no socket), binds
/// loopback only, and token-checks every connection before its frame is decoded.
/// The whole surface is absent from a release build — the module is gated on a
/// dev-loop feature (`control-wire`), which no `ipe release` artifact selects.
#[cfg(all(feature = "control-wire", not(target_arch = "wasm32")))]
fn spawn_control_bridge() -> tokio::sync::mpsc::UnboundedReceiver<ControlRequest> {
    let (handler, req_rx) = control_bridge_channel();
    tokio::spawn(async move {
        // A bind failure (no port/token, or a lost race for the loopback port) is
        // not fatal: the child simply runs with no control surface.
        let _ = crate::control::server::serve_control(handler).await;
    });
    req_rx
}

/// `tui_app` — terminal TEA driver for a `view : Model -> String` (the raw
/// frame is painted verbatim), the vehicle for the `Ui.cells` raw-cell escape.
/// Each decoded key's `(kind, value)` goes to every `Tui.Sub.onKey` handler the
/// current `subscriptions` declares (the codegen wraps the user's
/// `KeyEvent -> Msg` so the `{ kind, value }` record is built there); a key no
/// handler subscribes to is unobserved.
#[allow(clippy::type_complexity)]
pub fn tui_app<Model, Msg, E, FInit, FUpdate, FView, FSubs>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
) -> IpeTask<E, ()>
where
    E: Send + From<String> + crate::FromUnavailable + 'static,
    Model: Clone + Send + 'static,
    Msg: Clone + Send + IpeStringify + 'static,
    FInit: Fn(()) -> (Model, IpeCmd<Msg>) + Send + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FView: Fn(Model) -> String + Send + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + Send + 'static,
{
    // Wrap update in an Arc so it can be shared between the live-pass call
    // site and the debugger's reconstruct closure without requiring Clone.
    // The Arc is a single allocation per session; it is transparent to the
    // non-debugger build path (Arc<F>: Fn(...) when F: Fn(...)).
    let update = std::sync::Arc::new(update);
    Box::pin(async move {
        let _guard = match TuiGuard::enter() {
            Ok(g) => g,
            Err(e) => return IpeResult::Err(e.into_task_error()),
        };

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<CliEvent<Msg>>();

        // A refused key reader ends the app with an `Unavailable` error; the
        // guard restores the terminal.
        let key_tx = tx.clone();
        let started = crate::threads::spawn_named(KEY_READER_THREAD, move || {
            read_keys_loop(&key_tx, |k| {
                // Under the debugger, fold a Ctrl modifier on Left/Right into the
                // kind (`ctrlleft`/`ctrlright`) so the history step keys are
                // distinguishable on the flat (kind, value) channel.
                #[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
                let kind = if k.ctrl && (k.kind == "left" || k.kind == "right") {
                    format!("ctrl{}", k.kind)
                } else {
                    k.kind
                };
                #[cfg(not(all(feature = "debugger", not(target_arch = "wasm32"))))]
                let kind = k.kind;
                (kind, k.value)
            });
        });
        if let Err(e) = started {
            return IpeResult::Err(
                crate::threads::ThreadRefused::os(KEY_READER_THREAD, &e).into_error(),
            );
        }

        let (mut model, cmd0) = init(());
        cli_run_cmd(cmd0, &tx);
        let mut submgr = SubManager::new(tx.clone());
        submgr.update(subscriptions(model.clone()));

        #[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
        let mut dbg = {
            let upd = std::sync::Arc::clone(&update);
            TuiDebugger::new(model.clone(), move |msg, mdl| upd(msg, mdl))
        };

        let render_frame = move |m: &Model| view(m.clone());

        // Initial paint.
        #[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
        {
            let mut frame = render_frame(&model);
            frame.push_str("\r\n");
            frame.push_str(&dbg.status_line());
            paint(&frame);
        }
        #[cfg(not(all(feature = "debugger", not(target_arch = "wasm32"))))]
        paint(&render_frame(&model));

        while let Some(ev) = rx.recv().await {
            let msgs: Vec<Msg> = match ev {
                // The permit returns to the reader's budget as the key is taken.
                CliEvent::Key(kind, value, _permit) => {
                    #[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
                    {
                        // Ctrl-T: toggle time-travel mode.
                        if kind == crate::debugger::tui::TOGGLE_KIND
                            && value == crate::debugger::tui::TOGGLE_VALUE
                        {
                            let display_model = dbg.toggle().unwrap_or_else(|| model.clone());
                            let mut frame = render_frame(&display_model);
                            frame.push_str("\r\n");
                            frame.push_str(&dbg.status_line());
                            paint(&frame);
                            continue;
                        }
                        // Ctrl-Left / Ctrl-Right: step in time-travel mode.
                        if dbg.is_scrubbing() {
                            if kind == crate::debugger::tui::STEP_BACK_KIND {
                                if let Some(past) = dbg.step_back() {
                                    let mut frame = render_frame(&past);
                                    frame.push_str("\r\n");
                                    frame.push_str(&dbg.status_line());
                                    paint(&frame);
                                }
                                continue;
                            }
                            if kind == crate::debugger::tui::STEP_FWD_KIND {
                                if let Some(past) = dbg.step_fwd() {
                                    let mut frame = render_frame(&past);
                                    frame.push_str("\r\n");
                                    frame.push_str(&dbg.status_line());
                                    paint(&frame);
                                }
                                continue;
                            }
                        }
                    }
                    submgr.key_msgs(&kind, &value)
                }
                CliEvent::Msg(m) | CliEvent::PerformDone(m) => vec![m],
                CliEvent::Line(..) => continue,
                CliEvent::Eof => break,
            };
            if msgs.is_empty() {
                continue;
            }

            // Fold each message in order; the subscriptions are re-evaluated
            // after each, so the next message meets the model it produced.
            for msg in msgs {
                #[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
                let (next, cmd) = update(msg.clone(), model);
                #[cfg(not(all(feature = "debugger", not(target_arch = "wasm32"))))]
                let (next, cmd) = update(msg, model);

                model = next;

                #[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
                dbg.record(msg, model.clone());

                cli_run_cmd(cmd, &tx);
                submgr.update(subscriptions(model.clone()));
            }

            #[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
            {
                // In time-travel mode: stay frozen on the pinned past step.
                // Toggle Ctrl-T to return to the live head.
                let display_model = dbg.current_reconstructed().unwrap_or_else(|| model.clone());
                let mut frame = render_frame(&display_model);
                frame.push_str("\r\n");
                frame.push_str(&dbg.status_line());
                paint(&frame);
            }
            #[cfg(not(all(feature = "debugger", not(target_arch = "wasm32"))))]
            paint(&render_frame(&model));
        }
        submgr.stop_all();
        ok_res(())
    })
}

/// Render the Element view (twice: discover focusables, then scroll-correct + the
/// focus highlight) and paint it. Returns the focusables so the loop can dispatch
/// their input/click Msgs. Implements `renderElementFrameScroll` double pass.
fn render_and_paint<Model, Msg, FView>(
    view: &FView,
    model: &Model,
    inputs: &mut InputRegistry,
    focus_idx: &mut usize,
    scroll_y: &mut usize,
) -> Vec<Focusable<Msg>>
where
    Model: Clone,
    Msg: Clone,
    FView: Fn(Model) -> CellsView<Msg>,
{
    let (cols, rows) = term_size();
    let (_f1, fs1, content_h) = render_with_focus(
        &view(model.clone()).into_element(),
        cols,
        rows,
        *focus_idx,
        inputs,
        *scroll_y,
    );
    *focus_idx = clamp_focus(*focus_idx, fs1.len());
    *scroll_y = ensure_focus_visible(&fs1, *focus_idx, *scroll_y, rows, content_h);
    let (frame, fs2, _) = render_with_focus(
        &view(model.clone()).into_element(),
        cols,
        rows,
        *focus_idx,
        inputs,
        *scroll_y,
    );
    paint(&frame);
    fs2
}

/// Lay out `model` with the debugger status line appended, WITHOUT painting —
/// the I/O-free core of a debugger frame. Owns the `CellsView -> Element`
/// conversion so no time-travel render site can drift from the layout input
/// contract (`render_with_focus` takes `&Element`). Returns the annotated frame
/// string and the new focusables.
#[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
fn render_debug_annotated<Model, Msg, FView>(
    view: &FView,
    model: Model,
    dbg: &TuiDebugger<Msg, Model>,
    inputs: &mut InputRegistry,
    focus_idx: usize,
    scroll_y: usize,
) -> (String, Vec<Focusable<Msg>>)
where
    Model: Clone,
    Msg: Clone + IpeStringify,
    FView: Fn(Model) -> CellsView<Msg>,
{
    let (cols, rows) = term_size();
    let (frame, fs, _) = render_with_focus(
        &view(model).into_element(),
        cols,
        rows,
        focus_idx,
        inputs,
        scroll_y,
    );
    let mut annotated = frame;
    annotated.push_str("\r\n");
    annotated.push_str(&dbg.status_line());
    (annotated, fs)
}

/// The reply an [`apply_control_frame`] call yields, paired with the repaint it
/// requests. Keeping the repaint out of the seam (the seam is I/O-free) lets a
/// unit test observe both without touching a real terminal, and lets the live
/// loop own the single `paint` call. `frame` is `None` when the recomputed
/// surface is byte-identical to the last painted one — the minimal-repaint
/// guard: an appearance patch that changes nothing (or a redundant scrub step)
/// costs zero writes, never a full-screen redraw.
///
/// [`apply_control_frame`]: TuiSurface::apply_control_frame
#[cfg(all(feature = "control-wire", not(target_arch = "wasm32")))]
pub struct ApplyOutcome<Msg> {
    /// The child→parent reply frame (`Ack` or `ModelSnapshot`).
    pub reply: crate::control::ControlFrame,
    /// The annotated frame to paint, or `None` when nothing changed.
    pub repaint: Option<String>,
    /// The focusables of the freshly-rendered surface (unchanged when `repaint`
    /// is `None`, so the caller keeps its current set in that case).
    pub focusables: Option<Vec<Focusable<Msg>>>,
}

/// The mutable render surface of a running tui app — the input registry, the
/// focus cursor, the scroll offset, and the last painted frame. It owns the ONE
/// [`apply_control_frame`](Self::apply_control_frame) seam that realizes an
/// incoming [`ControlFrame`](crate::control::ControlFrame) onto the surface, so
/// the keyboard-driven scrub and the (later) wire-driven control both drive the
/// identical path — a second apply path is a divergence waiting to happen (the
/// `CellsView`-vs-`Element` drift that #2762 fixed).
#[cfg(all(feature = "control-wire", not(target_arch = "wasm32")))]
pub struct TuiSurface {
    inputs: InputRegistry,
    focus_idx: usize,
    scroll_y: usize,
    /// The frame most recently handed out for painting — the diff baseline that
    /// makes a no-op apply cost zero writes.
    last_frame: Option<String>,
}

#[cfg(all(feature = "control-wire", not(target_arch = "wasm32")))]
impl TuiSurface {
    fn new(inputs: InputRegistry, focus_idx: usize, scroll_y: usize) -> Self {
        Self {
            inputs,
            focus_idx,
            scroll_y,
            last_frame: None,
        }
    }

    /// The current focus cursor (test + caller observability).
    #[must_use]
    pub fn focus_idx(&self) -> usize {
        self.focus_idx
    }

    /// The current scroll offset (test + caller observability).
    #[must_use]
    pub fn scroll_y(&self) -> usize {
        self.scroll_y
    }

    /// The last frame handed out for painting, if any.
    #[must_use]
    pub fn last_frame(&self) -> Option<&str> {
        self.last_frame.as_deref()
    }

    /// Turn a freshly-rendered annotated frame into a repaint request: `Some`
    /// only when it differs from the last painted frame, and record it as the
    /// new baseline in that case. This is the minimal-repaint guard.
    fn diff_repaint(&mut self, annotated: String) -> Option<String> {
        if self.last_frame.as_deref() == Some(annotated.as_str()) {
            return None;
        }
        self.last_frame = Some(annotated.clone());
        Some(annotated)
    }

    /// Lay out `display_model` at the surface's current focus/scroll WITHOUT the
    /// debugger status line and WITHOUT painting — the debugger-free core of an
    /// appearance repaint. Owns the `CellsView -> Element` conversion so the
    /// appearance path never drifts from the layout input contract. Returns the
    /// frame string and the freshly-rendered focusables.
    ///
    /// This is the render the `control-wire` (default-`ipe dev watch`) appearance
    /// apply uses: no `TuiDebugger` in scope, so a hot-swap needs no recorder. A
    /// `--debugger` build renders through `render_debug_annotated` instead so the
    /// status-line overlay is preserved — the sole appearance path within each
    /// build, never two ad-hoc ones.
    #[cfg(not(feature = "debugger"))]
    fn render_surface<Model, Msg, FView>(
        &mut self,
        view: &FView,
        display_model: Model,
    ) -> (String, Vec<Focusable<Msg>>)
    where
        Model: Clone,
        Msg: Clone,
        FView: Fn(Model) -> CellsView<Msg>,
    {
        let (cols, rows) = term_size();
        let (frame, fs, _) = render_with_focus(
            &view(display_model).into_element(),
            cols,
            rows,
            self.focus_idx,
            &mut self.inputs,
            self.scroll_y,
        );
        (frame, fs)
    }

    /// Realize an incoming control frame onto the surface — the ONE apply seam
    /// on a default `ipe dev watch` (no debugger).
    ///
    /// The single parent→child command a `control-wire`-only build carries is the
    /// appearance hot-swap; the debugger's scrub/inspect frames are added by the
    /// `#[cfg(feature = "debugger")]` variant of this method (which threads a
    /// `TuiDebugger`). Splitting the signature this way lets the appearance path
    /// apply with NO recorder in scope while the debugger path still gets one.
    ///
    /// - [`ControlFrame::HotAppearance`] — register the appearance patch in the
    ///   dev overlay, then recompute the surface from the CURRENT `model` (never
    ///   through `update` — an appearance-only edit changes literals, not state)
    ///   and diff-repaint. Focus and scroll are preserved.
    /// - `Ack` / `ModelSnapshot` are child→parent REPLIES: receiving one is a
    ///   malformed exchange, failed closed with a rejecting `Ack` and no repaint.
    ///
    /// `model` is the live head model; the seam borrows it read-only and never
    /// mutates it.
    #[cfg(not(feature = "debugger"))]
    pub fn apply_control_frame<Model, Msg, FView>(
        &mut self,
        frame: crate::control::ControlFrame,
        view: &FView,
        model: &Model,
    ) -> ApplyOutcome<Msg>
    where
        Model: Clone,
        Msg: Clone + IpeStringify,
        FView: Fn(Model) -> CellsView<Msg>,
    {
        use crate::control::ControlFrame;
        match frame {
            ControlFrame::HotAppearance(patch) => {
                // Register the appearance overlay in the crate-root
                // `literal_table` module (present under `control-wire`). A tui
                // view's hoisted literals route through this same overlay, so the
                // recompute below reflects the edit.
                crate::literal_table::register_dev_patch(&patch.defaults, patch.patch.clone());

                // Recompute from the CURRENT model — NOT through `update` — with
                // no recorder in scope: an appearance edit changes literals, not
                // state, and a non-debugger watch has no scrub cursor to honour.
                let (frame_str, fs) = self.render_surface(view, model.clone());
                let repaint = self.diff_repaint(frame_str);
                ApplyOutcome {
                    reply: ControlFrame::Ack {
                        ok: true,
                        detail: "hot-appearance applied".to_owned(),
                    },
                    focusables: repaint.as_ref().map(|_| fs),
                    repaint,
                }
            }
            // Child→parent REPLIES are never a command the child applies. Fail
            // closed with a rejecting `Ack` (an exhaustive match — a new
            // parent→child variant must be handled, never silently swallowed).
            ControlFrame::Ack { .. } | ControlFrame::ModelSnapshot { .. } => ApplyOutcome {
                reply: ControlFrame::Ack {
                    ok: false,
                    detail: "not a parent-to-child command".to_owned(),
                },
                repaint: None,
                focusables: None,
            },
        }
    }
}

/// The debugger extensions of the apply seam: the recorder-driven scrub/inspect
/// arms, threaded a `&mut TuiDebugger`. A `--debugger` build (which implies
/// `control-wire`) carries these on top of the appearance apply above; the
/// appearance arm here is the SAME single path, rendered through
/// [`render_debug_annotated`] so the status-line overlay is preserved.
#[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
impl TuiSurface {
    /// Realize an incoming control frame — the ONE apply seam under `--debugger`.
    ///
    /// - [`ControlFrame::HotAppearance`] — recompute from the CURRENT model (the
    ///   scrub cursor is untouched, so a hot-swap while time-travelling repaints
    ///   the pinned step, not the live head) and diff-repaint.
    /// - [`ControlFrame::Debug`] — drive the recorder: `StepTo`/`Back`/`Forward`
    ///   move the scrub cursor and reconstruct the model at that step;
    ///   `InspectModel` reconstructs read-only and replies with a
    ///   [`ModelSnapshot`](crate::control::ControlFrame::ModelSnapshot); `Reset`
    ///   and `LiveTail` return to the live head. Every reconstruct re-folds
    ///   `update` over the retained messages and re-fires no `Cmd`, so a scrub
    ///   never perturbs the live model (determinism, principle 2).
    ///
    /// The reply is an [`Ack`](crate::control::ControlFrame::Ack) for every arm
    /// except `InspectModel`, which replies with the snapshot.
    pub fn apply_control_frame<Model, Msg, FView>(
        &mut self,
        frame: crate::control::ControlFrame,
        view: &FView,
        model: &Model,
        dbg: &mut TuiDebugger<Msg, Model>,
    ) -> ApplyOutcome<Msg>
    where
        Model: Clone,
        Msg: Clone + IpeStringify,
        FView: Fn(Model) -> CellsView<Msg>,
    {
        use crate::control::ControlFrame;
        match frame {
            ControlFrame::HotAppearance(patch) => {
                crate::literal_table::register_dev_patch(&patch.defaults, patch.patch.clone());

                // Recompute from the CURRENT model — NOT through `update`. The
                // scrub cursor is untouched, so a hot-swap while time-travelling
                // repaints the pinned step, not the live head.
                let display = dbg.current_reconstructed().unwrap_or_else(|| model.clone());
                let (annotated, fs) = render_debug_annotated(
                    view,
                    display,
                    dbg,
                    &mut self.inputs,
                    self.focus_idx,
                    self.scroll_y,
                );
                let repaint = self.diff_repaint(annotated);
                ApplyOutcome {
                    reply: ControlFrame::Ack {
                        ok: true,
                        detail: "hot-appearance applied".to_owned(),
                    },
                    focusables: repaint.as_ref().map(|_| fs),
                    repaint,
                }
            }
            ControlFrame::Debug(cmd) => self.apply_debug(cmd, view, model, dbg),
            // `Ack` / `ModelSnapshot` are child→parent REPLIES, never a command
            // the child applies. Fail closed with a rejecting `Ack` and no repaint
            // (an exhaustive match — a new parent→child variant must be handled
            // here, never silently swallowed).
            ControlFrame::Ack { .. } | ControlFrame::ModelSnapshot { .. } => ApplyOutcome {
                reply: ControlFrame::Ack {
                    ok: false,
                    detail: "not a parent-to-child command".to_owned(),
                },
                repaint: None,
                focusables: None,
            },
        }
    }

    /// The `Debug` arm of the seam (split out for readability). Drives the
    /// recorder's scrub cursor / inspection and shares the diff-repaint tail.
    fn apply_debug<Model, Msg, FView>(
        &mut self,
        cmd: crate::control::DebugCmd,
        view: &FView,
        model: &Model,
        dbg: &mut TuiDebugger<Msg, Model>,
    ) -> ApplyOutcome<Msg>
    where
        Model: Clone,
        Msg: Clone + IpeStringify,
        FView: Fn(Model) -> CellsView<Msg>,
    {
        use crate::control::{ControlFrame, DebugCmd};

        // `InspectModel` is read-only — it never moves the cursor and it renders
        // its own reply frame rather than repainting the live surface.
        if let DebugCmd::InspectModel(n) = cmd {
            // An empty history has no step to reconstruct — reply with the live
            // head at the requested index rather than fail.
            let (step, mdl) = match dbg.reconstruct_at(n) {
                Some(pair) => pair,
                None => (n, model.clone()),
            };
            // Render the model at step `n` to its frame — the tui rendering of
            // "the model at step n" (the surface has no `IpeStringify` bound on
            // `Model`, so its view frame is the faithful, bound-free snapshot).
            let (rendered, _fs) = render_debug_annotated(
                view,
                mdl,
                dbg,
                &mut self.inputs,
                self.focus_idx,
                self.scroll_y,
            );
            return ApplyOutcome {
                reply: ControlFrame::ModelSnapshot { step, rendered },
                repaint: None,
                focusables: None,
            };
        }

        // The cursor-moving / mode arms all reconstruct a model to display and
        // share the repaint tail below.
        let (display, detail) = match cmd {
            DebugCmd::StepTo(n) => (dbg.step_to(n), "scrub: step-to"),
            DebugCmd::Back => (dbg.step_back(), "scrub: back"),
            DebugCmd::Forward => (dbg.step_fwd(), "scrub: forward"),
            DebugCmd::Reset | DebugCmd::LiveTail => {
                // Return to the live head: leave scrub mode and repaint the live
                // model. (`Reset`'s recorder-fork semantics need the caller's
                // `init` model and a live-driver reset, which the wire cannot
                // carry; the in-process apply resolves both to "resume live".)
                dbg.live_tail();
                (None, "live-tail")
            }
            // `InspectModel` handled above.
            DebugCmd::InspectModel(_) => (None, "inspect"),
        };
        // A cursor arm that reconstructed a step displays it; otherwise (live
        // arms, or an empty history) display the live head.
        let display = display.unwrap_or_else(|| model.clone());
        let (annotated, fs) = render_debug_annotated(
            view,
            display,
            dbg,
            &mut self.inputs,
            self.focus_idx,
            self.scroll_y,
        );
        let repaint = self.diff_repaint(annotated);
        ApplyOutcome {
            reply: ControlFrame::Ack {
                ok: true,
                detail: detail.to_owned(),
            },
            focusables: repaint.as_ref().map(|_| fs),
            repaint,
        }
    }
}

/// Drive a keyboard-derived debugger command through the ONE apply seam, then
/// paint whatever repaint it requested. The keyboard scrub sites and the (later)
/// wire handler both funnel through [`TuiSurface::apply_control_frame`], so there
/// is exactly one apply path — never a keyboard path and a wire path that can
/// drift. Returns the freshly-rendered focusables, or the caller's current set
/// when the frame was unchanged.
///
/// The transient `TuiSurface` starts with an empty diff baseline, so a keyboard
/// step always paints — matching the pre-seam per-keypress repaint exactly; the
/// diff guard's dedup pays off on the wire path, where redundant frames recur.
#[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
#[allow(clippy::too_many_arguments)] // threads the loop's render surface + seam inputs
fn keyboard_scrub<Model, Msg, FView>(
    cmd: crate::control::DebugCmd,
    view: &FView,
    model: &Model,
    dbg: &mut TuiDebugger<Msg, Model>,
    inputs: &mut InputRegistry,
    focus_idx: usize,
    scroll_y: usize,
    current: Vec<Focusable<Msg>>,
) -> Vec<Focusable<Msg>>
where
    Model: Clone,
    Msg: Clone + IpeStringify,
    FView: Fn(Model) -> CellsView<Msg>,
{
    let mut surface = TuiSurface::new(std::mem::take(inputs), focus_idx, scroll_y);
    let outcome =
        surface.apply_control_frame(crate::control::ControlFrame::Debug(cmd), view, model, dbg);
    // Restore the (possibly edited) input registry to the loop's owner.
    *inputs = std::mem::take(&mut surface.inputs);
    if let Some(frame) = outcome.repaint {
        paint(&frame);
    }
    outcome.focusables.unwrap_or(current)
}

/// `Tui.tea` — terminal TEA driver for a `view : Model -> Cells msg`.
/// The `Cells msg` value wraps the same structured `Element` tree that `Ipe.Web`
/// renders; here it is laid out to ANSI cells by walking the typed attributes
/// (`tui::layout`), and `Ipe.Ui.Input.*` widgets become focusables. Tab /
/// Shift-Tab cycle focus; typing edits the focused text input (dispatching its
/// `onInput`); Enter/Space activates a button or toggles a checkbox/radio; the
/// view auto-scrolls to keep the focused element on screen. Ctrl-keys and any
/// unhandled key go to every `Tui.Sub.onKey` handler the current
/// `subscriptions` declares; with none active the key is unobserved.
#[allow(clippy::type_complexity, clippy::too_many_lines, unused_assignments)]
pub fn tui_app_ui<Model, Msg, E, FInit, FUpdate, FView, FSubs>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
) -> IpeTask<E, ()>
where
    E: Send + From<String> + crate::FromUnavailable + 'static,
    Model: Clone + Send + 'static,
    Msg: Clone + Send + IpeStringify + 'static,
    FInit: Fn(()) -> (Model, IpeCmd<Msg>) + Send + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FView: Fn(Model) -> CellsView<Msg> + Send + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + Send + 'static,
{
    // Wrap update in Arc — same rationale as tui_app.
    let update = std::sync::Arc::new(update);
    Box::pin(async move {
        let _guard = match TuiGuard::enter_mouse() {
            Ok(g) => g,
            Err(e) => return IpeResult::Err(e.into_task_error()),
        };

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<CliEvent<Msg>>();
        // A refused key reader ends the app as in `tui_app`.
        let key_tx = tx.clone();
        let started = crate::threads::spawn_named(KEY_READER_THREAD, move || {
            read_keys_loop(&key_tx, |k| {
                // The (kind, value) channel is flat, so fold the ctrl modifier on
                // Left/Right into the kind (`ctrlleft`/`ctrlright`) for the input
                // editor's word-jumps.
                let kind = if k.ctrl && (k.kind == "left" || k.kind == "right") {
                    format!("ctrl{}", k.kind)
                } else {
                    k.kind
                };
                (kind, k.value)
            });
        });
        if let Err(e) = started {
            return IpeResult::Err(
                crate::threads::ThreadRefused::os(KEY_READER_THREAD, &e).into_error(),
            );
        }

        let (mut model, cmd0) = init(());
        cli_run_cmd(cmd0, &tx);
        let mut submgr = SubManager::new(tx.clone());
        submgr.update(subscriptions(model.clone()));

        #[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
        let mut dbg = {
            let upd = std::sync::Arc::clone(&update);
            TuiDebugger::new(model.clone(), move |msg, mdl| upd(msg, mdl))
        };

        // The loopback control channel: `ipe dev watch` (parent) delivers hot-swap
        // (default watch) and time-travel (`--debugger`) frames here; the run loop
        // applies each through the ONE apply seam on its own thread (below).
        // Fail-closed and release-absent — `spawn_control_bridge` binds nothing
        // without a port + token, and the whole surface is gated on `control-wire`
        // (absent from every `ipe release` artifact).
        #[cfg(all(feature = "control-wire", not(target_arch = "wasm32")))]
        let mut control_rx = spawn_control_bridge();

        let mut inputs = InputRegistry::new();
        let mut focus_idx = 0usize;
        let mut scroll_y = 0usize;
        let mut focusables: Vec<Focusable<Msg>> =
            render_and_paint(&view, &model, &mut inputs, &mut focus_idx, &mut scroll_y);

        loop {
            // Fold the control channel into the run loop's event select so an
            // incoming frame is applied on THIS thread — the only writer of
            // `model`/`dbg`/the render surface. A keyboard event and a control
            // frame can never race the model.
            #[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
            let ev = tokio::select! {
                biased;
                req = control_rx.recv() => match req {
                    Some(req) => {
                        let outcome = {
                            let mut surface =
                                TuiSurface::new(std::mem::take(&mut inputs), focus_idx, scroll_y);
                            let outcome =
                                surface.apply_control_frame(req.frame, &view, &model, &mut dbg);
                            inputs = std::mem::take(&mut surface.inputs);
                            outcome
                        };
                        if let Some(frame) = outcome.repaint {
                            paint(&frame);
                        }
                        if let Some(fs) = outcome.focusables {
                            focusables = fs;
                        }
                        // Reply to the parent; a dropped receiver (parent gone) is
                        // benign — the frame was still applied.
                        let _ = req.reply.send(outcome.reply);
                        continue;
                    }
                    // The bridge sender was dropped (accept loop gone): stop
                    // draining control frames but keep serving app events.
                    None => match rx.recv().await {
                        Some(ev) => ev,
                        None => break,
                    },
                },
                ev = rx.recv() => match ev {
                    Some(ev) => ev,
                    None => break,
                },
            };
            // Default `ipe dev watch` (control-wire, no debugger): drain the control
            // channel for the appearance hot-swap only — the sole parent→child
            // command a non-debugger build carries. Applied on THIS thread (the
            // single writer of `model`/the render surface) through the ONE seam,
            // so a keyboard event and a control frame never race the model.
            #[cfg(all(
                feature = "control-wire",
                not(feature = "debugger"),
                not(target_arch = "wasm32")
            ))]
            let ev = tokio::select! {
                biased;
                req = control_rx.recv() => match req {
                    Some(req) => {
                        let outcome = {
                            let mut surface =
                                TuiSurface::new(std::mem::take(&mut inputs), focus_idx, scroll_y);
                            let outcome = surface.apply_control_frame(req.frame, &view, &model);
                            inputs = std::mem::take(&mut surface.inputs);
                            outcome
                        };
                        if let Some(frame) = outcome.repaint {
                            paint(&frame);
                        }
                        if let Some(fs) = outcome.focusables {
                            focusables = fs;
                        }
                        // Reply to the parent; a dropped receiver (parent gone) is
                        // benign — the frame was still applied.
                        let _ = req.reply.send(outcome.reply);
                        continue;
                    }
                    // The bridge sender was dropped (accept loop gone): stop
                    // draining control frames but keep serving app events.
                    None => match rx.recv().await {
                        Some(ev) => ev,
                        None => break,
                    },
                },
                ev = rx.recv() => match ev {
                    Some(ev) => ev,
                    None => break,
                },
            };
            // Release / plain build: no control surface — serve app events only.
            #[cfg(all(
                not(feature = "control-wire"),
                not(all(feature = "debugger", not(target_arch = "wasm32")))
            ))]
            let ev = match rx.recv().await {
                Some(ev) => ev,
                None => break,
            };
            // A wasm target under control-wire has no native control socket; the
            // control_rx binding is native-only, so serve app events directly.
            #[cfg(all(feature = "control-wire", target_arch = "wasm32"))]
            let ev = match rx.recv().await {
                Some(ev) => ev,
                None => break,
            };
            // A widget-produced message (click / input / focus) …
            let mut produced: Option<Msg> = None;
            // … or the messages the active `Tui.Sub.onKey` handlers map a key to.
            let mut from_keys: Vec<Msg> = Vec::new();
            match ev {
                CliEvent::Msg(m) | CliEvent::PerformDone(m) => produced = Some(m),
                CliEvent::Eof => break,
                CliEvent::Line(..) => continue,
                // The permit returns to the reader's budget as the key is taken.
                CliEvent::Key(kind, value, _permit) => {
                    // Debugger key intercept — must come before any app key handling.
                    #[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
                    {
                        // Ctrl-T: toggle time-travel mode — routed through the ONE
                        // apply seam. Entering pins the head step (`StepTo` of the
                        // last index, clamped); leaving resumes the live tail.
                        if kind == crate::debugger::tui::TOGGLE_KIND
                            && value == crate::debugger::tui::TOGGLE_VALUE
                        {
                            let cmd = if dbg.is_scrubbing() {
                                crate::control::DebugCmd::LiveTail
                            } else {
                                crate::control::DebugCmd::StepTo(usize::MAX)
                            };
                            focusables = keyboard_scrub(
                                cmd,
                                &view,
                                &model,
                                &mut dbg,
                                &mut inputs,
                                focus_idx,
                                scroll_y,
                                focusables,
                            );
                            continue;
                        }
                        // Ctrl-Left / Ctrl-Right: step in time-travel mode — same
                        // seam as Ctrl-T and (later) the wire, so a step can never
                        // diverge from a wire-driven `Back`/`Forward`.
                        if dbg.is_scrubbing() {
                            let cmd = if kind == crate::debugger::tui::STEP_BACK_KIND {
                                Some(crate::control::DebugCmd::Back)
                            } else if kind == crate::debugger::tui::STEP_FWD_KIND {
                                Some(crate::control::DebugCmd::Forward)
                            } else {
                                None
                            };
                            if let Some(cmd) = cmd {
                                focusables = keyboard_scrub(
                                    cmd,
                                    &view,
                                    &model,
                                    &mut dbg,
                                    &mut inputs,
                                    focus_idx,
                                    scroll_y,
                                    focusables,
                                );
                                continue;
                            }
                        }
                    }
                    // Mouse: wheel scrolls the viewport; a left-press focuses the
                    // hit element and activates it (if not an input).
                    if kind == "mouse" {
                        if let Some((btn, mcol, mrow, press)) = parse_mouse(&value) {
                            if press && (btn == 64 || btn == 65) {
                                let (cols, rows) = term_size();
                                let (_f, _fs, content_h) = render_with_focus(
                                    &view(model.clone()).into_element(),
                                    cols,
                                    rows,
                                    focus_idx,
                                    &mut inputs,
                                    scroll_y,
                                );
                                let max_scroll = content_h.saturating_sub(rows);
                                scroll_y = if btn == 64 {
                                    scroll_y.saturating_sub(3)
                                } else {
                                    (scroll_y + 3).min(max_scroll)
                                };
                                let (frame, fs, _) = render_with_focus(
                                    &view(model.clone()).into_element(),
                                    cols,
                                    rows,
                                    focus_idx,
                                    &mut inputs,
                                    scroll_y,
                                );
                                paint(&frame);
                                focusables = fs;
                                continue;
                            }
                            if press && btn == 0 {
                                if let Some(hit) = hit_test(
                                    &focusables,
                                    mcol.saturating_sub(1),
                                    mrow.saturating_sub(1),
                                    scroll_y,
                                ) {
                                    let old_focus = focus_idx;
                                    focus_idx = hit;
                                    // onBlur (old) + onFocus (new) on a click focus
                                    // change — same as Tab nav .
                                    dispatch_focus_change(&focusables, old_focus, hit, &tx);
                                    let is_input =
                                        focusables.get(hit).map(|f| f.is_input).unwrap_or(false);
                                    if !is_input {
                                        produced = focusables
                                            .get(hit)
                                            .and_then(|f| extract_click_msg(&f.events));
                                    }
                                    if produced.is_none() {
                                        focusables = render_and_paint(
                                            &view,
                                            &model,
                                            &mut inputs,
                                            &mut focus_idx,
                                            &mut scroll_y,
                                        );
                                        continue;
                                    }
                                    // else fall through to dispatch `produced`.
                                } else {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        }
                        // A left-press that produced a click Msg skips the key
                        // logic below (the `else`) and dispatches `produced`.
                    } else {
                        let n = focusables.len();
                        let focused_input = focusables
                            .get(focus_idx)
                            .map(|f| f.is_input)
                            .unwrap_or(false);
                        let is_shift_tab = kind == "other" && value.contains('Z');
                        let nav_fwd = kind == "tab" || (kind == "down" && !focused_input);
                        let nav_back = is_shift_tab || (kind == "up" && !focused_input);
                        // A focused <textarea>'s Enter inserts a newline (multiline
                        // edit), not a submit: remap to a char-insert so the generic
                        // edit path below handles it uniformly.
                        let is_textarea = focusables
                            .get(focus_idx)
                            .map(|f| f.input_type == "textarea")
                            .unwrap_or(false);
                        let (kind, value) = if focused_input && is_textarea && kind == "enter" {
                            ("char".to_string(), "\n".to_string())
                        } else {
                            (kind, value)
                        };

                        if (nav_fwd || nav_back) && n > 0 {
                            let old_focus = focus_idx;
                            focus_idx = if nav_back {
                                (focus_idx + n - 1) % n
                            } else {
                                (focus_idx + 1) % n
                            };
                            focusables = render_and_paint(
                                &view,
                                &model,
                                &mut inputs,
                                &mut focus_idx,
                                &mut scroll_y,
                            );
                            // onBlur (old) + onFocus (new) —  tuiDispatchFocusChange.
                            dispatch_focus_change(&focusables, old_focus, focus_idx, &tx);
                            continue;
                        }

                        if kind == "ctrl" {
                            from_keys = submgr.key_msgs(&kind, &value);
                            if from_keys.is_empty() {
                                continue;
                            }
                        } else if focused_input {
                            let is_cbr = focusables
                                .get(focus_idx)
                                .map(|f| f.is_checkbox_or_radio())
                                .unwrap_or(false);
                            if is_cbr && (kind == "space" || kind == "enter") {
                                produced = focusables
                                    .get(focus_idx)
                                    .and_then(|f| extract_click_msg(&f.events));
                                if produced.is_none() {
                                    continue;
                                }
                            } else if kind == "enter" {
                                let buf = inputs.get(focus_idx).buffer.clone();
                                produced = focusables.get(focus_idx).and_then(|f| {
                                    extract_input_msg(&f.events, "change", &buf)
                                        .or_else(|| extract_input_msg(&f.events, "input", &buf))
                                });
                                if produced.is_none() {
                                    continue;
                                }
                            } else {
                                let changed = edit_input(inputs.get(focus_idx), &kind, &value);
                                if changed {
                                    let buf = inputs.get(focus_idx).buffer.clone();
                                    inputs.get(focus_idx).last_value = buf.clone();
                                    produced = focusables
                                        .get(focus_idx)
                                        .and_then(|f| extract_input_msg(&f.events, "input", &buf));
                                    if produced.is_none() {
                                        // local echo (no onInput handler) — repaint only.
                                        focusables = render_and_paint(
                                            &view,
                                            &model,
                                            &mut inputs,
                                            &mut focus_idx,
                                            &mut scroll_y,
                                        );
                                        continue;
                                    }
                                } else {
                                    // cursor move / unhandled edit key — repaint the cursor.
                                    focusables = render_and_paint(
                                        &view,
                                        &model,
                                        &mut inputs,
                                        &mut focus_idx,
                                        &mut scroll_y,
                                    );
                                    continue;
                                }
                            }
                        } else if (kind == "enter" || kind == "space") && focus_idx < n {
                            produced = focusables
                                .get(focus_idx)
                                .and_then(|f| extract_click_msg(&f.events));
                            if produced.is_none() {
                                continue;
                            }
                        } else {
                            from_keys = submgr.key_msgs(&kind, &value);
                            if from_keys.is_empty() {
                                continue;
                            }
                        }
                    } // end key-logic else (non-mouse)
                }
            }

            // Fold each message in order; the subscriptions are re-evaluated
            // after each, so the next message meets the model it produced.
            let mut folded = false;
            for msg in produced.into_iter().chain(from_keys) {
                folded = true;
                #[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
                let (next, cmd) = update(msg.clone(), model);
                #[cfg(not(all(feature = "debugger", not(target_arch = "wasm32"))))]
                let (next, cmd) = update(msg, model);

                model = next;

                #[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
                dbg.record(msg, model.clone());

                cli_run_cmd(cmd, &tx);
                submgr.update(subscriptions(model.clone()));
            }

            if folded {
                #[cfg(all(feature = "debugger", not(target_arch = "wasm32")))]
                {
                    // In time-travel mode: freeze on the pinned past step.
                    // Toggle Ctrl-T to return to the live head.
                    let display_model =
                        dbg.current_reconstructed().unwrap_or_else(|| model.clone());
                    let (annotated, fs) = render_debug_annotated(
                        &view,
                        display_model,
                        &dbg,
                        &mut inputs,
                        focus_idx,
                        scroll_y,
                    );
                    paint(&annotated);
                    focusables = fs;
                }
                #[cfg(not(all(feature = "debugger", not(target_arch = "wasm32"))))]
                {
                    focusables =
                        render_and_paint(&view, &model, &mut inputs, &mut focus_idx, &mut scroll_y);
                }
            }
        }
        submgr.stop_all();
        ok_res(())
    })
}

// ── The apply-seam tests ────────────────────────────────────────────────────
//
// Every test CONSTRUCTS `ControlFrame`s directly — no transport, no socket — so
// it pins the in-process apply/scrub/inspect behavior and the single-seam
// invariant independently of any wire.
#[cfg(all(test, feature = "debugger", not(target_arch = "wasm32")))]
mod apply_seam_tests {
    use super::*;
    use crate::control::{ControlFrame, DebugCmd};
    use crate::tea::IpeCmd;

    #[derive(Clone, Debug, PartialEq)]
    enum TMsg {
        Add(i64),
    }

    impl IpeStringify for TMsg {
        fn ipe_show(&self) -> String {
            match self {
                TMsg::Add(n) => format!("Add({n})"),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq)]
    struct TModel {
        count: i64,
    }

    fn t_update(msg: TMsg, model: TModel) -> (TModel, IpeCmd<TMsg>) {
        let TMsg::Add(n) = msg;
        (
            TModel {
                count: model.count + n,
            },
            IpeCmd::None,
        )
    }

    // The view renders the model's count as text, so distinct models produce
    // distinct frames — the property the diff-repaint and reconstruct tests rely
    // on.
    fn t_view(model: TModel) -> CellsView<TMsg> {
        super::super::cells_text_(format!("count={}", model.count))
    }

    // A debugger seeded with N recorded steps folded from `t_update`, plus the
    // live head model. Step `i` records the msg and the model AFTER applying it.
    fn seeded(msgs: &[i64]) -> (TuiDebugger<TMsg, TModel>, TModel) {
        let mut dbg = TuiDebugger::new(TModel { count: 0 }, t_update);
        let mut live = TModel { count: 0 };
        for &n in msgs {
            let (next, _) = t_update(TMsg::Add(n), live.clone());
            dbg.record(TMsg::Add(n), next.clone());
            live = next;
        }
        (dbg, live)
    }

    // (a) A HotAppearance frame recomputes from the CURRENT model and repaints via
    // the diff guard — an inert patch (no literal-table mechanism in a tui build)
    // reproduces the identical frame, so the SECOND apply requests NO repaint (not
    // a full-screen redraw) — and focus/scroll are preserved across both.
    #[test]
    fn hot_appearance_diff_repaints_and_preserves_input_state() {
        let (mut dbg, live) = seeded(&[10, 5]);
        let mut surface = TuiSurface::new(InputRegistry::new(), 3, 7);

        let patch = crate::control::AppearancePatch::default();
        let first = surface.apply_control_frame(
            ControlFrame::HotAppearance(patch.clone()),
            &t_view,
            &live,
            &mut dbg,
        );
        assert!(
            matches!(first.reply, ControlFrame::Ack { ok: true, .. }),
            "hot-appearance replies Ack ok"
        );
        assert!(
            first.repaint.is_some(),
            "the first apply establishes the frame (a repaint)"
        );

        // Second identical apply: the recomputed frame equals the baseline, so the
        // diff guard requests NO paint — minimal repaint, never a full redraw.
        let second = surface.apply_control_frame(
            ControlFrame::HotAppearance(patch),
            &t_view,
            &live,
            &mut dbg,
        );
        assert!(
            second.repaint.is_none(),
            "an unchanged surface repaints nothing (no full-screen redraw)"
        );
        // Input state preserved across the appearance apply.
        assert_eq!(surface.focus_idx(), 3, "focus preserved");
        assert_eq!(surface.scroll_y(), 7, "scroll preserved");
    }

    // (b) StepTo / Back / Forward move the scrub cursor and reconstruct the model
    // at that step; the reconstructed model equals the live model at step n.
    #[test]
    fn debug_scrub_reconstructs_the_step_model() {
        let (mut dbg, live) = seeded(&[10, 5, 3]); // steps: 10, 15, 18
        let mut surface = TuiSurface::new(InputRegistry::new(), 0, 0);

        // StepTo(0) → model after the first msg (count = 10).
        let out = surface.apply_control_frame(
            ControlFrame::Debug(DebugCmd::StepTo(0)),
            &t_view,
            &live,
            &mut dbg,
        );
        assert!(matches!(out.reply, ControlFrame::Ack { ok: true, .. }));
        assert!(out.repaint.is_some(), "a scrub to a new step repaints");
        // reconstruct(0) == the model at step 0.
        assert_eq!(
            dbg.current_reconstructed(),
            Some(TModel { count: 10 }),
            "StepTo(0) reconstructs the step-0 model"
        );

        // Forward → step 1 (count = 15).
        let _ = surface.apply_control_frame(
            ControlFrame::Debug(DebugCmd::Forward),
            &t_view,
            &live,
            &mut dbg,
        );
        assert_eq!(dbg.current_reconstructed(), Some(TModel { count: 15 }));

        // Back → step 0 (count = 10).
        let _ = surface.apply_control_frame(
            ControlFrame::Debug(DebugCmd::Back),
            &t_view,
            &live,
            &mut dbg,
        );
        assert_eq!(dbg.current_reconstructed(), Some(TModel { count: 10 }));
    }

    // (c) InspectModel(n) returns the snapshot of the model at step n WITHOUT
    // moving the cursor; LiveTail restores live mode.
    #[test]
    fn inspect_model_snapshots_and_live_tail_restores_live() {
        let (mut dbg, live) = seeded(&[10, 5, 3]);
        let mut surface = TuiSurface::new(InputRegistry::new(), 0, 0);

        // Enter scrub at step 0 first, so we can prove Inspect does not move it.
        let _ = surface.apply_control_frame(
            ControlFrame::Debug(DebugCmd::StepTo(0)),
            &t_view,
            &live,
            &mut dbg,
        );
        assert!(dbg.is_scrubbing());

        let out = surface.apply_control_frame(
            ControlFrame::Debug(DebugCmd::InspectModel(1)),
            &t_view,
            &live,
            &mut dbg,
        );
        let (step, rendered) = match &out.reply {
            ControlFrame::ModelSnapshot { step, rendered } => (*step, rendered.clone()),
            other => {
                assert!(
                    matches!(other, ControlFrame::ModelSnapshot { .. }),
                    "InspectModel must reply ModelSnapshot, got {other:?}"
                );
                return;
            }
        };
        assert_eq!(step, 1, "the snapshot reflects the requested step");
        assert!(
            rendered.contains("count=15"),
            "the snapshot renders the step-1 model (count=15); got: {rendered:?}"
        );
        assert!(
            out.repaint.is_none(),
            "an inspection is read-only — it does not repaint the live surface"
        );
        // Cursor unmoved by the inspection.
        assert_eq!(
            dbg.current_reconstructed(),
            Some(TModel { count: 10 }),
            "InspectModel must not move the scrub cursor"
        );

        // LiveTail leaves scrub mode.
        let out = surface.apply_control_frame(
            ControlFrame::Debug(DebugCmd::LiveTail),
            &t_view,
            &live,
            &mut dbg,
        );
        assert!(matches!(out.reply, ControlFrame::Ack { ok: true, .. }));
        assert!(!dbg.is_scrubbing(), "LiveTail restores live mode");
    }

    // (d) The keyboard path and the frame path drive the IDENTICAL seam: a
    // Ctrl-Left keypress (folded to `Back`) and a directly-constructed
    // `Debug(Back)` frame produce the same rendered frame and the same cursor.
    #[test]
    fn keyboard_path_equals_frame_path() {
        // Frame path: seed, step to the tail, then Back one step.
        let (mut dbg_f, live_f) = seeded(&[10, 5, 3]);
        let mut surface_f = TuiSurface::new(InputRegistry::new(), 0, 0);
        let _ = surface_f.apply_control_frame(
            ControlFrame::Debug(DebugCmd::StepTo(2)),
            &t_view,
            &live_f,
            &mut dbg_f,
        );
        let frame_out = surface_f.apply_control_frame(
            ControlFrame::Debug(DebugCmd::Back),
            &t_view,
            &live_f,
            &mut dbg_f,
        );

        // Keyboard path: same seeded state and cursor, driven through
        // `keyboard_scrub` (the shared keyboard entry point).
        let (mut dbg_k, live_k) = seeded(&[10, 5, 3]);
        let mut inputs = InputRegistry::new();
        let _ = dbg_k.step_to(2);
        let kb_focusables = keyboard_scrub(
            DebugCmd::Back,
            &t_view,
            &live_k,
            &mut dbg_k,
            &mut inputs,
            0,
            0,
            Vec::new(),
        );

        // Same reconstructed cursor after the Back step.
        assert_eq!(
            dbg_f.current_reconstructed(),
            dbg_k.current_reconstructed(),
            "keyboard and frame paths land on the same scrub step"
        );
        // Same rendered frame (the seam is the sole frame producer).
        let frame_frame = frame_out.repaint.expect("the frame path repaints");
        let display_k = dbg_k
            .current_reconstructed()
            .unwrap_or_else(|| live_k.clone());
        let (kb_frame, _) = render_debug_annotated(&t_view, display_k, &dbg_k, &mut inputs, 0, 0);
        assert_eq!(
            frame_frame, kb_frame,
            "keyboard and frame paths render the identical frame"
        );
        assert_eq!(
            kb_focusables.len(),
            frame_out.focusables.map(|f| f.len()).unwrap_or(0),
            "both paths yield the same focusable set"
        );
    }

    // (e) The async→sync bridge: a frame handed to the accept-loop HANDLER
    // (the async side) is applied by a run-loop drain (the sync side that owns
    // Model/dbg) through the ONE seam, and the handler receives the reply the
    // run loop produced — never a bypass of the seam. Drives `control_bridge_channel`
    // exactly as `spawn_control_bridge` + the `tui_app_ui` select loop do, minus
    // the socket. `Debug(StepTo)` also proves determinism survives the bridge:
    // the reconstructed cursor equals the direct-seam cursor.
    #[tokio::test]
    async fn bridge_applies_through_the_seam_and_returns_the_reply() {
        let (handler, mut req_rx) = control_bridge_channel();

        // The run-loop side: own the seam state, drain one request, apply it via
        // `apply_control_frame`, and reply on the request's one-shot — mirroring
        // the `tui_app_ui` select arm.
        let run_loop = tokio::spawn(async move {
            let (mut dbg, live) = seeded(&[10, 5, 3]); // steps 10,15,18
            let mut surface = TuiSurface::new(InputRegistry::new(), 0, 0);
            let req = req_rx.recv().await.expect("the bridge delivers the frame");
            let outcome = surface.apply_control_frame(req.frame, &t_view, &live, &mut dbg);
            let cursor = dbg.current_reconstructed();
            let _ = req.reply.send(outcome.reply);
            cursor
        });

        // The async handler side: `serve_control` awaits this handler on its
        // per-connection task, so await it directly here — it never blocks the
        // worker, so no `spawn_blocking` is needed.
        let reply = handler(ControlFrame::Debug(DebugCmd::StepTo(1))).await;

        assert!(
            matches!(reply, ControlFrame::Ack { ok: true, .. }),
            "the run loop's Ack reaches the handler, got {reply:?}"
        );
        let cursor = run_loop.await.expect("the run loop joins");
        assert_eq!(
            cursor,
            Some(TModel { count: 15 }),
            "StepTo(1) over the bridge reconstructs the step-1 model — determinism \
             preserved across the async→sync hop"
        );
    }

    // (f) Fail-closed: if the run loop has already dropped its receiver (the child
    // is exiting), the handler never hangs — it returns a REJECTING Ack so the
    // parent falls back to a full rebuild rather than believe a frame applied.
    #[tokio::test]
    async fn bridge_fails_closed_when_the_run_loop_is_gone() {
        let (handler, req_rx) = control_bridge_channel();
        drop(req_rx); // the run loop is gone

        let reply = handler(ControlFrame::HotAppearance(
            crate::control::AppearancePatch::default(),
        ))
        .await;

        assert!(
            matches!(reply, ControlFrame::Ack { ok: false, .. }),
            "a frame with no run loop to apply it is rejected, not silently accepted; \
             got {reply:?}"
        );
    }

    // (g) The FULL loopback path — the socket-crossing integration `ipe dev watch`
    // exercises, driven directly over a real TCP connection (no PTY, no `unsafe`):
    // a parent client frames a token record + a control-frame record exactly as
    // `ipe`-cli's `send_control_frame` does, the child's real accept-loop
    // (`control::server::serve_conn`) token-checks and decodes it, hands it to the
    // real bridge handler (`control_bridge_channel`), the run-loop drain applies it
    // through the ONE seam (`apply_control_frame`) on the single writer thread, and
    // the child→parent reply travels back. This is the end-to-end proof the
    // per-path unit tests (which bypass the socket) cannot give: an appearance-only
    // frame hot-swaps to a positive `Ack` — the parent's signal to SKIP the rebuild
    // — with the live model, scrub cursor, and focus/scroll all preserved; and a
    // `Debug(StepTo)` frame replays the recorded Msg-log through the rebuilt
    // `update` over the wire, reconstructing the step model deterministically.
    // The bridge handler AWAITS the run loop's reply one-shot on its serving task
    // (it never blocks the worker), so this is sound on any runtime flavor; a
    // multi-thread flavor is used here so the accept-loop task, the serving task,
    // and the run-loop drain task all make progress concurrently over the socket,
    // mirroring a spawned child's `serve_control` + run loop.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_loopback_hot_swaps_and_replays_state_preserving() {
        use crate::control::server::serve_conn;
        use crate::control::{decode_frame, encode_frame, transport};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::{TcpListener, TcpStream};

        const SESSION_TOKEN: &str = "s3cr3t-loopback-token";

        // The child-side accept-loop reads its session token from the env, exactly
        // as a spawned `ipe dev watch` child does; a `full` feature build also runs the
        // recorder-round-trip test in this module, so this must not race — but each
        // connection is served once, synchronously here.
        crate::system::locked_set_var(transport::CONTROL_TOKEN_ENV, SESSION_TOKEN);

        // Frame a length-delimited record: a 4-byte big-endian length prefix over
        // the body — the same framing the parent's `send_control_frame` emits and
        // the child's `read_record` expects.
        fn record(body: &[u8]) -> Vec<u8> {
            let len = u32::try_from(body.len()).expect("a small record fits u32");
            let mut out = len.to_be_bytes().to_vec();
            out.extend_from_slice(body);
            out
        }

        // Bind an ephemeral loopback listener (the port `ipe dev watch` would lease and
        // hand the child as `IPE_CONTROL_PORT`), learn its addr for the client.
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind an ephemeral loopback listener");
        let addr = listener
            .local_addr()
            .expect("the listener has a local addr");

        // The bridge: the async handler `serve_control` calls, plus the receiver the
        // run loop drains — wired precisely as `spawn_control_bridge` does it.
        let (handler, mut req_rx) = control_bridge_channel();

        // The run-loop drain: owns the single-writer seam state and applies every
        // delivered frame through `apply_control_frame`, mirroring the `tui_app_ui`
        // select arm. Seed a recorded Msg-log so the replay path has history.
        let run_loop = tokio::spawn(async move {
            let (mut dbg, live) = seeded(&[10, 5, 3]); // steps 10, 15, 18
            let mut surface = TuiSurface::new(InputRegistry::new(), 4, 9);
            let mut cursors = Vec::new();
            while let Some(req) = req_rx.recv().await {
                let outcome = surface.apply_control_frame(req.frame, &t_view, &live, &mut dbg);
                cursors.push(dbg.current_reconstructed());
                let _ = req.reply.send(outcome.reply);
            }
            // The live head and preserved surface state after every apply — the
            // "state-preserving" proof.
            (live, surface.focus_idx(), surface.scroll_y(), cursors)
        });

        // The child accept-loop: serve two connections through the REAL
        // `serve_conn` — token-check, decode, dispatch to the bridge handler — one
        // per delivered frame, exactly as `spawn_conn` does per accepted peer.
        let handler = std::sync::Arc::new(handler);
        let accept_handler = std::sync::Arc::clone(&handler);
        let accept = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept a client");
                let _ = serve_conn(stream, &*accept_handler).await;
            }
        });

        // A parent client: connect, present the token record, then the frame
        // record, and read the reply frame back to EOF — the `send_control_frame`
        // shape.
        async fn round_trip(
            addr: std::net::SocketAddr,
            token: &str,
            wire_body: Vec<u8>,
        ) -> Vec<u8> {
            let mut client = TcpStream::connect(addr).await.expect("client connects");
            let mut wire = record(token.as_bytes());
            wire.extend_from_slice(&record(&wire_body));
            client.write_all(&wire).await.expect("write the wire");
            client.flush().await.expect("flush the wire");
            let mut reply = Vec::new();
            client
                .read_to_end(&mut reply)
                .await
                .expect("read the reply to EOF");
            reply
        }

        // (1) Appearance-only hot-swap: a `HotAppearance` frame applied over the
        // real socket replies with a positive `Ack` — the parent's SKIP-the-rebuild
        // signal. `encode_frame` yields the length-prefixed body; strip the prefix
        // so `round_trip` re-frames it exactly once.
        let appear = ControlFrame::HotAppearance(crate::control::AppearancePatch::default());
        let appear_wire = encode_frame(&appear).expect("a small frame encodes");
        let appear_body = appear_wire
            .get(4..)
            .expect("the encoded frame has a body")
            .to_vec();
        let appear_reply = round_trip(addr, SESSION_TOKEN, appear_body).await;
        let (appear_frame, _) =
            decode_frame(&appear_reply).expect("the child replies a decodable frame");
        assert!(
            matches!(appear_frame, ControlFrame::Ack { ok: true, .. }),
            "an appearance-only frame hot-swaps over the wire (Ack ok) — no rebuild; \
             got {appear_frame:?}"
        );

        // (2) Replay: a `Debug(StepTo(1))` frame replays the recorded Msg-log
        // through `update` over the wire, reconstructing the step-1 model.
        let step = ControlFrame::Debug(DebugCmd::StepTo(1));
        let step_wire = encode_frame(&step).expect("a small frame encodes");
        let step_body = step_wire
            .get(4..)
            .expect("the encoded frame has a body")
            .to_vec();
        let step_reply = round_trip(addr, SESSION_TOKEN, step_body).await;
        let (step_frame, _) =
            decode_frame(&step_reply).expect("the child replies a decodable frame");
        assert!(
            matches!(step_frame, ControlFrame::Ack { ok: true, .. }),
            "a scrub frame is applied over the wire (Ack ok); got {step_frame:?}"
        );

        accept.await.expect("the accept loop joins");
        // Dropping the last handler clone closes the bridge sender, ending the
        // run-loop drain so it can report its final state.
        drop(handler);
        let (live, focus, scroll, cursors) = run_loop.await.expect("the run loop joins");

        // State-preserving: the live head model is untouched by either frame (an
        // appearance edit changes literals, not state; a scrub is read-only), and
        // the surface's focus/scroll survive.
        assert_eq!(
            live,
            TModel { count: 18 },
            "the live head model is preserved across the hot-swap and the scrub"
        );
        assert_eq!(focus, 4, "focus is preserved across the wire apply");
        assert_eq!(scroll, 9, "scroll is preserved across the wire apply");
        // Determinism: `StepTo(1)` over the wire reconstructs the step-1 model
        // (count = 15) by replaying the Msg-log — the same result the direct-seam
        // path yields.
        assert_eq!(
            cursors.last().and_then(Clone::clone),
            Some(TModel { count: 15 }),
            "StepTo(1) replays the Msg-log over the wire to the step-1 model — \
             determinism preserved across the full socket path"
        );
    }
}

// ── The default-watch (control-wire, no debugger) apply-seam tests ───────────
//
// A default `ipe dev watch` on a tui app mounts the seam WITHOUT the recorder: the
// only parent→child command it carries is the appearance hot-swap. These pin
// that debugger-free path — the appearance apply, the minimal-repaint dedup, the
// preserved input state, the fail-closed reply-frame rejection, and the bridge's
// fail-closed behaviour when the run loop is gone — independently of any wire.
#[cfg(all(
    test,
    feature = "control-wire",
    not(feature = "debugger"),
    not(target_arch = "wasm32")
))]
mod control_wire_seam_tests {
    use super::*;
    use crate::control::{AppearancePatch, ControlFrame};

    #[derive(Clone, Debug, PartialEq)]
    struct TModel {
        count: i64,
    }

    impl IpeStringify for TModel {
        fn ipe_show(&self) -> String {
            format!("count={}", self.count)
        }
    }

    // Distinct models render distinct frames — the property the diff-repaint test
    // relies on. (`Msg` is `()`: a default watch drives no scrub, so the seam
    // never constructs one.)
    fn t_view(model: TModel) -> CellsView<()> {
        super::super::cells_text_(format!("count={}", model.count))
    }

    // (a) A HotAppearance frame recomputes from the CURRENT model with NO recorder
    // in scope, replies `Ack ok`, and preserves focus/scroll; a second identical
    // apply reproduces the frame, so the diff guard requests NO repaint (minimal
    // repaint, never a full redraw).
    #[test]
    fn hot_appearance_applies_without_a_debugger_and_diffs() {
        let live = TModel { count: 7 };
        let mut surface = TuiSurface::new(InputRegistry::new(), 2, 5);
        let patch = AppearancePatch::default();

        let first =
            surface.apply_control_frame(ControlFrame::HotAppearance(patch.clone()), &t_view, &live);
        assert!(
            matches!(first.reply, ControlFrame::Ack { ok: true, .. }),
            "hot-appearance replies Ack ok"
        );
        assert!(
            first.repaint.is_some(),
            "the first apply establishes the frame (a repaint)"
        );

        let second =
            surface.apply_control_frame(ControlFrame::HotAppearance(patch), &t_view, &live);
        assert!(
            second.repaint.is_none(),
            "an unchanged surface repaints nothing (no full-screen redraw)"
        );
        assert_eq!(surface.focus_idx(), 2, "focus preserved");
        assert_eq!(surface.scroll_y(), 5, "scroll preserved");
    }

    // (b) Fail closed: a child→parent REPLY frame arriving as a command is not a
    // parent→child command — it is rejected with a non-ok `Ack` and no repaint,
    // never silently applied.
    #[test]
    fn reply_frame_is_rejected_fail_closed() {
        let live = TModel { count: 0 };
        let mut surface = TuiSurface::new(InputRegistry::new(), 0, 0);
        let out = surface.apply_control_frame(
            ControlFrame::Ack {
                ok: true,
                detail: "not a command".to_owned(),
            },
            &t_view,
            &live,
        );
        assert!(
            matches!(out.reply, ControlFrame::Ack { ok: false, .. }),
            "a reply frame is not a parent-to-child command — rejected fail-closed"
        );
        assert!(out.repaint.is_none(), "a rejected frame repaints nothing");
    }

    // (c) Fail closed: with the run loop's receiver dropped (child exiting), the
    // bridge handler never hangs — it returns a REJECTING Ack so `ipe dev watch` falls
    // back to a full rebuild rather than believe a frame applied.
    #[tokio::test]
    async fn bridge_fails_closed_when_the_run_loop_is_gone() {
        let (handler, req_rx) = control_bridge_channel();
        drop(req_rx); // the run loop is gone

        let reply = handler(ControlFrame::HotAppearance(AppearancePatch::default())).await;

        assert!(
            matches!(reply, ControlFrame::Ack { ok: false, .. }),
            "a frame with no run loop to apply it is rejected, not silently accepted; \
             got {reply:?}"
        );
    }
}

// A `NoTerminal` refusal must surface as `Unavailable` (the runtime's
// caller-should-retry-elsewhere kind), carrying the probe's own text
// verbatim — never folded into `Unexpected` through the bare-`String`
// `From` bridge a plain `format!(...).into()` would take.
#[cfg(test)]
mod tui_enter_error_tests {
    use super::{TuiEnterError, classify_raw_mode_error};
    use crate::error::{IpeError, IpeErrorKind};
    use crate::terminal_access::NoTerminal;

    #[test]
    fn a_no_terminal_refusal_is_unavailable_with_the_probes_exact_text() {
        for reason in [
            NoTerminal::DumbTerm,
            NoTerminal::NoStdoutTty,
            NoTerminal::NoControllingTerminal,
        ] {
            let err: IpeError = TuiEnterError::NoTerminal(reason).into_task_error();
            let IpeError::Error(kind, info) = err;
            assert_eq!(
                kind,
                IpeErrorKind::Unavailable,
                "{reason:?} must be Unavailable, not folded into Unexpected"
            );
            assert_eq!(
                info.message,
                reason.text(),
                "the runtime error message must be exactly terminal_access's \
                 refusal text — the CLI gate and the runtime guard show the \
                 SAME text, so neither may restate or truncate it"
            );
        }
    }

    // The residual (non-terminal) raw-mode failure stays `Unexpected`: it is
    // not a fact `terminal_access::probe()` predicted, so it keeps its raw OS
    // context instead of being reclassified as a terminal refusal.
    #[test]
    fn a_residual_raw_mode_failure_stays_unexpected() {
        let io_err = std::io::Error::other("boom");
        let err: IpeError = TuiEnterError::RawMode(io_err).into_task_error();
        let IpeError::Error(kind, info) = err;
        assert_eq!(kind, IpeErrorKind::Unexpected);
        assert!(
            info.message.contains("enable raw mode"),
            "got: {}",
            info.message
        );
    }

    // `classify_raw_mode_error` is exercised directly on non-unix targets
    // (where ENXIO cannot be constructed): every residual error stays
    // `RawMode`, never silently reclassified.
    #[cfg(not(unix))]
    #[test]
    fn non_unix_raw_mode_errors_are_never_reclassified() {
        let io_err = std::io::Error::other("boom");
        assert!(matches!(
            classify_raw_mode_error(io_err),
            TuiEnterError::RawMode(_)
        ));
    }

    // On unix, an ENXIO raw-mode failure is reclassified as the same
    // `NoControllingTerminal` refusal the pre-check would have raised — the
    // residual-failure path and the probe path converge on one fact.
    #[cfg(unix)]
    #[test]
    fn unix_enxio_raw_mode_error_is_reclassified_as_no_controlling_terminal() {
        let io_err = std::io::Error::from_raw_os_error(rustix::io::Errno::NXIO.raw_os_error());
        assert!(matches!(
            classify_raw_mode_error(io_err),
            TuiEnterError::NoTerminal(NoTerminal::NoControllingTerminal)
        ));
    }
}

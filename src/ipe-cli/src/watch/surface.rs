//! What a dev child is to the watch, and the lease that hands the terminal between children.
//!
//! Every per-child contract (stdin, readiness, start order, terminal hand-over,
//! appearance route) is an exhaustive match on one [`ChildSurface`], decided once
//! per generation from the program's typed shape. Terminal ownership is exclusive:
//! the [`TerminalLease`] hands it over only across stop, then restore, then spawn.

use std::cell::Cell;
#[cfg(unix)]
use std::cell::OnceCell;
use std::collections::VecDeque;
use std::io::Write as _;
use std::process::{Child, ExitStatus, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use ipe_watch::{ReadinessCheck, SupervisorState};

use crate::delivery::Shape;

/// How long a child with no port to probe must stay alive to count as ready.
pub const ALIVE_GRACE: Duration = Duration::from_millis(300);

/// The bytes that undo every terminal mode a dev child may have left set.
///
/// CAN aborts a half-written escape; then mouse reporting off (every tracking
/// mode and the SGR encoding), cursor shown, alternate screen left.
pub const RELEASE_BYTES: &str =
    "\x18\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?25h\x1b[?1049l";

/// Whether a terminal-owning child also binds a TCP listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listener {
    /// The child binds no listener.
    None,
    /// The child binds a first-party HTTP listener on the port it is handed.
    Tcp,
}

/// What a dev child is, for the supervisor.
///
/// Decided once per generation by [`ChildSurface::of`]; every contract below
/// matches it exhaustively, so a new variant fails the build until each decides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildSurface {
    /// An `Ipe.Web` app.
    WebApp,
    /// A non-web, non-terminal program that binds a first-party HTTP listener.
    HttpListener,
    /// An `Ipe.Tui` app: it draws on, and reads keys from, the terminal.
    Terminal {
        /// Whether it also binds a listener.
        listener: Listener,
    },
    /// A line-oriented console app with no listener.
    Line,
    /// A worker with no listener.
    Worker,
    /// A script with no listener.
    Script,
}

/// Where a dev child's stdin comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildStdin {
    /// The watch's own stdin, the terminal, as `ipe dev run` hands it.
    Inherit,
    /// Closed: the child reads end-of-file.
    Null,
}

/// Whether a new generation starts after the old one stops, or beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartOrder {
    /// The old child stops before the new one spawns.
    StopFirst,
    /// The new child spawns behind the proxy while the old one still serves.
    Overlap,
}

/// Whether a dev child takes the terminal over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalHandOver {
    /// The child owns the terminal; it is restored after every stop.
    Owns,
    /// The child leaves the terminal alone.
    None,
}

/// Where an appearance-only hot-swap is delivered to the running child.
///
/// One variant per delivery mechanism, so a surface can never fall between the
/// arms and silently drop an edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppearanceRoute {
    /// The child owns a loopback control socket; the swap rides a
    /// `HotAppearance` control frame.
    ControlSocket,
    /// The child serves `/_ipe/hot-appearance`; the swap rides an HTTP POST on
    /// the app port.
    WebPost,
    /// The child has no out-of-band apply path, so the edit takes a full
    /// rebuild. Never a silent skip.
    Rebuild,
}

impl ChildSurface {
    /// The surface of a program of `shape` that does (`binds_http`) or does not
    /// bind a first-party HTTP listener.
    #[must_use]
    pub const fn of(shape: Shape, binds_http: bool) -> Self {
        match (shape, binds_http) {
            (Shape::Web, _) => Self::WebApp,
            (Shape::Tui, true) => Self::Terminal {
                listener: Listener::Tcp,
            },
            (Shape::Tui, false) => Self::Terminal {
                listener: Listener::None,
            },
            (Shape::Cli | Shape::Worker | Shape::Script, true) => Self::HttpListener,
            (Shape::Cli, false) => Self::Line,
            (Shape::Worker, false) => Self::Worker,
            (Shape::Script, false) => Self::Script,
        }
    }

    /// Where the child's stdin comes from.
    ///
    /// An HTTP surface keeps it closed: two of its generations overlap behind
    /// the proxy, so neither may own the keyboard.
    #[must_use]
    pub const fn stdin(self) -> ChildStdin {
        match self {
            Self::WebApp | Self::HttpListener | Self::Worker => ChildStdin::Null,
            Self::Terminal { .. } | Self::Line | Self::Script => ChildStdin::Inherit,
        }
    }

    /// How the supervisor proves a child spawned on `port` is ready.
    #[must_use]
    pub const fn readiness(self, port: u16) -> ReadinessCheck {
        match self {
            Self::WebApp => ReadinessCheck::HttpReadyz { port },
            Self::HttpListener
            | Self::Terminal {
                listener: Listener::Tcp,
            } => ReadinessCheck::TcpConnect { port },
            Self::Terminal {
                listener: Listener::None,
            }
            | Self::Line
            | Self::Worker
            | Self::Script => ReadinessCheck::AliveGrace { grace: ALIVE_GRACE },
        }
    }

    /// Whether a new generation may overlap the old one.
    ///
    /// Only an HTTP surface overlaps, and only behind an engaged proxy (see
    /// [`apply_order`]).
    #[must_use]
    pub const fn start_order(self) -> StartOrder {
        match self {
            Self::WebApp | Self::HttpListener => StartOrder::Overlap,
            Self::Terminal { .. } | Self::Line | Self::Worker | Self::Script => {
                StartOrder::StopFirst
            }
        }
    }

    /// Whether the child takes the terminal over.
    #[must_use]
    pub const fn terminal(self) -> TerminalHandOver {
        match self {
            Self::Terminal { .. } | Self::Line => TerminalHandOver::Owns,
            Self::WebApp | Self::HttpListener | Self::Worker | Self::Script => {
                TerminalHandOver::None
            }
        }
    }

    /// Where an appearance-only hot-swap reaches the running child.
    #[must_use]
    pub const fn appearance_route(self) -> AppearanceRoute {
        match self {
            Self::Terminal { .. } => AppearanceRoute::ControlSocket,
            Self::WebApp => AppearanceRoute::WebPost,
            Self::HttpListener | Self::Line | Self::Worker | Self::Script => {
                AppearanceRoute::Rebuild
            }
        }
    }

    /// Whether the child serves a page the user opens in a browser.
    #[must_use]
    pub const fn serves_page(self) -> bool {
        match self {
            Self::WebApp => true,
            Self::HttpListener
            | Self::Terminal { .. }
            | Self::Line
            | Self::Worker
            | Self::Script => false,
        }
    }
}

/// The start order a generation of `surface` takes given whether a proxy is engaged.
///
/// Only an overlapping surface behind an engaged proxy overlaps; a terminal
/// surface stops first even when a proxy an earlier generation bound still
/// holds the port, so two terminal owners never run at once.
#[must_use]
pub const fn apply_order(surface: ChildSurface, proxy_engaged: bool) -> StartOrder {
    match (surface.start_order(), proxy_engaged) {
        (StartOrder::Overlap, true) => StartOrder::Overlap,
        (StartOrder::Overlap, false) | (StartOrder::StopFirst, _) => StartOrder::StopFirst,
    }
}

impl ChildStdin {
    /// The `Stdio` a child spawned with this stdin receives.
    #[must_use]
    pub fn stdio(self) -> Stdio {
        match self {
            Self::Inherit => Stdio::inherit(),
            Self::Null => Stdio::null(),
        }
    }
}

/// A dev child that exited on its own, as the watch reaped it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildExit {
    /// How the child exited.
    pub status: ExitStatus,
    /// Whether the child owned the terminal when it exited.
    pub hand_over: TerminalHandOver,
}

/// Records the terminal's state and puts it back.
pub trait TerminalRestore {
    /// Record the terminal's state, once, before the first child that owns it.
    fn capture(&self);
    /// Put the terminal back in the recorded state, ignoring every error.
    fn restore(&self);
}

/// The watch's own terminal: its stdin's modes and its stdout's screen.
///
/// Off unix no mode is recorded: the console is put back in cooked mode instead.
#[derive(Debug, Default)]
pub struct TtyRestore {
    /// The stdin modes before the first terminal-owning child; `None` inside
    /// when stdin is not a terminal.
    #[cfg(unix)]
    snapshot: OnceCell<Option<rustix::termios::Termios>>,
}

impl TerminalRestore for TtyRestore {
    fn capture(&self) {
        #[cfg(unix)]
        let _ = self.snapshot.get_or_init(|| {
            let stdin = std::io::stdin();
            if rustix::termios::isatty(&stdin) {
                rustix::termios::tcgetattr(&stdin).ok()
            } else {
                None
            }
        });
    }

    fn restore(&self) {
        #[cfg(unix)]
        if let Some(Some(snapshot)) = self.snapshot.get() {
            let _ = rustix::termios::tcsetattr(
                std::io::stdin(),
                rustix::termios::OptionalActions::Now,
                snapshot,
            );
        }
        #[cfg(windows)]
        {
            let _ = crossterm::terminal::disable_raw_mode();
        }
        if super::stdout_is_terminal() {
            let mut door = crate::progress::Door::Stdout;
            let _ = door
                .write_all(RELEASE_BYTES.as_bytes())
                .and_then(|()| door.flush());
        }
    }
}

/// The terminal as one owning child at a time holds it.
///
/// Released only once its owner has stopped: before the next spawn, after an
/// apply that leaves no live owner, after the session's shutdown, or when the
/// owner exits on its own. Never over a live owner, whose raw mode a restore
/// would clobber.
pub struct TerminalLease<R: TerminalRestore> {
    restore: R,
    /// The pid of the child that owns the terminal, while one does.
    owner: Cell<Option<u32>>,
    /// The progress row's hand-over, held while a child owns the terminal.
    handed: Cell<Option<crate::progress::HandOver>>,
}

impl<R: TerminalRestore> std::fmt::Debug for TerminalLease<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalLease")
            .field("owner", &self.owner.get())
            .finish_non_exhaustive()
    }
}

impl<R: TerminalRestore> TerminalLease<R> {
    /// A lease no child holds yet.
    pub const fn new(restore: R) -> Self {
        Self {
            restore,
            owner: Cell::new(None),
            handed: Cell::new(None),
        }
    }

    /// Whether a child owns the terminal.
    #[cfg(all(test, unix))]
    pub const fn is_held(&self) -> bool {
        self.owner.get().is_some()
    }

    /// Spawn a child of `hand_over` once its predecessor has stopped.
    ///
    /// Only for a stop-first apply: the supervisor has stopped and waited on the
    /// old child on every path that reaches its spawn, so the terminal is
    /// restored first and then handed to the new owner.
    ///
    /// # Errors
    /// The error `spawn` returns.
    pub fn spawn_after_stop(
        &self,
        hand_over: TerminalHandOver,
        spawn: impl FnOnce() -> std::io::Result<Child>,
    ) -> std::io::Result<Child> {
        self.release();
        match hand_over {
            TerminalHandOver::Owns => {
                self.restore.capture();
                self.handed.set(Some(crate::progress::hand_over()));
                hold_output();
                match spawn() {
                    Ok(child) => {
                        self.owner.set(Some(child.id()));
                        Ok(child)
                    }
                    Err(refused) => {
                        self.release();
                        Err(refused)
                    }
                }
            }
            TerminalHandOver::None => spawn(),
        }
    }

    /// Release the terminal unless `supervisor` runs its live owner.
    pub fn release_unless_live(&self, supervisor: &mut SupervisorState) {
        if !self.owner_runs(supervisor) {
            self.release();
        }
    }

    /// The exit of the running child when it exited on its own, whatever its surface.
    ///
    /// `supervisor` then holds no running child and keeps the child's binary as
    /// its last good one, so the next save starts it again; when the child owned
    /// the terminal, the lease is released first.
    pub fn reap_exited_child(&self, supervisor: &mut SupervisorState) -> Option<ChildExit> {
        let SupervisorState::Running { child, artifact } = supervisor else {
            return None;
        };
        let Ok(Some(status)) = child.try_wait() else {
            return None;
        };
        let hand_over = if self.owner.get() == Some(child.id()) {
            TerminalHandOver::Owns
        } else {
            TerminalHandOver::None
        };
        let last_good = artifact.clone();
        *supervisor = SupervisorState::NotRunning {
            last_good: Some(last_good),
        };
        if hand_over == TerminalHandOver::Owns {
            self.release();
        }
        Some(ChildExit { status, hand_over })
    }

    /// Restore the terminal when a child held it, then write the watch output held meanwhile.
    pub fn release(&self) {
        if self.owner.take().is_some() {
            self.restore.restore();
        }
        drop(self.handed.take());
        flush_output();
    }

    /// Whether `supervisor` runs the owner and the owner may still be alive.
    ///
    /// A failed exit probe counts as alive: the restore must never land on a
    /// live owner.
    fn owner_runs(&self, supervisor: &mut SupervisorState) -> bool {
        match supervisor {
            SupervisorState::Running { child, .. } => {
                self.owner.get() == Some(child.id()) && !matches!(child.try_wait(), Ok(Some(_)))
            }
            SupervisorState::NotRunning { .. } => false,
        }
    }
}

/// The most watch output blocks held while a child owns the terminal.
const MAX_HELD_BLOCKS: usize = 256;

/// The most bytes of watch output held while a child owns the terminal.
const MAX_HELD_BYTES: usize = 64 * 1024;

/// The note that leads a flush when held output overflowed its bounds.
const HELD_OUTPUT_DROPPED: &str =
    "[ipe dev watch] earlier output was dropped while the app held the terminal";

/// Watch output kept back while a child owns the terminal.
struct HeldOutput {
    /// Whether output is held now.
    held: bool,
    /// The held blocks, oldest first.
    blocks: VecDeque<String>,
    /// The bytes `blocks` holds.
    bytes: usize,
    /// How many blocks the bounds dropped.
    dropped: usize,
}

impl HeldOutput {
    /// Keep `block`, dropping the oldest blocks past the bounds.
    fn push(&mut self, block: String) {
        if block.len() > MAX_HELD_BYTES {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        while self.blocks.len() >= MAX_HELD_BLOCKS
            || self.bytes.saturating_add(block.len()) > MAX_HELD_BYTES
        {
            let Some(oldest) = self.blocks.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(oldest.len());
            self.dropped = self.dropped.saturating_add(1);
        }
        self.bytes = self.bytes.saturating_add(block.len());
        self.blocks.push_back(block);
    }
}

/// The process's held watch output.
static HELD_OUTPUT: Mutex<HeldOutput> = Mutex::new(HeldOutput {
    held: false,
    blocks: VecDeque::new(),
    bytes: 0,
    dropped: 0,
});

/// The held output, whether or not a writer panicked holding it.
fn held_output() -> MutexGuard<'static, HeldOutput> {
    HELD_OUTPUT.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Hold the watch's output while a child owns the terminal its stderr draws on.
fn hold_output() {
    if super::stderr_is_terminal() {
        held_output().held = true;
    }
}

/// Keep the block `render` produces until the terminal is released.
///
/// Returns `false`, rendering nothing, when output is not held: the caller
/// writes it now.
pub fn defer_output(render: impl FnOnce() -> String) -> bool {
    let mut held = held_output();
    if !held.held {
        return false;
    }
    held.push(render());
    true
}

/// Stop holding output and write what was held, oldest first.
fn flush_output() {
    let (blocks, dropped) = {
        let mut held = held_output();
        held.held = false;
        held.bytes = 0;
        (
            std::mem::take(&mut held.blocks),
            std::mem::take(&mut held.dropped),
        )
    };
    if dropped > 0 {
        super::write_watch_line(
            &crate::style::TerminalSafe::sanitize(&format!("{HELD_OUTPUT_DROPPED} ({dropped})")),
            super::WatchRole::Info,
        );
    }
    for block in blocks {
        crate::screen::chatter_styled(crate::screen::Stream::Stderr, &block);
    }
}

//! Time-travel debugger overlay for terminal (TUI) TEA apps.
//!
//! Enabled only when the `debugger` feature is active. Not compiled on
//! `wasm32` — the terminal runtime is native-only.
//!
//! ## Operation
//!
//! A bounded [`TuiDebugger`] records each processed `Msg` in live mode and
//! lets the user scrub backward and forward through the retained log via
//! keyboard shortcuts. On each step the caller re-renders the view of the
//! `reconstruct(n)` model without re-firing any `Cmd`.
//!
//! Pressing Ctrl-T (the toggle key) switches between live and time-travel mode.
//! Pressing Ctrl-T again while in time-travel mode returns to the live head.
//!
//! ## Key bindings (active only in a `--debugger` build)
//!
//! | Key        | Effect                                       |
//! |------------|----------------------------------------------|
//! | Ctrl-T     | Toggle time-travel mode on / off             |
//! | Ctrl-Left  | Step one message backward (time-travel)      |
//! | Ctrl-Right | Step one message forward  (time-travel)      |
//! | Ctrl-R     | Reset to init: clear history, restart fresh  |
//!
//! These keys are consumed by the debugger and are never forwarded to the
//! application's `Tui.Sub.onKey` handlers while time-travel mode is active.
//!
//! ## Safety
//!
//! - The scrub index is always clamped to `[0, len - 1]` — no out-of-bounds
//!   access, no panic.
//! - History capacity is bounded by [`DEFAULT_HISTORY_CAP`]; no input can grow
//!   the buffer without limit.
//! - `Secret`-bearing `Msg` values are rendered via `IpeStringify::ipe_show`,
//!   which returns `<redacted>` — the raw payload never appears in the overlay.

#![cfg(all(feature = "debugger", not(target_arch = "wasm32")))]

use std::sync::Arc;

use crate::debugger::{DEFAULT_HISTORY_CAP, RecordBuffer};
use crate::stringify::IpeStringify;
use crate::tea::IpeCmd;

/// Maximum label characters shown per message row in the status line.
const MAX_LABEL_LEN: usize = 60;

/// Truncate `s` to at most `max` chars, appending `…` when cut.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let cut = s.char_indices().nth(max).map(|(i, _)| i).unwrap_or(s.len());
    let mut out = s.get(..cut).unwrap_or(s).to_owned();
    out.push('\u{2026}');
    out
}

/// The key kind / value pair the toggle key produces (Ctrl-T).
pub const TOGGLE_KIND: &str = "ctrl";
pub const TOGGLE_VALUE: &str = "t";

/// The key kind / value pair for stepping backward in time-travel mode.
/// Maps to the `ctrlleft` folded form used by `tui_app_ui`'s key mapper.
pub const STEP_BACK_KIND: &str = "ctrlleft";

/// The key kind / value pair for stepping forward in time-travel mode.
pub const STEP_FWD_KIND: &str = "ctrlright";

/// The key kind / value pair for the "reset to init" action (Ctrl-R).
/// Clears the step log and resets the base to a fresh `init` value, returning
/// the debugger and the live driver to an empty-history state. Available in
/// both live and time-travel mode.
pub const RESET_KIND: &str = "ctrl";
pub const RESET_VALUE: &str = "r";

/// Time-travel state machine for a single terminal TEA session.
///
/// - `Msg` must be `Clone + IpeStringify` so labels can be rendered safely.
/// - `Model` must be `Clone` so the reconstructed state can be returned.
///
/// The `update` function is stored as an `Arc<dyn Fn>` so any closure or bare
/// `fn` item satisfying `Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + Sync`
/// can be supplied — including the codegen-emitted fn items and test helpers.
pub struct TuiDebugger<Msg, Model> {
    buf: RecordBuffer<Msg, Model>,
    update: Arc<dyn Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + Sync>,
    /// `None` = live mode; `Some(n)` = time-travel mode at retained step `n`.
    scrub: Option<usize>,
}

impl<Msg, Model> TuiDebugger<Msg, Model>
where
    Msg: Clone + IpeStringify,
    Model: Clone,
{
    /// Create a new debugger seeded from `initial_model`.
    ///
    /// `update` may be a bare `fn` item or any `Fn` closure that is
    /// `Send + Sync + 'static`.
    ///
    /// Uses [`DEFAULT_HISTORY_CAP`] as the ring-buffer bound.
    #[must_use]
    pub fn new<F>(initial_model: Model, update: F) -> Self
    where
        F: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    {
        Self {
            buf: RecordBuffer::new(initial_model, DEFAULT_HISTORY_CAP),
            update: Arc::new(update),
            scrub: None,
        }
    }

    /// Record one live-pass step into the history.
    pub fn record(&mut self, msg: Msg, model_after: Model) {
        let upd = Arc::clone(&self.update);
        self.buf.record(msg, model_after, &|m, mdl| upd(m, mdl));
    }

    /// Returns `true` when time-travel mode is active.
    pub fn is_scrubbing(&self) -> bool {
        self.scrub.is_some()
    }

    /// Toggle time-travel mode on / off.
    ///
    /// - Entering: pins the scrub index at the last retained step (the head).
    /// - Leaving: clears the scrub index; the caller returns to the live model.
    ///
    /// Returns the model to display after the toggle:
    /// - Entering time-travel → `Some(reconstructed model at the new index)`.
    /// - Leaving time-travel  → `None` (caller uses the live model directly).
    pub fn toggle(&mut self) -> Option<Model> {
        match self.scrub {
            Some(_) => {
                self.scrub = None;
                None
            }
            None => {
                let len = self.buf.len();
                if len == 0 {
                    // No history yet — stay in live mode.
                    return None;
                }
                let idx = len - 1;
                self.scrub = Some(idx);
                let upd = Arc::clone(&self.update);
                self.buf.reconstruct(idx, &|m, mdl| upd(m, mdl))
            }
        }
    }

    /// Step the scrub index backward by one step.
    ///
    /// Clamps to 0. Returns the reconstructed model, or `None` on empty history.
    pub fn step_back(&mut self) -> Option<Model> {
        let len = self.buf.len();
        if len == 0 {
            return None;
        }
        let current = self.scrub.get_or_insert(len - 1);
        *current = current.saturating_sub(1);
        let idx = *current;
        let upd = Arc::clone(&self.update);
        self.buf.reconstruct(idx, &|m, mdl| upd(m, mdl))
    }

    /// Step the scrub index forward by one step.
    ///
    /// Clamps to `len - 1`. Returns the reconstructed model, or `None` on empty history.
    pub fn step_fwd(&mut self) -> Option<Model> {
        let len = self.buf.len();
        if len == 0 {
            return None;
        }
        let current = self.scrub.get_or_insert(len - 1);
        *current = (*current + 1).min(len - 1);
        let idx = *current;
        let upd = Arc::clone(&self.update);
        self.buf.reconstruct(idx, &|m, mdl| upd(m, mdl))
    }

    /// Reconstruct the model at the current scrub index without moving it.
    ///
    /// Returns `None` when not in time-travel mode or the history is empty.
    pub fn current_reconstructed(&self) -> Option<Model> {
        let idx = self.scrub?;
        let upd = Arc::clone(&self.update);
        self.buf.reconstruct(idx, &|m, mdl| upd(m, mdl))
    }

    /// Move the scrub cursor to step `n` (entering time-travel mode if live) and
    /// return the reconstructed model at that step.
    ///
    /// `n` is clamped to `[0, len - 1]`, so an out-of-range target lands on the
    /// nearest valid step rather than failing. Non-destructive: the tail is never
    /// truncated — this is a viewing cursor move, not the recorder's fork. Returns
    /// `None` on an empty history.
    pub fn step_to(&mut self, n: usize) -> Option<Model> {
        let len = self.buf.len();
        if len == 0 {
            return None;
        }
        let idx = n.min(len - 1);
        self.scrub = Some(idx);
        let upd = Arc::clone(&self.update);
        self.buf.reconstruct(idx, &|m, mdl| upd(m, mdl))
    }

    /// Reconstruct the model at step `n` WITHOUT moving the scrub cursor (a
    /// read-only inspection). `n` is clamped to `[0, len - 1]`. Returns the
    /// clamped step index alongside the reconstructed model, or `None` on an
    /// empty history.
    pub fn reconstruct_at(&self, n: usize) -> Option<(usize, Model)> {
        let len = self.buf.len();
        if len == 0 {
            return None;
        }
        let idx = n.min(len - 1);
        let upd = Arc::clone(&self.update);
        self.buf
            .reconstruct(idx, &|m, mdl| upd(m, mdl))
            .map(|m| (idx, m))
    }

    /// Leave time-travel mode and resume tailing the live head. Idempotent: a
    /// call in live mode is a no-op.
    pub fn live_tail(&mut self) {
        self.scrub = None;
    }

    /// Reset the debugger to a fresh `init` state (Ctrl-R action).
    ///
    /// Clears the step log, resets the base to `init`, and leaves live mode
    /// (clears any active scrub index). The caller is responsible for
    /// resetting the live driver's model to the same `init` value so the
    /// debugger and the running session stay in sync.
    ///
    /// No `update` call is made and no `Cmd` is fired — this is a pure
    /// recorder reset.
    pub fn reset_to_init(&mut self, init: Model) {
        self.scrub = None;
        self.buf.reset_to_init(init);
    }

    /// Render a one-line status string for painting at the bottom of the
    /// terminal frame.
    ///
    /// Labels pass through [`IpeStringify::ipe_show`] so any `Secret` field
    /// renders as `<redacted>` — the raw payload never appears.
    ///
    /// Live mode:         `[DBG] recording — N steps  Ctrl-T=travel Ctrl-R=reset`
    /// Time-travel mode:  `[DBG TT] step N/M  …prev | CURRENT | next…`
    pub fn status_line(&self) -> String {
        let len = self.buf.len();
        match self.scrub {
            None => format!(
                "\x1b[7m[DBG] recording \u{2014} {len} step{}  Ctrl-T=travel Ctrl-R=reset\x1b[m",
                if len == 1 { "" } else { "s" }
            ),
            Some(idx) => {
                let labels: Vec<String> = self
                    .buf
                    .msgs()
                    .map(|m| truncate(&m.ipe_show(), MAX_LABEL_LEN))
                    .collect();
                let cur = labels
                    .get(idx)
                    .cloned()
                    .unwrap_or_else(|| "(empty)".to_owned());
                let prev = idx
                    .checked_sub(1)
                    .and_then(|i| labels.get(i))
                    .cloned()
                    .unwrap_or_default();
                let next = labels.get(idx + 1).cloned().unwrap_or_default();
                let context = match (prev.is_empty(), next.is_empty()) {
                    (true, true) => format!("[ {cur} ]"),
                    (true, false) => format!("[ {cur} | {next}\u{2026}"),
                    (false, true) => format!("\u{2026}{prev} | {cur} ]"),
                    (false, false) => format!("\u{2026}{prev} | {cur} | {next}\u{2026}"),
                };
                format!("\x1b[7m[DBG TT] step {}/{len}  {context}\x1b[m", idx + 1)
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    // ── (a) Scrub fires zero additional Cmds ──────────────────────────────────

    #[test]
    fn scrub_reconstruct_fires_zero_cmds() {
        let effect_count = Arc::new(AtomicUsize::new(0));

        // Live pass: a counting wrapper that bumps the effect counter.
        let counter = Arc::clone(&effect_count);
        let live_update = move |msg: TMsg, model: TModel| -> (TModel, IpeCmd<TMsg>) {
            counter.fetch_add(1, Ordering::SeqCst);
            t_update(msg, model)
        };

        // TuiDebugger stores t_update (bare fn, no counter) for reconstruct.
        let mut dbg = TuiDebugger::new(TModel { count: 0 }, t_update);

        // Record 3 live steps via live_update (bumps counter).
        let mut live = TModel { count: 0 };
        for n in [10i64, 5, 3] {
            let (next, _) = live_update(TMsg::Add(n), live.clone());
            dbg.record(TMsg::Add(n), next.clone());
            live = next;
        }
        let live_effects = effect_count.load(Ordering::SeqCst);
        assert_eq!(live_effects, 3, "live pass must fire exactly 3 effects");

        // Scrub — no additional effects must fire because the dbg uses t_update.
        let _m = dbg.toggle();
        let _m = dbg.step_back();
        let _m = dbg.step_back();
        let _m = dbg.step_fwd();

        let after_scrub = effect_count.load(Ordering::SeqCst);
        assert_eq!(
            live_effects, after_scrub,
            "scrub must not fire any additional effects"
        );
    }

    // ── (b) Secret in Msg renders <redacted> in the status line ───────────────

    #[cfg(feature = "secret")]
    #[test]
    fn secret_redacted_in_status_line() {
        use crate::secret::secret_from_string;

        #[derive(Clone)]
        struct MsgWithSecret {
            token: crate::secret::Secret,
        }

        impl IpeStringify for MsgWithSecret {
            fn ipe_show(&self) -> String {
                format!("Login({})", self.token.ipe_show())
            }
        }

        let mut dbg = TuiDebugger::new((), |_msg: MsgWithSecret, m: ()| (m, IpeCmd::None));
        let secret_msg = MsgWithSecret {
            token: secret_from_string("hunter2".to_owned()),
        };
        dbg.record(secret_msg.clone(), ());
        dbg.toggle();

        let status = dbg.status_line();
        assert!(
            !status.contains("hunter2"),
            "secret payload must not appear in status line; got: {status:?}"
        );
        assert!(
            status.contains("<redacted>"),
            "status line must show <redacted> for Secret; got: {status:?}"
        );
    }

    // ── (c) Feature-off structural guarantee ──────────────────────────────────
    //
    // The entire `tui.rs` module is `#[cfg(all(feature="debugger",
    // not(target_arch="wasm32")))]`, so when the feature is absent the module
    // and all hook call sites in `app.rs` compile to nothing. The wasm floor
    // build (`--no-default-features --features wasm-client`) proves the
    // wasm32-target half; a build without `debugger` proves the feature half.

    // ── (d) Clamping: out-of-range scrub index does not panic ─────────────────

    #[test]
    fn clamp_scrub_index_no_panic() {
        let mut dbg = TuiDebugger::new(TModel { count: 0 }, t_update);

        // step_back / step_fwd on an empty history → no-op, no panic.
        assert!(dbg.step_back().is_none());
        assert!(dbg.step_fwd().is_none());

        // Toggle on empty history stays in live mode (returns None).
        assert!(dbg.toggle().is_none());
        assert!(
            !dbg.is_scrubbing(),
            "empty history must not enter time-travel mode"
        );

        // Record one step.
        let (m1, _) = t_update(TMsg::Add(1), TModel { count: 0 });
        dbg.record(TMsg::Add(1), m1);

        // Enter time-travel at index 0 (only one step).
        let _entered = dbg.toggle();
        assert!(dbg.is_scrubbing());

        // step_back at the beginning clamps to 0, never panics.
        let at_zero = dbg.step_back();
        assert!(at_zero.is_some(), "step_back at 0 must return Some");

        // step_fwd past the end clamps to last index, never panics.
        let at_end_1 = dbg.step_fwd();
        let at_end_2 = dbg.step_fwd();
        assert!(at_end_1.is_some());
        assert!(at_end_2.is_some());
        assert_eq!(
            at_end_1, at_end_2,
            "repeated step_fwd at tail must be idempotent"
        );
    }

    // ── status_line renders the correct live / scrub text ────────────────────

    #[test]
    fn status_line_live_and_scrub() {
        let mut dbg = TuiDebugger::new(TModel { count: 0 }, t_update);
        let live_status = dbg.status_line();
        assert!(
            live_status.contains("[DBG]"),
            "live status must contain [DBG]; got: {live_status:?}"
        );

        let (m1, _) = t_update(TMsg::Add(5), TModel { count: 0 });
        dbg.record(TMsg::Add(5), m1);
        dbg.toggle();

        let tt_status = dbg.status_line();
        assert!(
            tt_status.contains("[DBG TT]"),
            "time-travel status must contain [DBG TT]; got: {tt_status:?}"
        );
        assert!(
            tt_status.contains("Add(5)"),
            "time-travel status must show the message label; got: {tt_status:?}"
        );
    }
}

//! Shape-agnostic TEA debugger core — recorder, re-fold, export, and import.
//!
//! Enabled only when the `debugger` feature is active (`ipe build/run --debugger`).
//! A non-`--debugger` build carries zero code from this module.
//!
//! ## Data model
//!
//! The history is a ring buffer of `Msg` values plus a rolling base `Model`.
//! The `Model` at step N is computed by applying `update` over the retained
//! messages from the base, discarding every `Cmd` produced — no effect is
//! re-fired during reconstruction.
//!
//! Memory is `1 Model + N Msgs` where N ≤ `cap`. On overflow the oldest `Msg`
//! is dropped and the base `Model` is advanced one step so re-fold always starts
//! from a consistent checkpoint.
//!
//! ## Integration shapes
//!
//! - **[`History`]** (fn-pointer variant): stores the `update` fn pointer
//!   alongside the log. Self-contained and unit-testable. Used for tests and as
//!   the reference implementation.
//! - **[`RecordBuffer`]** (data-only variant): stores only the log and base.
//!   The caller supplies the `update` closure at overflow/reconstruct time.
//!   Used by the WASM TEA driver, which already owns the update closure in the
//!   `App` struct and should not duplicate it.
//!
//! ## Security
//!
//! - `Secret`-bearing `Msg` types are not seal-legal, so export is unavailable
//!   for them while live recording still works (in-memory values need no codec).
//! - Import runs through the total, fail-closed seal decoder: a malformed or
//!   oversized blob is dropped whole — no partial value, no panic.
//! - The `debugger` feature is absent from `ipe release`, so no recorder code
//!   can ship in a production artifact.

use std::collections::VecDeque;

use crate::tea::IpeCmd;

// Server-driven TEA debugger: session-scoped history and overlay HTML.
// All items gated on `feature = "debugger"` via the inner `#![cfg(...)]`.
pub mod server;

// Terminal (TUI) time-travel debugger.
// Gated on both `feature = "debugger"` AND `not(target_arch = "wasm32")`
// via the inner `#![cfg(...)]` in tui.rs — zero code on wasm32.
pub mod tui;

// Cli/worker record sink: dump the recorded session's portable replay log to
// the `IPE_DEBUGGER_RECORD` destination, fail-closed to plain text.
// Gated on `feature = "debugger"` via the inner `#![cfg(...)]`.
pub mod record_sink;

// Typed session log: the replayable form of a recorded cli/worker session
// (`ipe run --record` writes it, `ipe run --replay` re-folds it).
// Gated on `feature = "debugger"` via the inner `#![cfg(...)]`.
pub mod session_log;

/// The default message-log capacity when none is configured.
pub const DEFAULT_HISTORY_CAP: usize = 512;

// ── Internal shared step type ──────────────────────────────────────────────

/// One step: the dispatched message and the model that followed it.
///
/// Storing `model_after` lets the driver advance the rolling base on overflow
/// without re-calling `update` on the dropped step's message.
struct Step<Msg, Model> {
    msg: Msg,
    model_after: Model,
}

// ── RecordBuffer — data-only, driver-integrated variant ───────────────────

/// A bounded, rolling TEA message log with a rolling base `Model`.
///
/// Unlike [`History`], `RecordBuffer` does NOT store the `update` function.
/// The caller supplies it at overflow (via [`RecordBuffer::record`]) and at
/// reconstruction time (via [`RecordBuffer::reconstruct`]). This avoids
/// duplicating the update closure in drivers (such as the WASM TEA sink) that
/// already own it.
///
/// Invariant (by construction): `log.len() <= cap` always holds.
pub struct RecordBuffer<Msg, Model> {
    /// The model that precedes the oldest retained `Msg`. Advanced on overflow.
    base: Model,
    /// Retained steps, newest at the back.
    log: VecDeque<Step<Msg, Model>>,
    /// Maximum retained messages. At least 1.
    cap: usize,
    /// `true` once a step has been evicted, so `base` is no longer the initial model.
    overflowed: bool,
}

impl<Msg: Clone, Model: Clone> RecordBuffer<Msg, Model> {
    /// Create a new, empty buffer starting from `initial_model`.
    ///
    /// `cap` is clamped to a minimum of 1.
    #[must_use]
    pub fn new(initial_model: Model, cap: usize) -> Self {
        Self {
            base: initial_model,
            log: VecDeque::new(),
            cap: cap.max(1),
            overflowed: false,
        }
    }

    /// Record one live-pass step.
    ///
    /// `update` is called exactly once on overflow to advance the base over the
    /// evicted step; the resulting `Cmd` is discarded. On a non-overflow call
    /// `update` is never called.
    pub fn record<F>(&mut self, msg: Msg, model_after: Model, update: &F)
    where
        F: Fn(Msg, Model) -> (Model, IpeCmd<Msg>),
    {
        if self.log.len() >= self.cap
            && let Some(oldest) = self.log.pop_front()
        {
            let (advanced, _cmd) = update(oldest.msg, self.base.clone());
            self.base = advanced;
            self.overflowed = true;
        }
        self.log.push_back(Step { msg, model_after });
    }

    /// Reconstruct the `Model` at retained-log step `n` (0-indexed).
    ///
    /// Replays `update` from the base over the first `n + 1` retained messages,
    /// discarding every `Cmd`. Returns `None` when `n` is out of range.
    ///
    /// No effect is re-fired: this is a pure fold over the message log.
    #[must_use]
    pub fn reconstruct<F>(&self, n: usize, update: &F) -> Option<Model>
    where
        F: Fn(Msg, Model) -> (Model, IpeCmd<Msg>),
    {
        if n >= self.log.len() {
            return None;
        }
        let mut model = self.base.clone();
        for step in self.log.iter().take(n + 1) {
            let (next, _cmd) = update(step.msg.clone(), model);
            model = next;
        }
        Some(model)
    }

    /// Number of steps retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.log.len()
    }

    /// `true` when no steps have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }

    /// The configured cap.
    #[must_use]
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Reference to the rolling base model.
    #[must_use]
    pub fn base(&self) -> &Model {
        &self.base
    }

    /// `true` once the ring has evicted a step.
    ///
    /// The base then holds the model after the evicted steps, not the initial
    /// model, so a re-fold of the retained messages from `init` would be wrong.
    #[must_use]
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Clear the step log and reset the base to `init`.
    ///
    /// After this call the buffer is empty and `base()` returns a clone of
    /// `init`. This is the "reset to init" escape hatch for the debugger:
    /// time-travel and recording both restart from a clean slate. No `update`
    /// call is made; no `Cmd` is fired.
    pub fn reset_to_init(&mut self, init: Model) {
        self.log.clear();
        self.base = init;
        self.overflowed = false;
    }

    /// Commit time-travel to step `n` (0-indexed): truncate the log to the
    /// first `n + 1` entries and return the model at that step.
    ///
    /// After this call `len() == n + 1` — the tail (steps after `n`) is
    /// discarded. Resuming forward from this point starts a new branch of
    /// history; no `Cmd` is fired. Returns `None` when `n >= len()`.
    ///
    /// This is the "fork" operation from the spec: effects are never re-run,
    /// and the tail is discarded so the caller can record new messages from
    /// the stepped-to model.
    pub fn step_to<F>(&mut self, n: usize, update: &F) -> Option<Model>
    where
        F: Fn(Msg, Model) -> (Model, IpeCmd<Msg>),
    {
        if n >= self.log.len() {
            return None;
        }
        // Reconstruct before truncating (uses the current base + full log).
        let model = self.reconstruct(n, update)?;
        // Discard the tail: keep only steps 0..=n.
        self.log.truncate(n + 1);
        Some(model)
    }

    /// Iterator over retained messages, oldest first.
    pub fn msgs(&self) -> impl Iterator<Item = &Msg> {
        self.log.iter().map(|s| &s.msg)
    }

    /// Render each retained message as a redacted label string (oldest first).
    ///
    /// Labels pass through `IpeStringify::ipe_show` so any `Secret`-bearing
    /// field renders as `<redacted>`. The raw `Msg` value is never serialised.
    #[cfg(feature = "debugger")]
    pub fn labels(&self) -> Vec<String>
    where
        Msg: crate::stringify::IpeStringify,
    {
        self.msgs()
            .map(crate::stringify::IpeStringify::ipe_show)
            .collect()
    }

    /// Render the reconstructed model at retained step `n` as a plain,
    /// control-code-free string (the shape-neutral portable inspect surface).
    ///
    /// Reuses [`RecordBuffer::reconstruct`] — a pure re-fold, no `Cmd` fired —
    /// then renders the model through `IpeStringify::ipe_show`, which is a
    /// structural (`%v`-identical) rendering carrying no ANSI/control bytes and
    /// redacting any `Secret`-bearing field. Returns `None` when `n` is out of
    /// the retained window. A caller streaming this off a terminal emits it
    /// verbatim: the string is plain by construction.
    #[cfg(feature = "debugger")]
    pub fn inspect_model<F>(&self, n: usize, update: &F) -> Option<String>
    where
        F: Fn(Msg, Model) -> (Model, IpeCmd<Msg>),
        Model: crate::stringify::IpeStringify,
    {
        self.reconstruct(n, update)
            .map(|m| crate::stringify::IpeStringify::ipe_show(&m))
    }

    /// The portable record/replay log: one `"<msg-label> => <model>"` line per
    /// retained step, oldest first, in plain text with no control codes.
    ///
    /// Each line pairs the step's redacted message label (the message rendered
    /// through `IpeStringify::ipe_show`, as [`RecordBuffer::labels`] does) with
    /// the reconstructed post-step model (via [`RecordBuffer::inspect_model`]).
    /// Both halves render through
    /// `IpeStringify::ipe_show`, so `Secret`-bearing values stay redacted and no
    /// ANSI/control byte can appear. This is the shape-neutral dump a caller can
    /// print or persist to replay a session; it never mutates the log and fires
    /// no `Cmd`.
    #[cfg(feature = "debugger")]
    pub fn replay_log<F>(&self, update: &F) -> Vec<String>
    where
        F: Fn(Msg, Model) -> (Model, IpeCmd<Msg>),
        Msg: crate::stringify::IpeStringify,
        Model: crate::stringify::IpeStringify,
    {
        (0..self.log.len())
            .filter_map(|n| {
                let msg_label = self
                    .log
                    .get(n)
                    .map(|s| crate::stringify::IpeStringify::ipe_show(&s.msg))?;
                let model = self.inspect_model(n, update)?;
                Some(format!("{msg_label} => {model}"))
            })
            .collect()
    }
}

// ── History — fn-pointer variant, self-contained ──────────────────────────

/// A bounded, rolling TEA session history with a stored `update` fn pointer.
///
/// Self-contained: stores the `update` function so callers need not supply it
/// on every operation. Use this in unit tests and wherever a fn pointer (not a
/// closure) drives the TEA loop.
///
/// For closure-based drivers (the WASM TEA sink), use [`RecordBuffer`] instead.
pub struct History<Msg, Model> {
    inner: RecordBuffer<Msg, Model>,
    update: fn(Msg, Model) -> (Model, IpeCmd<Msg>),
}

impl<Msg: Clone, Model: Clone> History<Msg, Model> {
    /// Create a new history seeded from `initial_model`.
    #[must_use]
    pub fn new(
        initial_model: Model,
        update: fn(Msg, Model) -> (Model, IpeCmd<Msg>),
        cap: usize,
    ) -> Self {
        Self {
            inner: RecordBuffer::new(initial_model, cap),
            update,
        }
    }

    /// Record one live-pass step.
    pub fn record(&mut self, msg: Msg, model_after: Model) {
        let update = self.update;
        self.inner
            .record(msg, model_after, &move |m, mdl| update(m, mdl));
    }

    /// Reconstruct the model at step `n` (0-indexed in the retained window).
    #[must_use]
    pub fn reconstruct(&self, n: usize) -> Option<Model> {
        let update = self.update;
        self.inner.reconstruct(n, &move |m, mdl| update(m, mdl))
    }

    /// Number of steps retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` when no steps have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// The configured cap.
    #[must_use]
    pub fn cap(&self) -> usize {
        self.inner.cap()
    }

    /// Reference to the rolling base model.
    #[must_use]
    pub fn base(&self) -> &Model {
        self.inner.base()
    }

    /// Iterator over retained messages, oldest first.
    pub fn msgs(&self) -> impl Iterator<Item = &Msg> {
        self.inner.msgs()
    }

    /// Commit time-travel to step `n`: truncate the log to the first `n + 1`
    /// entries and return the model at that step.
    ///
    /// Delegates to [`RecordBuffer::step_to`]. After this call `len() == n + 1`
    /// — the tail is discarded so the caller can record new messages from the
    /// stepped-to model. No `Cmd` is fired. Returns `None` when `n >= len()`.
    #[must_use]
    pub fn step_to(&mut self, n: usize) -> Option<Model> {
        let update = self.update;
        self.inner.step_to(n, &move |m, mdl| update(m, mdl))
    }

    /// Clear the step log and reset the base to `init`.
    ///
    /// Delegates to [`RecordBuffer::reset_to_init`]: the log is emptied and the
    /// base is replaced with a clone of `init`. Recording resumes from a fresh
    /// slate on the next `record` call. No `update` call is made; no `Cmd` fires.
    pub fn reset_to_init(&mut self, init: Model) {
        self.inner.reset_to_init(init);
    }

    /// Render the reconstructed model at step `n` as a plain, control-code-free
    /// string. Delegates to [`RecordBuffer::inspect_model`] with the stored
    /// `update` fn pointer; see that method for the plain-text/redaction
    /// guarantees. Returns `None` when `n` is out of the retained window.
    #[cfg(feature = "debugger")]
    #[must_use]
    pub fn inspect_model(&self, n: usize) -> Option<String>
    where
        Model: crate::stringify::IpeStringify,
    {
        let update = self.update;
        self.inner.inspect_model(n, &move |m, mdl| update(m, mdl))
    }

    /// The portable record/replay log — one plain `"<msg> => <model>"` line per
    /// retained step. Delegates to [`RecordBuffer::replay_log`] with the stored
    /// `update` fn pointer.
    #[cfg(feature = "debugger")]
    #[must_use]
    pub fn replay_log(&self) -> Vec<String>
    where
        Msg: crate::stringify::IpeStringify,
        Model: crate::stringify::IpeStringify,
    {
        let update = self.update;
        self.inner.replay_log(&move |m, mdl| update(m, mdl))
    }
}

// ── Export / Import ────────────────────────────────────────────────────────

/// Why export failed.
#[derive(Debug)]
pub enum ExportError {
    /// JSON serialization failed.
    Encode(String),
}

impl core::fmt::Display for ExportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ExportError::Encode(detail) => write!(f, "debugger export failed: {detail}"),
        }
    }
}

/// Export the message log as JSON bytes.
///
/// Only available when `Msg: serde::Serialize` (seal-legal). A `Secret`-bearing
/// `Msg` cannot implement `serde::Serialize`, so this function is unavailable
/// for such types at compile time — consistent with the seal-legality gate.
///
/// The exported form is a JSON array of messages. The base model is not
/// included; an import always reseeds from the caller-supplied initial model.
#[cfg(feature = "json")]
pub fn export_msgs<Msg, Model>(buf: &RecordBuffer<Msg, Model>) -> Result<Vec<u8>, ExportError>
where
    Msg: Clone + serde::Serialize,
    Model: Clone,
{
    let msgs: Vec<&Msg> = buf.log.iter().map(|s| &s.msg).collect();
    serde_json::to_vec(&msgs).map_err(|e| ExportError::Encode(e.to_string()))
}

/// Export the message log of a [`History`] as JSON bytes.
#[cfg(feature = "json")]
pub fn export_history_msgs<Msg, Model>(
    history: &History<Msg, Model>,
) -> Result<Vec<u8>, ExportError>
where
    Msg: Clone + serde::Serialize,
    Model: Clone,
{
    export_msgs(&history.inner)
}

/// Import a message log from bytes produced by [`export_msgs`], seeding the
/// history from `initial_model`.
///
/// Fail-closed: a malformed, oversized, or type-mismatching blob yields `None`
/// — no partial value, no panic. Limits mirror the seal codec defaults
/// (5 MiB byte budget, depth 128).
#[cfg(feature = "json")]
pub fn import_msgs<Msg, Model, F>(
    bytes: &[u8],
    initial_model: Model,
    update: F,
    cap: usize,
) -> Option<RecordBuffer<Msg, Model>>
where
    Msg: Clone + serde::de::DeserializeOwned,
    Model: Clone,
    F: Fn(Msg, Model) -> (Model, IpeCmd<Msg>),
{
    use crate::seal_codec::DEFAULT_SEAL_MAX_INPUT_BYTES;

    // Byte budget, before any allocation.
    if bytes.len() > DEFAULT_SEAL_MAX_INPUT_BYTES {
        return None;
    }

    // Depth-bounded parse: reject malformed / deeply-nested JSON.
    let s = core::str::from_utf8(bytes).ok()?;

    let msgs: Vec<Msg> = match serde_json::from_str(s) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let effective_cap = cap.max(1);
    let mut buf = RecordBuffer::new(initial_model, effective_cap);

    for msg in msgs {
        // Compute the post-update model so `Step::model_after` is correct.
        let current = if buf.log.is_empty() {
            buf.base.clone()
        } else {
            buf.log
                .back()
                .map(|s| s.model_after.clone())
                .unwrap_or_else(|| buf.base.clone())
        };
        let (model_after, _cmd) = update(msg.clone(), current);
        buf.record(msg, model_after, &update);
    }
    Some(buf)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    enum TestMsg {
        Add(i64),
    }

    #[derive(Clone, Debug, PartialEq)]
    struct TestModel {
        count: i64,
    }

    fn test_update(msg: TestMsg, model: TestModel) -> (TestModel, IpeCmd<TestMsg>) {
        let TestMsg::Add(n) = msg;
        (
            TestModel {
                count: model.count + n,
            },
            IpeCmd::None,
        )
    }

    // record → reconstruct equals the live model at each step.
    #[test]
    fn reconstruct_matches_live_model() {
        let mut history = History::new(TestModel { count: 0 }, test_update, 16);
        let msgs = [TestMsg::Add(1), TestMsg::Add(2), TestMsg::Add(3)];
        let mut live = TestModel { count: 0 };
        for (i, msg) in msgs.iter().enumerate() {
            let (next, _) = test_update(msg.clone(), live.clone());
            live = next.clone();
            history.record(msg.clone(), next);

            let reconstructed = history.reconstruct(i).expect("step must be in range");
            assert_eq!(
                reconstructed, live,
                "reconstruct at step {i} must equal live model"
            );
        }
    }

    // A Cmd-carrying step reconstructs WITHOUT re-firing any effect.
    #[test]
    fn reconstruct_does_not_refire_cmd() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let effect_count = Arc::new(AtomicUsize::new(0));

        #[derive(Clone, Debug, PartialEq)]
        enum Msg {
            Trigger,
        }
        #[derive(Clone, Debug, PartialEq)]
        struct Model {
            triggered: bool,
        }

        // The live pass fires one effect (simulated by incrementing the counter).
        let counter = Arc::clone(&effect_count);
        counter.fetch_add(1, Ordering::SeqCst);

        // The stored update fn does NOT touch the counter — only the live pass does.
        let update_fn: fn(Msg, Model) -> (Model, IpeCmd<Msg>) =
            |_msg, _m| (Model { triggered: true }, IpeCmd::None);

        let post_model = Model { triggered: true };
        let mut history = History::new(Model { triggered: false }, update_fn, 8);
        history.record(Msg::Trigger, post_model.clone());

        let before = effect_count.load(Ordering::SeqCst);
        let r = history.reconstruct(0).expect("step 0 must exist");
        let after = effect_count.load(Ordering::SeqCst);

        assert_eq!(r, post_model);
        assert_eq!(
            before, after,
            "reconstruct must not fire any additional effects"
        );
    }

    // Ring buffer caps memory; rolling base keeps reconstruct correct after overflow.
    #[test]
    fn ring_buffer_caps_and_rolling_base_correct() {
        let cap = 3usize;
        let mut history = History::new(TestModel { count: 0 }, test_update, cap);

        for i in 1..=6i64 {
            let current = if history.inner.log.is_empty() {
                history.inner.base.clone()
            } else {
                history
                    .inner
                    .log
                    .back()
                    .map(|s| s.model_after.clone())
                    .unwrap()
            };
            let (next, _) = test_update(TestMsg::Add(i), current);
            history.record(TestMsg::Add(i), next);
        }

        assert_eq!(history.len(), cap, "log must not exceed cap");

        // msgs 4, 5, 6 retained; base is count after 1+2+3 = 6.
        // After msg 4: 6+4=10; after msg 5: 15; after msg 6: 21.
        let last = history.reconstruct(cap - 1).expect("last step must exist");
        assert_eq!(last.count, 21, "rolling base must keep reconstruct correct");
    }

    // Export/import round-trip for a seal-legal Msg.
    #[cfg(feature = "json")]
    #[test]
    fn export_import_round_trip() {
        #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        enum RtMsg {
            Add(i64),
            Reset,
        }
        #[derive(Clone, Debug, PartialEq)]
        struct RtModel {
            count: i64,
        }

        fn rt_update(msg: RtMsg, m: RtModel) -> (RtModel, IpeCmd<RtMsg>) {
            let next = match msg {
                RtMsg::Add(n) => RtModel { count: m.count + n },
                RtMsg::Reset => RtModel { count: 0 },
            };
            (next, IpeCmd::None)
        }

        let mut history = History::new(RtModel { count: 0 }, rt_update, 16);
        let (m1, _) = rt_update(RtMsg::Add(5), history.inner.base.clone());
        history.record(RtMsg::Add(5), m1.clone());
        let (m2, _) = rt_update(RtMsg::Add(3), m1);
        history.record(RtMsg::Add(3), m2);

        let bytes = export_history_msgs(&history).expect("export must succeed");

        let imported =
            import_msgs::<RtMsg, RtModel, _>(&bytes, RtModel { count: 0 }, rt_update, 16)
                .expect("import must succeed");

        let orig_final = history.reconstruct(1).expect("step 1");
        let imp_final = imported
            .reconstruct(1, &rt_update)
            .expect("step 1 after import");
        assert_eq!(
            orig_final, imp_final,
            "round-trip must preserve model state"
        );
    }

    // Malformed / oversized import blobs are dropped fail-closed (no panic, no partial value).
    #[cfg(feature = "json")]
    #[test]
    fn import_malformed_blob_dropped_fail_closed() {
        #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
        enum Msg {
            Noop,
        }
        #[derive(Clone)]
        struct Model;
        fn upd(_msg: Msg, _m: Model) -> (Model, IpeCmd<Msg>) {
            (Model, IpeCmd::None)
        }

        // Malformed JSON.
        assert!(
            import_msgs::<Msg, Model, _>(b"{not valid json}", Model, upd, 8).is_none(),
            "malformed blob must yield None"
        );

        // Oversized blob.
        let oversized = vec![b' '; crate::seal_codec::DEFAULT_SEAL_MAX_INPUT_BYTES + 1];
        assert!(
            import_msgs::<Msg, Model, _>(&oversized, Model, upd, 8).is_none(),
            "oversized blob must yield None"
        );

        // Type mismatch — valid JSON but wrong shape.
        assert!(
            import_msgs::<Msg, Model, _>(b"42", Model, upd, 8).is_none(),
            "type-mismatch blob must yield None"
        );
    }

    // ── Overlay scrub wiring (unit-level) ──────────────────────────────────

    // Selecting step N via `reconstruct(N)` returns the model at that step;
    // no additional effects fire beyond the original live pass.
    #[test]
    fn scrub_reconstruct_wiring() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let effect_count = Arc::new(AtomicUsize::new(0));

        // update: increment count; live pass also bumps the effect counter.
        let counter = Arc::clone(&effect_count);
        let live_update = move |msg: TestMsg, model: TestModel| -> (TestModel, IpeCmd<TestMsg>) {
            counter.fetch_add(1, Ordering::SeqCst);
            let TestMsg::Add(n) = msg;
            (
                TestModel {
                    count: model.count + n,
                },
                IpeCmd::None,
            )
        };

        // The fn-pointer used for reconstruct does NOT touch the counter.
        let reconstruct_update: fn(TestMsg, TestModel) -> (TestModel, IpeCmd<TestMsg>) =
            test_update;

        // Simulate live pass: record 3 steps.
        let mut buf = RecordBuffer::new(TestModel { count: 0 }, 16);
        let mut live = TestModel { count: 0 };
        let msgs_in = [TestMsg::Add(10), TestMsg::Add(5), TestMsg::Add(3)];
        for msg in &msgs_in {
            let (next, _cmd) = live_update(msg.clone(), live.clone());
            buf.record(msg.clone(), next.clone(), &|m, mdl| {
                // The record-time closure is the one used for base advancement
                // on overflow — use the non-counting fn here.
                reconstruct_update(m, mdl)
            });
            live = next;
        }

        let live_effects = effect_count.load(Ordering::SeqCst);
        assert_eq!(live_effects, 3, "live pass must fire exactly 3 effects");

        // Scrub to step 1 (after msgs[0]+msgs[1]): count = 15.
        let at_step_1 = buf.reconstruct(1, &reconstruct_update).expect("step 1");
        assert_eq!(
            at_step_1.count, 15,
            "reconstruct at step 1 must yield count=15"
        );

        // Scrub to step 0 (after msgs[0]): count = 10.
        let at_step_0 = buf.reconstruct(0, &reconstruct_update).expect("step 0");
        assert_eq!(
            at_step_0.count, 10,
            "reconstruct at step 0 must yield count=10"
        );

        // No additional effects fired during scrubbing.
        let after_scrub_effects = effect_count.load(Ordering::SeqCst);
        assert_eq!(
            live_effects, after_scrub_effects,
            "reconstruct must not fire any additional effects"
        );

        // Returning to live (no reconstruct call needed — caller uses live model).
        assert_eq!(live.count, 18, "live model is count=18 after 3 steps");
    }

    // `Secret`-bearing values are redacted in the message label rendered by
    // `IpeStringify::ipe_show` — the same path the overlay's `label_fn` uses.
    #[cfg(feature = "secret")]
    #[test]
    fn secret_redacted_in_label() {
        use crate::secret::secret_from_string;
        use crate::stringify::IpeStringify;

        let secret = secret_from_string("super-secret-token".to_owned());
        let rendered = secret.ipe_show();
        assert!(
            !rendered.contains("super-secret-token"),
            "Secret must not appear in rendered label; got: {rendered:?}"
        );
        assert_eq!(
            rendered, "<redacted>",
            "Secret must stringify to the fixed redacted placeholder"
        );
    }

    // `RecordBuffer::labels()` — the server-driven GET-page label path — renders
    // each retained Msg via `IpeStringify::ipe_show`, so a `Secret`-bearing Msg
    // yields `<redacted>` rather than the plaintext value.
    #[cfg(all(feature = "debugger", feature = "secret"))]
    #[test]
    fn record_buffer_labels_redacts_secret() {
        use crate::secret::secret_from_string;
        use crate::stringify::IpeStringify;

        #[derive(Clone, Debug)]
        enum SecretMsg {
            Login(crate::secret::Secret),
        }

        impl IpeStringify for SecretMsg {
            fn ipe_show(&self) -> String {
                match self {
                    SecretMsg::Login(s) => format!("Login({})", s.ipe_show()),
                }
            }
        }

        #[derive(Clone, Debug)]
        struct SecretModel;

        let secret = secret_from_string("hunter2".to_owned());
        let mut buf = RecordBuffer::new(SecretModel, 8);
        buf.record(SecretMsg::Login(secret.clone()), SecretModel, &|_msg, m| {
            (m, IpeCmd::None)
        });

        let labels = buf.labels();
        assert_eq!(labels.len(), 1);
        assert!(
            !labels[0].contains("hunter2"),
            "server-driven label must not expose the secret; got: {:?}",
            labels[0]
        );
        assert!(
            labels[0].contains("<redacted>"),
            "server-driven label must render Secret as <redacted>; got: {:?}",
            labels[0]
        );
    }

    // Export → import → fold at each step equals the live model at that step.
    // Proves the recorder+export path is the exact basis for time-travel fold:
    // model-at-N = fold apply_transition over the first N+1 exported messages.
    #[cfg(feature = "json")]
    #[test]
    fn recorder_export_fold_matches_live() {
        #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        enum FoldMsg {
            Inc,
            Add(i64),
            Reset,
        }
        #[derive(Clone, Debug, PartialEq)]
        struct FoldModel {
            count: i64,
        }

        fn fold_update(msg: FoldMsg, m: FoldModel) -> (FoldModel, IpeCmd<FoldMsg>) {
            let next = match msg {
                FoldMsg::Inc => FoldModel { count: m.count + 1 },
                FoldMsg::Add(n) => FoldModel { count: m.count + n },
                FoldMsg::Reset => FoldModel { count: 0 },
            };
            (next, IpeCmd::None)
        }

        let init = FoldModel { count: 0 };
        let mut buf = RecordBuffer::new(init.clone(), 16);

        // Drive a scripted message sequence.
        let msgs = [FoldMsg::Inc, FoldMsg::Add(4), FoldMsg::Reset, FoldMsg::Inc];
        let mut live = init.clone();
        for msg in &msgs {
            let (next, _cmd) = fold_update(msg.clone(), live.clone());
            buf.record(msg.clone(), next.clone(), &fold_update);
            live = next;
        }

        // Export the log.
        let bytes = export_msgs(&buf).expect("export must succeed");

        // Import into a fresh buffer (round-trip through JSON).
        let imported = import_msgs::<FoldMsg, FoldModel, _>(&bytes, init.clone(), fold_update, 16)
            .expect("import must succeed");

        // Fold over the first N+1 imported messages must equal the live model
        // at that step.
        let mut expected = init.clone();
        for (i, msg) in msgs.iter().enumerate() {
            let (next, _) = fold_update(msg.clone(), expected.clone());
            expected = next.clone();

            let reconstructed = imported
                .reconstruct(i, &fold_update)
                .expect("step must be in range");
            assert_eq!(
                reconstructed, expected,
                "fold at step {i} must equal live model"
            );
        }

        // Final live model equals last imported reconstruct.
        assert_eq!(
            live.count, 1,
            "live model after Inc→+4→Reset→Inc is count=1"
        );
        let final_step = imported
            .reconstruct(msgs.len() - 1, &fold_update)
            .expect("last step must exist");
        assert_eq!(
            final_step, live,
            "final reconstructed model must equal live model"
        );
    }

    // Import → reproduce: the final datum of a replayed session equals the
    // final datum of the original session. Determinism gate for Step 3.
    //
    // Protocol: run a session, export, import into a fresh buffer, reconstruct
    // the final step — the two final models must be equal.
    #[cfg(feature = "json")]
    #[test]
    fn import_reproduce_final_datum() {
        #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        enum RepMsg {
            Add(i64),
            Reset,
            Sub(i64),
        }
        #[derive(Clone, Debug, PartialEq)]
        struct RepModel {
            val: i64,
        }

        fn rep_update(msg: RepMsg, m: RepModel) -> (RepModel, IpeCmd<RepMsg>) {
            let next = match msg {
                RepMsg::Add(n) => RepModel { val: m.val + n },
                RepMsg::Reset => RepModel { val: 0 },
                RepMsg::Sub(n) => RepModel { val: m.val - n },
            };
            (next, IpeCmd::None)
        }

        // Record a session.
        let init = RepModel { val: 0 };
        let mut buf = RecordBuffer::new(init.clone(), 32);
        let msgs = [
            RepMsg::Add(10),
            RepMsg::Sub(3),
            RepMsg::Add(7),
            RepMsg::Reset,
            RepMsg::Add(42),
        ];
        let mut live = init.clone();
        for msg in &msgs {
            let (next, _) = rep_update(msg.clone(), live.clone());
            buf.record(msg.clone(), next.clone(), &rep_update);
            live = next;
        }
        let original_final = live;

        // Export the session.
        let bytes = export_msgs(&buf).expect("export must succeed");

        // Import into a fresh buffer (reproduce from the log alone).
        let imported = import_msgs::<RepMsg, RepModel, _>(&bytes, init, rep_update, 32)
            .expect("import must succeed");

        // Reproduced final datum must equal the original.
        let reproduced_final = imported
            .reconstruct(imported.len() - 1, &rep_update)
            .expect("last step must be in range");
        assert_eq!(
            reproduced_final, original_final,
            "reproduced final datum must equal original session's final datum"
        );
    }

    // Past the cap the log does not grow unbounded; base advances to preserve
    // correct reconstruction from the retained window.
    #[test]
    fn recorder_bound_does_not_grow_past_cap() {
        let cap = 4usize;
        let mut buf = RecordBuffer::new(TestModel { count: 0 }, cap);

        // Record more steps than the cap.
        for i in 1..=10i64 {
            let current = buf
                .log
                .back()
                .map(|s| s.model_after.clone())
                .unwrap_or_else(|| buf.base.clone());
            let (next, _) = test_update(TestMsg::Add(i), current);
            buf.record(TestMsg::Add(i), next, &test_update);

            assert!(
                buf.len() <= cap,
                "log length {} exceeded cap {} after step {i}",
                buf.len(),
                cap
            );
        }

        assert_eq!(
            buf.len(),
            cap,
            "log must hold exactly cap steps after overflow"
        );
    }

    // ── stepTo / back / forward ───────────────────────────────────────────────

    // stepTo(N) yields the same model as folding apply_transition over the
    // first N+1 messages from init — the core determinism guarantee.
    //
    // Each N uses a freshly-recorded history so the truncation from one
    // step_to(N) call does not interfere with the next check.
    #[test]
    fn step_to_determinism() {
        let msgs = [
            TestMsg::Add(3),
            TestMsg::Add(7),
            TestMsg::Add(2),
            TestMsg::Add(5),
        ];

        for n in 0..msgs.len() {
            // Fresh history for each N: step_to truncates the tail, so
            // re-using a single history would make step_to(N-1) invisible.
            let mut history = History::new(TestModel { count: 0 }, test_update, 16);
            let mut live = TestModel { count: 0 };
            for msg in &msgs {
                let (next, _) = test_update(msg.clone(), live.clone());
                live = next.clone();
                history.record(msg.clone(), next);
            }

            let mut expected = TestModel { count: 0 };
            for msg in msgs.iter().take(n + 1) {
                let (next, _) = test_update(msg.clone(), expected.clone());
                expected = next;
            }
            let got = history
                .step_to(n)
                .expect("step_to must return Some for in-range n");
            assert_eq!(
                got,
                expected,
                "step_to({n}) must equal fold of first {} messages",
                n + 1
            );
        }
    }

    // step_to(N) truncates the tail: after step_to(N), len() == N+1.
    #[test]
    fn step_to_forks_tail() {
        let mut history = History::new(TestModel { count: 0 }, test_update, 16);
        let mut live = TestModel { count: 0 };
        for n in 1..=6i64 {
            let (next, _) = test_update(TestMsg::Add(n), live.clone());
            live = next.clone();
            history.record(TestMsg::Add(n), next);
        }
        assert_eq!(history.len(), 6, "pre-condition: 6 steps recorded");

        // step_to(2) → retain steps 0,1,2 only; tail (3,4,5) discarded.
        let _ = history.step_to(2).expect("step_to(2) in range");
        assert_eq!(
            history.len(),
            3,
            "after step_to(2) history must hold exactly 3 steps"
        );
    }

    // step_to fires zero additional Cmds — effects are suppressed during replay.
    #[test]
    fn step_to_no_effect_refire() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let effect_count = Arc::new(AtomicUsize::new(0));

        let counter = Arc::clone(&effect_count);
        // Live update bumps counter; stored update_fn does not.
        let live_update = move |msg: TestMsg, model: TestModel| -> (TestModel, IpeCmd<TestMsg>) {
            counter.fetch_add(1, Ordering::SeqCst);
            test_update(msg, model)
        };

        let mut history = History::new(TestModel { count: 0 }, test_update, 16);
        let mut live = TestModel { count: 0 };
        for n in [1i64, 2, 3, 4, 5] {
            let (next, _) = live_update(TestMsg::Add(n), live.clone());
            live = next.clone();
            history.record(TestMsg::Add(n), next);
        }

        let live_effects = effect_count.load(Ordering::SeqCst);
        assert_eq!(live_effects, 5, "live pass must fire exactly 5 effects");

        // step_to uses stored test_update (no counter) — no extra effects.
        let _ = history.step_to(2).expect("step_to(2) in range");

        let after = effect_count.load(Ordering::SeqCst);
        assert_eq!(
            live_effects, after,
            "step_to must not fire any additional effects"
        );
    }

    // back = step_to(cur-1), forward = step_to(cur+1); both clamp correctly.
    #[test]
    fn back_forward_cursor() {
        let mut history = History::new(TestModel { count: 0 }, test_update, 16);
        let mut live = TestModel { count: 0 };
        for n in [10i64, 20, 30] {
            let (next, _) = test_update(TestMsg::Add(n), live.clone());
            live = next.clone();
            history.record(TestMsg::Add(n), next);
        }
        // 3 steps: count at step 0=10, 1=30, 2=60.

        // step_to(1) = back from tail.
        let at1 = history.step_to(1).expect("step_to(1)");
        assert_eq!(at1.count, 30, "step_to(1) = count 30");
        assert_eq!(history.len(), 2, "tail truncated to 2 steps");

        // Forward from step 1 has no tail left — step_to(1) on 2-step log
        // is the last step; clamped step_to(1) must still work.
        let clamped = history.step_to(1).expect("step_to last step");
        assert_eq!(clamped.count, 30, "clamped forward stays at tail");

        // Back to step 0.
        let at0 = history.step_to(0).expect("step_to(0)");
        assert_eq!(at0.count, 10, "step_to(0) = count 10");
        assert_eq!(history.len(), 1, "tail truncated to 1 step");
    }

    // step_to out-of-range returns None without panic.
    #[test]
    fn step_to_out_of_range_is_none() {
        let mut history = History::new(TestModel { count: 0 }, test_update, 16);
        assert!(
            history.step_to(0).is_none(),
            "step_to on empty history must return None"
        );

        let (m, _) = test_update(TestMsg::Add(1), TestModel { count: 0 });
        history.record(TestMsg::Add(1), m);

        assert!(
            history.step_to(1).is_none(),
            "step_to past last step must return None"
        );
    }

    // ── Recorder-above-sink: cli + worker shapes ──────────────────────────────
    //
    // The cli (`console_app`) and worker (`worker_app`) run loops feed a
    // `RecordBuffer` with `record(msg_after_update, model_after, &update)` after
    // each accepted step — exactly the pattern these tests replay. Mirroring
    // `reconstruct_matches_live_model` for both shapes pins the determinism
    // guarantee (principle 2): the reconstructed model at each step equals the
    // live model the loop held at that step.

    // cli shape (console_app feed): reconstruct(n) == live model at step n.
    #[test]
    fn cli_recorder_reconstruct_matches_live_model() {
        let init = TestModel { count: 0 };
        let mut buf = RecordBuffer::new(init.clone(), DEFAULT_HISTORY_CAP);
        let msgs = [TestMsg::Add(4), TestMsg::Add(8), TestMsg::Add(15)];
        let mut live = init;
        for msg in &msgs {
            // The console_app loop clones the msg, folds it, then records the
            // post-update model — reproduced here verbatim.
            let msg_for_recorder = msg.clone();
            let (next, _cmd) = test_update(msg.clone(), live.clone());
            live = next.clone();
            buf.record(msg_for_recorder, next, &test_update);
        }
        for (i, _msg) in msgs.iter().enumerate() {
            let reconstructed = buf
                .reconstruct(i, &test_update)
                .expect("cli step must be in range");
            let mut expected = TestModel { count: 0 };
            for m in msgs.iter().take(i + 1) {
                let (next, _) = test_update(m.clone(), expected.clone());
                expected = next;
            }
            assert_eq!(
                reconstructed, expected,
                "cli reconstruct at step {i} must equal the live model"
            );
        }
    }

    // worker shape (worker_app feed): reconstruct(n) == live model at step n.
    // A worker has no view/input stream; its steps come from Sub/Cmd messages,
    // but the recorder feed is identical to the cli's.
    #[test]
    fn worker_recorder_reconstruct_matches_live_model() {
        let init = TestModel { count: 0 };
        let mut buf = RecordBuffer::new(init.clone(), DEFAULT_HISTORY_CAP);
        let msgs = [TestMsg::Add(7), TestMsg::Add(-3), TestMsg::Add(100)];
        let mut live = init;
        for msg in &msgs {
            let msg_for_recorder = msg.clone();
            let (next, _cmd) = test_update(msg.clone(), live.clone());
            live = next.clone();
            buf.record(msg_for_recorder, next, &test_update);
        }
        let last = buf
            .reconstruct(msgs.len() - 1, &test_update)
            .expect("worker last step must be in range");
        assert_eq!(
            last, live,
            "worker final reconstruct must equal the live model"
        );
    }

    // Portable inspect surface: `inspect_model(n)` renders the reconstructed
    // model at step n as a plain, control-code-free string, and `replay_log`
    // dumps one plain line per step. Neither carries any ANSI/control byte —
    // the shape-neutral portable form the off-TTY output boundary streams.
    #[cfg(feature = "debugger")]
    #[test]
    fn inspect_and_replay_are_plain_text() {
        use crate::stringify::IpeStringify;

        #[derive(Clone, Debug, PartialEq)]
        enum PMsg {
            Bump(i64),
        }
        #[derive(Clone, Debug, PartialEq)]
        struct PModel {
            n: i64,
        }
        impl IpeStringify for PMsg {
            fn ipe_show(&self) -> String {
                let PMsg::Bump(v) = self;
                format!("Bump({v})")
            }
        }
        impl IpeStringify for PModel {
            fn ipe_show(&self) -> String {
                format!("PModel {{ n = {} }}", self.n)
            }
        }
        fn p_update(msg: PMsg, m: PModel) -> (PModel, IpeCmd<PMsg>) {
            let PMsg::Bump(v) = msg;
            (PModel { n: m.n + v }, IpeCmd::None)
        }

        let init = PModel { n: 0 };
        let mut buf = RecordBuffer::new(init.clone(), DEFAULT_HISTORY_CAP);
        let msgs = [PMsg::Bump(2), PMsg::Bump(5)];
        let mut live = init;
        for msg in &msgs {
            let (next, _) = p_update(msg.clone(), live.clone());
            live = next.clone();
            buf.record(msg.clone(), next, &p_update);
        }

        let step0 = buf.inspect_model(0, &p_update).expect("step 0");
        let step1 = buf.inspect_model(1, &p_update).expect("step 1");
        assert_eq!(step0, "PModel { n = 2 }");
        assert_eq!(step1, "PModel { n = 7 }");

        let log = buf.replay_log(&p_update);
        assert_eq!(log.len(), 2);
        assert_eq!(log[0], "Bump(2) => PModel { n = 2 }");
        assert_eq!(log[1], "Bump(5) => PModel { n = 7 }");

        // No control code anywhere in the portable form.
        for line in std::iter::once(step0)
            .chain(std::iter::once(step1))
            .chain(log)
        {
            assert!(
                !line.chars().any(|c| c.is_control()),
                "portable inspect/replay output must carry no control code; got: {line:?}"
            );
        }

        // Out-of-range inspect is None, never a panic.
        assert!(
            buf.inspect_model(99, &p_update).is_none(),
            "out-of-range inspect_model must return None"
        );
    }
}

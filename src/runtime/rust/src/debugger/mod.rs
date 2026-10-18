//! Shape-agnostic TEA debugger core — recorder, re-fold, export, and import.
//!
//! Enabled only when the `debugger` feature is active (`ipe dev build/run --debugger`).
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

use crate::retained::{Bytes, RetainedBytes};
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
// (`ipe dev run --record` writes it, `ipe dev run --replay` re-folds it).
// Gated on `feature = "debugger"` via the inner `#![cfg(...)]`.
pub mod session_log;

/// The default message-log capacity when none is configured.
pub const DEFAULT_HISTORY_CAP: usize = 512;

// ── Steps and the base, each built with its measure ───────────────────────

/// A retained value and its measure, built together; every field is private here.
///
/// Code outside this module cannot write a `Step` or `Base` literal, change a
/// held value without re-marking it, or construct a `Measured`: a mark is
/// always the measure of the value it sits beside.
mod marked {
    use crate::retained::{Bytes, RetainedBytes};

    mod sealed {
        /// Closes [`super::StepMark`] to the two policies this module defines.
        pub trait Sealed {}
        impl Sealed for super::Unmeasured {}
        impl Sealed for super::Measured {}
    }

    /// What a step and the base carry about their own size.
    ///
    /// Sealed: no other module or crate implements it.
    pub trait StepMark<Msg, Model>: sealed::Sealed + Copy {
        /// The mark of a step holding `msg` and `model_after`.
        fn of_step(msg: &Msg, model_after: &Model) -> Self;
        /// The mark of a base holding `base`.
        fn of_base(base: &Model) -> Self;
    }

    /// No measure: the policy of a recorder that holds no byte budget.
    #[derive(Clone, Copy)]
    pub struct Unmeasured;

    /// A measure taken once, when its value was built; `None` has no measure.
    #[derive(Clone, Copy)]
    pub struct Measured(Option<Bytes>);

    impl Measured {
        /// The bytes measured, or `None` when the value had no measure.
        #[must_use]
        pub const fn bytes(self) -> Option<Bytes> {
            self.0
        }
    }

    impl<Msg, Model> StepMark<Msg, Model> for Unmeasured {
        fn of_step(_msg: &Msg, _model_after: &Model) -> Self {
            Self
        }

        fn of_base(_base: &Model) -> Self {
            Self
        }
    }

    impl<Msg: RetainedBytes, Model: RetainedBytes> StepMark<Msg, Model> for Measured {
        fn of_step(msg: &Msg, model_after: &Model) -> Self {
            Self(step_measure(msg, model_after))
        }

        fn of_base(base: &Model) -> Self {
            Self(base.retained_bytes())
        }
    }

    /// The bytes one measured step keeps resident: its slot, its message and its model.
    ///
    /// The one formula both a step's mark and the fresh test walk use.
    pub fn step_measure<Msg: RetainedBytes, Model: RetainedBytes>(
        msg: &Msg,
        model_after: &Model,
    ) -> Option<Bytes> {
        Bytes::inline::<Step<Msg, Model, Measured>>()?
            .plus(msg)?
            .plus(model_after)
    }

    /// One step: the dispatched message, the model that followed it, and its mark.
    pub struct Step<Msg, Model, K> {
        msg: Msg,
        model_after: Model,
        mark: K,
    }

    impl<Msg, Model, K: StepMark<Msg, Model>> Step<Msg, Model, K> {
        /// A step marked from its own values.
        pub fn new(msg: Msg, model_after: Model) -> Self {
            let mark = K::of_step(&msg, &model_after);
            Self {
                msg,
                model_after,
                mark,
            }
        }
    }

    impl<Msg, Model, K> Step<Msg, Model, K> {
        /// The dispatched message.
        pub const fn msg(&self) -> &Msg {
            &self.msg
        }

        /// The model that followed the message.
        pub const fn model_after(&self) -> &Model {
            &self.model_after
        }

        /// The mark taken when the step was built.
        pub const fn mark(&self) -> K
        where
            K: Copy,
        {
            self.mark
        }

        /// The dispatched message, dropping the rest of the step.
        pub fn into_msg(self) -> Msg {
            self.msg
        }
    }

    /// The rolling base model and its mark.
    pub struct Base<Model, K> {
        model: Model,
        mark: K,
    }

    impl<Model, K> Base<Model, K> {
        /// A base marked from `model`.
        pub fn new<Msg>(model: Model) -> Self
        where
            K: StepMark<Msg, Model>,
        {
            let mark = K::of_base(&model);
            Self { model, mark }
        }

        /// Replace the model, re-marking it.
        pub fn set<Msg>(&mut self, model: Model)
        where
            K: StepMark<Msg, Model>,
        {
            self.mark = K::of_base(&model);
            self.model = model;
        }

        /// The base model.
        pub const fn model(&self) -> &Model {
            &self.model
        }

        /// The mark taken when the model was set.
        pub const fn mark(&self) -> K
        where
            K: Copy,
        {
            self.mark
        }
    }
}

use marked::{Base, Step};
pub use marked::{Measured, StepMark, Unmeasured};

// ── RecordBuffer — data-only, driver-integrated variant ───────────────────

/// A bounded, rolling TEA message log with a rolling base `Model`.
///
/// Unlike [`History`], `RecordBuffer` does NOT store the `update` function.
/// The caller supplies it at overflow (via [`RecordBuffer::record`]) and at
/// reconstruction time (via [`RecordBuffer::reconstruct`]). This avoids
/// duplicating the update closure in drivers (such as the WASM TEA sink) that
/// already own it.
///
/// `K` is the measure policy: [`Unmeasured`] (the default) for a recorder that
/// holds no byte budget, [`Measured`] for one charged against a budget. Only a
/// measured buffer implements [`RetainedBytes`], and it reads the marks each
/// step and the base carry, never the values.
///
/// Invariant (by construction): `log.len() <= cap` always holds.
pub struct RecordBuffer<Msg, Model, K = Unmeasured> {
    /// The model that precedes the oldest retained `Msg`. Advanced on overflow.
    base: Base<Model, K>,
    /// Retained steps, newest at the back.
    log: VecDeque<Step<Msg, Model, K>>,
    /// Maximum retained messages. At least 1.
    cap: usize,
    /// `true` once a step has been evicted, so `base` is no longer the initial model.
    overflowed: bool,
}

impl<Msg, Model> RetainedBytes for RecordBuffer<Msg, Model, Measured> {
    // The base plus every retained step, spare log slots included, read from
    // the marks taken when each was built.
    fn retained_bytes(&self) -> Option<Bytes> {
        self.resident_from(self.base.mark().bytes(), |step| step.mark().bytes())
    }
}

impl<Msg, Model> RecordBuffer<Msg, Model, Measured> {
    /// The resident total, given the base's measure and how to measure each step.
    fn resident_from(
        &self,
        base: Option<Bytes>,
        step: impl Fn(&Step<Msg, Model, Measured>) -> Option<Bytes>,
    ) -> Option<Bytes> {
        let frame = Bytes::inline::<Self>()?
            .checked_add(base?)?
            .checked_add(crate::retained::deque_frame(&self.log)?)?;
        self.log
            .iter()
            .try_fold(frame, |acc, s| acc.checked_add(step(s)?))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
impl<Msg: RetainedBytes, Model: RetainedBytes> RecordBuffer<Msg, Model, Measured> {
    /// The bytes [`RetainedBytes::retained_bytes`] charges, measured afresh.
    fn measured_fresh(&self) -> Option<Bytes> {
        self.resident_from(self.base.model().retained_bytes(), |s| {
            marked::step_measure(s.msg(), s.model_after())
        })
    }
}

impl<Msg: Clone, Model: Clone> RecordBuffer<Msg, Model, Unmeasured> {
    /// Create a new, empty, unmeasured buffer starting from `initial_model`.
    ///
    /// `cap` is clamped to a minimum of 1.
    #[must_use]
    pub fn new(initial_model: Model, cap: usize) -> Self {
        Self::start(initial_model, cap)
    }
}

impl<Msg: Clone + RetainedBytes, Model: Clone + RetainedBytes> RecordBuffer<Msg, Model, Measured> {
    /// Create a new, empty buffer starting from `initial_model`, each step measured once.
    ///
    /// `cap` is clamped to a minimum of 1.
    #[must_use]
    pub fn measured(initial_model: Model, cap: usize) -> Self {
        Self::start(initial_model, cap)
    }
}

impl<Msg: Clone, Model: Clone, K: StepMark<Msg, Model>> RecordBuffer<Msg, Model, K> {
    /// An empty buffer of policy `K` starting from `initial_model`.
    fn start(initial_model: Model, cap: usize) -> Self {
        Self {
            base: Base::new::<Msg>(initial_model),
            log: VecDeque::new(),
            cap: cap.max(1),
            overflowed: false,
        }
    }

    /// Record one live-pass step.
    ///
    /// `update` is called exactly once on overflow to advance the base over the
    /// evicted step; the resulting `Cmd` is discarded. On a non-overflow call
    /// `update` is never called. The new step is measured once, here, and so
    /// is an advanced base.
    pub fn record<F>(&mut self, msg: Msg, model_after: Model, update: &F)
    where
        F: Fn(Msg, Model) -> (Model, IpeCmd<Msg>),
    {
        if self.log.len() >= self.cap
            && let Some(oldest) = self.log.pop_front()
        {
            let (advanced, _cmd) = update(oldest.into_msg(), self.base.model().clone());
            self.base.set::<Msg>(advanced);
            self.overflowed = true;
        }
        self.log.push_back(Step::new(msg, model_after));
    }

    /// Clear the step log and reset the base to `init`.
    ///
    /// After this call the buffer is empty and `base()` returns a clone of
    /// `init`. This is the "reset to init" escape hatch for the debugger:
    /// time-travel and recording both restart from a clean slate. No `update`
    /// call is made; no `Cmd` is fired.
    pub fn reset_to_init(&mut self, init: Model) {
        self.log.clear();
        self.base.set::<Msg>(init);
        self.overflowed = false;
    }
}

impl<Msg: Clone, Model: Clone, K> RecordBuffer<Msg, Model, K> {
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
        let mut model = self.base.model().clone();
        for step in self.log.iter().take(n + 1) {
            let (next, _cmd) = update(step.msg().clone(), model);
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
        self.base.model()
    }

    /// `true` once the ring has evicted a step.
    ///
    /// The base then holds the model after the evicted steps, not the initial
    /// model, so a re-fold of the retained messages from `init` would be wrong.
    #[must_use]
    pub fn overflowed(&self) -> bool {
        self.overflowed
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
        self.log.iter().map(Step::msg)
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
                    .map(|s| crate::stringify::IpeStringify::ipe_show(s.msg()))?;
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
pub fn export_msgs<Msg, Model, K>(buf: &RecordBuffer<Msg, Model, K>) -> Result<Vec<u8>, ExportError>
where
    Msg: Clone + serde::Serialize,
    Model: Clone,
{
    let msgs: Vec<&Msg> = buf.log.iter().map(Step::msg).collect();
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
///
/// The buffer has measure policy `K`: every imported step is built through
/// [`RecordBuffer::record`], so it is marked by the same constructor as a
/// live one.
#[cfg(feature = "json")]
pub fn import_msgs<Msg, Model, F, K>(
    bytes: &[u8],
    initial_model: Model,
    update: F,
    cap: usize,
) -> Option<RecordBuffer<Msg, Model, K>>
where
    Msg: Clone + serde::de::DeserializeOwned,
    Model: Clone,
    F: Fn(Msg, Model) -> (Model, IpeCmd<Msg>),
    K: StepMark<Msg, Model>,
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
    let mut buf = RecordBuffer::<Msg, Model, K>::start(initial_model, effective_cap);

    for msg in msgs {
        // Compute the post-update model so `Step::model_after` is correct.
        let current = buf
            .log
            .back()
            .map_or_else(|| buf.base.model().clone(), |s| s.model_after().clone());
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
                history.inner.base().clone()
            } else {
                history
                    .inner
                    .log
                    .back()
                    .map(|s| s.model_after().clone())
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
        let (m1, _) = rt_update(RtMsg::Add(5), history.inner.base().clone());
        history.record(RtMsg::Add(5), m1.clone());
        let (m2, _) = rt_update(RtMsg::Add(3), m1);
        history.record(RtMsg::Add(3), m2);

        let bytes = export_history_msgs(&history).expect("export must succeed");

        let imported = import_msgs::<RtMsg, RtModel, _, Unmeasured>(
            &bytes,
            RtModel { count: 0 },
            rt_update,
            16,
        )
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
            import_msgs::<Msg, Model, _, Unmeasured>(b"{not valid json}", Model, upd, 8).is_none(),
            "malformed blob must yield None"
        );

        // Oversized blob.
        let oversized = vec![b' '; crate::seal_codec::DEFAULT_SEAL_MAX_INPUT_BYTES + 1];
        assert!(
            import_msgs::<Msg, Model, _, Unmeasured>(&oversized, Model, upd, 8).is_none(),
            "oversized blob must yield None"
        );

        // Type mismatch — valid JSON but wrong shape.
        assert!(
            import_msgs::<Msg, Model, _, Unmeasured>(b"42", Model, upd, 8).is_none(),
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
        let imported =
            import_msgs::<FoldMsg, FoldModel, _, Unmeasured>(&bytes, init.clone(), fold_update, 16)
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
        let imported = import_msgs::<RepMsg, RepModel, _, Unmeasured>(&bytes, init, rep_update, 32)
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
                .map(|s| s.model_after().clone())
                .unwrap_or_else(|| buf.base().clone());
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

    // ── A measured recorder charges the marks its steps were built with ──────

    mod measured {
        use super::super::*;
        use std::cell::Cell;
        use std::thread::LocalKey;

        thread_local! {
            static MSG_VISITS: Cell<u64> = const { Cell::new(0) };
            static MODEL_VISITS: Cell<u64> = const { Cell::new(0) };
        }

        fn bump(counter: &'static LocalKey<Cell<u64>>) {
            counter.with(|c| c.set(c.get() + 1));
        }

        /// The `retained_bytes` calls counted on this thread, as `(msgs, models)`.
        fn visits() -> (u64, u64) {
            (MSG_VISITS.with(Cell::get), MODEL_VISITS.with(Cell::get))
        }

        #[derive(Clone, Debug, PartialEq)]
        #[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
        enum TestMsg {
            Add(i64),
            Text(String),
            Unmeasurable,
        }

        #[derive(Clone, Debug, PartialEq)]
        struct TestModel {
            count: i64,
            text: String,
            unmeasurable: bool,
        }

        impl RetainedBytes for TestMsg {
            fn retained_bytes(&self) -> Option<Bytes> {
                bump(&MSG_VISITS);
                match self {
                    Self::Add(_) => Bytes::inline::<Self>(),
                    Self::Text(text) => Bytes::inline::<Self>()?.plus_count(text.capacity()),
                    Self::Unmeasurable => None,
                }
            }
        }

        impl RetainedBytes for TestModel {
            fn retained_bytes(&self) -> Option<Bytes> {
                bump(&MODEL_VISITS);
                if self.unmeasurable {
                    return None;
                }
                Bytes::inline::<Self>()?.plus_count(self.text.capacity())
            }
        }

        const fn model(count: i64) -> TestModel {
            TestModel {
                count,
                text: String::new(),
                unmeasurable: false,
            }
        }

        // An `Add` builds a fresh measurable model; `Text` stores its text;
        // `Unmeasurable` leaves the model as it was.
        fn update(msg: TestMsg, m: TestModel) -> (TestModel, IpeCmd<TestMsg>) {
            let next = match msg {
                TestMsg::Add(n) => model(m.count + n),
                TestMsg::Text(text) => TestModel { text, ..m },
                TestMsg::Unmeasurable => m,
            };
            (next, IpeCmd::None)
        }

        type Buf = RecordBuffer<TestMsg, TestModel, Measured>;

        /// Fold `msg` over `live` and record the step.
        fn push(buf: &mut Buf, live: &mut TestModel, msg: TestMsg) {
            let (next, _cmd) = update(msg.clone(), live.clone());
            *live = next.clone();
            buf.record(msg, next, &update);
        }

        /// A measured buffer of cap `cap` holding `n` recorded `Add` steps, and its live model.
        fn filled(cap: usize, n: i64) -> (Buf, TestModel) {
            let mut live = model(0);
            let mut buf = Buf::measured(live.clone(), cap);
            for i in 0..n {
                push(&mut buf, &mut live, TestMsg::Add(i));
            }
            (buf, live)
        }

        /// `true` when the charged total equals the fresh walk.
        fn agrees(buf: &Buf) -> bool {
            buf.retained_bytes() == buf.measured_fresh()
        }

        // The charge reads marks only, equals the fresh walk after every
        // record, and each value is measured once, when its step or base is built.
        #[test]
        fn measured_charge_reads_marks_and_equals_fresh() {
            const CAP: u64 = 512;
            const RECORDS: u64 = 600;
            let cap = usize::try_from(CAP).expect("the cap fits a usize");
            let start = visits();
            let mut live = model(0);
            let mut buf = Buf::measured(live.clone(), cap);
            let mut built = (visits().0 - start.0, visits().1 - start.1);
            let mut previous = buf.retained_bytes();
            for i in 0..RECORDS {
                // Step `i` carries `i` bytes of text in its message and its
                // model, and so does the base advanced over it: a mark that
                // kept another value's measure differs from the fresh walk.
                let len = usize::try_from(i).expect("a step index fits a usize");
                let pre = visits();
                push(&mut buf, &mut live, TestMsg::Text("x".repeat(len)));
                let post = visits();
                built = (built.0 + post.0 - pre.0, built.1 + post.1 - pre.1);

                let charged = buf.retained_bytes();
                assert_eq!(
                    visits(),
                    post,
                    "record {i}: a charge must read the marks, never walk the values"
                );
                assert!(charged.is_some(), "record {i}: every step is measurable");
                assert_ne!(
                    charged, previous,
                    "record {i}: each state measures differently"
                );
                assert_eq!(charged, buf.measured_fresh(), "record {i}");
                previous = charged;
            }
            assert_eq!(
                built.0, RECORDS,
                "each message is measured once, as its step is built"
            );
            assert_eq!(
                built.1,
                1 + RECORDS + (RECORDS - CAP),
                "the initial base, each step's model, and each advanced base are measured once"
            );
        }

        // A step carrying a 4 KiB string moves the charge and the fresh walk alike.
        #[test]
        fn a_large_step_moves_charge_and_fresh_alike() {
            let (mut buf, mut live) = filled(16, 3);
            let (charged, fresh) = (buf.retained_bytes(), buf.measured_fresh());
            push(&mut buf, &mut live, TestMsg::Text("x".repeat(4096)));
            let delta = |after: Option<Bytes>, before: Option<Bytes>| {
                after?.get().checked_sub(before?.get())
            };
            let charged_delta = delta(buf.retained_bytes(), charged);
            assert_eq!(charged_delta, delta(buf.measured_fresh(), fresh));
            assert!(
                charged_delta.is_some_and(|d| d >= 4096),
                "the string's bytes are charged: {charged_delta:?}"
            );
        }

        // Every mutator leaves the charge equal to the fresh walk.
        #[test]
        fn every_mutator_keeps_the_charge_fresh() {
            const CAP: usize = 512;
            const RECORDS: i64 = 600;
            for k in [0, CAP / 2, CAP - 1] {
                let (mut buf, _) = filled(CAP, RECORDS);
                assert!(buf.step_to(k, &update).is_some(), "step_to({k})");
                assert_eq!(buf.len(), k + 1);
                assert!(agrees(&buf), "step_to({k})");
            }

            let (mut buf, _) = filled(CAP, RECORDS);
            let before = buf.retained_bytes();
            let len = buf.len();
            assert!(buf.step_to(len, &update).is_none(), "step_to(len) refuses");
            assert_eq!(
                buf.retained_bytes(),
                before,
                "a refused step_to changes nothing"
            );
            assert!(agrees(&buf));

            // The new base differs in size from the advanced one it replaces,
            // so a base left with its old mark disagrees with the fresh walk.
            let advanced = buf.measured_fresh();
            buf.reset_to_init(TestModel {
                text: "y".repeat(100),
                ..model(7)
            });
            assert!(buf.is_empty());
            assert!(buf.retained_bytes().is_some());
            assert_ne!(buf.measured_fresh(), advanced, "reset_to_init");
            assert!(agrees(&buf), "reset_to_init");
        }

        // An imported buffer's steps are marked by the same constructor as live ones.
        #[cfg(feature = "json")]
        #[test]
        fn an_imported_buffer_charges_fresh() {
            let msgs: Vec<TestMsg> = (0..600).map(TestMsg::Add).collect();
            let blob = serde_json::to_vec(&msgs).expect("a test log encodes");
            let buf = import_msgs::<TestMsg, TestModel, _, Measured>(&blob, model(0), update, 512)
                .expect("a well-formed log imports");
            assert_eq!(buf.len(), 512);
            assert!(buf.retained_bytes().is_some());
            assert!(agrees(&buf), "import_msgs");
        }

        // Refusal: an unmeasured step keeps the charge `None` while it is
        // resident, and the record that evicts it is the first `Some`.
        #[test]
        fn an_unmeasured_step_refuses_until_evicted() {
            const CAP: usize = 8;
            let (mut buf, mut live) = filled(CAP, 8);
            push(&mut buf, &mut live, TestMsg::Unmeasurable);
            assert_eq!(
                buf.retained_bytes(),
                None,
                "an unmeasured step refuses the charge"
            );
            for i in 0..CAP - 1 {
                push(&mut buf, &mut live, TestMsg::Add(1));
                assert_eq!(
                    buf.retained_bytes(),
                    None,
                    "record {i}: the unmeasured step is still resident"
                );
            }
            push(&mut buf, &mut live, TestMsg::Add(1));
            assert!(
                buf.retained_bytes().is_some(),
                "the record that evicts the unmeasured step clears the refusal"
            );
            assert!(agrees(&buf));
        }

        // Refusal: only a truncation or reset that drops the unmeasured step clears it.
        #[test]
        fn truncating_or_resetting_past_an_unmeasured_step_clears_it() {
            let (mut buf, mut live) = filled(8, 3);
            push(&mut buf, &mut live, TestMsg::Unmeasurable);
            push(&mut buf, &mut live, TestMsg::Add(1));
            assert_eq!(buf.retained_bytes(), None);
            assert!(buf.step_to(3, &update).is_some());
            assert_eq!(
                buf.retained_bytes(),
                None,
                "a truncation that keeps the unmeasured step still refuses"
            );
            assert!(buf.step_to(2, &update).is_some());
            assert!(
                buf.retained_bytes().is_some(),
                "a truncation below it clears it"
            );
            assert!(agrees(&buf));

            let (mut buf, mut live) = filled(8, 3);
            push(&mut buf, &mut live, TestMsg::Unmeasurable);
            assert_eq!(buf.retained_bytes(), None);
            buf.reset_to_init(model(0));
            assert!(buf.retained_bytes().is_some(), "a reset clears it");
            assert!(agrees(&buf));
        }

        // Refusal: an unmeasured base refuses the charge until an overflow re-marks it.
        #[test]
        fn an_unmeasured_base_refuses_until_an_overflow_remarks_it() {
            const CAP: usize = 4;
            let mut buf = Buf::measured(model(0), CAP);
            let unmeasured = TestModel {
                unmeasurable: true,
                ..model(0)
            };
            buf.reset_to_init(unmeasured.clone());
            assert_eq!(
                buf.retained_bytes(),
                None,
                "an unmeasured base refuses the charge"
            );
            let mut live = unmeasured;
            for i in 0..CAP {
                push(&mut buf, &mut live, TestMsg::Add(1));
                assert_eq!(
                    buf.retained_bytes(),
                    None,
                    "record {i}: the base is not re-marked"
                );
            }
            push(&mut buf, &mut live, TestMsg::Add(1));
            assert!(
                buf.retained_bytes().is_some(),
                "the overflow advances and re-marks the base"
            );
            assert!(agrees(&buf));
        }
    }
}

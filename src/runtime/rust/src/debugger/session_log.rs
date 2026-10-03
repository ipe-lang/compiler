//! Typed session log: the replayable form of a recorded cli/worker session.
//!
//! `ipe run --record` writes it beside the plain trace (see
//! [`crate::debugger::record_sink`]); `ipe run --replay` decodes it and re-folds
//! `update` over the recorded messages with every `Cmd` discarded, so no I/O,
//! network or database effect runs again. The same program with the same log
//! prints the same output on every run.
//!
//! ## Wire form
//!
//! One JSON object: a format number, the schema tags of the recording
//! program's `Msg` and `Model` types, where the fold starts, and the retained
//! messages, oldest first. The start is:
//!
//! - `Init` — the ring never overflowed; the fold starts from `init`.
//! - `Base` — the ring overflowed and the `Model` is encodable; the log carries
//!   the rolling base and the fold starts from it.
//! - `Lost` — the ring overflowed and the `Model` is not encodable. Replay
//!   refuses: an overflowed log is never folded from `init`, because the
//!   retained messages follow the base, not the initial model.
//!
//! ## Trust boundary
//!
//! A log is untrusted input. The read is capped; the decode is total and whole,
//! so a refusal applies zero steps; the schema tags must match the running
//! program (a changed `Msg` type is refused by name, never partially applied);
//! and every printed line is stripped of control bytes, independently of the
//! strip the recorder applies when it writes.
//!
//! ## Which programs have a typed log
//!
//! The compiler picks the codec per program: [`Full`] when `Msg` and `Model`
//! are both encodable, [`MsgsOnly`] when only `Msg` is (an overflowed session is
//! then unreplayable), and [`TraceOnly`] when `Msg` is not encodable (it carries
//! a `Secret` or another value with no encoding): such a session is recorded as
//! a trace only, which `ipe run --replay` shows (sanitised, nothing re-run)
//! instead of folding, and a typed replay refuses with the reason.
//!
//! The encoder escapes every control character (`DEL` and C1 as well as C0),
//! so a log this runtime writes holds none raw.

#![cfg(feature = "debugger")]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::debugger::record_sink::plain_line;
use crate::debugger::{DEFAULT_HISTORY_CAP, RecordBuffer};
use crate::seal_codec::DEFAULT_SEAL_MAX_INPUT_BYTES;
use crate::stringify::IpeStringify;
use crate::tea::IpeCmd;

/// The wire-format number this runtime writes and accepts.
const FORMAT: u32 = 1;

/// A structural fingerprint of an emitted type, computed by the compiler.
pub type SchemaTag = [u8; 32];

/// Why a program's session has no replayable log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreplayable {
    /// The `Msg` type carries a value with no encoding, such as a `Secret`.
    MsgNotEncodable,
    /// The compiler could not recover the app's `Msg` or `Model` type.
    TypeUnknown,
}

/// Why a replay was refused; every refusal applies zero steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// This program's sessions are recorded as a trace only.
    Unreplayable(Unreplayable),
    /// The log file could not be opened or read.
    Unreadable(std::io::ErrorKind),
    /// The log is larger than the read cap.
    Oversized {
        /// The cap in bytes.
        cap: usize,
    },
    /// The log is not UTF-8.
    NotUtf8,
    /// The log ends before its JSON value does.
    Truncated,
    /// The log is not a session log of this program's shape.
    Malformed,
    /// The log was written in a format this runtime does not read.
    UnsupportedFormat(u32),
    /// The log was recorded against a different `Msg` type.
    MsgTypeChanged,
    /// The log's recorded base is a different `Model` type.
    ModelTypeChanged,
    /// The session overflowed the recorder ring and its base could not be encoded.
    Overflowed,
    /// The log holds more messages than a recorder ever retains.
    TooManySteps {
        /// The largest accepted message count.
        cap: usize,
    },
    /// Encoding the log failed.
    Encode,
}

impl core::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unreplayable(Unreplayable::MsgNotEncodable) => f.write_str(
                "replay refused: this program's Msg type carries a value with no encoding \
                 (such as a Secret), so its sessions are recorded as a trace only, never \
                 as a replayable log — `ipe run --replay out/session.ipelog` shows the trace",
            ),
            Self::Unreplayable(Unreplayable::TypeUnknown) => f.write_str(
                "replay refused: the compiler could not recover this app's Msg or Model \
                 type, so its sessions are recorded as a trace only (`ipe run --replay \
                 out/session.ipelog` shows it) — pass `update` and `view` as named \
                 functions or lambdas",
            ),
            Self::Unreadable(kind) => write!(f, "replay refused: the log cannot be read ({kind})"),
            Self::Oversized { cap } => write!(
                f,
                "replay refused: the log is larger than the {cap}-byte cap for a session log"
            ),
            Self::NotUtf8 => f.write_str("replay refused: the log is not UTF-8 text"),
            Self::Truncated => f.write_str("replay refused: the log is truncated"),
            Self::Malformed => f.write_str(
                "replay refused: the log is not a session log for this program's Msg type",
            ),
            Self::UnsupportedFormat(n) => write!(
                f,
                "replay refused: the log uses session-log format {n}; this build reads \
                 format {FORMAT}"
            ),
            Self::MsgTypeChanged => f.write_str(
                "replay refused: the log was recorded against a different Msg type — the \
                 program changed since recording; record the session again",
            ),
            Self::ModelTypeChanged => f.write_str(
                "replay refused: the log's recorded base is a different Model type — the \
                 program changed since recording; record the session again",
            ),
            Self::Overflowed => f.write_str(
                "replay refused: the session overflowed the recorder's history and this \
                 program's Model has no encoding, so the model the retained messages \
                 start from was not recorded — record a shorter session",
            ),
            Self::TooManySteps { cap } => write!(
                f,
                "replay refused: the log holds more than {cap} messages, more than a \
                 recorder retains"
            ),
            Self::Encode => f.write_str("the session log could not be encoded"),
        }
    }
}

/// A decoded log, ready to fold: where the fold starts and the messages.
pub struct Plan<Msg, Model> {
    /// The recorded base, or `None` to start from the program's `init`.
    base: Option<Model>,
    /// The messages to fold, oldest first.
    msgs: Vec<Msg>,
}

/// How a program's session log is encoded and decoded.
///
/// The compiler picks the implementation per program from what its `Msg` and
/// `Model` types can encode; see the module documentation.
pub trait SessionCodec<Msg, Model> {
    /// Refuse up front when this program has no replayable log.
    ///
    /// # Errors
    /// [`ReplayError::Unreplayable`] for a trace-only program.
    fn replayable(&self) -> Result<(), ReplayError> {
        Ok(())
    }

    /// Encode the typed log for `buf`.
    ///
    /// # Errors
    /// Why this program has no typed log, or [`ReplayError::Encode`].
    fn encode(&self, buf: &RecordBuffer<Msg, Model>) -> Result<Vec<u8>, ReplayError>;

    /// Decode a typed log whole into a [`Plan`].
    ///
    /// # Errors
    /// The [`ReplayError`] naming why the log is refused.
    fn decode(&self, bytes: &[u8]) -> Result<Plan<Msg, Model>, ReplayError>;
}

/// The codec of a program whose `Msg` cannot be encoded: a trace only.
pub struct TraceOnly(pub Unreplayable);

impl<Msg, Model> SessionCodec<Msg, Model> for TraceOnly {
    fn replayable(&self) -> Result<(), ReplayError> {
        Err(ReplayError::Unreplayable(self.0))
    }

    fn encode(&self, _buf: &RecordBuffer<Msg, Model>) -> Result<Vec<u8>, ReplayError> {
        Err(ReplayError::Unreplayable(self.0))
    }

    fn decode(&self, _bytes: &[u8]) -> Result<Plan<Msg, Model>, ReplayError> {
        Err(ReplayError::Unreplayable(self.0))
    }
}

/// The schema tags of the running program's `Msg` and `Model` types.
#[derive(Clone, Copy)]
struct Tags {
    msg: SchemaTag,
    model: SchemaTag,
}

/// The codec of a program whose `Msg` is encodable but whose `Model` is not.
///
/// An overflowed session is written with a lost start and refused at replay.
pub struct MsgsOnly(Tags);

impl MsgsOnly {
    /// Build the codec from the program's `Msg` and `Model` schema tags.
    #[must_use]
    pub const fn new(msg_tag: SchemaTag, model_tag: SchemaTag) -> Self {
        Self(Tags {
            msg: msg_tag,
            model: model_tag,
        })
    }
}

impl<Msg, Model> SessionCodec<Msg, Model> for MsgsOnly
where
    Msg: Clone + serde::Serialize + serde::de::DeserializeOwned,
    Model: Clone,
{
    fn encode(&self, buf: &RecordBuffer<Msg, Model>) -> Result<Vec<u8>, ReplayError> {
        let start: Start<()> = if buf.overflowed() {
            Start::Lost
        } else {
            Start::Init
        };
        encode_wire(self.0, start, buf)
    }

    fn decode(&self, bytes: &[u8]) -> Result<Plan<Msg, Model>, ReplayError> {
        let text = checked_header(bytes, self.0)?;
        // A base in a log whose `Model` tag matches a program with no `Model`
        // encoding was not written by this program's recorder.
        let wire: WireIn<Msg, serde::de::IgnoredAny> = decode_body(text)?;
        match wire.start {
            Start::Init => bounded_plan(None, wire.msgs),
            Start::Base(_) | Start::Lost => Err(ReplayError::Malformed),
        }
    }
}

/// The codec of a program whose `Msg` and `Model` are both encodable.
///
/// An overflowed session carries its rolling base and replays from it.
pub struct Full(Tags);

impl Full {
    /// Build the codec from the program's `Msg` and `Model` schema tags.
    #[must_use]
    pub const fn new(msg_tag: SchemaTag, model_tag: SchemaTag) -> Self {
        Self(Tags {
            msg: msg_tag,
            model: model_tag,
        })
    }
}

impl<Msg, Model> SessionCodec<Msg, Model> for Full
where
    Msg: Clone + serde::Serialize + serde::de::DeserializeOwned,
    Model: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    fn encode(&self, buf: &RecordBuffer<Msg, Model>) -> Result<Vec<u8>, ReplayError> {
        let start = if buf.overflowed() {
            Start::Base(buf.base())
        } else {
            Start::Init
        };
        encode_wire(self.0, start, buf)
    }

    fn decode(&self, bytes: &[u8]) -> Result<Plan<Msg, Model>, ReplayError> {
        let text = checked_header(bytes, self.0)?;
        let wire: WireIn<Msg, Model> = decode_body(text)?;
        match wire.start {
            Start::Init => bounded_plan(None, wire.msgs),
            Start::Base(base) => bounded_plan(Some(base), wire.msgs),
            Start::Lost => Err(ReplayError::Overflowed),
        }
    }
}

// ── Wire form ──────────────────────────────────────────────────────────────

/// Where a replay's fold starts, as written in the log.
#[derive(serde::Serialize, serde::Deserialize)]
enum Start<B> {
    /// From the program's `init`.
    Init,
    /// From the recorded rolling base.
    Base(B),
    /// The session overflowed and its base could not be encoded.
    Lost,
}

/// The log as written.
#[derive(serde::Serialize)]
struct WireOut<'a, Msg, B> {
    format: u32,
    msg_tag: String,
    model_tag: String,
    start: Start<B>,
    msgs: Vec<&'a Msg>,
}

/// The log's header, read before any typed value is decoded.
#[derive(serde::Deserialize)]
struct WireHeader {
    format: u32,
    msg_tag: String,
    model_tag: String,
    start: Start<serde::de::IgnoredAny>,
    // Present so a log without messages is malformed; skipped unread.
    #[allow(dead_code)] // required on the wire, never inspected
    msgs: serde::de::IgnoredAny,
}

/// The log's typed body; the header fields are skipped.
#[derive(serde::Deserialize)]
struct WireIn<Msg, B> {
    start: Start<B>,
    msgs: Vec<Msg>,
}

/// Lowercase hex of a schema tag, as written on the wire.
fn hex(tag: &SchemaTag) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(tag.len() * 2);
    for byte in tag {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Encode `buf`'s messages with `start` under the program's tags.
fn encode_wire<Msg, Model, B>(
    tags: Tags,
    start: Start<B>,
    buf: &RecordBuffer<Msg, Model>,
) -> Result<Vec<u8>, ReplayError>
where
    Msg: Clone + serde::Serialize,
    Model: Clone,
    B: serde::Serialize,
{
    let wire = WireOut {
        format: FORMAT,
        msg_tag: hex(&tags.msg),
        model_tag: hex(&tags.model),
        start,
        msgs: buf.msgs().collect(),
    };
    let mut bytes = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut bytes, ControlEscaping);
    serde::Serialize::serialize(&wire, &mut ser).map_err(|_| ReplayError::Encode)?;
    Ok(bytes)
}

/// Compact JSON that escapes every log hazard (`Cc ∪ Cf ∪ Zl ∪ Zp`), not only C0.
///
/// `serde_json` escapes `"`, `\` and the C0 range but writes `DEL`, the C1
/// controls (among them the single-character CSI and OSC introducers) and the
/// format characters (bidi overrides, zero-width characters, the tag block)
/// raw. Spelling every `crate::system::is_log_hazard` character through
/// `crate::escape::JsonHazardEscape`, the runtime's one JSON hazard spelling,
/// keeps the log file free of them by construction, so reading it with any
/// tool can neither drive nor reorder a terminal; the decoded values are
/// unchanged.
struct ControlEscaping;

impl serde_json::ser::Formatter for ControlEscaping {
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> std::io::Result<()>
    where
        W: ?Sized + Write,
    {
        let mut utf8 = [0u8; 4];
        for c in fragment.chars() {
            if crate::system::is_log_hazard(c) {
                write!(writer, "{}", crate::escape::JsonHazardEscape(c))?;
            } else {
                writer.write_all(c.encode_utf8(&mut utf8).as_bytes())?;
            }
        }
        Ok(())
    }
}

/// Classify a JSON decode failure: an early end is a truncation.
fn json_refusal(err: &serde_json::Error) -> ReplayError {
    if err.is_eof() {
        ReplayError::Truncated
    } else {
        ReplayError::Malformed
    }
}

/// Check a log's size, encoding, format and schema tags before any typed decode.
///
/// Returns the log as text for the typed decode.
fn checked_header(bytes: &[u8], tags: Tags) -> Result<&str, ReplayError> {
    if bytes.len() > DEFAULT_SEAL_MAX_INPUT_BYTES {
        return Err(ReplayError::Oversized {
            cap: DEFAULT_SEAL_MAX_INPUT_BYTES,
        });
    }
    let text = core::str::from_utf8(bytes).map_err(|_| ReplayError::NotUtf8)?;
    let header: WireHeader = serde_json::from_str(text).map_err(|e| json_refusal(&e))?;
    if header.format != FORMAT {
        return Err(ReplayError::UnsupportedFormat(header.format));
    }
    if header.msg_tag != hex(&tags.msg) {
        return Err(ReplayError::MsgTypeChanged);
    }
    match header.start {
        Start::Init => Ok(text),
        Start::Lost => Err(ReplayError::Overflowed),
        Start::Base(_) if header.model_tag != hex(&tags.model) => {
            Err(ReplayError::ModelTypeChanged)
        }
        Start::Base(_) => Ok(text),
    }
}

/// Decode the typed body of a log whose header already checked out.
fn decode_body<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, ReplayError> {
    serde_json::from_str(text).map_err(|e| json_refusal(&e))
}

/// Build a plan, refusing more messages than a recorder retains.
fn bounded_plan<Msg, Model>(
    base: Option<Model>,
    msgs: Vec<Msg>,
) -> Result<Plan<Msg, Model>, ReplayError> {
    if msgs.len() > DEFAULT_HISTORY_CAP {
        return Err(ReplayError::TooManySteps {
            cap: DEFAULT_HISTORY_CAP,
        });
    }
    Ok(Plan { base, msgs })
}

// ── Replay ─────────────────────────────────────────────────────────────────

/// Fold `plan` from its base (or `init_model`) and render every step.
///
/// One plain line for the start model, one `"<msg> => <model>"` line per step,
/// and one for the final model; each line passes through [`plain_line`], so no
/// log hazard (control, bidi, zero-width or tag character) from a decoded value
/// reaches the output. Every `Cmd` `update`
/// returns is dropped unrun.
#[must_use]
pub fn render_replay<Msg, Model, F>(plan: Plan<Msg, Model>, init_model: Model, update: &F) -> String
where
    Msg: IpeStringify,
    Model: IpeStringify,
    F: Fn(Msg, Model) -> (Model, IpeCmd<Msg>),
{
    let (origin, mut model) = plan
        .base
        .map_or(("init", init_model), |base| ("recorded base", base));
    let mut out = plain_line(&format!("start ({origin}): {}", model.ipe_show()));
    for msg in plan.msgs {
        let label = msg.ipe_show();
        let (next, _unrun) = update(msg, model);
        model = next;
        out.push_str(&plain_line(&format!("{label} => {}", model.ipe_show())));
    }
    out.push_str(&plain_line(&format!("final: {}", model.ipe_show())));
    out
}

/// The typed log a replay run reads, when `IPE_DEBUGGER_REPLAY` is set.
#[must_use]
pub fn replay_request() -> Option<PathBuf> {
    crate::system::read_env_var_os(crate::REPLAY_ENV).map(PathBuf::from)
}

/// Read at most the session-log cap from `path`.
fn read_capped(path: &Path) -> Result<Vec<u8>, ReplayError> {
    let file = std::fs::File::open(path).map_err(|e| ReplayError::Unreadable(e.kind()))?;
    let limit = u64::try_from(DEFAULT_SEAL_MAX_INPUT_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|e| ReplayError::Unreadable(e.kind()))?;
    if bytes.len() > DEFAULT_SEAL_MAX_INPUT_BYTES {
        return Err(ReplayError::Oversized {
            cap: DEFAULT_SEAL_MAX_INPUT_BYTES,
        });
    }
    Ok(bytes)
}

/// Decode the log at `path` whole and render its replay.
///
/// # Errors
/// The [`ReplayError`] naming why the log is refused; nothing is folded then.
pub fn replay_to_string<Msg, Model, C, F>(
    codec: &C,
    path: &Path,
    init_model: Model,
    update: &F,
) -> Result<String, ReplayError>
where
    C: SessionCodec<Msg, Model>,
    Msg: IpeStringify,
    Model: IpeStringify,
    F: Fn(Msg, Model) -> (Model, IpeCmd<Msg>),
{
    codec.replayable()?;
    let bytes = read_capped(path)?;
    let plan = codec.decode(&bytes)?;
    Ok(render_replay(plan, init_model, update))
}

/// Replay the log at `path` to stdout.
///
/// # Errors
/// The [`ReplayError`] naming why the log is refused; nothing is printed then.
pub fn replay_file<Msg, Model, C, F>(
    codec: &C,
    path: &Path,
    init_model: Model,
    update: &F,
) -> Result<(), ReplayError>
where
    C: SessionCodec<Msg, Model>,
    Msg: IpeStringify,
    Model: IpeStringify,
    F: Fn(Msg, Model) -> (Model, IpeCmd<Msg>),
{
    let out = replay_to_string(codec, path, init_model, update)?;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(out.as_bytes());
    let _ = lock.flush();
    Ok(())
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    enum Msg {
        Add(i64),
        Say(String),
    }
    #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Model {
        n: i64,
        last: String,
    }
    impl IpeStringify for Msg {
        fn ipe_show(&self) -> String {
            match self {
                Msg::Add(v) => format!("Add({v})"),
                Msg::Say(s) => format!("Say({s})"),
            }
        }
    }
    impl IpeStringify for Model {
        fn ipe_show(&self) -> String {
            format!("Model {{ n = {}, last = {} }}", self.n, self.last)
        }
    }
    fn update(msg: Msg, m: Model) -> (Model, IpeCmd<Msg>) {
        match msg {
            Msg::Add(v) => (
                Model {
                    n: m.n.saturating_add(v),
                    last: m.last,
                },
                IpeCmd::None,
            ),
            Msg::Say(s) => (Model { n: m.n, last: s }, IpeCmd::None),
        }
    }
    fn init() -> Model {
        Model {
            n: 0,
            last: String::new(),
        }
    }

    const MSG_TAG: SchemaTag = [1; 32];
    const MODEL_TAG: SchemaTag = [2; 32];

    fn full() -> Full {
        Full::new(MSG_TAG, MODEL_TAG)
    }

    /// Record `msgs` live into a ring of `cap`, returning the buffer and the
    /// live model after each step.
    fn record(msgs: &[Msg], cap: usize) -> (RecordBuffer<Msg, Model>, Vec<Model>) {
        let mut buf = RecordBuffer::new(init(), cap);
        let mut live = init();
        let mut models = Vec::new();
        for msg in msgs {
            let (next, _) = update(msg.clone(), live);
            live = next.clone();
            models.push(next.clone());
            buf.record(msg.clone(), next, &update);
        }
        (buf, models)
    }

    fn decode_full(bytes: &[u8]) -> Result<Plan<Msg, Model>, ReplayError> {
        SessionCodec::<Msg, Model>::decode(&full(), bytes)
    }

    fn encode_full(buf: &RecordBuffer<Msg, Model>) -> Vec<u8> {
        let encoded = full().encode(buf);
        assert!(encoded.is_ok(), "encode must succeed: {encoded:?}");
        encoded.unwrap_or_default()
    }

    // A replay prints the live session's models, from `init`, byte-identically
    // on every run.
    #[test]
    fn replay_matches_live_and_is_deterministic() {
        let msgs = [Msg::Add(2), Msg::Say("hi".into()), Msg::Add(5)];
        let (buf, live) = record(&msgs, 16);
        let bytes = encode_full(&buf);
        let plan_result = decode_full(&bytes);
        assert!(plan_result.is_ok(), "a fresh log must decode");
        let Ok(plan) = plan_result else { return };
        let first = render_replay(plan, init(), &update);
        let plan_result = decode_full(&bytes);
        assert!(plan_result.is_ok(), "a fresh log must decode");
        let Ok(plan) = plan_result else { return };
        let second = render_replay(plan, init(), &update);
        assert_eq!(first, second, "replaying twice must be byte-identical");
        let lines: Vec<&str> = first.lines().collect();
        assert_eq!(lines.len(), msgs.len() + 2, "start + steps + final");
        assert_eq!(
            lines.first().copied(),
            Some("start (init): Model { n = 0, last =  }")
        );
        for (i, model) in live.iter().enumerate() {
            let Some(msg) = msgs.get(i) else { return };
            let expected = format!("{} => {}", msg.ipe_show(), model.ipe_show());
            assert_eq!(lines.get(i + 1).copied(), Some(expected.as_str()));
        }
        assert_eq!(
            lines.last().copied(),
            Some("final: Model { n = 7, last = hi }")
        );
    }

    // cap + 1 steps overflow the ring: the log carries the rolling base and the
    // replay reproduces the live models, never a fold from `init`.
    #[test]
    fn overflowed_log_replays_from_recorded_base() {
        let cap = 4usize;
        let msgs: Vec<Msg> = (1..=5).map(Msg::Add).collect();
        let (buf, live) = record(&msgs, cap);
        assert!(buf.overflowed(), "cap + 1 steps must overflow the ring");
        let bytes = encode_full(&buf);
        let plan_result = decode_full(&bytes);
        assert!(plan_result.is_ok(), "an overflowed Full log must decode");
        let Ok(plan) = plan_result else { return };
        assert_eq!(
            plan.base.as_ref().map(|m| m.n),
            Some(1),
            "base after step 1"
        );
        let out = render_replay(plan, init(), &update);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.first().copied(),
            Some("start (recorded base): Model { n = 1, last =  }")
        );
        // The retained steps are live steps 2..=5.
        for (i, model) in live.iter().skip(1).enumerate() {
            let line_result = lines.get(i + 1);
            assert!(line_result.is_some(), "missing step line {i}");
            let Some(line) = line_result else { return };
            assert!(
                line.ends_with(&model.ipe_show()),
                "step {i}: {line} vs {model:?}"
            );
        }
    }

    // An overflowed session of a program whose Model has no encoding is
    // written with a lost start and refused at replay.
    #[test]
    fn overflowed_log_without_model_encoding_is_refused() {
        let codec = MsgsOnly::new(MSG_TAG, MODEL_TAG);
        let msgs: Vec<Msg> = (1..=5).map(Msg::Add).collect();
        let (buf, _) = record(&msgs, 4);
        let encoded = codec.encode(&buf);
        let bytes_result = encoded;
        assert!(bytes_result.is_ok(), "encode must succeed");
        let Ok(bytes) = bytes_result else { return };
        let decoded = SessionCodec::<Msg, Model>::decode(&codec, &bytes);
        assert!(matches!(decoded, Err(ReplayError::Overflowed)));

        // Not overflowed: the same codec replays from init.
        let (short, _) = record(&msgs, 16);
        let bytes_result = codec.encode(&short);
        assert!(bytes_result.is_ok(), "encode must succeed");
        let Ok(bytes) = bytes_result else { return };
        let plan = SessionCodec::<Msg, Model>::decode(&codec, &bytes);
        assert!(matches!(plan, Ok(Plan { base: None, .. })));
    }

    // A log recorded against a different Msg type is refused by name.
    #[test]
    fn changed_msg_type_is_refused() {
        let (buf, _) = record(&[Msg::Add(1)], 16);
        let bytes = encode_full(&buf);
        let other = Full::new([9; 32], MODEL_TAG);
        let decoded = SessionCodec::<Msg, Model>::decode(&other, &bytes);
        assert!(matches!(decoded, Err(ReplayError::MsgTypeChanged)));
    }

    // A recorded base of a different Model type is refused by name.
    #[test]
    fn changed_model_type_of_base_is_refused() {
        let msgs: Vec<Msg> = (1..=5).map(Msg::Add).collect();
        let (buf, _) = record(&msgs, 4);
        let bytes = encode_full(&buf);
        let other = Full::new(MSG_TAG, [9; 32]);
        let decoded = SessionCodec::<Msg, Model>::decode(&other, &bytes);
        assert!(matches!(decoded, Err(ReplayError::ModelTypeChanged)));
    }

    // Truncated, non-UTF-8, oversized, wrong-shape, future-format and
    // over-long logs are each refused whole.
    #[test]
    fn malformed_logs_are_refused() {
        let (buf, _) = record(&[Msg::Add(1), Msg::Add(2)], 16);
        let bytes = encode_full(&buf);

        let cut = bytes.get(..bytes.len() / 2).unwrap_or_default();
        assert!(matches!(decode_full(cut), Err(ReplayError::Truncated)));

        assert!(matches!(
            decode_full(&[0xff, 0xfe, 0x7b]),
            Err(ReplayError::NotUtf8)
        ));

        let oversized = vec![b' '; DEFAULT_SEAL_MAX_INPUT_BYTES + 1];
        assert!(matches!(
            decode_full(&oversized),
            Err(ReplayError::Oversized { .. })
        ));

        let tag = hex(&MSG_TAG);
        let model_tag = hex(&MODEL_TAG);
        let wrong_shape = format!(
            r#"{{"format":1,"msg_tag":"{tag}","model_tag":"{model_tag}","start":"Init","msgs":[42]}}"#
        );
        assert!(matches!(
            decode_full(wrong_shape.as_bytes()),
            Err(ReplayError::Malformed)
        ));

        let future = format!(
            r#"{{"format":2,"msg_tag":"{tag}","model_tag":"{model_tag}","start":"Init","msgs":[]}}"#
        );
        assert!(matches!(
            decode_full(future.as_bytes()),
            Err(ReplayError::UnsupportedFormat(2))
        ));

        let many = vec![r#"{"Add":1}"#; DEFAULT_HISTORY_CAP + 1].join(",");
        let too_many = format!(
            r#"{{"format":1,"msg_tag":"{tag}","model_tag":"{model_tag}","start":"Init","msgs":[{many}]}}"#
        );
        assert!(matches!(
            decode_full(too_many.as_bytes()),
            Err(ReplayError::TooManySteps { .. })
        ));
    }

    // A trace-only program writes no typed log and refuses replay with the
    // reason, before reading any file.
    #[test]
    fn trace_only_program_refuses_replay() {
        let codec = TraceOnly(Unreplayable::MsgNotEncodable);
        let (buf, _) = record(&[Msg::Add(1)], 16);
        assert!(matches!(
            codec.encode(&buf),
            Err(ReplayError::Unreplayable(Unreplayable::MsgNotEncodable))
        ));
        let replayed = replay_to_string(
            &codec,
            Path::new("/nonexistent/session.ipemsgs"),
            init(),
            &update,
        );
        let err_result = replayed;
        assert!(
            err_result.is_err(),
            "a trace-only program must refuse replay"
        );
        let Err(err) = err_result else { return };
        assert_eq!(
            err,
            ReplayError::Unreplayable(Unreplayable::MsgNotEncodable)
        );
        assert!(err.to_string().contains("Secret"), "{err}");
    }

    // A replay fires zero commands: the Cmd each step returns is dropped unrun.
    #[test]
    fn replay_fires_no_cmd() {
        let fired = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&fired);
        let effectful = move |msg: Msg, m: Model| -> (Model, IpeCmd<Msg>) {
            let flag = Arc::clone(&flag);
            let (next, _) = update(msg, m);
            let cmd = IpeCmd::Perform(Box::new(move || {
                flag.store(true, Ordering::SeqCst);
                Box::pin(async { Msg::Add(0) })
            }));
            (next, cmd)
        };
        let (buf, _) = record(&[Msg::Add(1), Msg::Add(2)], 16);
        let bytes = encode_full(&buf);
        let plan_result = decode_full(&bytes);
        assert!(plan_result.is_ok(), "a fresh log must decode");
        let Ok(plan) = plan_result else { return };
        let out = render_replay(plan, init(), &effectful);
        assert!(out.contains("final: Model { n = 3"), "{out}");
        assert!(!fired.load(Ordering::SeqCst), "a replay must fire no Cmd");
    }

    // A planted log whose values carry terminal escapes prints with every
    // control byte removed.
    #[test]
    fn replay_output_strips_control_bytes() {
        let laced = "\x1b[2J\x1b]8;;https://evil\x07link\x1b]8;;\x07\u{9b}31m";
        let (buf, _) = record(&[Msg::Say(laced.into())], 16);
        let bytes = encode_full(&buf);
        let plan_result = decode_full(&bytes);
        assert!(plan_result.is_ok(), "a fresh log must decode");
        let Ok(plan) = plan_result else { return };
        let out = render_replay(plan, init(), &update);
        assert!(
            !out.chars().any(|c| c.is_control() && c != '\n'),
            "replay output must carry no control byte: {out:?}"
        );
    }

    // The typed log on disk carries no raw control character: `DEL` and the C1
    // controls a `Msg` value holds are written escaped, and decode back intact.
    #[test]
    fn encoded_log_escapes_every_control_character() {
        let laced = "a\u{7f}b\u{9b}2J\u{9d}8;;https://evil\u{9c}\x1b[2Jc";
        let (buf, _) = record(&[Msg::Say(laced.into())], 16);
        let bytes = encode_full(&buf);
        let text_result = core::str::from_utf8(&bytes);
        assert!(text_result.is_ok(), "the log must be UTF-8");
        let Ok(text) = text_result else { return };
        assert!(
            !text.chars().any(char::is_control),
            "the log must carry no raw control character: {text:?}"
        );
        assert!(text.contains("\\u009b"), "C1 CSI must be escaped: {text}");
        let plan_result = decode_full(&bytes);
        assert!(plan_result.is_ok(), "an escaped log must decode");
        let Ok(plan) = plan_result else { return };
        assert_eq!(plan.msgs, vec![Msg::Say(laced.into())]);
    }

    // Format characters (bidi override, zero-width space, a tag character) a
    // `Msg` value holds are written escaped too, and decode back intact.
    #[test]
    fn encoded_log_escapes_every_format_hazard() {
        let laced = "a\u{202e}b\u{200b}c\u{e0041}d\u{2028}e";
        let (buf, _) = record(&[Msg::Say(laced.into())], 16);
        let bytes = encode_full(&buf);
        let text_result = core::str::from_utf8(&bytes);
        assert!(text_result.is_ok(), "the log must be UTF-8");
        let Ok(text) = text_result else { return };
        assert!(
            !text.chars().any(crate::system::is_log_hazard),
            "the log must carry no raw log hazard: {text:?}"
        );
        assert!(
            text.contains("\\u202e"),
            "bidi override must be escaped: {text}"
        );
        assert!(
            text.contains("\\udb40\\udc41"),
            "tag must be a surrogate pair: {text}"
        );
        let plan_result = decode_full(&bytes);
        assert!(plan_result.is_ok(), "an escaped log must decode");
        let Ok(plan) = plan_result else { return };
        assert_eq!(plan.msgs, vec![Msg::Say(laced.into())]);
    }

    // The capped read refuses an oversized file without reading it whole, and
    // a missing file is a typed refusal.
    #[test]
    fn capped_read_refuses_oversized_and_missing_files() {
        let dir = crate::scratch_core::test_temp_root()
            .join(format!("ipe_session_log_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(std::fs::create_dir_all(&dir).is_ok(), "make scratch dir");
        let big = dir.join("big.ipemsgs");
        assert!(
            std::fs::write(&big, vec![b' '; DEFAULT_SEAL_MAX_INPUT_BYTES + 1]).is_ok(),
            "write big log"
        );
        assert!(matches!(
            read_capped(&big),
            Err(ReplayError::Oversized { .. })
        ));
        assert!(matches!(
            read_capped(&dir.join("absent.ipemsgs")),
            Err(ReplayError::Unreadable(std::io::ErrorKind::NotFound))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

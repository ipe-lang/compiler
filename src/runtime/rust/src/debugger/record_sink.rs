//! The cli/worker record sink — dump a recorded session's portable replay log
//! to the destination named by `IPE_DEBUGGER_RECORD`, fail-closed to plain text.
//!
//! A run is recorded through [`start`], which reads the destination once and
//! registers the dump as the process's session-dump exit stage
//! (`crate::system::pre_exit`). The dump therefore runs on every exit the
//! funnel sees: the driver's normal end ([`Recording::finish`]), `System.exit`,
//! `Debug.todo`, an interrupt, and a panic that unwinds out of the loop. It
//! reads only the recorded values and runs no program code, and each of its
//! costs has a ceiling: [`DUMP_LOCK_WAIT`] for the recorder lock,
//! [`TRACE_MAX_BYTES`] for the trace, and the decoder's own cap for the typed
//! log.
//!
//! Beside a file destination it also writes the session's typed log (same
//! stem, extension [`crate::TYPED_LOG_EXTENSION`]) through the program's
//! [`SessionCodec`] — the replayable form `ipe dev run --replay` reads. A program
//! with no typed log (see [`crate::debugger::session_log`]) gets the trace
//! only, and any stale typed log from an earlier build is removed.
//!
//! Enabled only when the `debugger` feature is active. A non-`--debugger` build
//! carries zero code from this module.
//!
//! ## The output boundary (principle 1)
//!
//! The recorder's portable form ([`RecordBuffer::replay_log`]) is plain by
//! construction — every half renders through `IpeStringify::ipe_show`, which
//! emits no ANSI/control byte. This sink is the OUTPUT boundary that keeps it
//! plain regardless: [`plain_line`] strips every log hazard before a line
//! reaches a file/pipe, so a redirected log receives ZERO control codes and no
//! bidi, zero-width or tag character even if a body somehow carried one.
//! Absent proof the body is hazard-free, the sink still cannot feed one to the
//! destination — fail closed.
//!
//! The strip rule drops every `crate::system::is_log_hazard` character (Unicode
//! `Cc ∪ Cf ∪ Zl ∪ Zp`, the runtime's one hazard set, equal to the compiler's
//! `ipe_diagnostics::terminal::is_display_hazard`) and appends one settling
//! newline; a unit test here pins it against the compiler-side predicate for
//! every scalar value. A trace read back by the cli is sanitised again, line
//! by line, through `ipe_diagnostics::terminal::TerminalLine`, which drops the
//! same character set (and, unlike this filter, whole ANSI sequence bodies).

#![cfg(feature = "debugger")]

use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::{Duration, Instant};

use crate::debugger::RecordBuffer;
use crate::debugger::session_log::{ReplayError, SessionCodec};
use crate::stringify::IpeStringify;
use crate::system::pre_exit::{ExitDump, PreExitStages, Registration, StageRefused, StageTicket};
use crate::tea::IpeCmd;
use crate::{RECORD_ENV, TYPED_LOG_EXTENSION};

/// How long the dump waits for the recorder before it skips the session.
pub const DUMP_LOCK_WAIT: Duration = Duration::from_millis(250);

/// How often the dump retries a busy recorder within [`DUMP_LOCK_WAIT`].
const DUMP_LOCK_POLL: Duration = Duration::from_millis(1);

/// The most bytes a written trace holds: the session-log decoder's cap.
pub const TRACE_MAX_BYTES: usize = crate::seal_codec::DEFAULT_SEAL_MAX_INPUT_BYTES;

/// The phrase of the line that opens a trace cut to [`TRACE_MAX_BYTES`],
/// between the count of omitted steps and the cap.
const TRACE_OMITTED: &str = "earlier steps omitted: trace limit";

/// The sentinel `IPE_DEBUGGER_RECORD` value that selects stderr over a file.
const STDERR_SENTINEL: &str = "-";

/// Where a record dump lands: stderr, or a filesystem path.
///
/// A parsed value at the boundary (parse, don't validate): the raw env string is
/// turned into this two-variant choice once, so the writer never re-inspects the
/// sentinel. Absent env ⇒ no `RecordDest` at all (the dump is skipped upstream).
enum RecordDest {
    /// The `-` sentinel: write the dump to stderr.
    Stderr,
    /// A filesystem path: create/truncate and write the dump there.
    Path(std::path::PathBuf),
}

impl RecordDest {
    /// Parse the raw `IPE_DEBUGGER_RECORD` value into a destination.
    fn parse(raw: &str) -> Self {
        if raw == STDERR_SENTINEL {
            Self::Stderr
        } else {
            Self::Path(std::path::PathBuf::from(raw))
        }
    }
}

/// Render one replay-log line as plain, hazard-free text ending in exactly one
/// newline — the fail-closed output-boundary form.
///
/// Every `crate::system::is_log_hazard` character is stripped (C0/C1 and DEL —
/// every ANSI-escape introducer, carriage return and cursor-motion byte — plus
/// the bidi, zero-width, tag and line/paragraph-separator characters), then a
/// single settling newline is appended. A test in this module pins the rule.
#[must_use]
pub fn plain_line(body: &str) -> String {
    let mut plain: String = body
        .chars()
        .filter(|&c| !crate::system::is_log_hazard(c))
        .collect();
    plain.push('\n');
    plain
}

/// Render the whole replay log as one plain, control-free blob — one
/// `"<msg> => <model>"` line per retained step, each through [`plain_line`],
/// held to [`TRACE_MAX_BYTES`] (see [`render_capped`]).
///
/// Pure: it reads the recorded models, runs no `update`, fires no `Cmd` and
/// does no I/O.
#[must_use]
pub fn render_replay_blob<Msg, Model>(buf: &RecordBuffer<Msg, Model>) -> String
where
    Msg: Clone + IpeStringify,
    Model: Clone + IpeStringify,
{
    render_capped(buf, TRACE_MAX_BYTES)
}

/// The line that opens a trace from which `omitted` steps were cut at `cap`.
fn omitted_line(omitted: usize, cap: usize) -> String {
    plain_line(&format!("{omitted} {TRACE_OMITTED} {cap} bytes"))
}

/// The replay blob in at most `cap` bytes: the newest whole lines that fit.
///
/// When every line fits, the blob is every line. Otherwise it renders from
/// the newest step back, stops at the first line that does not fit, and
/// opens with one [`omitted_line`] that counts against `cap`. At most one
/// line past the kept ones is ever rendered, so the peak is `cap` plus one
/// line.
fn render_capped<Msg, Model>(buf: &RecordBuffer<Msg, Model>, cap: usize) -> String
where
    Msg: Clone + IpeStringify,
    Model: Clone + IpeStringify,
{
    let total = buf.len();
    let mut kept: Vec<String> = Vec::new();
    let mut used = 0usize;
    for line in buf.replay_lines().rev().map(|line| plain_line(&line)) {
        match used.checked_add(line.len()) {
            Some(next) if next <= cap => {
                used = next;
                kept.push(line);
            }
            _ => break,
        }
    }
    let mut out = String::new();
    if kept.len() < total {
        loop {
            let marker = omitted_line(total.saturating_sub(kept.len()), cap);
            if used.saturating_add(marker.len()) <= cap {
                out.push_str(&marker);
                break;
            }
            let Some(oldest) = kept.pop() else {
                return String::new();
            };
            used = used.saturating_sub(oldest.len());
        }
    }
    for line in kept.iter().rev() {
        out.push_str(line);
    }
    out
}

/// Write an already-plain replay `blob` to `dest`.
///
/// A write error never fails the program — the record dump is advisory dev tooling and must never turn a
/// working app into a failing one over a closed pipe or an unwritable path —
/// but a file that cannot be written is reported once (see [`report_unwritten`]).
fn write_blob(dest: &RecordDest, blob: &str) {
    match dest {
        RecordDest::Stderr => {
            let stderr = std::io::stderr();
            let mut lock = stderr.lock();
            let _ = lock.write_all(blob.as_bytes());
            let _ = lock.flush();
        }
        RecordDest::Path(path) => {
            if let Err(e) = replace_file(path, blob.as_bytes()) {
                report_unwritten(path, &e);
            }
        }
    }
}

/// Report, on the runtime log, a record file that was not written and why.
fn report_unwritten(path: &std::path::Path, err: &std::io::Error) {
    crate::system::emit_runtime_log(
        "debugger",
        &format!("record file {} not written: {err}", path.display()),
    );
}

/// The refusal of a record destination that is a symbolic link.
#[derive(Debug)]
struct SymlinkedDestination;

impl std::fmt::Display for SymlinkedDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the destination is a symbolic link; name a regular file instead")
    }
}

impl std::error::Error for SymlinkedDestination {}

/// Replace `path` with `bytes` through an [`AtomicSibling`](crate::scratch_core::AtomicSibling).
///
/// The sibling has an unguessable hidden name, is created exclusively, never
/// through a symlink, with mode 0600, and is renamed over `path`, so the dump
/// never writes through a symlink planted at the destination; a symlinked
/// destination is refused outright. A refused or failed write removes the
/// sibling.
///
/// # Errors
/// `InvalidInput` carrying [`SymlinkedDestination`] when `path` is a symbolic
/// link; any sibling creation, write or rename error.
fn replace_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            SymlinkedDestination,
        ));
    }
    let mut sibling = crate::scratch_core::AtomicSibling::create(path)?;
    sibling.write_all(bytes)?;
    sibling.commit()
}

/// Where the typed log beside the trace at `trace` lives, unless the trace's
/// own name would be reused.
fn typed_log_path(trace: &std::path::Path) -> Option<std::path::PathBuf> {
    let typed = trace.with_extension(TYPED_LOG_EXTENSION);
    (typed != trace).then_some(typed)
}

/// Remove a stale typed log at `typed`. `remove_file` on a symlink removes
/// the link, never its target.
fn remove_stale(typed: &std::path::Path) {
    if std::fs::symlink_metadata(typed).is_ok() {
        let _ = std::fs::remove_file(typed);
    }
}

/// Write the typed log for `buf` beside the trace at `trace`.
///
/// A program with no typed log removes any stale one instead, so a replay can
/// never pick up a log an earlier build of the program wrote. A log the encoder
/// refuses (past the decoder's cap, or a value that would not encode) is not
/// written, removes the stale one and is reported; a typed log that cannot be
/// written is reported like the trace (see [`report_unwritten`]).
fn write_typed_log<Msg, Model, C>(
    trace: &std::path::Path,
    buf: &RecordBuffer<Msg, Model>,
    codec: &C,
) where
    C: SessionCodec<Msg, Model>,
{
    let Some(typed) = typed_log_path(trace) else {
        return;
    };
    match codec.encode(buf) {
        Ok(bytes) => {
            if let Err(e) = replace_file(&typed, &bytes) {
                report_unwritten(&typed, &e);
            }
        }
        Err(ReplayError::Unreplayable(_)) => remove_stale(&typed),
        Err(refused) => {
            remove_stale(&typed);
            crate::system::emit_runtime_log(
                "debugger",
                &format!("typed log {} not written: {refused}", typed.display()),
            );
        }
    }
}

/// Why a session dump wrote less than the whole session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DumpSkipped {
    /// The recorder stayed locked past [`DUMP_LOCK_WAIT`]; nothing was written.
    RecorderBusy,
    /// A panic interrupted the recorder, so its base and steps may disagree:
    /// the trace was written, the typed log was not.
    Interrupted,
}

impl core::fmt::Display for DumpSkipped {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RecorderBusy => write!(
                f,
                "session not recorded: the recorder stayed busy past {} ms",
                DUMP_LOCK_WAIT.as_millis()
            ),
            Self::Interrupted => f.write_str(
                "session typed log not written: a panic interrupted the recorder; \
                 the trace was written",
            ),
        }
    }
}

/// The recorder as the dump found it.
enum Held<'a, T> {
    /// No panic touched it.
    Whole(MutexGuard<'a, T>),
    /// A panic unwound while it was locked.
    Torn(MutexGuard<'a, T>),
}

/// Lock `buf` within `wait`, retrying every [`DUMP_LOCK_POLL`].
fn lock_within<T>(buf: &Mutex<T>, wait: Duration) -> Result<Held<'_, T>, DumpSkipped> {
    let started = Instant::now();
    loop {
        match buf.try_lock() {
            Ok(guard) => return Ok(Held::Whole(guard)),
            Err(TryLockError::Poisoned(poisoned)) => return Ok(Held::Torn(poisoned.into_inner())),
            Err(TryLockError::WouldBlock) => {
                if started.elapsed() >= wait {
                    return Err(DumpSkipped::RecorderBusy);
                }
                std::thread::sleep(DUMP_LOCK_POLL);
            }
        }
    }
}

/// Dump the session `buf` holds to `dest`, waiting at most `wait` for it.
///
/// The plain trace is rendered by [`render_replay_blob`] and written to
/// `dest`, so a redirected log or file receives only plain, control-free
/// lines. A file destination also gets the typed log beside it (see
/// [`write_typed_log`]).
///
/// # Errors
/// [`DumpSkipped::RecorderBusy`] when the recorder stays locked past `wait`;
/// [`DumpSkipped::Interrupted`] when a panic left it torn.
fn dump_recorded<Msg, Model, C>(
    buf: &Mutex<RecordBuffer<Msg, Model>>,
    codec: &C,
    dest: &RecordDest,
    wait: Duration,
) -> Result<(), DumpSkipped>
where
    Msg: Clone + IpeStringify,
    Model: Clone + IpeStringify,
    C: SessionCodec<Msg, Model>,
{
    match lock_within(buf, wait)? {
        Held::Whole(buf) => {
            write_blob(dest, &render_replay_blob(&buf));
            if let RecordDest::Path(path) = dest {
                write_typed_log(path, &buf, codec);
            }
            Ok(())
        }
        Held::Torn(buf) => {
            write_blob(dest, &render_replay_blob(&buf));
            if let RecordDest::Path(path) = dest
                && let Some(typed) = typed_log_path(path)
            {
                remove_stale(&typed);
            }
            Err(DumpSkipped::Interrupted)
        }
    }
}

/// The session-dump exit stage of one recorded run.
struct SessionDump<Msg, Model, C> {
    buf: Arc<Mutex<RecordBuffer<Msg, Model>>>,
    codec: C,
    dest: RecordDest,
}

impl<Msg, Model, C> ExitDump for SessionDump<Msg, Model, C>
where
    Msg: Clone + IpeStringify,
    Model: Clone + IpeStringify,
    C: SessionCodec<Msg, Model>,
{
    fn dump(self: Box<Self>) {
        if let Err(skipped) = dump_recorded(&self.buf, &self.codec, &self.dest, DUMP_LOCK_WAIT) {
            crate::system::emit_runtime_log("debugger", &skipped.to_string());
        }
    }
}

/// A run being recorded: the recorder and the hold on its dump stage.
pub struct Recording<'s, Msg, Model> {
    buf: Arc<Mutex<RecordBuffer<Msg, Model>>>,
    ticket: StageTicket<'s>,
}

impl<Msg: Clone, Model: Clone> Recording<'_, Msg, Model> {
    /// Record one accepted step. The recorder is locked only for the step.
    pub fn record<F>(&self, msg: Msg, model_after: Model, update: &F)
    where
        F: Fn(Msg, Model) -> (Model, IpeCmd<Msg>),
    {
        self.buf
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .record(msg, model_after, update);
    }

    /// Dump the session now, at the run's normal end, unless the exit already
    /// did.
    pub fn finish(self) {
        self.ticket.retire();
    }
}

/// Why a run is not recorded.
#[derive(Debug, PartialEq, Eq)]
enum NotRecording {
    /// `IPE_DEBUGGER_RECORD` is unset.
    Unset,
    /// The dump stage was refused.
    Refused(StageRefused),
}

/// The runtime-log line of a recorder whose dump stage was refused.
fn refused_line(refused: StageRefused) -> &'static str {
    match refused {
        StageRefused::Held(_) => "session not recorded: another recorder holds the record stage",
        StageRefused::Exiting => "session not recorded: the process is exiting",
    }
}

/// Start recording a run from `initial` into `stages`, dumping to `dest`.
fn start_in<Msg, Model, C>(
    stages: &PreExitStages,
    dest: Option<RecordDest>,
    initial: Model,
    codec: C,
) -> Result<Recording<'_, Msg, Model>, NotRecording>
where
    Msg: Clone + Send + IpeStringify + 'static,
    Model: Clone + Send + IpeStringify + 'static,
    C: SessionCodec<Msg, Model> + Send + 'static,
{
    let dest = dest.ok_or(NotRecording::Unset)?;
    let buf = Arc::new(Mutex::new(RecordBuffer::new(
        initial,
        crate::debugger::DEFAULT_HISTORY_CAP,
    )));
    let stage = SessionDump {
        buf: Arc::clone(&buf),
        codec,
        dest,
    };
    let ticket = stages
        .register(Registration::SessionDump(Box::new(stage)))
        .map_err(NotRecording::Refused)?;
    Ok(Recording { buf, ticket })
}

/// Start recording a run from `initial`, when `IPE_DEBUGGER_RECORD` names a
/// destination.
///
/// The variable is read and parsed once, here. Unset, nothing is recorded and
/// no stage is registered. A dump stage another recorder holds is reported
/// once on the runtime log and the run goes unrecorded: two dumps never race
/// on one destination.
pub fn start<Msg, Model, C>(initial: Model, codec: C) -> Option<Recording<'static, Msg, Model>>
where
    Msg: Clone + Send + IpeStringify + 'static,
    Model: Clone + Send + IpeStringify + 'static,
    C: SessionCodec<Msg, Model> + Send + 'static,
{
    let dest = crate::system::read_env_var(RECORD_ENV)
        .ok()
        .map(|raw| RecordDest::parse(&raw));
    match start_in(crate::system::pre_exit::stages(), dest, initial, codec) {
        Ok(recording) => Some(recording),
        Err(NotRecording::Unset) => None,
        Err(NotRecording::Refused(refused)) => {
            crate::system::emit_runtime_log("debugger", refused_line(refused));
            None
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    enum Msg {
        Add(i64),
    }
    #[derive(Clone, Debug, PartialEq)]
    struct Model {
        n: i64,
    }
    impl IpeStringify for Msg {
        fn ipe_show(&self) -> String {
            let Msg::Add(v) = self;
            format!("Add({v})")
        }
    }
    impl IpeStringify for Model {
        fn ipe_show(&self) -> String {
            format!("Model {{ n = {} }}", self.n)
        }
    }
    fn update(msg: Msg, m: Model) -> (Model, IpeCmd<Msg>) {
        let Msg::Add(v) = msg;
        (Model { n: m.n + v }, IpeCmd::None)
    }

    // plain_line strips every control byte and settles with exactly one newline
    // — the fail-closed output boundary. A control-laced body reaches the sink
    // as plain text with zero control codes.
    #[test]
    fn plain_line_strips_all_control_bytes() {
        let laced = "\x1b[31mModel { n = 7 }\x1b[0m\r\x1b[2K\x07";
        let out = plain_line(laced);
        assert!(out.ends_with('\n'), "plain line settles with a newline");
        let body = out.strip_suffix('\n').expect("trailing newline");
        assert!(
            !body.chars().any(char::is_control),
            "off-TTY record line must carry zero control bytes; got: {body:?}"
        );
        assert!(!body.contains('\x1b'), "no ANSI escape may survive");
        // Printable payload preserved verbatim; only control bytes drop.
        assert_eq!(body, "[31mModel { n = 7 }[0m[2K");
    }

    // plain_line drops the whole hazard set (`Cc ∪ Cf ∪ Zl ∪ Zp`), not only
    // controls: a bidi override, zero-width space, tag character or line
    // separator in a model string never reaches the replay dump.
    #[test]
    fn plain_line_drops_the_hazard_set() {
        assert_eq!(
            plain_line("a\u{202E}b\u{200B}c\u{E0041}d\u{2028}e\x1b"),
            "abcde\n"
        );
        for c in (0..=u32::from(char::MAX)).filter_map(char::from_u32) {
            let expected = if ipe_diagnostics::terminal::is_display_hazard(c) {
                "\n".to_string()
            } else {
                format!("{c}\n")
            };
            assert_eq!(
                plain_line(&c.to_string()),
                expected,
                "U+{:04X}",
                u32::from(c)
            );
        }
    }

    // render_replay_blob is the plain replay log: one `"<msg> => <model>"` line
    // per step, zero control codes, bounded by the ring cap. No env, no I/O.
    #[test]
    fn render_replay_blob_is_plain_replay_log() {
        let mut buf = RecordBuffer::new(Model { n: 0 }, 8);
        let msgs = [Msg::Add(2), Msg::Add(5)];
        let mut live = Model { n: 0 };
        for msg in &msgs {
            let (next, _) = update(msg.clone(), live.clone());
            live = next.clone();
            buf.record(msg.clone(), next, &update);
        }
        let blob = render_replay_blob(&buf);
        assert_eq!(
            blob,
            "Add(2) => Model { n = 2 }\nAdd(5) => Model { n = 7 }\n"
        );
        assert!(
            !blob.chars().any(|c| c.is_control() && c != '\n'),
            "record blob must carry no control code other than line breaks; got: {blob:?}"
        );
    }

    // An empty session renders an empty blob — no spurious line, no panic.
    #[test]
    fn render_replay_blob_empty_session_is_empty() {
        let buf: RecordBuffer<Msg, Model> = RecordBuffer::new(Model { n: 0 }, 8);
        assert_eq!(render_replay_blob(&buf), "");
    }

    // The `-` sentinel parses to stderr; anything else is a path.
    #[test]
    fn record_dest_parse_sentinel_and_path() {
        assert!(matches!(RecordDest::parse("-"), RecordDest::Stderr));
        assert!(matches!(
            RecordDest::parse("/tmp/session.log"),
            RecordDest::Path(p) if p == std::path::Path::new("/tmp/session.log")
        ));
    }

    // Past the cap the rendered blob holds exactly `cap` lines — the dump is
    // bounded by the recorder's ring, never unbounded (principle 3 / principle 1
    // resource-exhaustion floor).
    #[test]
    fn render_replay_blob_is_bounded_by_ring_cap() {
        let cap = 4usize;
        let mut buf = RecordBuffer::new(Model { n: 0 }, cap);
        let mut live = Model { n: 0 };
        for i in 1..=20i64 {
            let (next, _) = update(Msg::Add(i), live.clone());
            live = next.clone();
            buf.record(Msg::Add(i), next, &update);
        }
        let blob = render_replay_blob(&buf);
        let lines = blob.lines().count();
        assert_eq!(lines, cap, "rendered blob must hold exactly cap lines");
    }

    // The dump replaces a regular file, and refuses a symlinked destination
    // without touching the link's target.
    #[cfg(unix)]
    #[test]
    fn replace_file_never_writes_through_a_symlink() {
        let dir = crate::scratch_core::test_temp_root()
            .join(format!("ipe_record_sink_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(std::fs::create_dir_all(&dir).is_ok(), "make scratch dir");

        let log = dir.join("session.ipelog");
        assert!(replace_file(&log, b"first\n").is_ok(), "fresh write");
        assert!(replace_file(&log, b"second\n").is_ok(), "replacing write");
        assert_eq!(
            std::fs::read_to_string(&log).ok().as_deref(),
            Some("second\n")
        );

        let victim = dir.join("victim.txt");
        assert!(std::fs::write(&victim, "keep").is_ok(), "write victim");
        let link = dir.join("linked.ipelog");
        assert!(
            std::os::unix::fs::symlink(&victim, &link).is_ok(),
            "plant link"
        );
        let refused = replace_file(&link, b"evil").err();
        assert_eq!(
            refused.as_ref().map(std::io::Error::kind),
            Some(std::io::ErrorKind::InvalidInput),
            "a symlinked log is refused"
        );
        assert!(
            refused
                .as_ref()
                .and_then(std::io::Error::get_ref)
                .is_some_and(|e| e.is::<SymlinkedDestination>()),
            "the refusal is typed"
        );
        assert_eq!(
            std::fs::read_to_string(&victim).ok().as_deref(),
            Some("keep")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Neither a written dump nor a failed one leaves its temp sibling behind.
    #[test]
    fn replace_file_leaves_only_the_destination() {
        let dir = crate::scratch_core::test_temp_root()
            .join(format!("ipe_record_sink_tmp_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = dir.join("session.ipelog");
        let blocked = dir.join("blocked.ipelog");
        assert!(
            std::fs::create_dir_all(blocked.join("x")).is_ok(),
            "make a non-empty dir at the blocked destination"
        );
        assert!(replace_file(&log, b"dump\n").is_ok(), "fresh write");
        assert!(replace_file(&blocked, b"dump\n").is_err(), "rename refused");
        let mut left: Vec<_> = std::fs::read_dir(&dir).map_or_else(
            |_| Vec::new(),
            |it| it.filter_map(|e| e.ok().map(|e| e.file_name())).collect(),
        );
        left.sort();
        assert_eq!(
            left,
            vec![
                std::ffi::OsString::from("blocked.ipelog"),
                std::ffi::OsString::from("session.ipelog")
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A message whose rendered line is `width` bytes of text past its label.
    #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Pad(String);
    impl IpeStringify for Pad {
        fn ipe_show(&self) -> String {
            self.0.clone()
        }
    }
    fn pad_update(msg: Pad, _: Pad) -> (Pad, IpeCmd<Pad>) {
        (msg, IpeCmd::None)
    }

    /// A ring of `count` steps whose trace lines are each `width + 5` bytes
    /// (`"<text> => <text>\n"` with the text half each side).
    fn padded(count: usize, width: usize) -> RecordBuffer<Pad, Pad> {
        let mut buf = RecordBuffer::new(Pad(String::new()), count.max(1));
        for i in 0..count {
            let text = format!("{i:0half$}", half = width / 2);
            buf.record(Pad(text.clone()), Pad(text), &pad_update);
        }
        buf
    }

    /// A scratch directory for one test, fresh.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = crate::scratch_core::test_temp_root()
            .join(format!("ipe_record_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(std::fs::create_dir_all(&dir).is_ok(), "make scratch dir");
        dir
    }

    // The dump reads the recorded models: rendering a recorded session never
    // calls `update`, so the exit path runs no program code.
    #[test]
    fn dump_reads_recorded_models_never_runs_update() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        fn counting(msg: Msg, m: Model) -> (Model, IpeCmd<Msg>) {
            CALLS.fetch_add(1, Ordering::SeqCst);
            update(msg, m)
        }
        let mut buf = RecordBuffer::new(Model { n: 0 }, 8);
        let mut live = Model { n: 0 };
        for i in 1..=5 {
            let (next, _) = update(Msg::Add(i), live);
            live = next.clone();
            buf.record(Msg::Add(i), next, &counting);
        }
        let before = CALLS.load(Ordering::SeqCst);
        let blob = render_replay_blob(&buf);
        assert_eq!(blob.lines().count(), 5);
        assert_eq!(CALLS.load(Ordering::SeqCst), before, "the dump ran update");
    }

    // Past the cap the trace keeps the newest whole steps, opened by one
    // marker naming exactly how many older steps it omitted.
    #[test]
    fn trace_keeps_the_newest_steps_within_the_cap() {
        let buf = padded(40, 200);
        let line = 205usize;
        assert_eq!(
            buf.replay_lines().map(|l| plain_line(&l).len()).max(),
            Some(line)
        );
        // Ten whole lines fill the cap exactly, so the marker evicts one.
        let cap = line * 10;
        let blob = render_capped(&buf, cap);
        assert!(blob.len() <= cap, "{} > {cap}", blob.len());
        let lines: Vec<&str> = blob.lines().collect();
        let kept = lines.len().saturating_sub(1);
        assert_eq!(
            lines.first().copied(),
            Some(omitted_line(40 - kept, cap).trim_end()),
            "the marker names the exact omitted count"
        );
        let newest = buf.replay_log().pop().unwrap_or_default();
        assert_eq!(lines.last().copied(), Some(newest.as_str()));
        assert_eq!(kept, 9, "the marker takes the room of one line");
    }

    // A trace of exactly the cap keeps every line and no marker; one byte
    // under it omits exactly the oldest step.
    #[test]
    fn trace_one_line_past_the_cap_omits_exactly_one() {
        let buf = padded(6, 200);
        let whole = render_capped(&buf, usize::MAX);
        let at_cap = render_capped(&buf, whole.len());
        assert_eq!(at_cap, whole, "a trace at the cap keeps every line");
        let past = render_capped(&buf, whole.len() - 1);
        let lines: Vec<&str> = past.lines().collect();
        assert_eq!(
            lines.first().copied(),
            Some(omitted_line(1, whole.len() - 1).trim_end())
        );
        assert_eq!(lines.len(), 6, "one marker and the five newest steps");
        assert!(past.len() < whole.len());
    }

    // A cap too small for even the marker writes nothing rather than a line
    // past it.
    #[test]
    fn trace_cap_below_the_marker_writes_nothing() {
        let buf = padded(3, 200);
        assert_eq!(render_capped(&buf, 8), "");
    }

    // A typed log past the decoder's cap is refused at encode: no file is
    // written and a stale one is removed.
    #[test]
    fn oversized_typed_log_is_refused_not_written() {
        use crate::debugger::session_log::Full;
        let dir = scratch("oversized");
        let trace = dir.join("session.ipelog");
        let typed = dir.join(format!("session.{TYPED_LOG_EXTENSION}"));
        assert!(std::fs::write(&typed, "stale").is_ok(), "plant stale log");
        let mut buf = RecordBuffer::new(Pad(String::new()), 4);
        let huge = "a".repeat(TRACE_MAX_BYTES);
        buf.record(Pad(huge.clone()), Pad(huge), &pad_update);
        let codec = Full::new([1; 32], [2; 32]);
        assert_eq!(
            SessionCodec::<Pad, Pad>::encode(&codec, &buf).map(|b| b.len()),
            Err(ReplayError::Oversized {
                cap: TRACE_MAX_BYTES
            })
        );
        write_typed_log(&trace, &buf, &codec);
        assert!(
            std::fs::symlink_metadata(&typed).is_err(),
            "an oversized log must leave no typed log"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A recorder another thread holds past the wait is skipped, in bounded
    // time, with nothing written.
    #[test]
    fn a_busy_recorder_skips_within_the_wait() {
        use crate::debugger::session_log::{TraceOnly, Unreplayable};
        let dir = scratch("busy");
        let trace = dir.join("session.ipelog");
        let buf = Arc::new(Mutex::new(RecordBuffer::<Msg, Model>::new(
            Model { n: 0 },
            8,
        )));
        let held = buf.lock().unwrap_or_else(PoisonError::into_inner);
        let dumping = Arc::clone(&buf);
        let dest = RecordDest::Path(trace.clone());
        let started = Instant::now();
        let outcome = std::thread::scope(|scope| {
            std::thread::Builder::new()
                .spawn_scoped(scope, || {
                    dump_recorded(
                        &dumping,
                        &TraceOnly(Unreplayable::MsgNotEncodable),
                        &dest,
                        DUMP_LOCK_WAIT,
                    )
                })
                .map(std::thread::ScopedJoinHandle::join)
        });
        let elapsed = started.elapsed();
        drop(held);
        assert!(matches!(outcome, Ok(Ok(Err(DumpSkipped::RecorderBusy)))));
        assert!(elapsed < DUMP_LOCK_WAIT * 2, "waited {elapsed:?}");
        assert!(
            std::fs::symlink_metadata(&trace).is_err(),
            "nothing is written"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A recorder a panic left torn still yields its trace, but never a typed
    // log whose base and steps may disagree; a stale one is removed.
    #[allow(clippy::panic)] // test: the panic poisons the recorder on purpose
    #[test]
    fn a_poisoned_recorder_writes_the_trace_not_the_typed_log() {
        use crate::debugger::session_log::Full;
        let dir = scratch("poisoned");
        let trace = dir.join("session.ipelog");
        let typed = dir.join(format!("session.{TYPED_LOG_EXTENSION}"));
        assert!(std::fs::write(&typed, "stale").is_ok(), "plant stale log");
        let buf = Arc::new(Mutex::new(padded(2, 8)));
        let poisoner = Arc::clone(&buf);
        let poisoning = std::thread::Builder::new().spawn(move || {
            let _held = poisoner.lock();
            panic!("a panic inside the recorder");
        });
        assert!(poisoning.is_ok_and(|t| t.join().is_err()));
        assert!(buf.is_poisoned());
        let outcome = dump_recorded(
            &buf,
            &Full::new([1; 32], [2; 32]),
            &RecordDest::Path(trace.clone()),
            DUMP_LOCK_WAIT,
        );
        assert_eq!(outcome, Err(DumpSkipped::Interrupted));
        assert_eq!(
            std::fs::read_to_string(&trace)
                .ok()
                .map(|t| t.lines().count()),
            Some(2)
        );
        assert!(
            std::fs::symlink_metadata(&typed).is_err(),
            "a torn recorder must leave no typed log"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // An unset destination records nothing and leaves the dump stage free.
    #[test]
    fn absent_record_env_registers_no_stage() {
        use crate::debugger::session_log::{TraceOnly, Unreplayable};
        let stages = &PreExitStages::new();
        let started = start_in::<Msg, Model, _>(
            stages,
            None,
            Model { n: 0 },
            TraceOnly(Unreplayable::MsgNotEncodable),
        );
        assert!(matches!(started, Err(NotRecording::Unset)));
        let free = stages.register(Registration::SessionDump(Box::new(SessionDump {
            buf: Arc::new(Mutex::new(RecordBuffer::<Msg, Model>::new(
                Model { n: 0 },
                1,
            ))),
            codec: TraceOnly(Unreplayable::MsgNotEncodable),
            dest: RecordDest::Stderr,
        })));
        assert!(free.is_ok(), "the dump stage was taken: {free:?}");
    }

    // A second recorder is refused, never a second dump racing on one
    // destination, and the refusal has its own runtime-log line.
    #[test]
    fn a_second_recorder_is_refused_and_reported() {
        use crate::debugger::session_log::{TraceOnly, Unreplayable};
        let stages = &PreExitStages::new();
        let first = start_in::<Msg, Model, _>(
            stages,
            Some(RecordDest::Stderr),
            Model { n: 0 },
            TraceOnly(Unreplayable::MsgNotEncodable),
        );
        assert!(first.is_ok());
        let second = start_in::<Msg, Model, _>(
            stages,
            Some(RecordDest::Stderr),
            Model { n: 0 },
            TraceOnly(Unreplayable::MsgNotEncodable),
        );
        let Err(NotRecording::Refused(refused)) = second else {
            unreachable!("a second recorder was accepted");
        };
        assert_eq!(
            refused,
            StageRefused::Held(crate::system::pre_exit::StageKind::SessionDump)
        );
        assert_eq!(
            refused_line(refused),
            "session not recorded: another recorder holds the record stage"
        );
    }

    // A program with no typed log removes a stale one beside the trace, so a
    // replay never reads a log an earlier build wrote.
    #[test]
    fn trace_only_program_removes_stale_typed_log() {
        use crate::debugger::session_log::{TraceOnly, Unreplayable};
        let dir = crate::scratch_core::test_temp_root()
            .join(format!("ipe_record_typed_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(std::fs::create_dir_all(&dir).is_ok(), "make scratch dir");
        let trace = dir.join("session.ipelog");
        let typed = dir.join("session.ipemsgs");
        assert!(std::fs::write(&typed, "stale").is_ok(), "plant stale log");
        let buf: RecordBuffer<Msg, Model> = RecordBuffer::new(Model { n: 0 }, 8);
        write_typed_log(&trace, &buf, &TraceOnly(Unreplayable::MsgNotEncodable));
        assert!(
            std::fs::symlink_metadata(&typed).is_err(),
            "the stale typed log must be removed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

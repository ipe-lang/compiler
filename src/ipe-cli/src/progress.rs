//! The stage-progress renderer: the one shape every multi-step `ipe` command
//! uses to report a running step and its outcome.
//!
//! A stage renders as a single gutter-indented line. While it runs the line is
//! a soft-yellow spinner and label (`  ⠙ Resolving the latest release…`); on
//! success the SAME line is rewritten to a light-green check and message
//! (`  ✓ Found ipe-v0.1.36`); on failure to a cross and message in orange (the
//! user can fix it) or light red (an internal `ipe` bug) (`  ✗ …`). The
//! rewrite is a carriage return, so a completed stage leaves one settled line
//! behind rather than a scroll of chatter.
//!
//! The colour palette, gutter, spinner frames, and glyphs all come from
//! [`crate::style`] — this module owns the stage *composition*, never a second
//! copy of a visual fact.
//!
//! Terminal vs plain is chosen once at construction. On a terminal the running
//! line animates and is rewritten in place with ANSI colour; off a terminal
//! (piped, redirected, `--plain`, `NO_COLOR`) each stage is a single flush-left
//! plain line with no spinner, no rewrite, and no escape codes, so logs and
//! scripts stay clean.
//!
//! A label or outcome message often quotes foreign text (a crate name from a
//! manifest, an OS error naming a path), so [`Stage`] parses each one into an
//! `ipe_diagnostics::terminal::TerminalLine` once, at entry, and the line
//! renderers take only that type: no ANSI sequence, control, bidi, zero-width
//! or tag character, and no newline or tab, reaches a progress line. The
//! character set dropped is the one the runtime's replay dump drops too.

use std::io::{IsTerminal, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use ipe_diagnostics::terminal::{TerminalLine, TerminalSafe};

use crate::cli_args::OutputFormat;
use crate::style::{self, GUTTER, Outcome, Palette};
use crate::threads::{self, ThreadRole};

/// How a stage line is presented: animated and rewritten in place on a
/// terminal, or one settled plain line per stage otherwise.
///
/// The two variants make the terminal/plain choice a parsed value carried by
/// the [`Stage`], not a boolean re-tested at each render site.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// A terminal: colour, an animated spinner, and in-place carriage-return
    /// rewrite of the running line into its outcome.
    Terminal,
    /// Not a terminal (pipe, redirect, `--plain`, `NO_COLOR`): one flush-left
    /// plain line per stage, no spinner, no rewrite, no ANSI.
    Plain,
}

impl Mode {
    /// The terminal mode when `stream` is a terminal and `NO_COLOR` is unset
    /// (per <https://no-color.org>), else the plain mode.
    #[must_use]
    pub fn for_stream(stream: &impl IsTerminal) -> Self {
        if style::use_color(stream) {
            Self::Terminal
        } else {
            Self::Plain
        }
    }

    /// The palette this mode paints with: the coloured palette on a terminal,
    /// the empty-escape plain palette otherwise.
    #[must_use]
    fn palette(self) -> &'static Palette {
        Palette::select(self == Self::Terminal)
    }
}

/// The ANSI sequence that clears from the cursor to the end of the line, so a
/// shorter outcome message never leaves a tail of the longer running line
/// behind after the carriage-return rewrite.
const CLEAR_TO_EOL: &str = "\x1b[0K";

/// Render the running line for `label` at spinner frame `frame_index`.
///
/// Terminal: a carriage return, the gutter, the light-yellow spinner frame, the
/// light-yellow label, and a clear-to-end so a previous longer frame leaves no
/// tail — with NO trailing newline, so the next frame or the outcome overwrites
/// this same line. Plain: the gutter and the bare label on its own line (no
/// spinner, no colour, no carriage return), emitted once when the stage starts.
#[must_use]
pub fn running_line(mode: Mode, label: &TerminalLine, frame_index: usize) -> String {
    let p = mode.palette();
    match mode {
        Mode::Terminal => {
            let frame = spinner_frame(frame_index);
            format!(
                "\r{GUTTER}{y}{frame}{r} {y}{label}{r}{CLEAR_TO_EOL}",
                // A running step wears the in-progress tint from the style SSOT.
                y = style::outcome_tint(Outcome::Step, p),
                r = p.reset,
            )
        }
        Mode::Plain => format!("{GUTTER}{label}\n"),
    }
}

/// Render the success outcome for `msg`.
///
/// Terminal: a carriage return over the running line, the gutter, a light-green
/// check glyph, the light-green message, a clear-to-end, and a newline that
/// settles the finished line. Plain: the gutter, the check glyph, and the plain
/// message on their own line.
#[must_use]
pub fn success_line(mode: Mode, msg: &TerminalLine) -> String {
    outcome_line(mode, Outcome::Success, msg)
}

/// Render the failure outcome for `msg`, blamed on `fault`.
///
/// Terminal: a carriage return over the running line, the gutter, a cross
/// glyph and message in orange (a failure the user can fix) or light red (an
/// internal `ipe` bug), a clear-to-end, and a settling newline. Plain: the
/// gutter, the cross glyph, and the plain message on their own line.
#[must_use]
pub fn failure_line(mode: Mode, fault: crate::screen::Fault, msg: &TerminalLine) -> String {
    outcome_line(mode, Outcome::Failure(fault), msg)
}

/// The shared outcome shape: `<glyph> <msg>` in the outcome's tint, rewriting
/// the running line in place on a terminal and standing alone in plain mode.
///
/// The glyph and tint both come from `outcome` via the [`crate::style`] SSOT,
/// so a success is a green check and a failure's cross is orange or light red
/// by blame, decided in one place, not a per-site pairing.
fn outcome_line(mode: Mode, outcome: Outcome, msg: &TerminalLine) -> String {
    let p = mode.palette();
    let (glyph, color) = outcome.glyph_and_tint(p);
    match mode {
        Mode::Terminal => format!(
            "\r{GUTTER}{color}{glyph}{r} {color}{msg}{r}{CLEAR_TO_EOL}\n",
            r = p.reset,
        ),
        Mode::Plain => format!("{GUTTER}{glyph} {msg}\n"),
    }
}

/// The spinner frame at `frame_index`, wrapping around the frame count so any
/// index is in range (no out-of-bounds on a raw tick counter).
#[must_use]
fn spinner_frame(frame_index: usize) -> &'static str {
    let frames = style::SPINNER_FRAMES;
    // `frames` is a fixed non-empty array, so the modulo index is always valid;
    // `.get` keeps it panic-free without a raw index regardless.
    let i = frame_index % frames.len();
    frames.get(i).copied().unwrap_or(frames[0])
}

/// A single running stage bound to an output stream.
///
/// Construct with [`Stage::start`], which paints the running line immediately;
/// finish it with [`Stage::success`] or [`Stage::failure`], which rewrites that
/// line (terminal) or appends the outcome line (plain). A stage dropped without
/// an explicit outcome settles its running line with a newline on a terminal so
/// the cursor does not sit mid-line — it makes no unproven success claim.
///
/// The stage does not animate on its own; a caller that wants motion calls
/// [`Stage::tick`] between units of work. A non-animating caller still gets a
/// correct, readable first frame and a clean rewrite to the outcome.
pub struct Stage<W: Write> {
    writer: W,
    mode: Mode,
    label: TerminalLine,
    frame_index: usize,
    /// Set once an outcome (or an explicit settle) has been written, so `Drop`
    /// does not settle a line the caller already closed.
    finished: bool,
}

impl<W: Write + IsTerminal> Stage<W> {
    /// Begin a stage on `writer` with the given running `label`, painting the
    /// running line at once.
    ///
    /// The mode is derived from `writer`'s terminal-ness and `NO_COLOR`. A write
    /// error while painting is swallowed — progress chatter is advisory and must
    /// never turn a working command into a failing one over a closed pipe.
    pub fn start(writer: W, label: impl Into<String>) -> Self {
        let mode = Mode::for_stream(&writer);
        Self::with_mode(writer, mode, label)
    }
}

impl<W: Write> Stage<W> {
    /// Begin a stage on `writer` in an explicit [`Mode`], painting the running
    /// line at once; `label` is parsed into a [`TerminalLine`] here. Used where the destination's terminal-ness is already known
    /// (or fixed, as in tests) rather than derived from the writer.
    pub fn with_mode(mut writer: W, mode: Mode, label: impl Into<String>) -> Self {
        let label = TerminalLine::sanitize(&label.into());
        let _ = write!(writer, "{}", running_line(mode, &label, 0));
        let _ = writer.flush();
        Self {
            writer,
            mode,
            label,
            frame_index: 0,
            finished: false,
        }
    }

    /// Advance the spinner by one frame (terminal only; a no-op in plain mode,
    /// which already emitted its single line at [`start`](Self::start)).
    pub fn tick(&mut self) {
        if self.mode != Mode::Terminal {
            return;
        }
        self.frame_index = self.frame_index.wrapping_add(1);
        let _ = write!(
            self.writer,
            "{}",
            running_line(self.mode, &self.label, self.frame_index)
        );
        let _ = self.writer.flush();
    }

    /// Replace the running label with `label`, parsed into a [`TerminalLine`]
    /// here.
    ///
    /// Terminal: the running line is redrawn in place. Plain: the new label is
    /// one more line, so a caller that relabels often bounds how many it emits.
    pub fn relabel(&mut self, label: impl Into<String>) {
        self.label = TerminalLine::sanitize(&label.into());
        let _ = write!(
            self.writer,
            "{}",
            running_line(self.mode, &self.label, self.frame_index)
        );
        let _ = self.writer.flush();
    }

    /// Write `block`, a newline-ended block of already-sanitised lines, above
    /// the running line.
    ///
    /// Terminal: the running line is cleared, the block written, and the
    /// running line redrawn beneath it, so foreign output and the stage never
    /// share a row. Plain: the block is written as is.
    pub fn write_above(&mut self, block: &TerminalSafe) {
        if self.mode == Mode::Terminal {
            let _ = write!(self.writer, "\r{CLEAR_TO_EOL}");
        }
        let _ = self.writer.write_all(block.as_str().as_bytes());
        if self.mode == Mode::Terminal {
            let _ = write!(
                self.writer,
                "{}",
                running_line(self.mode, &self.label, self.frame_index)
            );
        }
        let _ = self.writer.flush();
    }

    /// Finish the stage as a success, rewriting the running line to a
    /// light-green check and `msg`.
    pub fn success(mut self, msg: impl AsRef<str>) {
        self.finished = true;
        let _ = write!(
            self.writer,
            "{}",
            success_line(self.mode, &TerminalLine::sanitize(msg.as_ref()))
        );
        let _ = self.writer.flush();
    }

    /// Finish the stage as a failure, rewriting the running line to a cross and
    /// `msg` tinted by `fault` — orange when the user can fix it, light red
    /// when it is an internal `ipe` bug. Whether the command then stops or
    /// continues is the caller's decision — this only renders the line.
    pub fn failure(mut self, fault: crate::screen::Fault, msg: impl AsRef<str>) {
        self.finished = true;
        let _ = write!(
            self.writer,
            "{}",
            failure_line(self.mode, fault, &TerminalLine::sanitize(msg.as_ref()))
        );
        let _ = self.writer.flush();
    }
}

impl<W: Write> Drop for Stage<W> {
    /// Settle an unfinished stage on a terminal with a bare newline so the
    /// cursor leaves the running line rather than sitting on it — without
    /// claiming any outcome. Plain mode already emitted a complete line.
    fn drop(&mut self) {
        if self.finished || self.mode != Mode::Terminal {
            return;
        }
        let _ = writeln!(self.writer);
        let _ = self.writer.flush();
    }
}

/// Whether a slow step shows a spinner while it runs.
///
/// Decided once per command from its output format and stderr, so no render
/// site re-tests either.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Indicator {
    /// Nothing is painted.
    Silent,
    /// A delayed spinner on stderr, cleared before the step returns.
    Spinner,
}

impl Indicator {
    /// The indicator for a command's output `format` and its `stderr` mode.
    ///
    /// Only human output with a terminal stderr spins; machine output and a
    /// piped or `NO_COLOR` stderr never do.
    #[must_use]
    pub const fn decide(format: OutputFormat, stderr: Mode) -> Self {
        match (format, stderr) {
            (OutputFormat::Human, Mode::Terminal) => Self::Spinner,
            (OutputFormat::Human, Mode::Plain)
            | (OutputFormat::Plain | OutputFormat::Json, Mode::Terminal | Mode::Plain) => {
                Self::Silent
            }
        }
    }
}

/// When a pending spinner first paints and how fast it turns.
#[derive(Clone, Copy, Debug)]
struct Timing {
    /// How long a step runs before the first frame paints.
    delay: Duration,
    /// How long each frame stays up.
    frame: Duration,
}

/// The spinner timing every pending step uses.
const PENDING: Timing = Timing {
    delay: Duration::from_millis(400),
    frame: Duration::from_millis(80),
};

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the spinner would paint at once or turn slower than it waits [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    !PENDING.delay.is_zero()
        && !PENDING.frame.is_zero()
        && PENDING.frame.as_nanos() < PENDING.delay.as_nanos()
);

/// Run `body`, showing `label` beside a spinner on stderr while it is slow.
///
/// [`Indicator::Silent`] runs `body` inline with nothing painted. Under
/// [`Indicator::Spinner`] nothing paints unless `body` outlasts the delay, and
/// whatever painted is cleared, never settled, before this returns — on a
/// value, an error, or a panic alike. A ticker thread the OS refuses only
/// costs the spinner.
pub fn while_pending<T>(indicator: Indicator, label: &str, body: impl FnOnce() -> T) -> T {
    while_pending_on(indicator, std::io::stderr(), PENDING, label, body).0
}

/// [`while_pending`] on an explicit `writer` and `timing`.
///
/// Hands the writer back when it was never moved or its ticker joined, so a
/// test reads what was painted.
fn while_pending_on<W: Write + Send + 'static, T>(
    indicator: Indicator,
    writer: W,
    timing: Timing,
    label: &str,
    body: impl FnOnce() -> T,
) -> (T, Option<W>) {
    match indicator {
        Indicator::Silent => (body(), Some(writer)),
        Indicator::Spinner => {
            let label = TerminalLine::sanitize(label);
            let (stop, stopped) = mpsc::channel::<()>();
            let Ok(handle) = threads::spawn_named(ThreadRole::ProgressTicker, move || {
                tick(writer, &label, timing, &stopped)
            }) else {
                return (body(), None);
            };
            let mut ticker = Ticker {
                stop: Some(stop),
                handle: Some(handle),
            };
            let value = body();
            (value, ticker.finish())
        }
    }
}

/// A running ticker: dropping its sender stops it, joining it waits for the
/// clear.
struct Ticker<W> {
    stop: Option<Sender<()>>,
    handle: Option<JoinHandle<W>>,
}

impl<W> Ticker<W> {
    /// Stop the ticker and wait until it has cleared its line.
    fn finish(&mut self) -> Option<W> {
        drop(self.stop.take());
        self.handle.take().and_then(|handle| handle.join().ok())
    }
}

impl<W> Drop for Ticker<W> {
    /// Stop and join a ticker whose body erred or panicked.
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

/// The ticker loop: wait out the delay, then paint frames until stopped.
///
/// A stop before the delay paints nothing; a stop after any frame clears the
/// line without a newline.
fn tick<W: Write>(
    mut writer: W,
    label: &TerminalLine,
    timing: Timing,
    stopped: &Receiver<()>,
) -> W {
    if !matches!(
        stopped.recv_timeout(timing.delay),
        Err(RecvTimeoutError::Timeout)
    ) {
        return writer;
    }
    let mut frame = 0_usize;
    loop {
        let _ = writer.write_all(running_line(Mode::Terminal, label, frame).as_bytes());
        let _ = writer.flush();
        if !matches!(
            stopped.recv_timeout(timing.frame),
            Err(RecvTimeoutError::Timeout)
        ) {
            break;
        }
        frame = frame.wrapping_add(1);
    }
    let _ = writer.write_all(format!("\r{CLEAR_TO_EOL}").as_bytes());
    let _ = writer.flush();
    writer
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn plain_mode_is_one_flush_left_line_per_stage_with_no_ansi() {
        let running = running_line(
            Mode::Plain,
            &TerminalLine::from("Resolving the latest release…"),
            3,
        );
        assert_eq!(running, "  Resolving the latest release…\n");
        let ok = success_line(Mode::Plain, &TerminalLine::from("Found ipe-v0.1.36"));
        assert_eq!(ok, "  ✓ Found ipe-v0.1.36\n");
        let bad = failure_line(
            Mode::Plain,
            crate::screen::Fault::User,
            &TerminalLine::from("Binary not found — set IPE_VERSION"),
        );
        assert_eq!(bad, "  ✗ Binary not found — set IPE_VERSION\n");
        // No escape byte anywhere in plain output.
        for line in [running, ok, bad] {
            assert!(!line.contains('\x1b'), "plain output must carry no ANSI");
        }
    }

    #[test]
    fn terminal_running_line_rewrites_in_place_in_soft_yellow() {
        let line = running_line(
            Mode::Terminal,
            &TerminalLine::from("Resolving the latest release…"),
            1,
        );
        // A carriage return opens the rewrite; no trailing newline, so the next
        // frame or the outcome overwrites the same line.
        assert!(line.starts_with('\r'));
        assert!(!line.ends_with('\n'));
        assert!(line.contains(GUTTER));
        // The running colour is the single soft yellow, applied to both
        // spinner and label.
        assert!(line.contains(Palette::COLOR.yellow));
        assert!(line.contains("Resolving the latest release…"));
        // Frame index 1 selects the second spinner frame.
        assert!(line.contains(style::SPINNER_FRAMES[1]));
        // Clear-to-end guards against a longer previous frame's tail.
        assert!(line.contains(CLEAR_TO_EOL));
    }

    #[test]
    fn terminal_success_is_light_green_and_settles_with_a_newline() {
        let line = success_line(Mode::Terminal, &TerminalLine::from("Found ipe-v0.1.36"));
        assert!(line.starts_with('\r'));
        assert!(line.ends_with('\n'));
        assert!(line.contains(style::glyph::OK));
        assert!(line.contains(Palette::COLOR.green));
        assert!(line.contains("Found ipe-v0.1.36"));
        assert!(!line.contains(Palette::COLOR.orange));
        assert!(!line.contains(Palette::COLOR.light_red));
    }

    #[test]
    fn terminal_failure_is_orange_or_light_red_by_blame_and_settles_with_a_newline() {
        let user = failure_line(
            Mode::Terminal,
            crate::screen::Fault::User,
            &TerminalLine::from("Binary for latest release not found"),
        );
        assert!(user.starts_with('\r'));
        assert!(user.ends_with('\n'));
        assert!(user.contains(style::glyph::FAIL));
        assert!(
            user.contains(Palette::COLOR.orange),
            "a user-fixable failure is orange"
        );
        assert!(user.contains("Binary for latest release not found"));
        assert!(!user.contains(Palette::COLOR.green));
        assert!(!user.contains(Palette::COLOR.light_red));

        let internal = failure_line(
            Mode::Terminal,
            crate::screen::Fault::Internal,
            &TerminalLine::from("decode produced an invalid frame"),
        );
        assert!(
            internal.contains(Palette::COLOR.light_red),
            "an internal ipe bug is light red"
        );
        assert!(!internal.contains(Palette::COLOR.orange));
    }

    #[test]
    fn spinner_frame_wraps_and_never_indexes_out_of_bounds() {
        // Any tick count maps into the frame set without panicking.
        assert_eq!(spinner_frame(0), style::SPINNER_FRAMES[0]);
        assert_eq!(
            spinner_frame(style::SPINNER_FRAMES.len()),
            style::SPINNER_FRAMES[0]
        );
        let wrapped = style::SPINNER_FRAMES
            .get(usize::MAX % style::SPINNER_FRAMES.len())
            .copied();
        assert_eq!(Some(spinner_frame(usize::MAX)), wrapped);
    }

    #[test]
    fn stage_writes_running_then_success_to_its_buffer() {
        // A Vec<u8> is not a terminal, so drive the stage in plain mode
        // explicitly: a running line at start, then the success line.
        let mut buf: Vec<u8> = Vec::new();
        {
            let stage = Stage::with_mode(&mut buf, Mode::Plain, "Resolving the latest release…");
            stage.success("Found ipe-v0.1.36");
        }
        let text = String::from_utf8(buf).expect("stage output is utf-8");
        assert_eq!(
            text,
            "  Resolving the latest release…\n  ✓ Found ipe-v0.1.36\n"
        );
    }

    #[test]
    fn stage_writes_failure_line() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let stage = Stage::with_mode(&mut buf, Mode::Plain, "Checking for prebuilt binaries…");
            stage.failure(
                crate::screen::Fault::User,
                "No prebuilt binary — build from source",
            );
        }
        let text = String::from_utf8(buf).expect("stage output is utf-8");
        assert_eq!(
            text,
            "  Checking for prebuilt binaries…\n  ✗ No prebuilt binary — build from source\n"
        );
    }

    #[test]
    fn dropped_plain_stage_leaves_only_its_running_line() {
        // In plain mode a stage dropped without an outcome makes no success
        // claim and adds no extra newline — just the running line it emitted.
        let mut buf: Vec<u8> = Vec::new();
        {
            let _stage = Stage::with_mode(&mut buf, Mode::Plain, "Working…");
        }
        let text = String::from_utf8(buf).expect("stage output is utf-8");
        assert_eq!(text, "  Working…\n");
    }

    /// Foreign label and outcome text reach a plain stage as one terminal line each.
    #[test]
    fn a_relabel_redraws_in_place_on_a_terminal_and_adds_a_line_in_plain() {
        let mut buf = Vec::new();
        {
            let mut stage = Stage::with_mode(&mut buf, Mode::Plain, "first");
            stage.relabel("second\x1b[2J");
            stage.success("done");
        }
        let out = String::from_utf8(buf).expect("utf8");
        assert_eq!(out.lines().count(), 3, "{out:?}");
        assert!(!out.contains('\x1b'), "{out:?}");

        let mut buf = Vec::new();
        {
            let mut stage = Stage::with_mode(&mut buf, Mode::Terminal, "first");
            stage.relabel("second\x1b]0;x\x07");
        }
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.contains("second"), "{out:?}");
        assert!(!out.contains("\x1b]"), "{out:?}");
        // Two in-place frames and the settling newline of the drop.
        assert_eq!(out.matches('\n').count(), 1, "{out:?}");
    }

    #[test]
    fn a_block_written_above_a_terminal_stage_never_shares_its_row() {
        let mut buf = Vec::new();
        {
            let mut stage = Stage::with_mode(&mut buf, Mode::Terminal, "running");
            stage.write_above(&TerminalSafe::sanitize(" warning: x\n"));
        }
        let out = String::from_utf8(buf).expect("utf8");
        let cleared = format!("\r{CLEAR_TO_EOL} warning: x\n");
        assert!(out.contains(&cleared), "{out:?}");
        let after = out.split(&cleared).nth(1).unwrap_or_default();
        assert!(
            after.contains("running"),
            "the stage is redrawn below: {out:?}"
        );
    }

    #[test]
    fn plain_stage_lines_are_terminal_lines() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let stage = Stage::with_mode(&mut buf, Mode::Plain, "x\u{202E}y\n\x1b[2J");
            stage.failure(crate::screen::Fault::User, "a\u{200B}b\nc");
        }
        let text = String::from_utf8(buf).expect("stage output is utf-8");
        assert_eq!(text, "  xy\n  ✗ abc\n");
    }

    /// On a terminal the only escapes are the palette's own and each line settles once.
    #[test]
    fn terminal_stage_lines_carry_only_palette_escapes() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let stage = Stage::with_mode(&mut buf, Mode::Terminal, "x\u{202E}y\n\x1b[2J");
            stage.failure(
                crate::screen::Fault::User,
                "a\u{200B}b\nc\x1b]8;;https://evil\x07",
            );
        }
        let mut text = String::from_utf8(buf).expect("stage output is utf-8");
        assert!(
            !text.contains('\u{202E}') && !text.contains('\u{200B}'),
            "{text:?}"
        );
        let p = Palette::COLOR;
        for own in [
            CLEAR_TO_EOL,
            p.yellow,
            p.dim,
            p.green,
            p.light_red,
            p.orange,
            p.white,
            p.bold,
            p.reset,
        ] {
            if !own.is_empty() {
                text = text.replace(own, "");
            }
        }
        assert!(
            !text.contains('\x1b'),
            "a foreign escape survived: {text:?}"
        );
        assert_eq!(text.matches('\n').count(), 1, "one settled line: {text:?}");
        assert!(text.ends_with('\n'), "{text:?}");
    }

    /// A writer that signals its first write and keeps every byte.
    struct Signalling {
        bytes: Vec<u8>,
        first: Option<Sender<()>>,
    }

    impl Write for Signalling {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(buf);
            if let Some(first) = self.first.take() {
                let _ = first.send(());
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A writer whose bytes a test still holds after the ticker drops it.
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const QUICK: Timing = Timing {
        delay: Duration::ZERO,
        frame: Duration::from_millis(1),
    };

    fn cleared() -> String {
        format!("\r{CLEAR_TO_EOL}")
    }

    #[test]
    fn an_indicator_spins_only_for_human_output_on_a_terminal_stderr() {
        assert_eq!(
            Indicator::decide(OutputFormat::Human, Mode::Terminal),
            Indicator::Spinner
        );
        for (format, stderr) in [
            (OutputFormat::Human, Mode::Plain),
            (OutputFormat::Plain, Mode::Terminal),
            (OutputFormat::Plain, Mode::Plain),
            (OutputFormat::Json, Mode::Terminal),
            (OutputFormat::Json, Mode::Plain),
        ] {
            assert_eq!(
                Indicator::decide(format, stderr),
                Indicator::Silent,
                "{format:?} on {stderr:?}"
            );
        }
    }

    #[test]
    fn a_silent_pending_writes_nothing_and_runs_the_body() {
        let (value, writer) = while_pending_on(Indicator::Silent, Vec::new(), QUICK, "x", || 7);
        assert_eq!(value, 7);
        assert_eq!(writer, Some(Vec::new()));
    }

    #[test]
    fn a_pending_body_quicker_than_the_delay_writes_nothing() {
        let slow = Timing {
            delay: Duration::from_secs(10),
            frame: Duration::from_secs(1),
        };
        let (value, writer) = while_pending_on(Indicator::Spinner, Vec::new(), slow, "x", || 7);
        assert_eq!(value, 7);
        assert_eq!(writer, Some(Vec::new()));
    }

    #[test]
    fn a_pending_body_past_the_delay_is_cleared_before_it_returns() {
        let (first, painted) = mpsc::channel();
        let writer = Signalling {
            bytes: Vec::new(),
            first: Some(first),
        };
        let (value, writer) =
            while_pending_on(Indicator::Spinner, writer, QUICK, "reading", || {
                painted.recv_timeout(Duration::from_secs(5)).is_ok()
            });
        assert!(value, "the ticker painted while the body ran");
        assert!(
            writer.is_some(),
            "the ticker joined and handed its writer back"
        );
        let Some(writer) = writer else { return };
        let out = String::from_utf8_lossy(&writer.bytes).into_owned();
        assert!(
            style::SPINNER_FRAMES
                .iter()
                .any(|frame| out.contains(frame)),
            "{out:?}"
        );
        assert!(out.contains("reading"), "{out:?}");
        assert!(out.ends_with(&cleared()), "{out:?}");
        assert!(!out.contains('\n'), "{out:?}");
    }

    #[test]
    fn a_refused_ticker_thread_runs_the_body_without_a_spinner() {
        threads::refusal::refuse(ThreadRole::ProgressTicker);
        let (value, writer) = while_pending_on(Indicator::Spinner, Vec::new(), QUICK, "x", || 7);
        assert_eq!(value, 7);
        assert_eq!(writer, None);
    }

    #[test]
    #[allow(clippy::panic)] // the body panics on purpose to prove the ticker still joins
    fn an_erring_or_panicking_body_still_stops_and_joins_the_ticker() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let (value, _) = while_pending_on(
            Indicator::Spinner,
            Shared(Arc::clone(&bytes)),
            QUICK,
            "x",
            || Err::<(), &str>("refused"),
        );
        assert_eq!(value, Err("refused"));
        assert_eq!(Arc::strong_count(&bytes), 1);

        let writer = Shared(Arc::clone(&bytes));
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            while_pending_on(Indicator::Spinner, writer, QUICK, "x", || {
                std::thread::sleep(Duration::from_millis(5));
                panic!("the body fell over")
            })
        }));
        assert!(unwound.is_err());
        assert_eq!(
            Arc::strong_count(&bytes),
            1,
            "the ticker was joined and its writer dropped"
        );
        let out = bytes.lock().map(|b| b.clone()).unwrap_or_default();
        let out = String::from_utf8_lossy(&out);
        assert!(
            out.is_empty() || out.ends_with(&cleared()),
            "a painted line is cleared: {out:?}"
        );
    }

    #[test]
    fn a_painted_label_carries_no_escape_control_or_bidi_byte() {
        let (first, painted) = mpsc::channel();
        let writer = Signalling {
            bytes: Vec::new(),
            first: Some(first),
        };
        let hostile = "a\u{1b}]0;title\u{7}b\u{1b}[2Jc\u{202e}d\re";
        let (value, writer) = while_pending_on(Indicator::Spinner, writer, QUICK, hostile, || {
            painted.recv_timeout(Duration::from_secs(5)).is_ok()
        });
        assert!(value, "the ticker painted while the body ran");
        let Some(writer) = writer else { return };
        let out = String::from_utf8_lossy(&writer.bytes).into_owned();
        for injected in ["\u{1b}]", "\u{7}", "\u{1b}[2J", "\u{202e}", "d\re"] {
            assert!(!out.contains(injected), "{injected:?} reached {out:?}");
        }
    }

    #[test]
    fn a_pending_label_is_one_terminal_line() {
        let label = crate::text::doc_lookup_pending();
        assert_eq!(TerminalLine::sanitize(label).as_str(), label);
        assert!(!label.contains('\n'));
    }
}

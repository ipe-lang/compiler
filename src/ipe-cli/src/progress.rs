//! The stage-progress renderer: the one shape every multi-step `ipe` command
//! uses to report a running step and its outcome.
//!
//! A stage renders as a single gutter-indented line. While it runs the line is
//! a light-yellow spinner and label (`  ⠙ Resolving the latest release…`); on
//! success the SAME line is rewritten to a light-green check and message
//! (`  ✓ Found ipe-v0.1.36`); on failure to a light-red cross and message
//! (`  ✗ …`). The rewrite is a carriage return, so a completed stage leaves one
//! settled line behind rather than a scroll of chatter.
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

use ipe_diagnostics::terminal::TerminalLine;

use crate::style::{self, GUTTER, Outcome, Palette};

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

/// Render the failure outcome for `msg`.
///
/// Terminal: a carriage return over the running line, the gutter, a light-red
/// cross glyph, the light-red message, a clear-to-end, and a settling newline.
/// Plain: the gutter, the cross glyph, and the plain message on their own line.
#[must_use]
pub fn failure_line(mode: Mode, msg: &TerminalLine) -> String {
    outcome_line(mode, Outcome::Failure, msg)
}

/// The shared outcome shape: `<glyph> <msg>` in the outcome's tint, rewriting
/// the running line in place on a terminal and standing alone in plain mode.
///
/// The glyph and tint both come from `outcome` via the [`crate::style`] SSOT,
/// so a success is a green check and a failure a red cross by one decision, not
/// a per-site pairing.
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

    /// Finish the stage as a failure, rewriting the running line to a light-red
    /// cross and `msg`. Whether the command then stops or continues is the
    /// caller's decision — this only renders the line.
    pub fn failure(mut self, msg: impl AsRef<str>) {
        self.finished = true;
        let _ = write!(
            self.writer,
            "{}",
            failure_line(self.mode, &TerminalLine::sanitize(msg.as_ref()))
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

#[cfg(test)]
mod tests {
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
            &TerminalLine::from("Binary not found — set IPE_VERSION"),
        );
        assert_eq!(bad, "  ✗ Binary not found — set IPE_VERSION\n");
        // No escape byte anywhere in plain output.
        for line in [running, ok, bad] {
            assert!(!line.contains('\x1b'), "plain output must carry no ANSI");
        }
    }

    #[test]
    fn terminal_running_line_rewrites_in_place_in_light_yellow() {
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
        // The running colour is light (bright) yellow, applied to both spinner
        // and label.
        assert!(line.contains(Palette::COLOR.bright_yellow));
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
        assert!(!line.contains(Palette::COLOR.red));
    }

    #[test]
    fn terminal_failure_is_light_red_and_settles_with_a_newline() {
        let line = failure_line(
            Mode::Terminal,
            &TerminalLine::from("Binary for latest release not found"),
        );
        assert!(line.starts_with('\r'));
        assert!(line.ends_with('\n'));
        assert!(line.contains(style::glyph::FAIL));
        assert!(line.contains(Palette::COLOR.red));
        assert!(line.contains("Binary for latest release not found"));
        assert!(!line.contains(Palette::COLOR.green));
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
            stage.failure("No prebuilt binary — build from source");
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
    fn plain_stage_lines_are_terminal_lines() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let stage = Stage::with_mode(&mut buf, Mode::Plain, "x\u{202E}y\n\x1b[2J");
            stage.failure("a\u{200B}b\nc");
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
            stage.failure("a\u{200B}b\nc\x1b]8;;https://evil\x07");
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
            p.bright_yellow,
            p.dim,
            p.green,
            p.red,
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
}

//! The one serializer of a `Cli.tea` frame: a `Lines` view to stdout bytes.
//!
//! A line app's output surface is one typed value, [`LineSurface`], decided
//! once per run. Every frame byte goes through [`write_frame`] over that
//! value, and the closing byte through [`LineState::close`] or, on
//! `System.exit`, [`close_open_line_on_exit`]. The serializer
//! sees only sanitised [`Line`]s, never a layout, a terminal width, or `\r`:
//! a line is written whole, as the program spelled it, with no padding.

use super::{Line, LinesView};
use crate::color::TermProfile;
use std::sync::atomic::{AtomicBool, Ordering};

/// How a line's style is written.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LineStyle {
    /// No styling at all: not one escape sequence reaches the output.
    Plain,
    /// Each styled line's text inside its SGR open sequence and one reset,
    /// colours degraded to the profile.
    Sgr(TermProfile),
}

/// Where a frame's last line ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameEnd {
    /// Every line ends in `\n`: a pipe, a file, or a terminal whose echo
    /// cannot be relied on to end the prompt line.
    Newline,
    /// The last line stays open so the user types after the prompt; the next
    /// frame, or the close, ends it first unless an echoed input line did.
    PromptOpen,
}

/// The output surface of one line app run: its style and its frame end.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LineSurface {
    style: LineStyle,
    end: FrameEnd,
}

impl LineSurface {
    /// The surface of a decided style and frame end.
    ///
    /// Called only by `terminal_access::decide_line`, the one decision over
    /// the run's terminal facts.
    #[must_use]
    pub(crate) const fn decided(style: LineStyle, end: FrameEnd) -> Self {
        Self { style, end }
    }

    /// How this surface writes a line's style.
    #[must_use]
    pub const fn style(&self) -> LineStyle {
        self.style
    }

    /// Where this surface ends a frame's last line.
    #[must_use]
    pub const fn end(&self) -> FrameEnd {
        self.end
    }
}

/// How an input line read from stdin ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputEnd {
    /// Its `\n` (or `\r\n`) terminator.
    Newline,
    /// End of input with no terminator: the final line of the input.
    Eof,
}

/// What the `System.exit` stage of a `Cli.tea` run reads and seals.
///
/// Both bits change only while stdout's lock is held, by [`LineState::emit`]
/// and [`end_output`], so the stage sees the open bit of the bytes that
/// reached stdout, never of a frame still being written, and no frame lands
/// after the stage ended the output.
struct ExitLine {
    /// The last line written to stdout is still open.
    open: AtomicBool,
    /// The exit stage ended the output; nothing more is written.
    ended: AtomicBool,
}

impl ExitLine {
    const fn new() -> Self {
        Self {
            open: AtomicBool::new(false),
            ended: AtomicBool::new(false),
        }
    }
}

/// The process run's [`ExitLine`], read by [`close_open_line_on_exit`].
static EXIT_LINE: ExitLine = ExitLine::new();

/// Whether the last line written is still open (no `\n` after it yet).
///
/// Only a [`FrameEnd::PromptOpen`] frame opens it; the next frame, a
/// newline-ended input line, or [`LineState::close`] ends it. A state made by
/// [`LineState::for_exit_hook`] publishes the bit to the exit stage once the
/// bytes that set it are written ([`LineState::emit`]), so `System.exit` ends
/// an open line too. It is neither `Clone` nor `Copy`: a copy would publish a
/// second, diverging bit to the same exit stage.
#[derive(Default)]
pub struct LineState {
    line_open: bool,
    exit_line: Option<&'static ExitLine>,
}

impl std::fmt::Debug for LineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineState")
            .field("line_open", &self.line_open)
            .field("seen_on_exit", &self.exit_line.is_some())
            .finish()
    }
}

impl LineState {
    /// A state before its first frame, seen by no exit hook: no line open.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            line_open: false,
            exit_line: None,
        }
    }

    /// The process run's state, published to [`close_open_line_on_exit`].
    #[must_use]
    pub fn for_exit_hook() -> Self {
        Self::published_to(&EXIT_LINE)
    }

    /// A state before its first frame whose open bit `exit_line` follows.
    fn published_to(exit_line: &'static ExitLine) -> Self {
        exit_line.open.store(false, Ordering::SeqCst);
        Self {
            line_open: false,
            exit_line: Some(exit_line),
        }
    }

    /// Whether a line is open now.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.line_open
    }

    const fn set_open(&mut self, open: bool) {
        self.line_open = open;
    }

    /// An input line was read, delivered or dropped.
    ///
    /// A line ended by its newline was typed with Enter, whose echo already
    /// moved the cursor to a fresh line, so no frame needs to end the open
    /// one. A final line ended by end of input (`Ctrl-D` after text) echoes no
    /// newline, so the open line stays open. The echo is already on the
    /// terminal, so the exit stage learns of it at once.
    pub fn input_line(&mut self, end: InputEnd) {
        match end {
            InputEnd::Newline => {
                self.set_open(false);
                if let Some(exit_line) = self.exit_line {
                    exit_line.open.store(false, Ordering::SeqCst);
                }
            }
            InputEnd::Eof => {}
        }
    }

    /// The bytes that end the run's output: `\n` when a line is open, else
    /// nothing.
    #[must_use]
    pub const fn close(&mut self) -> &'static [u8] {
        let open = self.line_open;
        self.set_open(false);
        if open { b"\n" } else { b"" }
    }

    /// Write `bytes` this state produced (a frame or the close) to `out`, then
    /// publish the open bit they leave.
    ///
    /// `out` is the locked stdout, the lock the exit stage takes, so the
    /// stage never reads a bit whose bytes are not yet written. Once the
    /// stage has ended the output nothing is written: the process is exiting
    /// and the stage already wrote the last byte.
    pub fn emit<W: std::io::Write>(&self, out: &mut W, bytes: &[u8]) {
        if let Some(exit_line) = self.exit_line
            && exit_line.ended.load(Ordering::SeqCst)
        {
            return;
        }
        if !bytes.is_empty() {
            let _ = out.write_all(bytes);
        }
        let _ = out.flush();
        if let Some(exit_line) = self.exit_line {
            exit_line.open.store(self.line_open, Ordering::SeqCst);
        }
    }
}

/// The `System.exit` stage of a `Cli.tea` run: end the open line, if any.
///
/// Registered as the process exit hook, because `process::exit` skips the
/// loop's own [`LineState::close`]. It holds stdout's lock while it reads and
/// seals the shared bits, so the loop's close and this stage write the closing
/// `\n` at most once between them, and no frame follows it.
pub fn close_open_line_on_exit() {
    let mut out = std::io::stdout().lock();
    end_output(&EXIT_LINE, &mut out);
}

/// Seal `exit_line`, then write the `\n` an open line needs to `out`.
fn end_output<W: std::io::Write>(exit_line: &ExitLine, out: &mut W) {
    exit_line.ended.store(true, Ordering::SeqCst);
    if exit_line.open.swap(false, Ordering::SeqCst) {
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }
}

/// Serialize one frame of `view` for `surface`, advancing `state`.
///
/// A view of zero lines writes nothing. Otherwise an open line is ended
/// first, the lines follow in order separated by `\n`, and the last one ends
/// in `\n` under [`FrameEnd::Newline`] or stays open under
/// [`FrameEnd::PromptOpen`].
#[must_use]
pub fn write_frame<M>(
    view: &LinesView<M>,
    surface: &LineSurface,
    state: &mut LineState,
) -> Vec<u8> {
    let lines = view.lines();
    let mut out = Vec::new();
    if lines.is_empty() {
        return out;
    }
    if state.is_open() {
        out.push(b'\n');
    }
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            out.push(b'\n');
        }
        write_line(&mut out, line, surface.style);
    }
    match surface.end {
        FrameEnd::Newline => {
            out.push(b'\n');
            state.set_open(false);
        }
        FrameEnd::PromptOpen => state.set_open(true),
    }
    out
}

/// One line's bytes: its text, wrapped in its SGR open and a reset when the
/// style writes one.
fn write_line(out: &mut Vec<u8>, line: &Line, style: LineStyle) {
    let open = match style {
        LineStyle::Plain => String::new(),
        LineStyle::Sgr(profile) => super::layout::line_sgr_open(&line.attrs, profile),
    };
    if open.is_empty() {
        out.extend_from_slice(line.text.as_bytes());
    } else {
        out.extend_from_slice(open.as_bytes());
        out.extend_from_slice(line.text.as_bytes());
        out.extend_from_slice(super::layout::SGR_RESET.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        CliAttr, cli_line_, cli_lines_, cli_none_, cli_text_, term_color_red_, term_color_rgb_,
    };
    use super::*;

    const PLAIN_NEWLINE: LineSurface = LineSurface {
        style: LineStyle::Plain,
        end: FrameEnd::Newline,
    };

    /// Every style crossed with every frame end.
    fn all_surfaces() -> Vec<LineSurface> {
        let styles = [
            LineStyle::Plain,
            LineStyle::Sgr(TermProfile::TrueColor),
            LineStyle::Sgr(TermProfile::Ansi256),
            LineStyle::Sgr(TermProfile::Ansi16),
            LineStyle::Sgr(TermProfile::NoColor),
        ];
        let ends = [FrameEnd::Newline, FrameEnd::PromptOpen];
        styles
            .iter()
            .flat_map(|&style| ends.iter().map(move |&end| LineSurface { style, end }))
            .collect()
    }

    /// A multi-line view carrying every line style.
    fn styled_view() -> LinesView<()> {
        cli_lines_(vec![
            cli_line_(vec![CliAttr::Bold], "b".to_owned()),
            cli_line_(vec![CliAttr::Dim, CliAttr::Reverse], "d ".to_owned()),
            cli_line_(vec![CliAttr::Underline], " u".to_owned()),
            cli_line_(vec![CliAttr::FgColor(term_color_red_())], "c".to_owned()),
            cli_line_(
                vec![CliAttr::BgColor(term_color_rgb_(1, 2, 3))],
                "g".to_owned(),
            ),
            cli_text_("plain".to_owned()),
        ])
    }

    fn plain(view: &LinesView<()>) -> Vec<u8> {
        write_frame(view, &PLAIN_NEWLINE, &mut LineState::new())
    }

    // A view's own trailing spaces are content, never padding: the prompt
    // keeps its blank, and so does one written twice over.
    #[test]
    fn plain_frame_keeps_trailing_content_spaces() {
        assert_eq!(
            plain(&cli_text_("echoed 0 [] > ".to_owned())),
            b"echoed 0 [] > \n"
        );
        assert_eq!(plain(&cli_text_("  x  ".to_owned())), b"  x  \n");
        // One step past: a line of only spaces is still a line.
        assert_eq!(plain(&cli_text_("  ".to_owned())), b"  \n");
    }

    // Lines are written at their own width, not padded to the widest one.
    #[test]
    fn plain_frame_never_pads_to_widest_line() {
        let view = cli_lines_::<()>(vec![
            cli_text_("ab".to_owned()),
            cli_text_("abcdef".to_owned()),
        ]);
        assert_eq!(plain(&view), b"ab\nabcdef\n");
        for surface in all_surfaces() {
            let out = write_frame(&view, &surface, &mut LineState::new());
            assert!(
                !out.windows(3).any(|w| w == b"ab "),
                "padded under {surface:?}: {out:?}"
            );
        }
    }

    /// No bidi control or line separator a program spells reaches a line, under every style.
    ///
    /// CI job `runtime-full-features-run`.
    #[test]
    fn bidi_override_never_reaches_a_line() -> Result<(), String> {
        use super::super::cell::BIDI_AND_SEPARATOR_HAZARDS;
        for c in BIDI_AND_SEPARATOR_HAZARDS.iter().flat_map(Clone::clone) {
            let view = cli_text_::<()>(format!("a{c}b"));
            for surface in all_surfaces() {
                let out = write_frame(&view, &surface, &mut LineState::new());
                let text = String::from_utf8(out).map_err(|e| e.to_string())?;
                if text.contains(c) || !text.contains("a b") {
                    return Err(format!(
                        "U+{:04X} under {surface:?}: {text:?}",
                        u32::from(c)
                    ));
                }
            }
        }
        Ok(())
    }

    // No surface writes a carriage return, whatever the style or the end.
    #[test]
    fn no_surface_writes_cr() {
        let view = styled_view();
        for surface in all_surfaces() {
            let mut state = LineState::new();
            let mut out = write_frame(&view, &surface, &mut state);
            out.extend(write_frame(&view, &surface, &mut state));
            out.extend_from_slice(state.close());
            assert!(!out.contains(&b'\r'), "CR under {surface:?}: {out:?}");
        }
        // One step past: a CR the program itself spells is sanitised away.
        let out = plain(&cli_text_("a\rb".to_owned()));
        assert_eq!(out, b"a b\n");
    }

    // A plain surface writes no escape byte, even for a styled view or text
    // that spells an escape sequence.
    #[test]
    fn plain_frame_has_no_escape() {
        for end in [FrameEnd::Newline, FrameEnd::PromptOpen] {
            let surface = LineSurface {
                style: LineStyle::Plain,
                end,
            };
            let out = write_frame(&styled_view(), &surface, &mut LineState::new());
            assert!(!out.contains(&0x1b), "ESC under {surface:?}: {out:?}");
        }
        assert_eq!(plain(&styled_view()), b"b\nd \n u\nc\ng\nplain\n");
        let spelled = plain(&cli_text_("\u{1b}[31mred".to_owned()));
        assert!(!spelled.contains(&0x1b), "{spelled:?}");
        // One step past: the same view under `Sgr` does style.
        let sgr = LineSurface {
            style: LineStyle::Sgr(TermProfile::TrueColor),
            end: FrameEnd::Newline,
        };
        let styled = write_frame(&styled_view(), &sgr, &mut LineState::new());
        assert!(styled.starts_with(b"\x1b[1mb\x1b[0m\n"), "{styled:?}");
    }

    // A line longer than any terminal comes out whole under `Sgr`.
    #[test]
    fn sgr_line_is_never_clipped() {
        let long = "x".repeat(500);
        let sgr = LineSurface {
            style: LineStyle::Sgr(TermProfile::TrueColor),
            end: FrameEnd::Newline,
        };
        let out = write_frame(&cli_text_::<()>(long.clone()), &sgr, &mut LineState::new());
        assert_eq!(out, format!("{long}\n").into_bytes());
        let bold = write_frame(
            &cli_line_::<()>(vec![CliAttr::Bold], long.clone()),
            &sgr,
            &mut LineState::new(),
        );
        assert_eq!(bold, format!("\x1b[1m{long}\x1b[0m\n").into_bytes());
    }

    // A view with no line writes nothing, not a blank line, on every surface,
    // and leaves an open line open.
    #[test]
    fn plain_empty_view_writes_nothing() {
        for surface in all_surfaces() {
            let mut state = LineState::new();
            assert!(write_frame(&cli_none_::<()>(), &surface, &mut state).is_empty());
            assert!(write_frame(&cli_lines_::<()>(vec![]), &surface, &mut state).is_empty());
            assert_eq!(state.close(), b"");
        }
    }

    // The closing byte follows the state, not the mode: a newline-ended frame
    // leaves nothing to close; an open prompt is closed exactly once.
    #[test]
    fn closing_bytes_follow_the_mode() {
        let view = cli_text_::<()>("> ".to_owned());
        let mut state = LineState::new();
        let _ = write_frame(&view, &PLAIN_NEWLINE, &mut state);
        assert_eq!(state.close(), b"");

        let prompt = LineSurface {
            style: LineStyle::Plain,
            end: FrameEnd::PromptOpen,
        };
        let mut state = LineState::new();
        assert_eq!(write_frame(&view, &prompt, &mut state), b"> ");
        assert_eq!(state.close(), b"\n");
        // One step past: a second close writes nothing more.
        assert_eq!(state.close(), b"");
    }

    // An open prompt is ended before the next frame unless an echoed input
    // line already ended it.
    #[test]
    fn prompt_open_frame_ends_the_open_line_first() {
        let view = cli_text_::<()>("> ".to_owned());
        let prompt = LineSurface {
            style: LineStyle::Plain,
            end: FrameEnd::PromptOpen,
        };
        let mut state = LineState::new();
        assert_eq!(write_frame(&view, &prompt, &mut state), b"> ");
        assert_eq!(write_frame(&view, &prompt, &mut state), b"\n> ");
        state.input_line(InputEnd::Newline);
        assert_eq!(write_frame(&view, &prompt, &mut state), b"> ");
        state.input_line(InputEnd::Newline);
        assert_eq!(state.close(), b"");
    }

    // A final input line ended by end of input (text then `Ctrl-D`) echoed no
    // newline: the prompt line it was typed on is still open, so the next
    // frame and the close still end it.
    #[test]
    fn eof_ended_input_line_keeps_the_prompt_open() {
        let view = cli_text_::<()>("> ".to_owned());
        let prompt = LineSurface {
            style: LineStyle::Plain,
            end: FrameEnd::PromptOpen,
        };
        let mut state = LineState::new();
        assert_eq!(write_frame(&view, &prompt, &mut state), b"> ");
        state.input_line(InputEnd::Eof);
        assert_eq!(write_frame(&view, &prompt, &mut state), b"\n> ");
        state.input_line(InputEnd::Eof);
        assert_eq!(state.close(), b"\n");
    }

    const PLAIN_PROMPT: LineSurface = LineSurface {
        style: LineStyle::Plain,
        end: FrameEnd::PromptOpen,
    };

    // A re-render with no input line between (a ticker, a `Cmd` result)
    // starts on a new line instead of gluing onto the open prompt.
    #[test]
    fn prompt_open_render_after_render_starts_a_new_line() {
        let view = cli_lines_::<()>(vec![
            cli_text_("tick 1".to_owned()),
            cli_text_("> ".to_owned()),
        ]);
        let mut state = LineState::new();
        let mut out = write_frame(&view, &PLAIN_PROMPT, &mut state);
        out.extend(write_frame(&view, &PLAIN_PROMPT, &mut state));
        assert_eq!(out, b"tick 1\n> \ntick 1\n> ");
    }

    // An echoed (newline-ended) input line already ended the open prompt, so
    // the next frame starts where the cursor is.
    #[test]
    fn echoed_line_clears_open_state() {
        let view = cli_text_::<()>("> ".to_owned());
        let mut state = LineState::new();
        let _ = write_frame(&view, &PLAIN_PROMPT, &mut state);
        assert!(state.is_open());
        state.input_line(InputEnd::Newline);
        assert!(!state.is_open());
        assert_eq!(write_frame(&view, &PLAIN_PROMPT, &mut state), b"> ");
        // One step past: an input line with no frame open leaves it closed.
        let mut fresh = LineState::new();
        fresh.input_line(InputEnd::Newline);
        assert!(!fresh.is_open());
    }

    #[test]
    fn close_writes_newline_only_when_open() {
        let mut state = LineState::new();
        assert_eq!(state.close(), b"");
        let _ = write_frame(&cli_text_::<()>("> ".to_owned()), &PLAIN_PROMPT, &mut state);
        assert_eq!(state.close(), b"\n");
        assert_eq!(state.close(), b"");
        let _ = write_frame(&cli_text_::<()>("x".to_owned()), &PLAIN_NEWLINE, &mut state);
        assert_eq!(state.close(), b"");
    }

    /// Serialize one frame of `view` and emit it into `out`, as the loop does.
    fn emit_frame(
        view: &LinesView<()>,
        surface: &LineSurface,
        state: &mut LineState,
        out: &mut Vec<u8>,
    ) {
        let frame = write_frame(view, surface, state);
        state.emit(out, &frame);
    }

    fn prompt() -> LinesView<()> {
        cli_text_::<()>("> ".to_owned())
    }

    // The exit stage ends an open line exactly once: a fresh run has none, an
    // emitted prompt frame opens one, and a second stage run adds nothing.
    #[test]
    fn exit_close_ends_an_emitted_open_line_once() {
        static EXIT: ExitLine = ExitLine::new();
        EXIT.open.store(true, Ordering::SeqCst);
        let mut state = LineState::published_to(&EXIT);
        assert!(
            !EXIT.open.load(Ordering::SeqCst),
            "a fresh run has no open line"
        );
        let mut out = Vec::new();
        emit_frame(&prompt(), &PLAIN_PROMPT, &mut state, &mut out);
        assert_eq!(out, b"> ");
        let mut tail = Vec::new();
        end_output(&EXIT, &mut tail);
        end_output(&EXIT, &mut tail);
        assert_eq!(tail, b"\n");
    }

    // The loop's own close and the exit stage write the closing `\n` once
    // between them.
    #[test]
    fn loop_close_and_exit_close_write_one_newline() {
        static EXIT: ExitLine = ExitLine::new();
        let mut state = LineState::published_to(&EXIT);
        let mut out = Vec::new();
        emit_frame(&prompt(), &PLAIN_PROMPT, &mut state, &mut out);
        let close = state.close();
        state.emit(&mut out, close);
        assert_eq!(out, b"> \n");
        let mut tail = Vec::new();
        end_output(&EXIT, &mut tail);
        assert_eq!(tail, b"", "the loop's close already ended it");
    }

    // An echoed Enter is already on the terminal, so the exit stage learns at
    // once that it ended the open line.
    #[test]
    fn an_echoed_enter_reaches_the_exit_stage_at_once() {
        static EXIT: ExitLine = ExitLine::new();
        let mut state = LineState::published_to(&EXIT);
        let mut out = Vec::new();
        emit_frame(&prompt(), &PLAIN_PROMPT, &mut state, &mut out);
        state.input_line(InputEnd::Newline);
        let mut tail = Vec::new();
        end_output(&EXIT, &mut tail);
        assert_eq!(tail, b"", "the echoed Enter ended it");
    }

    // The exit stage reads the bit of the bytes on stdout, never of a frame
    // still being written: a frame computed but not emitted changes nothing
    // the stage sees, in either direction.
    #[test]
    fn a_frame_reaches_the_exit_stage_only_once_emitted() {
        static EXIT: ExitLine = ExitLine::new();
        let mut state = LineState::published_to(&EXIT);
        let opening = write_frame(&prompt(), &PLAIN_PROMPT, &mut state);
        assert!(
            !EXIT.open.load(Ordering::SeqCst),
            "the prompt is not written yet"
        );
        let mut out = Vec::new();
        state.emit(&mut out, &opening);
        assert!(EXIT.open.load(Ordering::SeqCst));
        // One step past: a closing frame computed but not yet written leaves the
        // written prompt open, so an exit now still ends it.
        let closing = write_frame(&cli_text_::<()>("x".to_owned()), &PLAIN_NEWLINE, &mut state);
        assert!(
            EXIT.open.load(Ordering::SeqCst),
            "the prompt is still open on stdout"
        );
        state.emit(&mut out, &closing);
        assert!(!EXIT.open.load(Ordering::SeqCst));
        assert_eq!(out, b"> \nx\n");
    }

    // Once the exit stage ended the output, no frame and no close follows its
    // last byte.
    #[test]
    fn nothing_is_written_after_the_exit_ended_the_output() {
        static EXIT: ExitLine = ExitLine::new();
        let mut state = LineState::published_to(&EXIT);
        let mut out = Vec::new();
        emit_frame(&prompt(), &PLAIN_PROMPT, &mut state, &mut out);
        end_output(&EXIT, &mut out);
        assert_eq!(out, b"> \n");
        emit_frame(&prompt(), &PLAIN_PROMPT, &mut state, &mut out);
        emit_frame(
            &cli_text_::<()>("x".to_owned()),
            &PLAIN_NEWLINE,
            &mut state,
            &mut out,
        );
        let close = state.close();
        state.emit(&mut out, close);
        assert_eq!(out, b"> \n", "the stage's newline is the last byte");
        // One step past: a state no exit stage sees always writes.
        let mut unseen = LineState::new();
        let mut free = Vec::new();
        emit_frame(&prompt(), &PLAIN_PROMPT, &mut unseen, &mut free);
        assert_eq!(free, b"> ");
    }

    /// Whether `T` is `Clone`: the inherent constant applies only to a
    /// `Clone` type, the trait's default answers for every other.
    struct CloneProbe<T>(std::marker::PhantomData<T>);
    trait NotClone {
        const IS_CLONE: bool = false;
    }
    impl<T> NotClone for CloneProbe<T> {}
    impl<T: Clone> CloneProbe<T> {
        const IS_CLONE: bool = true;
    }

    // One run has one state publishing to the exit stage: a copy would publish
    // its own open bit, so the stage could end a line the run already ended
    // or miss one it left open. Checked at build time: a `Clone` `LineState`
    // fails to compile this test.
    #[test]
    fn a_line_state_cannot_be_duplicated() {
        const { assert!(!CloneProbe::<LineState>::IS_CLONE) };
        // One step past: the probe tells a duplicable type apart.
        const { assert!(CloneProbe::<LineSurface>::IS_CLONE) };
    }
}

//! The one serializer of a `Cli.tea` frame: a `Lines` view to stdout bytes.
//!
//! A line app's output surface is one typed value, [`LineSurface`], decided
//! once per run. Every frame byte goes through [`write_frame`] over that
//! value, and the closing byte through [`LineState::close`]. The serializer
//! sees only sanitised [`Line`]s, never a layout, a terminal width, or `\r`:
//! a line is written whole, as the program spelled it, with no padding.

use super::{Line, LinesView};
use crate::color::TermProfile;

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
    /// The surface the stdout-only rule picks: a terminal stdout styles under
    /// the resolved colour profile and keeps the prompt line open; any other
    /// stdout writes plain, newline-ended lines.
    #[must_use]
    pub fn from_stdout_only() -> Self {
        match super::LineOutput::of_stdout() {
            super::LineOutput::Terminal => Self {
                style: LineStyle::Sgr(crate::color::resolve_term_profile()),
                end: FrameEnd::PromptOpen,
            },
            super::LineOutput::Plain => Self {
                style: LineStyle::Plain,
                end: FrameEnd::Newline,
            },
        }
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

/// Whether the last line written is still open (no `\n` after it yet).
///
/// Only a [`FrameEnd::PromptOpen`] frame opens it; the next frame, a
/// newline-ended input line, or [`LineState::close`] ends it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LineState {
    line_open: bool,
}

impl LineState {
    /// A run's state before its first frame: no line open.
    #[must_use]
    pub const fn new() -> Self {
        Self { line_open: false }
    }

    /// An input line was read. A line ended by its newline was typed with
    /// Enter, whose echo already moved the cursor to a fresh line, so no frame
    /// needs to end the open one. A final line ended by end of input (`Ctrl-D`
    /// after text) echoes no newline, so the open line stays open.
    pub const fn input_line(&mut self, end: InputEnd) {
        match end {
            InputEnd::Newline => self.line_open = false,
            InputEnd::Eof => {}
        }
    }

    /// The bytes that end the run's output: `\n` when a line is open, else
    /// nothing.
    #[must_use]
    pub const fn close(&mut self) -> &'static [u8] {
        if self.line_open {
            self.line_open = false;
            b"\n"
        } else {
            b""
        }
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
    if state.line_open {
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
            state.line_open = false;
        }
        FrameEnd::PromptOpen => state.line_open = true,
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
}

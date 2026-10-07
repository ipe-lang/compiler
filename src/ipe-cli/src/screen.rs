//! The one renderer for human-facing CLI output.
//!
//! Every human screen has the same frame:
//!
//! ```text
//!
//!   Ipê language - vN.N.N - https://github.com/ipe-lang/compiler
//!
//!   <content, indented by the two-space gutter>
//!
//! ```
//!
//! The header ([`crate::style::command_header`]) opens a process's human output
//! once; a later screen in the same run carries only its content. The "report
//! bugs" footer closes an error only when the fault is ipe's own
//! ([`Fault::Internal`]); a user or environment error never invites a bug report.
//!
//! A line's colour is its semantic [`Tone`], never a raw palette field picked at
//! the call site: light green for success, light red for an ipe-internal error,
//! light orange for a user error, soft white for common text, dim gray for
//! auxiliary text. Colour follows the destination stream (a terminal with
//! `NO_COLOR` unset); piped or `NO_COLOR` output is the same frame in plain
//! text.
//!
//! Machine output (`--json`, `--plain`, a `run` child's stdout) is never framed:
//! it goes through [`emit_machine`] byte for byte.

use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::CliError;
use crate::doc_search::DocMiss;
use crate::style::{self, GUTTER, Palette, REPORT_BUGS_PHRASE, TerminalSafe};

/// The semantic role of a piece of human output, which fixes its colour.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tone {
    /// A successful outcome — light green.
    Success,
    /// A failure inside ipe itself (a bug to report) — light red.
    InternalError,
    /// A failure the user can fix (misuse, a source error, the environment) —
    /// light orange.
    UserError,
    /// Common prose — soft white.
    Text,
    /// Auxiliary detail (hints, locations, URLs) — dim gray.
    Aux,
}

impl Tone {
    /// The escape that paints this tone under `p` (empty under the plain
    /// palette).
    #[must_use]
    pub const fn ink(self, p: &Palette) -> &'static str {
        match self {
            Self::Success => p.green,
            Self::InternalError => p.light_red,
            Self::UserError => p.orange,
            Self::Text => p.white,
            Self::Aux => p.dim,
        }
    }
}

/// Who a failed command's error belongs to — it picks the error [`Tone`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    /// The user can act on it: misuse, a source error, a missing prerequisite.
    User,
    /// ipe itself broke an invariant it promises (a bug to report).
    Internal,
}

impl Fault {
    /// The tone an error of this fault is painted in.
    #[must_use]
    pub const fn tone(self) -> Tone {
        match self {
            Self::User => Tone::UserError,
            Self::Internal => Tone::InternalError,
        }
    }
}

/// The destination stream of a screen: it decides the colour and receives the
/// bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stream {
    /// Standard output — requested output (help, reports, documentation).
    Stdout,
    /// Standard error — progress chatter and errors.
    Stderr,
}

impl Stream {
    /// Whether ANSI colour reaches this stream (a terminal, `NO_COLOR` unset).
    fn color(self) -> bool {
        match self {
            Self::Stdout => style::use_color(&std::io::stdout()),
            Self::Stderr => style::use_color(&std::io::stderr()),
        }
    }

    /// Write `text` whole and flush. Best effort: a closed stream (a reader
    /// that went away) drops the bytes rather than aborting the process.
    fn write(self, text: &str) {
        let _ = match self {
            Self::Stdout => {
                let mut out = std::io::stdout().lock();
                out.write_all(text.as_bytes()).and_then(|()| out.flush())
            }
            Self::Stderr => {
                let mut err = std::io::stderr().lock();
                err.write_all(text.as_bytes()).and_then(|()| err.flush())
            }
        };
    }
}

/// Whether a rendered screen opens with the product header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Header {
    /// The first human output of the process: the header leads.
    Shown,
    /// The header already opened this process's output.
    Omitted,
}

/// Set once the header has been written, so a process shows it exactly once.
static HEADER_WRITTEN: AtomicBool = AtomicBool::new(false);

/// Claim the header for the next screen: [`Header::Shown`] the first time,
/// [`Header::Omitted`] after.
fn claim_header() -> Header {
    if HEADER_WRITTEN.swap(true, Ordering::Relaxed) {
        Header::Omitted
    } else {
        Header::Shown
    }
}

/// Write the product header alone to `stream`, unless it was already written.
/// Leads a command's progress chatter before any screen exists.
pub fn emit_header(stream: Stream) {
    if claim_header() == Header::Shown {
        stream.write(&style::command_header(stream.color()));
    }
}

/// Write machine output (`--json`, `--plain`) to `stream` byte for byte —
/// never framed, never coloured.
pub fn emit_machine(stream: Stream, text: &str) {
    stream.write(text);
}

/// Prefix one relayed child-process chunk — one line, or one `\r`-terminated
/// progress-bar redraw — with [`style::RELAY_INDENT`] before it reaches the
/// terminal.
///
/// This is the single routine both `ipe dev build`'s and `ipe dev watch`'s cargo relay
/// loops call on every chunk `read_progress_chunk` hands them, so the relayed
/// Cargo diagnostics and progress bar sit one column off the edge instead of
/// flush against it — one shared indent for the one shared relay pattern,
/// rather than two call sites independently choosing "no indent at all".
/// Cargo's `\r` redraw and a plain `\n` line are treated alike: either
/// terminator means the chunk opened a fresh terminal row, so either gets
/// exactly one leading indent. A chunk that is only its own terminator (an
/// otherwise-blank line) is left untouched, matching [`style::gutter`]'s "a
/// blank line stays blank" rule.
#[must_use]
pub fn indent_relay_chunk(chunk: &str) -> String {
    if chunk.trim_end_matches(['\n', '\r']).is_empty() {
        return chunk.to_string();
    }
    format!("{}{chunk}", style::RELAY_INDENT)
}

/// A human screen under construction: guttered, toned lines bound to one
/// stream's palette.
pub struct Screen {
    /// Where the screen is written.
    stream: Stream,
    /// The palette resolved for [`Self::stream`].
    palette: &'static Palette,
    /// The body so far: every non-empty line already guttered, each ended by a
    /// newline.
    body: String,
    /// Whether the screen closes with the bug footer.
    bug_footer: bool,
}

impl Screen {
    /// A screen for `stream`, coloured when that stream takes colour.
    #[must_use]
    pub fn new(stream: Stream) -> Self {
        Self::with_color(stream, stream.color())
    }

    /// A screen for `stream` with colour forced on or off (deterministic
    /// rendering for tests).
    #[must_use]
    pub const fn with_color(stream: Stream, color: bool) -> Self {
        Self {
            stream,
            palette: Palette::select(color),
            body: String::new(),
            bug_footer: false,
        }
    }

    /// The palette this screen paints with, for trusted renderers that style a
    /// block before handing it to [`Self::styled`].
    #[must_use]
    pub const fn palette(&self) -> &'static Palette {
        self.palette
    }

    /// Append `text` painted in `tone`, one guttered line per text line.
    ///
    /// The text may be untrusted: it is sanitised to [`TerminalSafe`] first, so the tone's own
    /// escapes are the only control bytes it can carry.
    pub fn line(&mut self, tone: Tone, text: &str) -> &mut Self {
        let safe = TerminalSafe::sanitize(text);
        let ink = tone.ink(self.palette);
        let reset = if ink.is_empty() {
            ""
        } else {
            self.palette.reset
        };
        for line in safe.as_str().trim_matches('\n').split('\n') {
            if !line.is_empty() {
                self.body.push_str(GUTTER);
                self.body.push_str(ink);
                self.body.push_str(line);
                self.body.push_str(reset);
            }
            self.body.push('\n');
        }
        self
    }

    /// Append an empty separator line.
    pub fn blank(&mut self) -> &mut Self {
        self.body.push('\n');
        self
    }

    /// Append a block a trusted renderer already styled with [`Self::palette`] (a help page, a
    /// finding).
    ///
    /// Every line gains the gutter; edge newlines are dropped.
    pub fn styled(&mut self, block: &str) -> &mut Self {
        let block = block.trim_matches('\n');
        if !block.is_empty() {
            self.body.push_str(&style::gutter(block));
            self.body.push('\n');
        }
        self
    }

    /// Append a block whose renderer guttered some or all of its own lines (a self-rendering
    /// error).
    ///
    /// A line that already starts with the gutter is kept as is; any other non-empty line gains it,
    /// so no line reaches the terminal edge and none is indented twice.
    pub fn guttered(&mut self, block: &str) -> &mut Self {
        for line in block.trim_matches('\n').split('\n') {
            if !line.is_empty() && !line.starts_with(GUTTER) {
                self.body.push_str(GUTTER);
            }
            self.body.push_str(line);
            self.body.push('\n');
        }
        self
    }

    /// Close the screen with the bug footer: an internal error, or the top-level
    /// help overview, where a newcomer looks for where to report problems.
    pub const fn with_bug_footer(&mut self) -> &mut Self {
        self.bug_footer = true;
        self
    }

    /// Render the screen as text, with or without the header.
    #[must_use]
    pub fn render(&self, header: Header) -> String {
        let p = self.palette;
        let mut out = match header {
            Header::Shown => style::command_header(!p.reset.is_empty()),
            Header::Omitted => String::from("\n"),
        };
        out.push_str(self.body.trim_end_matches('\n'));
        out.push('\n');
        if self.bug_footer {
            let text = Tone::Text.ink(p);
            let aux = Tone::Aux.ink(p);
            let r = p.reset;
            let _ = write!(
                out,
                "\n{GUTTER}{text}{REPORT_BUGS_PHRASE}{r}{aux}{}{r}{text}.{r}\n",
                style::issues_url()
            );
        }
        out
    }

    /// Write the screen to its stream, with the header when it is the process's
    /// first human output.
    pub fn emit(&self) {
        self.stream.write(&self.render(claim_header()));
    }

    /// Render the screen as progress chatter: its lines alone, with no blank edge.
    ///
    /// The header leads when it is `header`.
    #[must_use]
    pub fn render_chatter(&self, header: Header) -> String {
        let mut out = match header {
            Header::Shown => style::command_header(!self.palette.reset.is_empty()),
            Header::Omitted => String::new(),
        };
        out.push_str(&self.body);
        out
    }

    /// Write the screen to its stream as progress chatter.
    ///
    /// A step line of a running command continues the output under the header
    /// instead of opening a new blank-edged block.
    pub fn emit_chatter(&self) {
        self.stream.write(&self.render_chatter(claim_header()));
    }
}

/// Write one line of progress chatter, painted in `tone`, to `stream`.
///
/// The text may be untrusted: it is sanitised like [`Screen::line`].
pub fn chatter(stream: Stream, tone: Tone, text: &str) {
    Screen::new(stream).line(tone, text).emit_chatter();
}

/// Write a block a trusted renderer already styled for `stream` as progress
/// chatter.
///
/// Lines the renderer already guttered keep their indent, as in
/// [`Screen::guttered`]; blank lines, leading and trailing ones included, are
/// kept as the renderer laid them out.
pub fn chatter_styled(stream: Stream, block: &str) {
    emit_header(stream);
    stream.write(&guttered_once(block));
}

/// Gutter every non-empty line of `block` that does not already start with the
/// gutter, keeping every newline.
fn guttered_once(block: &str) -> String {
    let mut out = String::with_capacity(block.len().saturating_add(GUTTER.len()));
    for line in block.split_inclusive('\n') {
        let text = line.trim_end_matches('\n');
        if !text.is_empty() && !text.starts_with(GUTTER) {
            out.push_str(GUTTER);
        }
        out.push_str(line);
    }
    out
}

/// Write a report a renderer produced for `format` to stdout.
///
/// The human form is a framed, guttered, styled block and becomes a screen; a
/// machine form (`--plain`, `--json`) is written byte for byte.
pub fn emit_report(format: crate::cli_args::OutputFormat, text: &str) {
    use crate::cli_args::OutputFormat::{Human, Json, Plain};
    match format {
        Human => {
            Screen::new(Stream::Stdout).guttered(text).emit();
        }
        Plain | Json => emit_machine(Stream::Stdout, text),
    }
}

/// Write a completed step as its own screen on `stream`: the success or failure
/// glyph, then `message` (see [`style::status_line`]).
pub fn status(stream: Stream, ok: bool, message: &TerminalSafe) {
    Screen::new(stream)
        .guttered(&style::status_line(ok, message, stream.color()))
        .emit();
}

/// Ask the user `question` on stdout.
///
/// Every line is guttered and sanitised, and no newline follows the last, so
/// the answer is typed on the same line.
pub fn prompt(question: &str) {
    emit_header(Stream::Stdout);
    let safe = TerminalSafe::sanitize(question);
    Stream::Stdout.write(&style::gutter(safe.as_str()));
}

/// Report a failed command on stderr in the one error frame.
///
/// The header (when not yet shown), the error in its [`Fault`]'s tone — or, for
/// an error that renders its own complete screen, that screen — then, for an
/// internal fault only, the bug footer.
///
/// An error that already wrote its final output (a machine-mode envelope, an
/// upgrade verdict) renders nothing here.
pub fn report_error(err: &CliError) {
    if let Some(screen) = error_screen(err, Stream::Stderr.color()) {
        screen.emit();
    }
}

/// Build the error screen for `err`, or `None` when the error already wrote its
/// final output.
#[must_use]
pub fn error_screen(err: &CliError, color: bool) -> Option<Screen> {
    let text = err.to_string();
    if text.trim().is_empty() {
        return None;
    }
    let fault = err.fault();
    let mut screen = Screen::with_color(Stream::Stderr, color);
    if let CliError::DocNotFound { miss } = err {
        doc_not_found(&mut screen, miss);
    } else if err.renders_own_screen() {
        // A self-rendering error (a help page, a gate report) is styled by
        // ipe's own renderers with the stderr palette, so its escapes pass
        // through; only the frame is added.
        screen.guttered(&text);
    } else {
        screen.line(fault.tone(), &text);
    }
    if fault == Fault::Internal {
        screen.with_bug_footer();
    }
    Some(screen)
}

/// The `ipe doc` miss: the query in the user-error tone, then the numbered
/// entries, each as the exact command that opens it.
fn doc_not_found(screen: &mut Screen, miss: &DocMiss) {
    screen.line(
        Tone::UserError,
        &crate::text::cli_doc_not_found(&miss.query),
    );
    if miss.hits.is_empty() {
        return;
    }
    let (header, more) = crate::doc_pick::human_parts(miss);
    screen.blank().line(Tone::Text, header);
    for line in crate::doc_pick::human_lines(miss) {
        screen.line(Tone::Text, &line);
    }
    if let Some(more) = more {
        screen.line(Tone::Aux, more);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(stream: Stream) -> Screen {
        Screen::with_color(stream, false)
    }

    #[test]
    fn frame_is_header_then_guttered_content() {
        let mut s = plain(Stream::Stdout);
        s.line(Tone::Text, "hello\nworld");
        let version = env!("CARGO_PKG_VERSION");
        assert_eq!(
            s.render(Header::Shown),
            format!(
                "\n  Ipê language - v{version} - {}\n\n  hello\n  world\n",
                style::REPO_URL
            )
        );
        assert_eq!(s.render(Header::Omitted), "\n  hello\n  world\n");
    }

    #[test]
    fn a_footed_screen_closes_with_the_bug_footer() {
        let mut s = plain(Stream::Stderr);
        s.line(Tone::InternalError, "boom").with_bug_footer();
        let out = s.render(Header::Omitted);
        assert!(
            out.ends_with(&format!(
                "  boom\n\n  {REPORT_BUGS_PHRASE}{}.\n",
                style::issues_url()
            )),
            "{out:?}"
        );
    }

    #[test]
    fn plain_screen_carries_no_ansi() {
        let mut s = plain(Stream::Stderr);
        s.line(Tone::InternalError, "x")
            .line(Tone::Success, "y")
            .line(Tone::Aux, "z")
            .with_bug_footer();
        let out = s.render(Header::Shown);
        assert!(!out.contains('\x1b'), "{out:?}");
    }

    #[test]
    fn each_tone_paints_its_palette_role() {
        let c = &Palette::COLOR;
        assert_eq!(Tone::Success.ink(c), c.green);
        assert_eq!(Tone::InternalError.ink(c), c.light_red);
        assert_eq!(Tone::UserError.ink(c), c.orange);
        assert_eq!(Tone::Text.ink(c), c.white);
        assert_eq!(Tone::Aux.ink(c), c.dim);
        assert_eq!(Fault::User.tone(), Tone::UserError);
        assert_eq!(Fault::Internal.tone(), Tone::InternalError);
        let mut s = Screen::with_color(Stream::Stderr, true);
        s.line(Tone::UserError, "bad");
        let out = s.render(Header::Omitted);
        assert!(
            out.contains(&format!("  {}bad{}", c.orange, c.reset)),
            "{out:?}"
        );
    }

    #[test]
    fn untrusted_line_text_cannot_inject_escapes() {
        let mut s = plain(Stream::Stderr);
        s.line(Tone::Text, "boom\u{1b}[2J\u{1b}[1;1H");
        let out = s.render(Header::Omitted);
        assert!(!out.contains('\x1b'), "{out:?}");
        assert!(out.contains("  boom"), "{out:?}");
    }

    #[test]
    fn chatter_is_the_lines_alone_with_no_blank_edge() {
        let mut s = plain(Stream::Stderr);
        s.line(Tone::Text, "• building\u{1b}[2J Main.ipe");
        assert_eq!(s.render_chatter(Header::Omitted), "  • building Main.ipe\n");
        let version = env!("CARGO_PKG_VERSION");
        assert_eq!(
            s.render_chatter(Header::Shown),
            format!(
                "\n  Ipê language - v{version} - {}\n\n  • building Main.ipe\n",
                style::REPO_URL
            )
        );
    }

    #[test]
    fn styled_chatter_keeps_its_blank_lines_and_indents_once() {
        assert_eq!(
            guttered_once("\n  already\nbare\n\n"),
            "\n  already\n  bare\n\n"
        );
    }

    #[test]
    fn guttered_block_is_indented_exactly_once() {
        let mut s = plain(Stream::Stderr);
        s.guttered("  already\nbare\n    nested");
        assert_eq!(
            s.render(Header::Omitted),
            "\n  already\n  bare\n    nested\n"
        );
    }

    #[test]
    fn styled_block_gains_the_gutter_and_keeps_blank_lines_empty() {
        let mut s = plain(Stream::Stdout);
        s.styled("\ntitle\n\nbody\n");
        assert_eq!(s.render(Header::Omitted), "\n  title\n\n  body\n");
    }

    #[test]
    fn a_user_error_is_orange_and_an_internal_error_light_red() {
        let usage = CliError::Usage(crate::text::msg::command_refusal(
            &"build",
            &"nothing to build here",
        ));
        let out = error_screen(&usage, true)
            .map(|s| s.render(Header::Omitted))
            .unwrap_or_default();
        assert!(out.contains(Palette::COLOR.orange), "{out:?}");
        assert!(!out.contains(Palette::COLOR.light_red), "{out:?}");
        assert!(!out.contains(REPORT_BUGS_PHRASE), "{out:?}");
    }

    /// An emitted build failed for `cargo` stderr `stderr`.
    fn emitted_build_failed(stderr: &str) -> CliError {
        CliError::EmittedBuildFailed {
            what: "the emitted program",
            code: 101,
            stderr: TerminalSafe::sanitize(stderr),
            runtime: None,
        }
    }

    #[test]
    fn only_an_internal_error_invites_a_bug_report() {
        let screen_of = |err: &CliError| {
            error_screen(err, false)
                .map(|s| s.render(Header::Omitted))
                .unwrap_or_default()
        };
        let miscompile = emitted_build_failed("error[E0609]: no field `x` on type `Y`");
        assert_eq!(miscompile.fault(), Fault::Internal);
        let out = screen_of(&miscompile);
        assert!(out.contains(REPORT_BUGS_PHRASE), "{out:?}");

        let offline = emitted_build_failed("Could not resolve host: index.crates.io");
        assert_eq!(offline.fault(), Fault::User);
        let out = screen_of(&offline);
        assert!(!out.contains(REPORT_BUGS_PHRASE), "{out:?}");

        let out = screen_of(&CliError::Usage(crate::text::msg::command_refusal(
            &"build",
            &"nothing to build here",
        )));
        assert!(!out.contains(REPORT_BUGS_PHRASE), "{out:?}");
    }

    #[test]
    fn a_doc_miss_lists_its_suggestions_as_commands() {
        let err = CliError::DocNotFound {
            miss: DocMiss {
                query: style::TerminalLine::sanitize("pipeline"),
                hits: vec![crate::doc_search::DocHit {
                    term: style::TerminalLine::sanitize("topic:pipelines"),
                    kind: crate::doc_bundle::DocKind::Topic,
                    summary: style::TerminalLine::sanitize("Pipelines"),
                }],
                closeness: crate::doc_search::Closeness::Match,
                truncated: true,
            },
        };
        let out = error_screen(&err, false)
            .map(|s| s.render(Header::Omitted))
            .unwrap_or_default();
        assert!(
            out.contains("  no documentation entry is named `pipeline`\n"),
            "{out:?}"
        );
        assert!(
            out.contains("    1. ipe doc topic:pipelines  Pipelines (topic)"),
            "{out:?}"
        );
        assert!(
            out.contains("  More entries match; refine the term."),
            "{out:?}"
        );
        assert!(!out.contains(REPORT_BUGS_PHRASE), "{out:?}");
    }

    #[test]
    fn an_error_that_already_wrote_its_output_renders_nothing() {
        assert!(error_screen(&CliError::DiagnosticJsonEmitted, false).is_none());
    }

    /// A clear-screen, a window-title OSC, a carriage return, and a cursor move,
    /// wrapped around the one printable word `foo`.
    const HOSTILE: &str = "\u{1b}[2J\u{1b}]0;pwned\u{7}\r\u{1b}[1;1Hfoo";

    /// Every escape ipe's own renderers paint with.
    ///
    /// The colour palette plus the diagnostic renderer's severity colours;
    /// anything else in a rendered screen was injected.
    const OWN_ESCAPES: [&str; 13] = [
        Palette::COLOR.yellow,
        Palette::COLOR.bright_yellow,
        Palette::COLOR.dim,
        Palette::COLOR.green,
        Palette::COLOR.red,
        Palette::COLOR.light_red,
        Palette::COLOR.orange,
        Palette::COLOR.white,
        Palette::COLOR.bold,
        Palette::COLOR.reset,
        "\x1b[31;1m",
        "\x1b[33;1m",
        "\x1b[34;1m",
    ];

    /// Assert `out` carries no control byte beyond ipe's own colour escapes and
    /// the two layout whitespaces.
    fn assert_no_foreign_control(out: &str) {
        let mut rest = out.to_owned();
        for esc in OWN_ESCAPES {
            rest = rest.replace(esc, "");
        }
        assert!(
            !rest
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t'),
            "foreign control byte reached the terminal: {out:?}"
        );
    }

    /// The coloured error screen `err` renders on a terminal.
    fn screen_of(err: &CliError) -> String {
        error_screen(err, true)
            .map(|s| s.render(Header::Omitted))
            .unwrap_or_default()
    }

    #[test]
    fn an_unknown_command_token_cannot_inject_escapes() {
        let err = crate::run_cli(&[HOSTILE.to_owned()]).err();
        assert!(
            matches!(err, Some(CliError::UnknownCommand { .. })),
            "{err:?}"
        );
        let out = err.as_ref().map(screen_of).unwrap_or_default();
        assert_no_foreign_control(&out);
        assert!(out.contains("unknown command `foo`"), "{out:?}");
    }

    #[test]
    fn an_unknown_group_verb_cannot_inject_escapes() {
        let err = crate::run_cli(&["dev".to_owned(), HOSTILE.to_owned()]).err();
        assert!(
            matches!(err, Some(CliError::UnknownGroupSub { .. })),
            "{err:?}"
        );
        let out = err.as_ref().map(screen_of).unwrap_or_default();
        assert_no_foreign_control(&out);
        assert!(out.contains("verb `foo`"), "{out:?}");
    }

    #[test]
    fn a_misused_flag_cannot_inject_escapes_into_the_help_screen() {
        let err = crate::run_cli(&["verify".to_owned(), format!("--bogus{HOSTILE}")]).err();
        assert!(
            matches!(
                err,
                Some(CliError::CommandUsage {
                    command: crate::verb::CommandName::Command("verify"),
                    ..
                })
            ),
            "{err:?}"
        );
        let out = err.as_ref().map(screen_of).unwrap_or_default();
        assert_no_foreign_control(&out);
    }

    #[test]
    fn a_manifest_value_cannot_inject_escapes_into_the_help_screen() {
        let err = crate::driver::with_help_on_misuse(
            crate::verb::Verb::DEV_BUILD,
            Err(CliError::Usage(crate::text::msg::command_refusal(
                &crate::verb::Verb::DEV_BUILD,
                &format!("unknown manifest value `{HOSTILE}`"),
            ))),
        )
        .err();
        assert!(
            matches!(err, Some(CliError::CommandUsage { .. })),
            "{err:?}"
        );
        let out = err.as_ref().map(screen_of).unwrap_or_default();
        assert_no_foreign_control(&out);
        assert!(out.contains("unknown manifest value `foo`"), "{out:?}");
    }

    #[test]
    fn a_hostile_path_cannot_inject_escapes() {
        let io = CliError::Io {
            path: std::path::PathBuf::from(format!("/tmp/{HOSTILE}.ipe")),
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        };
        let out = screen_of(&io);
        assert_no_foreign_control(&out);
        assert!(out.contains("/tmp/foo.ipe"), "{out:?}");

        let toolchain = CliError::ToolchainMissing(crate::toolchain::ToolchainMissing {
            intent: crate::toolchain::ToolIntent::Build,
            disposition: crate::toolchain::Disposition::NotOnPath {
                found_in: TerminalSafe::sanitize(&format!("/opt/{HOSTILE}")),
            },
        });
        let out = screen_of(&toolchain);
        assert_no_foreign_control(&out);
        assert!(out.contains("/opt/foo"), "{out:?}");
    }

    #[test]
    fn external_tool_output_cannot_inject_escapes() {
        let err = CliError::EmittedBuildFailed {
            what: "the emitted program",
            code: 101,
            stderr: TerminalSafe::sanitize(&format!("error: {HOSTILE}")),
            runtime: Some(crate::RuntimeContext {
                root: TerminalSafe::sanitize(&format!("/rt/{HOSTILE}")),
                version: TerminalSafe::sanitize(HOSTILE),
            }),
        };
        assert_no_foreign_control(&screen_of(&err));
    }

    #[test]
    fn machine_json_escapes_the_sanitised_message_exactly_once() {
        let err = CliError::Usage(crate::text::msg::command_refusal(
            &crate::verb::Verb::DEV_BUILD,
            &format!("bad value `a\"b\\c` {HOSTILE}"),
        ));
        let line = crate::machine_output::machine_error(
            crate::cli_args::OutputFormat::Json,
            "build",
            err.machine_kind(),
            &err.to_string(),
        );
        assert!(!line.contains('\u{1b}'), "{line:?}");
        let message = serde_json::from_str::<serde_json::Value>(line.trim_end())
            .ok()
            .and_then(|v| {
                v.pointer("/payload/message")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            });
        assert_eq!(
            message.as_deref(),
            Some("ipe dev build: bad value `a\"b\\c` foo")
        );
    }

    /// `indent_relay_chunk` is the single routine `ipe dev build` and `ipe dev watch`
    /// both call on every relayed cargo stderr chunk. Pin its two terminator
    /// shapes (`\n`-ended lines and `\r`-ended progress-bar redraws) plus the
    /// blank-line exemption, so neither relay site can drift back to "no
    /// indent at all" without this test catching it.
    #[test]
    fn indent_relay_chunk_adds_one_column_to_either_terminator() {
        assert_eq!(
            indent_relay_chunk("Compiling foo v0.1.0\n"),
            format!("{}Compiling foo v0.1.0\n", style::RELAY_INDENT)
        );
        assert_eq!(
            indent_relay_chunk("Building [=====>    ] 42%\r"),
            format!("{}Building [=====>    ] 42%\r", style::RELAY_INDENT)
        );
        // A chunk that is only a terminator (a blank line) stays blank, never
        // gaining a lone trailing indent space.
        assert_eq!(indent_relay_chunk("\n"), "\n");
    }
}

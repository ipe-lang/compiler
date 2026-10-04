//! The single source of truth for the `ipe` command-line look.
//!
//! It owns the colour palette, the status glyphs, the download spinner and
//! progress bar, and the two fixed strings (the repository URL and the "report
//! bugs" footer) that appear in both the CLI and the shell installer.
//!
//! Every visual fact lives here exactly once. The Rust help renderer, audit,
//! and diff import these constants directly; the shell installer
//! (`install.sh`) cannot import Rust, so it hand-mirrors the same
//! values and a drift test (`tests/install_style_drift.rs`) asserts the two
//! agree — an unmirrored change to either side fails CI.
//!
//! Colour is opt-in per output stream: ANSI escapes are emitted only when the
//! destination is a terminal and `NO_COLOR` is unset (per
//! <https://no-color.org>). Piped, redirected, or `NO_COLOR` output resolves to
//! the plain palette, whose every escape is the empty string, so one format
//! string yields either coloured or clean plain text.

use std::io::IsTerminal;

/// The repository home, shown in the CLI header and the "report bugs" footer,
/// and mirrored by the installer.
///
/// Re-exported from [`ipe_diagnostics`] rather than defined here, so the whole
/// binary — CLI and diagnostics alike — derives the URL from one constant.
pub use ipe_diagnostics::REPO_URL;

/// The lead phrase of the "report bugs" footer, before the issues URL.
pub const REPORT_BUGS_PHRASE: &str = "If you find any bugs, please report them at ";

/// The issue tracker URL the "report bugs" footer points at.
#[must_use]
pub fn issues_url() -> String {
    format!("{REPO_URL}/issues")
}

/// The "report bugs" footer, `{REPORT_BUGS_PHRASE}{issues_url()}.`, unstyled.
///
/// The installer mirrors the rendered text; the CLI renderer paints the same two parts.
#[must_use]
pub fn report_bugs_footer() -> String {
    format!("{REPORT_BUGS_PHRASE}{}.", issues_url())
}

/// The product header line, `Ipê language - v{version} - {REPO_URL}`.
///
/// Rendered with no colour; the help renderer inserts the palette escapes around
/// the segments. This is the plain skeleton the header text agrees on.
#[must_use]
pub fn header_line(version: &str) -> String {
    format!("Ipê language - v{version} - {REPO_URL}")
}

/// The left gutter that indents every human-facing line.
///
/// It leads help pages, banners, status chatter, and diagnostics. Two spaces, so
/// prose sits off the terminal edge while machine output (`--plain` / `--json` /
/// a `run` child's stdout) stays flush-left for `grep` / `awk` / `jq`. The single
/// width lives here so every command and the installer indent identically.
pub const GUTTER: &str = "  ";

/// Prefix every non-empty line of `text` with the [`GUTTER`].
///
/// Blank lines stay empty (an indented blank line is trailing whitespace, not
/// structure). This is how a command renders human output: build the plain body,
/// then gutter it once at the edge.
#[must_use]
pub fn gutter(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        // Split off the trailing newline so an empty line stays empty rather
        // than becoming two gutter spaces.
        let (body, newline) = line.strip_suffix('\n').map_or((line, ""), |b| (b, "\n"));
        if !body.is_empty() {
            out.push_str(GUTTER);
        }
        out.push_str(body);
        out.push_str(newline);
    }
    out
}

/// The single extra column relayed child (cargo) output is shifted by.
///
/// Cargo's own progress bar and diagnostics already carry their own internal
/// alignment; this is not a full [`GUTTER`] (that would fight cargo's column
/// math) but one shared space so the relay sits off the terminal edge instead
/// of flush against it. One space, defined once, so `ipe dev build`'s and `ipe
/// dev watch`'s cargo relays can never drift apart — the exact bug this constant
/// closes: two independent call sites hand-rolling the same "no indent at
/// all" default.
pub const RELAY_INDENT: &str = " ";

/// Frame a human block with exactly one leading and one trailing newline.
///
/// A command's output opens and closes with a blank edge — a consistent
/// breathing frame around the guttered prose. Any surrounding newlines in `body`
/// are normalised to one each.
///
/// Machine output (`--plain` / `--json`, a `run` child's stdout) is NEVER framed
/// — it stays flush and unwrapped for `grep` / `jq`, like the [`gutter`] it also
/// skips.
#[must_use]
pub fn frame(body: &str) -> String {
    format!("\n{}\n", body.trim_matches('\n'))
}

/// The status glyphs that lead a line of progress chatter: a step bullet, a
/// success check, and a failure cross. Shared by the CLI and the installer.
pub mod glyph {
    /// A step in progress (leads an in-flight status line).
    pub const STEP: &str = "•";
    /// A completed step (leads a success line).
    pub const OK: &str = "✓";
    /// A failed step (leads a failure line).
    pub const FAIL: &str = "✗";
}

/// The semantic role of a human-facing status line — the outcome the line
/// reports, independent of how it is painted.
///
/// This is the composition vocabulary above the raw [`glyph`] and [`Palette`]
/// facts: a call site names the *outcome* ([`Outcome::Success`]) and lets
/// [`outcome_glyph`] and [`outcome_tint`] resolve the glyph and tint together,
/// so the glyph and colour of an outcome are chosen in exactly one place. A
/// site that instead picks `glyph::OK` beside `palette.green` by hand can drift
/// (a green cross, a red check); routing through the outcome closes that class.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// A step in progress: the step bullet, painted in the running amber.
    Step,
    /// A completed step: the success check, painted green.
    Success,
    /// A failed step: the failure cross, painted red.
    Failure,
}

impl Outcome {
    /// The glyph and tint (against `p`) for this outcome, resolved together.
    #[must_use]
    pub const fn glyph_and_tint(self, p: &Palette) -> (&'static str, &'static str) {
        (outcome_glyph(self), outcome_tint(self, p))
    }
}

/// The glyph that leads a line reporting `outcome` — the single mapping from a
/// semantic outcome to its [`glyph`], so a step, a success, and a failure each
/// pick their bullet in one place.
#[must_use]
pub const fn outcome_glyph(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Step => glyph::STEP,
        Outcome::Success => glyph::OK,
        Outcome::Failure => glyph::FAIL,
    }
}

/// The tint (an escape from `p`) that paints a line reporting `outcome`.
///
/// Amber for a step in progress, green for a success, red for a failure — the
/// single mapping from a semantic outcome to its palette field, paired with
/// [`outcome_glyph`] so glyph and colour never drift apart.
#[must_use]
pub const fn outcome_tint(outcome: Outcome, p: &Palette) -> &'static str {
    match outcome {
        Outcome::Step => p.bright_yellow,
        Outcome::Success => p.green,
        Outcome::Failure => p.red,
    }
}

/// The braille download spinner, one frame per animation tick. The installer
/// mirrors these ten frames in its `spin_glyph` case.
pub const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// The progress-bar geometry: the total cell count and the filled/empty cell
/// characters. The installer mirrors these when it renders the download bar.
pub mod progress_bar {
    /// The bar's width in cells.
    pub const WIDTH: usize = 24;
    /// The character for a filled cell.
    pub const FILLED: char = '#';
    /// The character for an empty cell.
    pub const EMPTY: char = '-';
}

/// The ANSI palette, resolved once against a destination stream. When colour is
/// off every field is the empty string, so the same format code produces clean
/// plain text.
pub struct Palette {
    /// A soft Ipê-amarelo (256-colour 222), for the product name and command
    /// names.
    pub yellow: &'static str,
    /// A bright/light yellow (ANSI bright yellow), for the `ipe health`
    /// suggested-fix bullets — a stronger amber than [`yellow`](Self::yellow) so
    /// each actionable item stands out from the report above it.
    pub bright_yellow: &'static str,
    /// A mid grey (256-colour 244), for descriptions and the footer.
    pub dim: &'static str,
    /// A soft green (256-colour 114), for success emphasis.
    pub green: &'static str,
    /// A plain red, for failure emphasis.
    pub red: &'static str,
    /// A light red (ANSI bright red), for an internal (ipe-side) error.
    pub light_red: &'static str,
    /// A light orange (256-colour 215), for a user-side error.
    pub orange: &'static str,
    /// A soft white (256-colour 252), for common text.
    pub white: &'static str,
    /// A bold weight, for section titles and headers.
    pub bold: &'static str,
    /// Resets all attributes.
    pub reset: &'static str,
}

impl Palette {
    /// The coloured palette: a soft Ipê-amarelo (222) for names, a mid grey
    /// (244) for dim text, a soft green (114) for success, plain red for
    /// failure.
    pub const COLOR: Self = Self {
        yellow: "\x1b[38;5;222m",
        bright_yellow: "\x1b[93m",
        dim: "\x1b[38;5;244m",
        green: "\x1b[38;5;114m",
        red: "\x1b[31m",
        light_red: "\x1b[91m",
        orange: "\x1b[38;5;215m",
        white: "\x1b[38;5;252m",
        bold: "\x1b[1m",
        reset: "\x1b[0m",
    };

    /// The plain palette: every escape is empty, yielding aligned plain text.
    pub const PLAIN: Self = Self {
        yellow: "",
        bright_yellow: "",
        dim: "",
        green: "",
        red: "",
        light_red: "",
        orange: "",
        white: "",
        bold: "",
        reset: "",
    };

    /// Select the coloured palette when `color` is on, else the plain one.
    #[must_use]
    pub const fn select(color: bool) -> &'static Self {
        if color { &Self::COLOR } else { &Self::PLAIN }
    }

    /// Select the palette for `stream`: coloured only when it is a terminal and
    /// `NO_COLOR` is unset (per <https://no-color.org>).
    #[must_use]
    pub fn for_stream(stream: &impl IsTerminal) -> &'static Self {
        Self::select(use_color(stream))
    }
}

/// Whether to emit ANSI to `stream`: only when it is a terminal and `NO_COLOR`
/// is unset (per <https://no-color.org>).
#[must_use]
pub fn use_color(stream: &impl IsTerminal) -> bool {
    stream.is_terminal() && ipe_env::var_os("NO_COLOR").is_none()
}

/// Build the sandbox-override warning line for stderr.
///
/// Returns a guttered, framed string ready to pass to `eprint!`. Bold-red when
/// `p` is the colour palette; plain text when it is the plain palette (i.e.
/// when stderr is not a terminal or `NO_COLOR` is set). The message text and
/// interpolated values are owned by the caller; this function only applies the
/// palette and layout.
#[must_use]
pub fn sandbox_override_warning(p: &Palette, override_env: &str, axes: &str) -> String {
    frame(&gutter(&format!(
        "{bold}{red}warning: {override_env}=1 — running native Rust code ({axes}) WITHOUT a \
         capability jail. Its effects are NOT proven safe and it runs with your full authority. \
         Install a jail primitive to confine it; never set this in CI.{reset}",
        bold = p.bold,
        red = p.red,
        reset = p.reset,
    )))
}

/// Build the shadowed-abbreviation warning line for stderr.
///
/// A `{git=}` escape's requested abbreviated hex ref was shadowed by a
/// same-shaped branch or tag name, so git served that ref's commit instead of
/// resolving the hex as an object id. Warn, never refuse: the checkout
/// succeeded and `served` — the commit actually checked out — is what gets
/// locked. Bold-red when `p` is the colour palette; plain text otherwise.
#[must_use]
pub fn escape_abbrev_shadowed_warning(
    p: &Palette,
    pkg: &str,
    requested: &str,
    served: &str,
) -> String {
    frame(&gutter(&format!(
        "{bold}{red}warning: package `{pkg}`: requested rev `{requested}` is shadowed by a ref of \
         the same name — git served commit `{served}`, not an abbreviation lookup. Locking the \
         served commit; rename the ref or use its full SHA to pin the abbreviation instead.{reset}",
        bold = p.bold,
        red = p.red,
        reset = p.reset,
    )))
}

/// The product header that opens every human screen.
///
/// A leading blank line, then `Ipê language - vN.N.N - <repo>` in the gutter,
/// then a trailing blank line so the banner is set off from whatever chatter
/// follows it — the name light yellow, the version light green, the URL dim
/// gray. Never shown under `--plain`, `--json`, or `--quiet`.
///
/// Coloured when `use_color` is true; plain otherwise. [`crate::screen`] owns
/// when it is printed (once per process).
#[must_use]
pub fn command_header(use_color: bool) -> String {
    let version = env!("CARGO_PKG_VERSION");
    let p = Palette::select(use_color);
    format!(
        "\n{GUTTER}{y}Ipê language{r} - {g}v{version}{r} - {d}{REPO_URL}{r}\n\n",
        y = p.bright_yellow,
        g = p.green,
        d = p.dim,
        r = p.reset,
    )
}

/// Print the product header to stderr (once per process), respecting the terminal / `NO_COLOR`
/// state of stderr.
///
/// Called at the start of human-mode commands so the header leads their progress chatter.
pub fn print_command_header() {
    crate::screen::emit_header(crate::screen::Stream::Stderr);
}

/// The terminal-safe text boundary, defined once in the lowest shared crate so
/// a compiler stage that builds a user-facing refusal sanitises with the same
/// rules the CLI applies to every message it prints.
pub use ipe_diagnostics::terminal::TerminalSafe;

/// The single-terminal-line boundary; see [`ipe_diagnostics::terminal::TerminalLine`].
pub use ipe_diagnostics::terminal::TerminalLine;

/// A framed, guttered status line: a leading success/failure glyph, then the
/// message. `ok` picks the green check or the red cross; `color` toggles ANSI.
///
/// The one way a human-mode command reports a completed step — replacing a bare
/// left-flush spinner line with `<glyph> <message>` plus the 2-space gutter.
///
/// The message is already-sanitised [`TerminalSafe`], mirroring [`crate::screen::Screen::line`]:
/// the line's own glyph/colour escapes are the only control bytes the output may
/// carry, so a message routed here can never smuggle ANSI or control bytes to the
/// terminal.
#[must_use]
pub fn status_line(ok: bool, message: &TerminalSafe, color: bool) -> String {
    let p = Palette::select(color);
    let outcome = if ok {
        Outcome::Success
    } else {
        Outcome::Failure
    };
    let (glyph, tint) = outcome.glyph_and_tint(p);
    frame(&gutter(&format!("{tint}{glyph}{} {message}", p.reset)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_palette_carries_ansi_plain_does_not() {
        assert!(Palette::COLOR.yellow.contains('\x1b'));
        assert!(Palette::PLAIN.yellow.is_empty());
        // The bright-yellow field the health fix bullets use follows the same
        // rule: an escape under colour, empty under plain.
        assert!(Palette::COLOR.bright_yellow.contains('\x1b'));
        assert!(Palette::PLAIN.bright_yellow.is_empty());
        // `select` returns the coloured palette on true, the plain one on false.
        assert!(Palette::select(true).red.contains('\x1b'));
        assert!(Palette::select(false).red.is_empty());
    }

    #[test]
    fn outcome_pairs_each_glyph_with_its_tint_in_one_place() {
        // Each outcome resolves its glyph and tint together, so the pairing is
        // defined once — a step bullet in amber, a success check in green, a
        // failure cross in red.
        let c = &Palette::COLOR;
        assert_eq!(outcome_glyph(Outcome::Step), glyph::STEP);
        assert_eq!(outcome_glyph(Outcome::Success), glyph::OK);
        assert_eq!(outcome_glyph(Outcome::Failure), glyph::FAIL);
        assert_eq!(outcome_tint(Outcome::Step, c), c.bright_yellow);
        assert_eq!(outcome_tint(Outcome::Success, c), c.green);
        assert_eq!(outcome_tint(Outcome::Failure, c), c.red);
        // The convenience pairing agrees with the two field functions.
        assert_eq!(Outcome::Success.glyph_and_tint(c), (glyph::OK, c.green));
        // Under the plain palette every tint is empty, so no ANSI leaks.
        assert!(outcome_tint(Outcome::Failure, &Palette::PLAIN).is_empty());
    }

    #[test]
    fn status_line_routes_success_and_failure_through_the_outcome_ssot() {
        let ok = status_line(true, &TerminalSafe::sanitize("built"), true);
        assert!(ok.contains(glyph::OK), "success uses the check glyph");
        assert!(ok.contains(Palette::COLOR.green), "success is green");
        assert!(!ok.contains(Palette::COLOR.red), "success is never red");
        let bad = status_line(false, &TerminalSafe::sanitize("broke"), true);
        assert!(bad.contains(glyph::FAIL), "failure uses the cross glyph");
        assert!(bad.contains(Palette::COLOR.red), "failure is red");
        assert!(
            !bad.contains(Palette::COLOR.green),
            "failure is never green"
        );
        // Plain mode carries no ANSI in either outcome.
        assert!(!status_line(true, &TerminalSafe::sanitize("built"), false).contains('\x1b'));
        assert!(!status_line(false, &TerminalSafe::sanitize("broke"), false).contains('\x1b'));
    }

    #[test]
    fn footer_and_header_carry_the_repo_url() {
        assert!(report_bugs_footer().contains(REPO_URL));
        assert!(report_bugs_footer().ends_with("/issues."));
        assert!(header_line("9.9.9").contains(REPO_URL));
        assert!(header_line("9.9.9").contains("v9.9.9"));
    }

    #[test]
    fn command_header_has_leading_newline_gutter_version_and_url() {
        let h = command_header(false);
        // Starts with a blank line so the banner breathes at the top of output.
        assert!(h.starts_with('\n'), "banner has leading newline");
        // The 2-space gutter is present.
        assert!(h.contains(GUTTER), "banner has gutter");
        // The runtime version is embedded dynamically.
        assert!(
            h.contains(env!("CARGO_PKG_VERSION")),
            "banner carries crate version"
        );
        // The canonical project URL is present.
        assert!(h.contains(REPO_URL), "banner carries repo URL");
        // The plain variant has no ANSI escapes.
        assert!(!h.contains('\x1b'), "plain banner has no ANSI");
    }

    #[test]
    fn command_header_colour_mode_has_ansi() {
        let h = command_header(true);
        assert!(h.contains('\x1b'), "colour banner carries ANSI");
    }

    #[test]
    fn command_header_paints_name_version_and_url_in_their_roles() {
        let h = command_header(true);
        let c = &Palette::COLOR;
        let version = env!("CARGO_PKG_VERSION");
        assert!(
            h.contains(&format!("{}Ipê language{}", c.bright_yellow, c.reset)),
            "name is light yellow: {h:?}"
        );
        assert!(
            h.contains(&format!("{}v{version}{}", c.green, c.reset)),
            "version is light green: {h:?}"
        );
        assert!(
            h.contains(&format!("{}{REPO_URL}{}", c.dim, c.reset)),
            "URL is dim gray: {h:?}"
        );
        assert_eq!(
            command_header(false),
            format!("\n  Ipê language - v{version} - {REPO_URL}\n\n")
        );
    }

    #[test]
    fn report_bugs_footer_is_phrase_then_issues_url() {
        assert_eq!(
            report_bugs_footer(),
            format!("{REPORT_BUGS_PHRASE}{REPO_URL}/issues.")
        );
    }

    #[test]
    fn gutter_indents_prose_lines_and_leaves_blanks_empty() {
        let g = gutter("one\n\ntwo\n");
        assert_eq!(g, "  one\n\n  two\n");
        // A body with no trailing newline is still guttered.
        assert_eq!(gutter("tail"), "  tail");
        // The gutter is exactly the two-space SSOT width.
        assert_eq!(GUTTER, "  ");
    }

    #[test]
    fn frame_wraps_a_block_in_one_leading_and_trailing_newline() {
        // A bare body gains exactly one newline on each edge.
        assert_eq!(frame("  body"), "\n  body\n");
        // Surrounding newlines are normalised to one each (never doubled).
        assert_eq!(frame("\n\n  page\n\n"), "\n  page\n");
        // Interior blank lines are preserved.
        assert_eq!(frame("a\n\nb"), "\na\n\nb\n");
    }

    #[test]
    fn spinner_has_ten_frames_and_bar_chars_differ() {
        assert_eq!(SPINNER_FRAMES.len(), 10);
        // Every frame is a distinct non-empty glyph, and the filled/empty bar
        // cells are different characters so the bar reads.
        assert!(SPINNER_FRAMES.iter().all(|f| !f.is_empty()));
        assert_ne!(progress_bar::FILLED, progress_bar::EMPTY);
    }
}

//! Ipe.Tui — the one typed "is an interactive terminal available" probe.
//!
//! Std-only (no crossterm, no feature gate): both the `ipe dev run`/`ipe dev watch`
//! pre-build gate (over `Shape::Tui`, before any cargo work starts) and the
//! `tui`-feature runtime guard (`TuiGuard::enter*`, right before
//! `crossterm::terminal::enable_raw_mode`) decide from the SAME facts and the
//! SAME refusal text, so a Tui program is refused identically whether the
//! check runs before the build or inside the built binary.
//!
//! [`decide`] is pure and table-tested; [`probe`] is the only place that reads
//! the process environment or touches a file descriptor.
//!
//! A `Cli.tea` run's line surface is decided the same way: `decide_line` is
//! pure over [`LineFacts`], which name both stdin and stdout, and
//! `probe_line` is the only reader of those fds and of `TERM` on that path.

use std::ffi::OsString;
use std::io::IsTerminal;

/// Whether an interactive terminal is available for a Tui program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalAccess {
    Interactive,
    Refused(NoTerminal),
}

/// Why an interactive terminal is not available — closed set, one fix each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoTerminal {
    /// `TERM=dumb`: the terminal declares itself non-interactive.
    DumbTerm,
    /// Stdout is not a terminal (piped, redirected, or captured).
    NoStdoutTty,
    /// Stdin is not a terminal and no controlling terminal (`/dev/tty`) is
    /// reachable either — a detached or fully non-interactive session.
    NoControllingTerminal,
}

impl NoTerminal {
    /// The one phrase for this refusal, naming the fix. The CLI gate and the
    /// runtime guard both show this text verbatim — neither restates it.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::DumbTerm => {
                "a Tui app needs an interactive terminal, but TERM=dumb declares this one is not"
            }
            Self::NoStdoutTty => {
                "a Tui app needs an interactive terminal, but stdout is piped or redirected — run it directly in a terminal"
            }
            Self::NoControllingTerminal => {
                "a Tui app needs an interactive terminal, but none is reachable — stdin is piped or the session has no controlling terminal"
            }
        }
    }
}

/// The raw facts [`decide`] classifies. Grouping them lets `decide` stay pure
/// (and table-tested) while [`probe`] owns every side effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalFacts {
    pub stdout_tty: bool,
    pub stdin_tty: bool,
    pub term: Option<OsString>,
    /// Whether a controlling terminal is reachable some other way than stdin
    /// itself being one (on unix, whether `/dev/tty` opens). Always equal to
    /// `stdin_tty` on a target with no such fallback.
    pub dev_tty_opens: bool,
}

/// Classify [`TerminalFacts`] into a [`TerminalAccess`] decision. Pure: no I/O.
///
/// Order matters and is the refusal's specificity, most decisive first: a
/// non-terminal stdout makes any further check moot (nothing could render);
/// `TERM=dumb` is an explicit self-declaration; only then does the weaker
/// controlling-terminal signal (stdin / `/dev/tty`) apply.
#[must_use]
pub fn decide(facts: &TerminalFacts) -> TerminalAccess {
    if !facts.stdout_tty {
        return TerminalAccess::Refused(NoTerminal::NoStdoutTty);
    }
    if facts.term.as_deref() == Some(std::ffi::OsStr::new("dumb")) {
        return TerminalAccess::Refused(NoTerminal::DumbTerm);
    }
    if !facts.stdin_tty && !facts.dev_tty_opens {
        return TerminalAccess::Refused(NoTerminal::NoControllingTerminal);
    }
    TerminalAccess::Interactive
}

/// Gather [`TerminalFacts`] from the real process and classify them.
///
/// Reads `TERM` directly from the process environment (not through the
/// `System.setenv` overlay in `system.rs`): `crossterm::terminal::enable_raw_mode`
/// itself reads the real environment, so this probe must observe exactly what
/// crossterm will observe, overlay or not.
#[must_use]
pub fn probe() -> TerminalAccess {
    let stdout_tty = std::io::stdout().is_terminal();
    let stdin_tty = std::io::stdin().is_terminal();
    #[expect(
        clippy::disallowed_methods,
        reason = "crossterm reads the real env directly; this probe must observe the same, overlay or not"
    )]
    let term = std::env::var_os("TERM");
    let dev_tty_opens = stdin_tty || open_dev_tty();
    decide(&TerminalFacts {
        stdout_tty,
        stdin_tty,
        term,
        dev_tty_opens,
    })
}

/// Whether a controlling terminal is reachable through `/dev/tty` — tried only
/// when stdin itself is not a tty, mirroring crossterm's own `tty_fd` fallback.
/// Non-unix targets have no `/dev/tty`, so the fallback never succeeds there.
#[cfg(unix)]
fn open_dev_tty() -> bool {
    std::fs::File::open("/dev/tty").is_ok()
}

#[cfg(not(unix))]
fn open_dev_tty() -> bool {
    false
}

/// Whether stdin and stdout are one and the same terminal device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SameTerminal {
    /// Both are the same character device.
    Yes,
    /// They are different devices, or one is not a terminal.
    No,
    /// The probe could not tell; `decide_line` treats it as [`Self::No`].
    Unknown,
}

/// Whether a `Cli.tea` run holds the exit hook that ends an open line on exit.
///
/// `System.exit` skips the loop's own close, so a line may stay open only
/// when the hook that ends it on that path is registered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitClose {
    /// The hook is registered: an exit ends an open line.
    Registered,
    /// Another driver holds the one exit-hook slot, so an exit could leave a
    /// line open.
    Unavailable,
}

/// The raw facts `decide_line` classifies into a `Cli.tea` line surface.
///
/// Every fd the surface depends on is named here: the frame style depends on
/// stdout alone, but whether the last line may stay open depends on stdin's
/// echo and on stdin and stdout being one terminal.
#[derive(Clone, Debug, PartialEq)]
pub struct LineFacts {
    pub stdout_tty: bool,
    pub stdin_tty: bool,
    /// Whether stdin's terminal echoes typed input (termios `ECHO`).
    pub stdin_echo: bool,
    pub same_terminal: SameTerminal,
    /// `TERM`, read through the runtime env overlay.
    pub term: Option<String>,
    /// The colour profile a styled surface degrades to.
    pub profile: crate::color::TermProfile,
    pub exit_close: ExitClose,
}

/// Classify [`LineFacts`] into the one surface of a `Cli.tea` run. Pure: no I/O.
///
/// Style: a non-terminal stdout, or `TERM=dumb`, writes plain lines; any other
/// terminal is styled under the profile. End: the last line stays open only
/// when the echo of the user's Enter is certain to end it (stdin and stdout
/// one echoing terminal) and an exit is certain to end it otherwise; every
/// other combination, an unknown one included, ends each frame in `\n`.
#[cfg(feature = "tui")]
#[must_use]
pub fn decide_line(facts: &LineFacts) -> crate::tui::LineSurface {
    use crate::tui::{FrameEnd, LineStyle};
    let style = if !facts.stdout_tty || facts.term.as_deref() == Some("dumb") {
        LineStyle::Plain
    } else {
        LineStyle::Sgr(facts.profile)
    };
    let prompt_open = facts.stdout_tty
        && facts.stdin_tty
        && facts.stdin_echo
        && facts.same_terminal == SameTerminal::Yes
        && facts.exit_close == ExitClose::Registered;
    let end = if prompt_open {
        FrameEnd::PromptOpen
    } else {
        FrameEnd::Newline
    };
    crate::tui::LineSurface::decided(style, end)
}

/// Gather the [`LineFacts`] of this process's stdin and stdout.
///
/// The only fd and environment reads of the `Cli.tea` surface. A failed
/// syscall reads as the fact that ends frames in `\n` (no echo, not the same
/// terminal). `TERM` goes through the runtime env overlay, the reader
/// `color::resolve_term_profile` uses, since no crossterm sits on this path.
#[cfg(all(feature = "tui", not(target_arch = "wasm32")))]
#[must_use]
pub fn probe_line(exit_close: ExitClose) -> LineFacts {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let stdout_tty = stdout.is_terminal();
    let stdin_tty = stdin.is_terminal();
    let (stdin_echo, same_terminal) = probe_echo_and_device(&stdin, &stdout, stdin_tty, stdout_tty);
    LineFacts {
        stdout_tty,
        stdin_tty,
        stdin_echo,
        same_terminal,
        term: crate::system::read_env_var("TERM").ok(),
        profile: crate::color::resolve_term_profile(),
        exit_close,
    }
}

/// Stdin's echo flag, and whether stdin and stdout are one terminal.
///
/// One terminal means both are character devices with one device number.
#[cfg(all(feature = "tui", unix))]
fn probe_echo_and_device(
    stdin: &std::io::Stdin,
    stdout: &std::io::Stdout,
    stdin_tty: bool,
    stdout_tty: bool,
) -> (bool, SameTerminal) {
    use rustix::fs::FileType;
    let echo = stdin_tty
        && rustix::termios::tcgetattr(stdin)
            .is_ok_and(|t| t.local_modes.contains(rustix::termios::LocalModes::ECHO));
    if !(stdin_tty && stdout_tty) {
        return (echo, SameTerminal::No);
    }
    let same = match (rustix::fs::fstat(stdin), rustix::fs::fstat(stdout)) {
        (Ok(a), Ok(b))
            if FileType::from_raw_mode(a.st_mode) == FileType::CharacterDevice
                && FileType::from_raw_mode(b.st_mode) == FileType::CharacterDevice =>
        {
            if a.st_rdev == b.st_rdev {
                SameTerminal::Yes
            } else {
                SameTerminal::No
            }
        }
        _ => SameTerminal::Unknown,
    };
    (echo, same)
}

/// Stdin's echo flag, and whether stdin and stdout are one terminal.
///
/// No device number is read off unix: two console handles are taken as the
/// one console, and a console in its default cooked mode echoes input, so
/// both consoles read as one echoing terminal; anything else is unknown.
#[cfg(all(feature = "tui", not(unix), not(target_arch = "wasm32")))]
const fn probe_echo_and_device(
    _stdin: &std::io::Stdin,
    _stdout: &std::io::Stdout,
    stdin_tty: bool,
    stdout_tty: bool,
) -> (bool, SameTerminal) {
    if stdin_tty && stdout_tty {
        (true, SameTerminal::Yes)
    } else {
        (false, SameTerminal::Unknown)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::{NoTerminal, TerminalAccess, TerminalFacts, decide};
    use std::ffi::OsString;

    fn facts(
        stdout_tty: bool,
        stdin_tty: bool,
        term: Option<&str>,
        dev_tty_opens: bool,
    ) -> TerminalFacts {
        TerminalFacts {
            stdout_tty,
            stdin_tty,
            term: term.map(OsString::from),
            dev_tty_opens,
        }
    }

    #[test]
    fn stdout_not_a_tty_is_refused_first() {
        assert_eq!(
            decide(&facts(false, true, Some("xterm"), true)),
            TerminalAccess::Refused(NoTerminal::NoStdoutTty)
        );
    }

    #[test]
    fn dumb_term_is_refused() {
        assert_eq!(
            decide(&facts(true, true, Some("dumb"), true)),
            TerminalAccess::Refused(NoTerminal::DumbTerm)
        );
    }

    #[test]
    fn no_stdin_tty_and_no_dev_tty_is_refused() {
        assert_eq!(
            decide(&facts(true, false, Some("xterm"), false)),
            TerminalAccess::Refused(NoTerminal::NoControllingTerminal)
        );
    }

    #[test]
    fn no_stdin_tty_but_dev_tty_opens_is_interactive() {
        assert_eq!(
            decide(&facts(true, false, Some("xterm"), true)),
            TerminalAccess::Interactive
        );
    }

    #[test]
    fn all_tty_is_interactive() {
        assert_eq!(
            decide(&facts(true, true, Some("xterm"), true)),
            TerminalAccess::Interactive
        );
    }

    #[test]
    fn term_unset_is_interactive() {
        assert_eq!(
            decide(&facts(true, true, None, true)),
            TerminalAccess::Interactive
        );
    }
}

#[cfg(all(test, feature = "tui", not(target_arch = "wasm32")))]
mod line_tests {
    use super::{ExitClose, LineFacts, SameTerminal, decide_line};
    use crate::color::TermProfile;
    use crate::tui::{FrameEnd, LineStyle};

    /// The one fact set under which a frame's last line may stay open.
    fn interactive() -> LineFacts {
        LineFacts {
            stdout_tty: true,
            stdin_tty: true,
            stdin_echo: true,
            same_terminal: SameTerminal::Yes,
            term: Some("xterm-256color".to_owned()),
            profile: TermProfile::Ansi256,
            exit_close: ExitClose::Registered,
        }
    }

    /// Every fact combination, `TERM` drawn from unset, `dumb` and a real one.
    fn every_fact_set() -> Vec<LineFacts> {
        let mut all = Vec::new();
        for stdout_tty in [false, true] {
            for stdin_tty in [false, true] {
                for stdin_echo in [false, true] {
                    for same_terminal in
                        [SameTerminal::Yes, SameTerminal::No, SameTerminal::Unknown]
                    {
                        for term in [None, Some("dumb"), Some("xterm")] {
                            for exit_close in [ExitClose::Registered, ExitClose::Unavailable] {
                                all.push(LineFacts {
                                    stdout_tty,
                                    stdin_tty,
                                    stdin_echo,
                                    same_terminal,
                                    term: term.map(str::to_owned),
                                    profile: TermProfile::TrueColor,
                                    exit_close,
                                });
                            }
                        }
                    }
                }
            }
        }
        all
    }

    // A terminal stdout fed by a pipe: the stdout-only rule kept the prompt
    // line open, so every frame glued onto the last; the decision names stdin.
    #[test]
    fn stdout_tty_with_piped_stdin_ends_every_frame() {
        let piped = LineFacts {
            stdin_tty: false,
            stdin_echo: false,
            same_terminal: SameTerminal::No,
            ..interactive()
        };
        let stdout_only_end = if piped.stdout_tty {
            FrameEnd::PromptOpen
        } else {
            FrameEnd::Newline
        };
        assert_eq!(stdout_only_end, FrameEnd::PromptOpen);
        let surface = decide_line(&piped);
        assert_eq!(surface.end(), FrameEnd::Newline);
        assert_eq!(surface.style(), LineStyle::Sgr(TermProfile::Ansi256));
    }

    #[test]
    fn non_echoing_stdin_ends_every_frame() {
        let facts = LineFacts {
            stdin_echo: false,
            ..interactive()
        };
        assert_eq!(decide_line(&facts).end(), FrameEnd::Newline);
    }

    #[test]
    fn a_different_or_unknown_terminal_ends_every_frame() {
        for same_terminal in [SameTerminal::No, SameTerminal::Unknown] {
            let facts = LineFacts {
                same_terminal,
                ..interactive()
            };
            assert_eq!(
                decide_line(&facts).end(),
                FrameEnd::Newline,
                "{same_terminal:?}"
            );
        }
    }

    #[test]
    fn an_unheld_exit_hook_ends_every_frame() {
        let facts = LineFacts {
            exit_close: ExitClose::Unavailable,
            ..interactive()
        };
        assert_eq!(decide_line(&facts).end(), FrameEnd::Newline);
    }

    #[test]
    fn dumb_term_is_plain() {
        let facts = LineFacts {
            term: Some("dumb".to_owned()),
            ..interactive()
        };
        assert_eq!(decide_line(&facts).style(), LineStyle::Plain);
        // One step past: a terminal named otherwise is styled, NO_COLOR's
        // profile included (it drops colours, not bold).
        let no_color = LineFacts {
            term: Some("dumber".to_owned()),
            profile: TermProfile::NoColor,
            ..interactive()
        };
        assert_eq!(
            decide_line(&no_color).style(),
            LineStyle::Sgr(TermProfile::NoColor)
        );
    }

    #[test]
    fn non_tty_stdout_is_plain_for_every_other_fact() {
        for facts in every_fact_set().into_iter().filter(|f| !f.stdout_tty) {
            let surface = decide_line(&facts);
            assert_eq!(surface.style(), LineStyle::Plain, "{facts:?}");
            assert_eq!(surface.end(), FrameEnd::Newline, "{facts:?}");
        }
    }

    // Only the full conjunction keeps the prompt line open; dropping any one
    // fact of it ends every frame.
    #[test]
    fn only_the_full_conjunction_keeps_the_prompt_open() {
        for facts in every_fact_set() {
            let full = facts.stdout_tty
                && facts.stdin_tty
                && facts.stdin_echo
                && facts.same_terminal == SameTerminal::Yes
                && facts.exit_close == ExitClose::Registered;
            let expected = if full {
                FrameEnd::PromptOpen
            } else {
                FrameEnd::Newline
            };
            assert_eq!(decide_line(&facts).end(), expected, "{facts:?}");
        }
        assert_eq!(decide_line(&interactive()).end(), FrameEnd::PromptOpen);
    }
}

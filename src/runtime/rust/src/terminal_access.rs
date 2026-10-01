//! Ipe.Tui — the one typed "is an interactive terminal available" probe.
//!
//! Std-only (no crossterm, no feature gate): both the `ipe run`/`ipe watch`
//! pre-build gate (over `Shape::Tui`, before any cargo work starts) and the
//! `tui`-feature runtime guard (`TuiGuard::enter*`, right before
//! `crossterm::terminal::enable_raw_mode`) decide from the SAME facts and the
//! SAME refusal text, so a Tui program is refused identically whether the
//! check runs before the build or inside the built binary.
//!
//! [`decide`] is pure and table-tested; [`probe`] is the only place that reads
//! the process environment or touches a file descriptor.

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
    #[allow(clippy::disallowed_methods)]
    // crossterm reads the real env directly; this probe must observe the same, overlay or not
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

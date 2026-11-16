//! The CLI's browser opener: the runtime's one URL grammar and opener, with the CLI's job breakaway.
//!
//! The URL judge ([`BrowserUrl`] per [`BrowserOrigin`]) and the platform
//! opener live once, in `ipe_runtime_rust::browser_open`; this module only
//! re-exports them and picks the CLI's [`Breakaway`]. On Windows, once the CLI
//! has joined its own kill-on-close job, the opener breaks away from it so the
//! browser outlives the CLI; where a job the CLI was started in forbids
//! breaking away, the opener starts inside the CLI's job.

use ipe_runtime_rust::browser_open::Breakaway;
pub use ipe_runtime_rust::browser_open::{BrowserOrigin, BrowserUrl, OpenOutcome, OpenerRefusal};

/// Open `url` in the desktop's browser through the runtime's one opener, never through a shell.
///
/// A caller prints the URL whenever the outcome is not
/// [`OpenOutcome::Opened`]. Call it from a thread that outlives the opener: a
/// spawning thread's exit signals the opener.
///
/// A loopback server (`ipe doc --serve`, `ipe dev run` of a `web client`)
/// reaches it only as the opener it hands `loopback_http::announce`: that
/// seam is the one barrier between a test and a real browser, and a test
/// hands it a recording closure instead.
pub fn open_url(url: &BrowserUrl) -> OpenOutcome {
    ipe_runtime_rust::browser_open::open_url(url, cli_breakaway())
}

/// The CLI's job breakaway: out of its own job once joined, never before.
///
/// Before the CLI joins its job, a breakaway would answer only to a job the
/// CLI was started in, which may refuse it.
#[cfg(windows)]
fn cli_breakaway() -> Breakaway {
    if crate::remote_ingest::cli_job_joined() {
        Breakaway::PreferOutsideJob
    } else {
        Breakaway::Never
    }
}

/// The CLI's job breakaway: off Windows there is no job to leave.
#[cfg(not(windows))]
const fn cli_breakaway() -> Breakaway {
    Breakaway::Never
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    /// Off Windows the CLI has no job to leave, so it never asks to break away.
    #[test]
    fn the_cli_never_breaks_away_off_windows() {
        assert_eq!(cli_breakaway(), Breakaway::Never);
    }
}

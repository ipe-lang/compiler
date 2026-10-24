// Ipe.Io — line-oriented stdio. All effectful, so IpeTask-returning.
use super::{
    FromIpeError, FromLimitExceeded, IpeError, IpeResult, IpeTask, LimitRefusal, ok_res, str_err,
};

use std::io::{BufRead, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

/// The longest stdin line a read admits, in bytes, newline excluded.
const LINE_CAP_BYTES: u64 = 1024 * 1024;

/// The most bytes a refused over-long line's rest is discarded through to reach its newline.
const DRAIN_CAP_BYTES: u64 = 64 * 1024 * 1024;

/// The byte ceilings of one bounded line read.
#[derive(Clone, Copy, Debug)]
struct ReadCaps {
    /// The longest line admitted, newline excluded.
    line: u64,
    /// The bytes past `line + 2` discarded while looking for the refused line's newline.
    drain: u64,
}

const STDIN_CAPS: ReadCaps = ReadCaps {
    line: LINE_CAP_BYTES,
    drain: DRAIN_CAP_BYTES,
};

/// Set once a stdin read stops inside a line, so no later read starts mid-line.
static STDIN_DESYNCED: AtomicBool = AtomicBool::new(false);

/// How a bounded line read ended; a `Line`'s bytes are in the caller's buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LineEnd {
    /// A whole line, its newline and one `\r` before it stripped.
    Line,
    /// End of input before any byte.
    Eof,
}

/// Why a line read was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LineRefusal {
    /// The line ran past `cap` bytes; it was discarded, never split.
    TooLong { cap: u64 },
    /// An earlier read stopped inside a line, so the next byte is not a line start.
    Desynced,
    /// The line's bytes are not UTF-8.
    NotUtf8,
    /// The read failed with this OS error kind.
    Io(std::io::ErrorKind),
}

impl LineRefusal {
    /// The refusal in a generic error sink, each variant under its own kind.
    fn into_error<E: FromLimitExceeded + FromIpeError>(self, operation: &str) -> E {
        match self {
            Self::TooLong { cap } => LimitRefusal::new(format!(
                "the stdin line is longer than the {cap}-byte line cap; the line was discarded"
            ))
            .context(operation)
            .into_error(),
            Self::Desynced => LimitRefusal::new(
                "stdin is closed to reads: an earlier read stopped inside a line, \
                 so the next byte is not the start of a line",
            )
            .context(operation)
            .into_error(),
            Self::NotUtf8 => E::from_ipe_error(IpeError::invalid_input(format!(
                "{operation}: the stdin line is not valid UTF-8"
            ))),
            Self::Io(kind) => E::from_ipe_error(IpeError::io(format!(
                "{operation}: reading stdin failed: {kind}"
            ))),
        }
    }
}

/// Reads one line from `reader` into `buf` (empty on entry), refusing a line past `caps.line`.
///
/// A refused over-long line is discarded through its newline, at most
/// `caps.drain` bytes past the cap, so the next read starts at the next line.
/// When the discard budget runs out, or the read fails after consuming part of
/// a line, `desynced` is set and this and every later read refuses: an unread
/// remainder is never handed out as a line.
fn read_line_into<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    caps: ReadCaps,
    desynced: &AtomicBool,
) -> Result<LineEnd, LineRefusal> {
    if desynced.load(Ordering::Acquire) {
        return Err(LineRefusal::Desynced);
    }
    // Room for the line and its `\r\n`, so a CRLF line at the cap is admitted.
    let read = reader
        .by_ref()
        .take(caps.line.saturating_add(2))
        .read_until(b'\n', buf);
    let count = match read {
        Ok(count) => count,
        Err(e) => {
            if !buf.is_empty() {
                desynced.store(true, Ordering::Release);
            }
            return Err(LineRefusal::Io(e.kind()));
        }
    };
    if count == 0 {
        return Ok(LineEnd::Eof);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        if (buf.len() as u64) <= caps.line {
            return Ok(LineEnd::Line);
        }
        return Err(LineRefusal::TooLong { cap: caps.line });
    }
    if (buf.len() as u64) <= caps.line {
        return Ok(LineEnd::Line);
    }
    match drain_line(reader, caps.drain) {
        Ok(Drained::Boundary) => {}
        Ok(Drained::Exhausted) | Err(_) => desynced.store(true, Ordering::Release),
    }
    Err(LineRefusal::TooLong { cap: caps.line })
}

/// Where a discard of a refused line's rest stopped.
enum Drained {
    /// The newline (consumed) or the end of input: the next byte starts a line.
    Boundary,
    /// The budget ran out before a newline.
    Exhausted,
}

/// Discards bytes through the next newline, at most `budget` of them.
fn drain_line<R: BufRead>(reader: &mut R, budget: u64) -> std::io::Result<Drained> {
    let mut left = budget;
    loop {
        if left == 0 {
            return Ok(Drained::Exhausted);
        }
        let chunk = match reader.fill_buf() {
            Ok(chunk) => chunk,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if chunk.is_empty() {
            return Ok(Drained::Boundary);
        }
        let window = usize::try_from(left).map_or(chunk.len(), |left| left.min(chunk.len()));
        if let Some(at) = chunk.iter().take(window).position(|&b| b == b'\n') {
            reader.consume(at.saturating_add(1));
            return Ok(Drained::Boundary);
        }
        reader.consume(window);
        left = left.saturating_sub(window as u64);
    }
}

/// Reads one text line; end of input is the empty string.
fn read_text_line<R: BufRead>(
    reader: &mut R,
    caps: ReadCaps,
    desynced: &AtomicBool,
) -> Result<String, LineRefusal> {
    let mut buf = Vec::new();
    match read_line_into(reader, &mut buf, caps, desynced)? {
        LineEnd::Eof => Ok(String::new()),
        LineEnd::Line => String::from_utf8(buf).map_err(|_| LineRefusal::NotUtf8),
    }
}

/// `Io.readLine : () -> Task Error String`. Reads one line from stdin with the
/// trailing newline (and one `\r` before it) stripped. EOF yields an empty
/// string (Ok), matching the "no more input" convention rather than erroring.
///
/// Every stdin line read goes through [`read_line_into`] over the process-wide
/// buffered `StdinLock`, so bytes past one line stay for the next read. A line
/// over 1 MiB is refused as `LimitExceeded` and discarded through its newline,
/// never returned truncated with its tail left as the next answer.
#[must_use]
pub fn io_read_line<E: Send + FromLimitExceeded + FromIpeError + 'static>(
    _: (),
) -> IpeTask<E, String> {
    Box::pin(async move {
        let mut stdin = std::io::stdin().lock();
        match read_text_line(&mut stdin, STDIN_CAPS, &STDIN_DESYNCED) {
            Ok(line) => ok_res(line),
            Err(refusal) => IpeResult::Err(refusal.into_error("Io.readLine")),
        }
    })
}

/// Reads one line and seals it into a `Secret`, wiping every buffer that held its bytes.
///
/// The buffer is allocated at its final size, so the read never reallocates
/// and leaves a stale copy behind.
#[cfg(feature = "secret")]
fn read_secret_line<R: BufRead>(
    reader: &mut R,
    caps: ReadCaps,
    desynced: &AtomicBool,
) -> Result<crate::secret::Secret, LineRefusal> {
    use zeroize::Zeroize;
    let capacity = usize::try_from(caps.line.saturating_add(2)).unwrap_or(0);
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(capacity));
    match read_line_into(reader, &mut buf, caps, desynced)? {
        LineEnd::Eof => Ok(crate::secret::secret_from_string(String::new())),
        LineEnd::Line => match String::from_utf8(std::mem::take(&mut *buf)) {
            Ok(line) => Ok(crate::secret::secret_from_string(line)),
            Err(e) => {
                e.into_bytes().zeroize();
                Err(LineRefusal::NotUtf8)
            }
        },
    }
}

/// Restores the saved terminal attributes when dropped, so echo is turned back
/// on even if the read errors or the thread unwinds. This is the fail-safe: the
/// terminal is never left with echo disabled once the guard leaves scope.
#[cfg(all(unix, feature = "secret"))]
struct EchoGuard<F: std::os::fd::AsFd> {
    fd: F,
    prior: rustix::termios::Termios,
}

#[cfg(all(unix, feature = "secret"))]
impl<F: std::os::fd::AsFd> Drop for EchoGuard<F> {
    fn drop(&mut self) {
        // Best-effort restore; a failure here cannot itself be surfaced from
        // `drop`, and there is no safer state to fall back to than "re-apply the
        // attributes we captured before we changed them".
        let _ = rustix::termios::tcsetattr(
            &self.fd,
            rustix::termios::OptionalActions::Flush,
            &self.prior,
        );
    }
}

/// Disable terminal echo on `fd`, returning a guard that restores the prior mode on drop.
///
/// `None` when `fd` is not a tty (nothing to toggle — the caller then reads with
/// echo unchanged, i.e. a plain line read).
#[cfg(all(unix, feature = "secret"))]
fn suppress_echo<F: std::os::fd::AsFd>(fd: F) -> Option<EchoGuard<F>> {
    // Not a terminal (piped/redirected stdin): there is no echo state to change,
    // so report "no guard" and let the caller fall back to a normal read.
    if !rustix::termios::isatty(&fd) {
        return None;
    }
    let prior = rustix::termios::tcgetattr(&fd).ok()?;
    let mut raw = prior.clone();
    raw.local_modes.remove(rustix::termios::LocalModes::ECHO);
    rustix::termios::tcsetattr(&fd, rustix::termios::OptionalActions::Flush, &raw).ok()?;
    Some(EchoGuard { fd, prior })
}

/// `Io.readSecret : String -> Task Error Secret`. Writes `prompt` to stdout,
/// then reads one line from stdin with terminal echo suppressed (a password
/// read) and strips the trailing newline. The prior terminal mode is always
/// restored on return — success, error, or unwind — via an RAII guard.
///
/// The read line is sealed into an opaque [`crate::secret::Secret`] before it is
/// handed back — never returned as a bare `String`. The plaintext is reachable
/// only through the scoped `Secret.use` / `Secret.reveal` API, so a freshly-read
/// secret cannot flow into a log line, an error message, or a serialized payload
/// by accident. Gated behind the `secret` feature: a program that reads a secret
/// necessarily holds a `Secret`-typed value, which turns the feature on.
///
/// On a non-tty stdin (piped/redirected) there is no echo state to toggle, so
/// this degrades to a plain line read. On non-Unix targets, where no echo
/// toggle is wired, it also reads with echo unchanged. Bounded by the same
/// reader and caps as `readLine`: an over-long line is refused, never truncated.
#[cfg(feature = "secret")]
#[must_use]
pub fn io_read_secret<E: Send + FromLimitExceeded + FromIpeError + 'static>(
    prompt: String,
) -> IpeTask<E, crate::secret::Secret> {
    Box::pin(async move {
        {
            let mut out = std::io::stdout();
            let _ = out.write_all(prompt.as_bytes());
            let _ = out.flush();
        }

        #[cfg(unix)]
        let _echo_guard = suppress_echo(std::io::stdin());

        // Sealed into `Secret` at the read boundary: the bare plaintext never
        // escapes `read_secret_line`, so the sealed value's redaction /
        // no-`Debug` / zeroize-on-`Drop` protections cover it from the read on.
        let result = {
            let mut stdin = std::io::stdin().lock();
            match read_secret_line(&mut stdin, STDIN_CAPS, &STDIN_DESYNCED) {
                Ok(secret) => ok_res(secret),
                Err(refusal) => IpeResult::Err(refusal.into_error("Io.readSecret")),
            }
        };
        // Echo was suppressed, so the user's Enter produced no visible newline;
        // emit one so following output starts on a fresh line. Skipped on a
        // non-tty (no guard) to keep piped output byte-clean.
        #[cfg(unix)]
        if _echo_guard.is_some() {
            let mut out = std::io::stdout();
            let _ = out.write_all(b"\n");
            let _ = out.flush();
        }
        result
    })
}

/// `Io.writeStdout : String -> Task Error ()`. Writes verbatim (no newline).
#[must_use]
pub fn io_write_stdout<E: Send + From<String> + 'static>(s: String) -> IpeTask<E, ()> {
    Box::pin(async move {
        let r = (|| {
            let mut out = std::io::stdout();
            out.write_all(s.as_bytes())?;
            out.flush()
        })();
        match r {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(str_err(&format!("{e}"))),
        }
    })
}

/// `Io.writeStderr : String -> Task Error ()`. Writes verbatim (no newline).
#[must_use]
pub fn io_write_stderr<E: Send + From<String> + 'static>(s: String) -> IpeTask<E, ()> {
    Box::pin(async move {
        let r = (|| {
            let mut err = std::io::stderr();
            err.write_all(s.as_bytes())?;
            err.flush()
        })();
        match r {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(str_err(&format!("{e}"))),
        }
    })
}

/// `Io.println : String -> Task Error ()`. Writes the message followed by a
/// single `\n` to stdout, then flushes.
#[must_use]
pub fn io_println<E: Send + From<String> + 'static>(msg: String) -> IpeTask<E, ()> {
    Box::pin(async move {
        let r = (|| {
            let mut out = std::io::stdout();
            out.write_all(msg.as_bytes())?;
            out.write_all(b"\n")?;
            out.flush()
        })();
        match r {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(str_err(&format!("{e}"))),
        }
    })
}

/// `Io.eprintln : String -> Task Error ()`. Writes the message followed by a
/// single `\n` to stderr, then flushes.
#[must_use]
pub fn io_eprintln<E: Send + From<String> + 'static>(msg: String) -> IpeTask<E, ()> {
    Box::pin(async move {
        let r = (|| {
            let mut err = std::io::stderr();
            err.write_all(msg.as_bytes())?;
            err.write_all(b"\n")?;
            err.flush()
        })();
        match r {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(str_err(&format!("{e}"))),
        }
    })
}

#[cfg(test)]
mod line_reader_tests {
    use super::{
        LINE_CAP_BYTES, LineEnd, LineRefusal, ReadCaps, STDIN_CAPS, read_line_into, read_text_line,
    };
    use crate::{IpeError, IpeErrorKind};
    use std::io::{BufReader, Cursor, Read};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Caps small enough to drive every branch with short inputs.
    const SMALL: ReadCaps = ReadCaps { line: 4, drain: 8 };

    /// A reader whose every read fails.
    struct Failing;

    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("device gone"))
        }
    }

    fn cursor(bytes: &[u8]) -> Cursor<Vec<u8>> {
        Cursor::new(bytes.to_vec())
    }

    fn kind_of(refusal: LineRefusal) -> IpeErrorKind {
        let IpeError::Error(kind, _) = refusal.into_error::<IpeError>("Io.readLine");
        kind
    }

    #[test]
    fn two_lines_both_read() {
        let latch = AtomicBool::new(false);
        let mut input = cursor(b"a\nb\n");
        assert_eq!(
            read_text_line(&mut input, STDIN_CAPS, &latch),
            Ok("a".to_owned())
        );
        assert_eq!(
            read_text_line(&mut input, STDIN_CAPS, &latch),
            Ok("b".to_owned())
        );
        let mut buf = Vec::new();
        assert_eq!(
            read_line_into(&mut input, &mut buf, STDIN_CAPS, &latch),
            Ok(LineEnd::Eof)
        );
    }

    #[test]
    fn overlong_line_refused_and_next_answer_intact() {
        let latch = AtomicBool::new(false);
        let mut bytes = vec![b'y'; LINE_CAP_BYTES as usize + 1];
        bytes.extend_from_slice(b"\nn\n");
        let mut input = Cursor::new(bytes);
        assert_eq!(
            read_text_line(&mut input, STDIN_CAPS, &latch),
            Err(LineRefusal::TooLong {
                cap: LINE_CAP_BYTES
            })
        );
        assert_eq!(
            read_text_line(&mut input, STDIN_CAPS, &latch),
            Ok("n".to_owned())
        );
        assert!(
            !latch.load(Ordering::Acquire),
            "a drained line keeps stdin in sync"
        );
    }

    #[test]
    fn line_at_cap_admitted() {
        let latch = AtomicBool::new(false);
        let mut bytes = vec![b'y'; LINE_CAP_BYTES as usize];
        bytes.push(b'\n');
        let mut input = Cursor::new(bytes);
        let line = read_text_line(&mut input, STDIN_CAPS, &latch);
        assert_eq!(line.map(|l| l.len()), Ok(LINE_CAP_BYTES as usize));
    }

    #[test]
    fn final_line_at_cap_without_newline_admitted() {
        let latch = AtomicBool::new(false);
        let mut input = cursor(b"yyyy");
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Ok("yyyy".to_owned())
        );
    }

    #[test]
    fn final_line_past_cap_without_newline_refused() {
        let latch = AtomicBool::new(false);
        let mut input = cursor(b"yyyyy");
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Err(LineRefusal::TooLong { cap: 4 })
        );
        assert_eq!(read_text_line(&mut input, SMALL, &latch), Ok(String::new()));
    }

    #[test]
    fn drain_at_budget_reaches_the_next_line() {
        // 6 bytes fill the read window; the rest, newline included, is exactly the 8-byte budget.
        let latch = AtomicBool::new(false);
        let mut input = cursor(b"yyyyyyzzzzzzz\nn\n");
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Err(LineRefusal::TooLong { cap: 4 })
        );
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Ok("n".to_owned())
        );
    }

    #[test]
    fn drain_budget_exhausted_latches() {
        // One byte more than `drain_at_budget_reaches_the_next_line`: the newline is past the budget.
        let latch = AtomicBool::new(false);
        let mut input = cursor(b"yyyyyyzzzzzzzz\nn\n");
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Err(LineRefusal::TooLong { cap: 4 })
        );
        assert!(latch.load(Ordering::Acquire), "an undrained line latches");
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Err(LineRefusal::Desynced)
        );
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Err(LineRefusal::Desynced),
            "the latch holds for every later read"
        );
    }

    #[test]
    fn crlf_stripped_once() {
        let latch = AtomicBool::new(false);
        let mut input = cursor(b"a\r\nb\r\r\n");
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Ok("a".to_owned())
        );
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Ok("b\r".to_owned())
        );
    }

    #[test]
    fn crlf_line_at_cap_admitted() {
        let latch = AtomicBool::new(false);
        let mut input = cursor(b"yyyy\r\nn\n");
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Ok("yyyy".to_owned())
        );
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Ok("n".to_owned())
        );
    }

    #[test]
    fn crlf_line_past_cap_refused() {
        let latch = AtomicBool::new(false);
        let mut input = cursor(b"yyyyy\r\nn\n");
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Err(LineRefusal::TooLong { cap: 4 })
        );
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Ok("n".to_owned())
        );
        assert!(
            !latch.load(Ordering::Acquire),
            "a drained line keeps stdin in sync"
        );
    }

    #[test]
    fn final_line_without_newline() {
        let latch = AtomicBool::new(false);
        let mut input = cursor(b"a\ntail");
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Ok("a".to_owned())
        );
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Ok("tail".to_owned())
        );
        let mut buf = Vec::new();
        assert_eq!(
            read_line_into(&mut input, &mut buf, SMALL, &latch),
            Ok(LineEnd::Eof)
        );
    }

    #[test]
    fn invalid_utf8_refused() {
        let latch = AtomicBool::new(false);
        let mut input = cursor(b"\xff\nok\n");
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Err(LineRefusal::NotUtf8)
        );
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Ok("ok".to_owned())
        );
    }

    #[test]
    fn io_error_inside_a_line_latches() {
        let latch = AtomicBool::new(false);
        let mut input = BufReader::new(cursor(b"ab").chain(Failing));
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Err(LineRefusal::Io(std::io::ErrorKind::Other))
        );
        assert!(
            latch.load(Ordering::Acquire),
            "a read stopped mid-line latches"
        );
        let mut fresh = cursor(b"n\n");
        assert_eq!(
            read_text_line(&mut fresh, SMALL, &latch),
            Err(LineRefusal::Desynced)
        );
    }

    #[test]
    fn io_error_before_any_byte_does_not_latch() {
        let latch = AtomicBool::new(false);
        let mut input = BufReader::new(Failing);
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Err(LineRefusal::Io(std::io::ErrorKind::Other))
        );
        let mut fresh = cursor(b"n\n");
        assert_eq!(
            read_text_line(&mut fresh, SMALL, &latch),
            Ok("n".to_owned())
        );
    }

    #[test]
    fn io_error_while_draining_latches() {
        let latch = AtomicBool::new(false);
        let mut input = BufReader::new(cursor(b"yyyyyy").chain(Failing));
        assert_eq!(
            read_text_line(&mut input, SMALL, &latch),
            Err(LineRefusal::TooLong { cap: 4 })
        );
        assert!(
            latch.load(Ordering::Acquire),
            "an interrupted drain latches"
        );
    }

    #[test]
    fn refusals_keep_their_kind() {
        assert_eq!(
            kind_of(LineRefusal::TooLong { cap: 4 }),
            IpeErrorKind::LimitExceeded
        );
        assert_eq!(kind_of(LineRefusal::Desynced), IpeErrorKind::LimitExceeded);
        assert_eq!(kind_of(LineRefusal::NotUtf8), IpeErrorKind::InvalidInput);
        assert_eq!(
            kind_of(LineRefusal::Io(std::io::ErrorKind::BrokenPipe)),
            IpeErrorKind::Io
        );
    }

    #[cfg(feature = "secret")]
    #[test]
    fn secret_overlong_refused() {
        use super::read_secret_line;
        let latch = AtomicBool::new(false);
        let mut input = cursor(b"yyyyy\nn\n");
        let refused = read_secret_line(&mut input, SMALL, &latch);
        assert!(
            matches!(refused, Err(LineRefusal::TooLong { cap: 4 })),
            "an over-long secret is refused, never truncated"
        );
        let next = read_secret_line(&mut input, SMALL, &latch);
        assert!(next.is_ok(), "the next line is read whole");
        let Ok(secret) = next else { return };
        assert_eq!(crate::secret::secret_reveal(secret), "n");
    }

    #[cfg(feature = "secret")]
    #[test]
    fn secret_invalid_utf8_refused() {
        use super::read_secret_line;
        let latch = AtomicBool::new(false);
        let mut input = cursor(b"\xff\n");
        assert!(matches!(
            read_secret_line(&mut input, SMALL, &latch),
            Err(LineRefusal::NotUtf8)
        ));
    }
}

// The echo guard exists only when the `secret` feature is on (it is used solely
// by `io_read_secret`, which returns a `secret`-gated `Secret`), so its tests
// are gated the same way.
#[cfg(all(test, unix, feature = "secret"))]
mod echo_guard_tests {
    use super::suppress_echo;
    use std::os::fd::OwnedFd;

    /// Read the current `ECHO` bit of a tty fd.
    fn echo_on(fd: &OwnedFd) -> bool {
        rustix::termios::tcgetattr(fd)
            .is_ok_and(|t| t.local_modes.contains(rustix::termios::LocalModes::ECHO))
    }

    /// A real pty pair; both ends close when dropped.
    struct Pty {
        _master: OwnedFd,
        replica: OwnedFd,
    }

    fn open_pty() -> Option<Pty> {
        use rustix::pty::OpenptFlags;
        let master = rustix::pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).ok()?;
        rustix::pty::grantpt(&master).ok()?;
        rustix::pty::unlockpt(&master).ok()?;
        let name = rustix::pty::ptsname(&master, Vec::new()).ok()?;
        let replica = rustix::fs::open(
            name.as_c_str(),
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY,
            rustix::fs::Mode::empty(),
        )
        .ok()?;
        Some(Pty {
            _master: master,
            replica,
        })
    }

    // On a real tty, `suppress_echo` turns ECHO off for the guard's lifetime and
    // restores the prior mode (ECHO on) the moment the guard is dropped.
    #[test]
    fn suppresses_then_restores_echo_on_a_tty() {
        let pty = open_pty();
        assert!(pty.is_some(), "pty allocation failed");
        let Some(pty) = pty else { return };
        // Ensure the starting state has ECHO on.
        let start = rustix::termios::tcgetattr(&pty.replica);
        assert!(start.is_ok(), "tcgetattr failed");
        let Ok(mut t) = start else { return };
        t.local_modes.insert(rustix::termios::LocalModes::ECHO);
        assert!(
            rustix::termios::tcsetattr(&pty.replica, rustix::termios::OptionalActions::Now, &t)
                .is_ok()
        );
        assert!(echo_on(&pty.replica), "precondition: ECHO on");

        {
            let guard = suppress_echo(&pty.replica);
            assert!(guard.is_some(), "a tty must yield an echo guard");
            assert!(
                !echo_on(&pty.replica),
                "ECHO must be off while the guard lives"
            );
        } // guard drops here

        assert!(
            echo_on(&pty.replica),
            "ECHO must be restored after the guard drops"
        );
    }

    // A non-tty fd (a pipe) has no echo state to toggle: `suppress_echo` returns
    // `None`, so the caller falls back to a plain read — never panics.
    #[test]
    fn non_tty_yields_no_guard() {
        let fds = rustix::pipe::pipe();
        assert!(fds.is_ok(), "pipe failed");
        let Ok((read_fd, _write_fd)) = fds else {
            return;
        };
        assert!(
            suppress_echo(&read_fd).is_none(),
            "a pipe is not a tty; no echo guard"
        );
    }
}

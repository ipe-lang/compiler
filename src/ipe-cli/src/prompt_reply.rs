//! The one reader of a typed answer to an interactive prompt, under a byte ceiling.
//!
//! Every prompt the CLI puts to a person reads its answer here, so no answer
//! line can grow a buffer past [`REPLY_CAP`], and a line over it is refused
//! rather than read as an answer.

use std::io::BufRead;

/// Most bytes an answer line holds, its terminator included.
///
/// Every answer a prompt accepts (`y`, `yes`, a runtime word or number) fits
/// many times over.
pub const REPLY_CAP: usize = 256;

/// Most bytes of an over-long line skipped after its refusal, so the next
/// prompt starts on a fresh line rather than on the refused line's tail.
pub const REPLY_DRAIN_CAP: usize = 64 * 1024;

/// What one read of an answer line found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// A line, its `\n` or `\r\n` terminator removed.
    Line(String),
    /// Input ended before any byte.
    Ended,
    /// No answer could be taken from the input.
    Refused(ReplyRefusal),
}

/// Why an answer line was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyRefusal {
    /// The line runs past [`REPLY_CAP`].
    TooLong,
    /// The line is not UTF-8.
    NotUtf8,
    /// Reading failed.
    Unreadable,
}

/// A yes/no answer parsed from a [`Reply`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YesNo {
    /// `y` or `yes`, in any case.
    Yes,
    /// Any other non-empty line.
    No,
    /// A bare Enter: the prompt's default applies.
    Empty,
    /// Input ended or failed before a line: the prompt's own fallback applies.
    Unanswered,
    /// The line was refused; never consent.
    Refused(ReplyRefusal),
}

impl YesNo {
    /// Parse `reply` as a yes/no answer.
    #[must_use]
    pub fn of(reply: &Reply) -> Self {
        match reply {
            Reply::Line(line) => {
                let answer = line.trim();
                if answer.is_empty() {
                    Self::Empty
                } else if answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes") {
                    Self::Yes
                } else {
                    Self::No
                }
            }
            Reply::Ended | Reply::Refused(ReplyRefusal::Unreadable) => Self::Unanswered,
            Reply::Refused(refusal @ (ReplyRefusal::TooLong | ReplyRefusal::NotUtf8)) => {
                Self::Refused(*refusal)
            }
        }
    }

    /// The answer as consent: `Empty` takes `default`, `Unanswered` takes
    /// `fallback`, and a refused line is never consent.
    #[must_use]
    pub const fn consents(self, default: bool, fallback: bool) -> bool {
        match self {
            Self::Yes => true,
            Self::No | Self::Refused(_) => false,
            Self::Empty => default,
            Self::Unanswered => fallback,
        }
    }
}

/// Read one answer line from `input`, never buffering more than [`REPLY_CAP`] bytes.
pub fn read_reply(input: &mut impl BufRead) -> Reply {
    let mut line = Vec::with_capacity(REPLY_CAP);
    loop {
        let chunk = match input.fill_buf() {
            Ok(chunk) => chunk,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Reply::Refused(ReplyRefusal::Unreadable),
        };
        if chunk.is_empty() {
            return finish(line, false);
        }
        let room = REPLY_CAP.saturating_sub(line.len());
        let newline = chunk.iter().position(|&b| b == b'\n');
        let take = newline.map_or(chunk.len(), |at| at.saturating_add(1));
        if take > room {
            input.consume(room);
            drain_line(input);
            return Reply::Refused(ReplyRefusal::TooLong);
        }
        line.extend_from_slice(chunk.get(..take).unwrap_or_default());
        input.consume(take);
        if newline.is_some() {
            return finish(line, true);
        }
    }
}

/// Read one answer line from stdin.
#[must_use]
pub fn read_stdin_reply() -> Reply {
    read_reply(&mut std::io::stdin().lock())
}

/// Read a yes/no answer from stdin.
#[must_use]
pub fn read_stdin_yes_no() -> YesNo {
    YesNo::of(&read_stdin_reply())
}

/// The reply a read line makes, its terminator removed.
fn finish(mut line: Vec<u8>, terminated: bool) -> Reply {
    if line.is_empty() && !terminated {
        return Reply::Ended;
    }
    if terminated {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    }
    String::from_utf8(line).map_or(Reply::Refused(ReplyRefusal::NotUtf8), Reply::Line)
}

/// Skip the rest of a refused line, at most [`REPLY_DRAIN_CAP`] bytes.
fn drain_line(input: &mut impl BufRead) {
    let mut skipped: usize = 0;
    while skipped < REPLY_DRAIN_CAP {
        let (used, done) = match input.fill_buf() {
            Ok([]) | Err(_) => return,
            Ok(chunk) => {
                let room = REPLY_DRAIN_CAP.saturating_sub(skipped);
                match chunk.iter().position(|&b| b == b'\n') {
                    Some(at) if at < room => (at.saturating_add(1), true),
                    _ => (chunk.len().min(room), false),
                }
            }
        };
        input.consume(used);
        if done {
            return;
        }
        skipped = skipped.saturating_add(used);
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor, Read as _};

    use super::*;

    /// A line of `len` bytes of `a`, terminated.
    fn line_of(len: usize) -> Vec<u8> {
        let mut line = vec![b'a'; len];
        line.push(b'\n');
        line
    }

    #[test]
    fn a_line_at_the_cap_is_read_and_one_past_it_is_refused() {
        let at_cap = line_of(REPLY_CAP.saturating_sub(1));
        assert_eq!(
            read_reply(&mut Cursor::new(at_cap)),
            Reply::Line("a".repeat(REPLY_CAP.saturating_sub(1)))
        );
        let past_cap = line_of(REPLY_CAP);
        assert_eq!(
            read_reply(&mut Cursor::new(past_cap)),
            Reply::Refused(ReplyRefusal::TooLong)
        );
    }

    /// An endless line is refused after at most the cap plus the drain ceiling, never buffered whole.
    #[test]
    fn an_endless_line_is_refused_within_its_ceilings() {
        let endless = std::io::repeat(b'y').take(64 * 1024 * 1024);
        let mut input = BufReader::with_capacity(4096, endless);
        assert_eq!(
            read_reply(&mut input),
            Reply::Refused(ReplyRefusal::TooLong)
        );
        let left = input.into_inner().limit();
        let read = (64 * 1024 * 1024_u64).saturating_sub(left);
        assert!(read <= u64::try_from(REPLY_CAP + REPLY_DRAIN_CAP + 4096).unwrap_or(u64::MAX));
    }

    /// A refused line's tail is never taken as the next prompt's answer.
    #[test]
    fn the_tail_of_a_refused_line_never_answers_the_next_prompt() {
        let mut bytes = vec![b'a'; REPLY_CAP];
        bytes.extend_from_slice(b"y\nn\n");
        let mut input = Cursor::new(bytes);
        assert_eq!(
            YesNo::of(&read_reply(&mut input)),
            YesNo::Refused(ReplyRefusal::TooLong)
        );
        assert_eq!(YesNo::of(&read_reply(&mut input)), YesNo::No);
    }

    #[test]
    fn answers_parse_by_word_and_a_refusal_never_consents() {
        let yes = |bytes: &[u8]| YesNo::of(&read_reply(&mut Cursor::new(bytes.to_vec())));
        assert_eq!(yes(b"Yes\r\n"), YesNo::Yes);
        assert_eq!(yes(b" y \n"), YesNo::Yes);
        assert_eq!(yes(b"nope\n"), YesNo::No);
        assert_eq!(yes(b"\n"), YesNo::Empty);
        assert_eq!(yes(b""), YesNo::Unanswered);
        assert_eq!(yes(b"y"), YesNo::Yes);
        assert_eq!(yes(b"\xff\n"), YesNo::Refused(ReplyRefusal::NotUtf8));
        assert!(!YesNo::Refused(ReplyRefusal::TooLong).consents(true, true));
        assert!(YesNo::Empty.consents(true, false));
        assert!(!YesNo::Unanswered.consents(true, false));
    }

    /// No source under `src/` reads a line outside this reader and the loopback head reader, whose input is `Take`-capped.
    #[test]
    fn every_line_read_goes_through_a_capped_reader() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![root.clone()];
        let mut offenders = Vec::new();
        let mut walked = 0_usize;
        while let Some(dir) = stack.pop() {
            walked = walked.saturating_add(1);
            assert!(walked < 10_000, "source walk ceiling");
            for entry in std::fs::read_dir(&dir).expect("source dir") {
                let path = entry.expect("source entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    let rel = path.strip_prefix(&root).unwrap_or(&path).to_owned();
                    let allowed = rel == std::path::Path::new("loopback_http.rs");
                    let text = std::fs::read_to_string(&path).expect("source file");
                    if !allowed && text.contains(concat!("read_", "line(")) {
                        offenders.push(rel);
                    }
                }
            }
        }
        assert!(offenders.is_empty(), "unbounded line reads: {offenders:?}");
    }
}

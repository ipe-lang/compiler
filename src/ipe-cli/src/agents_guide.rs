//! The `AGENTS.md` coding-agent guide: one embedded asset, one stamp, one judge.
//!
//! [`ASSET`] is the guide's single source: `ipe init` writes [`rendered`] (a
//! [`GuideStamp`] line, then `ASSET`) and `ipe doc guide:agents` serves `ASSET`
//! itself. The stamp is written by [`GuideStamp::render`] and read only by
//! [`GuideStamp::parse`]; whether a file is current is judged by byte equality
//! with `ASSET` ([`judge`]), never by trusting what its stamp claims.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::num::NonZeroU64;

use ipe_fs_open::ByteCap;
use sha2::{Digest as _, Sha256};

pub use crate::output_dir::held::Unread;

/// The guide, embedded once; every consumer reads this constant.
pub const ASSET: &str = include_str!("../templates/AGENTS.md.in");

/// The guide's key in the `guide:` doc kind.
pub const GUIDE_KEY: &str = "agents";

/// The doc term that opens the guide.
pub const GUIDE_TERM: &str = "guide:agents";

/// The command that refreshes a project's guide.
pub const UPGRADE_HINT: &str = "ipe upgrade --agents";

/// The guide's title in the doc bundle.
pub const GUIDE_TITLE: &str = "AGENTS.md: the Ipê authoring guide for coding agents";

/// The file name of the guide in a project.
pub const FILE_NAME: &str = "AGENTS.md";

/// The longest stamp line, in bytes, the parser reads.
pub const STAMP_LINE_MAX: usize = 128;

/// The most bytes of a project's `AGENTS.md` any reader takes.
pub const GUIDE_READ_CAP: ByteCap = ByteCap::from_nonzero(NonZeroU64::MIN.saturating_add(65_535));

/// The largest guide the build admits, in bytes.
const ASSET_BYTE_BUDGET: usize = 20 * 1024;

/// The most lines the build admits in the guide.
const ASSET_LINE_BUDGET: usize = 350;

/// The stamp's format tag; a later format is a new tag this parser refuses.
const STAMP_TAG: &str = "<!-- ipe-guide:1 ipe ";

/// What every stamp-shaped first line starts with, whatever its format tag.
const STAMP_MARK: &str = "<!-- ipe-guide:";

/// The separator between the stamp's version and its digest.
const STAMP_DIGEST_SEP: &str = " sha256 ";

/// The stamp's closing.
const STAMP_CLOSE: &str = " -->";

/// Whether `a` and `b` hold the same bytes.
const fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    let (mut a, mut b) = (a, b);
    loop {
        match (a.split_first(), b.split_first()) {
            (None, None) => return true,
            (Some((x, ar)), Some((y, br))) => {
                if *x != *y {
                    return false;
                }
                a = ar;
                b = br;
            }
            (Some(_), None) | (None, Some(_)) => return false,
        }
    }
}

/// Whether `whole` is `head` followed by `tail`.
const fn is_concat(whole: &[u8], head: &[u8], tail: &[u8]) -> bool {
    match whole.split_at_checked(head.len()) {
        Some((h, t)) => bytes_eq(h, head) && bytes_eq(t, tail),
        None => false,
    }
}

/// The number of `\n`-terminated lines in `text`.
const fn line_count(text: &[u8]) -> usize {
    let mut rest = text;
    let mut lines = 0;
    while let Some((byte, tail)) = rest.split_first() {
        if *byte == b'\n' {
            lines += 1;
        }
        rest = tail;
    }
    lines
}

/// Whether `text` ends with a newline.
const fn ends_with_newline(text: &[u8]) -> bool {
    matches!(text.split_last(), Some((b'\n', _)))
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the doc term and the guide key drift apart [ledger #boundary]
const _: () = assert!(is_concat(
    GUIDE_TERM.as_bytes(),
    b"guide:",
    GUIDE_KEY.as_bytes()
));
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the guide outgrows its byte budget [ledger #boundary]
const _: () = assert!(ASSET.len() <= ASSET_BYTE_BUDGET);
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the guide outgrows its line budget [ledger #boundary]
const _: () = assert!(line_count(ASSET.as_bytes()) <= ASSET_LINE_BUDGET);
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the guide does not end with a newline [ledger #boundary]
const _: () = assert!(ends_with_newline(ASSET.as_bytes()));
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the read cap cannot hold a stamped guide at its budget [ledger #boundary]
const _: () = assert!(GUIDE_READ_CAP.get() > (ASSET_BYTE_BUDGET + STAMP_LINE_MAX + 1) as u64);

/// The SHA-256 of a guide body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetDigest([u8; 32]);

impl AssetDigest {
    /// The digest of `body`.
    #[must_use]
    pub fn of(body: &str) -> Self {
        Self(Sha256::digest(body.as_bytes()).into())
    }

    /// The digest spelled as 64 lowercase hex digits, exactly; `None` otherwise.
    fn parse_hex(hex_text: &str) -> Option<Self> {
        if hex_text.len() != 64
            || !hex_text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(hex_text, &mut out).ok()?;
        Some(Self(out))
    }
}

/// The first line of a generated `AGENTS.md`: the ipe that wrote it and its body's digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuideStamp {
    version: semver::Version,
    digest: AssetDigest,
}

/// Why a first line is not a stamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StampRefusal {
    /// The line is empty.
    NoStampLine,
    /// The line is longer than [`STAMP_LINE_MAX`] bytes.
    TooLong,
    /// The line is not `<!-- ipe-guide:1 ipe <semver> sha256 <hex> -->`.
    Grammar,
    /// The version is not a semver.
    Version,
    /// The digest is not 64 lowercase hex digits.
    Digest,
}

impl GuideStamp {
    /// The stamp of the running ipe over [`ASSET`].
    #[must_use]
    pub fn current() -> Self {
        Self {
            version: crate::version_check::current_version(),
            digest: AssetDigest::of(ASSET),
        }
    }

    /// The stamp line, without its newline.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "{STAMP_TAG}{}{STAMP_DIGEST_SEP}{}{STAMP_CLOSE}",
            self.version,
            hex::encode(self.digest.0)
        )
    }

    /// Parse one first line (without its newline) exactly: no trimming, no case folding.
    ///
    /// # Errors
    /// The [`StampRefusal`] naming what the line breaks.
    pub fn parse(line: &str) -> Result<Self, StampRefusal> {
        if line.is_empty() {
            return Err(StampRefusal::NoStampLine);
        }
        if line.len() > STAMP_LINE_MAX {
            return Err(StampRefusal::TooLong);
        }
        let inner = line
            .strip_prefix(STAMP_TAG)
            .and_then(|rest| rest.strip_suffix(STAMP_CLOSE))
            .ok_or(StampRefusal::Grammar)?;
        let (version, digest) = inner
            .split_once(STAMP_DIGEST_SEP)
            .ok_or(StampRefusal::Grammar)?;
        let version = semver::Version::parse(version).map_err(|_| StampRefusal::Version)?;
        let digest = AssetDigest::parse_hex(digest).ok_or(StampRefusal::Digest)?;
        Ok(Self { version, digest })
    }
}

/// Which way a guide differs from what ipe generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandEdit {
    /// A stamp whose digest is not its body's.
    Edited,
    /// No stamp, and the text is not the guide.
    Unstamped,
    /// A stamp-shaped first line that does not parse.
    MalformedStamp,
}

/// Why a guide is not current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleReason {
    /// An untouched guide an ipe no newer than this one wrote.
    OlderGuide {
        /// The ipe that wrote it.
        written_by: semver::Version,
    },
    /// An untouched guide a newer ipe wrote.
    NewerGuide {
        /// The ipe that wrote it.
        written_by: semver::Version,
    },
    /// A guide that differs from any ipe's untouched output.
    HandEdited(HandEdit),
}

/// What a project's `AGENTS.md` is, against this ipe's guide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuideStatus {
    /// It is this ipe's guide.
    Current,
    /// It is another guide.
    Stale(StaleReason),
    /// There is no `AGENTS.md`.
    Missing,
    /// It could not be read.
    Unread(Unread),
}

/// What [`judge`] found on a file's first line.
enum FirstLine<'a> {
    /// A stamp, and the body after its newline.
    Stamped(GuideStamp, &'a str),
    /// A stamp-shaped line that does not parse, or a stamp with no newline after it.
    Malformed,
    /// No stamp.
    Plain,
}

/// The text of `rendered()`: the current stamp line, then [`ASSET`].
#[must_use]
pub fn rendered() -> String {
    let mut out = GuideStamp::current().render();
    out.push('\n');
    out.push_str(ASSET);
    out
}

/// The text the judge reads: CRLF folded to LF only when every `\n` follows a `\r`.
fn line_ending_view(contents: &str) -> Cow<'_, str> {
    let pure_crlf = contents
        .match_indices('\n')
        .all(|(at, _)| contents.get(..at).is_some_and(|head| head.ends_with('\r')));
    if pure_crlf && contents.contains('\n') {
        Cow::Owned(contents.replace("\r\n", "\n"))
    } else {
        Cow::Borrowed(contents)
    }
}

/// Classify the first line of `view`.
fn first_line(view: &str) -> FirstLine<'_> {
    let (line, body) = view
        .split_once('\n')
        .map_or((view, None), |(line, body)| (line, Some(body)));
    if !line.starts_with(STAMP_MARK) {
        return FirstLine::Plain;
    }
    match (GuideStamp::parse(line), body) {
        (Ok(stamp), Some(body)) => FirstLine::Stamped(stamp, body),
        (Ok(_), None) | (Err(_), Some(_) | None) => FirstLine::Malformed,
    }
}

/// Judge the text of an `AGENTS.md` against [`ASSET`] for the `running` ipe.
///
/// Pure; never [`GuideStatus::Missing`] or [`GuideStatus::Unread`].
#[must_use]
pub fn judge(contents: &str, running: &semver::Version) -> GuideStatus {
    let view = line_ending_view(contents);
    match first_line(&view) {
        FirstLine::Plain => {
            if view == ASSET {
                GuideStatus::Current
            } else {
                GuideStatus::Stale(StaleReason::HandEdited(HandEdit::Unstamped))
            }
        }
        FirstLine::Malformed => {
            GuideStatus::Stale(StaleReason::HandEdited(HandEdit::MalformedStamp))
        }
        FirstLine::Stamped(stamp, body) => {
            let as_asset = body == ASSET;
            let untouched = AssetDigest::of(body) == stamp.digest;
            match (as_asset, untouched, stamp.version.cmp_precedence(running)) {
                (true, true | false, Ordering::Less | Ordering::Equal | Ordering::Greater) => {
                    GuideStatus::Current
                }
                (false, true, Ordering::Less | Ordering::Equal) => {
                    GuideStatus::Stale(StaleReason::OlderGuide {
                        written_by: stamp.version,
                    })
                }
                (false, true, Ordering::Greater) => GuideStatus::Stale(StaleReason::NewerGuide {
                    written_by: stamp.version,
                }),
                (false, false, Ordering::Less | Ordering::Equal | Ordering::Greater) => {
                    GuideStatus::Stale(StaleReason::HandEdited(HandEdit::Edited))
                }
            }
        }
    }
}

impl HandEdit {
    /// The fixed reason phrase.
    #[must_use]
    pub const fn phrase(self) -> &'static str {
        match self {
            Self::Edited => "edited by hand",
            Self::Unstamped => "no ipe stamp",
            Self::MalformedStamp => "unrecognised stamp",
        }
    }
}

impl GuideStatus {
    /// The one rendering of a status; only typed values reach it, never a byte of the file.
    #[must_use]
    pub fn phrase(&self) -> String {
        match self {
            Self::Current => "current".to_owned(),
            Self::Missing => "missing".to_owned(),
            Self::Stale(StaleReason::OlderGuide { written_by }) => {
                format!("stale (written by ipe {written_by})")
            }
            Self::Stale(StaleReason::NewerGuide { written_by }) => {
                format!("stale (written by a newer ipe {written_by})")
            }
            Self::Stale(StaleReason::HandEdited(edit)) => format!("stale ({})", edit.phrase()),
            Self::Unread(unread) => format!("not read ({})", unread.phrase(GUIDE_READ_CAP)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running() -> semver::Version {
        crate::version_check::current_version()
    }

    fn stamp_line(version: &str, body: &str) -> String {
        format!(
            "{STAMP_TAG}{version}{STAMP_DIGEST_SEP}{}{STAMP_CLOSE}",
            hex::encode(AssetDigest::of(body).0)
        )
    }

    /// A version greater than the running one.
    fn newer() -> semver::Version {
        let r = running();
        semver::Version::new(r.major.saturating_add(1), 0, 0)
    }

    const OLD_BODY: &str = "# An older guide\n\nIts text.\n";

    #[test]
    fn render_parse_round_trips() {
        let stamp = GuideStamp::current();
        assert_eq!(GuideStamp::parse(&stamp.render()), Ok(stamp));
    }

    #[test]
    fn the_current_stamp_line_fits_the_parser() {
        assert!(GuideStamp::current().render().len() <= STAMP_LINE_MAX);
    }

    #[test]
    fn stamp_grammar_refusals() {
        let good = stamp_line("1.2.3", OLD_BODY);
        assert!(GuideStamp::parse(&good).is_ok(), "control parses");
        let hex = hex::encode(AssetDigest::of(OLD_BODY).0);
        let cases: Vec<(String, StampRefusal)> = vec![
            (String::new(), StampRefusal::NoStampLine),
            (good.to_uppercase(), StampRefusal::Grammar),
            (
                format!(
                    "{STAMP_TAG}1.2.3{STAMP_DIGEST_SEP}{}{STAMP_CLOSE}",
                    hex.to_uppercase()
                ),
                StampRefusal::Digest,
            ),
            (
                format!(
                    "{STAMP_TAG}1.2.3{STAMP_DIGEST_SEP}{}{STAMP_CLOSE}",
                    hex.get(1..).unwrap_or_default()
                ),
                StampRefusal::Digest,
            ),
            (
                format!("{STAMP_TAG}1.2.3{STAMP_DIGEST_SEP}{hex}0{STAMP_CLOSE}"),
                StampRefusal::Digest,
            ),
            (
                good.replace("ipe-guide:1", "ipe-guide:2"),
                StampRefusal::Grammar,
            ),
            (good.replace(STAMP_CLOSE, ""), StampRefusal::Grammar),
            (format!(" {good}"), StampRefusal::Grammar),
            (format!("{good}\r"), StampRefusal::Grammar),
            (good.replace("1.2.3", "1.2"), StampRefusal::Version),
            (good.replace("1.2.3", "1.2.3\0"), StampRefusal::Version),
        ];
        for (line, want) in cases {
            assert_eq!(GuideStamp::parse(&line), Err(want), "line {line:?}");
        }
    }

    #[test]
    fn stamp_line_length_boundary() {
        // Pad the version's build metadata until the line is exactly the limit.
        let base = stamp_line("1.2.3+a", OLD_BODY);
        let pad = STAMP_LINE_MAX.saturating_sub(base.len());
        let at_max = stamp_line(&format!("1.2.3+a{}", "a".repeat(pad)), OLD_BODY);
        assert_eq!(at_max.len(), STAMP_LINE_MAX);
        assert!(GuideStamp::parse(&at_max).is_ok(), "128 bytes is read");
        let past = stamp_line(&format!("1.2.3+a{}", "a".repeat(pad + 1)), OLD_BODY);
        assert_eq!(past.len(), STAMP_LINE_MAX + 1);
        assert_eq!(GuideStamp::parse(&past), Err(StampRefusal::TooLong));
    }

    #[test]
    fn judge_rendered_is_current() {
        assert_eq!(judge(&rendered(), &running()), GuideStatus::Current);
    }

    #[test]
    fn judge_plain_asset_is_current() {
        assert_eq!(judge(ASSET, &running()), GuideStatus::Current);
    }

    #[test]
    fn judge_current_body_under_any_stamp_version_is_current() {
        let file = format!("{}\n{ASSET}", stamp_line("0.0.1", ASSET));
        assert_eq!(judge(&file, &running()), GuideStatus::Current);
        let newer_file = format!("{}\n{ASSET}", stamp_line(&newer().to_string(), ASSET));
        assert_eq!(judge(&newer_file, &running()), GuideStatus::Current);
    }

    #[test]
    fn judge_untouched_older_is_older_guide() {
        let file = format!("{}\n{OLD_BODY}", stamp_line("0.0.1", OLD_BODY));
        assert_eq!(
            judge(&file, &running()),
            GuideStatus::Stale(StaleReason::OlderGuide {
                written_by: semver::Version::new(0, 0, 1)
            })
        );
    }

    #[test]
    fn judge_untouched_at_running_version_is_older_guide() {
        let file = format!(
            "{}\n{OLD_BODY}",
            stamp_line(&running().to_string(), OLD_BODY)
        );
        assert_eq!(
            judge(&file, &running()),
            GuideStatus::Stale(StaleReason::OlderGuide {
                written_by: running()
            })
        );
    }

    #[test]
    fn judge_untouched_newer_is_newer_guide() {
        let file = format!("{}\n{OLD_BODY}", stamp_line(&newer().to_string(), OLD_BODY));
        assert_eq!(
            judge(&file, &running()),
            GuideStatus::Stale(StaleReason::NewerGuide {
                written_by: newer()
            })
        );
    }

    #[test]
    fn judge_digest_mismatch_is_edited() {
        let file = format!("{}\n{OLD_BODY}edit\n", stamp_line("0.0.1", OLD_BODY));
        assert_eq!(
            judge(&file, &running()),
            GuideStatus::Stale(StaleReason::HandEdited(HandEdit::Edited))
        );
    }

    #[test]
    fn a_stamp_claiming_the_current_digest_over_an_edited_body_is_edited() {
        let file = format!(
            "{}\n{ASSET}edit\n",
            stamp_line(&running().to_string(), ASSET)
        );
        assert_eq!(
            judge(&file, &running()),
            GuideStatus::Stale(StaleReason::HandEdited(HandEdit::Edited))
        );
    }

    #[test]
    fn judge_unstamped_other_text_is_unstamped() {
        assert_eq!(
            judge(OLD_BODY, &running()),
            GuideStatus::Stale(StaleReason::HandEdited(HandEdit::Unstamped))
        );
    }

    #[test]
    fn judge_malformed_stamp_is_malformed() {
        let file = format!("<!-- ipe-guide:2 whatever -->\n{ASSET}");
        assert_eq!(
            judge(&file, &running()),
            GuideStatus::Stale(StaleReason::HandEdited(HandEdit::MalformedStamp))
        );
    }

    #[test]
    fn judge_pure_crlf_rendered_is_current() {
        let crlf = rendered().replace('\n', "\r\n");
        assert_eq!(judge(&crlf, &running()), GuideStatus::Current);
    }

    #[test]
    fn judge_pure_crlf_older_is_older_guide() {
        let crlf = format!("{}\n{OLD_BODY}", stamp_line("0.0.1", OLD_BODY)).replace('\n', "\r\n");
        assert_eq!(
            judge(&crlf, &running()),
            GuideStatus::Stale(StaleReason::OlderGuide {
                written_by: semver::Version::new(0, 0, 1)
            })
        );
    }

    #[test]
    fn judge_mixed_endings_is_malformed_stamp() {
        let crlf = format!("{}\n{OLD_BODY}", stamp_line("0.0.1", OLD_BODY)).replace('\n', "\r\n");
        let mixed = format!("{crlf}bare\n");
        assert_eq!(
            judge(&mixed, &running()),
            GuideStatus::Stale(StaleReason::HandEdited(HandEdit::MalformedStamp))
        );
    }

    #[test]
    fn asset_is_terminal_safe_identity() {
        assert_eq!(crate::style::TerminalSafe::sanitize(ASSET).as_str(), ASSET);
    }

    #[test]
    fn guide_title_names_what_lookups_ask_for() {
        for word in ["AGENTS.md", "agents", "authoring"] {
            assert!(GUIDE_TITLE.contains(word), "title carries {word}");
        }
    }
}

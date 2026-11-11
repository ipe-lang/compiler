//! The `AGENTS.md` coding-agent guide: one embedded asset, one stamp, one judge.
//!
//! [`ASSET`] is the guide's single source: `ipe init` writes [`rendered`] (a
//! [`GuideStamp`] line, then `ASSET`) and `ipe doc guide:agents` serves `ASSET`
//! itself. The stamp is written by [`GuideStamp::render`] and read only by
//! [`GuideStamp::parse`]; whether a file is current is judged by byte equality
//! with `ASSET` ([`judge`]), never by trusting what its stamp claims.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::ffi::OsStr;
use std::num::NonZeroU64;

use ipe_fs_open::{ByteCap, FileId};
use sha2::{Digest as _, Sha256};

use crate::CliError;
use crate::output_dir::held::{self, BackedUp, Created, HeldDir, ReadMiss, Replaced};
pub use crate::output_dir::held::{BackupName, Unread};
pub use crate::project::NoProject;

/// The guide, embedded once; every consumer reads this constant.
pub const ASSET: &str = include_str!("../../templates/AGENTS.md.in");

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

/// What the text of a present, read `AGENTS.md` is.
enum Verdict {
    /// It is this ipe's guide.
    Current,
    /// It is another guide.
    Stale(StaleReason),
}

impl From<Verdict> for GuideStatus {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Current => Self::Current,
            Verdict::Stale(reason) => Self::Stale(reason),
        }
    }
}

/// Judge the text of an `AGENTS.md` against [`ASSET`] for the `running` ipe.
///
/// Pure; never [`GuideStatus::Missing`] or [`GuideStatus::Unread`].
#[must_use]
pub fn judge(contents: &str, running: &semver::Version) -> GuideStatus {
    verdict(contents, running).into()
}

/// The verdict on the text of an `AGENTS.md`.
fn verdict(contents: &str, running: &semver::Version) -> Verdict {
    let view = line_ending_view(contents);
    match first_line(&view) {
        FirstLine::Plain => {
            if view == ASSET {
                Verdict::Current
            } else {
                Verdict::Stale(StaleReason::HandEdited(HandEdit::Unstamped))
            }
        }
        FirstLine::Malformed => Verdict::Stale(StaleReason::HandEdited(HandEdit::MalformedStamp)),
        FirstLine::Stamped(stamp, body) => {
            let as_asset = body == ASSET;
            let untouched = AssetDigest::of(body) == stamp.digest;
            match (as_asset, untouched, stamp.version.cmp_precedence(running)) {
                (true, true | false, Ordering::Less | Ordering::Equal | Ordering::Greater) => {
                    Verdict::Current
                }
                (false, true, Ordering::Less | Ordering::Equal) => {
                    Verdict::Stale(StaleReason::OlderGuide {
                        written_by: stamp.version,
                    })
                }
                (false, true, Ordering::Greater) => Verdict::Stale(StaleReason::NewerGuide {
                    written_by: stamp.version,
                }),
                (false, false, Ordering::Less | Ordering::Equal | Ordering::Greater) => {
                    Verdict::Stale(StaleReason::HandEdited(HandEdit::Edited))
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

/// Read `AGENTS.md` in `dir` under [`GUIDE_READ_CAP`], with the identity of the handle read.
fn read_identified(dir: &HeldDir) -> Result<(String, FileId), ReadMiss> {
    let name = dir
        .entry(OsStr::new(FILE_NAME))
        .map_err(|e| held::read_miss(&e))?;
    dir.read_file_capped_identified(&name, GUIDE_READ_CAP)
        .map_err(|e| held::read_miss(&e))
}

/// Judge the `AGENTS.md` of the held project directory `dir` against this ipe's guide.
///
/// The file is read once, never through a link, under [`GUIDE_READ_CAP`].
#[must_use]
pub(crate) fn read_guide(dir: &HeldDir) -> GuideStatus {
    match read_identified(dir) {
        Ok((text, _)) => judge(&text, &crate::version_check::current_version()),
        Err(ReadMiss::Absent) => GuideStatus::Missing,
        Err(ReadMiss::Unread(unread)) => GuideStatus::Unread(unread),
    }
}

/// A file read and judged: the identity of the handle read and its exact text.
#[derive(Debug)]
pub struct JudgedFile {
    id: FileId,
    bytes: String,
}

/// What an upgrade does without asking.
#[derive(Debug)]
pub enum UpgradePlan {
    /// The file is this ipe's guide; nothing is written.
    Current,
    /// There is no file; it is created.
    Create,
    /// An untouched guide of an ipe no newer than this one; it is replaced.
    Replace {
        /// The ipe that wrote it.
        from: semver::Version,
        /// The file judged.
        judged: JudgedFile,
    },
}

/// A hand-edited file, replaced only with an [`OverwriteConsent`].
#[derive(Debug)]
pub struct HandEditedPlan {
    edit: HandEdit,
    judged: JudgedFile,
}

impl HandEditedPlan {
    /// How the file differs from the guide.
    #[must_use]
    pub const fn edit(&self) -> HandEdit {
        self.edit
    }

    /// The refusal of a write no one consented to; the file is left unchanged.
    #[must_use]
    pub fn refuse(self) -> GuideRefusal {
        GuideRefusal::HandEdited(self.edit)
    }
}

/// What [`plan`] found.
#[derive(Debug)]
pub enum Planned {
    /// The upgrade needs no question.
    Ready(UpgradePlan),
    /// The file was edited by hand; replacing it needs consent.
    NeedsConsent(HandEditedPlan),
}

/// The answer to the overwrite question, or why none was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Asked on a terminal; answered yes.
    Yes,
    /// Asked on a terminal; answered anything but yes.
    No,
    /// Human output with no terminal to ask on.
    NoTerminal,
    /// Machine output, which never asks.
    MachineOutput,
}

/// Proof that the user answered yes to overwriting a hand-edited guide.
///
/// Built only by [`consent`]; taken by value, so one answer licenses one write.
#[derive(Debug)]
pub struct OverwriteConsent(());

impl OverwriteConsent {
    /// Uses up the consent on the one write it licenses.
    const fn spend(self) {
        let Self(()) = self;
    }
}

/// The consent an answer gives; only [`Answer::Yes`] gives one.
#[must_use]
pub const fn consent(answer: Answer) -> Option<OverwriteConsent> {
    match answer {
        Answer::Yes => Some(OverwriteConsent(())),
        Answer::No | Answer::NoTerminal | Answer::MachineOutput => None,
    }
}

/// What an upgrade did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeOutcome {
    /// The file already was this ipe's guide.
    Current,
    /// An older untouched guide was replaced.
    Rewritten {
        /// The ipe that wrote it.
        from: semver::Version,
    },
    /// The file was created.
    Created,
    /// A hand-edited file was backed up, then replaced.
    Replaced {
        /// Where its bytes were kept.
        backup: BackupName,
    },
}

/// Why an upgrade wrote nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuideRefusal {
    /// The working directory is not a project root.
    OutsideProject(NoProject),
    /// The project directory could not be opened.
    ProjectUnheld,
    /// The file was edited by hand and no one consented to replacing it.
    HandEdited(HandEdit),
    /// A newer ipe wrote the file.
    NewerGuide {
        /// The ipe that wrote it.
        written_by: semver::Version,
    },
    /// The file could not be read.
    Unread(Unread),
    /// The file changed after it was judged.
    ChangedSinceRead,
    /// Every backup slot is taken.
    BackupSlotsFull,
}

impl GuideRefusal {
    /// The refusal's message: its reason, then its remedy; only typed values reach it.
    #[must_use]
    pub fn message(&self) -> crate::text::Message {
        use crate::text::msg;
        match self {
            Self::OutsideProject(NoProject::NoManifest) => {
                msg::agents_guide_no_manifest(&UPGRADE_HINT)
            }
            Self::OutsideProject(NoProject::LegacyToml) => msg::legacy_toml_hint(),
            Self::ProjectUnheld => msg::agents_guide_unheld(&FILE_NAME),
            Self::HandEdited(edit) => msg::agents_guide_hand_edited(
                &FILE_NAME,
                &edit.phrase(),
                &GUIDE_TERM,
                &UPGRADE_HINT,
            ),
            Self::NewerGuide { written_by } => msg::agents_guide_newer(
                &FILE_NAME,
                written_by,
                &crate::version_check::current_version(),
            ),
            Self::Unread(unread) => {
                msg::agents_guide_unread(&FILE_NAME, &unread.phrase(GUIDE_READ_CAP))
            }
            Self::ChangedSinceRead => msg::agents_guide_changed(&FILE_NAME, &UPGRADE_HINT),
            Self::BackupSlotsFull => msg::agents_guide_backups_full(
                &FILE_NAME,
                &crate::driver::BACKUP_DIR,
                &held::BACKUP_SLOTS,
                &UPGRADE_HINT,
            ),
        }
    }
}

/// Judge `AGENTS.md` in `dir` and decide what an upgrade does.
///
/// # Errors
/// [`GuideRefusal::Unread`] for a file that could not be read;
/// [`GuideRefusal::NewerGuide`] for a guide a newer ipe wrote.
pub(crate) fn plan(dir: &HeldDir) -> Result<Planned, GuideRefusal> {
    let (bytes, id) = match read_identified(dir) {
        Ok(read) => read,
        Err(ReadMiss::Absent) => return Ok(Planned::Ready(UpgradePlan::Create)),
        Err(ReadMiss::Unread(unread)) => return Err(GuideRefusal::Unread(unread)),
    };
    match verdict(&bytes, &crate::version_check::current_version()) {
        Verdict::Current => Ok(Planned::Ready(UpgradePlan::Current)),
        Verdict::Stale(StaleReason::OlderGuide { written_by }) => {
            Ok(Planned::Ready(UpgradePlan::Replace {
                from: written_by,
                judged: JudgedFile { id, bytes },
            }))
        }
        Verdict::Stale(StaleReason::NewerGuide { written_by }) => {
            Err(GuideRefusal::NewerGuide { written_by })
        }
        Verdict::Stale(StaleReason::HandEdited(edit)) => {
            Ok(Planned::NeedsConsent(HandEditedPlan {
                edit,
                judged: JudgedFile { id, bytes },
            }))
        }
    }
}

/// Write [`rendered`] to the staged file and sync it.
fn fill(file: &mut std::fs::File) -> std::io::Result<()> {
    use std::io::Write as _;
    file.write_all(rendered().as_bytes())?;
    file.sync_all()
}

/// Carry out a plan that needs no consent.
///
/// # Errors
/// [`CliError::AgentsGuideRefused`] with [`GuideRefusal::ChangedSinceRead`]
/// when the file changed after it was judged; [`CliError::Io`] on a filesystem
/// failure, the file left intact.
pub(crate) fn apply(dir: &HeldDir, plan: UpgradePlan) -> Result<UpgradeOutcome, CliError> {
    let name = OsStr::new(FILE_NAME);
    match plan {
        UpgradePlan::Current => Ok(UpgradeOutcome::Current),
        UpgradePlan::Create => match dir.create_if_absent(name, fill)? {
            Created::Done => Ok(UpgradeOutcome::Created),
            Created::Exists => Err(CliError::AgentsGuideRefused(GuideRefusal::ChangedSinceRead)),
        },
        UpgradePlan::Replace { from, judged } => {
            match dir.replace_if_unchanged(name, judged.id, &judged.bytes, GUIDE_READ_CAP, fill)? {
                Replaced::Done => Ok(UpgradeOutcome::Rewritten { from }),
                Replaced::Changed => {
                    Err(CliError::AgentsGuideRefused(GuideRefusal::ChangedSinceRead))
                }
            }
        }
    }
}

/// Back up a hand-edited file, then replace it, under the user's consent.
///
/// # Errors
/// [`CliError::AgentsGuideRefused`] with [`GuideRefusal::ChangedSinceRead`] or
/// [`GuideRefusal::BackupSlotsFull`]; [`CliError::Io`] on a filesystem
/// failure, the file left intact.
pub(crate) fn apply_consented(
    dir: &HeldDir,
    plan: HandEditedPlan,
    consent: OverwriteConsent,
) -> Result<UpgradeOutcome, CliError> {
    consent.spend();
    let judged = plan.judged;
    match dir.replace_backed_up(
        OsStr::new(FILE_NAME),
        judged.id,
        &judged.bytes,
        GUIDE_READ_CAP,
        fill,
    )? {
        BackedUp::Done(backup) => Ok(UpgradeOutcome::Replaced { backup }),
        BackedUp::Changed => Err(CliError::AgentsGuideRefused(GuideRefusal::ChangedSinceRead)),
        BackedUp::BackupSlotsFull => {
            Err(CliError::AgentsGuideRefused(GuideRefusal::BackupSlotsFull))
        }
    }
}

mod claims;

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

    /// A fresh, empty scratch directory unique to this test process.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = ipe_test_temp::temp_root()
            .join(format!("ipe_agents_guide_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("make scratch");
        std::fs::canonicalize(&dir).expect("canonicalize scratch")
    }

    fn held_at(path: &std::path::Path) -> HeldDir {
        HeldDir::open(path).expect("open dir").expect("dir exists")
    }

    /// The identity of the file at `path`.
    fn id_at(path: &std::path::Path) -> Option<FileId> {
        std::fs::File::open(path)
            .ok()
            .and_then(|file| FileId::of_file(&file).ok())
    }

    /// The names in `dir`, sorted; an absent directory lists nothing.
    fn names_in(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// No staged `.AGENTS.md.ipe-tmp.*` entry is left in `dir`.
    fn no_temp(dir: &std::path::Path) -> bool {
        !names_in(dir).iter().any(|name| name.contains(".ipe-tmp."))
    }

    fn older_guide() -> String {
        format!("{}\n{OLD_BODY}", stamp_line("0.0.1", OLD_BODY))
    }

    fn edited_guide() -> String {
        format!("{}\n{OLD_BODY}edit\n", stamp_line("0.0.1", OLD_BODY))
    }

    fn malformed_guide() -> String {
        format!("<!-- ipe-guide:2 whatever -->\n{ASSET}")
    }

    /// A project directory holding `AGENTS.md` with `contents`.
    fn with_guide(tag: &str, contents: &[u8]) -> (std::path::PathBuf, HeldDir) {
        let base = scratch(tag);
        std::fs::write(base.join(FILE_NAME), contents).expect("plant AGENTS.md");
        let dir = held_at(&base);
        (base, dir)
    }

    fn guide_bytes(base: &std::path::Path) -> Option<Vec<u8>> {
        std::fs::read(base.join(FILE_NAME)).ok()
    }

    /// The plan, when it needs no question.
    fn ready(dir: &HeldDir) -> Option<UpgradePlan> {
        match plan(dir) {
            Ok(Planned::Ready(plan)) => Some(plan),
            other => {
                assert!(matches!(other, Ok(Planned::Ready(_))), "{other:?}");
                None
            }
        }
    }

    /// The plan, when it needs consent.
    fn needs_consent(dir: &HeldDir) -> Option<HandEditedPlan> {
        match plan(dir) {
            Ok(Planned::NeedsConsent(plan)) => Some(plan),
            other => {
                assert!(matches!(other, Ok(Planned::NeedsConsent(_))), "{other:?}");
                None
            }
        }
    }

    fn yes() -> OverwriteConsent {
        consent(Answer::Yes).expect("yes consents")
    }

    /// Whether `result` is the changed-since-read refusal.
    fn is_changed(result: &Result<UpgradeOutcome, CliError>) -> bool {
        matches!(
            result,
            Err(CliError::AgentsGuideRefused(GuideRefusal::ChangedSinceRead))
        )
    }

    /// A FIFO named `AGENTS.md` in `base`.
    #[cfg(unix)]
    fn plant_fifo(base: &std::path::Path) {
        let made = std::process::Command::new("mkfifo")
            .arg(base.join(FILE_NAME))
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo creates the fixture");
    }

    /// Run `work` on its own thread; `None` when it does not finish within five seconds.
    #[cfg(unix)]
    fn within_timeout<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .spawn(move || {
                let _ = sent.send(work());
            })
            .expect("spawn the worker");
        received
            .recv_timeout(std::time::Duration::from_secs(5))
            .ok()
    }

    #[cfg(unix)]
    #[test]
    fn read_guide_symlink_is_unread_not_followed() {
        let base = scratch("read_link");
        let outside = scratch("read_link_outside");
        std::fs::write(outside.join("guide"), rendered()).expect("plant outside guide");
        std::os::unix::fs::symlink(outside.join("guide"), base.join(FILE_NAME))
            .expect("plant link");
        assert_eq!(
            read_guide(&held_at(&base)),
            GuideStatus::Unread(Unread::Link)
        );
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(unix)]
    #[test]
    fn read_guide_fifo_does_not_block() {
        let base = scratch("read_fifo");
        plant_fifo(&base);
        let dir = base.clone();
        let status = within_timeout(move || read_guide(&held_at(&dir)));
        assert_eq!(status, Some(GuideStatus::Unread(Unread::NotRegular)));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn read_guide_oversize_is_unread() {
        let cap = usize::try_from(GUIDE_READ_CAP.get()).expect("the cap fits usize");
        let (base, dir) = with_guide("read_over", &vec![b'a'; cap + 1]);
        assert_eq!(read_guide(&dir), GuideStatus::Unread(Unread::TooLarge));
        std::fs::write(base.join(FILE_NAME), vec![b'a'; cap]).expect("rewrite at the cap");
        assert_eq!(
            read_guide(&dir),
            GuideStatus::Stale(StaleReason::HandEdited(HandEdit::Unstamped))
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn read_guide_non_utf8_is_unread() {
        let (base, dir) = with_guide("read_utf8", &[0xff, 0xfe, b'\n']);
        assert_eq!(read_guide(&dir), GuideStatus::Unread(Unread::NotUtf8));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn read_guide_absent_is_missing() {
        let base = scratch("read_absent");
        assert_eq!(read_guide(&held_at(&base)), GuideStatus::Missing);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Each stale or missing state's remedy leaves a current guide.
    #[test]
    fn health_suggestion_clears_its_state() {
        let base = scratch("remedy_missing");
        let dir = held_at(&base);
        let created = ready(&dir).map(|plan| apply(&dir, plan));
        assert!(
            matches!(created, Some(Ok(UpgradeOutcome::Created))),
            "{created:?}"
        );
        assert_eq!(read_guide(&dir), GuideStatus::Current);
        let _ = std::fs::remove_dir_all(&base);

        let (base, dir) = with_guide("remedy_older", older_guide().as_bytes());
        let rewritten = ready(&dir).map(|plan| apply(&dir, plan));
        assert!(
            matches!(rewritten, Some(Ok(UpgradeOutcome::Rewritten { .. }))),
            "{rewritten:?}"
        );
        assert_eq!(read_guide(&dir), GuideStatus::Current);
        let _ = std::fs::remove_dir_all(&base);

        for (tag, contents) in [
            ("remedy_edited", edited_guide()),
            ("remedy_unstamped", OLD_BODY.to_owned()),
            ("remedy_malformed", malformed_guide()),
        ] {
            let (base, dir) = with_guide(tag, contents.as_bytes());
            let replaced = needs_consent(&dir).map(|plan| apply_consented(&dir, plan, yes()));
            assert!(
                matches!(replaced, Some(Ok(UpgradeOutcome::Replaced { .. }))),
                "{tag}: {replaced:?}"
            );
            assert_eq!(read_guide(&dir), GuideStatus::Current, "{tag}");
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    #[cfg(unix)]
    #[test]
    fn agents_symlink_refused_target_untouched() {
        let base = scratch("agents_link");
        let outside = scratch("agents_link_outside");
        std::fs::write(outside.join("guide"), older_guide()).expect("plant outside guide");
        let before = id_at(&outside.join("guide"));
        std::os::unix::fs::symlink(outside.join("guide"), base.join(FILE_NAME))
            .expect("plant link");
        let planned = plan(&held_at(&base));
        assert!(
            matches!(planned, Err(GuideRefusal::Unread(Unread::Link))),
            "{planned:?}"
        );
        assert!(
            std::fs::symlink_metadata(base.join(FILE_NAME))
                .is_ok_and(|meta| meta.file_type().is_symlink())
        );
        assert_eq!(
            std::fs::read_to_string(outside.join("guide")).ok(),
            Some(older_guide())
        );
        assert_eq!(id_at(&outside.join("guide")), before);
        assert!(no_temp(&base));
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(unix)]
    #[test]
    fn agents_fifo_refused_without_blocking() {
        let base = scratch("agents_fifo");
        plant_fifo(&base);
        let dir = base.clone();
        let refused = within_timeout(move || {
            matches!(
                plan(&held_at(&dir)),
                Err(GuideRefusal::Unread(Unread::NotRegular))
            )
        });
        assert_eq!(refused, Some(true));
        assert!(no_temp(&base));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn agents_oversize_refused() {
        let cap = usize::try_from(GUIDE_READ_CAP.get()).expect("the cap fits usize");
        let big = vec![b'a'; cap + 1];
        let (base, dir) = with_guide("agents_over", &big);
        let planned = plan(&dir);
        assert!(
            matches!(planned, Err(GuideRefusal::Unread(Unread::TooLarge))),
            "{planned:?}"
        );
        assert_eq!(guide_bytes(&base), Some(big));
        assert!(no_temp(&base));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Refusing a hand-edited plan names exactly the planned edit.
    #[test]
    fn agents_declined_refuses_with_the_planned_edit() {
        for (tag, contents, edit) in [
            ("declined_edited", edited_guide(), HandEdit::Edited),
            (
                "declined_unstamped",
                OLD_BODY.to_owned(),
                HandEdit::Unstamped,
            ),
            (
                "declined_malformed",
                malformed_guide(),
                HandEdit::MalformedStamp,
            ),
            (
                "declined_claimed",
                format!(
                    "{}\n{ASSET}edit\n",
                    stamp_line(&running().to_string(), ASSET)
                ),
                HandEdit::Edited,
            ),
        ] {
            let (base, dir) = with_guide(tag, contents.as_bytes());
            for answer in [Answer::No, Answer::NoTerminal, Answer::MachineOutput] {
                let Some(hand_edited) = needs_consent(&dir) else {
                    return;
                };
                assert_eq!(hand_edited.edit(), edit, "{tag}");
                assert!(consent(answer).is_none());
                assert_eq!(
                    hand_edited.refuse(),
                    GuideRefusal::HandEdited(edit),
                    "{tag}"
                );
            }
            assert_eq!(guide_bytes(&base), Some(contents.into_bytes()));
            assert!(!base.join(crate::driver::BACKUP_DIR).exists());
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    #[test]
    fn agents_hand_edited_changed_during_question() {
        for by_rename in [false, true] {
            let (base, dir) = with_guide("asked_changed", edited_guide().as_bytes());
            let Some(hand_edited) = needs_consent(&dir) else {
                return;
            };
            let now = if by_rename {
                std::fs::write(base.join("other"), edited_guide()).expect("stage rename");
                std::fs::rename(base.join("other"), base.join(FILE_NAME)).expect("rename over");
                edited_guide()
            } else {
                let changed = format!("{}more\n", edited_guide());
                std::fs::write(base.join(FILE_NAME), &changed).expect("edit in place");
                changed
            };
            let applied = apply_consented(&dir, hand_edited, yes());
            assert!(is_changed(&applied), "rename {by_rename}: {applied:?}");
            assert_eq!(guide_bytes(&base), Some(now.into_bytes()));
            assert!(names_in(&base.join(crate::driver::BACKUP_DIR)).is_empty());
            assert!(no_temp(&base));
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    #[cfg(unix)]
    #[test]
    fn agents_hand_edited_link_planted_during_question() {
        let (base, dir) = with_guide("asked_link", edited_guide().as_bytes());
        let outside = scratch("asked_link_outside");
        std::fs::write(outside.join("victim"), edited_guide()).expect("plant outside file");
        let Some(hand_edited) = needs_consent(&dir) else {
            return;
        };
        std::fs::remove_file(base.join(FILE_NAME)).expect("remove the file");
        std::os::unix::fs::symlink(outside.join("victim"), base.join(FILE_NAME))
            .expect("plant link");
        let applied = apply_consented(&dir, hand_edited, yes());
        assert!(is_changed(&applied), "{applied:?}");
        assert_eq!(
            std::fs::read_to_string(outside.join("victim")).ok(),
            Some(edited_guide())
        );
        assert!(
            std::fs::symlink_metadata(base.join(FILE_NAME))
                .is_ok_and(|meta| meta.file_type().is_symlink())
        );
        assert!(names_in(&base.join(crate::driver::BACKUP_DIR)).is_empty());
        assert!(no_temp(&base));
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn agents_consented_backup_slots_full() {
        let (base, dir) = with_guide("slots_full", edited_guide().as_bytes());
        let backups = base.join(crate::driver::BACKUP_DIR);
        std::fs::create_dir(&backups).expect("make backups");
        for slot in 0..held::BACKUP_SLOTS {
            let slot_name = if slot == 0 {
                format!("{FILE_NAME}.bak")
            } else {
                format!("{FILE_NAME}.bak.{slot}")
            };
            std::fs::write(backups.join(slot_name), "taken").expect("take slot");
        }
        let before = names_in(&backups);
        let Some(hand_edited) = needs_consent(&dir) else {
            return;
        };
        let applied = apply_consented(&dir, hand_edited, yes());
        assert!(
            matches!(
                applied,
                Err(CliError::AgentsGuideRefused(GuideRefusal::BackupSlotsFull))
            ),
            "{applied:?}"
        );
        assert_eq!(guide_bytes(&base), Some(edited_guide().into_bytes()));
        assert_eq!(names_in(&backups), before);
        assert!(no_temp(&base));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn agents_newer_guide_refused() {
        let file = format!("{}\n{OLD_BODY}", stamp_line(&newer().to_string(), OLD_BODY));
        let (base, dir) = with_guide("agents_newer", file.as_bytes());
        let planned = plan(&dir);
        assert!(
            matches!(&planned, Err(GuideRefusal::NewerGuide { written_by }) if *written_by == newer()),
            "{planned:?}"
        );
        assert_eq!(guide_bytes(&base), Some(file.into_bytes()));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn agents_write_failure_leaves_old_intact() {
        let fail = |_: &mut std::fs::File| Err(std::io::Error::other("disk full"));
        let (base, dir) = with_guide("write_fail", older_guide().as_bytes());
        let before = id_at(&base.join(FILE_NAME));
        let (bytes, id) = read_identified(&dir).expect("read the guide");
        let replaced =
            dir.replace_if_unchanged(OsStr::new(FILE_NAME), id, &bytes, GUIDE_READ_CAP, fail);
        assert!(matches!(replaced, Err(CliError::Io { .. })), "{replaced:?}");
        assert_eq!(guide_bytes(&base), Some(older_guide().into_bytes()));
        assert_eq!(id_at(&base.join(FILE_NAME)), before);
        assert!(no_temp(&base));
        let _ = std::fs::remove_dir_all(&base);

        let base = scratch("create_fail");
        let created = held_at(&base).create_if_absent(OsStr::new(FILE_NAME), fail);
        assert!(matches!(created, Err(CliError::Io { .. })), "{created:?}");
        assert!(names_in(&base).is_empty(), "{:?}", names_in(&base));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn agents_changed_since_read_not_overwritten() {
        for by_rename in [false, true] {
            let (base, dir) = with_guide("read_changed", older_guide().as_bytes());
            let Some(plan) = ready(&dir) else {
                return;
            };
            assert!(matches!(plan, UpgradePlan::Replace { .. }), "{plan:?}");
            let now = if by_rename {
                std::fs::write(base.join("other"), older_guide()).expect("stage rename");
                std::fs::rename(base.join("other"), base.join(FILE_NAME)).expect("rename over");
                older_guide()
            } else {
                let changed = format!("{}mine\n", older_guide());
                std::fs::write(base.join(FILE_NAME), &changed).expect("edit in place");
                changed
            };
            let applied = apply(&dir, plan);
            assert!(is_changed(&applied), "rename {by_rename}: {applied:?}");
            assert_eq!(guide_bytes(&base), Some(now.into_bytes()));
            assert!(no_temp(&base));
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    #[test]
    fn agents_created_file_not_clobbered() {
        let base = scratch("create_raced");
        let dir = held_at(&base);
        let Some(plan) = ready(&dir) else {
            return;
        };
        assert!(matches!(plan, UpgradePlan::Create), "{plan:?}");
        std::fs::write(base.join(FILE_NAME), "mine\n").expect("a file appears");
        let applied = apply(&dir, plan);
        assert!(is_changed(&applied), "{applied:?}");
        assert_eq!(guide_bytes(&base), Some(b"mine\n".to_vec()));
        assert!(no_temp(&base));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn agents_link_planted_after_plan_is_replaced_not_followed() {
        let (base, dir) = with_guide("plan_link", older_guide().as_bytes());
        let outside = scratch("plan_link_outside");
        std::fs::write(outside.join("victim"), older_guide()).expect("plant outside file");
        let Some(plan) = ready(&dir) else {
            return;
        };
        std::fs::remove_file(base.join(FILE_NAME)).expect("remove the file");
        std::os::unix::fs::symlink(outside.join("victim"), base.join(FILE_NAME))
            .expect("plant link");
        let applied = apply(&dir, plan);
        assert!(is_changed(&applied), "{applied:?}");
        assert_eq!(
            std::fs::read_to_string(outside.join("victim")).ok(),
            Some(older_guide())
        );
        assert!(no_temp(&base));
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn agents_current_is_no_op() {
        let (base, dir) = with_guide("current", rendered().as_bytes());
        let before = id_at(&base.join(FILE_NAME));
        let applied = ready(&dir).map(|plan| apply(&dir, plan));
        assert!(
            matches!(applied, Some(Ok(UpgradeOutcome::Current))),
            "{applied:?}"
        );
        assert_eq!(guide_bytes(&base), Some(rendered().into_bytes()));
        assert_eq!(id_at(&base.join(FILE_NAME)), before);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn agents_older_is_rewritten() {
        for crlf in [false, true] {
            let old = if crlf {
                older_guide().replace('\n', "\r\n")
            } else {
                older_guide()
            };
            let (base, dir) = with_guide("older", old.as_bytes());
            let applied = ready(&dir).map(|plan| apply(&dir, plan));
            assert!(
                matches!(&applied, Some(Ok(UpgradeOutcome::Rewritten { from })) if *from == semver::Version::new(0, 0, 1)),
                "crlf {crlf}: {applied:?}"
            );
            assert_eq!(guide_bytes(&base), Some(rendered().into_bytes()));
            assert!(no_temp(&base));
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    #[test]
    fn agents_missing_is_created() {
        let base = scratch("missing");
        let dir = held_at(&base);
        let applied = ready(&dir).map(|plan| apply(&dir, plan));
        assert!(
            matches!(applied, Some(Ok(UpgradeOutcome::Created))),
            "{applied:?}"
        );
        assert_eq!(guide_bytes(&base), Some(rendered().into_bytes()));
        assert!(no_temp(&base));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn agents_hand_edited_consented_backs_up_and_replaces() {
        let (base, dir) = with_guide("consented", edited_guide().as_bytes());
        let backups = base.join(crate::driver::BACKUP_DIR);
        let applied = needs_consent(&dir).map(|plan| apply_consented(&dir, plan, yes()));
        assert!(
            matches!(&applied, Some(Ok(UpgradeOutcome::Replaced { backup })) if backup.to_string() == ".ipe-backup/AGENTS.md.bak"),
            "{applied:?}"
        );
        assert_eq!(
            std::fs::read_to_string(backups.join("AGENTS.md.bak")).ok(),
            Some(edited_guide())
        );
        assert_eq!(guide_bytes(&base), Some(rendered().into_bytes()));

        std::fs::write(base.join(FILE_NAME), "second edit\n").expect("edit again");
        let applied = needs_consent(&dir).map(|plan| apply_consented(&dir, plan, yes()));
        assert!(
            matches!(&applied, Some(Ok(UpgradeOutcome::Replaced { backup })) if backup.to_string() == ".ipe-backup/AGENTS.md.bak.1"),
            "{applied:?}"
        );
        assert_eq!(
            std::fs::read_to_string(backups.join("AGENTS.md.bak.1"))
                .ok()
                .as_deref(),
            Some("second edit\n")
        );
        assert_eq!(
            std::fs::read_to_string(backups.join("AGENTS.md.bak")).ok(),
            Some(edited_guide())
        );
        assert_eq!(guide_bytes(&base), Some(rendered().into_bytes()));
        assert!(no_temp(&base));
        let _ = std::fs::remove_dir_all(&base);
    }
}

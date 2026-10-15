//! Why a listed entry holds no units, as the `refusals` row that records it.
//!
//! Every entry a git listing names ends as exactly one of: a `files` row with
//! its units, one `refusals` row with an [`Unreviewable`] reason, absent from
//! disk, or owned by a declared inner root. [`classify`] is the one total map
//! from a read's result to that end, and [`Refused`] is the only row shape: a
//! reason the review app can acknowledge carries a [`RefusalDigest`] of what it
//! acknowledges, and a blocking reason carries none.

use crate::model::{Lang, RepoTag};
use crate::walk::{DiskRefusal, NameRefusal, ReadRefusal};

/// Why a listed entry has no units; the `refusals.reason` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Unreviewable {
    /// The bytes read (at most the text ceiling) are not UTF-8.
    NotUtf8,
    /// The file is past the text ceiling and within the hash ceiling.
    TooLarge,
    /// Git records the entry as a symbolic link.
    SymlinkEntry,
    /// Git records the entry as a submodule commit.
    GitlinkEntry,
    /// Git records a mode that names no regular file.
    UnknownMode,
    /// The file is past the hash ceiling, or the run's hash budget is spent.
    PastHashCeiling,
    /// The listed name is not UTF-8.
    NonUtf8Name,
    /// The listed name is not a plain repository-relative path.
    NotRepoRelative,
    /// The entry is an untracked nested repository.
    NestedRepository,
    /// On disk the path is not a regular file reached through real directories.
    NotRegular,
    /// The path could not be inspected or read.
    Unreadable,
    /// The file changed between the no-follow check and the read.
    Replaced,
}

impl Unreviewable {
    /// Every reason, built from an exhaustive match so a new variant fails the
    /// build until it is listed here too.
    pub const ALL: [Self; 12] = match Self::NotUtf8 {
        Self::NotUtf8
        | Self::TooLarge
        | Self::SymlinkEntry
        | Self::GitlinkEntry
        | Self::UnknownMode
        | Self::PastHashCeiling
        | Self::NonUtf8Name
        | Self::NotRepoRelative
        | Self::NestedRepository
        | Self::NotRegular
        | Self::Unreadable
        | Self::Replaced => [
            Self::NotUtf8,
            Self::TooLarge,
            Self::SymlinkEntry,
            Self::GitlinkEntry,
            Self::UnknownMode,
            Self::PastHashCeiling,
            Self::NonUtf8Name,
            Self::NotRepoRelative,
            Self::NestedRepository,
            Self::NotRegular,
            Self::Unreadable,
            Self::Replaced,
        ],
    };

    /// The stored spelling of the reason.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::NotUtf8 => "not-utf8",
            Self::TooLarge => "too-large",
            Self::SymlinkEntry => "symlink-entry",
            Self::GitlinkEntry => "gitlink-entry",
            Self::UnknownMode => "unknown-mode",
            Self::PastHashCeiling => "past-hash-ceiling",
            Self::NonUtf8Name => "non-utf8-name",
            Self::NotRepoRelative => "not-repo-relative",
            Self::NestedRepository => "nested-repository",
            Self::NotRegular => "not-regular",
            Self::Unreadable => "unreadable",
            Self::Replaced => "replaced",
        }
    }

    /// Whether a row of this reason carries a digest a review can acknowledge.
    ///
    /// A blocking reason has none: only a change to the tree clears it.
    pub const fn ackable(self) -> bool {
        match self {
            Self::NotUtf8
            | Self::TooLarge
            | Self::SymlinkEntry
            | Self::GitlinkEntry
            | Self::UnknownMode => true,
            Self::PastHashCeiling
            | Self::NonUtf8Name
            | Self::NotRepoRelative
            | Self::NestedRepository
            | Self::NotRegular
            | Self::Unreadable
            | Self::Replaced => false,
        }
    }
}

/// Whether two texts hold the same bytes, usable in a `const` context.
const fn same_text(a: &str, b: &str) -> bool {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    loop {
        match (a.split_first(), b.split_first()) {
            (None, None) => return true,
            (Some((x, rest_a)), Some((y, rest_b))) if *x == *y => {
                a = rest_a;
                b = rest_b;
            }
            _ => return false,
        }
    }
}

/// Whether some tag of `reasons` is spelled twice.
const fn has_duplicate_tag(reasons: &[Unreviewable]) -> bool {
    let mut rest = reasons;
    while let Some((first, later)) = rest.split_first() {
        let mut others = later;
        while let Some((other, tail)) = others.split_first() {
            if same_text(first.tag(), other.tag()) {
                return true;
            }
            others = tail;
        }
        rest = later;
    }
    false
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if two reasons share a stored tag
const _: () = assert!(!has_duplicate_tag(&Unreviewable::ALL));

/// A reason whose digest is taken over the entry's content bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentReason {
    NotUtf8,
    TooLarge,
}

/// A reason whose digest is taken over the blob id git stages for the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeReason {
    SymlinkEntry,
    GitlinkEntry,
    UnknownMode,
}

/// A reason no digest can acknowledge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocking {
    PastHashCeiling,
    NonUtf8Name,
    NotRepoRelative,
    NestedRepository,
    NotRegular,
    Unreadable,
    Replaced,
}

impl ContentReason {
    const fn reason(self) -> Unreviewable {
        match self {
            Self::NotUtf8 => Unreviewable::NotUtf8,
            Self::TooLarge => Unreviewable::TooLarge,
        }
    }
}

impl ModeReason {
    const fn reason(self) -> Unreviewable {
        match self {
            Self::SymlinkEntry => Unreviewable::SymlinkEntry,
            Self::GitlinkEntry => Unreviewable::GitlinkEntry,
            Self::UnknownMode => Unreviewable::UnknownMode,
        }
    }
}

impl Blocking {
    const fn reason(self) -> Unreviewable {
        match self {
            Self::PastHashCeiling => Unreviewable::PastHashCeiling,
            Self::NonUtf8Name => Unreviewable::NonUtf8Name,
            Self::NotRepoRelative => Unreviewable::NotRepoRelative,
            Self::NestedRepository => Unreviewable::NestedRepository,
            Self::NotRegular => Unreviewable::NotRegular,
            Self::Unreadable => Unreviewable::Unreadable,
            Self::Replaced => Unreviewable::Replaced,
        }
    }
}

/// A git object id as `git ls-files -s` prints it: 40 or 64 lowercase hex digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oid(String);

impl Oid {
    /// Parses an object field, or `None` when it is not a full lowercase hex id.
    pub fn parse(field: &[u8]) -> Option<Self> {
        let hex = field
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b));
        if !hex || !matches!(field.len(), 40 | 64) {
            return None;
        }
        Some(Self(field.iter().map(|&b| char::from(b)).collect()))
    }
}

/// What a review acknowledges of a refused entry: `refusal-blake3:` and 64 hex.
///
/// The digest binds the reason tag and either the content bytes or the
/// staged blob id, each under its own domain, so it never equals a `files.sha`
/// stamp, a unit attestation, or the digest of another reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalDigest(String);

impl RefusalDigest {
    const SCHEME: &str = "refusal-blake3:";
    const DOMAIN: &[u8] = b"ipe-index/refusal-digest/v1\0";

    fn framed(reason: Unreviewable, kind: &[u8], body: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(Self::DOMAIN);
        h.update(reason.tag().as_bytes());
        h.update(b"\0");
        h.update(kind);
        h.update(body);
        Self(format!("{}{}", Self::SCHEME, h.finalize().to_hex()))
    }

    /// The digest of an entry refused for its content, whose blake3 is `content`.
    pub fn of_content(reason: ContentReason, content: &blake3::Hash) -> Self {
        Self::framed(reason.reason(), b"content\0", content.as_bytes())
    }

    /// The digest of an entry refused for its staged mode, whose blob id is `oid`.
    pub fn of_oid(reason: ModeReason, oid: &Oid) -> Self {
        Self::framed(reason.reason(), b"oid\0", oid.0.as_bytes())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One refusal as its row holds it: the reason, the size seen, the digest.
///
/// The constructors tie the digest to the reason: an ackable reason always
/// carries the digest its own constructor took, and a blocking one never does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    reason: Unreviewable,
    size: Option<u64>,
    digest: Option<RefusalDigest>,
}

impl Refused {
    /// A refusal for content whose blake3 is `content`, `size` bytes long.
    pub fn content(reason: ContentReason, size: u64, content: &blake3::Hash) -> Self {
        Self {
            reason: reason.reason(),
            size: Some(size),
            digest: Some(RefusalDigest::of_content(reason, content)),
        }
    }

    /// A refusal for a staged mode whose blob id is `oid`.
    pub fn mode(reason: ModeReason, oid: &Oid) -> Self {
        Self {
            reason: reason.reason(),
            size: None,
            digest: Some(RefusalDigest::of_oid(reason, oid)),
        }
    }

    /// A blocking refusal, with the size seen when one was.
    pub const fn blocking(reason: Blocking, size: Option<u64>) -> Self {
        Self {
            reason: reason.reason(),
            size,
            digest: None,
        }
    }

    pub const fn reason(&self) -> Unreviewable {
        self.reason
    }

    pub const fn size(&self) -> Option<u64> {
        self.size
    }

    pub const fn digest(&self) -> Option<&RefusalDigest> {
        self.digest.as_ref()
    }
}

/// A refused entry of one walk: its raw listed name, its language, its refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedEntry {
    /// The repository-relative name exactly as the listing gave it.
    pub name: Vec<u8>,
    pub lang: Lang,
    pub refused: Refused,
}

/// How one listed file ends after its read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The text its units are extracted from.
    Ingested(String),
    /// A refusal row.
    Refused(Refused),
    /// Gone from disk: no row.
    Absent,
    /// Owned by a declared inner root, whose walk records it.
    Claimed,
}

/// The end of one read, total over every [`ReadRefusal`].
pub fn classify(read: Result<String, ReadRefusal>) -> Outcome {
    let refusal = match read {
        Ok(text) => return Outcome::Ingested(text),
        Err(refusal) => refusal,
    };
    Outcome::Refused(match refusal {
        ReadRefusal::Absent => return Outcome::Absent,
        ReadRefusal::Claimed(_) => return Outcome::Claimed,
        ReadRefusal::Name(NameRefusal::NonUtf8 { .. }) => {
            Refused::blocking(Blocking::NonUtf8Name, None)
        }
        ReadRefusal::Name(NameRefusal::NotRepoRelative { .. }) => {
            Refused::blocking(Blocking::NotRepoRelative, None)
        }
        ReadRefusal::NotRegular(found) => Refused::blocking(disk_reason(&found), None),
        ReadRefusal::Replaced => Refused::blocking(Blocking::Replaced, None),
        ReadRefusal::Io(_) => Refused::blocking(Blocking::Unreadable, None),
        ReadRefusal::NotUtf8 { size, content } => {
            Refused::content(ContentReason::NotUtf8, size, &content)
        }
        ReadRefusal::TooLarge { size, content } => {
            Refused::content(ContentReason::TooLarge, size, &content)
        }
        ReadRefusal::PastHashCeiling { at_least } => {
            Refused::blocking(Blocking::PastHashCeiling, Some(at_least))
        }
    })
}

/// The blocking reason a no-follow disk check earns.
///
/// A declared root found moved at read time is a tree that changed under the
/// run, so the path is [`Blocking::Replaced`]; the walk itself fails the run
/// on a moved root before any read.
pub const fn disk_reason(found: &DiskRefusal) -> Blocking {
    match found {
        DiskRefusal::Symlink | DiskRefusal::LinkedAncestor { .. } | DiskRefusal::NotAFile => {
            Blocking::NotRegular
        }
        DiskRefusal::Unreadable { .. } => Blocking::Unreadable,
        DiskRefusal::RootMoved { .. } => Blocking::Replaced,
    }
}

/// The stable id of a refusal row: 64 lowercase hex over the repository tag and the raw name.
///
/// The domain prefix holds a NUL, which no stored path holds, so a refusal id
/// never equals a [`crate::store::unit_uid`].
pub fn refusal_uid(tag: &RepoTag, raw_name: &[u8]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"ipe-index/refusal/v1\0");
    h.update(tag.as_str().as_bytes());
    h.update(b"\0");
    h.update(raw_name);
    h.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Kind;
    use crate::store::{TABLE_SCHEMA, unit_uid};

    /// The quoted words of the SQL list that follows `opening` in the schema.
    fn sql_list(opening: &str) -> Vec<String> {
        let Some((_, after)) = TABLE_SCHEMA.split_once(opening) else {
            return Vec::new();
        };
        let Some((list, _)) = after.split_once(')') else {
            return Vec::new();
        };
        list.split(',')
            .map(|w| w.trim().trim_matches('\'').to_string())
            .collect()
    }

    // T9: the stored reason tags, the blocking ones, and the language spellings
    // of `refusals` are the ones the code writes, and a refusal id never
    // equals a unit id.
    #[test]
    fn refusal_rows_share_no_id_with_units_and_match_the_schema() {
        let tags: Vec<String> = Unreviewable::ALL
            .iter()
            .map(|r| r.tag().to_string())
            .collect();
        assert_eq!(sql_list("reason TEXT NOT NULL CHECK (reason IN ("), tags);
        let blocking: Vec<String> = Unreviewable::ALL
            .iter()
            .filter(|r| !r.ackable())
            .map(|r| r.tag().to_string())
            .collect();
        assert_eq!(sql_list("CHECK ((digest IS NULL) = (reason IN ("), blocking);
        let langs: Vec<String> = Lang::ALL.iter().map(|l| l.as_str().to_string()).collect();
        assert_eq!(sql_list("lang   TEXT NOT NULL CHECK (lang IN ("), langs);

        let tag = RepoTag::parse("ipe").unwrap();
        let kinds = [
            Kind::Module,
            Kind::File,
            Kind::Fn,
            Kind::Struct,
            Kind::Enum,
            Kind::Impl,
            Kind::Const,
            Kind::Binding,
            Kind::Block,
            Kind::Trait,
        ];
        let names: [&[u8]; 4] = [b"a.rs", b"src/\xffbad.sh", b"img.png", b""];
        for name in names {
            let uid = refusal_uid(&tag, name);
            assert_eq!(uid.len(), 64);
            assert!(
                uid.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
            let text = String::from_utf8_lossy(name);
            let tagged = tag.tagged(&text);
            for kind in kinds {
                for qualified in ["", "crate", text.as_ref()] {
                    assert_ne!(uid, unit_uid(&tagged, kind, qualified));
                    assert_ne!(uid, unit_uid(&text, kind, qualified));
                }
            }
        }
        let other = RepoTag::parse("sky").unwrap();
        assert_ne!(refusal_uid(&tag, b"a.rs"), refusal_uid(&other, b"a.rs"));
    }

    // A digest names its reason and its domain: the same bytes under another
    // reason, or an oid under the content domain, give another digest, and the
    // text is the one spelling the `refusals.digest` CHECK admits.
    #[test]
    fn a_refusal_digest_is_domain_separated() {
        let h = blake3::hash(b"\xff");
        let not_utf8 = RefusalDigest::of_content(ContentReason::NotUtf8, &h);
        let too_large = RefusalDigest::of_content(ContentReason::TooLarge, &h);
        assert_ne!(not_utf8, too_large);
        let text = not_utf8.as_str();
        assert_eq!(text.len(), 79);
        assert!(text.starts_with("refusal-blake3:"));
        assert_ne!(text.get(15..), Some(h.to_hex().as_str()));
        let oid = Oid::parse(b"6178079822d17af2d34fce4cfbdf355568324720").unwrap();
        let link = RefusalDigest::of_oid(ModeReason::SymlinkEntry, &oid);
        let gitlink = RefusalDigest::of_oid(ModeReason::GitlinkEntry, &oid);
        assert_ne!(link, gitlink);
        assert_eq!(link.as_str().len(), 79);
    }

    // Only a full lowercase id is an `Oid`.
    #[test]
    fn oid_parse_refuses_anything_but_a_full_lowercase_id() {
        let sha1 = "6178079822d17af2d34fce4cfbdf355568324720";
        assert!(Oid::parse(sha1.as_bytes()).is_some());
        assert!(Oid::parse("a".repeat(64).as_bytes()).is_some());
        for bad in [
            "abc".to_string(),
            sha1.to_uppercase(),
            sha1.get(1..).unwrap_or_default().to_string(),
            format!("{sha1}0"),
            "g".repeat(40),
            String::new(),
        ] {
            assert_eq!(Oid::parse(bad.as_bytes()), None, "{bad}");
        }
    }

    // Every ackable reason is built with its digest, every blocking one without.
    #[test]
    fn a_refused_row_carries_a_digest_exactly_when_ackable() {
        let h = blake3::hash(b"x");
        let oid = Oid::parse("b".repeat(40).as_bytes()).unwrap();
        let rows = [
            Refused::content(ContentReason::NotUtf8, 1, &h),
            Refused::content(ContentReason::TooLarge, 1, &h),
            Refused::mode(ModeReason::SymlinkEntry, &oid),
            Refused::mode(ModeReason::GitlinkEntry, &oid),
            Refused::mode(ModeReason::UnknownMode, &oid),
            Refused::blocking(Blocking::PastHashCeiling, None),
            Refused::blocking(Blocking::NonUtf8Name, None),
            Refused::blocking(Blocking::NotRepoRelative, None),
            Refused::blocking(Blocking::NestedRepository, None),
            Refused::blocking(Blocking::NotRegular, None),
            Refused::blocking(Blocking::Unreadable, None),
            Refused::blocking(Blocking::Replaced, None),
        ];
        let reasons: Vec<Unreviewable> = rows.iter().map(Refused::reason).collect();
        assert_eq!(reasons, Unreviewable::ALL);
        for row in &rows {
            assert_eq!(row.digest().is_some(), row.reason().ackable(), "{row:?}");
        }
    }

    // A read refused for its bytes keeps their digest and size; an absent or
    // claimed path makes no row.
    #[test]
    fn classify_is_total_over_read_refusals() {
        let h = blake3::hash(b"\xff");
        assert_eq!(
            classify(Err(ReadRefusal::NotUtf8 {
                size: 1,
                content: h
            })),
            Outcome::Refused(Refused::content(ContentReason::NotUtf8, 1, &h))
        );
        assert_eq!(classify(Err(ReadRefusal::Absent)), Outcome::Absent);
        assert_eq!(
            classify(Err(ReadRefusal::Claimed(RepoTag::parse("in").unwrap()))),
            Outcome::Claimed
        );
        assert_eq!(
            classify(Err(ReadRefusal::Io(std::io::ErrorKind::PermissionDenied))),
            Outcome::Refused(Refused::blocking(Blocking::Unreadable, None))
        );
        assert_eq!(
            classify(Ok("fn a() {}".to_string())),
            Outcome::Ingested("fn a() {}".to_string())
        );
    }
}

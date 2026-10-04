// The single source of truth for Ipê's lexical path seal.
//
// Every `Path` value is text produced by `seal(text, regime)`: the runtime
// `Path.fromString` seal (`crate::path`) calls it with the host regime, and the
// compiler's literal-path gate (`ipe_diagnostics::path_check`) calls it
// under BOTH regimes through `PathLitText::seal`, refusing a literal either
// regime refuses. The module is
// dependency-free (std only): the runtime references it as a sibling module
// (`crate::path_core::…`), and the standalone `ipe_path_core` crate `include!`s
// this exact file so the compiler seals a literal without pulling in the
// runtime's heavy optional dependencies (tokio, serde, sqlx, …).
//
// Regular (`//`) comments, not inner docs (`//!`): this file is `include!`d
// verbatim into the `ipe_path_core` crate root, where a leading `//!` after the
// `include!` item would be an illegal mid-file inner attribute. The crate-level
// docs live in `ipe_path_core`'s `lib.rs`.
//
// # One seal, two regimes
//
// * `seal` — THE constructor: NUL refusal, the Windows dot/space `..` disguise
//   refusal, lexical cleaning and the escape check, all under one `Regime`.
// * `PathLitText` — a literal sealed under both regimes; its only builder is
//   `PathLitText::seal`, so the two forms always come from one raw text.
// * `clean_with` / `escapes_root` / `Volume` / `ElementClass` — the regime-
//   parametrised primitives the seal and the runtime child-join parse share.

/// The separator regime a path is read under.
///
/// An enum rather than a `bool` so a call site names the regime it means and
/// can never pass it negated or in the wrong argument slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Regime {
    /// `/` alone separates elements; no volume prefix exists.
    Unix,
    /// `\` and `/` both separate elements; a drive / UNC / namespace volume may
    /// lead the path.
    Windows,
}

/// The separator regime of the build target.
pub const HOST: Regime = if cfg!(windows) {
    Regime::Windows
} else {
    Regime::Unix
};

impl Regime {
    /// Does this regime honour `\` and volume prefixes?
    #[must_use]
    pub const fn is_windows(self) -> bool {
        matches!(self, Self::Windows)
    }

    /// The canonical separator a cleaned path is written with.
    #[must_use]
    pub const fn separator(self) -> u8 {
        match self {
            Self::Unix => b'/',
            Self::Windows => b'\\',
        }
    }

    /// The regime's name as a diagnostic spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unix => "Unix",
            Self::Windows => "Windows",
        }
    }
}

/// Why [`seal`] refused a text.
///
/// Each variant names one refusal class; an exhaustive `match` forces every
/// consumer (the runtime `Display`, the compiler diagnostic) to handle each one.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SealRefusal {
    /// The text holds a NUL byte — a C-string terminator that truncates a path
    /// at the syscall boundary, enabling a poisoned-NUL bypass.
    Nul,
    /// An element Windows strips to `..` (trailing dots / spaces).
    DisguisedParent,
    /// The cleaned form climbs above its root.
    Escape {
        /// The cleaned form whose first element is the climb.
        cleaned: String,
    },
}

impl SealRefusal {
    /// The refusal's runtime message for the refused `path`.
    #[must_use]
    pub const fn describe<'a>(&'a self, path: &'a str) -> SealRefusalText<'a> {
        SealRefusalText { why: self, path }
    }
}

/// A [`SealRefusal`] paired with the text it refused, rendered by `Display`.
///
/// The one message table for a seal refusal at the Ipê-facing boundary.
#[derive(Clone, Copy, Debug)]
pub struct SealRefusalText<'a> {
    why: &'a SealRefusal,
    path: &'a str,
}

impl std::fmt::Display for SealRefusalText<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = self.path;
        match self.why {
            SealRefusal::Nul => f.write_str(
                "Ipe.Path: path contains a NUL byte (a syscall-boundary truncation / traversal risk)",
            ),
            SealRefusal::DisguisedParent => write!(
                f,
                "Ipe.Path: path element resolves to `..` after Windows trailing dot/space \
                 stripping (a traversal disguise): {path:?}"
            ),
            SealRefusal::Escape { cleaned } => write!(
                f,
                "Ipe.Path: path escapes its root via `..` traversal: {path:?} (cleaned: {cleaned:?})"
            ),
        }
    }
}

/// Does `s` contain a NUL byte?
///
/// A NUL is a C-string terminator that truncates a path at the syscall boundary
/// (`"safe.txt\0../../etc/passwd"` reaches the kernel as `"safe.txt"` on one code
/// path and the full string on another — a classic poisoned-NUL bypass), so it
/// is refused under every regime.
#[must_use]
pub fn has_nul(s: &str) -> bool {
    s.as_bytes().contains(&0)
}

/// Seal `text` into a path's one representation under `regime`.
///
/// Refuses a NUL byte, (under Windows) an element Windows strips to `..`, and a
/// cleaned form that climbs above its root; otherwise returns the cleaned form.
/// The empty text cleans to `"."`.
///
/// # Errors
///
/// Returns the [`SealRefusal`] naming the first refusal met.
///
/// # Examples (illustrative only — `text`, not a compiled doctest)
///
/// ```text
/// seal("a\\b/../c", Regime::Unix)     // Ok("c")    — `\` is a filename byte
/// seal("a\\b/../c", Regime::Windows)  // Ok("a\\c") — `\` separates
/// seal("..\\secret", Regime::Windows) // Err(SealRefusal::Escape { .. })
/// seal("a\0b", Regime::Unix)          // Err(SealRefusal::Nul)
/// ```
pub fn seal(text: &str, regime: Regime) -> Result<String, SealRefusal> {
    if has_nul(text) {
        return Err(SealRefusal::Nul);
    }
    // Windows strips trailing dots and spaces from every path element at the
    // syscall, so `".. "` and `"..."` name the parent directory even though the
    // lexical scan sees a literal filename. Refused before cleaning so the
    // disguise never resolves into a traversal the `..` scan failed to count.
    if regime.is_windows()
        && ElementClass::windows_elements(text).any(|c| c == ElementClass::DisguisedParent)
    {
        return Err(SealRefusal::DisguisedParent);
    }
    let cleaned = clean_with(text, regime);
    if escapes_root(&cleaned, regime) {
        return Err(SealRefusal::Escape { cleaned });
    }
    Ok(cleaned)
}

/// A source path literal sealed under every separator regime.
///
/// The compiler cannot know the final target, so a literal carries the sealed
/// form for each regime. The fields are
/// private and [`PathLitText::seal`] is the only builder, so both forms always
/// come from the same raw text.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct PathLitText {
    raw: String,
    unix: String,
    windows: String,
}

/// Why [`PathLitText::seal`] refused a literal: the regime and its refusal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LiteralRefusal {
    /// The regime whose seal refused (Unix is tried first).
    pub regime: Regime,
    /// That regime's refusal.
    pub why: SealRefusal,
}

impl PathLitText {
    /// Seal `raw` under both regimes; a refusal under either refuses the literal.
    ///
    /// A literal illegal on any target is illegal, so the compile-time gate is
    /// the union of both regimes' refusals.
    ///
    /// # Errors
    ///
    /// Returns the first regime's [`LiteralRefusal`] (Unix, then Windows).
    pub fn seal(raw: &str) -> Result<Self, LiteralRefusal> {
        let under =
            |regime: Regime| seal(raw, regime).map_err(|why| LiteralRefusal { regime, why });
        let unix = under(Regime::Unix)?;
        let windows = under(Regime::Windows)?;
        Ok(Self {
            raw: raw.to_owned(),
            unix,
            windows,
        })
    }

    /// The raw source text the literal was sealed from.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The literal's sealed form under `regime`.
    #[must_use]
    pub fn sealed(&self, regime: Regime) -> &str {
        match regime {
            Regime::Unix => &self.unix,
            Regime::Windows => &self.windows,
        }
    }
}

/// Is byte `c` an element separator under the active separator set?
///
/// Unix honours only `/`; Windows ALSO honours `\`, because Windows accepts
/// either at a syscall — so both must count, or the un-honoured one smuggles a
/// `..` past the traversal scan.
pub(crate) const fn is_sep(c: u8, regime: Regime) -> bool {
    c == b'/' || (regime.is_windows() && c == b'\\')
}

/// The namespace tag of a `\\?\…` / `\\.\…` prefix.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Namespace {
    /// `\\?\…` — verbatim: handed to the object manager without normalisation.
    Verbatim,
    /// `\\.\…` — the Win32 device namespace.
    Device,
}

/// The leading VOLUME of a path under Windows rules, parsed once.
///
/// Every consumer that asks "does this path carry a volume, and how long is
/// it?" reads this one parse, so the drive / UNC / namespace grammar lives in
/// one place. Unix never has a volume ([`Volume::None`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Volume<'a> {
    /// No volume: a Unix path, or a relative / root-relative Windows path.
    None,
    /// `X:` — a drive designator. Win32 reads ANY first UTF-16 unit followed by
    /// `:` as a drive (`é:`, `1:`, `::` included), so any non-separator
    /// character encoded as one UTF-16 unit qualifies — not only ASCII letters.
    /// A character outside the BMP is two UTF-16 units, so Win32 never pairs it
    /// with the `:` and it is not a drive.
    Drive(char),
    /// `\\server\share` — a UNC root; the share is absent for a bare `\\server`.
    Unc {
        server: &'a str,
        share: Option<&'a str>,
    },
    /// `\\?\UNC\server\share` — a verbatim UNC root. The server and share are
    /// part of the volume, so `..` can never climb out of the share and a
    /// root-relative path anchors on the right server.
    VerbatimUnc {
        server: &'a str,
        share: Option<&'a str>,
    },
    /// `\\?\name` / `\\.\name` — a verbatim or device namespace plus its first
    /// component (`\\?\C:`, `\\.\PhysicalDrive0`); `name` is absent for a bare
    /// `\\?` / `\\.`.
    Namespaced {
        tag: Namespace,
        name: Option<&'a str>,
    },
}

/// Split `s` at its first regime separator: the component before it, and the
/// text after it (`None` when `s` holds no separator).
fn split_component(s: &str, regime: Regime) -> (&str, Option<&str>) {
    s.bytes()
        .position(|c| is_sep(c, regime))
        .map_or((s, None), |i| {
            // A separator is one ASCII byte, so `i` and `i + 1` are char boundaries.
            (s.get(..i).unwrap_or(""), s.get(i + 1..))
        })
}

/// Byte length of an optional `\component` tail.
fn tail_len(component: Option<&str>) -> usize {
    component.map_or(0, |c| 1 + c.len())
}

impl<'a> Volume<'a> {
    /// Parse the leading volume of `path`; always [`Volume::None`] on Unix.
    #[must_use]
    pub fn parse(path: &'a str, regime: Regime) -> Self {
        if !regime.is_windows() {
            return Self::None;
        }
        let mut chars = path.chars();
        if let (Some(c), Some(':')) = (chars.next(), chars.next())
            && !u8::try_from(c).is_ok_and(|c| is_sep(c, regime))
            && c.len_utf16() == 1
        {
            return Self::Drive(c);
        }
        let b = path.as_bytes();
        let lead = |i: usize| b.get(i).is_some_and(|&c| is_sep(c, regime));
        if !(lead(0) && lead(1)) {
            return Self::None;
        }
        let (first, after) = split_component(path.get(2..).unwrap_or(""), regime);
        let component = |s: &'a str| split_component(s, regime).0;
        let tag = match first {
            "?" => Namespace::Verbatim,
            "." => Namespace::Device,
            server => {
                return Self::Unc {
                    server,
                    share: after.map(component),
                };
            }
        };
        if tag == Namespace::Verbatim
            && let Some(a) = after
            && let (name, Some(unc)) = split_component(a, regime)
            && name.eq_ignore_ascii_case("UNC")
        {
            let (server, share) = split_component(unc, regime);
            return Self::VerbatimUnc {
                server,
                share: share.map(component),
            };
        }
        Self::Namespaced {
            tag,
            name: after.map(component),
        }
    }

    /// Length in bytes of the volume prefix (`0` for [`Volume::None`]).
    #[must_use]
    pub fn byte_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Drive(c) => c.len_utf8() + 1,
            Self::Unc { server, share } => 2 + server.len() + tail_len(share),
            // `\\?\UNC\` is eight bytes.
            Self::VerbatimUnc { server, share } => 8 + server.len() + tail_len(share),
            // `\\?` / `\\.` is three bytes.
            Self::Namespaced { name, .. } => 3 + tail_len(name),
        }
    }

    /// Is this a drive designator (`X:`)? A drive alone is drive-RELATIVE,
    /// never rooted.
    #[must_use]
    pub const fn is_drive(self) -> bool {
        matches!(self, Self::Drive(_))
    }

    /// Can this volume anchor a Windows root-relative path (`\x`)?
    ///
    /// Only a volume that names one location completely: a drive, a UNC or
    /// verbatim-UNC root with both a server and a share, or a namespace with a
    /// non-UNC name. A device-namespace `\\.\UNC` (whose server and share this
    /// parse leaves outside the volume) or an incomplete UNC is refused, so a
    /// root-relative path is never anchored on the wrong server.
    #[must_use]
    pub fn anchors(self) -> bool {
        let named = |part: Option<&str>| part.is_some_and(|p| !p.is_empty());
        match self {
            Self::None => false,
            Self::Drive(_) => true,
            Self::Unc { server, share } | Self::VerbatimUnc { server, share } => {
                !server.is_empty() && named(share)
            }
            Self::Namespaced { name, .. } => {
                named(name) && !name.is_some_and(|n| n.eq_ignore_ascii_case("UNC"))
            }
        }
    }
}

/// Length in bytes of the leading VOLUME name of `path` under Windows rules:
/// the byte length of its [`Volume::parse`].
///
/// `0` on Unix, where no path element is ever consumed as a volume. The volume
/// is copied through `clean_with` untouched and is the floor the `..` scan can
/// never pop below — so `..` can neither delete a drive letter nor climb out of
/// a UNC share.
#[must_use]
pub fn volume_name_len(path: &str, regime: Regime) -> usize {
    Volume::parse(path, regime).byte_len()
}

/// How Windows filename canonicalisation reads one raw path element (the bytes
/// between two separators).
///
/// THE element classifier: the seal under either regime
/// and the runtime child-join parse all read an element through
/// [`ElementClass::of`], so the dot-and-space rule is stated once. Each consumer
/// decides which classes it refuses; the classes themselves never differ.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ElementClass {
    /// An empty element (a doubled or trailing separator).
    Empty,
    /// The exact `.` token.
    Current,
    /// The exact `..` token.
    Parent,
    /// Only dots and spaces with at least two dots, other than the exact `..`
    /// (`.. `, `. .`, `...`, ` .. `): Windows strips trailing dots and spaces,
    /// so it can name the parent directory.
    DisguisedParent,
    /// Only dots and spaces with at most one dot, other than the exact `.`
    /// (` `, `. `, ` . `): Windows strips it to the directory itself.
    DisguisedCurrent,
    /// Holds a `:` — a drive designator (`é:`, `1:`) or an alternate data
    /// stream (`a:b`).
    Colon,
    /// A reserved Win32 DOS device name (see [`is_dos_device`]).
    DosDevice,
    /// A name ending in a dot or a space (`a.`, `a `, `a.txt.`): Win32 strips
    /// the tail, so the element opens a different entry (`a`, `a.txt`).
    StrippedTail,
    /// Any other element.
    Name,
}

impl ElementClass {
    /// Classify one raw element.
    #[must_use]
    pub fn of(e: &[u8]) -> Self {
        match e {
            b"" => Self::Empty,
            b"." => Self::Current,
            b".." => Self::Parent,
            _ if e.iter().all(|&c| c == b'.' || c == b' ') => {
                // "at least two dots" without a full count (dodges the
                // naive-bytecount lint).
                if e.iter().filter(|&&c| c == b'.').nth(1).is_some() {
                    Self::DisguisedParent
                } else {
                    Self::DisguisedCurrent
                }
            }
            _ if e.contains(&b':') => Self::Colon,
            _ if is_dos_device(e) => Self::DosDevice,
            [.., b'.' | b' '] => Self::StrippedTail,
            _ => Self::Name,
        }
    }

    /// Classify every raw element of `path` split over the Windows separators.
    ///
    /// Windows honours both `\` and `/` at a syscall, so a scan that split on
    /// only one would let the other hide a disguised element. The exact `..`
    /// token classifies as [`Self::Parent`], never [`Self::DisguisedParent`]: a
    /// consumer refusing the disguise leaves an in-bounds `a\..\b` to the
    /// lexical `..` scan and [`escapes_root`].
    pub fn windows_elements(path: &str) -> impl Iterator<Item = Self> + '_ {
        path.as_bytes()
            .split(|&c| is_sep(c, Regime::Windows))
            .map(Self::of)
    }
}

/// Does the raw element `e` name a reserved Win32 DOS device?
///
/// Win32 opens a device, not a file, for `CON`, `PRN`, `AUX`, `NUL`,
/// `COM0`–`COM9`, `LPT0`–`LPT9`, the superscript-digit `COM¹²³` / `LPT¹²³`, and
/// `CONIN$` / `CONOUT$`, matched case-insensitively on the element's stem: the
/// text before its first `.` or `:`, with trailing spaces dropped. An extension
/// does not escape the device (`nul.txt`, `aux.tar.gz`) on older Windows
/// versions, so the check fails closed on every version. The case fold is the
/// NT one (see `device_fold`), not ASCII alone.
#[must_use]
pub fn is_dos_device(e: &[u8]) -> bool {
    let stem_end = e
        .iter()
        .position(|&c| c == b'.' || c == b':')
        .unwrap_or(e.len());
    let mut stem = e.get(..stem_end).unwrap_or(e);
    while let [rest @ .., b' '] = stem {
        stem = rest;
    }
    let named = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
        .iter()
        .any(|n| device_fold(stem).eq(n.bytes()));
    // `COM` / `LPT` hold no `I`, so the one non-ASCII fold never reaches them.
    let numbered = stem.split_at_checked(3).is_some_and(|(head, digit)| {
        (head.eq_ignore_ascii_case(b"COM") || head.eq_ignore_ascii_case(b"LPT"))
            // An ASCII digit, or the UTF-8 encoding of `¹` / `²` / `³`.
            && matches!(digit, [b'0'..=b'9'] | [0xC2, 0xB9 | 0xB2 | 0xB3])
    });
    named || numbered
}

/// Upcase a device-name stem the way NT compares device names.
///
/// NT matches a device name through its Unicode upcase table, not ASCII alone.
/// The only non-ASCII characters that upcase to an ASCII letter are `ı`
/// (U+0131, UTF-8 `C4 B1`) to `I` and `ſ` (U+017F) to `S`; no device name holds
/// an `S`, so `ı` is the one fold beyond ASCII. Every other byte is
/// ASCII-upcased (a no-op on a non-ASCII byte), so `İ` (U+0130), which upcases
/// to itself, never matches `I`.
fn device_fold(stem: &[u8]) -> impl Iterator<Item = u8> + '_ {
    let mut rest = stem;
    std::iter::from_fn(move || {
        let (unit, tail) = match rest {
            [0xC4, 0xB1, tail @ ..] => (b'I', tail),
            [c, tail @ ..] => (c.to_ascii_uppercase(), tail),
            [] => return None,
        };
        rest = tail;
        Some(unit)
    })
}

/// Why a child element can never be joined beneath a root.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ElementRefusal {
    /// The `..` parent token.
    Parent,
    /// A `:` — a drive designator (`é:`, `1:`) or an alternate data stream
    /// (`a:b`), either of which re-anchors or aliases the element.
    Colon,
    /// Only dots and spaces, other than the exact `.`/`..`: Windows strips
    /// trailing dots and spaces, so it names `.` or `..` (`" "`, `". "`,
    /// `".. "`, `"..."`).
    DotSpaceRun,
    /// A reserved DOS device name (`CON`, `nul.txt`, `COM1`): Win32 opens the
    /// device, not a file beneath the root.
    DosDevice,
    /// A name ending in a dot or a space (`a.`, `a `): Win32 strips the tail and
    /// opens another entry than the one named.
    StrippedTail,
}

impl ElementRefusal {
    /// The refusal reason a join reports after the child.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Parent => "contains a `..` element",
            Self::Colon => "contains a `:` (a drive designator or an alternate data stream)",
            Self::DotSpaceRun => {
                "contains an element made only of dots and spaces (Windows strips it to `.` or `..`)"
            }
            Self::DosDevice => {
                "contains a reserved Windows device name (`CON`, `NUL`, `COM1`, ...) that opens a device"
            }
            Self::StrippedTail => {
                "contains an element ending in a dot or a space (Windows strips it to another name)"
            }
        }
    }
}

/// One element of a child path, parsed once by [`ChildElement::parse`].
///
/// THE per-element verdict of every join beneath a root: `Path.under`,
/// `Path.absolute`, `File.walk` and every static-file mount read each element
/// through this parse. Under Windows it refuses the forms Win32 resolves to
/// something other than an entry of that name beneath the root: `..`, a `:` (a
/// drive or a stream), a dot/space run (`.` or `..` once stripped), a reserved
/// DOS device, and a name whose trailing dot or space Win32 strips. Under Unix
/// only `..` is refused; a device name, a `:`, a `\` or a trailing dot is a
/// legal name there.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChildElement {
    /// An empty element (a doubled separator), dropped by cleaning.
    Empty,
    /// The exact `.` token, dropped by cleaning.
    Current,
    /// A plain name that stays that name after the regime's canonicalisation.
    Name,
}

impl ChildElement {
    /// Classify one raw element under `regime`, or say why it may never be
    /// joined.
    ///
    /// # Errors
    ///
    /// The [`ElementRefusal`] naming the class of `e` the regime refuses.
    pub fn parse(e: &[u8], regime: Regime) -> Result<Self, ElementRefusal> {
        match regime {
            Regime::Unix => match e {
                b"" => Ok(Self::Empty),
                b"." => Ok(Self::Current),
                b".." => Err(ElementRefusal::Parent),
                _ => Ok(Self::Name),
            },
            Regime::Windows => match ElementClass::of(e) {
                ElementClass::Empty => Ok(Self::Empty),
                ElementClass::Current => Ok(Self::Current),
                ElementClass::Name => Ok(Self::Name),
                ElementClass::Parent => Err(ElementRefusal::Parent),
                ElementClass::Colon => Err(ElementRefusal::Colon),
                ElementClass::DisguisedParent | ElementClass::DisguisedCurrent => {
                    Err(ElementRefusal::DotSpaceRun)
                }
                ElementClass::DosDevice => Err(ElementRefusal::DosDevice),
                ElementClass::StrippedTail => Err(ElementRefusal::StrippedTail),
            },
        }
    }
}

/// Why a segment list is not a [`RelPath`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RelPathRefusal {
    /// No segment at all: the list names the root itself.
    Empty,
    /// A segment holds a NUL byte.
    Nul,
    /// A segment holds a byte the regime reads as a separator (a decoded `%2F`
    /// or `%5C`, or a raw `\` under Windows).
    Separator,
    /// A segment is empty or the exact `.`, so it names no entry.
    NotAName,
    /// A segment is an element the regime refuses to join.
    Element(ElementRefusal),
}

/// A relative path whose every segment is a plain name under one regime.
///
/// Built only by [`RelPath::from_segments`], so holding one proves that no
/// segment can climb, re-anchor, name a device or alias another entry under
/// that regime. The text joins the segments with the regime's separator, and
/// the path keeps the regime it was judged under, so a join can never re-read
/// it under another.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RelPath {
    /// The segments joined with the regime's separator; never empty.
    text: String,
    /// The byte offset where the last segment starts.
    last_start: usize,
    /// The regime every segment was judged under.
    regime: Regime,
}

impl RelPath {
    /// Parse `segs` (one entry name each, already decoded) under `regime`.
    ///
    /// Each segment is checked in order: a NUL byte, then a separator byte, then
    /// the [`ChildElement::parse`] verdict, which must be a name.
    ///
    /// # Errors
    ///
    /// The [`RelPathRefusal`] of the first refused segment, or `Empty` for no
    /// segment.
    pub fn from_segments<'s>(
        segs: impl IntoIterator<Item = &'s str>,
        regime: Regime,
    ) -> Result<Self, RelPathRefusal> {
        let mut text = String::new();
        let mut last_start = None;
        for seg in segs {
            let bytes = seg.as_bytes();
            if has_nul(seg) {
                return Err(RelPathRefusal::Nul);
            }
            if bytes.iter().any(|&b| is_sep(b, regime)) {
                return Err(RelPathRefusal::Separator);
            }
            match ChildElement::parse(bytes, regime) {
                Ok(ChildElement::Name) => {}
                Ok(ChildElement::Empty | ChildElement::Current) => {
                    return Err(RelPathRefusal::NotAName);
                }
                Err(why) => return Err(RelPathRefusal::Element(why)),
            }
            if last_start.is_some() {
                text.push(char::from(regime.separator()));
            }
            last_start = Some(text.len());
            text.push_str(seg);
        }
        last_start
            .map(|last_start| Self {
                text,
                last_start,
                regime,
            })
            .ok_or(RelPathRefusal::Empty)
    }

    /// The segments joined with the regime's separator.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The regime every segment was judged under.
    #[must_use]
    pub const fn regime(&self) -> Regime {
        self.regime
    }

    /// The last segment (the entry's own name).
    #[must_use]
    pub fn last(&self) -> &str {
        self.text.get(self.last_start..).unwrap_or("")
    }
}

/// Does a CLEANED path climb above its root?
///
/// Checks the path AFTER its volume
/// prefix (a drive/UNC volume is itself the root and can never be escaped). True
/// when that remainder's FIRST element is a `..` climb — the shape `clean_with`
/// leaves when a leading `..` could not be resolved away. A rooted remainder
/// (begins with a separator) can never escape: `clean_with` stops `..` at the
/// root. Separator-aware so a Windows `..\` escape is caught exactly as a Unix
/// `../` is.
///
/// # Two-layer defence
///
/// The primary check is the exact `..` token (the token `clean_with` scans and
/// counts). As independent defence-in-depth, the FIRST element is ALSO rejected
/// when it is a non-empty run made SOLELY of dots with length >= 2 (`..`, `...`,
/// `....`, …): so even if a future `clean_with` change ever produced a glued-dot
/// run — a single-point cleaner bug — this escape check would still catch it
/// without relying on the cleaner. The two layers reject independently.
///
/// This over-rejects a legitimate top-level filename made solely of dots
/// (e.g. `...` as a real filename). That is ACCEPTABLE — it fails closed, and
/// matches the Windows [`ElementClass::DisguisedParent`] refusal, which already
/// rejects the same all-dots family (Windows canonicalisation would alias it to `..`).
#[must_use]
pub fn escapes_root(cleaned: &str, regime: Regime) -> bool {
    let vol = volume_name_len(cleaned, regime);
    let rest = cleaned.get(vol..).unwrap_or("");
    let rb = rest.as_bytes();
    // The FIRST element of the remainder: bytes up to the first separator.
    let first = rb.split(|&c| is_sep(c, regime)).next().unwrap_or(&[]);
    // Layer 1: the exact `..` climb token.
    if first == b".." {
        return true;
    }
    // Layer 2 (defence-in-depth): any leading all-dots run of length >= 2. Even
    // a glued `...`/`....` a broken cleaner might emit is caught here, without
    // depending on the cleaner having split it back into discrete `..` tokens.
    let all_dots = first.iter().all(|&c| c == b'.');
    // Length >= 2: a second byte exists (guarded so a single `.` element, which
    // is not a climb, is never rejected).
    let two_or_more = first.get(1).is_some();
    all_dots && two_or_more
}

/// Faithful port of , driven by the chosen separator set.
///
/// `windows == true` selects the Windows separator set (`\` and `/`) plus
/// volume-prefix parsing; `false` is Unix (`/` only, no volume). Split so both
/// branches are unit-testable on any host — the Windows traversal defences are
/// proven on Linux CI, not left to a Windows-only build.
///
/// Lexically simplifies a path: collapses repeated separators, resolves `.`/`..`
/// elements, drops a trailing separator (except a root), normalises every input
/// separator to the platform separator, and preserves a leading Windows volume
/// prefix (drive / UNC) that the `..` scan can never pop below. Pure byte work —
/// multi-byte UTF-8 path elements are copied intact (their bytes are never a
/// separator or ASCII `.`), so the result is valid UTF-8.
#[must_use]
pub fn clean_with(path: &str, regime: Regime) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let b = path.as_bytes();
    let n = b.len();
    // Total byte access (no `[]` indexing — clippy::indexing_slicing / no-panic
    // gate). Out-of-range reads as `None`, never panics.
    let at = |i: usize| -> Option<u8> { b.get(i).copied() };
    let sep = regime.separator();

    let vol = volume_name_len(path, regime);
    let mut out: Vec<u8> = Vec::with_capacity(n + 1);
    // Copy the volume prefix through verbatim, normalising its separators (a UNC
    // `//server/share` becomes `\\server\share`). The `..` scan's floor,
    // `dotdot`, is anchored past it, so `..` can never delete or climb out of a
    // drive/UNC root.
    for i in 0..vol {
        match at(i) {
            Some(c) if is_sep(c, regime) => out.push(sep),
            Some(c) => out.push(c),
            None => {}
        }
    }
    // Width of the emitted volume prefix. The relative-part separator decisions
    // floor here (0 for a Unix/relative path), so consecutive leading `..`s stay
    // separated (`../..`, never a glued `....` that `escapes_root` would miss).
    let volw = out.len();
    let mut r = vol;
    // A path is rooted when the byte just after the volume is a separator. A
    // BARE drive (`C:` with no following separator) is drive-RELATIVE, not
    // rooted — so `C:..\x` keeps its leading `..` and is rejected as an escape,
    // never silently resolved against the drive root.
    let rooted = at(vol).is_some_and(|c| is_sep(c, regime));
    if rooted {
        out.push(sep);
        r += 1;
    }
    // `dotdot` is the index in `out` past which leading `..`s have been written
    // (for a relative path) or past the volume + root separator — popping never
    // crosses it. Anchored AFTER the root separator (if any) is written.
    let mut dotdot = out.len();
    while r < n {
        if at(r).is_some_and(|c| is_sep(c, regime)) {
            // empty path element → skip
            r += 1;
        } else if at(r) == Some(b'.')
            && (r + 1 == n || at(r + 1).is_some_and(|c| is_sep(c, regime)))
        {
            // `.` element → skip
            r += 1;
        } else if at(r) == Some(b'.')
            && at(r + 1) == Some(b'.')
            && (r + 2 == n || at(r + 2).is_some_and(|c| is_sep(c, regime)))
        {
            // `..` element → back up
            r += 2;
            if out.len() > dotdot {
                // pop the last element
                let mut w = out.len() - 1;
                while w > dotdot && out.get(w).copied().is_none_or(|c| c != sep) {
                    w -= 1;
                }
                out.truncate(w);
            } else if !rooted {
                // cannot back up → keep the `..`
                if out.len() > volw {
                    out.push(sep);
                }
                out.push(b'.');
                out.push(b'.');
                dotdot = out.len();
            }
        } else {
            // real path element → append a separator (if needed) then the element
            if (rooted && out.len() != dotdot) || (!rooted && out.len() != volw) {
                out.push(sep);
            }
            while r < n && !at(r).is_some_and(|c| is_sep(c, regime)) {
                if let Some(c) = at(r) {
                    out.push(c);
                }
                r += 1;
            }
        }
    }
    if out.is_empty() {
        return ".".to_string();
    }
    String::from_utf8(out).unwrap_or_else(|_| ".".to_string())
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    /// Seal `raw` as a literal, returning its (Unix, Windows) forms.
    fn literal(raw: &str) -> Result<(String, String), LiteralRefusal> {
        PathLitText::seal(raw).map(|t| {
            (
                t.sealed(Regime::Unix).to_owned(),
                t.sealed(Regime::Windows).to_owned(),
            )
        })
    }

    /// Does the literal `raw` refuse under `regime` for the class `class`?
    fn literal_refused(raw: &str, regime: Regime, class: fn(&SealRefusal) -> bool) -> bool {
        literal(raw).is_err_and(|r| r.regime == regime && class(&r.why))
    }

    const fn is_nul(r: &SealRefusal) -> bool {
        matches!(r, SealRefusal::Nul)
    }

    const fn is_escape(r: &SealRefusal) -> bool {
        matches!(r, SealRefusal::Escape { .. })
    }

    const fn is_disguise(r: &SealRefusal) -> bool {
        matches!(r, SealRefusal::DisguisedParent)
    }

    // ── seal: one text, two regimes ──────────────────────────────────────────

    #[test]
    fn seal_reads_backslash_per_regime() {
        // `\` is a filename byte under Unix and a separator under Windows, so
        // the same text names a different file per regime.
        assert_eq!(seal("a\\b/../c", Regime::Unix), Ok("c".to_string()));
        assert_eq!(seal("a\\b/../c", Regime::Windows), Ok("a\\c".to_string()));
    }

    #[test]
    fn seal_refuses_nul_under_both_regimes() {
        for regime in [Regime::Unix, Regime::Windows] {
            assert_eq!(
                seal("safe\0bad", regime),
                Err(SealRefusal::Nul),
                "{regime:?}"
            );
        }
    }

    #[test]
    fn seal_refuses_disguise_only_under_windows() {
        assert_eq!(
            seal(".. \\x", Regime::Windows),
            Err(SealRefusal::DisguisedParent)
        );
        assert!(seal(".. \\x", Regime::Unix).is_ok());
    }

    #[test]
    fn seal_escape_carries_the_cleaned_form() {
        assert_eq!(
            seal("a/../../etc", Regime::Unix),
            Err(SealRefusal::Escape {
                cleaned: "../etc".to_string()
            })
        );
    }

    #[test]
    fn host_regime_matches_the_build_target() {
        assert_eq!(HOST.is_windows(), cfg!(windows));
    }

    // ── PathLitText: accepted literals carry each regime's seal ──────────────

    #[test]
    fn literal_pair_is_each_regimes_seal() {
        for raw in [
            "src/Main.ipe",
            "/usr/share/data",
            "a/b/../c",
            "/a/../../b",
            "",
            "a\\b/../c",
            "a\\..\\b",
            "C:\\x\\..\\y",
            "\\\\srv\\shr\\x",
        ] {
            let pair = literal(raw);
            let expected =
                seal(raw, Regime::Unix).and_then(|u| seal(raw, Regime::Windows).map(|w| (u, w)));
            assert_eq!(pair.ok(), expected.ok(), "{raw:?}");
        }
    }

    #[test]
    fn literal_keeps_its_raw_text() {
        let text = PathLitText::seal("a/./b").ok();
        assert_eq!(text.as_ref().map(PathLitText::raw), Some("a/./b"));
    }

    #[test]
    fn literal_forms_differ_where_the_regimes_do() {
        assert_eq!(
            literal("a\\b/../c").ok(),
            Some(("c".to_string(), "a\\c".to_string()))
        );
        assert_eq!(
            literal("a\\..\\b").ok(),
            Some(("a\\..\\b".to_string(), "b".to_string()))
        );
    }

    #[test]
    fn literal_empty_cleans_to_dot() {
        assert_eq!(literal("").ok(), Some((".".to_string(), ".".to_string())));
    }

    // ── PathLitText: refused under the Unix regime ───────────────────────────

    #[test]
    fn literal_nul_refused() {
        assert!(literal_refused("safe\0bad", Regime::Unix, is_nul));
    }

    #[test]
    fn literal_leading_dotdot_refused() {
        assert!(literal_refused("../secret", Regime::Unix, is_escape));
        assert!(literal_refused("..", Regime::Unix, is_escape));
        // "a/../../etc" cleans to "../etc".
        assert!(literal_refused("a/../../etc", Regime::Unix, is_escape));
    }

    // ── PathLitText: refused ONLY under the Windows regime ───────────────────
    //    Each of these is a Unix-clean no-op (a `\` is a plain filename byte on
    //    Unix) yet a traversal on Windows, so the literal is refused on every
    //    host at compile time.

    #[test]
    fn literal_windows_only_refusals() {
        for raw in ["..\\secret", "C:..\\x", "a\\..\\..\\b"] {
            assert!(seal(raw, Regime::Unix).is_ok(), "{raw:?} is Unix-legal");
            assert!(literal_refused(raw, Regime::Windows, is_escape), "{raw:?}");
        }
        assert!(literal_refused(".. \\x", Regime::Windows, is_disguise));
    }

    #[test]
    fn literal_all_dots_refused_under_unix_first() {
        // `...` escapes under Unix's glued-dot layer before Windows is tried.
        assert!(literal_refused("...", Regime::Unix, is_escape));
    }

    // ── clean_with: Unix / Windows byte-for-byte spot checks ──────────────────

    #[test]
    fn clean_collapses_repeated_separators() {
        assert_eq!(clean_with("a//b///c", Regime::Unix), "a/b/c");
    }

    #[test]
    fn clean_empty_gives_dot() {
        assert_eq!(clean_with("", Regime::Unix), ".");
    }

    #[test]
    fn win_unc_root_not_escapable() {
        let cleaned = clean_with("\\\\server\\share\\..\\..\\x", Regime::Windows);
        assert_eq!(cleaned, "\\\\server\\share\\x");
        assert!(!escapes_root(&cleaned, Regime::Windows));
    }

    #[test]
    fn volume_name_len_recognises_drive_and_unc() {
        assert_eq!(volume_name_len("C:\\x", Regime::Windows), 2);
        assert_eq!(volume_name_len("\\\\srv\\shr\\x", Regime::Windows), 9);
        assert_eq!(volume_name_len("relative\\x", Regime::Windows), 0);
        assert_eq!(volume_name_len("C:\\x", Regime::Unix), 0);
    }

    #[test]
    fn volume_parse_follows_the_win32_drive_and_verbatim_unc_grammar() {
        // Any single-UTF-16-unit character before `:` is a drive, as in Win32.
        assert_eq!(volume_name_len("é:\\x", Regime::Windows), 3);
        assert_eq!(volume_name_len("1:x", Regime::Windows), 2);
        assert!(Volume::parse("é:", Regime::Windows).is_drive());
        // A non-BMP character is two UTF-16 units: never a drive.
        assert_eq!(volume_name_len("𝒳:x", Regime::Windows), 0);
        // A verbatim UNC root keeps its server and share inside the volume.
        assert_eq!(
            volume_name_len("\\\\?\\UNC\\srv\\shr\\x", Regime::Windows),
            15
        );
        assert!(Volume::parse("\\\\?\\UNC\\srv\\shr\\x", Regime::Windows).anchors());
        assert_eq!(
            clean_with("\\\\?\\UNC\\srv\\shr\\..\\..", Regime::Windows),
            "\\\\?\\UNC\\srv\\shr\\"
        );
        assert_eq!(volume_name_len("\\\\?\\C:\\x", Regime::Windows), 6);
        // A device-namespace UNC and an incomplete UNC name no anchoring volume.
        assert!(!Volume::parse("\\\\.\\UNC\\srv\\shr\\x", Regime::Windows).anchors());
        assert!(!Volume::parse("\\\\srv", Regime::Windows).anchors());
        assert!(!Volume::parse("\\x", Regime::Windows).anchors());
    }

    // ── ElementClass: the one element classifier ──────────────────────────────

    #[test]
    fn element_class_names_the_dot_space_aliases() {
        for (e, want) in [
            ("", ElementClass::Empty),
            (".", ElementClass::Current),
            ("..", ElementClass::Parent),
            (".. ", ElementClass::DisguisedParent),
            ("...", ElementClass::DisguisedParent),
            (". .", ElementClass::DisguisedParent),
            (" ", ElementClass::DisguisedCurrent),
            (". ", ElementClass::DisguisedCurrent),
            (" . ", ElementClass::DisguisedCurrent),
            ("a:b", ElementClass::Colon),
            ("CON", ElementClass::DosDevice),
            ("a.b", ElementClass::Name),
            ("..foo", ElementClass::Name),
        ] {
            assert_eq!(ElementClass::of(e.as_bytes()), want, "{e:?}");
        }
    }

    #[test]
    fn element_class_names_the_stripped_tail() {
        for (e, want) in [
            ("a.", ElementClass::StrippedTail),
            ("a ", ElementClass::StrippedTail),
            ("a.txt.", ElementClass::StrippedTail),
            ("CON.", ElementClass::DosDevice),
            ("a.b", ElementClass::Name),
        ] {
            assert_eq!(ElementClass::of(e.as_bytes()), want, "{e:?}");
        }
    }

    // ── RelPath: one typed relative path per regime ───────────────────────────

    #[test]
    fn rel_path_windows_regime_refuses_escaping_segments() {
        let element = RelPathRefusal::Element;
        let cases: [(&[&str], RelPathRefusal); 20] = [
            (&["a\\..\\x"], RelPathRefusal::Separator),
            (&["a\\COM1"], RelPathRefusal::Separator),
            (&["a/b"], RelPathRefusal::Separator),
            (&["C:x"], element(ElementRefusal::Colon)),
            (&["x:stream"], element(ElementRefusal::Colon)),
            (&["f.txt::$DATA"], element(ElementRefusal::Colon)),
            (&["CON"], element(ElementRefusal::DosDevice)),
            (&["nul.txt"], element(ElementRefusal::DosDevice)),
            (&["LPT9.log"], element(ElementRefusal::DosDevice)),
            (&["COM1"], element(ElementRefusal::DosDevice)),
            (&[".. "], element(ElementRefusal::DotSpaceRun)),
            (&["a."], element(ElementRefusal::StrippedTail)),
            (&["a "], element(ElementRefusal::StrippedTail)),
            (&["."], RelPathRefusal::NotAName),
            (&[""], RelPathRefusal::NotAName),
            (&[".."], element(ElementRefusal::Parent)),
            (&["a\0"], RelPathRefusal::Nul),
            (&[], RelPathRefusal::Empty),
            // A refused segment after an accepted one still refuses the whole.
            (&["ok", "CON"], element(ElementRefusal::DosDevice)),
            (&["ok", ""], RelPathRefusal::NotAName),
        ];
        for (segs, want) in cases {
            assert_eq!(
                RelPath::from_segments(segs.iter().copied(), Regime::Windows),
                Err(want),
                "{segs:?}"
            );
        }
        let ok = RelPath::from_segments(["a", "b.css"], Regime::Windows);
        assert_eq!(ok.as_ref().map(RelPath::as_str), Ok("a\\b.css"));
        assert_eq!(ok.as_ref().map(RelPath::last), Ok("b.css"));
        assert_eq!(ok.as_ref().map(RelPath::regime), Ok(Regime::Windows));
    }

    #[test]
    fn rel_path_unix_regime_accepts_legal_names() {
        for seg in [
            "a\\..\\x", "C:x", "x:stream", "CON", "nul.txt", "LPT9.log", ".. ", "a.",
        ] {
            let rel = RelPath::from_segments([seg], Regime::Unix);
            assert_eq!(rel.as_ref().map(RelPath::as_str), Ok(seg), "{seg:?}");
            assert_eq!(rel.as_ref().map(RelPath::last), Ok(seg), "{seg:?}");
        }
        for (seg, want) in [
            ("..", RelPathRefusal::Element(ElementRefusal::Parent)),
            (".", RelPathRefusal::NotAName),
            ("", RelPathRefusal::NotAName),
            ("a/b", RelPathRefusal::Separator),
            ("a\0", RelPathRefusal::Nul),
        ] {
            assert_eq!(
                RelPath::from_segments([seg], Regime::Unix),
                Err(want),
                "{seg:?}"
            );
        }
        let ok = RelPath::from_segments(["a", "b.css"], Regime::Unix);
        assert_eq!(ok.as_ref().map(RelPath::as_str), Ok("a/b.css"));
        assert_eq!(ok.as_ref().map(RelPath::last), Ok("b.css"));
    }

    #[test]
    fn dos_device_names_are_recognised_on_their_stem() {
        for e in [
            "CON",
            "con",
            "con.txt",
            "NUL ",
            "nul.txt",
            "COM1",
            "lpt9",
            "COM0",
            "COM\u{b9}",
            "LPT\u{b3}",
            "CONOUT$",
            "conin$",
            "aux.tar.gz",
            "PRN:",
            "AUX :x",
            "CON.",
            "CON .txt",
            "LPT0",
            "CONIN$",
            "lpt\u{b9}",
            "CON\u{131}N$",
            "con\u{131}n$",
            "CON\u{131}N$.txt",
        ] {
            assert!(is_dos_device(e.as_bytes()), "{e:?} is a device");
        }
        for e in [
            "CONSOLE",
            "COM10",
            "nulx",
            "xCON",
            "COM",
            "LPT",
            "COM\u{b4}",
            "CO",
            "",
            "COMa",
            "CON\u{131}N",
            "\u{131}CON",
        ] {
            assert!(!is_dos_device(e.as_bytes()), "{e:?} is a plain name");
        }
    }

    #[test]
    fn disguised_dotdot_is_exactly_the_disguised_parent_class() {
        // The seal and gate rule, stated independently of the classifier: an
        // all-dots-and-spaces element with at least two dots, other than `..`.
        let rule = |e: &[u8]| {
            e != b".."
                && e.iter().all(|&c| c == b'.' || c == b' ')
                && e.iter().filter(|&&c| c == b'.').nth(1).is_some()
        };
        for e in [
            "", ".", "..", "...", ".. ", " ", ". ", " .. ", "a", "a.", ". . .",
        ] {
            let disguised =
                ElementClass::windows_elements(e).any(|c| c == ElementClass::DisguisedParent);
            assert_eq!(disguised, rule(e.as_bytes()), "{e:?}");
        }
    }

    // ── escapes_root: two-layer defence against a leading all-dots element ─────

    #[test]
    fn escapes_root_rejects_exact_leading_dotdot() {
        // Layer 1: the exact `..` token, whole or as a leading element.
        for (regime, s) in [
            (Regime::Unix, ".."),
            (Regime::Unix, "../x"),
            (Regime::Windows, ".."),
            (Regime::Windows, "..\\x"),
        ] {
            assert!(
                escapes_root(s, regime),
                "leading `..` must escape ({s:?}, {regime:?})"
            );
        }
    }

    #[test]
    fn escapes_root_rejects_leading_glued_dots() {
        // Layer 2 (defence-in-depth): a leading all-dots run of length >= 2 is
        // rejected DIRECTLY, without the cleaner having to split it into `..`
        // tokens. These are the shapes a broken cleaner might glue together.
        for (regime, s) in [
            (Regime::Unix, "..."),
            (Regime::Unix, "...."),
            (Regime::Unix, ".../x"),
            (Regime::Unix, "..../x"),
            (Regime::Windows, "..."),
            (Regime::Windows, "....\\x"),
        ] {
            assert!(
                escapes_root(s, regime),
                "leading glued-dot run must escape ({s:?}, {regime:?})"
            );
        }
    }

    #[test]
    fn escapes_root_allows_in_bounds_and_dotted_names() {
        // A single `.` is not a climb; a legitimate in-bounds cleaned path does
        // not escape; and a name that has dots PLUS other chars (`..foo`) is a
        // real filename, not an all-dots run, so it is NOT rejected.
        for (regime, s) in [
            (Regime::Unix, "a/b"),
            (Regime::Unix, "."),
            (Regime::Unix, "..foo"),
            (Regime::Unix, "..foo/bar"),
            (Regime::Unix, "foo.."),
            (Regime::Windows, "..foo\\bar"),
        ] {
            assert!(
                !escapes_root(s, regime),
                "in-bounds / dotted-name path must NOT escape ({s:?}, {regime:?})"
            );
        }
        // `a/../b` resolves in-bounds and does not escape after cleaning.
        assert_eq!(clean_with("a/../b", Regime::Unix), "b");
        assert!(!escapes_root(
            &clean_with("a/../b", Regime::Unix),
            Regime::Unix
        ));
    }
}

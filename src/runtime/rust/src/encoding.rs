//! Encoding kernels for Ipe.Encoding — base64 / url-percent / hex.
//! Each fn backs an Ipê-side signature declared in `src/stdlib/Ipe/Encoding.ipe`.

use super::IpeResult;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

/// The set of bytes `urlEncode` percent-encodes, matching
/// `url.QueryEscape` (`encodeQueryComponent`): every byte is escaped EXCEPT
/// the ASCII alphanumerics and the four unreserved marks `-` `_` `.` `~`
/// (RFC 3986 §2.3). Space is handled separately (`%20` → `+`) below.
const QUERY: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

// ── Bytes-on-Rust convention ──────────────────────────────────────────────
//
// TEXT path: the `Encoding.*` kernels below treat their `String` argument as
// TEXT and go through its UTF-8 bytes (`s.as_bytes()` on encode,
// `String::from_utf8` on decode). This avoids silent truncation (`c as u8`
// dropping every codepoint > 255) and makes `decode(encode s) == Ok s` for
// every `String`. Non-ASCII goes through the correct UTF-8 bytes, not Latin-1.
//
// BYTE path: the binary pipelines (compression / email / websocket) operate on
// `Vec<u8>` end-to-end and need no String↔bytes bridge. The `Encoding.*` text
// path and the JWT path (jwt.rs, which owns its own raw-byte base64/hex) are
// unaffected.

/// The RFC grammar a URL component is decoded under.
///
/// The two grammars differ in exactly one byte: under `Form`
/// (`application/x-www-form-urlencoded`, a query key or value) a `+` means a
/// space; under `Path` (an RFC 3986 path segment) a `+` is a literal `+`. Both
/// decode `%XX` to the byte `0xXX` and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlGrammar {
    /// An RFC 3986 path segment: `+` is literal.
    Path,
    /// A form-encoded query key or value: `+` is a space.
    Form,
}

/// A byte position inside the raw (still-encoded) component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteOffset(usize);

impl ByteOffset {
    /// The position as a plain byte index into the raw component.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

/// A component length in bytes, kept apart from positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentLen(usize);

impl ComponentLen {
    /// The length as a plain byte count.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

/// The largest raw component `decode_component` accepts.
///
/// Equal to the server's default request-body ceiling, so a form field that
/// fits in a body is never refused for length, while no input can make the
/// decoder allocate without a bound.
pub const MAX_URL_COMPONENT_LEN: ComponentLen = ComponentLen(32 * 1024 * 1024);

/// Why a URL component was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeRefusal {
    /// A `%` at this raw offset is not followed by two hex digits.
    MalformedEscape { at: ByteOffset },
    /// The decoded bytes stop being UTF-8 at the escape or byte at this raw offset.
    InvalidUtf8 { at: ByteOffset },
    /// The raw component is longer than `cap` bytes.
    TooLong { cap: ComponentLen },
}

impl std::fmt::Display for DecodeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedEscape { at } => write!(
                f,
                "malformed percent-escape at byte {} (a '%' must be followed by two hex digits)",
                at.get()
            ),
            Self::InvalidUtf8 { at } => {
                write!(
                    f,
                    "decoded bytes are not valid UTF-8 (at byte {})",
                    at.get()
                )
            }
            Self::TooLong { cap } => write!(f, "component longer than {} bytes", cap.get()),
        }
    }
}

/// Decode one URL component under `grammar`, refusing anything malformed.
///
/// This is the single percent-decoder of the runtime: every URL component (a
/// path parameter, a query key or value, `Encoding.urlDecode`,
/// `Encoding.percentDecode`, `Http.parseQuery`, a database DSN part) and every
/// cookie name and value is decoded here. It is total and strict: a `%` not
/// followed by two hex digits, decoded bytes that are not UTF-8 (overlong forms
/// such as `%C0%AF` included), and a component longer than
/// `MAX_URL_COMPONENT_LEN` are each a typed refusal, never a lossy or
/// pass-through success.
///
/// # Errors
///
/// Returns the `DecodeRefusal` naming the first defect found.
pub fn decode_component(raw: &str, grammar: UrlGrammar) -> Result<String, DecodeRefusal> {
    decode_component_within(raw, grammar, MAX_URL_COMPONENT_LEN)
}

/// Split a URL path on its raw `/` separators, without decoding.
///
/// Surrounding `/` are trimmed first, so `/a/b/` and `/a/b` yield the same
/// segments and `/` yields none. This is the one split rule for a URL path:
/// [`decode_path_segments`] decodes each piece it yields, and a route pattern
/// is split by it too, so a pattern and a request path always agree on where
/// their segments lie.
///
/// # Errors
///
/// `DecodeRefusal::TooLong` for a path over `MAX_URL_COMPONENT_LEN` bytes.
pub fn raw_path_segments(path: &str) -> Result<Vec<&str>, DecodeRefusal> {
    if path.len() > MAX_URL_COMPONENT_LEN.get() {
        return Err(DecodeRefusal::TooLong {
            cap: MAX_URL_COMPONENT_LEN,
        });
    }
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    Ok(trimmed.split('/').collect())
}

/// Decode one raw path segment under the path grammar (`+` stays literal).
///
/// # Errors
///
/// The refusal of `decode_component` under [`UrlGrammar::Path`].
pub fn decode_path_segment(raw: &str) -> Result<String, DecodeRefusal> {
    decode_component(raw, UrlGrammar::Path)
}

/// Split a URL path on its raw `/` separators ([`raw_path_segments`]) and
/// decode each segment under the path grammar ([`decode_path_segment`]).
///
/// Splitting precedes decoding, so an encoded `%2F` stays inside its segment.
/// This is the one definition of a well-formed request path: the route matcher
/// reads its segments from here and the request gate refuses exactly what this
/// refuses.
///
/// # Errors
///
/// `DecodeRefusal::TooLong` for a path over `MAX_URL_COMPONENT_LEN` bytes, else
/// the refusal of the first segment that does not decode.
pub fn decode_path_segments(path: &str) -> Result<Vec<String>, DecodeRefusal> {
    raw_path_segments(path)?
        .into_iter()
        .map(decode_path_segment)
        .collect()
}

/// One path segment, percent-encoded so [`decode_path_segment`] reads back
/// exactly the text it was encoded from.
///
/// The RFC 3986 unreserved bytes (`A-Z a-z 0-9 - . _ ~`) stay plain and every
/// other byte becomes an uppercase `%HH`, so a `/` inside the text never
/// becomes a separator and a `+` is never read as a space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedSegment(String);

impl EncodedSegment {
    /// The encoded text, ready to join with `/`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why a text cannot be a path segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeRefusal {
    /// The empty text: the path split trims and collapses it away.
    Empty,
    /// `.` or `..`: a client normalizes it away before the path reaches a matcher.
    Dot,
    /// The encoded segment would be longer than `cap` bytes.
    TooLong { cap: ComponentLen },
}

impl std::fmt::Display for EncodeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "an empty text cannot be a path segment"),
            Self::Dot => write!(f, "`.` and `..` cannot be path segments"),
            Self::TooLong { cap } => write!(f, "encoded segment longer than {} bytes", cap.get()),
        }
    }
}

/// Encode `text` as one path segment, the inverse of [`decode_path_segment`].
///
/// # Errors
///
/// `Empty` and `Dot` for a text no segment can carry back unchanged, and
/// `TooLong` when the encoding exceeds `MAX_URL_COMPONENT_LEN`.
pub fn encode_path_segment(text: &str) -> Result<EncodedSegment, EncodeRefusal> {
    let too_long = EncodeRefusal::TooLong {
        cap: MAX_URL_COMPONENT_LEN,
    };
    match text {
        "" => return Err(EncodeRefusal::Empty),
        "." | ".." => return Err(EncodeRefusal::Dot),
        _ if text.len() > MAX_URL_COMPONENT_LEN.get() => return Err(too_long),
        _ => {}
    }
    let encoded = escape_segment(text);
    if encoded.len() > MAX_URL_COMPONENT_LEN.get() {
        return Err(too_long);
    }
    Ok(EncodedSegment(encoded))
}

/// The one path-segment alphabet: the unreserved bytes stay plain, every other
/// byte of the UTF-8 text becomes an uppercase `%HH`.
fn escape_segment(text: &str) -> String {
    utf8_percent_encode(text, QUERY).to_string()
}

/// A raw query string proven safe to copy byte-for-byte into a `Location`.
///
/// It holds only printable ASCII (`0x21..=0x7E`) other than `#`, every `%`
/// starts a two-hex-digit escape, and it is at most `MAX_URL_COMPONENT_LEN`
/// bytes, so it is a subset of what an HTTP header value admits and can never
/// end the query or reach the authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryText(String);

/// Why a raw query cannot be copied into a `Location`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryTextRefusal {
    /// A control byte, space, `#` or non-ASCII byte at this offset.
    Byte { at: ByteOffset },
    /// A `%` at this offset is not followed by two hex digits.
    MalformedEscape { at: ByteOffset },
    /// The query is longer than `cap` bytes.
    TooLong { cap: ComponentLen },
}

impl QueryText {
    /// Admit `raw` (the query without its leading `?`).
    ///
    /// # Errors
    ///
    /// The first byte outside the admitted alphabet, the first malformed
    /// escape, or `TooLong`.
    pub fn parse(raw: &str) -> Result<Self, QueryTextRefusal> {
        if raw.len() > MAX_URL_COMPONENT_LEN.get() {
            return Err(QueryTextRefusal::TooLong {
                cap: MAX_URL_COMPONENT_LEN,
            });
        }
        let bytes = raw.as_bytes();
        let hex_at = |k: usize| bytes.get(k).copied().and_then(hex_value).is_some();
        for (i, b) in bytes.iter().copied().enumerate() {
            match b {
                b'%' if !(hex_at(i.saturating_add(1)) && hex_at(i.saturating_add(2))) => {
                    return Err(QueryTextRefusal::MalformedEscape { at: ByteOffset(i) });
                }
                b'#' => return Err(QueryTextRefusal::Byte { at: ByteOffset(i) }),
                0x21..=0x7E => {}
                _ => return Err(QueryTextRefusal::Byte { at: ByteOffset(i) }),
            }
        }
        Ok(Self(raw.to_owned()))
    }

    /// The admitted query text, without a leading `?`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A mount base path, encoded once for a browser-visible `Location`: `""` for
/// the root base, else `/seg/...` with no trailing `/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedBase(String);

impl EncodedBase {
    /// Encode every segment of `base` with [`encode_path_segment`].
    ///
    /// # Errors
    ///
    /// The refusal of the first segment no path can carry back unchanged, or
    /// `TooLong` once the encoded base passes `MAX_URL_COMPONENT_LEN`.
    pub fn encode(base: &DecodedPath) -> Result<Self, EncodeRefusal> {
        let mut text = String::new();
        for segment in base.segments() {
            text.push('/');
            text.push_str(encode_path_segment(segment)?.as_str());
            if text.len() > MAX_URL_COMPONENT_LEN.get() {
                return Err(EncodeRefusal::TooLong {
                    cap: MAX_URL_COMPONENT_LEN,
                });
            }
        }
        Ok(Self(text))
    }

    /// The encoded base, `""` or `/seg/...`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A request path split on its raw `/` separators, each segment decoded once
/// under the RFC 3986 path grammar ([`decode_path_segments`]).
///
/// A request path is parsed into this once, at the request boundary; every
/// route matcher, param resolver and base-path strip then reads the decoded
/// segments and never re-parses the raw text. Splitting precedes decoding, so
/// an encoded `%2F` stays inside its segment and never becomes a separator.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DecodedPath(Vec<String>);

impl DecodedPath {
    /// Split `path` and decode every segment.
    ///
    /// # Errors
    ///
    /// The `DecodeRefusal` of the first segment that is not a well-formed,
    /// UTF-8 percent-encoding, or `TooLong` for an oversized path.
    pub fn parse(path: &str) -> Result<Self, DecodeRefusal> {
        decode_path_segments(path).map(Self)
    }

    /// The decoded segments, in path order.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.0
    }

    /// Is this the root path (`/`, no segments)?
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// The path below `base`, when `base`'s segments are a whole-segment
    /// prefix of this path's.
    ///
    /// The comparison is segment-wise on decoded segments, so a base `/app`
    /// strips `/app/x` to `/x` and `/app` to `/`, but never touches `/apple`
    /// (`None`): a base is a path prefix, not a string prefix.
    #[must_use]
    pub fn strip_base(&self, base: &Self) -> Option<Self> {
        self.0
            .strip_prefix(base.0.as_slice())
            .map(|rest| Self(rest.to_vec()))
    }
}

/// Whether a request path ends with a `/` after its last segment.
///
/// The root path has no last segment, so it is always `Absent`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrailingSlash {
    /// The path ends with its last segment (`/a`).
    Absent,
    /// The path ends with a `/` after its last segment (`/a/`).
    Present,
}

/// A request path parsed once: its decoded segments and its trailing slash.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RequestPath {
    decoded: DecodedPath,
    trailing: TrailingSlash,
}

impl RequestPath {
    /// Decode every segment of `raw` and record whether it ends with `/`.
    ///
    /// # Errors
    ///
    /// The refusal of [`DecodedPath::parse`].
    pub fn parse(raw: &str) -> Result<Self, DecodeRefusal> {
        let decoded = DecodedPath::parse(raw)?;
        let trailing = if !decoded.is_root() && raw.ends_with('/') {
            TrailingSlash::Present
        } else {
            TrailingSlash::Absent
        };
        Ok(Self { decoded, trailing })
    }

    /// The decoded segments.
    #[must_use]
    pub const fn decoded(&self) -> &DecodedPath {
        &self.decoded
    }

    /// Whether the path ends with `/` after its last segment.
    #[must_use]
    pub const fn trailing(&self) -> TrailingSlash {
        self.trailing
    }

    /// The one canonical spelling of this path ([`canonical_path`]).
    ///
    /// # Errors
    ///
    /// `TooLong` when the spelling exceeds `MAX_URL_COMPONENT_LEN`.
    pub fn canonical(&self) -> Result<CanonicalPath, EncodeRefusal> {
        canonical_path(&self.decoded, self.trailing)
    }

    /// This path below `base` ([`DecodedPath::strip_base`]), its trailing
    /// slash kept unless nothing is left below `base`.
    ///
    /// `None` too when the rest starts with an empty segment (`/billing//x`
    /// below `/billing`): no request path parses to a leading empty segment,
    /// so its spelling (`//x`) would read back as another path (`/x`), and
    /// the path has no place below `base`.
    #[must_use]
    pub fn below(&self, base: &DecodedPath) -> Option<Self> {
        let decoded = self.decoded.strip_base(base)?;
        if decoded.segments().first().is_some_and(String::is_empty) {
            return None;
        }
        let trailing = if decoded.is_root() {
            TrailingSlash::Absent
        } else {
            self.trailing
        };
        Some(Self { decoded, trailing })
    }
}

/// The canonical text of a request path; only [`canonical_path`] builds one.
///
/// Every route matcher compares two values of this type, so a raw spelling
/// and a canonical spelling of one path can never route apart.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CanonicalPath(String);

impl CanonicalPath {
    /// The canonical text: `/`, or `/seg/...` with each segment escaped.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One decoded segment spelled in the one segment alphabet, total over text.
///
/// The empty segment stays empty, and `.` and `..` become `%2E` and `%2E%2E`,
/// so the spelling reads back as the same segment and is never normalized
/// away by a client or a file service.
#[must_use]
pub fn canonical_segment(text: &str) -> String {
    match text {
        "." => "%2E".to_owned(),
        ".." => "%2E%2E".to_owned(),
        _ => escape_segment(text),
    }
}

/// The one encoder from decoded segments back to request-path text.
///
/// Each segment is spelled by [`canonical_segment`] and joined with `/`; the
/// root is `/`, empty inner segments are kept, and `trailing` adds a final
/// `/` after the last segment. It is injective and the left inverse of
/// [`RequestPath::parse`]: a `:`, `*`, `{` or `/` inside a segment is
/// escaped, so no decoded text can read as a separator or a router sigil.
///
/// # Errors
///
/// `TooLong` when the text would exceed `MAX_URL_COMPONENT_LEN`; each decoded
/// byte spells at most three bytes, and the growth is checked per segment.
pub fn canonical_path(
    path: &DecodedPath,
    trailing: TrailingSlash,
) -> Result<CanonicalPath, EncodeRefusal> {
    let too_long = EncodeRefusal::TooLong {
        cap: MAX_URL_COMPONENT_LEN,
    };
    if path.is_root() {
        return Ok(CanonicalPath("/".to_owned()));
    }
    let mut text = String::new();
    for segment in path.segments() {
        let spelled = canonical_segment(segment);
        let grown = text
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_add(spelled.len()))
            .ok_or(too_long)?;
        if grown > MAX_URL_COMPONENT_LEN.get() {
            return Err(too_long);
        }
        text.push('/');
        text.push_str(&spelled);
    }
    if trailing == TrailingSlash::Present {
        if text.len() >= MAX_URL_COMPONENT_LEN.get() {
            return Err(too_long);
        }
        text.push('/');
    }
    Ok(CanonicalPath(text))
}

/// The longest text [`MountBase::parse`] admits, in bytes.
pub const MAX_MOUNT_BASE_LEN: usize = 1024;

/// The longest text [`BundlePath::parse`] admits, in bytes.
pub const MAX_BUNDLE_PATH_LEN: usize = 1024;

/// Why a text is not a mount base.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountBaseRefusal {
    /// Longer than [`MAX_MOUNT_BASE_LEN`]; judged before any byte is scanned.
    TooLong { len: usize },
    /// A non-root base that does not start with `/` (`app`).
    NoLeadingSlash,
    /// A non-root base that ends with `/` (`/app/`); only the root is `/`.
    TrailingSlash,
    /// Two adjacent separators (`/a//b`).
    EmptySegment,
    /// A `.` or `..` segment, which a client normalizes away.
    DotSegment,
    /// A byte outside the unreserved set `[A-Za-z0-9-._~]` (`%`, `?`, `#`, `\` included).
    Reserved { byte: u8 },
}

impl std::fmt::Display for MountBaseRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong { len } => write!(
                f,
                "a mount base is at most {MAX_MOUNT_BASE_LEN} bytes (this one is {len})"
            ),
            Self::NoLeadingSlash => write!(f, "a mount base starts with `/`"),
            Self::TrailingSlash => write!(f, "a mount base other than `/` ends without `/`"),
            Self::EmptySegment => write!(f, "a mount base has no empty segment (`//`)"),
            Self::DotSegment => write!(f, "a mount base has no `.` or `..` segment"),
            Self::Reserved { byte } => write!(
                f,
                "a mount base holds only the bytes A-Z a-z 0-9 - . _ ~ and `/` (found byte 0x{byte:02X})"
            ),
        }
    }
}

/// Why a text is not a bundle-relative asset path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundlePathRefusal {
    /// The empty text.
    Empty,
    /// Longer than [`MAX_BUNDLE_PATH_LEN`]; judged before any byte is scanned.
    TooLong { len: usize },
    /// A leading `/`: the path is relative to the bundle root.
    LeadingSlash,
    /// An empty segment (`a//b`, or a trailing `/`).
    EmptySegment,
    /// A `.` or `..` segment.
    DotSegment,
    /// A byte outside `[A-Za-z0-9._-]`.
    Reserved { byte: u8 },
}

impl std::fmt::Display for BundlePathRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "a bundle path is not empty"),
            Self::TooLong { len } => write!(
                f,
                "a bundle path is at most {MAX_BUNDLE_PATH_LEN} bytes (this one is {len})"
            ),
            Self::LeadingSlash => write!(f, "a bundle path does not start with `/`"),
            Self::EmptySegment => write!(f, "a bundle path has no empty segment"),
            Self::DotSegment => write!(f, "a bundle path has no `.` or `..` segment"),
            Self::Reserved { byte } => write!(
                f,
                "a bundle path holds only the bytes A-Z a-z 0-9 . _ - and `/` (found byte 0x{byte:02X})"
            ),
        }
    }
}

/// Why one segment of a mount base or a bundle path is refused.
enum SegmentFault {
    Empty,
    Dot,
    Reserved(u8),
}

/// Judge one `/`-free segment against the byte set `admits`.
fn check_segment(segment: &str, admits: fn(u8) -> bool) -> Result<(), SegmentFault> {
    match segment {
        "" => Err(SegmentFault::Empty),
        "." | ".." => Err(SegmentFault::Dot),
        _ => segment
            .bytes()
            .find(|&b| !admits(b))
            .map_or(Ok(()), |b| Err(SegmentFault::Reserved(b))),
    }
}

/// The RFC 3986 unreserved bytes: the only bytes a mount base segment holds.
const fn is_mount_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// The bytes a bundle path segment holds.
const fn is_bundle_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_')
}

/// Where a bundle is served: the root, or one or more unreserved segments.
///
/// Every URL a shell loads is derived from this one value, so no site joins a
/// base string by hand. Its grammar is `""` or `/` for the root, else
/// (`/` segment)+ with each segment non-empty, not `.` or `..`, and made only
/// of the unreserved bytes `[A-Za-z0-9-._~]`; such a segment percent-encodes to
/// itself, so the raw, decoded and encoded forms are one text. There is no
/// `Default`: a site that means the root names [`MountBase::root`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MountBase {
    path: DecodedPath,
    prefix: String,
}

impl MountBase {
    /// The root base: the bundle is served at `/`.
    #[must_use]
    pub const fn root() -> Self {
        Self {
            path: DecodedPath(Vec::new()),
            prefix: String::new(),
        }
    }

    /// Parse `text` as a mount base: `""`, `/`, or (`/` segment)+.
    ///
    /// # Errors
    ///
    /// `TooLong` before any byte is scanned, then the first defect found:
    /// `NoLeadingSlash`, `TrailingSlash`, `EmptySegment`, `DotSegment` or
    /// `Reserved`.
    pub fn parse(text: &str) -> Result<Self, MountBaseRefusal> {
        if text.len() > MAX_MOUNT_BASE_LEN {
            return Err(MountBaseRefusal::TooLong { len: text.len() });
        }
        if text.is_empty() || text == "/" {
            return Ok(Self::root());
        }
        let Some(rest) = text.strip_prefix('/') else {
            return Err(MountBaseRefusal::NoLeadingSlash);
        };
        if rest.ends_with('/') {
            return Err(MountBaseRefusal::TrailingSlash);
        }
        let segments = rest
            .split('/')
            .map(|segment| {
                check_segment(segment, is_mount_byte)
                    .map(|()| segment.to_owned())
                    .map_err(|fault| match fault {
                        SegmentFault::Empty => MountBaseRefusal::EmptySegment,
                        SegmentFault::Dot => MountBaseRefusal::DotSegment,
                        SegmentFault::Reserved(byte) => MountBaseRefusal::Reserved { byte },
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            path: DecodedPath(segments),
            prefix: text.to_owned(),
        })
    }

    /// The base as a URL path prefix: `""` for the root, else `/seg/...`.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The directory URL the bundle is served at: `/` or `/seg/.../`.
    #[must_use]
    pub fn dir_url(&self) -> String {
        let mut url = String::with_capacity(self.prefix.len().saturating_add(1));
        url.push_str(&self.prefix);
        url.push('/');
        url
    }

    /// The base's decoded segments, for a segment-wise strip of a request path.
    #[must_use]
    pub const fn to_decoded(&self) -> &DecodedPath {
        &self.path
    }

    /// The base encoded for a browser-visible `Location`.
    ///
    /// Infallible: every segment is unreserved, so [`encode_path_segment`]
    /// leaves it unchanged, and the base is far below `MAX_URL_COMPONENT_LEN`.
    #[must_use]
    pub fn encoded(&self) -> EncodedBase {
        EncodedBase(self.prefix.clone())
    }

    /// The absolute URL path of the asset `path` in a bundle served at this base.
    #[must_use]
    pub fn url_of(&self, path: &BundlePath) -> String {
        let mut url = String::with_capacity(
            self.prefix
                .len()
                .saturating_add(path.rel().len())
                .saturating_add(1),
        );
        url.push_str(&self.prefix);
        url.push('/');
        url.push_str(path.rel());
        url
    }

    /// The base's segments, in path order.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.path.segments().iter().map(String::as_str)
    }

    /// The cookie-name suffix that tells this base's cookies from every other base's.
    #[must_use]
    pub fn cookie_suffix(&self) -> CookieSuffix {
        CookieSuffix::of(&self.prefix)
    }
}

/// The suffix a mount's runtime cookie names carry: `""` for the root.
///
/// Each byte of the base is kept when it is one of `[A-Za-z0-9-.~]`; `_`
/// becomes `_5F` and `/` becomes `_2F`. A `_` in the output always opens a
/// three-byte escape, so two distinct bases never share a suffix, and every
/// output byte is an RFC 6265 `token` byte.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CookieSuffix(String);

impl CookieSuffix {
    /// The suffix of the base text `prefix`, which [`MountBase::parse`] admitted.
    fn of(prefix: &str) -> Self {
        let mut out = String::with_capacity(prefix.len().saturating_mul(3));
        for ch in prefix.chars() {
            match ch {
                '_' => out.push_str("_5F"),
                '/' => out.push_str("_2F"),
                _ => out.push(ch),
            }
        }
        Self(out)
    }

    /// The suffix text, appended to a cookie base name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The scheme every [`ServerOrigin`] is written with.
const ORIGIN_SCHEME: &str = "https://";

/// The WebSocket scheme of a [`ServerOrigin`]'s authority.
const ORIGIN_WS_SCHEME: &str = "wss://";

/// The longest host a [`ServerOrigin`] admits, in bytes.
pub const MAX_ORIGIN_HOST_LEN: usize = 253;

/// The longest dot-separated label of a [`ServerOrigin`] host, in bytes.
pub const MAX_ORIGIN_LABEL_LEN: usize = 63;

/// The longest text [`ServerOrigin::parse`] scans: `https://`, a host and `:65535`.
pub const MAX_ORIGIN_LEN: usize = ORIGIN_SCHEME.len() + MAX_ORIGIN_HOST_LEN + 6;

/// The most origins a [`ServerOrigins`] list holds.
pub const MAX_SERVER_ORIGINS: usize = 16;

/// The port an `https` origin names when it writes none.
const DEFAULT_HTTPS_PORT: u16 = 443;

/// Why a text is not a server origin.
///
/// No variant carries the refused text, so a refusal is shown without
/// echoing author input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerOriginRefusal {
    /// Longer than [`MAX_ORIGIN_LEN`]; judged before any byte is scanned.
    TooLong { len: usize },
    /// The text does not open with `https://` (`http://`, `wss://`, `HTTPS://`).
    NotHttps,
    /// A `*` wildcard.
    Wildcard,
    /// A `@`: the authority names a user.
    Userinfo,
    /// A `/`, `?` or `#`: something follows the authority.
    AfterAuthority,
    /// An uppercase letter; a host is written in lowercase only.
    Uppercase,
    /// An IP literal: a `[` or `]`, or a host whose last label is a number.
    IpLiteral,
    /// A byte outside `[a-z0-9.-]` and the port's `:`, whitespace, controls
    /// and non-ASCII included.
    Byte { byte: u8 },
    /// No host between the scheme and the port.
    EmptyHost,
    /// The host is longer than [`MAX_ORIGIN_HOST_LEN`].
    HostTooLong { len: usize },
    /// Two adjacent dots, or a leading or trailing dot.
    EmptyLabel,
    /// A label longer than [`MAX_ORIGIN_LABEL_LEN`].
    LabelTooLong { len: usize },
    /// A label that starts or ends with `-`.
    LabelHyphen,
    /// A `:` with no digits after it, or a port holding a non-digit.
    PortMalformed,
    /// A port written with a leading zero (`:0443`).
    PortLeadingZero,
    /// A port outside `1..=65535`.
    PortOutOfRange,
    /// The port `443` written out; that origin is written without a port.
    DefaultPort,
}

impl std::fmt::Display for ServerOriginRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong { len } => write!(
                f,
                "a server origin is at most {MAX_ORIGIN_LEN} bytes (this one is {len})"
            ),
            Self::NotHttps => write!(f, "a server origin starts with `https://`"),
            Self::Wildcard => write!(f, "a server origin names one host, never a `*` wildcard"),
            Self::Userinfo => write!(f, "a server origin carries no user name (`@`)"),
            Self::AfterAuthority => write!(
                f,
                "a server origin ends after its host and port: no `/`, path, query or fragment"
            ),
            Self::Uppercase => write!(f, "a server origin host is written in lowercase"),
            Self::IpLiteral => write!(f, "a server origin names a host name, never an IP address"),
            Self::Byte { byte } => write!(
                f,
                "a server origin host holds only the bytes a-z 0-9 - and `.` (found byte 0x{byte:02X})"
            ),
            Self::EmptyHost => write!(f, "a server origin names a host"),
            Self::HostTooLong { len } => write!(
                f,
                "a server origin host is at most {MAX_ORIGIN_HOST_LEN} bytes (this one is {len})"
            ),
            Self::EmptyLabel => write!(
                f,
                "a server origin host has no empty label (`..`, or a leading or trailing `.`)"
            ),
            Self::LabelTooLong { len } => write!(
                f,
                "a server origin host label is at most {MAX_ORIGIN_LABEL_LEN} bytes (this one is {len})"
            ),
            Self::LabelHyphen => write!(
                f,
                "a server origin host label neither starts nor ends with `-`"
            ),
            Self::PortMalformed => write!(f, "a server origin port is digits after `:`"),
            Self::PortLeadingZero => write!(f, "a server origin port has no leading zero"),
            Self::PortOutOfRange => write!(f, "a server origin port is in 1..=65535"),
            Self::DefaultPort => {
                write!(f, "a server origin on port 443 is written without the port")
            }
        }
    }
}

/// One `https` origin a bundle may reach: `https://`, a host, an optional port.
///
/// Built only by [`ServerOrigin::parse`], so every value has one spelling: a
/// lowercase host name of dot-separated `[a-z0-9-]` labels that is not an IP
/// address, and a port other than `443` written without leading zeros. The
/// same value renders the `https` and `wss` forms, so no consumer joins a
/// scheme to author text.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerOrigin {
    authority: String,
}

impl ServerOrigin {
    /// Parse `text` as `https://`, a host, then an optional `:` port.
    ///
    /// # Errors
    ///
    /// `TooLong` before any byte is scanned, `NotHttps`, then the first
    /// refused byte (`Wildcard`, `Userinfo`, `AfterAuthority`, `Uppercase`,
    /// `IpLiteral`, `Byte`), then the port, then the host's shape.
    pub fn parse(text: &str) -> Result<Self, ServerOriginRefusal> {
        if text.len() > MAX_ORIGIN_LEN {
            return Err(ServerOriginRefusal::TooLong { len: text.len() });
        }
        let authority = text
            .strip_prefix(ORIGIN_SCHEME)
            .ok_or(ServerOriginRefusal::NotHttps)?;
        if let Some(byte) = authority.bytes().find(|&b| !is_origin_byte(b)) {
            return Err(origin_byte_refusal(byte));
        }
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        if let Some(port) = port {
            check_origin_port(port)?;
        }
        check_origin_host(host)?;
        Ok(Self {
            authority: authority.to_owned(),
        })
    }

    /// The host and the optional `:port`, without a scheme.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// The origin as `https://`, the host, then the optional `:port`.
    #[must_use]
    pub fn https(&self) -> String {
        let mut out = String::new();
        self.write_https(&mut out);
        out
    }

    /// The same authority under `wss://`, the origin's WebSocket form.
    #[must_use]
    pub fn wss(&self) -> String {
        let mut out = String::new();
        self.write_wss(&mut out);
        out
    }

    /// Append the `https` form to `out`.
    pub fn write_https(&self, out: &mut String) {
        out.push_str(ORIGIN_SCHEME);
        out.push_str(&self.authority);
    }

    /// Append the `wss` form to `out`.
    pub fn write_wss(&self, out: &mut String) {
        out.push_str(ORIGIN_WS_SCHEME);
        out.push_str(&self.authority);
    }
}

/// The bytes an origin's authority may hold: a host's, and the port's `:`.
const fn is_origin_byte(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b':')
}

/// The refusal a byte outside [`is_origin_byte`] earns.
const fn origin_byte_refusal(byte: u8) -> ServerOriginRefusal {
    match byte {
        b'*' => ServerOriginRefusal::Wildcard,
        b'@' => ServerOriginRefusal::Userinfo,
        b'/' | b'?' | b'#' => ServerOriginRefusal::AfterAuthority,
        b'A'..=b'Z' => ServerOriginRefusal::Uppercase,
        b'[' | b']' => ServerOriginRefusal::IpLiteral,
        _ => ServerOriginRefusal::Byte { byte },
    }
}

/// Judge the port text after the `:`.
fn check_origin_port(port: &str) -> Result<(), ServerOriginRefusal> {
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ServerOriginRefusal::PortMalformed);
    }
    if port.len() > 1 && port.starts_with('0') {
        return Err(ServerOriginRefusal::PortLeadingZero);
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(ServerOriginRefusal::PortOutOfRange),
        Ok(DEFAULT_HTTPS_PORT) => Err(ServerOriginRefusal::DefaultPort),
        Ok(_) => Ok(()),
    }
}

/// Judge the host: its length, each label, and that it is not a number.
fn check_origin_host(host: &str) -> Result<(), ServerOriginRefusal> {
    if host.is_empty() {
        return Err(ServerOriginRefusal::EmptyHost);
    }
    if host.len() > MAX_ORIGIN_HOST_LEN {
        return Err(ServerOriginRefusal::HostTooLong { len: host.len() });
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err(ServerOriginRefusal::EmptyLabel);
        }
        if label.len() > MAX_ORIGIN_LABEL_LEN {
            return Err(ServerOriginRefusal::LabelTooLong { len: label.len() });
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ServerOriginRefusal::LabelHyphen);
        }
    }
    if host.rsplit('.').next().is_some_and(is_numeric_label) {
        return Err(ServerOriginRefusal::IpLiteral);
    }
    Ok(())
}

/// Whether a URL parser reads `label`, as a host's last label, as an IPv4
/// number: decimal digits, or `0x` and hex digits.
fn is_numeric_label(label: &str) -> bool {
    label.strip_prefix("0x").map_or_else(
        || label.bytes().all(|b| b.is_ascii_digit()),
        |hex| hex.bytes().all(|b| b.is_ascii_hexdigit()),
    )
}

/// Why a list of origins is not a [`ServerOrigins`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerOriginsRefusal {
    /// More than [`MAX_SERVER_ORIGINS`] distinct origins.
    LimitExceeded,
}

impl std::fmt::Display for ServerOriginsRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LimitExceeded => write!(
                f,
                "a bundle names at most {MAX_SERVER_ORIGINS} server origins"
            ),
        }
    }
}

/// The origins a bundle may reach besides its own.
///
/// Sorted, distinct, and at most [`MAX_SERVER_ORIGINS`] long. The empty list
/// is an offline bundle. There is no `Default`: a site that means none names
/// [`ServerOrigins::none`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ServerOrigins(Vec<ServerOrigin>);

impl ServerOrigins {
    /// No server origin: the bundle reaches only its own origin.
    #[must_use]
    pub const fn none() -> Self {
        Self(Vec::new())
    }

    /// The sorted, de-duplicated list of `origins`.
    ///
    /// # Errors
    ///
    /// `LimitExceeded` as soon as more than [`MAX_SERVER_ORIGINS`] distinct
    /// origins are seen; nothing more of `origins` is read.
    pub fn new(
        origins: impl IntoIterator<Item = ServerOrigin>,
    ) -> Result<Self, ServerOriginsRefusal> {
        let mut set = std::collections::BTreeSet::new();
        for origin in origins {
            set.insert(origin);
            if set.len() > MAX_SERVER_ORIGINS {
                return Err(ServerOriginsRefusal::LimitExceeded);
            }
        }
        Ok(Self(set.into_iter().collect()))
    }

    /// The origins, in sorted order.
    pub fn origins(&self) -> impl Iterator<Item = &ServerOrigin> {
        self.0.iter()
    }

    /// The number of origins.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the list is empty: an offline bundle.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A bundle-relative asset path: `/`-separated segments of `[A-Za-z0-9._-]`.
///
/// It has no leading `/` and no empty, `.` or `..` segment. The asset's URL is
/// [`MountBase::url_of`] and its file is the bundle directory joined with
/// [`BundlePath::file_segments`]: one value, two projections, so neither is
/// re-derived from the other's text.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BundlePath(String);

impl BundlePath {
    /// Parse `text` as a bundle-relative asset path.
    ///
    /// # Errors
    ///
    /// `Empty`, then `TooLong` before any byte is scanned, then the first
    /// defect found: `LeadingSlash`, `EmptySegment`, `DotSegment` or
    /// `Reserved`.
    pub fn parse(text: &str) -> Result<Self, BundlePathRefusal> {
        if text.is_empty() {
            return Err(BundlePathRefusal::Empty);
        }
        if text.len() > MAX_BUNDLE_PATH_LEN {
            return Err(BundlePathRefusal::TooLong { len: text.len() });
        }
        if text.starts_with('/') {
            return Err(BundlePathRefusal::LeadingSlash);
        }
        for segment in text.split('/') {
            check_segment(segment, is_bundle_byte).map_err(|fault| match fault {
                SegmentFault::Empty => BundlePathRefusal::EmptySegment,
                SegmentFault::Dot => BundlePathRefusal::DotSegment,
                SegmentFault::Reserved(byte) => BundlePathRefusal::Reserved { byte },
            })?;
        }
        Ok(Self(text.to_owned()))
    }

    /// The path relative to the bundle root, with no leading `/`.
    #[must_use]
    pub fn rel(&self) -> &str {
        &self.0
    }

    /// The path's segments, in order, for a join under the bundle directory.
    pub fn file_segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// The content-addressed path of a `kind` asset whose digest begins `head`.
    ///
    /// Infallible: the stem is fixed and lowercase hex is in the segment grammar.
    #[must_use]
    pub fn hashed(kind: HashedAsset, head: [u8; 8]) -> Self {
        let stem = match kind {
            HashedAsset::Widget => "widget",
            HashedAsset::WidgetGlue => "widget-glue",
        };
        let hex: String = head.iter().map(|b| format!("{b:02x}")).collect();
        Self(format!("_ipe/{stem}.{hex}.js"))
    }
}

/// A content-addressed asset family served under `_ipe/`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashedAsset {
    /// An author widget module: `_ipe/widget.<hex16>.js`.
    Widget,
    /// The widget registration glue: `_ipe/widget-glue.<hex16>.js`.
    WidgetGlue,
}

/// A route parameter name, proven to match `[A-Za-z_][A-Za-z0-9_]*`.
///
/// This is the one parameter-name grammar of every route syntax in the
/// runtime: a `Web.route` pattern and an `Ipe.Server` path both admit their
/// names through [`ParamNames::admit`], so no route table can hold an empty,
/// non-identifier or repeated name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ParamName(String);

impl ParamName {
    /// Parse `raw` (the text after the `:` or `*` sigil) as a parameter name.
    ///
    /// # Errors
    ///
    /// `Empty` for an empty name, `NotIdentifier` at the first byte outside the
    /// identifier grammar (a leading digit included).
    pub fn parse(raw: &str) -> Result<Self, ParamNameRefusal> {
        let bytes = raw.as_bytes();
        let Some(&first) = bytes.first() else {
            return Err(ParamNameRefusal::Empty);
        };
        let bad = if first.is_ascii_alphabetic() || first == b'_' {
            bytes
                .iter()
                .position(|&b| !(b.is_ascii_alphanumeric() || b == b'_'))
        } else {
            Some(0)
        };
        bad.map_or_else(
            || Ok(Self(raw.to_owned())),
            |at| Err(ParamNameRefusal::NotIdentifier { at: ByteOffset(at) }),
        )
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ParamName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a route parameter name was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamNameRefusal {
    /// The sigil is not followed by a name.
    Empty,
    /// The byte at this offset of the name breaks `[A-Za-z_][A-Za-z0-9_]*`.
    NotIdentifier { at: ByteOffset },
    /// An earlier parameter of the same route already has this name.
    Duplicate { name: ParamName },
}

impl std::fmt::Display for ParamNameRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("a parameter has no name (write `:name`)"),
            Self::NotIdentifier { at } => write!(
                f,
                "a parameter name breaks `[A-Za-z_][A-Za-z0-9_]*` at byte {} of the name",
                at.get()
            ),
            Self::Duplicate { name } => write!(
                f,
                "parameter `{name}` appears twice (each parameter of a route needs its own name)"
            ),
        }
    }
}

/// The parameter names one route has admitted so far.
///
/// A route parser admits each name through one `ParamNames`, which parses it
/// ([`ParamName::parse`]) and refuses a repeat.
#[derive(Debug, Default)]
pub struct ParamNames(std::collections::HashSet<ParamName>);

impl ParamNames {
    /// Parse `raw` as a parameter name this route has not admitted yet.
    ///
    /// # Errors
    ///
    /// The refusal of [`ParamName::parse`], or `Duplicate` for a repeat.
    pub fn admit(&mut self, raw: &str) -> Result<ParamName, ParamNameRefusal> {
        let name = ParamName::parse(raw)?;
        if self.0.insert(name.clone()) {
            Ok(name)
        } else {
            Err(ParamNameRefusal::Duplicate { name })
        }
    }
}

/// One segment of a parsed route pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatternSeg {
    /// A literal segment, already decoded: it must equal the decoded request
    /// segment.
    Literal(String),
    /// A `:name` segment: captures the decoded request segment as `name`.
    Param(ParamName),
}

/// A route pattern parsed once, at registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutePattern(Vec<PatternSeg>);

impl RoutePattern {
    /// Split `pattern` by the request-path split rule and classify each raw
    /// segment by [`route_segment`], the one segment grammar `Ipe.Web` and
    /// `Ipe.Server` patterns share.
    ///
    /// # Errors
    ///
    /// The refusal of the first malformed segment, or `TooLong` for an
    /// oversized pattern.
    pub fn parse(pattern: &str) -> Result<Self, RouteSegmentRefusal> {
        let mut names = ParamNames::default();
        raw_path_segments(pattern)
            .map_err(RouteSegmentRefusal::Decode)?
            .into_iter()
            .map(|raw| route_segment(raw, &mut names))
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    /// The parsed segments, in pattern order.
    #[must_use]
    pub fn segments(&self) -> &[PatternSeg] {
        &self.0
    }

    /// The `:name`s of the parameter segments, in pattern order.
    pub fn param_names(&self) -> impl Iterator<Item = &str> {
        self.0.iter().filter_map(|seg| match seg {
            PatternSeg::Param(name) => Some(name.as_str()),
            PatternSeg::Literal(_) => None,
        })
    }
}

/// Classify one raw segment of a route pattern.
///
/// The one segment grammar of every route pattern: a segment led by `*` (a
/// catch-all) is refused; a segment led by `:` is a parameter whose name is
/// admitted by [`ParamNames::admit`]; any other segment holds no `:` or `*`
/// and is a literal decoded by the strict path-segment decoder.
///
/// # Errors
///
/// `CatchAll`, the parameter-name refusal, `MidSegmentSigil`, or the decode
/// refusal of the literal.
fn route_segment(raw: &str, names: &mut ParamNames) -> Result<PatternSeg, RouteSegmentRefusal> {
    if raw.starts_with('*') {
        return Err(RouteSegmentRefusal::CatchAll);
    }
    if let Some(name) = raw.strip_prefix(':') {
        return names
            .admit(name)
            .map(PatternSeg::Param)
            .map_err(RouteSegmentRefusal::ParamName);
    }
    if let Some(at) = raw.find([':', '*']) {
        return Err(RouteSegmentRefusal::MidSegmentSigil { at: ByteOffset(at) });
    }
    decode_path_segment(raw)
        .map(PatternSeg::Literal)
        .map_err(RouteSegmentRefusal::Decode)
}

/// Why one segment of a route pattern was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteSegmentRefusal {
    /// A literal segment (or the whole pattern) does not decode.
    Decode(DecodeRefusal),
    /// A `:name` segment's name is empty, not an identifier, or a repeat.
    ParamName(ParamNameRefusal),
    /// A segment is led by `*`: a catch-all, which no route serves.
    CatchAll,
    /// A literal segment holds a `:` or `*` after its first byte.
    MidSegmentSigil {
        /// Offset of the sigil within the segment.
        at: ByteOffset,
    },
}

impl std::fmt::Display for RouteSegmentRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(refusal) => write!(f, "{refusal}"),
            Self::ParamName(refusal) => write!(f, "{refusal}"),
            Self::CatchAll => f.write_str("a `*` catch-all segment is not served"),
            Self::MidSegmentSigil { at } => write!(
                f,
                "a `:` or `*` at byte {} of a segment is neither a parameter nor a literal",
                at.get()
            ),
        }
    }
}

/// A route pattern refused at registration: the pattern text and why it did
/// not parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutePatternRefusal {
    /// The pattern text as registered, scrubbed where the refusal is built.
    pub pattern: crate::system::RefusedText,
    /// Why its first malformed segment was refused.
    pub refusal: RouteSegmentRefusal,
}

impl std::fmt::Display for RoutePatternRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "route pattern `{}` is malformed: {}",
            self.pattern, self.refusal
        )
    }
}

/// The decoded values a route pattern's `:param` segments captured, in
/// pattern order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteParams(Vec<String>);

impl RouteParams {
    /// The `i`-th captured value, if the pattern has that many params.
    #[must_use]
    pub fn get(&self, i: usize) -> Option<&str> {
        self.0.get(i).map(String::as_str)
    }

    /// The captured values, for a route builder.
    #[must_use]
    pub fn into_segments(self) -> Vec<String> {
        self.0
    }
}

/// Match a decoded `path` against a parsed `pattern`: equal segment counts; a
/// `:name` segment captures the corresponding decoded segment; a literal
/// segment (decoded at registration) must equal it. Returns the captured
/// params in pattern order, or `None`.
#[must_use]
pub fn match_route(pattern: &RoutePattern, path: &DecodedPath) -> Option<RouteParams> {
    let pat = pattern.segments();
    let segs = path.segments();
    if pat.len() != segs.len() {
        return None;
    }
    let mut params = Vec::new();
    for (ps, us) in pat.iter().zip(segs) {
        match ps {
            PatternSeg::Param(_) => params.push(us.clone()),
            PatternSeg::Literal(lit) if lit == us => {}
            PatternSeg::Literal(_) => return None,
        }
    }
    Some(RouteParams(params))
}

/// An `Ipe.Server` route pattern parsed once, at listen: its segments, its
/// trailing slash, and the one router spelling rendered from them.
///
/// A literal segment is spelled by [`canonical_segment`], the same encoder
/// every request path is rewritten through, so a router compares two outputs
/// of one function and a raw spelling can never route apart from its
/// canonical one. A parameter is spelled by its position alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerPattern {
    pattern: RoutePattern,
    trailing: TrailingSlash,
    router_path: String,
}

/// The request methods one `Ipe.Server` handler serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointMethod {
    Connect,
    Delete,
    Get,
    Head,
    Options,
    Patch,
    Post,
    Put,
    Trace,
    /// Every method.
    Any,
}

impl EndpointMethod {
    /// The method a route names, `ANY` for every method, matched without
    /// regard to ASCII case; `None` for a name that is no HTTP method.
    ///
    /// This is the one method grammar: the server refuses a handler whose
    /// method it does not name at listen, and the compiler refuses a literal
    /// `Server.api` method it does not name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        const NAMES: [(&str, EndpointMethod); 10] = [
            ("CONNECT", EndpointMethod::Connect),
            ("DELETE", EndpointMethod::Delete),
            ("GET", EndpointMethod::Get),
            ("HEAD", EndpointMethod::Head),
            ("OPTIONS", EndpointMethod::Options),
            ("PATCH", EndpointMethod::Patch),
            ("POST", EndpointMethod::Post),
            ("PUT", EndpointMethod::Put),
            ("TRACE", EndpointMethod::Trace),
            ("ANY", EndpointMethod::Any),
        ];
        NAMES
            .iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(name))
            .map(|(_, method)| *method)
    }

    /// Whether some request method is served by both.
    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        self == other || self == Self::Any || other == Self::Any
    }
}

/// The most parameters one `Ipe.Server` route pattern holds.
///
/// A ceiling on the parameters of one pattern, so its captures and its
/// router spelling stay bounded whatever the pattern text holds; the compiler
/// refuses a literal pattern past it with the same ceiling.
pub const MAX_SERVER_PARAMS: usize = 25;

/// Why an `Ipe.Server` route pattern was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerPatternRefusal {
    /// The pattern does not start with `/`.
    NotAbsolute,
    /// A segment is refused by the route segment grammar.
    Segment(RouteSegmentRefusal),
    /// The pattern holds more than [`MAX_SERVER_PARAMS`] parameters.
    TooManyParams {
        /// The ceiling, [`MAX_SERVER_PARAMS`].
        cap: usize,
    },
    /// The router spelling would exceed [`MAX_URL_COMPONENT_LEN`].
    Render(EncodeRefusal),
}

impl std::fmt::Display for ServerPatternRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAbsolute => f.write_str("a route path starts with `/`"),
            Self::Segment(refusal) => write!(f, "{refusal}"),
            Self::TooManyParams { cap } => {
                write!(f, "a route path holds at most {cap} `:` parameters")
            }
            Self::Render(refusal) => write!(f, "{refusal}"),
        }
    }
}

impl ServerPattern {
    /// Parse `raw`: split by the request-path split rule, each segment
    /// classified by [`route_segment`], the grammar `Web.route` patterns
    /// share.
    ///
    /// # Errors
    ///
    /// `Segment` for an oversized pattern, `NotAbsolute` for one without a
    /// leading `/`, then the refusal of the first malformed segment, then
    /// `TooManyParams` past [`MAX_SERVER_PARAMS`] parameters, then `Render`
    /// when the router spelling is oversized.
    pub fn parse(raw: &str) -> Result<Self, ServerPatternRefusal> {
        let raws = raw_path_segments(raw).map_err(|refusal| {
            ServerPatternRefusal::Segment(RouteSegmentRefusal::Decode(refusal))
        })?;
        if !raw.starts_with('/') {
            return Err(ServerPatternRefusal::NotAbsolute);
        }
        let mut names = ParamNames::default();
        let segments = raws
            .into_iter()
            .map(|seg| route_segment(seg, &mut names))
            .collect::<Result<Vec<_>, _>>()
            .map_err(ServerPatternRefusal::Segment)?;
        let pattern = RoutePattern(segments);
        if pattern.param_names().count() > MAX_SERVER_PARAMS {
            return Err(ServerPatternRefusal::TooManyParams {
                cap: MAX_SERVER_PARAMS,
            });
        }
        let trailing = if !pattern.0.is_empty() && raw.ends_with('/') {
            TrailingSlash::Present
        } else {
            TrailingSlash::Absent
        };
        let router_path =
            router_spelling(&pattern, trailing).map_err(ServerPatternRefusal::Render)?;
        Ok(Self {
            pattern,
            trailing,
            router_path,
        })
    }

    /// The parsed segments.
    #[must_use]
    pub const fn pattern(&self) -> &RoutePattern {
        &self.pattern
    }

    /// Whether the pattern ends with `/` after its last segment.
    #[must_use]
    pub const fn trailing(&self) -> TrailingSlash {
        self.trailing
    }

    /// The decoded parameter values of `path` when this pattern matches it.
    ///
    /// A match needs the same trailing slash and, segment by segment, an equal
    /// decoded literal or any parameter value: the router's own rule, checked
    /// again on decoded segments rather than on spellings.
    #[must_use]
    pub fn captures(&self, path: &RequestPath) -> Option<RouteParams> {
        if self.trailing == path.trailing() {
            match_route(&self.pattern, path.decoded())
        } else {
            None
        }
    }

    /// The spelling the router registers: `/`, or `/seg/...` with each
    /// literal canonical and the parameter numbered `n` in pattern order
    /// spelled `{pn}`. A literal's `{`, `}`, `:` and `*` are percent-escaped
    /// by [`canonical_segment`], so no literal can read as a capture.
    ///
    /// Two patterns have one spelling exactly when they have one shape: the
    /// same trailing slash and, position by position, the same decoded
    /// literal or a parameter each. Parameter names never reach the router,
    /// so two patterns of one shape are one route, never a router conflict.
    #[must_use]
    pub fn router_path(&self) -> &str {
        &self.router_path
    }
}

/// The router spelling of `pattern` ([`ServerPattern::router_path`]).
fn router_spelling(
    pattern: &RoutePattern,
    trailing: TrailingSlash,
) -> Result<String, EncodeRefusal> {
    let too_long = EncodeRefusal::TooLong {
        cap: MAX_URL_COMPONENT_LEN,
    };
    if pattern.0.is_empty() {
        return Ok("/".to_owned());
    }
    let mut text = String::new();
    let mut push = |piece: &str| {
        let grown = text.len().checked_add(piece.len()).ok_or(too_long)?;
        if grown > MAX_URL_COMPONENT_LEN.get() {
            return Err(too_long);
        }
        text.push_str(piece);
        Ok(())
    };
    let mut ordinal: usize = 0;
    for seg in &pattern.0 {
        push("/")?;
        match seg {
            PatternSeg::Literal(lit) => push(&canonical_segment(lit))?,
            PatternSeg::Param(_) => {
                push("{p")?;
                push(&ordinal.to_string())?;
                push("}")?;
                ordinal = ordinal.saturating_add(1);
            }
        }
    }
    if trailing == TrailingSlash::Present {
        push("/")?;
    }
    Ok(text)
}

/// `decode_component` under an explicit length cap.
fn decode_component_within(
    raw: &str,
    grammar: UrlGrammar,
    cap: ComponentLen,
) -> Result<String, DecodeRefusal> {
    if raw.len() > cap.get() {
        return Err(DecodeRefusal::TooLong { cap });
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        match c {
            b'%' => {
                let hi = bytes.get(i + 1).copied().and_then(hex_value);
                let lo = bytes.get(i + 2).copied().and_then(hex_value);
                let (Some(hi), Some(lo)) = (hi, lo) else {
                    return Err(DecodeRefusal::MalformedEscape { at: ByteOffset(i) });
                };
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' if grammar == UrlGrammar::Form => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|e| DecodeRefusal::InvalidUtf8 {
        at: raw_offset_of(bytes, e.utf8_error().valid_up_to()),
    })
}

/// The value of one ASCII hex digit, or `None` for any other byte.
const fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// The raw offset that produced decoded byte number `decoded`.
///
/// Only called after a scan that accepted every escape, so each `%` starts a
/// three-byte escape yielding one decoded byte and every other byte yields one.
fn raw_offset_of(raw: &[u8], decoded: usize) -> ByteOffset {
    let mut i = 0;
    let mut produced = 0;
    while let Some(&c) = raw.get(i) {
        if produced == decoded {
            break;
        }
        i += if c == b'%' { 3 } else { 1 };
        produced += 1;
    }
    ByteOffset(i)
}

/// A number of query pairs, kept apart from lengths and positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairCount(usize);

impl PairCount {
    /// The count as a plain number.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

/// The most `key=value` pairs one query string may carry.
///
/// Bounds the map a single request or `Http.parseQuery` call can build.
pub const MAX_QUERY_PAIRS: PairCount = PairCount(1024);

/// Why a query string was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryRefusal {
    /// A key or value is not a well-formed form component.
    Component(DecodeRefusal),
    /// The query carries more than `cap` pairs.
    TooManyPairs { cap: PairCount },
}

impl std::fmt::Display for QueryRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Component(refusal) => refusal.fmt(f),
            Self::TooManyPairs { cap } => write!(f, "more than {} query pairs", cap.get()),
        }
    }
}

/// Decode a form-encoded query string (no leading `?`) into its pairs.
///
/// Pairs split on `&` (empty pairs skipped) and each on its first `=` (a bare
/// key maps to `""`); every key and value is decoded by `decode_component`
/// under the form grammar. A repeated key keeps its FIRST value. The whole
/// query is refused when any component is malformed or it carries more than
/// `MAX_QUERY_PAIRS` pairs — there is no partial, lenient result.
///
/// # Errors
///
/// Returns the `QueryRefusal` naming the first defect found.
pub fn decode_form_query(
    raw: &str,
) -> Result<std::collections::HashMap<String, String>, QueryRefusal> {
    decode_form_query_within(raw, MAX_QUERY_PAIRS)
}

/// `decode_form_query` under an explicit pair cap.
fn decode_form_query_within(
    raw: &str,
    cap: PairCount,
) -> Result<std::collections::HashMap<String, String>, QueryRefusal> {
    let mut out = std::collections::HashMap::new();
    let mut pairs = 0;
    for pair in raw.split('&').filter(|p| !p.is_empty()) {
        pairs += 1;
        if pairs > cap.get() {
            return Err(QueryRefusal::TooManyPairs { cap });
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = decode_component(k, UrlGrammar::Form).map_err(QueryRefusal::Component)?;
        let v = decode_component(v, UrlGrammar::Form).map_err(QueryRefusal::Component)?;
        out.entry(k).or_insert(v);
    }
    Ok(out)
}

/// Ipê `base64Encode : String -> String` — encodes the input's UTF-8 bytes.
#[must_use]
pub fn base64_encode(s: String) -> String {
    B64.encode(s.as_bytes())
}

/// Ipê `base64Decode : String -> Result Error String` — decodes to bytes, then
/// requires them to be valid UTF-8 (the Ipê `String` invariant), so
/// `base64Decode (base64Encode s) == Ok s` for every `String s`. Non-UTF-8
/// payloads surface as `Err` (raw-byte round-tripping lives on `Ipe.Bytes`).
#[must_use]
pub fn base64_decode<E: From<String>>(s: String) -> IpeResult<E, String> {
    match B64.decode(s.as_bytes()) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(text) => IpeResult::Ok(text),
            Err(e) => {
                IpeResult::Err(format!("base64: decoded bytes are not valid UTF-8: {e}").into())
            }
        },
        Err(e) => IpeResult::Err(format!("base64: {e}").into()),
    }
}

/// Ipê `urlEncode : String -> String` — space becomes `+` (not %20); the
/// ASCII unreserved set (`A-Za-z0-9` plus `-_.~`) is left verbatim; every
/// other byte is percent-encoded.
#[must_use]
pub fn url_encode(s: String) -> String {
    // QUERY encodes space as %20 (it is in the set); QueryEscape uses '+'.
    // '+' itself is not in the unreserved set, so it encodes to %2B first —
    // making the %20 → '+' swap unambiguous on decode.
    utf8_percent_encode(&s, QUERY)
        .to_string()
        .replace("%20", "+")
}

/// Ipê `urlDecode : String -> Result Error String` — `QueryUnescape`.
///
/// Decodes under the form grammar (`+` -> space, then `%XX`, so a literal
/// `%2B` round-trips back to `+`) through `decode_component`, so it fails
/// closed with `Err` on a malformed percent-escape, on decoded bytes that are
/// not valid UTF-8, and on an over-cap component.
#[must_use]
pub fn url_decode<E: From<String>>(s: String) -> IpeResult<E, String> {
    decode_kernel("urlDecode", &s, UrlGrammar::Form)
}

/// Ipê `percentDecode : String -> Result Error String` — the RFC 3986 §2.1
/// percent-decode for a URL path, a `file:`/`sqlite:` location, or any other
/// non-form component.
///
/// Decodes `%XX` under the path grammar (`+` stays a literal `+`) through
/// `decode_component`, refusing exactly what `url_decode` refuses.
#[must_use]
pub fn path_decode<E: From<String>>(s: String) -> IpeResult<E, String> {
    decode_kernel("percentDecode", &s, UrlGrammar::Path)
}

/// Run `decode_component` for the kernel `name`, rendering a refusal as its error.
fn decode_kernel<E: From<String>>(
    name: &str,
    s: &str,
    grammar: UrlGrammar,
) -> IpeResult<E, String> {
    match decode_component(s, grammar) {
        Ok(text) => IpeResult::Ok(text),
        Err(refusal) => IpeResult::Err(format!("{name}: {refusal}").into()),
    }
}

/// Ipê `hexEncode : String -> String` — encodes the input's UTF-8 bytes, so a
/// non-ASCII character becomes the hex of its UTF-8 encoding rather than a
/// codepoint truncated to one byte.
#[must_use]
pub fn encoding_hex_encode(s: String) -> String {
    hex::encode(s.as_bytes())
}

/// Ipê `hexDecode : String -> Result Error String` — decodes to bytes, then
/// requires them to be valid UTF-8 (the Ipê `String` invariant), so
/// `hexDecode (hexEncode s) == Ok s` for every `String s`. Non-UTF-8 payloads
/// (e.g. the hex of a raw digest) surface as `Err`; use `Ipe.Bytes.fromHex` to
/// round-trip arbitrary bytes. (jwt.rs owns its own `hex::decode` on raw
/// `&[u8]` and never routes through this kernel.)
#[must_use]
pub fn encoding_hex_decode<E: From<String>>(s: String) -> IpeResult<E, String> {
    match hex::decode(&s) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(text) => IpeResult::Ok(text),
            Err(e) => {
                IpeResult::Err(format!("hexDecode: decoded bytes are not valid UTF-8: {e}").into())
            }
        },
        Err(e) => IpeResult::Err(format!("hexDecode: {e}").into()),
    }
}

// ── Concrete (non-generic) wrappers for generated Ipê code ─────────────
//
// The generic `base64_decode<E>`, `url_decode<E>`, `path_decode<E>`,
// `encoding_hex_decode<E>` above
// use a flexible `E: From<String>` bound so the error type can be inferred from
// surrounding context. Generated Ipê code sets `IpeError = ipe_runtime::error::
// IpeError`, but Rust's type inference cannot pin `E` when
// the error arm discards the value (e.g. `Err _ ->` in a case expression).
// These concrete aliases pin `E = IpeError` up-front, eliminating the
// ambiguity without changing the runtime semantics — construction still
// routes through `IpeError: From<String>` (classified `Unexpected`).

/// Generated-code alias for `base64_decode` with `E = IpeError`.
#[must_use]
pub fn ipe_base64_decode(s: String) -> IpeResult<crate::error::IpeError, String> {
    base64_decode(s)
}

/// Generated-code alias for `url_decode` with `E = IpeError`.
#[must_use]
pub fn ipe_url_decode(s: String) -> IpeResult<crate::error::IpeError, String> {
    url_decode(s)
}

/// Generated-code alias for `path_decode` with `E = IpeError`.
#[must_use]
pub fn ipe_percent_decode(s: String) -> IpeResult<crate::error::IpeError, String> {
    path_decode(s)
}

/// Generated-code alias for `encoding_hex_decode` with `E = IpeError`.
#[must_use]
pub fn ipe_encoding_hex_decode(s: String) -> IpeResult<crate::error::IpeError, String> {
    encoding_hex_decode(s)
}

// ── Ipe.Bytes kernels ─────────────────────────────────────────
//
// `Bytes` is a distinct primitive (`Vec<u8>`); its kernel implementations
// (`bytes_to_hex`, `bytes_from_hex`, `bytes_to_base64`, `bytes_from_base64`,
// `bytes_to_string`, `bytes_length`) live in `bytes.rs`, not on a
// `type alias Bytes = String` convention. The `ipe_bytes` / `bytes_to_ipe`
// helpers below serve the Latin-1 byte-pipeline needs of `encoding.rs`,
// `compression.rs`, `ws_client.rs`, `server.rs`, and `email.rs`.

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Round-trip properties over ARBITRARY Unicode strings, co-located with the
    // kernels whose doc comments promise `decode (encode s) == Ok s` for every
    // `String s`. The example tests below pin a few fixed strings; these cover
    // the whole `String` domain — the regression class they guard is a decode
    // that stops being the exact inverse of its encoder for some input the
    // fixed cases miss. Concretely, a "fast" rewrite to Latin-1 byte coercion
    // (`c as u8`) truncates every codepoint > 255, so it would still pass the
    // ASCII fixed tests yet map distinct inputs to the same bytes and fail
    // round-trip for any non-Latin-1 char — the credential-confusion hazard the
    // `base64_no_collision_above_255` test warns about, promoted to a universal.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn base64_roundtrip_any_string(s in ".*") {
            let decoded: IpeResult<String, String> = base64_decode(base64_encode(s.clone()));
            prop_assert_eq!(decoded, IpeResult::Ok(s));
        }

        #[test]
        fn hex_roundtrip_any_string(s in ".*") {
            let decoded: IpeResult<String, String> =
                encoding_hex_decode(encoding_hex_encode(s.clone()));
            prop_assert_eq!(decoded, IpeResult::Ok(s));
        }

        // `url_encode`/`url_decode` must round-trip despite the `%20` -> `+`
        // rewrite: a literal `+`, space, and `%` are the ambiguous bytes, and the
        // encoder resolves them by emitting `%2B` for a literal `+` before the
        // swap. Any input that already contains `+`/space/`%` is exactly where a
        // naive `+`<->space swap breaks, so covering the full `String` domain
        // pins that the two are honest inverses.
        #[test]
        fn url_roundtrip_any_string(s in ".*") {
            let decoded: IpeResult<String, String> = url_decode(url_encode(s.clone()));
            prop_assert_eq!(decoded, IpeResult::Ok(s));
        }

        // Every text a segment can carry reads back unchanged, stays ONE segment
        // under the path split, and spells only unreserved bytes and `%HH`.
        #[test]
        fn path_segment_roundtrip_any_string(s in ".+") {
            prop_assume!(s != "." && s != "..");
            let encoded = encode_path_segment(&s);
            prop_assert!(encoded.is_ok(), "{s:?} must encode");
            let encoded = encoded.map(|e| e.as_str().to_owned()).unwrap_or_default();
            prop_assert_eq!(raw_path_segments(&encoded), Ok(vec![encoded.as_str()]));
            prop_assert_eq!(decode_path_segment(&encoded), Ok(s));
            prop_assert!(encoded.bytes().all(|b| b.is_ascii_alphanumeric()
                || matches!(b, b'-' | b'.' | b'_' | b'~' | b'%')));
        }
    }

    /// The canonical spelling of the decoded path with `segments` and `trailing`.
    fn canonical_of(segments: &[&str], trailing: TrailingSlash) -> String {
        let path = DecodedPath(segments.iter().map(|s| (*s).to_owned()).collect());
        canonical_path(&path, trailing).map_or_else(|_| String::new(), |c| c.as_str().to_owned())
    }

    /// Prove the refusals: every byte a router or a client could read as
    /// structure is escaped inside a segment, and nothing is dropped.
    #[test]
    fn canonical_path_escapes_every_structural_byte() {
        for (segment, want) in [
            ("a/b", "/a%2Fb"),
            ("a:b", "/a%3Ab"),
            (":id", "/%3Aid"),
            ("*rest", "/%2Arest"),
            ("100%", "/100%25"),
            ("a?b", "/a%3Fb"),
            ("a#b", "/a%23b"),
            ("{x}", "/%7Bx%7D"),
            ("a b", "/a%20b"),
            ("a\0b", "/a%00b"),
            ("caf\u{e9}", "/caf%C3%A9"),
            (".", "/%2E"),
            ("..", "/%2E%2E"),
            ("A-z_0.9~", "/A-z_0.9~"),
        ] {
            assert_eq!(
                canonical_of(&[segment], TrailingSlash::Absent),
                want,
                "{segment:?}"
            );
        }
        assert_eq!(canonical_of(&[], TrailingSlash::Absent), "/");
        assert_eq!(canonical_of(&[], TrailingSlash::Present), "/");
        assert_eq!(
            canonical_of(&["a", "", "b"], TrailingSlash::Absent),
            "/a//b"
        );
        assert_eq!(canonical_of(&["a"], TrailingSlash::Present), "/a/");
    }

    /// Prove the ceiling: a path whose spelling passes `MAX_URL_COMPONENT_LEN`
    /// is refused, while the last legal length is spelled.
    #[test]
    fn canonical_path_length_is_bounded() {
        let cap = MAX_URL_COMPONENT_LEN.get();
        let fits = DecodedPath(vec!["a".repeat(cap - 1)]);
        assert!(canonical_path(&fits, TrailingSlash::Absent).is_ok());
        assert!(matches!(
            canonical_path(&fits, TrailingSlash::Present),
            Err(EncodeRefusal::TooLong { .. })
        ));
        let grows = DecodedPath(vec!["/".repeat(cap / 3 + 1)]);
        assert!(matches!(
            canonical_path(&grows, TrailingSlash::Absent),
            Err(EncodeRefusal::TooLong { .. })
        ));
    }

    /// A raw path and its trailing slash parse into one `RequestPath`; the
    /// root never carries a trailing slash.
    #[test]
    fn request_path_records_the_trailing_slash() {
        let parsed = |raw: &str| RequestPath::parse(raw).map(|p| p.trailing());
        assert_eq!(parsed("/a"), Ok(TrailingSlash::Absent));
        assert_eq!(parsed("/a/"), Ok(TrailingSlash::Present));
        assert_eq!(parsed("/"), Ok(TrailingSlash::Absent));
        assert_eq!(parsed("//"), Ok(TrailingSlash::Absent));
        assert!(matches!(
            RequestPath::parse("/%zz"),
            Err(DecodeRefusal::MalformedEscape { .. })
        ));
    }

    /// A path re-based below a mount keeps its trailing slash, except at the
    /// mount itself; a path outside the mount has no place below it.
    #[test]
    fn request_path_below_a_base_is_segment_bounded() {
        let base = DecodedPath::parse("/billing").expect("base parses");
        let below = |raw: &str| {
            RequestPath::parse(raw)
                .ok()
                .and_then(|p| p.below(&base))
                .and_then(|p| p.canonical().ok())
                .map(|c| c.as_str().to_owned())
        };
        assert_eq!(below("/billing/x/"), Some("/x/".to_owned()));
        assert_eq!(below("/billing/x"), Some("/x".to_owned()));
        assert_eq!(below("/billing/"), Some("/".to_owned()));
        assert_eq!(below("/billing"), Some("/".to_owned()));
        assert_eq!(below("/%62illing/x"), Some("/x".to_owned()));
        assert_eq!(below("/billings/x"), None);
        assert_eq!(below("/other"), None);
        // A rest led by an empty segment has no spelling that reads back as
        // itself, so it has no place below the base.
        assert_eq!(below("/billing//x"), None);
        assert_eq!(below("/billing//"), Some("/".to_owned()));
        assert_eq!(below("/billing/x//y"), Some("/x//y".to_owned()));
    }

    /// Every path below a base spells as text that parses back to it: a
    /// mount hands its router exactly the path its parse names.
    #[test]
    fn request_path_below_a_base_reads_back_as_itself() {
        let base = DecodedPath::parse("/billing").expect("base parses");
        let mut checked = 0_usize;
        for raw in [
            "/billing//x",
            "/billing///x/",
            "/billing/x//y/",
            "/billing/%2E%2E",
            "/billing/a%2Fb",
            "/billing/",
        ] {
            let parsed = RequestPath::parse(raw).expect("the request parses");
            let Some(below) = parsed.below(&base) else {
                continue;
            };
            let spelled = below.canonical().expect("the rest spells");
            assert_eq!(
                RequestPath::parse(spelled.as_str()).as_ref(),
                Ok(&below),
                "{raw}"
            );
            checked = checked.saturating_add(1);
        }
        assert_eq!(checked, 4, "the paths with a place below the base");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        // The encoder is the left inverse of the parse, idempotent through a
        // parse, and injective over decoded paths.
        #[test]
        fn canonical_path_round_trips_and_is_injective(
            a in proptest::collection::vec(".*", 0..5),
            b in proptest::collection::vec(".*", 0..5),
            slash_a in proptest::bool::ANY,
            slash_b in proptest::bool::ANY,
        ) {
            let request = |segments: Vec<String>, slash: bool| -> Option<RequestPath> {
                let text = format!("/{}{}", segments.iter().map(|s| canonical_segment(s)).collect::<Vec<_>>().join("/"), if slash { "/" } else { "" });
                RequestPath::parse(&text).ok()
            };
            let (Some(p), Some(q)) = (request(a, slash_a), request(b, slash_b)) else {
                return Err(TestCaseError::fail("a canonical spelling must parse"));
            };
            let (Ok(cp), Ok(cq)) = (p.canonical(), q.canonical()) else {
                return Err(TestCaseError::fail("a short path must spell"));
            };
            prop_assert_eq!(RequestPath::parse(cp.as_str()), Ok(p.clone()));
            let again = RequestPath::parse(cp.as_str()).ok().and_then(|r| r.canonical().ok());
            prop_assert_eq!(again.as_ref(), Some(&cp));
            prop_assert_eq!(p == q, cp == cq);
        }
    }

    /// Prove the refusals: a text no segment carries back unchanged is refused,
    /// and the encoding is the canonical uppercase-hex form.
    #[test]
    fn path_segment_encoding_refusals_and_form() {
        assert_eq!(encode_path_segment(""), Err(EncodeRefusal::Empty));
        assert_eq!(encode_path_segment("."), Err(EncodeRefusal::Dot));
        assert_eq!(encode_path_segment(".."), Err(EncodeRefusal::Dot));
        let huge = "a".repeat(MAX_URL_COMPONENT_LEN.get() + 1);
        assert!(matches!(
            encode_path_segment(&huge),
            Err(EncodeRefusal::TooLong { .. })
        ));
        let grows = "/".repeat(MAX_URL_COMPONENT_LEN.get() / 3 + 1);
        assert!(matches!(
            encode_path_segment(&grows),
            Err(EncodeRefusal::TooLong { .. })
        ));
        for (text, want) in [
            ("...", "..."),
            ("a b", "a%20b"),
            ("a+b", "a%2Bb"),
            ("a/b", "a%2Fb"),
            ("caf\u{e9}", "caf%C3%A9"),
            ("%41", "%2541"),
            ("A-z_0.9~", "A-z_0.9~"),
        ] {
            assert_eq!(
                encode_path_segment(text).map(|e| e.as_str().to_owned()),
                Ok(want.to_owned()),
                "{text:?}"
            );
        }
    }

    #[test]
    fn test_base64_roundtrip() {
        let encoded = base64_encode("Hello, Ipe!".to_string());
        assert_eq!(encoded, "SGVsbG8sIElwZSE=");
        let decoded: IpeResult<String, String> = base64_decode(encoded);
        assert!(matches!(decoded, IpeResult::Ok(ref s) if s == "Hello, Ipe!"));
    }

    // non-ASCII goes through UTF-8 , not Latin-1 truncation.
    #[test]
    fn base64_hex_nonascii_utf8_bytes() {
        // base64/hex of "café" = UTF-8 bytes 63 61 66 C3 A9.
        assert_eq!(base64_encode("café".to_string()), "Y2Fmw6k=");
        assert_eq!(encoding_hex_encode("café".to_string()), "636166c3a9");
    }

    #[test]
    fn base64_hex_roundtrip_nonascii() {
        let b64: IpeResult<String, String> = base64_decode(base64_encode("café €".to_string()));
        assert!(matches!(b64, IpeResult::Ok(ref s) if s == "café €"));
        let hx: IpeResult<String, String> =
            encoding_hex_decode(encoding_hex_encode("café €".to_string()));
        assert!(matches!(hx, IpeResult::Ok(ref s) if s == "café €"));
    }

    // SECURITY: two strings that differ only ABOVE codepoint 255 must NOT
    // collide after base64 (a truncating `c as u8` would map both to 0xAC →
    // identical Basic-auth headers = credential confusion). '€'=U+20AC,
    // '¬'=U+00AC.
    #[test]
    fn base64_no_collision_above_255() {
        let euro = base64_encode("p€".to_string());
        let neg = base64_encode("p¬".to_string());
        assert_ne!(euro, neg, "distinct inputs must produce distinct base64");
    }

    #[test]
    fn test_base64_decode_invalid() {
        let bad: IpeResult<String, String> = base64_decode("not-valid-base64!@#".to_string());
        assert!(matches!(bad, IpeResult::Err(_)));
    }

    #[test]
    fn test_url_roundtrip() {
        let encoded = url_encode("hello world/foo?bar=baz&q=á".to_string());
        assert!(encoded.contains('+')); // space -> '+'
        assert!(!encoded.contains("%20"));
        assert!(encoded.contains("%2F")); // slash
        let decoded: IpeResult<String, String> = url_decode(encoded);
        assert!(matches!(decoded, IpeResult::Ok(ref s) if s == "hello world/foo?bar=baz&q=á"));
    }

    // A malformed percent-escape (a `%` not followed by two hex digits) is
    // turned away at the boundary — the documented fail-closed contract — by
    // both kernels, whatever their `+` grammar.
    #[test]
    fn test_url_decode_malformed_escape() {
        for bad in ["a%ZZb", "100%done", "trailing%", "%A", "%G0", "%2"] {
            let got: IpeResult<String, String> = url_decode(bad.to_string());
            assert!(
                matches!(got, IpeResult::Err(_)),
                "malformed percent-escape {bad:?} must be rejected"
            );
            let got: IpeResult<String, String> = path_decode(bad.to_string());
            assert!(
                matches!(got, IpeResult::Err(_)),
                "malformed percent-escape {bad:?} must be rejected by percentDecode"
            );
        }
    }

    // `percentDecode` keeps `+` literal; `urlDecode` reads it as a space.
    #[test]
    fn test_percent_decode_plus_is_literal() {
        let path: IpeResult<String, String> = path_decode("a+b%20c".to_string());
        assert!(matches!(path, IpeResult::Ok(ref s) if s == "a+b c"));
        let form: IpeResult<String, String> = url_decode("a+b%20c".to_string());
        assert!(matches!(form, IpeResult::Ok(ref s) if s == "a b c"));
    }

    // The non-UTF-8 decode path stays an `Err` (a well-formed `%C0` escape whose
    // decoded byte is not valid UTF-8).
    #[test]
    fn test_url_decode_invalid_utf8() {
        let bad: IpeResult<String, String> = url_decode("bad-utf8-%C0".to_string());
        assert!(matches!(bad, IpeResult::Err(_)));
    }

    // Well-formed input — plain ASCII, `%XX` (any case), and a literal `+` —
    // must NOT be rejected by the strict scan.
    #[test]
    fn test_url_decode_well_formed_ok() {
        let space: IpeResult<String, String> = url_decode("%20".to_string());
        assert!(matches!(space, IpeResult::Ok(ref s) if s == " "));
        let plus: IpeResult<String, String> = url_decode("a+b".to_string());
        assert!(matches!(plus, IpeResult::Ok(ref s) if s == "a b"));
        let slash_lower: IpeResult<String, String> = url_decode("%2f".to_string());
        assert!(matches!(slash_lower, IpeResult::Ok(ref s) if s == "/"));
        let slash_upper: IpeResult<String, String> = url_decode("%2F".to_string());
        assert!(matches!(slash_upper, IpeResult::Ok(ref s) if s == "/"));
        let ascii: IpeResult<String, String> = url_decode("plain-ascii_1.0~".to_string());
        assert!(matches!(ascii, IpeResult::Ok(ref s) if s == "plain-ascii_1.0~"));
    }

    // `percentDecode` is the RFC 3986 decode: a `+` stays literal (the form
    // decode's `+` -> space never applies), and `%2B` / `%20` decode to `+` /
    // space.
    #[test]
    fn test_percent_decode_keeps_plus() {
        let plus: IpeResult<String, String> = path_decode("a+b".to_string());
        assert!(matches!(plus, IpeResult::Ok(ref s) if s == "a+b"));
        let escaped_plus: IpeResult<String, String> = path_decode("%2B".to_string());
        assert!(matches!(escaped_plus, IpeResult::Ok(ref s) if s == "+"));
        let space: IpeResult<String, String> = path_decode("a%20b".to_string());
        assert!(matches!(space, IpeResult::Ok(ref s) if s == "a b"));
        let path: IpeResult<String, String> = path_decode("/t/a+b.db".to_string());
        assert!(matches!(path, IpeResult::Ok(ref s) if s == "/t/a+b.db"));
    }

    // `percentDecode` refuses every malformed escape `urlDecode` refuses, and a
    // non-UTF-8 decode.
    #[test]
    fn test_percent_decode_refusals() {
        for bad in [
            "a%ZZb",
            "%zz",
            "100%done",
            "trailing%",
            "%A",
            "%2",
            "%G0",
            "bad-utf8-%C0",
        ] {
            let got: IpeResult<String, String> = path_decode(bad.to_string());
            assert!(
                matches!(got, IpeResult::Err(ref e) if e.starts_with("percentDecode: ")),
                "malformed input {bad:?} must be rejected by percentDecode"
            );
        }
    }

    #[test]
    fn test_hex_roundtrip() {
        let encoded = encoding_hex_encode("Hi!".to_string());
        assert_eq!(encoded, "486921");
        let decoded: IpeResult<String, String> = encoding_hex_decode(encoded);
        assert!(matches!(decoded, IpeResult::Ok(ref s) if s == "Hi!"));
    }

    #[test]
    fn test_encoding_hex_decode_invalid() {
        let bad: IpeResult<String, String> = encoding_hex_decode("zz".to_string());
        assert!(matches!(bad, IpeResult::Err(_)));
        let odd: IpeResult<String, String> = encoding_hex_decode("a".to_string());
        assert!(matches!(odd, IpeResult::Err(_)));
    }

    // ── decode_component: the single strict core ──────────────────────────

    fn refusal(raw: &str, grammar: UrlGrammar) -> Option<DecodeRefusal> {
        decode_component(raw, grammar).err()
    }

    #[test]
    fn decode_component_refuses_malformed_escape() {
        for grammar in [UrlGrammar::Path, UrlGrammar::Form] {
            assert_eq!(
                refusal("a%zzb", grammar),
                Some(DecodeRefusal::MalformedEscape { at: ByteOffset(1) })
            );
            assert_eq!(
                refusal("trailing%", grammar),
                Some(DecodeRefusal::MalformedEscape { at: ByteOffset(8) })
            );
            assert_eq!(
                refusal("%A", grammar),
                Some(DecodeRefusal::MalformedEscape { at: ByteOffset(0) })
            );
            assert_eq!(
                refusal("ok%20and%ZZbad", grammar),
                Some(DecodeRefusal::MalformedEscape { at: ByteOffset(8) })
            );
            // A `%` before a multi-byte char is malformed, not a boundary panic.
            assert_eq!(
                refusal("%é", grammar),
                Some(DecodeRefusal::MalformedEscape { at: ByteOffset(0) })
            );
        }
    }

    #[test]
    fn decode_component_refuses_invalid_utf8() {
        for grammar in [UrlGrammar::Path, UrlGrammar::Form] {
            // A truncated two-byte sequence.
            assert_eq!(
                refusal("%C3", grammar),
                Some(DecodeRefusal::InvalidUtf8 { at: ByteOffset(0) })
            );
            // A lead byte followed by a non-continuation byte.
            assert_eq!(
                refusal("x%C3%28", grammar),
                Some(DecodeRefusal::InvalidUtf8 { at: ByteOffset(1) })
            );
            // The overlong encoding of `/` — the classic path-traversal smuggle.
            assert_eq!(
                refusal("a%C0%AF", grammar),
                Some(DecodeRefusal::InvalidUtf8 { at: ByteOffset(1) })
            );
        }
    }

    #[test]
    fn decode_component_plus_depends_on_grammar() {
        assert_eq!(
            decode_component("a+b", UrlGrammar::Path),
            Ok("a+b".to_string())
        );
        assert_eq!(
            decode_component("a+b", UrlGrammar::Form),
            Ok("a b".to_string())
        );
        // `%2B` is a literal `+` under both grammars, so it round-trips.
        for grammar in [UrlGrammar::Path, UrlGrammar::Form] {
            assert_eq!(decode_component("a%2Bb", grammar), Ok("a+b".to_string()));
            assert_eq!(
                decode_component("caf%C3%A9", grammar),
                Ok("café".to_string())
            );
        }
    }

    #[test]
    fn decode_component_length_cap() {
        let cap = ComponentLen(8);
        assert_eq!(
            decode_component_within("aaaaaaaa", UrlGrammar::Path, cap),
            Ok("aaaaaaaa".to_string())
        );
        assert_eq!(
            decode_component_within("aaaaaaaaa", UrlGrammar::Path, cap),
            Err(DecodeRefusal::TooLong { cap })
        );
        // The shipped cap: one byte past it is refused before any decoding.
        let past = "a".repeat(MAX_URL_COMPONENT_LEN.get() + 1);
        assert_eq!(
            refusal(&past, UrlGrammar::Form),
            Some(DecodeRefusal::TooLong {
                cap: MAX_URL_COMPONENT_LEN
            })
        );
    }

    // ── decode_form_query: the one query splitter ─────────────────────────

    #[test]
    fn decode_form_query_first_wins_and_bare_keys() {
        let decoded = decode_form_query("a=1&b=two+words%21&a=ignored&flag&&c=x=y");
        assert!(decoded.is_ok(), "a well-formed query must decode");
        let Ok(q) = decoded else { return };
        assert_eq!(q.get("a").map(String::as_str), Some("1"));
        assert_eq!(q.get("b").map(String::as_str), Some("two words!"));
        assert_eq!(q.get("flag").map(String::as_str), Some(""));
        assert_eq!(q.get("c").map(String::as_str), Some("x=y"));
        assert_eq!(q.len(), 4);
        assert_eq!(decode_form_query(""), Ok(std::collections::HashMap::new()));
    }

    #[test]
    fn decode_form_query_refuses_any_malformed_component() {
        for bad in ["a=%zz", "%zz=1", "a=1&b=%C3", "a=1&a=%zz", "q=100%"] {
            assert!(
                matches!(decode_form_query(bad), Err(QueryRefusal::Component(_))),
                "{bad:?} must be refused whole"
            );
        }
    }

    #[test]
    fn decode_form_query_pair_cap() {
        let cap = PairCount(3);
        assert!(decode_form_query_within("a=1&b=2&c=3", cap).is_ok());
        // Empty pairs do not count toward the cap.
        assert!(decode_form_query_within("a=1&&b=2&c=3&", cap).is_ok());
        assert_eq!(
            decode_form_query_within("a=1&b=2&c=3&d=4", cap),
            Err(QueryRefusal::TooManyPairs { cap })
        );
        // The shipped cap: exactly at it decodes, one past it is refused.
        let at: Vec<String> = (0..MAX_QUERY_PAIRS.get())
            .map(|i| format!("k{i}=v"))
            .collect();
        assert!(decode_form_query(&at.join("&")).is_ok());
        let past = format!("{}&extra=1", at.join("&"));
        assert_eq!(
            decode_form_query(&past),
            Err(QueryRefusal::TooManyPairs {
                cap: MAX_QUERY_PAIRS
            })
        );
    }

    #[test]
    fn raw_path_segments_trims_and_splits_without_decoding() {
        assert_eq!(raw_path_segments("/"), Ok(vec![]));
        assert_eq!(raw_path_segments(""), Ok(vec![]));
        assert_eq!(raw_path_segments("//"), Ok(vec![]));
        assert_eq!(raw_path_segments("/a/b/"), Ok(vec!["a", "b"]));
        assert_eq!(raw_path_segments("/a%2Fb"), Ok(vec!["a%2Fb"]));
        let long = "a".repeat(MAX_URL_COMPONENT_LEN.get() + 1);
        assert_eq!(
            raw_path_segments(&long),
            Err(DecodeRefusal::TooLong {
                cap: MAX_URL_COMPONENT_LEN
            })
        );
    }

    #[test]
    fn decoded_path_root_and_segments() {
        let root = DecodedPath::parse("/").unwrap();
        assert!(root.is_root());
        assert!(root.segments().is_empty());
        let p = DecodedPath::parse("/a%2Fb/c").unwrap();
        assert!(!p.is_root());
        assert_eq!(p.segments(), ["a/b".to_string(), "c".to_string()]);
        assert!(DecodedPath::parse("/a/%zz").is_err());
    }

    /// A base is a whole-segment prefix: `/app` never strips `/apple`.
    #[test]
    fn strip_base_is_segment_bounded() {
        let dp = |p: &str| DecodedPath::parse(p).unwrap();
        let base = dp("/app");
        assert_eq!(dp("/apple").strip_base(&base), None);
        assert_eq!(dp("/apple/x").strip_base(&base), None);
        assert_eq!(dp("/app/x").strip_base(&base), Some(dp("/x")));
        let at_base = dp("/app").strip_base(&base);
        assert_eq!(at_base, Some(dp("/")));
        assert!(at_base.is_some_and(|p| p.is_root()));
        assert_eq!(dp("/other/app").strip_base(&base), None);
        // Segments compare decoded: `%61pp` is the segment `app`.
        assert_eq!(dp("/%61pp/x").strip_base(&base), Some(dp("/x")));
        // The root base strips nothing.
        assert_eq!(dp("/app/x").strip_base(&dp("/")), Some(dp("/app/x")));
    }

    /// The one parameter-name grammar admits exactly `[A-Za-z_][A-Za-z0-9_]*`
    /// and refuses a repeat within one route.
    #[test]
    fn param_name_grammar_and_uniqueness() {
        for ok in ["a", "_", "_x", "A", "a_Z9", "snake_case_1"] {
            assert!(
                ParamName::parse(ok).is_ok_and(|n| n.as_str() == ok && n.to_string() == ok),
                "{ok} must be admitted verbatim"
            );
        }
        assert_eq!(ParamName::parse(""), Err(ParamNameRefusal::Empty));
        for (bad, at) in [
            ("1a", 0),
            ("-", 0),
            ("\u{e9}", 0),
            ("a\u{e9}", 1),
            ("a-b", 1),
            ("a_Z9 ", 4),
        ] {
            assert_eq!(
                ParamName::parse(bad),
                Err(ParamNameRefusal::NotIdentifier { at: ByteOffset(at) }),
                "{bad}"
            );
        }
        let mut names = ParamNames::default();
        assert!(names.admit("id").is_ok());
        assert!(names.admit("Id").is_ok());
        assert!(matches!(
            names.admit("id"),
            Err(ParamNameRefusal::Duplicate { name }) if name.as_str() == "id"
        ));
        assert!(matches!(
            names.admit("9"),
            Err(ParamNameRefusal::NotIdentifier { .. })
        ));
    }

    /// Every malformed mount base is refused with its own variant; each
    /// refusal has a well-formed neighbour that is admitted.
    #[test]
    fn mount_base_refuses_each_variant() {
        for ok in ["/app", "/a-b/c.d~e", "/A9/_z", "/a/b/c", "/.well"] {
            assert!(
                MountBase::parse(ok).is_ok_and(|b| b.prefix() == ok),
                "{ok} must be admitted verbatim"
            );
        }
        for (bad, want) in [
            ("app", MountBaseRefusal::NoLeadingSlash),
            ("a/b", MountBaseRefusal::NoLeadingSlash),
            ("/app/", MountBaseRefusal::TrailingSlash),
            ("//", MountBaseRefusal::TrailingSlash),
            ("/a//b", MountBaseRefusal::EmptySegment),
            ("/..", MountBaseRefusal::DotSegment),
            ("/.", MountBaseRefusal::DotSegment),
            ("/a/./b", MountBaseRefusal::DotSegment),
            ("/a/../b", MountBaseRefusal::DotSegment),
            ("/a%2Fb", MountBaseRefusal::Reserved { byte: b'%' }),
            ("/a?b", MountBaseRefusal::Reserved { byte: b'?' }),
            ("/a#b", MountBaseRefusal::Reserved { byte: b'#' }),
            ("/a\\b", MountBaseRefusal::Reserved { byte: b'\\' }),
            ("/a b", MountBaseRefusal::Reserved { byte: b' ' }),
            ("/a\"b", MountBaseRefusal::Reserved { byte: b'"' }),
            ("/\u{e9}", MountBaseRefusal::Reserved { byte: 0xC3 }),
            ("/a;b", MountBaseRefusal::Reserved { byte: b';' }),
            ("/a<b", MountBaseRefusal::Reserved { byte: b'<' }),
            ("/a>b", MountBaseRefusal::Reserved { byte: b'>' }),
            ("/a%zz", MountBaseRefusal::Reserved { byte: b'%' }),
        ] {
            assert_eq!(MountBase::parse(bad), Err(want), "{bad:?}");
        }
    }

    /// Distinct bases have distinct cookie suffixes, `/a-b`, `/a_b` and
    /// `/a/b` included, and every suffix byte is a cookie-name `token` byte.
    #[test]
    fn cookie_suffix_is_injective_over_mount_bases() {
        let segments = [
            "a", "b", "a-b", "a_b", "_", "__", "_2F", "_5F", "a.b", "a~b", "2F",
        ];
        let mut bases = vec![MountBase::root()];
        for first in segments {
            bases.push(MountBase::parse(&format!("/{first}")).unwrap());
            for second in segments {
                bases.push(MountBase::parse(&format!("/{first}/{second}")).unwrap());
            }
        }
        let mut seen = std::collections::HashMap::new();
        for base in &bases {
            let suffix = base.cookie_suffix();
            assert!(
                suffix
                    .as_str()
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'~' | b'_')),
                "{suffix:?}"
            );
            if let Some(other) = seen.insert(suffix.clone(), base.clone()) {
                assert_eq!(&other, base, "{other:?} and {base:?} share {suffix:?}");
            }
        }
        let suffix = |text: &str| MountBase::parse(text).unwrap().cookie_suffix();
        assert_eq!(suffix("").as_str(), "");
        assert_eq!(suffix("/a-b").as_str(), "_2Fa-b");
        assert_eq!(suffix("/a_b").as_str(), "_2Fa_5Fb");
        assert_eq!(suffix("/a/b").as_str(), "_2Fa_2Fb");
    }

    /// `""` and `/` are the root; `//` is not.
    #[test]
    fn mount_base_root_accepts_empty_and_slash_only() {
        assert_eq!(MountBase::parse(""), Ok(MountBase::root()));
        assert_eq!(MountBase::parse("/"), Ok(MountBase::root()));
        assert_eq!(MountBase::root().prefix(), "");
        assert_eq!(MountBase::root().dir_url(), "/");
        assert!(MountBase::root().to_decoded().is_root());
        assert!(MountBase::parse("//").is_err());
    }

    /// The length ceiling is judged before any byte is scanned: a base one
    /// past the limit made only of refused bytes reports `TooLong`, and the
    /// last legal length is admitted.
    #[test]
    fn mount_base_too_long_refused_before_scan() {
        let over_reserved = format!("/{}", "%".repeat(MAX_MOUNT_BASE_LEN));
        assert_eq!(
            MountBase::parse(&over_reserved),
            Err(MountBaseRefusal::TooLong {
                len: MAX_MOUNT_BASE_LEN + 1
            })
        );
        let over = format!("/{}", "a".repeat(MAX_MOUNT_BASE_LEN));
        assert_eq!(
            MountBase::parse(&over),
            Err(MountBaseRefusal::TooLong {
                len: MAX_MOUNT_BASE_LEN + 1
            })
        );
        let at_limit = format!("/{}", "a".repeat(MAX_MOUNT_BASE_LEN - 1));
        assert!(MountBase::parse(&at_limit).is_ok_and(|b| b.prefix() == at_limit));
    }

    /// A content-addressed path is a member of the parsed grammar, byte for byte.
    #[test]
    fn hashed_bundle_path_is_in_the_grammar() {
        let head = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        for (kind, want) in [
            (HashedAsset::Widget, "_ipe/widget.0123456789abcdef.js"),
            (
                HashedAsset::WidgetGlue,
                "_ipe/widget-glue.0123456789abcdef.js",
            ),
        ] {
            let path = BundlePath::hashed(kind, head);
            assert_eq!(path.rel(), want);
            assert_eq!(BundlePath::parse(want), Ok(path));
        }
    }

    /// Every malformed bundle path is refused with its own variant; each
    /// refusal has a well-formed neighbour that is admitted.
    #[test]
    fn bundle_path_refuses_each_variant() {
        for ok in [
            "index.html",
            "pkg/app_bg.wasm",
            "_ipe/widget.0123abcd.js",
            "a-b/c.d",
            ".hidden",
        ] {
            assert!(
                BundlePath::parse(ok).is_ok_and(|p| p.rel() == ok),
                "{ok} must be admitted verbatim"
            );
        }
        for (bad, want) in [
            ("", BundlePathRefusal::Empty),
            ("/index.html", BundlePathRefusal::LeadingSlash),
            ("a//b", BundlePathRefusal::EmptySegment),
            ("a/", BundlePathRefusal::EmptySegment),
            ("..", BundlePathRefusal::DotSegment),
            ("a/../b", BundlePathRefusal::DotSegment),
            ("./a", BundlePathRefusal::DotSegment),
            ("a~b", BundlePathRefusal::Reserved { byte: b'~' }),
            ("a%2Fb", BundlePathRefusal::Reserved { byte: b'%' }),
            ("a\\b", BundlePathRefusal::Reserved { byte: b'\\' }),
            ("a?b", BundlePathRefusal::Reserved { byte: b'?' }),
            ("a\"b", BundlePathRefusal::Reserved { byte: b'"' }),
        ] {
            assert_eq!(BundlePath::parse(bad), Err(want), "{bad:?}");
        }
        let over = "a".repeat(MAX_BUNDLE_PATH_LEN + 1);
        assert_eq!(
            BundlePath::parse(&over),
            Err(BundlePathRefusal::TooLong {
                len: MAX_BUNDLE_PATH_LEN + 1
            })
        );
        let over_reserved = "%".repeat(MAX_BUNDLE_PATH_LEN + 1);
        assert_eq!(
            BundlePath::parse(&over_reserved),
            Err(BundlePathRefusal::TooLong {
                len: MAX_BUNDLE_PATH_LEN + 1
            })
        );
        assert!(BundlePath::parse(&"a".repeat(MAX_BUNDLE_PATH_LEN)).is_ok());
    }

    /// Every projection of a mount base agrees with the one carried value:
    /// the infallible encoding equals encoding its decoded segments.
    #[test]
    fn mount_base_projections_agree() {
        for text in ["", "/", "/app", "/a-b/c.d~e/f_g"] {
            let base = MountBase::parse(text).unwrap();
            assert_eq!(
                Ok(base.encoded()),
                EncodedBase::encode(base.to_decoded()),
                "{text}"
            );
            assert_eq!(base.encoded().as_str(), base.prefix());
            assert_eq!(
                base.segments().collect::<Vec<_>>(),
                base.to_decoded()
                    .segments()
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
            );
        }
        let base = MountBase::parse("/app/v1").unwrap();
        assert_eq!(base.dir_url(), "/app/v1/");
        assert_eq!(base.segments().collect::<Vec<_>>(), ["app", "v1"]);
        let asset = BundlePath::parse("pkg/app_bg.wasm").unwrap();
        assert_eq!(base.url_of(&asset), "/app/v1/pkg/app_bg.wasm");
        assert_eq!(MountBase::root().url_of(&asset), "/pkg/app_bg.wasm");
        assert_eq!(
            asset.file_segments().collect::<Vec<_>>(),
            ["pkg", "app_bg.wasm"]
        );
        let request = DecodedPath::parse("/app/v1/pkg/app_bg.wasm").unwrap();
        assert_eq!(
            request.strip_base(base.to_decoded()),
            Some(DecodedPath::parse("/pkg/app_bg.wasm").unwrap())
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod server_pattern_tests {
    use super::*;

    fn refusal(raw: &str) -> Option<ServerPatternRefusal> {
        ServerPattern::parse(raw).err()
    }

    /// Prove the refusals: a pattern the router could misread, or one no
    /// request could ever reach, is refused at parse with its typed cause.
    #[test]
    fn malformed_server_patterns_are_refused() {
        use ParamNameRefusal as N;
        use RouteSegmentRefusal as S;
        use ServerPatternRefusal as R;
        assert_eq!(refusal("/:"), Some(R::Segment(S::ParamName(N::Empty))));
        assert!(matches!(
            refusal("/:a/:a"),
            Some(R::Segment(S::ParamName(N::Duplicate { .. })))
        ));
        assert!(matches!(
            refusal("/:a-b"),
            Some(R::Segment(S::ParamName(N::NotIdentifier { .. })))
        ));
        for catch_all in ["/*rest", "/f/*", "/a/:x/*y", "/*"] {
            assert_eq!(
                refusal(catch_all),
                Some(R::Segment(S::CatchAll)),
                "{catch_all}"
            );
        }
        for (mid, at) in [("/a:b", 1), ("/v-:id", 2), ("/x/ab*", 2), ("/q/a*:b", 1)] {
            assert_eq!(
                refusal(mid),
                Some(R::Segment(S::MidSegmentSigil { at: ByteOffset(at) })),
                "{mid}"
            );
        }
        assert!(matches!(
            refusal("/a/%zz"),
            Some(R::Segment(S::Decode(DecodeRefusal::MalformedEscape { .. })))
        ));
        assert!(matches!(
            refusal("/ab%C0%AF"),
            Some(R::Segment(S::Decode(DecodeRefusal::InvalidUtf8 { .. })))
        ));
        for relative in ["", "api", "api/:id", ":id"] {
            assert_eq!(refusal(relative), Some(R::NotAbsolute), "{relative:?}");
        }
    }

    /// Prove the refusal: one parameter past [`MAX_SERVER_PARAMS`] is refused
    /// at parse; the ceiling itself is served.
    #[test]
    fn a_pattern_past_the_parameter_ceiling_is_refused() {
        let params = |n: usize| -> String {
            (0..n)
                .flat_map(|i| ["/:v".to_owned(), i.to_string()])
                .collect()
        };
        assert!(ServerPattern::parse(&params(MAX_SERVER_PARAMS)).is_ok());
        assert_eq!(
            refusal(&params(MAX_SERVER_PARAMS + 1)),
            Some(ServerPatternRefusal::TooManyParams {
                cap: MAX_SERVER_PARAMS
            })
        );
    }

    /// Two patterns spell alike exactly when they have one shape: parameter
    /// names never matter, a trailing slash and a decoded literal always do.
    #[test]
    #[allow(clippy::expect_used)] // test table: every pattern is well-formed
    fn patterns_spell_alike_exactly_when_they_share_a_shape() {
        let spell = |raw: &str| {
            ServerPattern::parse(raw)
                .expect("well-formed pattern")
                .router_path()
                .to_owned()
        };
        for (a, b) in [
            ("/a/:x", "/a/:y"),
            ("/café", "/caf%C3%A9"),
            ("/:a/:b", "/:c/:d"),
            ("/%61", "/a"),
        ] {
            assert_eq!(spell(a), spell(b), "{a} {b}");
        }
        for (a, b) in [
            ("/a/", "/a"),
            ("/a/b", "/a/:x"),
            ("/a/:x", "/a/:x/"),
            ("/a%2Fb", "/a/b"),
            ("/a//b", "/a/b"),
            ("/:x/a", "/a/:x"),
        ] {
            assert_ne!(spell(a), spell(b), "{a} {b}");
        }
    }

    /// A pattern captures a request path of its shape only: the same
    /// trailing slash and an equal decoded literal at every literal position.
    #[test]
    #[allow(clippy::expect_used)] // test table: every pattern and probe is well-formed
    fn a_pattern_captures_only_paths_of_its_shape() {
        let captured = |pattern: &str, request: &str| {
            ServerPattern::parse(pattern)
                .expect("well-formed pattern")
                .captures(&RequestPath::parse(request).expect("well-formed probe"))
                .map(RouteParams::into_segments)
        };
        assert_eq!(
            captured("/greet/:name", "/greet/caf%C3%A9"),
            Some(vec!["café".to_owned()])
        );
        assert_eq!(
            captured("/greet/:name", "/greet/a%2Fb"),
            Some(vec!["a/b".to_owned()])
        );
        assert_eq!(captured("/a/", "/a/"), Some(vec![]));
        assert_eq!(captured("/", "/"), Some(vec![]));
        for (pattern, request) in [
            ("/a/", "/a"),
            ("/a", "/a/"),
            ("/greet/:name", "/greet/a/b"),
            ("/greet/:name", "/greet"),
            ("/greet/:name", "/hello/bob"),
        ] {
            assert_eq!(captured(pattern, request), None, "{pattern} {request}");
        }
    }

    /// One byte past the parse ceiling is refused; a pattern within it whose
    /// router spelling grows past the ceiling is refused at render.
    #[test]
    fn over_ceiling_server_patterns_are_refused() {
        let cap = MAX_URL_COMPONENT_LEN.get();
        let past = format!("/{}", "a".repeat(cap));
        assert!(matches!(
            refusal(&past),
            Some(ServerPatternRefusal::Segment(RouteSegmentRefusal::Decode(
                DecodeRefusal::TooLong { .. }
            )))
        ));
        let at_cap = format!("/{}", "a".repeat(cap - 1));
        assert_eq!(
            ServerPattern::parse(&at_cap).map(|p| p.router_path().len()),
            Ok(cap)
        );
        let grows = format!("/{}", "+".repeat(cap / 2));
        assert_eq!(
            refusal(&grows),
            Some(ServerPatternRefusal::Render(EncodeRefusal::TooLong {
                cap: MAX_URL_COMPONENT_LEN
            }))
        );
    }

    /// A pattern registers under the canonical spelling of its literals, so
    /// every raw spelling of one path registers alike.
    #[test]
    #[allow(clippy::expect_used)] // test table: every pattern is well-formed
    fn server_patterns_render_their_canonical_spelling() {
        for (raw, rendered) in [
            ("/", "/"),
            ("//", "/"),
            ("/greet/:name", "/greet/{p0}"),
            ("/:a/x/:b/", "/{p0}/x/{p1}/"),
            ("/{id}", "/%7Bid%7D"),
            ("/a/{{b}}", "/a/%7B%7Bb%7D%7D"),
            ("/a%7Bb%7D", "/a%7Bb%7D"),
            ("/café", "/caf%C3%A9"),
            ("/caf%C3%A9", "/caf%C3%A9"),
            ("/%61pi", "/api"),
            ("/a/", "/a/"),
            ("//a//", "/a/"),
            ("/a//b", "/a//b"),
            ("/a+b", "/a%2Bb"),
            ("/a/%3Ax", "/a/%3Ax"),
            ("/a/%2A", "/a/%2A"),
            ("/a%2Fb", "/a%2Fb"),
            ("/%2E/:_x1", "/%2E/{p0}"),
        ] {
            let pattern = ServerPattern::parse(raw).expect("well-formed pattern");
            assert_eq!(pattern.router_path(), rendered, "{raw:?}");
        }
        let slash = ServerPattern::parse("/a/").expect("well-formed pattern");
        assert_eq!(slash.trailing(), TrailingSlash::Present);
        let root = ServerPattern::parse("/").expect("well-formed pattern");
        assert_eq!(root.trailing(), TrailingSlash::Absent);
        assert!(root.pattern().segments().is_empty());
    }

    /// The router spelling of a literal pattern is the canonical spelling of
    /// every request path naming the same decoded segments.
    #[test]
    #[allow(clippy::expect_used)] // test table: every pattern and probe is well-formed
    fn a_literal_pattern_spells_as_its_requests_do() {
        for (pattern, request) in [
            ("/café", "/caf%c3%a9"),
            ("/%61pi", "/api"),
            ("/a+b", "/a%2bb"),
            ("/a/", "/%61/"),
            ("/a%2Fb", "/a%2fb"),
        ] {
            let pattern = ServerPattern::parse(pattern).expect("well-formed pattern");
            let request = RequestPath::parse(request).expect("well-formed probe");
            assert_eq!(
                Some(pattern.router_path()),
                request.canonical().ok().as_ref().map(CanonicalPath::as_str),
            );
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod server_origin_tests {
    use super::*;

    /// A host of exactly `len` bytes: 63-byte labels of `a` joined by dots,
    /// then a shorter last label.
    fn host_of(len: usize) -> String {
        let mut host = String::new();
        while host.len() < len {
            if !host.is_empty() {
                host.push('.');
            }
            let room = len.saturating_sub(host.len()).min(MAX_ORIGIN_LABEL_LEN);
            host.push_str(&"a".repeat(room));
        }
        host
    }

    /// Each refused spelling beside the valid neighbour that parses, so each
    /// refusal is pinned to its one defect.
    #[test]
    fn each_refused_shape_has_a_parsing_neighbour() {
        let cases: [(&str, &str, ServerOriginRefusal); 12] = [
            (
                "http://api.example",
                "https://api.example",
                ServerOriginRefusal::NotHttps,
            ),
            (
                "HTTPS://api.example",
                "https://api.example",
                ServerOriginRefusal::NotHttps,
            ),
            ("https://*", "https://a", ServerOriginRefusal::Wildcard),
            (
                "https://*.example",
                "https://a.example",
                ServerOriginRefusal::Wildcard,
            ),
            (
                "https://u@api.example",
                "https://api.example",
                ServerOriginRefusal::Userinfo,
            ),
            (
                "https://api.example/",
                "https://api.example",
                ServerOriginRefusal::AfterAuthority,
            ),
            (
                "https://api.example?q",
                "https://api.example",
                ServerOriginRefusal::AfterAuthority,
            ),
            (
                "https://api.example#f",
                "https://api.example",
                ServerOriginRefusal::AfterAuthority,
            ),
            (
                "https://Api.example",
                "https://api.example",
                ServerOriginRefusal::Uppercase,
            ),
            (
                "https://-api.example",
                "https://api.example",
                ServerOriginRefusal::LabelHyphen,
            ),
            (
                "https://api..example",
                "https://api.example",
                ServerOriginRefusal::EmptyLabel,
            ),
            (
                "https://api.example.",
                "https://api.example",
                ServerOriginRefusal::EmptyLabel,
            ),
        ];
        for (refused, neighbour, why) in cases {
            assert_eq!(ServerOrigin::parse(refused), Err(why), "{refused:?}");
            assert!(ServerOrigin::parse(neighbour).is_ok(), "{neighbour:?}");
        }
    }

    /// IP literals of either family, and bytes outside the host alphabet.
    #[test]
    fn ip_literals_and_foreign_bytes_are_refused() {
        let cases: [(&str, &str, ServerOriginRefusal); 6] = [
            (
                "https://1.2.3.4",
                "https://1.2.3.a",
                ServerOriginRefusal::IpLiteral,
            ),
            (
                "https://0x7f000001",
                "https://x7f000001",
                ServerOriginRefusal::IpLiteral,
            ),
            (
                "https://[::1]",
                "https://a1",
                ServerOriginRefusal::IpLiteral,
            ),
            (
                "https://ap\u{ed}.example",
                "https://api.example",
                ServerOriginRefusal::Byte { byte: 0xC3 },
            ),
            (
                "https://api .example",
                "https://api.example",
                ServerOriginRefusal::Byte { byte: b' ' },
            ),
            (
                "https://api\n.example",
                "https://api.example",
                ServerOriginRefusal::Byte { byte: b'\n' },
            ),
        ];
        for (refused, neighbour, why) in cases {
            assert_eq!(ServerOrigin::parse(refused), Err(why), "{refused:?}");
            assert!(ServerOrigin::parse(neighbour).is_ok(), "{neighbour:?}");
        }
    }

    /// Ports: the default written out, zero, past `u16`, a leading zero, none.
    #[test]
    fn malformed_ports_are_refused() {
        let cases: [(&str, &str, ServerOriginRefusal); 5] = [
            (
                "https://api.example:443",
                "https://api.example:444",
                ServerOriginRefusal::DefaultPort,
            ),
            (
                "https://api.example:0",
                "https://api.example:1",
                ServerOriginRefusal::PortOutOfRange,
            ),
            (
                "https://api.example:65536",
                "https://api.example:65535",
                ServerOriginRefusal::PortOutOfRange,
            ),
            (
                "https://api.example:08443",
                "https://api.example:8443",
                ServerOriginRefusal::PortLeadingZero,
            ),
            (
                "https://api.example:",
                "https://api.example:9",
                ServerOriginRefusal::PortMalformed,
            ),
        ];
        for (refused, neighbour, why) in cases {
            assert_eq!(ServerOrigin::parse(refused), Err(why), "{refused:?}");
            assert!(ServerOrigin::parse(neighbour).is_ok(), "{neighbour:?}");
        }
    }

    /// A 64-byte label and a 254-byte host are refused; one byte less parses.
    #[test]
    fn label_and_host_lengths_are_bounded() {
        let label = |len: usize| format!("https://{}.example", "a".repeat(len));
        assert_eq!(
            ServerOrigin::parse(&label(MAX_ORIGIN_LABEL_LEN + 1)),
            Err(ServerOriginRefusal::LabelTooLong { len: 64 })
        );
        assert!(ServerOrigin::parse(&label(MAX_ORIGIN_LABEL_LEN)).is_ok());
        let host = |len: usize| format!("https://{}", host_of(len));
        assert_eq!(host_of(MAX_ORIGIN_HOST_LEN).len(), 253);
        assert_eq!(
            ServerOrigin::parse(&host(MAX_ORIGIN_HOST_LEN + 1)),
            Err(ServerOriginRefusal::HostTooLong { len: 254 })
        );
        assert!(ServerOrigin::parse(&host(MAX_ORIGIN_HOST_LEN)).is_ok());
        let text = format!("https://{}", "a".repeat(MAX_ORIGIN_LEN));
        assert_eq!(
            ServerOrigin::parse(&text),
            Err(ServerOriginRefusal::TooLong { len: text.len() })
        );
    }

    /// A parsed origin renders its two schemes over one authority.
    #[test]
    fn an_origin_renders_https_and_wss() {
        let origin = ServerOrigin::parse("https://media.example:8443");
        assert_eq!(
            origin.as_ref().map(ServerOrigin::https).ok().as_deref(),
            Some("https://media.example:8443")
        );
        assert_eq!(
            origin.as_ref().map(ServerOrigin::wss).ok().as_deref(),
            Some("wss://media.example:8443")
        );
    }

    /// Sixteen distinct origins are a list; a seventeenth is refused, and a
    /// repeat neither counts nor appears twice.
    #[test]
    #[allow(clippy::expect_used)] // every generated origin is well-formed
    fn a_seventeenth_origin_is_refused() {
        let origin =
            |i: usize| ServerOrigin::parse(&format!("https://s{i}.example")).expect("origin");
        let sixteen: Vec<ServerOrigin> = (0..MAX_SERVER_ORIGINS).map(origin).collect();
        let doubled = ServerOrigins::new(sixteen.iter().cloned().chain(sixteen.iter().cloned()));
        assert_eq!(
            doubled.as_ref().map(ServerOrigins::len),
            Ok(MAX_SERVER_ORIGINS)
        );
        let mut seventeen = sixteen;
        seventeen.push(origin(MAX_SERVER_ORIGINS));
        assert_eq!(
            ServerOrigins::new(seventeen),
            Err(ServerOriginsRefusal::LimitExceeded)
        );
    }

    /// The list is sorted whatever order it was given in.
    #[test]
    #[allow(clippy::expect_used)] // both origins are well-formed
    fn origins_are_sorted() {
        let b = ServerOrigin::parse("https://b.example").expect("origin");
        let a = ServerOrigin::parse("https://a.example").expect("origin");
        let list = ServerOrigins::new([b.clone(), a.clone()]).expect("two origins");
        assert_eq!(list.origins().collect::<Vec<_>>(), vec![&a, &b]);
    }
}

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
    let encoded = utf8_percent_encode(text, QUERY).to_string();
    if encoded.len() > MAX_URL_COMPONENT_LEN.get() {
        return Err(too_long);
    }
    Ok(EncodedSegment(encoded))
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
}

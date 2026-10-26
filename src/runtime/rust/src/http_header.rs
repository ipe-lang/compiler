//! Canonical HTTP header-name casing and the one header fold, shared by
//! Ipe.Web, Ipe.Http.Server and the HTTP client.
//!
//! Canonical MIME case: `content-type` → `Content-Type`, `x-ipe-web` →
//! `X-Ipe-Web`. hyper/axum expose request header names lower-cased, so the
//! runtime re-derives the canonical form at the request boundary for both
//! storage and lookup. The fold turns a message's header entries into the
//! program-visible dict under one arity table, so the Web and Server request
//! builders and the client's response reader never pick different copies.

/// Canonicalise a `-`-separated header name (`content-type` -> `Content-Type`).
///
/// Upper-cases the first ASCII letter of each `-`-separated segment and
/// lower-cases the rest. Only `-` triggers the next-uppercase; `_`/`.`/digits
/// are non-triggers.
///
/// Accepted divergence: a name containing bytes outside the header-token set
/// (e.g. a space or non-ASCII byte) is always title-cased per segment, rather
/// than returned unchanged. Such names cannot reach the request boundary —
/// hyper/axum reject invalid header names on parse — so the divergence is
/// unobservable in practice.
pub(crate) fn canonical_header(k: &str) -> String {
    let mut out = String::with_capacity(k.len());
    let mut at_segment_start = true;
    for c in k.chars() {
        if c == '-' {
            out.push('-');
            at_segment_start = true;
        } else if at_segment_start {
            out.push(c.to_ascii_uppercase());
            at_segment_start = false;
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// How often one header name may appear in a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeaderArity {
    /// At most once: a second copy makes the message ambiguous.
    Singleton,
    /// A comma-separated list: copies combine, in arrival order, with `", "`.
    List,
    /// A cookie header, whose items the cookie parser reads from its bytes.
    CookieJar,
}

/// The arity of the header named `canonical` (its [`canonical_header`] form).
///
/// The list names are closed; every other name, known or not, is a
/// singleton, so a repeated header no rule combines is refused, never guessed.
pub(crate) fn header_arity(canonical: &str) -> HeaderArity {
    match canonical {
        "Accept"
        | "Accept-Charset"
        | "Accept-Encoding"
        | "Accept-Language"
        | "Cache-Control"
        | "Connection"
        | "Forwarded"
        | "If-Match"
        | "If-None-Match"
        | "Pragma"
        | "Te"
        | "Trailer"
        | "Transfer-Encoding"
        | "Upgrade"
        | "Via"
        | "Warning"
        | "X-Forwarded-For"
        | "Sec-Websocket-Extensions"
        | "Sec-Websocket-Protocol" => HeaderArity::List,
        "Cookie" | "Set-Cookie" => HeaderArity::CookieJar,
        _ => HeaderArity::Singleton,
    }
}

/// Why a message's headers have no one program-visible reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeaderRefusal {
    /// A singleton header appears more than once.
    DuplicateSingleton,
    /// A header value holds a byte outside visible ASCII, space and tab.
    NotVisibleAscii,
}

impl HeaderRefusal {
    /// The fixed text a refused response reads; it never names the header.
    #[cfg(any(
        feature = "http_client",
        all(target_arch = "wasm32", feature = "wasm-client")
    ))]
    pub(crate) const fn response_text(self) -> &'static str {
        match self {
            Self::DuplicateSingleton => "http: the response repeats a header that must appear once",
            Self::NotVisibleAscii => {
                "http: the response carries a header value that is not visible ASCII"
            }
        }
    }
}

/// The header text of `bytes`, when every byte is visible ASCII, space or tab.
fn header_text(bytes: &[u8]) -> Option<&str> {
    if bytes
        .iter()
        .all(|&b| b == b'\t' || (b' '..=b'~').contains(&b))
    {
        std::str::from_utf8(bytes).ok()
    } else {
        None
    }
}

/// The one fold of a message's header entries into a dict keyed by canonical name.
///
/// Every entry is judged from its raw bytes, so an undecodable copy cannot hide
/// a duplicate. A singleton seen twice, or a value outside visible ASCII,
/// refuses the whole message; list copies combine in arrival order. A cookie
/// header is left to its own reader.
fn fold_headers<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> Result<crate::dict::IpeDict<String>, HeaderRefusal> {
    use std::collections::hash_map::Entry;
    let mut dict = crate::dict::IpeDict::new();
    for (name, bytes) in entries {
        let canonical = canonical_header(name);
        let arity = header_arity(&canonical);
        if arity == HeaderArity::CookieJar {
            continue;
        }
        let text = header_text(bytes).ok_or(HeaderRefusal::NotVisibleAscii)?;
        match dict.entry(canonical) {
            Entry::Vacant(slot) => {
                slot.insert(text.to_owned());
            }
            Entry::Occupied(mut slot) => match arity {
                HeaderArity::List => {
                    let combined = slot.get_mut();
                    combined.push_str(", ");
                    combined.push_str(text);
                }
                HeaderArity::Singleton | HeaderArity::CookieJar => {
                    return Err(HeaderRefusal::DuplicateSingleton);
                }
            },
        }
    }
    Ok(dict)
}

/// A request's headers as the program reads them, keyed by canonical name.
///
/// Only [`RequestHeaders::parse`] builds one, at the listener, so every
/// program-visible request header dict comes from the one fold. `Cookie` is
/// absent: the cookie parser reads it item by item from its bytes.
#[cfg(feature = "server")]
#[derive(Clone)]
pub(crate) struct RequestHeaders(crate::dict::IpeDict<String>);

#[cfg(feature = "server")]
impl RequestHeaders {
    /// Fold the request's header entries.
    ///
    /// # Errors
    ///
    /// A [`HeaderRefusal`] when a singleton repeats or a value is not visible
    /// ASCII; the listener answers it with the fixed 400.
    pub(crate) fn parse(map: &axum::http::HeaderMap) -> Result<Self, HeaderRefusal> {
        fold_headers(
            map.iter()
                .map(|(name, value)| (name.as_str(), value.as_bytes())),
        )
        .map(Self)
    }

    /// The program-visible dict.
    pub(crate) const fn as_dict(&self) -> &crate::dict::IpeDict<String> {
        &self.0
    }

    /// The value of the header named `canonical`, list copies combined.
    pub(crate) fn get(&self, canonical: &str) -> Option<&str> {
        self.0.get(canonical).map(String::as_str)
    }
}

/// Fold a response's header entries into the program-visible dict.
///
/// The browser hands `fetch` its headers already combined per name, so there a
/// repeat never reaches the fold.
///
/// # Errors
///
/// A [`HeaderRefusal`] when a singleton repeats or a value is not visible
/// ASCII. `Set-Cookie` is never refused: the dict keeps its last decodable copy.
#[cfg(any(
    feature = "http_client",
    all(target_arch = "wasm32", feature = "wasm-client")
))]
pub(crate) fn response_headers<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> Result<crate::dict::IpeDict<String>, HeaderRefusal> {
    let entries: Vec<(&str, &[u8])> = entries.into_iter().collect();
    let mut dict = fold_headers(entries.iter().copied())?;
    let set_cookie = entries
        .iter()
        .copied()
        .rev()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .find_map(|(_, bytes)| header_text(bytes));
    if let Some(text) = set_cookie {
        dict.insert("Set-Cookie".to_owned(), text.to_owned());
    }
    Ok(dict)
}

/// Strip a scheme's IMPLICIT default port (`:443` for `https`, `:80` for
/// `http`) from a `host[:port]` authority string, if present. Any other
/// scheme (or an authority without that exact suffix) passes through
/// unchanged.
#[cfg(feature = "server")]
fn strip_default_port<'a>(authority: &'a str, scheme: &str) -> &'a str {
    let suffix = match scheme {
        "https" => ":443",
        "http" => ":80",
        _ => return authority,
    };
    authority.strip_suffix(suffix).unwrap_or(authority)
}

/// Whether an `Origin` header's host disagrees with a `Host` header, once
/// each side's scheme-implied default port is normalized away. Returns
/// `true` when they are CROSS-origin (a mismatch); `false` when same-origin
/// OR when `host` is empty (nothing to compare against — every existing call
/// site treats an empty `Host` as "don't reject").
///
/// Shared by every "compare Origin's host against Host" call site in the
/// runtime (`live/csrf.rs::origin_mismatch`, `live/console.rs::
/// is_cross_origin_ingest`, `server.rs::ws_cross_origin`) so the three never
/// drift to different normalization behavior. Browsers omit the default
/// port from BOTH the `Origin` and `Host` headers they send, so a raw string
/// compare is right in the overwhelming common case — but a reverse proxy or
/// non-browser client that sets an EXPLICIT `:443`/`:80` (e.g. `Origin:
/// https://example.com` vs `Host: example.com:443`) would otherwise trip a
/// false-positive cross-origin rejection. This is an availability nit (every
/// caller fails CLOSED on a mismatch — over-rejecting, never under-
/// rejecting), not a vulnerability; still worth normalizing correctly rather
/// than leaving three copies of the same raw-string-compare gap.
#[cfg(feature = "server")]
pub(crate) fn origin_host_mismatch(origin: &str, host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    let (scheme, origin_authority) = origin.split_once("://").unwrap_or(("", origin));
    let origin_host = strip_default_port(origin_authority, scheme);
    let host_host = strip_default_port(host, scheme);
    origin_host != host_host
}

/// RFC 6265 cookie name and value grammar, held in types.
///
/// One grammar for the server request parser, the `Set-Cookie` builder and the
/// browser `document.cookie` reader, so a cookie reads back the same on every
/// host. A name holds only RFC 7230 `token` bytes and a value only RFC 6265
/// `cookie-octet` bytes; every other byte (non-ASCII, a CTL including CR/LF,
/// `;`, `,`, whitespace, `"`, `\`) and `%` itself is written `%XX`, so the
/// encoding is injective and [`cookie::decode`] inverts it exactly.
#[cfg(any(
    feature = "server",
    all(target_arch = "wasm32", feature = "wasm-client")
))]
pub mod cookie {
    use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

    /// The ASCII bytes a cookie value writes as `%XX`.
    ///
    /// Every byte that is not an RFC 6265 `cookie-octet`, and `%` itself.
    /// Non-ASCII bytes are always written `%XX`.
    const VALUE_ESCAPED: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'%')
        .add(b',')
        .add(b';')
        .add(b'\\');

    /// The ASCII bytes a cookie name writes as `%XX`.
    ///
    /// Every byte that is not an RFC 7230 `tchar`, and `%` itself. Non-ASCII
    /// bytes are always written `%XX`.
    const NAME_ESCAPED: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'%')
        .add(b'(')
        .add(b')')
        .add(b',')
        .add(b'/')
        .add(b':')
        .add(b';')
        .add(b'<')
        .add(b'=')
        .add(b'>')
        .add(b'?')
        .add(b'@')
        .add(b'[')
        .add(b'\\')
        .add(b']')
        .add(b'{')
        .add(b'}');

    /// The fixed base of a cookie name the runtime itself sets.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum RuntimeCookie {
        /// `ipe_csrf`: the `Middleware.withCsrf` cookie outside production.
        ServerCsrf,
        /// `__ipe_csrf`: the `Ipe.Web` CSRF cookie when cookies are not `Secure`.
        WebCsrf,
        /// `__Host-ipe_csrf`: a CSRF cookie when cookies are `Secure`.
        HostCsrf,
        /// `ipe_sid`: the `Ipe.Web` session cookie.
        Session,
        /// `__Host-ipe_sid`: the root `Ipe.Web` session cookie when cookies are `Secure`.
        HostSession,
    }

    impl RuntimeCookie {
        const fn base(self) -> &'static str {
            match self {
                Self::ServerCsrf => "ipe_csrf",
                Self::WebCsrf => "__ipe_csrf",
                Self::HostCsrf => "__Host-ipe_csrf",
                Self::Session => "ipe_sid",
                Self::HostSession => "__Host-ipe_sid",
            }
        }
    }

    /// A non-empty cookie name: the program's text and its `token` wire form.
    ///
    /// The wire form is an injective function of the text, so two names are
    /// equal exactly when their texts are.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct CookieName {
        text: String,
        wire: String,
    }

    impl CookieName {
        /// Parse `raw`, percent-encoding every byte that is not a `token` byte.
        ///
        /// An empty name has no representation: a `Set-Cookie` line starting
        /// with `=` is a nameless cookie a browser sends back as a bare value,
        /// which a server reads as some other cookie.
        #[must_use]
        pub fn parse(raw: &str) -> Option<Self> {
            (!raw.is_empty()).then(|| Self {
                text: raw.to_owned(),
                wire: utf8_percent_encode(raw, NAME_ESCAPED).to_string(),
            })
        }

        /// The name of a runtime cookie: `base` followed by `suffix`.
        ///
        /// Non-empty by construction, since every base is.
        #[must_use]
        pub fn runtime(base: RuntimeCookie, suffix: &str) -> Self {
            let text = format!("{}{suffix}", base.base());
            let wire = utf8_percent_encode(&text, NAME_ESCAPED).to_string();
            Self { text, wire }
        }

        /// The name as the program wrote it.
        #[must_use]
        pub fn text(&self) -> &str {
            &self.text
        }

        /// The encoded name sent on the wire.
        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.wire
        }
    }

    impl std::fmt::Display for CookieName {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.wire)
        }
    }

    /// A cookie value made only of RFC 6265 `cookie-octet` bytes other than `%`.
    ///
    /// A cookie value is the cookie's secret half (a session id, a token), so
    /// its `Debug` prints [`crate::redact::REDACTED`], never the value.
    #[derive(Clone, PartialEq, Eq)]
    pub struct CookieValue(String);

    impl std::fmt::Debug for CookieValue {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_tuple("CookieValue")
                .field(&crate::redact::Redacted::new(()))
                .finish()
        }
    }

    impl CookieValue {
        /// Encode `raw`, percent-encoding `%` and every byte that is not a `cookie-octet`.
        ///
        /// A value made of the other `cookie-octet` bytes is kept byte-for-byte.
        #[must_use]
        pub fn encode(raw: &str) -> Self {
            Self(utf8_percent_encode(raw, VALUE_ESCAPED).to_string())
        }

        /// The encoded value.
        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    /// Invert the cookie percent-encoding of `wire`.
    ///
    /// Decoded by the runtime's one percent-decoder under the path grammar, so
    /// a `+` stays a `+`. A `%` not followed by two hex digits, or bytes that
    /// are not UTF-8, have no decoding: the result is `None`, never a lossy
    /// replacement.
    #[must_use]
    pub fn decode(wire: &str) -> Option<String> {
        crate::encoding::decode_component(wire, crate::encoding::UrlGrammar::Path).ok()
    }

    /// The most `;`-separated pieces read from one request's cookie jar.
    ///
    /// Counted over every `Cookie` header of the request together, before any
    /// piece is decoded, so the work a jar costs is bounded. Pieces past the
    /// ceiling are dropped: a browser keeps fewer cookies per domain than
    /// this, so only a jar no browser sends loses them.
    pub const MAX_REQUEST_COOKIES: std::num::NonZeroUsize =
        std::num::NonZeroUsize::MIN.saturating_add(255);

    /// The decoded `(name, value)` pairs of one request's cookie jar, in order:
    /// the raw bytes of every `Cookie` header, or of `document.cookie`.
    ///
    /// Each `;`-separated pair is judged on its own bytes: a pair holding a
    /// byte outside visible ASCII and tab is skipped, never the whole header,
    /// so a cookie another party set cannot drop the session or CSRF cookie
    /// beside it. A pair is kept only when its wire name is exactly the
    /// encoding of a non-empty name, so a lookup by name matches only what a
    /// `Set-Cookie` line would have written for it, and when its value
    /// decodes. Every other pair is skipped. Each name is the program's text.
    /// At most [`MAX_REQUEST_COOKIES`] pieces are read.
    pub fn request_cookies<'a, I>(jar: I) -> impl Iterator<Item = (String, String)> + 'a
    where
        I: IntoIterator<Item = &'a [u8]>,
        I::IntoIter: 'a,
    {
        jar.into_iter()
            .flat_map(|header| header.split(|b| *b == b';'))
            .take(MAX_REQUEST_COOKIES.get())
            .filter_map(request_cookie_pair)
    }

    /// One decoded `name=value` pair of a `Cookie` header, or `None` to skip it.
    fn request_cookie_pair(pair: &[u8]) -> Option<(String, String)> {
        if !pair.iter().all(|&b| matches!(b, b'\t' | b' '..=b'~')) {
            return None;
        }
        let (wire_name, wire_value) = std::str::from_utf8(pair).ok()?.split_once('=')?;
        let wire_name = wire_name.trim();
        let name = CookieName::parse(&decode(wire_name)?)?;
        if name.as_str() != wire_name {
            return None;
        }
        let value = decode(wire_value.trim())?;
        Some((name.text, value))
    }

    #[cfg(test)]
    #[cfg(not(target_arch = "wasm32"))]
    mod tests {
        use super::{CookieName, CookieValue, MAX_REQUEST_COOKIES, decode, request_cookies};

        /// The browser reader and the server parser are one function: a pair
        /// decodes, and a non-canonical or undecodable pair is skipped.
        #[test]
        fn request_cookies_decodes_and_skips_non_canonical_pairs() {
            let pairs: Vec<(String, String)> = request_cookies([
                b"my%20sid=%C3%A9%3B%25; ipe%5Fsid=forged; a=%ZZ; =v; theme=dark; theme=light"
                    .as_slice(),
            ])
            .collect();
            assert_eq!(
                pairs,
                [
                    ("my sid".to_owned(), "é;%".to_owned()),
                    ("theme".to_owned(), "dark".to_owned()),
                    ("theme".to_owned(), "light".to_owned()),
                ]
            );
        }

        /// A pair holding a byte outside visible ASCII is skipped on its own:
        /// the session cookie beside it survives, in every header of the jar.
        #[test]
        fn request_cookies_skip_only_the_pair_with_a_non_ascii_byte() {
            let jar: [&[u8]; 3] = [
                b"x=\xC3\xA9; ipe_sid=abc",
                b"y=\x80; z=\x01v; csrf=t",
                b"w=\x7F",
            ];
            let pairs: Vec<(String, String)> = request_cookies(jar).collect();
            assert_eq!(
                pairs,
                [
                    ("ipe_sid".to_owned(), "abc".to_owned()),
                    ("csrf".to_owned(), "t".to_owned()),
                ]
            );
        }

        /// A jar reads at most the ceiling's pieces, counted across headers.
        #[test]
        fn request_cookies_read_at_most_the_ceiling() {
            let max = MAX_REQUEST_COOKIES.get();
            let first = (1..max)
                .map(|i| format!("c{i}=v"))
                .collect::<Vec<_>>()
                .join("; ");
            let second = "last=v; over=v";
            let pairs: Vec<(String, String)> =
                request_cookies([first.as_bytes(), second.as_bytes()]).collect();
            assert_eq!(pairs.len(), max, "{} pairs read", pairs.len());
            assert_eq!(
                pairs.last().map(|(k, _)| k.as_str()),
                Some("last"),
                "the pair at the ceiling is read"
            );
            assert!(
                pairs.iter().all(|(k, _)| k != "over"),
                "a pair past the ceiling is dropped"
            );
        }

        /// Every byte encodes to the same wire form the RFC grammar names: a
        /// `cookie-octet` other than `%` is kept, every other byte is `%XX`,
        /// and decoding inverts the name encoder over every ASCII byte.
        #[test]
        fn encoders_keep_exactly_the_rfc_octets_and_round_trip() {
            for b in 0u8..=0x7F {
                let raw = char::from(b).to_string();
                let value_kept = matches!(
                    b,
                    0x21 | 0x23..=0x24 | 0x26..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E
                );
                let want = if value_kept {
                    raw.clone()
                } else {
                    format!("%{b:02X}")
                };
                assert_eq!(CookieValue::encode(&raw).as_str(), want, "byte {b:#04x}");
                let name = CookieName::parse(&raw);
                let wire = name.as_ref().map(CookieName::as_str);
                assert_eq!(
                    wire.and_then(decode).as_deref(),
                    Some(raw.as_str()),
                    "byte {b:#04x}"
                );
            }
            assert_eq!(CookieValue::encode("é").as_str(), "%C3%A9");
            assert_eq!(decode("%c3%a9").as_deref(), Some("é"));
        }

        /// A malformed escape, a truncated escape and an overlong UTF-8 form
        /// have no decoding, while `+` stays `+` and `%00` is the NUL byte.
        #[test]
        fn decode_refuses_malformed_escapes_and_invalid_utf8() {
            for wire in ["%ZZ", "%4", "%", "a%G1", "%C0%AF", "%FF", "%C3"] {
                assert_eq!(decode(wire), None, "{wire:?} must have no decoding");
            }
            assert_eq!(decode("a+b").as_deref(), Some("a+b"));
            assert_eq!(decode("%2B").as_deref(), Some("+"));
            assert_eq!(decode("%00").as_deref(), Some("\0"));
        }

        /// Every byte value, as the character of that code point, encodes to
        /// RFC wire bytes only and decodes back to itself, as a value and as a
        /// name.
        #[test]
        fn every_byte_round_trips_through_rfc_wire_bytes() {
            const fn is_cookie_octet(b: u8) -> bool {
                matches!(b, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E)
            }
            fn is_tchar(b: u8) -> bool {
                b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".as_slice().contains(&b)
            }
            for b in 0u8..=0xFF {
                let raw = char::from(b).to_string();
                let value = CookieValue::encode(&raw);
                assert!(
                    value.as_str().bytes().all(is_cookie_octet),
                    "byte {b:#04x}: value wire {:?} holds a non-cookie-octet",
                    value.as_str()
                );
                assert_eq!(
                    decode(value.as_str()).as_deref(),
                    Some(raw.as_str()),
                    "byte {b:#04x}: value"
                );
                let name = CookieName::parse(&raw);
                let Some(name) = name else {
                    panic!("byte {b:#04x}: a non-empty name parses");
                };
                assert!(
                    name.as_str().bytes().all(is_tchar),
                    "byte {b:#04x}: name wire {:?} holds a non-tchar",
                    name.as_str()
                );
                assert_eq!(
                    decode(name.as_str()).as_deref(),
                    Some(raw.as_str()),
                    "byte {b:#04x}: name"
                );
            }
        }

        /// A cookie value's `Debug` never prints the value it holds.
        #[test]
        fn cookie_value_debug_prints_no_value() {
            let shown = format!("{:?}", CookieValue::encode("T0K3N"));
            assert_eq!(shown, "CookieValue(<redacted>)");
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::canonical_header;
    #[cfg(feature = "server")]
    use super::origin_host_mismatch;

    /// Well-formed header names — byte-identical to
    /// `textproto.CanonicalMIMEHeaderKey`.
    #[test]
    fn canonical_header_matches_go_canonical_mime_key() {
        for (input, want) in [
            ("content-type", "Content-Type"),
            ("CONTENT-TYPE", "Content-Type"),
            ("Content-Type", "Content-Type"),
            ("x-forwarded-for", "X-Forwarded-For"),
            ("x-ipe-web", "X-Ipe-Web"),
            ("etag", "Etag"),
            ("www-authenticate", "Www-Authenticate"),
            ("host", "Host"),
            ("a", "A"),
            ("", ""),
            ("MiXeD-cAsE", "Mixed-Case"),
            ("x_custom", "X_custom"),
            ("123-abc", "123-Abc"),
            ("x--y", "X--Y"),
            ("-x", "-X"),
            ("x-", "X-"),
        ] {
            assert_eq!(canonical_header(input), want, "input {input:?}");
        }
    }

    /// Invalid-token names are the accepted divergence: title-cased here.
    /// These names cannot reach the request boundary (hyper/axum reject them
    /// on parse), so the divergence is unobservable in practice; this test
    /// pins the behaviour so any future change to the canonicaliser is caught.
    #[test]
    fn canonical_header_invalid_token_is_accepted_divergence() {
        assert_eq!(canonical_header("foo bar"), "Foo bar");
        assert_eq!(canonical_header("über-key"), "über-Key");
    }

    /// Baseline: same host, no port anywhere — same-origin (browsers'
    /// common case for both headers).
    #[cfg(feature = "server")]
    #[test]
    fn origin_host_mismatch_same_origin_no_ports() {
        assert!(!origin_host_mismatch("https://example.com", "example.com"));
    }

    /// Cross-origin host — must still be flagged regardless of the port
    /// normalization added by this fix.
    #[cfg(feature = "server")]
    #[test]
    fn origin_host_mismatch_different_host_is_flagged() {
        assert!(origin_host_mismatch(
            "https://evil.example",
            "victim.example"
        ));
    }

    /// The bug this fix closes: `https://example.com` (implicit :443) vs
    /// `Host: example.com:443` (explicit) is the SAME origin. Pre-fix (raw
    /// string compare) this was a false-positive mismatch.
    #[cfg(feature = "server")]
    #[test]
    fn origin_host_mismatch_normalizes_explicit_default_https_port() {
        assert!(!origin_host_mismatch(
            "https://example.com",
            "example.com:443"
        ));
    }

    /// Same bug, `http`/`:80` side.
    #[cfg(feature = "server")]
    #[test]
    fn origin_host_mismatch_normalizes_explicit_default_http_port() {
        assert!(!origin_host_mismatch(
            "http://example.com",
            "example.com:80"
        ));
    }

    /// A NON-default explicit port must still compare as a mismatch when the
    /// other side omits it — normalization only strips the SCHEME-IMPLIED
    /// default port, not arbitrary ports.
    #[cfg(feature = "server")]
    #[test]
    fn origin_host_mismatch_nondefault_port_still_flagged() {
        assert!(origin_host_mismatch(
            "https://example.com",
            "example.com:8443"
        ));
        assert!(!origin_host_mismatch(
            "https://example.com:8443",
            "example.com:8443"
        ));
    }

    /// Empty Host header → never a mismatch (matches every call site's own
    /// pre-existing `!host.is_empty()` guard — nothing to compare against).
    #[cfg(feature = "server")]
    #[test]
    fn origin_host_mismatch_empty_host_is_never_flagged() {
        assert!(!origin_host_mismatch("https://evil.example", ""));
    }

    /// The request fold of `entries`, appended in order.
    #[cfg(feature = "server")]
    fn fold(
        entries: &[(&'static str, &[u8])],
    ) -> Result<super::RequestHeaders, super::HeaderRefusal> {
        let mut map = axum::http::HeaderMap::new();
        for (name, bytes) in entries {
            map.append(
                *name,
                axum::http::HeaderValue::from_bytes(bytes).expect("test header value"),
            );
        }
        super::RequestHeaders::parse(&map)
    }

    #[cfg(feature = "server")]
    #[test]
    fn two_authorization_headers_refused() {
        assert!(matches!(
            fold(&[
                ("authorization", b"Bearer a"),
                ("authorization", b"Bearer b")
            ]),
            Err(super::HeaderRefusal::DuplicateSingleton)
        ));
        let one = fold(&[("authorization", b"Bearer a")]).expect("one copy is admitted");
        assert_eq!(one.get("Authorization"), Some("Bearer a"));
    }

    #[cfg(feature = "server")]
    #[test]
    fn two_host_headers_refused() {
        assert!(matches!(
            fold(&[("host", b"a.example"), ("host", b"b.example")]),
            Err(super::HeaderRefusal::DuplicateSingleton)
        ));
    }

    /// A name outside the arity table is a singleton: a repeat is refused.
    #[cfg(feature = "server")]
    #[test]
    fn two_unknown_headers_refused() {
        assert!(matches!(
            fold(&[("x-tenant", b"a"), ("x-tenant", b"b")]),
            Err(super::HeaderRefusal::DuplicateSingleton)
        ));
    }

    /// An undecodable copy is judged from its bytes, so it neither vanishes
    /// nor hides the decodable copy beside it; alone it refuses too.
    #[cfg(feature = "server")]
    #[test]
    fn undecodable_copy_does_not_hide_duplicate() {
        assert!(
            fold(&[
                ("authorization", b"\xC3\xA9"),
                ("authorization", b"Bearer x")
            ])
            .is_err()
        );
        assert!(matches!(
            fold(&[("authorization", b"\xC3\xA9")]),
            Err(super::HeaderRefusal::NotVisibleAscii)
        ));
        assert!(matches!(
            fold(&[("accept", b"a"), ("accept", b"\xC3\xA9")]),
            Err(super::HeaderRefusal::NotVisibleAscii)
        ));
    }

    #[cfg(feature = "server")]
    #[test]
    fn list_header_combined_in_order() {
        let folded = fold(&[("accept", b"a"), ("accept", b"b")]).expect("list copies combine");
        assert_eq!(folded.get("Accept"), Some("a, b"));
    }

    /// A split cookie header, even one carrying a non-ASCII pair, is left to
    /// the cookie parser and never enters the dict.
    #[cfg(feature = "server")]
    #[test]
    fn split_cookie_header_admitted() {
        let folded = fold(&[("cookie", b"a=1"), ("cookie", b"b=\xC3\xA9")])
            .expect("a split cookie header is admitted");
        assert!(!folded.as_dict().contains_key("Cookie"));
    }

    #[cfg(feature = "http_client")]
    #[test]
    fn refusal_text_names_no_header() {
        for refusal in [
            super::HeaderRefusal::DuplicateSingleton,
            super::HeaderRefusal::NotVisibleAscii,
        ] {
            let text = refusal.response_text();
            assert!(!text.contains("Authorization"), "{text}");
            assert!(!text.contains("Content-Type"), "{text}");
        }
    }

    /// Repeated `Set-Cookie` in a response keeps its last decodable copy and
    /// never refuses; a repeated singleton does.
    #[cfg(feature = "http_client")]
    #[test]
    fn response_set_cookie_keeps_last_decodable_copy() {
        let dict = super::response_headers([
            ("set-cookie", b"a=1".as_slice()),
            ("set-cookie", b"b=2".as_slice()),
            ("set-cookie", b"c=\xC3\xA9".as_slice()),
        ])
        .expect("repeated Set-Cookie is admitted");
        assert_eq!(dict.get("Set-Cookie").map(String::as_str), Some("b=2"));
        assert_eq!(
            super::response_headers([
                ("content-type", b"a".as_slice()),
                ("content-type", b"b".as_slice()),
            ]),
            Err(super::HeaderRefusal::DuplicateSingleton)
        );
    }
}

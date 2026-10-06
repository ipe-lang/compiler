//! `Ipe.Url` — a typed, opaque URL (parse-don't-validate).
//!
//! The ONLY way to obtain a `Url` is through [`url_from_string`] (the seal): it
//! parses the raw string with the `url` crate — the SAME parser
//! `ipe_runtime::ssrf` uses to validate outbound-request targets (`reqwest::Url`
//! is `pub use url::Url`), so the type boundary and the SSRF guard share one
//! canonical parse and cannot diverge on what counts as a valid URL.
//!
//! A `Url` is always ABSOLUTE: `url::Url::parse` rejects a scheme-less / relative
//! string (`"/path"`, `"example.com"`), so a value of this type always carries a
//! scheme and (for a hierarchical scheme) a host. This is the property the SSRF
//! guard depends on — a host to check — so making it a construction invariant
//! means downstream code never re-encounters a scheme-confused or hostless URL.
//!
//! The `Url.Builder` primitive [`url_build_query`] percent-encodes every key and
//! value through the `url` crate's `form_urlencoded` serializer, so a caller
//! building a query string cannot forget to encode a metacharacter (`&`, `=`,
//! ` `, `#`) — closing the query-injection footgun that raw string-concatenation
//! leaves open.
//!
//! # Trust model — what `Url` does and does NOT guarantee
//!
//! `Url` guarantees the string is a syntactically valid absolute URL with a
//! scheme. It deliberately does NOT decide whether that URL is SAFE to fetch —
//! an `http://169.254.169.254/` is a perfectly valid `Url`. The SSRF
//! scheme-allowlist and private-IP-deny policy (`ipe_runtime::ssrf`) is the
//! separate runtime authority over which validated URLs an outbound request may
//! actually reach; `Url` is the syntactic parse boundary that feeds it.

use super::IpeResult;
use crate::core::IpeMaybe;
use url::{Url as UrlCrate, form_urlencoded};

/// `Ipe.Url`'s opaque, validated newtype. See the module doc for the
/// construction contract. The wrapped `url::Url` is always an absolute,
/// scheme-carrying URL produced by [`url_from_string`].
///
/// `Clone` / `Debug` / `PartialEq` / `Eq` are derived on `url::Url` and safe: a
/// URL is not a secret, so printing or comparing it leaks nothing the caller did
/// not already hand in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url(UrlCrate);

// `Url.toString` keeps the full URL; an implicit rendering shows `shown`.
crate::stringify::show_row!("Url", Redacted, [] Url, |u| u.shown());

impl Url {
    /// The URL reduced to scheme, host, port and path.
    ///
    /// Userinfo, query and fragment, where credentials and tokens travel, never
    /// appear. The parser ends the authority at the first `/`, `?` or `#` (and,
    /// under a special scheme, `\`), so a credential holding one of them
    /// spills out of the userinfo: `user:pw@host` parses with scheme `user`,
    /// no host and path `pw@host`, and `https://u:1/pw@host` with host `u`.
    /// The `@` that ended the userinfo stays literal in the path, query or
    /// fragment it spilled into. With no host, or an `@` or `\` past the
    /// authority, only the scheme is shown. A scheme outside
    /// [`NAMEABLE_SCHEMES`] may be a user name, so it is withheld.
    fn shown(&self) -> String {
        use crate::stringify::REDACTED_SHOW;
        let scheme = match SchemeShown::of(self.0.scheme()) {
            SchemeShown::Known(scheme) => Some(scheme),
            SchemeShown::Withheld => None,
        };
        let spilled = [Some(self.0.path()), self.0.query(), self.0.fragment()]
            .into_iter()
            .flatten()
            .any(|part| part.contains(['@', '\\']));
        if self.0.host_str().is_none() || spilled {
            return scheme.map_or_else(
                || REDACTED_SHOW.to_owned(),
                |scheme| format!("{scheme}:{REDACTED_SHOW}"),
            );
        }
        let mut shown = self.0.clone();
        let _ = shown.set_password(None);
        let _ = shown.set_username("");
        shown.set_query(None);
        shown.set_fragment(None);
        let after_scheme = shown.as_str().strip_prefix(shown.scheme()).unwrap_or(":");
        format!("{}{after_scheme}", scheme.unwrap_or(REDACTED_SHOW))
    }
}

/// `Ipe.Url.fromString : String -> Result Error Url` — THE seal. The only public
/// constructor: every `Url` value in a Ipê program traces back to one of these
/// calls, so a reviewer can `grep` this one symbol to audit every place a raw
/// string becomes a typed URL.
///
/// Fails closed (`Err`) when the string is not a syntactically valid ABSOLUTE
/// URL — a relative reference (`"/path"`), a scheme-less host (`"example.com"`),
/// or otherwise unparseable input all surface as a typed `Err`, never a silent
/// accept. Succeeds with the parsed, normalised URL otherwise.
#[must_use]
pub fn url_from_string<E: From<String>>(s: String) -> IpeResult<E, Url> {
    match UrlCrate::parse(&s) {
        Ok(u) => IpeResult::Ok(Url(u)),
        // The input is not echoed: an unparseable URL may hold credentials the
        // parser never separated from the rest of the text.
        Err(e) => IpeResult::Err(format!("Ipe.Url: not a valid absolute URL ({e})").into()),
    }
}

/// `Ipe.Url.toString : Url -> String` — THE un-parse: recover the serialized URL
/// string. Consumes the `Url` (the typed proof is spent when the raw string
/// comes back out).
#[must_use]
pub fn url_to_string(u: Url) -> String {
    u.0.into()
}

/// `Ipe.Url.scheme : Url -> String` — the URL's scheme (`"https"`, `"http"`, …),
/// always lowercase and always present (an absolute URL has one).
#[must_use]
pub fn url_scheme(u: Url) -> String {
    u.0.scheme().to_string()
}

/// The schemes an error message may name.
///
/// `user:password@host` parses with the user name as its scheme, so a scheme
/// outside this well-known set is withheld rather than echoed.
const NAMEABLE_SCHEMES: [&str; 22] = [
    "http",
    "https",
    "ws",
    "wss",
    "ftp",
    "ftps",
    "sftp",
    "file",
    "data",
    "blob",
    "about",
    "javascript",
    "mailto",
    "tel",
    "gopher",
    "dict",
    "ldap",
    "ldaps",
    "ssh",
    "telnet",
    "postgres",
    "postgresql",
];

/// Stands in for a scheme that may be a user name or token.
const WITHHELD_SCHEME: &str = "<withheld: may be a user name>";

/// A URL's scheme as an error message may show it.
///
/// Holds no text read from the URL: only one of [`NAMEABLE_SCHEMES`] is named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemeShown {
    /// A well-known scheme.
    Known(&'static str),
    /// A scheme that may be part of the URL's credentials.
    Withheld,
}

impl SchemeShown {
    /// `scheme`, when it is well known; else withheld.
    #[must_use]
    pub fn of(scheme: &str) -> Self {
        NAMEABLE_SCHEMES
            .into_iter()
            .find(|known| known.eq_ignore_ascii_case(scheme))
            .map_or(Self::Withheld, Self::Known)
    }
}

impl std::fmt::Display for SchemeShown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Known(scheme) => write!(f, "{scheme:?}"),
            Self::Withheld => f.write_str(WITHHELD_SCHEME),
        }
    }
}

/// `Ipe.Url`'s private `schemeShown : Url -> String` — the scheme as an error
/// message may show it.
///
/// Backs `Ipe.Url.checkScheme`'s refusal, so the Ipê surface and the runtime's
/// outbound refusals name the same schemes and withhold the rest.
#[must_use]
pub fn url_scheme_shown(u: Url) -> String {
    SchemeShown::of(u.0.scheme()).to_string()
}

/// `Ipe.Url.host : Url -> Maybe String` — the host component (a registered name
/// or IP literal), or `Nothing` for a scheme whose URLs have no host (e.g.
/// `mailto:` / `data:`).
#[must_use]
pub fn url_host(u: Url) -> IpeMaybe<String> {
    match u.0.host_str() {
        Some(h) => IpeMaybe::Just(h.to_string()),
        None => IpeMaybe::Nothing,
    }
}

/// `Ipe.Url.port : Url -> Maybe Int` — the port, taking the scheme's known
/// default into account (`https://x` → `443`), or `Nothing` when neither an
/// explicit port nor a known default exists.
#[must_use]
pub fn url_port(u: Url) -> IpeMaybe<i64> {
    match u.0.port_or_known_default() {
        Some(p) => IpeMaybe::Just(i64::from(p)),
        None => IpeMaybe::Nothing,
    }
}

/// `Ipe.Url.path : Url -> String` — the path component (begins with `/` for a
/// hierarchical URL; `""` for a URL with no path).
#[must_use]
pub fn url_path(u: Url) -> String {
    u.0.path().to_string()
}

/// `Ipe.Url.query : Url -> Maybe String` — the raw query string (WITHOUT the
/// leading `?`), or `Nothing` when the URL has no query.
#[must_use]
pub fn url_query(u: Url) -> IpeMaybe<String> {
    match u.0.query() {
        Some(q) => IpeMaybe::Just(q.to_string()),
        None => IpeMaybe::Nothing,
    }
}

/// `Ipe.Url.fragment : Url -> Maybe String` — the fragment (WITHOUT the leading
/// `#`), or `Nothing` when the URL has no fragment.
#[must_use]
pub fn url_fragment(u: Url) -> IpeMaybe<String> {
    match u.0.fragment() {
        Some(f) => IpeMaybe::Just(f.to_string()),
        None => IpeMaybe::Nothing,
    }
}

/// `Ipe.Url.Builder.queryString : List (String, String) -> String` — the
/// injection-safe query-string builder. Percent-encodes EVERY key and value
/// through the `url` crate's `form_urlencoded` serializer, so a caller cannot
/// forget to encode a metacharacter: an `&` / `=` / space / `#` in a value is
/// encoded, never emitted raw where it would split off a new parameter (a
/// query-injection). Returns the encoded string WITHOUT a leading `?`; the empty
/// list yields `""`.
#[must_use]
pub fn url_build_query(pairs: Vec<(String, String)>) -> String {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        ser.append_pair(&k, &v);
    }
    ser.finish()
}

/// `Ipe.Url`'s opaque, validated same-origin RELATIVE reference — the
/// path plus optional query plus optional fragment projection (RFC 3986 §4.2).
/// NOT a [`Url`]: a
/// `Url` is always absolute, a `UrlRelative` never carries a scheme or
/// authority. The ONLY constructor is [`url_relative`] (the seal): it re-uses
/// the `url` crate — the SAME parser [`url_from_string`] and `ipe_runtime::ssrf`
/// use — via `base.join`, so the relative-href boundary and the absolute-URL /
/// SSRF boundary cannot diverge on what parses.
///
/// The three components are stored already-extracted from the parsed result, so
/// the accessors are total field reads. `Clone` / `Debug` / `PartialEq` / `Eq`
/// are safe (a same-origin path is not a secret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlRelative {
    /// The path component — always present (`/`, `/a/b`, `./x` normalised).
    path: String,
    /// The raw query without the leading `?`, or `None`.
    query: Option<String>,
    /// The fragment without the leading `#`, or `None`.
    fragment: Option<String>,
}

// The reference string, identical to [`url_relative_to_string`].
crate::stringify::show_row!("UrlRelative", Value, [] UrlRelative, |r| r.render());

impl UrlRelative {
    /// Re-serialise the path + optional query + optional fragment triple. The single place
    /// the reference string is assembled, so `toString` and `IpeStringify` agree.
    fn render(&self) -> String {
        let mut out = self.path.clone();
        if let Some(q) = &self.query {
            out.push('?');
            out.push_str(q);
        }
        if let Some(f) = &self.fragment {
            out.push('#');
            out.push_str(f);
        }
        out
    }
}

/// The fixed same-origin base every relative reference is resolved against. Its
/// host is the reserved `.invalid` TLD (RFC 6761 §6.4 — guaranteed never to
/// resolve), so a bug that let an absolute or protocol-relative reference
/// through would point at a non-routable name, not a real attacker host. Only
/// the ORIGIN of a join result is compared against this, never fetched.
const RELATIVE_BASE: &str = "https://ipe-relative.invalid/";

/// `True` when `c` is an ASCII/Unicode control (code `0..=31` or `127`) — a
/// character a browser strips BEFORE scheme detection, so `ja\tvascript:` would
/// fold to `javascript:`. Rejecting on presence (never stripping) keeps the
/// smuggle unrepresentable rather than silently rewritten.
fn is_control(c: char) -> bool {
    let code = c as u32;
    code < 32 || code == 127
}

/// `True` when a `:` appears before the first `/` — the signature of an
/// absolute-URL scheme (`javascript:…`, `http:…`), where in a genuine relative
/// path a `:` may appear only inside a segment (after a `/`).
fn scheme_colon_before_slash(s: &str) -> bool {
    match s.split('/').next() {
        Some(before) => before.contains(':'),
        None => false,
    }
}

/// `Ipe.Url.relative : String -> Result Error Relative` — THE seal for a
/// same-origin relative reference. The ONLY [`UrlRelative`] constructor.
///
/// DEFENSE IN DEPTH, fail-closed. First the string-level guards (retained from
/// the predicate this kernel subsumes) reject, on PRESENCE, every shape a
/// browser could fold into a cross-origin or scheme-changing navigation: the
/// empty string, any control char, a leading protocol-relative `//`, any
/// backslash `\` (browsers fold `\`→`/`), and a `:` before the first `/` (an
/// absolute scheme). THEN the `url` crate resolves the survivor against a fixed
/// same-origin base and the result is accepted ONLY when it introduced no
/// scheme change and no authority — `joined.origin() == base.origin()`. Either
/// gate alone would reject the adversarial set; requiring both is the margin
/// that survives a single mistake. On success the parsed `path`/`query`/
/// `fragment` are extracted and stored.
#[must_use]
pub fn url_relative<E: From<String>>(raw: String) -> IpeResult<E, UrlRelative> {
    let reject = |why: &str| -> IpeResult<E, UrlRelative> {
        // The input is not echoed: a refused reference may carry userinfo.
        IpeResult::Err(format!("Ipe.Url: unsafe relative reference ({why})").into())
    };
    // ── String-level guards (fail-closed on presence, never strip). ──
    if raw.is_empty() {
        return reject("empty");
    }
    if raw.chars().any(is_control) {
        return reject("control character");
    }
    if raw.starts_with("//") {
        return reject("protocol-relative (leading //)");
    }
    if raw.contains('\\') {
        return reject("backslash (browsers fold \\ to /)");
    }
    if scheme_colon_before_slash(&raw) {
        return reject("scheme before first slash");
    }
    // ── url-crate resolution: same base, same origin, no scheme/authority. ──
    let base = match UrlCrate::parse(RELATIVE_BASE) {
        Ok(b) => b,
        // The base is a fixed valid literal; a parse failure is impossible, but
        // fail closed rather than unwrap.
        Err(_) => return reject("internal base parse"),
    };
    let joined = match base.join(&raw) {
        Ok(j) => j,
        Err(e) => return reject(&format!("does not resolve to a relative reference: {e}")),
    };
    // Any scheme change or authority introduction shows up as a different
    // origin; an equal origin proves the reference stayed same-origin.
    if joined.origin() != base.origin() || joined.scheme() != base.scheme() {
        return reject("resolves cross-origin or scheme-changing");
    }
    // A same-origin join can still differ in host only via userinfo/host the
    // origin check already caught; assert no host/userinfo survived for depth.
    if joined.username() != base.username() || joined.host_str() != base.host_str() {
        return reject("carries userinfo or host");
    }
    // Guard the OUTPUT projection, not just the input and the resolved origin.
    // `..`-normalisation can pop past root and leave the PATH beginning `//`
    // (`/..//evil.com` → path `//evil.com`): the resolved absolute URL's origin
    // is unchanged (the `//evil.com` is a path there, not an authority), so the
    // origin gate passes — but the reference this projects to (scheme + authority
    // stripped) is `//evil.com`, which a browser reads as PROTOCOL-RELATIVE in an
    // `href`/`src`. Reject on the rendered path's leading `//`, closing the gap
    // between the representation the gate checks and the one the sink emits. A
    // legitimate path with an INTERNAL `//` (`/a//b`) is unaffected.
    let path = joined.path().to_string();
    if path.starts_with("//") {
        return reject("projects to a protocol-relative reference (leading //)");
    }
    IpeResult::Ok(UrlRelative {
        path,
        query: joined.query().map(str::to_string),
        fragment: joined.fragment().map(str::to_string),
    })
}

/// `Ipe.Url.Relative.path : Relative -> String` — the path projection (always
/// present).
#[must_use]
pub fn url_relative_path(r: UrlRelative) -> String {
    r.path
}

/// `Ipe.Url.Relative.query : Relative -> Maybe String` — the query (no `?`), or
/// `Nothing`.
#[must_use]
pub fn url_relative_query(r: UrlRelative) -> IpeMaybe<String> {
    match r.query {
        Some(q) => IpeMaybe::Just(q),
        None => IpeMaybe::Nothing,
    }
}

/// `Ipe.Url.Relative.fragment : Relative -> Maybe String` — the fragment (no
/// `#`), or `Nothing`.
#[must_use]
pub fn url_relative_fragment(r: UrlRelative) -> IpeMaybe<String> {
    match r.fragment {
        Some(f) => IpeMaybe::Just(f),
        None => IpeMaybe::Nothing,
    }
}

/// `Ipe.Url.Relative.toString : Relative -> String` — recover the reference
/// string (path + optional query + optional fragment).
#[must_use]
pub fn url_relative_to_string(r: UrlRelative) -> String {
    r.render()
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    fn parse(s: &str) -> Url {
        match url_from_string::<String>(s.to_string()) {
            IpeResult::Ok(u) => u,
            IpeResult::Err(e) => panic!("expected {s:?} to be a valid Url, got Err: {e}"),
        }
    }

    // ── (a) a valid URL round-trips through parse → accessors → build ─────────

    #[test]
    fn valid_url_parses_and_exposes_typed_components() {
        let u = parse("https://user@example.com:8443/a/b?q=1#frag");
        assert_eq!(url_scheme(u.clone()), "https");
        assert_eq!(
            url_host(u.clone()),
            IpeMaybe::Just("example.com".to_string())
        );
        assert_eq!(url_port(u.clone()), IpeMaybe::Just(8443));
        assert_eq!(url_path(u.clone()), "/a/b");
        assert_eq!(url_query(u.clone()), IpeMaybe::Just("q=1".to_string()));
        assert_eq!(url_fragment(u), IpeMaybe::Just("frag".to_string()));
    }

    #[test]
    fn to_string_round_trips_the_parsed_url() {
        let raw = "https://example.com/a?x=1";
        assert_eq!(url_to_string(parse(raw)), raw);
    }

    #[test]
    fn port_falls_back_to_the_scheme_default() {
        // No explicit port → the known default for `https` is 443.
        assert_eq!(url_port(parse("https://example.com/")), IpeMaybe::Just(443));
    }

    // ── (b) an invalid / relative URL is a typed absence (Err) ───────────────

    #[test]
    fn relative_reference_is_rejected() {
        let r: IpeResult<String, Url> = url_from_string("/just/a/path".to_string());
        assert!(
            matches!(r, IpeResult::Err(_)),
            "a scheme-less relative reference must be a typed Err, never a silent accept"
        );
    }

    #[test]
    fn scheme_less_host_is_rejected() {
        let r: IpeResult<String, Url> = url_from_string("example.com/x".to_string());
        assert!(
            matches!(r, IpeResult::Err(_)),
            "a bare host with no scheme is not an absolute URL"
        );
    }

    #[test]
    fn garbage_is_rejected() {
        let r: IpeResult<String, Url> = url_from_string("not a url at all".to_string());
        assert!(matches!(r, IpeResult::Err(_)));
    }

    #[test]
    fn mailto_has_no_host() {
        // A `mailto:` URL is a valid absolute URL but carries no host component.
        assert_eq!(url_host(parse("mailto:a@b.com")), IpeMaybe::Nothing);
    }

    #[test]
    fn media_src_allowlist_rejects_anchor_schemes() {
        // A media `src` (`Ipe.Html.Attributes.imageSrc` / `Ipe.Ui.imageSrc`) is a
        // FETCH sink narrowed to `http`/`https` ONLY — a strictly tighter policy
        // than the navigation `href` allowlist, which also admits `mailto`/`tel`.
        // The `url` crate emits distinct normalised schemes for those anchor
        // targets, so the Ipê-side `mediaSchemes = ["http","https"]` membership
        // check has a concrete `"mailto"` / `"tel"` to turn away. Pin that the
        // scheme strings the media allowlist tests against are exactly these, so a
        // parser change that folded `tel:` into a network scheme would break the
        // build rather than silently open a media sink.
        let media_schemes = ["http", "https"];
        for good in ["http://example.com/i.png", "https://example.com/i.png"] {
            let s = url_scheme(parse(good));
            assert!(
                media_schemes.contains(&s.as_str()),
                "{good:?} scheme {s:?} must be in the media allowlist"
            );
        }
        for anchor in ["mailto:a@b.com", "tel:+15551234"] {
            let s = url_scheme(parse(anchor));
            assert!(
                !media_schemes.contains(&s.as_str()),
                "{anchor:?} scheme {s:?} is an anchor scheme and must NOT reach a media src"
            );
        }
        // The exact scheme strings, pinned so a normalisation regression is caught.
        assert_eq!(url_scheme(parse("mailto:a@b.com")), "mailto");
        assert_eq!(url_scheme(parse("tel:+15551234")), "tel");
    }

    // ── (b') the scheme is NORMALISED — the property the Ipê-side allowlist
    // (`Ipe.Url.checkScheme`) relies on. A lowercase allowlist can only be
    // evasion-proof if `url_scheme` lowercases and strips scheme control chars;
    // pin that here so a `url`-crate change that stopped normalising would break
    // the build, not silently open a `JavaScript:` / `ja\tvascript:` bypass at
    // every href/link/share sink.

    /// A user name parsed as the scheme is withheld; a well-known scheme is
    /// named, quoted, whatever its case.
    #[test]
    fn scheme_shown_names_only_a_well_known_scheme() {
        for raw in ["admin:s3cr3t@host", "apikey123:x@api.example", "ADMIN:pw@h"] {
            let shown = url_scheme_shown(parse(raw));
            assert_eq!(shown, WITHHELD_SCHEME, "{raw:?}");
            for secret in ["admin", "ADMIN", "s3cr3t", "apikey123", "pw"] {
                assert!(!shown.contains(secret), "{secret:?} leaked into {shown}");
            }
        }
        for (raw, shown) in [
            ("javascript:alert(1)", "\"javascript\""),
            ("FTP://files.example/", "\"ftp\""),
            ("https://example.com/", "\"https\""),
        ] {
            assert_eq!(url_scheme_shown(parse(raw)), shown, "{raw:?}");
        }
    }

    /// A refused string is never echoed: it may hold credentials the parser
    /// never separated from the rest of the text.
    #[test]
    fn refusals_never_echo_the_input() {
        for raw in [
            "http://admin:s3cr3t@exa mple.com/",
            "http://admin:s3cr3t@[bad/x",
        ] {
            let refused = url_from_string::<String>(raw.to_owned());
            assert!(matches!(refused, IpeResult::Err(_)), "{raw:?}");
            let IpeResult::Err(shown) = refused else {
                continue;
            };
            for secret in ["admin", "s3cr3t"] {
                assert!(!shown.contains(secret), "{secret:?} leaked into {shown}");
            }
        }
        for raw in [
            "//admin:s3cr3t@evil.example/",
            "https://admin:s3cr3t@evil.example/",
        ] {
            let refused = url_relative::<String>(raw.to_owned());
            assert!(matches!(refused, IpeResult::Err(_)), "{raw:?}");
            let IpeResult::Err(shown) = refused else {
                continue;
            };
            for secret in ["admin", "s3cr3t", "evil.example"] {
                assert!(!shown.contains(secret), "{secret:?} leaked into {shown}");
            }
        }
    }

    #[test]
    fn scheme_is_lowercased() {
        // Mixed-case schemes normalise to lowercase, so a `JavaScript:` cannot
        // evade a lowercase allowlist by case alone.
        assert_eq!(url_scheme(parse("HTTP://x.com")), "http");
        assert_eq!(url_scheme(parse("hTtPs://y.com")), "https");
        assert_eq!(url_scheme(parse("JavaScript:alert(1)")), "javascript");
    }

    #[test]
    fn control_chars_in_scheme_are_stripped() {
        // A tab / newline embedded in the scheme is stripped during parse, so
        // `ja\tvascript:` normalises to `javascript` — it cannot slip past a
        // `javascript`-denying allowlist as a distinct string.
        assert_eq!(url_scheme(parse("ja\tvascript:x")), "javascript");
        assert_eq!(url_scheme(parse("java\nscript:x")), "javascript");
    }

    // ── (c) the builder percent-encodes metacharacters (no injection) ────────

    #[test]
    fn builder_encodes_query_metacharacters_no_injection() {
        // A value containing `&`, `=`, ` ` and `#` must NOT be able to split off a
        // new parameter or terminate the query — every metacharacter is encoded.
        let q = url_build_query(vec![
            ("q".to_string(), "a&b=c d#e".to_string()),
            ("next".to_string(), "/dashboard".to_string()),
        ]);
        // No raw `&`/`=` from the value leaks into a parameter boundary: the only
        // `&` is the ONE the serializer put between the two pairs, and the only
        // `=` are the two key/value separators.
        assert_eq!(q.matches('&').count(), 1, "exactly one pair separator");
        assert_eq!(q.matches('=').count(), 2, "exactly one `=` per pair");
        assert!(
            !q.contains(' ') && !q.contains('#'),
            "space and `#` must be percent-encoded, never raw: {q}"
        );
        // The encoded value round-trips back to the original via a re-parse — the
        // proof that encoding is lossless, not lossy sanitisation.
        #[expect(
            clippy::disallowed_methods,
            reason = "test oracle: the serializer's own inverse; `url` builds without the strict core's `encoding` feature"
        )]
        let round: std::collections::HashMap<String, String> =
            form_urlencoded::parse(q.as_bytes()).into_owned().collect();
        assert_eq!(round.get("q").map(String::as_str), Some("a&b=c d#e"));
        assert_eq!(round.get("next").map(String::as_str), Some("/dashboard"));
    }

    #[test]
    fn builder_empty_list_is_empty_string() {
        assert_eq!(url_build_query(Vec::new()), "");
    }

    #[test]
    fn built_query_composes_into_a_valid_url() {
        // End-to-end: build a query, splice it, re-parse — the whole loop closes.
        let q = url_build_query(vec![("name".to_string(), "a b&c".to_string())]);
        let u = parse(&format!("https://example.com/search?{q}"));
        assert_eq!(url_query(u), IpeMaybe::Just(q));
    }

    // ── Url.relative — prove the refusals (the SSRF boundary) ────────────────

    fn rel(s: &str) -> IpeResult<String, UrlRelative> {
        url_relative(s.to_string())
    }
    fn is_err(s: &str) -> bool {
        matches!(rel(s), IpeResult::Err(_))
    }
    fn is_ok(s: &str) -> bool {
        matches!(rel(s), IpeResult::Ok(_))
    }

    /// Every adversarial reference — the exact set the deleted `isSafeRelativeRef`
    /// predicate turned away, plus the `join`-specific smuggles the crate move
    /// could otherwise wave through — is a typed `Err`, never a `Relative`.
    #[test]
    fn relative_rejects_every_adversarial_reference() {
        for bad in [
            "",                         // empty
            "javascript:alert(1)",      // script scheme
            "data:text/html,x",         // data scheme
            "file:///etc/passwd",       // file scheme
            "//evil.com",               // protocol-relative
            "/\\evil.com",              // backslash-folded protocol-relative
            "\\\\evil.com",             // backslash-folded protocol-relative
            "ja\tvascript:x",           // tab-smuggled scheme (control char)
            "java\nscript:x",           // newline-smuggled scheme (control char)
            "\u{09}javascript:",        // leading raw tab control
            "http://evil.com@good.com", // userinfo host confusion
            "https://evil.com/x",       // absolute cross-origin
            "foo:bar",                  // bare scheme-colon before slash
            "mailto:a@b.com",           // absolute non-web scheme
        ] {
            assert!(
                is_err(bad),
                "adversarial relative reference {bad:?} MUST be a typed Err"
            );
        }
    }

    /// The percent-encoded control-char smuggle stays same-origin. A leading
    /// `/%09javascript:x` resolves to an opaque same-origin path (no scheme
    /// introduced), so if accepted it renders back as that same path — it can
    /// never become a `javascript:` navigation. The bare `%09javascript:`
    /// (colon before slash) is rejected outright.
    #[test]
    fn percent_encoded_control_never_cross_origin() {
        if let IpeResult::Ok(r) = rel("/%09javascript:x") {
            // Whatever survives is a same-origin path, never a scheme.
            assert!(url_relative_path(r).starts_with('/'));
        }
        assert!(is_err("%09javascript:"));
    }

    /// Every valid same-origin reference is accepted and round-trips through
    /// `toString`.
    #[test]
    fn relative_accepts_and_round_trips_valid_references() {
        for good in [
            "/",
            "/static/x.css",
            "/a/b?q=1#top",
            "./page",
            "../up",
            "?tab=2",
            "#anchor",
        ] {
            assert!(is_ok(good), "valid relative reference {good:?} MUST be Ok");
        }
    }

    #[test]
    fn relative_extracts_path_query_fragment() {
        let r = match rel("/a/b?q=1#top") {
            IpeResult::Ok(r) => r,
            IpeResult::Err(e) => panic!("expected Ok, got {e}"),
        };
        assert_eq!(url_relative_path(r.clone()), "/a/b");
        assert_eq!(
            url_relative_query(r.clone()),
            IpeMaybe::Just("q=1".to_string())
        );
        assert_eq!(
            url_relative_fragment(r.clone()),
            IpeMaybe::Just("top".to_string())
        );
        assert_eq!(url_relative_to_string(r), "/a/b?q=1#top");
    }

    /// A `..`-traversal that pops past root MUST NOT project to a
    /// protocol-relative reference. `/..//evil.com` normalises to the PATH
    /// `//evil.com`; the resolved absolute URL's origin is unchanged (there the
    /// `//evil.com` is a path, not an authority), so the origin gate alone would
    /// wave it through — but the projected reference (`path` + optional query +
    /// fragment, scheme/authority stripped) is `//evil.com`, which a browser reads
    /// as a protocol-relative cross-origin navigation in an `href`/`src`. The
    /// output-projection guard rejects every shape that pops to a leading `//`.
    #[test]
    fn relative_traversal_to_protocol_relative_is_rejected() {
        for bad in [
            "/..//evil.com",
            "/../..//evil.com",
            "/x/..//evil.com",
            "/./..//evil.com",
            "/a/../..//evil.com",
            "/%2e%2e//evil.com",
            "/..//..//evil.com",
            "foo/..//evil.com",
            "/..//..//..//evil.com",
        ] {
            assert!(
                is_err(bad),
                "traversal-to-protocol-relative {bad:?} MUST be a typed Err, \
                 not a `//evil.com` reference"
            );
            // And no accepted reference ever renders with a leading `//`.
            if let IpeResult::Ok(r) = rel(bad) {
                assert!(
                    !url_relative_to_string(r).starts_with("//"),
                    "{bad:?} projected to a protocol-relative reference"
                );
            }
        }
        // A LEGITIMATE internal double-slash path stays accepted (not over-rejected).
        for good in ["/normal//double/seg", "/path//to//x", "/a/b?q=//y"] {
            assert!(
                is_ok(good),
                "legit internal `//` path {good:?} MUST stay Ok"
            );
            if let IpeResult::Ok(r) = rel(good) {
                assert!(!url_relative_to_string(r).starts_with("//"));
            }
        }
    }

    #[test]
    fn relative_query_and_fragment_only_round_trip() {
        let q = match rel("?tab=2") {
            IpeResult::Ok(r) => r,
            IpeResult::Err(e) => panic!("expected Ok, got {e}"),
        };
        assert_eq!(url_relative_to_string(q), "/?tab=2");
        let f = match rel("#anchor") {
            IpeResult::Ok(r) => r,
            IpeResult::Err(e) => panic!("expected Ok, got {e}"),
        };
        assert_eq!(url_relative_to_string(f), "/#anchor");
    }
}

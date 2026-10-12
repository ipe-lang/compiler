//! Proof that a cookieless page request may mint a session.
//!
//! A browser stamps every request with Fetch Metadata (`Sec-Fetch-Site`,
//! `Sec-Fetch-Mode`, `Sec-Fetch-Dest`). A session is minted only when that
//! metadata proves a top-level navigation, an embeddable frame navigation, or a
//! same-origin client-router navigation (`X-Ipe-Nav: 1`), or when the client
//! sends no Fetch Metadata at all. A cross-site subresource or frame request
//! never mints: no `init`, no session slot, no cookie.
//!
//! [`MintProof`] has one constructor, [`MintProof::judge`], so the only way the
//! page handler reaches a fresh session id is through a judged request.

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, VARY};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

const SEC_FETCH_SITE: &str = "sec-fetch-site";
const SEC_FETCH_MODE: &str = "sec-fetch-mode";
const SEC_FETCH_DEST: &str = "sec-fetch-dest";
const IPE_NAV: &str = "x-ipe-nav";

/// The request headers a page response's session outcome depends on.
const MINT_INPUTS: [&str; 4] = [
    "Sec-Fetch-Site",
    "Sec-Fetch-Mode",
    "Sec-Fetch-Dest",
    "X-Ipe-Nav",
];

/// The fixed body of a refused mint; it never echoes the request.
const REFUSED_BODY: &str = "{\"status\":\"session_mint_refused\"}";

/// Whether this app may be framed by a cross-origin ancestor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Embedding {
    /// A valid frame-ancestors allowlist is configured.
    Embeddable,
    /// No cross-origin framing is configured (or its value was refused).
    NotEmbeddable,
}

impl Embedding {
    /// The embedding mode the served app runs under.
    #[must_use]
    pub fn configured() -> Self {
        crate::telemetry::frame_ancestors().map_or(Self::NotEmbeddable, |_| Self::Embeddable)
    }
}

/// Why a cookieless page request was refused a session.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MintRefusal {
    /// A cross-site or same-site request that is not a navigation.
    CrossSiteSubresource,
    /// A frame navigation while the app is not embeddable.
    FrameNotEmbeddable,
    /// A same-origin request that is neither a navigation nor the client router.
    UnprovenSameOrigin,
    /// Partial, duplicated, non-ASCII, or unrecognised Fetch Metadata.
    Malformed,
}

/// Evidence that a request may mint a session.
#[derive(Debug)]
pub struct MintProof(());

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Site {
    SameOrigin,
    SameSite,
    CrossSite,
    None,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Navigate,
    SameOrigin,
    NoCors,
    Cors,
    WebSocket,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Dest {
    Document,
    Iframe,
    Frame,
    Empty,
    Other,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FetchMetadata {
    Absent,
    Present { site: Site, mode: Mode, dest: Dest },
}

/// One header's value: absent, unreadable (duplicated or non-ASCII), or its single line.
#[derive(Clone, Copy)]
enum Field<'a> {
    Absent,
    Unreadable,
    Value(&'a str),
}

fn field<'a>(headers: &'a HeaderMap, name: &str) -> Field<'a> {
    let mut lines = headers.get_all(name).iter();
    let Some(first) = lines.next() else {
        return Field::Absent;
    };
    if lines.next().is_some() {
        return Field::Unreadable;
    }
    first.to_str().map_or(Field::Unreadable, Field::Value)
}

impl Site {
    fn parse(token: &str) -> Self {
        match token {
            "same-origin" => Self::SameOrigin,
            "same-site" => Self::SameSite,
            "cross-site" => Self::CrossSite,
            "none" => Self::None,
            _ => Self::Unknown,
        }
    }
}

impl Mode {
    fn parse(token: &str) -> Self {
        match token {
            "navigate" => Self::Navigate,
            "same-origin" => Self::SameOrigin,
            "no-cors" => Self::NoCors,
            "cors" => Self::Cors,
            "websocket" => Self::WebSocket,
            _ => Self::Unknown,
        }
    }
}

impl Dest {
    fn parse(token: &str) -> Self {
        match token {
            "document" => Self::Document,
            "iframe" => Self::Iframe,
            "frame" => Self::Frame,
            "empty" => Self::Empty,
            _ => Self::Other,
        }
    }
}

impl FetchMetadata {
    /// `None` when some but not all three headers are present.
    fn parse(headers: &HeaderMap) -> Option<Self> {
        let site = field(headers, SEC_FETCH_SITE);
        let mode = field(headers, SEC_FETCH_MODE);
        let dest = field(headers, SEC_FETCH_DEST);
        match (site, mode, dest) {
            (Field::Absent, Field::Absent, Field::Absent) => Some(Self::Absent),
            (Field::Absent, _, _) | (_, Field::Absent, _) | (_, _, Field::Absent) => None,
            (site, mode, dest) => Some(Self::Present {
                site: read(site, Site::parse, Site::Unknown),
                mode: read(mode, Mode::parse, Mode::Unknown),
                dest: read(dest, Dest::parse, Dest::Unknown),
            }),
        }
    }
}

fn read<T>(value: Field<'_>, parse: fn(&str) -> T, unknown: T) -> T {
    match value {
        Field::Value(token) => parse(token),
        Field::Absent | Field::Unreadable => unknown,
    }
}

/// True only for exactly one `X-Ipe-Nav` line whose value is `1`.
fn client_router(headers: &HeaderMap) -> bool {
    matches!(field(headers, IPE_NAV), Field::Value("1"))
}

impl MintProof {
    /// Judge whether a cookieless page request may mint a session.
    ///
    /// # Errors
    ///
    /// The [`MintRefusal`] naming why the request's Fetch Metadata does not
    /// prove a first-party arrival.
    pub fn judge(headers: &HeaderMap, embedding: Embedding) -> Result<Self, MintRefusal> {
        let Some(metadata) = FetchMetadata::parse(headers) else {
            return Err(MintRefusal::Malformed);
        };
        let FetchMetadata::Present { site, mode, dest } = metadata else {
            return Ok(Self(()));
        };
        if site == Site::Unknown || mode == Mode::Unknown || dest == Dest::Unknown {
            return Err(MintRefusal::Malformed);
        }
        match (site, mode, dest) {
            (_, Mode::Navigate, Dest::Document) => Ok(Self(())),
            (_, Mode::Navigate, Dest::Iframe | Dest::Frame) => match embedding {
                Embedding::Embeddable => Ok(Self(())),
                Embedding::NotEmbeddable => Err(MintRefusal::FrameNotEmbeddable),
            },
            (Site::SameOrigin, _, _) if client_router(headers) => Ok(Self(())),
            (Site::SameOrigin, _, _) => Err(MintRefusal::UnprovenSameOrigin),
            (
                Site::SameSite | Site::CrossSite | Site::None | Site::Unknown,
                Mode::Navigate
                | Mode::SameOrigin
                | Mode::NoCors
                | Mode::Cors
                | Mode::WebSocket
                | Mode::Unknown,
                Dest::Document
                | Dest::Iframe
                | Dest::Frame
                | Dest::Empty
                | Dest::Other
                | Dest::Unknown,
            ) => Err(MintRefusal::CrossSiteSubresource),
        }
    }
}

/// The 403 a refused mint answers with: a fixed body, no cookie, never cached.
#[must_use]
pub fn refused(_why: MintRefusal) -> Response {
    (
        StatusCode::FORBIDDEN,
        [
            (CONTENT_TYPE, "application/json"),
            (CACHE_CONTROL, "no-store"),
        ],
        REFUSED_BODY,
    )
        .into_response()
}

/// Merge the mint inputs into `headers`' `Vary`.
///
/// A `Vary` that already names `*` stays as is; a name already listed (in any
/// case) is not repeated. An unreadable existing `Vary` becomes `*`, the
/// variant no cache can reuse wrongly.
pub fn vary_on_mint_inputs(headers: &mut HeaderMap) {
    let mut tokens: Vec<String> = Vec::new();
    for line in headers.get_all(VARY) {
        let Ok(text) = line.to_str() else {
            headers.insert(VARY, HeaderValue::from_static("*"));
            return;
        };
        tokens.extend(
            text.split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_owned),
        );
    }
    if tokens.iter().any(|t| t == "*") {
        return;
    }
    for name in MINT_INPUTS {
        if !tokens.iter().any(|t| t.eq_ignore_ascii_case(name)) {
            tokens.push(name.to_owned());
        }
    }
    let merged =
        HeaderValue::from_str(&tokens.join(", ")).unwrap_or_else(|_| HeaderValue::from_static("*"));
    headers.insert(VARY, merged);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One `mint_refusals` row: the three Fetch Metadata values, the extra
    /// lines, and the verdict.
    struct Row {
        site: Option<&'static str>,
        mode: Option<&'static str>,
        dest: Option<&'static str>,
        ipe_nav: bool,
        duplicate_mode: bool,
        embedding: Embedding,
        verdict: Result<(), MintRefusal>,
    }

    const fn row(
        site: Option<&'static str>,
        mode: Option<&'static str>,
        dest: Option<&'static str>,
        verdict: Result<(), MintRefusal>,
    ) -> Row {
        Row {
            site,
            mode,
            dest,
            ipe_nav: false,
            duplicate_mode: false,
            embedding: Embedding::NotEmbeddable,
            verdict,
        }
    }

    fn headers_for(r: &Row) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (name, value) in [
            (SEC_FETCH_SITE, r.site),
            (SEC_FETCH_MODE, r.mode),
            (SEC_FETCH_DEST, r.dest),
        ] {
            if let Some(v) = value {
                h.append(name, HeaderValue::from_static(v));
            }
        }
        if r.duplicate_mode {
            h.append(SEC_FETCH_MODE, HeaderValue::from_static("navigate"));
        }
        if r.ipe_nav {
            h.insert(IPE_NAV, HeaderValue::from_static("1"));
        }
        h
    }

    fn verdict(h: &HeaderMap, embedding: Embedding) -> Result<(), MintRefusal> {
        MintProof::judge(h, embedding).map(|_| ())
    }

    /// Prove the refusals: every subresource, unembeddable frame, unproven
    /// same-origin, and malformed shape is refused with its exact reason, and
    /// the four first-party shapes are admitted.
    #[test]
    fn mint_refusals() {
        use MintRefusal::{
            CrossSiteSubresource, FrameNotEmbeddable, Malformed, UnprovenSameOrigin,
        };
        let cs = Some("cross-site");
        let so = Some("same-origin");
        let rows = [
            row(
                cs,
                Some("no-cors"),
                Some("image"),
                Err(CrossSiteSubresource),
            ),
            row(cs, Some("cors"), Some("empty"), Err(CrossSiteSubresource)),
            row(
                Some("same-site"),
                Some("no-cors"),
                Some("script"),
                Err(CrossSiteSubresource),
            ),
            row(
                cs,
                Some("navigate"),
                Some("iframe"),
                Err(FrameNotEmbeddable),
            ),
            row(cs, Some("navigate"), Some("frame"), Err(FrameNotEmbeddable)),
            row(so, Some("cors"), Some("empty"), Err(UnprovenSameOrigin)),
            Row {
                ipe_nav: true,
                ..row(cs, Some("cors"), Some("empty"), Err(CrossSiteSubresource))
            },
            Row {
                duplicate_mode: true,
                ..row(cs, Some("navigate"), Some("document"), Err(Malformed))
            },
            row(
                Some("cross-origin"),
                Some("navigate"),
                Some("document"),
                Err(Malformed),
            ),
            row(cs, Some("Navigate"), Some("document"), Err(Malformed)),
            row(cs, None, None, Err(Malformed)),
            row(None, Some("navigate"), Some("document"), Err(Malformed)),
            // Admitted: no Fetch Metadata at all.
            row(None, None, None, Ok(())),
            // Admitted: a top-level navigation from any site.
            row(cs, Some("navigate"), Some("document"), Ok(())),
            // Admitted: a frame navigation while embeddable.
            Row {
                embedding: Embedding::Embeddable,
                ..row(cs, Some("navigate"), Some("iframe"), Ok(()))
            },
            // Admitted: the same-origin client router.
            Row {
                ipe_nav: true,
                ..row(so, Some("cors"), Some("empty"), Ok(()))
            },
        ];
        for (i, r) in rows.iter().enumerate() {
            let h = headers_for(r);
            assert_eq!(verdict(&h, r.embedding), r.verdict, "row {i}: {h:?}");
        }
    }

    /// A non-ASCII value and an `X-Ipe-Nav` other than one `1` line prove nothing.
    #[test]
    #[allow(clippy::expect_used)] // test fixture: the literal bytes are a valid header value
    fn unreadable_values_never_prove() {
        let mut h = HeaderMap::new();
        h.insert(SEC_FETCH_SITE, HeaderValue::from_static("same-origin"));
        h.insert(SEC_FETCH_MODE, HeaderValue::from_static("cors"));
        h.insert(
            SEC_FETCH_DEST,
            HeaderValue::from_bytes(b"empt\xc3\xa9").expect("an opaque header value"),
        );
        h.insert(IPE_NAV, HeaderValue::from_static("1"));
        assert_eq!(
            verdict(&h, Embedding::Embeddable),
            Err(MintRefusal::Malformed)
        );

        h.insert(SEC_FETCH_DEST, HeaderValue::from_static("empty"));
        assert_eq!(verdict(&h, Embedding::Embeddable), Ok(()));
        h.append(IPE_NAV, HeaderValue::from_static("1"));
        assert_eq!(
            verdict(&h, Embedding::Embeddable),
            Err(MintRefusal::UnprovenSameOrigin)
        );
        h.insert(IPE_NAV, HeaderValue::from_static("true"));
        assert_eq!(
            verdict(&h, Embedding::Embeddable),
            Err(MintRefusal::UnprovenSameOrigin)
        );
    }

    fn vary_of(h: &HeaderMap) -> Vec<&str> {
        h.get_all(VARY)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect()
    }

    /// `Vary` gains every mint input once, keeps what it named, and leaves `*` alone.
    #[test]
    fn vary_merges_with_existing_values() {
        let mut h = HeaderMap::new();
        vary_on_mint_inputs(&mut h);
        assert_eq!(
            vary_of(&h),
            ["Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, X-Ipe-Nav"]
        );

        let mut h = HeaderMap::new();
        h.append(VARY, HeaderValue::from_static("Accept-Encoding"));
        h.append(VARY, HeaderValue::from_static("sec-fetch-mode, Origin"));
        vary_on_mint_inputs(&mut h);
        assert_eq!(
            vary_of(&h),
            ["Accept-Encoding, sec-fetch-mode, Origin, Sec-Fetch-Site, Sec-Fetch-Dest, X-Ipe-Nav"]
        );

        let mut h = HeaderMap::new();
        h.append(VARY, HeaderValue::from_static("Origin, *"));
        vary_on_mint_inputs(&mut h);
        assert_eq!(vary_of(&h), ["Origin, *"]);

        let mut h = HeaderMap::new();
        vary_on_mint_inputs(&mut h);
        vary_on_mint_inputs(&mut h);
        assert_eq!(
            vary_of(&h),
            ["Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, X-Ipe-Nav"]
        );
    }

    /// An unreadable existing `Vary` fails closed to `*`.
    #[test]
    #[allow(clippy::expect_used)] // test fixture: the literal bytes are a valid header value
    fn unreadable_vary_becomes_star() {
        let mut h = HeaderMap::new();
        h.append(
            VARY,
            HeaderValue::from_bytes(b"Orig\xc3\xadn").expect("an opaque header value"),
        );
        vary_on_mint_inputs(&mut h);
        assert_eq!(vary_of(&h), ["*"]);
    }
}

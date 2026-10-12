//! Proof that a cookieless page request may mint a session.
//!
//! A browser stamps every request with Fetch Metadata (`Sec-Fetch-Site`,
//! `Sec-Fetch-Mode`, `Sec-Fetch-Dest`). A session is minted only when that
//! metadata proves a top-level navigation, a same-origin frame navigation (the
//! framing every page response's `X-Frame-Options: SAMEORIGIN` admits), a frame
//! navigation while the app is embeddable, or a same-origin client-router
//! navigation (`X-Ipe-Nav: 1`), or when the client sends no Fetch Metadata at
//! all. A cross-site subresource or frame request never mints: no `init`, no
//! session slot, no cookie.
//!
//! A request carrying a session cookie is judged by the same parse: a
//! cross-site or same-site subresource, a frame navigation while not
//! embeddable, malformed metadata, or (while the cookie is `SameSite=None`) no
//! metadata at all is refused before any session lookup.
//!
//! [`Arrival`] parses the metadata once; [`Arrival::mint`] is the one
//! constructor of [`MintProof`] and [`Arrival::rejoin`] of [`RejoinProof`], so
//! neither the page handler nor the SSE stream reaches a fresh session id or a
//! cookie's session except through a judged request.

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
    /// A same-site or cross-site frame navigation while the app is not embeddable.
    FrameNotEmbeddable,
    /// A same-origin request that is neither a navigation nor the client router.
    UnprovenSameOrigin,
    /// Partial, duplicated, non-ASCII, or unrecognised Fetch Metadata.
    Malformed,
}

/// Evidence that a request may mint a session.
#[derive(Debug)]
pub struct MintProof(());

/// The `Sec-Fetch-Site` value; `User` is `none`, an arrival the user started.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Initiator {
    SameOrigin,
    SameSite,
    CrossSite,
    User,
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
    Present {
        site: Initiator,
        mode: Mode,
        dest: Dest,
    },
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

impl Initiator {
    fn parse(token: &str) -> Self {
        match token {
            "same-origin" => Self::SameOrigin,
            "same-site" => Self::SameSite,
            "cross-site" => Self::CrossSite,
            "none" => Self::User,
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
                site: read(site, Initiator::parse, Initiator::Unknown),
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

/// A page request's Fetch Metadata, parsed once into the arrival it proves.
///
/// Both session outcomes are judged from it: [`Arrival::rejoin`] admits a
/// cookie's session key, [`Arrival::mint`] a fresh session.
pub struct Arrival {
    shape: Shape,
    embedding: Embedding,
}

/// What a request's Fetch Metadata proves about where it came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Shape {
    /// No Fetch Metadata header at all.
    Absent,
    /// Partial, duplicated, non-ASCII, or unrecognised Fetch Metadata.
    Malformed,
    /// A top-level navigation from any site.
    TopLevel,
    /// A same-origin frame navigation.
    SameOriginFrame,
    /// A same-site, cross-site, or user-started frame navigation.
    ForeignFrame,
    /// A same-origin request carrying the client router's `X-Ipe-Nav: 1`.
    ClientRouter,
    /// Any other same-origin request.
    SameOriginOther,
    /// A same-site, cross-site, or user-started request that is not a navigation.
    Subresource,
}

impl Shape {
    fn parse(headers: &HeaderMap) -> Self {
        let Some(metadata) = FetchMetadata::parse(headers) else {
            return Self::Malformed;
        };
        let FetchMetadata::Present { site, mode, dest } = metadata else {
            return Self::Absent;
        };
        if site == Initiator::Unknown || mode == Mode::Unknown || dest == Dest::Unknown {
            return Self::Malformed;
        }
        match (site, mode, dest) {
            (_, Mode::Navigate, Dest::Document) => Self::TopLevel,
            (Initiator::SameOrigin, Mode::Navigate, Dest::Iframe | Dest::Frame) => {
                Self::SameOriginFrame
            }
            (_, Mode::Navigate, Dest::Iframe | Dest::Frame) => Self::ForeignFrame,
            (Initiator::SameOrigin, _, _) if client_router(headers) => Self::ClientRouter,
            (Initiator::SameOrigin, _, _) => Self::SameOriginOther,
            (
                Initiator::SameSite | Initiator::CrossSite | Initiator::User | Initiator::Unknown,
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
            ) => Self::Subresource,
        }
    }
}

/// Why a page request carrying a session cookie was refused its session.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RejoinRefusal {
    /// A same-site, cross-site, or user-started request that is not a navigation.
    CrossSiteSubresource,
    /// A same-site or cross-site frame navigation while the app is not embeddable.
    FrameNotEmbeddable,
    /// No Fetch Metadata while the cookie is `SameSite=None`.
    Unattested,
    /// Partial, duplicated, non-ASCII, or unrecognised Fetch Metadata.
    Malformed,
}

/// Evidence that a request may act on the session its cookie names.
///
/// It holds that session's key, the only one the page handler or the SSE
/// stream looks up; it derives no `Debug`.
pub struct RejoinProof(crate::web::store::SessionKey);

impl RejoinProof {
    /// The admitted session key.
    #[must_use]
    pub fn into_key(self) -> crate::web::store::SessionKey {
        self.0
    }
}

impl Arrival {
    /// Parse a page request's Fetch Metadata under the app's embedding mode.
    #[must_use]
    pub fn judge(headers: &HeaderMap, embedding: Embedding) -> Self {
        Self {
            shape: Shape::parse(headers),
            embedding,
        }
    }

    /// Judge whether this request may act on the session `key` names.
    ///
    /// # Errors
    ///
    /// The [`RejoinRefusal`] naming why the request does not prove a
    /// first-party arrival.
    pub fn rejoin(&self, key: crate::web::store::SessionKey) -> Result<RejoinProof, RejoinRefusal> {
        match (self.shape, self.embedding) {
            (Shape::Absent, Embedding::NotEmbeddable)
            | (
                Shape::TopLevel
                | Shape::SameOriginFrame
                | Shape::ClientRouter
                | Shape::SameOriginOther,
                _,
            )
            | (Shape::ForeignFrame, Embedding::Embeddable) => Ok(RejoinProof(key)),
            (Shape::Absent, Embedding::Embeddable) => Err(RejoinRefusal::Unattested),
            (Shape::Malformed, _) => Err(RejoinRefusal::Malformed),
            (Shape::ForeignFrame, Embedding::NotEmbeddable) => {
                Err(RejoinRefusal::FrameNotEmbeddable)
            }
            (Shape::Subresource, _) => Err(RejoinRefusal::CrossSiteSubresource),
        }
    }

    /// Judge whether this request may mint a session.
    ///
    /// # Errors
    ///
    /// The [`MintRefusal`] naming why the request does not prove a
    /// first-party arrival.
    pub const fn mint(&self) -> Result<MintProof, MintRefusal> {
        match (self.shape, self.embedding) {
            (Shape::Absent | Shape::TopLevel | Shape::SameOriginFrame | Shape::ClientRouter, _)
            | (Shape::ForeignFrame, Embedding::Embeddable) => Ok(MintProof(())),
            (Shape::Malformed, _) => Err(MintRefusal::Malformed),
            (Shape::ForeignFrame, Embedding::NotEmbeddable) => Err(MintRefusal::FrameNotEmbeddable),
            (Shape::SameOriginOther, _) => Err(MintRefusal::UnprovenSameOrigin),
            (Shape::Subresource, _) => Err(MintRefusal::CrossSiteSubresource),
        }
    }
}

/// The fixed 403 a refused session answers with: no cookie, never cached.
fn forbidden() -> Response {
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

/// The 403 a refused rejoin answers with, the same fixed response as a refused mint.
#[must_use]
pub fn refused_rejoin(_why: RejoinRefusal) -> Response {
    forbidden()
}

/// The 403 a refused mint answers with: a fixed body, no cookie, never cached.
#[must_use]
pub fn refused(_why: MintRefusal) -> Response {
    forbidden()
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
        Arrival::judge(h, embedding).mint().map(|_| ())
    }

    /// Prove the refusals: every subresource, unembeddable frame, unproven
    /// same-origin, and malformed shape is refused with its exact reason, and
    /// every first-party shape is admitted.
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
            row(
                Some("same-site"),
                Some("navigate"),
                Some("iframe"),
                Err(FrameNotEmbeddable),
            ),
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
            // Admitted: a same-origin frame navigation, the framing the page's
            // `X-Frame-Options: SAMEORIGIN` already allows.
            row(so, Some("navigate"), Some("iframe"), Ok(())),
            row(so, Some("navigate"), Some("frame"), Ok(())),
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

    /// A [`Row`] read only for its headers.
    const fn shape(
        site: Option<&'static str>,
        mode: Option<&'static str>,
        dest: Option<&'static str>,
    ) -> Row {
        row(site, mode, dest, Ok(()))
    }

    /// The rejoin verdict for `r`'s headers under `embedding`.
    fn rejoin_verdict(r: &Row, embedding: Embedding) -> Option<Result<(), RejoinRefusal>> {
        let key =
            crate::web::store::SessionKey::parse(&"a".repeat(crate::web::store::SESSION_ID_LEN))?;
        Some(
            Arrival::judge(&headers_for(r), embedding)
                .rejoin(key)
                .map(|_| ()),
        )
    }

    /// Prove the rejoin refusals: under each embedding mode, every
    /// subresource, malformed shape, unembeddable frame and (while embeddable)
    /// metadata-less request is refused with its exact reason, beside the
    /// admitted first-party shapes.
    #[test]
    fn rejoin_refusals() {
        use Embedding::{Embeddable, NotEmbeddable};
        use RejoinRefusal::{CrossSiteSubresource, FrameNotEmbeddable, Malformed, Unattested};
        let cs = Some("cross-site");
        let ss = Some("same-site");
        let so = Some("same-origin");
        let ok: Result<(), RejoinRefusal> = Ok(());
        let sub = Err(CrossSiteSubresource);
        // (headers, not-embeddable verdict, embeddable verdict)
        let rows = [
            (shape(cs, Some("no-cors"), Some("image")), sub, sub),
            (shape(ss, Some("no-cors"), Some("image")), sub, sub),
            (shape(cs, Some("cors"), Some("empty")), sub, sub),
            (
                shape(Some("none"), Some("no-cors"), Some("image")),
                sub,
                sub,
            ),
            (
                Row {
                    ipe_nav: true,
                    ..shape(cs, Some("cors"), Some("empty"))
                },
                sub,
                sub,
            ),
            (
                shape(cs, Some("navigate"), Some("iframe")),
                Err(FrameNotEmbeddable),
                ok,
            ),
            (
                shape(ss, Some("navigate"), Some("frame")),
                Err(FrameNotEmbeddable),
                ok,
            ),
            (shape(None, None, None), ok, Err(Unattested)),
            (shape(cs, None, None), Err(Malformed), Err(Malformed)),
            (
                Row {
                    duplicate_mode: true,
                    ..shape(so, Some("navigate"), Some("document"))
                },
                Err(Malformed),
                Err(Malformed),
            ),
            (
                shape(Some("cross-origin"), Some("navigate"), Some("document")),
                Err(Malformed),
                Err(Malformed),
            ),
            // Admitted in both modes: a top-level navigation, a same-origin
            // frame, and any same-origin request (client router or not).
            (shape(cs, Some("navigate"), Some("document")), ok, ok),
            (shape(so, Some("navigate"), Some("iframe")), ok, ok),
            (shape(so, Some("cors"), Some("empty")), ok, ok),
            (
                Row {
                    ipe_nav: true,
                    ..shape(so, Some("cors"), Some("empty"))
                },
                ok,
                ok,
            ),
        ];
        for (i, (r, not_embeddable, embeddable)) in rows.iter().enumerate() {
            assert_eq!(
                rejoin_verdict(r, NotEmbeddable),
                Some(*not_embeddable),
                "row {i}, not embeddable"
            );
            assert_eq!(
                rejoin_verdict(r, Embeddable),
                Some(*embeddable),
                "row {i}, embeddable"
            );
        }
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

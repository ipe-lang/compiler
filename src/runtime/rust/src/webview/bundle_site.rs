//! The desktop shell's bundle, served from memory under the shell's custom scheme.
//!
//! [`BundleSite::parse`] re-checks at startup the table the packer proved,
//! and [`BundleSite::respond`] answers one request: GET or HEAD on the exact
//! local origin, routed through [`bundle_route::route`], every answer carrying
//! its type, `nosniff`, `no-store`, `no-referrer` and the bundle's one policy.

use std::collections::HashMap;

use crate::app_data::{StorageKey, StorageKeyRefusal};
use crate::bundle_route::{self, MediaType, Route};
use crate::csp::{Directive, SchemeSpelling};
use crate::encoding::{BundlePath, BundlePathRefusal, MountBase, MountBaseRefusal};

/// The file a bundle opens on.
const INDEX: &str = "index.html";

/// One asset the shell embeds.
#[derive(Debug, Clone, Copy)]
pub struct SiteAsset {
    /// The bundle-relative path.
    pub path: &'static str,
    /// The asset's bytes.
    pub bytes: &'static [u8],
}

/// The table a shell crate embeds, as the packer wrote it.
#[derive(Debug, Clone, Copy)]
pub struct SiteConfig {
    /// The window title.
    pub title: &'static str,
    /// The bundle id the webview's storage is keyed by.
    pub storage_key: &'static str,
    /// The mount base the bundle is served at.
    pub base: &'static str,
    /// The `Content-Security-Policy` value every asset answers with.
    pub csp: &'static str,
    /// Every asset of the bundle.
    pub assets: &'static [SiteAsset],
}

/// Why an embedded table is not a [`BundleSite`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiteRefusal {
    /// An asset path is outside the bundle path grammar.
    Path(BundlePathRefusal),
    /// Two assets share a path.
    Duplicate,
    /// The base is no mount base.
    Base(MountBaseRefusal),
    /// The bundle holds no root `index.html`.
    NoIndex,
    /// The policy value does not parse as the runtime's policy.
    Csp,
    /// The bundle id is no storage key.
    StorageKey(StorageKeyRefusal),
}

impl std::fmt::Display for SiteRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Path(_) => f.write_str("an embedded asset path is outside the bundle grammar"),
            Self::Duplicate => f.write_str("two embedded assets share a path"),
            Self::Base(_) => f.write_str("the embedded mount base is malformed"),
            Self::NoIndex => f.write_str("the bundle holds no index.html"),
            Self::Csp => f.write_str("the embedded content security policy is malformed"),
            Self::StorageKey(refusal) => write!(f, "{refusal}"),
        }
    }
}

/// The request methods a site tells apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteMethod {
    /// `GET`.
    Get,
    /// `HEAD`: the headers of a GET, no body.
    Head,
    /// Every other method, answered 405.
    Other,
}

impl SiteMethod {
    /// Parse a request method; methods are case-sensitive.
    #[must_use]
    pub fn parse(method: &str) -> Self {
        match method {
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            _ => Self::Other,
        }
    }
}

/// The status a site answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteStatus {
    /// 200.
    Ok,
    /// 404.
    NotFound,
    /// 405.
    MethodNotAllowed,
}

impl SiteStatus {
    /// The numeric status code.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
        }
    }
}

/// `Content-Type`.
pub const CONTENT_TYPE: &str = "Content-Type";
/// `X-Content-Type-Options`.
pub const X_CONTENT_TYPE_OPTIONS: &str = "X-Content-Type-Options";
/// `Cache-Control`.
pub const CACHE_CONTROL: &str = "Cache-Control";
/// `Referrer-Policy`.
pub const REFERRER_POLICY: &str = "Referrer-Policy";
/// `Content-Security-Policy`.
pub const CONTENT_SECURITY_POLICY: &str = "Content-Security-Policy";
/// `Allow`.
pub const ALLOW: &str = "Allow";

/// One header, name and value, both checked visible ASCII.
pub type SiteHeader = (&'static str, &'static str);

/// One answer of a site.
#[derive(Clone, PartialEq, Eq)]
pub struct SiteResponse {
    /// The status.
    pub status: SiteStatus,
    /// The headers, in order.
    pub headers: Vec<SiteHeader>,
    /// The body: empty unless a GET found an asset.
    pub body: &'static [u8],
}

/// A bundle proven well-formed, answering requests on one exact origin.
#[derive(Debug, Clone)]
pub struct BundleSite {
    origin: SchemeSpelling,
    base: MountBase,
    assets: HashMap<BundlePath, &'static [u8]>,
    csp: &'static str,
    key: StorageKey,
    title: &'static str,
}

impl BundleSite {
    /// Parse `config` into a site answering on `origin`.
    ///
    /// # Errors
    /// The first [`SiteRefusal`] in order: the storage key, each path, a
    /// duplicate, the base, the root index, then the policy.
    pub fn parse(config: &SiteConfig, origin: SchemeSpelling) -> Result<Self, SiteRefusal> {
        let key = StorageKey::parse(config.storage_key).map_err(SiteRefusal::StorageKey)?;
        let mut assets = HashMap::with_capacity(config.assets.len());
        for asset in config.assets {
            let path = BundlePath::parse(asset.path).map_err(SiteRefusal::Path)?;
            if assets.insert(path, asset.bytes).is_some() {
                return Err(SiteRefusal::Duplicate);
            }
        }
        let base = MountBase::parse(config.base).map_err(SiteRefusal::Base)?;
        let has_index = BundlePath::parse(INDEX).is_ok_and(|index| assets.contains_key(&index));
        if !has_index {
            return Err(SiteRefusal::NoIndex);
        }
        if !policy_is_well_formed(config.csp) {
            return Err(SiteRefusal::Csp);
        }
        Ok(Self {
            origin,
            base,
            assets,
            csp: config.csp,
            key,
            title: config.title,
        })
    }

    /// The storage key the webview's data is kept under.
    #[must_use]
    pub const fn storage_key(&self) -> &StorageKey {
        &self.key
    }

    /// The window title.
    #[must_use]
    pub const fn title(&self) -> &'static str {
        self.title
    }

    /// The URL the window opens on: `spelling`'s origin, the base, then `index.html`.
    ///
    /// The window navigates in the platform's own spelling, which the engine
    /// hands the scheme handler back in the site's spelling.
    #[must_use]
    pub fn start_url(&self, spelling: SchemeSpelling) -> String {
        let index = BundlePath::parse(INDEX)
            .map_or_else(|_| self.base.dir_url(), |index| self.base.url_of(&index));
        format!("{}{index}", spelling.origin())
    }

    /// Answer `method` on `uri`.
    ///
    /// A URI off the exact origin, or a target the route refuses or misses,
    /// is a 404 with an empty body; a method other than GET or HEAD is a 405.
    #[must_use]
    pub fn respond(&self, method: &str, uri: &str) -> SiteResponse {
        let method = SiteMethod::parse(method);
        if method == SiteMethod::Other {
            return SiteResponse {
                status: SiteStatus::MethodNotAllowed,
                headers: vec![
                    (ALLOW, "GET, HEAD"),
                    (X_CONTENT_TYPE_OPTIONS, "nosniff"),
                    (CACHE_CONTROL, "no-store"),
                ],
                body: &[],
            };
        }
        let found = self.origin.local_target(uri).and_then(|target| {
            match bundle_route::route(&self.base, &target, |path| self.assets.contains_key(path)) {
                Route::Asset(path) | Route::Index(path) => self
                    .assets
                    .get(&path)
                    .map(|bytes| (MediaType::of(&path), *bytes)),
                Route::NotFound => None,
            }
        });
        let Some((media, bytes)) = found else {
            return SiteResponse {
                status: SiteStatus::NotFound,
                headers: vec![
                    (X_CONTENT_TYPE_OPTIONS, "nosniff"),
                    (CACHE_CONTROL, "no-store"),
                ],
                body: &[],
            };
        };
        SiteResponse {
            status: SiteStatus::Ok,
            headers: vec![
                (CONTENT_TYPE, media.header_value()),
                (X_CONTENT_TYPE_OPTIONS, "nosniff"),
                (CACHE_CONTROL, "no-store"),
                (REFERRER_POLICY, "no-referrer"),
                (CONTENT_SECURITY_POLICY, self.csp),
            ],
            body: if method == SiteMethod::Head {
                &[]
            } else {
                bytes
            },
        }
    }
}

/// Whether `value` reads as a policy the runtime emits.
///
/// Every byte is visible ASCII or a space, never a `,` (which would start a
/// second policy); directives are separated by `;`; each is a directive the
/// runtime names, at most once, followed by its sources.
fn policy_is_well_formed(value: &str) -> bool {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| (b == b' ' || b.is_ascii_graphic()) && b != b',')
    {
        return false;
    }
    let mut seen = Vec::with_capacity(Directive::ALL.len());
    for part in value.split(';') {
        let mut tokens = part.split(' ').filter(|token| !token.is_empty());
        let Some(directive) = tokens.next().and_then(Directive::from_name) else {
            return false;
        };
        if seen.contains(&directive) {
            return false;
        }
        seen.push(directive);
    }
    true
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    const POLICY: &str = "default-src 'none'; script-src ipe-app://localhost 'wasm-unsafe-eval'; connect-src ipe-app://localhost";

    const ASSETS: &[SiteAsset] = &[
        SiteAsset {
            path: "index.html",
            bytes: b"<html></html>",
        },
        SiteAsset {
            path: "app.js",
            bytes: b"run()",
        },
        SiteAsset {
            path: "pkg/app_bg.wasm",
            bytes: b"\0asm",
        },
    ];

    const CONFIG: SiteConfig = SiteConfig {
        title: "Notes",
        storage_key: "com.acme.notes",
        base: "/",
        csp: POLICY,
        assets: ASSETS,
    };

    fn site(origin: SchemeSpelling) -> Option<BundleSite> {
        BundleSite::parse(&CONFIG, origin).ok()
    }

    fn is_empty_404(response: &SiteResponse) -> bool {
        response.status == SiteStatus::NotFound && response.body.is_empty()
    }

    #[test]
    fn bundle_site_refuses_traversal_and_encoded_dot_dot() {
        let Some(site) = site(SchemeSpelling::Scheme) else {
            assert!(site(SchemeSpelling::Scheme).is_some());
            return;
        };
        for target in [
            "/../x",
            "/%2e%2e/x",
            "/a/%2F",
            "/a\\b",
            "/./app.js",
            "/pkg/../app.js",
        ] {
            let uri = format!("ipe-app://localhost{target}");
            assert!(is_empty_404(&site.respond("GET", &uri)), "{uri}");
        }
        assert_eq!(
            site.respond("GET", "ipe-app://localhost/app.js").status,
            SiteStatus::Ok
        );
    }

    #[test]
    fn bundle_site_refuses_a_foreign_authority() {
        for (origin, uri) in [
            (SchemeSpelling::Scheme, "ipe-app://localhost.evil/"),
            (SchemeSpelling::Scheme, "ipe-app://localhost@evil/"),
            (SchemeSpelling::Scheme, "ipe-app://evil/"),
            (SchemeSpelling::Scheme, "ipe-app://localhost:1/"),
            (SchemeSpelling::Scheme, "ipe-app://LOCALHOST/"),
            (SchemeSpelling::Scheme, "https://ipe-app.localhost/"),
            (SchemeSpelling::HttpsHost, "https://ipe-app.localhost.evil/"),
            (SchemeSpelling::HttpsHost, "http://ipe-app.localhost/"),
            (SchemeSpelling::HttpsHost, "ipe-app://localhost/"),
            (SchemeSpelling::Scheme, "file:///etc/passwd"),
        ] {
            let Some(site) = site(origin) else {
                assert!(site(origin).is_some());
                return;
            };
            assert!(is_empty_404(&site.respond("GET", uri)), "{origin:?} {uri}");
        }
        let Some(https) = site(SchemeSpelling::HttpsHost) else {
            return;
        };
        assert_eq!(
            https.respond("GET", "https://ipe-app.localhost/").status,
            SiteStatus::Ok
        );
    }

    #[test]
    fn bundle_site_answers_post_with_405() {
        let Some(site) = site(SchemeSpelling::Scheme) else {
            return;
        };
        for method in ["POST", "PUT", "DELETE", "OPTIONS", "get", "TRACE"] {
            let response = site.respond(method, "ipe-app://localhost/index.html");
            assert_eq!(response.status, SiteStatus::MethodNotAllowed, "{method}");
            assert!(response.body.is_empty());
        }
    }

    #[test]
    fn bundle_site_head_has_no_body() {
        let Some(site) = site(SchemeSpelling::Scheme) else {
            return;
        };
        let get = site.respond("GET", "ipe-app://localhost/app.js");
        let head = site.respond("HEAD", "ipe-app://localhost/app.js");
        assert_eq!(get.body, b"run()");
        assert!(head.body.is_empty());
        assert_eq!(head.status, SiteStatus::Ok);
        assert_eq!(head.headers, get.headers);
    }

    #[test]
    fn bundle_site_responses_carry_type_nosniff_and_csp() {
        let Some(site) = site(SchemeSpelling::Scheme) else {
            return;
        };
        for (uri, media) in [
            ("ipe-app://localhost", "text/html; charset=utf-8"),
            ("ipe-app://localhost/", "text/html; charset=utf-8"),
            ("ipe-app://localhost/?q=1", "text/html; charset=utf-8"),
            ("ipe-app://localhost/notes/42", "text/html; charset=utf-8"),
            (
                "ipe-app://localhost/app.js",
                "text/javascript; charset=utf-8",
            ),
            ("ipe-app://localhost/pkg/app_bg.wasm", "application/wasm"),
        ] {
            let response = site.respond("GET", uri);
            assert_eq!(response.status, SiteStatus::Ok, "{uri}");
            let header = |name: &str| {
                response
                    .headers
                    .iter()
                    .find(|(n, _)| *n == name)
                    .map(|(_, v)| *v)
            };
            assert_eq!(header(CONTENT_TYPE), Some(media), "{uri}");
            assert_eq!(header(X_CONTENT_TYPE_OPTIONS), Some("nosniff"));
            assert_eq!(header(CACHE_CONTROL), Some("no-store"));
            assert_eq!(header(REFERRER_POLICY), Some("no-referrer"));
            assert_eq!(header(CONTENT_SECURITY_POLICY), Some(POLICY));
        }
        assert_eq!(
            site.start_url(SchemeSpelling::Scheme),
            "ipe-app://localhost/index.html"
        );
        assert_eq!(
            site.start_url(SchemeSpelling::HttpsHost),
            "https://ipe-app.localhost/index.html"
        );
    }

    #[test]
    fn bundle_site_parse_refuses_a_bad_table() {
        const DOT_DOT: &[SiteAsset] = &[
            SiteAsset {
                path: "index.html",
                bytes: b"",
            },
            SiteAsset {
                path: "../x.js",
                bytes: b"",
            },
        ];
        const TWICE: &[SiteAsset] = &[
            SiteAsset {
                path: "index.html",
                bytes: b"",
            },
            SiteAsset {
                path: "index.html",
                bytes: b"",
            },
        ];
        const NO_INDEX: &[SiteAsset] = &[SiteAsset {
            path: "app.js",
            bytes: b"",
        }];
        let with = |assets: &'static [SiteAsset],
                    base: &'static str,
                    csp: &'static str,
                    key: &'static str| {
            BundleSite::parse(
                &SiteConfig {
                    title: "Notes",
                    storage_key: key,
                    base,
                    csp,
                    assets,
                },
                SchemeSpelling::Scheme,
            )
            .err()
        };
        assert!(matches!(
            with(DOT_DOT, "/", POLICY, "com.acme.notes"),
            Some(SiteRefusal::Path(_))
        ));
        assert_eq!(
            with(TWICE, "/", POLICY, "com.acme.notes"),
            Some(SiteRefusal::Duplicate)
        );
        assert!(matches!(
            with(ASSETS, "app", POLICY, "com.acme.notes"),
            Some(SiteRefusal::Base(_))
        ));
        assert_eq!(
            with(NO_INDEX, "/", POLICY, "com.acme.notes"),
            Some(SiteRefusal::NoIndex)
        );
        for csp in [
            "",
            "default-src 'none', script-src *",
            "default-src 'none'; default-src *",
            "made-up-src 'none'",
            "default-src 'none'\r\nX-Evil: 1",
            "default-src 'none';",
            "default-src \u{e9}",
        ] {
            assert_eq!(
                with(ASSETS, "/", csp, "com.acme.notes"),
                Some(SiteRefusal::Csp),
                "{csp:?}"
            );
        }
        assert_eq!(
            with(ASSETS, "/", POLICY, "con.acme"),
            Some(SiteRefusal::StorageKey(StorageKeyRefusal::Element(
                crate::path_core::ElementRefusal::DosDevice
            )))
        );
        assert_eq!(with(ASSETS, "/", POLICY, "com.acme.notes"), None);
    }
}

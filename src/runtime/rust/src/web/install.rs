//! The browser install offer of a `web served` app: its web app manifest,
//! its icon, and the two `<head>` links that name them.
//!
//! The facts are the build's own: the package name and the icon the CLI
//! parsed and sized, registered once by the generated `main`. Every URL is
//! built from the app's [`MountBase`] through [`MountBase::url_of`], and the
//! manifest is a `serde_json` value, so no text is ever joined by hand.

use std::sync::OnceLock;

use crate::encoding::{BundlePath, BundlePathRefusal, MountBase};

/// The install facts a build fixes: the package name and its PNG icon.
#[derive(Debug, PartialEq, Eq)]
pub struct InstallFacts {
    /// The package `name`: the manifest's `name` and `short_name`.
    pub name: &'static str,
    /// The icon's PNG bytes, as the build read them.
    pub icon_png: &'static [u8],
    /// The icon's side in px; the icon is square.
    pub icon_side: u32,
}

/// The install offer: the facts and their two content-addressed bundle paths.
#[derive(Debug, PartialEq, Eq)]
pub struct InstallOffer {
    facts: &'static InstallFacts,
    manifest: BundlePath,
    icon: BundlePath,
}

/// Why the install facts cannot become an offer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallRefusal {
    /// A content-addressed path is outside the bundle-path grammar.
    Path(BundlePathRefusal),
}

impl std::fmt::Display for InstallRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Path(refusal) => write!(f, "the install offer has no asset path: {refusal}"),
        }
    }
}

impl std::error::Error for InstallRefusal {}

/// The content type of the web app manifest.
pub const MANIFEST_CONTENT_TYPE: &str = "application/manifest+json";

/// The content type of the icon.
pub const ICON_CONTENT_TYPE: &str = "image/png";

/// The cache policy of both content-addressed install assets.
pub const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// The first 16 hex digits of the SHA-256 of `bytes`.
fn digest_hex16(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = digest;
    [b0, b1, b2, b3, b4, b5, b6, b7]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl InstallOffer {
    /// The offer of `facts`, its manifest and icon paths content-addressed.
    ///
    /// The manifest path is addressed by the manifest at the root base: the
    /// URL path already carries the base, so one digest names every base.
    ///
    /// # Errors
    ///
    /// [`InstallRefusal::Path`] when a built path leaves the bundle-path grammar.
    pub fn of(facts: &'static InstallFacts) -> Result<Self, InstallRefusal> {
        let icon = BundlePath::parse(&format!("_ipe/icon.{}.png", digest_hex16(facts.icon_png)))
            .map_err(InstallRefusal::Path)?;
        let root_manifest = manifest_value(facts, &MountBase::root(), &icon).to_string();
        let manifest = BundlePath::parse(&format!(
            "_ipe/manifest.{}.webmanifest",
            digest_hex16(root_manifest.as_bytes())
        ))
        .map_err(InstallRefusal::Path)?;
        Ok(Self {
            facts,
            manifest,
            icon,
        })
    }

    /// The bundle path of the manifest: `_ipe/manifest.<hex16>.webmanifest`.
    #[must_use]
    pub const fn manifest_path(&self) -> &BundlePath {
        &self.manifest
    }

    /// The bundle path of the icon: `_ipe/icon.<hex16>.png`.
    #[must_use]
    pub const fn icon_path(&self) -> &BundlePath {
        &self.icon
    }

    /// The icon's PNG bytes.
    #[must_use]
    pub const fn icon_png(&self) -> &'static [u8] {
        self.facts.icon_png
    }

    /// The manifest JSON of the app served at `base`.
    #[must_use]
    pub fn manifest_json(&self, base: &MountBase) -> String {
        manifest_value(self.facts, base, &self.icon).to_string()
    }
}

/// The manifest of `facts` served at `base`, whose icon is at `icon`.
///
/// It has no `theme_color` and no `orientation`: the app keeps the browser's
/// own colours and every orientation.
fn manifest_value(facts: &InstallFacts, base: &MountBase, icon: &BundlePath) -> serde_json::Value {
    let dir = base.dir_url();
    serde_json::json!({
        "name": facts.name,
        "short_name": facts.name,
        "id": dir,
        "start_url": dir,
        "scope": dir,
        "display": "standalone",
        "icons": [{
            "src": base.url_of(icon),
            "sizes": format!("{0}x{0}", facts.icon_side),
            "type": ICON_CONTENT_TYPE,
            "purpose": "any",
        }],
    })
}

/// The program's install offer; write-once, the first registration wins.
static OFFER: OnceLock<InstallOffer> = OnceLock::new();

/// Register the build's install facts. Called once by the generated `main`
/// before the server starts; a later call is a no-op.
///
/// # Errors
///
/// [`InstallRefusal`] when the facts cannot become an offer; the server must
/// not start with an install offer it cannot serve.
pub fn register(facts: &'static InstallFacts) -> Result<(), InstallRefusal> {
    let offer = InstallOffer::of(facts)?;
    // A repeat registration is ignored: the first is authoritative.
    let _ = OFFER.set(offer);
    Ok(())
}

/// The registered install offer, or `None` when the build offers no install.
#[must_use]
pub fn registered() -> Option<&'static InstallOffer> {
    OFFER.get()
}

/// The `<link rel="manifest">` and `<link rel="apple-touch-icon">` tags of
/// the app served at `base`, or the empty text when it offers no install.
///
/// The manifest link carries no `crossorigin`, so the browser fetches it
/// without credentials.
#[must_use]
pub fn head_links(offer: Option<&InstallOffer>, base: &MountBase) -> String {
    offer.map_or_else(String::new, |offer| {
        let manifest = crate::escape::html_attr(&base.url_of(offer.manifest_path()));
        let icon = crate::escape::html_attr(&base.url_of(offer.icon_path()));
        format!(
            "<link rel=\"manifest\" href=\"{manifest}\"><link rel=\"apple-touch-icon\" href=\"{icon}\">"
        )
    })
}

/// One install asset answer: the bytes, their type, `immutable`, and the
/// security headers; no cookie and no `Vary`.
fn asset_response(content_type: &'static str, body: axum::body::Body) -> axum::response::Response {
    use axum::http::header;
    use axum::response::IntoResponse;
    crate::server::with_security_headers(
        (
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, IMMUTABLE),
            ],
            body,
        )
            .into_response(),
        crate::server::response_security_headers(),
    )
}

/// Mount the manifest and icon routes of `offer` on the root-relative
/// `router` of the app served at `base`; with no offer, `router` is returned
/// unchanged.
///
/// The routes are explicit, so they never reach the page handler and never
/// read or mint a session. The manifest body folds in `base`, so it is built
/// once per mounted app and leaked to `'static`, a bounded allocation.
pub fn mount_routes<S>(
    router: axum::Router<S>,
    offer: Option<&'static InstallOffer>,
    base: &MountBase,
) -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    use axum::routing::get;
    let Some(offer) = offer else {
        return router;
    };
    let route_root = MountBase::root();
    let manifest: &'static str = Box::leak(offer.manifest_json(base).into_boxed_str());
    let icon = offer.icon_png();
    router
        .route(
            &route_root.url_of(offer.manifest_path()),
            get(move || async move { asset_response(MANIFEST_CONTENT_TYPE, manifest.into()) }),
        )
        .route(
            &route_root.url_of(offer.icon_path()),
            get(move || async move { asset_response(ICON_CONTENT_TYPE, icon.into()) }),
        )
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    /// A name carrying every byte JSON must escape.
    const HOSTILE_NAME: &str = "a\"b\\c</script>d\u{2028}e\u{1}f";

    static HOSTILE: InstallFacts = InstallFacts {
        name: HOSTILE_NAME,
        icon_png: b"\x89PNG\r\n\x1a\nicon",
        icon_side: 512,
    };

    static PLAIN: InstallFacts = InstallFacts {
        name: "todo",
        icon_png: b"\x89PNG\r\n\x1a\nicon",
        icon_side: 192,
    };

    fn offer(facts: &'static InstallFacts) -> InstallOffer {
        InstallOffer::of(facts).expect("the facts make an offer")
    }

    fn parsed(json: &str) -> serde_json::Value {
        serde_json::from_str(json).expect("the manifest is JSON")
    }

    fn base(raw: &str) -> MountBase {
        MountBase::parse(raw).expect("a mount base")
    }

    /// A name with `"`, `\`, `</script>`, U+2028 and a control byte round-trips.
    #[test]
    fn the_manifest_name_round_trips_through_the_encoder() {
        let manifest = parsed(&offer(&HOSTILE).manifest_json(&MountBase::root()));
        for key in ["/name", "/short_name"] {
            assert_eq!(
                manifest.pointer(key).and_then(serde_json::Value::as_str),
                Some(HOSTILE_NAME),
                "{key}"
            );
        }
    }

    /// `id`, `start_url`, `scope` and the icon `src` follow the base.
    #[test]
    fn manifest_urls_follow_the_mount_base() {
        let offer = offer(&PLAIN);
        let icon = offer.icon_path().rel().to_owned();
        for (raw, dir) in [("/", "/"), ("/app", "/app/")] {
            let manifest = parsed(&offer.manifest_json(&base(raw)));
            let text = |pointer: &str| {
                manifest
                    .pointer(pointer)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            };
            for key in ["/id", "/start_url", "/scope"] {
                assert_eq!(text(key).as_deref(), Some(dir), "{key} under {raw}");
            }
            assert_eq!(text("/icons/0/src"), Some(format!("{dir}{icon}")), "{raw}");
            assert_eq!(text("/icons/0/sizes").as_deref(), Some("192x192"));
            assert_eq!(text("/icons/0/type").as_deref(), Some("image/png"));
            assert_eq!(text("/icons/0/purpose").as_deref(), Some("any"));
            assert_eq!(text("/display").as_deref(), Some("standalone"));
        }
    }

    /// The manifest has no `theme_color` and no `orientation` key.
    #[test]
    fn the_manifest_names_no_theme_colour_or_orientation() {
        let manifest = parsed(&offer(&PLAIN).manifest_json(&base("/app")));
        let keys: Vec<&str> = manifest
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "name",
                "short_name",
                "id",
                "start_url",
                "scope",
                "display",
                "icons"
            ]
        );
    }

    /// Both asset paths are content-addressed and in the bundle grammar.
    #[test]
    fn asset_paths_are_content_addressed() {
        let offer = offer(&PLAIN);
        let manifest = offer.manifest_path().rel();
        let icon = offer.icon_path().rel();
        assert!(
            manifest.starts_with("_ipe/manifest.") && manifest.ends_with(".webmanifest"),
            "{manifest}"
        );
        assert!(
            icon.starts_with("_ipe/icon.") && icon.ends_with(".png"),
            "{icon}"
        );
        assert_eq!(
            manifest.len(),
            "_ipe/manifest.".len() + 16 + ".webmanifest".len()
        );
        assert_eq!(icon.len(), "_ipe/icon.".len() + 16 + ".png".len());
        assert_ne!(
            offer.manifest_path(),
            super::InstallOffer::of(&HOSTILE)
                .expect("an offer")
                .manifest_path(),
            "a changed name changes the manifest URL"
        );
    }

    /// No offer writes no head link; an offer writes both under the base.
    #[test]
    fn head_links_are_absent_without_an_offer() {
        assert_eq!(head_links(None, &base("/app")), "");
        let offer = offer(&PLAIN);
        let links = head_links(Some(&offer), &base("/app"));
        assert_eq!(
            links,
            format!(
                "<link rel=\"manifest\" href=\"/app/{}\"><link rel=\"apple-touch-icon\" href=\"/app/{}\">",
                offer.manifest_path().rel(),
                offer.icon_path().rel()
            )
        );
        assert!(!links.contains("crossorigin"), "{links}");
        assert!(!links.contains("theme-color"), "{links}");
    }
}

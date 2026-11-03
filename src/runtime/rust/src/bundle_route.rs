//! The one request-to-asset route and the one media-type table for a client
//! bundle.
//!
//! Every host that answers a browser from a bundle — the `ipe dev run` loopback
//! server and the desktop webview's scheme handler — routes a request target
//! through [`route`] and types the answer through [`MediaType`]. Neither host
//! has path logic of its own, and neither builds a filesystem path from a
//! request: [`route`] only names a [`BundlePath`], and the host answers from the
//! bytes it already holds under that key.

use crate::encoding::{BundlePath, MountBase};

/// The `Content-Type` of an asset, judged from its file extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MediaType {
    /// `text/html; charset=utf-8`.
    Html,
    /// `text/javascript; charset=utf-8`.
    Javascript,
    /// `application/wasm`: the type `WebAssembly.instantiateStreaming` requires.
    Wasm,
    /// `text/css; charset=utf-8`.
    Css,
    /// `application/json`.
    Json,
    /// `image/svg+xml`.
    Svg,
    /// `image/png`.
    Png,
    /// `image/x-icon`.
    Icon,
    /// `image/jpeg`.
    Jpeg,
    /// `image/gif`.
    Gif,
    /// `image/webp`.
    Webp,
    /// `application/xml`.
    Xml,
    /// `font/woff`.
    Woff,
    /// `font/woff2`.
    Woff2,
    /// `font/ttf`.
    Ttf,
    /// `application/manifest+json`.
    WebManifest,
    /// `text/plain; charset=utf-8`.
    Text,
    /// `application/octet-stream`: every extension the table does not name.
    OctetStream,
}

impl MediaType {
    /// Every extension with a type of its own; any other is [`Self::OctetStream`].
    ///
    /// The one table every shell's lookup is generated from or checked against.
    pub const BY_EXTENSION: &'static [(&'static str, Self)] = &[
        ("html", Self::Html),
        ("js", Self::Javascript),
        ("mjs", Self::Javascript),
        ("wasm", Self::Wasm),
        ("css", Self::Css),
        ("json", Self::Json),
        ("map", Self::Json),
        ("svg", Self::Svg),
        ("png", Self::Png),
        ("ico", Self::Icon),
        ("jpg", Self::Jpeg),
        ("jpeg", Self::Jpeg),
        ("gif", Self::Gif),
        ("webp", Self::Webp),
        ("xml", Self::Xml),
        ("woff", Self::Woff),
        ("woff2", Self::Woff2),
        ("ttf", Self::Ttf),
        ("webmanifest", Self::WebManifest),
        ("txt", Self::Text),
    ];

    /// The type of a file whose extension (the text after its last `.`) is `ext`.
    ///
    /// Case-sensitive: `PNG` is not `png`, so it is `application/octet-stream`.
    #[must_use]
    pub fn of_extension(ext: &str) -> Self {
        Self::BY_EXTENSION
            .iter()
            .find(|(known, _)| *known == ext)
            .map_or(Self::OctetStream, |(_, media)| *media)
    }

    /// The type of the asset at `path`, from its last segment's extension.
    #[must_use]
    pub fn of(path: &BundlePath) -> Self {
        path.file_segments()
            .last()
            .and_then(|name| name.rsplit_once('.'))
            .map_or(Self::OctetStream, |(_, ext)| Self::of_extension(ext))
    }

    /// The `Content-Type` header value.
    #[must_use]
    pub const fn header_value(self) -> &'static str {
        match self {
            Self::Html => "text/html; charset=utf-8",
            Self::Javascript => "text/javascript; charset=utf-8",
            Self::Css => "text/css; charset=utf-8",
            Self::Text => "text/plain; charset=utf-8",
            Self::Wasm
            | Self::Json
            | Self::Svg
            | Self::Png
            | Self::Icon
            | Self::Jpeg
            | Self::Gif
            | Self::Webp
            | Self::Xml
            | Self::Woff
            | Self::Woff2
            | Self::Ttf
            | Self::WebManifest
            | Self::OctetStream => self.essence(),
        }
    }

    /// The type without parameters (`text/html`, never `text/html; charset=utf-8`).
    #[must_use]
    pub const fn essence(self) -> &'static str {
        match self {
            Self::Html => "text/html",
            Self::Javascript => "text/javascript",
            Self::Wasm => "application/wasm",
            Self::Css => "text/css",
            Self::Json => "application/json",
            Self::Svg => "image/svg+xml",
            Self::Png => "image/png",
            Self::Icon => "image/x-icon",
            Self::Jpeg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::Webp => "image/webp",
            Self::Xml => "application/xml",
            Self::Woff => "font/woff",
            Self::Woff2 => "font/woff2",
            Self::Ttf => "font/ttf",
            Self::WebManifest => "application/manifest+json",
            Self::Text => "text/plain",
            Self::OctetStream => "application/octet-stream",
        }
    }
}

/// What a request target names in a bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// The asset the target names exactly.
    Asset(BundlePath),
    /// A directory's `index.html`, or the base's for an extensionless deep link.
    Index(BundlePath),
    /// Nothing in the bundle: outside the base, refused, or absent.
    NotFound,
}

/// The file a directory request answers with.
const INDEX_FILE: &str = "index.html";

/// Route the request `target` of a bundle served at `base`.
///
/// `has` says whether the bundle holds an asset; it is the only view of the
/// bundle, so nothing here enumerates or lists a directory. The query and the
/// fragment are dropped, then the path is refused (`NotFound`), never
/// normalised, when it holds a `%`, a `\`, a NUL or other control byte, an
/// empty segment other than a trailing one, or a `.` or `..` segment, or when
/// it lies outside `base` (segment-wise: `/app` never matches `/apple`). A
/// trailing `/` (or the base itself) answers that directory's `index.html` when
/// `has` holds it. An absent path whose last segment has no `.` answers the
/// base's `index.html` (the client router's deep link); any other absent path
/// is `NotFound`.
///
/// A request method is judged by the caller before this route: only GET and
/// HEAD are routed.
#[must_use]
pub fn route(base: &MountBase, target: &str, has: impl Fn(&BundlePath) -> bool) -> Route {
    let path = target
        .split_once(['?', '#'])
        .map_or(target, |(path, _)| path);
    if path
        .bytes()
        .any(|b| b == b'%' || b == b'\\' || b.is_ascii_control())
    {
        return Route::NotFound;
    }
    let Some(rest) = path.strip_prefix('/') else {
        return Route::NotFound;
    };
    let mut segments: Vec<&str> = rest.split('/').collect();
    let is_dir = segments.last().is_some_and(|last| last.is_empty());
    if is_dir {
        segments.pop();
    }
    if segments.iter().any(|segment| segment.is_empty()) {
        return Route::NotFound;
    }
    let mut below = segments.into_iter();
    for base_segment in base.segments() {
        if below.next() != Some(base_segment) {
            return Route::NotFound;
        }
    }
    let below: Vec<&str> = below.collect();
    let Some(last) = below.last() else {
        return index_at("", &has);
    };
    let joined = below.join("/");
    if is_dir {
        return index_at(&joined, &has);
    }
    let Ok(asset) = BundlePath::parse(&joined) else {
        return Route::NotFound;
    };
    if has(&asset) {
        Route::Asset(asset)
    } else if last.contains('.') {
        Route::NotFound
    } else {
        index_at("", &has)
    }
}

/// The `index.html` of the directory `dir` (`""` for the bundle root), when held.
fn index_at(dir: &str, has: &impl Fn(&BundlePath) -> bool) -> Route {
    let text = if dir.is_empty() {
        INDEX_FILE.to_owned()
    } else {
        format!("{dir}/{INDEX_FILE}")
    };
    match BundlePath::parse(&text) {
        Ok(index) if has(&index) => Route::Index(index),
        Ok(_) | Err(_) => Route::NotFound,
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::{MediaType, Route, route};
    use crate::encoding::{BundlePath, MountBase};

    #[allow(clippy::panic)] // a fixture names a valid path or fails the test
    fn path(text: &str) -> BundlePath {
        BundlePath::parse(text).unwrap_or_else(|refusal| panic!("{text}: {refusal}"))
    }

    #[allow(clippy::panic)] // a fixture names a valid base or fails the test
    fn base(text: &str) -> MountBase {
        MountBase::parse(text).unwrap_or_else(|refusal| panic!("{text}: {refusal}"))
    }

    const HELD: &[&str] = &[
        "index.html",
        "app.js",
        "pkg/app_bg.wasm",
        "docs/index.html",
        "pkg/a.b",
    ];

    fn held(asset: &BundlePath) -> bool {
        HELD.contains(&asset.rel())
    }

    #[test]
    fn bundle_route_refuses_traversal_and_foreign_base() {
        let root = base("/");
        for target in [
            "/../x",
            "/%2e%2e/x",
            "/a/%2F",
            "/a\\b",
            "//etc/passwd",
            "/./app.js",
            "/pkg/../app.js",
            "/pkg/./app_bg.wasm",
            "/pkg//app_bg.wasm",
            "/app.js\0",
            "/app\n.js",
            "app.js",
            "",
            "/a b",
            "/\u{e9}",
        ] {
            assert_eq!(route(&root, target, held), Route::NotFound, "{target:?}");
        }
        let app = base("/app");
        for target in [
            "/x",
            "/app.js",
            "/apple/app.js",
            "/apple",
            "/",
            "/index.html",
        ] {
            assert_eq!(route(&app, target, held), Route::NotFound, "{target:?}");
        }
        assert_eq!(route(&app, "/app/", held), Route::Index(path("index.html")));
        assert_eq!(route(&app, "/app", held), Route::Index(path("index.html")));
        assert_eq!(
            route(&app, "/app/app.js?v=1#top", held),
            Route::Asset(path("app.js"))
        );
        assert_eq!(
            route(&root, "/pkg/app_bg.wasm", held),
            Route::Asset(path("pkg/app_bg.wasm"))
        );
        assert_eq!(route(&root, "/pkg/", held), Route::NotFound);
        assert_eq!(
            route(&root, "/docs/", held),
            Route::Index(path("docs/index.html"))
        );
        assert_eq!(route(&root, "/", |_| false), Route::NotFound);
    }

    #[test]
    fn bundle_route_spa_fallback_only_for_extensionless_paths() {
        let root = base("");
        assert_eq!(
            route(&root, "/settings/profile", held),
            Route::Index(path("index.html"))
        );
        assert_eq!(route(&root, "/missing.js", held), Route::NotFound);
        assert_eq!(route(&root, "/pkg/missing.wasm", held), Route::NotFound);
        assert_eq!(
            route(&root, "/pkg/a.b", held),
            Route::Asset(path("pkg/a.b"))
        );
        assert_eq!(route(&root, "/settings", |_| false), Route::NotFound);
        let app = base("/app");
        assert_eq!(
            route(&app, "/app/settings", held),
            Route::Index(path("index.html"))
        );
        assert_eq!(route(&app, "/settings", held), Route::NotFound);
    }

    #[test]
    fn media_type_of_is_total_over_known_extensions() {
        for (ext, media) in MediaType::BY_EXTENSION {
            assert_eq!(MediaType::of_extension(ext), *media, "{ext}");
            assert_ne!(*media, MediaType::OctetStream, "{ext}");
            assert!(
                media.header_value().starts_with(media.essence()),
                "{ext}: {} is not a {}",
                media.header_value(),
                media.essence()
            );
        }
        for (i, (ext, _)) in MediaType::BY_EXTENSION.iter().enumerate() {
            assert_eq!(
                MediaType::BY_EXTENSION
                    .iter()
                    .skip(i.saturating_add(1))
                    .find(|(other, _)| other == ext),
                None,
                "{ext} is listed twice"
            );
        }
        for unknown in ["", "dat", "PNG", "html5", "exe"] {
            assert_eq!(MediaType::of_extension(unknown), MediaType::OctetStream);
        }
        assert_eq!(
            MediaType::of_extension("js").header_value(),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            MediaType::of_extension("html").header_value(),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            MediaType::of_extension("webmanifest").header_value(),
            "application/manifest+json"
        );
    }

    #[test]
    fn media_type_of_reads_the_last_segment_extension() {
        assert_eq!(MediaType::of(&path("pkg/app_bg.wasm")), MediaType::Wasm);
        assert_eq!(MediaType::of(&path("a.b/README")), MediaType::OctetStream);
        assert_eq!(MediaType::of(&path("x.tar.gz")), MediaType::OctetStream);
        assert_eq!(MediaType::of(&path("index.html")), MediaType::Html);
    }
}

//! The `Content-Security-Policy` the runtime's HTML responses carry.
//!
//! One typed builder, [`ContentSecurityPolicy`], composes every header value
//! from the closed [`Directive`] and [`Source`] vocabularies, so no call site
//! spells a directive string. A [`Profile`] names the response a policy guards;
//! header assembly (`telemetry::security_headers`) takes it as a required
//! parameter. An inline element a profile admits is admitted by a hash computed
//! from the same constant the response embeds, never a copied digest.

use crate::telemetry::FrameAncestors;

#[cfg(all(feature = "server", feature = "web-core"))]
use crate::web::console::{CONSOLE_CSS, CONSOLE_JS};

/// A policy directive the runtime emits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Directive {
    /// `default-src`: the fallback for every fetch directive not listed.
    DefaultSrc,
    /// `script-src`.
    ScriptSrc,
    /// `script-src-attr`: inline event-handler attributes.
    ScriptSrcAttr,
    /// `style-src`.
    StyleSrc,
    /// `style-src-elem`: `<style>` and `<link rel=stylesheet>` elements.
    StyleSrcElem,
    /// `style-src-attr`: `style="…"` attributes.
    StyleSrcAttr,
    /// `img-src`.
    ImgSrc,
    /// `font-src`.
    FontSrc,
    /// `media-src`.
    MediaSrc,
    /// `connect-src`: `fetch`, `EventSource` and `WebSocket` targets.
    ConnectSrc,
    /// `manifest-src`.
    ManifestSrc,
    /// `worker-src`.
    WorkerSrc,
    /// `frame-src`.
    FrameSrc,
    /// `object-src`.
    ObjectSrc,
    /// `base-uri`.
    BaseUri,
    /// `form-action`.
    FormAction,
    /// `frame-ancestors`: who may embed the response.
    FrameAncestors,
}

impl Directive {
    /// The directive name as the header spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DefaultSrc => "default-src",
            Self::ScriptSrc => "script-src",
            Self::ScriptSrcAttr => "script-src-attr",
            Self::StyleSrc => "style-src",
            Self::StyleSrcElem => "style-src-elem",
            Self::StyleSrcAttr => "style-src-attr",
            Self::ImgSrc => "img-src",
            Self::FontSrc => "font-src",
            Self::MediaSrc => "media-src",
            Self::ConnectSrc => "connect-src",
            Self::ManifestSrc => "manifest-src",
            Self::WorkerSrc => "worker-src",
            Self::FrameSrc => "frame-src",
            Self::ObjectSrc => "object-src",
            Self::BaseUri => "base-uri",
            Self::FormAction => "form-action",
            Self::FrameAncestors => "frame-ancestors",
        }
    }
}

/// A `'sha256-…'` source admitting one inline element by its exact text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CspHash(String);

impl CspHash {
    /// The hash source of `text`: `'sha256-<base64(sha256(text))>'`.
    #[cfg(all(feature = "server", feature = "web-core"))]
    #[must_use]
    pub fn of(text: &str) -> Self {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use sha2::{Digest, Sha256};
        Self(format!(
            "'sha256-{}'",
            STANDARD.encode(Sha256::digest(text.as_bytes()))
        ))
    }

    /// The source expression, quotes included.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A source expression in a directive's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source<'a> {
    /// `'none'`: nothing is admitted.
    None,
    /// `'self'`: the response's own origin.
    SelfOrigin,
    /// `'unsafe-inline'`; the profiles place it only in `style-src-attr`.
    UnsafeInline,
    /// The `data:` scheme.
    Data,
    /// The `blob:` scheme.
    Blob,
    /// The hash of one runtime constant.
    Hash(&'a CspHash),
    /// The operator's parsed `IPE_WEB_FRAME_ANCESTORS` sources.
    Embed(&'a FrameAncestors),
}

impl<'a> Source<'a> {
    /// The source expression as the header spells it.
    #[must_use]
    pub const fn text(self) -> &'a str {
        match self {
            Self::None => "'none'",
            Self::SelfOrigin => "'self'",
            Self::UnsafeInline => "'unsafe-inline'",
            Self::Data => "data:",
            Self::Blob => "blob:",
            Self::Hash(hash) => hash.as_str(),
            Self::Embed(framing) => framing.sources(),
        }
    }
}

/// Declares [`Profile`] and [`Profile::ALL`] from one variant list.
///
/// A variant cannot exist outside `ALL`, so no test iterating `ALL` skips one.
macro_rules! profiles {
    ($($(#[doc = $doc:expr])* $(#[cfg($cfg:meta)])? $variant:ident,)+) => {
        /// The response a policy guards.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Profile {
            $($(#[doc = $doc])* $(#[cfg($cfg)])? $variant,)+
        }

        impl Profile {
            /// Every profile, in declaration order.
            pub const ALL: &'static [Self] = &[$($(#[cfg($cfg)])? Self::$variant,)+];
        }
    };
}

profiles! {
    /// An `Ipe.Http.Server` handler response or a static file: no inline
    /// script or style element applies.
    Response,
    /// The `/_ipe/console` operator dashboard: its one script and one style
    /// element are admitted by hash, and it is never framed cross-origin.
    #[cfg(all(feature = "server", feature = "web-core"))]
    Console,
}

impl Profile {
    /// The embed list the profile's `frame-ancestors` names, given the
    /// operator's: `None` frames the response same-origin only.
    #[must_use]
    pub const fn embed_list(self, framing: Option<&FrameAncestors>) -> Option<&FrameAncestors> {
        match self {
            Self::Response => framing,
            #[cfg(all(feature = "server", feature = "web-core"))]
            Self::Console => None,
        }
    }
}

/// The inline-element hashes of the console page.
#[cfg(all(feature = "server", feature = "web-core"))]
struct ConsoleHashes {
    script: CspHash,
    style: CspHash,
}

/// The console hashes, computed once from [`CONSOLE_JS`] and [`CONSOLE_CSS`].
#[cfg(all(feature = "server", feature = "web-core"))]
fn console_hashes() -> &'static ConsoleHashes {
    static CELL: std::sync::OnceLock<ConsoleHashes> = std::sync::OnceLock::new();
    CELL.get_or_init(|| ConsoleHashes {
        script: CspHash::of(CONSOLE_JS),
        style: CspHash::of(CONSOLE_CSS),
    })
}

/// A `Content-Security-Policy` value: an ordered list of directives.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContentSecurityPolicy<'a> {
    directives: Vec<(Directive, Vec<Source<'a>>)>,
}

impl<'a> ContentSecurityPolicy<'a> {
    /// The policy of `profile` under the operator's embed list `framing`.
    #[must_use]
    pub fn for_profile(profile: Profile, framing: Option<&'a FrameAncestors>) -> Self {
        let ancestors = profile
            .embed_list(framing)
            .map_or(Source::SelfOrigin, Source::Embed);
        match profile {
            Profile::Response => Self::response(ancestors),
            #[cfg(all(feature = "server", feature = "web-core"))]
            Profile::Console => Self::console(ancestors),
        }
    }

    /// The policy holding only `frame-ancestors <framing>`.
    #[must_use]
    pub fn frame_only(framing: &'a FrameAncestors) -> Self {
        Self::default().with(Directive::FrameAncestors, vec![Source::Embed(framing)])
    }

    /// The `Response` profile with `frame-ancestors` set to `ancestors`.
    fn response(ancestors: Source<'a>) -> Self {
        use Directive as D;
        use Source as S;
        Self::default()
            .with(D::DefaultSrc, vec![S::None])
            .with(D::ScriptSrc, vec![S::SelfOrigin])
            .with(D::ScriptSrcAttr, vec![S::None])
            .with(D::StyleSrc, vec![S::SelfOrigin])
            .with(D::StyleSrcElem, vec![S::SelfOrigin])
            .with(D::StyleSrcAttr, vec![S::UnsafeInline])
            .with(D::ImgSrc, vec![S::SelfOrigin, S::Data, S::Blob])
            .with(D::FontSrc, vec![S::SelfOrigin, S::Data])
            .with(D::MediaSrc, vec![S::SelfOrigin, S::Blob])
            .with(D::ConnectSrc, vec![S::SelfOrigin])
            .with(D::ManifestSrc, vec![S::SelfOrigin])
            .with(D::WorkerSrc, vec![S::SelfOrigin])
            .with(D::FrameSrc, vec![S::SelfOrigin])
            .with(D::ObjectSrc, vec![S::None])
            .with(D::BaseUri, vec![S::None])
            .with(D::FormAction, vec![S::SelfOrigin])
            .with(D::FrameAncestors, vec![ancestors])
    }

    /// The `Console` profile with `frame-ancestors` set to `ancestors`.
    #[cfg(all(feature = "server", feature = "web-core"))]
    fn console(ancestors: Source<'a>) -> Self {
        use Directive as D;
        use Source as S;
        let hashes = console_hashes();
        Self::default()
            .with(D::DefaultSrc, vec![S::None])
            .with(D::ScriptSrc, vec![S::Hash(&hashes.script)])
            .with(D::ScriptSrcAttr, vec![S::None])
            .with(D::StyleSrc, vec![S::Hash(&hashes.style)])
            .with(D::ConnectSrc, vec![S::SelfOrigin])
            .with(D::ImgSrc, vec![S::SelfOrigin])
            .with(D::ObjectSrc, vec![S::None])
            .with(D::BaseUri, vec![S::None])
            .with(D::FormAction, vec![S::None])
            .with(D::FrameAncestors, vec![ancestors])
    }

    /// The policy with `directive` appended.
    fn with(mut self, directive: Directive, sources: Vec<Source<'a>>) -> Self {
        self.directives.push((directive, sources));
        self
    }

    /// The sources of `directive`, or `None` when the policy omits it.
    #[must_use]
    pub fn sources(&self, directive: Directive) -> Option<&[Source<'a>]> {
        self.directives
            .iter()
            .find(|(d, _)| *d == directive)
            .map(|(_, sources)| sources.as_slice())
    }

    /// Every directive with its sources, in header order.
    #[must_use = "the iterator is lazy"]
    pub fn directives(&self) -> impl Iterator<Item = (Directive, &[Source<'a>])> {
        self.directives
            .iter()
            .map(|(d, sources)| (*d, sources.as_slice()))
    }

    /// The header value: `name source…` directives joined by `"; "`.
    #[must_use]
    pub fn header_value(&self) -> String {
        let mut out = String::new();
        for (d, sources) in &self.directives {
            if !out.is_empty() {
                out.push_str("; ");
            }
            out.push_str(d.name());
            for source in sources {
                out.push(' ');
                out.push_str(source.text());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact `Response` header value under the same-origin default.
    const RESPONSE_SAME_ORIGIN: &str = "default-src 'none'; script-src 'self'; \
        script-src-attr 'none'; style-src 'self'; style-src-elem 'self'; \
        style-src-attr 'unsafe-inline'; img-src 'self' data: blob:; \
        font-src 'self' data:; media-src 'self' blob:; connect-src 'self'; \
        manifest-src 'self'; worker-src 'self'; frame-src 'self'; \
        object-src 'none'; base-uri 'none'; form-action 'self'; \
        frame-ancestors 'self'";

    fn embed() -> Option<FrameAncestors> {
        FrameAncestors::parse(" https://a.example https://b.example ")
            .ok()
            .flatten()
    }

    /// Every profile's policy, same-origin and under an embed list.
    fn every_policy(framing: Option<&FrameAncestors>) -> Vec<(Profile, ContentSecurityPolicy<'_>)> {
        Profile::ALL
            .iter()
            .flat_map(|p| {
                [
                    (*p, ContentSecurityPolicy::for_profile(*p, None)),
                    (*p, ContentSecurityPolicy::for_profile(*p, framing)),
                ]
            })
            .collect()
    }

    #[test]
    fn profile_all_lists_each_variant_once() {
        for (i, p) in Profile::ALL.iter().enumerate() {
            assert_eq!(Profile::ALL.iter().position(|q| q == p), Some(i), "{p:?}");
        }
        let declared = if cfg!(all(feature = "server", feature = "web-core")) {
            2
        } else {
            1
        };
        assert_eq!(Profile::ALL.len(), declared);
    }

    #[test]
    fn response_profile_exact_header() {
        assert_eq!(
            ContentSecurityPolicy::for_profile(Profile::Response, None).header_value(),
            RESPONSE_SAME_ORIGIN
        );
    }

    #[cfg(all(feature = "server", feature = "web-core"))]
    #[test]
    fn console_profile_exact_header() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use sha2::{Digest, Sha256};
        let script = STANDARD.encode(Sha256::digest(CONSOLE_JS.as_bytes()));
        let style = STANDARD.encode(Sha256::digest(CONSOLE_CSS.as_bytes()));
        let want = format!(
            "default-src 'none'; script-src 'sha256-{script}'; script-src-attr 'none'; \
             style-src 'sha256-{style}'; connect-src 'self'; img-src 'self'; \
             object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
        );
        let framing = embed();
        for framing in [None, framing.as_ref()] {
            assert_eq!(
                ContentSecurityPolicy::for_profile(Profile::Console, framing).header_value(),
                want
            );
        }
    }

    #[test]
    fn script_src_never_unsafe() {
        let framing = embed();
        for (profile, policy) in every_policy(framing.as_ref()) {
            for directive in [Directive::ScriptSrc, Directive::ScriptSrcAttr] {
                let sources = policy.sources(directive);
                assert!(sources.is_some(), "{profile:?} omits {directive:?}");
                for source in sources.into_iter().flatten() {
                    let text = source.text();
                    for banned in [
                        "'unsafe-inline'",
                        "'unsafe-eval'",
                        "'unsafe-hashes'",
                        "data:",
                        "*",
                    ] {
                        assert!(
                            !text.contains(banned),
                            "{profile:?} {directive:?} admits {text}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn unsafe_inline_only_in_style_attr() {
        let framing = embed();
        for (profile, policy) in every_policy(framing.as_ref()) {
            let holders: Vec<Directive> = policy
                .directives()
                .filter(|(_, sources)| sources.contains(&Source::UnsafeInline))
                .map(|(d, _)| d)
                .collect();
            let want: &[Directive] = if policy.sources(Directive::StyleSrcAttr).is_some() {
                &[Directive::StyleSrcAttr]
            } else {
                &[]
            };
            assert_eq!(holders, want, "{profile:?}");
            assert_eq!(
                policy.header_value().matches("'unsafe-inline'").count(),
                want.len(),
                "{profile:?}"
            );
        }
        assert!(
            ContentSecurityPolicy::for_profile(Profile::Response, None)
                .sources(Directive::StyleSrcAttr)
                .is_some_and(|s| s == [Source::UnsafeInline])
        );
    }

    #[test]
    fn no_profile_carries_a_nonce() {
        let framing = embed();
        for (profile, policy) in every_policy(framing.as_ref()) {
            assert!(!policy.header_value().contains("'nonce-"), "{profile:?}");
        }
    }

    #[cfg(all(feature = "server", feature = "web-core"))]
    #[test]
    fn hashes_match_constants() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use sha2::{Digest, Sha256};
        let recompute = |text: &str| {
            format!(
                "'sha256-{}'",
                STANDARD.encode(Sha256::digest(text.as_bytes()))
            )
        };
        let hashes = console_hashes();
        assert_eq!(hashes.script.as_str(), recompute(CONSOLE_JS));
        assert_eq!(hashes.style.as_str(), recompute(CONSOLE_CSS));
        let mutated_js = format!("{CONSOLE_JS} ");
        let mutated_css = format!("{CONSOLE_CSS} ");
        assert_ne!(hashes.script.as_str(), recompute(&mutated_js));
        assert_ne!(hashes.style.as_str(), recompute(&mutated_css));
        assert_ne!(hashes.script, CspHash::of(&mutated_js));
        let policy = ContentSecurityPolicy::for_profile(Profile::Console, None);
        assert_eq!(
            policy.sources(Directive::ScriptSrc),
            Some([Source::Hash(&hashes.script)].as_slice())
        );
        assert_eq!(
            policy.sources(Directive::StyleSrc),
            Some([Source::Hash(&hashes.style)].as_slice())
        );
    }

    #[test]
    fn frame_ancestors_substituted() {
        let framing = embed();
        assert!(framing.is_some());
        let framed = ContentSecurityPolicy::for_profile(Profile::Response, framing.as_ref());
        let value = framed.header_value();
        let rest = value.strip_suffix("frame-ancestors https://a.example https://b.example");
        let same_origin_rest = RESPONSE_SAME_ORIGIN.strip_suffix("frame-ancestors 'self'");
        assert!(
            rest.is_some() && rest == same_origin_rest,
            "the embed list replaces only the `frame-ancestors` sources: {value}"
        );
        assert!(value.starts_with("default-src 'none'; "), "{value}");
        assert_ne!(value, "frame-ancestors https://a.example https://b.example");
        assert_eq!(
            framing
                .as_ref()
                .map(|fa| ContentSecurityPolicy::frame_only(fa).header_value()),
            Some("frame-ancestors https://a.example https://b.example".to_owned())
        );
    }
}

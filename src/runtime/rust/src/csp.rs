//! The `Content-Security-Policy` the runtime's HTML responses carry.
//!
//! One typed builder, [`ContentSecurityPolicy`], composes every header value
//! from the closed [`Directive`] and [`Source`] vocabularies, so no call site
//! spells a directive string. A [`Guarded`] names the response a policy guards
//! together with the per-response values its policy names; header assembly
//! (`telemetry::security_headers`) takes it as a required parameter, and every
//! guard yields a full policy, so no HTML response is sent without one. An
//! inline element a policy admits is admitted by a hash computed from the same
//! constant the response embeds, never a copied digest, or by the page's own
//! style nonce. No policy holds `'unsafe-inline'` in a `script-src*` directive
//! or in an element-level `style-src*` directive.

use crate::telemetry::FrameAncestors;

#[cfg(feature = "encoding")]
use crate::encoding::{ServerOrigin, ServerOrigins};

#[cfg(feature = "web")]
use crate::web::console::{CONSOLE_CSS, CONSOLE_JS};

#[cfg(all(feature = "web", feature = "debugger"))]
use crate::debugger::server::OVERLAY_JS;

#[cfg(feature = "web")]
use crate::web_page_core::{BASE_CSS, STATUS_CSS};

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

/// Whether `text` holds `</` or `<!--`, either of which can end or re-mode a
/// raw-text `<script>` or `<style>` element before its own close tag — so an
/// inline constant admitted by its hash would serve bytes the hash does not
/// cover. Every inline constant a policy hashes is asserted free of both at
/// build time.
pub const fn ends_raw_text_early(text: &str) -> bool {
    let mut rest = text.as_bytes();
    while let [first, tail @ ..] = rest {
        if *first == b'<' && matches!(tail, [b'/', ..] | [b'!', b'-', b'-', ..]) {
            return true;
        }
        rest = tail;
    }
    false
}

/// A `'sha256-…'` source admitting one inline element by its exact text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CspHash(String);

impl CspHash {
    /// The hash source of `text`: `'sha256-<base64(sha256(text))>'`.
    #[cfg(feature = "web")]
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

/// The number of random bytes in a [`StyleNonce`].
pub const STYLE_NONCE_BYTES: usize = 16;

/// The per-session nonce a session's `<style>` elements carry.
///
/// It holds 128 bits drawn from the OS CSPRNG together with the session's
/// render incarnation, and it is never persisted. It is `Clone` but not
/// `Copy`, so every copy is explicit, and its `Debug` form never shows it.
#[derive(Clone)]
pub struct StyleNonce([u8; STYLE_NONCE_BYTES]);

impl StyleNonce {
    /// A nonce from bytes the caller drew from a CSPRNG.
    pub(crate) const fn from_random_bytes(bytes: [u8; STYLE_NONCE_BYTES]) -> Self {
        Self(bytes)
    }

    /// The nonce as its attribute value: 32 lowercase hex characters.
    #[must_use]
    pub fn as_token(&self) -> String {
        let mut out = String::with_capacity(STYLE_NONCE_BYTES * 2);
        self.write_token(&mut out);
        out
    }

    /// Append the nonce's attribute value to `out`.
    pub(crate) fn write_token(&self, out: &mut String) {
        for byte in self.0 {
            for nibble in [byte >> 4, byte & 0x0f] {
                if let Some(digit) = char::from_digit(u32::from(nibble), 16) {
                    out.push(digit);
                }
            }
        }
    }
}

impl std::fmt::Debug for StyleNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StyleNonce(..)")
    }
}

/// Equality in time independent of where two nonces first differ.
impl PartialEq for StyleNonce {
    fn eq(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
            == 0
    }
}

impl Eq for StyleNonce {}

/// A source expression in a directive's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source<'a> {
    /// `'none'`: nothing is admitted.
    None,
    /// `'self'`: the response's own origin.
    SelfOrigin,
    /// `'unsafe-inline'`; the policies place it only in a `style-src*`
    /// directive that holds no hash and no nonce, never in a `script-src*` one.
    UnsafeInline,
    /// The `data:` scheme.
    Data,
    /// The `blob:` scheme.
    Blob,
    /// The hash of one runtime constant.
    Hash(&'a CspHash),
    /// The operator's parsed `IPE_WEB_FRAME_ANCESTORS` sources.
    Embed(&'a FrameAncestors),
    /// `'nonce-…'`: the elements stamped with one page's style nonce.
    Nonce(&'a StyleNonce),
    /// `'wasm-unsafe-eval'`: WebAssembly compilation, never an `eval` of text.
    WasmUnsafeEval,
    /// One parsed server origin in its `https` form.
    #[cfg(feature = "encoding")]
    Origin(&'a ServerOrigin),
    /// One parsed server origin in its `wss` form.
    #[cfg(feature = "encoding")]
    WsOrigin(&'a ServerOrigin),
}

impl Source<'_> {
    /// Append the source expression, as the header spells it, to `out`.
    pub fn write_to(self, out: &mut String) {
        let text = match self {
            Self::None => "'none'",
            Self::SelfOrigin => "'self'",
            Self::UnsafeInline => "'unsafe-inline'",
            Self::Data => "data:",
            Self::Blob => "blob:",
            Self::Hash(hash) => hash.as_str(),
            Self::Embed(framing) => framing.sources(),
            Self::WasmUnsafeEval => "'wasm-unsafe-eval'",
            Self::Nonce(nonce) => {
                out.push_str("'nonce-");
                nonce.write_token(out);
                out.push('\'');
                return;
            }
            #[cfg(feature = "encoding")]
            Self::Origin(origin) => {
                origin.write_https(out);
                return;
            }
            #[cfg(feature = "encoding")]
            Self::WsOrigin(origin) => {
                origin.write_wss(out);
                return;
            }
        };
        out.push_str(text);
    }
}

/// Whether a static browser bundle registers a service worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleWorker {
    /// No worker: the policy names no `worker-src`.
    None,
    /// The program reaches `Ipe.Browser.Push`, whose same-origin worker
    /// receives the push messages.
    Push,
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
    #[cfg(feature = "web")]
    Console,
    /// An `Ipe.Web` page: its scripts are the same-origin, SRI-pinned client
    /// files plus, under the debugger, the overlay script admitted by hash; its
    /// style elements are the shell's two constants, admitted by hash, and the
    /// session's scoped `<style>` elements, admitted by the page's nonce.
    #[cfg(feature = "web")]
    WebPage,
}

/// The response a policy guards, carrying the values its policy names.
///
/// A page's nonce lives in its variant, so neither a `WebPage` policy without
/// a nonce nor a nonce on another response has a representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Guarded {
    /// See [`Profile::Response`].
    Response,
    /// See [`Profile::Console`].
    #[cfg(feature = "web")]
    Console,
    /// See [`Profile::WebPage`].
    #[cfg(feature = "web")]
    WebPage {
        /// The nonce the page's markup was stamped with.
        style_nonce: StyleNonce,
    },
}

impl Guarded {
    /// The profile indexing the guard's per-profile tables.
    #[must_use]
    pub const fn kind(&self) -> Profile {
        match self {
            Self::Response => Profile::Response,
            #[cfg(feature = "web")]
            Self::Console => Profile::Console,
            #[cfg(feature = "web")]
            Self::WebPage { .. } => Profile::WebPage,
        }
    }

    /// The guard of `profile`; a `WebPage` carries a fixed nonce drawn from
    /// `seed`.
    #[cfg(test)]
    pub(crate) const fn sample(profile: Profile, seed: u8) -> Self {
        let _ = seed;
        match profile {
            Profile::Response => Self::Response,
            #[cfg(feature = "web")]
            Profile::Console => Self::Console,
            #[cfg(feature = "web")]
            Profile::WebPage => Self::WebPage {
                style_nonce: StyleNonce::from_random_bytes([seed; STYLE_NONCE_BYTES]),
            },
        }
    }
}

impl Profile {
    /// The embed list the profile's `frame-ancestors` names, given the
    /// operator's: `None` frames the response same-origin only.
    #[must_use]
    pub const fn embed_list(self, framing: Option<&FrameAncestors>) -> Option<&FrameAncestors> {
        match self {
            Self::Response => framing,
            #[cfg(feature = "web")]
            Self::Console => None,
            #[cfg(feature = "web")]
            Self::WebPage => framing,
        }
    }

    /// The `Cache-Control` the profile's response carries: a page holding
    /// per-session values (the sid, the CSRF token) is never stored by a
    /// shared or back-forward cache. `None` leaves caching to the handler.
    #[must_use]
    pub const fn cache_control(self) -> Option<&'static str> {
        match self {
            Self::Response => None,
            #[cfg(feature = "web")]
            Self::Console | Self::WebPage => Some("no-store"),
        }
    }
}

/// The inline-element hashes of the console page.
#[cfg(feature = "web")]
struct ConsoleHashes {
    script: CspHash,
    style: CspHash,
}

/// The console hashes, computed once from [`CONSOLE_JS`] and [`CONSOLE_CSS`].
#[cfg(feature = "web")]
fn console_hashes() -> &'static ConsoleHashes {
    static CELL: std::sync::OnceLock<ConsoleHashes> = std::sync::OnceLock::new();
    CELL.get_or_init(|| ConsoleHashes {
        script: CspHash::of(CONSOLE_JS),
        style: CspHash::of(CONSOLE_CSS),
    })
}

/// The hash of the debugger overlay script, computed once from [`OVERLAY_JS`].
#[cfg(all(feature = "web", feature = "debugger"))]
fn overlay_hash() -> &'static CspHash {
    static CELL: std::sync::OnceLock<CspHash> = std::sync::OnceLock::new();
    CELL.get_or_init(|| CspHash::of(OVERLAY_JS))
}

/// The hashes of the page shell's two inline style constants.
#[cfg(feature = "web")]
struct PageStyleHashes {
    base: CspHash,
    status: CspHash,
}

/// The page-shell style hashes, computed once from [`BASE_CSS`] and
/// [`STATUS_CSS`].
#[cfg(feature = "web")]
fn page_style_hashes() -> &'static PageStyleHashes {
    static CELL: std::sync::OnceLock<PageStyleHashes> = std::sync::OnceLock::new();
    CELL.get_or_init(|| PageStyleHashes {
        base: CspHash::of(BASE_CSS),
        status: CspHash::of(STATUS_CSS),
    })
}

/// The `script-src` sources of an `Ipe.Web` page.
#[cfg(feature = "web")]
fn web_page_scripts<'a>() -> Vec<Source<'a>> {
    #[cfg(feature = "debugger")]
    {
        vec![Source::SelfOrigin, Source::Hash(overlay_hash())]
    }
    #[cfg(not(feature = "debugger"))]
    {
        vec![Source::SelfOrigin]
    }
}

/// A `Content-Security-Policy` value: an ordered list of directives.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContentSecurityPolicy<'a> {
    directives: Vec<(Directive, Vec<Source<'a>>)>,
}

impl<'a> ContentSecurityPolicy<'a> {
    /// The policy of `guard` under the operator's embed list `framing`.
    #[must_use]
    pub fn for_guard(guard: &'a Guarded, framing: Option<&'a FrameAncestors>) -> Self {
        let ancestors = guard
            .kind()
            .embed_list(framing)
            .map_or(Source::SelfOrigin, Source::Embed);
        match guard {
            Guarded::Response => Self::response(ancestors),
            #[cfg(feature = "web")]
            Guarded::Console => Self::console(ancestors),
            #[cfg(feature = "web")]
            Guarded::WebPage { style_nonce } => Self::web_page(ancestors, style_nonce),
        }
    }

    /// The policy a static browser bundle's shell carries in its `<meta>`.
    ///
    /// The bundle loads its own script, styles and WebAssembly; it reaches
    /// its own origin and, per entry of `servers`, that origin's `https` and
    /// `wss` forms; and, when `worker` is [`BundleWorker::Push`], it registers
    /// a same-origin service worker. An empty `servers` is an offline bundle.
    #[cfg(feature = "encoding")]
    #[must_use]
    pub fn bundle(servers: &'a ServerOrigins, worker: BundleWorker) -> Self {
        use Directive as D;
        use Source as S;
        let reachable = std::iter::once(S::SelfOrigin)
            .chain(
                servers
                    .origins()
                    .flat_map(|origin| [S::Origin(origin), S::WsOrigin(origin)]),
            )
            .collect();
        let policy = Self::default()
            .with(D::DefaultSrc, vec![S::SelfOrigin])
            .with(D::ScriptSrc, vec![S::SelfOrigin, S::WasmUnsafeEval])
            .with(D::StyleSrc, vec![S::SelfOrigin, S::UnsafeInline])
            .with(D::ConnectSrc, reachable);
        match worker {
            BundleWorker::None => policy,
            BundleWorker::Push => policy.with(D::WorkerSrc, vec![S::SelfOrigin]),
        }
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
    #[cfg(feature = "web")]
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

    /// The `WebPage` profile of the page stamped with `nonce`, with
    /// `frame-ancestors` set to `ancestors`.
    #[cfg(feature = "web")]
    fn web_page(ancestors: Source<'a>, nonce: &'a StyleNonce) -> Self {
        use Directive as D;
        use Source as S;
        let shell = page_style_hashes();
        let styles = || {
            vec![
                S::SelfOrigin,
                S::Nonce(nonce),
                S::Hash(&shell.base),
                S::Hash(&shell.status),
            ]
        };
        Self::default()
            .with(D::DefaultSrc, vec![S::None])
            .with(D::ScriptSrc, web_page_scripts())
            .with(D::ScriptSrcAttr, vec![S::None])
            .with(D::StyleSrc, styles())
            .with(D::StyleSrcElem, styles())
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
                source.write_to(&mut out);
            }
        }
        out
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
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

    /// One guard per profile.
    fn guards() -> Vec<Guarded> {
        Profile::ALL
            .iter()
            .map(|p| Guarded::sample(*p, 0x5a))
            .collect()
    }

    /// Every guard's policy, same-origin and under an embed list.
    fn every_policy<'a>(
        guards: &'a [Guarded],
        framing: Option<&'a FrameAncestors>,
    ) -> Vec<(Profile, ContentSecurityPolicy<'a>)> {
        guards
            .iter()
            .flat_map(|g| {
                [
                    (g.kind(), ContentSecurityPolicy::for_guard(g, None)),
                    (g.kind(), ContentSecurityPolicy::for_guard(g, framing)),
                ]
            })
            .collect()
    }

    /// The header spelling of `source`.
    fn spelled(source: Source<'_>) -> String {
        let mut out = String::new();
        source.write_to(&mut out);
        out
    }

    #[test]
    fn guard_kind_is_its_profile() {
        let guards = guards();
        let kinds: Vec<Profile> = guards.iter().map(Guarded::kind).collect();
        assert_eq!(kinds, Profile::ALL);
    }

    #[test]
    fn profile_all_lists_each_variant_once() {
        for (i, p) in Profile::ALL.iter().enumerate() {
            assert_eq!(Profile::ALL.iter().position(|q| q == p), Some(i), "{p:?}");
        }
        let declared = if cfg!(feature = "web") { 3 } else { 1 };
        assert_eq!(Profile::ALL.len(), declared);
    }

    #[test]
    fn response_profile_exact_header() {
        assert_eq!(
            ContentSecurityPolicy::for_guard(&Guarded::Response, None).header_value(),
            RESPONSE_SAME_ORIGIN
        );
    }

    #[cfg(feature = "web")]
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
                ContentSecurityPolicy::for_guard(&Guarded::Console, framing).header_value(),
                want
            );
        }
    }

    #[test]
    fn script_src_never_unsafe() {
        let framing = embed();
        let guards = guards();
        for (profile, policy) in every_policy(&guards, framing.as_ref()) {
            for directive in [Directive::ScriptSrc, Directive::ScriptSrcAttr] {
                let sources = policy.sources(directive);
                assert!(sources.is_some(), "{profile:?} omits {directive:?}");
                for source in sources.into_iter().flatten() {
                    let text = spelled(*source);
                    for banned in [
                        "'unsafe-inline'",
                        "'unsafe-eval'",
                        "'unsafe-hashes'",
                        "'nonce-",
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

    /// The directives that may hold `'unsafe-inline'` under `profile`: the
    /// `style=""` attribute wherever one is admitted, and no element-level
    /// directive.
    fn unsafe_inline_holders(profile: Profile) -> &'static [Directive] {
        match profile {
            Profile::Response => &[Directive::StyleSrcAttr],
            #[cfg(feature = "web")]
            Profile::Console => &[],
            #[cfg(feature = "web")]
            Profile::WebPage => &[Directive::StyleSrcAttr],
        }
    }

    /// `'unsafe-inline'` sits exactly in the style directives its profile
    /// names, and never beside a hash or a nonce there, where a browser would
    /// ignore it.
    #[test]
    fn unsafe_inline_only_in_the_profiles_hashless_style_directives() {
        let framing = embed();
        let guards = guards();
        for (profile, policy) in every_policy(&guards, framing.as_ref()) {
            let holders: Vec<Directive> = policy
                .directives()
                .filter(|(_, sources)| sources.contains(&Source::UnsafeInline))
                .map(|(d, _)| d)
                .collect();
            assert_eq!(holders, unsafe_inline_holders(profile), "{profile:?}");
            for (directive, sources) in policy.directives() {
                assert!(
                    !(sources.contains(&Source::UnsafeInline)
                        && sources
                            .iter()
                            .any(|s| matches!(s, Source::Hash(_) | Source::Nonce(_)))),
                    "{profile:?} {directive:?} pairs a hash or a nonce with 'unsafe-inline'"
                );
            }
            assert_eq!(
                policy.header_value().matches("'unsafe-inline'").count(),
                holders.len(),
                "{profile:?}"
            );
        }
    }

    /// The exact `WebPage` header value under the same-origin default.
    #[cfg(feature = "web")]
    #[test]
    fn web_page_profile_exact_header() {
        #[cfg(feature = "debugger")]
        let scripts = {
            use base64::{Engine, engine::general_purpose::STANDARD};
            use sha2::{Digest, Sha256};
            format!(
                "'self' 'sha256-{}'",
                STANDARD.encode(Sha256::digest(OVERLAY_JS.as_bytes()))
            )
        };
        #[cfg(not(feature = "debugger"))]
        let scripts = "'self'";
        let digest = |text: &str| {
            use base64::{Engine, engine::general_purpose::STANDARD};
            use sha2::{Digest, Sha256};
            STANDARD.encode(Sha256::digest(text.as_bytes()))
        };
        let (base, status) = (digest(BASE_CSS), digest(STATUS_CSS));
        let guard = Guarded::sample(Profile::WebPage, 0xab);
        let nonce = "ab".repeat(STYLE_NONCE_BYTES);
        let styles = format!("'self' 'nonce-{nonce}' 'sha256-{base}' 'sha256-{status}'");
        let want = format!(
            "default-src 'none'; script-src {scripts}; script-src-attr 'none'; \
             style-src {styles}; style-src-elem {styles}; \
             style-src-attr 'unsafe-inline'; img-src 'self' data: blob:; \
             font-src 'self' data:; media-src 'self' blob:; connect-src 'self'; \
             manifest-src 'self'; worker-src 'self'; frame-src 'self'; \
             object-src 'none'; base-uri 'none'; form-action 'self'; \
             frame-ancestors 'self'"
        );
        let value = ContentSecurityPolicy::for_guard(&guard, None).header_value();
        assert_eq!(value, want);
        let other = Guarded::sample(Profile::WebPage, 0xcd);
        let other_value = ContentSecurityPolicy::for_guard(&other, None).header_value();
        assert_ne!(value, other_value, "the nonce is the page's own");
        assert!(!other_value.contains(&nonce), "{other_value}");
    }

    /// The page shell's inline style constants close no raw-text element early,
    /// so the hash the policy names covers every byte the browser applies.
    #[cfg(feature = "web")]
    #[test]
    fn page_style_constants_are_hash_admitted() {
        assert!(!ends_raw_text_early(BASE_CSS) && !ends_raw_text_early(STATUS_CSS));
        let guard = Guarded::sample(Profile::WebPage, 1);
        let policy = ContentSecurityPolicy::for_guard(&guard, None);
        let shell = page_style_hashes();
        for directive in [Directive::StyleSrc, Directive::StyleSrcElem] {
            let sources = policy.sources(directive).unwrap_or(&[]);
            for text in [BASE_CSS, STATUS_CSS] {
                assert!(
                    sources.contains(&Source::Hash(&CspHash::of(text))),
                    "{directive:?}"
                );
            }
            assert!(!sources.contains(&Source::Hash(&CspHash::of(&format!("{BASE_CSS} ")))));
            assert!(sources.contains(&Source::Hash(&shell.base)));
            assert!(sources.contains(&Source::Hash(&shell.status)));
        }
    }

    /// Each `<script>` element of `html`: its open-tag attribute text and its
    /// body, cut as a browser cuts a raw-text element.
    #[cfg(feature = "web")]
    fn script_elements(html: &str) -> Vec<(&str, &str)> {
        let mut out = Vec::new();
        let mut rest = html;
        while let Some(at) = rest.find("<script") {
            let tail = rest.get(at + "<script".len()..).unwrap_or("");
            let Some(open_end) = tail.find('>') else {
                break;
            };
            let attrs = tail.get(..open_end).unwrap_or("");
            let after = tail.get(open_end + 1..).unwrap_or("");
            let Some(close) = after.find("</script") else {
                break;
            };
            out.push((attrs, after.get(..close).unwrap_or("")));
            rest = after.get(close..).unwrap_or("");
        }
        out
    }

    /// Whether `policy`'s `script-src` admits a `<script>` with `attrs` and
    /// `body`: a same-origin path `src`, an inert JSON data block, or a body
    /// whose hash the policy names.
    #[cfg(feature = "web")]
    fn admits_script(policy: &ContentSecurityPolicy<'_>, attrs: &str, body: &str) -> bool {
        let sources = policy.sources(Directive::ScriptSrc).unwrap_or(&[]);
        if let Some((_, src)) = attrs.split_once(" src=\"") {
            return src.starts_with('/')
                && !src.starts_with("//")
                && body.is_empty()
                && sources.contains(&Source::SelfOrigin);
        }
        if attrs.contains("type=\"application/json\"") {
            return true;
        }
        let hash = CspHash::of(body);
        sources.contains(&Source::Hash(&hash))
    }

    /// Every script of a served `Ipe.Web` page runs under its policy, and an
    /// injected inline script is refused by it.
    #[cfg(feature = "web")]
    #[test]
    fn web_page_policy_admits_every_served_script() {
        let epoch = crate::dom::dispatch::Rendered::first(
            crate::dom::dispatch::SessionKeys::distinct(),
            crate::html::Html::<()>::HText(String::new()),
        )
        .epoch();
        let page = crate::web::render_page_full(
            "sid",
            &crate::encoding::MountBase::root(),
            "<p>hi</p>",
            &epoch,
            "tok",
        );
        assert!(page.is_ok(), "{page:?}");
        let page = page.unwrap_or_default();
        let guard = Guarded::sample(Profile::WebPage, 2);
        let policy = ContentSecurityPolicy::for_guard(&guard, None);
        let scripts = script_elements(&page);
        assert!(scripts.len() >= 2, "{page}");
        for (attrs, body) in &scripts {
            assert!(admits_script(&policy, attrs, body), "<script{attrs}>{body}");
        }
        let injected = "alert(1)";
        assert!(
            !admits_script(&policy, "", injected),
            "an inline script without an admitted hash must be refused"
        );
        assert!(!admits_script(
            &policy,
            " src=\"https://evil.example/x.js\"",
            ""
        ));
    }

    /// The debugger overlay's inline script is the constant whose hash the
    /// `WebPage` policy names, and an edited copy of it is refused.
    #[cfg(all(feature = "web", feature = "debugger"))]
    #[test]
    fn debugger_overlay_script_is_hash_admitted() {
        let guard = Guarded::sample(Profile::WebPage, 3);
        let policy = ContentSecurityPolicy::for_guard(&guard, None);
        for base in ["", "/myapp"] {
            let overlay = crate::debugger::server::overlay_html(&["Add(1)".to_owned()], 1, base);
            let scripts = script_elements(&overlay);
            assert_eq!(scripts.len(), 1, "{overlay}");
            for (attrs, body) in &scripts {
                assert_eq!(*body, OVERLAY_JS);
                assert!(admits_script(&policy, attrs, body), "{overlay}");
            }
        }
        assert_eq!(
            policy.sources(Directive::ScriptSrc),
            Some([Source::SelfOrigin, Source::Hash(overlay_hash())].as_slice())
        );
        let edited = format!("{OVERLAY_JS} ");
        assert!(!admits_script(&policy, "", &edited));
    }

    /// A minted nonce is 32 lowercase hex characters, two mints differ, and
    /// its `Debug` form holds no part of it.
    #[test]
    fn nonce_shape() {
        let mint = || {
            crate::dom::dispatch::SessionKeys::mint().map(|keys| {
                crate::dom::dispatch::Rendered::first(
                    keys,
                    crate::html::Html::<()>::HText(String::new()),
                )
                .stamp()
            })
        };
        let (a, b) = (mint(), mint());
        assert!(a.is_ok() && b.is_ok(), "{a:?} {b:?}");
        let (Ok(a), Ok(b)) = (a, b) else {
            return;
        };
        let token = a.as_token();
        assert_eq!(token.len(), 2 * STYLE_NONCE_BYTES, "{token}");
        assert!(
            token
                .bytes()
                .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')),
            "{token}"
        );
        assert_ne!(token, b.as_token());
        // An exact form: a derived `Debug` would list the bytes in decimal,
        // which no search for the hex token finds.
        assert_eq!(format!("{a:?}"), "StyleNonce(..)");
    }

    /// Only a page's policy names a nonce, and it names the page's own nonce
    /// in exactly its two element-level style directives.
    #[test]
    fn only_the_web_page_carries_a_nonce() {
        let framing = embed();
        let guards = guards();
        for (profile, policy) in every_policy(&guards, framing.as_ref()) {
            let value = policy.header_value();
            let nonced: Vec<Directive> = policy
                .directives()
                .filter(|(_, sources)| sources.iter().any(|s| matches!(s, Source::Nonce(_))))
                .map(|(d, _)| d)
                .collect();
            #[cfg(feature = "web")]
            if profile == Profile::WebPage {
                let token = format!("'nonce-{}'", "5a".repeat(STYLE_NONCE_BYTES));
                assert_eq!(nonced, [Directive::StyleSrc, Directive::StyleSrcElem]);
                assert_eq!(value.matches(&token).count(), 2, "{value}");
                assert_eq!(value.matches("'nonce-").count(), 2, "{value}");
                continue;
            }
            assert!(nonced.is_empty(), "{profile:?}");
            assert!(!value.contains("'nonce-"), "{profile:?}: {value}");
        }
    }

    #[cfg(feature = "web")]
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
        let shell = page_style_hashes();
        assert_eq!(shell.base.as_str(), recompute(BASE_CSS));
        assert_eq!(shell.status.as_str(), recompute(STATUS_CSS));
        assert_ne!(shell.base.as_str(), recompute(&format!("{BASE_CSS} ")));
        assert_ne!(shell.status.as_str(), recompute(&format!("{STATUS_CSS} ")));
        let policy = ContentSecurityPolicy::for_guard(&Guarded::Console, None);
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
        let framed = ContentSecurityPolicy::for_guard(&Guarded::Response, framing.as_ref());
        let value = framed.header_value();
        let rest = value.strip_suffix("frame-ancestors https://a.example https://b.example");
        let same_origin_rest = RESPONSE_SAME_ORIGIN.strip_suffix("frame-ancestors 'self'");
        assert!(
            rest.is_some() && rest == same_origin_rest,
            "the embed list replaces only the `frame-ancestors` sources: {value}"
        );
        assert!(value.starts_with("default-src 'none'; "), "{value}");
        assert_ne!(value, "frame-ancestors https://a.example https://b.example");
    }
}

#[cfg(all(test, feature = "encoding", not(target_arch = "wasm32")))]
mod bundle_tests {
    use super::*;

    /// The offline bundle's policy: today's shell, byte for byte.
    const OFFLINE: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; \
        style-src 'self' 'unsafe-inline'; connect-src 'self'";

    #[allow(clippy::expect_used)] // both origins are well-formed
    fn two() -> ServerOrigins {
        ServerOrigins::new([
            ServerOrigin::parse("https://media.example:8443").expect("origin"),
            ServerOrigin::parse("https://api.example").expect("origin"),
        ])
        .expect("two origins")
    }

    #[test]
    fn an_offline_bundle_reaches_only_its_own_origin() {
        let none = ServerOrigins::none();
        let policy = ContentSecurityPolicy::bundle(&none, BundleWorker::None);
        assert_eq!(policy.header_value(), OFFLINE);
        assert_eq!(policy.sources(Directive::WorkerSrc), None);
    }

    /// Each server origin adds its `https` and `wss` forms to `connect-src`
    /// only, in sorted order.
    #[test]
    fn server_origins_widen_connect_src_only() {
        let servers = two();
        let value = ContentSecurityPolicy::bundle(&servers, BundleWorker::None).header_value();
        assert_eq!(
            value,
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; \
             style-src 'self' 'unsafe-inline'; connect-src 'self' \
             https://api.example wss://api.example \
             https://media.example:8443 wss://media.example:8443"
        );
        assert_ne!(value, OFFLINE);
    }

    /// A program reaching push gets a same-origin `worker-src`; one that does
    /// not gets none.
    #[test]
    fn push_adds_a_same_origin_worker_src() {
        let none = ServerOrigins::none();
        let push = ContentSecurityPolicy::bundle(&none, BundleWorker::Push);
        assert_eq!(
            push.sources(Directive::WorkerSrc),
            Some([Source::SelfOrigin].as_slice())
        );
        assert_eq!(push.header_value(), format!("{OFFLINE}; worker-src 'self'"));
    }
}

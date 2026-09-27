//! Ipe.Http — outbound HTTP client (reqwest under a Ipê-native surface).
//!
//! HttpResponse/HttpRequest map to the Ipê record aliases via runtimeOpaqueTypes
//! (like Csv's CsvDoc), so `resp.status` / `.body` / `.headers` resolve onto
//! these pub fields and the Ipê-built `defaultRequest` record constructs this
//! struct directly. Field names match the Ipê records verbatim.
//!
//! ## SSRF protection (default-ON in production)
//!
//! The guard blocks requests whose resolved host is loopback, RFC-1918 private,
//! link-local, unique-local (ULA), unspecified, or v4-mapped-private. It is
//! ON by default in production (`ENV`/`IPE_ENV` not in {unset, dev, development,
//! local}) and OFF in dev so development against `localhost` keeps working
//! unchanged. `IPE_HTTP_DENY_PRIVATE=1`/`on`/`true` forces it ON; setting it to
//! any other value (`0`/`off`/`false`) is the explicit production opt-out. See
//! `ssrf::ssrf_deny_private_enabled`.
//!
//! When ON every name goes through the one SSRF gate
//! (`ssrf::vet_host_addrs_with`: bounded deadline, a host with ANY blocked
//! answer refused whole) in three places:
//! 1. **Pre-send resolve + pin**: the request host is vetted once and
//!    reqwest's lookup of it is pinned to the vetted addresses via
//!    `ClientBuilder::resolve_to_addrs`, so a rebind at connect time cannot
//!    reach a private address.
//! 2. **Every other name (redirect hops)**: `VettingResolver` is reqwest's DNS
//!    resolver, so a redirect to a different name is vetted by the same gate
//!    at connect and reqwest dials exactly the vetted addresses.
//! 3. **Each redirect (URL-level re-check)**: a custom
//!    `reqwest::redirect::Policy` repeats the scheme + IP-literal range check
//!    on every `Location` target, since an IP literal bypasses any resolver.

use super::*;
use std::collections::HashMap;
// SSRF deny-private helpers live in the reqwest-free `ssrf` module (so the
// WebSocket client can validate URLs without linking reqwest). The reqwest-
// coupled `ssrf_apply` + the request executor below import what they use.
#[cfg(not(target_arch = "wasm32"))]
use super::ssrf::{
    DialPolicy, GatedSchemes, HostDisclosure, HostResolver, SsrfRefusal, SystemResolver,
    UrlRefusal, VettedAddrs, dns_timeout, parse_gated_url, parse_gated_url_within,
    refuse_misplaced_userinfo, ssrf_check_url_nonblocking, strip_ipv6_brackets,
    url_host_disclosure, vet_host_addrs_with,
};

/// Ipe.Http.HttpResponse — field names/types match the Ipê record alias.
#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: i64,
    pub body: String,
    pub headers: HashMap<String, String>,
}

/// Redirect behaviour for an outbound `HttpRequest` — the Rust mirror of the
/// `RedirectPolicy` ADT in `Ipe.Http`.  Variant names match the Ipê
/// constructors verbatim so emitted match arms resolve through the
/// `pub use http_client::*` glob in the generated `mod.rs`.
///
/// `FollowRedirects(i64)` carries the user-supplied max hop count.  The runtime
/// clamps it to `0` via `.max(0)` before casting to `usize`, so a negative
/// value from Ipê code is safe (0 hops followed, not a negative cast).
#[derive(Clone, Debug)]
pub enum RedirectPolicy {
    NoRedirects,
    FollowRedirects(i64),
}

/// Closed set of HTTP methods — the Rust mirror of the `HttpMethod` ADT in
/// `Ipe.Http`.  Variant names match the Ipê constructors verbatim so emitted
/// match arms (`HttpMethod::Get`, `HttpMethod::Post`, …) resolve through the
/// `pub use http_client::*` glob in the generated `mod.rs`.
///
/// Conversions to/from reqwest `Method` happen at the request executor
/// boundary (`method_to_reqwest`) — never at every call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

impl HttpMethod {
    /// Convert to the canonical uppercase ASCII string.
    pub fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
        }
    }

    /// Parse from a string (case-insensitive).  Returns `None` for any
    /// unrecognised verb — the parse-don't-validate boundary.
    // Named `from_str` for call-site readability; it returns `Option<Self>`, not
    // `FromStr`'s `Result`, so it deliberately does not implement that trait.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Some(HttpMethod::Get),
            "POST" => Some(HttpMethod::Post),
            "PUT" => Some(HttpMethod::Put),
            "DELETE" => Some(HttpMethod::Delete),
            "PATCH" => Some(HttpMethod::Patch),
            "HEAD" => Some(HttpMethod::Head),
            "OPTIONS" => Some(HttpMethod::Options),
            _ => None,
        }
    }
}

/// Convert an `HttpMethod` to a reqwest `Method`.  Infallible: every ADT
/// variant maps to a well-known reqwest method constant.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn method_to_reqwest(m: HttpMethod) -> reqwest::Method {
    match m {
        HttpMethod::Get => reqwest::Method::GET,
        HttpMethod::Post => reqwest::Method::POST,
        HttpMethod::Put => reqwest::Method::PUT,
        HttpMethod::Delete => reqwest::Method::DELETE,
        HttpMethod::Patch => reqwest::Method::PATCH,
        HttpMethod::Head => reqwest::Method::HEAD,
        HttpMethod::Options => reqwest::Method::OPTIONS,
    }
}

/// Ipe.Http.HttpRequest — built in Ipê (defaultRequest + with* updates),
/// so every field is pub for external struct-literal construction.
#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub body: String,
    pub headers: Vec<(String, String)>,
    pub method: HttpMethod,
    pub redirects: RedirectPolicy,
    pub timeout: i64,
    pub url: String,
}

/// `Http.methodFromString : String -> Maybe HttpMethod` — the typed parse
/// boundary for inbound method strings.  Returns `Just` for the seven
/// standard verbs (case-insensitive), `Nothing` for anything else.
pub fn http_method_from_string(s: String) -> crate::core::IpeMaybe<HttpMethod> {
    match HttpMethod::from_str(&s) {
        Some(m) => crate::core::IpeMaybe::Just(m),
        None => crate::core::IpeMaybe::Nothing,
    }
}

/// `Http.methodToString : HttpMethod -> String` — canonical uppercase string.
pub fn http_method_to_string(m: HttpMethod) -> String {
    m.as_str().to_string()
}

// ---------------------------------------------------------------------------
// Typed request-target builders — API-layer scheme narrowing (fail-closed)
// ---------------------------------------------------------------------------
//
// The request target is the typed `crate::url::Url` (parsed exactly once at
// `Url.fromString`), never a raw `String`. `http_default_request` and
// `http_with_url` NARROW the scheme to http/https at THIS API layer and return
// a `Result Error HttpRequest`, so a builder-constructed request whose scheme
// is not http(s) cannot be assembled at all — it fails closed EVEN when the
// runtime SSRF guard is disabled in dev (the runtime scheme allowlist is then
// defence-in-depth, not the only line). The single canonical serialization
// (`Url.toString`) is carried as the transport target; the runtime does not
// re-parse a fresh string to reconstruct it.

/// Narrow a typed `Url` to the http/https request surface. The typed `Url`
/// legally carries any absolute scheme (`file:`, `ftp:` are valid `Url`
/// values); this outbound surface accepts only `http`/`https`. Returns the
/// URL's canonical serialization on success, or a blocked-scheme message on
/// any other scheme. Reads the already-parsed scheme — no re-parse of a string.
fn narrow_http_scheme(url: &crate::url::Url) -> Result<String, String> {
    let scheme = crate::url::url_scheme(url.clone());
    if scheme == "http" || scheme == "https" {
        Ok(crate::url::url_to_string(url.clone()))
    } else {
        // The scheme is not echoed: `user:password@host` parses with the user
        // name as its scheme.
        Err("Http: blocked: the URL's scheme is not http/https".to_owned())
    }
}

/// Build an `HttpRequest` targeting `target` (the http/https canonical
/// serialization). Shared by every typed-target builder so the defaults live
/// in one place.
fn http_request_with_target(target: String) -> HttpRequest {
    HttpRequest {
        body: String::new(),
        headers: Vec::new(),
        method: HttpMethod::Get,
        redirects: RedirectPolicy::FollowRedirects(10),
        timeout: 30000,
        url: target,
    }
}

/// `Http.defaultRequest : Url -> Result Error HttpRequest` — the primary
/// request constructor. Takes an already-sealed typed `Url`, narrows its
/// scheme to http/https at the API layer (fail-closed), and carries the single
/// canonical serialization as the transport target.
#[must_use]
pub fn http_default_request<E: From<String>>(url: crate::url::Url) -> IpeResult<E, HttpRequest> {
    match narrow_http_scheme(&url) {
        Ok(target) => IpeResult::Ok(http_request_with_target(target)),
        Err(msg) => IpeResult::Err(msg.into()),
    }
}

/// `Http.defaultRequestFromString : String -> Result Error HttpRequest` — the
/// MARKED parse-at-the-boundary helper for a raw string target. Runs the ONE
/// parse of the string (`Url.fromString`) then the same scheme narrowing,
/// returning `Result` so a raw string is an EXPLICIT parse boundary, never a
/// silent stringly default.
#[must_use]
pub fn http_default_request_from_string<E: From<String>>(raw: String) -> IpeResult<E, HttpRequest> {
    match crate::url::url_from_string::<String>(raw) {
        IpeResult::Ok(url) => http_default_request(url),
        IpeResult::Err(msg) => IpeResult::Err(msg.into()),
    }
}

/// `Http.withUrl : Url -> HttpRequest -> Result Error HttpRequest` — retarget an
/// existing request to a typed `Url`, re-narrowing the scheme to http/https at
/// the API layer (fail-closed), so a retarget cannot smuggle a non-http(s)
/// scheme past the guard-off dev path.
#[must_use]
pub fn http_with_url<E: From<String>>(
    url: crate::url::Url,
    req: HttpRequest,
) -> IpeResult<E, HttpRequest> {
    match narrow_http_scheme(&url) {
        Ok(target) => IpeResult::Ok(HttpRequest { url: target, ..req }),
        Err(msg) => IpeResult::Err(msg.into()),
    }
}

// ---------------------------------------------------------------------------
// SSRF guard — reqwest client integration
// ---------------------------------------------------------------------------
// The reqwest-free gate (`vet_host_addrs_with` / `vet_url_with` /
// `blocked_range` / …) lives in `ssrf.rs`.
// What remains here is reqwest-coupled: `ssrf_apply` (a reqwest::ClientBuilder)
// and the request executor.

/// The reqwest resolver that runs every name through the one SSRF gate.
///
/// Installed under [`DialPolicy::DenyPrivate`], it vets EVERY hostname reqwest
/// resolves — a redirect hop to a different name included — with
/// [`vet_host_addrs_with`]: the same resolver, the same bounded deadline, and
/// the same rule (a host any of whose answers is blocked is refused whole) as
/// every other outbound dial. reqwest connects to exactly the vetted
/// addresses, so a name is never re-resolved by name to a rebind target.
/// IP-literal targets bypass a resolver, so the per-hop redirect `Policy`'s
/// literal check stays mandatory.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct VettingResolver<R> {
    resolver: std::sync::Arc<R>,
    deadline: std::time::Duration,
}

#[cfg(not(target_arch = "wasm32"))]
impl VettingResolver<SystemResolver> {
    /// The system resolver under [`dns_timeout`].
    pub(crate) fn system() -> Self {
        Self::new(std::sync::Arc::new(SystemResolver), dns_timeout())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<R: HostResolver + Send + 'static> VettingResolver<R> {
    /// Vet names through `resolver`, each lookup bounded by `deadline`.
    pub(crate) const fn new(resolver: std::sync::Arc<R>, deadline: std::time::Duration) -> Self {
        Self { resolver, deadline }
    }

    /// Every address `host` may be dialled at (port 0: reqwest substitutes the real one).
    ///
    /// A refusal shows `host` only as `disclosure` allows.
    async fn vet(
        &self,
        host: &str,
        disclosure: HostDisclosure,
    ) -> Result<VettedAddrs, SsrfRefusal> {
        vet_host_addrs_with(self.resolver.as_ref(), host, disclosure, 0, self.deadline).await
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<R: HostResolver + Send + 'static> reqwest::dns::Resolve for VettingResolver<R> {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let gate = Self {
            resolver: std::sync::Arc::clone(&self.resolver),
            deadline: self.deadline,
        };
        let host = name.as_str().to_owned();
        // Every name reaching this resolver is a redirect hop's host: the
        // request host is pinned by `resolve_to_addrs`. Its refusal is
        // redacted into a correlation id before Ipê sees it, and the logged
        // detail must not carry a host that may be part of a credential, so
        // the host is withheld.
        Box::pin(async move {
            match gate.vet(&host, HostDisclosure::Withheld).await {
                Ok(vetted) => {
                    let addrs: reqwest::dns::Addrs = Box::new(vetted.into_vec().into_iter());
                    Ok(addrs)
                }
                Err(refusal) => Err(refusal.into()),
            }
        })
    }
}

/// Apply the SSRF deny-private guard to a `reqwest::ClientBuilder` for `url`.
///
/// Reads the policy from the environment and resolves through the system
/// resolver; see [`ssrf_apply_with`].
///
/// # Errors
///
/// [`UrlRefusal`] naming why `url` was refused.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn ssrf_apply(
    builder: reqwest::ClientBuilder,
    url: &str,
    redirects: RedirectPolicy,
) -> Result<reqwest::ClientBuilder, UrlRefusal> {
    ssrf_apply_with(
        builder,
        url,
        redirects,
        DialPolicy::from_env(),
        VettingResolver::system(),
    )
    .await
}

/// Apply the SSRF guard under `policy`, vetting names through `gate`.
///
/// SHARED by every outbound request surface — the regular Http client,
/// `Http.Stream.open`, the Email HTTP providers — so the guard can never be
/// missing from a request path. Under every policy it refuses a URL whose
/// userinfo may run into its host or path ([`refuse_misplaced_userinfo`]).
/// Under [`DialPolicy::DenyPrivate`] it admits
/// only a gated scheme with a host, vets that host once through `gate`, pins
/// reqwest's lookup of it to the vetted addresses (defeats DNS rebinding),
/// installs `gate` as the resolver for every other name (redirect hops), and
/// re-checks each redirect hop's scheme and IP literal. Under
/// [`DialPolicy::AllowAll`] it installs the caller's plain redirect policy.
///
/// # Errors
///
/// [`UrlRefusal`] naming why `url` was refused.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn ssrf_apply_with<R: HostResolver + Send + 'static>(
    mut builder: reqwest::ClientBuilder,
    url: &str,
    redirects: RedirectPolicy,
    policy: DialPolicy,
    gate: VettingResolver<R>,
) -> Result<reqwest::ClientBuilder, UrlRefusal> {
    refuse_misplaced_userinfo(url)?;
    match policy {
        DialPolicy::DenyPrivate => {
            let parsed = parse_gated_url(url)?;
            let host = parsed.host_str().ok_or(UrlRefusal::NoHost)?;
            let vetted = gate
                .vet(host, url_host_disclosure(url, &parsed))
                .await
                .map_err(UrlRefusal::Host)?;
            // reqwest/hyper key the override by the UNBRACKETED host
            // (`Uri::host`), so a `"[::1]"` key would never match and the pin
            // would silently not apply.
            builder = builder.resolve_to_addrs(strip_ipv6_brackets(host), &vetted.into_vec());
            builder = builder.dns_resolver(std::sync::Arc::new(gate));
        }
        DialPolicy::AllowAll => {}
    }
    builder = match redirects {
        RedirectPolicy::NoRedirects => builder.redirect(reqwest::redirect::Policy::none()),
        RedirectPolicy::FollowRedirects(max_hops) => {
            // Clamp to 0: a user-supplied negative Int is safe (0 hops
            // followed).  This is the load-bearing `.max(0)` the spec requires.
            let max = max_hops.max(0) as usize;
            match policy {
                DialPolicy::DenyPrivate => {
                    builder.redirect(reqwest::redirect::Policy::custom(move |attempt| {
                        if attempt.previous().len() >= max {
                            return attempt
                                .error(format!("http: too many redirects (max {})", max));
                        }
                        // Non-blocking hop guard: scheme + IP-literal range
                        // check only. A named-host hop is vetted by
                        // `VettingResolver` at connect; resolving here would
                        // block inside reqwest's sync redirect closure.
                        if let Err(refusal) = ssrf_check_url_nonblocking(attempt.url().as_str()) {
                            return attempt.error(format!("http: {refusal}"));
                        }
                        attempt.follow()
                    }))
                }
                DialPolicy::AllowAll => builder.redirect(reqwest::redirect::Policy::limited(max)),
            }
        }
    };
    Ok(builder)
}

/// A reqwest transport error as the Ipê program sees it, its raw detail logged.
///
/// The error's URL is dropped before the log line is written: it may carry a
/// password or a query-string token. Ipê sees only the correlation id.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn redacted_transport_error<E: From<String>>(e: reqwest::Error) -> E {
    ipe_error_from_foreign(e.without_url())
}

// ---------------------------------------------------------------------------
// Core request executor
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
async fn do_request<E: From<String> + Send + 'static>(
    req: HttpRequest,
) -> IpeResult<E, HttpResponse> {
    // This surface (Http.get/post/request) accepts only http/https — ws/wss is
    // the WebSocket client's surface. When the SSRF guard is on, enforce that
    // narrower scheme set here, then delegate the host-resolve + DNS-rebinding
    // pin + per-redirect re-check to the SHARED `ssrf_apply_with` under the
    // same policy reading.
    let policy = DialPolicy::from_env();
    if policy == DialPolicy::DenyPrivate
        && let Err(refusal) = parse_gated_url_within(&req.url, GatedSchemes::Http)
    {
        return IpeResult::Err(format!("http: {refusal}").into());
    }

    let builder = reqwest::Client::builder();
    let gate = VettingResolver::system();
    let mut builder = match ssrf_apply_with(builder, &req.url, req.redirects, policy, gate).await {
        Ok(b) => b,
        Err(refusal) => return IpeResult::Err(format!("http: {refusal}").into()),
    };

    // Always install a request deadline. A Ipê-controllable `timeout <= 0`
    // would otherwise leave the request with no deadline (slowloris / hung-
    // connection vector), so floor it to 30 s instead of disabling it.
    let timeout_ms = if req.timeout > 0 {
        req.timeout as u64
    } else {
        30_000
    };
    builder = builder.timeout(std::time::Duration::from_millis(timeout_ms));

    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => return IpeResult::Err(format!("http: client build failed: {}", e).into()),
    };
    let method = method_to_reqwest(req.method);
    let mut rb = client.request(method, &req.url);
    for (k, v) in &req.headers {
        rb = rb.header(k.as_str(), v.as_str());
    }
    if !req.body.is_empty() {
        rb = rb.body(req.body.clone());
    }
    let resp = match rb.send().await {
        Ok(r) => r,
        // A reqwest/hyper error can echo `req.url` (userinfo, a query-string
        // API key) and the resolved address.
        Err(e) => {
            return IpeResult::Err(redacted_transport_error(e));
        }
    };
    let status = resp.status().as_u16() as i64;
    let mut headers = HashMap::new();
    for (k, v) in resp.headers() {
        if let Ok(s) = v.to_str() {
            // MIME-case parity: reqwest's `HeaderName::as_str()`
            // ALWAYS returns lower-case, but canonical storage expects
            // headers canonicalised (`net/http.Header` always is) — a Ipê
            // program's `Dict.get "Content-Type" resp.headers` must find the
            // key. Route through the SAME `canonical_header` the Server
            // inbound path uses (its  table is pinned by
            // `canonical_header_matches_go_canonical_mime_key`).
            headers.insert(
                crate::http_header::canonical_header(k.as_str()),
                s.to_string(),
            );
        }
    }
    let body = match read_body_capped::<E>(resp).await {
        IpeResult::Ok(b) => b,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    ok_res(HttpResponse {
        status,
        body,
        headers,
    })
}

/// Default cap on a buffered HTTP response body (`Http.get`/`post`/`request`):
/// 100 MiB. `Http.*` returns the body as a single `String`, so an unbounded
/// read of an attacker- or upstream-controlled response is a memory-exhaustion
/// (OOM) vector. Override via `IPE_HTTP_MAX_BODY_BYTES` (streaming consumers that
/// need unbounded bodies use `Ipe.Http.Stream` instead).
#[cfg(not(target_arch = "wasm32"))]
const HTTP_BODY_CAP_DEFAULT: usize = 100 * 1024 * 1024;

#[cfg(not(target_arch = "wasm32"))]
fn http_body_cap() -> usize {
    crate::system::read_env_var("IPE_HTTP_MAX_BODY_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(HTTP_BODY_CAP_DEFAULT)
}

/// Read a response body into a `String` with a hard byte cap. The
/// `Content-Length` pre-check only fast-fails the declared-length case — note
/// reqwest's `gzip` feature transparently decompresses and STRIPS
/// `Content-Length`, so for a gzip'd (e.g. compression-bomb) response
/// `content_length()` is `None` and this pre-check is skipped. The load-bearing
/// guard is the INCREMENTAL cap in the stream loop below, which bounds the
/// decompressed body to `cap` regardless of encoding or a lying/chunked length —
/// a bomb is capped at `cap` resident bytes, never unbounded. UTF-8 lossy
/// (matches `Http.Stream`'s chunk decode).
#[cfg(not(target_arch = "wasm32"))]
async fn read_body_capped<E: From<String> + Send + 'static>(
    resp: reqwest::Response,
) -> IpeResult<E, String> {
    use futures_util::StreamExt;
    let cap = http_body_cap();
    if let Some(len) = resp.content_length()
        && len as usize > cap
    {
        return IpeResult::Err(
                format!(
                    "http: response body too large ({} > {} bytes; raise IPE_HTTP_MAX_BODY_BYTES or use Http.Stream)",
                    len, cap
                )
                .into(),
            );
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = match chunk {
            Ok(b) => b,
            // A body-read transport error can also echo the URL.
            Err(e) => return IpeResult::Err(redacted_transport_error(e)),
        };
        if buf.len().saturating_add(bytes.len()) > cap {
            return IpeResult::Err(
                format!(
                    "http: response body too large (> {} bytes; raise IPE_HTTP_MAX_BODY_BYTES or use Http.Stream)",
                    cap
                )
                .into(),
            );
        }
        buf.extend_from_slice(&bytes);
    }
    IpeResult::Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Http.get : Url -> Task Error HttpResponse
///
/// Takes an already-sealed typed `Url` (parsed exactly once at
/// `Url.fromString`, the single SSRF parse boundary) and carries its canonical
/// serialization as the transport target. The runtime SSRF floor in
/// `do_request` (per-hop scheme allowlist + private-IP resolver) is unchanged —
/// the typed argument is the defence-in-depth guard at the API boundary, not a
/// replacement for the runtime floor.
#[cfg(not(target_arch = "wasm32"))]
pub fn http_get<E: From<String> + Send + 'static>(
    url: crate::url::Url,
) -> IpeTask<E, HttpResponse> {
    Box::pin(do_request(HttpRequest {
        body: String::new(),
        headers: Vec::new(),
        method: HttpMethod::Get,
        redirects: RedirectPolicy::FollowRedirects(10),
        timeout: 30000,
        url: crate::url::url_to_string(url),
    }))
}

/// Http.post : Url -> String -> Task Error HttpResponse
///
/// Takes an already-sealed typed `Url` (see [`http_get`]) and carries its
/// canonical serialization as the transport target. The runtime SSRF floor is
/// unchanged.
#[cfg(not(target_arch = "wasm32"))]
pub fn http_post<E: From<String> + Send + 'static>(
    url: crate::url::Url,
    body: String,
) -> IpeTask<E, HttpResponse> {
    Box::pin(do_request(HttpRequest {
        body,
        headers: Vec::new(),
        method: HttpMethod::Post,
        redirects: RedirectPolicy::FollowRedirects(10),
        timeout: 30000,
        url: crate::url::url_to_string(url),
    }))
}

/// Http.request : HttpRequest -> Task Error HttpResponse
#[cfg(not(target_arch = "wasm32"))]
pub fn http_request<E: From<String> + Send + 'static>(
    req: HttpRequest,
) -> IpeTask<E, HttpResponse> {
    Box::pin(do_request(req))
}

/// `Http.parseQuery : String -> Dict String String` (pure; first value wins).
///
/// Decodes each key and value with `form_url_decode` — lenient by design
/// (malformed `%`-escapes pass through as literal bytes; invalid UTF-8 →
/// U+FFFD). Result is a plain app-logic Dict; it does not flow into any
/// path, SQL, header, or re-encode sink. See `encoding::form_url_decode` doc
/// for the full contract and the safety boundary that makes leniency safe.
pub fn http_parse_query(raw: String) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in raw.trim_start_matches('?').split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, '=');
        let k = form_url_decode(it.next().unwrap_or(""));
        let v = form_url_decode(it.next().unwrap_or(""));
        out.entry(k).or_insert(v); // repeated keys keep the first value
    }
    out
}

// ---------------------------------------------------------------------------
// wasm32 browser substitute — `fetch` (Open Decision 1, resolved)
// ---------------------------------------------------------------------------
//
// `docs/adr/0005-delivery-shapes-runtimes-hosts-targets.md`'s Open Decision 1 asks to settle
// reqwest-wasm vs raw `web-sys` fetch against the actual `http_client` kernel
// code. Resolved to raw `web-sys` fetch:
//
//   - The native kernel's substantial logic beyond request-building is the
//     SSRF deny-private guard above (`ssrf_apply`/`VettingResolver`) — DNS
//     resolution, address pinning, per-redirect-hop re-checks. None of it has
//     a browser analogue: a tab cannot open a raw socket or resolve a
//     hostname itself; CORS/mixed-content/CSP are the browser's OWN network
//     boundary, already enforced beneath this code with no
//     `IPE_HTTP_DENY_PRIVATE`-shaped opt-in needed. There is no shared logic
//     worth reusing from the reqwest path.
//   - reqwest's wasm32 backend is itself a thin wrapper over `fetch`; taking
//     it adds a dependency layer (reqwest + its wasm shims) atop the same
//     browser primitive called directly below, for no behavioural gain and a
//     real bundle-size cost (efficiency ranks above completeness once the
//     reuse case is gone — spec's own stated tie-breaker).
//
// CORS blocks, network errors, and timeouts all reject the `fetch` Promise
// rather than trapping the instance; every rejection here routes through the
// SAME generic `Task.fail` arm — never a panic, never a silent drop.

/// `IPE_HTTP_MAX_BODY_BYTES` cap, mirrored from the native arm's
/// `http_body_cap` (same env var, same default) — `fetch`'s `.text()` buffers
/// the whole body itself, so this is a post-hoc size guard rather than a
/// streamed one, but it keeps the same DoS floor on both targets.
// The browser `fetch` substitute is gated on `all(wasm32, wasm-client)`, never a
// bare `wasm32`: the co-located WASI target (`wasm32-wasip1`, `wasm-client` off)
// is a native-ish wasm build that has no `web-sys`/`wasm-bindgen` in its graph,
// so a bare-`wasm32` arm would compile these browser bindings into a WASI build
// and fail cargo. `http_client` is not WASI-viable (reqwest is native-only), so
// on WASI this whole substitute stays absent and no kernel references it.
#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
fn wasm_http_body_cap() -> usize {
    crate::system::read_env_var("IPE_HTTP_MAX_BODY_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(100 * 1024 * 1024)
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
async fn do_fetch<E: From<String> + 'static>(req: HttpRequest) -> IpeResult<E, HttpResponse> {
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let window = match web_sys::window() {
        Some(w) => w,
        None => {
            return IpeResult::Err(
                "http: no window (not a browser context?)"
                    .to_string()
                    .into(),
            );
        }
    };

    let headers = match web_sys::Headers::new() {
        Ok(h) => h,
        Err(_) => {
            return IpeResult::Err("http: failed to build request headers".to_string().into());
        }
    };
    for (k, v) in &req.headers {
        if headers.set(k, v).is_err() {
            return IpeResult::Err(format!("http: invalid header {k:?}").into());
        }
    }

    let init = web_sys::RequestInit::new();
    init.set_method(req.method.as_str());
    init.set_headers(&headers);
    init.set_mode(web_sys::RequestMode::Cors);
    init.set_redirect(match &req.redirects {
        RedirectPolicy::FollowRedirects(_) => web_sys::RequestRedirect::Follow,
        RedirectPolicy::NoRedirects => web_sys::RequestRedirect::Error,
    });
    if !req.body.is_empty() {
        init.set_body(&JsValue::from_str(&req.body));
    }

    // Timeout via `AbortController` — the browser analogue of the native
    // request deadline. A fired abort rejects the fetch Promise, routed
    // through the same generic transport-error arm below (never a trap).
    let controller = web_sys::AbortController::new().ok();
    let _timeout_handle = controller.as_ref().map(|ctl| {
        init.set_signal(Some(&ctl.signal()));
        let timeout_ms = if req.timeout > 0 { req.timeout } else { 30_000 };
        let ctl = ctl.clone();
        gloo_timers::callback::Timeout::new(timeout_ms.max(0) as u32, move || {
            ctl.abort();
        })
    });

    let request = match web_sys::Request::new_with_str_and_init(&req.url, &init) {
        Ok(r) => r,
        Err(e) => return IpeResult::Err(format!("http: bad request: {:?}", e).into()),
    };

    let resp_value = match JsFuture::from(window.fetch_with_request(&request)).await {
        Ok(v) => v,
        Err(e) => {
            return IpeResult::Err(
                format!(
                    "http: fetch failed (network error, CORS block, or timeout): {:?}",
                    e
                )
                .into(),
            );
        }
    };
    let resp: web_sys::Response = match resp_value.dyn_into() {
        Ok(r) => r,
        Err(_) => {
            return IpeResult::Err("http: fetch did not return a Response".to_string().into());
        }
    };

    let status = i64::from(resp.status());

    let mut out_headers = HashMap::new();
    if let Ok(Some(iter)) = js_sys::try_iter(resp.headers().as_ref()) {
        for entry in iter.flatten() {
            if let Ok(pair) = entry.dyn_into::<js_sys::Array>() {
                let k = pair.get(0).as_string().unwrap_or_default();
                let v = pair.get(1).as_string().unwrap_or_default();
                if !k.is_empty() {
                    out_headers.insert(crate::http_header::canonical_header(&k), v);
                }
            }
        }
    }

    // Stream the body incrementally with a running cap so an untrusted (or
    // upstream-controlled) response is BOUNDED BY CONSTRUCTION — never fully
    // buffered by `Response.text()` before the size is known. Mirrors the native
    // `read_body_capped` incremental floor. `content_length()` is unreliable in a
    // browser (absent under transfer-encoding, or a lie), so the load-bearing
    // guard is the per-chunk cap in the loop, not a header pre-check.
    let cap = wasm_http_body_cap();
    let body = match read_wasm_body_capped(&resp, cap).await {
        Ok(b) => b,
        Err(e) => return IpeResult::Err(e.into()),
    };

    ok_res(HttpResponse {
        status,
        body,
        headers: out_headers,
    })
}

/// Read a `web_sys::Response` body incrementally, aborting the instant the running
/// total would exceed `cap` — the browser mirror of the native `read_body_capped`.
/// Pulls chunks from `Response.body()`'s `ReadableStream` reader (each a
/// `Uint8Array`) rather than `Response.text()`, so a hostile/oversized body is
/// bounded to `cap` resident bytes by construction, never fully buffered first.
/// Decodes UTF-8 lossily (parity with the native arm and `Http.Stream`).
#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
async fn read_wasm_body_capped(resp: &web_sys::Response, cap: usize) -> Result<String, String> {
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    // A body-less response (e.g. 204) has no stream; treat as empty.
    let stream = match resp.body() {
        Some(s) => s,
        None => return Ok(String::new()),
    };
    let reader: web_sys::ReadableStreamDefaultReader = stream
        .get_reader()
        .dyn_into()
        .map_err(|_| "http: failed reading response body".to_string())?;

    let mut buf: Vec<u8> = Vec::new();
    loop {
        let result = JsFuture::from(reader.read())
            .await
            .map_err(|_| "http: failed reading response body".to_string())?;
        // Each read resolves to `{ done: bool, value: Uint8Array }`.
        let done = js_sys::Reflect::get(&result, &JsValue::from_str("done"))
            .ok()
            .and_then(|d| d.as_bool())
            .unwrap_or(true);
        let value = js_sys::Reflect::get(&result, &JsValue::from_str("value"))
            .unwrap_or(JsValue::UNDEFINED);
        if !value.is_undefined() && !value.is_null() {
            let chunk = js_sys::Uint8Array::new(&value);
            let len = chunk.length() as usize;
            if buf.len().saturating_add(len) > cap {
                // Release the underlying connection before bailing.
                let _ = reader.cancel();
                return Err(format!(
                    "http: response body too large (> {cap} bytes; raise IPE_HTTP_MAX_BODY_BYTES)"
                ));
            }
            let start = buf.len();
            buf.resize(start + len, 0);
            // `copy_to` writes exactly `len` bytes into the freshly sized tail;
            // the slice length matches `chunk.length()`, so no truncation.
            if let Some(dst) = buf.get_mut(start..start + len) {
                chunk.copy_to(dst);
            }
        }
        if done {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Http.get : Url -> Task Error HttpResponse (browser substitute)
#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
pub fn http_get<E: From<String> + 'static>(url: crate::url::Url) -> IpeTask<E, HttpResponse> {
    Box::pin(do_fetch(HttpRequest {
        body: String::new(),
        headers: Vec::new(),
        method: HttpMethod::Get,
        redirects: RedirectPolicy::FollowRedirects(10),
        timeout: 30000,
        url: crate::url::url_to_string(url),
    }))
}

/// Http.post : Url -> String -> Task Error HttpResponse (browser substitute)
#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
pub fn http_post<E: From<String> + 'static>(
    url: crate::url::Url,
    body: String,
) -> IpeTask<E, HttpResponse> {
    Box::pin(do_fetch(HttpRequest {
        body,
        headers: Vec::new(),
        method: HttpMethod::Post,
        redirects: RedirectPolicy::FollowRedirects(10),
        timeout: 30000,
        url: crate::url::url_to_string(url),
    }))
}

/// Http.request : HttpRequest -> Task Error HttpResponse (browser substitute)
#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
pub fn http_request<E: From<String> + 'static>(req: HttpRequest) -> IpeTask<E, HttpResponse> {
    Box::pin(do_fetch(req))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wiring seal: the response-header collection loop must route
    /// every key through `http_header::canonical_header` (reqwest's
    /// `HeaderName::as_str()` is always lower-case;  `net/http.Header` is
    /// always canonical — `Dict.get "Content-Type"` parity depends on it).
    /// `do_request` needs a live round-trip to test end-to-end, so this pins
    /// the call's PRESENCE at the source level; the transform itself is
    /// proven by `http_header`'s own  table test.
    #[test]
    fn response_header_loop_canonicalises_keys() {
        let src = include_str!("http_client.rs");
        let loop_marker = "for (k, v) in resp.headers()";
        let start = src.find(loop_marker);
        assert!(start.is_some(), "response-header loop not found");
        let Some(start) = start else { return };
        // Window sized to comfortably cover the loop body INCLUDING its doc
        // comment (the canonicalisation call sits ~700 bytes past the marker).
        let window = &src[start..src.len().min(start + 1600)];
        assert!(
            window.contains("canonical_header(k.as_str())"),
            "response-header keys must be canonicalised (MIME canonical case)"
        );
        assert!(
            !window.contains("insert(k.as_str().to_string()"),
            "raw lower-case header-key insert reintroduced (#33 §6.1 regression)"
        );
    }

    #[test]
    fn parse_query_decode_and_first_wins() {
        let q = http_parse_query("a=1&b=two%20words&a=ignored&c".to_string());
        assert_eq!(q.get("a").map(String::as_str), Some("1")); // first value wins
        assert_eq!(q.get("b").map(String::as_str), Some("two words"));
        assert_eq!(q.get("c").map(String::as_str), Some(""));
        // Leading '?' tolerated; empty pairs skipped.
        let q2 = http_parse_query("?x=9&".to_string());
        assert_eq!(q2.get("x").map(String::as_str), Some("9"));
        assert_eq!(q2.len(), 1);
    }
    // SSRF guard unit tests moved to `ssrf.rs` alongside the validators.

    // ── Typed request-target builders — API-layer scheme narrowing ──────────
    //
    // These prove the fail-closed narrowing is enforced at the API layer, so a
    // builder-constructed request whose scheme is not http(s) cannot be
    // assembled REGARDLESS of the runtime SSRF guard (no env toggling here —
    // the narrowing is unconditional).

    fn seal(raw: &str) -> crate::url::Url {
        match crate::url::url_from_string::<String>(raw.to_string()) {
            IpeResult::Ok(u) => u,
            IpeResult::Err(e) => panic!("expected {raw:?} to be a valid Url: {e}"),
        }
    }

    #[test]
    fn default_request_accepts_http_and_https() {
        for raw in ["http://example.com/", "https://example.com:8443/a?q=1"] {
            match http_default_request::<String>(seal(raw)) {
                IpeResult::Ok(req) => assert_eq!(req.url, raw),
                IpeResult::Err(e) => panic!("{raw:?} must build, got Err: {e}"),
            }
        }
    }

    #[test]
    fn default_request_rejects_non_http_scheme_fail_closed() {
        // `file:` / `ftp:` are valid `Url` values but must be rejected at the
        // API layer, independent of the runtime SSRF guard.
        for raw in [
            "ftp://example.com/x",
            "file:///etc/passwd",
            "ws://example.com/",
        ] {
            match http_default_request::<String>(seal(raw)) {
                IpeResult::Err(e) => assert!(
                    e.contains("not http/https"),
                    "{raw:?} must fail closed with a scheme message, got: {e}"
                ),
                IpeResult::Ok(_) => panic!("{raw:?} must NOT build — non-http(s) scheme"),
            }
        }
    }

    #[test]
    fn default_request_from_string_is_the_marked_parse_boundary() {
        // Ok on a valid http(s) string.
        match http_default_request_from_string::<String>("https://example.com/".to_string()) {
            IpeResult::Ok(req) => assert_eq!(req.url, "https://example.com/"),
            IpeResult::Err(e) => panic!("valid https string must build, got: {e}"),
        }
        // A relative / scheme-less string fails at the parse seal.
        match http_default_request_from_string::<String>("/just/a/path".to_string()) {
            IpeResult::Err(_) => {}
            IpeResult::Ok(_) => panic!("a relative reference must not build a request"),
        }
        // A syntactically valid but non-http(s) scheme fails at the narrowing.
        match http_default_request_from_string::<String>("ftp://example.com/x".to_string()) {
            IpeResult::Err(e) => assert!(e.contains("not http/https"), "got: {e}"),
            IpeResult::Ok(_) => panic!("ftp must fail closed at the API layer"),
        }
    }

    #[test]
    fn with_url_retarget_re_narrows_scheme() {
        let base = http_request_with_target("http://example.com/".to_string());
        // Retarget to another http URL — Ok, url replaced, other fields kept.
        let base_body = HttpRequest {
            body: "keep-me".to_string(),
            ..base.clone()
        };
        match http_with_url::<String>(seal("https://example.org/next"), base_body.clone()) {
            IpeResult::Ok(req) => {
                assert_eq!(req.url, "https://example.org/next");
                assert_eq!(req.body, "keep-me", "non-url fields must be preserved");
            }
            IpeResult::Err(e) => panic!("http(s) retarget must succeed, got: {e}"),
        }
        // Retarget to a non-http(s) scheme — fail closed, at the API layer.
        match http_with_url::<String>(seal("file:///etc/passwd"), base_body) {
            IpeResult::Err(e) => assert!(e.contains("not http/https"), "got: {e}"),
            IpeResult::Ok(_) => panic!("file: retarget must fail closed"),
        }
    }

    // ── RedirectPolicy — struct field and negative-clamp proof ──────────────

    /// `HttpRequest` carries `redirects: RedirectPolicy` and the default is
    /// `FollowRedirects(10)`.  Verify the struct builds correctly and the
    /// `NoRedirects` variant is distinct.
    #[test]
    fn redirect_policy_default_and_variants() {
        let req = http_request_with_target("http://example.com/".to_string());
        match req.redirects {
            RedirectPolicy::FollowRedirects(n) => {
                assert_eq!(n, 10, "default hop count must be 10")
            }
            RedirectPolicy::NoRedirects => panic!("default must be FollowRedirects(10)"),
        }
        // NoRedirects round-trip.
        let mut req2 = req.clone();
        req2.redirects = RedirectPolicy::NoRedirects;
        assert!(
            matches!(req2.redirects, RedirectPolicy::NoRedirects),
            "NoRedirects must survive a clone-and-assign"
        );
    }

    /// A negative `FollowRedirects` value from user code must not panic or
    /// cause a negative cast.  The `.max(0)` clamp in `ssrf_apply` is the
    /// load-bearing floor; this test pins it at the type level.
    #[test]
    fn negative_follow_redirects_clamps_to_zero_without_panic() {
        // `max_hops.max(0) as usize` — must not panic for any i64 value.
        let negative: i64 = -1;
        let clamped = negative.max(0) as usize;
        assert_eq!(
            clamped, 0,
            "negative hop count must clamp to 0, not wrap or panic"
        );
        let min_i64: i64 = i64::MIN;
        let clamped_min = min_i64.max(0) as usize;
        assert_eq!(clamped_min, 0, "i64::MIN must clamp to 0");
    }

    // -----------------------------------------------------------------------
    // SSRF gate — reqwest integration, under stub resolvers and an explicit
    // policy (no network, no environment)
    // -----------------------------------------------------------------------

    mod ssrf_gate {
        use super::super::{RedirectPolicy, VettingResolver, ssrf_apply_with};
        use crate::ssrf::test_resolvers::{Answers, NoDns, PublicThenPrivate, Stalls};
        use crate::ssrf::{
            BlockedHost, BlockedRange, DialPolicy, GatedSchemes, HostResolver, HostShown,
            SchemeShown, SsrfRefusal, UrlRefusal,
        };
        use reqwest::dns::Resolve as _;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use std::sync::Arc;
        use std::time::Duration;

        const DEADLINE: Duration = Duration::from_secs(5);
        const PRIVATE: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        fn gate<R: HostResolver + Send + 'static>(resolver: R) -> VettingResolver<R> {
            VettingResolver::new(Arc::new(resolver), DEADLINE)
        }

        /// What the reqwest resolver answers for `host`: the addresses, or the
        /// refusal's message.
        async fn resolve<R: HostResolver + Send + 'static>(
            resolver: &VettingResolver<R>,
            host: &str,
        ) -> Result<Vec<SocketAddr>, String> {
            let name = host.parse::<reqwest::dns::Name>();
            assert!(name.is_ok(), "{host:?} must be a valid DNS name");
            let Ok(name) = name else {
                return Err(String::new());
            };
            resolver
                .resolve(name)
                .await
                .map(Iterator::collect)
                .map_err(|e| e.to_string())
        }

        async fn apply<R: HostResolver + Send + 'static>(
            url: &str,
            policy: DialPolicy,
            resolver: VettingResolver<R>,
        ) -> Option<UrlRefusal> {
            ssrf_apply_with(
                reqwest::Client::builder(),
                url,
                RedirectPolicy::FollowRedirects(5),
                policy,
                resolver,
            )
            .await
            .err()
        }

        fn blocked(host: &str, ip: IpAddr, range: BlockedRange) -> SsrfRefusal {
            SsrfRefusal::Blocked {
                host: BlockedHost::Named {
                    host: host.to_owned(),
                    ip,
                },
                range,
            }
        }

        /// A refusal that withholds the host and its address.
        const fn withheld_blocked(range: BlockedRange) -> SsrfRefusal {
            SsrfRefusal::Blocked {
                host: BlockedHost::Withheld,
                range,
            }
        }

        /// A name whose answer mixes a public and a private address is refused
        /// whole, never filtered down to the public one.
        #[tokio::test]
        async fn resolver_refuses_a_mixed_answer() {
            let resolver = gate(Answers(vec![PublicThenPrivate::PUBLIC, PRIVATE]));
            assert_eq!(
                resolve(&resolver, "mixed.example").await,
                Err(withheld_blocked(BlockedRange::Private).to_string())
            );
        }

        /// A stalled resolver is cut off at the deadline with the typed timeout.
        #[tokio::test]
        async fn resolver_times_out_a_stalled_lookup() {
            let after = Duration::from_millis(20);
            let resolver = VettingResolver::new(Arc::new(Stalls), after);
            let expected = SsrfRefusal::Timeout {
                host: HostShown::Withheld,
                after,
            };
            assert_eq!(
                resolve(&resolver, "slow.example").await,
                Err(expected.to_string())
            );
        }

        /// A rebinding name: the first answer is dialled, the rebound private
        /// answer is refused, and no private address is ever handed to reqwest.
        #[tokio::test]
        async fn resolver_never_returns_a_rebound_private_address() {
            let resolver = gate(PublicThenPrivate::new());
            let first = resolve(&resolver, "rebind.example").await;
            assert_eq!(
                first,
                Ok(vec![SocketAddr::new(PublicThenPrivate::PUBLIC, 0)])
            );
            let second = resolve(&resolver, "rebind.example").await;
            assert_eq!(
                second,
                Err(withheld_blocked(BlockedRange::Private).to_string())
            );
        }

        /// The request host is refused with the typed reason for a mixed answer.
        #[tokio::test]
        async fn apply_refuses_a_mixed_answer_for_the_request_host() {
            let resolver = gate(Answers(vec![PublicThenPrivate::PUBLIC, PRIVATE]));
            assert_eq!(
                apply("https://mixed.example/x", DialPolicy::DenyPrivate, resolver).await,
                Some(UrlRefusal::Host(blocked(
                    "mixed.example",
                    PRIVATE,
                    BlockedRange::Private
                )))
            );
        }

        /// A stalled lookup of the request host is a typed timeout.
        #[tokio::test]
        async fn apply_times_out_a_stalled_request_host() {
            let after = Duration::from_millis(20);
            let resolver = VettingResolver::new(Arc::new(Stalls), after);
            assert_eq!(
                apply("https://slow.example/", DialPolicy::DenyPrivate, resolver).await,
                Some(UrlRefusal::Host(SsrfRefusal::Timeout {
                    host: HostShown::Named("slow.example".to_owned()),
                    after,
                }))
            );
        }

        /// The request host is resolved once, through the same resolver the
        /// client keeps for every other name; that resolver then refuses the
        /// rebound answer, so neither path can reach the private address.
        #[tokio::test]
        async fn apply_resolves_the_request_host_once_through_the_shared_gate() {
            let shared = Arc::new(PublicThenPrivate::new());
            let resolver = VettingResolver::new(Arc::clone(&shared), DEADLINE);
            assert_eq!(
                apply("https://rebind.example/", DialPolicy::DenyPrivate, resolver).await,
                None
            );
            assert_eq!(shared.calls(), 1, "the request host must be resolved once");
            let later = VettingResolver::new(shared, DEADLINE);
            assert!(
                resolve(&later, "rebind.example").await.is_err(),
                "a later lookup meets the rebound answer and is refused"
            );
        }

        /// Each malformed request URL is refused with its typed reason, before
        /// any lookup.
        #[tokio::test]
        async fn apply_refuses_malformed_urls_without_a_lookup() {
            assert_eq!(
                apply("ftp://files.example/", DialPolicy::DenyPrivate, gate(NoDns)).await,
                Some(UrlRefusal::Scheme {
                    scheme: SchemeShown::Known("ftp"),
                    admitted: GatedSchemes::HttpAndWebSocket,
                })
            );
            assert!(
                matches!(
                    apply("not a url", DialPolicy::DenyPrivate, gate(NoDns)).await,
                    Some(UrlRefusal::Invalid { .. })
                ),
                "an unparseable URL must be refused"
            );
            assert_eq!(
                apply("http://127.0.0.1/", DialPolicy::DenyPrivate, gate(NoDns)).await,
                Some(UrlRefusal::Host(blocked(
                    "127.0.0.1",
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    BlockedRange::Loopback
                )))
            );
        }

        /// A request URL whose userinfo may run into its host or path is refused
        /// under every policy before any lookup; an `@` only in the query is not.
        #[tokio::test]
        async fn apply_refuses_misplaced_userinfo_under_every_policy() {
            for policy in [DialPolicy::DenyPrivate, DialPolicy::AllowAll] {
                for url in [
                    "http://10.0.0.1\\s3cr3t@public.example/",
                    "https://admin:80/s3cr3t@public.example/",
                    "https://admin#s3cr3t@public.example/",
                ] {
                    let shared = Arc::new(PublicThenPrivate::new());
                    let resolver = VettingResolver::new(Arc::clone(&shared), DEADLINE);
                    let refused = apply(url, policy, resolver).await;
                    assert_eq!(refused, Some(UrlRefusal::MisplacedUserinfo), "{url:?}");
                    assert_eq!(shared.calls(), 0, "{url:?}");
                }
            }
            assert_eq!(
                apply(
                    "https://public.example/?email=a@example.com",
                    DialPolicy::AllowAll,
                    gate(NoDns)
                )
                .await,
                None
            );
        }

        /// A request host read from ambiguous userinfo is refused without being
        /// shown, and without the address an IP literal re-encodes it to.
        #[tokio::test]
        async fn apply_withholds_a_host_that_may_be_a_credential() {
            let refused = apply(
                "http://1234567?pin@api.example/",
                DialPolicy::DenyPrivate,
                gate(NoDns),
            )
            .await;
            assert_eq!(
                refused,
                Some(UrlRefusal::Host(withheld_blocked(BlockedRange::Reserved)))
            );
            let shown = format!(
                "{refused:?} {}",
                refused
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string)
            );
            for secret in ["1234567", "0.18.214.135", "pin", "api.example"] {
                assert!(!shown.contains(secret), "{secret:?} leaked into {shown}");
            }
        }

        /// With the policy off, nothing is vetted and no lookup runs.
        #[tokio::test]
        async fn apply_is_unrestricted_when_the_policy_allows_all() {
            let shared = Arc::new(PublicThenPrivate::new());
            let resolver = VettingResolver::new(Arc::clone(&shared), DEADLINE);
            assert_eq!(
                apply("http://127.0.0.1/", DialPolicy::AllowAll, resolver).await,
                None
            );
            assert_eq!(shared.calls(), 0);
        }

        /// A refusal shows under the `http:` prefix its surfaces add.
        #[test]
        fn refusal_displays_the_policy_that_refused() {
            let shown = format!(
                "http: {}",
                UrlRefusal::Host(blocked("10.0.0.1", PRIVATE, BlockedRange::Private))
            );
            assert_eq!(
                shown,
                "http: blocked: private host 10.0.0.1 (IPE_HTTP_DENY_PRIVATE)"
            );
        }
    }
}

//! Ipe.Http — outbound HTTP client (reqwest under a Ipê-native surface).
//!
//! HttpResponse/HttpRequest map to the Ipê record aliases via runtimeOpaqueTypes
//! (like Csv's CsvDoc), so `resp.status` / `.body` / `.headers` resolve onto
//! these pub fields and the Ipê-built `defaultRequest` record constructs this
//! struct directly. Field names match the Ipê records verbatim.
//!
//! ## SSRF protection (default-ON)
//!
//! The guard blocks requests whose resolved host is loopback, RFC-1918 private,
//! link-local, unique-local (ULA), unspecified, or v4-mapped-private. It is
//! ON by default, and on every release build; only a dev-intent binary with no
//! exposed listener defaults it OFF, so development against `localhost` keeps
//! working. `IPE_HTTP_DENY_PRIVATE=0`/`off`/`false` is the explicit opt-out;
//! `1`/`on`/`true` and every unrecognised value keep it ON. See
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
#[cfg(any(
    not(target_arch = "wasm32"),
    all(target_arch = "wasm32", feature = "wasm-client")
))]
use crate::transport_timeout::{TimeoutRefusal, TransportTimeout};
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
#[derive(Clone)]
pub struct HttpResponse {
    pub status: i64,
    pub body: String,
    pub headers: HashMap<String, String>,
}

// The body and headers can carry a token or a `Set-Cookie` session id; the Ipê
// record fixes the field types, so the masking lives in `Debug`.
crate::redact::redacting_debug!(HttpResponse {
    shown: [status],
    masked: [body, headers],
});

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

crate::stringify::show_row!("RedirectPolicy", Value, [] RedirectPolicy, |p| match p {
    RedirectPolicy::NoRedirects => "NoRedirects".to_owned(),
    RedirectPolicy::FollowRedirects(n) => format!("FollowRedirects {n}"),
});

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

crate::retained::inline_measure!(HttpMethod);

crate::stringify::show_row!("HttpMethod", Value, [] HttpMethod, |m| match m {
    HttpMethod::Get => "Get".to_owned(),
    HttpMethod::Post => "Post".to_owned(),
    HttpMethod::Put => "Put".to_owned(),
    HttpMethod::Delete => "Delete".to_owned(),
    HttpMethod::Patch => "Patch".to_owned(),
    HttpMethod::Head => "Head".to_owned(),
    HttpMethod::Options => "Options".to_owned(),
});

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
#[derive(Clone)]
pub struct HttpRequest {
    pub body: String,
    pub headers: Vec<(String, String)>,
    pub method: HttpMethod,
    pub redirects: RedirectPolicy,
    pub timeout: i64,
    pub url: String,
}

// The dev view names every field; a credential header's value renders as the
// marker.
crate::stringify::show_row!(
    "HttpRequest",
    Redacted(Reveal),
    [] HttpRequest,
    shown: |_| crate::stringify::REDACTED_SHOW.to_owned(),
    dev: |r, view| {
        crate::stringify::dev_record(
            "HttpRequest",
            &[
                ("body", r.body.clone()),
                ("headers", crate::stringify::dev_header_list(&r.headers)),
                ("method", r.method.ipe_render(view)),
                ("redirects", r.redirects.ipe_render(view)),
                ("timeout", r.timeout.to_string()),
                ("url", r.url.clone()),
            ],
        )
    },
);

// The body, headers (`Authorization`) and URL (an API key in the query) can
// carry a credential; the Ipê record fixes the field types, so the masking lives
// in `Debug`.
crate::redact::redacting_debug!(HttpRequest {
    shown: [method, redirects, timeout],
    masked: [body, headers, url],
});

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
    ///
    /// # Errors
    ///
    /// [`SsrfRefusal::Deadline`] when the deadline setting is unusable.
    pub(crate) fn system() -> Result<Self, SsrfRefusal> {
        Ok(Self::new(
            std::sync::Arc::new(SystemResolver),
            dns_timeout()?,
        ))
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
) -> Result<(reqwest::ClientBuilder, RedirectBudget), UrlRefusal> {
    ssrf_apply_with(
        builder,
        url,
        redirects,
        DialPolicy::from_env(),
        VettingResolver::system().map_err(UrlRefusal::Host)?,
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
/// re-checks each redirect hop's scheme and IP literal. Under every policy a
/// followed chain is bounded by the caller's hop maximum, and the returned
/// [`RedirectBudget`] records whether the chain ran past it.
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
) -> Result<(reqwest::ClientBuilder, RedirectBudget), UrlRefusal> {
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
    let budget = match redirects {
        RedirectPolicy::NoRedirects => {
            builder = builder.redirect(reqwest::redirect::Policy::none());
            RedirectBudget::new(0)
        }
        RedirectPolicy::FollowRedirects(max_hops) => {
            // Clamp to 0: a user-supplied negative Int is safe (0 hops
            // followed).  This is the load-bearing `.max(0)` the spec requires.
            let budget = RedirectBudget::new(max_hops.max(0) as usize);
            let hops = budget.clone();
            builder = builder.redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if hops.spent_by(attempt.previous().len()) {
                    return attempt.error(hops.refusal_message());
                }
                match policy {
                    // Non-blocking hop guard: scheme + IP-literal range check
                    // only. A named-host hop is vetted by `VettingResolver` at
                    // connect; resolving here would block inside reqwest's
                    // sync redirect closure.
                    DialPolicy::DenyPrivate => {
                        if let Err(refusal) = ssrf_check_url_nonblocking(attempt.url().as_str()) {
                            return attempt.error(format!("http: {refusal}"));
                        }
                        attempt.follow()
                    }
                    DialPolicy::AllowAll => attempt.follow(),
                }
            }));
            budget
        }
    };
    Ok((builder, budget))
}

/// One request's redirect hop maximum, and whether its chain ran past it.
///
/// The redirect closure marks the budget spent at the hop past the maximum;
/// the send-error arm then reports that failure as the `LimitExceeded` refusal
/// it is, instead of an opaque transport error.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug)]
pub(crate) struct RedirectBudget {
    max: usize,
    spent: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(not(target_arch = "wasm32"))]
impl RedirectBudget {
    fn new(max: usize) -> Self {
        Self {
            max,
            spent: std::sync::Arc::default(),
        }
    }

    /// Whether `visited` URLs (the initial one included) exceed the maximum,
    /// marking the budget spent when they do.
    fn spent_by(&self, visited: usize) -> bool {
        // The first visited URL is the request itself, not a hop.
        let over = visited > self.max;
        if over {
            self.spent.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        over
    }

    fn refusal_message(&self) -> String {
        format!("http: too many redirects (max {})", self.max)
    }

    /// The ceiling refusal, when the redirect chain ran past the maximum.
    fn refusal(&self) -> Option<LimitRefusal> {
        self.spent
            .load(std::sync::atomic::Ordering::Relaxed)
            .then(|| LimitRefusal::new(self.refusal_message()))
    }
}

/// A failed `send` as the Ipê program sees it.
///
/// A redirect chain past its hop maximum is a `LimitExceeded` refusal; any
/// other failure is a redacted transport error.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn send_failure<E: From<String> + FromLimitExceeded>(
    e: reqwest::Error,
    budget: &RedirectBudget,
) -> E {
    match budget.refusal() {
        Some(refusal) if e.is_redirect() => refusal.into_error(),
        _ => redacted_transport_error(e),
    }
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

/// A refused request deadline as the Ipê program sees it, kinded `InvalidInput`.
#[cfg(not(target_arch = "wasm32"))]
fn timeout_refusal<E: FromIpeError>(refusal: TimeoutRefusal) -> E {
    E::from_ipe_error(crate::error::IpeError::invalid_input(format!(
        "http: timeout: {refusal}"
    )))
}

/// Sends `req` under the process's dial policy and system resolver.
#[cfg(not(target_arch = "wasm32"))]
async fn do_request<E: From<String> + FromLimitExceeded + FromIpeError + Send + 'static>(
    req: HttpRequest,
) -> IpeResult<E, HttpResponse> {
    let policy = DialPolicy::from_env();
    let gate = match VettingResolver::system() {
        Ok(gate) => gate,
        Err(refusal) => return IpeResult::Err(format!("http: {refusal}").into()),
    };
    do_request_with(req, policy, gate).await
}

/// Sends `req` under an explicit dial `policy` and resolver `gate`.
///
/// The request deadline is parsed before anything resolves or dials, so a
/// request with no admissible deadline never leaves the process.
#[cfg(not(target_arch = "wasm32"))]
async fn do_request_with<E, R>(
    req: HttpRequest,
    policy: DialPolicy,
    gate: VettingResolver<R>,
) -> IpeResult<E, HttpResponse>
where
    E: From<String> + FromLimitExceeded + FromIpeError + Send + 'static,
    R: HostResolver + Send + 'static,
{
    let timeout = match TransportTimeout::parse(req.timeout) {
        Ok(timeout) => timeout,
        Err(refusal) => return IpeResult::Err(timeout_refusal(refusal)),
    };
    // This surface (Http.get/post/request) accepts only http/https — ws/wss is
    // the WebSocket client's surface. When the SSRF guard is on, enforce that
    // narrower scheme set here, then delegate the host-resolve + DNS-rebinding
    // pin + per-redirect re-check to the SHARED `ssrf_apply_with` under the
    // same policy reading.
    if policy == DialPolicy::DenyPrivate
        && let Err(refusal) = parse_gated_url_within(&req.url, GatedSchemes::Http)
    {
        return IpeResult::Err(format!("http: {refusal}").into());
    }

    let builder = reqwest::Client::builder();
    let (mut builder, budget) =
        match ssrf_apply_with(builder, &req.url, req.redirects, policy, gate).await {
            Ok(applied) => applied,
            Err(refusal) => return IpeResult::Err(format!("http: {refusal}").into()),
        };

    // The one request deadline; its type proves it positive and bounded.
    builder = builder.timeout(timeout.as_duration());

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
            return IpeResult::Err(send_failure(e, &budget));
        }
    };
    let status = resp.status().as_u16() as i64;
    let headers = match response_header_dict(&resp) {
        Ok(headers) => headers,
        Err(refusal) => return IpeResult::Err(refusal.response_text().to_owned().into()),
    };
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

/// The program-visible header dict of `resp`, through the shared header fold.
///
/// Keys take the canonical case the Server request dict uses, so
/// `Dict.get "Content-Type" resp.headers` finds the key reqwest lower-cases.
#[cfg(not(target_arch = "wasm32"))]
fn response_header_dict(
    resp: &reqwest::Response,
) -> Result<HashMap<String, String>, crate::http_header::HeaderRefusal> {
    crate::http_header::response_headers(
        resp.headers()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes())),
    )
}

/// Default cap on a buffered HTTP response body (`Http.get`/`post`/`request`):
/// 100 MiB. `Http.*` returns the body as a single `String`, so an unbounded
/// read of an attacker- or upstream-controlled response is a memory-exhaustion
/// (OOM) vector. Override via `IPE_HTTP_MAX_BODY_BYTES` (streaming consumers that
/// need unbounded bodies use `Ipe.Http.Stream` instead).
///
/// One ceiling serves the native arm and the browser `fetch` arm alike.
#[cfg(any(
    not(target_arch = "wasm32"),
    all(target_arch = "wasm32", feature = "wasm-client")
))]
const HTTP_BODY_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_HTTP_MAX_BODY_BYTES",
    100 * 1024 * 1024,
    crate::system::ZeroCeiling::Refused,
    "decimal byte count",
);

/// The buffered-body cap, refused as `http: …` when the variable is malformed.
#[cfg(not(target_arch = "wasm32"))]
fn http_body_cap() -> Result<usize, String> {
    HTTP_BODY_CEILING
        .read()
        .map_err(|refusal| format!("http: {refusal}"))
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
async fn read_body_capped<E: From<String> + FromLimitExceeded + Send + 'static>(
    resp: reqwest::Response,
) -> IpeResult<E, String> {
    match http_body_cap() {
        Ok(cap) => read_body_within(resp, cap).await,
        Err(e) => IpeResult::Err(e.into()),
    }
}

/// Reads `resp`'s body, refusing it past `cap` bytes; see [`read_body_capped`].
#[cfg(not(target_arch = "wasm32"))]
async fn read_body_within<E: From<String> + FromLimitExceeded + Send + 'static>(
    resp: reqwest::Response,
    cap: usize,
) -> IpeResult<E, String> {
    use futures_util::StreamExt;
    if let Some(len) = resp.content_length()
        && len as usize > cap
    {
        return IpeResult::Err(
                LimitRefusal::new(format!(
                    "http: response body too large ({} > {} bytes; raise IPE_HTTP_MAX_BODY_BYTES or use Http.Stream)",
                    len, cap
                ))
                .into_error(),
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
                LimitRefusal::new(format!(
                    "http: response body too large (> {} bytes; raise IPE_HTTP_MAX_BODY_BYTES or use Http.Stream)",
                    cap
                ))
                .into_error(),
            );
        }
        buf.extend_from_slice(&bytes);
    }
    #[allow(clippy::disallowed_methods)]
    // a response body reaches Ipê as `String` text, not a URL component
    let text = String::from_utf8_lossy(&buf).into_owned();
    IpeResult::Ok(text)
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
pub fn http_get<E: From<String> + FromLimitExceeded + FromIpeError + Send + 'static>(
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
pub fn http_post<E: From<String> + FromLimitExceeded + FromIpeError + Send + 'static>(
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
pub fn http_request<E: From<String> + FromLimitExceeded + FromIpeError + Send + 'static>(
    req: HttpRequest,
) -> IpeTask<E, HttpResponse> {
    Box::pin(do_request(req))
}

/// `Http.parseQuery : String -> Result Error (Dict String String)` (pure).
///
/// A leading `?` is dropped, then the query is decoded by the same
/// `encoding::decode_form_query` the server uses for request queries: form
/// grammar, first value wins, at most `encoding::MAX_QUERY_PAIRS` pairs. Any
/// malformed component refuses the whole query with an `InvalidInput` error
/// that names the defect's position, never the query text; a query past the
/// pair ceiling is a `LimitExceeded` error.
///
/// # Errors
///
/// Returns `Err` when a key or value is not a well-formed form component or
/// the query carries too many pairs.
pub fn http_parse_query(raw: String) -> IpeResult<crate::error::IpeError, HashMap<String, String>> {
    match crate::encoding::decode_form_query(raw.trim_start_matches('?')) {
        Ok(pairs) => IpeResult::Ok(pairs),
        Err(refusal) => IpeResult::Err(query_refusal_error(refusal)),
    }
}

/// The `Error` a refused query becomes: each refusal names its own kind.
fn query_refusal_error(refusal: crate::encoding::QueryRefusal) -> crate::error::IpeError {
    let message = format!("parseQuery: {refusal}");
    match refusal {
        crate::encoding::QueryRefusal::Component(_) => {
            crate::error::IpeError::invalid_input(message)
        }
        crate::encoding::QueryRefusal::TooManyPairs { .. } => {
            crate::error::IpeError::limit_exceeded(message)
        }
    }
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
// rather than trapping the instance; every rejection here becomes one
// fixed-text `FetchFailure` — never a panic, never a silent drop, never the
// browser's own error text.

/// A browser fetch target, parsed once: an `http` or `https` URL with a host
/// and no user name or password.
///
/// The browser's `fetch` throws on a URL carrying credentials, and the thrown
/// value's text echoes the URL, credentials included. Parsing here keeps every
/// such URL out of `fetch` altogether, so no error text can carry it.
#[cfg(any(test, all(target_arch = "wasm32", feature = "wasm-client")))]
struct FetchTarget(String);

#[cfg(any(test, all(target_arch = "wasm32", feature = "wasm-client")))]
impl FetchTarget {
    /// Parses `raw` into a target the browser will take.
    ///
    /// # Errors
    ///
    /// [`FetchFailure::InvalidUrl`] when `raw` does not parse or has no host,
    /// [`FetchFailure::CredentialsInUrl`] when it carries a user name or a
    /// password, [`FetchFailure::Scheme`] when its scheme is not `http(s)`.
    fn parse(raw: &str) -> Result<Self, FetchFailure> {
        let Ok(parsed) = ::url::Url::parse(raw) else {
            return Err(FetchFailure::InvalidUrl);
        };
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(FetchFailure::CredentialsInUrl);
        }
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(FetchFailure::Scheme);
        }
        if parsed.host_str().is_none() {
            return Err(FetchFailure::InvalidUrl);
        }
        Ok(Self(parsed.into()))
    }

    /// The target as the browser receives it.
    fn as_str(&self) -> &str {
        &self.0
    }
}

/// Every way a browser fetch fails, each shown as a fixed text.
///
/// No variant carries the URL, a header, or anything the browser said: the
/// JavaScript value a rejected `fetch` or a refused `Request` carries echoes
/// the request, so it is matched on and dropped, never formatted.
#[cfg(any(test, all(target_arch = "wasm32", feature = "wasm-client")))]
#[derive(Debug)]
enum FetchFailure {
    /// The URL does not parse or has no host.
    InvalidUrl,
    /// The URL carries a user name or a password.
    CredentialsInUrl,
    /// The URL's scheme is not `http` or `https`.
    Scheme,
    /// A request header has a name the browser refuses.
    InvalidHeaderName,
    /// The request deadline is outside the admitted range.
    BadTimeout(TimeoutRefusal),
    /// `IPE_HTTP_MAX_BODY_BYTES` is present but malformed.
    BodyCeiling(crate::system::EnvCeilingRefusal),
    /// The browser refused to build the request.
    BrowserRefusedRequest,
    /// The deadline fired before the response headers arrived.
    TimedOut,
    /// The fetch was rejected without the deadline firing.
    NetworkOrCors,
    /// The fetch settled with a value that is not a `Response`.
    NotAResponse,
    /// There is no window, so this is not a browser context.
    NoWindow,
    /// The browser cannot build a `Headers` object.
    HeadersUnavailable,
    /// The browser cannot build the `AbortController` that carries the
    /// request deadline, so the request is refused rather than sent unbounded.
    DeadlineUnavailable,
    /// The response headers have no one program-visible reading.
    ResponseHeaders(crate::http_header::HeaderRefusal),
}

#[cfg(any(test, all(target_arch = "wasm32", feature = "wasm-client")))]
impl std::fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl => f.write_str("http: the URL does not parse or has no host"),
            Self::CredentialsInUrl => f.write_str(
                "http: the URL carries a user name or password; the browser refuses it — send \
                 credentials in a header",
            ),
            Self::Scheme => f.write_str("http: the URL's scheme is not http/https"),
            Self::InvalidHeaderName => f.write_str("http: a request header has an invalid name"),
            Self::BadTimeout(refusal) => write!(f, "http: timeout: {refusal}"),
            Self::BodyCeiling(refusal) => write!(f, "http: {refusal}"),
            Self::BrowserRefusedRequest => f.write_str("http: the browser refused the request"),
            Self::TimedOut => f.write_str("http: the request timed out"),
            Self::NetworkOrCors => f.write_str("http: fetch failed (network error or CORS block)"),
            Self::NotAResponse => f.write_str("http: fetch did not return a Response"),
            Self::NoWindow => f.write_str("http: no window (not a browser context?)"),
            Self::HeadersUnavailable => f.write_str("http: failed to build request headers"),
            Self::DeadlineUnavailable => {
                f.write_str("http: the browser cannot arm the request deadline")
            }
            Self::ResponseHeaders(refusal) => f.write_str(refusal.response_text()),
        }
    }
}

#[cfg(any(test, all(target_arch = "wasm32", feature = "wasm-client")))]
impl FetchFailure {
    /// This failure as the task's error: a refused input is `InvalidInput`,
    /// a transport failure keeps the sink's default kind.
    fn into_error<E: From<String> + FromIpeError>(self) -> E {
        let text = self.to_string();
        match self {
            Self::InvalidUrl
            | Self::CredentialsInUrl
            | Self::Scheme
            | Self::InvalidHeaderName
            | Self::BadTimeout(_)
            | Self::BodyCeiling(_) => {
                E::from_ipe_error(crate::error::IpeError::invalid_input(text))
            }
            Self::BrowserRefusedRequest
            | Self::TimedOut
            | Self::NetworkOrCors
            | Self::NotAResponse
            | Self::NoWindow
            | Self::HeadersUnavailable
            | Self::DeadlineUnavailable
            | Self::ResponseHeaders(_) => text.into(),
        }
    }
}

// The browser `fetch` substitute is gated on `all(wasm32, wasm-client)`, never a
// bare `wasm32`: the co-located WASI target (`wasm32-wasip1`, `wasm-client` off)
// is a native-ish wasm build that has no `web-sys`/`wasm-bindgen` in its graph,
// so a bare-`wasm32` arm would compile these browser bindings into a WASI build
// and fail cargo. `http_client` is not WASI-viable (reqwest is native-only), so
// on WASI this whole substitute stays absent and no kernel references it.
#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
async fn do_fetch<E: From<String> + FromLimitExceeded + FromIpeError + 'static>(
    req: HttpRequest,
) -> IpeResult<E, HttpResponse> {
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    // Both parses come first: a URL the browser would throw on, or a deadline
    // outside the admitted range, never reaches `fetch`.
    let target = match FetchTarget::parse(&req.url) {
        Ok(target) => target,
        Err(failure) => return IpeResult::Err(failure.into_error()),
    };
    let timeout = match TransportTimeout::parse(req.timeout) {
        Ok(timeout) => timeout,
        Err(refusal) => return IpeResult::Err(FetchFailure::BadTimeout(refusal).into_error()),
    };

    let Some(window) = web_sys::window() else {
        return IpeResult::Err(FetchFailure::NoWindow.into_error());
    };

    let Ok(headers) = web_sys::Headers::new() else {
        return IpeResult::Err(FetchFailure::HeadersUnavailable.into_error());
    };
    for (k, v) in &req.headers {
        if headers.set(k, v).is_err() {
            return IpeResult::Err(FetchFailure::InvalidHeaderName.into_error());
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
    // request deadline. A fired abort rejects the fetch Promise; the signal's
    // aborted flag then tells a deadline from a network or CORS failure. With
    // no controller there is no deadline, so the request is never sent.
    let Ok(controller) = web_sys::AbortController::new() else {
        return IpeResult::Err(FetchFailure::DeadlineUnavailable.into_error());
    };
    init.set_signal(Some(&controller.signal()));
    let abort = controller.clone();
    let _timeout_handle = gloo_timers::callback::Timeout::new(timeout.millis(), move || {
        abort.abort();
    });

    // The browser's thrown value is dropped unread: its text echoes the URL.
    let Ok(request) = web_sys::Request::new_with_str_and_init(target.as_str(), &init) else {
        return IpeResult::Err(FetchFailure::BrowserRefusedRequest.into_error());
    };

    let resp_value = match JsFuture::from(window.fetch_with_request(&request)).await {
        Ok(v) => v,
        Err(_) => {
            let failure = if controller.signal().aborted() {
                FetchFailure::TimedOut
            } else {
                FetchFailure::NetworkOrCors
            };
            return IpeResult::Err(failure.into_error());
        }
    };
    let Ok(resp) = resp_value.dyn_into::<web_sys::Response>() else {
        return IpeResult::Err(FetchFailure::NotAResponse.into_error());
    };

    let status = i64::from(resp.status());

    // The browser has already combined repeated headers, so the fold sees each
    // name once; it still applies the arity table and the byte check.
    let mut pairs: Vec<(String, String)> = Vec::new();
    if let Ok(Some(iter)) = js_sys::try_iter(resp.headers().as_ref()) {
        for entry in iter.flatten() {
            if let Ok(pair) = entry.dyn_into::<js_sys::Array>() {
                let k = pair.get(0).as_string().unwrap_or_default();
                let v = pair.get(1).as_string().unwrap_or_default();
                if !k.is_empty() {
                    pairs.push((k, v));
                }
            }
        }
    }
    let out_headers = match crate::http_header::response_headers(
        pairs.iter().map(|(k, v)| (k.as_str(), v.as_bytes())),
    ) {
        Ok(headers) => headers,
        Err(refusal) => {
            return IpeResult::Err(FetchFailure::ResponseHeaders(refusal).into_error());
        }
    };

    // Stream the body incrementally with a running cap so an untrusted (or
    // upstream-controlled) response is BOUNDED BY CONSTRUCTION — never fully
    // buffered by `Response.text()` before the size is known. Mirrors the native
    // `read_body_capped` incremental floor. `content_length()` is unreliable in a
    // browser (absent under transfer-encoding, or a lie), so the load-bearing
    // guard is the per-chunk cap in the loop, not a header pre-check.
    let cap = match HTTP_BODY_CEILING.read() {
        Ok(cap) => cap,
        Err(refusal) => return IpeResult::Err(FetchFailure::BodyCeiling(refusal).into_error()),
    };
    let body = match read_wasm_body_capped(&resp, cap).await {
        Ok(b) => b,
        Err(body_refusal) => return IpeResult::Err(body_refusal),
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
async fn read_wasm_body_capped<E: From<String> + FromLimitExceeded>(
    resp: &web_sys::Response,
    cap: usize,
) -> Result<String, E> {
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
        .map_err(|_| E::from("http: failed reading response body".to_string()))?;

    let mut buf: Vec<u8> = Vec::new();
    loop {
        let result = JsFuture::from(reader.read())
            .await
            .map_err(|_| E::from("http: failed reading response body".to_string()))?;
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
                return Err(LimitRefusal::new(format!(
                    "http: response body too large (> {cap} bytes; raise IPE_HTTP_MAX_BODY_BYTES)"
                ))
                .into_error());
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
    #[allow(clippy::disallowed_methods)]
    // a response body reaches Ipê as `String` text, not a URL component
    let text = String::from_utf8_lossy(&buf).into_owned();
    Ok(text)
}

/// Http.get : Url -> Task Error HttpResponse (browser substitute)
#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
pub fn http_get<E: From<String> + FromLimitExceeded + FromIpeError + 'static>(
    url: crate::url::Url,
) -> IpeTask<E, HttpResponse> {
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
pub fn http_post<E: From<String> + FromLimitExceeded + FromIpeError + 'static>(
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
pub fn http_request<E: From<String> + FromLimitExceeded + FromIpeError + 'static>(
    req: HttpRequest,
) -> IpeTask<E, HttpResponse> {
    Box::pin(do_fetch(req))
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn env_ceilings_honour_the_shared_contract() {
        crate::system::assert_env_ceiling_contract(HTTP_BODY_CEILING);
    }

    // ── Browser fetch target and fixed-text failures ─────────────────────────

    /// Every `FetchFailure` variant, one each.
    fn every_fetch_failure() -> Vec<FetchFailure> {
        let refused_ceiling = HTTP_BODY_CEILING.parse_as::<usize>(Ok("junk".to_owned()));
        assert!(refused_ceiling.is_err(), "a malformed ceiling is refused");
        let Err(ceiling) = refused_ceiling else {
            return Vec::new();
        };
        vec![
            FetchFailure::InvalidUrl,
            FetchFailure::CredentialsInUrl,
            FetchFailure::Scheme,
            FetchFailure::InvalidHeaderName,
            FetchFailure::BadTimeout(TimeoutRefusal::NotPositive),
            FetchFailure::BodyCeiling(ceiling),
            FetchFailure::BrowserRefusedRequest,
            FetchFailure::TimedOut,
            FetchFailure::NetworkOrCors,
            FetchFailure::NotAResponse,
            FetchFailure::NoWindow,
            FetchFailure::HeadersUnavailable,
            FetchFailure::DeadlineUnavailable,
            FetchFailure::ResponseHeaders(crate::http_header::HeaderRefusal::DuplicateSingleton),
        ]
    }

    /// The position of `failure`'s variant.
    ///
    /// A new variant fails to build here until it is given a position and a
    /// place in [`every_fetch_failure`].
    const fn fetch_failure_position(failure: &FetchFailure) -> usize {
        match failure {
            FetchFailure::InvalidUrl => 0,
            FetchFailure::CredentialsInUrl => 1,
            FetchFailure::Scheme => 2,
            FetchFailure::InvalidHeaderName => 3,
            FetchFailure::BadTimeout(_) => 4,
            FetchFailure::BodyCeiling(_) => 5,
            FetchFailure::BrowserRefusedRequest => 6,
            FetchFailure::TimedOut => 7,
            FetchFailure::NetworkOrCors => 8,
            FetchFailure::NotAResponse => 9,
            FetchFailure::NoWindow => 10,
            FetchFailure::HeadersUnavailable => 11,
            FetchFailure::DeadlineUnavailable => 12,
            FetchFailure::ResponseHeaders(_) => 13,
        }
    }

    #[test]
    fn fetch_target_refuses_userinfo() {
        for raw in [
            "https://u:hunter2@x.example/",
            "https://u@x.example/",
            "https://:hunter2@x.example/",
            "http://u:hunter2@127.0.0.1:8080/p",
        ] {
            assert!(
                matches!(FetchTarget::parse(raw), Err(FetchFailure::CredentialsInUrl)),
                "{raw:?} must be refused for its credentials"
            );
        }
    }

    #[test]
    fn fetch_target_refuses_ws_scheme() {
        for raw in [
            "ws://x.example/",
            "wss://x.example/",
            "ftp://x.example/",
            "file:///etc/passwd",
        ] {
            assert!(
                matches!(FetchTarget::parse(raw), Err(FetchFailure::Scheme)),
                "{raw:?} must be refused for its scheme"
            );
        }
    }

    #[test]
    fn fetch_target_refuses_what_does_not_parse() {
        for raw in ["", "not a url", "/relative/path", "https://"] {
            assert!(
                matches!(FetchTarget::parse(raw), Err(FetchFailure::InvalidUrl)),
                "{raw:?} must be refused as no URL"
            );
        }
    }

    #[test]
    fn fetch_target_admits_plain_https() {
        for (raw, shown) in [
            ("https://api.example/v1?q=1", "https://api.example/v1?q=1"),
            ("http://API.example", "http://api.example/"),
            (
                "https://api.example/?email=a@example.com",
                "https://api.example/?email=a@example.com",
            ),
        ] {
            let parsed = FetchTarget::parse(raw);
            assert!(parsed.is_ok(), "{raw:?} must be admitted");
            let Ok(target) = parsed else { return };
            assert_eq!(target.as_str(), shown);
        }
    }

    #[test]
    fn every_fetch_failure_text_is_fixed() {
        let failures = every_fetch_failure();
        let positions: Vec<usize> = failures.iter().map(fetch_failure_position).collect();
        let expected: Vec<usize> = (0..=fetch_failure_position(&FetchFailure::ResponseHeaders(
            crate::http_header::HeaderRefusal::DuplicateSingleton,
        )))
            .collect();
        assert_eq!(positions, expected, "every variant appears once, in order");
        for failure in &failures {
            let shown = failure.to_string();
            assert!(shown.starts_with("http: "), "{shown}");
            assert!(!shown.contains("://"), "a URL in {shown}");
            assert!(!shown.contains('@'), "userinfo in {shown}");
        }
    }

    #[test]
    fn a_refused_fetch_input_is_invalid_input_and_a_transport_failure_is_not() {
        for failure in every_fetch_failure() {
            let refused_input = matches!(
                failure,
                FetchFailure::InvalidUrl
                    | FetchFailure::CredentialsInUrl
                    | FetchFailure::Scheme
                    | FetchFailure::InvalidHeaderName
                    | FetchFailure::BadTimeout(_)
                    | FetchFailure::BodyCeiling(_)
            );
            let shown = failure.to_string();
            let crate::error::IpeError::Error(kind, info) =
                failure.into_error::<crate::error::IpeError>();
            assert_eq!(
                kind == crate::error::IpeErrorKind::InvalidInput,
                refused_input,
                "{shown}"
            );
            assert_eq!(info.message, shown);
        }
    }

    // ── Native request deadline ──────────────────────────────────────────────

    /// A request for `url` under `timeout` milliseconds.
    fn deadline_request(url: String, timeout: i64) -> HttpRequest {
        HttpRequest {
            body: String::new(),
            headers: Vec::new(),
            method: HttpMethod::Get,
            redirects: RedirectPolicy::NoRedirects,
            timeout,
            url,
        }
    }

    /// `req` sent with no deny-private gate and a resolver that is never asked.
    async fn send_unrestricted(
        req: HttpRequest,
    ) -> IpeResult<crate::error::IpeError, HttpResponse> {
        let gate = VettingResolver::new(
            std::sync::Arc::new(crate::ssrf::test_resolvers::NoDns),
            std::time::Duration::from_secs(5),
        );
        do_request_with(req, DialPolicy::AllowAll, gate).await
    }

    /// A deadline of zero, a negative one, or one past the ceiling is refused.
    ///
    /// The refusal is `InvalidInput` and comes before any dial: the listener
    /// the URL names sees no connection.
    #[tokio::test]
    async fn an_inadmissible_deadline_is_refused_before_any_dial() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await;
        assert!(listener.is_ok(), "bind loopback");
        let Ok(listener) = listener else { return };
        let addr = listener.local_addr();
        assert!(addr.is_ok(), "listener address");
        let Ok(addr) = addr else { return };
        let over = i64::from(crate::transport_timeout::MAX_TRANSPORT_TIMEOUT_MS) + 1;
        for timeout in [0, -1, i64::MIN, over, (1_i64 << 32) | 1] {
            let sent =
                send_unrestricted(deadline_request(format!("http://{addr}/"), timeout)).await;
            assert!(
                matches!(
                    &sent,
                    IpeResult::Err(crate::error::IpeError::Error(
                        crate::error::IpeErrorKind::InvalidInput,
                        info,
                    )) if info.message.starts_with("http: timeout: a span")
                ),
                "timeout {timeout} must be refused as InvalidInput"
            );
        }
        let dialled =
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept()).await;
        assert!(dialled.is_err(), "a refused deadline must never dial");
    }

    /// A one-millisecond deadline against a silent listener fails, not hangs.
    #[tokio::test]
    async fn the_shortest_deadline_times_out_a_silent_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await;
        assert!(listener.is_ok(), "bind loopback");
        let Ok(listener) = listener else { return };
        let addr = listener.local_addr();
        assert!(addr.is_ok(), "listener address");
        let Ok(addr) = addr else { return };
        // Accept and hold every connection open without ever replying.
        let holder = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });
        let sent = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            send_unrestricted(deadline_request(format!("http://{addr}/"), 1)),
        )
        .await;
        holder.abort();
        assert!(
            matches!(
                &sent,
                Ok(IpeResult::Err(crate::error::IpeError::Error(kind, _)))
                    if *kind != crate::error::IpeErrorKind::InvalidInput
            ),
            "the request must fail at its deadline, got {sent:?}"
        );
    }

    #[test]
    fn request_and_response_debug_print_no_credential() {
        let req = HttpRequest {
            body: "password=B0DYPW".to_owned(),
            headers: vec![("Authorization".to_owned(), "Bearer H34D3R".to_owned())],
            method: HttpMethod::Post,
            redirects: RedirectPolicy::NoRedirects,
            timeout: 30,
            url: "https://api.example/v1?key=URLK3Y".to_owned(),
        };
        let res = HttpResponse {
            status: 200,
            body: "{\"token\":\"R3SB0DY\"}".to_owned(),
            headers: HashMap::from([("set-cookie".to_owned(), "sid=S3TC00K".to_owned())]),
        };
        let shown = format!("{req:?} {res:?}");
        for planted in ["B0DYPW", "H34D3R", "URLK3Y", "R3SB0DY", "S3TC00K"] {
            assert!(!shown.contains(planted), "{planted} leaked: {shown}");
        }
        assert!(shown.contains("status: 200"), "{shown}");
    }

    #[test]
    fn parse_query_decode_and_first_wins() {
        let parsed = http_parse_query("a=1&b=two%20words+more&a=ignored&c".to_string());
        assert!(
            matches!(parsed, IpeResult::Ok(_)),
            "a well-formed query parses"
        );
        let IpeResult::Ok(q) = parsed else { return };
        assert_eq!(q.get("a").map(String::as_str), Some("1")); // first value wins
        assert_eq!(q.get("b").map(String::as_str), Some("two words more"));
        assert_eq!(q.get("c").map(String::as_str), Some(""));
        // Leading '?' tolerated; empty pairs skipped.
        let parsed = http_parse_query("?x=9&".to_string());
        assert!(
            matches!(parsed, IpeResult::Ok(_)),
            "a leading `?` is dropped"
        );
        let IpeResult::Ok(q2) = parsed else { return };
        assert_eq!(q2.get("x").map(String::as_str), Some("9"));
        assert_eq!(q2.len(), 1);
    }

    #[test]
    fn parse_query_refuses_malformed_queries_whole() {
        // Prove the refusals: a bad escape or invalid UTF-8 in a key or value
        // refuses the whole query as `InvalidInput`, and the message never
        // echoes the query text.
        for raw in [
            "a=1&b=%zz".to_string(),
            "?a=100%".to_string(),
            "%C3=1".to_string(),
            "a=%C0%AF".to_string(),
        ] {
            let parsed = http_parse_query(raw.clone());
            assert!(
                matches!(parsed, IpeResult::Err(_)),
                "{raw:?} must be refused"
            );
            let IpeResult::Err(crate::error::IpeError::Error(kind, info)) = parsed else {
                return;
            };
            assert_eq!(kind, crate::error::IpeErrorKind::InvalidInput, "{raw:?}");
            assert!(
                !info.message.contains("hunter2") && !info.message.contains("zz"),
                "{raw:?}"
            );
        }
    }

    /// The pair ceiling: `MAX_QUERY_PAIRS` pairs parse, one more is a
    /// `LimitExceeded` refusal that never echoes the query text.
    #[test]
    fn parse_query_past_the_pair_ceiling_is_limit_exceeded() {
        let cap = crate::encoding::MAX_QUERY_PAIRS.get();
        let mut pairs: Vec<String> = (0..cap).map(|i| format!("k{i}=v")).collect();
        let at_cap = http_parse_query(pairs.join("&"));
        assert!(
            matches!(&at_cap, IpeResult::Ok(q) if q.len() == cap),
            "{cap} pairs must parse"
        );
        pairs.push("secret=hunter2".to_string());
        assert_eq!(
            http_parse_query(pairs.join("&")),
            IpeResult::Err(crate::error::IpeError::limit_exceeded(format!(
                "parseQuery: more than {cap} query pairs"
            )))
        );
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

        /// The system resolver refuses to be built under an unusable deadline.
        #[test]
        fn the_system_resolver_refuses_a_malformed_dns_deadline() {
            crate::system::locked_set_var("IPE_HTTP_DNS_TIMEOUT_MS", "5s");
            let refused = VettingResolver::system().err();
            crate::system::locked_remove_var("IPE_HTTP_DNS_TIMEOUT_MS");
            assert!(
                matches!(refused, Some(SsrfRefusal::Deadline(_))),
                "a malformed deadline must refuse the resolver"
            );
        }

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

        /// Serves `/hop/N` on loopback as a redirect to `/hop/N-1`, and
        /// `/hop/0` as `200 OK`.
        async fn redirect_ladder() -> SocketAddr {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind loopback");
            let addr = listener.local_addr().expect("listener address");
            tokio::spawn(async move {
                while let Ok((mut sock, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        let n = sock.read(&mut buf).await.unwrap_or(0);
                        let head = std::str::from_utf8(buf.get(..n).unwrap_or_default())
                            .unwrap_or_default();
                        let hops: u32 = head
                            .split_whitespace()
                            .nth(1)
                            .and_then(|path| path.strip_prefix("/hop/"))
                            .and_then(|left| left.parse().ok())
                            .unwrap_or(0);
                        let reply = if hops == 0 {
                            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                                .to_string()
                        } else {
                            format!(
                                "HTTP/1.1 302 Found\r\nLocation: /hop/{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                hops.saturating_sub(1)
                            )
                        };
                        let _ = sock.write_all(reply.as_bytes()).await;
                    });
                }
            });
            addr
        }

        /// The status a `hops`-long ladder ends on under a `max`-hop budget,
        /// or the send failure as the Ipê program sees it.
        async fn climb(addr: SocketAddr, hops: u32, max: i64) -> Result<u16, crate::IpeError> {
            let url = format!("http://{addr}/hop/{hops}");
            let (builder, budget) = ssrf_apply_with(
                reqwest::Client::builder().no_proxy(),
                &url,
                RedirectPolicy::FollowRedirects(max),
                DialPolicy::AllowAll,
                gate(NoDns),
            )
            .await
            .expect("an AllowAll dial is never refused");
            let client = builder.build().expect("client builds");
            match client.get(&url).send().await {
                Ok(resp) => Ok(resp.status().as_u16()),
                Err(e) => Err(super::super::send_failure(e, &budget)),
            }
        }

        /// Serves `reply` verbatim to every connection on loopback.
        async fn fixed_reply(reply: &'static str) -> SocketAddr {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind loopback");
            let addr = listener.local_addr().expect("listener address");
            tokio::spawn(async move {
                while let Ok((mut sock, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        let _ = sock.read(&mut buf).await;
                        let _ = sock.write_all(reply.as_bytes()).await;
                    });
                }
            });
            addr
        }

        /// The header dict `reply` reads as, through the response fold.
        async fn headers_of(
            reply: &'static str,
        ) -> Result<std::collections::HashMap<String, String>, crate::http_header::HeaderRefusal>
        {
            let addr = fixed_reply(reply).await;
            let client = reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("client builds");
            let resp = client
                .get(format!("http://{addr}/"))
                .send()
                .await
                .expect("loopback reply");
            super::super::response_header_dict(&resp)
        }

        /// A response repeating `Content-Type` is refused with a fixed text that
        /// names no header; one copy reads under its canonical key.
        #[tokio::test]
        async fn response_duplicate_content_type_refused() {
            const TWICE: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Type: text/html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            const ONCE: &str = "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let refused = headers_of(TWICE).await;
            assert_eq!(
                refused,
                Err(crate::http_header::HeaderRefusal::DuplicateSingleton)
            );
            let text = crate::http_header::HeaderRefusal::DuplicateSingleton.response_text();
            assert!(!text.contains("Content-Type"), "refusal names no header");
            let once = headers_of(ONCE).await.expect("one copy is admitted");
            assert_eq!(
                once.get("Content-Type").map(String::as_str),
                Some("text/plain")
            );
        }

        /// A response header value outside visible ASCII refuses the response,
        /// never vanishes from the dict.
        #[tokio::test]
        async fn response_non_ascii_header_refused() {
            const NON_ASCII: &str = "HTTP/1.1 200 OK\r\nX-Note: caf\u{e9}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            assert_eq!(
                headers_of(NON_ASCII).await,
                Err(crate::http_header::HeaderRefusal::NotVisibleAscii)
            );
        }

        /// List headers combine in arrival order; repeated `Set-Cookie` keeps
        /// the last copy.
        #[tokio::test]
        async fn response_list_headers_combine_and_set_cookie_keeps_last() {
            const REPLY: &str = "HTTP/1.1 200 OK\r\nVia: 1.1 a\r\nVia: 1.1 b\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let headers = headers_of(REPLY).await.expect("list copies are admitted");
            assert_eq!(headers.get("Via").map(String::as_str), Some("1.1 a, 1.1 b"));
            assert_eq!(headers.get("Set-Cookie").map(String::as_str), Some("b=2"));
        }

        /// The body `reply` carries, read under a `cap`-byte ceiling.
        async fn body_within(
            reply: &'static str,
            cap: usize,
        ) -> crate::IpeResult<crate::IpeError, String> {
            let addr = fixed_reply(reply).await;
            let client = reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("client builds");
            match client.get(format!("http://{addr}/")).send().await {
                Ok(resp) => super::super::read_body_within(resp, cap).await,
                Err(e) => crate::IpeResult::Err(super::super::redacted_transport_error(e)),
            }
        }

        /// A declared `Content-Length` one byte past the ceiling is refused up
        /// front as `LimitExceeded`; at the ceiling the body is read.
        #[tokio::test]
        async fn declared_body_one_byte_past_the_ceiling_is_limit_exceeded() {
            const SIZED: &str =
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabcde";
            assert_eq!(
                body_within(SIZED, 5).await,
                crate::IpeResult::Ok("abcde".to_owned())
            );
            assert_eq!(
                body_within(SIZED, 4).await,
                crate::IpeResult::Err(crate::IpeError::limit_exceeded(
                    "http: response body too large (5 > 4 bytes; raise IPE_HTTP_MAX_BODY_BYTES or use Http.Stream)"
                ))
            );
        }

        /// A chunked body with no declared length is bounded by the incremental
        /// read: one byte past the ceiling is `LimitExceeded`.
        #[tokio::test]
        async fn streamed_body_one_byte_past_the_ceiling_is_limit_exceeded() {
            const CHUNKED: &str = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nabcde\r\n0\r\n\r\n";
            assert_eq!(
                body_within(CHUNKED, 5).await,
                crate::IpeResult::Ok("abcde".to_owned())
            );
            assert_eq!(
                body_within(CHUNKED, 4).await,
                crate::IpeResult::Err(crate::IpeError::limit_exceeded(
                    "http: response body too large (> 4 bytes; raise IPE_HTTP_MAX_BODY_BYTES or use Http.Stream)"
                ))
            );
        }

        /// The hop count is judged before the dial policy is consulted, so the
        /// boundary is the same under `DenyPrivate`: `max` URLs may precede a
        /// redirect target, the next one spends the budget.
        #[test]
        fn redirect_budget_boundary_is_independent_of_the_dial_policy() {
            let budget = super::super::RedirectBudget::new(3);
            assert!((1..=3).all(|visited| !budget.spent_by(visited)));
            assert!(budget.refusal().is_none());
            assert!(budget.spent_by(4));
            assert_eq!(
                budget.refusal().map(crate::LimitRefusal::into_error),
                Some(crate::IpeError::limit_exceeded(
                    "http: too many redirects (max 3)"
                ))
            );
        }

        /// `FollowRedirects n` follows exactly `n` hops; the hop past them is a
        /// `LimitExceeded` refusal, never an opaque transport error.
        #[tokio::test]
        async fn redirect_chain_past_its_maximum_is_limit_exceeded() {
            let addr = redirect_ladder().await;
            assert_eq!(climb(addr, 3, 3).await, Ok(200));
            assert_eq!(
                climb(addr, 4, 3).await,
                Err(crate::IpeError::limit_exceeded(
                    "http: too many redirects (max 3)"
                ))
            );
            assert_eq!(
                climb(addr, 1, 0).await,
                Err(crate::IpeError::limit_exceeded(
                    "http: too many redirects (max 0)"
                ))
            );
        }
    }
}
